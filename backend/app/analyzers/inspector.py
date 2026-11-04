"""File Inspector: chỉ ĐỌC file, không bao giờ thực thi hay sửa đổi."""
from __future__ import annotations

import hashlib
import os
import re
import stat
import sys
from datetime import datetime, timezone
from pathlib import Path

from ..core.config import settings
from ..core.models import FileReport
from . import file_types as ft

_BIDI_CHARS = set("\u202a\u202b\u202c\u202d\u202e\u2066\u2067\u2068\u2069")
_HEADER_BYTES = 64 * 1024
_CHUNK = 1024 * 1024


class InspectError(Exception):
    pass


def _escape_name(name: str) -> str:
    """Escape ký tự điều khiển / bidi để hiển thị an toàn."""
    out = []
    for ch in name:
        if ch in _BIDI_CHARS or ord(ch) < 32 or ord(ch) == 127:
            out.append(f"\\u{ord(ch):04x}")
        else:
            out.append(ch)
    return "".join(out)


def _iso(ts: float | None) -> str | None:
    if ts is None:
        return None
    return datetime.fromtimestamp(ts, tz=timezone.utc).isoformat()


def _created(st: os.stat_result) -> str | None:
    birth = getattr(st, "st_birthtime", None)
    if birth is not None:
        return _iso(birth)
    if sys.platform == "win32":
        return _iso(st.st_ctime)
    return None  # Linux không có thời điểm tạo đáng tin cậy


def _hash_file(path: Path) -> tuple[str, str]:
    md5, sha = hashlib.md5(usedforsecurity=False), hashlib.sha256()
    with open(path, "rb") as f:
        while chunk := f.read(_CHUNK):
            md5.update(chunk)
            sha.update(chunk)
    return md5.hexdigest(), sha.hexdigest()


def _name_signals(original_name: str, signals: dict[str, list[str]]) -> None:
    if any(c in _BIDI_CHARS for c in original_name):
        signals.setdefault("rtl_override", []).append(
            f"Tên file chứa ký tự điều hướng Unicode: {_escape_name(original_name)}"
        )
    parts = original_name.lower().split(".")
    if len(parts) >= 3:
        last, prev = "." + parts[-1].strip(), "." + parts[-2].strip()
        if last in ft.EXEC_LIKE_EXTS and prev in ft.DOC_LIKE_EXTS:
            signals.setdefault("double_extension", []).append(
                f"{_escape_name(original_name)} (đuôi thật: {last}, đuôi giả: {prev})"
            )


def _extension_signals(ext: str, detected: ft.DetectedType, signals: dict[str, list[str]]) -> None:
    expected = ft.TYPES[detected.id][2]
    if detected.id in ("unknown",):
        return
    if ext in expected:
        return
    if detected.id in ("docx", "xlsx", "pptx", "apk", "jar", "zip") and ext in ft.ZIP_FAMILY_EXTS:
        return
    if detected.category == "executable":
        signals.setdefault("executable_disguised", []).append(
            f"Nội dung là {detected.label} nhưng đuôi file là '{ext or '(không có)'}'"
        )
    elif detected.category in ("text", "script"):
        if ext in ft.BINARY_ONLY_EXTS:
            signals.setdefault("extension_mismatch", []).append(
                f"Nội dung là văn bản nhưng đuôi file là '{ext}' (kỳ vọng định dạng nhị phân)"
            )
    else:
        signals.setdefault("extension_mismatch", []).append(
            f"Nội dung là {detected.label} nhưng đuôi file là '{ext or '(không có)'}'"
        )


def inspect_file(path: str | os.PathLike, original_name: str | None = None) -> FileReport:
    p = Path(path)
    st = os.lstat(p)  # lstat: không đi theo symlink
    if stat.S_ISLNK(st.st_mode):
        raise InspectError("Không phân tích symlink.")
    if not stat.S_ISREG(st.st_mode):
        raise InspectError("Đường dẫn không phải file thường.")

    raw_name = original_name if original_name is not None else p.name
    ext = os.path.splitext(raw_name)[1].lower().strip()

    with open(p, "rb") as f:
        header = f.read(_HEADER_BYTES)

    detected, extra_meta = ft.detect(p, header)
    md5, sha256 = _hash_file(p)

    signals: dict[str, list[str]] = {}
    _name_signals(raw_name, signals)
    _extension_signals(ext, detected, signals)

    zip_names = extra_meta.pop("_zip_names", None)
    if zip_names:
        if any(n.lower().endswith("vbaproject.bin") for n in zip_names):
            signals.setdefault("has_macros", []).append("Tìm thấy vbaProject.bin trong tài liệu")
        if detected.id == "zip":
            risky = [n for n in zip_names if os.path.splitext(n.lower())[1] in ft.EXEC_LIKE_EXTS]
            if risky:
                signals.setdefault("archive_contains_executable", []).extend(risky[:10])

    text = None
    content_class = "binary"
    if detected.category in ("text", "script"):
        content_class = "script" if (ext in ft.SCRIPT_EXTS or detected.category == "script") else "text"
        with open(p, "rb") as f:
            text = ft.decode_text(f.read(settings.max_scan_bytes))
    elif ext in ft.SCRIPT_EXTS and detected.category != "executable":
        content_class = "script"

    metadata = {"detected_label": detected.label, **extra_meta}
    if text is not None:
        metadata["line_count"] = text.count("\n") + 1
        metadata["scanned_bytes"] = min(st.st_size, settings.max_scan_bytes)

    return FileReport(
        name=_escape_name(raw_name),
        extension=ext,
        size=st.st_size,
        md5=md5,
        sha256=sha256,
        modified=_iso(st.st_mtime),
        created=_created(st),
        detected=detected,
        content_class=content_class,
        metadata=metadata,
        signals=signals,
        text=text,
    )
