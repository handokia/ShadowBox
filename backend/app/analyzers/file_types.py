"""Nhận diện định dạng thực tế bằng magic bytes (không tin phần mở rộng)."""
from __future__ import annotations

import zipfile
from pathlib import Path

from ..core.models import DetectedType

# id -> (label, category, extension hợp lệ)
TYPES: dict[str, tuple[str, str, set[str]]] = {
    "pe":      ("Windows PE executable", "executable", {".exe", ".dll", ".sys", ".scr", ".ocx", ".cpl", ".drv", ".efi"}),
    "dos_mz":  ("DOS/MZ executable", "executable", {".exe", ".com", ".sys", ".dll"}),
    "elf":     ("ELF executable", "executable", {"", ".so", ".elf", ".bin", ".o", ".out"}),
    "pdf":     ("PDF document", "document", {".pdf"}),
    "ole":     ("OLE2 container (legacy Office / MSI)", "document", {".doc", ".xls", ".ppt", ".dot", ".xlt", ".msi", ".msg", ".pps"}),
    "rtf":     ("Rich Text Format", "document", {".rtf", ".doc"}),
    "zip":     ("ZIP archive", "archive", {".zip"}),
    "docx":    ("Word document (OOXML)", "document", {".docx", ".docm", ".dotx", ".dotm"}),
    "xlsx":    ("Excel workbook (OOXML)", "document", {".xlsx", ".xlsm", ".xltx", ".xltm"}),
    "pptx":    ("PowerPoint (OOXML)", "document", {".pptx", ".pptm", ".potx", ".ppsx"}),
    "apk":     ("Android package", "archive", {".apk"}),
    "jar":     ("Java archive", "archive", {".jar", ".war"}),
    "rar":     ("RAR archive", "archive", {".rar"}),
    "7z":      ("7-Zip archive", "archive", {".7z"}),
    "gzip":    ("GZIP archive", "archive", {".gz", ".tgz"}),
    "png":     ("PNG image", "image", {".png"}),
    "jpeg":    ("JPEG image", "image", {".jpg", ".jpeg", ".jpe"}),
    "gif":     ("GIF image", "image", {".gif"}),
    "lnk":     ("Windows shortcut", "shortcut", {".lnk"}),
    "script":  ("Script (shebang)", "script", set()),
    "text":    ("Plain text", "text", set()),
    "unknown": ("Unknown binary", "unknown", set()),
}

# Họ OOXML/ZIP: đổi qua lại giữa các đuôi này không đáng ngờ.
ZIP_FAMILY_EXTS = (
    TYPES["zip"][2] | TYPES["docx"][2] | TYPES["xlsx"][2] | TYPES["pptx"][2] | TYPES["apk"][2] | TYPES["jar"][2]
)

# Đuôi mà nội dung bắt buộc phải là nhị phân đúng định dạng; file văn bản mang đuôi này là đáng ngờ.
BINARY_ONLY_EXTS = (
    TYPES["pe"][2] | TYPES["pdf"][2] | TYPES["png"][2] | TYPES["jpeg"][2] | TYPES["gif"][2]
    | TYPES["rar"][2] | TYPES["7z"][2] | ZIP_FAMILY_EXTS | TYPES["lnk"][2]
)

SCRIPT_EXTS = {".ps1", ".psm1", ".bat", ".cmd", ".vbs", ".vbe", ".js", ".jse", ".wsf", ".hta", ".py", ".pyw", ".sh", ".reg"}
EXEC_LIKE_EXTS = {".exe", ".scr", ".com", ".pif", ".bat", ".cmd", ".vbs", ".vbe", ".js", ".jse", ".ps1", ".lnk", ".hta", ".jar", ".msi", ".wsf"}
DOC_LIKE_EXTS = {".pdf", ".doc", ".docx", ".xls", ".xlsx", ".ppt", ".pptx", ".txt", ".jpg", ".jpeg", ".png", ".gif", ".zip", ".rtf", ".mp3", ".mp4"}

_SIGNATURES: list[tuple[bytes, int, str]] = [
    (b"%PDF-", 0, "pdf"),
    (b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1", 0, "ole"),
    (b"{\\rtf", 0, "rtf"),
    (b"\x89PNG\r\n\x1a\n", 0, "png"),
    (b"\xff\xd8\xff", 0, "jpeg"),
    (b"GIF87a", 0, "gif"),
    (b"GIF89a", 0, "gif"),
    (b"Rar!\x1a\x07", 0, "rar"),
    (b"7z\xbc\xaf\x27\x1c", 0, "7z"),
    (b"\x1f\x8b", 0, "gzip"),
    (b"\x7fELF", 0, "elf"),
    (b"L\x00\x00\x00\x01\x14\x02\x00", 0, "lnk"),
]

_BOMS = (b"\xef\xbb\xbf", b"\xff\xfe", b"\xfe\xff")


def _dt(type_id: str) -> DetectedType:
    label, category, _ = TYPES[type_id]
    return DetectedType(id=type_id, label=label, category=category)


def _looks_like_text(sample: bytes) -> bool:
    if not sample:
        return True
    if sample.startswith(_BOMS):
        return True
    if b"\x00" in sample:
        return False
    printable = sum(1 for b in sample if b in (9, 10, 13) or 32 <= b < 127 or b >= 128)
    return printable / len(sample) >= 0.95


def decode_text(data: bytes) -> str:
    if data.startswith((b"\xff\xfe", b"\xfe\xff")):
        return data.decode("utf-16", errors="replace")
    return data.decode("utf-8-sig", errors="replace")


def refine_zip(path: Path) -> tuple[DetectedType, dict]:
    """Phân loại ZIP-based bằng danh sách tên entry (không giải nén nội dung)."""
    meta: dict = {}
    try:
        with zipfile.ZipFile(path) as zf:
            infos = zf.infolist()
            names = [i.filename for i in infos[:10000]]
            meta["zip_entries"] = len(infos)
            meta["zip_uncompressed_total"] = sum(i.file_size for i in infos[:10000])
    except (zipfile.BadZipFile, OSError, RuntimeError):
        meta["zip_error"] = "Không đọc được cấu trúc ZIP"
        return _dt("zip"), meta

    lower = [n.lower() for n in names]
    meta["zip_names_sample"] = names[:50]
    meta["_zip_names"] = names  # dùng nội bộ, inspector sẽ gỡ trước khi trả ra
    if "androidmanifest.xml" in lower:
        return _dt("apk"), meta
    if any(n.startswith("word/") for n in lower):
        return _dt("docx"), meta
    if any(n.startswith("xl/") for n in lower):
        return _dt("xlsx"), meta
    if any(n.startswith("ppt/") for n in lower):
        return _dt("pptx"), meta
    if "meta-inf/manifest.mf" in lower:
        return _dt("jar"), meta
    return _dt("zip"), meta


def detect(path: Path, header: bytes) -> tuple[DetectedType, dict]:
    """Trả về (loại, metadata bổ sung)."""
    if header.startswith(b"MZ") and len(header) >= 64:
        off = int.from_bytes(header[0x3C:0x40], "little")
        if 0 < off <= len(header) - 4 and header[off:off + 4] == b"PE\x00\x00":
            return _dt("pe"), {}
        return _dt("dos_mz"), {}
    if header.startswith((b"PK\x03\x04", b"PK\x05\x06")):
        return refine_zip(path)
    for magic, offset, type_id in _SIGNATURES:
        if header[offset:offset + len(magic)] == magic:
            return _dt(type_id), {}
    sample = header[:8192]
    if _looks_like_text(sample):
        return (_dt("script") if sample.startswith(b"#!") else _dt("text")), {}
    return _dt("unknown"), {}
