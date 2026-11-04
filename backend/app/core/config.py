"""Cấu hình ShadowBox, đọc từ biến môi trường."""
from __future__ import annotations

import os
from dataclasses import dataclass, field
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[3]


@dataclass(frozen=True)
class Settings:
    max_upload_bytes: int = field(
        default_factory=lambda: int(os.getenv("SHADOWBOX_MAX_UPLOAD_MB", "50")) * 1024 * 1024
    )
    rules_path: Path = field(
        default_factory=lambda: Path(
            os.getenv("SHADOWBOX_RULES", str(REPO_ROOT / "rules" / "risk" / "default.json"))
        )
    )
    script_rules_dir: Path = field(
        default_factory=lambda: Path(
            os.getenv("SHADOWBOX_SCRIPT_RULES", str(REPO_ROOT / "rules" / "scripts"))
        )
    )
    yara_rules_dir: Path = field(
        default_factory=lambda: Path(
            os.getenv("SHADOWBOX_YARA_RULES", str(REPO_ROOT / "rules" / "yara"))
        )
    )
    # Quét YARA chạy trong process con; quá thời gian này sẽ bị kill.
    yara_timeout_s: float = field(
        default_factory=lambda: float(os.getenv("SHADOWBOX_YARA_TIMEOUT", "20"))
    )
    # File lớn hơn mức này bị bỏ qua ở bước YARA (vẫn có hash và phân tích khác).
    yara_max_bytes: int = field(
        default_factory=lambda: int(os.getenv("SHADOWBOX_YARA_MAX_MB", "64")) * 1024 * 1024
    )
    tmp_dir: Path | None = field(
        default_factory=lambda: Path(os.environ["SHADOWBOX_TMP_DIR"])
        if os.getenv("SHADOWBOX_TMP_DIR")
        else None
    )
    # Số byte tối đa đọc để quét nội dung văn bản/script.
    max_scan_bytes: int = 1024 * 1024
    cors_origins: tuple[str, ...] = (
        "http://localhost:5173",
        "http://127.0.0.1:5173",
        "tauri://localhost",
        "http://tauri.localhost",
    )


settings = Settings()
