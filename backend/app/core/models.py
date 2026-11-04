"""Các cấu trúc dữ liệu dùng chung giữa Inspector, Scanner và API."""
from __future__ import annotations

from dataclasses import asdict, dataclass, field
from typing import Any


@dataclass
class DetectedType:
    id: str            # vd: "pe", "pdf", "docx"
    label: str         # vd: "Windows PE executable"
    category: str      # executable | document | archive | image | script | text | shortcut | unknown


@dataclass
class FileReport:
    """Kết quả của File Inspector: dữ kiện + tín hiệu, chưa có điểm rủi ro."""
    name: str                      # tên hiển thị đã escape ký tự điều khiển
    extension: str
    size: int
    md5: str
    sha256: str
    modified: str | None
    created: str | None
    detected: DetectedType
    content_class: str             # script | text | binary
    metadata: dict[str, Any] = field(default_factory=dict)
    # signal -> danh sách bằng chứng (chuỗi)
    signals: dict[str, list[str]] = field(default_factory=dict)
    # Văn bản trích để Risk Scanner quét (không đưa ra API).
    text: str | None = field(default=None, repr=False)

    def public_dict(self) -> dict[str, Any]:
        d = asdict(self)
        d.pop("text", None)
        return d


@dataclass
class Finding:
    rule_id: str
    title: str
    severity: str
    points: int
    description: str
    evidence: list[str]


@dataclass
class AnalysisResult:
    file: dict[str, Any]
    score: int
    level: str
    verdict: str
    findings: list[Finding]
    disclaimer: str
    rules_version: int

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)
