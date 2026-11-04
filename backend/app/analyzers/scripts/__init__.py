"""Script Analyzer: chọn bộ phân tích theo ngôn ngữ (đuôi file, nếu không có thì nhận diện từ nội dung)."""
from __future__ import annotations

import ipaddress
import re
from dataclasses import dataclass, field

from ...core.models import Finding, FileReport
from .base import ScriptAnalyzer
from .batch import BatchAnalyzer
from .javascript import JavaScriptAnalyzer
from .powershell import PowerShellAnalyzer
from .python_script import PythonAnalyzer

ANALYZERS: tuple[ScriptAnalyzer, ...] = (
    PowerShellAnalyzer(),
    BatchAnalyzer(),
    PythonAnalyzer(),
    JavaScriptAnalyzer(),
)

_SNIFF_THRESHOLD = 2
_URL_RE = re.compile(r"https?://[^\s'\"<>)\]]{4,200}", re.I)
_IP_RE = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
_MAX_IOCS = 20


@dataclass
class ScriptAnalysis:
    findings: list[Finding] = field(default_factory=list)
    info: dict = field(default_factory=dict)


def select_analyzer(ext: str, text: str) -> tuple[ScriptAnalyzer | None, str | None]:
    for a in ANALYZERS:
        if ext in a.extensions:
            return a, "extension"
    scored = [(a.sniff_score(text), a) for a in ANALYZERS]
    best_score, best = max(scored, key=lambda t: t[0])
    if best_score >= _SNIFF_THRESHOLD:
        return best, "content"
    return None, None


def extract_iocs(text: str) -> dict[str, list[str]]:
    urls = list(dict.fromkeys(_URL_RE.findall(text)))[:_MAX_IOCS]
    ips: list[str] = []
    for m in _IP_RE.findall(text):
        try:
            ip = ipaddress.ip_address(m)
        except ValueError:
            continue
        if ip.is_unspecified or ip.is_loopback or m in ips:
            continue
        ips.append(m)
        if len(ips) >= _MAX_IOCS:
            break
    return {"urls": urls, "ips": ips}


def analyze_script(report: FileReport) -> ScriptAnalysis:
    if report.text is None or report.detected.category not in ("text", "script"):
        return ScriptAnalysis()
    analyzer, source = select_analyzer(report.extension, report.text)
    if analyzer is None:
        return ScriptAnalysis()
    findings = analyzer.analyze(report.text)
    info = {
        "language": analyzer.language,
        "display_name": analyzer.display_name,
        "language_source": source,
        "iocs": extract_iocs(report.text),
    }
    return ScriptAnalysis(findings=findings, info=info)
