"""AnalysisService: lớp dùng chung cho Web (upload) và Desktop (đường dẫn cục bộ)."""
from __future__ import annotations

from functools import lru_cache
from pathlib import Path

from ..core.config import settings
from ..core.models import AnalysisResult
from ..scanners.rules import RuleSet, evaluate, load_rules
from ..scanners.yara_scan import scan_file as yara_scan
from .inspector import inspect_file
from .scripts import analyze_script


@lru_cache(maxsize=1)
def get_rules() -> RuleSet:
    return load_rules(settings.rules_path)


def analyze_path(path: str | Path, original_name: str | None = None, use_yara: bool = True) -> AnalysisResult:
    report = inspect_file(path, original_name=original_name)

    extra = []
    script = analyze_script(report)
    if script.info:
        report.metadata["script"] = script.info
        extra.extend(script.findings)

    if use_yara:
        outcome = yara_scan(path, report.size)
        report.metadata["yara"] = outcome.info
        extra.extend(outcome.findings)

    return evaluate(report, get_rules(), extra_findings=extra)
