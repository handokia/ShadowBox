"""Rule engine: chấm điểm theo quy tắc có trọng số, mọi finding đều kèm bằng chứng."""
from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path
from typing import Iterable

from ..core.models import AnalysisResult, FileReport, Finding

MAX_EVIDENCE = 5

DISCLAIMER = (
    "Kết quả dựa trên phân tích tĩnh và quy tắc heuristic. "
    "'No threats detected' không có nghĩa là file an toàn."
)


@dataclass
class SignalRule:
    id: str
    signal: str
    title: str
    severity: str
    points: int
    description: str


@dataclass
class RuleSet:
    version: int
    levels: list[dict]
    signal_rules: list[SignalRule]


def load_rules(path: str | Path) -> RuleSet:
    data = json.loads(Path(path).read_text(encoding="utf-8"))
    levels = sorted(data["levels"], key=lambda l: l["min"])
    if not levels or levels[0]["min"] != 0:
        raise ValueError("levels phải bắt đầu từ min = 0")
    signal_rules = [SignalRule(**r) for r in data.get("signal_rules", [])]
    return RuleSet(data["version"], levels, signal_rules)


def _level_for(score: int, levels: list[dict]) -> dict:
    chosen = levels[0]
    for lv in levels:
        if score >= lv["min"]:
            chosen = lv
    return chosen


def evaluate(report: FileReport, rules: RuleSet, extra_findings: Iterable[Finding] = ()) -> AnalysisResult:
    """Gộp tín hiệu của Inspector với finding từ Script Analyzer / YARA rồi chấm điểm."""
    findings: list[Finding] = []
    for sr in rules.signal_rules:
        evidence = report.signals.get(sr.signal)
        if evidence:
            findings.append(Finding(sr.id, sr.title, sr.severity, sr.points, sr.description, evidence[:MAX_EVIDENCE]))
    findings.extend(extra_findings)

    findings.sort(key=lambda f: f.points, reverse=True)
    score = max(0, min(100, sum(f.points for f in findings)))
    level = _level_for(score, rules.levels)

    return AnalysisResult(
        file=report.public_dict(),
        score=score,
        level=level["id"],
        verdict=level["label"],
        findings=findings,
        disclaimer=DISCLAIMER,
        rules_version=rules.version,
    )
