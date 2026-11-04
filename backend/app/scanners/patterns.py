"""Khớp mẫu regex theo dòng, dùng chung cho các Script Analyzer."""
from __future__ import annotations

import json
import re
from dataclasses import dataclass
from functools import lru_cache
from pathlib import Path

from ..core.models import Finding

MAX_LINES = 20000
MAX_EVIDENCE = 5
SNIPPET_LEN = 160


@dataclass(frozen=True)
class PatternRule:
    id: str
    title: str
    severity: str
    points: int
    description: str
    match: str  # "any" | "all"
    patterns: tuple[re.Pattern, ...]


def _snippet(line: str) -> str:
    s = line.strip()
    return s if len(s) <= SNIPPET_LEN else s[:SNIPPET_LEN] + "…"


@lru_cache(maxsize=32)
def load_pattern_rules(path: str) -> tuple[PatternRule, ...]:
    data = json.loads(Path(path).read_text(encoding="utf-8"))
    rules: list[PatternRule] = []
    for r in data["rules"]:
        if r["match"] not in ("any", "all"):
            raise ValueError(f"{r['id']}: match phải là 'any' hoặc 'all'")
        rules.append(
            PatternRule(
                id=r["id"], title=r["title"], severity=r["severity"], points=int(r["points"]),
                description=r["description"], match=r["match"],
                patterns=tuple(re.compile(p) for p in r["patterns"]),
            )
        )
    return tuple(rules)


def match_rule(rule: PatternRule, lines: list[str]) -> list[str] | None:
    """Trả về danh sách bằng chứng 'L<dòng>: <đoạn trích>' hoặc None nếu không khớp."""
    evidence: list[str] = []
    for pat in rule.patterns:
        hit = None
        for i, line in enumerate(lines, 1):
            if pat.search(line):
                hit = f"L{i}: {_snippet(line)}"
                break
        if hit is None:
            if rule.match == "all":
                return None
            continue
        evidence.append(hit)
    if not evidence:
        return None
    return list(dict.fromkeys(evidence))[:MAX_EVIDENCE]


def evaluate_patterns(rules: tuple[PatternRule, ...], lines: list[str]) -> list[Finding]:
    findings: list[Finding] = []
    for rule in rules:
        evidence = match_rule(rule, lines[:MAX_LINES])
        if evidence:
            findings.append(Finding(rule.id, rule.title, rule.severity, rule.points, rule.description, evidence))
    return findings
