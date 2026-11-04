"""Nền tảng chung cho Script Analyzer. Chỉ phân tích tĩnh văn bản, không bao giờ thực thi."""
from __future__ import annotations

import re
from pathlib import Path

from ...core.config import settings
from ...core.models import Finding
from ...scanners.patterns import MAX_LINES, evaluate_patterns, load_pattern_rules

_SNIFF_WINDOW = 200_000


def blank_blocks(text: str, pattern: str) -> str:
    """Thay các khối comment bằng dòng trống, giữ nguyên số dòng để bằng chứng đúng số."""
    return re.sub(pattern, lambda m: "\n" * m.group().count("\n"), text, flags=re.S)


def blank_line_comments(text: str, prefix_regex: str) -> str:
    """Xóa các dòng chỉ chứa comment (không đụng tới comment cuối dòng để tránh cắt nhầm chuỗi)."""
    rx = re.compile(prefix_regex)
    return "\n".join("" if rx.match(line) else line for line in text.split("\n"))


class ScriptAnalyzer:
    language: str = ""
    display_name: str = ""
    extensions: frozenset[str] = frozenset()
    rules_file: str = ""
    sniff_patterns: tuple[re.Pattern, ...] = ()

    def strip_comments(self, text: str) -> str:
        return text

    def sniff_score(self, text: str) -> int:
        window = text[:_SNIFF_WINDOW]
        return sum(1 for p in self.sniff_patterns if p.search(window))

    def rules_path(self) -> Path:
        return settings.script_rules_dir / self.rules_file

    def analyze(self, text: str) -> list[Finding]:
        lines = self.strip_comments(text).splitlines()[:MAX_LINES]
        return evaluate_patterns(load_pattern_rules(str(self.rules_path())), lines)
