import re

from .base import ScriptAnalyzer, blank_line_comments


class BatchAnalyzer(ScriptAnalyzer):
    language = "batch"
    display_name = "BAT / CMD"
    extensions = frozenset({".bat", ".cmd"})
    rules_file = "batch.json"
    sniff_patterns = (
        re.compile(r"(?im)^\s*@?echo\s+off\b"),
        re.compile(r"(?im)^\s*@?(set|goto|call|setlocal|endlocal)\b"),
        re.compile(r"%~?dp0|%~?[0-9fnx]+\b|%[A-Za-z_]\w*%"),
        re.compile(r"(?m)^\s*:[A-Za-z_]\w*\s*$"),
        re.compile(r"(?im)^\s*rem\b"),
    )

    def strip_comments(self, text: str) -> str:
        return blank_line_comments(text, r"(?i)^\s*(@?rem\b|::)")
