import re

from .base import ScriptAnalyzer, blank_line_comments


class PythonAnalyzer(ScriptAnalyzer):
    language = "python"
    display_name = "Python"
    extensions = frozenset({".py", ".pyw"})
    rules_file = "python.json"
    sniff_patterns = (
        re.compile(r"(?m)^\s*(import|from)\s+[\w.]+"),
        re.compile(r"(?m)^\s*def\s+\w+\s*\("),
        re.compile(r"__name__\s*==\s*['\"]__main__['\"]"),
        re.compile(r"(?m)^\s*print\s*\("),
        re.compile(r"^#!.*\bpython", re.M),
    )

    def strip_comments(self, text: str) -> str:
        return blank_line_comments(text, r"^\s*#")
