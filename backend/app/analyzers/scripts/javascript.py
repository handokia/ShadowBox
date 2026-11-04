import re

from .base import ScriptAnalyzer, blank_blocks, blank_line_comments


class JavaScriptAnalyzer(ScriptAnalyzer):
    """JS cho Node, trình duyệt và Windows Script Host (.js, .jse, .hta, .wsf)."""

    language = "javascript"
    display_name = "JavaScript"
    extensions = frozenset({".js", ".jse", ".mjs", ".cjs", ".hta", ".wsf"})
    rules_file = "javascript.json"
    sniff_patterns = (
        re.compile(r"\b(function|const|let|var)\s+[A-Za-z_$][\w$]*"),
        re.compile(r"=>"),
        re.compile(r"\brequire\s*\("),
        re.compile(r"\bconsole\.(log|error)\s*\("),
        re.compile(r"(?i)\bWScript\.|\bActiveXObject\b"),
        re.compile(r"^#!.*\bnode\b", re.M),
    )

    def strip_comments(self, text: str) -> str:
        text = blank_blocks(text, r"/\*.*?\*/")
        return blank_line_comments(text, r"^\s*//")
