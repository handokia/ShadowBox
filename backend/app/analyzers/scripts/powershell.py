import re

from .base import ScriptAnalyzer, blank_blocks, blank_line_comments

# Cmdlet dạng Verb-Noun viết hoa đúng chuẩn PowerShell. Hai cmdlet khác nhau trở lên mới đáng tin.
_CMDLET = re.compile(r"\b(?:Set|Get|New|Invoke|Add|Start|Remove|Import|Out|Write)-[A-Z][A-Za-z]+")


class PowerShellAnalyzer(ScriptAnalyzer):
    language = "powershell"
    display_name = "PowerShell"
    extensions = frozenset({".ps1", ".psm1", ".psd1"})
    rules_file = "powershell.json"
    sniff_patterns = (
        re.compile(r"(?m)^\s*\$[A-Za-z_]\w*\s*="),
        re.compile(r"(?i)\bparam\s*\("),
        re.compile(r"(?i)\[System\.[A-Za-z.]+\]"),
        re.compile(r"(?i)^#!.*\bpwsh\b", re.M),
    )

    def sniff_score(self, text: str) -> int:
        cmdlets = set(_CMDLET.findall(text[:200_000]))
        cmdlet_score = 2 if len(cmdlets) >= 2 else len(cmdlets)
        return cmdlet_score + super().sniff_score(text)

    def strip_comments(self, text: str) -> str:
        text = blank_blocks(text, r"<#.*?#>")
        return blank_line_comments(text, r"^\s*#")
