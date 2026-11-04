"""Tích hợp YARA-X: chạy worker trong process con có timeout, rồi đổi kết quả thành Finding."""
from __future__ import annotations

import json
import os
import subprocess
import sys
from dataclasses import dataclass, field
from pathlib import Path

from ..core.config import settings
from ..core.models import Finding

BACKEND_DIR = Path(__file__).resolve().parents[2]
_ALLOWED_SEVERITY = {"low", "medium", "high"}
_MAX_OUTPUT = 2_000_000
_ENV_KEYS = ("SYSTEMROOT", "PATH", "TEMP", "TMP", "TMPDIR")


@dataclass
class YaraOutcome:
    findings: list[Finding] = field(default_factory=list)
    info: dict = field(default_factory=dict)


def findings_from_matches(matches: list[dict]) -> list[Finding]:
    findings: list[Finding] = []
    for m in matches:
        meta = m.get("meta") or {}
        severity = str(meta.get("severity", "medium")).lower()
        if severity not in _ALLOWED_SEVERITY:
            severity = "medium"
        try:
            points = max(0, min(50, int(meta.get("points", 10))))
        except (TypeError, ValueError):
            points = 10
        evidence: list[str] = []
        for p in m.get("patterns", []):
            for hit in p.get("matches", []):
                evidence.append(f"{p['id']} tại offset 0x{int(hit['offset']):x} ({int(hit['length'])} byte)")
        if not evidence:
            evidence = ["Điều kiện luật YARA khớp (không gắn với chuỗi cụ thể)"]
        findings.append(
            Finding(
                rule_id=f"YARA:{m['identifier']}",
                title=str(meta.get("title", m["identifier"])),
                severity=severity,
                points=points,
                description=str(meta.get("description", f"Khớp luật YARA {m['identifier']}.")),
                evidence=evidence[:5],
            )
        )
    return findings


def scan_file(path: str | os.PathLike, size: int) -> YaraOutcome:
    info: dict = {"engine": "yara-x", "status": "ok"}
    if size > settings.yara_max_bytes:
        info["status"] = "skipped_too_large"
        return YaraOutcome(info=info)

    env = {k: os.environ[k] for k in _ENV_KEYS if k in os.environ}
    env.update({"PYTHONIOENCODING": "utf-8", "PYTHONDONTWRITEBYTECODE": "1"})
    cmd = [sys.executable, "-m", "app.scanners.yara_worker", str(path), str(settings.yara_rules_dir)]
    try:
        proc = subprocess.run(
            cmd, capture_output=True, timeout=settings.yara_timeout_s, cwd=BACKEND_DIR, env=env, check=False
        )
    except subprocess.TimeoutExpired:
        info["status"] = "timeout"
        return YaraOutcome(info=info)
    except OSError as e:
        info.update(status="error", error=str(e))
        return YaraOutcome(info=info)

    try:
        data = json.loads(proc.stdout[:_MAX_OUTPUT].decode("utf-8", errors="replace"))
    except json.JSONDecodeError:
        stderr = proc.stderr[:300].decode("utf-8", "replace") if proc.stderr else ""
        info.update(status="error", error=stderr or "worker không trả về JSON")
        return YaraOutcome(info=info)

    if not data.get("ok"):
        if data.get("error") == "yara_x_not_installed":
            info.update(status="unavailable", hint="pip install yara-x")
        else:
            info.update(status="error", error=str(data.get("error"))[:300])
        return YaraOutcome(info=info)

    info["rules_loaded"] = data.get("rules_loaded", 0)
    if data.get("errors"):
        info["rule_errors"] = data["errors"][:10]
    return YaraOutcome(findings=findings_from_matches(data.get("matches", [])), info=info)
