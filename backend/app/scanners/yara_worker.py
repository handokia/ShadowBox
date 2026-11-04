"""Worker chạy YARA-X trong process riêng: python -m app.scanners.yara_worker <file> <rules_dir>

Process cha áp timeout và môi trường tối thiểu. Worker chỉ in đúng một dòng JSON ra stdout.
Chạy `python -m app.scanners.yara_worker --selftest` để kiểm tra yara-x đã cài đúng.
"""
from __future__ import annotations

import json
import re
import sys
from pathlib import Path

_RULE_DEF = re.compile(r"(?m)^\s*(?:(?:private|global)\s+)*rule\s+[A-Za-z_]\w*")
MAX_MATCHES_PER_PATTERN = 5


def _limit_memory() -> None:
    try:  # chỉ có trên Linux/macOS; Windows bỏ qua
        import resource

        limit = 1024 * 1024 * 1024
        resource.setrlimit(resource.RLIMIT_AS, (limit, limit))
    except Exception:
        pass


def _emit(obj: dict) -> int:
    sys.stdout.write(json.dumps(obj, ensure_ascii=False, default=str))
    sys.stdout.flush()
    return 0


def _to_meta(raw) -> dict:
    try:
        return {str(k): v for k, v in raw}
    except Exception:
        try:
            return dict(raw)
        except Exception:
            return {}


def scan(path: str, rules_dir: str) -> dict:
    try:
        import yara_x
    except ImportError:
        return {"ok": False, "error": "yara_x_not_installed"}

    sources: list[tuple[str, str]] = []
    errors: list[str] = []
    files = sorted(list(Path(rules_dir).glob("*.yar")) + list(Path(rules_dir).glob("*.yara")))
    for f in files:
        try:
            src = f.read_text(encoding="utf-8")
            yara_x.compile(src)  # kiểm tra riêng từng file để một file lỗi không làm hỏng cả bộ
            sources.append((f.name, src))
        except Exception as e:  # noqa: BLE001
            errors.append(f"{f.name}: {e}")

    rules_loaded = sum(len(_RULE_DEF.findall(src)) for _, src in sources)
    if not sources:
        return {"ok": True, "rules_loaded": 0, "errors": errors, "matches": []}

    compiler = yara_x.Compiler()
    for name, src in sources:
        compiler.add_source(src, origin=name)
    rules = compiler.build()
    scanner = yara_x.Scanner(rules)
    results = scanner.scan_file(path) if hasattr(scanner, "scan_file") else scanner.scan(Path(path).read_bytes())

    matches = []
    for r in results.matching_rules:
        patterns = []
        for p in r.patterns:
            ms = [{"offset": m.offset, "length": m.length} for m in list(p.matches)[:MAX_MATCHES_PER_PATTERN]]
            if ms:
                patterns.append({"id": p.identifier, "matches": ms})
        matches.append(
            {
                "identifier": r.identifier,
                "tags": list(getattr(r, "tags", []) or []),
                "meta": _to_meta(getattr(r, "metadata", ())),
                "patterns": patterns,
            }
        )
    return {"ok": True, "rules_loaded": rules_loaded, "errors": errors, "matches": matches}


def selftest() -> int:
    try:
        import yara_x
    except ImportError:
        print("yara_x chưa được cài. Chạy: pip install yara-x")
        return 1
    rules = yara_x.compile('rule t { meta: severity = "high" strings: $a = "abc" condition: $a }')
    res = yara_x.Scanner(rules).scan(b"xxabcxx")
    r = res.matching_rules[0]
    p = list(r.patterns)[0]
    m = list(p.matches)[0]
    print("OK", r.identifier, dict(_to_meta(r.metadata)), p.identifier, m.offset, m.length)
    return 0


def main(argv: list[str]) -> int:
    if len(argv) == 2 and argv[1] == "--selftest":
        return selftest()
    if len(argv) != 3:
        return _emit({"ok": False, "error": "usage: yara_worker <file> <rules_dir>"})
    _limit_memory()
    try:
        return _emit(scan(argv[1], argv[2]))
    except Exception as e:  # noqa: BLE001
        return _emit({"ok": False, "error": f"{type(e).__name__}: {e}"})


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
