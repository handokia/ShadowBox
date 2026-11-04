"""Chạy thử không cần FastAPI: python -m app.cli <file>  (chạy từ thư mục backend/)"""
from __future__ import annotations

import argparse
import json
import sys

from .analyzers.inspector import InspectError
from .analyzers.service import analyze_path


def main() -> int:
    ap = argparse.ArgumentParser(prog="shadowbox", description="Phân tích tĩnh một file (không thực thi).")
    ap.add_argument("path")
    args = ap.parse_args()
    try:
        result = analyze_path(args.path)
    except (InspectError, OSError) as e:
        print(f"Lỗi: {e}", file=sys.stderr)
        return 1
    print(json.dumps(result.to_dict(), ensure_ascii=False, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
