#!/usr/bin/env python3
"""Run the AAI security attack suite (PBL demo)."""

from __future__ import annotations

import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent


def main() -> int:
    from src.V2.securecc.aai_security.runner import print_text_report, run_attack_suite

    report = run_attack_suite(project_root=ROOT)
    print(print_text_report(report))
    if "--json" in sys.argv:
        print(json.dumps(report, indent=2))
    return 0 if report["metrics"]["attack_success_rate_asr"] == 0.0 else 2


if __name__ == "__main__":
    raise SystemExit(main())
