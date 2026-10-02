#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

echo "=============================================="
echo "VULNHGNN 2.0 — ARTIFACT REGRESSION"
echo "=============================================="

python - <<'PY'
from src.V2.securecc.artifacts import (
    ARTIFACT_SCHEMA_VERSION,
    get_artifact_layout,
)

assert ARTIFACT_SCHEMA_VERSION == 1

layout = get_artifact_layout()
layout.ensure()

expected = {
    "evidence": layout.evidence,
    "verification": layout.verification,
    "benchmark": layout.benchmark,
    "measurement": layout.measurement,
    "protection": layout.protection,
    "evaluation": layout.evaluation,
}

for name, path in expected.items():
    assert path.exists(), path
    assert path.is_dir(), path
    print(f"  {name:12} PASS")

print()
print("ARTIFACT REGRESSION PASS")
print("Directories :", len(expected), "/ 6")
PY
