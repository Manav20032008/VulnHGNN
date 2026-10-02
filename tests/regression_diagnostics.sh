#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

echo "=============================================="
echo "VULNHGNN 2.0 — DIAGNOSTICS REGRESSION"
echo "=============================================="

TMP_JSON="$(mktemp)"
trap 'rm -f "$TMP_JSON"' EXIT

./securecc diagnose \
    test_files/test_02_cwe190.c \
    --format json > "$TMP_JSON"

python - "$TMP_JSON" <<'PY'
import json
import sys

path = sys.argv[1]
data = json.load(open(path, encoding="utf-8"))

assert data["format"] == "vulnhgnn-diagnostics"
assert data["schema_version"] == 1
assert data["finding_count"] == 1
assert data["status"] == "FINDINGS_PRESENT"

item = data["diagnostics"][0]

assert item["cwe_id"] == "CWE-190"
assert item["function"]
assert item["block"]
assert item["node_id"]
assert item["root_cause"]
assert item["security_impact"]
assert item["repair_strategy"]
assert item["verification"]
assert item["evidence"]

print("  schema             : PASS")
print("  CWE-190 diagnostic : PASS")
print("  evidence           : PASS")
print("  repair             : PASS")
print("  verification       : PASS")
PY

test -f build/evidence/test_02_cwe190.diagnostics.json

echo "  artifact            : PASS"
echo
echo "DIAGNOSTICS REGRESSION PASS"
