#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

echo "=============================================="
echo "VULNHGNN 2.0 — POLICY REGRESSION"
echo "=============================================="

python - <<'PY'
from pathlib import Path

from src.V2.hardening.audit import audit_binary
from src.V2.securecc.policy import (
    DEFAULT_POLICY,
    evaluate_hardening,
    evaluate_verification,
)
from src.V2.securecc.verify import verify_binary

binary = Path("build/test_01_clean")

assert binary.exists(), binary

audit = audit_binary(binary)

hardening = evaluate_hardening(
    audit,
    DEFAULT_POLICY,
)

assert hardening["passed"] is True
assert hardening["failures"] == []

verification = verify_binary(
    binary,
    expected_output=(
        "Result: 1\n"
        "Pointer value: 100\n"
    ),
)

verification_policy = evaluate_verification(
    verification,
    DEFAULT_POLICY,
)

assert verification_policy["passed"] is True
assert verification_policy["failures"] == []

print("  hardening policy     : PASS")
print("  verification policy : PASS")
print("  required hardening   : 7/7")
print("  required verification: 4/4")

print()
print("POLICY REGRESSION PASS")
PY
