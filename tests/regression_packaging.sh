#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

echo "VULNHGNN 2.0 PACKAGING REGRESSION"
echo

echo "[1/6] Installed command"
COMMAND_PATH="$(command -v securecc)"
test -n "$COMMAND_PATH"
echo "  securecc : $COMMAND_PATH"
echo "  PASS"

echo
echo "[2/6] Version"
VERSION_OUTPUT="$(securecc --version)"
echo "$VERSION_OUTPUT"
echo "$VERSION_OUTPUT" | grep -q "VulnHGNN 2.0 SecureCC 2.0.0"
echo "  PASS"

echo
echo "[3/6] CLI help"
HELP_OUTPUT="$(securecc --help)"
echo "$HELP_OUTPUT" | grep -q "scan"
echo "$HELP_OUTPUT" | grep -q "verify"
echo "$HELP_OUTPUT" | grep -q "diagnose"
echo "$HELP_OUTPUT" | grep -q "benchmark"
echo "  PASS"

echo
echo "[4/6] Installed scan"
SCAN_OUTPUT="$(securecc scan test_files/)"
echo "$SCAN_OUTPUT"
echo "$SCAN_OUTPUT" | grep -q "18"
echo "  PASS"

echo
echo "[5/6] Installed diagnostics"
DIAG_OUTPUT="$(securecc diagnose test_files/test_02_cwe190.c)"
echo "$DIAG_OUTPUT"
echo "$DIAG_OUTPUT" | grep -q "CWE-190"
echo "  PASS"

echo
echo "[6/6] Installed benchmark"
BENCH_OUTPUT="$(securecc benchmark test_files/)"
echo "$BENCH_OUTPUT"
echo "$BENCH_OUTPUT" | grep -q "Stages passed.*6/6"
echo "$BENCH_OUTPUT" | grep -q "VULNHGNN_2.0_VERIFIED"
echo "  PASS"

echo
echo "PACKAGING REGRESSION PASS"
