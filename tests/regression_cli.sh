#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

echo "VULNHGNN 2.0 CLI REGRESSION"
echo

echo "[1/4] Version"
VERSION_OUTPUT="$(securecc --version)"
echo "$VERSION_OUTPUT"
echo "$VERSION_OUTPUT" | grep -q "VulnHGNN 2.0 SecureCC 2.0.0"
echo "  PASS"

echo
echo "[2/4] Command surface"

COMMANDS=(
    build
    report
    scan
    fix
    verify
    explain
    diagnose
    harden
    protect
    learn
    benchmark
)

HELP_OUTPUT="$(securecc --help)"

for command in "${COMMANDS[@]}"; do
    echo "$HELP_OUTPUT" | grep -qE "(^|[,{])${command}([,}]|[[:space:]]+)" || {
        echo "  FAIL: missing command $command"
        exit 1
    }
done

echo "  Commands verified : ${#COMMANDS[@]}/11"
echo "  PASS"

echo
echo "[3/4] Compile"

rm -f build/regression_cli_test

securecc build \
    test_files/test_01_clean.c \
    -o build/regression_cli_test

test -x build/regression_cli_test

echo "  PASS"

echo
echo "[4/4] Existing pipeline benchmark"

BENCH_OUTPUT="$(securecc benchmark test_files/)"
echo "$BENCH_OUTPUT"

echo "$BENCH_OUTPUT" | grep -q "Stages passed.*6/6"
echo "$BENCH_OUTPUT" | grep -q "VULNHGNN_2.0_VERIFIED"

echo "  PASS"

echo
echo "CLI REGRESSION PASS"
