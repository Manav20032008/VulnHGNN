#!/usr/bin/env bash
set -uo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

echo "================================================================================"
echo "VULNHGNN 2.0 — FULL REGRESSION"
echo "================================================================================"
echo

TESTS=(
    tests/regression_cli.sh
    tests/regression_artifacts.sh
    tests/regression_policy.sh
    tests/regression_project_verify.sh
    tests/regression_provenance.sh
    tests/regression_provenance_tamper.sh
    tests/regression_evidence.sh
    tests/regression_diagnostics.sh
    tests/regression_protection.sh
    tests/regression_measurement.sh
    tests/regression_packaging.sh
)

TOTAL=${#TESTS[@]}
PASSED=0
FAILED=0

for test_script in "${TESTS[@]}"; do
    echo
    echo "--------------------------------------------------------------------------------"
    echo "RUNNING : $test_script"
    echo "--------------------------------------------------------------------------------"

    if "$ROOT/$test_script"; then
        echo "RESULT  : PASS"
        PASSED=$((PASSED + 1))
    else
        echo "RESULT  : FAIL"
        FAILED=$((FAILED + 1))
    fi
done

echo
echo "================================================================================"
echo "FULL REGRESSION SUMMARY"
echo "================================================================================"
echo
echo "Total tests : $TOTAL"
echo "Passed      : $PASSED"
echo "Failed      : $FAILED"
echo

if [ "$FAILED" -ne 0 ]; then
    echo "FINAL STATUS : REGRESSION_FAILED"
    exit 1
fi

echo "FINAL STATUS : VULNHGNN_2.0_REGRESSION_VERIFIED"
echo "================================================================================"
