#!/usr/bin/env bash

set -u

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

echo "============================================================"
echo "VULNHGNN 2.0 — REGRESSION TEST"
echo "============================================================"

OUTPUT="$(./securecc verify test_files/ 2>&1)"
STATUS=$?

echo "$OUTPUT"
echo

if [ "$STATUS" -ne 0 ]; then
    echo "REGRESSION FAIL: securecc verify exited with code $STATUS"
    exit 1
fi

check() {
    local expected="$1"
    if ! grep -Fq "$expected" <<< "$OUTPUT"; then
        echo "REGRESSION FAIL: missing:"
        echo "  $expected"
        exit 1
    fi
}

check "Files scanned  : 10"
check "Files verified : 10"
check "Files unverified: 0"
check "Files failed   : 0"
check "Findings       : 18"

for file in \
    test_01_clean.c \
    test_02_cwe190.c \
    test_03_cwe191.c \
    test_04_cwe369.c \
    test_05_cwe476.c \
    test_06_dual_190_191.c \
    test_07_dual_369_476.c \
    test_08_triple_190_191_369.c \
    test_09_triple_191_369_476.c \
    test_10_all_vulnerabilities.c
do
    if ! grep -Fq "$file" <<< "$OUTPUT"; then
        echo "REGRESSION FAIL: fixture missing from verification output: $file"
        exit 1
    fi

    line="$(grep -F "$file" <<< "$OUTPUT")"

    if ! grep -Fq "PROJECT_VERIFY_VERIFIED" <<< "$line"; then
        echo "REGRESSION FAIL: fixture not verified: $file"
        echo "$line"
        exit 1
    fi
done

if ! grep -Fq "FINAL STATUS : PROJECT_VERIFY_VERIFIED" <<< "$OUTPUT"; then
    echo "REGRESSION FAIL: final project status is not VERIFIED"
    exit 1
fi

echo "============================================================"
echo "REGRESSION PASS"
echo "============================================================"
echo "Fixtures verified : 10/10"
echo "Findings verified  : 18"
echo "Final status       : PROJECT_VERIFY_VERIFIED"
echo "============================================================"
