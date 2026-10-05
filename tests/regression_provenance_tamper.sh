#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

SOURCE="test_files/test_01_clean.c"
BINARY="build/test_01_clean"
MANIFEST="build/test_01_clean.securecc.json"

BACKUP_BINARY="/tmp/vulnhgnn_tamper_binary_backup"
BACKUP_SOURCE="/tmp/vulnhgnn_tamper_source_backup"

cleanup() {
    if [[ -f "$BACKUP_BINARY" ]]; then
        cp "$BACKUP_BINARY" "$BINARY"
        rm -f "$BACKUP_BINARY"
    fi

    if [[ -f "$BACKUP_SOURCE" ]]; then
        cp "$BACKUP_SOURCE" "$SOURCE"
        rm -f "$BACKUP_SOURCE"
    fi
}

trap cleanup EXIT

echo "============================================================"
echo "VULNHGNN 2.0 — PROVENANCE TAMPER REGRESSION"
echo "============================================================"

echo "[1/7] Create verified secure build"

./securecc build --secure "$SOURCE" >/tmp/securecc_tamper_build.log

grep -q "FINAL STATUS : SECURE_BUILD_VERIFIED" \
    /tmp/securecc_tamper_build.log

test -f "$BINARY"
test -f "$MANIFEST"

echo "      PASS"

echo "[2/7] Verify original binary"

set +e
./securecc verify "$BINARY" --expect $'Result: 1\nPointer value: 100\n' \
    >/tmp/securecc_tamper_original.log 2>&1
ORIGINAL_EXIT=$?
set -e

if [[ "$ORIGINAL_EXIT" -ne 0 ]]; then
    cat /tmp/securecc_tamper_original.log
    echo "      FAIL: original binary did not verify"
    exit 1
fi

grep -q "Binary hash.*PASS" \
    /tmp/securecc_tamper_original.log

grep -q "Source hash.*PASS" \
    /tmp/securecc_tamper_original.log

echo "      PASS"

echo "[3/7] Tamper with binary"

cp "$BINARY" "$BACKUP_BINARY"

python - "$BINARY" <<'PY'
from pathlib import Path
import sys

path = Path(sys.argv[1])

data = bytearray(path.read_bytes())

if not data:
    raise SystemExit("binary is empty")

data[-1] ^= 0x01

path.write_bytes(data)
PY

set +e
./securecc verify "$BINARY" --expect $'Result: 1\nPointer value: 100\n' \
    >/tmp/securecc_tamper_binary.log 2>&1
BINARY_EXIT=$?
set -e

if [[ "$BINARY_EXIT" -eq 0 ]]; then
    cat /tmp/securecc_tamper_binary.log
    echo "      FAIL: tampered binary was accepted"
    exit 1
fi

grep -qiE \
    "binary integrity|binary hash does not match|hash.*FAIL" \
    /tmp/securecc_tamper_binary.log

echo "      PASS — tampered binary rejected"

cleanup

echo "[4/7] Restore and re-verify binary"

set +e
./securecc verify "$BINARY" --expect $'Result: 1\nPointer value: 100\n' \
    >/tmp/securecc_tamper_restore.log 2>&1
RESTORE_EXIT=$?
set -e

if [[ "$RESTORE_EXIT" -ne 0 ]]; then
    cat /tmp/securecc_tamper_restore.log
    echo "      FAIL: restored binary did not verify"
    exit 1
fi

echo "      PASS"

echo "[5/7] Tamper with source"

cp "$SOURCE" "$BACKUP_SOURCE"

printf '\n/* provenance tamper regression */\n' >> "$SOURCE"

set +e
./securecc verify "$BINARY" --expect $'Result: 1\nPointer value: 100\n' \
    >/tmp/securecc_tamper_source.log 2>&1
SOURCE_EXIT=$?
set -e

if [[ "$SOURCE_EXIT" -eq 0 ]]; then
    cat /tmp/securecc_tamper_source.log
    echo "      FAIL: tampered source was accepted"
    exit 1
fi

grep -qiE \
    "source integrity|source hash|hash.*FAIL" \
    /tmp/securecc_tamper_source.log

echo "      PASS — tampered source rejected"

cleanup

echo "[6/7] Restore and re-verify source"

set +e
./securecc verify "$BINARY" --expect $'Result: 1\nPointer value: 100\n' \
    >/tmp/securecc_tamper_final.log 2>&1
FINAL_EXIT=$?
set -e

if [[ "$FINAL_EXIT" -ne 0 ]]; then
    cat /tmp/securecc_tamper_final.log
    echo "      FAIL: restored artifacts did not verify"
    exit 1
fi

echo "      PASS"

echo "[7/7] Confirm project verification remains intact"

./tests/regression_project_verify.sh \
    >/tmp/securecc_tamper_project.log 2>&1

grep -q "Fixtures verified : 10/10" \
    /tmp/securecc_tamper_project.log

grep -q "Findings verified  : 18" \
    /tmp/securecc_tamper_project.log

grep -q "FINAL STATUS : PROJECT_VERIFY_VERIFIED" \
    /tmp/securecc_tamper_project.log

echo "      PASS"

echo
echo "============================================================"
echo "PROVENANCE TAMPER REGRESSION PASS"
echo "Original binary       : VERIFIED"
echo "Binary tampering      : REJECTED"
echo "Source tampering      : REJECTED"
echo "Artifacts restored    : VERIFIED"
echo "Project verification  : 10/10"
echo "============================================================"
