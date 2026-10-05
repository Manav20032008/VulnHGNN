#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

echo "============================================================"
echo "VULNHGNN 2.0 — PROVENANCE REGRESSION TEST"
echo "============================================================"

SOURCE="test_files/test_01_clean.c"
BINARY="build/test_01_clean"
MANIFEST="build/test_01_clean.securecc.json"

echo "[1/5] Secure build"

./securecc build --secure "$SOURCE" >/tmp/securecc_provenance_build.log

grep -q "FINAL STATUS : SECURE_BUILD_VERIFIED" \
    /tmp/securecc_provenance_build.log

echo "      PASS"

echo "[2/5] Manifest schema"

python - "$MANIFEST" <<'PY'
import json
import sys
from pathlib import Path

manifest_path = Path(sys.argv[1])
data = json.loads(manifest_path.read_text())

assert data["manifest_version"] == 2
assert data["manifest_format"] == "securecc-provenance"

assert data["binary"]
assert data["binary_sha256"]

assert data["source"]
assert data["source_sha256"]

assert data["compiler"]
assert data["compiler_command"]

assert data["environment"]
assert data["environment"]["system"]
assert data["environment"]["machine"]
assert data["environment"]["python_version"]

assert data["security_analysis"]["passed"] is True
assert data["hardening"]["passed"] is True
assert data["build"]["passed"] is True

assert data["verification"]["required"] is True
assert data["verification"]["status"] == "SECURE_BUILD_VERIFIED"

print("      PASS")
PY

echo "[3/5] Binary integrity"

python - "$BINARY" "$MANIFEST" <<'PY'
import hashlib
import json
import sys
from pathlib import Path

binary = Path(sys.argv[1])
manifest = Path(sys.argv[2])

expected = json.loads(manifest.read_text())["binary_sha256"]

digest = hashlib.sha256()

with binary.open("rb") as handle:
    while chunk := handle.read(1024 * 1024):
        digest.update(chunk)

actual = digest.hexdigest()

assert actual == expected, (
    f"binary hash mismatch: expected {expected}, got {actual}"
)

print("      PASS")
PY

echo "[4/5] Source integrity"

python - "$SOURCE" "$MANIFEST" <<'PY'
import hashlib
import json
import sys
from pathlib import Path

source = Path(sys.argv[1])
manifest = Path(sys.argv[2])

expected = json.loads(manifest.read_text())["source_sha256"]

digest = hashlib.sha256()

with source.open("rb") as handle:
    while chunk := handle.read(1024 * 1024):
        digest.update(chunk)

actual = digest.hexdigest()

assert actual == expected, (
    f"source hash mismatch: expected {expected}, got {actual}"
)

print("      PASS")
PY

echo "[5/5] Provenance API"

python - "$BINARY" <<'PY'
import sys
from pathlib import Path

from src.V2.securecc.provenance import (
    read_manifest,
    validate_manifest,
)

binary = Path(sys.argv[1])

manifest = read_manifest(binary)
result = validate_manifest(manifest)

assert result["valid"] is True
assert result["manifest_version"] == 2
assert result["supported_version"] is True
assert result["missing_fields"] == []

print("      PASS")
PY

echo
echo "============================================================"
echo "PROVENANCE REGRESSION PASS"
echo "Manifest version : 2"
echo "Binary integrity  : PASS"
echo "Source integrity  : PASS"
echo "Schema validation : PASS"
echo "============================================================"
