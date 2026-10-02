#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

SOURCE="build/test_01_clean"
PROTECTED_DIR="build/protected"
EVIDENCE_DIR="build/protection"

mkdir -p "$PROTECTED_DIR" "$EVIDENCE_DIR"

profiles=(
    "strip-unneeded"
    "strip-debug"
)

echo "=============================================="
echo "VULNHGNN 2.0 — PROTECTION REGRESSION"
echo "=============================================="

for profile in "${profiles[@]}"; do
    output="$PROTECTED_DIR/test_01_clean_${profile}"
    evidence="$EVIDENCE_DIR/test_01_clean.${profile}.protection.json"

    rm -f "$output" "$evidence"

    echo
    echo "[PROTECT] profile=$profile"

    ./securecc protect \
        "$SOURCE" \
        -o "$output" \
        --profile "$profile" \
        --format json \
        > "/tmp/securecc_protect_${profile}.json"

    python - "$profile" "$output" "$evidence" <<'PY'
import json
import sys
from pathlib import Path

profile = sys.argv[1]
output = Path(sys.argv[2])
evidence = Path(sys.argv[3])

with open(f"/tmp/securecc_protect_{profile}.json") as f:
    result = json.load(f)

assert result["schema_version"] == 1
assert result["status"] == "PROTECTED"

assert result["profile"]["name"] == profile
assert result["profile"]["operation"] == profile

assert result["returncode"] == 0

assert result["before"]["elf"] is True
assert result["after"]["elf"] is True
assert result["after"]["passed"] is True
assert result["hardening_preserved"] is True

behavior = result["behavior"]

assert behavior["verified"] is True
assert behavior["preserved"] is True
assert behavior["exit_code_match"] is True
assert behavior["stdout_match"] is True
assert behavior["stderr_match"] is True

assert output.exists()
assert output.stat().st_size > 0

assert evidence.exists()

with evidence.open() as f:
    report = json.load(f)

assert report["evidence_version"] == 1
assert report["evidence_format"] == "vulnhgnn-protection-evidence"

assert len(report["source_sha256"]) == 64
assert len(report["output_sha256"]) == 64

assert report["profile"]["name"] == profile
assert report["operation"] == profile

assert report["security"]["hardening_preserved"] is True

assert report["behavior"]["verified"] is True
assert report["behavior"]["preserved"] is True

assert report["status"] == "PROTECTED"

assert report["measurement"]["size_before"] > 0
assert report["measurement"]["size_after"] > 0

print(f"  transformation : PASS")
print(f"  hardening      : PASS")
print(f"  behavior       : PASS")
print(f"  evidence       : PASS")
print(f"  profile        : {profile}")
print(f"  size before    : {report['measurement']['size_before']}")
print(f"  size after     : {report['measurement']['size_after']}")
print(
    f"  reduction      : "
    f"{report['measurement']['size_reduction_percent']:.2f}%"
)
PY

    echo "[PASS] $profile"
done

echo
echo "=============================================="
echo "PROTECTION REGRESSION PASS"
echo "Profiles verified : ${#profiles[@]}/${#profiles[@]}"
echo "=============================================="
