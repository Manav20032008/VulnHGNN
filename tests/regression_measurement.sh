#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

SOURCE="build/test_01_clean"
OUTPUT_DIR="build/measurement/test_01_clean"
REPORT="build/measurement/test_01_clean.measurement.json"

echo "=============================================="
echo "VULNHGNN 2.0 — MEASUREMENT REGRESSION"
echo "=============================================="

rm -rf "$OUTPUT_DIR"
rm -f "$REPORT"

echo
echo "[1/3] Runtime measurement"

python - <<'PY'
from pathlib import Path

from src.V2.securecc.measurement import (
    measure_protection,
    save_measurement,
)

source = Path("build/test_01_clean")
output = Path("build/measurement/test_01_clean")

report = measure_protection(source, output)

save_measurement(
    report,
    Path("build/measurement/test_01_clean.measurement.json"),
)

assert report["status"] == "MEASUREMENT_VERIFIED"
assert report["runtime_runs_per_binary"] == 10

print("  measurement : PASS")
print("  profiles    :", len(report["profiles"]))
print("  runs        :", report["runtime_runs_per_binary"])
PY

echo
echo "[2/3] Schema validation"

python - <<'PY'
import json
from pathlib import Path

path = Path(
    "build/measurement/test_01_clean.measurement.json"
)

assert path.exists()

with path.open() as f:
    report = json.load(f)

assert report["measurement_schema_version"] == 2
assert report["measurement_format"] == (
    "vulnhgnn-protection-measurement"
)

assert report["status"] == "MEASUREMENT_VERIFIED"

assert report["summary"]["profiles_total"] == 2
assert report["summary"]["profiles_passed"] == 2
assert report["summary"]["behavior_preserved"] is True
assert report["summary"]["hardening_preserved"] is True
assert report["summary"][
    "runtime_measurements_completed"
] is True

for item in report["profiles"]:
    assert item["status"] == "PROTECTED"
    assert item["behavior_preserved"] is True
    assert item["hardening_preserved"] is True

    baseline = item["baseline_runtime"]
    protected = item["protected_runtime"]

    assert baseline["statistics"]["runs"] == 10
    assert protected["statistics"]["runs"] == 10

    for stats in (
        baseline["statistics"],
        protected["statistics"],
    ):
        assert stats["minimum_seconds"] > 0
        assert stats["median_seconds"] > 0
        assert stats["mean_seconds"] > 0
        assert stats["maximum_seconds"] > 0
        assert stats["stddev_seconds"] >= 0

    assert item["runtime_delta_seconds"] is not None
    assert item["runtime_delta_percent"] is not None

print("  schema       : PASS")
print("  profiles     : 2/2")
print("  runtime runs : 10/10 per binary")
PY

echo
echo "[3/3] Measurement report"

python - <<'PY'
import json

with open(
    "build/measurement/test_01_clean.measurement.json"
) as f:
    report = json.load(f)

for item in report["profiles"]:
    baseline = item["baseline_runtime"]["statistics"]
    protected = item["protected_runtime"]["statistics"]

    print()
    print("  PROFILE :", item["profile"])
    print(
        "    size reduction :",
        f"{item['size']['reduction_percent']:.2f}%",
    )
    print(
        "    baseline median:",
        f"{baseline['median_seconds']:.6f}s",
    )
    print(
        "    protected median:",
        f"{protected['median_seconds']:.6f}s",
    )
    print(
        "    runtime delta  :",
        f"{item['runtime_delta_percent']:.2f}%",
    )
    print(
        "    behavior       :",
        "PASS" if item["behavior_preserved"] else "FAIL",
    )
    print(
        "    hardening      :",
        "PASS" if item["hardening_preserved"] else "FAIL",
    )

print()
print("MEASUREMENT REGRESSION PASS")
print("Report :", "build/measurement/test_01_clean.measurement.json")
PY

echo
echo "=============================================="
echo "PHASE 11.4 PASS"
echo "=============================================="
