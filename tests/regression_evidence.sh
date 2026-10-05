#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

echo "============================================================"
echo "VULNHGNN 2.0 — EVIDENCE REGRESSION"
echo "============================================================"

rm -f build/evidence/*.evidence.json

files=(
  test_01_clean.c
  test_02_cwe190.c
  test_03_cwe191.c
  test_04_cwe369.c
  test_05_cwe476.c
  test_06_dual_190_191.c
  test_07_dual_369_476.c
  test_08_triple_190_191_369.c
  test_09_triple_191_369_476.c
  test_10_all_vulnerabilities.c
)

expected_findings=(0 1 1 1 1 2 2 3 3 4)

for i in "${!files[@]}"; do
    file="${files[$i]}"
    expected="${expected_findings[$i]}"

    echo "[EXPLAIN] $file"

    ./securecc explain "test_files/$file" --format json \
        > "/tmp/securecc_evidence_$i.json"

    python - "$i" "$file" "$expected" <<'PY'
import json
import sys
from pathlib import Path

index = sys.argv[1]
filename = sys.argv[2]
expected = int(sys.argv[3])

with open(f"/tmp/securecc_evidence_{index}.json") as f:
    result = json.load(f)

report = result["evidence_report"]

assert report["report_version"] == 1
assert report["report_format"] == "vulnhgnn-evidence"
assert report["finding_count"] == expected

artifact = Path(result["evidence_artifact"])
assert artifact.exists(), f"missing artifact: {artifact}"

saved = json.loads(artifact.read_text())

assert saved["report_version"] == 1
assert saved["report_format"] == "vulnhgnn-evidence"
assert saved["finding_count"] == expected
assert saved["source_sha256"]

if expected > 0:
    assert len(saved["evidence"]) > 0
    assert len(saved["explanations"]) > 0
else:
    assert saved["evidence"] == []
    assert saved["explanations"] == []

print(
    f"      PASS — findings={expected}, "
    f"evidence={len(saved['evidence'])}"
)
PY
done

count="$(find build/evidence -maxdepth 1 -name '*.evidence.json' | wc -l)"

if [[ "$count" -ne 10 ]]; then
    echo "FAIL: expected 10 evidence artifacts, found $count"
    exit 1
fi

echo
echo "Checking JSON artifact integrity..."

python - <<'PY'
import json
from pathlib import Path

files = sorted(Path("build/evidence").glob("*.evidence.json"))

assert len(files) == 10

for path in files:
    data = json.loads(path.read_text())

    assert data["report_version"] == 1
    assert data["report_format"] == "vulnhgnn-evidence"
    assert data["source_sha256"]
    assert isinstance(data["evidence"], list)
    assert isinstance(data["explanations"], list)

print(f"JSON ARTIFACTS PASS — {len(files)}/10")
PY

echo
echo "EVIDENCE REGRESSION PASS"
echo "Artifacts : $count/10"
echo "============================================================"
