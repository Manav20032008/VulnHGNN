#!/usr/bin/env python3
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from V2.explain.evidence_report import build_evidence_report, save_evidence_report


class E:
    def __init__(self, **kw):
        self.__dict__.update(kw)

    def to_dict(self):
        return dict(self.__dict__)


source = ROOT / "test_files" / "test_01_clean.c"

explanation = E(
    cwe_id="CWE-476",
    title="NULL Pointer Dereference",
    severity="HIGH",
    root_cause="Allocator-derived pointer reaches a dereference without evidence of a NULL guard.",
    security_impact="A NULL dereference can terminate the process.",
    vulnerable_operation="%1 = load ptr %p",
    function="main",
    block="block_0",
    node_id="inst_7",
    evidence=[
        {
            "role": "vulnerable_operation",
            "node_id": "inst_7",
            "instruction": "%1 = load ptr %p",
            "function": "main",
            "block": "block_0",
            "reason": "Target operation",
        }
    ],
    repair_strategy="Validate the pointer before dereference.",
    verification="Targeted-CWE removal and security re-analysis.",
    confidence_basis="Evidence coverage from the analyzed LLVM IR graph; not an invented probability.",
)

result = {
    "tool": "VulnHGNN 2.0 SecureCC",
    "source": str(source),
    "findings": [{"cwe_id": "CWE-476"}],
    "explanations": [explanation],
}

report = build_evidence_report(
    result,
    source=source,
    verification={
        "status": "PROJECT_VERIFY_VERIFIED",
        "repair_passed": True,
        "compile_passed": True,
        "hardening_passed": True,
        "runtime_passed": True,
        "security_rescan_passed": True,
        "behavior_passed": True,
        "behavior_verified": True,
    },
    provenance={
        "manifest_version": 2,
        "source_sha256": "example",
        "binary_sha256": "example",
    },
)

assert report["report_version"] == 1
assert report["report_format"] == "vulnhgnn-evidence"
assert report["finding_count"] == 1
assert report["cwes"] == ["CWE-476"]
assert len(report["evidence"]) == 1
assert report["evidence"][0]["role"] == "vulnerable_operation"
assert report["verification"]["status"] == "PROJECT_VERIFY_VERIFIED"
assert report["provenance"]["manifest_version"] == 2

output = ROOT / "build" / "evidence" / "regression_evidence.json"
save_evidence_report(report, output)

print("EVIDENCE REPORT REGRESSION PASS")
print(f"Report version : {report['report_version']}")
print(f"Findings       : {report['finding_count']}")
print(f"Evidence items : {len(report['evidence'])}")
print(f"Status         : {report['status']}")
print(f"Report         : {output}")
