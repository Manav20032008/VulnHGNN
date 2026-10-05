import json
from collections import Counter


def build_phase2_report(sample, localized_findings):
    filename = ""
    if isinstance(sample, dict):
        filename = sample.get("filename", "")

    severity = Counter(x.severity for x in localized_findings)
    cwes = Counter(x.cwe_id for x in localized_findings)

    return {
        "phase": "VulnHGNN 2.0 Phase 2",
        "filename": filename,
        "finding_count": len(localized_findings),
        "severity_counts": dict(severity),
        "cwe_counts": dict(cwes),
        "findings": [x.to_dict() for x in localized_findings],
    }


def report_json(sample, localized_findings, indent=2):
    return json.dumps(
        build_phase2_report(sample, localized_findings),
        indent=indent,
        default=str,
    )


def print_report(sample, localized_findings):
    filename = sample.get("filename", "") if isinstance(sample, dict) else ""

    print("=" * 88)
    print("VULNHGNN PHASE 2 — LOCALIZATION REPORT")
    print("=" * 88)
    print(f"FILE: {filename}")
    print(f"FINDINGS: {len(localized_findings)}")
    print()

    for index, item in enumerate(localized_findings, start=1):
        print("-" * 88)
        print(f"[{index}] {item.cwe_id} — {item.title}")
        print(f"Severity              : {item.severity}")
        print(f"Detector confidence   : {item.confidence:.2%}")
        print(f"Localization confidence: {item.localization_confidence:.2%}")
        print(f"Function              : {item.function or 'unknown'}")
        print(f"Block                 : {item.vulnerable_block or 'unknown'}")
        print(f"Node                  : {item.vulnerable_node}")
        print(f"Instruction           : {item.vulnerable_instruction}")
        print(f"Rationale             : {item.rationale}")

        if item.source_file:
            location = item.source_file
            if item.source_line is not None:
                location += f":{item.source_line}"
            if item.source_column is not None:
                location += f":{item.source_column}"
            print(f"Source location       : {location}")

        print("Evidence path:")
        for step in item.evidence:
            print(
                f"  [{step.role}] {step.node_id}"
                f"  ({step.relation or 'direct'})"
            )
            print(f"      {step.instruction}")

    print("=" * 88)
