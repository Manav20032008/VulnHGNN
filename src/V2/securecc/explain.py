from __future__ import annotations

import json
from pathlib import Path

from .analysis import analyze_source
from ..explain.evidence_report import build_evidence_report, save_evidence_report


def explain_source(source: Path) -> dict:
    source = Path(source).resolve()

    if not source.exists():
        raise FileNotFoundError(f"source file not found: {source}")

    if source.suffix.lower() not in {".c", ".cc", ".cpp", ".cxx"}:
        raise ValueError("SecureCC explain supports C/C++ source files only.")

    result = analyze_source(source)

    findings = result.get("findings", [])
    explanations = result.get("explanations", [])

    finding_by_cwe = {}

    for finding in findings:
        cwe = getattr(finding, "cwe_id", None)
        if cwe and cwe not in finding_by_cwe:
            finding_by_cwe[cwe] = finding

    for explanation in explanations:
        cwe = getattr(explanation, "cwe_id", None)
        finding = finding_by_cwe.get(cwe)

        if finding is None:
            continue

        function = getattr(finding, "function", None)
        if function:
            explanation.function = function

        instruction = getattr(finding, "instruction", None)
        if instruction:
            explanation.vulnerable_operation = instruction

    base_result = {
        "tool": "VulnHGNN 2.0 SecureCC",
        "command": "explain",
        "source": str(source),
        "finding_count": len(findings),
        "cwes": list(
            dict.fromkeys(
                getattr(f, "cwe_id", "")
                for f in findings
                if getattr(f, "cwe_id", "")
            )
        ),
        "findings": findings,
        "explanations": explanations,
    }

    evidence_report = build_evidence_report(
        base_result,
        source=source,
    )

    return {
        **base_result,
        "evidence_report": evidence_report,
    }


def json_report(result: dict) -> str:
    return json.dumps(
        result,
        indent=2,
        default=lambda obj: obj.to_dict()
        if hasattr(obj, "to_dict")
        else str(obj),
    )


def text_report(result: dict) -> str:
    lines = [
        "=" * 88,
        "VULNHGNN 2.0 — SECURECC EXPLAIN",
        "=" * 88,
        f"Source        : {result['source']}",
        f"Findings      : {result['finding_count']}",
        "CWEs          : "
        + (", ".join(result["cwes"]) if result["cwes"] else "none"),
        "",
    ]

    if not result["explanations"]:
        lines += [
            "No supported vulnerability explanation is available.",
            "",
            "STATUS        : NO EXPLANATIONS",
            "=" * 88,
        ]
        return "\n".join(lines)

    for index, explanation in enumerate(result["explanations"], 1):
        e = explanation.to_dict()

        lines += [
            "-" * 88,
            f"[{index}] {e['cwe_id']} — {e['title']}",
            f"Severity       : {e['severity']}",
            f"Function       : {e['function']}",
            f"Basic block    : {e['block']}",
            f"Instruction    : {e['node_id']}",
            f"Operation      : {e['vulnerable_operation']}",
            "",
            f"Root cause     : {e['root_cause']}",
            f"Security impact: {e['security_impact']}",
            f"Repair strategy: {e['repair_strategy']}",
            f"Verification   : {e['verification']}",
            f"Confidence     : {e['confidence_basis']}",
            "",
            "Evidence:",
        ]

        for item in e.get("evidence", []):
            lines.append(
                f"  - [{item['role']}] "
                f"{item['node_id']}: {item['instruction']}"
            )

    evidence = result.get("evidence_report", {})

    lines += [
        "",
        "-" * 88,
        "EVIDENCE REPORT",
        f"Report version : {evidence.get('report_version', 'unknown')}",
        f"Evidence items : {len(evidence.get('evidence', []))}",
        f"Source SHA-256 : {evidence.get('source_sha256', 'unknown')}",
        f"Status         : {evidence.get('status', 'UNKNOWN')}",
        "",
        "STATUS        : EXPLANATION GENERATED",
        "=" * 88,
    ]

    return "\n".join(lines)
