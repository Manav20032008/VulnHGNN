from __future__ import annotations

import json


def _finding_dict(finding):
    if hasattr(finding, "to_dict"):
        return finding.to_dict()
    return {
        "cwe_id": getattr(finding, "cwe_id", ""),
        "title": getattr(finding, "title", ""),
        "severity": getattr(finding, "severity", ""),
        "confidence": getattr(finding, "confidence", 0.0),
        "message": getattr(finding, "message", ""),
        "function": getattr(finding, "function", None),
        "instruction": getattr(finding, "instruction", None),
        "evidence": list(getattr(finding, "evidence", []) or []),
        "detector": getattr(finding, "detector", "unknown"),
        "node_id": getattr(finding, "node_id", None),
    }


def _localized_dict(item):
    return item.to_dict() if hasattr(item, "to_dict") else dict(item)


def _explanation_dict(item):
    return item.to_dict() if hasattr(item, "to_dict") else dict(item)


def build_report(result):
    findings = result["findings"]
    localized = result["localized"]
    explanations = result["explanations"]

    return {
        "tool": "VulnHGNN 2.0 SecureCC",
        "stage": "scan",
        "source": result["source"],
        "graph": {
            "nodes": result["node_count"],
            "edges": result["edge_count"],
        },
        "finding_count": len(findings),
        "cwes": list(dict.fromkeys(x.cwe_id for x in findings)),
        "findings": [_finding_dict(x) for x in findings],
        "localization": [_localized_dict(x) for x in localized],
        "explanations": [_explanation_dict(x) for x in explanations],
    }


def print_report(result):
    report = build_report(result)

    print("=" * 88)
    print("VULNHGNN 2.0 — SECURECC SECURITY SCAN")
    print("=" * 88)
    print(f"Source        : {report['source']}")
    print(
        f"Graph         : {report['graph']['nodes']} nodes, "
        f"{report['graph']['edges']} edges"
    )
    print(f"Findings      : {report['finding_count']}")

    if not report["findings"]:
        print()
        print("STATUS        : NO SUPPORTED FINDINGS")
        print("=" * 88)
        return

    print(f"CWEs          : {', '.join(report['cwes'])}")
    print()

    for index, finding in enumerate(report["findings"], 1):
        print("-" * 88)
        print(
            f"[{index}] {finding['cwe_id']} — "
            f"{finding.get('title') or 'Security finding'}"
        )
        print(f"Severity      : {finding.get('severity', 'unknown')}")
        print(
            f"Confidence    : "
            f"{float(finding.get('confidence', 0.0)):.2%}"
        )
        print(f"Function      : {finding.get('function') or 'unknown'}")
        print(f"Node          : {finding.get('node_id')}")
        print(f"Instruction   : {finding.get('instruction') or 'unknown'}")
        print(f"Message       : {finding.get('message') or ''}")

    print()
    print("STATUS        : FINDINGS PRESENT")
    print("=" * 88)


def print_json(result):
    print(json.dumps(build_report(result), indent=2, default=str))
