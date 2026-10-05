from __future__ import annotations

import hashlib
import json
from pathlib import Path
from typing import Any


EVIDENCE_REPORT_VERSION = 1


def _to_dict(value: Any) -> Any:
    if hasattr(value, "to_dict"):
        return value.to_dict()
    if isinstance(value, dict):
        return value
    return value


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        while chunk := handle.read(1024 * 1024):
            digest.update(chunk)
    return digest.hexdigest()


def build_evidence_report(
    result: dict[str, Any],
    *,
    source: Path | None = None,
    verification: dict[str, Any] | None = None,
    provenance: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """Build a deterministic, evidence-first Phase 8 report.

    This layer packages already-observed findings/explanations. It does not
    invent confidence, source locations, repairs, or verification results.
    """
    source_path = Path(source).resolve() if source else None

    explanations = [
        _to_dict(item) for item in result.get("explanations", [])
    ]
    findings = [
        _to_dict(item) for item in result.get("findings", [])
    ]

    evidence_items = []
    for explanation in explanations:
        for item in explanation.get("evidence", []):
            evidence_items.append({
                "cwe_id": explanation.get("cwe_id"),
                "role": item.get("role", ""),
                "node_id": item.get("node_id", ""),
                "instruction": item.get("instruction", ""),
                "function": item.get("function", ""),
                "block": item.get("block", ""),
                "reason": item.get("reason", ""),
            })

    report = {
        "report_version": EVIDENCE_REPORT_VERSION,
        "report_format": "vulnhgnn-evidence",
        "tool": result.get("tool", "VulnHGNN 2.0 SecureCC"),
        "command": "evidence",
        "source": str(source_path or result.get("source", "")),
        "source_sha256": (
            _sha256(source_path)
            if source_path is not None and source_path.exists()
            else None
        ),
        "finding_count": len(findings),
        "cwes": list(dict.fromkeys(
            item.get("cwe_id")
            for item in findings
            if item.get("cwe_id")
        )) or list(dict.fromkeys(
            item.get("cwe_id")
            for item in explanations
            if item.get("cwe_id")
        )),
        "findings": findings,
        "explanations": explanations,
        "evidence": evidence_items,
        "verification": verification if verification is not None else None,
        "provenance": provenance if provenance is not None else None,
    }

    # Deterministic status: only observed states are used.
    if verification is None:
        report["status"] = "EVIDENCE_ONLY"
    else:
        status = verification.get("status")
        if status:
            report["status"] = status
        else:
            report["status"] = "EVIDENCE_WITHOUT_FINAL_STATUS"

    return report


def save_evidence_report(report: dict[str, Any], path: Path) -> Path:
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        json.dumps(report, indent=2, sort_keys=True),
        encoding="utf-8",
    )
    return path


def render_evidence_text(report: dict[str, Any]) -> str:
    lines = [
        "=" * 88,
        "VULNHGNN 2.0 — SECURITY EVIDENCE REPORT",
        "=" * 88,
        f"Source        : {report.get('source', '')}",
        f"Findings      : {report.get('finding_count', 0)}",
        "CWEs          : " + (
            ", ".join(report.get("cwes", [])) or "none"
        ),
        f"Status        : {report.get('status', 'UNKNOWN')}",
        "",
    ]

    explanations = report.get("explanations", [])
    if not explanations:
        lines += [
            "No supported vulnerability explanations are available.",
            "",
        ]
    else:
        for index, item in enumerate(explanations, 1):
            lines += [
                "-" * 88,
                f"[{index}] {item.get('cwe_id', 'UNKNOWN')} — "
                f"{item.get('title', 'Unknown vulnerability')}",
                f"Severity       : {item.get('severity', 'unknown')}",
                f"Function       : {item.get('function', 'unknown')}",
                f"Basic block    : {item.get('block', 'unknown')}",
                f"Instruction    : {item.get('node_id', 'unknown')}",
                f"Operation      : {item.get('vulnerable_operation', '')}",
                f"Root cause     : {item.get('root_cause', '')}",
                f"Security impact: {item.get('security_impact', '')}",
                f"Repair strategy: {item.get('repair_strategy', '')}",
                f"Verification   : {item.get('verification', '')}",
                "",
                "Evidence:",
            ]
            for evidence in item.get("evidence", []):
                lines.append(
                    f"  - [{evidence.get('role', '')}] "
                    f"{evidence.get('node_id', '')}: "
                    f"{evidence.get('instruction', '')}"
                )

    verification = report.get("verification")
    if verification:
        lines += ["", "VERIFICATION"]
        for key in (
            "status",
            "repair_passed",
            "compile_passed",
            "hardening_passed",
            "runtime_passed",
            "security_rescan_passed",
            "behavior_passed",
            "behavior_verified",
        ):
            if key in verification:
                lines.append(f"  {key:25}: {verification[key]}")

    provenance = report.get("provenance")
    if provenance:
        lines += ["", "PROVENANCE"]
        for key in (
            "manifest_version",
            "source_sha256",
            "binary_sha256",
        ):
            if key in provenance:
                lines.append(f"  {key:25}: {provenance[key]}")

    lines += [
        "",
        "=" * 88,
        f"FINAL STATUS : {report.get('status', 'UNKNOWN')}",
        "=" * 88,
    ]
    return "\n".join(lines)
