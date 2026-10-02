from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from .evidence_report import build_evidence_report


UNIFIED_REPORT_VERSION = 1


def _as_dict(value: Any) -> Any:
    """Convert project model objects into JSON-safe dictionaries."""
    if value is None:
        return None

    if hasattr(value, "to_dict"):
        return value.to_dict()

    if hasattr(value, "__dict__"):
        return dict(value.__dict__)

    return value


def _serialize_hardening(hardening: Any) -> dict[str, Any] | None:
    """
    Serialize BinaryAudit while preserving its computed `passed` property.

    BinaryAudit exposes most fields through __dict__, but `passed` is
    computed and therefore may not appear in __dict__.
    """
    if hardening is None:
        return None

    data = _as_dict(hardening)

    if not isinstance(data, dict):
        return data

    if hasattr(hardening, "passed"):
        data["passed"] = bool(hardening.passed)

    return data


def _serialize_gate(gate: Any) -> dict[str, Any] | None:
    """Serialize VerificationGateResult."""
    if gate is None:
        return None

    data = _as_dict(gate)

    if not isinstance(data, dict):
        return data

    if hasattr(gate, "accepted"):
        data["accepted"] = bool(gate.accepted)

    return data


def _verification_status(
    verification: Any,
    gate: dict[str, Any] | None,
) -> str:
    """
    Convert the authoritative verification result into a stable status.

    VerificationGateResult.accepted is authoritative for the final gate.
    """
    if gate is not None:
        if gate.get("accepted") is True:
            return "VERIFIED"

        if gate.get("accepted") is False:
            return "VERIFICATION_FAILED"

    if isinstance(verification, dict):
        status = verification.get("status")
        if status:
            return str(status)

    return "VERIFICATION_RESULT_AVAILABLE"


def build_unified_evidence(
    explain_result: dict[str, Any],
    *,
    verification: dict[str, Any] | None = None,
    provenance: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """
    Combine explanation/evidence with verification and provenance.

    The report is intentionally evidence-first:
      source
      CWE findings
      explanations
      graph evidence
      verification
      hardening
      provenance
      final verification gate
    """

    base = build_evidence_report(
        explain_result,
        verification=verification,
        provenance=provenance,
    )

    verification_data = (
        {
            key: _as_dict(value)
            for key, value in verification.items()
        }
        if verification is not None
        else None
    )

    hardening = (
        _serialize_hardening(verification.get("hardening"))
        if verification
        else None
    )

    gate = (
        _serialize_gate(verification.get("gate"))
        if verification
        else None
    )

    manifest = (
        verification.get("manifest")
        if verification
        else None
    )

    manifest = _as_dict(manifest)

    report = {
        "unified_report_version": UNIFIED_REPORT_VERSION,
        "report_format": "vulnhgnn-unified-evidence",
        "tool": "VulnHGNN 2.0 SecureCC",

        "source": base.get("source"),
        "source_sha256": base.get("source_sha256"),

        "finding_count": base.get("finding_count", 0),
        "cwes": base.get("cwes", []),

        "findings": base.get("findings", []),
        "explanations": base.get("explanations", []),
        "evidence": base.get("evidence", []),

        "repair": {
            "available": verification is not None,
        },

        "verification": verification_data,

        "hardening": hardening,

        "provenance": {
            "available": (
                provenance is not None
                or manifest is not None
            ),
            "manifest": manifest,
            "source_sha256": (
                provenance.get("source_sha256")
                if provenance
                else (
                    manifest.get("source_sha256")
                    if isinstance(manifest, dict)
                    else None
                )
            ),
            "binary_sha256": (
                provenance.get("binary_sha256")
                if provenance
                else (
                    manifest.get("binary_sha256")
                    if isinstance(manifest, dict)
                    else None
                )
            ),
        },

        "verification_gate": gate,
    }

    if verification is None:
        report["status"] = "EVIDENCE_ONLY"
    else:
        report["status"] = _verification_status(
            verification,
            gate,
        )

    return report


def save_unified_evidence(
    report: dict[str, Any],
    path: Path,
) -> Path:
    """Persist unified evidence as deterministic JSON."""
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)

    path.write_text(
        json.dumps(
            report,
            indent=2,
            sort_keys=True,
            default=str,
        ),
        encoding="utf-8",
    )

    return path
