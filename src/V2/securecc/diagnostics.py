from __future__ import annotations

import json
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any

DIAGNOSTICS_SCHEMA_VERSION = 1


def _as_dict(value: Any) -> dict[str, Any]:
    if isinstance(value, dict):
        return value

    if hasattr(value, "to_dict"):
        result = value.to_dict()
        if isinstance(result, dict):
            return result

    if hasattr(value, "__dataclass_fields__"):
        return asdict(value)

    return {}


@dataclass
class Diagnostic:
    cwe_id: str
    title: str
    severity: str
    source: str
    function: str
    block: str
    node_id: str
    instruction: str
    vulnerable_operation: str
    root_cause: str
    security_impact: str
    evidence: list[dict[str, Any]]
    repair_strategy: str
    verification: str

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


def build_diagnostics(
    explanation_result: dict[str, Any],
) -> dict[str, Any]:
    source = str(explanation_result.get("source", ""))

    raw_explanations = explanation_result.get("explanations", [])
    diagnostics: list[Diagnostic] = []

    for raw in raw_explanations:
        item = _as_dict(raw)

        evidence_items = []
        for evidence in item.get("evidence", []) or []:
            evidence_items.append(_as_dict(evidence))

        diagnostics.append(
            Diagnostic(
                cwe_id=str(item.get("cwe_id", "")),
                title=str(item.get("title", "")),
                severity=str(item.get("severity", "")),
                source=source,
                function=str(item.get("function", "")),
                block=str(item.get("block", "")),
                node_id=str(item.get("node_id", "")),
                instruction=str(
                    item.get("vulnerable_operation", "")
                ),
                vulnerable_operation=str(
                    item.get("vulnerable_operation", "")
                ),
                root_cause=str(item.get("root_cause", "")),
                security_impact=str(
                    item.get("security_impact", "")
                ),
                evidence=evidence_items,
                repair_strategy=str(
                    item.get("repair_strategy", "")
                ),
                verification=str(
                    item.get("verification", "")
                ),
            )
        )

    return {
        "tool": "VulnHGNN 2.0 SecureCC",
        "format": "vulnhgnn-diagnostics",
        "schema_version": DIAGNOSTICS_SCHEMA_VERSION,
        "source": source,
        "finding_count": len(diagnostics),
        "diagnostics": [
            item.to_dict()
            for item in diagnostics
        ],
        "status": "FINDINGS_PRESENT"
        if diagnostics
        else "CLEAN",
    }


def diagnose_source(source: Path) -> dict[str, Any]:
    from .explain import explain_source

    explanation = explain_source(source)
    return build_diagnostics(explanation)


def save_diagnostics(
    result: dict[str, Any],
    path: Path,
) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        json.dumps(
            result,
            indent=2,
            sort_keys=True,
        ),
        encoding="utf-8",
    )
    return path


def text_report(result: dict[str, Any]) -> str:
    lines = [
        "=" * 88,
        "VULNHGNN 2.0 — SECURECC DIAGNOSTICS",
        "=" * 88,
        f"Source        : {result.get('source', '')}",
        f"Findings      : {result.get('finding_count', 0)}",
        "",
    ]

    diagnostics = result.get("diagnostics", [])

    if not diagnostics:
        lines.extend(
            [
                "STATUS        : CLEAN",
                "No supported V2 security findings were detected.",
                "=" * 88,
            ]
        )
        return "\n".join(lines)

    for index, diagnostic in enumerate(
        diagnostics,
        start=1,
    ):
        lines.extend(
            [
                "-" * 88,
                f"FINDING {index}",
                "-" * 88,
                f"CWE           : {diagnostic.get('cwe_id', '')}",
                f"Title         : {diagnostic.get('title', '')}",
                f"Severity      : {diagnostic.get('severity', '')}",
                f"Function      : {diagnostic.get('function', '')}",
                f"Block         : {diagnostic.get('block', '')}",
                f"Node          : {diagnostic.get('node_id', '')}",
                f"Operation     : {diagnostic.get('vulnerable_operation', '')}",
                "",
                "Root cause:",
                f"  {diagnostic.get('root_cause', '')}",
                "",
                "Security impact:",
                f"  {diagnostic.get('security_impact', '')}",
                "",
                "Evidence:",
            ]
        )

        for evidence in diagnostic.get("evidence", []):
            role = evidence.get("role", "")
            node = evidence.get("node_id", "")
            instruction = evidence.get("instruction", "")
            reason = evidence.get("reason", "")

            lines.append(
                f"  [{role}] {node} {instruction}"
            )

            if reason:
                lines.append(
                    f"      {reason}"
                )

        lines.extend(
            [
                "",
                "Repair strategy:",
                f"  {diagnostic.get('repair_strategy', '')}",
                "",
                "Verification:",
                f"  {diagnostic.get('verification', '')}",
                "",
            ]
        )

    lines.extend(
        [
            f"STATUS        : {result.get('status', '')}",
            "=" * 88,
        ]
    )

    return "\n".join(lines)


def json_report(result: dict[str, Any]) -> str:
    return json.dumps(
        result,
        indent=2,
        sort_keys=True,
    )
