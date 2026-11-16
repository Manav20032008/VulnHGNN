"""UI pipeline stage builders (Analyze + agent sessions)."""

from __future__ import annotations

from typing import Any


def _detect_detail(scan: dict[str, Any]) -> str:
    lines = ["V2 detection engine + source analysis merged into findings."]
    for f in (scan.get("findings") or [])[:10]:
        cwe = f.get("cwe_id") or "—"
        title = f.get("title") or ""
        sev = f.get("severity") or "info"
        fn = f.get("function") or ""
        loc = f"{fn}: " if fn else ""
        lines.append(f"[{sev}] {cwe} {loc}{title}")
    return "\n".join(lines)


def build_engine_pipeline_stages(
    analysis: dict,
    scan: dict[str, Any],
    *,
    heal: dict[str, Any] | None = None,
) -> list[dict[str, Any]]:
    graph = scan.get("graph") or {}
    if isinstance(graph, dict) and "nodes" in graph and isinstance(graph["nodes"], list):
        node_count = len(graph["nodes"])
        edge_count = len(graph.get("edges") or [])
        graph_summary = f"{node_count} nodes · {edge_count} edges"
    else:
        graph_summary = (
            f"{graph.get('nodes', analysis.get('node_count', 0))} nodes · "
            f"{graph.get('edges', analysis.get('edge_count', 0))} edges"
        )

    cwes = scan.get("cwes") or []
    loc_count = len(scan.get("localization") or [])
    explain_count = len(scan.get("explanations") or [])
    finding_count = int(scan.get("finding_count") or 0)
    detect_summary = (
        f"{finding_count} finding(s) · CWEs: {', '.join(cwes) if cwes else 'none'}"
    )

    stages: list[dict[str, Any]] = [
        {
            "id": "compile",
            "label": "Compile → LLVM IR",
            "status": "complete",
            "summary": f"{analysis.get('llvm_ir_line_count', 0)} IR lines",
            "detail": analysis.get("llvm_ir_preview") or "",
        },
        {
            "id": "parse",
            "label": "Parse IR",
            "status": "complete",
            "summary": "Structured IR ready for graph build",
            "detail": "Parsed LLVM bitcode text into JSON blocks, instructions, and debug metadata.",
        },
        {
            "id": "graph",
            "label": "Heterogeneous graph",
            "status": "complete",
            "summary": graph_summary,
            "detail": "Basic blocks and instructions linked for path-sensitive analysis.",
        },
        {
            "id": "detect",
            "label": "Detect",
            "status": "complete",
            "summary": detect_summary,
            "detail": _detect_detail(scan),
        },
    ]
    stages.extend(
        [
            {
                "id": "localize",
                "label": "Localize",
                "status": "complete",
                "summary": f"{loc_count} evidence chain(s)",
                "detail": "Graph paths from sources to vulnerable instructions.",
            },
            {
                "id": "explain",
                "label": "Explain",
                "status": "complete",
                "summary": f"{explain_count} CWE narrative(s)",
                "detail": "Root cause, impact, and repair strategy per CWE.",
            },
        ]
    )

    if heal:
        st = str(heal.get("status") or "unknown").upper()
        detail = str(heal.get("message") or "")
        per = {**(heal.get("per_cwe") or {}), **(heal.get("advisory_per_cwe") or {})}
        if per:
            bits = ", ".join(
                f"{cwe}:{'cleared' if ok else 'remaining'}" for cwe, ok in per.items()
            )
            detail = f"{detail}\nVerification: {bits}".strip()
        stages.append(
            {
                "id": "repair",
                "label": "Catalog heal + verify",
                "status": "complete" if st == "VERIFIED" else "partial",
                "summary": st or "unknown",
                "detail": detail,
            }
        )

    return stages


def build_python_pipeline_stages(
    analysis: dict,
    scan: dict[str, Any],
) -> list[dict[str, Any]]:
    cwes = scan.get("cwes") or []
    finding_count = int(scan.get("finding_count") or 0)
    bandit = "available" if analysis.get("bandit_available") else "not installed"
    stages: list[dict[str, Any]] = [
        {
            "id": "parse",
            "label": "Parse Python",
            "status": "complete",
            "summary": f"{analysis.get('ast_line_count', 0)} source lines",
            "detail": "AST parse of editor/uploaded .py (syntax errors reported as findings).",
        },
        {
            "id": "detect",
            "label": "Detect",
            "status": "complete",
            "summary": f"{finding_count} finding(s) · CWEs: {', '.join(cwes) if cwes else 'none'}",
            "detail": f"Built-in AST rules + Bandit ({bandit}).\n{_detect_detail(scan)}",
        },
    ]
    stages.append(
        {
            "id": "explain",
            "label": "Explain",
            "status": "complete",
            "summary": f"{len(scan.get('explanations') or [])} narrative(s)",
            "detail": "Short root-cause text per finding (IR localization not applicable).",
        }
    )
    return stages
