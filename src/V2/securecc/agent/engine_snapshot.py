"""Full engine analyze snapshot for agent pipeline UI."""

from __future__ import annotations

from pathlib import Path
from typing import Any

from src.V2.securecc.analysis import analyze_source
from src.V2.securecc.languages import language_id_from_suffix
from src.V2.securecc.scan import build_report


def _scan_payload_from_analysis(analysis: dict) -> dict[str, Any]:
    """Scan report for API/agent UI; viz graph is returned separately."""
    report = build_report(analysis)
    graph = analysis.get("graph")
    graph_json: dict[str, Any] | None = None
    if graph is not None:
        try:
            from src.V2.securecc.web.serializers import serialize_graph

            highlight: set[str] = set()
            for finding in report.get("findings", []):
                node = finding.get("node_id")
                if node:
                    highlight.add(str(node))
            for loc in report.get("localization", []):
                vn = loc.get("vulnerable_node")
                if vn:
                    highlight.add(str(vn))
            graph_json = serialize_graph(graph, highlight_nodes=highlight)
        except ImportError:
            graph_json = None
    return dict(report), graph_json


def collect_engine_snapshot(source: Path) -> dict[str, Any]:
    source = source.resolve()
    analysis = analyze_source(source)
    scan, graph_json = _scan_payload_from_analysis(analysis)
    return {
        "language": language_id_from_suffix(source.suffix),
        "analysis": analysis,
        "scan": scan,
        "graph": graph_json,
    }