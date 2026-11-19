"""Compose compile repair → HGNN → adjudication → enrichment for web Analyze."""

from __future__ import annotations

from pathlib import Path
from typing import Any

from ..compile_repair import analyze_with_compile_repair
from ..adjudication import adjudicate_engine_scan
from ..agent_enrichment import enrich_confirmed_scan
from .cfg_viz import build_flow_views
from .serializers import analysis_bundle


def run_engine_pipeline_pass(
    source: Path,
    *,
    source_text: str,
    language: str,
) -> dict[str, Any]:
    """
    Full C/C++ engine pass. Returns analysis, bundle, scans, flow, compile_repair, enrichment.
    Raises RuntimeError if compile cannot be satisfied after repair attempts.
    """
    analysis, path_used, content_used, compile_meta = analyze_with_compile_repair(
        source,
        source_text=source_text,
        language=language,
    )
    bundle = analysis_bundle(analysis)
    raw_graph = analysis.get("graph")
    engine_scan = bundle["scan"]

    adj = adjudicate_engine_scan(engine_scan, source_text=content_used, language=language)
    display_scan, enrichment = enrich_confirmed_scan(
        adj["display_scan"],
        source_text=content_used,
        language=language,
    )

    highlight = {
        str(f.get("node_id"))
        for f in (engine_scan.get("findings") or [])
        if f.get("node_id")
    }
    flow = build_flow_views(raw_graph, highlight_nodes=highlight)

    return {
        "analysis": analysis,
        "bundle": bundle,
        "engine_scan": engine_scan,
        "adjudication": adj["meta"],
        "verification": adj["verification"],
        "scan": display_scan,
        "graph": bundle["graph"],
        "flow": flow,
        "compile_repair": compile_meta,
        "enrichment": enrichment,
        "source_text_used": content_used,
        "source_path_used": path_used,
    }