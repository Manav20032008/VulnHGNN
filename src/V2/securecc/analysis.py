from __future__ import annotations

import importlib
import subprocess
import tempfile
from pathlib import Path


def _load_graph_builder():
    module = importlib.import_module("src.const_graph")
    return module.build_heterogeneous_graph


def _load_ir_parser():
    module = importlib.import_module("src.ir_parser")
    return module.parse_ll_file


def _load_detection():
    candidates = [
        "src.V2.detection.engine",
        "src.v2.detection.engine",
    ]
    last = None
    for name in candidates:
        try:
            module = importlib.import_module(name)
            return module.DetectionEngine
        except Exception as exc:
            last = exc
    raise RuntimeError(
        "V2 detection engine is not available. "
        "Install/merge the Phase 1 V2 detection package."
    ) from last


def _load_localization():
    module = importlib.import_module("src.V2.localization.localizer")
    return module.VulnerabilityLocalizer


def _load_explainability():
    module = importlib.import_module("src.V2.explain.engine")
    return module.ExplainabilityEngine


def compile_to_ir(source: Path) -> Path:
    compiler = "clang++" if source.suffix.lower() == ".cpp" else "clang"

    if not source.exists():
        raise FileNotFoundError(f"source file not found: {source}")

    with tempfile.NamedTemporaryFile(
        suffix=".ll", prefix="securecc_", delete=False
    ) as tmp:
        ll_path = Path(tmp.name)

    cmd = [
        compiler,
        "-S",
        "-emit-llvm",
        "-g",
        "-O0",
        "-Xclang",
        "-disable-O0-optnone",
        "-w",
        str(source),
        "-o",
        str(ll_path),
    ]

    result = subprocess.run(cmd, text=True, capture_output=True)

    if result.returncode != 0:
        try:
            ll_path.unlink()
        except FileNotFoundError:
            pass
        raise RuntimeError(
            f"LLVM analysis compilation failed:\n{result.stderr.strip()}"
        )

    return ll_path


def analyze_source(source: Path) -> dict:
    """
    Run the deterministic V2 source -> IR -> graph -> detection ->
    localization -> explanation path.

    This function does not use the ML model and does not invent a
    probability. The current V2 detection engine supplies the findings.
    """

    source = source.resolve()
    ll_path = compile_to_ir(source)

    try:
        parse_ll_file = _load_ir_parser()
        build_graph = _load_graph_builder()

        ir_json = parse_ll_file(str(ll_path))
        graph = build_graph(ir_json)

        sample = {
            "filename": source.name,
            "source_file": str(source),
            "graph": graph,
        }

        DetectionEngine = _load_detection()
        engine = DetectionEngine()
        findings = engine.analyze(sample)

        VulnerabilityLocalizer = _load_localization()
        localized = VulnerabilityLocalizer().localize(sample, findings)

        ExplainabilityEngine = _load_explainability()
        cwes = list(dict.fromkeys(x.cwe_id for x in findings))
        explanations = ExplainabilityEngine().explain_all(graph, cwes)

        return {
            "source": str(source),
            "llvm_ir": str(ll_path),
            "node_count": graph.number_of_nodes(),
            "edge_count": graph.number_of_edges(),
            "findings": findings,
            "cwes": cwes,
            "localized": localized,
            "explanations": explanations,
        }
    finally:
        try:
            ll_path.unlink()
        except FileNotFoundError:
            pass
