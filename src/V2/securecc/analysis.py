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
    from .languages import compiler_for_source, is_cpp_suffix, is_java_path

    if is_java_path(source):
        from .java_ir import compile_java_to_ir

        return compile_java_to_ir(source)

    compiler = compiler_for_source(source)

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
    if is_cpp_suffix(source.suffix):
        cmd[1:1] = ["-std=c++17"]

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
        findings = list(engine.analyze(sample))

        from .compile_diagnostics import collect_compiler_warnings

        diag_findings = collect_compiler_warnings(source)
        existing_keys = {
            (f.cwe_id, f.instruction, getattr(f.location, "line", None))
            for f in findings
        }
        for item in diag_findings:
            key = (
                item.cwe_id,
                item.instruction,
                getattr(item.location, "line", None),
            )
            if key not in existing_keys:
                findings.append(item)
                existing_keys.add(key)

        VulnerabilityLocalizer = _load_localization()
        localized = VulnerabilityLocalizer().localize(sample, findings)

        ExplainabilityEngine = _load_explainability()
        cwes = list(dict.fromkeys(x.cwe_id for x in findings))
        explanations = ExplainabilityEngine().explain_all(graph, cwes)

        llvm_ir_preview = ""
        llvm_ir_line_count = 0
        try:
            ir_lines = ll_path.read_text(encoding="utf-8", errors="replace").splitlines()
            llvm_ir_line_count = len(ir_lines)
            head = ir_lines[:56]
            llvm_ir_preview = "\n".join(head)
            if llvm_ir_line_count > len(head):
                llvm_ir_preview += "\n; … (truncated)"
        except OSError:
            pass

        return {
            "source": str(source),
            "llvm_ir": str(ll_path),
            "llvm_ir_preview": llvm_ir_preview,
            "llvm_ir_line_count": llvm_ir_line_count,
            "graph": graph,
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
