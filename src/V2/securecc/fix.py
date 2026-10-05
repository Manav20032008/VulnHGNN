from __future__ import annotations

import json
import subprocess
import tempfile
from pathlib import Path
from typing import Any

from .analysis import compile_to_ir


def _load_graph_builder():
    import importlib
    return importlib.import_module("src.const_graph").build_heterogeneous_graph


def _load_ir_parser():
    import importlib
    return importlib.import_module("src.ir_parser").parse_ll_file


def _load_repair_components():
    from src.V2.repair.engine import RepairEngine
    from src.V2.repair.planner import RepairPlanner
    from src.V2.repair.verifier import RepairVerifier
    return RepairEngine, RepairPlanner, RepairVerifier


def _read_text(path: Path) -> str:
    return path.read_text(encoding="utf-8", errors="replace")


def _write_text(path: Path, text: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8")


def _graph_sample(source: Path, ll_path: Path) -> tuple[dict, Any]:
    parse_ll_file = _load_ir_parser()
    build_graph = _load_graph_builder()
    ir_json = parse_ll_file(str(ll_path))
    graph = build_graph(ir_json)
    sample = {
        "filename": source.name,
        "source_file": str(source.resolve()),
        "graph": graph,
    }
    return sample, graph


def _compile_patched_ir(ll_path: Path, output: Path) -> dict:
    """
    Compile patched LLVM IR without executing it.

    This is an artifact/build check only. Runtime execution belongs to the
    Phase-8 sandbox and Phase-8.1 verification gate.
    """
    compiler = "clang++" if ll_path.suffix.lower() == ".bc" else "clang"
    output.parent.mkdir(parents=True, exist_ok=True)
    result = subprocess.run(
        [compiler, str(ll_path), "-O0", "-o", str(output)],
        text=True,
        capture_output=True,
    )
    return {
        "passed": result.returncode == 0,
        "compiler": compiler,
        "output": str(output),
        "returncode": result.returncode,
        "stderr": result.stderr.strip(),
    }


def fix_source(
    source: Path,
    output_dir: Path | None = None,
    keep_ir: bool = True,
    build_artifact: bool = True,
) -> dict:
    """
    SecureCC deterministic fix pipeline.

        source
          -> LLVM IR
          -> V2 detection
          -> localization
          -> repair plan
          -> existing IR healer
          -> IR verification
          -> detector re-analysis
          -> optional compile check

    Important:
      * The original source file is never overwritten.
      * A compiler accepting patched IR is NOT sufficient for acceptance.
      * Final VERIFIED requires repair verification and detector re-analysis.
      * Runtime execution is intentionally not performed here.
    """
    source = Path(source).resolve()
    if not source.exists():
        raise FileNotFoundError(f"source file not found: {source}")
    if source.suffix.lower() not in {".c", ".cc", ".cpp", ".cxx"}:
        raise ValueError("SecureCC fix currently supports C/C++ source files only.")

    if output_dir is None:
        output_dir = Path("build") / "securecc_fix" / source.stem
    output_dir = Path(output_dir).resolve()
    output_dir.mkdir(parents=True, exist_ok=True)

    # Import here so `securecc --help` remains lightweight.
    from .analysis import _load_detection, _load_localization
    RepairEngine, RepairPlanner, RepairVerifier = _load_repair_components()

    original_ir = compile_to_ir(source)
    try:
        original_sample, original_graph = _graph_sample(source, original_ir)

        DetectionEngine = _load_detection()
        detector = DetectionEngine()
        findings = detector.analyze(original_sample)

        VulnerabilityLocalizer = _load_localization()
        localized = VulnerabilityLocalizer().localize(original_sample, findings)

        planner = RepairPlanner()
        plan = planner.plan(localized)

        result = {
            "tool": "VulnHGNN 2.0 SecureCC",
            "command": "fix",
            "source": str(source),
            "output_dir": str(output_dir),
            "original_graph": {
                "nodes": original_graph.number_of_nodes(),
                "edges": original_graph.number_of_edges(),
            },
            "detected_cwes": sorted({x.cwe_id for x in findings}),
            "finding_count": len(findings),
            "plan": plan.to_dict(),
            "repair": None,
            "verification": None,
            "detector_verification": None,
            "build_check": None,
            "status": "UNKNOWN",
        }

        if not findings:
            result["status"] = "CLEAN"
            result["message"] = "No supported V2 vulnerabilities were detected."
            return result

        if not plan.actions:
            result["status"] = "REJECTED"
            result["message"] = "Findings were detected, but no deterministic repair action exists."
            return result

        repairer = RepairEngine()
        repair = repairer.repair(_read_text(original_ir), plan)
        result["repair"] = repair.to_dict()

        verifier = RepairVerifier()
        verification = verifier.verify_result(_read_text(original_ir), repair)
        result["verification"] = verification

        if not verification["passed"]:
            result["status"] = "REJECTED"
            result["message"] = verification["message"]
            return result

        patched_ir_path = output_dir / f"{source.stem}.patched.ll"
        _write_text(patched_ir_path, repair.patched_ir)
        result["patched_ir"] = str(patched_ir_path)

        # Rebuild the patched IR into the standard graph representation and
        # perform the detector-level acceptance check.
        patched_sample, patched_graph = _graph_sample(source, patched_ir_path)
        detector_verification = verifier.verify_graph_pair(
            original_sample,
            patched_sample,
            target_cwes=sorted({x.cwe_id for x in findings}),
            engine=detector,
        )
        result["detector_verification"] = detector_verification
        result["patched_graph"] = {
            "nodes": patched_graph.number_of_nodes(),
            "edges": patched_graph.number_of_edges(),
        }

        if not detector_verification["passed"]:
            result["status"] = "REJECTED"
            result["message"] = detector_verification["message"]
            return result

        # Compile the candidate artifact, but do not execute it.
        if build_artifact:
            artifact = output_dir / source.stem
            result["build_check"] = _compile_patched_ir(patched_ir_path, artifact)
            if not result["build_check"]["passed"]:
                result["status"] = "REJECTED"
                result["message"] = "Patched IR passed security re-analysis but failed compilation."
                return result

        result["status"] = "VERIFIED"
        result["message"] = (
            "Patch candidate verified: repair checks passed, targeted CWEs "
            "disappeared under V2 re-analysis, no new CWEs were introduced, "
            "and the patched IR compiled successfully."
            if build_artifact
            else
            "Patch candidate verified: repair checks passed and targeted CWEs "
            "disappeared under V2 re-analysis with no new CWEs."
        )
        return result
    finally:
        # Preserve the candidate IR only; the compiler's temporary original IR
        # is not part of the user-facing output.
        try:
            original_ir.unlink()
        except FileNotFoundError:
            pass


def json_report(result: dict) -> str:
    return json.dumps(result, indent=2, default=str)
