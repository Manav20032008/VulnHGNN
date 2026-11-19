from __future__ import annotations

import json
import tempfile
from pathlib import Path
from typing import Any

from flask import Flask, jsonify, render_template, request, send_from_directory

from ..metadata import version_report
from ..analysis import analyze_source
from ..explain import explain_source
from ..diagnostics import diagnose_source
from ..learn import learn_source
from ..fix import fix_source
from ..languages import (
    LANGUAGE_CHOICES,
    SUPPORTED_SUFFIXES,
    language_id_from_suffix,
    validate_supported_suffix,
    workspace_name_for_language,
)
from ..pipeline_stages import build_engine_pipeline_stages
from ..scan_merge import (
    ensure_healed_banner,
    merge_explain_payload,
    source_looks_healed,
)
from .serializers import _to_jsonable, analysis_bundle


def _project_root() -> Path:
    return Path(__file__).resolve().parents[4]


def _uploads_dir(root: Path) -> Path:
    path = root / "build" / "web_uploads"
    path.mkdir(parents=True, exist_ok=True)
    return path


def _resolve_source(path_str: str, root: Path, uploads: Path) -> Path:
    raw = Path(path_str)
    if raw.is_absolute():
        candidate = raw.resolve()
    else:
        candidate = (root / raw).resolve()

    uploads_resolved = uploads.resolve()
    root_resolved = root.resolve()

    if str(candidate).startswith(str(uploads_resolved)):
        return candidate
    if str(candidate).startswith(str(root_resolved)):
        return candidate
    raise ValueError("source path must be inside the project or web uploads")


def _list_samples(root: Path) -> list[dict[str, str]]:
    test_dir = root / "test_files"
    samples: list[dict[str, str]] = []
    if test_dir.is_dir():
        paths: list[Path] = []
        for pattern in ("test_*.c", "test_*.cpp"):
            paths.extend(test_dir.glob(pattern))
        for path in sorted(paths, key=lambda p: (p.stem.lower(), p.suffix.lower())):
            rel = path.relative_to(root).as_posix()
            lang = "C++" if path.suffix.lower() == ".cpp" else "C"
            stem = path.stem.lower()
            if stem.startswith("hello") or stem == "main":
                category = "Basics"
            elif stem.startswith("test_"):
                category = "Test & CWE samples"
            else:
                category = lang
            samples.append(
                {
                    "id": rel,
                    "label": path.name,
                    "path": rel,
                    "language": lang,
                    "category": category,
                }
            )
    return samples


def _pipeline_stages(analysis: dict, scan: dict[str, Any]) -> list[dict[str, Any]]:
    return build_engine_pipeline_stages(analysis, scan)


def _build_compile_failed_payload(
    source: Path,
    base_source: dict[str, Any],
    error_message: str,
    *,
    include_fix: bool,
) -> dict[str, Any]:
    from src.V2.detection.catalog import catalog_payload
    from ..compile_diagnostics import collect_compiler_diagnostics
    from ..live_lint import run_live_lint
    from ..source_heuristics import scan_source_heuristics

    lang = language_id_from_suffix(source.suffix)
    compile_diags = collect_compiler_diagnostics(source)
    heuristics = scan_source_heuristics(base_source.get("content") or "", language=lang)
    live = run_live_lint(base_source.get("content") or "", language=lang)
    merged_compile = _merge_compile_diags(compile_diags, heuristics, error_message)

    empty_scan: dict[str, Any] = {
        "tool": "VulnHGNN 2.0 SecureCC",
        "stage": "scan",
        "source": str(source),
        "graph": {"nodes": 0, "edges": 0},
        "finding_count": 0,
        "cwes": [],
        "findings": [],
        "localization": [],
        "explanations": [],
    }

    return {
        "meta": version_report(),
        "vulnerability_catalog": catalog_payload(),
        "source": base_source,
        "compile": {
            "ok": False,
            "message": error_message,
            "diagnostics": merged_compile,
            "live_diagnostics": live.get("diagnostics") or [],
        },
        "scan": empty_scan,
        "graph": None,
        "explain": {
            "tool": "VulnHGNN 2.0 SecureCC",
            "command": "explain",
            "source": str(source),
            "finding_count": 0,
            "explanations": [],
            "evidence_report": None,
            "note": "Fix compile errors, then re-run Analyze for IR-based CWE detection.",
        },
        "diagnostics": {
            "tool": "VulnHGNN 2.0 SecureCC",
            "command": "diagnose",
            "source": str(source),
            "finding_count": 0,
            "diagnostics": [],
        },
        "learn": {
            "tool": "VulnHGNN 2.0 SecureCC",
            "command": "learn",
            "source": str(source),
            "finding_count": 0,
            "lessons": [],
        },
        "fix": None if not include_fix else {"status": "SKIPPED", "message": "Compile failed — repair not run."},
        "pipeline": {
            "stages": [
                {
                    "id": "compile",
                    "label": "Compile → LLVM IR",
                    "status": "failed",
                    "summary": "Compilation failed",
                    "detail": error_message[:2000],
                }
            ]
        },
        "analysis_status": "compile_failed",
    }


def _merge_compile_diags(
    compiler: list[dict],
    heuristics: list[dict],
    error_message: str,
) -> list[dict]:
    seen: set[tuple[Any, ...]] = set()
    out: list[dict] = []
    for item in compiler + heuristics:
        key = (item.get("line"), item.get("message", "")[:100])
        if key in seen:
            continue
        seen.add(key)
        out.append(item)
    if not out and error_message:
        out.append(
            {
                "line": 1,
                "column": 1,
                "category": "ERROR",
                "title": "Compile failed",
                "message": error_message.splitlines()[0][:500],
                "source": "compiler",
            }
        )
    return sorted(out, key=lambda x: (x.get("line") or 0, x.get("column") or 0))


def build_preview_payload(source: Path) -> dict[str, Any]:
    """Lightweight engine pass for live preview (no heal / explain / AI)."""
    from .cfg_viz import build_flow_views

    raw_graph = None
    try:
        analysis = analyze_source(source)
    except RuntimeError as exc:
        return {
            "preview": True,
            "finding_count": 0,
            "cwes": [],
            "findings": [],
            "graph": None,
            "flow": {"functions": []},
            "graph_counts": {"nodes": 0, "edges": 0},
            "compile": {"ok": False, "message": str(exc)},
        }
    bundle = analysis_bundle(analysis)
    scan = bundle["scan"]
    graph = bundle.get("graph")
    raw_graph = analysis.get("graph")

    graph_counts: dict[str, Any] = {"nodes": "—", "edges": "—"}
    if isinstance(graph, dict):
        nodes = graph.get("shown_nodes") or graph.get("total_nodes")
        if nodes is None and isinstance(graph.get("nodes"), list):
            nodes = len(graph["nodes"])
        edges = graph.get("edges")
        if isinstance(edges, list):
            edge_n = len(edges)
        else:
            edge_n = graph.get("edge_count", "—")
        graph_counts = {"nodes": nodes or 0, "edges": edge_n}

    highlight = {
        str(f.get("node_id"))
        for f in (scan.get("findings") or [])
        if f.get("node_id")
    }
    flow = build_flow_views(raw_graph, highlight_nodes=highlight)

    return {
        "preview": True,
        "finding_count": int(scan.get("finding_count") or 0),
        "cwes": scan.get("cwes") or [],
        "findings": (scan.get("findings") or [])[:25],
        "graph": graph,
        "flow": flow,
        "graph_counts": graph_counts,
        "compile": {"ok": True},
    }


def build_dashboard_payload(source: Path, *, include_fix: bool) -> dict[str, Any]:
    from src.V2.detection.catalog import catalog_payload

    content = source.read_text(encoding="utf-8", errors="replace")
    base_source = {
        "path": str(source),
        "name": source.name,
        "content": content,
        "language": language_id_from_suffix(source.suffix),
    }

    from src.V2.detection.catalog import catalog_payload
    from src.V2.securecc.agent.ai_source_review import ai_source_review
    from .analyze_orchestrator import run_engine_pipeline_pass

    lang = language_id_from_suffix(source.suffix)
    try:
        pass_out = run_engine_pipeline_pass(source, source_text=content, language=lang)
    except RuntimeError as exc:
        return _build_compile_failed_payload(source, base_source, str(exc), include_fix=include_fix)

    analysis = pass_out["analysis"]
    if pass_out["source_text_used"] != content:
        content = pass_out["source_text_used"]
        base_source["content"] = content

    explain = explain_source(pass_out["source_path_used"])
    diagnostics = diagnose_source(pass_out["source_path_used"])
    learn = learn_source(pass_out["source_path_used"])

    engine_scan = pass_out["engine_scan"]
    display_scan = pass_out["scan"]
    ai_review: dict[str, Any] | None = None
    if include_fix and not source_looks_healed(content):
        ai_review = ai_source_review(pass_out["source_path_used"], language=lang)

    explain_payload = merge_explain_payload(_to_jsonable(explain), display_scan)

    heal_blob: dict[str, Any] | None = None

    payload: dict[str, Any] = {
        "meta": version_report(),
        "vulnerability_catalog": catalog_payload(),
        "source": {
            **base_source,
        },
        "engine_scan": engine_scan,
        "adjudication": pass_out["adjudication"],
        "verification": pass_out["verification"],
        "compile_repair": pass_out["compile_repair"],
        "enrichment": pass_out["enrichment"],
        "scan": display_scan,
        "graph": pass_out["graph"],
        "flow": pass_out["flow"],
        "explain": explain_payload,
        "diagnostics": _to_jsonable(diagnostics),
        "learn": _to_jsonable(learn),
        "fix": None,
        "pipeline": {
            "stages": build_engine_pipeline_stages(
                analysis,
                display_scan,
                engine_scan=engine_scan,
                adjudication=pass_out["adjudication"],
                compile_repair=pass_out["compile_repair"],
                enrichment=pass_out["enrichment"],
                heal=heal_blob,
                diagnostics=_to_jsonable(diagnostics),
                learn=_to_jsonable(learn),
            )
        },
        "compile": {"ok": True},
        "analysis_status": "ok",
    }

    if include_fix:
        from src.V2.heal.catalog_heal import catalog_heal_source

        if source_looks_healed(content):
            payload["fix"] = {
                "status": "SKIPPED",
                "message": (
                    "Source is already marked as healed. Uncheck Catalog heal and run Analyze "
                    "to confirm engine findings only."
                ),
                "command": "catalog_heal",
                "patched_source": content,
            }
        else:
            heal_result = catalog_heal_source(
                source,
                max_ai_attempts=2,
                advisory_issues=(ai_review or {}).get("issues") or [],
            )
            if str(heal_result.get("status", "")).upper() == "VERIFIED":
                patched = ensure_healed_banner(str(heal_result.get("patched_source") or content))
                heal_result = dict(heal_result)
                heal_result["patched_source"] = patched
            payload["fix"] = _to_jsonable(heal_result)
            payload["fix"]["command"] = "catalog_heal"
            heal_blob = payload["fix"]
            patched_src = heal_result.get("patched_source") or content
            if str(heal_result.get("status", "")).upper() == "VERIFIED" and patched_src:
                import tempfile as _tf

                suffix = source.suffix or ".c"
                with _tf.NamedTemporaryFile(
                    mode="w",
                    suffix=suffix,
                    prefix="securecc_heal_",
                    delete=False,
                    encoding="utf-8",
                ) as hf:
                    hf.write(patched_src)
                    heal_path = Path(hf.name)
                try:
                    post = run_engine_pipeline_pass(
                        heal_path, source_text=patched_src, language=lang
                    )
                    payload["post_heal_adjudication"] = post["adjudication"]
                    payload["post_heal_verification"] = post["verification"]
                    payload["post_heal_engine_scan"] = post["engine_scan"]
                    payload["scan"] = post["scan"]
                    payload["verification"] = post["verification"]
                    payload["adjudication"] = post["adjudication"]
                    payload["enrichment"] = post["enrichment"]
                    display_scan = post["scan"]
                    payload["explain"] = merge_explain_payload(
                        payload["explain"], post["scan"]
                    )
                except RuntimeError as exc:
                    payload["post_heal_error"] = str(exc)
                finally:
                    try:
                        heal_path.unlink(missing_ok=True)
                    except OSError:
                        pass
            with tempfile.TemporaryDirectory(prefix="securecc_web_ir_") as tmp:
                try:
                    ir_fix = fix_source(
                        source,
                        output_dir=Path(tmp),
                        keep_ir=True,
                        build_artifact=False,
                    )
                    payload["fix"]["ir_repair"] = _to_jsonable(ir_fix)
                except Exception as exc:
                    payload["fix"]["ir_repair"] = {"status": "SKIPPED", "message": str(exc)}
            payload["pipeline"] = {
                "stages": build_engine_pipeline_stages(
                    analysis,
                    payload["scan"],
                    engine_scan=payload.get("post_heal_engine_scan") or engine_scan,
                    adjudication=payload["adjudication"],
                    compile_repair=pass_out["compile_repair"],
                    enrichment=payload.get("enrichment"),
                    heal=heal_blob,
                    diagnostics=payload.get("diagnostics"),
                    learn=payload.get("learn"),
                )
            }

    from ..program_run import attach_program_run_if_clean
    from ..quality_ratings import build_quality_ratings

    attach_program_run_if_clean(
        payload,
        source_path=Path(pass_out["source_path_used"]),
        source_text=payload.get("source", {}).get("content"),
    )

    try:
        payload["quality_ratings"] = build_quality_ratings(
            source_text=payload.get("source", {}).get("content") or content,
            language=lang,
            source_path=Path(pass_out["source_path_used"]),
            diagnostics=payload.get("diagnostics"),
            scan=payload.get("scan") or {},
            verification=str(payload.get("verification") or ""),
            adjudication=payload.get("adjudication") or {},
            engine_scan=payload.get("post_heal_engine_scan") or engine_scan,
        )
    except Exception as exc:
        payload["quality_ratings"] = {
            "status": "ERROR",
            "message": str(exc)[:300],
            "dimensions": {},
        }

    return payload


def create_app(project_root: Path | None = None) -> Flask:
    root = (project_root or _project_root()).resolve()
    from ..env_loader import load_project_env

    load_project_env(root)
    uploads = _uploads_dir(root)

    app = Flask(
        __name__,
        template_folder=str(Path(__file__).parent / "templates"),
        static_folder=str(Path(__file__).parent / "static"),
        static_url_path="/static",
    )
    app.config["PROJECT_ROOT"] = str(root)
    app.config["MAX_CONTENT_LENGTH"] = 512 * 1024

    @app.route("/")
    def index():
        return render_template("index.html", version=version_report())

    @app.route("/api/vulnerability-catalog")
    def api_vulnerability_catalog():
        from src.V2.detection.catalog import catalog_payload

        return jsonify(catalog_payload())

    @app.route("/api/meta")
    def api_meta():
        clang_ok = False
        try:
            import shutil

            clang_ok = shutil.which("clang") is not None
        except Exception:
            pass
        from ..groq_config import groq_status
        from ..java_ir import javac_available, java_llvm_tool_available

        return jsonify(
            {
                **version_report(),
                "project_root": str(root),
                "clang_available": clang_ok,
                "javac_available": javac_available(),
                "java_llvm_available": java_llvm_tool_available(),
                "supported_languages": list(LANGUAGE_CHOICES),
                "supported_suffixes": sorted(SUPPORTED_SUFFIXES),
                **groq_status(root),
            }
        )

    @app.route("/api/samples")
    def api_samples():
        return jsonify({"samples": _list_samples(root)})

    _EDITOR_DEFAULT = "editor_workspace.c"

    def _check_suffix(name: str) -> None:
        validate_supported_suffix(Path(name).suffix)

    @app.route("/api/source")
    def api_source():
        path_str = request.args.get("path")
        if not path_str:
            return jsonify({"error": "path is required"}), 400
        try:
            source = _resolve_source(str(path_str), root, uploads)
        except ValueError as exc:
            return jsonify({"error": str(exc)}), 400
        if not source.exists():
            return jsonify({"error": f"file not found: {source}"}), 404
        try:
            _check_suffix(source.name)
        except ValueError as exc:
            return jsonify({"error": str(exc)}), 400
        rel = source.relative_to(root).as_posix()
        return jsonify(
            {
                "path": rel,
                "name": source.name,
                "content": source.read_text(encoding="utf-8", errors="replace"),
                "language": language_id_from_suffix(source.suffix),
            }
        )

    @app.route("/api/analyze", methods=["POST"])
    def api_analyze():
        data = request.get_json(silent=True) or {}
        path_str = data.get("path") or request.form.get("path")
        source_text = data.get("source")
        filename = data.get("filename") or _EDITOR_DEFAULT
        language = (data.get("language") or "").strip().lower()
        include_fix = bool(data.get("include_fix", False))

        if source_text is not None:
            if not isinstance(source_text, str):
                return jsonify({"error": "source must be a string"}), 400
            if language:
                filename = workspace_name_for_language(language)
            name = Path(str(filename)).name
            try:
                _check_suffix(name)
            except ValueError as exc:
                return jsonify({"error": str(exc)}), 400
            dest = uploads / name
            dest.write_text(source_text, encoding="utf-8")
            source = dest
        elif path_str:
            try:
                source = _resolve_source(str(path_str), root, uploads)
            except ValueError as exc:
                return jsonify({"error": str(exc)}), 400

            if not source.exists():
                return jsonify({"error": f"file not found: {source}"}), 404
            try:
                _check_suffix(source.name)
            except ValueError as exc:
                return jsonify({"error": str(exc)}), 400
        else:
            return jsonify({"error": "path or source is required"}), 400

        try:
            payload = build_dashboard_payload(source, include_fix=include_fix)
        except Exception as exc:
            return jsonify({"error": str(exc)}), 500

        if isinstance(payload.get("source"), dict):
            payload["source"]["language"] = language_id_from_suffix(source.suffix)
        return jsonify(payload)

    @app.route("/api/analyze/preview", methods=["POST"])
    def api_analyze_preview():
        data = request.get_json(silent=True) or {}
        source_text = data.get("source")
        filename = data.get("filename") or _EDITOR_DEFAULT
        language = (data.get("language") or "").strip().lower()

        if source_text is None or not isinstance(source_text, str):
            return jsonify({"error": "source must be a string"}), 400
        if language:
            filename = workspace_name_for_language(language)
        name = Path(str(filename)).name
        try:
            _check_suffix(name)
        except ValueError as exc:
            return jsonify({"error": str(exc)}), 400
        dest = uploads / name
        dest.write_text(source_text, encoding="utf-8")
        source = dest
        try:
            payload = build_preview_payload(source)
        except Exception as exc:
            return jsonify({"error": str(exc)}), 500
        return jsonify(payload)

    @app.route("/api/lint/live", methods=["POST"])
    def api_live_lint():
        data = request.get_json(silent=True) or {}
        source = data.get("source")
        language = (data.get("language") or "c").strip().lower()
        if not isinstance(source, str):
            return jsonify({"error": "source must be a string"}), 400
        try:
            from ..live_lint import run_live_lint

            return jsonify(run_live_lint(source, language=language))
        except Exception as exc:
            return jsonify({"error": str(exc)}), 500

    @app.route("/api/lint/semantic", methods=["POST"])
    def api_semantic_lint():
        data = request.get_json(silent=True) or {}
        source = data.get("source")
        language = (data.get("language") or "c").strip().lower()
        if not isinstance(source, str):
            return jsonify({"error": "source must be a string"}), 400
        try:
            from ..live_lint import run_live_lint

            return jsonify(run_live_lint(source, language=language))
        except Exception as exc:
            return jsonify({"error": str(exc)}), 500

    @app.route("/api/lint/live/apply", methods=["POST"])
    @app.route("/api/lint/semantic/apply", methods=["POST"])
    def api_live_fix_apply():
        data = request.get_json(silent=True) or {}
        source = data.get("source")
        language = (data.get("language") or "c").strip().lower()
        if not isinstance(source, str):
            return jsonify({"error": "source must be a string"}), 400
        if language == "java":
            return jsonify(
                {
                    "source": source,
                    "applied_count": 0,
                    "applied": [],
                    "note": "Automatic fixes for Java are not available yet.",
                }
            )
        try:
            from ..live_fix import apply_live_fixes

            corrected, applied = apply_live_fixes(source, language=language)
            return jsonify(
                {
                    "source": corrected,
                    "applied_count": len(applied),
                    "applied": applied,
                }
            )
        except Exception as exc:
            return jsonify({"error": str(exc)}), 500

    @app.route("/api/upload", methods=["POST"])
    def api_upload():
        if "file" not in request.files:
            return jsonify({"error": "missing file field"}), 400
        file = request.files["file"]
        if not file.filename:
            return jsonify({"error": "empty filename"}), 400

        name = Path(file.filename).name
        try:
            _check_suffix(name)
        except ValueError as exc:
            return jsonify({"error": str(exc)}), 400

        dest = uploads / name
        file.save(dest)
        rel = dest.relative_to(root).as_posix()
        return jsonify(
            {
                "path": rel,
                "name": name,
                "language": language_id_from_suffix(Path(name).suffix),
            }
        )

    @app.route("/api/journey/start", methods=["POST"])
    def api_journey_start():
        data = request.get_json(silent=True) or {}
        path_str = data.get("path")
        if not path_str:
            return jsonify({"error": "path is required"}), 400
        try:
            source = _resolve_source(str(path_str), root, uploads)
        except ValueError as exc:
            return jsonify({"error": str(exc)}), 400
        if not source.exists():
            return jsonify({"error": f"file not found: {source}"}), 404
        try:
            from .journey import start_journey

            payload = start_journey(source)
        except Exception as exc:
            return jsonify({"error": str(exc)}), 500
        return jsonify(payload)

    @app.route("/api/journey/download")
    def api_journey_download():
        session_id = request.args.get("session_id", "")
        if not session_id:
            return jsonify({"error": "session_id is required"}), 400
        try:
            from .journey import download_content, get_session

            session = get_session(session_id)
            if not session:
                return jsonify({"error": "unknown journey session"}), 404
            name, content = download_content(session)
        except ValueError as exc:
            return jsonify({"error": str(exc)}), 404
        except Exception as exc:
            return jsonify({"error": str(exc)}), 500
        from flask import Response

        return Response(
            content,
            mimetype="text/x-c",
            headers={
                "Content-Disposition": f'attachment; filename="{name}"',
            },
        )

    @app.route("/api/journey/advance", methods=["POST"])
    def api_journey_advance():
        data = request.get_json(silent=True) or {}
        session_id = data.get("session_id")
        action = data.get("action", "continue")
        question = (data.get("question") or data.get("message") or "").strip()
        if not session_id:
            return jsonify({"error": "session_id is required"}), 400
        try:
            from .journey import journey_advance

            payload = journey_advance(session_id, action, question=question)
        except KeyError:
            return jsonify({"error": "unknown journey session"}), 404
        except ValueError as exc:
            return jsonify({"error": str(exc)}), 400
        except Exception as exc:
            return jsonify({"error": str(exc)}), 500
        return jsonify(payload)

    @app.route("/api/chat", methods=["POST"])
    def api_chat():
        data = request.get_json(silent=True) or {}
        message = (data.get("message") or "").strip()
        if not message:
            return jsonify({"error": "message is required"}), 400

        source_text = data.get("source")
        if source_text is not None and not isinstance(source_text, str):
            return jsonify({"error": "source must be a string"}), 400

        path_str = data.get("path")
        filename = data.get("filename") or _EDITOR_DEFAULT
        language = (data.get("language") or "c").strip().lower()
        history = data.get("history") if isinstance(data.get("history"), list) else []
        analysis_context = data.get("analysis_context") if isinstance(data.get("analysis_context"), dict) else None

        if source_text is None:
            if not path_str:
                return jsonify({"error": "source or path is required"}), 400
            try:
                source = _resolve_source(str(path_str), root, uploads)
            except ValueError as exc:
                return jsonify({"error": str(exc)}), 400
            if not source.exists():
                return jsonify({"error": f"file not found: {source}"}), 404
            source_text = source.read_text(encoding="utf-8", errors="replace")
            filename = source.name
            language = language_id_from_suffix(source.suffix)
        elif language:
            filename = workspace_name_for_language(language)

        try:
            from ..code_chat import chat_about_code

            out = chat_about_code(
                message=message,
                source_text=source_text,
                language=language,
                filename=Path(str(filename)).name,
                history=history,
                analysis_context=analysis_context,
            )
        except ValueError as exc:
            return jsonify({"error": str(exc)}), 400
        except RuntimeError as exc:
            return jsonify({"error": str(exc)}), 503
        except Exception as exc:
            return jsonify({"error": str(exc)}), 500

        return jsonify(out)

    @app.route("/api/agent", methods=["POST"])
    def api_agent():
        data = request.get_json(silent=True) or {}
        path_str = data.get("path")
        source_text = data.get("source")
        filename = data.get("filename") or _EDITOR_DEFAULT
        language = (data.get("language") or "").strip().lower()
        message = (data.get("message") or "").strip()

        if not message:
            return jsonify({"error": "message is required"}), 400

        if source_text is not None:
            if not isinstance(source_text, str):
                return jsonify({"error": "source must be a string"}), 400
            if language:
                filename = workspace_name_for_language(language)
            name = Path(str(filename)).name
            try:
                _check_suffix(name)
            except ValueError as exc:
                return jsonify({"error": str(exc)}), 400
            dest = uploads / name
            dest.write_text(source_text, encoding="utf-8")
            source = dest
        elif path_str:
            try:
                source = _resolve_source(str(path_str), root, uploads)
            except ValueError as exc:
                return jsonify({"error": str(exc)}), 400
            if not source.exists():
                return jsonify({"error": f"file not found: {source}"}), 404
        else:
            return jsonify({"error": "path or source is required"}), 400

        try:
            from ..agent import run_agent_session

            session = run_agent_session(
                source=source,
                user_message=message,
                project_root=root,
                model=data.get("model"),
            )
        except Exception as exc:
            return jsonify({"error": str(exc)}), 500

        rel = source.relative_to(root).as_posix()
        session["source_path"] = rel
        return jsonify(session)

    @app.route("/api/aai-security/run", methods=["POST"])
    def api_aai_run():
        try:
            from ..aai_security.runner import run_attack_suite

            report = run_attack_suite(project_root=root)
            return jsonify(report)
        except Exception as exc:
            return jsonify({"error": str(exc)}), 500

    @app.route("/api/aai-security/report")
    def api_aai_report():
        metrics_path = root / "build" / "aai_security" / "metrics.json"
        if not metrics_path.is_file():
            return jsonify({"error": "no report yet; run the attack suite first"}), 404
        try:
            return jsonify(json.loads(metrics_path.read_text(encoding="utf-8")))
        except Exception as exc:
            return jsonify({"error": str(exc)}), 500

    @app.route("/api/aai-security/log")
    def api_aai_log():
        log_path = root / "build" / "aai_security" / "attack_log.jsonl"
        limit = min(int(request.args.get("limit", 40)), 200)
        if not log_path.is_file():
            return jsonify({"entries": [], "path": str(log_path)})
        lines = log_path.read_text(encoding="utf-8").strip().splitlines()
        entries = []
        for line in lines[-limit:]:
            try:
                entries.append(json.loads(line))
            except json.JSONDecodeError:
                entries.append({"raw": line})
        return jsonify({"entries": entries, "path": str(log_path.resolve())})

    @app.route("/docs/visualizations.html")
    def legacy_viz():
        docs = root / "docs" / "visualizations.html"
        if docs.is_file():
            return send_from_directory(docs.parent, docs.name)
        return ("Not found", 404)

    return app


def run_server(
    host: str = "127.0.0.1",
    port: int = 5050,
    debug: bool = False,
    project_root: Path | None = None,
) -> None:
    from ..env_loader import load_project_env

    load_project_env(project_root or _project_root())
    app = create_app(project_root)
    print(f"VulnHGNN SecureCC dashboard: http://{host}:{port}")
    app.run(host=host, port=port, debug=debug, use_reloader=False)
