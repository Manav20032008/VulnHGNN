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
        for path in sorted(test_dir.glob("test_*.c")):
            rel = path.relative_to(root).as_posix()
            samples.append({"id": rel, "label": path.name, "path": rel})
    return samples


def build_dashboard_payload(source: Path, *, include_fix: bool) -> dict[str, Any]:
    analysis = analyze_source(source)
    bundle = analysis_bundle(analysis)

    explain = explain_source(source)
    diagnostics = diagnose_source(source)
    learn = learn_source(source)

    payload: dict[str, Any] = {
        "meta": version_report(),
        "source": {
            "path": str(source),
            "name": source.name,
            "content": source.read_text(encoding="utf-8", errors="replace"),
        },
        "scan": bundle["scan"],
        "graph": bundle["graph"],
        "explain": _to_jsonable(explain),
        "diagnostics": _to_jsonable(diagnostics),
        "learn": _to_jsonable(learn),
        "fix": None,
    }

    if include_fix:
        with tempfile.TemporaryDirectory(prefix="securecc_web_") as tmp:
            fix_result = fix_source(
                source,
                output_dir=Path(tmp),
                keep_ir=True,
                build_artifact=True,
            )
            payload["fix"] = _to_jsonable(fix_result)

    return payload


def create_app(project_root: Path | None = None) -> Flask:
    root = (project_root or _project_root()).resolve()
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

    @app.route("/api/meta")
    def api_meta():
        clang_ok = False
        try:
            import shutil

            clang_ok = shutil.which("clang") is not None
        except Exception:
            pass
        return jsonify(
            {
                **version_report(),
                "project_root": str(root),
                "clang_available": clang_ok,
            }
        )

    @app.route("/api/samples")
    def api_samples():
        return jsonify({"samples": _list_samples(root)})

    @app.route("/api/analyze", methods=["POST"])
    def api_analyze():
        data = request.get_json(silent=True) or {}
        path_str = data.get("path") or request.form.get("path")
        include_fix = bool(data.get("include_fix", False))

        if not path_str:
            return jsonify({"error": "path is required"}), 400

        try:
            source = _resolve_source(str(path_str), root, uploads)
        except ValueError as exc:
            return jsonify({"error": str(exc)}), 400

        if not source.exists():
            return jsonify({"error": f"file not found: {source}"}), 404
        if source.suffix.lower() not in {".c", ".cc", ".cpp", ".cxx"}:
            return jsonify({"error": "only C/C++ source files are supported"}), 400

        try:
            payload = build_dashboard_payload(source, include_fix=include_fix)
        except Exception as exc:
            return jsonify({"error": str(exc)}), 500

        return jsonify(payload)

    @app.route("/api/upload", methods=["POST"])
    def api_upload():
        if "file" not in request.files:
            return jsonify({"error": "missing file field"}), 400
        file = request.files["file"]
        if not file.filename:
            return jsonify({"error": "empty filename"}), 400

        name = Path(file.filename).name
        if Path(name).suffix.lower() not in {".c", ".cc", ".cpp", ".cxx"}:
            return jsonify({"error": "only C/C++ source files are supported"}), 400

        dest = uploads / name
        file.save(dest)
        rel = dest.relative_to(root).as_posix()
        return jsonify({"path": rel, "name": name})

    @app.route("/api/agent", methods=["POST"])
    def api_agent():
        data = request.get_json(silent=True) or {}
        path_str = data.get("path")
        message = (data.get("message") or "").strip()

        if not path_str or not message:
            return jsonify({"error": "path and message are required"}), 400

        try:
            source = _resolve_source(str(path_str), root, uploads)
        except ValueError as exc:
            return jsonify({"error": str(exc)}), 400

        if not source.exists():
            return jsonify({"error": f"file not found: {source}"}), 404

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
    app = create_app(project_root)
    print(f"VulnHGNN SecureCC dashboard: http://{host}:{port}")
    app.run(host=host, port=port, debug=debug, use_reloader=False)
