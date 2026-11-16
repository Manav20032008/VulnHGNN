from __future__ import annotations

import json
import tempfile
from pathlib import Path
from typing import Any

from ..analysis import analyze_source
from ..diagnostics import diagnose_source
from ..explain import explain_source
from ..fix import fix_source
from ..learn import learn_source
from ..scan import build_report


def _jsonable(obj: Any) -> Any:
    if hasattr(obj, "to_dict"):
        return obj.to_dict()
    if isinstance(obj, dict):
        return {k: _jsonable(v) for k, v in obj.items()}
    if isinstance(obj, (list, tuple)):
        return [_jsonable(x) for x in obj]
    if isinstance(obj, (str, int, float, bool)) or obj is None:
        return obj
    return str(obj)


def run_tool(
    tool: str,
    source: Path,
    *,
    advisory_issues: list[dict[str, Any]] | None = None,
) -> dict[str, Any]:
    tool = tool.strip().lower()
    source = Path(source).resolve()

    if not source.exists():
        raise FileNotFoundError(f"source not found: {source}")

    if tool == "scan":
        analysis = analyze_source(source)
        report = build_report(analysis)
        return {
            "tool": "scan",
            "finding_count": report["finding_count"],
            "cwes": report["cwes"],
            "findings": report["findings"][:10],
            "status": "CLEAN" if report["finding_count"] == 0 else "FINDINGS",
        }

    if tool == "explain":
        result = explain_source(source)
        explanations = [_jsonable(x) for x in result.get("explanations", [])]
        return {
            "tool": "explain",
            "finding_count": result.get("finding_count", 0),
            "cwes": result.get("cwes", []),
            "explanations": explanations,
        }

    if tool == "diagnose":
        result = diagnose_source(source)
        return _jsonable(result)

    if tool == "learn":
        result = learn_source(source)
        return _jsonable(result)

    if tool == "fix":
        with tempfile.TemporaryDirectory(prefix="securecc_agent_fix_") as tmp:
            result = fix_source(
                source,
                output_dir=Path(tmp),
                keep_ir=True,
                build_artifact=True,
            )
            payload = _jsonable(result)
            payload["tool"] = "fix"
            return payload

    if tool == "catalog_heal":
        from src.V2.heal.catalog_heal import catalog_heal_source

        result = catalog_heal_source(
            source,
            max_ai_attempts=2,
            advisory_issues=advisory_issues or [],
        )
        payload = _jsonable(result)
        payload["tool"] = "catalog_heal"
        return payload

    if tool == "ai_source_review":
        from .ai_source_review import ai_source_review as run_ai_review
        from ..languages import language_id_from_suffix

        lang = language_id_from_suffix(source.suffix)
        payload = run_ai_review(source, language=lang)
        return payload

    if tool == "rescan":
        return run_tool("scan", source)

    raise ValueError(f"unknown tool: {tool}")
