"""AI-assisted quality scores (code quality, security, compiler health) for web Analyze."""

from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any

_MAX_SOURCE = 16_000


def _clamp(score: float) -> int:
    return max(0, min(100, int(round(score))))


def _label(score: int) -> str:
    if score >= 90:
        return "Excellent"
    if score >= 75:
        return "Good"
    if score >= 60:
        return "Fair"
    if score >= 40:
        return "Needs work"
    return "Poor"


def _dimension(score: int, summary: str) -> dict[str, Any]:
    return {
        "score": _clamp(score),
        "label": _label(_clamp(score)),
        "summary": (summary or "")[:400],
    }


def _compiler_items(compiler_payload: list[dict] | dict[str, Any] | None) -> list[dict]:
    if not compiler_payload:
        return []
    if isinstance(compiler_payload, list):
        return compiler_payload
    return list(compiler_payload.get("diagnostics") or compiler_payload.get("items") or [])


def _heuristic_scores(
    *,
    compiler_items: list[dict],
    scan: dict[str, Any],
    verification: str,
    adjudication: dict[str, Any],
) -> dict[str, Any]:
    items = compiler_items
    errors = sum(1 for d in items if str(d.get("category", "")).upper() == "ERROR" or d.get("compiler_kind") == "error")
    warnings = sum(1 for d in items if d.get("compiler_kind") == "warning" or str(d.get("category", "")).upper() == "WARNING")
    compiler_score = _clamp(100 - errors * 18 - warnings * 4)

    confirmed = int(scan.get("finding_count") or 0)
    candidates = int(adjudication.get("engine_candidate_count") or scan.get("finding_count") or 0)
    secure_score = _clamp(100 - confirmed * 22 - max(0, candidates - confirmed) * 6)
    if str(verification).upper() == "CLEAN" and confirmed == 0:
        secure_score = max(secure_score, 88)

    code_score = _clamp((compiler_score * 0.35) + (secure_score * 0.65))
    overall = _clamp((compiler_score + secure_score + code_score) / 3)

    return {
        "status": "HEURISTIC",
        "message": "Scores estimated from compiler output and scan results (Groq unavailable).",
        "dimensions": {
            "code_quality": _dimension(
                code_score,
                "Readability and structure inferred from compile health and security posture.",
            ),
            "secure_code": _dimension(
                secure_score,
                f"Verification {verification or '—'} · {confirmed} confirmed · {candidates} engine candidates.",
            ),
            "compiler_diagnostics": _dimension(
                compiler_score,
                f"{errors} error(s), {warnings} warning(s) from the compiler check.",
            ),
        },
        "overall": _dimension(overall, "Composite of quality, security, and compiler health."),
    }


def _parse_groq_ratings(raw: str) -> dict[str, Any] | None:
    try:
        data = json.loads(raw)
    except json.JSONDecodeError:
        m = re.search(r"\{[\s\S]*\}", raw)
        if not m:
            return None
        data = json.loads(m.group(0))

    dims = data.get("dimensions") or data
    out_dims: dict[str, Any] = {}
    for key in ("code_quality", "secure_code", "compiler_diagnostics"):
        block = dims.get(key) or {}
        score = block.get("score", block.get("rating"))
        if score is None:
            continue
        out_dims[key] = _dimension(int(score), str(block.get("summary") or block.get("rationale") or ""))

    if len(out_dims) < 3:
        return None

    overall_block = data.get("overall") or {}
    overall_score = overall_block.get("score")
    if overall_score is None:
        overall_score = sum(d["score"] for d in out_dims.values()) / len(out_dims)
    return {
        "status": "COMPLETE",
        "message": "",
        "dimensions": out_dims,
        "overall": _dimension(int(overall_score), str(overall_block.get("summary") or "AI composite score.")),
    }


def build_quality_ratings(
    *,
    source_text: str,
    language: str,
    source_path: Path | None,
    diagnostics: dict[str, Any] | None,
    scan: dict[str, Any],
    verification: str,
    adjudication: dict[str, Any],
    engine_scan: dict[str, Any] | None,
) -> dict[str, Any]:
    compiler_items: list[dict] = []
    if source_path and source_path.is_file():
        try:
            from src.V2.securecc.compile_diagnostics import collect_compiler_diagnostics

            compiler_items = collect_compiler_diagnostics(source_path)
        except Exception:
            compiler_items = []

    context = {
        "language": language,
        "verification": verification,
        "confirmed_findings": scan.get("finding_count"),
        "cwes": scan.get("cwes"),
        "engine_candidates": (adjudication or {}).get("engine_candidate_count"),
        "compiler_diagnostics": compiler_items[:25],
        "security_diagnostics_count": len((diagnostics or {}).get("diagnostics") or []),
        "engine_finding_count": (engine_scan or {}).get("finding_count"),
    }

    from src.V2.securecc.groq_config import groq_api_key, groq_model

    api_key = groq_api_key()
    if not api_key:
        out = _heuristic_scores(
            compiler_items=compiler_items,
            scan=scan,
            verification=verification,
            adjudication=adjudication or {},
        )
        out["context"] = context
        return out

    try:
        from groq import Groq
    except ImportError:
        out = _heuristic_scores(
            compiler_items=compiler_items,
            scan=scan,
            verification=verification,
            adjudication=adjudication or {},
        )
        out["message"] = "Install groq package for AI quality ratings."
        out["context"] = context
        return out

    system = (
        "You rate C/C++/Java student or lab code for a security workbench. "
        "Return ONLY JSON with this shape: "
        '{"dimensions":{"code_quality":{"score":0-100,"summary":"one sentence"},'
        '"secure_code":{"score":0-100,"summary":"one sentence"},'
        '"compiler_diagnostics":{"score":0-100,"summary":"one sentence"}},'
        '"overall":{"score":0-100,"summary":"one short sentence"}}. '
        "Scores are integers 0-100 (higher is better). "
        "code_quality: clarity, structure, maintainability, idiomatic use. "
        "secure_code: vulnerability risk using scan/adjudication context (lower score if issues likely). "
        "compiler_diagnostics: how clean the build is (errors/warnings). "
        "Use the pipeline context; do not invent CWEs not in context."
    )
    user_body = {
        "source": (source_text or "")[:_MAX_SOURCE],
        "pipeline_context": context,
    }

    try:
        client = Groq(api_key=api_key)
        response = client.chat.completions.create(
            model=groq_model(),
            messages=[
                {"role": "system", "content": system},
                {"role": "user", "content": json.dumps(user_body, indent=0)},
            ],
            temperature=0.2,
            response_format={"type": "json_object"},
        )
        raw = (response.choices[0].message.content or "").strip()
        parsed = _parse_groq_ratings(raw)
        if parsed:
            parsed["context"] = context
            return parsed
    except Exception as exc:
        out = _heuristic_scores(
            compiler_items=compiler_items,
            scan=scan,
            verification=verification,
            adjudication=adjudication or {},
        )
        out["status"] = "FALLBACK"
        out["message"] = str(exc)[:300]
        out["context"] = context
        return out

    out = _heuristic_scores(
        compiler_items=compiler_items,
        scan=scan,
        verification=verification,
        adjudication=adjudication or {},
    )
    out["status"] = "FALLBACK"
    out["message"] = "Could not parse AI ratings."
    out["context"] = context
    return out