"""AI adjudication of HGNN engine candidates against source (final user-facing findings)."""

from __future__ import annotations

import json
import re
from typing import Any

MAX_CANDIDATES = 30


def _evidence_snippet(finding: dict[str, Any], limit: int = 240) -> str:
    ev = finding.get("evidence") or []
    if not isinstance(ev, list) or not ev:
        msg = (finding.get("message") or finding.get("instruction") or "")[:limit]
        return msg
    parts = []
    for step in ev[:4]:
        if isinstance(step, dict):
            bits = [
                step.get("relation"),
                step.get("node_id"),
                (step.get("description") or step.get("text") or "")[:80],
            ]
            parts.append(" ".join(str(b) for b in bits if b))
        else:
            parts.append(str(step)[:80])
    return " | ".join(parts)[:limit]


def _compact_candidates(findings: list[dict[str, Any]]) -> list[dict[str, Any]]:
    out = []
    for i, f in enumerate(findings[:MAX_CANDIDATES]):
        out.append(
            {
                "id": i,
                "cwe_id": f.get("cwe_id"),
                "title": (f.get("title") or "")[:120],
                "severity": f.get("severity"),
                "confidence": f.get("confidence"),
                "function": f.get("function"),
                "node_id": f.get("node_id"),
                "message": (f.get("message") or "")[:400],
                "evidence": _evidence_snippet(f),
            }
        )
    return out


def _parse_decisions(raw: str) -> list[dict[str, Any]]:
    try:
        data = json.loads(raw)
    except json.JSONDecodeError:
        m = re.search(r"\{[\s\S]*\}", raw)
        if not m:
            return []
        data = json.loads(m.group(0))
    decisions = data.get("decisions") or data.get("findings") or []
    if not isinstance(decisions, list):
        return []
    cleaned = []
    for d in decisions:
        if not isinstance(d, dict):
            continue
        vid = str(d.get("verdict") or d.get("status") or "").upper()
        if vid not in {"CONFIRMED", "REJECTED", "INCONCLUSIVE"}:
            continue
        cleaned.append(
            {
                "id": int(d.get("id", d.get("candidate_id", -1))),
                "verdict": vid,
                "rationale": str(d.get("rationale") or d.get("reason") or "")[:500],
                "cwe_id": d.get("cwe_id"),
            }
        )
    return cleaned


def _apply_decisions(
    engine_scan: dict[str, Any],
    decisions: list[dict[str, Any]],
) -> tuple[dict[str, Any], dict[str, Any]]:
    findings = list(engine_scan.get("findings") or [])
    by_id = {d["id"]: d for d in decisions if d.get("id", -1) >= 0}

    confirmed: list[dict[str, Any]] = []
    rejected: list[dict[str, Any]] = []
    inconclusive: list[dict[str, Any]] = []

    for i, f in enumerate(findings[:MAX_CANDIDATES]):
        dec = by_id.get(i)
        if not dec:
            inconclusive.append({**f, "adjudication_verdict": "INCONCLUSIVE", "adjudication_rationale": "No AI verdict"})
            continue
        verdict = dec["verdict"]
        enriched = {
            **f,
            "adjudication_verdict": verdict,
            "adjudication_rationale": dec.get("rationale", ""),
        }
        if verdict == "CONFIRMED":
            confirmed.append(enriched)
        elif verdict == "REJECTED":
            rejected.append(enriched)
        else:
            inconclusive.append(enriched)

    for i, f in enumerate(findings[MAX_CANDIDATES:], MAX_CANDIDATES):
        inconclusive.append({**f, "adjudication_verdict": "INCONCLUSIVE", "adjudication_rationale": "Not reviewed (cap)"})

    confirmed_cwes = list(dict.fromkeys(str(x.get("cwe_id")) for x in confirmed if x.get("cwe_id")))
    display = dict(engine_scan)
    display["findings"] = confirmed
    display["finding_count"] = len(confirmed)
    display["cwes"] = confirmed_cwes

    conf_keys = {str(x.get("cwe_id")).upper() for x in confirmed if x.get("cwe_id")}
    loc = []
    for item in engine_scan.get("localization") or []:
        cwe = str(item.get("cwe_id") or "").upper()
        if cwe and cwe in conf_keys:
            loc.append(item)
    display["localization"] = loc

    expl = []
    for item in engine_scan.get("explanations") or []:
        cwe = str(item.get("cwe_id") or "").upper()
        if cwe and cwe in conf_keys:
            expl.append(item)
    display["explanations"] = expl

    meta = {
        "engine_candidate_count": len(findings),
        "confirmed_count": len(confirmed),
        "rejected_count": len(rejected),
        "inconclusive_count": len(inconclusive),
        "confirmed": confirmed,
        "rejected": rejected,
        "inconclusive": inconclusive,
        "decisions": decisions,
    }
    return display, meta


def _verification_label(meta: dict[str, Any], status: str) -> str:
    if status == "SKIPPED":
        return "PARTIAL"
    if meta["inconclusive_count"] > 0:
        return "PARTIAL"
    if meta["confirmed_count"] == 0:
        return "CLEAN"
    return "FINDINGS"


def adjudicate_engine_scan(
    engine_scan: dict[str, Any],
    *,
    source_text: str,
    language: str = "c",
) -> dict[str, Any]:
    """Return {display_scan, meta, verification}."""
    findings = list(engine_scan.get("findings") or [])
    if not findings:
        display = dict(engine_scan)
        return {
            "display_scan": display,
            "meta": {
                "status": "COMPLETE",
                "engine_candidate_count": 0,
                "confirmed_count": 0,
                "rejected_count": 0,
                "inconclusive_count": 0,
                "confirmed": [],
                "rejected": [],
                "inconclusive": [],
                "decisions": [],
            },
            "verification": "CLEAN",
        }

    from src.V2.securecc.groq_config import groq_api_key, groq_model

    api_key = groq_api_key()
    if not api_key:
        display, meta = _apply_decisions(engine_scan, [])
        meta["status"] = "SKIPPED"
        meta["message"] = "GROQ_API_KEY not set — showing 0 confirmed; engine candidates preserved for review."
        meta["engine_only_scan"] = dict(engine_scan)
        display["findings"] = []
        display["finding_count"] = 0
        display["cwes"] = []
        display["localization"] = []
        display["explanations"] = []
        return {
            "display_scan": display,
            "meta": meta,
            "verification": "PARTIAL",
        }

    try:
        from groq import Groq
    except ImportError:
        display, meta = _apply_decisions(engine_scan, [])
        meta["status"] = "SKIPPED"
        meta["message"] = "groq package not installed"
        meta["engine_only_scan"] = dict(engine_scan)
        display["findings"] = []
        display["finding_count"] = 0
        display["cwes"] = []
        display["localization"] = []
        display["explanations"] = []
        return {
            "display_scan": display,
            "meta": meta,
            "verification": "PARTIAL",
        }

    candidates = _compact_candidates(findings)
    system = (
        "You are the final security adjudicator for a static analysis pipeline. "
        "The HGNN engine produced CANDIDATE findings with IR evidence. "
        "Compare each candidate to the FULL source. "
        'Return ONLY JSON: {"decisions":[{"id":number,"verdict":"CONFIRMED"|"REJECTED"|"INCONCLUSIVE",'
        '"cwe_id":"CWE-XXX|null","rationale":"one sentence"}]}. '
        "CONFIRMED only if the vulnerability is genuinely present in source (reachable, not a false positive). "
        "REJECTED if the pattern is a false alarm, guarded, dead code, or test_01_clean-style safe code. "
        "INCONCLUSIVE only if evidence is insufficient. "
        "Be strict on non-vulnerable code: prefer REJECTED over CONFIRMED when unsure is false positive. "
        f"Language: {language}. One decision per candidate id. No markdown."
    )
    user_payload = {
        "source": source_text[:20000],
        "candidates": candidates,
    }

    client = Groq(api_key=api_key)
    response = client.chat.completions.create(
        model=groq_model(),
        messages=[
            {"role": "system", "content": system},
            {"role": "user", "content": json.dumps(user_payload, indent=0)},
        ],
        temperature=0.1,
        response_format={"type": "json_object"},
    )
    raw = (response.choices[0].message.content or "").strip()
    decisions = _parse_decisions(raw)
    display, meta = _apply_decisions(engine_scan, decisions)
    meta["status"] = "COMPLETE"
    verification = _verification_label(meta, "COMPLETE")
    return {
        "display_scan": display,
        "meta": meta,
        "verification": verification,
    }