"""Post-adjudication agents: CWE classification + user-facing explanations."""

from __future__ import annotations

import json
import re
from typing import Any


def _groq_json(system: str, user: str) -> dict[str, Any] | None:
    from src.V2.securecc.groq_config import groq_api_key, groq_model

    if not groq_api_key():
        return None
    try:
        from groq import Groq
    except ImportError:
        return None
    client = Groq(api_key=groq_api_key())
    response = client.chat.completions.create(
        model=groq_model(),
        messages=[
            {"role": "system", "content": system},
            {"role": "user", "content": user},
        ],
        temperature=0.2,
        response_format={"type": "json_object"},
    )
    raw = (response.choices[0].message.content or "").strip()
    try:
        return json.loads(raw)
    except json.JSONDecodeError:
        m = re.search(r"\{[\s\S]*\}", raw)
        return json.loads(m.group(0)) if m else None


def enrich_confirmed_scan(
    display_scan: dict[str, Any],
    *,
    source_text: str,
    language: str = "c",
) -> tuple[dict[str, Any], dict[str, Any]]:
    """Classifier + explainer on confirmed findings. Returns (updated_scan, enrichment_meta)."""
    findings = list(display_scan.get("findings") or [])
    if not findings:
        return display_scan, {"status": "skipped", "classifier": None, "explainer": None}

    meta: dict[str, Any] = {"status": "complete", "classifier": None, "explainer": None}
    compact = [
        {
            "i": i,
            "cwe_id": f.get("cwe_id"),
            "title": f.get("title"),
            "severity": f.get("severity"),
            "message": (f.get("message") or "")[:400],
            "rationale": f.get("adjudication_rationale", ""),
        }
        for i, f in enumerate(findings)
    ]

    clf = _groq_json(
        'Classify each confirmed finding. JSON: {"items":[{"i":number,"cwe_id":"CWE-XXX",'
        '"severity":"low|medium|high|critical","title":"short"}]}. '
        "Normalize CWE IDs. No new findings.",
        json.dumps({"findings": compact, "source_excerpt": source_text[:12000]}, indent=0),
    )
    if clf and isinstance(clf.get("items"), list):
        meta["classifier"] = {"status": "ok", "count": len(clf["items"])}
        by_i = {int(x.get("i", -1)): x for x in clf["items"] if isinstance(x, dict)}
        for i, f in enumerate(findings):
            u = by_i.get(i)
            if not u:
                continue
            if u.get("cwe_id"):
                f["cwe_id"] = u["cwe_id"]
            if u.get("severity"):
                f["severity"] = u["severity"]
            if u.get("title"):
                f["title"] = u["title"]
    else:
        meta["classifier"] = {"status": "skipped"}

    expl = _groq_json(
        'Explain each finding for developers. JSON: {"explanations":[{"i":number,'
        '"root_cause":"...","security_impact":"...","repair_strategy":"..."}]}. '
        f"Language context: {language}.",
        json.dumps({"findings": compact, "source": source_text[:16000]}, indent=0),
    )
    explanations = list(display_scan.get("explanations") or [])
    if expl and isinstance(expl.get("explanations"), list):
        meta["explainer"] = {"status": "ok", "count": len(expl["explanations"])}
        for item in expl["explanations"]:
            if not isinstance(item, dict):
                continue
            i = int(item.get("i", -1))
            if i < 0 or i >= len(findings):
                continue
            f = findings[i]
            explanations.append(
                {
                    "cwe_id": f.get("cwe_id"),
                    "title": f.get("title"),
                    "severity": f.get("severity"),
                    "root_cause": item.get("root_cause", ""),
                    "security_impact": item.get("security_impact", ""),
                    "repair_strategy": item.get("repair_strategy", ""),
                    "verification": "Re-run Analyze after fix.",
                    "confidence_basis": "AI explanation on adjudicator-confirmed finding.",
                    "evidence": f.get("evidence") or [],
                }
            )
    else:
        meta["explainer"] = {"status": "skipped"}

    out = dict(display_scan)
    out["findings"] = findings
    out["cwes"] = list(dict.fromkeys(str(x.get("cwe_id")) for x in findings if x.get("cwe_id")))
    out["explanations"] = explanations
    return out, meta