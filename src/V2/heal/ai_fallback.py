"""Groq-based full-source heal when deterministic patches leave CWEs."""

from __future__ import annotations

import json
import re
from typing import Any


def ai_heal_source(
    source: str,
    *,
    remaining_cwes: list[str],
    findings_summary: list[dict[str, Any]],
    language: str = "cpp",
) -> tuple[str | None, str]:
    from src.V2.securecc.groq_config import groq_api_key, groq_model

    api_key = groq_api_key()
    if not api_key:
        return None, "GROQ_API_KEY not configured"

    try:
        from groq import Groq
    except ImportError:
        return None, "groq package not installed"

    system = (
        'Return ONLY JSON: {"patched_source": "<complete fixed file>"}. '
        f"Language: {language}. Fix ALL listed CWEs using safe idiomatic code. "
        "Preserve includes and overall structure. No markdown."
    )
    user = json.dumps(
        {
            "remaining_cwes": remaining_cwes,
            "findings": findings_summary[:20],
            "original_source": source[:14000],
        },
        indent=2,
    )

    client = Groq(api_key=api_key)
    response = client.chat.completions.create(
        model=groq_model(),
        messages=[
            {"role": "system", "content": system},
            {"role": "user", "content": user},
        ],
        temperature=0.15,
        response_format={"type": "json_object"},
    )
    raw = (response.choices[0].message.content or "").strip()
    try:
        data = json.loads(raw)
    except json.JSONDecodeError:
        match = re.search(r"\{[\s\S]*\}", raw)
        if not match:
            return None, "AI returned non-JSON"
        data = json.loads(match.group(0))

    patched = data.get("patched_source") or data.get("patched_c") or data.get("source")
    if not isinstance(patched, str) or len(patched) < 20:
        return None, "AI JSON missing patched_source"
    return patched, "ok"
