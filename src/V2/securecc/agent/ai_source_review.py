"""Groq advisory review of source text (not verified by SecureCC engine)."""

from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any


def ai_source_review(source: Path, *, language: str = "c") -> dict[str, Any]:
    from src.V2.securecc.groq_config import groq_api_key, groq_model

    text = source.read_text(encoding="utf-8", errors="replace")
    api_key = groq_api_key()
    if not api_key:
        return {
            "tool": "ai_source_review",
            "status": "SKIPPED",
            "message": "GROQ_API_KEY not configured",
            "issues": [],
            "issue_count": 0,
        }

    try:
        from groq import Groq
    except ImportError:
        return {
            "tool": "ai_source_review",
            "status": "SKIPPED",
            "message": "groq package not installed",
            "issues": [],
            "issue_count": 0,
        }

    system = (
        'Return ONLY JSON: {"issues": ['
        '{"severity":"low|medium|high","cwe_id":"CWE-XXX or null","line":number or null,'
        '"title":"short","message":"why it matters"}]}. '
        f"Language: {language}. Review for security bugs, undefined behavior, and common CWE patterns. "
        "Do not claim code is verified or safe. Max 8 issues. No markdown."
    )
    user = json.dumps(
        {
            "filename": source.name,
            "source": text[:16000],
        },
        indent=0,
    )

    client = Groq(api_key=api_key)
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
        data = json.loads(raw)
    except json.JSONDecodeError:
        match = re.search(r"\{[\s\S]*\}", raw)
        if not match:
            return {
                "tool": "ai_source_review",
                "status": "ERROR",
                "message": "AI returned non-JSON",
                "issues": [],
                "issue_count": 0,
            }
        data = json.loads(match.group(0))

    issues = data.get("issues") or []
    if not isinstance(issues, list):
        issues = []
    cleaned: list[dict[str, Any]] = []
    for item in issues[:8]:
        if not isinstance(item, dict):
            continue
        cleaned.append(
            {
                "severity": str(item.get("severity") or "medium"),
                "cwe_id": item.get("cwe_id"),
                "line": item.get("line"),
                "title": str(item.get("title") or "Issue")[:120],
                "message": str(item.get("message") or "")[:500],
            }
        )

    return {
        "tool": "ai_source_review",
        "status": "OK",
        "message": f"{len(cleaned)} advisory issue(s)",
        "issues": cleaned,
        "issue_count": len(cleaned),
    }
