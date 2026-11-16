from __future__ import annotations

import json
import os
import re
from typing import Any

from .prompts import SYSTEM_PROMPT


def _extract_json(text: str) -> dict[str, Any]:
    text = text.strip()
    try:
        return json.loads(text)
    except json.JSONDecodeError:
        match = re.search(r"\{[\s\S]*\}", text)
        if match:
            return json.loads(match.group(0))
        raise


def plan_next_step(
    *,
    user_message: str,
    source_path: str,
    history: list[dict[str, Any]],
    model_name: str | None = None,
) -> dict[str, Any]:
    api_key = os.environ.get("GROQ_API_KEY")
    if not api_key:
        raise RuntimeError(
            "AI analysis is not configured on the server. "
            "Set the required API key in the server environment (see README)."
        )

    try:
        from groq import Groq
    except ImportError:
        raise RuntimeError(
            "AI analysis dependencies are missing on the server. "
            "Install project requirements (see README)."
        ) from None

    model_id = model_name or os.environ.get(
        "GROQ_MODEL", "openai/gpt-oss-120b"
    )

    context = {
        "source_file": source_path,
        "user_message": user_message,
        "prior_steps": history[-6:],
    }

    prompt = (
        "Given the context JSON below, choose the next action.\n"
        f"{json.dumps(context, indent=2)}"
    )

    client = Groq(api_key=api_key)
    response = client.chat.completions.create(
        model=model_id,
        messages=[
            {"role": "system", "content": SYSTEM_PROMPT},
            {"role": "user", "content": prompt},
        ],
        temperature=0.2,
        response_format={"type": "json_object"},
    )

    raw = (response.choices[0].message.content or "").strip()
    return _extract_json(raw)
