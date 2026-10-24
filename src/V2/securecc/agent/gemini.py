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
    api_key = os.environ.get("GEMINI_API_KEY") or os.environ.get("GOOGLE_API_KEY")
    if not api_key:
        raise RuntimeError(
            "Set GEMINI_API_KEY (or GOOGLE_API_KEY) to use the Gemini agent."
        )

    try:
        import google.generativeai as genai
    except ImportError:
        raise RuntimeError(
            "Install the Gemini SDK: python -m pip install google-generativeai"
        ) from None

    genai.configure(api_key=api_key)
    model_id = model_name or os.environ.get("GEMINI_MODEL", "gemini-2.0-flash")

    model = genai.GenerativeModel(
        model_id,
        system_instruction=SYSTEM_PROMPT,
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

    response = model.generate_content(
        prompt,
        generation_config=genai.GenerationConfig(
            temperature=0.2,
            response_mime_type="application/json",
        ),
    )

    raw = (response.text or "").strip()
    return _extract_json(raw)
