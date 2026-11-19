"""Lightweight Groq chat grounded in the current editor source and optional analysis."""

from __future__ import annotations

import json
from typing import Any

_MAX_SOURCE = 28_000
_MAX_MSG = 8_000
_MAX_HISTORY = 16
_MAX_ANALYSIS_JSON = 12_000


def _trim(text: str, limit: int) -> str:
    text = (text or "").strip()
    if len(text) <= limit:
        return text
    return text[:limit] + "\n… [truncated]"


def _normalize_history(history: list[Any]) -> list[dict[str, str]]:
    if not isinstance(history, list):
        return []
    out: list[dict[str, str]] = []
    for item in history[-_MAX_HISTORY:]:
        if not isinstance(item, dict):
            continue
        role = (item.get("role") or "").strip().lower()
        if role not in {"user", "assistant"}:
            continue
        content = _trim(str(item.get("content") or ""), _MAX_MSG)
        if not content:
            continue
        out.append({"role": role, "content": content})
    return out


def _analysis_block(analysis_context: dict[str, Any] | None) -> str:
    if not analysis_context:
        return "No SecureCC analysis has been run yet for this session."
    try:
        blob = json.dumps(analysis_context, indent=2, default=str)
    except (TypeError, ValueError):
        blob = str(analysis_context)
    return _trim(blob, _MAX_ANALYSIS_JSON)


def chat_about_code(
    *,
    message: str,
    source_text: str,
    language: str,
    filename: str,
    history: list[dict[str, Any]] | None = None,
    analysis_context: dict[str, Any] | None = None,
) -> dict[str, Any]:
    from src.V2.securecc.groq_config import groq_api_key, groq_model

    user_message = _trim(message, _MAX_MSG)
    if not user_message:
        raise ValueError("message is required")

    api_key = groq_api_key()
    if not api_key:
        raise RuntimeError(
            "Groq is not configured. Set GROQ_API_KEY in .env and restart the web server."
        )

    try:
        from groq import Groq
    except ImportError as exc:
        raise RuntimeError("Install the groq package: pip install groq") from exc

    lang = (language or "c").strip().lower()
    name = (filename or "source").strip() or "source"
    source_block = _trim(source_text or "", _MAX_SOURCE)
    if not source_block:
        source_block = "(empty editor)"

    system = (
        "You are SecureCC Code Assistant in the VulnHGNN workbench. "
        "Your reader is often a beginner: use warm, clear language and avoid jargon unless you briefly define it. "
        "Format answers as clean Markdown that will be rendered in a chat UI: "
        "use ## for section titles (not long **bold** lines), short paragraphs, and simple bullet lists. "
        "Put multi-line code in fenced blocks with a language tag (e.g. ```cpp). "
        "Use inline `code` only for identifiers or one-liners. "
        "Do not use markdown tables, horizontal rules (---), or ASCII art. "
        "Prefer a short summary first, then details. "
        "Answer about the user's source, security, bugs, and SecureCC/HGNN analysis when provided. "
        "If you cite vulnerabilities, include CWE IDs when known. "
        "Never invent analysis results that are not in the analysis context."
    )

    context_user = (
        f"File: {name}\n"
        f"Language: {lang}\n\n"
        f"Source code:\n{source_block}\n\n"
        f"SecureCC analysis context (JSON; may be empty):\n{_analysis_block(analysis_context)}"
    )

    messages: list[dict[str, str]] = [
        {"role": "system", "content": system},
        {"role": "user", "content": context_user},
        {"role": "assistant", "content": "Understood. I have the source and any analysis context. Ask your question."},
    ]
    messages.extend(_normalize_history(history))
    messages.append({"role": "user", "content": user_message})

    model = groq_model()
    client = Groq(api_key=api_key)
    response = client.chat.completions.create(
        model=model,
        messages=messages,
        temperature=0.35,
        max_tokens=2048,
    )
    choice = response.choices[0].message if response.choices else None
    reply = (choice.content or "").strip() if choice else ""
    if not reply:
        raise RuntimeError("Empty response from model")

    usage = None
    if getattr(response, "usage", None):
        usage = {
            "prompt_tokens": getattr(response.usage, "prompt_tokens", None),
            "completion_tokens": getattr(response.usage, "completion_tokens", None),
        }

    return {
        "reply": reply,
        "model": model,
        "usage": usage,
    }