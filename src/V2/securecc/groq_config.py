from __future__ import annotations

import os
from pathlib import Path
from typing import Any

_PLACEHOLDER_KEYS = frozenset(
    {
        "",
        "gsk_your_key_here",
        "your_key_here",
        "changeme",
    }
)


def groq_api_key() -> str | None:
    raw = (os.environ.get("GROQ_API_KEY") or "").strip()
    if not raw or raw in _PLACEHOLDER_KEYS or raw.startswith("gsk_your"):
        return None
    return raw


def groq_model() -> str:
    return (os.environ.get("GROQ_MODEL") or "openai/gpt-oss-120b").strip()


def groq_status(project_root: Path | None = None) -> dict[str, Any]:
    """Diagnostics for dashboard / journey (no secret values)."""
    from .env_loader import find_project_root, load_project_env

    root = find_project_root(project_root)
    env_path = root / ".env"
    loaded = load_project_env(root)

    key = groq_api_key()
    has_dotenv = False
    try:
        import dotenv  # noqa: F401

        has_dotenv = True
    except ImportError:
        pass

    groq_pkg = False
    try:
        import groq  # noqa: F401

        groq_pkg = True
    except ImportError:
        pass

    reason = "ok"
    hint = ""
    raw_key = (os.environ.get("GROQ_API_KEY") or "").strip()
    if not key:
        reason = "missing_key"
        if raw_key and (raw_key in _PLACEHOLDER_KEYS or raw_key.startswith("gsk_your")):
            hint = "Replace the placeholder in .env with your real Groq key (gsk_...), then restart securecc web."
        elif env_path.is_file():
            text = env_path.read_text(encoding="utf-8", errors="replace")
            if "GROQ_API_KEY" in text and not any(
                line.strip().startswith("GROQ_API_KEY=") and not line.strip().startswith("#")
                for line in text.splitlines()
            ):
                hint = (
                    "GROQ_API_KEY is in .env but commented out. "
                    "Use GROQ_API_KEY=gsk_... with no # at the start of that line."
                )
            else:
                hint = "Set GROQ_API_KEY=gsk_... in project .env, then restart securecc web."
        else:
            hint = f"Create {env_path} with GROQ_API_KEY=gsk_... and restart the server."
    elif not groq_pkg:
        reason = "no_package"
        hint = "Run: pip install groq"
    elif not has_dotenv:
        hint = "Optional: pip install python-dotenv to load .env automatically."

    return {
        "groq_configured": bool(key and groq_pkg),
        "groq_reason": reason,
        "groq_hint": hint,
        "groq_model": groq_model() if key else None,
        "env_file": str(env_path) if env_path.is_file() else None,
        "env_loaded": loaded is not None,
        "project_root": str(root),
    }
