"""AI-assisted compile error repair (syntax/types) before LLVM IR build."""

from __future__ import annotations

import json
import re
import tempfile
from pathlib import Path
from typing import Any


def ai_compile_repair(
    source_text: str,
    compiler_error: str,
    *,
    language: str = "c",
) -> dict[str, Any]:
    from src.V2.securecc.groq_config import groq_api_key, groq_model

    if not groq_api_key():
        return {
            "status": "SKIPPED",
            "message": "GROQ_API_KEY not set",
            "source": None,
        }
    try:
        from groq import Groq
    except ImportError:
        return {"status": "SKIPPED", "message": "groq not installed", "source": None}

    system = (
        "Fix compile errors only. Return ONLY JSON: "
        '{"status":"OK"|"FAILED","source":"full fixed source","summary":"one line"}. '
        f"Language: {language}. Output must compile. No markdown fences. "
        "Minimal diff: fix errors shown in compiler output, preserve intent."
    )
    user = json.dumps(
        {
            "compiler_error": compiler_error[:8000],
            "source": source_text[:24000],
        },
        indent=0,
    )

    client = Groq(api_key=groq_api_key())
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
        m = re.search(r"\{[\s\S]*\}", raw)
        if not m:
            return {"status": "FAILED", "message": "non-JSON AI response", "source": None}
        data = json.loads(m.group(0))

    if str(data.get("status", "")).upper() != "OK":
        return {
            "status": "FAILED",
            "message": data.get("summary") or "AI could not repair",
            "source": None,
        }
    fixed = data.get("source")
    if not fixed or not str(fixed).strip():
        return {"status": "FAILED", "message": "empty source from AI", "source": None}
    return {
        "status": "OK",
        "message": str(data.get("summary") or "repaired"),
        "source": str(fixed),
    }


def analyze_with_compile_repair(
    source: Path,
    *,
    source_text: str,
    language: str,
    max_attempts: int = 2,
) -> tuple[dict[str, Any], Path, str, dict[str, Any]]:
    """
    Run analyze_source; on compile failure attempt AI repair and retry.
    Returns (analysis, path_used, content_used, compile_repair_meta).
    """
    from src.V2.securecc.analysis import analyze_source

    repairs: list[dict[str, Any]] = []
    path = source
    content = source_text

    try:
        analysis = analyze_source(path)
        return analysis, path, content, {"status": "ok", "attempts": 0, "repairs": repairs}
    except RuntimeError as first_err:
        err = str(first_err)
        for attempt in range(max_attempts):
            fix = ai_compile_repair(content, err, language=language)
            repairs.append(fix)
            if fix.get("status") != "OK" or not fix.get("source"):
                break
            content = fix["source"]
            suffix = source.suffix or ".c"
            with tempfile.NamedTemporaryFile(
                mode="w",
                suffix=suffix,
                prefix="securecc_repair_",
                delete=False,
                encoding="utf-8",
            ) as tmp:
                tmp.write(content)
                path = Path(tmp.name)
            try:
                analysis = analyze_source(path)
                return analysis, path, content, {
                    "status": "repaired",
                    "attempts": attempt + 1,
                    "repairs": repairs,
                }
            except RuntimeError as exc:
                err = str(exc)
        raise RuntimeError(err) from first_err