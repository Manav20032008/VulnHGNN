from __future__ import annotations

import hashlib
import tempfile
import time
from pathlib import Path
from typing import Any

from .compile_diagnostics import collect_compiler_diagnostics
from .languages import workspace_name_for_language
from .source_heuristics import scan_source_heuristics
from .semantic.semantic_engine import analyze_semantics, to_local_diagnostic


def _dedupe_key(item: dict[str, Any]) -> tuple[Any, ...]:
    return (
        item.get("source"),
        item.get("line"),
        item.get("column"),
        (item.get("message") or "")[:120],
    )


def _merge_diagnostics(items: list[dict[str, Any]]) -> list[dict[str, Any]]:
    seen: set[tuple[Any, ...]] = set()
    out: list[dict[str, Any]] = []
    for item in sorted(items, key=lambda x: (x.get("line") or 0, x.get("column") or 0)):
        key = _dedupe_key(item)
        if key in seen:
            continue
        seen.add(key)
        out.append(item)
    return out


def _write_temp_source(source: str, language: str) -> Path:
    name = workspace_name_for_language(language)
    suffix = Path(name).suffix
    handle = tempfile.NamedTemporaryFile(
        mode="w",
        encoding="utf-8",
        suffix=suffix,
        prefix="securecc_lint_",
        delete=False,
    )
    handle.write(source)
    handle.flush()
    handle.close()
    return Path(handle.name)


def run_live_lint(source: str, *, language: str) -> dict[str, Any]:
    started = time.perf_counter()
    language = (language or "c").lower()
    if not source or not source.strip():
        return {
            "diagnostics": [],
            "stats": {"matched": 0, "elapsed_ms": 0.0},
            "partial": False,
        }

    items: list[dict[str, Any]] = list(scan_source_heuristics(source, language=language))

    if language != "java":
        try:
            report = analyze_semantics(source)
            items.extend(to_local_diagnostic(d) for d in report.diagnostics)
        except Exception:
            pass
    try:
        path = _write_temp_source(source, language)
        try:
            items.extend(collect_compiler_diagnostics(path))
        finally:
            path.unlink(missing_ok=True)
    except OSError as exc:
        return {
            "diagnostics": _merge_diagnostics(items),
            "stats": {"matched": len(items), "elapsed_ms": 0.0, "error": str(exc)},
            "partial": True,
        }

    merged = _merge_diagnostics(items)
    return {
        "diagnostics": merged,
        "stats": {
            "matched": len(merged),
            "elapsed_ms": round((time.perf_counter() - started) * 1000, 3),
            "source_hash": hashlib.sha1(source.encode("utf-8")).hexdigest(),
        },
        "partial": False,
    }
