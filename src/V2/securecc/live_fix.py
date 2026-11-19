from __future__ import annotations

from typing import Any

from .semantic.semantic_engine import analyze_semantics, apply_safe_fixes
from .source_fixes import apply_edits, collect_template_fixes


def apply_live_fixes(source: str, *, language: str) -> tuple[str, list[dict[str, Any]]]:
    """
    Apply conservative automatic fixes for live lint issues:
    - Semantic HIGH-confidence type renames
    - printf(identifier) → printf("%d", identifier)
    - gets(buf) → fgets (single-line)
    - Required includes when those edits apply
    """
    language = (language or "c").lower()
    if language == "java":
        return source, []

    applied: list[dict[str, Any]] = []
    corrected = source

    report = analyze_semantics(corrected)
    corrected, sem_applied = apply_safe_fixes(corrected, report, only_high=True)
    for diagnostic in sem_applied:
        applied.append(
            {
                "kind": "semantic",
                "line": diagnostic.line,
                "description": f'Use `{diagnostic.suggested_type}` for `{diagnostic.variable}`',
            }
        )

    template_edits, template_meta = collect_template_fixes(corrected, language=language)
    if template_edits:
        next_source = apply_edits(corrected, template_edits)
        if next_source != corrected:
            corrected = next_source
            applied.extend(template_meta)

    return corrected, applied
