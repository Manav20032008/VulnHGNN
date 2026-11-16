"""Verify advisory AI review issues cleared after heal (re-run source review)."""

from __future__ import annotations

import re
import tempfile
from pathlib import Path
from typing import Any


_CWE_RE = re.compile(r"^CWE-\d+$", re.I)


def advisory_cwes_from_issues(issues: list[dict[str, Any]] | None) -> set[str]:
    out: set[str] = set()
    for item in issues or []:
        cwe = item.get("cwe_id")
        if not isinstance(cwe, str):
            continue
        cwe = cwe.strip().upper()
        if _CWE_RE.match(cwe):
            out.add(cwe)
    return out


def verify_advisory_cleared(
    original_issues: list[dict[str, Any]] | None,
    patched_source: str,
    *,
    source_suffix: str,
    language: str,
) -> dict[str, Any]:
    """Re-run AI source review on patched code; compare CWE ids to original advisory set."""
    targets = sorted(advisory_cwes_from_issues(original_issues))
    if not targets:
        return {
            "passed": True,
            "target_cwes": [],
            "remaining_cwes": [],
            "per_cwe": {},
            "message": "No advisory CWE targets.",
        }

    from src.V2.securecc.agent.ai_source_review import ai_source_review

    with tempfile.NamedTemporaryFile(
        mode="w",
        encoding="utf-8",
        suffix=source_suffix,
        delete=False,
        prefix="securecc_adv_verify_",
    ) as tmp:
        path = Path(tmp.name)
        path.write_text(patched_source, encoding="utf-8")

    try:
        review = ai_source_review(path, language=language)
    finally:
        path.unlink(missing_ok=True)

    remaining = sorted(advisory_cwes_from_issues(review.get("issues")) & set(targets))
    per = {cwe: cwe not in set(remaining) for cwe in targets}
    passed = len(remaining) == 0
    return {
        "passed": passed,
        "target_cwes": targets,
        "remaining_cwes": remaining,
        "per_cwe": per,
        "message": "Advisory issues cleared after re-review."
        if passed
        else f"Advisory still present: {', '.join(remaining)}",
        "review_status": review.get("status"),
        "issue_count": review.get("issue_count"),
    }
