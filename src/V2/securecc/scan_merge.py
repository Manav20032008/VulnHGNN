"""Merge supplemental source review hits into scan report (single findings surface)."""

from __future__ import annotations

from typing import Any

# Skip gap-fill after catalog/deterministic heal (avoids Groq re-flagging fixed code).
HEALED_APPLY_BANNER = "/* SecureCC: catalog-healed source — re-analyze without Catalog heal to confirm. */\n"

_HEALED_SOURCE_MARKERS = (
    "/* SecureCC: catalog-healed",
    "/* healed:",
    "/* healed",
    "bounded copy",
    "strncpy(",
    "std::strncpy(",
)


def source_looks_healed(source_text: str) -> bool:
    return bool(source_text and any(m in source_text for m in _HEALED_SOURCE_MARKERS))


def ensure_healed_banner(source_text: str) -> str:
    if not source_text:
        return HEALED_APPLY_BANNER
    if source_looks_healed(source_text):
        return source_text
    return HEALED_APPLY_BANNER + source_text


def should_gap_fill_merge(scan: dict[str, Any], source_text: str = "") -> bool:
    """Only add supplemental findings when the engine is clean and source is not post-heal."""
    if int(scan.get("finding_count") or 0) > 0:
        return False
    if source_text and source_looks_healed(source_text):
        return False
    return True


def build_display_scan(
    engine_scan: dict[str, Any],
    ai_review: dict[str, Any] | None,
    *,
    source_text: str = "",
) -> dict[str, Any]:
    """Engine scan for UI; gap-fill from review only when engine is clean and not healed."""
    base = dict(engine_scan)
    if not should_gap_fill_merge(base, source_text):
        return base
    return merge_ai_review_into_scan(base, ai_review)


def ai_issue_to_finding(issue: dict[str, Any]) -> dict[str, Any]:
    line = issue.get("line")
    fn = f"line {line}" if line else None
    cwe = issue.get("cwe_id")
    if not cwe or str(cwe).lower() in {"null", "none", ""}:
        cwe = "CWE-OTHER"
    return {
        "cwe_id": str(cwe),
        "title": str(issue.get("title") or "Security finding")[:120],
        "severity": str(issue.get("severity") or "medium"),
        "confidence": 0.78,
        "message": str(issue.get("message") or "")[:500],
        "function": fn,
        "instruction": str(issue.get("message") or "—")[:200],
        "evidence": [],
        "detector": "securecc_source",
        "node_id": None,
        "compiler_stage": "source",
        "compiler_stage_label": "Source analysis",
        "line": line,
    }


def _issue_to_explanation(issue: dict[str, Any]) -> dict[str, Any]:
    cwe = issue.get("cwe_id") or "CWE-OTHER"
    msg = str(issue.get("message") or issue.get("title") or "")
    return {
        "cwe_id": str(cwe),
        "title": str(issue.get("title") or "Security finding")[:120],
        "severity": str(issue.get("severity") or "medium"),
        "root_cause": msg[:500],
        "security_impact": msg[:500],
        "repair_strategy": "Remediate at the indicated source location and re-run analysis.",
        "verification": "Re-run SecureCC analysis after applying the fix.",
        "confidence_basis": "Source-level security pattern.",
        "evidence": [],
    }


def merge_ai_review_into_scan(
    scan: dict[str, Any],
    ai_review: dict[str, Any] | None,
) -> dict[str, Any]:
    """Append review issues as normal scan findings (skip CWEs already reported by engine)."""
    out = dict(scan)
    if not ai_review or ai_review.get("status") == "SKIPPED":
        return out

    issues = ai_review.get("issues") or []
    if not issues:
        return out

    findings = list(out.get("findings") or [])
    explanations = list(out.get("explanations") or [])
    engine_cwes = {
        str(f.get("cwe_id") or "").upper()
        for f in findings
        if f.get("cwe_id")
    }
    expl_cwes = {str(e.get("cwe_id") or "").upper() for e in explanations if e.get("cwe_id")}

    for issue in issues:
        if not isinstance(issue, dict):
            continue
        cwe = issue.get("cwe_id")
        if not cwe or str(cwe).lower() in {"null", "none", ""}:
            continue
        key = str(cwe).upper()
        if key in engine_cwes:
            continue
        findings.append(ai_issue_to_finding(issue))
        engine_cwes.add(key)
        if key not in expl_cwes:
            explanations.append(_issue_to_explanation(issue))
            expl_cwes.add(key)

    out["findings"] = findings
    out["finding_count"] = len(findings)
    out["cwes"] = list(
        dict.fromkeys(str(f.get("cwe_id")) for f in findings if f.get("cwe_id"))
    )
    out["explanations"] = explanations
    return out


def merge_explain_payload(
    explain: dict[str, Any],
    merged_scan: dict[str, Any],
) -> dict[str, Any]:
    """Add scan explanations for CWEs missing from the explain command output."""
    out = dict(explain)
    ex_list = list(out.get("explanations") or [])
    known = {str(e.get("cwe_id") or "").upper() for e in ex_list if e.get("cwe_id")}
    for exp in merged_scan.get("explanations") or []:
        key = str(exp.get("cwe_id") or "").upper()
        if key and key not in known:
            ex_list.append(exp)
            known.add(key)
    out["explanations"] = ex_list
    out["finding_count"] = merged_scan.get("finding_count", out.get("finding_count"))
    return out
