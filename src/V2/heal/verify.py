"""Re-scan verification after catalog heal."""

from __future__ import annotations

import tempfile
from pathlib import Path

from src.V2.localization.models import ValidationResult


def _cwe_set_from_analysis(analysis: dict) -> set[str]:
    return {f.cwe_id for f in analysis.get("findings") or []}


def _is_internal_fn(function: str) -> bool:
    fn = function or ""
    if fn.startswith("_ZNSt3__") or fn.startswith("_ZNKSt3__"):
        return True
    if fn.startswith("__clang") or fn == "__clang_call_terminate":
        return True
    return False


def _user_target_cwes(analysis: dict, targets: set[str]) -> set[str]:
    """Catalog CWEs still present in user code (exclude libc++ / compiler glue)."""
    out: set[str] = set()
    for f in analysis.get("findings") or []:
        if f.cwe_id not in targets or _is_internal_fn(f.function):
            continue
        out.add(f.cwe_id)
    return out


def verify_patched_source(
    original_analysis: dict,
    patched_source: str,
    *,
    source_suffix: str,
    target_cwes: set[str] | None = None,
) -> ValidationResult:
    from src.V2.securecc.analysis import analyze_source

    original_cwes = sorted(_cwe_set_from_analysis(original_analysis))
    targets = set(target_cwes) if target_cwes else set(original_cwes)

    with tempfile.NamedTemporaryFile(
        mode="w",
        encoding="utf-8",
        suffix=source_suffix,
        delete=False,
        prefix="securecc_heal_",
    ) as tmp:
        path = Path(tmp.name)
        path.write_text(patched_source, encoding="utf-8")

    try:
        patched_analysis = analyze_source(path)
    except RuntimeError as exc:
        return ValidationResult(
            passed=False,
            original_cwes=original_cwes,
            remaining_cwes=sorted(targets),
            new_cwes=[],
            original_finding_count=len(original_analysis.get("findings") or []),
            patched_finding_count=0,
            removed_target_findings=0,
            message=f"Patched source did not compile: {exc}",
            original_findings=[],
            patched_findings=[],
        )
    finally:
        path.unlink(missing_ok=True)

    patched_user = _user_target_cwes(patched_analysis, targets)
    remaining = sorted(targets & patched_user)
    removed = targets - patched_user
    original_user = _user_target_cwes(original_analysis, targets)
    new_cwes = sorted(
        _user_target_cwes(patched_analysis, set()) - original_user - targets
    )

    passed = len(remaining) == 0 and not new_cwes
    message = (
        "All targeted CWEs cleared after re-scan."
        if passed
        else f"Remaining: {', '.join(remaining) or 'none'}; new: {', '.join(new_cwes) or 'none'}"
    )

    return ValidationResult(
        passed=passed,
        original_cwes=original_cwes,
        remaining_cwes=remaining,
        new_cwes=new_cwes,
        original_finding_count=len(original_analysis.get("findings") or []),
        patched_finding_count=len(patched_analysis.get("findings") or []),
        removed_target_findings=len(removed),
        message=message,
        original_findings=[],
        patched_findings=[],
    )
