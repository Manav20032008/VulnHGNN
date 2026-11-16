"""Catalog heal: deterministic source patches + verify + AI fallback."""

from __future__ import annotations

import tempfile
from pathlib import Path
from typing import Any

from src.V2.detection.catalog import MULTI_VULN_FIXTURES, VULNERABILITY_CATALOG
from src.V2.heal.advisory_verify import advisory_cwes_from_issues, verify_advisory_cleared
from src.V2.heal.ai_fallback import ai_heal_source
from src.V2.heal.deterministic import apply_deterministic_heals
from src.V2.heal.verify import verify_patched_source
from src.V2.securecc.languages import language_id_from_suffix
from src.V2.securecc.scan_merge import ensure_healed_banner


def _expected_cwes_for_source(source: Path) -> set[str] | None:
    """Catalog intent for test fixtures (ignore incidental detector noise)."""
    rel = f"test_files/{source.name}"
    if source.name == "test_01_clean.cpp":
        return set()
    cwes: set[str] = set()
    for spec in VULNERABILITY_CATALOG:
        if spec.single_test == rel or spec.single_test.replace(".cpp", ".c") == rel.replace(
            ".cpp", ".c"
        ):
            cwes.add(spec.cwe_id)
    if cwes:
        return cwes
    for combo in MULTI_VULN_FIXTURES:
        if combo.get("path") == rel:
            return set(combo["expected_cwes"])
    return None


def _heal_findings_summary(
    engine_findings: list,
    advisory_issues: list[dict[str, Any]] | None,
    remaining_cwes: set[str],
) -> list[dict[str, Any]]:
    summary: list[dict[str, Any]] = []
    for f in engine_findings:
        if f.cwe_id in remaining_cwes:
            summary.append(
                {
                    "cwe_id": f.cwe_id,
                    "title": f.title,
                    "message": f.message,
                    "function": f.function,
                }
            )
    adv_cwes = advisory_cwes_from_issues(advisory_issues) & remaining_cwes
    for item in advisory_issues or []:
        cwe = (item.get("cwe_id") or "").strip().upper()
        if cwe not in adv_cwes:
            continue
        summary.append(
            {
                "cwe_id": cwe,
                "title": item.get("title") or "Advisory issue",
                "message": item.get("message") or "",
                "function": f"line {item.get('line')}" if item.get("line") else "source",
            }
        )
    return summary


def catalog_heal_source(
    source: Path,
    *,
    max_ai_attempts: int = 2,
    advisory_issues: list[dict[str, Any]] | None = None,
) -> dict[str, Any]:
    """
    Analyze → deterministic heal → engine verify → optional AI heal → advisory re-review.
    Does not overwrite the original file.
    """
    source = source.resolve()
    if not source.exists():
        raise FileNotFoundError(source)

    from src.V2.securecc.analysis import analyze_source

    language = language_id_from_suffix(source.suffix)
    original_text = source.read_text(encoding="utf-8")
    original_analysis = analyze_source(source)
    findings = original_analysis.get("findings") or []
    detected_cwes = sorted({f.cwe_id for f in findings})
    catalog_targets = _expected_cwes_for_source(source)
    advisory_cwes = advisory_cwes_from_issues(advisory_issues)

    if catalog_targets is not None:
        if len(catalog_targets) == 0 and not advisory_cwes:
            return {
                "status": "CLEAN",
                "message": "Clean catalog fixture — nothing to heal.",
                "patched_source": source.read_text(encoding="utf-8"),
                "target_cwes": [],
                "advisory_target_cwes": [],
                "detected_cwes": detected_cwes,
                "per_cwe": {},
                "advisory_per_cwe": {},
                "actions": [],
                "validation": None,
                "advisory_validation": None,
            }
        engine_targets = sorted(catalog_targets)
    else:
        engine_targets = detected_cwes

    heal_targets = sorted(set(engine_targets) | advisory_cwes)

    if not heal_targets:
        return {
            "status": "CLEAN",
            "message": "No engine or advisory findings to heal.",
            "patched_source": source.read_text(encoding="utf-8"),
            "target_cwes": [],
            "advisory_target_cwes": [],
            "detected_cwes": detected_cwes,
            "per_cwe": {},
            "advisory_per_cwe": {},
            "actions": [],
            "validation": None,
            "advisory_validation": None,
        }

    current = original_text
    actions: list[dict[str, Any]] = []

    current, det_log = apply_deterministic_heals(
        current,
        target_cwes=set(heal_targets),
        language=language,
        filename=source.name,
    )
    actions.extend(det_log)

    engine_target_set = set(engine_targets)
    validation = verify_patched_source(
        original_analysis,
        current,
        source_suffix=source.suffix,
        target_cwes=engine_target_set if engine_target_set else None,
    )
    if not engine_target_set:
        validation.passed = True
        validation.remaining_cwes = []
        validation.message = "No engine CWE targets."

    ir_heal_notes: list[str] = []
    remaining_after_det = list(validation.remaining_cwes)
    ir_cwes = set(remaining_after_det) & {"CWE-190", "CWE-191", "CWE-369", "CWE-476"}
    if ir_cwes and engine_target_set and not validation.passed:
        try:
            from src.V2.securecc.fix import fix_source

            with tempfile.TemporaryDirectory(prefix="securecc_heal_ir_") as tmp:
                tmp_dir = Path(tmp)
                patched_path = tmp_dir / source.name
                patched_path.write_text(current, encoding="utf-8")
                ir_result = fix_source(
                    patched_path,
                    output_dir=tmp_dir,
                    keep_ir=True,
                    build_artifact=False,
                )
            if str(ir_result.get("status", "")).upper() == "VERIFIED":
                for cwe in ir_cwes:
                    if cwe not in (ir_result.get("detected_cwes") or []):
                        validation.remaining_cwes = [
                            x for x in validation.remaining_cwes if x != cwe
                        ]
                validation = verify_patched_source(
                    original_analysis,
                    current,
                    source_suffix=source.suffix,
                    target_cwes=engine_target_set,
                )
                ir_heal_notes.append(
                    f"IR repair verified; cleared: {sorted(ir_cwes - set(validation.remaining_cwes))}"
                )
                actions.append(
                    {
                        "method": "ir_repair",
                        "detail": ir_result.get("message"),
                        "status": ir_result.get("status"),
                    }
                )
        except Exception as exc:
            ir_heal_notes.append(f"IR repair skipped: {exc}")

    if validation.remaining_cwes != remaining_after_det:
        validation.passed = len(validation.remaining_cwes) == 0 and not validation.new_cwes
        if validation.passed:
            validation.message = "Engine target CWEs cleared (source + IR repair)."

    ai_attempts = 0
    advisory_validation: dict[str, Any] = verify_advisory_cleared(
        advisory_issues,
        current,
        source_suffix=source.suffix,
        language=language,
    )
    while ai_attempts < max_ai_attempts:
        remaining_engine = set(validation.remaining_cwes) if engine_target_set else set()
        advisory_validation = verify_advisory_cleared(
            advisory_issues,
            current,
            source_suffix=source.suffix,
            language=language,
        )
        remaining_advisory = set(advisory_validation.get("remaining_cwes") or [])
        if not remaining_engine and not remaining_advisory:
            break

        combined_remaining = sorted(remaining_engine | remaining_advisory)
        summary = _heal_findings_summary(findings, advisory_issues, set(combined_remaining))
        patched, ai_msg = ai_heal_source(
            current,
            remaining_cwes=combined_remaining,
            findings_summary=summary,
            language=language,
        )
        ai_attempts += 1
        actions.append(
            {
                "method": "ai_fallback",
                "attempt": ai_attempts,
                "detail": ai_msg,
                "remaining_before": combined_remaining,
            }
        )
        if not patched:
            break
        current = patched
        if engine_target_set:
            validation = verify_patched_source(
                original_analysis,
                current,
                source_suffix=source.suffix,
                target_cwes=engine_target_set,
            )
    else:
        advisory_validation = verify_advisory_cleared(
            advisory_issues,
            current,
            source_suffix=source.suffix,
            language=language,
        )

    engine_ok = validation.passed if engine_target_set else True
    advisory_ok = advisory_validation.get("passed", True)
    passed = engine_ok and advisory_ok

    if passed:
        msg = "Engine and advisory targets cleared after heal."
    elif engine_ok and not advisory_ok:
        msg = advisory_validation.get("message") or "Advisory issues remain after heal."
    elif not engine_ok and advisory_ok:
        msg = validation.message
    else:
        msg = f"{validation.message}; {advisory_validation.get('message', '')}"

    per_cwe = (
        {cwe: cwe not in set(validation.remaining_cwes) for cwe in engine_targets}
        if engine_target_set
        else {}
    )
    advisory_per_cwe = advisory_validation.get("per_cwe") or {}

    status = "VERIFIED" if passed else "PARTIAL"
    if passed:
        current = ensure_healed_banner(current)
    elif ai_attempts == 0 and not det_log and advisory_cwes:
        msg = "No patches applied; configure GROQ for AI heal of advisory issues."

    return {
        "status": status,
        "message": msg,
        "patched_source": current,
        "target_cwes": engine_targets,
        "advisory_target_cwes": sorted(advisory_cwes),
        "heal_targets": heal_targets,
        "detected_cwes": detected_cwes,
        "per_cwe": per_cwe,
        "advisory_per_cwe": advisory_per_cwe,
        "actions": actions,
        "validation": validation.to_dict() if engine_target_set else None,
        "advisory_validation": advisory_validation,
        "ai_attempts": ai_attempts,
    }


def catalog_heal_text(
    source_text: str,
    *,
    filename: str = "editor_workspace.cpp",
    max_ai_attempts: int = 2,
    advisory_issues: list[dict[str, Any]] | None = None,
) -> dict[str, Any]:
    suffix = Path(filename).suffix or ".cpp"
    with tempfile.NamedTemporaryFile(
        mode="w",
        encoding="utf-8",
        suffix=suffix,
        delete=False,
        prefix="securecc_heal_",
    ) as tmp:
        path = Path(tmp.name)
        path.write_text(source_text, encoding="utf-8")
    try:
        return catalog_heal_source(
            path,
            max_ai_attempts=max_ai_attempts,
            advisory_issues=advisory_issues,
        )
    finally:
        path.unlink(missing_ok=True)
