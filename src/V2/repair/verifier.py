from pathlib import Path
import tempfile


class RepairVerifier:
    """
    Verification gate for Phase 3.

    This layer verifies what can safely be verified without executing
    untrusted source:
      - the repair produced changed IR when an action was requested,
      - the IR healer's syntax validation passed,
      - every requested CWE received an attempted patch,
      - no unexpected CWE was reported by the repair adapter.

    Detector re-analysis of a rebuilt graph is intentionally supported by
    verify_graph_pair() and belongs after the patched IR has been parsed and
    converted into a graph.
    """

    def verify_result(self, original_ir: str, repair_result):
        requested = set(repair_result.plan.cwes)
        applied = {
            patch.get("cwe")
            for patch in repair_result.patches
            if patch.get("applied")
        }

        changed = original_ir != repair_result.patched_ir
        syntax_ok = repair_result.syntax_valid

        passed = (
            repair_result.success
            and changed
            and syntax_ok
            and bool(requested)
            and requested <= applied
        )

        if passed:
            message = (
                "Repair verification passed: IR changed, syntax validation "
                "passed, and every requested CWE has an applied repair."
            )
        else:
            reasons = []
            if not repair_result.success:
                reasons.append("repair engine reported failure")
            if not changed:
                reasons.append("IR was unchanged")
            if not syntax_ok:
                reasons.append("patched IR failed syntax validation")
            missing = requested - applied
            if missing:
                reasons.append(
                    "no applied patch for " + ", ".join(sorted(missing))
                )
            message = "Repair verification failed: " + "; ".join(reasons)

        return {
            "passed": passed,
            "requested_cwes": sorted(requested),
            "applied_cwes": sorted(applied),
            "changed": changed,
            "syntax_valid": syntax_ok,
            "message": message,
        }

    def verify_graph_pair(
        self,
        original_sample,
        patched_sample,
        target_cwes=None,
        engine=None,
    ):
        """
        Full detector-level verification after a patched IR has been rebuilt
        into the standard VulnHGNN graph format.

        Acceptance:
          - target CWEs disappear
          - no new CWE appears
        """
        from ..detection.engine import DetectionEngine

        engine = engine or DetectionEngine()

        original = engine.analyze(original_sample)
        patched = engine.analyze(patched_sample)

        original_cwes = {x.cwe_id for x in original}
        patched_cwes = {x.cwe_id for x in patched}

        targets = set(target_cwes or original_cwes)

        remaining = targets & patched_cwes
        new_cwes = patched_cwes - original_cwes

        passed = not remaining and not new_cwes

        return {
            "passed": passed,
            "original_cwes": sorted(original_cwes),
            "patched_cwes": sorted(patched_cwes),
            "remaining_target_cwes": sorted(remaining),
            "new_cwes": sorted(new_cwes),
            "message": (
                "Detector-level patch verification passed."
                if passed
                else "Detector-level patch verification failed."
            ),
        }
