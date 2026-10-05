from collections import Counter

from ..analysis.graph_adapter import GraphAdapter
from ..detection.engine import DetectionEngine
from .localizer import VulnerabilityLocalizer


class PatchValidator:
    """
    Phase-2 validation gate.

    A patched graph is accepted only when:
      1. Every targeted CWE is absent after the patch.
      2. No new CWE appears.

    This intentionally validates detector output, not generated code
    execution. Sandboxed compilation/execution belongs to a later phase.
    """

    def __init__(self, engine=None):
        self.engine = engine or DetectionEngine()
        self.localizer = VulnerabilityLocalizer()

    @staticmethod
    def _cwes(findings):
        return set(f.cwe_id for f in findings)

    @staticmethod
    def _signature(finding):
        return (
            finding.cwe_id,
            finding.node_id,
            finding.instruction,
        )

    def validate(self, original_sample, patched_sample, target_cwes=None):
        original = self.engine.analyze(original_sample)
        patched = self.engine.analyze(patched_sample)

        original_cwes = self._cwes(original)
        patched_cwes = self._cwes(patched)

        targets = set(target_cwes or original_cwes)

        remaining = targets & patched_cwes
        new_cwes = patched_cwes - original_cwes

        original_target_count = sum(
            1 for f in original if f.cwe_id in targets
        )
        patched_target_count = sum(
            1 for f in patched if f.cwe_id in targets
        )

        removed = max(0, original_target_count - patched_target_count)

        passed = not remaining and not new_cwes

        if passed:
            message = (
                "PATCH VALIDATION PASSED: targeted vulnerabilities are no "
                "longer detected and no new CWE was introduced."
            )
        else:
            reasons = []
            if remaining:
                reasons.append(
                    "remaining target CWEs: " + ", ".join(sorted(remaining))
                )
            if new_cwes:
                reasons.append(
                    "new CWEs: " + ", ".join(sorted(new_cwes))
                )
            message = "PATCH VALIDATION FAILED: " + "; ".join(reasons)

        original_localized = self.localizer.localize(
            original_sample, original
        )
        patched_localized = self.localizer.localize(
            patched_sample, patched
        )

        return {
            "result": {
                "passed": passed,
                "original_cwes": sorted(original_cwes),
                "remaining_cwes": sorted(remaining),
                "new_cwes": sorted(new_cwes),
                "original_finding_count": len(original),
                "patched_finding_count": len(patched),
                "removed_target_findings": removed,
                "message": message,
            },
            "original_findings": [
                x.to_dict() for x in original_localized
            ],
            "patched_findings": [
                x.to_dict() for x in patched_localized
            ],
        }
