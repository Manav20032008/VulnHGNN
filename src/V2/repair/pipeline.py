import json
from pathlib import Path

from ..detection.engine import DetectionEngine
from ..localization.localizer import VulnerabilityLocalizer
from .engine import RepairEngine
from .planner import RepairPlanner
from .verifier import RepairVerifier


class RepairPipeline:
    """
    Phase-3 orchestration:

        detect -> localize -> plan -> repair -> verify

    It deliberately does not execute generated code.
    """

    def __init__(self):
        self.detector = DetectionEngine()
        self.localizer = VulnerabilityLocalizer()
        self.planner = RepairPlanner()
        self.repairer = RepairEngine()
        self.verifier = RepairVerifier()

    def analyze_graph(self, sample):
        findings = self.detector.analyze(sample)
        localized = self.localizer.localize(sample, findings)
        plan = self.planner.plan(localized)

        return {
            "findings": findings,
            "localized": localized,
            "plan": plan,
        }

    def repair_ir_for_graph(self, sample, ll_content):
        analysis = self.analyze_graph(sample)

        result = self.repairer.repair(
            ll_content,
            analysis["plan"],
        )

        verification = self.verifier.verify_result(
            ll_content,
            result,
        )

        return {
            "analysis": analysis,
            "repair": result,
            "verification": verification,
        }

    @staticmethod
    def json_summary(output):
        return json.dumps(
            {
                "plan": output["analysis"]["plan"].to_dict(),
                "repair": output["repair"].to_dict(),
                "verification": output["verification"],
            },
            indent=2,
            default=str,
        )
