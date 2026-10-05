from typing import Optional

from .models import RepairPlan, RepairResult


class RepairEngine:
    """
    V2 repair adapter.

    The original project already contains src/ir_healer.py. Phase 3 does not
    duplicate that implementation. Instead this layer:
      1. accepts only a Phase-2 RepairPlan,
      2. restricts repairs to supported CWEs,
      3. passes exact localized instructions to the existing IR healer,
      4. records every resulting patch,
      5. exposes syntax validation to the verification stage.
    """

    SUPPORTED = {"CWE-190", "CWE-191", "CWE-369", "CWE-476"}

    def __init__(self):
        self._healer = None

    def _load_healer(self):
        if self._healer is None:
            from ...ir_healer import repair_ir
            self._healer = repair_ir
        return self._healer

    def repair(
        self,
        ll_content: str,
        plan: RepairPlan,
    ) -> RepairResult:
        if not isinstance(ll_content, str):
            raise TypeError("ll_content must be a string")

        unsupported = [
            action.cwe_id
            for action in plan.actions
            if action.cwe_id not in self.SUPPORTED
        ]

        if unsupported:
            return RepairResult(
                success=False,
                patched_ir=ll_content,
                plan=plan,
                message=(
                    "Repair rejected because unsupported CWEs were present: "
                    + ", ".join(sorted(set(unsupported)))
                ),
            )

        if not plan.actions:
            return RepairResult(
                success=True,
                patched_ir=ll_content,
                plan=plan,
                syntax_valid=True,
                message="No repair actions were requested.",
            )

        healer = self._load_healer()

        localized = [
            {
                "cwe": action.cwe_id,
                "node_id": action.node_id,
                "text": action.instruction,
                "function": action.target_function,
                "block": action.target_block,
            }
            for action in plan.actions
        ]

        cwes = plan.cwes

        result = healer(
            ll_content,
            cwes,
            vuln_instructions=localized,
        )

        return RepairResult(
            success=bool(result.get("success", False)),
            patched_ir=result.get("patched_ir", ll_content),
            plan=plan,
            patches=result.get("patches", []),
            syntax_valid=bool(result.get("is_valid", False)),
            syntax_issues=result.get("validation_issues", []),
            message=result.get("message", ""),
        )
