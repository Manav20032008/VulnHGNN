from .models import RepairAction, RepairPlan


STRATEGIES = {
    "CWE-190": (
        "overflow_checked_arithmetic",
        "Replace vulnerable signed arithmetic with checked overflow handling."
    ),
    "CWE-191": (
        "underflow_checked_arithmetic",
        "Replace vulnerable signed subtraction with checked underflow handling."
    ),
    "CWE-369": (
        "zero_divisor_guard",
        "Guard division/remainder with an explicit non-zero divisor check."
    ),
    "CWE-476": (
        "null_pointer_guard",
        "Guard the pointer dereference with an explicit NULL check."
    ),
}


class RepairPlanner:
    """Convert Phase-2 localized findings into deterministic repair actions."""

    def plan(self, localized_findings):
        plan = RepairPlan()

        for finding in localized_findings:
            strategy = STRATEGIES.get(finding.cwe_id)

            if strategy is None:
                plan.warnings.append(
                    f"No deterministic repair strategy exists for {finding.cwe_id}."
                )
                continue

            name, description = strategy

            plan.actions.append(
                RepairAction(
                    cwe_id=finding.cwe_id,
                    node_id=finding.vulnerable_node,
                    instruction=finding.vulnerable_instruction,
                    strategy=name,
                    description=description,
                    safe=True,
                    target_function=finding.function,
                    target_block=finding.vulnerable_block,
                    evidence_nodes=[
                        x.node_id for x in finding.evidence
                    ],
                )
            )

        return plan
