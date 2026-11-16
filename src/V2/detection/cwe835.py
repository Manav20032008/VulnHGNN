from __future__ import annotations

import re

from ..analysis.finding import SecurityFinding
from .base import BaseDetector
from .cfg_utils import (
    block_branch_instructions,
    blocks_by_function,
    cfg_successors,
    function_has_return,
)

_ALWAYS_TRUE_BR = re.compile(r"\bbr\s+i1\s+true\s*,", re.I)


class CWE835Detector(BaseDetector):
    """CWE-835: infinite / non-terminating loop (LLVM CFG)."""

    cwe_id = "CWE-835"
    title = "Infinite Loop"
    severity = "MEDIUM"

    def detect(self, graph, context=None):
        findings = []

        for func, block_nodes in blocks_by_function(graph).items():
            if not function_has_return(graph, func):
                inst = block_nodes[0] if block_nodes else "unknown"
                findings.append(
                    SecurityFinding(
                        cwe_id=self.cwe_id,
                        title=self.title,
                        severity=self.severity,
                        confidence=0.90,
                        message="Function has no return — control flow may never terminate.",
                        function=func,
                        instruction=f"function {func}",
                        evidence=["no ret in function"],
                        detector="CWE835Detector",
                        node_id=inst,
                        compiler_stage=self.compiler_stage,
                    )
                )
                continue

            for block in block_nodes:
                if block in cfg_successors(graph, block):
                    findings.append(
                        SecurityFinding(
                            cwe_id=self.cwe_id,
                            title=self.title,
                            severity=self.severity,
                            confidence=0.93,
                            message="Basic block branches to itself (self-loop).",
                            function=func,
                            instruction=f"CFG: {block} -> {block}",
                            evidence=["self_loop"],
                            detector="CWE835Detector",
                            node_id=block,
                            compiler_stage=self.compiler_stage,
                        )
                    )

                for inst_id, attrs in block_branch_instructions(graph, block):
                    text = attrs.get("text", "") or ""
                    if _ALWAYS_TRUE_BR.search(text):
                        findings.append(
                            SecurityFinding(
                                cwe_id=self.cwe_id,
                                title=self.title,
                                severity=self.severity,
                                confidence=0.88,
                                message="Branch condition is always true — loop may never exit.",
                                function=func,
                                instruction=text[:200],
                                evidence=["br i1 true"],
                                detector="CWE835Detector",
                                node_id=inst_id,
                                compiler_stage=self.compiler_stage,
                            )
                        )
        return findings
