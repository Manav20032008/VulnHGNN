from __future__ import annotations

import re

from ..analysis.dataflow import DataFlowAnalyzer
from ..analysis.finding import SecurityFinding
from .base import BaseDetector

_LOCK_RE = re.compile(
    r"@(?P<fn>pthread_mutex_lock|pthread_rwlock_rdlock|pthread_rwlock_wrlock|sem_wait)\s*\("
)
_UNLOCK_RE = re.compile(
    r"@(?P<fn>pthread_mutex_unlock|pthread_rwlock_unlock|sem_post)\s*\("
)


def _lock_arg(text: str) -> str | None:
    m = re.search(r"\((?:ptr\s+)?(%[-\w.$]+)", text)
    return m.group(1) if m else None


class CWE833Detector(BaseDetector):
    """
    CWE-833: Deadlock (heuristic).
    Flags double-lock on the same mutex and nested locks without release.
    """

    cwe_id = "CWE-833"
    title = "Deadlock"
    severity = "HIGH"

    def detect(self, graph, context=None):
        analyzer = DataFlowAnalyzer(graph)
        findings: list[SecurityFinding] = []

        by_func: dict[str, list] = {}
        for info in analyzer.instructions:
            by_func.setdefault(info.function, []).append(info)

        for func, insts in by_func.items():
            held: set[str] = set()
            lock_order: list[str] = []

            for info in insts:
                text = info.attrs.get("text", "") or ""
                if info.attrs.get("opcode") != "call":
                    continue

                lock_m = _LOCK_RE.search(text)
                if lock_m:
                    arg = _lock_arg(text)
                    if not arg:
                        continue
                    root = analyzer._root(arg)
                    if root in held:
                        findings.append(
                            SecurityFinding(
                                cwe_id="CWE-667",
                                title="Improper Locking",
                                severity="HIGH",
                                confidence=0.92,
                                message="Mutex already held — second lock on the same primitive.",
                                function=func,
                                instruction=text[:200],
                                evidence=[f"mutex={root}", "double_lock"],
                                detector="CWE833Detector",
                                node_id=info.node_id,
                                compiler_stage=self.compiler_stage,
                            )
                        )
                    else:
                        if len(lock_order) >= 1 and lock_order[-1] != root:
                            findings.append(
                                SecurityFinding(
                                    cwe_id=self.cwe_id,
                                    title=self.title,
                                    severity=self.severity,
                                    confidence=0.78,
                                    message=(
                                        "Nested lock on a second primitive without releasing the "
                                        "first — classic deadlock risk if another thread inverts order."
                                    ),
                                    function=func,
                                    instruction=text[:200],
                                    evidence=[
                                        f"held={lock_order[-1]}",
                                        f"acquiring={root}",
                                    ],
                                    detector="CWE833Detector",
                                    node_id=info.node_id,
                                    compiler_stage=self.compiler_stage,
                                )
                            )
                        held.add(root)
                        lock_order.append(root)

                unlock_m = _UNLOCK_RE.search(text)
                if unlock_m:
                    arg = _lock_arg(text)
                    if arg:
                        root = analyzer._root(arg)
                        held.discard(root)
                        if lock_order and lock_order[-1] == root:
                            lock_order.pop()
                        elif root in lock_order:
                            lock_order = [x for x in lock_order if x != root]

        return findings
