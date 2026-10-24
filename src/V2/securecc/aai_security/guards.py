from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Any


@dataclass
class GuardResult:
    attack: bool
    types: list[str] = field(default_factory=list)
    risk: float = 0.0
    action: str = "ALLOW"
    matched_patterns: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "attack": self.attack,
            "types": self.types,
            "risk": self.risk,
            "action": self.action,
            "matched_patterns": self.matched_patterns,
        }


INJECTION_PATTERNS: list[tuple[str, str]] = [
    (r"ignore\s+(the\s+)?(previous\s+)?(instructions?|security\s+policy)", "prompt_injection"),
    (r"disable\s+(the\s+)?(validation|verification|verify)", "policy_bypass"),
    (r"mark\s+.{0,40}\s+safe", "policy_bypass"),
    (r"\b(bypass|skip|override)\s+(verify|verification|policy)", "policy_bypass"),
    (r"you\s+are\s+now\s+(in\s+)?(developer|admin|unrestricted)\s+mode", "prompt_injection"),
    (r"do\s+not\s+(run|call)\s+verify", "policy_bypass"),
    (r"jailbreak", "prompt_injection"),
    (r"email\s+.{0,80}(source|findings|secrets)", "data_exfiltration"),
    (r"exfiltrat", "data_exfiltration"),
    (r"infinite\s+loop", "dos_abuse"),
]

INDIRECT_INJECTION_PATTERNS: list[tuple[str, str]] = [
    (r"SYSTEM\s*:\s*approve", "indirect_injection"),
    (r"IGNORE\s+SECURECC", "indirect_injection"),
]

POISON_PATTERNS: list[tuple[str, str]] = [
    (r"\bsystem\s*\(", "output_poisoning"),
    (r"\bexec\s*\(", "output_poisoning"),
    (r"\bpopen\s*\(", "output_poisoning"),
    (r"/etc/passwd", "data_exfil_risk"),
    (r"\bgetenv\s*\(", "data_exfil_risk"),
    (r"\bsocket\s*\(", "output_poisoning"),
    (r"\b(curl|wget)\s+", "output_poisoning"),
    (r"read\s*\(\s*0\s*,", "output_poisoning"),
]


def detect_prompt_threats(text: str) -> GuardResult:
    if not text or not text.strip():
        return GuardResult(attack=False, action="ALLOW")

    types: list[str] = []
    matched: list[str] = []

    for pattern, label in INJECTION_PATTERNS + INDIRECT_INJECTION_PATTERNS:
        if re.search(pattern, text, re.IGNORECASE | re.MULTILINE):
            matched.append(pattern)
            if label not in types:
                types.append(label)

    if not types:
        return GuardResult(attack=False, action="ALLOW")

    risk = min(0.99, 0.55 + 0.12 * len(types))
    return GuardResult(
        attack=True,
        types=types,
        risk=risk,
        action="BLOCK",
        matched_patterns=matched,
    )


def detect_code_poisoning(code: str) -> GuardResult:
    if not code or not code.strip():
        return GuardResult(attack=False, action="ALLOW")

    types: list[str] = []
    matched: list[str] = []

    for pattern, label in POISON_PATTERNS:
        if re.search(pattern, code, re.IGNORECASE):
            matched.append(pattern)
            if label not in types:
                types.append(label)

    if not types:
        return GuardResult(attack=False, action="ALLOW")

    risk = min(0.99, 0.6 + 0.1 * len(types))
    return GuardResult(
        attack=True,
        types=types,
        risk=risk,
        action="BLOCK",
        matched_patterns=matched,
    )
