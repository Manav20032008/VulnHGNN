from __future__ import annotations

import json
from pathlib import Path

from .analysis import analyze_source


LESSONS = {
    "CWE-190": {
        "topic": "Integer Overflow",
        "concept": "Signed integer arithmetic can exceed the representable range of its type.",
        "why": "An overflow can produce an incorrect arithmetic result and may affect later security-sensitive decisions.",
        "practice": "Validate operands or use checked arithmetic before accepting the result.",
    },
    "CWE-191": {
        "topic": "Integer Underflow",
        "concept": "Signed subtraction can produce a value outside the representable range.",
        "why": "An underflow can produce an invalid value that propagates into later computations.",
        "practice": "Validate subtraction operands or use checked arithmetic.",
    },
    "CWE-369": {
        "topic": "Divide By Zero",
        "concept": "Division and remainder operations require a valid non-zero divisor.",
        "why": "A zero divisor can terminate the program and make the computation invalid.",
        "practice": "Check the divisor before performing division or remainder.",
    },
    "CWE-476": {
        "topic": "NULL Pointer Dereference",
        "concept": "A pointer returned by an allocation operation may be NULL when allocation fails.",
        "why": "Dereferencing NULL can terminate the process and create a memory-safety failure.",
        "practice": "Check pointers before their first dereference and handle allocation failure.",
    },
}


def learn_source(source: Path) -> dict:
    source = Path(source)

    if not source.exists():
        raise FileNotFoundError(f"source file not found: {source}")

    analysis = analyze_source(source)

    findings = analysis.get("findings", [])
    explanations = analysis.get("explanations", [])

    findings_by_cwe = {}
    for finding in findings:
        findings_by_cwe.setdefault(finding.cwe_id, []).append(finding)

    explanation_by_cwe = {
        explanation.cwe_id: explanation
        for explanation in explanations
    }

    lessons = []

    for cwe_id in analysis.get("cwes", []):
        lesson = LESSONS.get(
            cwe_id,
            {
                "topic": cwe_id,
                "concept": "A security finding was detected by SecureCC.",
                "why": "The detected operation requires security review.",
                "practice": "Review the localized evidence and apply a verified repair.",
            },
        )

        finding_items = findings_by_cwe.get(cwe_id, [])
        explanation = explanation_by_cwe.get(cwe_id)

        lessons.append(
            {
                "cwe_id": cwe_id,
                "topic": lesson["topic"],
                "concept": lesson["concept"],
                "why": lesson["why"],
                "secure_practice": lesson["practice"],
                "finding_count": len(finding_items),
                "function": (
                    finding_items[0].function
                    if finding_items and finding_items[0].function
                    else getattr(explanation, "function", None)
                    if explanation
                    else None
                ),
                "instruction": (
                    finding_items[0].instruction
                    if finding_items and finding_items[0].instruction
                    else getattr(explanation, "vulnerable_operation", None)
                    if explanation
                    else None
                ),
            }
        )

    return {
        "tool": "VulnHGNN 2.0 SecureCC",
        "command": "learn",
        "source": str(source.resolve()),
        "finding_count": len(findings),
        "cwes": analysis.get("cwes", []),
        "lessons": lessons,
        "status": "FINDINGS_PRESENT" if findings else "NO_FINDINGS",
    }


def text_report(result: dict) -> str:
    lines = [
        "=" * 88,
        "VULNHGNN 2.0 — SECURECC LEARN",
        "=" * 88,
        f"Source        : {result['source']}",
        f"Findings      : {result['finding_count']}",
        f"CWEs          : {', '.join(result['cwes']) if result['cwes'] else 'none'}",
        "",
    ]

    if not result["lessons"]:
        lines.extend(
            [
                "No security findings were detected.",
                "The analyzed source passed the current SecureCC security rules.",
                "",
            ]
        )
    else:
        for index, lesson in enumerate(result["lessons"], 1):
            lines.extend(
                [
                    "-" * 88,
                    f"[{index}] {lesson['cwe_id']} — {lesson['topic']}",
                    "",
                    "What is happening?",
                    f"  {lesson['concept']}",
                    "",
                    "Why does it matter?",
                    f"  {lesson['why']}",
                    "",
                    "Secure coding practice",
                    f"  {lesson['secure_practice']}",
                    "",
                    f"Function    : {lesson['function'] or 'unknown'}",
                    f"Instruction : {lesson['instruction'] or 'unknown'}",
                    "",
                ]
            )

    lines.extend(
        [
            "-" * 88,
            "Learning status: "
            + (
                "SECURITY LESSON GENERATED"
                if result["lessons"]
                else "NO LESSON REQUIRED"
            ),
            "=" * 88,
        ]
    )

    return "\n".join(lines)


def json_report(result: dict) -> str:
    return json.dumps(result, indent=2)
