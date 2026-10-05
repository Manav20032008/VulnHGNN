import json
from pathlib import Path

def save_json(explanations, path):
    Path(path).write_text(
        json.dumps([e.to_dict() for e in explanations], indent=2),
        encoding="utf-8"
    )
    return path

def render_text(explanations):
    lines = ["VulnHGNN 2.0 — Explainability Report", "=" * 48]
    for e in explanations:
        lines += [
            "", f"{e.cwe_id} — {e.title}",
            f"Severity       : {e.severity}",
            f"Function       : {e.function}",
            f"Basic block    : {e.block}",
            f"Instruction    : {e.node_id}",
            f"Operation      : {e.vulnerable_operation}",
            f"Root cause     : {e.root_cause}",
            f"Security impact: {e.security_impact}",
            f"Repair strategy: {e.repair_strategy}",
            f"Verification   : {e.verification}",
            "Evidence:"
        ]
        for item in e.evidence:
            lines.append(f"  - [{item.role}] {item.node_id}: {item.instruction}")
    return "\n".join(lines)
