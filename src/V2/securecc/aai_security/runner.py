from __future__ import annotations

import json
import time
from pathlib import Path
from typing import Any

from .audit import append_audit_event, default_log_path
from .guards import GuardResult, detect_code_poisoning, detect_prompt_threats
from .policy import DEFAULT_AAI_POLICY, evaluate_tool_call
from .scenarios import ALL_SCENARIOS, Scenario


def _evaluate_scenario(
    scenario: Scenario,
    policy=DEFAULT_AAI_POLICY,
) -> dict[str, Any]:
    t0 = time.perf_counter()

    prompt_guard = detect_prompt_threats(scenario.prompt)
    code_injection_guard = detect_prompt_threats(scenario.code)
    code_guard = detect_code_poisoning(scenario.code)

    if code_injection_guard.attack:
        code_guard = GuardResult(
            attack=True,
            types=list(dict.fromkeys(code_guard.types + code_injection_guard.types)),
            risk=max(code_guard.risk, code_injection_guard.risk),
            action="BLOCK",
            matched_patterns=code_guard.matched_patterns
            + code_injection_guard.matched_patterns,
        )

    prompt_blocked = (
        policy.block_on_prompt_injection
        and (prompt_guard.action == "BLOCK" or code_injection_guard.action == "BLOCK")
    )
    code_blocked = (
        policy.block_on_code_poisoning and code_guard.action == "BLOCK"
    )

    tool_decision = evaluate_tool_call(
        scenario.attempted_tool,
        policy=policy,
        prompt_blocked=prompt_blocked or code_blocked,
        verify_passed=scenario.verify_passed,
    )

    blocked = (
        prompt_blocked
        or code_blocked
        or not tool_decision["allowed"]
    )

    detected = (
        prompt_guard.attack
        or code_injection_guard.attack
        or code_guard.attack
        or not tool_decision["allowed"]
    )

    latency_ms = (time.perf_counter() - t0) * 1000.0

    risk = max(
        prompt_guard.risk,
        code_guard.risk,
        float(tool_decision.get("risk", 0.0)),
    )

    action_taken = "BLOCKED" if blocked else "ALLOWED"

    return {
        "scenario_id": scenario.id,
        "family": scenario.family,
        "expected_malicious": scenario.malicious,
        "description": scenario.description,
        "prompt_guard": prompt_guard.to_dict(),
        "code_injection_guard": code_injection_guard.to_dict(),
        "code_guard": code_guard.to_dict(),
        "tool_decision": tool_decision,
        "detected": detected,
        "blocked": blocked,
        "action_taken": action_taken,
        "risk_score": round(risk, 4),
        "attempted_tool": scenario.attempted_tool,
        "latency_ms": round(latency_ms, 3),
    }


def compute_metrics(results: list[dict[str, Any]]) -> dict[str, Any]:
    tp = fp = fn = tn = 0
    latencies: list[float] = []

    for row in results:
        malicious = row["expected_malicious"]
        detected = row["detected"] or row["blocked"]
        latencies.append(float(row["latency_ms"]))

        if malicious and detected:
            tp += 1
        elif malicious:
            fn += 1
        elif detected:
            fp += 1
        else:
            tn += 1

    recall = tp / (tp + fn) if (tp + fn) else 0.0
    fpr = fp / (fp + tn) if (fp + tn) else 0.0
    precision = tp / (tp + fp) if (tp + fp) else 0.0
    f1 = (
        2 * precision * recall / (precision + recall)
        if (precision + recall)
        else 0.0
    )
    asr = fn / (tp + fn) if (tp + fn) else 0.0
    block_rate = sum(1 for r in results if r["expected_malicious"] and r["blocked"])
    block_rate /= sum(1 for r in results if r["expected_malicious"]) or 1

    return {
        "confusion": {"TP": tp, "FP": fp, "FN": fn, "TN": tn},
        "detection_recall_tpr": round(recall, 4),
        "false_positive_rate": round(fpr, 4),
        "precision": round(precision, 4),
        "f1_score": round(f1, 4),
        "attack_success_rate_asr": round(asr, 4),
        "malicious_block_rate": round(block_rate, 4),
        "mean_time_to_detect_ms": round(sum(latencies) / len(latencies), 3)
        if latencies
        else 0.0,
        "scenario_count": len(results),
        "attack_count": sum(1 for r in results if r["expected_malicious"]),
        "benign_count": sum(1 for r in results if not r["expected_malicious"]),
    }


def run_attack_suite(
    *,
    project_root: Path | None = None,
    log_path: Path | None = None,
    scenarios: list[Scenario] | None = None,
) -> dict[str, Any]:
    root = project_root or Path.cwd()
    log_file = log_path or default_log_path(root)
    items = scenarios or ALL_SCENARIOS

    results: list[dict[str, Any]] = []
    for scenario in items:
        outcome = _evaluate_scenario(scenario)
        results.append(outcome)
        append_audit_event(
            log_file,
            {
                "event": "aai_security_evaluation",
                "scenario": scenario.to_dict(),
                "outcome": outcome,
            },
        )

    metrics = compute_metrics(results)
    report = {
        "tool": "VulnHGNN 2.0 SecureCC",
        "module": "aai_security",
        "policy": DEFAULT_AAI_POLICY.to_dict(),
        "metrics": metrics,
        "results": results,
        "audit_log": str(log_file.resolve()),
    }

    metrics_path = log_file.parent / "metrics.json"
    metrics_path.write_text(json.dumps(report, indent=2), encoding="utf-8")

    return report


def print_text_report(report: dict[str, Any]) -> str:
    m = report["metrics"]
    lines = [
        "=" * 72,
        "VULNHGNN 2.0 — AGENTIC AI SECURITY ATTACK SUITE",
        "=" * 72,
        f"Scenarios : {m['scenario_count']} "
        f"(attacks {m['attack_count']}, benign {m['benign_count']})",
        f"Audit log : {report['audit_log']}",
        "",
        "Metrics",
        f"  Detection recall (TPR) : {m['detection_recall_tpr']:.2%}",
        f"  False positive rate    : {m['false_positive_rate']:.2%}",
        f"  Precision              : {m['precision']:.2%}",
        f"  F1 score               : {m['f1_score']:.2%}",
        f"  Attack success rate    : {m['attack_success_rate_asr']:.2%}",
        f"  Malicious block rate   : {m['malicious_block_rate']:.2%}",
        f"  Mean time to detect    : {m['mean_time_to_detect_ms']:.3f} ms",
        f"  Confusion matrix       : {m['confusion']}",
        "",
    ]

    for row in report["results"]:
        flag = "BLOCK" if row["blocked"] else "ALLOW"
        lines.append(
            f"  [{row['scenario_id']}] {flag} "
            f"risk={row['risk_score']:.2f} "
            f"tool={row['attempted_tool']} "
            f"detected={row['detected']}"
        )

    lines.append("=" * 72)
    text = "\n".join(lines)
    return text
