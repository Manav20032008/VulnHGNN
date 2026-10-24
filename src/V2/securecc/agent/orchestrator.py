from __future__ import annotations

import uuid
from pathlib import Path
from typing import Any

from ..aai_security.audit import append_audit_event, default_log_path
from ..aai_security.guards import detect_code_poisoning, detect_prompt_threats
from ..aai_security.policy import DEFAULT_AAI_POLICY, evaluate_tool_call
from .gemini import plan_next_step
from .tools import run_tool


MAX_AGENT_STEPS = 8


def _verify_passed_from_fix(result: dict[str, Any]) -> bool:
    return str(result.get("status", "")).upper() == "VERIFIED"


def run_agent_session(
    *,
    source: Path,
    user_message: str,
    project_root: Path | None = None,
    max_steps: int = MAX_AGENT_STEPS,
    model: str | None = None,
) -> dict[str, Any]:
    root = project_root or Path.cwd()
    source = Path(source).resolve()
    session_id = str(uuid.uuid4())
    log_path = default_log_path(root)

    prompt_guard = detect_prompt_threats(user_message)
    session: dict[str, Any] = {
        "session_id": session_id,
        "source": str(source),
        "user_message": user_message,
        "status": "running",
        "steps": [],
        "final_message": "",
        "blocked": False,
        "verify_passed": False,
        "tool_outputs": {},
    }

    if prompt_guard.action == "BLOCK":
        session["status"] = "blocked"
        session["blocked"] = True
        session["final_message"] = (
            "Request blocked by AAI security: prompt injection or policy bypass "
            f"detected ({', '.join(prompt_guard.types)}). "
            "SecureCC verification cannot be disabled by user prompts."
        )
        append_audit_event(
            log_path,
            {
                "event": "agent_session_blocked",
                "session_id": session_id,
                "prompt_guard": prompt_guard.to_dict(),
                "user_message": user_message,
            },
        )
        return session

    history: list[dict[str, Any]] = []

    for step_index in range(max_steps):
        try:
            decision = plan_next_step(
                user_message=user_message,
                source_path=str(source),
                history=history,
                model_name=model,
            )
        except Exception as exc:
            session["status"] = "error"
            session["final_message"] = f"Agent planner failed: {exc}"
            return session

        action = str(decision.get("action", "")).lower()

        if action == "respond":
            session["status"] = "completed"
            session["final_message"] = str(decision.get("message", ""))
            session["steps"].append(
                {"step": step_index, "action": "respond", "decision": decision}
            )
            break

        if action != "tool":
            session["status"] = "error"
            session["final_message"] = f"Invalid agent action: {decision}"
            break

        tool_name = str(decision.get("tool", "")).lower()
        gate = evaluate_tool_call(
            tool_name,
            policy=DEFAULT_AAI_POLICY,
            prompt_blocked=False,
            verify_passed=session["verify_passed"]
            if tool_name in {"complete", "deploy", "approve_patch"}
            else None,
        )

        if not gate["allowed"]:
            blocked_step = {
                "step": step_index,
                "action": "tool_blocked",
                "tool": tool_name,
                "gate": gate,
                "decision": decision,
            }
            session["steps"].append(blocked_step)
            append_audit_event(
                log_path,
                {
                    "event": "agent_tool_blocked",
                    "session_id": session_id,
                    "tool": tool_name,
                    "gate": gate,
                },
            )
            history.append(
                {
                    "tool_blocked": tool_name,
                    "reason": gate["reason"],
                }
            )
            continue

        if tool_name not in DEFAULT_AAI_POLICY.allowed_tools and tool_name != "rescan":
            session["steps"].append(
                {
                    "step": step_index,
                    "action": "tool_blocked",
                    "tool": tool_name,
                    "reason": "not_in_allowlist",
                }
            )
            continue

        try:
            tool_result = run_tool(tool_name, source)
        except Exception as exc:
            tool_result = {"tool": tool_name, "error": str(exc)}

        if tool_name == "fix":
            repair_blob = tool_result.get("repair") or {}
            patched_ir_text = ""
            if isinstance(repair_blob, dict):
                patched_ir_text = str(repair_blob.get("patched_ir", ""))
            poison = detect_code_poisoning(patched_ir_text)
            if poison.action == "BLOCK":
                session["blocked"] = True
                session["status"] = "blocked"
                session["final_message"] = (
                    "Repair output blocked by AAI code guard: "
                    f"{', '.join(poison.types)}"
                )
                append_audit_event(
                    log_path,
                    {
                        "event": "agent_output_blocked",
                        "session_id": session_id,
                        "poison_guard": poison.to_dict(),
                    },
                )
                session["steps"].append(
                    {
                        "step": step_index,
                        "action": "output_blocked",
                        "tool": tool_name,
                        "guard": poison.to_dict(),
                    }
                )
                return session
            if _verify_passed_from_fix(tool_result):
                session["verify_passed"] = True

        detail = _detail_for_client(tool_name, tool_result)
        session["tool_outputs"][tool_name] = detail

        step_record = {
            "step": step_index,
            "action": "tool",
            "tool": tool_name,
            "reason": decision.get("reason", ""),
            "result_summary": _summarize_tool_result(tool_result),
            "has_detail": True,
        }
        session["steps"].append(step_record)
        history.append({"tool": tool_name, "summary": step_record["result_summary"]})

        append_audit_event(
            log_path,
            {
                "event": "agent_tool_executed",
                "session_id": session_id,
                "tool": tool_name,
                "summary": step_record["result_summary"],
            },
        )
    else:
        if session["status"] == "running":
            session["status"] = "max_steps"
            session["final_message"] = (
                "Agent reached the step limit. Review tool summaries in the session log."
            )

    return session


def _detail_for_client(tool_name: str, result: dict[str, Any]) -> dict[str, Any]:
    """Full tool payload for UI; truncate huge IR strings."""
    from .tools import _jsonable

    detail = _jsonable(result)
    if not isinstance(detail, dict):
        return {"tool": tool_name, "payload": detail}

    if tool_name == "fix":
        repair = detail.get("repair")
        if isinstance(repair, dict) and repair.get("patched_ir"):
            ir = str(repair["patched_ir"])
            if len(ir) > 800:
                repair["patched_ir"] = ir[:800] + "\n... [truncated for UI]"

    detail.setdefault("tool", tool_name)
    return detail


def _summarize_tool_result(result: dict[str, Any]) -> dict[str, Any]:
    if "error" in result:
        return {"error": result["error"]}
    if result.get("tool") == "scan" or result.get("tool") == "rescan":
        return {
            "finding_count": result.get("finding_count"),
            "cwes": result.get("cwes"),
            "status": result.get("status"),
        }
    if result.get("tool") == "fix":
        return {
            "status": result.get("status"),
            "message": result.get("message"),
            "detected_cwes": result.get("detected_cwes"),
        }
    if result.get("tool") == "explain":
        return {
            "finding_count": result.get("finding_count"),
            "cwes": result.get("cwes"),
        }
    return {
        "keys": list(result.keys())[:12],
        "finding_count": result.get("finding_count"),
        "status": result.get("status"),
    }
