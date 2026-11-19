from __future__ import annotations

import uuid
from pathlib import Path
from typing import Any

from ..aai_security.audit import append_audit_event, default_log_path
from ..aai_security.guards import detect_code_poisoning, detect_prompt_threats
from ..aai_security.policy import DEFAULT_AAI_POLICY, evaluate_tool_call
from ..languages import language_id_from_suffix
from ..pipeline_stages import build_engine_pipeline_stages
from ..scan_merge import build_display_scan, should_gap_fill_merge
from .ai_source_review import ai_source_review
from .engine_snapshot import collect_engine_snapshot
from .groq import plan_next_step
from .tools import run_tool


MAX_AGENT_STEPS = 8


def _verify_passed_from_fix(result: dict[str, Any]) -> bool:
    return str(result.get("status", "")).upper() == "VERIFIED"


def _heal_from_outputs(tool_outputs: dict[str, Any]) -> dict[str, Any] | None:
    for key in ("catalog_heal", "fix"):
        blob = tool_outputs.get(key)
        if isinstance(blob, dict) and blob.get("status"):
            return blob
    return None


def _build_session_pipeline(
    *,
    snapshot: dict[str, Any] | None,
    tool_outputs: dict[str, Any],
    bootstrap_error: str | None = None,
) -> dict[str, Any]:
    heal = _heal_from_outputs(tool_outputs)

    if snapshot:
        stages = build_engine_pipeline_stages(
            snapshot["analysis"],
            snapshot["scan"],
            heal=heal,
            diagnostics=tool_outputs.get("diagnose"),
            learn=tool_outputs.get("learn"),
        )
    else:
        empty_scan: dict[str, Any] = {
            "finding_count": 0,
            "findings": [],
            "cwes": [],
            "localization": [],
            "explanations": [],
        }
        ai = tool_outputs.get("ai_source_review") or {}
        merged = build_display_scan(empty_scan, ai, source_text="")
        fc = int(merged.get("finding_count") or 0)
        cwes = merged.get("cwes") or []
        stages = [
            {
                "id": "compile",
                "label": "Compile → LLVM IR",
                "status": "failed",
                "summary": "Compilation failed",
                "detail": bootstrap_error or "Could not compile or analyze source.",
            },
            {
                "id": "detect",
                "label": "Detect",
                "status": "complete" if fc else "partial",
                "summary": (
                    f"{fc} finding(s) · CWEs: {', '.join(cwes) if cwes else 'none'}"
                    if fc
                    else "Analysis unavailable until compile succeeds"
                ),
                "detail": bootstrap_error or "",
            },
        ]

    return {"stages": stages}


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
    lang = language_id_from_suffix(source.suffix)

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
        "pipeline": None,
        "ai_review": None,
        "engine_scan": None,
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
    snapshot: dict[str, Any] | None = None
    bootstrap_error: str | None = None

    session["steps"].append({"step": -2, "action": "bootstrap", "phase": "engine_snapshot"})
    try:
        snapshot = collect_engine_snapshot(source)
        scan = snapshot["scan"]
        session["tool_outputs"]["scan"] = {
            "tool": "scan",
            "finding_count": scan.get("finding_count"),
            "cwes": scan.get("cwes"),
            "status": "FINDINGS" if scan.get("finding_count") else "CLEAN",
        }
        history.append(
            {
                "bootstrap_scan": {
                    "finding_count": scan.get("finding_count"),
                    "cwes": scan.get("cwes"),
                },
            }
        )
    except Exception as exc:
        bootstrap_error = str(exc)
        session["engine_bootstrap_error"] = bootstrap_error
        history.append({"bootstrap_scan_error": bootstrap_error})

    session["steps"].append({"step": -1, "action": "bootstrap", "phase": "ai_source_review"})
    ai_result = ai_source_review(source, language=lang)
    session["tool_outputs"]["ai_source_review"] = ai_result
    session["ai_review"] = ai_result
    if snapshot:
        src_text = source.read_text(encoding="utf-8", errors="replace")
        engine_scan = snapshot["scan"]
        display = build_display_scan(engine_scan, ai_result, source_text=src_text)
        snapshot["scan"] = display
        session["engine_scan"] = {
            "finding_count": display.get("finding_count"),
            "cwes": display.get("cwes"),
            "status": "FINDINGS" if display.get("finding_count") else "CLEAN",
        }
    history.append(
        {
            "ai_source_review": {
                "issue_count": ai_result.get("issue_count"),
                "status": ai_result.get("status"),
            }
        }
    )

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
            session["final_message"] = f"AI planner failed: {exc}"
            break

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

        if tool_name not in DEFAULT_AAI_POLICY.allowed_tools:
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
            heal_advisory: list[dict[str, Any]] | None = None
            if tool_name == "catalog_heal":
                prior = session.get("tool_outputs", {}).get("ai_source_review") or session.get(
                    "ai_review"
                )
                if isinstance(prior, dict):
                    heal_advisory = list(prior.get("issues") or [])
            tool_result = run_tool(
                tool_name,
                source,
                advisory_issues=heal_advisory if tool_name == "catalog_heal" else None,
            )
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
                session["pipeline"] = _build_session_pipeline(
                    snapshot=snapshot,
                    tool_outputs=session["tool_outputs"],
                    bootstrap_error=bootstrap_error,
                )
                return session
            if _verify_passed_from_fix(tool_result):
                session["verify_passed"] = True

        if tool_name in {"catalog_heal", "fix"} and _verify_passed_from_fix(tool_result):
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

    session["pipeline"] = _build_session_pipeline(
        snapshot=snapshot,
        tool_outputs=session["tool_outputs"],
        bootstrap_error=bootstrap_error,
    )
    if snapshot:
        scan_out = dict(snapshot["scan"])
        g = scan_out.get("graph")
        if isinstance(g, dict) and isinstance(g.get("nodes"), list):
            scan_out["graph"] = {
                "nodes": g.get("total_nodes", len(g.get("nodes") or [])),
                "edges": len(g.get("edges") or []),
            }
        session["display_scan"] = scan_out
        session["display_graph"] = snapshot.get("graph")
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
    if result.get("tool") == "ai_source_review":
        return {
            "issue_count": result.get("issue_count"),
            "status": result.get("status"),
        }
    if result.get("tool") == "fix" or result.get("tool") == "catalog_heal":
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
