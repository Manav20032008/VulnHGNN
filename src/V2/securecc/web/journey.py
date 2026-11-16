from __future__ import annotations

import tempfile
import uuid
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
from typing import Any

from ..analysis import compile_to_ir
from ..fix import fix_source
from .serializers import _to_jsonable, analysis_bundle, serialize_graph


class JourneyAction(str, Enum):
    CONTINUE = "continue"
    APPROVE_FIX = "approve_fix"
    REJECT_FIX = "reject_fix"
    SKIP_FIX = "skip_fix"
    RESTART = "restart"
    ASK = "ask"
    DOWNLOAD = "download"


PIPELINE_STEPS = [
    "compile",
    "parse_ir",
    "build_graph",
    "detect",
    "review_findings",
    "propose_fix",
    "await_fix_approval",
    "apply_fix",
    "complete",
]


@dataclass
class JourneySession:
    session_id: str
    source: Path
    source_content: str
    current_step: str = "compile"
    step_index: int = 0
    finding_index: int = 0
    status: str = "active"
    messages: list[dict[str, str]] = field(default_factory=list)
    completed_steps: list[str] = field(default_factory=list)
    ir_path: Path | None = None
    ir_text: str = ""
    ir_json: dict[str, Any] | None = None
    graph: Any = None
    findings: list[Any] = field(default_factory=list)
    localized: list[Any] = field(default_factory=list)
    explanations: list[Any] = field(default_factory=list)
    scan_report: dict[str, Any] | None = None
    graph_json: dict[str, Any] | None = None
    repair_plan: dict[str, Any] | None = None
    fix_result: dict[str, Any] | None = None
    patched_source_content: str = ""
    awaiting: str = "continue"
    compile_error: str = ""
    step_anchor: dict[str, str] = field(default_factory=dict)
    simulation: dict[str, Any] | None = None


_SESSIONS: dict[str, JourneySession] = {}


def _load_graph_builder():
    import importlib

    return importlib.import_module("src.const_graph").build_heterogeneous_graph


def _load_ir_parser():
    import importlib

    return importlib.import_module("src.ir_parser").parse_ll_file


def _load_detection():
    import importlib

    for name in ("src.V2.detection.engine", "src.v2.detection.engine"):
        try:
            return importlib.import_module(name).DetectionEngine
        except Exception:
            continue
    raise RuntimeError("V2 detection engine not available")


def _load_localization():
    import importlib

    return importlib.import_module("src.V2.localization.localizer").VulnerabilityLocalizer


def _load_explainability():
    import importlib

    return importlib.import_module("src.V2.explain.engine").ExplainabilityEngine


def _load_repair_planner():
    from src.V2.repair.planner import RepairPlanner

    return RepairPlanner


def _finding_dict(finding: Any) -> dict[str, Any]:
    if hasattr(finding, "to_dict"):
        return finding.to_dict()
    return dict(finding)


def _localized_dict(item: Any) -> dict[str, Any]:
    return item.to_dict() if hasattr(item, "to_dict") else dict(item)


def _explanation_dict(item: Any) -> dict[str, Any]:
    return item.to_dict() if hasattr(item, "to_dict") else dict(item)


def _append_message(session: JourneySession, role: str, content: str, speak: str = "") -> None:
    msg: dict[str, str] = {"role": role, "content": content}
    if speak and role == "assistant":
        msg["speak"] = speak
    session.messages.append(msg)


def _append_assistant(
    session: JourneySession,
    event: str,
    fallback_display: str,
    fallback_speak: str | None = None,
    *,
    fresh_step: bool = False,
) -> None:
    from .journey_ai import conversational_pair

    if fresh_step:
        session.messages = []
    display, speak_text = conversational_pair(
        session, event, fallback_display, fallback_speak
    )
    msg: dict[str, str] = {
        "role": "assistant",
        "content": display,
        "speak": speak_text,
    }
    if fresh_step:
        session.step_anchor = dict(msg)
    session.messages.append(msg)


def _trim_step_messages(session: JourneySession) -> None:
    """Keep only the current step anchor plus the latest Q&A."""
    if not session.step_anchor or len(session.messages) < 2:
        return
    tail = session.messages[-2:]
    session.messages = [dict(session.step_anchor), *tail]


def _narrate_analysis_complete(session: JourneySession) -> str:
    count = len(session.findings)
    if count == 0:
        return (
            "Your file compiled and passed our security checks — I didn't find "
            "issues in the categories we scan for. You're done unless you want "
            "to ask a question about the analysis."
        )
    cwes = sorted({getattr(f, "cwe_id", "") for f in session.findings})
    return (
        f"I finished analyzing **{session.source.name}**. I found **{count}** "
        f"issue(s): {', '.join(cwes)}. I'll walk through each one and then "
        "suggest a fix you can approve."
    )


def _current_finding_bundle(session: JourneySession) -> dict[str, Any]:
    idx = session.finding_index
    if session.findings and idx >= len(session.findings):
        idx = len(session.findings) - 1
    finding = _finding_dict(session.findings[idx]) if idx < len(session.findings) else {}
    loc = (
        _localized_dict(session.localized[idx])
        if idx < len(session.localized)
        else {}
    )
    cwe = finding.get("cwe_id")
    expl = None
    for item in session.explanations:
        e = _explanation_dict(item)
        if e.get("cwe_id") == cwe:
            expl = e
            break
    return {"finding": finding, "localization": loc, "explanation": expl}


def _narrate_finding(session: JourneySession) -> tuple[str, str]:
    bundle = _current_finding_bundle(session)
    f = bundle["finding"]
    loc = bundle["localization"]
    expl = bundle["explanation"] or {}
    idx = session.finding_index + 1
    total = len(session.findings)
    cwe = f.get("cwe_id", "issue")
    title = f.get("title", "security issue")
    fn = loc.get("function") or f.get("function") or "unknown"
    sev = f.get("severity", "unknown")
    display = (
        f"**Review {idx}/{total}** — **{cwe}** ({title}). "
        f"Severity **{sev}** in `{fn}`."
    )
    if expl.get("root_cause"):
        display += f"\n\n{expl['root_cause']}"
    if expl.get("repair_strategy"):
        display += f"\n\n**Suggested fix:** {expl['repair_strategy']}"
    display += "\n\nApprove to continue, or ask me to explain further."
    speak = (
        f"Finding {idx} of {total}: {cwe}, {sev} severity. "
        f"I have a fix suggestion when you are ready to continue."
    )
    return display, speak


def _narrate_propose_fix(session: JourneySession) -> str:
    plan = session.repair_plan or {}
    actions = plan.get("actions") or []
    if not actions:
        warnings = plan.get("warnings") or []
        return (
            "No deterministic repair actions are available for these findings. "
            + (" ".join(warnings) if warnings else "")
            + " You may skip repair and finish."
        )
    lines = ["Here's what I recommend changing:"]
    for action in actions:
        lines.append(f"• **{action.get('cwe_id')}** — {action.get('description')}")
    lines.append(
        "\nIf you **Approve**, I'll apply a verified repair and prepare an updated "
        "C file you can download. **Reject** to stay here, or **Skip** to finish without a fix."
    )
    return "\n".join(lines)


def _can_download(session: JourneySession) -> bool:
    return bool(
        session.patched_source_content
        or (session.status == "complete" and not session.findings)
    )


def _wants_download(text: str) -> bool:
    import re

    lower = (text or "").lower()
    if re.search(r"\bdownload\b", lower):
        return True
    return bool(
        re.search(r"\b(save|export|get)\b", lower)
        and re.search(r"\b(file|fix|source|code|patched|suggested)\b", lower)
    )


def _allowed_actions(session: JourneySession) -> list[str]:
    extra: list[str] = []
    if _can_download(session):
        extra.append(JourneyAction.DOWNLOAD.value)
    if session.status in ("complete", "failed"):
        return extra + [JourneyAction.RESTART.value]
    if session.compile_error:
        return [JourneyAction.RESTART.value]
    step = session.current_step
    if step == "await_fix_approval":
        return [
            JourneyAction.APPROVE_FIX.value,
            JourneyAction.REJECT_FIX.value,
            JourneyAction.SKIP_FIX.value,
            JourneyAction.ASK.value,
        ]
    if step == "complete":
        return extra + [JourneyAction.RESTART.value]
    if step in ("apply_fix",):
        return [JourneyAction.CONTINUE.value, JourneyAction.ASK.value] + extra
    return [JourneyAction.CONTINUE.value, JourneyAction.ASK.value] + extra


def _artifact_for_step(session: JourneySession) -> dict[str, Any]:
    """Conversation-first: summary cards only (no raw code / IR)."""
    bundle = _current_finding_bundle(session) if session.findings else {}
    f = bundle.get("finding") or {}
    fix = session.fix_result or {}
    return {
        "kind": "summary",
        "title": "At a glance",
        "finding_count": len(session.findings),
        "current_cwe": f.get("cwe_id"),
        "current_title": f.get("title"),
        "severity": f.get("severity"),
        "fix_status": fix.get("status"),
        "step": session.current_step,
    }


_CWE_FIX_SNIPPETS: dict[str, str] = {
    "CWE-190": (
        "/* CWE-190: use checked addition */\n"
        "if (__builtin_add_overflow(a, b, &result)) {\n"
        "    return -1;  /* or handle overflow */\n"
        "}"
    ),
    "CWE-191": (
        "/* CWE-191: use checked subtraction */\n"
        "if (__builtin_sub_overflow(a, b, &result)) {\n"
        "    return -1;\n"
        "}"
    ),
    "CWE-369": (
        "/* CWE-369: guard division */\n"
        "if (divisor == 0) {\n"
        "    return -1;\n"
        "}\n"
        "result = dividend / divisor;"
    ),
    "CWE-476": (
        "/* CWE-476: NULL check before dereference */\n"
        "if (ptr == NULL) {\n"
        "    return -1;\n"
        "}\n"
        "value = *ptr;"
    ),
}


def _guess_issue_line(
    source_lines: list[str], loc: dict[str, Any], finding: dict[str, Any]
) -> int | None:
    line_no = loc.get("source_line")
    if isinstance(line_no, int) and 1 <= line_no <= len(source_lines):
        return line_no
    instr = (loc.get("vulnerable_instruction") or finding.get("instruction") or "").lower()
    for i, line in enumerate(source_lines, start=1):
        stripped = line.strip().lower()
        if not stripped or stripped.startswith("//"):
            continue
        if "malloc" in instr and "malloc" in stripped:
            return i
        if "+" in instr and "+" in line and "=" in line:
            return i
        if "/" in instr and "/" in line and "div" not in stripped:
            return i
    return None


def _fix_snippet_for_session(session: JourneySession, cwe_id: str | None) -> str:
    plan = session.repair_plan or {}
    actions = plan.get("actions") or []
    parts: list[str] = []
    for action in actions:
        if cwe_id and action.get("cwe_id") != cwe_id:
            continue
        parts.append(f"/* {action.get('cwe_id')}: {action.get('description')} */")
        snippet = _CWE_FIX_SNIPPETS.get(action.get("cwe_id", ""), "")
        if snippet:
            parts.append(snippet)
        parts.append(f"/* IR target: {action.get('instruction', '')} */")
    if not parts and cwe_id:
        expl_bundle = _current_finding_bundle(session)
        expl = (expl_bundle.get("explanation") or {}).get("repair_strategy")
        if expl:
            parts.append(f"/* Strategy: {expl} */")
        snippet = _CWE_FIX_SNIPPETS.get(cwe_id, "")
        if snippet:
            parts.append(snippet)
    if session.patched_source_content and session.status == "complete":
        parts.append("/* Verified repair applied — use Download for full file. */")
    return "\n\n".join(parts) if parts else "/* Approve fix to generate a verified patch. */"


def _build_code_view(session: JourneySession) -> dict[str, Any]:
    source_lines = session.source_content.splitlines()
    show_steps = {
        "review_findings",
        "await_fix_approval",
        "apply_fix",
        "complete",
    }
    if session.current_step == "await_fix_approval" and session.repair_plan:
        bundle = {}
        f = {}
        loc = {}
        cwe = None
        issue_line = None
        lines_out = [
            {"number": n, "text": line}
            for n, line in enumerate(source_lines[: min(24, len(source_lines))], start=1)
        ]
        return {
            "visible": True,
            "cwe_id": "Repair plan",
            "function": None,
            "issue_line": issue_line,
            "lines": lines_out,
            "highlight_lines": [],
            "ir_instruction": "",
            "suggested_fix": _fix_snippet_for_session(session, None),
            "patched_preview": "",
        }
    if not session.findings or session.current_step not in show_steps:
        return {"visible": False}

    bundle = _current_finding_bundle(session)
    f = bundle.get("finding") or {}
    loc = bundle.get("localization") or {}
    cwe = f.get("cwe_id")
    issue_line = _guess_issue_line(source_lines, loc, f)

    if issue_line is None and source_lines:
        issue_line = min(len(source_lines), max(1, len(source_lines) // 2))

    window = 4
    start = max(1, (issue_line or 1) - window)
    end = min(len(source_lines), (issue_line or 1) + window)
    lines_out = [
        {"number": n, "text": source_lines[n - 1]} for n in range(start, end + 1)
    ]
    highlight = [issue_line] if issue_line and start <= issue_line <= end else []

    return {
        "visible": True,
        "cwe_id": cwe,
        "function": loc.get("function") or f.get("function"),
        "issue_line": issue_line,
        "lines": lines_out,
        "highlight_lines": highlight,
        "ir_instruction": loc.get("vulnerable_instruction") or f.get("instruction"),
        "suggested_fix": _fix_snippet_for_session(session, cwe),
        "patched_preview": session.patched_source_content[:4000]
        if session.patched_source_content
        else "",
    }


def _ir_preview(session: JourneySession, limit: int = 10) -> list[str]:
    if not session.ir_text:
        return []
    lines = []
    for line in session.ir_text.splitlines():
        stripped = line.strip()
        if not stripped or stripped.startswith(";"):
            continue
        lines.append(stripped[:120])
        if len(lines) >= limit:
            break
    return lines


def _build_stage_view(session: JourneySession) -> dict[str, Any]:
    """Visual compiler output for the current phase (not a full IR dump)."""
    step = session.current_step
    source_n = len(session.source_content.splitlines())
    pipeline = [
        {"id": "source", "label": "C source", "done": True},
        {"id": "ir", "label": "LLVM IR", "done": "compile" in session.completed_steps},
        {"id": "parse", "label": "Parsed IR", "done": "parse_ir" in session.completed_steps},
        {"id": "graph", "label": "Graph", "done": "build_graph" in session.completed_steps},
        {"id": "detect", "label": "Findings", "done": "detect" in session.completed_steps},
    ]
    cards: list[dict[str, Any]] = []
    preview: list[str] = []

    if step in {"await_compile"} and "compile" not in session.completed_steps:
        cards.append({"label": "Input", "value": f"{source_n} C lines"})
        cards.append({"label": "Next output", "value": "LLVM IR via clang"})
        preview = session.source_content.splitlines()[:8]
    elif "compile" in session.completed_steps:
        ir_lines = len(session.ir_text.splitlines()) if session.ir_text else 0
        cards.append({"label": "IR lines", "value": str(ir_lines)})
        preview = _ir_preview(session)
    if session.ir_json:
        funcs = session.ir_json.get("functions") if isinstance(session.ir_json, dict) else None
        nfunc = len(funcs) if isinstance(funcs, list) else "—"
        cards.append({"label": "Parsed functions", "value": str(nfunc)})
    if session.graph is not None:
        cards.append({"label": "Graph nodes", "value": str(session.graph.number_of_nodes())})
        cards.append({"label": "Graph edges", "value": str(session.graph.number_of_edges())})
    if session.findings:
        cards.append({"label": "Findings", "value": str(len(session.findings))})

    return {
        "title": _step_label(step),
        "pipeline": pipeline,
        "cards": cards,
        "preview_title": "Compiler output (preview)",
        "preview": preview,
    }


def _build_simulation(session: JourneySession) -> dict[str, Any]:
    source_lines = session.source_content.splitlines()
    if not session.findings:
        return {
            "active": False,
            "message": "Run detection first, then ask to simulate.",
        }
    bundle = _current_finding_bundle(session)
    f = bundle.get("finding") or {}
    loc = bundle.get("localization") or {}
    cwe = f.get("cwe_id") or "CWE"
    issue = _guess_issue_line(source_lines, loc, f) or 1
    start = max(1, issue - 3)
    end = min(len(source_lines), issue + 3)
    lines = [{"number": n, "text": source_lines[n - 1], "hot": n == issue} for n in range(start, end + 1)]
    steps = [
        {
            "title": "1. Reach the line",
            "detail": f"Input flows into `{loc.get('function') or f.get('function') or 'main'}` and hits line {issue}.",
        },
        {
            "title": "2. Trigger",
            "detail": f"{cwe}: attacker supplies a value that breaks the assumption on the highlighted line.",
        },
        {
            "title": "3. Effect",
            "detail": "Memory or control state is corrupted (crash, leak, or unexpected branch).",
        },
        {
            "title": "4. Fix",
            "detail": "The suggested check stops the bad value before that line runs.",
        },
    ]
    return {
        "active": True,
        "cwe_id": cwe,
        "title": f.get("title") or "Attack walkthrough",
        "issue_line": issue,
        "lines": lines,
        "steps": steps,
        "fix": _fix_snippet_for_session(session, cwe),
    }


def _run_compile(session: JourneySession) -> None:
    try:
        session.ir_path = compile_to_ir(session.source)
        session.ir_text = session.ir_path.read_text(encoding="utf-8", errors="replace")
        session.compile_error = ""
    except Exception as exc:
        session.compile_error = str(exc)
        raise


def _run_parse(session: JourneySession) -> None:
    if not session.ir_path:
        raise RuntimeError("compile step required first")
    parse_ll_file = _load_ir_parser()
    session.ir_json = parse_ll_file(str(session.ir_path))


def _run_graph(session: JourneySession) -> None:
    if session.ir_json is None:
        raise RuntimeError("parse step required first")
    build_graph = _load_graph_builder()
    session.graph = build_graph(session.ir_json)


def _run_detect(session: JourneySession) -> None:
    if session.graph is None:
        raise RuntimeError("graph step required first")
    sample = {
        "filename": session.source.name,
        "source_file": str(session.source),
        "graph": session.graph,
    }
    DetectionEngine = _load_detection()
    engine = DetectionEngine()
    session.findings = engine.analyze(sample)
    VulnerabilityLocalizer = _load_localization()
    session.localized = VulnerabilityLocalizer().localize(sample, session.findings)
    ExplainabilityEngine = _load_explainability()
    cwes = list(dict.fromkeys(x.cwe_id for x in session.findings))
    session.explanations = ExplainabilityEngine().explain_all(session.graph, cwes)

    analysis = {
        "source": str(session.source),
        "graph": session.graph,
        "node_count": session.graph.number_of_nodes(),
        "edge_count": session.graph.number_of_edges(),
        "findings": session.findings,
        "cwes": cwes,
        "localized": session.localized,
        "explanations": session.explanations,
    }
    bundle = analysis_bundle(analysis)
    session.scan_report = bundle["scan"]
    session.graph_json = bundle["graph"]


def _run_propose_fix(session: JourneySession) -> None:
    if not session.localized:
        session.repair_plan = {"actions": [], "warnings": ["No localized findings."]}
        return
    planner = _load_repair_planner()()
    plan = planner.plan(session.localized)
    session.repair_plan = plan.to_dict()


def _run_apply_fix(session: JourneySession) -> None:
    with tempfile.TemporaryDirectory(prefix="securecc_journey_fix_") as tmp:
        session.fix_result = _to_jsonable(
            fix_source(
                session.source,
                output_dir=Path(tmp),
                keep_ir=True,
                build_artifact=True,
            )
        )


def _preview_next_phase(next_step: str) -> tuple[str, str]:
    """Screen + speak preview before user approves running a phase."""
    previews: dict[str, tuple[str, str]] = {
        "compile": (
            "**Phase: Compile** — We'll turn your C source into LLVM IR. "
            "Syntax errors stop here; security rules come later.",
            "Next I will compile your file to intermediate representation. Approve when ready.",
        ),
        "parse_ir": (
            "**Phase: Parse IR** — We structure the IR so the analyzer can reason about functions and instructions.",
            "Next we parse the IR into a structured form. Approve to continue.",
        ),
        "build_graph": (
            "**Phase: Build graph** — We connect basic blocks and data flow. "
            "Many memory and control issues show up on this graph.",
            "Next we build the control and data flow graph. Approve to continue.",
        ),
        "detect": (
            "**Phase: Detect** — We run CWE detectors (overflow, buffers, UAF, loops, and more). "
            "Issues tied to a compiler stage will be explained in review.",
            "Next we run security detection on the graph. Approve to scan.",
        ),
    }
    return previews.get(
        next_step,
        ("Approve to run the next compiler step.", "Approve the next step when ready."),
    )


def _advance_pipeline(session: JourneySession) -> None:
    """Run exactly one pipeline phase after user approves."""
    session.simulation = None
    step = session.current_step

    if step == "await_compile":
        try:
            _run_compile(session)
            session.completed_steps.append("compile")
            disp, spk = _preview_next_phase("parse_ir")
            disp = (
                f"**Compile complete** — LLVM IR generated for **{session.source.name}**.\n\n"
                + disp
            )
            spk = f"Compile succeeded. {spk}"
            _append_assistant(session, "post_compile", disp, spk, fresh_step=True)
            session.current_step = "await_parse"
        except Exception:
            session.status = "failed"
            _append_message(
                session,
                "assistant",
                f"Compile failed.\n\n{session.compile_error}",
                "Compile failed. Fix errors and start over.",
            )
        return

    if step == "await_parse":
        _run_parse(session)
        session.completed_steps.append("parse_ir")
        disp, spk = _preview_next_phase("build_graph")
        disp = "**Parse complete** — IR is structured.\n\n" + disp
        spk = f"Parse complete. {spk}"
        _append_assistant(session, "post_parse", disp, spk, fresh_step=True)
        session.current_step = "await_graph"
        return

    if step == "await_graph":
        _run_graph(session)
        session.completed_steps.append("build_graph")
        disp, spk = _preview_next_phase("detect")
        disp = "**Graph built** — ready for detectors.\n\n" + disp
        spk = f"Graph is ready. {spk}"
        _append_assistant(session, "post_graph", disp, spk, fresh_step=True)
        session.current_step = "await_detect"
        return

    if step == "await_detect":
        _run_detect(session)
        session.completed_steps.append("detect")
        count = len(session.findings)
        if count == 0:
            disp = (
                "**Detection complete** — no issues in our rule set for this file. "
                "Journey finished; you can still ask questions."
            )
            _append_assistant(
                session,
                "detect_clean",
                disp,
                "Scan complete. No issues found.",
                fresh_step=True,
            )
            session.current_step = "complete"
            session.status = "complete"
            return
        cwes = ", ".join(sorted({getattr(f, "cwe_id", "") for f in session.findings}))
        disp = (
            f"**Detection complete** — **{count}** issue(s): {cwes}. "
            "We'll review each and then suggest a verified fix."
        )
        session.finding_index = 0
        fd, fs = _narrate_finding(session)
        combined = disp + "\n\n" + fd
        _append_assistant(
            session,
            "finding_review",
            combined,
            fs,
            fresh_step=True,
        )
        session.current_step = "review_findings"
        return

    if step == "review_findings":
        session.finding_index += 1
        if session.finding_index < len(session.findings):
            fd, fs = _narrate_finding(session)
            _append_assistant(session, "finding_review", fd, fs, fresh_step=True)
            return
        session.completed_steps.append("review_findings")
        _run_propose_fix(session)
        fb = _narrate_propose_fix(session)
        _append_assistant(
            session,
            "propose_fix",
            fb,
            "Here is my repair plan. Approve fix, skip, or ask questions.",
            fresh_step=True,
        )
        session.current_step = "await_fix_approval"
        return

    if step == "await_fix_approval":
        return

    if step == "apply_fix":
        session.completed_steps.append("apply_fix")
        session.current_step = "complete"
        session.status = "complete"
        status = (session.fix_result or {}).get("status", "unknown")
        disp = (
            f"**Verification:** {status}. "
            f"{(session.fix_result or {}).get('message', '')}"
        )
        spk = f"Verification status is {status}."
        if str(status).upper() == "VERIFIED":
            from .journey_ai import generate_patched_c_source

            patched = generate_patched_c_source(session)
            if patched:
                session.patched_source_content = patched
                disp += "\n\n**Download** your updated C file below."
                spk += " Your fixed source is ready to download."
        _append_assistant(session, "fix_complete", disp, spk, fresh_step=True)
        return

    if step == "complete":
        session.status = "complete"


def start_journey(source: Path) -> dict[str, Any]:
    source = source.resolve()
    session_id = str(uuid.uuid4())
    session = JourneySession(
        session_id=session_id,
        source=source,
        source_content=source.read_text(encoding="utf-8", errors="replace"),
    )
    _SESSIONS[session_id] = session

    disp, spk = _preview_next_phase("compile")
    welcome = (
        f"Let's walk through **{session.source.name}** like a compiler pipeline — "
        "compile, parse, graph, detect, then review and fix. "
        "I'll pause after **each phase** for your approval.\n\n" + disp
    )
    _append_assistant(session, "welcome", welcome, spk, fresh_step=True)
    session.current_step = "await_compile"

    return session_to_payload(session)


def journey_advance(session_id: str, action: str, question: str = "") -> dict[str, Any]:
    session = _SESSIONS.get(session_id)
    if not session:
        raise KeyError("unknown journey session")

    action = (action or JourneyAction.CONTINUE.value).lower()

    if action == JourneyAction.RESTART.value:
        src = session.source
        _cleanup_session(session)
        return start_journey(src)

    if action == JourneyAction.ASK.value:
        _append_message(session, "user", question)
        if _wants_download(question):
            if _can_download(session):
                _append_message(
                    session,
                    "assistant",
                    f"Downloading **{session.source.name}** (repaired) now.",
                    "Starting your file download.",
                )
            else:
                _append_message(
                    session,
                    "assistant",
                    "There is no fixed file yet — **approve and verify** the repair first, "
                    "then ask to download again.",
                    "Approve the fix first, then you can download.",
                )
            _trim_step_messages(session)
            payload = session_to_payload(session)
            if _can_download(session):
                payload["trigger_download"] = True
            return payload

        import re

        if re.search(r"\b(simulat|walk.?through the attack|attack scenario)\b", (question or "").lower()):
            session.simulation = _build_simulation(session)
            if session.simulation.get("active"):
                msg = (
                    f"**Simulation on screen** for **{session.simulation.get('cwe_id')}** — "
                    "highlighted source, four attack steps, and the fix. "
                    "This stays visual so voice does not re-read the whole walkthrough."
                )
                speak = "Simulation is on screen: highlighted line, four steps, and the fix."
            else:
                msg = session.simulation.get("message") or "Detection must finish first."
                speak = "Run detection before a simulation."
            _append_message(session, "assistant", msg, speak)
            _trim_step_messages(session)
            return session_to_payload(session)

        from .journey_ai import answer_scoped_pair

        display, speak = answer_scoped_pair(session, question)
        _append_message(session, "assistant", display, speak)
        _trim_step_messages(session)
        return session_to_payload(session)

    if action == JourneyAction.DOWNLOAD.value:
        if not _can_download(session):
            raise ValueError("no fixed source available to download yet")
        payload = session_to_payload(session)
        payload["trigger_download"] = True
        return payload

    if action == JourneyAction.REJECT_FIX.value:
        _append_message(
            session,
            "assistant",
            "Repair not applied. You can Approve when ready, or Skip to finish.",
        )
        return session_to_payload(session)

    if action == JourneyAction.SKIP_FIX.value:
        session.completed_steps.append("await_fix_approval_skipped")
        session.current_step = "complete"
        session.status = "complete"
        _append_message(
            session,
            "assistant",
            "Skipped repair. Journey complete — original source unchanged.",
        )
        return session_to_payload(session)

    if action == JourneyAction.APPROVE_FIX.value:
        if session.current_step != "await_fix_approval":
            raise ValueError("approve_fix is only valid while awaiting fix approval")
        _append_message(
            session,
            "assistant",
            "Applying the repair and running verification — one moment…",
        )
        _run_apply_fix(session)
        session.current_step = "apply_fix"
        fix = session.fix_result or {}
        status = fix.get("status", "unknown")
        msg = f"Fix status: **{status}**. {fix.get('message', '')}"
        if str(status).upper() == "VERIFIED":
            from .journey_ai import generate_patched_c_source

            patched = generate_patched_c_source(session)
            if patched:
                session.patched_source_content = patched
                msg += "\n\nDownload your updated C file when you're ready."
        _append_assistant(
            session,
            "fix_applied",
            msg,
            f"Fix applied. Status {status}. Approve to finish.",
            fresh_step=True,
        )
        return session_to_payload(session)

    if action != JourneyAction.CONTINUE.value:
        raise ValueError(f"unsupported action: {action}")

    if session.status == "failed":
        raise ValueError("compile failed — restart the journey")

    _advance_pipeline(session)
    return session_to_payload(session)


def _ui_pipeline_steps(session: JourneySession) -> list[dict[str, str]]:
    rail = [
        ("compile", ("await_compile",)),
        ("parse_ir", ("await_parse",)),
        ("build_graph", ("await_graph",)),
        ("detect", ("await_detect",)),
        ("review", ("review_findings",)),
        ("fix", ("await_fix_approval", "apply_fix", "propose_fix")),
        ("done", ("complete",)),
    ]
    current = session.current_step
    active_i = 0
    if session.status == "complete":
        active_i = len(rail) - 1
    else:
        for i, (_, steps) in enumerate(rail):
            if current in steps:
                active_i = i
                break
        if current == "await_compile" and "compile" not in session.completed_steps:
            active_i = 0

    out = []
    for i, (pid, _) in enumerate(rail):
        label = _step_label(pid if pid != "review" else "review_findings")
        if pid == "review":
            label = "Review"
        elif pid == "fix":
            label = "Fix"
        elif pid == "done":
            label = "Done"
        if session.status == "complete":
            state = "done"
        elif i < active_i:
            state = "done"
        elif i == active_i:
            state = "active"
        else:
            state = "pending"
        out.append({"id": pid, "label": label, "state": state})
    return out


def get_session(session_id: str) -> JourneySession | None:
    return _SESSIONS.get(session_id)


def download_content(session: JourneySession) -> tuple[str, str]:
    if session.patched_source_content:
        name = f"securecc_fixed_{session.source.stem}.c"
        return name, session.patched_source_content
    if session.status == "complete" and not session.findings:
        return session.source.name, session.source_content
    raise ValueError("no downloadable source for this session")


def _cleanup_session(session: JourneySession) -> None:
    if session.ir_path and session.ir_path.exists():
        try:
            session.ir_path.unlink()
        except OSError:
            pass
    _SESSIONS.pop(session.session_id, None)


def session_to_payload(session: JourneySession) -> dict[str, Any]:
    download_name = f"securecc_fixed_{session.source.stem}.c"
    if session.patched_source_content:
        download_name = f"securecc_fixed_{session.source.stem}.c"
    elif session.status == "complete" and not session.findings:
        download_name = session.source.name

    return {
        "session_id": session.session_id,
        "source": {
            "path": str(session.source),
            "name": session.source.name,
        },
        "status": session.status,
        "current_step": session.current_step,
        "step_label": _step_label(session.current_step),
        "finding_index": session.finding_index,
        "finding_count": len(session.findings),
        "pipeline_steps": _ui_pipeline_steps(session),
        "allowed_actions": _allowed_actions(session),
        "artifact": _artifact_for_step(session),
        "messages": list(session.messages),
        "compile_error": session.compile_error or None,
        "download_available": _can_download(session),
        "download_filename": download_name,
        "code_view": _build_code_view(session),
        "stage_view": _build_stage_view(session),
        "simulation": session.simulation,
    }


def _step_label(step_id: str) -> str:
    labels = {
        "await_compile": "Compile",
        "compile": "Compile → LLVM IR",
        "await_parse": "Parse IR",
        "parse_ir": "Parse IR",
        "await_graph": "Build graph",
        "build_graph": "Build graph",
        "await_detect": "Detect CWEs",
        "detect": "Detect CWEs",
        "review_findings": "Review findings",
        "propose_fix": "Propose repair",
        "await_fix_approval": "Approve fix",
        "apply_fix": "Verify repair",
        "complete": "Complete",
    }
    return labels.get(step_id, step_id.replace("_", " ").title())
