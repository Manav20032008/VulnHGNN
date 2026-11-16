from __future__ import annotations

import json
import os
import re
from typing import Any

SCOPE_REFUSAL = (
    "That’s outside this security review — ask about this file, its CWEs, memory issues, "
    "compiler steps, or the suggested fix."
)

_SECURITY_TERMS = frozenset(
    {
        "heap",
        "stack",
        "buffer",
        "overflow",
        "underflow",
        "malloc",
        "free",
        "calloc",
        "realloc",
        "pointer",
        "uaf",
        "use-after-free",
        "double free",
        "cwe",
        "llvm",
        "ir",
        "compile",
        "parser",
        "graph",
        "severity",
        "vulnerability",
        "exploit",
        "memory",
        "leak",
        "race",
        "deadlock",
        "integer",
        "sanitize",
        "fix",
        "repair",
        "verification",
        "example",
        "simulate",
        "simulation",
        "attack",
        "attacker",
        "payload",
        "scenario",
        "walkthrough",
        "demonstrate",
    }
)


def _groq_client():
    from ..groq_config import groq_api_key

    api_key = groq_api_key()
    if not api_key:
        return None
    try:
        from groq import Groq
    except ImportError:
        return None
    return Groq(api_key=api_key)


def _model() -> str:
    from ..groq_config import groq_model

    return groq_model()


def _extract_json(text: str) -> dict[str, Any]:
    text = (text or "").strip()
    try:
        return json.loads(text)
    except json.JSONDecodeError:
        match = re.search(r"\{[\s\S]*\}", text)
        if match:
            return json.loads(match.group(0))
        raise


def _session_context(session: Any) -> dict[str, Any]:
    findings = []
    for raw in session.findings:
        f = raw.to_dict() if hasattr(raw, "to_dict") else dict(raw)
        findings.append(
            {
                "cwe_id": f.get("cwe_id"),
                "title": f.get("title"),
                "severity": f.get("severity"),
                "message": f.get("message"),
                "function": f.get("function"),
                "compiler_stage": f.get("compiler_stage"),
            }
        )
    plan = session.repair_plan or {}
    fix = session.fix_result or {}
    idx = getattr(session, "finding_index", 0)
    if findings and idx >= len(findings):
        idx = len(findings) - 1
    current = findings[idx] if findings and idx < len(findings) else {}
    return {
        "file": session.source.name,
        "step": session.current_step,
        "finding_count": len(session.findings),
        "finding_index": idx,
        "current_finding": current,
        "findings": findings[:12],
        "repair_plan": plan.get("actions") or [],
        "fix_status": fix.get("status"),
        "fix_message": fix.get("message"),
    }


def _chat(system: str, user: str, json_mode: bool = False) -> str | None:
    client = _groq_client()
    if not client:
        return None
    kwargs: dict[str, Any] = {
        "model": _model(),
        "messages": [
            {"role": "system", "content": system},
            {"role": "user", "content": user},
        ],
        "temperature": 0.25,
    }
    if json_mode:
        kwargs["response_format"] = {"type": "json_object"}
    try:
        resp = client.chat.completions.create(**kwargs)
        return (resp.choices[0].message.content or "").strip()
    except Exception as exc:
        global _LAST_GROQ_ERROR
        _LAST_GROQ_ERROR = str(exc)[:240]
        return None


_LAST_GROQ_ERROR: str = ""


def shorten_for_speak(text: str, max_len: int = 200) -> str:
    plain = re.sub(r"\*\*([^*]+)\*\*", r"\1", text or "")
    plain = re.sub(r"\s+", " ", plain).strip()
    if len(plain) <= max_len:
        return plain
    cut = plain[: max_len - 1].rsplit(" ", 1)[0]
    return cut + "…"


def conversational_pair(
    session: Any,
    event: str,
    fallback_display: str,
    fallback_speak: str | None = None,
) -> tuple[str, str]:
    """Chat text (screen) + short line for TTS."""
    speak_fb = fallback_speak or shorten_for_speak(fallback_display, 180)
    system = (
        "You are SecureCC, a calm British-style security copilot (JARVIS-like tone). "
        "Return ONLY JSON with keys display and speak. "
        "display: 2–4 sentences for the chat UI; markdown **bold** allowed; no code/IR. "
        "speak: at most 2 short spoken sentences; no markdown; brief summary only. "
        "Mention the compiler phase when relevant. End speak with what the user should do next "
        "(approve step, ask a question). Stay on this analysis session."
    )
    user = (
        f"Event: {event}\n"
        f"Context:\n{json.dumps(_session_context(session), indent=2)}\n\n"
        f"Draft display:\n{fallback_display}\n\n"
        f"Draft speak:\n{speak_fb}"
    )
    raw = _chat(system, user, json_mode=True)
    if raw:
        try:
            data = _extract_json(raw)
            display = (data.get("display") or fallback_display).strip()
            speak = (data.get("speak") or speak_fb).strip()
            if display and speak:
                return display, shorten_for_speak(speak, 220)
        except (json.JSONDecodeError, TypeError):
            pass
    return fallback_display, speak_fb


def conversational_step(session: Any, event: str, fallback: str) -> str:
    display, _ = conversational_pair(session, event, fallback)
    return display


def _question_relates_to_review(question: str) -> bool:
    lower = question.lower()
    if any(term in lower for term in _SECURITY_TERMS):
        return True
    return bool(
        re.search(
            r"\b(cwe-\d+|what do you mean|explain|why is|how does|tell me about|give me|show me|can you)\b",
            lower,
        )
    )


def _question_intent(question: str) -> str:
    lower = question.lower()
    if re.search(
        r"\b(simulate|simulation|walkthrough|walk through|model the attack|attack scenario)\b",
        lower,
    ) or (re.search(r"\battack\b", lower) and re.search(r"\b(how|would|could|simulate)\b", lower)):
        return "attack_simulation"
    if re.search(
        r"\b(example|for instance|such as|demonstrate|show me an|give me an|sample)\b",
        lower,
    ):
        return "example"
    return "general"


def _is_clearly_off_topic(question: str) -> bool:
    lower = question.lower()
    patterns = (
        r"\bweather\b",
        r"\brecipe\b",
        r"\bfootball\b",
        r"\bcricket score\b",
        r"\bstock price\b",
        r"\bbitcoin price\b",
        r"\bwrite (me )?a poem\b",
        r"\bwho is (elon|messi|trump)\b",
        r"\bcapital of (france|india|usa)\b",
    )
    return any(re.search(p, lower) for p in patterns)


def _local_concept_answer(question: str, session: Any) -> tuple[str, str] | None:
    lower = question.lower()
    if "heap" in lower:
        display = (
            "The **heap** is dynamic memory your program gets from `malloc` / `calloc` "
            "(and frees with `free`). Bugs here — overflows, use-after-free, double-free — "
            "often show up in our **graph** and **detect** phases for this file."
        )
        if session.findings:
            cwes = ", ".join(
                sorted({getattr(f, "cwe_id", "") for f in session.findings})[:4]
            )
            display += f"\n\nFor **{session.source.name}**, we flagged: {cwes}."
        speak = (
            "The heap is dynamic memory from malloc and free. "
            "Many serious bugs are heap-related; I can tie this to your findings."
        )
        return display, speak
    if ("stack" in lower and "overflow" in lower) or lower.strip() in ("stack", "what is stack"):
        display = (
            "The **stack** holds locals and return addresses per function call. "
            "**Stack overflow** means writing past a stack buffer — classic CWE-121/122 territory."
        )
        speak = "The stack stores local variables; overflowing it corrupts memory and is a common CWE."
        return display, speak
    return None


def _local_example_answer(question: str, session: Any) -> tuple[str, str] | None:
    bundle_ctx = _session_context(session)
    findings = bundle_ctx.get("findings") or []
    cur = bundle_ctx.get("current_finding") or {}
    cwe = cur.get("cwe_id") or (findings[0].get("cwe_id") if findings else "CWE-190")
    snippets = {
        "CWE-190": (
            "**Vulnerable example:**\n```c\nint sum = a + b;  /* signed overflow if a,b large */\n```\n"
            "**Safer pattern:**\n```c\nint sum;\nif (__builtin_add_overflow(a, b, &sum)) { /* error */ }\n```"
        ),
        "CWE-476": (
            "**Vulnerable:**\n```c\nint x = *p;\n```\n"
            "**Safer:**\n```c\nif (p == NULL) return -1;\nint x = *p;\n```"
        ),
    }
    body = snippets.get(cwe, snippets["CWE-190"])
    body += f"\n\nThis illustrates the kind of issue we're reviewing in **{session.source.name}**."
    speak = "Here is a short before and after example for this class of bug."
    return body, speak


def _local_attack_simulation(session: Any) -> tuple[str, str]:
    ctx = _session_context(session)
    findings = ctx.get("findings") or []
    if not findings:
        display = (
            "**Attack simulation (conceptual):** With no findings yet, run the **detect** phase first. "
            "Then I can walk through how an attacker would abuse the specific weakness."
        )
        return display, "Complete detection first, then ask me to simulate the attack."

    cur = ctx.get("current_finding") or findings[0]
    cwe = cur.get("cwe_id", "CWE")
    title = cur.get("title", "weakness")
    display = (
        f"**Attack simulation for {cwe}** ({title}) on **{session.source.name}**:\n\n"
        "1. **Recon** — Attacker feeds inputs that reach the vulnerable path.\n"
        "2. **Trigger** — They push values that violate assumptions (overflow, NULL, bad length).\n"
        "3. **Impact** — Memory corruption or logic bug leads to crash, data leak, or control hijack.\n"
        "4. **Mitigation** — Our suggested fix blocks the trigger at the source.\n\n"
        "This is educational for *your* code only — not a weaponized exploit."
    )
    speak = (
        f"Simulation: an attacker would trigger {cwe} via crafted inputs, "
        "then exploit the resulting memory or logic failure."
    )
    return display, speak


def _system_prompt_for_intent(intent: str) -> str:
    base = (
        "You are SecureCC, a C/C++ security copilot for ONE file review. "
        "Return ONLY JSON: {\"display\": \"...\", \"speak\": \"...\"}. "
        "Stay helpful and conversational. Refuse ONLY obvious off-topic trivia (sports, recipes)."
    )
    if intent == "attack_simulation":
        return (
            base
            + " Intent: ATTACK SIMULATION for the current finding(s). "
            "display: numbered steps (4–6) describing how an attacker would abuse THIS vulnerability "
            "in THIS file — recon, trigger input, technical effect, impact, what the fix stops. "
            "Educational only; no real-world targeting. Markdown ok; short fenced C ok if needed. "
            "speak: 2 sentences summarizing the attack path."
        )
    if intent == "example":
        return (
            base
            + " Intent: EXAMPLE. "
            "display: brief vulnerable vs fixed C snippet (max ~10 lines total) tied to the active CWE. "
            "Use markdown code fences. Relate to session findings. "
            "speak: one sentence on what the example shows."
        )
    return (
        base
        + " Answer concepts, phases, findings, fixes, examples, and attack scenarios for this session. "
        "display: 2–5 sentences; markdown ok. speak: 1–2 short sentences."
    )


def answer_scoped_pair(session: Any, question: str) -> tuple[str, str]:
    q = (question or "").strip()
    if not q:
        return (
            "Ask about this phase, a vulnerability, or the suggested fix.",
            "What would you like to know about this step?",
        )

    if _is_clearly_off_topic(q):
        return SCOPE_REFUSAL, shorten_for_speak(SCOPE_REFUSAL, 180)

    intent = _question_intent(q)
    if intent == "attack_simulation":
        local = _local_attack_simulation(session)
    elif intent == "example":
        local = _local_example_answer(q, session)
    else:
        local = _local_concept_answer(q, session)
    if local and not _groq_client():
        return local

    on_topic = _question_relates_to_review(q) or intent in ("example", "attack_simulation")

    system = _system_prompt_for_intent(intent)
    user = f"Question: {q}\nIntent: {intent}\n\nSession:\n{json.dumps(_session_context(session), indent=2)}"
    raw = _chat(system, user, json_mode=True)
    if raw:
        try:
            data = _extract_json(raw)
            display = (data.get("display") or "").strip()
            speak = (data.get("speak") or "").strip()
            refused = display == SCOPE_REFUSAL or (
                "outside this security review" in display.lower()
            )
            if refused and on_topic:
                if intent == "attack_simulation":
                    return _local_attack_simulation(session)
                if intent == "example":
                    ex = _local_example_answer(q, session)
                    if ex:
                        return ex
                local = _local_concept_answer(q, session)
                if local:
                    return local
                display = (
                    f"Good question. In this review, that ties to the CWEs and memory rules "
                    f"we're checking on **{session.source.name}**. "
                    "Ask me to link it to a specific finding if you want more detail."
                )
                speak = shorten_for_speak(display, 200)
            elif refused:
                return SCOPE_REFUSAL, shorten_for_speak(SCOPE_REFUSAL, 180)
            if display:
                return display, shorten_for_speak(speak or display, 200)
        except (json.JSONDecodeError, TypeError):
            pass

    if on_topic:
        fallback = (
            "I couldn't reach the AI right now, but your question fits this security review — "
            "try again in a moment or ask about a specific CWE from the findings."
        )
        return fallback, shorten_for_speak(fallback, 200)

    from ..groq_config import groq_status

    st = groq_status()
    if st.get("groq_hint"):
        fallback = f"AI is unavailable — {st['groq_hint']}"
    elif _LAST_GROQ_ERROR:
        fallback = f"AI request failed — {_LAST_GROQ_ERROR}"
    else:
        fallback = (
            "AI is unavailable. Check GROQ_API_KEY in .env and restart securecc web."
        )
    return fallback, shorten_for_speak(fallback, 180)


def answer_scoped_question(session: Any, question: str) -> str:
    return answer_scoped_pair(session, question)[0]


def generate_patched_c_source(session: Any) -> str | None:
    """Produce downloadable C source after verified repair (AI-assisted from plan)."""
    fix = session.fix_result or {}
    if str(fix.get("status", "")).upper() != "VERIFIED":
        return None

    system = (
        'You output ONLY JSON: {"patched_c": "<full valid C file>"}. '
        "Apply the repair plan to fix security issues in the original C source. "
        "Keep the same overall structure; use safe patterns (checks, bounded functions). "
        "No markdown, no explanation outside JSON."
    )
    user = json.dumps(
        {
            "original_c": session.source_content[:12000],
            "repair_plan": (session.repair_plan or {}).get("actions") or [],
            "findings": _session_context(session)["findings"],
        },
        indent=2,
    )
    raw = _chat(system, user, json_mode=True)
    if not raw:
        return _annotated_fallback_source(session)
    try:
        data = _extract_json(raw)
        patched = data.get("patched_c") or data.get("source")
        if isinstance(patched, str) and len(patched) > 20:
            return patched
    except (json.JSONDecodeError, TypeError):
        pass
    return _annotated_fallback_source(session)


def _annotated_fallback_source(session: Any) -> str:
    lines = [
        "/* SecureCC suggested repairs (verify with scan before production use) */",
    ]
    for action in (session.repair_plan or {}).get("actions") or []:
        lines.append(f"/* - {action.get('cwe_id')}: {action.get('description')} */")
    lines.append("")
    lines.append(session.source_content)
    return "\n".join(lines)
