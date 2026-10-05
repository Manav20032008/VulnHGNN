"""
ir_healer.py — deterministic LLVM-IR remediation for VulnHGNN 2.0.

This module preserves the public API used by Phase 3:
    repair_ir(ll_content, detected_cwes, vuln_instructions=None)

Design goals for SecureCC:
  * do not insert a branch in the middle of an existing basic block;
  * keep the original SSA result name whenever possible;
  * support LLVM opaque pointers and immediate integer operands;
  * make generated IR compilable before SecureCC can accept it;
  * target only the localized instruction text when localization is supplied.

The previous IR healer used branch/label templates that could leave the
original basic block with instructions after a newly inserted terminator.
That is not valid LLVM control flow. The implementations below prefer
branch-free transformations where they are sufficient.
"""

from __future__ import annotations

import re
from typing import Optional


_repair_counter = 0


def _next_id() -> int:
    global _repair_counter
    _repair_counter += 1
    return _repair_counter


def _reset_counter() -> None:
    global _repair_counter
    _repair_counter = 0


def _clean_instruction(text: str) -> str:
    """Remove trailing LLVM debug metadata for comparison."""
    text = text.strip()
    return re.sub(r",?\s*![A-Za-z_][\w.]*\s*!\d+\s*$", "", text).strip()


def _is_vulnerable_line(stripped_line: str, vuln_texts: set[str]) -> bool:
    if not vuln_texts:
        return True
    clean_line = _clean_instruction(stripped_line)
    return any(clean_line == _clean_instruction(v) for v in vuln_texts)


def _integer_type_width(typ: str) -> int:
    m = re.fullmatch(r"i(\d+)", typ)
    return int(m.group(1)) if m else 32


def _append_declarations(lines: list[str], declarations: set[str]) -> list[str]:
    if not declarations:
        return lines

    existing = "\n".join(lines)
    missing = [d for d in sorted(declarations) if d not in existing]
    if not missing:
        return lines

    # Put intrinsic declarations before the first define. This is valid LLVM
    # module-level placement and keeps the declarations easy to inspect.
    insert_at = next(
        (i for i, line in enumerate(lines) if line.startswith("define ")),
        len(lines),
    )
    prefix = [d for d in missing]
    prefix.append("")
    return lines[:insert_at] + prefix + lines[insert_at:]


def _repair_cwe190_ir(
    lines: list[str],
    vuln_instructions: list[dict],
    declarations: set[str],
) -> tuple[list[str], int]:
    """
    Repair signed/unsigned integer add/mul using LLVM's
    with.overflow intrinsics and a branch-free safe fallback.

    The overflow intrinsic is lowered by LLVM/Clang normally.
    We deliberately avoid llvm.*.sat.* because those names can
    become unresolved external symbols on the direct clang path.
    """
    patched: list[str] = []
    count = 0

    pattern = re.compile(
        r"^(\s*)(%[\w.$-]+)\s*=\s*"
        r"(add|mul)\s+"
        r"(?:(nsw|nuw)(?:\s+(nsw|nuw))?\s+)?"
        r"(i\d+)\s+([^,\s]+)\s*,\s*([^\s,]+)"
    )

    vuln_texts = {
        x.get("text", "").strip()
        for x in vuln_instructions
        if x.get("text")
    }

    for line in lines:
        stripped = line.strip()
        m = pattern.match(stripped)

        if not m or not _is_vulnerable_line(stripped, vuln_texts):
            patched.append(line)
            continue

        indent, result, opcode, flag1, flag2, typ, a, b = m.groups()

        unsigned = flag1 == "nuw" or flag2 == "nuw"

        if opcode == "add":
            intrinsic = (
                f"@llvm.uadd.with.overflow.{typ}"
                if unsigned
                else f"@llvm.sadd.with.overflow.{typ}"
            )
        else:
            intrinsic = (
                f"@llvm.umul.with.overflow.{typ}"
                if unsigned
                else f"@llvm.smul.with.overflow.{typ}"
            )

        pair_type = f"{{{typ}, i1}}"
        uid = _next_id()

        declarations.add(
            f"declare {pair_type} {intrinsic}({typ}, {typ})"
        )

        checked = f"%securecc_arith_{uid}"
        value = f"%securecc_value_{uid}"
        overflow = f"%securecc_overflow_{uid}"

        patched.append(
            f"{indent}{checked} = call {pair_type} {intrinsic}"
            f"({typ} {a}, {typ} {b})"
        )
        patched.append(
            f"{indent}{value} = extractvalue {pair_type} {checked}, 0"
        )
        patched.append(
            f"{indent}{overflow} = extractvalue {pair_type} {checked}, 1"
        )

        # Safe deterministic fallback.
        #
        # For security remediation we choose zero on overflow rather
        # than allowing an invalid wrapped arithmetic result.
        patched.append(
            f"{indent}{result} = select i1 {overflow}, "
            f"{typ} 0, {typ} {value}"
        )

        count += 1

    return patched, count


def _repair_cwe191_ir(
    lines: list[str],
    vuln_instructions: list[dict],
    declarations: set[str],
) -> tuple[list[str], int]:
    """
    Repair integer subtraction using LLVM's with.overflow intrinsic
    and a branch-free safe fallback.
    """
    patched: list[str] = []
    count = 0

    pattern = re.compile(
        r"^(\s*)(%[\w.$-]+)\s*=\s*"
        r"sub\s+"
        r"(?:(nsw|nuw)(?:\s+(nsw|nuw))?\s+)?"
        r"(i\d+)\s+([^,\s]+)\s*,\s*([^\s,]+)"
    )

    vuln_texts = {
        x.get("text", "").strip()
        for x in vuln_instructions
        if x.get("text")
    }

    for line in lines:
        stripped = line.strip()
        m = pattern.match(stripped)

        if not m or not _is_vulnerable_line(stripped, vuln_texts):
            patched.append(line)
            continue

        indent, result, flag1, flag2, typ, a, b = m.groups()

        unsigned = flag1 == "nuw" or flag2 == "nuw"

        intrinsic = (
            f"@llvm.usub.with.overflow.{typ}"
            if unsigned
            else f"@llvm.ssub.with.overflow.{typ}"
        )

        pair_type = f"{{{typ}, i1}}"
        uid = _next_id()

        declarations.add(
            f"declare {pair_type} {intrinsic}({typ}, {typ})"
        )

        checked = f"%securecc_sub_{uid}"
        value = f"%securecc_sub_value_{uid}"
        overflow = f"%securecc_sub_overflow_{uid}"

        patched.append(
            f"{indent}{checked} = call {pair_type} {intrinsic}"
            f"({typ} {a}, {typ} {b})"
        )
        patched.append(
            f"{indent}{value} = extractvalue {pair_type} {checked}, 0"
        )
        patched.append(
            f"{indent}{overflow} = extractvalue {pair_type} {checked}, 1"
        )
        patched.append(
            f"{indent}{result} = select i1 {overflow}, "
            f"{typ} 0, {typ} {value}"
        )

        count += 1

    return patched, count

def _repair_cwe369_ir(lines: list[str], vuln_instructions: list[dict]) -> tuple[list[str], int]:
    """Replace a possibly-zero divisor with a safe non-zero selected value."""
    patched: list[str] = []
    count = 0

    pattern = re.compile(
        r"^(\s*)(%[\w.$-]+)\s*=\s*"
        r"(sdiv|udiv|srem|urem)\s+"
        r"(i\d+)\s+([^,\s]+)\s*,\s*([^\s,]+)"
    )

    vuln_texts = {
        x.get("text", "").strip() for x in vuln_instructions if x.get("text")
    }

    for line in lines:
        stripped = line.strip()
        m = pattern.match(stripped)
        if not m or not _is_vulnerable_line(stripped, vuln_texts):
            patched.append(line)
            continue

        indent, result, opcode, typ, dividend, divisor = m.groups()
        uid = _next_id()
        safe_divisor = f"%securecc_divisor_{uid}"
        is_zero = f"%securecc_divisor_zero_{uid}"

        patched.append(
            f"{indent}{is_zero} = icmp eq {typ} {divisor}, 0"
        )
        patched.append(
            f"{indent}{safe_divisor} = select i1 {is_zero}, {typ} 1, {typ} {divisor}"
        )
        patched.append(
            f"{indent}{result} = {opcode} {typ} {dividend}, {safe_divisor}"
        )
        count += 1

    return patched, count

def _collect_allocated_aliases(lines: list[str]) -> set[str]:
    """
    Recover pointers derived from heap allocation.

    Handles the common LLVM pattern:

        %p = call ptr @malloc(...)
        store ptr %p, ptr %slot
        %q = load ptr, ptr %slot
        call ... %q

    as well as direct SSA aliases, bitcasts, addrspacecasts, selects,
    and repeated stack-slot loads.
    """
    aliases: set[str] = set()
    pointer_slots: set[str] = set()

    changed = True

    while changed:
        changed = False

        for line in lines:
            stripped = line.strip()

            # Direct allocator result.
            m = re.match(
                r"^(%[\w.$-]+)\s*=\s*call\b.*@"
                r"(?:malloc|calloc|realloc|aligned_alloc)\b",
                stripped,
            )
            if m and m.group(1) not in aliases:
                aliases.add(m.group(1))
                changed = True
                continue

            # Pointer aliases through bitcast/addrspacecast.
            m = re.match(
                r"^(%[\w.$-]+)\s*=\s*"
                r"(?:bitcast|addrspacecast)\b.*?"
                r"\b(%[\w.$-]+)(?:\s|,|$)",
                stripped,
            )
            if m and m.group(2) in aliases and m.group(1) not in aliases:
                aliases.add(m.group(1))
                changed = True
                continue

            # Pointer select aliases.
            m = re.match(
                r"^(%[\w.$-]+)\s*=\s*select\s+i1\s+"
                r"%[^,]+,\s+ptr\s+(%[\w.$-]+),\s+ptr\s+(%[\w.$-]+)",
                stripped,
            )
            if m and (
                m.group(2) in aliases or m.group(3) in aliases
            ) and m.group(1) not in aliases:
                aliases.add(m.group(1))
                changed = True
                continue

            # Track pointer stack slots receiving allocated pointers:
            #
            # store ptr %4, ptr %3
            #
            # If %4 is allocator-derived, %3 becomes an allocation slot.
            m = re.match(
                r"^store\s+ptr\s+(%[\w.$-]+),\s+ptr\s+(%[\w.$-]+)",
                stripped,
            )
            if m and m.group(1) in aliases:
                if m.group(2) not in pointer_slots:
                    pointer_slots.add(m.group(2))
                    changed = True
                continue

            # Load the allocator-derived pointer back out:
            #
            # %5 = load ptr, ptr %3
            #
            # If %3 is an allocation slot, %5 is allocator-derived.
            m = re.match(
                r"^(%[\w.$-]+)\s*=\s*load\s+ptr\s*,\s*ptr\s+(%[\w.$-]+)",
                stripped,
            )
            if m and m.group(2) in pointer_slots:
                if m.group(1) not in aliases:
                    aliases.add(m.group(1))
                    changed = True
                continue

    return aliases


def _repair_cwe476_ir(
    lines: list[str],
    vuln_instructions: list[dict],
) -> tuple[list[str], int]:
    """
    Repair all malloc/calloc/realloc-derived pointer dereferences.

    A malloc result may be loaded from a stack slot multiple times.
    Protecting only the first dereference is incomplete, so this pass
    intentionally repairs every relevant dereference.

    We use:
        %is_null = icmp eq ptr %p, null
        %fallback = alloca <type>
        store <type> 0, ptr %fallback
        %safe = select i1 %is_null, ptr %fallback, ptr %p

    The original pointer is retained for free().
    """

    aliases = _collect_allocated_aliases(lines)

    # Also recover pointer values loaded from allocator-backed stack slots.
    stack_slots: set[str] = set()

    for line in lines:
        stripped = line.strip()

        m = re.match(
            r"^store\s+ptr\s+(%[\w.$-]+),\s+ptr\s+(%[\w.$-]+)",
            stripped,
        )
        if m and m.group(1) in aliases:
            stack_slots.add(m.group(2))

    # Values loaded from those stack slots are allocator-derived aliases.
    changed = True
    while changed:
        changed = False

        for line in lines:
            stripped = line.strip()

            m = re.match(
                r"^(%[\w.$-]+)\s*=\s*load\s+ptr,\s+ptr\s+(%[\w.$-]+)",
                stripped,
            )

            if m and m.group(2) in stack_slots:
                if m.group(1) not in aliases:
                    aliases.add(m.group(1))
                    changed = True

    patched: list[str] = []
    count = 0

    # Typed load through allocator-derived pointer.
    load_re = re.compile(
        r"^(\s*)(%[\w.$-]+)\s*=\s*load\s+"
        r"(i\d+)\s*,\s*ptr\s+(%[\w.$-]+)(.*)$"
    )

    # Typed store through allocator-derived pointer.
    store_re = re.compile(
        r"^(\s*)store\s+"
        r"(i\d+)\s+([^,\s]+)\s*,\s*ptr\s+(%[\w.$-]+)(.*)$"
    )

    # GEP through allocator-derived pointer.
    gep_re = re.compile(
        r"^(\s*)(%[\w.$-]+)\s*=\s*getelementptr\s+"
        r"(.+?),\s*ptr\s+(%[\w.$-]+)(.*)$"
    )

    for line in lines:
        stripped = line.strip()

        # --------------------------------------------------------
        # LOAD
        # --------------------------------------------------------
        m = load_re.match(stripped)

        if m and m.group(4) in aliases:
            indent, result, typ, ptr, suffix = m.groups()

            uid = _next_id()
            is_null = f"%securecc_ptr_null_{uid}"
            fallback = f"%securecc_ptr_fallback_{uid}"
            safe_ptr = f"%securecc_ptr_safe_{uid}"

            patched.extend([
                f"{indent}{is_null} = icmp eq ptr {ptr}, null",
                f"{indent}{fallback} = alloca {typ}, align 8",
                f"{indent}store {typ} 0, ptr {fallback}, align 8",
                f"{indent}{safe_ptr} = select i1 {is_null}, ptr {fallback}, ptr {ptr}",
                f"{indent}{result} = load {typ}, ptr {safe_ptr}{suffix}",
            ])

            # The result is not itself a pointer alias.
            count += 1
            continue

        # --------------------------------------------------------
        # STORE
        # --------------------------------------------------------
        m = store_re.match(stripped)

        if m and m.group(4) in aliases:
            indent, typ, value, ptr, suffix = m.groups()

            uid = _next_id()
            is_null = f"%securecc_ptr_null_{uid}"
            fallback = f"%securecc_ptr_fallback_{uid}"
            safe_ptr = f"%securecc_ptr_safe_{uid}"

            patched.extend([
                f"{indent}{is_null} = icmp eq ptr {ptr}, null",
                f"{indent}{fallback} = alloca {typ}, align 8",
                f"{indent}store {typ} 0, ptr {fallback}, align 8",
                f"{indent}{safe_ptr} = select i1 {is_null}, ptr {fallback}, ptr {ptr}",
                f"{indent}store {typ} {value}, ptr {safe_ptr}{suffix}",
            ])

            count += 1
            continue

        # --------------------------------------------------------
        # GEP
        # --------------------------------------------------------
        m = gep_re.match(stripped)

        if m and m.group(4) in aliases:
            indent, result, gep_body, ptr, suffix = m.groups()

            uid = _next_id()
            is_null = f"%securecc_ptr_null_{uid}"
            safe_ptr = f"%securecc_ptr_safe_{uid}"

            # For GEP we can normalize the base pointer without
            # dereferencing memory at this point.
            patched.extend([
                f"{indent}{is_null} = icmp eq ptr {ptr}, null",
                f"{indent}{safe_ptr} = select i1 {is_null}, ptr null, ptr {ptr}",
                f"{indent}{result} = getelementptr {gep_body}, ptr {safe_ptr}{suffix}",
            ])

            aliases.add(result)
            count += 1
            continue

        # --------------------------------------------------------
        # MEMORY / STRING CALL
        #
        # Example:
        #   %6 = call ptr @strcpy(ptr noundef %5, ptr noundef @.str)
        #
        # If %5 is allocator-derived, protect the pointer argument
        # without changing the original pointer used by free().
        # --------------------------------------------------------
        call_re = re.match(
            r"^(\s*)(%[\w.$-]+\s*=\s*)?call\s+"
            r".*?@([A-Za-z_][\w.$-]*)\((.*)\)(.*)$",
            stripped,
        )

        if call_re:
            indent, result_prefix, function_name, args, call_suffix = call_re.groups()

            memory_calls = {
                "strcpy", "strncpy", "strcat", "strncat",
                "memcpy", "memmove", "memset",
                "sprintf", "snprintf",
                "scanf", "sscanf", "fscanf",
            }

            if function_name in memory_calls:
                # Find pointer arguments whose SSA value is allocator-derived.
                pointer_arg_re = re.compile(
                    r"ptr(?:\s+[A-Za-z_][\w.$-]*)*\s+(%[\w.$-]+)"
                )

                pointer_match = None

                for pm in pointer_arg_re.finditer(args):
                    if pm.group(1) in aliases:
                        pointer_match = pm
                        break

                if pointer_match:
                    ptr = pointer_match.group(1)

                    uid = _next_id()
                    is_null = f"%securecc_ptr_null_{uid}"
                    fallback = f"%securecc_ptr_fallback_{uid}"
                    safe_ptr = f"%securecc_ptr_safe_{uid}"

                    patched.extend([
                        f"{indent}{is_null} = icmp eq ptr {ptr}, null",
                        f"{indent}{fallback} = alloca i8, i64 4096, align 1",
                        f"{indent}{safe_ptr} = select i1 {is_null}, ptr {fallback}, ptr {ptr}",
                    ])

                    safe_args = (
                        args[:pointer_match.start(1)]
                        + safe_ptr
                        + args[pointer_match.end(1):]
                    )

                    call_line = (
                        f"{indent}{result_prefix or ''}"
                        f"call "
                    )

                    # Recover the original call prefix from the stripped
                    # instruction rather than reconstructing its attributes.
                    call_start = stripped.find("call ")
                    original_call = stripped[call_start:]

                    original_arg_start = original_call.find("(")
                    original_arg_end = original_call.rfind(")")

                    if original_arg_start >= 0 and original_arg_end > original_arg_start:
                        original_args = original_call[
                            original_arg_start + 1:original_arg_end
                        ]

                        repaired_args = (
                            original_args[:pointer_match.start(1)]
                            + safe_ptr
                            + original_args[pointer_match.end(1):]
                        )

                        patched_call = (
                            original_call[:original_arg_start + 1]
                            + repaired_args
                            + original_call[original_arg_end:]
                        )

                        patched.append(f"{indent}{result_prefix or ''}{patched_call}")
                        count += 1
                        continue

        # --------------------------------------------------------
        # Do NOT alter allocator calls or free().
        # --------------------------------------------------------
        patched.append(line)

    return patched, count

def validate_ir_syntax(ll_content: str) -> tuple[bool, list[str]]:
    """Lightweight structural validation; SecureCC also performs a real clang build."""
    issues: list[str] = []
    if ll_content.count("{") != ll_content.count("}"):
        issues.append("Unbalanced braces in LLVM IR text")
    return not issues, issues


IR_HEALERS = {
    "CWE-190": _repair_cwe190_ir,
    "CWE-191": _repair_cwe191_ir,
    "CWE-369": _repair_cwe369_ir,
    "CWE-476": _repair_cwe476_ir,
}

HEAL_DESCRIPTIONS = {
    "CWE-190": "Replaced vulnerable integer arithmetic with LLVM with.overflow checks and a safe fallback.",
    "CWE-191": "Replaced vulnerable subtraction with LLVM with.overflow checking and a safe fallback.",
    "CWE-369": "Selected a non-zero divisor before integer division/remainder without adding a branch.",
    "CWE-476": "Protected all malloc-derived memory dereferences with checked safe fallback pointers.",
}


def repair_ir(
    ll_content: str,
    detected_cwes: list,
    vuln_instructions: Optional[list] = None,
) -> dict:
    """Apply deterministic repairs and return the original Phase-3 result schema."""
    _reset_counter()

    if not detected_cwes:
        return {
            "success": True,
            "patched_ir": ll_content,
            "patches": [],
            "total_patches": 0,
            "is_valid": True,
            "validation_issues": [],
            "message": "No vulnerabilities detected — IR is already clean.",
        }

    instructions = vuln_instructions or []
    lines = ll_content.split("\n")
    declarations: set[str] = set()
    patches: list[dict] = []
    total = 0

    for cwe in detected_cwes:
        healer = IR_HEALERS.get(cwe)
        if healer is None:
            patches.append({
                "cwe": cwe,
                "description": f"No IR healer available for {cwe}.",
                "applied": False,
                "count": 0,
            })
            continue

        cwe_instructions = [
            item for item in instructions if item.get("cwe") == cwe
        ] if instructions else []

        if cwe == "CWE-190":
            lines, count = healer(lines, cwe_instructions, declarations)
        elif cwe == "CWE-191":
            lines, count = healer(lines, cwe_instructions, declarations)
        else:
            lines, count = healer(lines, cwe_instructions)

        patches.append({
            "cwe": cwe,
            "description": HEAL_DESCRIPTIONS.get(cwe, "Applied IR repair."),
            "applied": count > 0,
            "count": count,
        })
        total += count

    lines = _append_declarations(lines, declarations)
    patched_ir = "\n".join(lines)
    is_valid, issues = validate_ir_syntax(patched_ir)

    return {
        "success": True,
        "patched_ir": patched_ir,
        "patches": patches,
        "total_patches": total,
        "is_valid": is_valid,
        "validation_issues": issues,
        "message": f"Applied {total} IR-level patch(es) for {len(detected_cwes)} CWE(s).",
    }
