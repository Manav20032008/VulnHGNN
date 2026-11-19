from __future__ import annotations

import re
from typing import Any


def scan_source_heuristics(source: str, *, language: str) -> list[dict[str, Any]]:
    """Fast pattern checks on raw source (hints, not proof)."""
    return _c_family_heuristics(source)


_IDENT = r"[A-Za-z_]\w*"
_SAME_VAR_DIV = re.compile(rf"\b({_IDENT})\s*(/|%)\s*\1\b")
_FOR_ZERO_INIT = re.compile(
    rf"\bfor\s*\(\s*(?:[\w\s*]+\s+)?({_IDENT})\s*=\s*0\b"
)
# Assignment / init to literal zero (not ==, !=, <=, etc.)
_ZERO_ASSIGN = re.compile(rf"\b({_IDENT})\s*(?<![!=<>])=\s*0\b")
# Any other assignment clears our "known zero" hint for that name.
_ANY_ASSIGN = re.compile(rf"\b({_IDENT})\s*(?<![!=<>])=\s*([^=;]+)")


def _vars_that_can_be_zero(source: str) -> set[str]:
    """Loop counters and similar bindings that start at zero."""
    found: set[str] = set()
    for line in source.splitlines():
        head = line.split("//")[0]
        for match in _FOR_ZERO_INIT.finditer(head):
            found.add(match.group(1))
        # while (i == 0) / while (i <= 0) — divisor may be zero on path
        for match in re.finditer(rf"\bwhile\s*\(\s*({_IDENT})\s*(?:==|<=)\s*0\b", head):
            found.add(match.group(1))
    return found


def _apply_zero_assignments(stripped: str, assigned_zero: set[str]) -> None:
    """Update assigned_zero from assignments on this line (after division check)."""
    for match in _ZERO_ASSIGN.finditer(stripped):
        assigned_zero.add(match.group(1))
    for match in _ANY_ASSIGN.finditer(stripped):
        var = match.group(1)
        rhs = match.group(2).strip()
        if re.match(r"^0\b", rhs):
            assigned_zero.add(var)
        else:
            assigned_zero.discard(var)


def _check_variable_division(
    stripped: str,
    lineno: int,
    loop_zero_vars: set[str],
    assigned_zero_vars: set[str],
    seen: set[tuple[int, str]],
) -> list[dict[str, Any]]:
    out: list[dict[str, Any]] = []
    same_var_on_line: set[str] = set()
    for match in _SAME_VAR_DIV.finditer(stripped):
        var = match.group(1)
        op = match.group(2)
        same_var_on_line.add(var)
        key = (lineno, f"same-{var}-{op}")
        if key in seen:
            continue
        seen.add(key)
        out.append(
            _item(
                line=lineno,
                column=match.start() + 1,
                category="WARNING",
                title="Possible division by zero",
                message=(
                    f"`{var} {op} {var}` is undefined when {var} is 0 "
                    f"(e.g. first loop iteration). Confirm CWE-369 with Analyze after compile."
                ),
                source="heuristic",
                cwe_id="CWE-369",
            )
        )

    for match in re.finditer(rf"/\s*({_IDENT})\b", stripped):
        divisor = match.group(1)
        if divisor in same_var_on_line:
            continue
        if divisor in loop_zero_vars:
            key = (lineno, f"div-loop-{divisor}")
            if key in seen:
                continue
            seen.add(key)
            out.append(
                _item(
                    line=lineno,
                    column=match.start() + 1,
                    category="WARNING",
                    title="Possible division by zero in loop",
                    message=(
                        f"Dividing by `{divisor}` but a `for` loop initializes `{divisor} = 0`, "
                        f"so the divisor may be zero (CWE-369). Guard before divide or start from 1."
                    ),
                    source="heuristic",
                    cwe_id="CWE-369",
                )
            )
        elif divisor in assigned_zero_vars:
            key = (lineno, f"div-assign-{divisor}")
            if key in seen:
                continue
            seen.add(key)
            out.append(
                _item(
                    line=lineno,
                    column=match.start() + 1,
                    category="WARNING",
                    title="Possible division by zero",
                    message=(
                        f"Dividing by `{divisor}` which was assigned `0` earlier "
                        f"(undefined behavior; CWE-369). Confirm with Analyze after compile."
                    ),
                    source="heuristic",
                    cwe_id="CWE-369",
                )
            )

    for match in re.finditer(rf"%\s*({_IDENT})\b", stripped):
        divisor = match.group(1)
        if divisor in same_var_on_line:
            continue
        if divisor in loop_zero_vars:
            key = (lineno, f"mod-loop-{divisor}")
            if key in seen:
                continue
            seen.add(key)
            out.append(
                _item(
                    line=lineno,
                    column=match.start() + 1,
                    category="WARNING",
                    title="Possible modulo by zero in loop",
                    message=(
                        f"Remainder with `{divisor}` may hit zero when the loop counter starts at 0."
                    ),
                    source="heuristic",
                    cwe_id="CWE-369",
                )
            )
        elif divisor in assigned_zero_vars:
            key = (lineno, f"mod-assign-{divisor}")
            if key in seen:
                continue
            seen.add(key)
            out.append(
                _item(
                    line=lineno,
                    column=match.start() + 1,
                    category="WARNING",
                    title="Possible modulo by zero",
                    message=(
                        f"Modulo by `{divisor}` which was assigned `0` earlier (CWE-369)."
                    ),
                    source="heuristic",
                    cwe_id="CWE-369",
                )
            )
    return out


def _c_family_heuristics(source: str) -> list[dict[str, Any]]:
    out: list[dict[str, Any]] = []
    div_zero = re.compile(r"/\s*0\b|/\s*0\s*;|/\s*0\s*\)|%\s*0\b")
    loop_zero_vars = _vars_that_can_be_zero(source)
    assigned_zero: set[str] = set()
    seen: set[tuple[int, str]] = set()
    dangerous = (
        (re.compile(r"\bstrcpy\s*\("), "CWE-787", "strcpy may overflow the destination buffer."),
        (re.compile(r"\bgets\s*\("), "CWE-676", "gets is unsafe and can overflow buffers."),
        (re.compile(r"\bsprintf\s*\("), "CWE-134", "sprintf can overflow if the format or inputs are unbounded."),
        (re.compile(r"\bscanf\s*\(\s*[^\"]*%s"), "CWE-787", "scanf with %s can overflow without field width."),
        (re.compile(r"\bprintf\s*\(\s*[^\"'%]"), "CWE-134", "printf first argument should be a format string, not a variable."),
    )
    for lineno, line in enumerate(source.splitlines(), start=1):
        stripped = line.split("//")[0]
        if div_zero.search(stripped):
            key = (lineno, "literal-zero")
            if key not in seen:
                seen.add(key)
                out.append(
                    _item(
                        line=lineno,
                        column=1,
                        category="WARNING",
                        title="Possible division by zero",
                        message="Expression divides by literal zero (undefined behavior; may map to CWE-369 after IR analysis).",
                        source="heuristic",
                        cwe_id="CWE-369",
                    )
                )
        out.extend(
            _check_variable_division(
                stripped,
                lineno,
                loop_zero_vars,
                assigned_zero
                | {m.group(1) for m in _ZERO_ASSIGN.finditer(stripped)},
                seen,
            )
        )
        _apply_zero_assignments(stripped, assigned_zero)
        for pattern, cwe, msg in dangerous:
            if pattern.search(stripped):
                out.append(
                    _item(
                        line=lineno,
                        column=1,
                        category="WARNING",
                        title="Risky API or usage",
                        message=msg,
                        source="heuristic",
                        cwe_id=cwe,
                    )
                )
                break
    return out


def _python_heuristics(source: str) -> list[dict[str, Any]]:
    out: list[dict[str, Any]] = []
    assigned_zero: set[str] = set()
    seen: set[tuple[int, str]] = set()
    for lineno, line in enumerate(source.splitlines(), start=1):
        stripped = line.split("#")[0]
        if re.search(r"/\s*0\b|/\s*0\s*#|%\s*0\b", stripped):
            out.append(
                _item(
                    line=lineno,
                    column=1,
                    category="WARNING",
                    title="Possible division by zero",
                    message="Literal division or modulo by zero.",
                    source="heuristic",
                    cwe_id="CWE-369",
                )
            )
        out.extend(
            _check_variable_division(
                stripped,
                lineno,
                set(),
                assigned_zero
                | {m.group(1) for m in _ZERO_ASSIGN.finditer(stripped)},
                seen,
            )
        )
        _apply_zero_assignments(stripped, assigned_zero)
    return out


def _item(
    *,
    line: int,
    column: int,
    category: str,
    title: str,
    message: str,
    source: str,
    cwe_id: str | None = None,
) -> dict[str, Any]:
    return {
        "line": line,
        "column": column,
        "category": category,
        "title": title,
        "message": message,
        "source": source,
        "cwe_id": cwe_id,
    }
