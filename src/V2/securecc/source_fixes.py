from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Any


@dataclass(frozen=True)
class SourceEdit:
    start: int
    end: int
    replacement: str
    kind: str
    line: int
    description: str


def apply_edits(source: str, edits: list[SourceEdit]) -> str:
    if not edits:
        return source
    ordered = sorted(edits, key=lambda e: e.start, reverse=True)
    for i in range(len(ordered) - 1):
        if ordered[i].start < ordered[i + 1].end:
            return source
    out = source
    for edit in ordered:
        out = out[: edit.start] + edit.replacement + out[edit.end :]
    return out


def _line_of(source: str, index: int) -> int:
    return source.count("\n", 0, index) + 1


def collect_printf_int_fixes(source: str) -> list[SourceEdit]:
    """Fix printf(x) → printf("%d", x) when the sole argument is a simple identifier."""
    edits: list[SourceEdit] = []
    pattern = re.compile(r"\bprintf\s*\(\s*([A-Za-z_]\w*)\s*\)")
    for match in pattern.finditer(source):
        ident = match.group(1)
        if ident in {"printf", "fprintf", "sprintf", "snprintf"}:
            continue
        start, end = match.span()
        edits.append(
            SourceEdit(
                start=start,
                end=end,
                replacement=f'printf("%d", {ident})',
                kind="printf_format",
                line=_line_of(source, start),
                description=f'Use a format string: printf("%d", {ident})',
            )
        )
    return edits


def collect_stdio_include_edit(source: str, *, language: str) -> SourceEdit | None:
    if language not in {"c", "cpp"}:
        return None
    if "printf" not in source:
        return None
    if re.search(r'#\s*include\s*<stdio\.h>', source):
        return None
    if language == "cpp" and re.search(r'#\s*include\s*<cstdio>', source):
        return None
    newline = "\r\n" if "\r\n" in source else "\n"
    include_line = "#include <stdio.h>" + newline
    if language == "cpp":
        include_line = "#include <cstdio>" + newline
    includes = list(re.finditer(r"(?m)^[\t ]*#\s*include\s*<[^>]+>[\t ]*(?:\r?\n|$)", source))
    if includes:
        insert_at = includes[-1].end()
    else:
        insert_at = 0
    return SourceEdit(
        start=insert_at,
        end=insert_at,
        replacement=include_line,
        kind="include",
        line=_line_of(source, insert_at),
        description="Added stdio include for printf",
    )


def collect_gets_replacement_edits(source: str) -> list[SourceEdit]:
    """Replace gets(buf) with a bounded fgets line (single-line call only)."""
    edits: list[SourceEdit] = []
    pattern = re.compile(r"\bgets\s*\(\s*([A-Za-z_]\w*)\s*\)\s*;")
    for match in pattern.finditer(source):
        buf = match.group(1)
        start, end = match.span()
        replacement = f'if (fgets({buf}, sizeof({buf}), stdin)) {{ {buf}[strcspn({buf}, "\\n")] = 0; }}'
        edits.append(
            SourceEdit(
                start=start,
                end=end,
                replacement=replacement,
                kind="gets_to_fgets",
                line=_line_of(source, start),
                description=f"Replaced gets({buf}) with fgets + trim",
            )
        )
    return edits


def collect_string_h_include(source: str) -> SourceEdit | None:
    if "strcspn" not in source:
        return None
    if re.search(r'#\s*include\s*<string\.h>', source):
        return None
    newline = "\r\n" if "\r\n" in source else "\n"
    includes = list(re.finditer(r"(?m)^[\t ]*#\s*include\s*<[^>]+>[\t ]*(?:\r?\n|$)", source))
    insert_at = includes[-1].end() if includes else 0
    return SourceEdit(
        start=insert_at,
        end=insert_at,
        replacement="#include <string.h>" + newline,
        kind="include",
        line=_line_of(source, insert_at),
        description="Added string.h for strcspn",
    )


def collect_template_fixes(source: str, *, language: str) -> tuple[list[SourceEdit], list[dict[str, Any]]]:
    edits: list[SourceEdit] = []
    meta: list[dict[str, Any]] = []

    for edit in collect_printf_int_fixes(source):
        edits.append(edit)
        meta.append({"kind": edit.kind, "line": edit.line, "description": edit.description})

    gets_edits = collect_gets_replacement_edits(source)
    if gets_edits:
        edits.extend(gets_edits)
        for edit in gets_edits:
            meta.append({"kind": edit.kind, "line": edit.line, "description": edit.description})
        inc = collect_string_h_include(source)
        if inc:
            edits.append(inc)
            meta.append({"kind": inc.kind, "line": inc.line, "description": inc.description})

    stdio = collect_stdio_include_edit(source, language=language)
    needs_stdio = any(e.kind in {"printf_format", "gets_to_fgets"} for e in edits)
    if stdio and needs_stdio:
        edits.append(stdio)
        meta.append({"kind": stdio.kind, "line": stdio.line, "description": stdio.description})

    return edits, meta


def edits_to_applied_records(edits: list[SourceEdit]) -> list[dict[str, Any]]:
    return [{"kind": e.kind, "line": e.line, "description": e.description} for e in edits]
