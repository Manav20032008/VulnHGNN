"""LLVM IR heap allocation/deallocation patterns (C libc + C++ operator new/delete)."""

from __future__ import annotations

import re

# C: @malloc @calloc @realloc
# C++ Itanium ABI (clang on macOS/Linux): @_Znwm @_Znam @_Znwj @_ZdlPv @_ZdaPv
_HEAP_ALLOC_SYMBOL = re.compile(
    r"@(?:malloc|calloc|realloc|_Zn[wam]{2}|_Znwj)\b"
)
_HEAP_DEALLOC_SYMBOL = re.compile(
    r"@(?:free|_ZdlPv|_ZdaPv|_ZdlPvm|_ZdlPvj)\b"
)

# Call-site text heuristics (substring checks on instruction text).
def is_heap_alloc_call(text: str) -> bool:
    return bool(text and _HEAP_ALLOC_SYMBOL.search(text))


def is_heap_dealloc_call(text: str) -> bool:
    return bool(text and _HEAP_DEALLOC_SYMBOL.search(text))


def is_dealloc_call_excluding_self_use(text: str) -> bool:
    """True if this call releases heap memory (for UAF: dealloc itself is not a 'use')."""
    return is_heap_dealloc_call(text)


def ptr_arg_from_dealloc(text: str) -> str | None:
    """First pointer SSA operand passed to free or operator delete."""
    if not text:
        return None
    m = re.search(
        r"@(?:free|_ZdlPv|_ZdaPv|_ZdlPvm|_ZdlPvj)\s*\(\s*(?:ptr\s+)?(?:[\w.]+\s+)?(%[-\w.$]+)",
        text,
    )
    return m.group(1) if m else None


def heap_alloc_size_operand(text: str) -> str | None:
    """
    Size argument for OOM / dynamic-size heuristics.
    malloc(n) -> n; operator new(size) -> size (first arg).
    """
    if not text or not is_heap_alloc_call(text):
        return None
    m = re.search(
        r"@(?:malloc|realloc)\((?:i\d+\s+)?([^,)]+)",
        text,
    )
    if m:
        return m.group(1).strip()
    m = re.search(
        r"@(?:calloc)\([^,]+,\s*(?:i\d+\s+)?([^)]+)\)",
        text,
    )
    if m:
        return m.group(1).strip()
    m = re.search(
        r"@_Zn[wam]{2}\([^,]*?(?:i\d+\s+)?([^,)]+)",
        text,
    )
    if m:
        return m.group(1).strip()
    return None
