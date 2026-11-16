#!/usr/bin/env python3
"""Regenerate test_files/*.cpp twins from test_files/*.c sources."""

from __future__ import annotations

import re
from pathlib import Path

INCLUDE_MAP = {
    "#include <stdio.h>": "#include <cstdio>",
    "#include <stdlib.h>": "#include <cstdlib>",
    "#include <string.h>": "#include <cstring>",
    "#include <stddef.h>": "#include <cstddef>",
    "#include <stdint.h>": "#include <cstdint>",
}

STD_FUNCS = (
    "printf",
    "fprintf",
    "sprintf",
    "snprintf",
    "scanf",
    "sscanf",
    "fscanf",
    "malloc",
    "calloc",
    "realloc",
    "free",
    "strlen",
    "strcpy",
    "strcat",
    "strncpy",
    "strncat",
    "memcpy",
    "memset",
    "memcmp",
    "exit",
    "abort",
)


SKIP_CPP_STEMS = frozenset(
    {
        "test_01_clean",
        "test_04_cwe369",
        "test_05_cwe476",
        "test_20_cwe415",
        "test_21_cwe416",
        "test_22_cwe401",
    }
)


def convert(content: str, basename: str) -> str:
    content = re.sub(rf"\b{re.escape(basename)}\.c\b", f"{basename}.cpp", content)
    for old, new in INCLUDE_MAP.items():
        content = content.replace(old, new)
    if any(h in content for h in ("#include <c", "#include <cstring>")):
        for fn in STD_FUNCS:
            content = re.sub(rf"(?<![\w.:]){fn}\s*\(", rf"std::{fn}(", content)
    return content


def main() -> int:
    print(
        "Idiomatic C++ fixtures are maintained by scripts/write_idiomatic_cpp_fixtures.py"
    )
    print("This sync script is disabled to avoid overwriting them.")
    return 0

    root = Path(__file__).resolve().parents[1] / "test_files"
    for cpath in sorted(root.glob("*.c")):
        if cpath.stem in SKIP_CPP_STEMS:
            print(f"skip (hand-written C++): {cpath.stem}")
            continue
        cpp_path = cpath.with_suffix(".cpp")
        out = convert(cpath.read_text(encoding="utf-8"), cpath.stem)
        cpp_path.write_text(out, encoding="utf-8")
        print(cpp_path.relative_to(root.parent))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
