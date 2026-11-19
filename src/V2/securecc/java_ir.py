"""Compile Java sources to LLVM IR for the same HGNN pipeline as C/C++."""

from __future__ import annotations

import os
import re
import shutil
import subprocess
import tempfile
from pathlib import Path
from typing import Any

_JAVAC_DIAG = re.compile(
    r"^(?P<file>.*?):(?P<line>\d+):\s*(?P<kind>error|warning):\s*(?P<message>.+)$"
)


def javac_available() -> bool:
    return shutil.which("javac") is not None


def java_llvm_tool_available() -> bool:
    return jllvm_binary() is not None


def jllvm_binary() -> str | None:
    env = (os.environ.get("SECURECC_JLLVM") or "").strip()
    if env:
        p = Path(env).expanduser()
        if p.is_file():
            return str(p.resolve())
    for name in ("jllvm", "jllvm.exe"):
        found = shutil.which(name)
        if found:
            return found
    return None


def compile_java_to_ir(source: Path) -> Path:
    """javac → jllvm (--emit-ir). Caller deletes the returned .ll path."""
    source = source.resolve()
    if not source.exists():
        raise FileNotFoundError(f"source file not found: {source}")

    if not javac_available():
        raise RuntimeError(
            "Java analysis requires a JDK (javac on PATH). "
            "Install a JDK and set JAVA_HOME if needed."
        )
    tool = jllvm_binary()
    if not tool:
        raise RuntimeError(
            "Java LLVM IR requires the jllvm compiler on PATH "
            "(or set SECURECC_JLLVM to its binary). "
            "Build from https://github.com/nktkt/jllvm — then javac + jllvm feed the same IR pipeline as clang."
        )

    with tempfile.TemporaryDirectory(prefix="securecc_java_") as tmp:
        classes = Path(tmp) / "classes"
        classes.mkdir()
        javac = subprocess.run(
            ["javac", "-encoding", "UTF-8", "-d", str(classes), str(source)],
            text=True,
            capture_output=True,
        )
        if javac.returncode != 0:
            err = (javac.stderr or javac.stdout or "").strip()
            raise RuntimeError(f"Java compilation failed:\n{err}")

        class_files = sorted(classes.rglob("*.class"))
        if not class_files:
            raise RuntimeError("javac produced no class files")

        with tempfile.NamedTemporaryFile(
            suffix=".ll", prefix="securecc_java_", delete=False
        ) as ll_tmp:
            ll_path = Path(ll_tmp.name)

        cmd = [tool, *[str(p) for p in class_files], "--emit-ir", "-o", str(ll_path)]
        result = subprocess.run(cmd, text=True, capture_output=True)
        if result.returncode != 0:
            try:
                ll_path.unlink()
            except OSError:
                pass
            err = (result.stderr or result.stdout or "").strip()
            raise RuntimeError(f"Java LLVM IR generation failed:\n{err}")

        return ll_path


def run_javac_diagnostics(source: Path) -> str:
    if not javac_available():
        return ""
    source = source.resolve()
    result = subprocess.run(
        ["javac", "-encoding", "UTF-8", "-Xlint:all", str(source)],
        text=True,
        capture_output=True,
    )
    return (result.stdout or "") + "\n" + (result.stderr or "")


def parse_javac_diagnostics(combined: str) -> list[dict]:
    items: list[dict] = []
    seen: set[tuple[Any, ...]] = set()
    for line in combined.splitlines():
        match = _JAVAC_DIAG.match(line.strip())
        if not match:
            continue
        kind = match.group("kind")
        line_no = int(match.group("line"))
        message = match.group("message")
        key = (kind, line_no, message[:100])
        if key in seen:
            continue
        seen.add(key)
        items.append(
            {
                "line": line_no,
                "column": 1,
                "category": "ERROR" if kind == "error" else "WARNING",
                "title": "Compile error" if kind == "error" else "Java lint",
                "message": message,
                "source": "compiler",
                "compiler_kind": kind,
            }
        )
    return sorted(items, key=lambda x: (x.get("line") or 0, x.get("column") or 0))