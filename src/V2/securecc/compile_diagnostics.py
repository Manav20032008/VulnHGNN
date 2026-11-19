from __future__ import annotations

import re
import shutil
import subprocess
from pathlib import Path

from src.V2.analysis.finding import SecurityFinding, SourceLocation
from src.V2.detection.catalog import STAGE_COMPILER_WARNING
from src.V2.securecc.languages import compiler_for_source, is_java_path

_DIAG_LINE = re.compile(
    r"^(?P<file>.*?):(?P<line>\d+):(?P<col>\d+):\s*"
    r"(?P<kind>warning|error|note):\s*(?P<message>.+)$"
)

_RULES: tuple[tuple[re.Pattern[str], str, str, str], ...] = (
    (re.compile(r"uninitialized", re.I), "CWE-457", "Use of Uninitialized Variable", "MEDIUM"),
    (re.compile(r"format string", re.I), "CWE-134", "Use of Externally-Controlled Format String", "HIGH"),
    (re.compile(r"array subscript.*(?:read|load)", re.I), "CWE-125", "Out-of-bounds Read", "HIGH"),
    (re.compile(r"index .* outside .* bounds.*read", re.I), "CWE-125", "Out-of-bounds Read", "HIGH"),
    (re.compile(r"array subscript", re.I), "CWE-787", "Out-of-bounds Write", "HIGH"),
    (re.compile(r"out of bounds", re.I), "CWE-787", "Out-of-bounds Write", "HIGH"),
    (re.compile(r"memory leak", re.I), "CWE-401", "Memory Leak", "MEDIUM"),
    (re.compile(r"exhausted|allocation .* too large", re.I), "CWE-789", "Memory Allocation with Excessive Size", "HIGH"),
    (re.compile(r"infinite loop|cannot be terminated", re.I), "CWE-835", "Infinite Loop", "MEDIUM"),
    (re.compile(r"implicit declaration", re.I), "CWE-477", "Use of Obsolete Function", "MEDIUM"),
    (re.compile(r"deprecated", re.I), "CWE-477", "Use of Obsolete Function", "LOW"),
)


def _map_message_to_cwe(message: str) -> tuple[str, str, str]:
    cwe_id, title, severity = "CWE-GENERIC", "Compiler Diagnostic", "LOW"
    for pattern, cid, ctitle, sev in _RULES:
        if pattern.search(message):
            cwe_id, title, severity = cid, ctitle, sev
            break
    return cwe_id, title, severity


def _parse_clang_diagnostics(combined: str, *, kinds: frozenset[str]) -> list[dict]:
    items: list[dict] = []
    seen: set[tuple[str, int, str]] = set()
    for line in combined.splitlines():
        match = _DIAG_LINE.match(line.strip())
        if not match:
            continue
        kind = match.group("kind")
        if kind not in kinds:
            continue
        message = match.group("message")
        line_no = int(match.group("line"))
        col_no = int(match.group("col"))
        key = (kind, line_no, message[:100])
        if key in seen:
            continue
        seen.add(key)
        cwe_id, title, sev = _map_message_to_cwe(message)
        category = "ERROR" if kind == "error" else "WARNING"
        items.append(
            {
                "line": line_no,
                "column": col_no,
                "category": category,
                "title": title if kind == "warning" else "Compile error",
                "message": message,
                "source": "compiler",
                "cwe_id": cwe_id if kind == "warning" else None,
                "severity": sev if kind == "warning" else "HIGH",
                "compiler_kind": kind,
            }
        )
    return items


def _run_clang_syntax_check(source: Path) -> str:
    source = source.resolve()
    compiler = compiler_for_source(source)
    if not shutil.which(compiler):
        return ""
    cmd = [
        compiler,
        "-fsyntax-only",
        "-Wall",
        "-Wextra",
        "-Wformat=2",
        "-Wuninitialized",
        "-Wno-unused-parameter",
        str(source),
    ]
    result = subprocess.run(cmd, text=True, capture_output=True)
    return (result.stdout or "") + "\n" + (result.stderr or "")


def collect_compiler_diagnostics(source: Path) -> list[dict]:
    """Clang or javac errors and warnings for live lint / analyze UI."""
    if is_java_path(source):
        from .java_ir import parse_javac_diagnostics, run_javac_diagnostics

        combined = run_javac_diagnostics(source)
        if not combined.strip():
            return []
        return parse_javac_diagnostics(combined)

    combined = _run_clang_syntax_check(source)
    if not combined.strip():
        return []
    return _parse_clang_diagnostics(combined, kinds=frozenset({"error", "warning"}))


def collect_compiler_warnings(source: Path) -> list[SecurityFinding]:
    """Run clang with security-oriented warnings and map diagnostics to CWE findings."""
    if is_java_path(source):
        return []

    combined = _run_clang_syntax_check(source)
    if not combined.strip():
        return []

    findings: list[SecurityFinding] = []
    seen: set[tuple[str, int, str]] = set()

    for line in combined.splitlines():
        match = _DIAG_LINE.match(line.strip())
        if not match or match.group("kind") != "warning":
            continue
        message = match.group("message")
        file_path = match.group("file")
        line_no = int(match.group("line"))
        col_no = int(match.group("col"))

        cwe_id, title, severity = _map_message_to_cwe(message)

        key = (cwe_id, line_no, message[:80])
        if key in seen:
            continue
        seen.add(key)

        findings.append(
            SecurityFinding(
                cwe_id=cwe_id,
                title=title,
                severity=severity,
                confidence=0.85,
                message=message,
                location=SourceLocation(file=file_path, line=line_no, column=col_no),
                function=None,
                instruction=f"{file_path}:{line_no}:{col_no}",
                evidence=[f"clang_warning={message}"],
                detector="ClangDiagnostics",
                node_id=None,
                compiler_stage=STAGE_COMPILER_WARNING,
            )
        )
    return findings
