from __future__ import annotations

import ast
import json
import shutil
import subprocess
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from src.V2.analysis.finding import SecurityFinding, SourceLocation
from src.V2.detection.catalog import STAGE_PYTHON_AST, STAGE_PYTHON_BANDIT
from src.V2.securecc.scan import build_report


@dataclass
class PythonExplanation:
    cwe_id: str
    title: str
    root_cause: str
    security_impact: str
    repair_strategy: str
    confidence_basis: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "cwe_id": self.cwe_id,
            "title": self.title,
            "root_cause": self.root_cause,
            "security_impact": self.security_impact,
            "repair_strategy": self.repair_strategy,
            "confidence_basis": self.confidence_basis,
            "evidence": [],
        }


class _FindingVisitor(ast.NodeVisitor):
    def __init__(self, source_path: Path, source_lines: list[str]) -> None:
        self.source_path = source_path
        self.source_lines = source_lines
        self.findings: list[SecurityFinding] = []
        self._function_stack: list[str] = []

    def _line_snippet(self, lineno: int) -> str:
        if 1 <= lineno <= len(self.source_lines):
            return self.source_lines[lineno - 1].strip()
        return ""

    def _add(
        self,
        node: ast.AST,
        *,
        cwe_id: str,
        title: str,
        severity: str,
        message: str,
        confidence: float = 0.85,
        detector: str = "python_ast",
    ) -> None:
        lineno = getattr(node, "lineno", None) or 0
        col = getattr(node, "col_offset", None)
        func = self._function_stack[-1] if self._function_stack else None
        snippet = self._line_snippet(lineno) if lineno else message
        self.findings.append(
            SecurityFinding(
                cwe_id=cwe_id,
                title=title,
                severity=severity,
                confidence=confidence,
                message=message,
                location=SourceLocation(
                    file=str(self.source_path),
                    line=lineno or None,
                    column=col,
                ),
                function=func,
                instruction=snippet,
                detector=detector,
                compiler_stage=STAGE_PYTHON_AST,
            )
        )

    def visit_FunctionDef(self, node: ast.FunctionDef) -> None:
        self._function_stack.append(node.name)
        self.generic_visit(node)
        self._function_stack.pop()

    visit_AsyncFunctionDef = visit_FunctionDef

    def visit_Call(self, node: ast.Call) -> None:
        name = _call_name(node.func)
        if name in {"eval", "exec"}:
            self._add(
                node,
                cwe_id="CWE-94",
                title="Improper Control of Generation of Code",
                severity="HIGH",
                message=f"Avoid {name}() with untrusted input.",
            )
        elif name == "pickle.loads":
            self._add(
                node,
                cwe_id="CWE-502",
                title="Deserialization of Untrusted Data",
                severity="HIGH",
                message="pickle.loads on untrusted data can execute arbitrary code.",
            )
        elif name in {"yaml.load", "yaml.unsafe_load"}:
            self._add(
                node,
                cwe_id="CWE-502",
                title="Deserialization of Untrusted Data",
                severity="HIGH",
                message="Use yaml.safe_load or an explicit Loader.",
            )
        elif name == "subprocess.run" or name == "subprocess.call" or name == "os.system":
            if _keyword_true(node, "shell"):
                self._add(
                    node,
                    cwe_id="CWE-78",
                    title="OS Command Injection",
                    severity="HIGH",
                    message="shell=True with external input enables command injection.",
                )
        self.generic_visit(node)


def _call_name(func: ast.AST) -> str:
    if isinstance(func, ast.Name):
        return func.id
    if isinstance(func, ast.Attribute):
        base = _call_name(func.value) if not isinstance(func.value, ast.Name) else func.value.id
        if base:
            return f"{base}.{func.attr}"
        return func.attr
    return ""


def _keyword_true(node: ast.Call, name: str) -> bool:
    for kw in node.keywords:
        if kw.arg == name and isinstance(kw.value, ast.Constant) and kw.value.value is True:
            return True
    return False


def _bandit_findings(source: Path) -> list[SecurityFinding]:
    if not shutil.which("bandit"):
        return []
    try:
        proc = subprocess.run(
            ["bandit", "-q", "-f", "json", str(source)],
            capture_output=True,
            text=True,
            timeout=60,
        )
    except (OSError, subprocess.TimeoutExpired):
        return []
    raw = proc.stdout.strip()
    if not raw:
        return []
    try:
        data = json.loads(raw)
    except json.JSONDecodeError:
        return []

    out: list[SecurityFinding] = []
    for item in data.get("results") or []:
        cwe = item.get("issue_cwe") or {}
        cwe_id = cwe.get("id")
        if cwe_id and not str(cwe_id).startswith("CWE-"):
            cwe_id = f"CWE-{cwe_id}"
        if not cwe_id:
            cwe_id = "CWE-OTHER"
        line = item.get("line_number")
        out.append(
            SecurityFinding(
                cwe_id=str(cwe_id),
                title=item.get("issue_text", "Bandit finding")[:120],
                severity=str(item.get("issue_severity", "MEDIUM")).upper(),
                confidence=0.9,
                message=item.get("issue_text", ""),
                location=SourceLocation(file=str(source), line=line),
                instruction=(item.get("code") or "").strip(),
                detector="bandit",
                compiler_stage=STAGE_PYTHON_BANDIT,
            )
        )
    return out


def _dedupe_findings(findings: list[SecurityFinding]) -> list[SecurityFinding]:
    seen: set[tuple[Any, ...]] = set()
    out: list[SecurityFinding] = []
    for f in findings:
        key = (
            f.cwe_id,
            getattr(f.location, "line", None) if f.location else None,
            (f.instruction or "")[:80],
        )
        if key in seen:
            continue
        seen.add(key)
        out.append(f)
    return out


def analyze_python_source(source: Path) -> dict:
    source = source.resolve()
    text = source.read_text(encoding="utf-8", errors="replace")
    lines = text.splitlines()
    findings: list[SecurityFinding] = []

    try:
        tree = ast.parse(text, filename=str(source))
        visitor = _FindingVisitor(source, lines)
        visitor.visit(tree)
        findings.extend(visitor.findings)
    except SyntaxError as exc:
        findings.append(
            SecurityFinding(
                cwe_id="CWE-1104",
                title="Syntax error",
                severity="HIGH",
                confidence=1.0,
                message=str(exc.msg or exc),
                location=SourceLocation(file=str(source), line=exc.lineno, column=exc.offset),
                instruction=lines[exc.lineno - 1].strip() if exc.lineno and exc.lineno <= len(lines) else "",
                detector="python_parser",
                compiler_stage=STAGE_PYTHON_AST,
            )
        )

    findings.extend(_bandit_findings(source))
    findings = _dedupe_findings(findings)

    localized: list[dict[str, Any]] = []
    for f in findings:
        localized.append(
            {
                "cwe_id": f.cwe_id,
                "title": f.title,
                "vulnerable_node": None,
                "evidence": [
                    {
                        "role": "source_line",
                        "node_id": f"line:{getattr(f.location, 'line', '')}",
                        "instruction": f.instruction or f.message,
                    }
                ],
            }
        )

    explanations: list[PythonExplanation] = []
    for f in findings:
        line = getattr(f.location, "line", None) if f.location else None
        explanations.append(
            PythonExplanation(
                cwe_id=f.cwe_id,
                title=f.title,
                root_cause=f.message,
                security_impact=f"Unsafe pattern at line {line or '?'} in Python source.",
                repair_strategy="Remove unsafe API usage or validate/sanitize inputs.",
                confidence_basis=f"Detector: {f.detector}",
            )
        )

    return {
        "source": str(source),
        "language": "python",
        "llvm_ir_preview": "",
        "llvm_ir_line_count": 0,
        "graph": None,
        "node_count": 0,
        "edge_count": 0,
        "findings": findings,
        "cwes": list(dict.fromkeys(x.cwe_id for x in findings)),
        "localized": localized,
        "explanations": explanations,
        "ast_line_count": len(lines),
        "bandit_available": shutil.which("bandit") is not None,
    }


def python_analysis_bundle(analysis: dict) -> dict[str, Any]:
    report = build_report(analysis)
    return {"scan": report, "graph": None, "source_path": analysis.get("source")}
