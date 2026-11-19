"""Compile and run user source when analysis is clean (native stdout for web Output)."""

from __future__ import annotations

import re
import shutil
import subprocess
import tempfile
from pathlib import Path
from typing import Any

from .languages import compiler_for_source, is_java_path, is_cpp_suffix

_MAX_OUT = 48_000
_RUN_TIMEOUT = 3.0


def _truncate(text: str, limit: int = _MAX_OUT) -> str:
    if len(text) <= limit:
        return text
    return text[:limit] + "\n… (truncated)"


def _java_main_class(source: Path) -> str | None:
    try:
        text = source.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return None
    m = re.search(r"public\s+class\s+(\w+)", text)
    if m:
        return m.group(1)
    stem = source.stem
    if re.search(rf"\bclass\s+{re.escape(stem)}\b", text):
        return stem
    return stem


def _run_timed(command: list[str], *, cwd: str) -> dict[str, Any]:
    import time

    start = time.monotonic()
    try:
        proc = subprocess.run(
            command,
            cwd=cwd,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            timeout=_RUN_TIMEOUT,
            check=False,
        )
        duration = time.monotonic() - start
        return {
            "returncode": proc.returncode,
            "stdout": proc.stdout or "",
            "stderr": proc.stderr or "",
            "timed_out": False,
            "duration_seconds": duration,
        }
    except subprocess.TimeoutExpired as exc:
        return {
            "returncode": None,
            "stdout": exc.stdout or "",
            "stderr": exc.stderr or "",
            "timed_out": True,
            "duration_seconds": time.monotonic() - start,
        }


def run_clean_program(source: Path) -> dict[str, Any]:
    """
    Build a native artifact from source and run with a short timeout.
    For Java: javac + java. For C/C++: clang/clang++ link + execute.
    """
    source = source.resolve()
    if not source.is_file():
        return {"status": "skipped", "message": "source not found"}

    with tempfile.TemporaryDirectory(prefix="securecc_run_") as tmp:
        work = Path(tmp)
        cwd = str(work)

        if is_java_path(source):
            if not shutil.which("javac") or not shutil.which("java"):
                return {"status": "skipped", "message": "JDK required to run Java output"}
            dest = work / source.name
            dest.write_text(
                source.read_text(encoding="utf-8", errors="replace"),
                encoding="utf-8",
            )
            javac = subprocess.run(
                ["javac", "-encoding", "UTF-8", str(dest)],
                cwd=cwd,
                text=True,
                capture_output=True,
            )
            if javac.returncode != 0:
                return {
                    "status": "compile_failed",
                    "message": "javac failed",
                    "stderr": _truncate((javac.stderr or javac.stdout or "").strip()),
                    "stdout": "",
                    "exit_code": javac.returncode,
                }
            main = _java_main_class(dest)
            if not main:
                return {"status": "skipped", "message": "Could not determine Java main class"}
            return _runtime_payload(_run_timed(["java", "-cp", cwd, main], cwd=cwd))

        compiler = compiler_for_source(source)
        if not shutil.which(compiler):
            return {"status": "skipped", "message": f"{compiler} not on PATH"}

        dest = work / source.name
        dest.write_text(
            source.read_text(encoding="utf-8", errors="replace"),
            encoding="utf-8",
        )
        binary = work / "securecc_prog"
        cmd = [compiler, str(dest), "-O0", "-g0", "-o", str(binary)]
        if is_cpp_suffix(source.suffix):
            cmd[1:1] = ["-std=c++17"]
        else:
            cmd.append("-lm")

        build = subprocess.run(cmd, cwd=cwd, text=True, capture_output=True)
        if build.returncode != 0:
            return {
                "status": "compile_failed",
                "message": "Native compile failed",
                "stderr": _truncate((build.stderr or build.stdout or "").strip()),
                "stdout": "",
                "exit_code": build.returncode,
            }

        return _runtime_payload(_run_timed([str(binary)], cwd=cwd))


def _runtime_payload(result: dict[str, Any]) -> dict[str, Any]:
    out: dict[str, Any] = {
        "status": "ok",
        "stdout": _truncate(result.get("stdout") or ""),
        "stderr": _truncate(result.get("stderr") or ""),
        "exit_code": result.get("returncode"),
        "timed_out": bool(result.get("timed_out")),
        "duration_seconds": round(float(result.get("duration_seconds") or 0), 3),
    }
    if result.get("timed_out"):
        out["status"] = "timeout"
        out["message"] = f"Program exceeded {_RUN_TIMEOUT}s limit"
    elif result.get("returncode") not in (0, None):
        out["status"] = "run_failed"
        out["message"] = f"Exit code {result.get('returncode')}"
    else:
        out["message"] = "Program ran successfully"
    return out


def attach_program_run_if_clean(
    payload: dict[str, Any],
    *,
    source_path: Path,
    source_text: str | None = None,
) -> None:
    """Set payload['program_run'] when scan has zero confirmed findings."""
    if payload.get("compile", {}).get("ok") is False:
        payload["program_run"] = None
        return
    scan = payload.get("scan") or {}
    if int(scan.get("finding_count") or 0) > 0:
        payload["program_run"] = None
        return
    try:
        if source_text is not None:
            with tempfile.NamedTemporaryFile(
                mode="w",
                suffix=source_path.suffix or ".c",
                prefix="securecc_runsrc_",
                delete=False,
                encoding="utf-8",
            ) as hf:
                hf.write(source_text)
                tmp = Path(hf.name)
            try:
                payload["program_run"] = run_clean_program(tmp)
            finally:
                try:
                    tmp.unlink(missing_ok=True)
                except OSError:
                    pass
        else:
            payload["program_run"] = run_clean_program(source_path)
    except Exception as exc:
        payload["program_run"] = {
            "status": "error",
            "message": str(exc)[:500],
            "stdout": "",
            "stderr": "",
        }