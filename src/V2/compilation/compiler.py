from __future__ import annotations
from dataclasses import dataclass, field
from pathlib import Path
import os, shutil, subprocess, tempfile

@dataclass
class CompilationResult:
    success: bool
    source: str
    output: str | None = None
    command: list[str] = field(default_factory=list)
    stdout: str = ""
    stderr: str = ""
    returncode: int | None = None
    timed_out: bool = False

class SecureCompiler:
    """Controlled C/C++ -> LLVM IR compilation. Never executes the program."""
    def __init__(self, clang: str | None = None, timeout: int = 15):
        self.clang = clang or shutil.which("clang") or "clang"
        self.timeout = timeout

    def version(self) -> str:
        try:
            p = subprocess.run([self.clang, "--version"], capture_output=True, text=True, timeout=5)
            return (p.stdout or p.stderr).splitlines()[0]
        except Exception as exc:
            return f"unavailable: {exc}"

    def compile_to_ir(self, source: str | Path, output: str | Path | None = None, optimization="O0") -> CompilationResult:
        src = Path(source).resolve()
        if not src.is_file():
            return CompilationResult(False, str(src), stderr=f"source file not found: {src}")
        if output is None:
            fd, name = tempfile.mkstemp(suffix=".ll", prefix="vulnhgnn_"); os.close(fd)
            out = Path(name)
        else:
            out = Path(output).resolve(); out.parent.mkdir(parents=True, exist_ok=True)
        cmd = [self.clang, "-S", "-emit-llvm", f"-{optimization}", "-g0", "-fno-discard-value-names", str(src), "-o", str(out)]
        try:
            p = subprocess.run(cmd, capture_output=True, text=True, timeout=self.timeout)
            return CompilationResult(p.returncode == 0 and out.exists(), str(src), str(out) if out.exists() else None, cmd, p.stdout, p.stderr, p.returncode)
        except subprocess.TimeoutExpired as exc:
            return CompilationResult(False, str(src), str(out) if out.exists() else None, cmd, exc.stdout or "", exc.stderr or "", timed_out=True)
