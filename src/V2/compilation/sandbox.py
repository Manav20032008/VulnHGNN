from __future__ import annotations
from dataclasses import dataclass
import os, resource, subprocess
from typing import Sequence

@dataclass(frozen=True)
class SandboxLimits:
    timeout_seconds: int = 5
    cpu_seconds: int = 2
    memory_mb: int = 256
    file_size_mb: int = 32
    max_processes: int = 8

@dataclass
class SandboxResult:
    success: bool
    stdout: str = ""
    stderr: str = ""
    returncode: int | None = None
    timed_out: bool = False
    blocked: bool = False

class SandboxedRunner:
    """Resource-control layer for future validation; not a full security boundary."""
    def __init__(self, limits: SandboxLimits | None = None): self.limits = limits or SandboxLimits()
    def _limits(self):
        L=self.limits
        resource.setrlimit(resource.RLIMIT_CPU,(L.cpu_seconds,L.cpu_seconds))
        m=L.memory_mb*1024*1024; resource.setrlimit(resource.RLIMIT_AS,(m,m))
        f=L.file_size_mb*1024*1024; resource.setrlimit(resource.RLIMIT_FSIZE,(f,f))
        resource.setrlimit(resource.RLIMIT_NPROC,(L.max_processes,L.max_processes)); os.setsid()
    def run(self, command: Sequence[str], cwd: str | None = None) -> SandboxResult:
        if not command: return SandboxResult(False, blocked=True, stderr="empty command")
        try:
            p=subprocess.run(list(command),cwd=cwd,capture_output=True,text=True,timeout=self.limits.timeout_seconds,preexec_fn=self._limits)
            return SandboxResult(p.returncode==0,p.stdout,p.stderr,p.returncode)
        except subprocess.TimeoutExpired as exc:
            return SandboxResult(False,exc.stdout or "",exc.stderr or "",timed_out=True)
