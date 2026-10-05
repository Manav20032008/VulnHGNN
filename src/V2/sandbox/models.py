from dataclasses import dataclass, field
from typing import Optional

@dataclass(frozen=True)
class SandboxPolicy:
    timeout_seconds: float = 2.0
    memory_limit_mb: int = 256
    cpu_seconds: int = 2
    network: bool = False
    inherit_environment: bool = False
    working_directory: Optional[str] = None

@dataclass
class RuntimeResult:
    command: list[str]
    returncode: Optional[int]
    stdout: str
    stderr: str
    timed_out: bool
    memory_limited: bool
    isolation_mode: str
    duration_seconds: float
    policy: SandboxPolicy
    notes: list[str] = field(default_factory=list)

    @property
    def passed(self) -> bool:
        return not self.timed_out and self.returncode == 0 and not self.memory_limited
