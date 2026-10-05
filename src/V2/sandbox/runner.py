import os
import resource
import shutil
import signal
import subprocess
import time

from .models import SandboxPolicy, RuntimeResult

class SandboxRunner:
    """Defense-in-depth local execution runner."""
    def __init__(self, policy: SandboxPolicy | None = None):
        self.policy = policy or SandboxPolicy()

    @staticmethod
    def _namespace_command(command: list[str]) -> tuple[list[str], str]:
        unshare = shutil.which("unshare")
        if not unshare:
            return command, "resource-limited subprocess"
        return [unshare, "--user", "--map-root-user", "--mount", "--pid", "--fork", "--net", "--mount-proc", "--", *command], "linux namespaces + resource limits"

    def _preexec(self):
        policy = self.policy
        def apply_limits():
            os.setsid()
            cpu = max(1, int(policy.cpu_seconds))
            resource.setrlimit(resource.RLIMIT_CPU, (cpu, cpu + 1))
            mem = max(16, int(policy.memory_limit_mb)) * 1024 * 1024
            resource.setrlimit(resource.RLIMIT_AS, (mem, mem))
            resource.setrlimit(resource.RLIMIT_NOFILE, (128, 128))
            resource.setrlimit(resource.RLIMIT_NPROC, (64, 64))
        return apply_limits

    def _execute(self, command, mode, env, cwd, notes):
        start = time.monotonic()
        try:
            proc = subprocess.run(command, cwd=cwd, env=env, stdin=subprocess.DEVNULL,
                                  stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True,
                                  timeout=self.policy.timeout_seconds,
                                  preexec_fn=self._preexec(), check=False)
            return RuntimeResult(command=command, returncode=proc.returncode,
                stdout=proc.stdout, stderr=proc.stderr, timed_out=False,
                memory_limited=proc.returncode in (-signal.SIGXCPU, -signal.SIGKILL),
                isolation_mode=mode, duration_seconds=time.monotonic()-start,
                policy=self.policy, notes=notes.copy())
        except subprocess.TimeoutExpired as exc:
            return RuntimeResult(command=command, returncode=None,
                stdout=exc.stdout or "", stderr=exc.stderr or "", timed_out=True,
                memory_limited=False, isolation_mode=mode,
                duration_seconds=time.monotonic()-start, policy=self.policy,
                notes=notes.copy())

    def run(self, command: list[str]) -> RuntimeResult:
        if not command:
            raise ValueError("Sandbox command cannot be empty")
        cwd = self.policy.working_directory
        env = os.environ.copy() if self.policy.inherit_environment else {
            "PATH": os.environ.get("PATH", "/usr/bin:/bin"), "LANG": "C", "LC_ALL": "C"
        }
        notes = []
        namespaced, strong_mode = self._namespace_command(command)
        if strong_mode == "resource-limited subprocess":
            return self._execute(command, strong_mode, env, cwd, notes)
        result = self._execute(namespaced, strong_mode, env, cwd, notes)
        if result.returncode == 0 or result.timed_out:
            return result
        err = (result.stderr or "").lower()
        namespace_failure_markers = (
            "operation not permitted",
            "permission denied",
            "unshare failed",
            "invalid argument",
            "resource temporarily unavailable",
            "fork failed",
            "cannot allocate memory",
        )
        if any(marker in err for marker in namespace_failure_markers):
            notes.append(
                "Linux namespace isolation unavailable on this host; "
                "fell back to resource-limited subprocess isolation."
            )
            return self._execute(
                command, "resource-limited subprocess", env, cwd, notes
            )
        return result
