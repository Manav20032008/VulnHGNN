from dataclasses import dataclass
from pathlib import Path
from .models import SandboxPolicy, RuntimeResult
from .runner import SandboxRunner

@dataclass
class VerificationReport:
    name: str
    passed: bool
    result: RuntimeResult
    expected: str

class RuntimeVerifier:
    def __init__(self, policy: SandboxPolicy | None = None):
        self.runner = SandboxRunner(policy)

    def run_expected_success(self, name: str, executable: Path, expected_output: str) -> VerificationReport:
        result = self.runner.run([str(executable)])
        normalized_expected = expected_output.strip()
        normalized_actual = result.stdout.strip()

        passed = (
            result.passed
            and result.returncode == 0
            and normalized_actual == normalized_expected
        )

        return VerificationReport(
            name,
            passed,
            result,
            f"exit=0, stdout={expected_output!r}",
        )

    def run_expected_timeout(self, name: str, executable: Path) -> VerificationReport:
        result = self.runner.run([str(executable)])
        return VerificationReport(name, result.timed_out, result, "execution must be terminated by timeout policy")
