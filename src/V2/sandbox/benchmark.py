import shutil
import tempfile
from pathlib import Path

from .compiler import SandboxCompiler
from .models import SandboxPolicy
from .verifier import RuntimeVerifier


def write_fixture(directory: Path, name: str, source: str) -> Path:
    path = directory / name
    path.write_text(source, encoding="utf-8")
    return path


def main():
    print("=" * 68)
    print("VulnHGNN 2.0 — PHASE 8 SANDBOX + RUNTIME VERIFICATION")
    print("=" * 68)
    if not shutil.which("clang"):
        print("[FAIL] clang not found")
        return 1

    with tempfile.TemporaryDirectory(prefix="vulnhgnn_phase8_") as td:
        work = Path(td)
        compiler = SandboxCompiler()
        policy = SandboxPolicy(timeout_seconds=1.0, memory_limit_mb=128, cpu_seconds=1,
                               network=False, inherit_environment=False, working_directory=str(work))
        verifier = RuntimeVerifier(policy)
        fixtures = {
            "safe_execution": '#include <stdio.h>\nint main(void) { puts("VULNHGNN_RUNTIME_OK"); return 0; }\n',
            "timeout_enforcement": '#include <unistd.h>\nint main(void) { for (;;) { sleep(1); } }\n',
        }
        results = []
        for name, source in fixtures.items():
            src = write_fixture(work, f"{name}.c", source)
            exe = work / name
            try:
                compiler.compile(src, exe)
            except Exception as exc:
                print(f"[FAIL] {name}: compilation failed: {exc}")
                return 1
            report = (verifier.run_expected_success(name, exe, "VULNHGNN_RUNTIME_OK")
                      if name == "safe_execution" else verifier.run_expected_timeout(name, exe))
            results.append(report)
            print(f"[{('PASS' if report.passed else 'FAIL')}] {name}")
            print(f"       isolation: {report.result.isolation_mode}")
            print(f"       returncode: {report.result.returncode}")
            print(f"       duration: {report.result.duration_seconds:.3f}s")
            for note in report.result.notes:
                print(f"       note: {note}")
            if report.result.stderr.strip():
                print(f"       stderr: {report.result.stderr.strip()[:180]}")

        passed = sum(r.passed for r in results)
        print()
        print("-" * 68)
        print("Sandbox policy")
        print(f"  timeout       : {policy.timeout_seconds}s")
        print(f"  memory limit  : {policy.memory_limit_mb} MB")
        print(f"  CPU limit     : {policy.cpu_seconds}s")
        print(f"  network       : {'enabled' if policy.network else 'disabled by policy'}")
        print("  environment   : sanitized")
        print("  stdin         : /dev/null")
        print("-" * 68)
        print(f"PHASE 8 RESULT: {passed}/{len(results)} mandatory runtime cases passed")
        print("=" * 68)
        return 0 if passed == len(results) else 1


if __name__ == "__main__":
    raise SystemExit(main())
