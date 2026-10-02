import subprocess
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[3]
CLI = ["python3", "-m", "src.V2.securecc"]


def run(*args):
    return subprocess.run(CLI + list(args), cwd=ROOT, text=True, capture_output=True)


def main():
    print("=" * 68)
    print("VulnHGNN 2.0 — PHASE 9 SECURECC CLI BENCHMARK")
    print("=" * 68)

    cases = []
    cases.append(("version", run("--version").returncode == 0))

    with tempfile.TemporaryDirectory(prefix="securecc_phase9_") as td:
        out = Path(td) / "hello"
        cases.append((
            "secure_build",
            run("build", "test_files/test_01_clean.c", "-o", str(out), "--secure").returncode == 0
            and out.exists()
        ))
        cases.append((
            "machine_report",
            run("report", "test_files/test_01_clean.c", "--secure").returncode == 0
        ))

    passed = 0
    for name, ok in cases:
        print(f"[{'PASS' if ok else 'FAIL'}] {name}")
        passed += int(ok)

    print()
    print(f"PHASE 9 RESULT: {passed}/{len(cases)} CLI cases passed")
    print("=" * 68)
    return 0 if passed == len(cases) else 1


if __name__ == "__main__":
    raise SystemExit(main())
