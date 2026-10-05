import json
import subprocess
from pathlib import Path

ROOT = Path(__file__).resolve().parents[3]


def run(*args):
    return subprocess.run(
        ["python3", "-m", "src.V2.securecc", *args],
        cwd=ROOT,
        text=True,
        capture_output=True,
    )


def main():
    print("=" * 88)
    print("VulnHGNN 2.0 — SECURECC ANALYSIS INTEGRATION BENCHMARK")
    print("=" * 88)

    cases = [
        ("clean_scan", "test_files/test_01_clean.c", []),
        ("cwe190_scan", "test_files/test_02_cwe190.c", ["CWE-190"]),
        ("cwe191_scan", "test_files/test_03_cwe191.c", ["CWE-191"]),
        ("cwe369_scan", "test_files/test_04_cwe369.c", ["CWE-369"]),
        ("cwe476_scan", "test_files/test_05_cwe476.c", ["CWE-476"]),
    ]

    passed = 0

    for name, source, expected in cases:
        result = run("scan", source, "--format", "json")

        ok = result.returncode == 0
        payload = None

        if ok:
            try:
                payload = json.loads(result.stdout)
                actual = payload.get("cwes", [])
                ok = actual == expected
            except Exception:
                ok = False

        print(f"[{'PASS' if ok else 'FAIL'}] {name}")

        if not ok:
            print("       returncode:", result.returncode)
            if result.stdout:
                print("       stdout:", result.stdout[:500])
            if result.stderr:
                print("       stderr:", result.stderr[:500])

        passed += int(ok)

    print()
    print(
        f"SECURECC ANALYSIS RESULT: {passed}/{len(cases)} cases passed"
    )
    print("=" * 88)

    return 0 if passed == len(cases) else 1


if __name__ == "__main__":
    raise SystemExit(main())
