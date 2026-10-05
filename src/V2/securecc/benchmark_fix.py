from pathlib import Path
import json
import subprocess
import sys


CASES = {
    "test_01_clean.c": "CLEAN",
    "test_02_cwe190.c": "VERIFIED",
    "test_03_cwe191.c": "VERIFIED",
    "test_04_cwe369.c": "VERIFIED",
    "test_05_cwe476.c": "VERIFIED",
}


def main():
    root = Path(__file__).resolve().parents[3]
    passed = 0

    print("=" * 88)
    print("VULNHGNN PHASE 9.2 SECURECC FIX BENCHMARK")
    print("=" * 88)

    for filename, expected_status in CASES.items():
        source = root / "test_files" / filename
        cmd = [
            sys.executable,
            "-m",
            "src.V2.securecc.cli",
            "fix",
            str(source),
            "--format",
            "json",
        ]

        completed = subprocess.run(
            cmd,
            cwd=root,
            text=True,
            capture_output=True,
        )

        try:
            data = json.loads(completed.stdout)
            actual = data.get("status")
        except json.JSONDecodeError:
            actual = "INVALID_JSON"

        ok = completed.returncode == 0 and actual == expected_status
        if ok:
            passed += 1

        print("-" * 88)
        print(filename)
        print(f"  EXPECTED : {expected_status}")
        print(f"  ACTUAL   : {actual}")
        print(f"  RESULT   : {'PASS' if ok else 'FAIL'}")
        if not ok:
            print("  STDERR   :", completed.stderr.strip())

    print("=" * 88)
    print(f"PHASE 9.2 RESULT: {passed}/{len(CASES)} cases passed")
    print(f"CASE ACCURACY   : {100.0 * passed / len(CASES):.1f}%")
    print("=" * 88)

    if passed != len(CASES):
        raise SystemExit(1)


if __name__ == "__main__":
    main()
