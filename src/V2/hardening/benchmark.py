from pathlib import Path
import tempfile
from .compiler import SecureCompiler
from .audit import audit_binary

ROOT = Path(__file__).resolve().parents[3]
CASES = [f"test_{i:02d}_" for i in range(1,11)]

def main():
    print("=" * 68)
    print("VulnHGNN 2.0 — PHASE 7 BINARY HARDENING BENCHMARK")
    print("=" * 68)
    compiler = SecureCompiler()
    info = compiler.version()
    if not info["available"]:
        print("ERROR: clang unavailable")
        return 1
    print(f"Compiler: {info['version']}\n")

    sources = sorted((ROOT / "test_files").glob("*.c"))
    passed = 0
    with tempfile.TemporaryDirectory(prefix="vulnhgnn_phase7_") as td:
        td = Path(td)
        for source in sources:
            output = td / (source.stem + ".secure")
            result = compiler.build(source, output)
            if not result["success"]:
                print(f"[FAIL] {source.name} — compilation")
                continue
            audit = audit_binary(output)
            ok = audit.passed
            print(f"[{'PASS' if ok else 'FAIL'}] {source.name}")
            if not ok:
                print("       failed:", ", ".join(c["name"] for c in audit.checks if not c["passed"]))
            passed += int(ok)

    total = len(sources)
    print("\n" + "=" * 68)
    print(f"PHASE 7 RESULT: {passed}/{total} cases passed")
    print(f"HARDENING COVERAGE: {100.0*passed/max(total,1):.1f}%")
    print("=" * 68)
    return 0 if passed == total else 1

if __name__ == "__main__":
    raise SystemExit(main())
