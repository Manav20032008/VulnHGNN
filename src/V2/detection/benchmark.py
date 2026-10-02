import pickle
from pathlib import Path
from .engine import DetectionEngine

EXPECTED = {
    "test_files_test_01_clean.json": set(),
    "test_files_test_02_cwe190.json": {"CWE-190"},
    "test_files_test_03_cwe191.json": {"CWE-191"},
    "test_files_test_04_cwe369.json": {"CWE-369"},
    "test_files_test_05_cwe476.json": {"CWE-476"},
    "test_files_test_06_dual_190_191.json": {"CWE-190", "CWE-191"},
    "test_files_test_07_dual_369_476.json": {"CWE-369", "CWE-476"},
    "test_files_test_08_triple_190_191_369.json": {"CWE-190", "CWE-191", "CWE-369"},
    "test_files_test_09_triple_191_369_476.json": {"CWE-191", "CWE-369", "CWE-476"},
    "test_files_test_10_all_vulnerabilities.json": {"CWE-190", "CWE-191", "CWE-369", "CWE-476"},
}

def main():
    root = Path(__file__).resolve().parents[3]
    graph_path = root / "data" / "graphs.pkl"

    with graph_path.open("rb") as f:
        samples = pickle.load(f)

    engine = DetectionEngine()
    passed = 0
    total = len(EXPECTED)

    print("=" * 88)
    print("VulnHGNN 2.0 — Phase 1 Detection Benchmark")
    print("=" * 88)

    for sample in samples:
        filename = sample["filename"]
        expected = EXPECTED.get(filename, set())

        findings = engine.analyze(sample)
        actual = {f.cwe_id for f in findings}

        print("\n" + "-" * 88)
        print(filename)
        print("-" * 88)

        if findings:
            for f in findings:
                print(
                    f"  [{f.cwe_id}] {f.severity:<8} "
                    f"confidence={f.confidence:.2f} node={f.node_id}"
                )
                print(f"      {f.message}")
                print(f"      {f.instruction}")
        else:
            print("  No findings")

        ok = actual == expected
        print(
            f"\n  EXPECTED: {', '.join(sorted(expected)) if expected else 'CLEAN'}"
        )
        print(
            f"  ACTUAL  : {', '.join(sorted(actual)) if actual else 'CLEAN'}"
        )
        print(f"  RESULT  : {'PASS' if ok else 'FAIL'}")

        if ok:
            passed += 1

    print("\n" + "=" * 88)
    print(f"BENCHMARK RESULT: {passed}/{total} cases passed")
    print(f"CASE ACCURACY   : {passed / total:.1%}")
    print("=" * 88)

    if passed != total:
        raise SystemExit(1)

if __name__ == "__main__":
    main()
