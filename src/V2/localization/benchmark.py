from pathlib import Path
import pickle

from ..detection.engine import DetectionEngine
from .localizer import VulnerabilityLocalizer


EXPECTED = {
    "test_files_test_01_clean.json": [],
    "test_files_test_02_cwe190.json": ["CWE-190"],
    "test_files_test_03_cwe191.json": ["CWE-191"],
    "test_files_test_04_cwe369.json": ["CWE-369"],
    "test_files_test_05_cwe476.json": ["CWE-476"],
    "test_files_test_06_dual_190_191.json": ["CWE-190", "CWE-191"],
    "test_files_test_07_dual_369_476.json": ["CWE-369", "CWE-476"],
    "test_files_test_08_triple_190_191_369.json": [
        "CWE-190", "CWE-191", "CWE-369"
    ],
    "test_files_test_09_triple_191_369_476.json": [
        "CWE-191", "CWE-369", "CWE-476"
    ],
    "test_files_test_10_all_vulnerabilities.json": [
        "CWE-190", "CWE-191", "CWE-369", "CWE-476"
    ],
}


def main():
    root = Path(__file__).resolve().parents[3]
    graph_path = root / "data" / "graphs.pkl"

    with graph_path.open("rb") as handle:
        samples = pickle.load(handle)

    engine = DetectionEngine()
    localizer = VulnerabilityLocalizer()

    passed = 0
    total = len(samples)

    print("=" * 88)
    print("VULNHGNN PHASE 2 LOCALIZATION BENCHMARK")
    print("=" * 88)

    for sample in samples:
        filename = sample["filename"]
        expected = set(EXPECTED.get(filename, []))

        findings = engine.analyze(sample)
        localized = localizer.localize(sample, findings)

        actual = {x.cwe_id for x in localized}

        # Phase 2 must preserve Phase 1 detection exactly.
        detection_ok = actual == expected

        # Every finding must have a concrete target instruction.
        localization_ok = all(
            x.vulnerable_node is not None
            and bool(x.vulnerable_instruction)
            and x.localization_confidence > 0.0
            for x in localized
        )

        ok = detection_ok and localization_ok

        if ok:
            passed += 1

        print("-" * 88)
        print(filename)
        print(f"  EXPECTED CWEs : {sorted(expected)}")
        print(f"  ACTUAL CWEs   : {sorted(actual)}")
        print(f"  LOCALIZED     : {len(localized)}")
        for item in localized:
            print(
                f"    {item.cwe_id:<8} node={item.vulnerable_node} "
                f"block={item.vulnerable_block} "
                f"loc_conf={item.localization_confidence:.2f}"
            )
        print(f"  RESULT        : {'PASS' if ok else 'FAIL'}")

    print("=" * 88)
    print(f"PHASE 2 RESULT: {passed}/{total} cases passed")
    print(f"CASE ACCURACY : {100.0 * passed / total:.1f}%")
    print("=" * 88)

    if passed != total:
        raise SystemExit(1)


if __name__ == "__main__":
    main()
