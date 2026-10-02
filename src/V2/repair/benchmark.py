from pathlib import Path
import pickle

from ..detection.engine import DetectionEngine
from ..localization.localizer import VulnerabilityLocalizer
from .planner import RepairPlanner


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

    detector = DetectionEngine()
    localizer = VulnerabilityLocalizer()
    planner = RepairPlanner()

    passed = 0

    print("=" * 88)
    print("VULNHGNN PHASE 3 REPAIR-PLAN BENCHMARK")
    print("=" * 88)

    for sample in samples:
        filename = sample["filename"]
        expected = set(EXPECTED.get(filename, []))

        findings = detector.analyze(sample)
        localized = localizer.localize(sample, findings)
        plan = planner.plan(localized)

        actual = set(plan.cwes)

        # Phase 3 must preserve the Phase-1 CWE set and produce one
        # deterministic repair action for every localized finding.
        ok = (
            actual == expected
            and len(plan.actions) == len(localized)
            and all(action.safe for action in plan.actions)
        )

        if ok:
            passed += 1

        print("-" * 88)
        print(filename)
        print(f"  DETECTED CWEs : {sorted(expected)}")
        print(f"  REPAIR CWEs   : {sorted(actual)}")
        print(f"  ACTIONS       : {len(plan.actions)}")

        for action in plan.actions:
            print(
                f"    {action.cwe_id:<8} node={action.node_id} "
                f"strategy={action.strategy}"
            )

        print(f"  RESULT        : {'PASS' if ok else 'FAIL'}")

    print("=" * 88)
    print(f"PHASE 3 RESULT: {passed}/{len(samples)} cases passed")
    print(f"CASE ACCURACY : {100.0 * passed / len(samples):.1f}%")
    print("=" * 88)

    if passed != len(samples):
        raise SystemExit(1)


if __name__ == "__main__":
    main()
