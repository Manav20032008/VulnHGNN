from pathlib import Path
import pickle
from ..analysis.graph_adapter import GraphAdapter
from .engine import ExplainabilityEngine, EXPECTED

ROOT = Path(__file__).resolve().parents[3]
GRAPH_PATH = ROOT / "data" / "graphs.pkl"

def main():
    print("=" * 64)
    print("VulnHGNN 2.0 — PHASE 6 EXPLAINABILITY BENCHMARK")
    print("=" * 64)

    with open(GRAPH_PATH, "rb") as f:
        records = pickle.load(f)

    engine = ExplainabilityEngine()
    passed = 0

    for record in records:
        name = record["filename"]
        graph = GraphAdapter.graph(record)
        expected = EXPECTED[name]
        explanations = engine.explain_all(graph, expected)
        explained = [e.cwe_id for e in explanations]
        complete = all(
            e.node_id and e.vulnerable_operation and e.root_cause
            and e.security_impact and e.repair_strategy
            for e in explanations
        )
        ok = explained == expected and complete
        print(f"[{'PASS' if ok else 'FAIL'}] {name}")
        if not ok:
            print(f"       expected : {expected}")
            print(f"       explained: {explained}")
        passed += int(ok)

    accuracy = 100.0 * passed / max(len(records), 1)
    print()
    print("=" * 64)
    print(f"PHASE 6 RESULT: {passed}/{len(records)} cases passed")
    print(f"EXPLANATION COVERAGE: {accuracy:.1f}%")
    print("=" * 64)
    return 0 if passed == len(records) else 1

if __name__ == "__main__":
    raise SystemExit(main())
