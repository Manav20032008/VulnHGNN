from pathlib import Path
import torch
from .adapter import GraphTensorAdapter
from .model import VulnHGNNV2
from .schema import SCHEMA

ROOT = Path(__file__).resolve().parents[3]
GRAPH_PATH = ROOT / "data" / "graphs.pkl"

def main():
    print("="*64)
    print("VulnHGNN 2.0 — PHASE 5 MODEL CONTRACT BENCHMARK")
    print("="*64)
    if not GRAPH_PATH.exists():
        print("[FAIL] data/graphs.pkl not found")
        return 1
    records = GraphTensorAdapter.load_graphs(GRAPH_PATH)
    adapter = GraphTensorAdapter(SCHEMA.node_feature_dim)
    model = VulnHGNNV2().eval()
    print(f"Graphs: {len(records)} | Features: {SCHEMA.node_feature_dim} | "
          f"Edge types: {SCHEMA.edge_type_count} | Classes: {SCHEMA.num_classes}")
    passed = 0
    with torch.no_grad():
        for record in records:
            try:
                d = adapter.convert(record["graph"])
                y = model(d.x,d.edge_index,d.edge_type)
                ok = tuple(y.shape) == (1,SCHEMA.num_classes) and bool(torch.isfinite(y).all())
            except Exception as e:
                ok = False
                print("       ",e)
            print(f"[{'PASS' if ok else 'FAIL'}] {record.get('filename','unknown')}")
            passed += int(ok)
    acc = 100*passed/max(len(records),1)
    print("="*64)
    print(f"PHASE 5 RESULT: {passed}/{len(records)} cases passed")
    print(f"CONTRACT COVERAGE: {acc:.1f}%")
    print("="*64)
    print("NOTE: structural inference coverage, NOT trained-model accuracy.")
    return 0 if passed == len(records) else 1

if __name__ == "__main__":
    raise SystemExit(main())
