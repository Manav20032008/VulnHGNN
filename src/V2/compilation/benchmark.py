from pathlib import Path
import tempfile
from .pipeline import SecureCompilationPipeline
ROOT=Path(__file__).resolve().parents[3]; TEST_DIR=ROOT/"test_files"
CASES=[f"test_{i:02d}_{n}.c" for i,n in [(1,"clean"),(2,"cwe190"),(3,"cwe191"),(4,"cwe369"),(5,"cwe476"),(6,"dual_190_191"),(7,"dual_369_476"),(8,"triple_190_191_369"),(9,"triple_191_369_476"),(10,"all_vulnerabilities")]]
def main():
    pipe=SecureCompilationPipeline(); passed=0
    print("="*62); print("VulnHGNN 2.0 — PHASE 4 SECURE COMPILATION BENCHMARK"); print("="*62); print(f"Clang: {pipe.compiler.version()}"); print()
    with tempfile.TemporaryDirectory(prefix="vulnhgnn_phase4_") as tmp:
        for name in CASES:
            r=pipe.compile_source(TEST_DIR/name,Path(tmp)/(Path(name).stem+".ll")); ok=r.passed
            passed+=ok; print(f"[{('PASS' if ok else 'FAIL')}] {name}")
            if not ok: print(f"       {r.message}\n       {(r.compilation.stderr or '')[:500]}")
    acc=100*passed/len(CASES); print(); print("="*62); print(f"PHASE 4 RESULT: {passed}/{len(CASES)} cases passed"); print(f"CASE ACCURACY : {acc:.1f}%"); print("="*62)
    return 0 if passed==len(CASES) else 1
if __name__=="__main__": raise SystemExit(main())
