from __future__ import annotations
from dataclasses import dataclass
from pathlib import Path
import shutil, subprocess

@dataclass
class IRValidationResult:
    valid: bool
    diagnostics: list[str]

class LLVMIRValidator:
    """LLVM IR syntax validation without executing generated code."""
    def validate(self, ir_file: str | Path, llvm_as: str | None = None) -> IRValidationResult:
        path=Path(ir_file).resolve()
        if not path.is_file(): return IRValidationResult(False,[f"IR file not found: {path}"])
        assembler=llvm_as or shutil.which("llvm-as")
        if not assembler:
            text=path.read_text(errors="replace"); d=[]
            if "define " not in text: d.append("no LLVM function definition found")
            if text.count("{") != text.count("}"): d.append("unbalanced LLVM IR braces")
            return IRValidationResult(not d,d)
        try:
            p=subprocess.run([assembler,str(path),"-o","/dev/null"],capture_output=True,text=True,timeout=10)
        except subprocess.TimeoutExpired: return IRValidationResult(False,["llvm-as validation timed out"])
        d=[x.strip() for x in (p.stderr or "").splitlines() if x.strip()]
        return IRValidationResult(p.returncode==0,d)
