from __future__ import annotations
from dataclasses import dataclass
from pathlib import Path
from .compiler import CompilationResult, SecureCompiler
from .validator import IRValidationResult, LLVMIRValidator

@dataclass
class SecureCompilationResult:
    compilation: CompilationResult
    ir_validation: IRValidationResult | None
    passed: bool
    message: str

class SecureCompilationPipeline:
    def __init__(self, compiler=None, validator=None):
        self.compiler=compiler or SecureCompiler(); self.validator=validator or LLVMIRValidator()
    def compile_source(self, source: str | Path, output: str | Path | None = None):
        c=self.compiler.compile_to_ir(source,output)
        if not c.success or not c.output:
            return SecureCompilationResult(c,None,False,"Clang/LLVM compilation failed.")
        v=self.validator.validate(c.output); ok=c.success and v.valid
        return SecureCompilationResult(c,v,ok,"Compilation and LLVM IR validation passed." if ok else "LLVM IR validation failed.")
