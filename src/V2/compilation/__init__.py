"""VulnHGNN 2.0 Phase 4: secure compilation and validation."""
from .compiler import SecureCompiler, CompilationResult
from .sandbox import SandboxLimits, SandboxedRunner, SandboxResult
from .validator import LLVMIRValidator, IRValidationResult
from .pipeline import SecureCompilationPipeline
