import shutil
import subprocess
from pathlib import Path

class SandboxCompiler:
    """Trusted-fixture compiler for runtime verification."""
    def __init__(self, compiler: str | None = None):
        self.compiler = compiler or shutil.which("clang")
        if not self.compiler:
            raise RuntimeError("clang was not found on PATH")

    def compile(self, source: Path, output: Path) -> None:
        result = subprocess.run([self.compiler, "-O2", "-fstack-protector-all", "-fPIE", "-pie", str(source), "-o", str(output)],
                                stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, check=False)
        if result.returncode != 0:
            raise RuntimeError(f"Compilation failed for {source.name}:\n{result.stderr}")
