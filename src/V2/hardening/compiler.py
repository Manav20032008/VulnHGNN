from __future__ import annotations

from pathlib import Path
import shutil
import subprocess

from .profile import HardeningProfile


class SecureCompiler:
    def __init__(self, profile=None, compiler=None):
        self.profile = profile or HardeningProfile()
        self.compiler = compiler or shutil.which("clang")

    def version(self):
        if not self.compiler:
            return {
                "available": False,
                "version": "",
            }

        p = subprocess.run(
            [self.compiler, "--version"],
            capture_output=True,
            text=True,
            timeout=10,
        )

        return {
            "available": p.returncode == 0,
            "version": p.stdout.splitlines()[0] if p.stdout else "",
        }

    def _prepare_ir_for_hardening(self, source: Path) -> Path:
        """
        Prepare LLVM IR for SecureCC hardening.

        Clang's frontend normally attaches stack-protector function
        attributes when compiling C/C++. When SecureCC starts from
        already-generated LLVM IR, that frontend step has already
        happened and the IR may not contain an explicit SSP attribute.

        For IR inputs, explicitly require stack protection on the
        existing function attribute group.

        The original IR is never modified.
        """
        if source.suffix.lower() not in {".ll", ".bc"}:
            return source

        # LLVM bitcode cannot be safely modified as text.
        # Keep the existing behavior for bitcode rather than pretending
        # that a textual transformation is possible.
        if source.suffix.lower() == ".bc":
            return source

        text = source.read_text(encoding="utf-8")

        # If the IR already has an explicit stack-protector requirement,
        # preserve it exactly.
        if "sspreq" in text or "sspstrong" in text or " ssp" in text:
            return source

        marker = "attributes #0 = {"

        if marker not in text:
            raise RuntimeError(
                "LLVM IR hardening failed: function attribute group #0 "
                "was not found"
            )

        patched = text.replace(
            marker,
            "attributes #0 = { sspreq",
            1,
        )

        prepared = source.with_name(
            f"{source.stem}.hardened.ll"
        )

        prepared.write_text(
            patched,
            encoding="utf-8",
        )

        return prepared

    def build(self, source, output):
        if not self.compiler:
            raise RuntimeError("clang was not found on PATH")

        source = Path(source)
        output = Path(output)

        output.parent.mkdir(
            parents=True,
            exist_ok=True,
        )

        compile_source = self._prepare_ir_for_hardening(
            source
        )

        cmd = [
            self.compiler,
            *self.profile.compile_flags(),
            str(compile_source),
            *self.profile.link_flags(),
            "-o",
            str(output),
        ]

        p = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=30,
        )

        return {
            "success": (
                p.returncode == 0
                and output.exists()
            ),
            "command": cmd,
            "returncode": p.returncode,
            "stdout": p.stdout,
            "stderr": p.stderr,
            "output": str(output),
            "source": str(source),
            "compile_source": str(compile_source),
        }