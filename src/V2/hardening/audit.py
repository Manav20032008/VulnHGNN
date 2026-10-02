from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
import shutil
import subprocess


@dataclass
class BinaryAudit:
    path: str
    is_elf: bool = False
    is_pie: bool = False
    relro: bool = False
    bind_now: bool = False
    nx_stack: bool = False
    stack_canary_reference: bool = False
    fortify_reference: bool = False
    checks: list = field(default_factory=list)

    @property
    def passed(self):
        """
        Overall binary-hardening result.

        FORTIFY is intentionally informational here because
        _FORTIFY_SOURCE does not necessarily produce a *_chk symbol
        for every program. The mandatory hardening requirements remain:

        - ELF
        - PIE
        - RELRO
        - BIND_NOW
        - NX stack
        - stack protector
        """
        return all(
            [
                self.is_elf,
                self.is_pie,
                self.relro,
                self.bind_now,
                self.nx_stack,
                self.stack_canary_reference,
            ]
        )


def _readelf(args, path):
    """
    Run readelf and return stdout + stderr.

    Returning an empty string when readelf is unavailable preserves
    the previous audit behavior: the corresponding checks simply fail.
    """
    exe = shutil.which("readelf")

    if not exe:
        return ""

    try:
        result = subprocess.run(
            [exe, *args, str(path)],
            capture_output=True,
            text=True,
            timeout=10,
            check=False,
        )
        return result.stdout + result.stderr
    except (OSError, subprocess.SubprocessError):
        return ""


def _has_stack_protector_reference(symbols: str) -> bool:
    """
    Detect references emitted by GCC/Clang stack-protector support.

    The normal glibc/Linux reference is:

        __stack_chk_fail

    Some toolchains/platforms may emit one of the related forms instead.
    Keep the detection explicit rather than searching for a generic
    'stack' substring, which could create false positives.
    """
    stack_protector_symbols = (
        "__stack_chk_fail",
        "__stack_chk_fail_local",
        "__stack_chk_guard",
    )

    return any(symbol in symbols for symbol in stack_protector_symbols)


def _has_fortify_reference(symbols: str) -> bool:
    """
    Detect common glibc FORTIFY wrapper references.

    FORTIFY remains informational and is not part of BinaryAudit.passed,
    because a correctly hardened binary may legitimately contain no
    *_chk reference depending on which library operations it uses.
    """
    fortify_markers = (
        "_chk@",
        "__*_chk",
    )

    return any(marker in symbols for marker in fortify_markers)


def audit_binary(path):
    """
    Perform deterministic ELF hardening checks.

    Public API intentionally remains:

        audit_binary(path) -> BinaryAudit

    Existing callers can continue using:
        audit.is_elf
        audit.is_pie
        audit.relro
        audit.bind_now
        audit.nx_stack
        audit.stack_canary_reference
        audit.fortify_reference
        audit.checks
        audit.passed
    """
    path = Path(path)

    audit = BinaryAudit(str(path))

    header = _readelf(["-h"], path)
    program = _readelf(["-l"], path)
    dynamic = _readelf(["-d"], path)
    symbols = _readelf(["-Ws"], path)

    # ------------------------------------------------------------
    # ELF
    # ------------------------------------------------------------
    audit.is_elf = "ELF" in header

    # ------------------------------------------------------------
    # PIE
    #
    # A PIE executable is represented as ET_DYN in the ELF header.
    # ------------------------------------------------------------
    audit.is_pie = (
        "Type:" in header
        and "DYN" in header
    )

    # ------------------------------------------------------------
    # RELRO
    # ------------------------------------------------------------
    audit.relro = "GNU_RELRO" in program

    # ------------------------------------------------------------
    # BIND_NOW
    #
    # Depending on linker/readelf output, BIND_NOW can appear directly
    # or through the DF_BIND_NOW/NOW dynamic flag.
    # ------------------------------------------------------------
    audit.bind_now = (
        "BIND_NOW" in dynamic
        or (
            "FLAGS" in dynamic
            and "NOW" in dynamic
        )
    )

    # ------------------------------------------------------------
    # NX stack
    #
    # GNU_STACK without RWE means the stack is not simultaneously
    # readable/writable/executable.
    # ------------------------------------------------------------
    stack_segments = [
        line
        for line in program.splitlines()
        if "GNU_STACK" in line
    ]

    audit.nx_stack = (
        bool(stack_segments)
        and not any("RWE" in line for line in stack_segments)
    )

    # ------------------------------------------------------------
    # Stack protector
    #
    # Do not weaken this check to "compiler flag was requested".
    # We inspect the resulting binary for actual stack-protector
    # runtime support.
    # ------------------------------------------------------------
    audit.stack_canary_reference = _has_stack_protector_reference(
        symbols
    )

    # ------------------------------------------------------------
    # FORTIFY
    #
    # Informational only.
    # ------------------------------------------------------------
    audit.fortify_reference = _has_fortify_reference(symbols)

    # ------------------------------------------------------------
    # Human-readable checks
    #
    # Keep the existing check names because other SecureCC components
    # may consume them.
    # ------------------------------------------------------------
    audit.checks = [
        {
            "name": "ELF",
            "passed": audit.is_elf,
        },
        {
            "name": "PIE",
            "passed": audit.is_pie,
        },
        {
            "name": "RELRO",
            "passed": audit.relro,
        },
        {
            "name": "BIND_NOW",
            "passed": audit.bind_now,
        },
        {
            "name": "NX stack",
            "passed": audit.nx_stack,
        },
        {
            "name": "stack protector",
            "passed": audit.stack_canary_reference,
        },
        {
            "name": "FORTIFY",
            "passed": audit.fortify_reference,
        },
    ]

    return audit