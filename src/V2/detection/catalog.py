from __future__ import annotations

from dataclasses import dataclass
from typing import Any


# Stages align with the SecureCC compile / analysis pipeline (coarse compiler levels).
STAGE_FRONTEND_ERROR = "frontend_error"
STAGE_COMPILER_WARNING = "compiler_warning"
STAGE_LLVM_IR_EMIT = "llvm_ir_emit"
STAGE_LLVM_IR_GRAPH = "llvm_ir_graph"
STAGE_PYTHON_AST = "python_ast"
STAGE_PYTHON_BANDIT = "python_bandit"


COMPILER_STAGES: tuple[str, ...] = (
    STAGE_FRONTEND_ERROR,
    STAGE_COMPILER_WARNING,
    STAGE_LLVM_IR_EMIT,
    STAGE_LLVM_IR_GRAPH,
)


STAGE_LABELS: dict[str, str] = {
    STAGE_FRONTEND_ERROR: "Frontend (parse / semantic error)",
    STAGE_COMPILER_WARNING: "Compiler diagnostics (clang -Wall)",
    STAGE_LLVM_IR_EMIT: "LLVM IR emission",
    STAGE_LLVM_IR_GRAPH: "LLVM IR graph analysis",
    STAGE_PYTHON_AST: "Python AST static analysis",
    STAGE_PYTHON_BANDIT: "Bandit (optional)",
}


@dataclass(frozen=True)
class VulnerabilitySpec:
    cwe_id: str
    title: str
    severity: str
    compiler_stage: str
    single_test: str
    description: str

    def to_dict(self) -> dict[str, Any]:
        cpp_path = self.single_test
        c_path = (
            cpp_path.replace(".cpp", ".c")
            if cpp_path.endswith(".cpp")
            else cpp_path.replace(".cc", ".c")
        )
        return {
            "cwe_id": self.cwe_id,
            "title": self.title,
            "severity": self.severity,
            "compiler_stage": self.compiler_stage,
            "compiler_stage_label": STAGE_LABELS.get(
                self.compiler_stage, self.compiler_stage
            ),
            "single_test": cpp_path,
            "single_test_c": c_path,
            "description": self.description,
        }


# Supported vulnerability types and primary regression fixtures.
VULNERABILITY_CATALOG: tuple[VulnerabilitySpec, ...] = (
    VulnerabilitySpec(
        "CWE-190",
        "Integer Overflow",
        "HIGH",
        STAGE_LLVM_IR_GRAPH,
        "test_files/test_02_cwe190.cpp",
        "Signed add/mul with nsw on LLVM IR when overflow is not proven safe.",
    ),
    VulnerabilitySpec(
        "CWE-191",
        "Integer Underflow",
        "HIGH",
        STAGE_LLVM_IR_GRAPH,
        "test_files/test_03_cwe191.cpp",
        "Signed sub with nsw when underflow is not proven safe.",
    ),
    VulnerabilitySpec(
        "CWE-369",
        "Divide by Zero",
        "HIGH",
        STAGE_LLVM_IR_GRAPH,
        "test_files/test_04_cwe369.cpp",
        "Division/remainder when divisor is zero or not proven non-zero.",
    ),
    VulnerabilitySpec(
        "CWE-476",
        "NULL Pointer Dereference",
        "HIGH",
        STAGE_LLVM_IR_GRAPH,
        "test_files/test_05_cwe476.cpp",
        "Dereference of malloc-family pointer without proven non-NULL check.",
    ),
    VulnerabilitySpec(
        "CWE-121",
        "Stack-based Buffer Overflow",
        "HIGH",
        STAGE_LLVM_IR_GRAPH,
        "test_files/test_11_cwe121.cpp",
        "Unbounded libc copy/format calls (e.g. strcpy) in LLVM IR.",
    ),
    VulnerabilitySpec(
        "CWE-134",
        "Use of Externally-Controlled Format String",
        "HIGH",
        STAGE_LLVM_IR_GRAPH,
        "test_files/test_12_cwe134.cpp",
        "printf-family call without a string-literal format in IR.",
    ),
    VulnerabilitySpec(
        "CWE-457",
        "Use of Uninitialized Variable",
        "MEDIUM",
        STAGE_COMPILER_WARNING,
        "test_files/test_13_cwe457.cpp",
        "Clang -Wuninitialized diagnostic on potentially uninitialized use.",
    ),
    VulnerabilitySpec(
        "CWE-787",
        "Out-of-bounds Write",
        "HIGH",
        STAGE_COMPILER_WARNING,
        "test_files/test_14_cwe787.cpp",
        "Clang array bounds / subscript warnings where available.",
    ),
    VulnerabilitySpec(
        "CWE-122",
        "Heap-based Buffer Overflow",
        "HIGH",
        STAGE_LLVM_IR_GRAPH,
        "test_files/test_17_cwe122.cpp",
        "Unbounded copy into a heap allocation (malloc + strcpy/memcpy).",
    ),
    VulnerabilitySpec(
        "CWE-125",
        "Out-of-bounds Read",
        "HIGH",
        STAGE_COMPILER_WARNING,
        "test_files/test_18_cwe125.cpp",
        "Invalid array index read (Clang bounds + IR GEP heuristics).",
    ),
    VulnerabilitySpec(
        "CWE-789",
        "Memory Allocation with Excessive Size",
        "HIGH",
        STAGE_LLVM_IR_GRAPH,
        "test_files/test_19_cwe789.cpp",
        "Unchecked multiply/large constant passed to malloc (OOM risk).",
    ),
    VulnerabilitySpec(
        "CWE-400",
        "Uncontrolled Resource Consumption",
        "HIGH",
        STAGE_LLVM_IR_GRAPH,
        "test_files/test_19_cwe789.cpp",
        "Non-constant allocation size from user/input-driven expression.",
    ),
    VulnerabilitySpec(
        "CWE-415",
        "Double Free",
        "HIGH",
        STAGE_LLVM_IR_GRAPH,
        "test_files/test_20_cwe415.cpp",
        "Second free of the same heap pointer in one function.",
    ),
    VulnerabilitySpec(
        "CWE-416",
        "Use After Free",
        "HIGH",
        STAGE_LLVM_IR_GRAPH,
        "test_files/test_21_cwe416.cpp",
        "Load/store/call through a pointer after free.",
    ),
    VulnerabilitySpec(
        "CWE-401",
        "Memory Leak",
        "MEDIUM",
        STAGE_LLVM_IR_GRAPH,
        "test_files/test_22_cwe401.cpp",
        "malloc without matching free before function exit.",
    ),
    VulnerabilitySpec(
        "CWE-835",
        "Infinite Loop",
        "MEDIUM",
        STAGE_LLVM_IR_GRAPH,
        "test_files/test_24_cwe835.cpp",
        "Non-terminating CFG: self-loop, always-true branch, or no return.",
    ),
    VulnerabilitySpec(
        "CWE-833",
        "Deadlock",
        "HIGH",
        STAGE_LLVM_IR_GRAPH,
        "test_files/test_25_cwe833.cpp",
        "Nested pthread locks without release (lock-order deadlock risk).",
    ),
    VulnerabilitySpec(
        "CWE-667",
        "Improper Locking",
        "HIGH",
        STAGE_LLVM_IR_GRAPH,
        "test_files/test_26_cwe667.cpp",
        "Double lock on the same mutex without an intervening unlock.",
    ),
)


MULTI_VULN_FIXTURES: tuple[dict[str, Any], ...] = (
    {
        "path": "test_files/test_06_dual_190_191.cpp",
        "path_c": "test_files/test_06_dual_190_191.c",
        "expected_cwes": ["CWE-190", "CWE-191"],
    },
    {
        "path": "test_files/test_07_dual_369_476.cpp",
        "path_c": "test_files/test_07_dual_369_476.c",
        "expected_cwes": ["CWE-369", "CWE-476"],
    },
    {
        "path": "test_files/test_08_triple_190_191_369.cpp",
        "path_c": "test_files/test_08_triple_190_191_369.c",
        "expected_cwes": ["CWE-190", "CWE-191", "CWE-369"],
    },
    {
        "path": "test_files/test_09_triple_191_369_476.cpp",
        "path_c": "test_files/test_09_triple_191_369_476.c",
        "expected_cwes": ["CWE-191", "CWE-369", "CWE-476"],
    },
    {
        "path": "test_files/test_10_all_vulnerabilities.cpp",
        "path_c": "test_files/test_10_all_vulnerabilities.c",
        "expected_cwes": ["CWE-190", "CWE-191", "CWE-369", "CWE-476"],
    },
    {
        "path": "test_files/test_15_combo_extended.cpp",
        "path_c": "test_files/test_15_combo_extended.c",
        "expected_cwes": [
            "CWE-190",
            "CWE-121",
            "CWE-134",
        ],
    },
    {
        "path": "test_files/test_16_all_detectable.cpp",
        "path_c": "test_files/test_16_all_detectable.c",
        "expected_cwes": [
            "CWE-190",
            "CWE-191",
            "CWE-369",
            "CWE-476",
            "CWE-121",
            "CWE-134",
        ],
    },
    {
        "path": "test_files/test_23_memory_combo.cpp",
        "path_c": "test_files/test_23_memory_combo.c",
        "expected_cwes": [
            "CWE-122",
            "CWE-416",
        ],
    },
    {
        "path": "test_files/test_27_logic_combo.cpp",
        "path_c": "test_files/test_27_logic_combo.c",
        "expected_cwes": [
            "CWE-835",
            "CWE-833",
        ],
    },
)


def catalog_by_cwe() -> dict[str, VulnerabilitySpec]:
    return {item.cwe_id: item for item in VULNERABILITY_CATALOG}


def catalog_payload() -> dict[str, Any]:
    return {
        "compiler_stages": [
            {"id": s, "label": STAGE_LABELS.get(s, s)} for s in COMPILER_STAGES
        ],
        "vulnerabilities": [v.to_dict() for v in VULNERABILITY_CATALOG],
        "multi_vuln_fixtures": list(MULTI_VULN_FIXTURES),
        "clean_fixture": "test_files/test_01_clean.cpp",
        "clean_fixture_c": "test_files/test_01_clean.c",
    }
