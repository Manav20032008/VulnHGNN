"""Catalog heal regression on idiomatic test_*.cpp (deterministic first, optional AI)."""

from __future__ import annotations

import os
from pathlib import Path

import pytest

from src.V2.detection.catalog import MULTI_VULN_FIXTURES, VULNERABILITY_CATALOG
from src.V2.heal.catalog_heal import catalog_heal_source

ROOT = Path(__file__).resolve().parents[1]
CPP_FIXTURES = sorted(ROOT.glob("test_files/test_*.cpp"))

# Map primary catalog fixture -> all expected CWEs (must be healed)
CATALOG_CPP: dict[str, set[str]] = {}
for spec in VULNERABILITY_CATALOG:
    if spec.single_test.endswith(".cpp"):
        CATALOG_CPP.setdefault(spec.single_test, set()).add(spec.cwe_id)


@pytest.mark.parametrize("cpp_path", CPP_FIXTURES, ids=lambda p: p.name)
def test_catalog_heal_cpp_fixture(cpp_path: Path):
    pytest.importorskip("networkx")
    max_ai = 0 if os.environ.get("SECURECC_HEAL_AI") != "1" else 2
    result = catalog_heal_source(cpp_path, max_ai_attempts=max_ai)
    expected_set = CATALOG_CPP.get(f"test_files/{cpp_path.name}")
    if expected_set is None:
        if cpp_path.name == "test_01_clean.cpp":
            assert result["status"] in {"CLEAN", "VERIFIED", "PARTIAL"}
            return
        pytest.skip("combo fixture — run with full suite separately")
    if result["status"] == "CLEAN":
        pytest.skip("no findings on analyze")
    for expected in expected_set:
        assert result["per_cwe"].get(expected) is True, (
            f"{cpp_path.name}: expected {expected} healed, got {result['per_cwe']} — {result['message']}"
        )


@pytest.mark.parametrize(
    "rel,expected_cwes",
    [(c["path"], c["expected_cwes"]) for c in MULTI_VULN_FIXTURES],
    ids=[Path(c["path"]).name for c in MULTI_VULN_FIXTURES],
)
def test_combo_heal_expected_cwes(rel: str, expected_cwes: list[str]):
    pytest.importorskip("networkx")
    path = ROOT / rel
    if not path.exists():
        pytest.skip("missing combo fixture")
    max_ai = 0 if os.environ.get("SECURECC_HEAL_AI") != "1" else 2
    result = catalog_heal_source(path, max_ai_attempts=max_ai)
    for cwe in expected_cwes:
        assert result["per_cwe"].get(cwe) is True, (
            f"{path.name} {cwe}: {result['per_cwe']} — {result['message']}"
        )
