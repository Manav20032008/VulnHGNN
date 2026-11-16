"""End-to-end analyze_source checks for C++ fixture twins (.cpp)."""

from __future__ import annotations

from pathlib import Path

import pytest

from src.V2.detection.catalog import MULTI_VULN_FIXTURES, VULNERABILITY_CATALOG
from src.V2.securecc.analysis import analyze_source

ROOT = Path(__file__).resolve().parents[1]


def _cwe_set(source: Path) -> set[str]:
    result = analyze_source(source)
    return {f.cwe_id for f in result.get("findings") or []}


@pytest.mark.parametrize(
    "spec",
    VULNERABILITY_CATALOG,
    ids=[s.cwe_id for s in VULNERABILITY_CATALOG],
)
def test_cpp_single_fixture_triggers_catalog_cwe(spec):
    cpp = ROOT / spec.single_test
    assert cpp.is_file(), f"missing {cpp}"
    found = _cwe_set(cpp)
    assert spec.cwe_id in found, f"{cpp.name}: expected {spec.cwe_id}, got {sorted(found)}"


@pytest.mark.parametrize(
    "fixture",
    MULTI_VULN_FIXTURES,
    ids=[f["path"] for f in MULTI_VULN_FIXTURES],
)
def test_cpp_multi_fixture_expected_cwes(fixture):
    cpp = ROOT / fixture["path"]
    assert cpp.is_file(), f"missing {cpp}"
    expected = set(fixture["expected_cwes"])
    found = _cwe_set(cpp)
    missing = expected - found
    assert not missing, f"{cpp.name}: missing {sorted(missing)} (found {sorted(found)})"


def test_cpp_clean_fixture_has_no_core_cwes():
    cpp = ROOT / "test_files/test_01_clean.cpp"
    found = _cwe_set(cpp)
    core = {"CWE-190", "CWE-191", "CWE-369", "CWE-476"}
    assert not (found & core), f"clean fixture should not hit {found & core}"
