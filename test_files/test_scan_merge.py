from src.V2.securecc.scan_merge import merge_ai_review_into_scan, should_gap_fill_merge, source_looks_healed


def test_merge_adds_ai_cwes_when_engine_empty():
    scan = {
        "finding_count": 0,
        "findings": [],
        "cwes": [],
        "explanations": [],
    }
    ai = {
        "status": "OK",
        "issues": [
            {"cwe_id": "CWE-190", "line": 6, "title": "Overflow", "severity": "high", "message": "x"},
            {"cwe_id": "CWE-835", "line": 6, "title": "Loop", "severity": "medium", "message": "y"},
        ],
    }
    merged = merge_ai_review_into_scan(scan, ai)
    assert merged["finding_count"] == 2
    assert set(merged["cwes"]) == {"CWE-190", "CWE-835"}
    assert merged["findings"][0]["detector"] == "securecc_source"
    assert merged["findings"][0]["compiler_stage_label"] == "Source analysis"


def test_source_looks_healed_banner():
    assert source_looks_healed("/* SecureCC: catalog-healed */\nint x;") is True
    assert source_looks_healed("int x;") is False

    scan = {"finding_count": 0, "findings": [], "cwes": []}
    assert should_gap_fill_merge(scan, "int x; /* healed: fix */") is False


def test_gap_fill_when_engine_clean():
    scan = {"finding_count": 0, "findings": [], "cwes": []}
    assert should_gap_fill_merge(scan, "int main(){}") is True


def test_merge_skips_duplicate_engine_cwe():
    scan = {
        "finding_count": 1,
        "findings": [{"cwe_id": "CWE-190", "title": "Engine hit"}],
        "cwes": ["CWE-190"],
        "explanations": [],
    }
    ai = {
        "status": "OK",
        "issues": [{"cwe_id": "CWE-190", "title": "Dup", "severity": "high", "message": "m"}],
    }
    merged = merge_ai_review_into_scan(scan, ai)
    assert merged["finding_count"] == 1
