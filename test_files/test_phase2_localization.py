import pickle
from pathlib import Path

from src.V2.detection.engine import DetectionEngine
from src.V2.localization.localizer import VulnerabilityLocalizer


def load_samples():
    root = Path(__file__).resolve().parents[1]
    with (root / "data" / "graphs.pkl").open("rb") as handle:
        return pickle.load(handle)


def test_every_phase1_finding_is_localized():
    engine = DetectionEngine()
    localizer = VulnerabilityLocalizer()

    for sample in load_samples():
        findings = engine.analyze(sample)
        localized = localizer.localize(sample, findings)

        assert len(localized) == len(findings)

        for finding, item in zip(findings, localized):
            assert item.cwe_id == finding.cwe_id
            assert item.vulnerable_node == finding.node_id
            assert item.vulnerable_instruction
            assert item.vulnerable_block is not None
            assert 0.0 < item.localization_confidence <= 1.0
            assert item.evidence
            assert item.evidence[0].node_id is not None
