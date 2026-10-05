from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path


ARTIFACT_SCHEMA_VERSION = 1


@dataclass(frozen=True)
class ArtifactLayout:
    root: Path

    @property
    def evidence(self) -> Path:
        return self.root / "evidence"

    @property
    def verification(self) -> Path:
        return self.root / "verify"

    @property
    def benchmark(self) -> Path:
        return self.root / "benchmark"

    @property
    def measurement(self) -> Path:
        return self.root / "measurement"

    @property
    def protection(self) -> Path:
        return self.root / "protection"

    @property
    def evaluation(self) -> Path:
        return self.root / "evaluation"

    def ensure(self) -> None:
        for path in (
            self.evidence,
            self.verification,
            self.benchmark,
            self.measurement,
            self.protection,
            self.evaluation,
        ):
            path.mkdir(
                parents=True,
                exist_ok=True,
            )


def get_artifact_layout(
    repo_root: Path | None = None,
) -> ArtifactLayout:
    if repo_root is None:
        repo_root = (
            Path(__file__)
            .resolve()
            .parents[3]
        )

    layout = ArtifactLayout(
        root=Path(repo_root).resolve() / "build"
    )

    return layout
