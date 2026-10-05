from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path


@dataclass(frozen=True)
class BehaviorExpectation:
    stdin: str = ""
    stdout: str = ""
    stderr: str = ""
    exit_code: int = 0


class BehaviorOracle:
    """
    Loads explicit behavioral expectations for verification.

    The oracle is data-driven:
        source file -> expected stdin/stdout/stderr/exit code

    Missing expectations are intentionally treated as
    unavailable rather than as a failed behavior test.
    """

    def __init__(self, path: Path | None = None):
        self.path = Path(path) if path else None
        self._tests: dict[str, BehaviorExpectation] = {}

        if self.path is not None:
            self._load()

    def _load(self) -> None:
        if not self.path.exists():
            raise FileNotFoundError(
                f"behavior specification not found: {self.path}"
            )

        data = json.loads(
            self.path.read_text(encoding="utf-8")
        )

        if not isinstance(data, dict):
            raise ValueError(
                "behavior specification must be a JSON object"
            )

        version = data.get("version")

        if version != 1:
            raise ValueError(
                f"unsupported behavior specification version: {version}"
            )

        tests = data.get("tests", {})

        if not isinstance(tests, dict):
            raise ValueError(
                "'tests' must be an object"
            )

        for source_name, expectation in tests.items():

            if not isinstance(expectation, dict):
                raise ValueError(
                    f"behavior entry for {source_name!r} "
                    "must be an object"
                )

            self._tests[source_name] = BehaviorExpectation(
                stdin=str(expectation.get("stdin", "")),
                stdout=str(expectation.get("stdout", "")),
                stderr=str(expectation.get("stderr", "")),
                exit_code=int(
                    expectation.get("exit_code", 0)
                ),
            )

    def get(
        self,
        source: Path | str,
    ) -> BehaviorExpectation | None:

        source = Path(source)

        candidates = [
            source.name,
            str(source),
        ]

        for candidate in candidates:
            if candidate in self._tests:
                return self._tests[candidate]

        return None

    def has(
        self,
        source: Path | str,
    ) -> bool:
        return self.get(source) is not None

    def names(self) -> list[str]:
        return sorted(self._tests)
