"""Finding: one review issue, with evidence and a concrete fix."""
from __future__ import annotations

from dataclasses import asdict, dataclass


SEVERITY_WEIGHT = {"critical": 15, "high": 8, "medium": 4, "low": 1}


@dataclass(frozen=True)
class Finding:
    """A single issue found in reviewed code.

    ``line`` is 1-based. ``evidence`` is the exact source line (or node
    text) that triggered the rule, so a reviewer can verify it without
    re-running the tool. ``suggestion`` is a concrete fix, not a vague
    hint.
    """

    rule: str
    severity: str  # critical | high | medium | low
    category: str  # security | bug | quality
    title: str
    message: str
    file: str
    line: int
    evidence: str = ""
    suggestion: str = ""

    def to_dict(self) -> dict:
        return asdict(self)

    @property
    def weight(self) -> int:
        return SEVERITY_WEIGHT.get(self.severity, 1)
