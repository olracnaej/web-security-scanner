"""Data shared by all checks."""

from __future__ import annotations

from dataclasses import dataclass
from enum import IntEnum


class Severity(IntEnum):
    INFO = 0
    LOW = 1
    MEDIUM = 2
    HIGH = 3

    @property
    def label(self) -> str:
        return self.name.lower()


@dataclass(frozen=True)
class Finding:
    check_id: str
    title: str
    severity: Severity
    description: str
    recommendation: str
    evidence: str = ""
