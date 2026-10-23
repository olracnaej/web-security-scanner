"""Score and grade.

Rules (also in the README):
  * Start at 100.
  * Subtract 20 per high, 8 per medium and 3 per low problem. Info costs 0.
  * Each TYPE of problem counts once, at its worst severity, however many
    places it appears (three cookies without HttpOnly are one problem).
  * Grade: A 90+, B 80+, C 70+, D 60+, otherwise F.
  * Any high-severity finding caps the grade at D.
"""

from __future__ import annotations

from dataclasses import dataclass

from scanner.models import Finding, Severity

WEIGHTS = {Severity.HIGH: 20, Severity.MEDIUM: 8, Severity.LOW: 3, Severity.INFO: 0}
GRADE_STEPS = ((90, "A"), (80, "B"), (70, "C"), (60, "D"))


@dataclass(frozen=True)
class Score:
    value: int
    grade: str
    breakdown: dict  # severity label -> {"types": n, "points": p}


def grade_for(value: int) -> str:
    for minimum, letter in GRADE_STEPS:
        if value >= minimum:
            return letter
    return "F"


def score_findings(findings) -> Score:
    worst: dict[str, Severity] = {}
    for finding in findings:
        worst[finding.check_id] = max(worst.get(finding.check_id, finding.severity), finding.severity)

    breakdown = {}
    for severity in sorted(Severity, reverse=True):
        types = sum(1 for s in worst.values() if s == severity)
        breakdown[severity.label] = {"types": types, "points": types * WEIGHTS[severity]}

    value = max(0, 100 - sum(item["points"] for item in breakdown.values()))
    grade = grade_for(value)
    if breakdown["high"]["types"]:
        grade = max(grade, "D")  # letters sort A < B < C < D < F
    return Score(value, grade, breakdown)
