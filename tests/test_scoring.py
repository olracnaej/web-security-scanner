import pytest

from scanner.models import Finding, Severity
from scanner.scoring import grade_for, score_findings


def f(check_id, severity):
    return Finding(check_id, "t", severity, "d", "r")


def test_no_findings_is_a_perfect_score():
    score = score_findings([])
    assert (score.value, score.grade) == (100, "A")


def test_info_costs_nothing():
    assert score_findings([f("a", Severity.INFO)]).value == 100


@pytest.mark.parametrize(
    "severity, value",
    [(Severity.LOW, 97), (Severity.MEDIUM, 92), (Severity.HIGH, 80)],
)
def test_weights(severity, value):
    assert score_findings([f("a", severity)]).value == value


def test_same_type_of_problem_counts_once():
    three_cookies = [f("cookies.no-httponly", Severity.LOW)] * 3
    assert score_findings(three_cookies).value == 97


def test_worst_severity_of_a_type_is_the_one_counted():
    mixed = [f("cookies.no-httponly", Severity.LOW), f("cookies.no-httponly", Severity.MEDIUM)]
    score = score_findings(mixed)
    assert score.value == 92
    assert score.breakdown["medium"] == {"types": 1, "points": 8}
    assert score.breakdown["low"] == {"types": 0, "points": 0}


def test_score_never_goes_below_zero():
    many = [f(f"x{i}", Severity.HIGH) for i in range(10)]
    assert score_findings(many).value == 0


@pytest.mark.parametrize(
    "value, grade",
    [(100, "A"), (90, "A"), (89, "B"), (80, "B"), (79, "C"), (70, "C"),
     (69, "D"), (60, "D"), (59, "F"), (0, "F")],
)
def test_grade_boundaries(value, grade):
    assert grade_for(value) == grade


def test_one_high_finding_caps_the_grade_at_d():
    score = score_findings([f("exposed.git", Severity.HIGH)])
    assert score.value == 80          # would be a B by points alone
    assert score.grade == "D"


def test_cap_does_not_improve_a_worse_grade():
    many = [f(f"x{i}", Severity.HIGH) for i in range(5)]
    assert score_findings(many).grade == "F"
