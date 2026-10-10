"""Scoring: a transparent 0-100 score and A-F grade. See docs/scoring.md."""

from __future__ import annotations

from collections.abc import Iterable

from sitecheckup.audit.models import Finding
from sitecheckup.models import Severity

PENALTY: dict[Severity, int] = {
    Severity.HIGH: 20,
    Severity.MEDIUM: 8,
    Severity.LOW: 3,
    Severity.INFO: 0,
}

# (minimum score, grade), checked in order.
GRADE_BANDS: tuple[tuple[int, str], ...] = ((90, "A"), (80, "B"), (70, "C"), (60, "D"), (0, "F"))

# The worst failed severity limits the best attainable grade.
GRADE_CAP: dict[Severity, str] = {Severity.HIGH: "C", Severity.MEDIUM: "B"}


def _grade_for(score: int) -> str:
    for minimum, grade in GRADE_BANDS:
        if score >= minimum:
            return grade
    return "F"  # pragma: no cover - the last band accepts every non-negative score


def compute_score(findings: Iterable[Finding]) -> tuple[int, str]:
    """Return ``(score, grade)`` for the failed findings in ``findings``.

    ``score = max(0, 100 - sum(PENALTY[severity]))`` over failed findings; the
    grade comes from ``GRADE_BANDS`` and is then capped by ``GRADE_CAP`` so a
    single serious issue cannot hide behind many passing checks.
    """
    failed = [f for f in findings if f.failed]
    score = max(0, 100 - sum(PENALTY[f.severity] for f in failed))
    grade = _grade_for(score)
    for severity, cap in GRADE_CAP.items():
        if any(f.severity is severity for f in failed) and grade < cap:
            grade = cap  # letters sort alphabetically: "A" < "B" < ... < "F"
    return score, grade
