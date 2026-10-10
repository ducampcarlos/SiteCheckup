from __future__ import annotations

import pytest

from sitecheckup.audit.models import AuditReport, Finding, Status
from sitecheckup.audit.scoring import compute_score
from sitecheckup.models import Severity


def finding(severity: Severity, status: Status = Status.FAIL, fid: str = "x") -> Finding:
    return Finding(
        id=fid,
        title="t",
        category="c",
        severity=severity,
        status=status,
        description="d",
        remediation="r",
    )


def test_severity_ordering() -> None:
    assert Severity.HIGH.at_least(Severity.MEDIUM)
    assert not Severity.LOW.at_least(Severity.MEDIUM)
    assert Severity.INFO.rank < Severity.LOW.rank


@pytest.mark.parametrize(
    ("severities", "score", "grade"),
    [
        ([], 100, "A"),
        ([Severity.INFO] * 5, 100, "A"),
        ([Severity.LOW] * 3, 91, "A"),
        ([Severity.LOW] * 4, 88, "B"),
        ([Severity.MEDIUM], 92, "B"),  # medium caps the grade at B
        ([Severity.MEDIUM] * 3, 76, "C"),
        ([Severity.HIGH], 80, "C"),  # high caps the grade at C
        ([Severity.HIGH] * 2, 60, "D"),
        ([Severity.HIGH] * 6, 0, "F"),
    ],
)
def test_score_and_grade(severities: list[Severity], score: int, grade: str) -> None:
    assert compute_score([finding(s) for s in severities]) == (score, grade)


def test_only_failed_findings_count() -> None:
    findings = [finding(Severity.HIGH, Status.PASS), finding(Severity.HIGH, Status.SKIPPED)]
    assert compute_score(findings) == (100, "A")


def test_report_helpers() -> None:
    report = AuditReport(
        target="https://example.com",
        findings=[
            finding(Severity.LOW, fid="a"),
            finding(Severity.HIGH, fid="b"),
            finding(Severity.HIGH, Status.PASS, fid="c"),
        ],
    )
    assert [f.id for f in report.failures] == ["b", "a"]
    assert report.counts() == {"high": 1, "medium": 0, "low": 1, "info": 0}
    assert report.worst() is Severity.HIGH
    assert report.exceeds(Severity.HIGH)
    assert not AuditReport(target="x").exceeds(Severity.INFO)
    assert AuditReport(target="x").worst() is None
