"""Data models for audit results."""

from __future__ import annotations

from datetime import UTC, datetime
from enum import StrEnum

from pydantic import BaseModel, Field

from sitecheckup import __version__
from sitecheckup.models import Severity


class Status(StrEnum):
    """Outcome of running a single check."""

    PASS = "pass"  # noqa: S105 - not a credential
    FAIL = "fail"
    SKIPPED = "skipped"
    ERROR = "error"


class Finding(BaseModel):
    """The result of one check, with everything needed to act on it."""

    id: str
    title: str
    category: str
    severity: Severity
    status: Status
    description: str
    evidence: str = ""
    remediation: str
    references: list[str] = Field(default_factory=list)

    @property
    def failed(self) -> bool:
        """True if the check found a problem."""
        return self.status is Status.FAIL


class AuditReport(BaseModel):
    """A complete audit of one target."""

    tool_version: str = __version__
    target: str
    generated_at: datetime = Field(default_factory=lambda: datetime.now(UTC))
    requests_made: int = 0
    truncated: bool = False
    wordpress_detected: bool = False
    score: int = 100
    grade: str = "A"
    findings: list[Finding] = Field(default_factory=list)

    @property
    def failures(self) -> list[Finding]:
        """Failed findings, worst first."""
        failed = [f for f in self.findings if f.failed]
        return sorted(failed, key=lambda f: -f.severity.rank)

    def counts(self) -> dict[str, int]:
        """Number of failed findings per severity (all severities present)."""
        result = {s.value: 0 for s in reversed(list(Severity))}
        for finding in self.failures:
            result[finding.severity.value] += 1
        return result

    def worst(self) -> Severity | None:
        """Highest severity among failed findings, if any."""
        failures = self.failures
        return failures[0].severity if failures else None

    def exceeds(self, threshold: Severity) -> bool:
        """True if any failed finding is at or above ``threshold``."""
        return any(f.severity.at_least(threshold) for f in self.failures)
