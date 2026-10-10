"""Data models for compare results."""

from __future__ import annotations

from datetime import UTC, datetime
from enum import StrEnum

from pydantic import BaseModel, Field

from sitecheckup import __version__


class Level(StrEnum):
    """How serious an issue is for the migration."""

    BLOCKING = "blocking"
    WARNING = "warning"
    INFO = "info"


class Verdict(StrEnum):
    """Overall classification of one URL."""

    BLOCKING = "blocking"
    WARNING = "warning"
    OK = "ok"


class Issue(BaseModel):
    """One difference between old and new, with a stable code."""

    code: str
    level: Level
    message: str


class Hop(BaseModel):
    """One redirect hop."""

    url: str
    status: int


class Snapshot(BaseModel):
    """What one site returned for one URL."""

    url: str
    final_url: str
    status: int
    chain: list[Hop] = Field(default_factory=list)
    loop: bool = False
    blocked_redirect: str | None = None
    error: str | None = None
    elapsed_ms: int = 0
    title: str | None = None
    meta_description: str | None = None
    canonical: str | None = None
    h1: str | None = None
    noindex: bool = False
    security_headers: list[str] = Field(default_factory=list)
    is_html: bool = False

    @property
    def reachable(self) -> bool:
        """True if an HTTP response was received."""
        return self.error is None and self.status > 0

    @property
    def redirected(self) -> bool:
        """True if at least one redirect was followed."""
        return bool(self.chain)


class UrlResult(BaseModel):
    """Comparison of one old URL with its counterpart on the new site."""

    path: str
    new_path: str
    old: Snapshot
    new: Snapshot
    issues: list[Issue] = Field(default_factory=list)

    @property
    def verdict(self) -> Verdict:
        """Worst issue level, collapsed to blocking / warning / ok."""
        levels = {i.level for i in self.issues}
        if Level.BLOCKING in levels:
            return Verdict.BLOCKING
        if Level.WARNING in levels:
            return Verdict.WARNING
        return Verdict.OK


class CompareReport(BaseModel):
    """Complete result of a ``compare`` run."""

    tool_version: str = __version__
    old_base: str
    new_base: str
    generated_at: datetime = Field(default_factory=lambda: datetime.now(UTC))
    source: str = "unknown"
    requests_made: int = 0
    truncated: bool = False
    results: list[UrlResult] = Field(default_factory=list)
    site_issues: list[Issue] = Field(default_factory=list)

    def by_verdict(self, verdict: Verdict) -> list[UrlResult]:
        """Results with the given verdict."""
        return [r for r in self.results if r.verdict is verdict]

    def counts(self) -> dict[str, int]:
        """Number of URLs per verdict."""
        return {v.value: len(self.by_verdict(v)) for v in Verdict}

    def needs_attention(self, *, include_warnings: bool) -> bool:
        """True if any URL (or site-wide issue) is blocking, or a warning when requested."""
        levels = {Level.BLOCKING, Level.WARNING} if include_warnings else {Level.BLOCKING}
        return bool(
            self.by_verdict(Verdict.BLOCKING)
            or (include_warnings and self.by_verdict(Verdict.WARNING))
            or any(i.level in levels for i in self.site_issues)
        )

    def issue_totals(self) -> dict[str, int]:
        """Number of occurrences of each issue code, most common first."""
        totals: dict[str, int] = {}
        for result in self.results:
            for issue in result.issues:
                if issue.level is not Level.INFO:
                    totals[issue.code] = totals.get(issue.code, 0) + 1
        return dict(sorted(totals.items(), key=lambda kv: (-kv[1], kv[0])))
