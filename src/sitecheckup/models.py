"""Small shared types."""

from __future__ import annotations

from enum import StrEnum


class Severity(StrEnum):
    """Finding severity, ordered ``info < low < medium < high``."""

    INFO = "info"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"

    @property
    def rank(self) -> int:
        """Numeric rank used for sorting and threshold comparisons."""
        return _RANK[self]

    def at_least(self, other: Severity) -> bool:
        """Return True if this severity is ``other`` or worse."""
        return self.rank >= other.rank


_RANK = {Severity.INFO: 0, Severity.LOW: 1, Severity.MEDIUM: 2, Severity.HIGH: 3}
