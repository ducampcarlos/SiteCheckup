"""Check base class and the plugin-style registry.

To add a check, subclass :class:`Check`, fill in the metadata, implement
:meth:`Check.run`, and decorate the class with :func:`register`::

    @register
    class MyCheck(Check):
        id = "hygiene-my-check"
        title = "Something is configured"
        category = "hygiene"
        severity = Severity.LOW
        description = "Why this matters."
        remediation = "How to fix it."
        references = ("https://owasp.org/...",)

        def run(self, ctx: AuditContext) -> Outcome:
            return Outcome.ok() if ... else Outcome.fail("what was seen")
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass
from typing import TYPE_CHECKING, ClassVar, TypeVar

from sitecheckup.audit.models import Finding, Status
from sitecheckup.models import Severity

if TYPE_CHECKING:
    from sitecheckup.audit.context import AuditContext


@dataclass(frozen=True)
class Outcome:
    """What a check observed. The runner turns it into a :class:`Finding`."""

    status: Status
    evidence: str = ""
    severity: Severity | None = None  # overrides the check default when set

    @classmethod
    def ok(cls, evidence: str = "") -> Outcome:
        """The check passed."""
        return cls(Status.PASS, evidence)

    @classmethod
    def fail(cls, evidence: str, severity: Severity | None = None) -> Outcome:
        """The check found a problem (optionally with a more specific severity)."""
        return cls(Status.FAIL, evidence, severity)

    @classmethod
    def skip(cls, reason: str) -> Outcome:
        """The check does not apply to this target."""
        return cls(Status.SKIPPED, reason)


class Check(ABC):
    """A single, small, independently testable audit check."""

    id: ClassVar[str]
    title: ClassVar[str]
    category: ClassVar[str]
    severity: ClassVar[Severity]
    description: ClassVar[str]
    remediation: ClassVar[str]
    references: ClassVar[tuple[str, ...]] = ()
    wordpress_only: ClassVar[bool] = False

    @abstractmethod
    def run(self, ctx: AuditContext) -> Outcome:
        """Inspect the target through ``ctx`` and report what was observed."""

    def finding(self, outcome: Outcome) -> Finding:
        """Combine this check's metadata with an outcome."""
        return Finding(
            id=self.id,
            title=self.title,
            category=self.category,
            severity=outcome.severity or self.severity,
            status=outcome.status,
            description=self.description,
            evidence=outcome.evidence,
            remediation=self.remediation,
            references=list(self.references),
        )


_C = TypeVar("_C", bound=type[Check])
_REGISTRY: dict[str, type[Check]] = {}

_REQUIRED = ("id", "title", "category", "severity", "description", "remediation")


def register(cls: _C) -> _C:
    """Class decorator that adds a check to the registry (IDs must be unique)."""
    missing = [name for name in _REQUIRED if not hasattr(cls, name)]
    if missing:
        raise TypeError(f"{cls.__name__} is missing check metadata: {', '.join(missing)}")
    if cls.id in _REGISTRY:
        raise ValueError(f"Duplicate check id {cls.id!r}")
    _REGISTRY[cls.id] = cls
    return cls


def all_checks() -> list[Check]:
    """Instantiate every registered check, in registration order."""
    from sitecheckup.audit import checks  # noqa: F401, PLC0415 - triggers registration

    return [cls() for cls in _REGISTRY.values()]
