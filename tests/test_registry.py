from __future__ import annotations

import re

import pytest

from sitecheckup.audit import base
from sitecheckup.audit.base import Check, Outcome, all_checks, register
from sitecheckup.audit.context import AuditContext
from sitecheckup.models import Severity


def test_builtin_checks_have_unique_stable_ids_and_metadata() -> None:
    checks = all_checks()
    ids = [c.id for c in checks]
    assert len(ids) == len(set(ids)) >= 25
    for check in checks:
        assert re.fullmatch(r"[a-z]+(-[a-z0-9]+)+", check.id), check.id
        assert check.title and check.description and check.remediation
        assert check.references or check.severity is Severity.INFO or check.id


def test_register_rejects_missing_metadata() -> None:
    class Incomplete(Check):
        id = "test-incomplete"

        def run(self, ctx: AuditContext) -> Outcome:  # pragma: no cover
            return Outcome.ok()

    with pytest.raises(TypeError, match="missing check metadata"):
        register(Incomplete)


def test_register_rejects_duplicates() -> None:
    first = type(all_checks()[0])
    with pytest.raises(ValueError, match="Duplicate"):
        register(first)


def test_custom_check_can_be_registered(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(base, "_REGISTRY", dict(base._REGISTRY))

    @register
    class Custom(Check):
        id = "custom-example"
        title = "Custom"
        category = "custom"
        severity = Severity.LOW
        description = "d"
        remediation = "r"

        def run(self, ctx: AuditContext) -> Outcome:  # pragma: no cover
            return Outcome.ok()

    assert "custom-example" in [c.id for c in all_checks()]
