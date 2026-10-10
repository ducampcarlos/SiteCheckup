from __future__ import annotations

from collections.abc import Callable

import httpx
import pytest

from sitecheckup.audit import base
from sitecheckup.audit.base import Check, Outcome, register
from sitecheckup.audit.context import AuditContext
from sitecheckup.audit.models import Status
from sitecheckup.audit.runner import TargetUnreachable, run_audit
from sitecheckup.http import PoliteClient
from sitecheckup.models import Severity
from tests.conftest import FakeSite, ok_cert

BASE = "https://example.com"


def test_full_audit_of_a_minimal_site(
    site: FakeSite, make_client: Callable[..., PoliteClient]
) -> None:
    site.html(f"{BASE}/", "<html><title>Hi</title></html>", headers=[("server", "nginx/1.25.0")])
    report = run_audit(BASE + "/", make_client(BASE), cert_provider=ok_cert)
    by_id = {f.id: f for f in report.findings}
    assert by_id["headers-server-disclosure"].status is Status.FAIL
    assert by_id["headers-csp"].status is Status.FAIL
    assert by_id["wp-xmlrpc"].status is Status.SKIPPED  # not WordPress
    assert not report.wordpress_detected
    assert 0 < report.score < 100
    assert report.requests_made == len(site.calls)
    assert report.requests_made < 60


def test_wordpress_checks_run_when_detected(
    site: FakeSite, make_client: Callable[..., PoliteClient]
) -> None:
    site.html(f"{BASE}/", '<link href="/wp-content/themes/x/s.css">')
    report = run_audit(BASE + "/", make_client(BASE), cert_provider=ok_cert)
    assert report.wordpress_detected
    assert {f.id: f for f in report.findings}["wp-xmlrpc"].status is Status.PASS


def test_skip_option_excludes_checks(
    site: FakeSite, make_client: Callable[..., PoliteClient]
) -> None:
    site.html(f"{BASE}/", "<html></html>")
    report = run_audit(BASE + "/", make_client(BASE), skip={"headers-csp"}, cert_provider=ok_cert)
    assert "headers-csp" not in {f.id for f in report.findings}


def test_unreachable_target_raises(
    site: FakeSite, make_client: Callable[..., PoliteClient]
) -> None:
    site.error = httpx.ConnectError("refused")
    with pytest.raises(TargetUnreachable, match="Could not reach"):
        run_audit(BASE + "/", make_client(BASE))


def test_request_cap_truncates_the_run(
    site: FakeSite, make_client: Callable[..., PoliteClient]
) -> None:
    site.html(f"{BASE}/", "<html></html>")
    report = run_audit(BASE + "/", make_client(BASE, max_requests=5), cert_provider=ok_cert)
    assert report.truncated
    assert report.requests_made == 5
    assert any("Request cap" in f.evidence for f in report.findings)


def test_a_crashing_check_is_reported_not_fatal(
    site: FakeSite, make_client: Callable[..., PoliteClient], monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(base, "_REGISTRY", dict(base._REGISTRY))

    @register
    class Boom(Check):
        id = "test-boom"
        title = "Boom"
        category = "test"
        severity = Severity.HIGH
        description = "d"
        remediation = "r"

        def run(self, ctx: AuditContext) -> Outcome:
            raise ValueError("kaboom")

    site.html(f"{BASE}/", "<html></html>")
    seen: list[str] = []
    report = run_audit(
        BASE + "/", make_client(BASE), on_check=lambda c: seen.append(c.id), cert_provider=ok_cert
    )
    boom = next(f for f in report.findings if f.id == "test-boom")
    assert boom.status is Status.ERROR
    assert "kaboom" in boom.evidence
    assert "test-boom" in seen
    assert not boom.failed  # errors never affect the score
