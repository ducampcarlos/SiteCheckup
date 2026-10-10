from __future__ import annotations

from collections.abc import Callable
from datetime import UTC, datetime, timedelta

import httpx
import pytest

from sitecheckup.audit.checks.transport import Hsts, HttpsRedirect, TlsCertificate
from sitecheckup.audit.context import AuditContext
from sitecheckup.audit.models import Status
from sitecheckup.models import Severity
from sitecheckup.tlsinfo import CertInfo
from tests.conftest import FakeSite

Ctx = Callable[..., AuditContext]


def cert_expiring_in(days: int) -> CertInfo:
    return CertInfo(
        verified=True,
        issuer="Example CA",
        not_after=datetime.now(UTC) + timedelta(days=days, hours=1),
    )


class TestHttpsRedirect:
    def test_permanent_redirect_passes(self, site: FakeSite, make_ctx: Ctx) -> None:
        site.redirect("http://example.com/", "https://example.com/")
        outcome = HttpsRedirect().run(make_ctx())
        assert outcome.status is Status.PASS

    def test_temporary_redirect_is_low(self, site: FakeSite, make_ctx: Ctx) -> None:
        site.redirect("http://example.com/", "https://example.com/", 302)
        outcome = HttpsRedirect().run(make_ctx())
        assert (outcome.status, outcome.severity) == (Status.FAIL, Severity.LOW)

    def test_plain_http_200_fails_high(self, site: FakeSite, make_ctx: Ctx) -> None:
        site.html("http://example.com/", "<html></html>")
        outcome = HttpsRedirect().run(make_ctx())
        assert outcome.status is Status.FAIL
        assert outcome.severity is None  # falls back to the check's HIGH default
        assert HttpsRedirect.severity is Severity.HIGH

    def test_redirect_to_http_fails(self, site: FakeSite, make_ctx: Ctx) -> None:
        site.redirect("http://example.com/", "http://example.com/home")
        assert HttpsRedirect().run(make_ctx()).status is Status.FAIL

    def test_http_target_with_port_is_tested_on_same_port(
        self, site: FakeSite, make_ctx: Ctx
    ) -> None:
        site.html("http://localhost:8080/", "<html></html>")
        outcome = HttpsRedirect().run(make_ctx("http://localhost:8080"))
        assert outcome.status is Status.FAIL
        assert "http://localhost:8080/" in outcome.evidence

    def test_https_on_custom_port_is_skipped(self, site: FakeSite, make_ctx: Ctx) -> None:
        assert HttpsRedirect().run(make_ctx("https://example.com:8443")).status is Status.SKIPPED

    def test_unreachable_http_is_skipped(self, site: FakeSite, make_ctx: Ctx) -> None:
        site.error = httpx.ConnectError("refused")
        assert HttpsRedirect().run(make_ctx()).status is Status.SKIPPED


class TestTlsCertificate:
    def test_healthy_certificate_passes(self, site: FakeSite, make_ctx: Ctx) -> None:
        outcome = TlsCertificate().run(make_ctx(cert=cert_expiring_in(90)))
        assert outcome.status is Status.PASS
        assert "Example CA" in outcome.evidence

    @pytest.mark.parametrize(("days", "severity"), [(20, Severity.MEDIUM), (3, Severity.HIGH)])
    def test_expiring_soon(
        self, site: FakeSite, make_ctx: Ctx, days: int, severity: Severity
    ) -> None:
        outcome = TlsCertificate().run(make_ctx(cert=cert_expiring_in(days)))
        assert (outcome.status, outcome.severity) == (Status.FAIL, severity)

    def test_expired(self, site: FakeSite, make_ctx: Ctx) -> None:
        outcome = TlsCertificate().run(make_ctx(cert=cert_expiring_in(-5)))
        assert outcome.status is Status.FAIL
        assert "expired" in outcome.evidence

    def test_verification_failure(self, site: FakeSite, make_ctx: Ctx) -> None:
        bad = CertInfo(verified=False, error="self-signed certificate")
        outcome = TlsCertificate().run(make_ctx(cert=bad))
        assert outcome.status is Status.FAIL
        assert "self-signed" in outcome.evidence

    def test_unknown_expiry_still_passes(self, site: FakeSite, make_ctx: Ctx) -> None:
        assert TlsCertificate().run(make_ctx()).status is Status.PASS

    def test_http_target_on_custom_port_is_skipped(self, site: FakeSite, make_ctx: Ctx) -> None:
        assert TlsCertificate().run(make_ctx("http://localhost:8080")).status is Status.SKIPPED

    def test_http_default_port_probes_443(
        self, site: FakeSite, make_client: Callable[..., object]
    ) -> None:
        calls: list[tuple[str, int]] = []

        def provider(host: str, port: int) -> CertInfo:
            calls.append((host, port))
            return cert_expiring_in(90)

        ctx = AuditContext("http://example.com/", make_client("http://example.com"), provider)  # type: ignore[arg-type]
        TlsCertificate().run(ctx)
        assert calls == [("example.com", 443)]

    def test_custom_https_port_is_used(
        self, site: FakeSite, make_client: Callable[..., object]
    ) -> None:
        calls: list[tuple[str, int]] = []

        def provider(host: str, port: int) -> CertInfo:
            calls.append((host, port))
            return cert_expiring_in(90)

        ctx = AuditContext(
            "https://example.com:8443/", make_client("https://example.com:8443"), provider
        )  # type: ignore[arg-type]
        TlsCertificate().run(ctx)
        assert calls == [("example.com", 8443)]


class TestHsts:
    def _home(self, site: FakeSite, value: str | None) -> None:
        headers = [("strict-transport-security", value)] if value else []
        site.html("https://example.com/", "<html></html>", headers=headers)

    def test_missing(self, site: FakeSite, make_ctx: Ctx) -> None:
        self._home(site, None)
        assert Hsts().run(make_ctx()).status is Status.FAIL

    def test_short_max_age_is_low(self, site: FakeSite, make_ctx: Ctx) -> None:
        self._home(site, "max-age=300")
        outcome = Hsts().run(make_ctx())
        assert (outcome.status, outcome.severity) == (Status.FAIL, Severity.LOW)

    def test_good_value(self, site: FakeSite, make_ctx: Ctx) -> None:
        self._home(site, "max-age=31536000; includeSubDomains; preload")
        outcome = Hsts().run(make_ctx())
        assert outcome.status is Status.PASS
        assert "includeSubDomains" in outcome.evidence

    def test_garbage_value_counts_as_zero(self, site: FakeSite, make_ctx: Ctx) -> None:
        self._home(site, "nonsense")
        assert Hsts().run(make_ctx()).severity is Severity.LOW

    def test_skipped_over_http(self, site: FakeSite, make_ctx: Ctx) -> None:
        site.html("http://localhost:8080/", "<html></html>")
        assert Hsts().run(make_ctx("http://localhost:8080")).status is Status.SKIPPED
