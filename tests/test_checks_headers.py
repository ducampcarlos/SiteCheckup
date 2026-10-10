from __future__ import annotations

from collections.abc import Callable

import pytest

from sitecheckup.audit.checks.headers import (
    Clickjacking,
    ContentSecurityPolicy,
    ContentTypeOptions,
    CrossOriginHeaders,
    PermissionsPolicy,
    PoweredByDisclosure,
    ReferrerPolicy,
    ServerDisclosure,
)
from sitecheckup.audit.context import AuditContext
from sitecheckup.audit.models import Status
from sitecheckup.models import Severity
from tests.conftest import FakeSite

Ctx = Callable[..., AuditContext]


def home(site: FakeSite, **headers: str) -> None:
    site.html(
        "https://example.com/",
        "<html></html>",
        headers=[(k.replace("_", "-"), v) for k, v in headers.items()],
    )


class TestCsp:
    def test_missing(self, site: FakeSite, make_ctx: Ctx) -> None:
        home(site)
        outcome = ContentSecurityPolicy().run(make_ctx())
        assert outcome.status is Status.FAIL
        assert outcome.severity is None

    def test_report_only_is_low(self, site: FakeSite, make_ctx: Ctx) -> None:
        home(site, content_security_policy_report_only="default-src 'self'")
        assert ContentSecurityPolicy().run(make_ctx()).severity is Severity.LOW

    @pytest.mark.parametrize(
        "policy",
        [
            "default-src 'self' 'unsafe-inline'",
            "script-src * ; img-src 'self'",
            "script-src 'self' 'unsafe-eval'",
        ],
    )
    def test_weak_policies(self, site: FakeSite, make_ctx: Ctx, policy: str) -> None:
        home(site, content_security_policy=policy)
        outcome = ContentSecurityPolicy().run(make_ctx())
        assert (outcome.status, outcome.severity) == (Status.FAIL, Severity.LOW)

    def test_no_script_source(self, site: FakeSite, make_ctx: Ctx) -> None:
        home(site, content_security_policy="img-src 'self'")
        assert ContentSecurityPolicy().run(make_ctx()).status is Status.FAIL

    def test_good_policy(self, site: FakeSite, make_ctx: Ctx) -> None:
        home(site, content_security_policy="default-src 'self'; script-src 'self'")
        assert ContentSecurityPolicy().run(make_ctx()).status is Status.PASS


class TestClickjacking:
    def test_missing(self, site: FakeSite, make_ctx: Ctx) -> None:
        home(site)
        assert Clickjacking().run(make_ctx()).status is Status.FAIL

    def test_xfo(self, site: FakeSite, make_ctx: Ctx) -> None:
        home(site, x_frame_options="sameorigin")
        assert Clickjacking().run(make_ctx()).status is Status.PASS

    def test_frame_ancestors(self, site: FakeSite, make_ctx: Ctx) -> None:
        home(site, content_security_policy="frame-ancestors 'none'")
        assert Clickjacking().run(make_ctx()).status is Status.PASS

    def test_obsolete_value(self, site: FakeSite, make_ctx: Ctx) -> None:
        home(site, x_frame_options="ALLOW-FROM https://example.org")
        outcome = Clickjacking().run(make_ctx())
        assert outcome.status is Status.FAIL
        assert "obsolete" in outcome.evidence


def test_content_type_options(site: FakeSite, make_ctx: Ctx) -> None:
    home(site)
    assert ContentTypeOptions().run(make_ctx()).status is Status.FAIL
    site.routes.clear()
    home(site, x_content_type_options="nosniff")
    assert ContentTypeOptions().run(make_ctx()).status is Status.PASS


class TestReferrerPolicy:
    @pytest.mark.parametrize(
        ("value", "expected"),
        [
            (None, Status.FAIL),
            ("unsafe-url", Status.FAIL),
            ("strict-origin-when-cross-origin", Status.PASS),
        ],
    )
    def test_values(
        self, site: FakeSite, make_ctx: Ctx, value: str | None, expected: Status
    ) -> None:
        home(site, **({"referrer_policy": value} if value else {}))
        assert ReferrerPolicy().run(make_ctx()).status is expected


def test_permissions_policy(site: FakeSite, make_ctx: Ctx) -> None:
    home(site)
    assert PermissionsPolicy().run(make_ctx()).status is Status.FAIL
    site.routes.clear()
    home(site, permissions_policy="camera=()")
    assert PermissionsPolicy().run(make_ctx()).status is Status.PASS


class TestCrossOrigin:
    def test_all_missing(self, site: FakeSite, make_ctx: Ctx) -> None:
        home(site)
        outcome = CrossOriginHeaders().run(make_ctx())
        assert outcome.status is Status.FAIL
        assert "cross-origin-opener-policy" in outcome.evidence
        assert CrossOriginHeaders.severity is Severity.INFO

    def test_all_present(self, site: FakeSite, make_ctx: Ctx) -> None:
        home(
            site,
            cross_origin_opener_policy="same-origin",
            cross_origin_resource_policy="same-site",
            cross_origin_embedder_policy="require-corp",
        )
        assert CrossOriginHeaders().run(make_ctx()).status is Status.PASS


class TestServerDisclosure:
    @pytest.mark.parametrize(
        ("server", "expected"),
        [
            ("nginx/1.25.3", Status.FAIL),
            ("Apache/2.4.58 (Ubuntu)", Status.FAIL),
            ("nginx", Status.PASS),
            ("", Status.PASS),
        ],
    )
    def test_values(self, site: FakeSite, make_ctx: Ctx, server: str, expected: Status) -> None:
        home(site, **({"server": server} if server else {}))
        assert ServerDisclosure().run(make_ctx()).status is expected


class TestPoweredBy:
    def test_versioned_banner_is_low(self, site: FakeSite, make_ctx: Ctx) -> None:
        home(site, x_powered_by="PHP/8.2.12")
        outcome = PoweredByDisclosure().run(make_ctx())
        assert (outcome.status, outcome.severity) == (Status.FAIL, Severity.LOW)

    def test_unversioned_banner_is_info(self, site: FakeSite, make_ctx: Ctx) -> None:
        home(site, x_powered_by="Express")
        assert PoweredByDisclosure().run(make_ctx()).severity is Severity.INFO

    def test_clean(self, site: FakeSite, make_ctx: Ctx) -> None:
        home(site)
        assert PoweredByDisclosure().run(make_ctx()).status is Status.PASS
