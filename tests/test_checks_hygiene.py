from __future__ import annotations

from collections.abc import Callable

from sitecheckup.audit.checks.hygiene import CacheHeaders, MixedContent, RobotsTxt, SecurityTxt
from sitecheckup.audit.context import AuditContext
from sitecheckup.audit.models import Status
from sitecheckup.models import Severity
from tests.conftest import FakeSite

Ctx = Callable[..., AuditContext]
BASE = "https://example.com"


def test_robots_txt(site: FakeSite, make_ctx: Ctx) -> None:
    site.html(f"{BASE}/", "<html></html>")
    assert RobotsTxt().run(make_ctx()).status is Status.FAIL
    site.add(
        f"{BASE}/robots.txt",
        text="User-agent: *\nDisallow:",
        headers={"content-type": "text/plain"},
    )
    assert RobotsTxt().run(make_ctx()).status is Status.PASS


def test_robots_txt_html_catch_all_does_not_count(site: FakeSite, make_ctx: Ctx) -> None:
    site.html(f"{BASE}/", "<html></html>")
    site.html(f"{BASE}/robots.txt", "<html>home</html>")
    assert RobotsTxt().run(make_ctx()).status is Status.FAIL


def test_security_txt(site: FakeSite, make_ctx: Ctx) -> None:
    site.html(f"{BASE}/", "<html></html>")
    assert SecurityTxt().run(make_ctx()).status is Status.FAIL
    site.add(
        f"{BASE}/.well-known/security.txt",
        text="Contact: mailto:security@example.com\nExpires: 2027-01-01T00:00:00Z",
    )
    assert SecurityTxt().run(make_ctx()).status is Status.PASS


def test_security_txt_legacy_location(site: FakeSite, make_ctx: Ctx) -> None:
    site.html(f"{BASE}/", "<html></html>")
    site.add(f"{BASE}/security.txt", text="Contact: https://example.com/report")
    assert SecurityTxt().run(make_ctx()).status is Status.PASS


class TestMixedContent:
    def test_active_content_is_medium(self, site: FakeSite, make_ctx: Ctx) -> None:
        site.html(
            f"{BASE}/",
            '<script src="http://cdn.example.org/a.js"></script><img src="http://example.com/a.png">',
        )
        outcome = MixedContent().run(make_ctx())
        assert (outcome.status, outcome.severity) == (Status.FAIL, Severity.MEDIUM)
        assert "2 insecure" in outcome.evidence

    def test_passive_only_is_low(self, site: FakeSite, make_ctx: Ctx) -> None:
        site.html(f"{BASE}/", '<img src="http://example.com/a.png">')
        assert MixedContent().run(make_ctx()).severity is Severity.LOW

    def test_clean(self, site: FakeSite, make_ctx: Ctx) -> None:
        site.html(
            f"{BASE}/",
            '<script src="https://example.com/a.js"></script><img src="//example.com/b.png">',
        )
        assert MixedContent().run(make_ctx()).status is Status.PASS

    def test_skipped_on_http(self, site: FakeSite, make_ctx: Ctx) -> None:
        site.html("http://localhost:8080/", '<img src="http://example.com/a.png">')
        assert MixedContent().run(make_ctx("http://localhost:8080")).status is Status.SKIPPED


class TestCacheHeaders:
    def test_none(self, site: FakeSite, make_ctx: Ctx) -> None:
        site.html(f"{BASE}/", "<html></html>")
        assert CacheHeaders().run(make_ctx()).status is Status.FAIL

    def test_validators_are_enough(self, site: FakeSite, make_ctx: Ctx) -> None:
        site.html(f"{BASE}/", "<html></html>", headers=[("etag", '"abc"')])
        assert CacheHeaders().run(make_ctx()).status is Status.PASS

    def test_public_with_cookie_is_medium(self, site: FakeSite, make_ctx: Ctx) -> None:
        site.html(
            f"{BASE}/",
            "<html></html>",
            headers=[("cache-control", "public, max-age=600"), ("set-cookie", "sid=1")],
        )
        outcome = CacheHeaders().run(make_ctx())
        assert (outcome.status, outcome.severity) == (Status.FAIL, Severity.MEDIUM)

    def test_explicit_cache_control(self, site: FakeSite, make_ctx: Ctx) -> None:
        site.html(f"{BASE}/", "<html></html>", headers=[("cache-control", "max-age=60")])
        assert CacheHeaders().run(make_ctx()).status is Status.PASS
