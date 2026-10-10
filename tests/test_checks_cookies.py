from __future__ import annotations

from collections.abc import Callable

from sitecheckup.audit.checks.cookies import (
    CookieHttpOnly,
    CookieSameSite,
    CookieSecure,
    parse_set_cookie,
)
from sitecheckup.audit.context import AuditContext
from sitecheckup.audit.models import Status
from sitecheckup.models import Severity
from tests.conftest import FakeSite

Ctx = Callable[..., AuditContext]


def serve(site: FakeSite, *cookies: str, url: str = "https://example.com/") -> None:
    site.html(url, "<html></html>", headers=[("set-cookie", c) for c in cookies])


def test_parse_set_cookie() -> None:
    cookie = parse_set_cookie("PHPSESSID=abc123; Path=/; Secure; HttpOnly; SameSite=Lax")
    assert (cookie.name, cookie.secure, cookie.httponly, cookie.samesite) == (
        "PHPSESSID",
        True,
        True,
        "Lax",
    )
    assert cookie.sensitive
    bare = parse_set_cookie("theme=dark")
    assert not (bare.secure or bare.httponly or bare.samesite or bare.sensitive)


def test_no_cookies_means_not_applicable(site: FakeSite, make_ctx: Ctx) -> None:
    site.html("https://example.com/", "<html></html>")
    for check in (CookieSecure(), CookieHttpOnly(), CookieSameSite()):
        assert check.run(make_ctx()).status is Status.SKIPPED


def test_all_flags_set_passes(site: FakeSite, make_ctx: Ctx) -> None:
    serve(site, "sid=1; Secure; HttpOnly; SameSite=Strict")
    for check in (CookieSecure(), CookieHttpOnly(), CookieSameSite()):
        assert check.run(make_ctx()).status is Status.PASS


def test_missing_secure_on_session_cookie_is_medium(site: FakeSite, make_ctx: Ctx) -> None:
    serve(site, "sessionid=1; HttpOnly", "theme=dark; Secure")
    outcome = CookieSecure().run(make_ctx())
    assert (outcome.status, outcome.severity) == (Status.FAIL, Severity.MEDIUM)
    assert "sessionid" in outcome.evidence
    assert "theme" not in outcome.evidence


def test_missing_httponly_on_ordinary_cookie_is_low(site: FakeSite, make_ctx: Ctx) -> None:
    serve(site, "theme=dark; Secure")
    outcome = CookieHttpOnly().run(make_ctx())
    assert (outcome.status, outcome.severity) == (Status.FAIL, Severity.LOW)


def test_secure_not_evaluated_over_http(site: FakeSite, make_ctx: Ctx) -> None:
    serve(site, "sid=1", url="http://localhost:8080/")
    ctx = make_ctx("http://localhost:8080")
    assert CookieSecure().run(ctx).status is Status.SKIPPED
    assert CookieHttpOnly().run(ctx).status is Status.FAIL


def test_samesite_none_requires_secure(site: FakeSite, make_ctx: Ctx) -> None:
    serve(site, "a=1; SameSite=None", "b=1; SameSite=None; Secure", "c=1")
    outcome = CookieSameSite().run(make_ctx())
    assert outcome.status is Status.FAIL
    assert "a, c" in outcome.evidence
