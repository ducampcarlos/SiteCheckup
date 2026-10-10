"""Cookie attribute checks (Secure, HttpOnly, SameSite) on the homepage response."""

from __future__ import annotations

import re
from dataclasses import dataclass

from sitecheckup.audit.base import Check, Outcome, register
from sitecheckup.audit.context import AuditContext
from sitecheckup.models import Severity

_MDN = "https://developer.mozilla.org/docs/Web/HTTP/Headers/Set-Cookie"
_OWASP = "https://owasp.org/www-community/controls/SecureCookieAttribute"
_SESSIONISH = re.compile(r"sess|sid|auth|token|login|jwt|csrf", re.IGNORECASE)


@dataclass(frozen=True)
class Cookie:
    """A parsed ``Set-Cookie`` header (attributes only; values are discarded)."""

    name: str
    secure: bool
    httponly: bool
    samesite: str | None

    @property
    def sensitive(self) -> bool:
        """True if the name suggests a session or authentication cookie."""
        return bool(_SESSIONISH.search(self.name))


def parse_set_cookie(raw: str) -> Cookie:
    """Parse one ``Set-Cookie`` header value into a :class:`Cookie`."""
    first, *attrs = [part.strip() for part in raw.split(";")]
    flags = {a.split("=", 1)[0].strip().lower(): a.partition("=")[2].strip() for a in attrs}
    return Cookie(
        name=first.split("=", 1)[0].strip(),
        secure="secure" in flags,
        httponly="httponly" in flags,
        samesite=flags.get("samesite") or None,
    )


def _cookies(ctx: AuditContext) -> list[Cookie]:
    return [parse_set_cookie(raw) for raw in ctx.homepage.headers.get_list("set-cookie")]


def _verdict(offenders: list[Cookie], what: str) -> Outcome:
    names = ", ".join(c.name for c in offenders)
    severity = Severity.MEDIUM if any(c.sensitive for c in offenders) else Severity.LOW
    return Outcome.fail(f"Cookies without {what}: {names}", severity)


@register
class CookieSecure(Check):
    """Cookies must carry the Secure attribute on HTTPS sites."""

    id = "cookies-secure"
    title = "Cookies have the Secure flag"
    category = "cookies"
    severity = Severity.MEDIUM
    description = (
        "Cookies without Secure may be sent over plain HTTP, where they can be read or replaced "
        "by anyone on the network path. Session-like cookie names raise the severity."
    )
    remediation = (
        "Set the Secure attribute on every cookie (framework session settings usually expose it)."
    )
    references = (_MDN, _OWASP)

    def run(self, ctx: AuditContext) -> Outcome:
        """Flag cookies set on an HTTPS page without ``Secure``."""
        cookies = _cookies(ctx)
        if not cookies:
            return Outcome.skip("The homepage sets no cookies.")
        if ctx.final_scheme != "https":
            return Outcome.skip("Homepage is served over HTTP, where Secure cannot take effect.")
        bad = [c for c in cookies if not c.secure]
        return _verdict(bad, "Secure") if bad else Outcome.ok(f"{len(cookies)} cookie(s) checked.")


@register
class CookieHttpOnly(Check):
    """Cookies should carry HttpOnly unless scripts genuinely need them."""

    id = "cookies-httponly"
    title = "Cookies have the HttpOnly flag"
    category = "cookies"
    severity = Severity.LOW
    description = (
        "HttpOnly hides a cookie from JavaScript, so an XSS bug cannot steal it. Session-like "
        "cookie names raise the severity."
    )
    remediation = "Set HttpOnly on session and authentication cookies."
    references = (
        "https://developer.mozilla.org/docs/Web/HTTP/Cookies#restrict_access_to_cookies",
        _OWASP,
    )

    def run(self, ctx: AuditContext) -> Outcome:
        """Flag cookies without ``HttpOnly``."""
        cookies = _cookies(ctx)
        if not cookies:
            return Outcome.skip("The homepage sets no cookies.")
        bad = [c for c in cookies if not c.httponly]
        return (
            _verdict(bad, "HttpOnly") if bad else Outcome.ok(f"{len(cookies)} cookie(s) checked.")
        )


@register
class CookieSameSite(Check):
    """Cookies should declare a SameSite policy."""

    id = "cookies-samesite"
    title = "Cookies declare SameSite"
    category = "cookies"
    severity = Severity.LOW
    description = (
        "SameSite=Lax or Strict stops browsers attaching the cookie to cross-site requests, "
        "reducing cross-site request forgery. SameSite=None requires Secure."
    )
    remediation = "Set 'SameSite=Lax' (or 'Strict' where possible) on cookies."
    references = ("https://developer.mozilla.org/docs/Web/HTTP/Cookies#samesite_attribute", _OWASP)

    def run(self, ctx: AuditContext) -> Outcome:
        """Flag cookies with no SameSite, or SameSite=None without Secure."""
        cookies = _cookies(ctx)
        if not cookies:
            return Outcome.skip("The homepage sets no cookies.")
        bad = [
            c
            for c in cookies
            if c.samesite is None or (c.samesite.lower() == "none" and not c.secure)
        ]
        return (
            _verdict(bad, "a safe SameSite")
            if bad
            else Outcome.ok(f"{len(cookies)} cookie(s) checked.")
        )
