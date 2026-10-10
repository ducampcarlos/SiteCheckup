"""Transport security: HTTPS enforcement, certificate health, HSTS."""

from __future__ import annotations

import re
from urllib.parse import urlsplit

from sitecheckup.audit.base import Check, Outcome, register
from sitecheckup.audit.context import AuditContext
from sitecheckup.models import Severity

_MDN_HSTS = "https://developer.mozilla.org/docs/Web/HTTP/Headers/Strict-Transport-Security"
HSTS_MIN_SECONDS = 15_552_000  # 180 days


@register
class HttpsRedirect(Check):
    """Plain HTTP must redirect to HTTPS."""

    id = "transport-https-redirect"
    title = "HTTP redirects to HTTPS"
    category = "transport"
    severity = Severity.HIGH
    description = (
        "Visitors who type or follow an http:// link should be sent to HTTPS "
        "immediately; otherwise traffic and cookies can be read or altered in transit."
    )
    remediation = (
        "Add a site-wide permanent (301/308) redirect from http:// to https:// at the web "
        "server or CDN, then enable HSTS once every subdomain works over HTTPS."
    )
    references = (
        "https://owasp.org/www-project-secure-headers/",
        "https://cheatsheetseries.owasp.org/cheatsheets/Transport_Layer_Security_Cheat_Sheet.html",
    )

    def run(self, ctx: AuditContext) -> Outcome:
        """Request the http:// root without following redirects."""
        if ctx.scheme == "https" and ctx.port not in (None, 443):
            return Outcome.skip("HTTPS target on a non-default port; no HTTP twin to test.")
        netloc = urlsplit(ctx.origin).netloc
        response = ctx.fetch(f"http://{netloc}/")
        if not response.ok:
            return Outcome.skip(f"http://{netloc}/ is not reachable ({response.error}).")
        location = response.headers.get("location", "")
        if response.status in {301, 302, 303, 307, 308} and location.lower().startswith("https://"):
            if response.status in {302, 303, 307}:
                return Outcome.fail(
                    f"http://{netloc}/ redirects to {location} with a temporary "
                    f"{response.status}; browsers and crawlers will not cache it.",
                    Severity.LOW,
                )
            return Outcome.ok(f"http://{netloc}/ -> {response.status} {location}")
        if response.status in {301, 302, 303, 307, 308}:
            return Outcome.fail(
                f"http://{netloc}/ redirects ({response.status}) to {location or 'unknown'}, "
                "which is not an https:// URL."
            )
        return Outcome.fail(f"http://{netloc}/ answered {response.status} over plain HTTP.")


@register
class TlsCertificate(Check):
    """The certificate must verify and not be close to expiry."""

    id = "transport-tls-certificate"
    title = "TLS certificate is valid and not close to expiry"
    category = "transport"
    severity = Severity.HIGH
    description = (
        "An invalid, mismatched or expired certificate triggers browser warnings and breaks "
        "API clients. Severity is high when verification fails or expiry is within 7 days, "
        "medium within 30 days."
    )
    remediation = (
        "Renew or reissue the certificate, make sure it covers the exact hostname, and "
        "automate renewal (for example ACME/Let's Encrypt with monitoring on expiry)."
    )
    references = (
        "https://developer.mozilla.org/docs/Web/Security/Transport_Layer_Security",
        "https://cheatsheetseries.owasp.org/cheatsheets/Transport_Layer_Security_Cheat_Sheet.html",
    )

    def run(self, ctx: AuditContext) -> Outcome:
        """Perform one TLS handshake against the target host."""
        if ctx.scheme == "http" and ctx.port not in (None, 80):
            return Outcome.skip("Plain-HTTP target on a non-default port; TLS not applicable.")
        port = 443 if ctx.scheme == "http" or ctx.port is None else ctx.port
        cert = ctx.cert_provider(ctx.host, port)
        if not cert.verified:
            return Outcome.fail(
                f"Certificate verification failed on {ctx.host}:{port}: {cert.error}"
            )
        days = cert.days_left()
        detail = f"issuer {cert.issuer or 'unknown'}"
        if days is None:
            return Outcome.ok(f"Certificate verified ({detail}); expiry date unavailable.")
        if days < 0:
            return Outcome.fail(f"Certificate expired {-days} day(s) ago ({detail}).")
        if days <= 7:
            return Outcome.fail(f"Certificate expires in {days} day(s) ({detail}).", Severity.HIGH)
        if days <= 30:
            return Outcome.fail(
                f"Certificate expires in {days} day(s) ({detail}).", Severity.MEDIUM
            )
        return Outcome.ok(f"Certificate valid for another {days} day(s) ({detail}).")


@register
class Hsts(Check):
    """HTTPS responses should carry a sensible Strict-Transport-Security header."""

    id = "transport-hsts"
    title = "HSTS is enabled with a long max-age"
    category = "transport"
    severity = Severity.MEDIUM
    description = (
        "Strict-Transport-Security tells browsers to use HTTPS only, which defeats "
        "downgrade and cookie-stripping attacks. A max-age under 180 days is considered too "
        "short to be effective."
    )
    remediation = (
        "Send 'Strict-Transport-Security: max-age=31536000; includeSubDomains' on HTTPS "
        "responses. Start with a short max-age while testing, then raise it."
    )
    references = (
        _MDN_HSTS,
        "https://owasp.org/www-project-secure-headers/#strict-transport-security",
    )

    def run(self, ctx: AuditContext) -> Outcome:
        """Inspect the HSTS header on the final HTTPS homepage response."""
        if ctx.final_scheme != "https":
            return Outcome.skip("Homepage is not served over HTTPS; HSTS is ignored on HTTP.")
        value = ctx.homepage.headers.get("strict-transport-security")
        if not value:
            return Outcome.fail("No Strict-Transport-Security header on the HTTPS homepage.")
        match = re.search(r"max-age\s*=\s*\"?(\d+)", value, re.IGNORECASE)
        max_age = int(match.group(1)) if match else 0
        if max_age < HSTS_MIN_SECONDS:
            return Outcome.fail(
                f"HSTS max-age is {max_age}s (< {HSTS_MIN_SECONDS}s): {value}", Severity.LOW
            )
        extras = [d for d in ("includeSubDomains", "preload") if d.lower() in value.lower()]
        return Outcome.ok(f"{value} ({', '.join(extras) or 'no includeSubDomains/preload'})")
