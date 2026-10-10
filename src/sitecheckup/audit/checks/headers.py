"""Security response headers and information-leaking headers."""

from __future__ import annotations

import re

from sitecheckup.audit.base import Check, Outcome, register
from sitecheckup.audit.context import AuditContext
from sitecheckup.models import Severity

_OWASP_HEADERS = "https://owasp.org/www-project-secure-headers/"
_MDN = "https://developer.mozilla.org/docs/Web/HTTP/Headers"


def _csp_directives(value: str) -> dict[str, str]:
    result: dict[str, str] = {}
    for part in value.split(";"):
        name, _, rest = part.strip().partition(" ")
        if name:
            result[name.lower()] = rest.strip()
    return result


@register
class ContentSecurityPolicy(Check):
    """A Content-Security-Policy that restricts script sources."""

    id = "headers-csp"
    title = "Content-Security-Policy is set and not trivially bypassable"
    category = "headers"
    severity = Severity.MEDIUM
    description = (
        "CSP limits where scripts and other resources may load from, which is the main "
        "browser-side mitigation for cross-site scripting. Policies that allow "
        "'unsafe-inline', 'unsafe-eval' or wildcards for scripts give little protection."
    )
    remediation = (
        "Start with 'Content-Security-Policy-Report-Only', collect violations, then enforce a "
        "policy such as \"default-src 'self'; script-src 'self'; object-src 'none'; "
        "base-uri 'self'; frame-ancestors 'self'\"."
    )
    references = (f"{_MDN}/Content-Security-Policy", f"{_OWASP_HEADERS}#content-security-policy")

    def run(self, ctx: AuditContext) -> Outcome:
        """Evaluate the enforced CSP on the homepage."""
        headers = ctx.homepage.headers
        enforced = headers.get("content-security-policy")
        if not enforced:
            if headers.get("content-security-policy-report-only"):
                return Outcome.fail(
                    "Only Content-Security-Policy-Report-Only is set.", Severity.LOW
                )
            return Outcome.fail("No Content-Security-Policy header.")
        directives = _csp_directives(enforced)
        script_src = directives.get("script-src") or directives.get("default-src") or ""
        weak = [
            token
            for token in ("'unsafe-inline'", "'unsafe-eval'", "*", "data:", "http:")
            if token in script_src.split()
        ]
        if not script_src:
            return Outcome.fail("CSP has no script-src or default-src directive.", Severity.LOW)
        if weak:
            return Outcome.fail(
                f"CSP script sources allow {', '.join(weak)}: {script_src}", Severity.LOW
            )
        return Outcome.ok(f"script sources: {script_src}")


@register
class Clickjacking(Check):
    """Framing protection via X-Frame-Options or CSP frame-ancestors."""

    id = "headers-clickjacking"
    title = "Clickjacking protection (X-Frame-Options / frame-ancestors)"
    category = "headers"
    severity = Severity.MEDIUM
    description = (
        "Without framing protection another site can embed this one in an invisible frame and "
        "trick users into clicking."
    )
    remediation = (
        "Send \"Content-Security-Policy: frame-ancestors 'self'\" (preferred) and/or "
        "'X-Frame-Options: SAMEORIGIN' for older browsers."
    )
    references = (f"{_MDN}/X-Frame-Options", f"{_OWASP_HEADERS}#x-frame-options")

    def run(self, ctx: AuditContext) -> Outcome:
        """Look for X-Frame-Options or a frame-ancestors directive."""
        headers = ctx.homepage.headers
        xfo = headers.get("x-frame-options")
        csp = _csp_directives(headers.get("content-security-policy", ""))
        if "frame-ancestors" in csp:
            return Outcome.ok(f"frame-ancestors {csp['frame-ancestors']}")
        if xfo and xfo.strip().upper() in {"DENY", "SAMEORIGIN"}:
            return Outcome.ok(f"X-Frame-Options: {xfo}")
        if xfo:
            return Outcome.fail(f"X-Frame-Options has a weak or obsolete value: {xfo}")
        return Outcome.fail("Neither X-Frame-Options nor CSP frame-ancestors is set.")


@register
class ContentTypeOptions(Check):
    """X-Content-Type-Options: nosniff."""

    id = "headers-content-type-options"
    title = "X-Content-Type-Options: nosniff"
    category = "headers"
    severity = Severity.LOW
    description = "Stops browsers from guessing content types, which can turn uploads into scripts."
    remediation = "Send 'X-Content-Type-Options: nosniff' on all responses."
    references = (f"{_MDN}/X-Content-Type-Options", f"{_OWASP_HEADERS}#x-content-type-options")

    def run(self, ctx: AuditContext) -> Outcome:
        """Require the nosniff value."""
        value = ctx.homepage.headers.get("x-content-type-options", "")
        if value.strip().lower() == "nosniff":
            return Outcome.ok("nosniff")
        return Outcome.fail(f"Header missing or wrong value: {value or 'not set'}")


@register
class ReferrerPolicy(Check):
    """A restrictive Referrer-Policy."""

    id = "headers-referrer-policy"
    title = "Referrer-Policy limits URL leakage"
    category = "headers"
    severity = Severity.LOW
    description = (
        "The Referer header can leak full URLs (including tokens in query strings) to third "
        "parties. A restrictive policy keeps that data on your own origin."
    )
    remediation = "Send 'Referrer-Policy: strict-origin-when-cross-origin' (or stricter)."
    references = (f"{_MDN}/Referrer-Policy", f"{_OWASP_HEADERS}#referrer-policy")

    def run(self, ctx: AuditContext) -> Outcome:
        """Fail when absent or set to an unsafe value."""
        value = ctx.homepage.headers.get("referrer-policy", "").strip().lower()
        if not value:
            return Outcome.fail("No Referrer-Policy header.")
        if value in {"unsafe-url", "no-referrer-when-downgrade", "origin-when-cross-origin"}:
            return Outcome.fail(f"Permissive Referrer-Policy: {value}")
        return Outcome.ok(value)


@register
class PermissionsPolicy(Check):
    """Permissions-Policy limits powerful browser features."""

    id = "headers-permissions-policy"
    title = "Permissions-Policy is set"
    category = "headers"
    severity = Severity.LOW
    description = (
        "Permissions-Policy disables browser features (camera, microphone, geolocation...) "
        "the site does not need, limiting the impact of injected or third-party content."
    )
    remediation = "Send e.g. 'Permissions-Policy: camera=(), microphone=(), geolocation=()'."
    references = (f"{_MDN}/Permissions-Policy", f"{_OWASP_HEADERS}#permissions-policy")

    def run(self, ctx: AuditContext) -> Outcome:
        """Require the header to be present."""
        value = ctx.homepage.headers.get("permissions-policy")
        return Outcome.ok(value) if value else Outcome.fail("No Permissions-Policy header.")


@register
class CrossOriginHeaders(Check):
    """Cross-origin isolation headers (defence in depth)."""

    id = "headers-cross-origin"
    title = "Cross-origin isolation headers (COOP/CORP/COEP)"
    category = "headers"
    severity = Severity.INFO
    description = (
        "Cross-Origin-Opener-Policy, Cross-Origin-Resource-Policy and "
        "Cross-Origin-Embedder-Policy isolate the page from other origins. They are "
        "defence in depth and not required for every site, so this is informational."
    )
    remediation = (
        "Consider 'Cross-Origin-Opener-Policy: same-origin' and "
        "'Cross-Origin-Resource-Policy: same-site' if the site does not rely on cross-origin popups "
        "or embeds."
    )
    references = (
        f"{_MDN}/Cross-Origin-Opener-Policy",
        f"{_OWASP_HEADERS}#cross-origin-opener-policy",
    )

    def run(self, ctx: AuditContext) -> Outcome:
        """Report which of the three headers are absent."""
        names = (
            "cross-origin-opener-policy",
            "cross-origin-resource-policy",
            "cross-origin-embedder-policy",
        )
        missing = [n for n in names if n not in ctx.homepage.headers]
        if not missing:
            return Outcome.ok("COOP, CORP and COEP are all set.")
        return Outcome.fail("Not set: " + ", ".join(missing))


_VERSION_RE = re.compile(r"\d+\.\d+|/\d")


@register
class ServerDisclosure(Check):
    """The Server header should not reveal software versions."""

    id = "headers-server-disclosure"
    title = "Server header does not disclose a version"
    category = "headers"
    severity = Severity.LOW
    description = (
        "Version banners make it trivial to look up known vulnerabilities for the exact "
        "software in use."
    )
    remediation = (
        "Hide versions: 'server_tokens off;' (nginx), 'ServerTokens Prod' and "
        "'ServerSignature Off' (Apache), or strip the header at the CDN/proxy."
    )
    references = (f"{_MDN}/Server", "https://owasp.org/www-project-web-security-testing-guide/")

    def run(self, ctx: AuditContext) -> Outcome:
        """Fail when the Server header contains something that looks like a version."""
        value = ctx.homepage.headers.get("server", "")
        if value and _VERSION_RE.search(value):
            return Outcome.fail(f"Server: {value}")
        return Outcome.ok(f"Server: {value}" if value else "No Server header.")


@register
class PoweredByDisclosure(Check):
    """Framework banners such as X-Powered-By."""

    id = "headers-powered-by"
    title = "No framework banner headers (X-Powered-By and friends)"
    category = "headers"
    severity = Severity.LOW
    description = (
        "Headers such as X-Powered-By, X-AspNet-Version and X-Generator advertise the "
        "technology stack and often its version."
    )
    remediation = (
        "Remove the headers: 'expose_php = Off' for PHP, 'header_remove(\"X-Powered-By\")', "
        "or 'proxy_hide_header X-Powered-By;' in nginx."
    )
    references = (f"{_MDN}/X-Powered-By",)

    def run(self, ctx: AuditContext) -> Outcome:
        """Fail if any banner header is present; severity drops if it has no version."""
        found = {
            name: ctx.homepage.headers[name]
            for name in ("x-powered-by", "x-aspnet-version", "x-aspnetmvc-version", "x-generator")
            if name in ctx.homepage.headers
        }
        if not found:
            return Outcome.ok("No banner headers.")
        text = "; ".join(f"{k}: {v}" for k, v in found.items())
        has_version = any(re.search(r"\d", v) for v in found.values())
        return Outcome.fail(text, Severity.LOW if has_version else Severity.INFO)
