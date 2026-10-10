"""Basic hygiene: robots.txt, security.txt, mixed content, caching."""

from __future__ import annotations

from sitecheckup.audit.base import Check, Outcome, register
from sitecheckup.audit.context import AuditContext
from sitecheckup.models import Severity


@register
class RobotsTxt(Check):
    """robots.txt exists."""

    id = "hygiene-robots-txt"
    title = "robots.txt is present"
    category = "hygiene"
    severity = Severity.INFO
    description = (
        "robots.txt tells well-behaved crawlers what to skip and where the sitemap is. It is not "
        "an access control: never list secret paths in it."
    )
    remediation = "Publish /robots.txt with a Sitemap: line and sensible Disallow rules."
    references = ("https://developer.mozilla.org/docs/Glossary/Robots.txt",)

    def run(self, ctx: AuditContext) -> Outcome:
        """GET /robots.txt."""
        res = ctx.fetch("/robots.txt")
        if res.status == 200 and "html" not in res.content_type:
            return Outcome.ok(f"{len(res.body)} bytes")
        return Outcome.fail(f"/robots.txt -> HTTP {res.status}")


@register
class SecurityTxt(Check):
    """security.txt exists (RFC 9116)."""

    id = "hygiene-security-txt"
    title = "security.txt is published"
    category = "hygiene"
    severity = Severity.INFO
    description = (
        "RFC 9116 security.txt gives researchers a clear, private channel to report problems."
    )
    remediation = "Publish /.well-known/security.txt with Contact: and Expires: fields."
    references = ("https://www.rfc-editor.org/rfc/rfc9116", "https://securitytxt.org/")

    def run(self, ctx: AuditContext) -> Outcome:
        """GET /.well-known/security.txt, then the legacy /security.txt."""
        for path in ("/.well-known/security.txt", "/security.txt"):
            res = ctx.fetch(path)
            if res.status == 200 and b"Contact:" in res.body:
                return Outcome.ok(f"Found {path}")
        return Outcome.fail("No security.txt with a Contact field found.")


@register
class MixedContent(Check):
    """HTTP sub-resources on an HTTPS page."""

    id = "hygiene-mixed-content"
    title = "No mixed content on the homepage"
    category = "hygiene"
    severity = Severity.MEDIUM
    description = (
        "Scripts, frames and stylesheets loaded over http:// from an HTTPS page can be tampered "
        "with (medium); images and media are lower risk (low)."
    )
    remediation = (
        "Change the references to https:// (or protocol-relative paths), fix hard-coded URLs "
        "left over from migrations in the database/templates, and add "
        "'upgrade-insecure-requests' to the CSP as a safety net."
    )
    references = ("https://developer.mozilla.org/docs/Web/Security/Mixed_content",)

    def run(self, ctx: AuditContext) -> Outcome:
        """Scan homepage resources for http:// URLs when the page itself is HTTPS."""
        if ctx.final_scheme != "https":
            return Outcome.skip("Homepage is not served over HTTPS.")
        insecure = [r for r in ctx.page.resources if r.url.lower().startswith("http://")]
        if not insecure:
            return Outcome.ok("No http:// sub-resources found.")
        active = [r for r in insecure if r.active]
        sample = ", ".join(f"{r.tag} {r.url}" for r in insecure[:3])
        return Outcome.fail(
            f"{len(insecure)} insecure reference(s) ({len(active)} active): {sample}",
            Severity.MEDIUM if active else Severity.LOW,
        )


@register
class CacheHeaders(Check):
    """Cache-Control sanity on the homepage."""

    id = "hygiene-cache-headers"
    title = "Homepage has sensible cache headers"
    category = "hygiene"
    severity = Severity.LOW
    description = (
        "Responses without any caching headers are re-downloaded every time; responses that set "
        "cookies but are marked public can be cached by shared proxies and leak between users."
    )
    remediation = (
        "Send an explicit Cache-Control: 'public, max-age=...' for static pages, "
        "'private, no-store' for anything personalised or that sets session cookies."
    )
    references = ("https://developer.mozilla.org/docs/Web/HTTP/Caching",)

    def run(self, ctx: AuditContext) -> Outcome:
        """Look for validators/freshness headers and cookie-vs-public conflicts."""
        headers = ctx.homepage.headers
        cache_control = headers.get("cache-control", "").lower()
        if headers.get_list("set-cookie") and "public" in cache_control:
            return Outcome.fail(
                f"Response sets cookies but is publicly cacheable: {cache_control}", Severity.MEDIUM
            )
        if not any(h in headers for h in ("cache-control", "expires", "etag", "last-modified")):
            return Outcome.fail("No Cache-Control, Expires, ETag or Last-Modified header.")
        return Outcome.ok(cache_control or "validators present (ETag/Last-Modified)")
