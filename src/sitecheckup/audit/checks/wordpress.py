"""WordPress-specific checks. They run only when WordPress is detected."""

from __future__ import annotations

import json
import re

from sitecheckup.audit.base import Check, Outcome, register
from sitecheckup.audit.context import AuditContext
from sitecheckup.models import Severity

_WP_HARDENING = "https://developer.wordpress.org/advanced-administration/security/hardening/"


class WordPressCheck(Check):
    """Marker base class: skipped automatically on non-WordPress sites."""

    wordpress_only = True
    category = "wordpress"


@register
class WpVersionDisclosure(WordPressCheck):
    """The generator meta tag reveals the WordPress version."""

    id = "wp-version-disclosure"
    title = "WordPress version is not disclosed"
    severity = Severity.LOW
    description = (
        "The <meta name='generator'> tag advertises the exact WordPress version, which makes "
        "targeted attacks against outdated installs easier."
    )
    remediation = (
        "Remove the generator tag (remove_action('wp_head', 'wp_generator')) and, more "
        "importantly, keep core updated so the version does not matter."
    )
    references = (_WP_HARDENING,)

    def run(self, ctx: AuditContext) -> Outcome:
        """Look for a versioned WordPress generator tag."""
        generator = ctx.page.generator or ""
        if re.match(r"wordpress\s+\d", generator, re.IGNORECASE):
            return Outcome.fail(f"generator meta tag: {generator}")
        return Outcome.ok("No versioned generator tag found.")


@register
class WpXmlRpc(WordPressCheck):
    """xmlrpc.php is reachable."""

    id = "wp-xmlrpc"
    title = "xmlrpc.php is not reachable"
    severity = Severity.MEDIUM
    description = (
        "xmlrpc.php enables password guessing at scale (system.multicall) and pingback abuse. "
        "Most sites do not need it. Only a GET is sent; the endpoint's standard 'POST only' "
        "answer is enough to prove it is live."
    )
    remediation = (
        "Block /xmlrpc.php at the web server or with a hardening plugin, unless a specific "
        "integration (such as the mobile app or Jetpack) requires it."
    )
    references = (_WP_HARDENING,)

    def run(self, ctx: AuditContext) -> Outcome:
        """GET /xmlrpc.php and look for the XML-RPC banner."""
        res = ctx.fetch("/xmlrpc.php")
        if res.status in {200, 405} and b"XML-RPC server accepts POST requests only" in res.body:
            return Outcome.fail(f"/xmlrpc.php answers HTTP {res.status} with the XML-RPC banner.")
        return Outcome.ok(f"/xmlrpc.php -> HTTP {res.status}")


# Pretty permalinks expose the REST API at /wp-json/; plain permalinks only via ?rest_route=.
_REST_USER_PATHS = (
    "/wp-json/wp/v2/users?per_page=3",
    "/?rest_route=/wp/v2/users&per_page=3",
)


@register
class WpRestUsers(WordPressCheck):
    """User enumeration through the REST API."""

    id = "wp-user-enumeration-rest"
    title = "REST API does not list users publicly"
    severity = Severity.MEDIUM
    description = (
        "/wp-json/wp/v2/users (or /?rest_route=/wp/v2/users) returns user slugs (often the login name) to anonymous visitors, "
        "giving attackers half of every credential pair."
    )
    remediation = (
        "Restrict the users endpoint to authenticated requests (a small mu-plugin using the "
        "rest_endpoints filter, or your security plugin) and make sure login names differ from "
        "public author slugs."
    )
    references = (_WP_HARDENING, "https://developer.wordpress.org/rest-api/reference/users/")

    def run(self, ctx: AuditContext) -> Outcome:
        """GET the users endpoint (pretty and plain-permalink forms) and look for a user list."""
        tried = []
        for path in _REST_USER_PATHS:
            res = ctx.fetch(path)
            tried.append(f"{path.split('?')[0]} -> HTTP {res.status}")
            if res.status != 200:
                continue
            try:
                data = json.loads(res.text)
            except ValueError:
                continue
            if isinstance(data, list) and data and all(isinstance(u, dict) for u in data):
                slugs = ", ".join(str(u.get("slug", "?")) for u in data[:3])
                return Outcome.fail(
                    f"Anonymous request to {path.split('&')[0]} returned {len(data)} user(s): {slugs}"
                )
        return Outcome.ok("No user list returned (" + "; ".join(tried) + ").")


@register
class WpAuthorEnumeration(WordPressCheck):
    """User enumeration through ?author=N redirects."""

    id = "wp-user-enumeration-author"
    title = "?author=N does not reveal usernames"
    severity = Severity.MEDIUM
    description = (
        "Requesting /?author=1 redirects to /author/<login>/ on default installs, revealing "
        "the username of the first account."
    )
    remediation = (
        "Redirect or 404 ?author= queries for anonymous visitors, or set a different "
        "user_nicename so the slug is not the login."
    )
    references = (_WP_HARDENING,)

    def run(self, ctx: AuditContext) -> Outcome:
        """Request /?author=1 without following the redirect."""
        res = ctx.fetch("/?author=1")
        location = res.headers.get("location", "")
        match = re.search(r"/author/([^/?#]+)", location)
        if res.status in {301, 302} and match:
            return Outcome.fail(f"/?author=1 redirects to {location}")
        return Outcome.ok(f"/?author=1 -> HTTP {res.status}")


@register
class WpReadmeLicense(WordPressCheck):
    """readme.html and license.txt are left in place."""

    id = "wp-readme-license"
    title = "readme.html / license.txt are not exposed"
    severity = Severity.LOW
    description = "readme.html shows the installed version and confirms the platform."
    remediation = "Delete readme.html and license.txt (WordPress restores them on updates, so block them at the server instead)."
    references = (_WP_HARDENING,)

    def run(self, ctx: AuditContext) -> Outcome:
        """GET both files and check for WordPress content."""
        hits = []
        for path in ("/readme.html", "/license.txt"):
            res = ctx.fetch(path)
            if res.status == 200 and b"WordPress" in res.body:
                hits.append(path)
        if hits:
            return Outcome.fail("Reachable: " + ", ".join(hits))
        return Outcome.ok("Neither file is reachable.")


@register
class WpDebugLog(WordPressCheck):
    """wp-content/debug.log left readable."""

    id = "wp-debug-log"
    title = "wp-content/debug.log is not exposed"
    severity = Severity.HIGH
    description = (
        "With WP_DEBUG_LOG enabled, PHP errors (paths, queries, sometimes personal data) are "
        "written to a file that is publicly downloadable by default."
    )
    remediation = (
        "Delete the file, set WP_DEBUG_LOG to a path outside the web root (or disable it), and "
        "deny access to *.log files."
    )
    references = ("https://wordpress.org/documentation/article/debugging-in-wordpress/",)

    def run(self, ctx: AuditContext) -> Outcome:
        """GET the log and look for PHP log lines."""
        res = ctx.fetch("/wp-content/debug.log")
        if res.status == 200 and re.search(
            rb"PHP (Warning|Notice|Fatal error|Deprecated)", res.body
        ):
            return Outcome.fail(
                f"/wp-content/debug.log is downloadable ({len(res.body)} bytes read)."
            )
        return Outcome.ok(f"/wp-content/debug.log -> HTTP {res.status}")


@register
class WpLoginNote(WordPressCheck):
    """wp-login.php accessibility note."""

    id = "wp-login-exposed"
    title = "wp-login.php is reachable from the internet"
    severity = Severity.INFO
    description = (
        "The login page is expected on most sites, but it is the main target of password "
        "guessing. This is a note, not a vulnerability."
    )
    remediation = (
        "Add rate limiting or a WAF rule, enforce strong passwords and two-factor "
        "authentication, and consider restricting /wp-admin by IP or VPN for editors."
    )
    references = (_WP_HARDENING,)

    def run(self, ctx: AuditContext) -> Outcome:
        """Report whether the login form answers publicly."""
        res = ctx.fetch("/wp-login.php")
        if res.status == 200 and b"user_login" in res.body:
            return Outcome.fail("/wp-login.php serves the login form to anonymous visitors.")
        return Outcome.ok(f"/wp-login.php -> HTTP {res.status}")


_ASSET_RE = re.compile(
    r"/wp-content/(plugins|themes)/([A-Za-z0-9_.-]+)/[^\"'\s?>]*(?:\?ver=([A-Za-z0-9_.-]+))?"
)


@register
class WpPluginThemeDisclosure(WordPressCheck):
    """Plugin and theme names (and versions) visible in the page source."""

    id = "wp-plugin-theme-disclosure"
    title = "Plugin and theme names are not enumerable from page source"
    severity = Severity.INFO
    description = (
        "Asset URLs reveal which plugins and themes are installed. This is detection only: "
        "SiteCheckup does not look versions up in vulnerability databases. Exposed versions "
        "raise the severity to low."
    )
    remediation = (
        "Keep every plugin and theme updated and remove unused ones. Hiding names is not a "
        "substitute for patching."
    )
    references = (_WP_HARDENING,)

    def run(self, ctx: AuditContext) -> Outcome:
        """Collect plugin/theme slugs (and ?ver= values) from the homepage source."""
        found: dict[str, str | None] = {}
        for kind, slug, ver in _ASSET_RE.findall(ctx.homepage.text):
            key = f"{kind.rstrip('s')}:{slug}"
            if found.get(key) is None:
                found[key] = ver or None
        if not found:
            return Outcome.ok("No plugin or theme paths in the page source.")
        label = ", ".join(f"{k}{' ' + v if v else ''}" for k, v in sorted(found.items()))
        severity = Severity.LOW if any(found.values()) else Severity.INFO
        return Outcome.fail(label, severity)
