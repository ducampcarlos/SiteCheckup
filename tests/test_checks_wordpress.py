from __future__ import annotations

import json
from collections.abc import Callable

from sitecheckup.audit.checks.wordpress import (
    WpAuthorEnumeration,
    WpDebugLog,
    WpLoginNote,
    WpPluginThemeDisclosure,
    WpReadmeLicense,
    WpRestUsers,
    WpVersionDisclosure,
    WpXmlRpc,
)
from sitecheckup.audit.context import AuditContext
from sitecheckup.audit.models import Status
from sitecheckup.models import Severity
from tests.conftest import FakeSite

Ctx = Callable[..., AuditContext]
BASE = "https://example.com"

WP_HOME = """<html><head>
<meta name="generator" content="WordPress 6.4.2">
<link rel="stylesheet" href="https://example.com/wp-content/themes/twentytwentyfour/style.css?ver=1.2">
<script src="https://example.com/wp-content/plugins/contact-form-7/js/index.js?ver=5.9.3"></script>
<script src="https://example.com/wp-content/plugins/contact-form-7/js/other.js"></script>
<script src="https://example.com/wp-content/plugins/seo-helper/app.js"></script>
</head><body></body></html>"""


def wp(site: FakeSite) -> None:
    site.html(f"{BASE}/", WP_HOME)


def test_wordpress_detection_variants(site: FakeSite, make_ctx: Ctx) -> None:
    site.html(f"{BASE}/", "<html><body>plain</body></html>")
    assert not make_ctx().is_wordpress
    site.html(f"{BASE}/", "<meta name='generator' content='WordPress 6.0'>")
    assert make_ctx().is_wordpress
    site.html(
        f"{BASE}/",
        "<p>x</p>",
        headers=[("link", '<https://example.com/wp-json/>; rel="https://api.w.org/"')],
    )
    assert make_ctx().is_wordpress
    site.html(f"{BASE}/", '<img src="/wp-includes/images/x.png">')
    assert make_ctx().is_wordpress


def test_version_disclosure(site: FakeSite, make_ctx: Ctx) -> None:
    wp(site)
    outcome = WpVersionDisclosure().run(make_ctx())
    assert outcome.status is Status.FAIL
    assert "6.4.2" in outcome.evidence
    site.html(f"{BASE}/", '<meta name="generator" content="WordPress"><link href="/wp-content/x">')
    assert WpVersionDisclosure().run(make_ctx()).status is Status.PASS


def test_xmlrpc(site: FakeSite, make_ctx: Ctx) -> None:
    wp(site)
    assert WpXmlRpc().run(make_ctx()).status is Status.PASS
    site.add(f"{BASE}/xmlrpc.php", 405, text="XML-RPC server accepts POST requests only.")
    assert WpXmlRpc().run(make_ctx()).status is Status.FAIL


def test_rest_user_enumeration(site: FakeSite, make_ctx: Ctx) -> None:
    wp(site)
    assert WpRestUsers().run(make_ctx()).status is Status.PASS
    users = [{"id": 1, "slug": "editor-one"}, {"id": 2, "slug": "editor-two"}]
    site.add(f"{BASE}/wp-json/wp/v2/users?per_page=3", text=json.dumps(users))
    outcome = WpRestUsers().run(make_ctx())
    assert outcome.status is Status.FAIL
    assert "editor-one" in outcome.evidence


def test_rest_user_enumeration_with_plain_permalinks(site: FakeSite, make_ctx: Ctx) -> None:
    wp(site)  # /wp-json/ is a 404 on plain permalinks; the API lives behind ?rest_route=
    site.add(
        f"{BASE}/?rest_route=/wp/v2/users&per_page=3", text=json.dumps([{"slug": "admin-user"}])
    )
    outcome = WpRestUsers().run(make_ctx())
    assert outcome.status is Status.FAIL
    assert "rest_route" in outcome.evidence


def test_rest_users_blocked_or_malformed(site: FakeSite, make_ctx: Ctx) -> None:
    wp(site)
    for url in (
        f"{BASE}/wp-json/wp/v2/users?per_page=3",
        f"{BASE}/?rest_route=/wp/v2/users&per_page=3",
    ):
        site.add(url, 401, text='{"code":"rest_cannot_access"}')
    assert WpRestUsers().run(make_ctx()).status is Status.PASS
    for url in (
        f"{BASE}/wp-json/wp/v2/users?per_page=3",
        f"{BASE}/?rest_route=/wp/v2/users&per_page=3",
    ):
        site.add(url, 200, text="not json")
    assert WpRestUsers().run(make_ctx()).status is Status.PASS
    for url in (
        f"{BASE}/wp-json/wp/v2/users?per_page=3",
        f"{BASE}/?rest_route=/wp/v2/users&per_page=3",
    ):
        site.add(url, 200, text="[]")
    assert WpRestUsers().run(make_ctx()).status is Status.PASS


def test_author_enumeration(site: FakeSite, make_ctx: Ctx) -> None:
    wp(site)
    assert WpAuthorEnumeration().run(make_ctx()).status is Status.PASS
    site.redirect(f"{BASE}/?author=1", f"{BASE}/author/admin-user/")
    outcome = WpAuthorEnumeration().run(make_ctx())
    assert outcome.status is Status.FAIL
    assert "/author/admin-user/" in outcome.evidence


def test_readme_and_license(site: FakeSite, make_ctx: Ctx) -> None:
    wp(site)
    assert WpReadmeLicense().run(make_ctx()).status is Status.PASS
    site.html(f"{BASE}/readme.html", "<h1>WordPress</h1> Version 6.4")
    outcome = WpReadmeLicense().run(make_ctx())
    assert outcome.status is Status.FAIL
    assert "/readme.html" in outcome.evidence


def test_debug_log(site: FakeSite, make_ctx: Ctx) -> None:
    wp(site)
    assert WpDebugLog().run(make_ctx()).status is Status.PASS
    site.add(
        f"{BASE}/wp-content/debug.log",
        text="[01-Jan-2026 00:00:00 UTC] PHP Warning:  Undefined variable",
    )
    assert WpDebugLog().run(make_ctx()).status is Status.FAIL
    assert WpDebugLog.severity is Severity.HIGH


def test_login_note(site: FakeSite, make_ctx: Ctx) -> None:
    wp(site)
    assert WpLoginNote().run(make_ctx()).status is Status.PASS
    site.html(f"{BASE}/wp-login.php", '<form><input name="user_login"></form>')
    outcome = WpLoginNote().run(make_ctx())
    assert outcome.status is Status.FAIL
    assert WpLoginNote.severity is Severity.INFO


def test_plugin_and_theme_disclosure(site: FakeSite, make_ctx: Ctx) -> None:
    wp(site)
    outcome = WpPluginThemeDisclosure().run(make_ctx())
    assert outcome.status is Status.FAIL
    assert outcome.severity is Severity.LOW  # versions are exposed
    assert "plugin:contact-form-7 5.9.3" in outcome.evidence
    assert "theme:twentytwentyfour 1.2" in outcome.evidence
    assert "plugin:seo-helper" in outcome.evidence


def test_plugin_disclosure_names_only_is_info(site: FakeSite, make_ctx: Ctx) -> None:
    site.html(f"{BASE}/", '<script src="/wp-content/plugins/seo-helper/app.js"></script>')
    assert WpPluginThemeDisclosure().run(make_ctx()).severity is Severity.INFO
    site.html(f"{BASE}/", "<html>/wp-includes/</html>")
    assert WpPluginThemeDisclosure().run(make_ctx()).status is Status.PASS
