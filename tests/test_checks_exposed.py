from __future__ import annotations

from collections.abc import Callable

from sitecheckup.audit.checks.exposed import (
    DiagnosticLeftovers,
    DirectoryListing,
    ExposedBackups,
    ExposedEnv,
    ExposedGit,
)
from sitecheckup.audit.context import AuditContext
from sitecheckup.audit.models import Status
from tests.conftest import FakeSite

Ctx = Callable[..., AuditContext]
BASE = "https://example.com"


def test_clean_site_passes_everything(site: FakeSite, make_ctx: Ctx) -> None:
    ctx = make_ctx()
    for check in (
        ExposedGit(),
        ExposedEnv(),
        ExposedBackups(),
        DirectoryListing(),
        DiagnosticLeftovers(),
    ):
        assert check.run(ctx).status is Status.PASS


def test_git_head_exposed(site: FakeSite, make_ctx: Ctx) -> None:
    site.add(
        f"{BASE}/.git/HEAD", text="ref: refs/heads/main\n", headers={"content-type": "text/plain"}
    )
    outcome = ExposedGit().run(make_ctx())
    assert outcome.status is Status.FAIL
    assert "/.git/HEAD" in outcome.evidence


def test_git_config_exposed(site: FakeSite, make_ctx: Ctx) -> None:
    site.add(f"{BASE}/.git/config", text="[core]\n\trepositoryformatversion = 0\n")
    assert ExposedGit().run(make_ctx()).status is Status.FAIL


def test_catch_all_200_page_is_not_a_false_positive(site: FakeSite, make_ctx: Ctx) -> None:
    spa = "<html><body>Welcome, the single page app</body></html>"
    for path in ("/.git/HEAD", "/.env", "/backup.zip", "/phpinfo.php", "/wp-config.php.bak"):
        site.html(BASE + path, spa)
    ctx = make_ctx()
    assert ExposedGit().run(ctx).status is Status.PASS
    assert ExposedEnv().run(ctx).status is Status.PASS
    assert ExposedBackups().run(ctx).status is Status.PASS
    assert DiagnosticLeftovers().run(ctx).status is Status.PASS


def test_env_file_exposed_without_leaking_contents(site: FakeSite, make_ctx: Ctx) -> None:
    secret = "hunter2-not-a-real-secret"
    site.add(
        f"{BASE}/.env",
        text=f"APP_ENV=production\nDB_PASSWORD={secret}\n",
        headers={"content-type": "text/plain"},
    )
    outcome = ExposedEnv().run(make_ctx())
    assert outcome.status is Status.FAIL
    assert secret not in outcome.evidence
    assert "not recorded" in outcome.evidence


def test_redirect_is_not_a_hit(site: FakeSite, make_ctx: Ctx) -> None:
    site.redirect(f"{BASE}/.env", "/login")
    assert ExposedEnv().run(make_ctx()).status is Status.PASS


def test_backup_archives_and_dumps(site: FakeSite, make_ctx: Ctx) -> None:
    site.add(
        f"{BASE}/backup.zip",
        content=b"PK\x03\x04" + b"\x00" * 50,
        headers={"content-type": "application/zip"},
    )
    site.add(
        f"{BASE}/db.sql",
        text="-- MySQL dump 10.13\nCREATE TABLE users (id int);",
        headers={"content-type": "text/plain"},
    )
    site.add(
        f"{BASE}/wp-config.php.bak",
        text="<?php define('DB_PASSWORD', 'x');",
        headers={"content-type": "text/plain"},
    )
    outcome = ExposedBackups().run(make_ctx())
    assert outcome.status is Status.FAIL
    for path in ("/backup.zip", "/db.sql", "/wp-config.php.bak"):
        assert path in outcome.evidence


def test_directory_listing_detected(site: FakeSite, make_ctx: Ctx) -> None:
    site.html(
        f"{BASE}/uploads/",
        "<html><head><title>Index of /uploads/</title></head><body><h1>Index of /uploads/</h1></body></html>",
    )
    outcome = DirectoryListing().run(make_ctx())
    assert outcome.status is Status.FAIL
    assert "/uploads/" in outcome.evidence


def test_diagnostics_detected(site: FakeSite, make_ctx: Ctx) -> None:
    site.html(f"{BASE}/phpinfo.php", "<title>phpinfo()</title>PHP Version 8.2")
    site.html(f"{BASE}/server-status", "<h1>Apache Server Status for example.com</h1>")
    outcome = DiagnosticLeftovers().run(make_ctx())
    assert outcome.status is Status.FAIL
    assert "/phpinfo.php" in outcome.evidence
    assert "/server-status" in outcome.evidence


def test_each_probe_is_a_single_request(site: FakeSite, make_ctx: Ctx) -> None:
    ctx = make_ctx()
    ExposedGit().run(ctx)
    ExposedGit().run(ctx)  # cached: no additional traffic
    assert sorted(site.calls) == [f"{BASE}/.git/HEAD", f"{BASE}/.git/config"]
    assert all(r.method == "GET" for r in site.requests)
