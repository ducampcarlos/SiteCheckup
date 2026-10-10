"""Presence checks for commonly exposed files and paths.

Every probe is a single GET without following redirects. A hit requires both a
200 response and content that matches a signature, so catch-all pages that
return 200 for everything do not produce false positives. Contents of exposed
files are never stored in findings, only their presence and size.
"""

from __future__ import annotations

import re
from collections.abc import Callable
from dataclasses import dataclass

from sitecheckup.audit.base import Check, Outcome, register
from sitecheckup.audit.context import AuditContext
from sitecheckup.http import Fetched
from sitecheckup.models import Severity

_OWASP_WSTG = "https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/02-Configuration_and_Deployment_Management_Testing/04-Review_Old_Backup_and_Unreferenced_Files_for_Sensitive_Information"
_ENV_LINE = re.compile(rb"^[A-Z][A-Z0-9_]{2,}\s*=", re.MULTILINE)
_SQL = re.compile(
    rb"CREATE TABLE|INSERT INTO|-- MySQL dump|PostgreSQL database dump", re.IGNORECASE
)

Matcher = Callable[[Fetched], bool]


@dataclass(frozen=True)
class Probe:
    """One path to request and the signature that proves it is really exposed."""

    path: str
    matches: Matcher


def _not_html(res: Fetched) -> bool:
    return res.status == 200 and "html" not in res.content_type and bool(res.body)


def _contains(*needles: bytes) -> Matcher:
    def match(res: Fetched) -> bool:
        return res.status == 200 and any(n in res.body for n in needles)

    return match


def _env(res: Fetched) -> bool:
    return _not_html(res) and bool(_ENV_LINE.search(res.body))


def _archive(res: Fetched) -> bool:
    return _not_html(res) and (
        res.body.startswith((b"PK\x03\x04", b"\x1f\x8b")) or bool(_SQL.search(res.body))
    )


def _source_backup(res: Fetched) -> bool:
    return _not_html(res) and any(n in res.body for n in (b"<?php", b"DB_PASSWORD", b"DB_NAME"))


def _listing(res: Fetched) -> bool:
    text = res.text[:4096]
    return res.status == 200 and (
        "<title>Index of /" in text or "<h1>Index of /" in text or "Directory listing for" in text
    )


def _scan(ctx: AuditContext, probes: tuple[Probe, ...]) -> list[tuple[Probe, Fetched]]:
    hits = []
    for probe in probes:
        response = ctx.fetch(probe.path)
        if response.ok and probe.matches(response):
            hits.append((probe, response))
    return hits


class ProbeCheck(Check):
    """Base class: a check that fails when any of its probes hits."""

    probes: tuple[Probe, ...] = ()
    redacted = False  # True when hits are sensitive files whose contents must not be recorded

    def run(self, ctx: AuditContext) -> Outcome:
        """Request each probe path once and report hits without echoing contents."""
        hits = _scan(ctx, self.probes)
        if not hits:
            return Outcome.ok(f"{len(self.probes)} path(s) checked; none exposed.")
        lines = [
            f"{p.path} -> HTTP {r.status}, {len(r.body)} bytes{'+' if r.body_truncated else ''}"
            for p, r in hits
        ]
        note = " (contents deliberately not recorded)" if self.redacted else ""
        return Outcome.fail("; ".join(lines) + note)


@register
class ExposedGit(ProbeCheck):
    """A reachable .git directory leaks source code and history."""

    id = "exposed-git"
    title = "No exposed .git directory"
    category = "exposed-files"
    severity = Severity.HIGH
    description = (
        "A web-accessible .git directory lets anyone download the repository, including "
        "history, configuration and sometimes credentials."
    )
    remediation = (
        "Deploy build artefacts, not working copies. Block dot-directories at the web server "
        "('location ~ /\\. { deny all; }'), and rotate any secret that was ever committed."
    )
    references = (_OWASP_WSTG,)
    redacted = True
    probes = (
        Probe("/.git/HEAD", _contains(b"ref: refs/")),
        Probe("/.git/config", _contains(b"[core]")),
    )


@register
class ExposedEnv(ProbeCheck):
    """A reachable .env file usually contains credentials."""

    id = "exposed-env"
    title = "No exposed .env file"
    category = "exposed-files"
    severity = Severity.HIGH
    description = "Environment files commonly hold database passwords, API keys and app secrets."
    remediation = (
        "Move the file outside the web root or deny access to it, then rotate every secret it "
        "contained: assume it was read."
    )
    references = (_OWASP_WSTG,)
    redacted = True
    probes = (Probe("/.env", _env), Probe("/.env.production", _env))


@register
class ExposedBackups(ProbeCheck):
    """Backups and editor copies left in the web root."""

    id = "exposed-backups"
    title = "No backup or archive files in the web root"
    category = "exposed-files"
    severity = Severity.HIGH
    description = (
        "Database dumps, archives and *.bak copies of configuration files are downloadable by "
        "anyone who guesses the name, and often contain credentials or full site content."
    )
    remediation = (
        "Delete the files, store backups outside the web root, and add a deploy-time check that "
        "fails if archives or *.bak/*.old/*~ files appear in the published directory."
    )
    references = (_OWASP_WSTG,)
    redacted = True
    probes = (
        Probe("/backup.zip", _archive),
        Probe("/backup.sql", _archive),
        Probe("/db.sql", _archive),
        Probe("/dump.sql", _archive),
        Probe("/site.zip", _archive),
        Probe("/www.zip", _archive),
        Probe("/backup.tar.gz", _archive),
        Probe("/wp-config.php.bak", _source_backup),
        Probe("/wp-config.php~", _source_backup),
        Probe("/config.php.bak", _source_backup),
    )


@register
class DirectoryListing(ProbeCheck):
    """Auto-generated directory indexes."""

    id = "exposed-directory-listing"
    title = "Directory listing is disabled"
    category = "exposed-files"
    severity = Severity.MEDIUM
    description = (
        "Directory indexes reveal file names (backups, exports, uploads) that should not be "
        "discoverable."
    )
    remediation = "Disable auto-indexing ('autoindex off;' in nginx, 'Options -Indexes' in Apache)."
    references = (_OWASP_WSTG,)
    probes = tuple(
        Probe(path, _listing)
        for path in ("/", "/uploads/", "/images/", "/assets/", "/files/", "/backup/", "/backups/")
    )


@register
class DiagnosticLeftovers(ProbeCheck):
    """phpinfo pages, server-status and database admin tools."""

    id = "exposed-diagnostics"
    title = "No diagnostic or admin-tool leftovers (phpinfo, server-status, Adminer)"
    category = "exposed-files"
    severity = Severity.MEDIUM
    description = (
        "phpinfo() pages, Apache server-status and database admin tools expose configuration "
        "details and attack surface to the whole internet."
    )
    remediation = (
        "Remove the files, or restrict them by IP/VPN and authentication. Never leave "
        "diagnostics on production."
    )
    references = (_OWASP_WSTG,)
    probes = (
        Probe("/phpinfo.php", _contains(b"phpinfo()", b"PHP Version")),
        Probe("/info.php", _contains(b"phpinfo()", b"PHP Version")),
        Probe("/server-status", _contains(b"Apache Server Status")),
        Probe("/adminer.php", _contains(b"Adminer")),
        Probe("/phpmyadmin/", _contains(b"phpMyAdmin")),
    )
