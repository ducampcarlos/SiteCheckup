"""The comparison rules: pure functions from two snapshots to a list of issues."""

from __future__ import annotations

from urllib.parse import urlsplit

from pydantic import BaseModel

from sitecheckup.compare.models import Issue, Level, Snapshot
from sitecheckup.http import host_key

TEMPORARY_REDIRECTS = frozenset({302, 303, 307})


class CompareSettings(BaseModel):
    """Thresholds used by the rules (all overridable)."""

    max_redirect_chain: int = 2
    slow_ratio: float = 1.5
    slow_delta_ms: int = 500


def _path_key(url: str) -> str:
    parts = urlsplit(url)
    path = parts.path.rstrip("/") or "/"
    return f"{path}?{parts.query}" if parts.query else path


def _norm(text: str | None) -> str | None:
    return " ".join(text.split()) if text else None


def _issue(code: str, level: Level, message: str) -> Issue:
    return Issue(code=code, level=level, message=message)


def _status_issues(old: Snapshot, new: Snapshot) -> list[Issue]:
    if new.error:
        return [_issue("new_unreachable", Level.BLOCKING, f"New site request failed: {new.error}")]
    if new.status >= 500:
        return [_issue("server_error", Level.BLOCKING, f"New site returns HTTP {new.status}.")]
    old_ok = old.reachable and old.status < 400
    if new.status >= 400:
        if old_ok:
            code = "missing_on_new" if new.status in {404, 410} else "client_error"
            return [
                _issue(
                    code,
                    Level.BLOCKING,
                    f"Old site returns {old.status} but the new site returns {new.status}.",
                )
            ]
        if old.status != new.status:
            return [_issue("status_differs", Level.INFO, f"Status {old.status} -> {new.status}.")]
        return []
    if old.reachable and old.status >= 400:
        return [
            _issue(
                "fixed_on_new",
                Level.INFO,
                f"Old site returned {old.status}; new returns {new.status}.",
            )
        ]
    return []


def _redirect_issues(
    old: Snapshot, new: Snapshot, old_base: str, expected_final: str, settings: CompareSettings
) -> list[Issue]:
    issues: list[Issue] = []
    if new.loop:
        issues.append(_issue("redirect_loop", Level.BLOCKING, "The new site redirects in a loop."))
        return issues
    if new.blocked_redirect:
        level = (
            Level.BLOCKING
            if host_key(new.blocked_redirect) == host_key(old_base)
            else Level.WARNING
        )
        code = "redirects_to_old_site" if level is Level.BLOCKING else "external_redirect"
        issues.append(
            _issue(code, level, f"Redirects away from the new site to {new.blocked_redirect}.")
        )
    hops = len(new.chain)
    if hops > settings.max_redirect_chain:
        issues.append(
            _issue(
                "redirect_chain_long",
                Level.WARNING,
                f"{hops} redirects before the final page (limit {settings.max_redirect_chain}): "
                + " -> ".join(h.url for h in new.chain)
                + f" -> {new.final_url}",
            )
        )
    if new.redirected and not old.redirected:
        first = new.chain[0]
        issues.append(
            _issue(
                "unexpected_redirect",
                Level.WARNING,
                f"Old site serves the URL directly; the new site redirects ({first.status}) to "
                f"{new.chain[1].url if hops > 1 else new.final_url}.",
            )
        )
    if (
        new.redirected
        and new.chain[0].status in TEMPORARY_REDIRECTS
        and (not old.redirected or old.chain[0].status != new.chain[0].status)
    ):
        issues.append(
            _issue(
                "temporary_redirect",
                Level.WARNING,
                f"The first redirect is temporary ({new.chain[0].status}); use 301/308 for permanent moves.",
            )
        )
    if (
        old.redirected
        and new.redirected
        and not new.loop
        and _path_key(new.final_url) != _path_key(expected_final)
    ):
        issues.append(
            _issue(
                "redirect_target_changed",
                Level.WARNING,
                f"Both redirect, but to different pages: {_path_key(expected_final)} (old) vs "
                f"{_path_key(new.final_url)} (new).",
            )
        )
    if old.redirected and not new.redirected and new.status < 400:
        issues.append(
            _issue(
                "redirect_removed",
                Level.INFO,
                "Old site redirected; new site serves the page directly.",
            )
        )
    return issues


def _metadata_issues(old: Snapshot, new: Snapshot, old_base: str, new_base: str) -> list[Issue]:
    issues: list[Issue] = []
    old_title, new_title = _norm(old.title), _norm(new.title)
    if old_title and not new_title:
        issues.append(_issue("title_missing", Level.WARNING, f"Title lost (was {old_title!r})."))
    elif old_title != new_title and new_title:
        issues.append(
            _issue(
                "title_changed", Level.WARNING, f"Title changed: {old_title!r} -> {new_title!r}."
            )
        )
    old_desc, new_desc = _norm(old.meta_description), _norm(new.meta_description)
    if old_desc and not new_desc:
        issues.append(
            _issue(
                "meta_description_lost",
                Level.WARNING,
                "Meta description is missing on the new page.",
            )
        )
    elif old_desc and new_desc and old_desc != new_desc:
        issues.append(
            _issue("meta_description_changed", Level.INFO, "Meta description text changed.")
        )
    old_h1, new_h1 = _norm(old.h1), _norm(new.h1)
    if old_h1 and not new_h1:
        issues.append(_issue("h1_lost", Level.WARNING, f"<h1> lost (was {old_h1!r})."))
    elif old_h1 and new_h1 and old_h1 != new_h1:
        issues.append(_issue("h1_changed", Level.INFO, f"<h1> changed: {old_h1!r} -> {new_h1!r}."))
    issues.extend(_canonical_issues(old, new, old_base, new_base))
    if new.noindex and not old.noindex:
        issues.append(
            _issue(
                "noindex_added",
                Level.BLOCKING,
                "The new page is marked noindex; it will drop out of search.",
            )
        )
    elif old.noindex and not new.noindex:
        issues.append(
            _issue(
                "noindex_removed", Level.INFO, "The old page was noindex; the new one is indexable."
            )
        )
    lost = sorted(set(old.security_headers) - set(new.security_headers))
    if lost:
        issues.append(
            _issue(
                "security_header_lost",
                Level.INFO,
                "Security headers present on old but missing on new: " + ", ".join(lost),
            )
        )
    return issues


def _canonical_issues(old: Snapshot, new: Snapshot, old_base: str, new_base: str) -> list[Issue]:
    if not new.canonical:
        if old.canonical:
            return [_issue("canonical_missing", Level.WARNING, "Canonical link was removed.")]
        return []
    canonical_host = host_key(new.canonical)
    if canonical_host == host_key(old_base) and host_key(old_base) != host_key(new_base):
        return [
            _issue(
                "canonical_points_to_old_host",
                Level.BLOCKING,
                f"Canonical still points at the old host: {new.canonical}",
            )
        ]
    if canonical_host != host_key(new_base) and canonical_host != ("", None):
        return [
            _issue(
                "canonical_host_changed",
                Level.WARNING,
                f"Canonical points at a different host: {new.canonical}",
            )
        ]
    return []


def _timing_issues(old: Snapshot, new: Snapshot, settings: CompareSettings) -> list[Issue]:
    delta = new.elapsed_ms - old.elapsed_ms
    if delta >= settings.slow_delta_ms and new.elapsed_ms >= old.elapsed_ms * settings.slow_ratio:
        return [
            _issue(
                "slower",
                Level.WARNING,
                f"Slower on the new site: {old.elapsed_ms} ms -> {new.elapsed_ms} ms (+{delta} ms).",
            )
        ]
    return []


def evaluate(
    old: Snapshot,
    new: Snapshot,
    *,
    old_base: str,
    new_base: str,
    expected_final: str | None = None,
    settings: CompareSettings | None = None,
) -> list[Issue]:
    """Compare two snapshots of the same page and return the differences found.

    Args:
        old: Snapshot from the old site.
        new: Snapshot from the new site.
        old_base: Base URL of the old site (used for host comparisons).
        new_base: Base URL of the new site.
        expected_final: Where the new page should end up if the old one redirected
            (after applying the path map); defaults to the old final URL.
        settings: Thresholds.
    """
    cfg = settings or CompareSettings()
    issues = _status_issues(old, new)
    if new.error:
        return issues
    issues += _redirect_issues(old, new, old_base, expected_final or old.final_url, cfg)
    if new.status < 400 and old.reachable and old.status < 400 and old.is_html and new.is_html:
        issues += _metadata_issues(old, new, old_base, new_base)
    if new.status < 400 and old.reachable:
        issues += _timing_issues(old, new, cfg)
    return issues
