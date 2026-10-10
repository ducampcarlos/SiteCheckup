"""Fetch each URL from both sites and compare the results."""

from __future__ import annotations

from collections.abc import Callable, Iterable
from urllib.parse import urljoin, urlsplit

from sitecheckup.compare.models import CompareReport, Hop, Issue, Level, Snapshot, UrlResult
from sitecheckup.compare.rules import CompareSettings, evaluate
from sitecheckup.htmlinfo import parse_page
from sitecheckup.http import Fetched, PoliteClient, RequestBudgetExceeded

TRACKED_SECURITY_HEADERS = (
    "content-security-policy",
    "strict-transport-security",
    "x-frame-options",
    "x-content-type-options",
    "referrer-policy",
    "permissions-policy",
)


def snapshot(fetched: Fetched) -> Snapshot:
    """Convert a raw fetch into the comparable :class:`Snapshot`."""
    is_html = fetched.ok and "html" in fetched.content_type
    info = parse_page(fetched.text) if is_html else None
    x_robots = fetched.headers.get("x-robots-tag", "").lower()
    return Snapshot(
        url=fetched.url,
        final_url=fetched.final_url,
        status=fetched.status,
        chain=[Hop(url=h.url, status=h.status) for h in fetched.chain],
        loop=fetched.loop,
        blocked_redirect=fetched.blocked_redirect,
        error=fetched.error,
        elapsed_ms=round(fetched.elapsed * 1000),
        title=info.title if info else None,
        meta_description=info.meta_description if info else None,
        canonical=urljoin(fetched.final_url, info.canonical) if info and info.canonical else None,
        h1=info.h1 if info else None,
        noindex=bool(info and info.noindex) or "noindex" in x_robots,
        security_headers=[h for h in TRACKED_SECURITY_HEADERS if h in fetched.headers],
        is_html=is_html,
    )


SITEWIDE_THRESHOLD = 0.9


def site_wide_issues(results: list[UrlResult]) -> list[Issue]:
    """Spot header regressions that affect (nearly) every page, so they are reported once.

    Per-URL results only mention a lost security header as information; repeating the
    same warning on every page would bury the pages that actually broke.
    """
    issues = []
    for header in TRACKED_SECURITY_HEADERS:
        had = [r for r in results if header in r.old.security_headers and 0 < r.new.status < 400]
        lost = [r for r in had if header not in r.new.security_headers]
        if had and len(lost) / len(had) >= SITEWIDE_THRESHOLD:
            issues.append(
                Issue(
                    code="security_header_lost_sitewide",
                    level=Level.WARNING,
                    message=f"{header} was sent on the old site but is missing on the new one "
                    f"({len(lost)} of {len(had)} comparable pages).",
                )
            )
    return issues


def _join(base: str, path: str) -> str:
    return path if "://" in path else base.rstrip("/") + path


def compare_sites(
    old_base: str,
    new_base: str,
    paths: Iterable[str],
    client: PoliteClient,
    *,
    path_map: dict[str, str] | None = None,
    settings: CompareSettings | None = None,
    source: str = "unknown",
    on_result: Callable[[UrlResult], None] | None = None,
) -> CompareReport:
    """Compare every path on the old site with its counterpart on the new site.

    Stops early (``truncated=True``) if the client's request cap is reached.
    """
    mapping = path_map or {}
    report = CompareReport(old_base=old_base, new_base=new_base, source=source)
    for path in paths:
        new_path = mapping.get(path, path)
        try:
            old_snap = snapshot(client.fetch(_join(old_base, path)))
            new_snap = snapshot(client.fetch(_join(new_base, new_path)))
        except RequestBudgetExceeded:
            report.truncated = True
            break
        final_path = urlsplit(old_snap.final_url).path or "/"
        expected_final = _join(new_base, mapping.get(final_path, final_path))
        result = UrlResult(
            path=path,
            new_path=new_path,
            old=old_snap,
            new=new_snap,
            issues=evaluate(
                old_snap,
                new_snap,
                old_base=old_base,
                new_base=new_base,
                expected_final=expected_final,
                settings=settings,
            ),
        )
        report.results.append(result)
        if on_result:
            on_result(result)
    report.site_issues = site_wide_issues(report.results)
    report.requests_made = client.requests_made
    return report
