"""Where the list of old URLs comes from: a file, the sitemap, or a shallow crawl."""

from __future__ import annotations

import re
from collections import deque
from pathlib import Path
from urllib.parse import urldefrag, urljoin, urlsplit
from urllib.robotparser import RobotFileParser

from sitecheckup.htmlinfo import parse_page
from sitecheckup.http import PoliteClient, RequestBudgetExceeded, host_key

ROBOTS_AGENT = "SiteCheckup"
_SKIP_EXTENSIONS = frozenset(
    [
        "jpg",
        "jpeg",
        "png",
        "gif",
        "webp",
        "svg",
        "ico",
        "css",
        "js",
        "map",
        "json",
        "xml",
        "pdf",
        "zip",
        "gz",
        "tar",
        "mp3",
        "mp4",
        "webm",
        "woff",
        "woff2",
        "ttf",
        "eot",
    ]
)
_LOC = re.compile(
    r"<loc>\s*(?:<!\[CDATA\[)?\s*(.*?)\s*(?:\]\]>)?\s*</loc>", re.IGNORECASE | re.DOTALL
)
MAX_CHILD_SITEMAPS = 10


def to_path(url: str) -> str:
    """Reduce a URL (or path) to ``/path?query`` without fragment."""
    clean = urldefrag(url.strip())[0]
    parts = urlsplit(clean)
    path = parts.path or "/"
    return f"{path}?{parts.query}" if parts.query else path


def _dedupe(paths: list[str], limit: int) -> list[str]:
    return list(dict.fromkeys(paths))[:limit]


def read_urls_file(path: Path, limit: int) -> list[str]:
    """Read one path or URL per line (``#`` comments and blank lines ignored)."""
    lines = path.read_text(encoding="utf-8").splitlines()
    return _dedupe(
        [to_path(ln) for ln in lines if ln.strip() and not ln.lstrip().startswith("#")], limit
    )


def sitemap_urls(client: PoliteClient, old_base: str, limit: int) -> list[str]:
    """Collect paths from ``/sitemap.xml`` (and child sitemaps of an index).

    Locations are parsed with a regular expression rather than an XML parser so a
    hostile sitemap cannot trigger entity-expansion attacks. Only the *path* of
    each entry is used, and requests always go to the old site, never to the host
    named in the sitemap.
    """
    base = old_base.rstrip("/")
    paths: list[str] = []
    pending = deque([f"{base}/sitemap.xml"])
    children = 0
    seen: set[str] = set()
    while pending and len(paths) < limit:
        url = pending.popleft()
        if url in seen:
            continue
        seen.add(url)
        response = client.fetch(url)
        if response.status != 200:
            continue
        for loc in _LOC.findall(response.text):
            if urlsplit(loc).path.lower().endswith(".xml"):
                if children < MAX_CHILD_SITEMAPS:
                    children += 1
                    pending.append(f"{base}{to_path(loc)}")
            else:
                paths.append(to_path(loc))
    return _dedupe(paths, limit)


def load_robots(client: PoliteClient, base: str) -> RobotFileParser:
    """Fetch and parse robots.txt; follows the usual rules for missing/forbidden files."""
    parser = RobotFileParser()
    response = client.fetch(f"{base.rstrip('/')}/robots.txt")
    if response.status in {401, 403}:
        parser.parse(["User-agent: *", "Disallow: /"])
    elif response.status == 200:
        parser.parse(response.text.splitlines())
    else:
        parser.parse([])
    return parser


def crawl(client: PoliteClient, old_base: str, max_pages: int) -> list[str]:
    """Breadth-first, same-host, robots-aware crawl starting at the old site's root."""
    base = old_base.rstrip("/")
    robots = load_robots(client, base)
    site = host_key(base)
    queue = deque([f"{base}/"])
    visited: set[str] = set()
    found: list[str] = []
    while queue and len(found) < max_pages:
        url = queue.popleft()
        if url in visited or not robots.can_fetch(ROBOTS_AGENT, url):
            continue
        visited.add(url)
        try:
            response = client.fetch(url)
        except RequestBudgetExceeded:
            break
        if response.status != 200 or "html" not in response.content_type:
            continue
        found.append(to_path(url))
        for href in parse_page(response.text).links:
            target = urldefrag(urljoin(response.final_url, href))[0]
            parts = urlsplit(target)
            extension = parts.path.rsplit(".", 1)[-1].lower() if "." in parts.path else ""
            if (
                parts.scheme in {"http", "https"}
                and host_key(target) == site
                and extension not in _SKIP_EXTENSIONS
                and target not in visited
            ):
                queue.append(target)
    return _dedupe(found, max_pages)
