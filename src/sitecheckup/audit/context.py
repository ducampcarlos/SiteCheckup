"""Shared, cached view of the target that checks read from."""

from __future__ import annotations

from functools import cached_property
from urllib.parse import urlsplit

from sitecheckup.htmlinfo import PageInfo, parse_page
from sitecheckup.http import DEFAULT_MAX_BYTES, Fetched, PoliteClient
from sitecheckup.tlsinfo import CertProvider, fetch_certificate


class AuditContext:
    """Everything a check may look at, with each URL fetched at most once."""

    def __init__(
        self,
        target: str,
        client: PoliteClient,
        cert_provider: CertProvider = fetch_certificate,
    ) -> None:
        """Create a context for ``target`` (a normalized http(s) URL)."""
        self.target = target
        self.client = client
        self.cert_provider = cert_provider
        parts = urlsplit(target)
        self.scheme = parts.scheme
        self.host = parts.hostname or ""
        self.port = parts.port
        self.origin = f"{parts.scheme}://{parts.netloc}"
        self._cache: dict[tuple[str, bool], Fetched] = {}

    def fetch(self, path_or_url: str, *, follow: bool = False) -> Fetched:
        """GET a path (relative to the origin) or absolute URL, memoized.

        Redirects are not followed unless ``follow`` is set, so a probe for
        ``/.env`` is never mistaken for a hit just because it redirected.
        """
        url = path_or_url if "://" in path_or_url else f"{self.origin}{path_or_url}"
        key = (url, follow)
        if key not in self._cache:
            self._cache[key] = self.client.fetch(url, follow=follow, max_bytes=DEFAULT_MAX_BYTES)
        return self._cache[key]

    @cached_property
    def homepage(self) -> Fetched:
        """The target URL, with same-site redirects followed."""
        return self.fetch(self.target, follow=True)

    @property
    def final_scheme(self) -> str:
        """Scheme of the page the homepage fetch ended on."""
        return urlsplit(self.homepage.final_url).scheme

    @cached_property
    def page(self) -> PageInfo:
        """Parsed homepage metadata (empty if the homepage is not HTML)."""
        if "html" in self.homepage.content_type or self.homepage.text.lstrip().startswith("<"):
            return parse_page(self.homepage.text)
        return PageInfo()

    @cached_property
    def is_wordpress(self) -> bool:
        """Heuristic WordPress detection from the homepage only (no extra requests)."""
        home = self.homepage
        body = home.text.lower()
        generator = (self.page.generator or "").lower()
        return (
            "/wp-content/" in body
            or "/wp-includes/" in body
            or generator.startswith("wordpress")
            or "api.w.org" in home.headers.get("link", "")
        )
