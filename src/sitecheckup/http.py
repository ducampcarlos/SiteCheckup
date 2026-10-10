"""A deliberately polite HTTP client.

Every request made by SiteCheckup goes through :class:`PoliteClient`, which
enforces an identifiable User-Agent, a request-rate limit, timeouts, a hard cap
on the number of requests per run, a cap on bytes read per response, and a
same-site policy for redirects.
"""

from __future__ import annotations

import time
from collections.abc import Callable, Iterable
from dataclasses import dataclass, field
from types import TracebackType
from typing import Self
from urllib.parse import urldefrag, urljoin, urlsplit

import httpx

from sitecheckup import __version__

USER_AGENT = (
    f"SiteCheckup/{__version__} (+https://github.com/ducampcarlos/SiteCheckup; passive-check)"
)
DEFAULT_RATE = 2.0
DEFAULT_TIMEOUT = 10.0
DEFAULT_MAX_BYTES = 512 * 1024
MAX_REDIRECTS = 10
REDIRECT_STATUSES = frozenset({301, 302, 303, 307, 308})
_DEFAULT_PORTS = {"http": 80, "https": 443}


class RequestBudgetExceeded(RuntimeError):
    """Raised when the per-run request cap has been reached."""


def host_key(url: str) -> tuple[str, int | None]:
    """Identify a site by hostname (minus ``www.``) and non-default port.

    ``http://example.com`` and ``https://www.example.com`` map to the same key,
    which is how the client decides whether a redirect stays on the same site.
    """
    parts = urlsplit(url)
    host = (parts.hostname or "").lower().removeprefix("www.")
    port = parts.port
    if port is not None and port == _DEFAULT_PORTS.get(parts.scheme):
        port = None
    return host, port


@dataclass(frozen=True)
class Hop:
    """One redirect response that was followed."""

    url: str
    status: int


@dataclass
class Fetched:
    """The outcome of fetching one URL, including any redirects followed."""

    url: str
    final_url: str
    status: int
    headers: httpx.Headers = field(default_factory=httpx.Headers)
    body: bytes = b""
    elapsed: float = 0.0
    chain: list[Hop] = field(default_factory=list)
    error: str | None = None
    loop: bool = False
    body_truncated: bool = False
    blocked_redirect: str | None = None

    @property
    def ok(self) -> bool:
        """True if a response was received (any status code)."""
        return self.error is None and self.status > 0

    @property
    def text(self) -> str:
        """Body decoded as text (undecodable bytes are replaced)."""
        return self.body.decode("utf-8", errors="replace")

    @property
    def content_type(self) -> str:
        """Lower-cased media type without parameters."""
        content_type: str = self.headers.get("content-type", "")
        return content_type.split(";", maxsplit=1)[0].strip().lower()

    @property
    def redirect_count(self) -> int:
        """Number of redirects followed before the final response."""
        return len(self.chain)


class PoliteClient:
    """Rate-limited, budgeted, same-site HTTP client built on ``httpx``."""

    def __init__(
        self,
        *,
        allowed_sites: Iterable[str],
        user_agent: str = USER_AGENT,
        rate: float = DEFAULT_RATE,
        timeout: float = DEFAULT_TIMEOUT,
        max_requests: int = 200,
        transport: httpx.BaseTransport | None = None,
        sleep: Callable[[float], None] = time.sleep,
        clock: Callable[[], float] = time.monotonic,
    ) -> None:
        """Create a client.

        Args:
            allowed_sites: URLs whose sites redirects may be followed to.
            user_agent: Sent with every request.
            rate: Maximum requests per second; ``0`` disables throttling.
            timeout: Per-request timeout in seconds.
            max_requests: Hard cap on requests for the lifetime of this client.
            transport: Optional custom ``httpx`` transport (used by tests).
            sleep: Injectable sleep function.
            clock: Injectable monotonic clock.
        """
        self._allowed = {host_key(u) for u in allowed_sites}
        self.rate = rate
        self.max_requests = max_requests
        self.requests_made = 0
        self._sleep = sleep
        self._clock = clock
        self._next_slot = 0.0
        self._client = httpx.Client(
            headers={"User-Agent": user_agent, "Accept": "*/*"},
            timeout=timeout,
            follow_redirects=False,
            transport=transport,
        )

    def __enter__(self) -> Self:
        return self

    def __exit__(
        self,
        exc_type: type[BaseException] | None,
        exc: BaseException | None,
        tb: TracebackType | None,
    ) -> None:
        self.close()

    def close(self) -> None:
        """Release the underlying connection pool."""
        self._client.close()

    def _throttle(self) -> None:
        if self.rate <= 0:
            return
        wait = self._next_slot - self._clock()
        if wait > 0:
            self._sleep(wait)
        self._next_slot = max(self._clock(), self._next_slot) + 1.0 / self.rate

    def _once(self, method: str, url: str, max_bytes: int) -> Fetched:
        if self.requests_made >= self.max_requests:
            raise RequestBudgetExceeded(f"Request cap of {self.max_requests} reached.")
        self._throttle()
        self.requests_made += 1
        start = self._clock()
        try:
            with self._client.stream(method, url) as response:
                body = bytearray()
                truncated = False
                if method != "HEAD":
                    for chunk in response.iter_bytes():
                        body += chunk
                        if len(body) > max_bytes:
                            del body[max_bytes:]
                            truncated = True
                            break
                return Fetched(
                    url=url,
                    final_url=url,
                    status=response.status_code,
                    headers=response.headers,
                    body=bytes(body),
                    elapsed=self._clock() - start,
                    body_truncated=truncated,
                )
        except httpx.HTTPError as exc:
            return Fetched(
                url=url,
                final_url=url,
                status=0,
                elapsed=self._clock() - start,
                error=f"{type(exc).__name__}: {exc}",
            )

    def fetch(
        self,
        url: str,
        *,
        method: str = "GET",
        follow: bool = True,
        max_bytes: int = DEFAULT_MAX_BYTES,
    ) -> Fetched:
        """Fetch ``url``, optionally following same-site redirects manually.

        Redirects to other sites are never followed; the unfollowed target is
        reported in ``blocked_redirect``. Redirect loops are detected and
        reported via ``loop``. Network errors are returned, not raised.

        Raises:
            RequestBudgetExceeded: if the per-run request cap is hit.
        """
        current = urldefrag(url)[0]
        seen = {current}
        chain: list[Hop] = []
        total = 0.0
        while True:
            result = self._once(method, current, max_bytes)
            total += result.elapsed
            result.url = url
            result.elapsed = total
            result.chain = chain
            if result.error or not follow or result.status not in REDIRECT_STATUSES:
                return result
            location = result.headers.get("location")
            if not location:
                return result
            target = urldefrag(urljoin(current, location))[0]
            if host_key(target) not in self._allowed:
                result.blocked_redirect = target
                return result
            chain.append(Hop(current, result.status))
            if target in seen:
                result.loop = True
                result.final_url = target
                return result
            if len(chain) > MAX_REDIRECTS:
                result.error = f"Stopped after {MAX_REDIRECTS} redirects"
                return result
            seen.add(target)
            current = target
