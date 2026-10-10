"""Shared fixtures: a fake in-memory website served through respx (no real network)."""

from __future__ import annotations

import socket
from collections.abc import Callable, Iterator
from typing import Any

import httpx
import pytest
import respx

from sitecheckup.audit.context import AuditContext
from sitecheckup.http import PoliteClient
from sitecheckup.tlsinfo import CertInfo


@pytest.fixture(autouse=True)
def _no_real_network(monkeypatch: pytest.MonkeyPatch) -> None:
    """Fail loudly if any test tries to open a real socket."""

    def blocked(*_: Any, **__: Any) -> None:
        raise RuntimeError("Network access is disabled in tests")

    monkeypatch.setattr(socket.socket, "connect", blocked)


class FakeSite:
    """A tiny routing table: exact URL -> response. Unknown URLs return 404."""

    def __init__(self) -> None:
        self.routes: dict[str, Callable[[], httpx.Response]] = {}
        self.calls: list[str] = []
        self.requests: list[httpx.Request] = []

    def add(
        self,
        url: str,
        status: int = 200,
        *,
        text: str = "",
        content: bytes | None = None,
        headers: list[tuple[str, str]] | dict[str, str] | None = None,
    ) -> None:
        """Register a response for an exact URL (query string included)."""
        hdrs = list(headers.items()) if isinstance(headers, dict) else list(headers or [])

        def build() -> httpx.Response:
            if content is not None:
                return httpx.Response(status, content=content, headers=hdrs)
            return httpx.Response(status, text=text, headers=hdrs)

        self.routes[url] = build

    def html(self, url: str, body: str, status: int = 200, **kw: Any) -> None:
        """Register an HTML response."""
        headers = [("content-type", "text/html; charset=utf-8"), *list(kw.pop("headers", []))]
        self.add(url, status, text=body, headers=headers, **kw)

    def redirect(self, url: str, to: str, status: int = 301) -> None:
        """Register a redirect."""
        self.add(url, status, headers={"location": to})

    def handler(self, request: httpx.Request) -> httpx.Response:
        """respx side effect."""
        key = str(request.url)
        self.calls.append(key)
        self.requests.append(request)
        build = (
            self.routes.get(key) or self.routes.get(key.rstrip("/")) or self.routes.get(key + "/")
        )
        return build() if build else httpx.Response(404, text="not found")


@pytest.fixture
def site() -> Iterator[FakeSite]:
    """A fake site wired into httpx for the duration of the test."""
    fake = FakeSite()
    with respx.mock(assert_all_called=False) as router:
        router.route().mock(side_effect=fake.handler)
        yield fake


@pytest.fixture
def make_client() -> Callable[..., PoliteClient]:
    """Factory for unthrottled clients."""

    def factory(*sites: str, **kw: Any) -> PoliteClient:
        kw.setdefault("rate", 0)
        return PoliteClient(allowed_sites=sites or ["https://example.com"], **kw)

    return factory


GOOD_CERT = CertInfo(verified=True, issuer="Example CA", subject="example.com", not_after=None)


@pytest.fixture
def make_ctx(
    site: FakeSite, make_client: Callable[..., PoliteClient]
) -> Callable[..., AuditContext]:
    """Factory: ``make_ctx("https://example.com", cert=CertInfo(...))``."""

    def factory(target: str = "https://example.com/", cert: CertInfo = GOOD_CERT) -> AuditContext:
        return AuditContext(target, make_client(target), lambda _h, _p: cert)

    return factory
