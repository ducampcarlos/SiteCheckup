from __future__ import annotations

from collections.abc import Callable

import httpx
import pytest
import respx

from sitecheckup.http import (
    USER_AGENT,
    PoliteClient,
    RequestBudgetExceeded,
    host_key,
)
from tests.conftest import FakeSite


def test_host_key_ignores_www_scheme_and_default_ports() -> None:
    assert host_key("http://www.Example.com/") == host_key("https://example.com:443/x")
    assert host_key("http://localhost:8080") != host_key("http://localhost:8081")


def test_sends_identifiable_user_agent(
    site: FakeSite, make_client: Callable[..., PoliteClient]
) -> None:
    make_client().fetch("https://example.com/")
    assert site.requests[0].headers["user-agent"] == USER_AGENT
    assert "SiteCheckup/" in USER_AGENT


def test_follows_same_site_redirects_and_records_chain(
    site: FakeSite, make_client: Callable[..., PoliteClient]
) -> None:
    site.redirect("https://example.com/a", "/b")
    site.redirect("https://example.com/b", "https://www.example.com/c", 302)
    site.add("https://www.example.com/c", text="done")
    result = make_client().fetch("https://example.com/a")
    assert result.status == 200
    assert result.final_url == "https://www.example.com/c"
    assert [(h.url, h.status) for h in result.chain] == [
        ("https://example.com/a", 301),
        ("https://example.com/b", 302),
    ]
    assert result.redirect_count == 2


def test_does_not_follow_when_disabled(
    site: FakeSite, make_client: Callable[..., PoliteClient]
) -> None:
    site.redirect("https://example.com/a", "/b")
    result = make_client().fetch("https://example.com/a", follow=False)
    assert result.status == 301
    assert result.chain == []


def test_refuses_to_follow_redirect_to_other_site(
    site: FakeSite, make_client: Callable[..., PoliteClient]
) -> None:
    site.redirect("https://example.com/out", "https://elsewhere.example.org/")
    result = make_client().fetch("https://example.com/out")
    assert result.status == 301
    assert result.blocked_redirect == "https://elsewhere.example.org/"
    assert site.calls == ["https://example.com/out"]


def test_detects_redirect_loop(site: FakeSite, make_client: Callable[..., PoliteClient]) -> None:
    site.redirect("https://example.com/a", "/b")
    site.redirect("https://example.com/b", "/a")
    result = make_client().fetch("https://example.com/a")
    assert result.loop
    assert result.redirect_count == 2


def test_stops_after_too_many_redirects(
    site: FakeSite, make_client: Callable[..., PoliteClient]
) -> None:
    for i in range(30):
        site.redirect(f"https://example.com/{i}", f"/{i + 1}")
    result = make_client().fetch("https://example.com/0")
    assert result.error and "redirects" in result.error
    assert not result.ok


def test_redirect_without_location_is_returned_as_is(
    site: FakeSite, make_client: Callable[..., PoliteClient]
) -> None:
    site.add("https://example.com/x", 301)
    assert make_client().fetch("https://example.com/x").status == 301


def test_network_errors_are_returned_not_raised(make_client: Callable[..., PoliteClient]) -> None:
    with respx.mock() as router:
        router.route().mock(side_effect=httpx.ConnectError("boom"))
        result = make_client().fetch("https://example.com/")
    assert not result.ok
    assert result.error and "ConnectError" in result.error


def test_body_is_capped(site: FakeSite, make_client: Callable[..., PoliteClient]) -> None:
    site.add("https://example.com/big", content=b"x" * 5000)
    result = make_client().fetch("https://example.com/big", max_bytes=1000)
    assert len(result.body) == 1000
    assert result.body_truncated


def test_head_requests_have_no_body(
    site: FakeSite, make_client: Callable[..., PoliteClient]
) -> None:
    site.add("https://example.com/", text="hello")
    assert make_client().fetch("https://example.com/", method="HEAD").body == b""


def test_request_budget_is_enforced(
    site: FakeSite, make_client: Callable[..., PoliteClient]
) -> None:
    client = make_client(max_requests=2)
    client.fetch("https://example.com/1")
    client.fetch("https://example.com/2")
    with pytest.raises(RequestBudgetExceeded):
        client.fetch("https://example.com/3")
    assert client.requests_made == 2


def test_rate_limit_spaces_requests(site: FakeSite) -> None:
    now = [0.0]
    sleeps: list[float] = []

    def sleep(seconds: float) -> None:
        sleeps.append(seconds)
        now[0] += seconds

    client = PoliteClient(
        allowed_sites=["https://example.com"], rate=2.0, sleep=sleep, clock=lambda: now[0]
    )
    for i in range(3):
        client.fetch(f"https://example.com/{i}")
    assert sleeps == [pytest.approx(0.5), pytest.approx(0.5)]


def test_context_manager_closes_client(site: FakeSite) -> None:
    with PoliteClient(allowed_sites=["https://example.com"], rate=0) as client:
        client.fetch("https://example.com/")


def test_text_and_content_type(site: FakeSite, make_client: Callable[..., PoliteClient]) -> None:
    site.add(
        "https://example.com/", text="héllo", headers={"content-type": "Text/HTML; charset=utf-8"}
    )
    result = make_client().fetch("https://example.com/")
    assert result.text == "héllo"
    assert result.content_type == "text/html"
