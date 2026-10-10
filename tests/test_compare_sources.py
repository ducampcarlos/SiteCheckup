from __future__ import annotations

from collections.abc import Callable
from pathlib import Path

from sitecheckup.compare.sources import crawl, load_robots, read_urls_file, sitemap_urls, to_path
from sitecheckup.http import PoliteClient
from tests.conftest import FakeSite

OLD = "http://old.example.test"


def test_to_path() -> None:
    assert to_path("https://example.com") == "/"
    assert to_path("https://example.com/a/b?x=1#frag") == "/a/b?x=1"
    assert to_path("/relative#x") == "/relative"


def test_urls_file(tmp_path: Path) -> None:
    f = tmp_path / "urls.txt"
    f.write_text("# my list\n/\nhttps://old.example.test/about\n\n/about\n/contact\n")
    assert read_urls_file(f, limit=10) == ["/", "/about", "/contact"]
    assert read_urls_file(f, limit=2) == ["/", "/about"]


def test_sitemap_with_cdata_and_foreign_host(
    site: FakeSite, make_client: Callable[..., PoliteClient]
) -> None:
    site.add(
        f"{OLD}/sitemap.xml",
        text=(
            '<?xml version="1.0"?><urlset>'
            "<url><loc>https://www.example.test/</loc></url>"
            "<url><loc><![CDATA[https://www.example.test/about]]></loc></url>"
            "<url><loc>\n  https://www.example.test/blog/post-1  \n</loc></url>"
            "</urlset>"
        ),
    )
    assert sitemap_urls(make_client(OLD), OLD, 100) == ["/", "/about", "/blog/post-1"]
    assert site.calls == [f"{OLD}/sitemap.xml"]  # never requests the host named in the sitemap


def test_sitemap_index_is_followed_with_a_cap(
    site: FakeSite, make_client: Callable[..., PoliteClient]
) -> None:
    children = "".join(f"<sitemap><loc>https://x.test/s{i}.xml</loc></sitemap>" for i in range(15))
    site.add(f"{OLD}/sitemap.xml", text=f"<sitemapindex>{children}</sitemapindex>")
    for i in range(15):
        site.add(
            f"{OLD}/s{i}.xml", text=f"<urlset><url><loc>https://x.test/p{i}</loc></url></urlset>"
        )
    paths = sitemap_urls(make_client(OLD), OLD, 100)
    assert paths == [f"/p{i}" for i in range(10)]


def test_missing_sitemap_returns_nothing(
    site: FakeSite, make_client: Callable[..., PoliteClient]
) -> None:
    assert sitemap_urls(make_client(OLD), OLD, 100) == []


def test_sitemap_limit(site: FakeSite, make_client: Callable[..., PoliteClient]) -> None:
    locs = "".join(f"<url><loc>/p{i}</loc></url>" for i in range(10))
    site.add(f"{OLD}/sitemap.xml", text=f"<urlset>{locs}</urlset>")
    assert len(sitemap_urls(make_client(OLD), OLD, 3)) == 3


def test_robots_parsing_rules(site: FakeSite, make_client: Callable[..., PoliteClient]) -> None:
    site.add(f"{OLD}/robots.txt", text="User-agent: *\nDisallow: /private/\n")
    robots = load_robots(make_client(OLD), OLD)
    assert robots.can_fetch("SiteCheckup", f"{OLD}/public")
    assert not robots.can_fetch("SiteCheckup", f"{OLD}/private/x")


def test_robots_403_disallows_everything_and_404_allows(
    site: FakeSite, make_client: Callable[..., PoliteClient]
) -> None:
    site.add(f"{OLD}/robots.txt", 403)
    assert not load_robots(make_client(OLD), OLD).can_fetch("SiteCheckup", f"{OLD}/")
    site.routes.clear()
    assert load_robots(make_client(OLD), OLD).can_fetch("SiteCheckup", f"{OLD}/")


def test_crawl_is_same_host_robots_aware_and_capped(
    site: FakeSite, make_client: Callable[..., PoliteClient]
) -> None:
    site.add(f"{OLD}/robots.txt", text="User-agent: *\nDisallow: /secret\n")
    site.html(
        f"{OLD}/",
        '<a href="/a">a</a><a href="/secret">s</a><a href="https://elsewhere.example.org/x">e</a>'
        '<a href="/file.pdf">pdf</a><a href="mailto:x@example.test">m</a><a href="/b#frag">b</a>',
    )
    site.html(f"{OLD}/a", '<a href="/">home</a><a href="/c">c</a>')
    site.html(f"{OLD}/b", "b")
    site.html(f"{OLD}/c", "c")
    client = make_client(OLD)
    assert crawl(client, OLD, max_pages=100) == ["/", "/a", "/b", "/c"]
    assert not any("elsewhere" in c or "secret" in c or ".pdf" in c for c in site.calls)
    assert crawl(make_client(OLD), OLD, max_pages=2) == ["/", "/a"]


def test_crawl_skips_non_html_and_errors(
    site: FakeSite, make_client: Callable[..., PoliteClient]
) -> None:
    site.html(f"{OLD}/", '<a href="/data">d</a><a href="/missing">m</a>')
    site.add(f"{OLD}/data", text="{}", headers={"content-type": "application/json"})
    assert crawl(make_client(OLD), OLD, 10) == ["/"]


def test_crawl_stops_when_request_cap_is_hit(
    site: FakeSite, make_client: Callable[..., PoliteClient]
) -> None:
    site.html(f"{OLD}/", '<a href="/a">a</a><a href="/b">b</a>')
    site.html(f"{OLD}/a", "a")
    assert crawl(make_client(OLD, max_requests=3), OLD, 10) == ["/", "/a"]
