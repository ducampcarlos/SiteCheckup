from __future__ import annotations

from collections.abc import Callable
from pathlib import Path

import pytest

from sitecheckup.compare.engine import compare_sites, snapshot
from sitecheckup.compare.models import Level, Verdict
from sitecheckup.compare.pathmap import PathMapError, load_path_map
from sitecheckup.http import PoliteClient
from tests.conftest import FakeSite

OLD = "http://old.example.test"
NEW = "http://new.example.test"


def page(title: str, *, desc: str = "d", canonical: str = "", extra: str = "") -> str:
    link = f'<link rel="canonical" href="{canonical}">' if canonical else ""
    return (
        f'<html><head><title>{title}</title><meta name="description" content="{desc}">{link}{extra}'
        f"</head><body><h1>{title}</h1></body></html>"
    )


@pytest.fixture
def client(make_client: Callable[..., PoliteClient]) -> PoliteClient:
    return make_client(OLD, NEW, max_requests=100)


def test_snapshot_extracts_metadata(site: FakeSite, client: PoliteClient) -> None:
    site.html(
        f"{OLD}/p",
        page("Hello", canonical="/p", extra='<meta name="robots" content="noindex">'),
        headers=[("x-content-type-options", "nosniff")],
    )
    snap = snapshot(client.fetch(f"{OLD}/p"))
    assert (snap.title, snap.h1, snap.meta_description) == ("Hello", "Hello", "d")
    assert snap.canonical == f"{OLD}/p"  # resolved against the page URL
    assert snap.noindex
    assert snap.security_headers == ["x-content-type-options"]
    assert snap.is_html


def test_x_robots_tag_header_counts_as_noindex(site: FakeSite, client: PoliteClient) -> None:
    site.html(f"{OLD}/p", page("Hello"), headers=[("x-robots-tag", "noindex, nofollow")])
    assert snapshot(client.fetch(f"{OLD}/p")).noindex


def test_end_to_end_comparison(site: FakeSite, client: PoliteClient) -> None:
    site.html(f"{OLD}/", page("Home", canonical=f"{OLD}/"))
    site.html(f"{NEW}/", page("Home", canonical=f"{NEW}/"))
    site.html(f"{OLD}/gone", page("Gone"))  # new returns 404
    site.html(f"{OLD}/about", page("About us"))
    site.html(f"{NEW}/about", page("Our story"))
    site.html(f"{OLD}/mapped", page("Mapped"))
    site.html(f"{NEW}/new-home/mapped", page("Mapped"))
    seen = []
    report = compare_sites(
        OLD,
        NEW,
        ["/", "/gone", "/about", "/mapped"],
        client,
        path_map={"/mapped": "/new-home/mapped"},
        source="test",
        on_result=seen.append,
    )
    verdicts = {r.path: r.verdict for r in report.results}
    assert verdicts == {
        "/": Verdict.OK,
        "/gone": Verdict.BLOCKING,
        "/about": Verdict.WARNING,
        "/mapped": Verdict.OK,
    }
    assert report.counts() == {"blocking": 1, "warning": 1, "ok": 2}
    assert report.issue_totals() == {"missing_on_new": 1, "title_changed": 1}
    assert len(seen) == 4
    assert report.requests_made == 8
    assert report.results[3].new_path == "/new-home/mapped"
    assert not report.truncated


def test_redirect_chain_detection_end_to_end(site: FakeSite, client: PoliteClient) -> None:
    site.html(f"{OLD}/specials", page("Specials"))
    site.redirect(f"{NEW}/specials", "/offers")
    site.redirect(f"{NEW}/offers", "/offers/")
    site.redirect(f"{NEW}/offers/", "/deals")
    site.html(f"{NEW}/deals", page("Specials"))
    result = compare_sites(OLD, NEW, ["/specials"], client).results[0]
    assert result.verdict is Verdict.WARNING
    assert "redirect_chain_long" in {i.code for i in result.issues}
    assert result.new.final_url == f"{NEW}/deals"


def test_redirect_loop_end_to_end(site: FakeSite, client: PoliteClient) -> None:
    site.html(f"{OLD}/a", page("A"))
    site.redirect(f"{NEW}/a", "/b")
    site.redirect(f"{NEW}/b", "/a")
    result = compare_sites(OLD, NEW, ["/a"], client).results[0]
    assert result.verdict is Verdict.BLOCKING
    assert any(i.code == "redirect_loop" and i.level is Level.BLOCKING for i in result.issues)


def test_request_cap_stops_the_run(
    site: FakeSite, make_client: Callable[..., PoliteClient]
) -> None:
    for path in ("/a", "/b", "/c"):
        site.html(OLD + path, page("X"))
        site.html(NEW + path, page("X"))
    report = compare_sites(OLD, NEW, ["/a", "/b", "/c"], make_client(OLD, NEW, max_requests=3))
    assert report.truncated
    assert len(report.results) == 1


def test_path_map_to_absolute_url(site: FakeSite, client: PoliteClient) -> None:
    site.html(f"{OLD}/p", page("P"))
    site.html("http://new.example.test/else/p", page("P"))
    report = compare_sites(
        OLD, NEW, ["/p"], client, path_map={"/p": "http://new.example.test/else/p"}
    )
    assert report.results[0].verdict is Verdict.OK


class TestPathMap:
    def test_loads_csv_with_header_comments_and_missing_slashes(self, tmp_path: Path) -> None:
        f = tmp_path / "map.csv"
        f.write_text(
            "old_path,new_path\n# comment\n\n/old,/new\nfoo,bar\n/x?y=1,https://new.example.test/z\n"
        )
        assert load_path_map(f) == {
            "/old": "/new",
            "/foo": "/bar",
            "/x?y=1": "https://new.example.test/z",
        }

    def test_headerless_file(self, tmp_path: Path) -> None:
        f = tmp_path / "map.csv"
        f.write_text("/a,/b\n")
        assert load_path_map(f) == {"/a": "/b"}

    def test_malformed_row(self, tmp_path: Path) -> None:
        f = tmp_path / "map.csv"
        f.write_text("/only-one-column\n")
        with pytest.raises(PathMapError, match=r"map\.csv:1"):
            load_path_map(f)
