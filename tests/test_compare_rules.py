from __future__ import annotations

from sitecheckup.compare.models import Hop, Issue, Level, Snapshot
from sitecheckup.compare.rules import CompareSettings, evaluate

OLD = "http://old.example.test"
NEW = "http://new.example.test"


def snap(base: str, path: str = "/page", **kw: object) -> Snapshot:
    defaults: dict[str, object] = {
        "url": base + path,
        "final_url": base + path,
        "status": 200,
        "title": "Page | Shop",
        "meta_description": "A page",
        "h1": "Page",
        "canonical": base + path,
        "is_html": True,
        "elapsed_ms": 100,
        "security_headers": ["x-content-type-options"],
    }
    defaults.update(kw)
    return Snapshot(**defaults)  # type: ignore[arg-type]


def codes(issues: list[Issue]) -> set[str]:
    return {i.code for i in issues}


def run(old: Snapshot, new: Snapshot, **kw: object) -> list[Issue]:
    return evaluate(old, new, old_base=OLD, new_base=NEW, **kw)  # type: ignore[arg-type]


def test_identical_pages_have_no_issues() -> None:
    assert run(snap(OLD), snap(NEW)) == []


def test_missing_page_is_blocking() -> None:
    issues = run(snap(OLD), snap(NEW, status=404, is_html=True))
    assert [(i.code, i.level) for i in issues] == [("missing_on_new", Level.BLOCKING)]


def test_other_4xx_and_5xx() -> None:
    assert codes(run(snap(OLD), snap(NEW, status=403))) == {"client_error"}
    assert codes(run(snap(OLD), snap(NEW, status=502))) == {"server_error"}


def test_unreachable_new_site() -> None:
    issues = run(snap(OLD), snap(NEW, status=0, error="ConnectError: refused"))
    assert codes(issues) == {"new_unreachable"}


def test_page_that_was_already_broken_is_not_a_regression() -> None:
    assert run(snap(OLD, status=404), snap(NEW, status=404)) == []
    assert codes(run(snap(OLD, status=404), snap(NEW, status=410))) == {"status_differs"}
    assert codes(run(snap(OLD, status=404), snap(NEW))) == {"fixed_on_new"}


def test_long_redirect_chain_is_flagged() -> None:
    chain = [Hop(url=f"{NEW}/{i}", status=301) for i in range(3)]
    new = snap(NEW, chain=chain, final_url=f"{NEW}/final")
    found = codes(run(snap(OLD), new))
    assert "redirect_chain_long" in found
    assert "unexpected_redirect" in found


def test_chain_within_limit_is_ok_when_old_also_redirects() -> None:
    old = snap(OLD, chain=[Hop(url=OLD + "/page", status=301)], final_url=OLD + "/target")
    new = snap(NEW, chain=[Hop(url=NEW + "/page", status=301)], final_url=NEW + "/target")
    assert run(old, new, expected_final=NEW + "/target") == []


def test_chain_limit_is_configurable() -> None:
    chain = [Hop(url=f"{NEW}/{i}", status=301) for i in range(2)]
    new = snap(NEW, chain=chain, final_url=f"{NEW}/f")
    old = snap(OLD, chain=[Hop(url=OLD + "/page", status=301)], final_url=f"{OLD}/f")
    assert "redirect_chain_long" not in codes(run(old, new, expected_final=f"{NEW}/f"))
    strict = CompareSettings(max_redirect_chain=1)
    assert "redirect_chain_long" in codes(run(old, new, expected_final=f"{NEW}/f", settings=strict))


def test_redirect_loop_is_blocking() -> None:
    new = snap(NEW, status=301, loop=True, chain=[Hop(url=NEW + "/a", status=301)])
    assert [(i.code, i.level) for i in run(snap(OLD), new)] == [("redirect_loop", Level.BLOCKING)]


def test_temporary_redirect_is_flagged() -> None:
    new = snap(NEW, chain=[Hop(url=NEW + "/page", status=302)], final_url=NEW + "/elsewhere")
    assert {"temporary_redirect", "unexpected_redirect"} <= codes(run(snap(OLD), new))


def test_redirect_to_different_target_is_flagged() -> None:
    old = snap(OLD, chain=[Hop(url=OLD + "/page", status=301)], final_url=OLD + "/a")
    new = snap(NEW, chain=[Hop(url=NEW + "/page", status=301)], final_url=NEW + "/b")
    assert "redirect_target_changed" in codes(run(old, new, expected_final=NEW + "/a"))


def test_trailing_slash_difference_is_not_a_target_change() -> None:
    old = snap(OLD, chain=[Hop(url=OLD + "/page", status=301)], final_url=OLD + "/a")
    new = snap(NEW, chain=[Hop(url=NEW + "/page", status=301)], final_url=NEW + "/a/")
    assert run(old, new, expected_final=NEW + "/a") == []


def test_redirect_removed_is_informational() -> None:
    old = snap(OLD, chain=[Hop(url=OLD + "/page", status=301)], final_url=OLD + "/a")
    issues = run(old, snap(NEW))
    assert [(i.code, i.level) for i in issues] == [("redirect_removed", Level.INFO)]


def test_redirect_back_to_old_host_is_blocking() -> None:
    new = snap(NEW, status=301, blocked_redirect=OLD + "/page")
    assert "redirects_to_old_site" in codes(run(snap(OLD), new))


def test_redirect_to_unrelated_host_is_warning() -> None:
    new = snap(NEW, status=301, blocked_redirect="https://cdn.example.org/page")
    issues = run(snap(OLD), new)
    assert ("external_redirect", Level.WARNING) in [(i.code, i.level) for i in issues]


def test_metadata_changes() -> None:
    new = snap(NEW, title="Different", meta_description=None, h1=None)
    found = codes(run(snap(OLD), new))
    assert {"title_changed", "meta_description_lost", "h1_lost"} <= found


def test_title_lost_and_whitespace_only_changes() -> None:
    assert "title_missing" in codes(run(snap(OLD), snap(NEW, title=None)))
    assert run(snap(OLD, title="A  B"), snap(NEW, title=" A B ")) == []


def test_text_changes_without_loss_are_informational() -> None:
    issues = run(snap(OLD), snap(NEW, meta_description="Another", h1="Other"))
    assert {i.level for i in issues} == {Level.INFO}


def test_canonical_pointing_at_old_host_is_blocking() -> None:
    new = snap(NEW, canonical=OLD + "/page")
    issues = run(snap(OLD), new)
    assert [(i.code, i.level) for i in issues] == [("canonical_points_to_old_host", Level.BLOCKING)]


def test_canonical_other_host_and_missing() -> None:
    assert "canonical_host_changed" in codes(
        run(snap(OLD), snap(NEW, canonical="https://other.example.org/p"))
    )
    assert "canonical_missing" in codes(run(snap(OLD), snap(NEW, canonical=None)))
    assert run(snap(OLD, canonical=None), snap(NEW, canonical=None)) == []


def test_noindex_added_is_blocking_and_removed_is_info() -> None:
    added = run(snap(OLD), snap(NEW, noindex=True))
    assert [(i.code, i.level) for i in added] == [("noindex_added", Level.BLOCKING)]
    removed = run(snap(OLD, noindex=True), snap(NEW))
    assert [(i.code, i.level) for i in removed] == [("noindex_removed", Level.INFO)]


def test_lost_security_headers() -> None:
    issues = run(snap(OLD), snap(NEW, security_headers=[]))
    assert [(i.code, i.level) for i in issues] == [("security_header_lost", Level.INFO)]
    assert "x-content-type-options" in issues[0].message


def test_slowdown_needs_both_ratio_and_absolute_delta() -> None:
    assert "slower" in codes(run(snap(OLD, elapsed_ms=200), snap(NEW, elapsed_ms=1200)))
    assert run(snap(OLD, elapsed_ms=10), snap(NEW, elapsed_ms=400)) == []  # tiny absolute change
    assert run(snap(OLD, elapsed_ms=5000), snap(NEW, elapsed_ms=5600)) == []  # under the ratio


def test_non_html_pages_skip_metadata_rules() -> None:
    old = snap(OLD, is_html=False, title=None)
    new = snap(NEW, is_html=False, title=None, noindex=True)
    assert run(old, new) == []
