from __future__ import annotations

import csv
import io
import json
import re

from rich.console import Console

from sitecheckup.audit.models import AuditReport, Finding, Status
from sitecheckup.audit.scoring import compute_score
from sitecheckup.compare.models import CompareReport, Hop, Issue, Level, Snapshot, UrlResult
from sitecheckup.models import Severity
from sitecheckup.reporting.render import (
    CSV_COLUMNS,
    Format,
    compare_csv,
    render_audit,
    render_compare,
)
from sitecheckup.reporting.terminal import render_audit_terminal, render_compare_terminal

EVIL = '<script>alert("x")</script>'


def make_audit(truncated: bool = False) -> AuditReport:
    findings = [
        Finding(
            id="a-high",
            title="High one",
            category="c",
            severity=Severity.HIGH,
            status=Status.FAIL,
            description="desc",
            evidence=f"saw {EVIL} | pipe",
            remediation="fix it",
            references=["https://example.org/ref"],
        ),
        Finding(
            id="b-pass",
            title="Good",
            category="c",
            severity=Severity.LOW,
            status=Status.PASS,
            description="d",
            evidence="fine",
            remediation="r",
        ),
        Finding(
            id="c-skip",
            title="N/A",
            category="c",
            severity=Severity.LOW,
            status=Status.SKIPPED,
            description="d",
            evidence="not applicable",
            remediation="r",
        ),
        Finding(
            id="d-err",
            title="Broke",
            category="c",
            severity=Severity.LOW,
            status=Status.ERROR,
            description="d",
            evidence="ValueError: x",
            remediation="r",
        ),
    ]
    score, grade = compute_score(findings)
    return AuditReport(
        target="https://example.com",
        findings=findings,
        score=score,
        grade=grade,
        requests_made=12,
        truncated=truncated,
        wordpress_detected=True,
    )


def snap(base: str, path: str, **kw: object) -> Snapshot:
    data: dict[str, object] = {
        "url": base + path,
        "final_url": base + path,
        "status": 200,
        "title": "T",
        "is_html": True,
    }
    data.update(kw)
    return Snapshot(**data)  # type: ignore[arg-type]


def make_compare(truncated: bool = False) -> CompareReport:
    old, new = "http://old.example.test", "http://new.example.test"
    results = [
        UrlResult(path="/ok", new_path="/ok", old=snap(old, "/ok"), new=snap(new, "/ok")),
        UrlResult(
            path="/gone",
            new_path="/gone",
            old=snap(old, "/gone"),
            new=snap(new, "/gone", status=404),
            issues=[Issue(code="missing_on_new", level=Level.BLOCKING, message="404 | on new")],
        ),
        UrlResult(
            path="/mapped",
            new_path="/moved",
            old=snap(old, "/mapped"),
            new=snap(new, "/moved", chain=[Hop(url=new + "/moved", status=301)]),
            issues=[
                Issue(code="title_changed", level=Level.WARNING, message="Title changed"),
                Issue(code="h1_changed", level=Level.INFO, message="info only"),
            ],
        ),
        UrlResult(
            path="=cmd",
            new_path="/x",
            old=snap(old, "=cmd", title="=HYPERLINK(1)"),
            new=snap(new, "/x"),
        ),
    ]
    return CompareReport(
        old_base=old,
        new_base=new,
        source="sitemap",
        results=results,
        requests_made=8,
        truncated=truncated,
        site_issues=[
            Issue(
                code="security_header_lost_sitewide",
                level=Level.WARNING,
                message="x-frame-options lost",
            )
        ],
    )


def test_audit_json_round_trips() -> None:
    data = json.loads(render_audit(make_audit(), Format.JSON))
    assert data["grade"] in "ABCDF"
    assert AuditReport.model_validate(data).target == "https://example.com"


def test_audit_html_is_self_contained_and_escaped() -> None:
    html = render_audit(make_audit(truncated=True), Format.HTML)
    assert html.startswith("<!doctype html>")
    assert EVIL not in html
    assert "&lt;script&gt;" in html
    assert not re.search(r"<script|<link |src=|@import|url\(", html)
    for fragment in (
        "High one",
        "a-high",
        "fix it",
        "https://example.org/ref",
        "Passed (1)",
        "Not applicable (1)",
        "request cap",
        "Checks that errored",
    ):
        assert fragment in html


def test_audit_markdown() -> None:
    md = render_audit(make_audit(truncated=True), Format.MD)
    assert md.startswith("# SiteCheckup audit: https://example.com")
    assert "### [HIGH] High one (`a-high`)" in md
    assert "- <https://example.org/ref>" in md
    assert "pipe" in md
    assert "## Not applicable" in md
    assert "request cap" in md
    assert "Checks that errored" in md


def test_empty_audit_renders() -> None:
    report = AuditReport(target="https://example.com")
    assert "No findings" in render_audit(report, Format.HTML)
    assert "No findings" in render_audit(report, Format.MD)


def test_compare_html_and_markdown_sections() -> None:
    report = make_compare(truncated=True)
    html = render_compare(report, Format.HTML)
    md = render_compare(report, Format.MD)
    for text in (html, md):
        assert "missing_on_new" in text
        assert "title_changed" in text
        assert "security_header_lost_sitewide" in text
        assert "request cap" in text
    assert "Blocking (1)" in html
    assert "## Warnings (1)" in md
    assert "## OK (2)" in md
    assert "404 \\| on new" in md  # pipes escaped inside table-like text
    assert "`/mapped` → `/moved`" in md


def test_compare_json() -> None:
    data = json.loads(render_compare(make_compare(), Format.JSON))
    assert data["results"][1]["issues"][0]["code"] == "missing_on_new"


def test_compare_csv_has_every_url_and_neutralizes_formulas() -> None:
    rows = list(csv.reader(io.StringIO(compare_csv(make_compare()))))
    assert tuple(rows[0]) == CSV_COLUMNS
    assert len(rows) == 5
    by_path = {r[0].lstrip("'"): r for r in rows[1:]}
    assert by_path["/gone"][2] == "blocking"
    assert by_path["/mapped"][8] == "1"  # new redirects
    assert by_path["/mapped"][-1] == "title_changed;h1_changed"
    formula_row = next(r for r in rows[1:] if r[0].startswith("'"))
    assert formula_row[0] == "'=cmd"
    assert formula_row[9] == "'=HYPERLINK(1)"


def render_to_text(fn, *args, **kw) -> str:  # type: ignore[no-untyped-def]
    console = Console(record=True, width=110, file=io.StringIO(), force_terminal=False)
    fn(*args, console, **kw)
    return console.export_text()


def test_terminal_audit_summary() -> None:
    text = render_to_text(render_audit_terminal, make_audit(truncated=True), verbose=True)
    assert "grade" in text
    assert "a-high" in text
    assert "Fix: fix it" in text
    assert "request cap" in text
    assert "1 passed, 1 failed, 1 not applicable, 1 errored" in text


def test_terminal_audit_without_findings() -> None:
    text = render_to_text(render_audit_terminal, AuditReport(target="https://example.com"))
    assert "No findings." in text


def test_terminal_compare_summary_and_limit() -> None:
    report = make_compare(truncated=True)
    text = render_to_text(render_compare_terminal, report, limit=1)
    assert "1 blocking" in text
    assert "Site-wide" in text
    assert "missing_on_new" in text
    assert "and 1 more" in text
    clean = CompareReport(old_base="a", new_base="b", results=[make_compare().results[0]])
    assert "No differences" in render_to_text(render_compare_terminal, clean)
