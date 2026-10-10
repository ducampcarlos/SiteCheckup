"""File-format renderers (HTML, Markdown, JSON, CSV) for audit and compare reports."""

from __future__ import annotations

import csv
import io
from enum import StrEnum

from jinja2 import Environment, PackageLoader

from sitecheckup.audit.models import AuditReport
from sitecheckup.compare.models import CompareReport, UrlResult, Verdict


class Format(StrEnum):
    """Output formats selectable with ``--format``."""

    HTML = "html"
    JSON = "json"
    MD = "md"


def _md_cell(value: object) -> str:
    text = " ".join(str(value).split())
    return text.replace("|", "\\|")


def _env(*, html: bool) -> Environment:
    # Markdown output is plain text, so HTML escaping would only corrupt it; the HTML
    # templates (the only ones rendered in a browser) always run with autoescape on.
    env = Environment(
        loader=PackageLoader("sitecheckup", "templates"),
        autoescape=html,  # noqa: S701
        trim_blocks=True,
        lstrip_blocks=True,
        keep_trailing_newline=True,
    )
    env.filters["md_cell"] = _md_cell
    return env


def render_audit(report: AuditReport, fmt: Format) -> str:
    """Render an audit report as HTML, Markdown or JSON (self-contained, no external assets)."""
    if fmt is Format.JSON:
        return report.model_dump_json(indent=2) + "\n"
    template = "audit.html.j2" if fmt is Format.HTML else "audit.md.j2"
    return _env(html=fmt is Format.HTML).get_template(template).render(report=report)


def render_compare(report: CompareReport, fmt: Format) -> str:
    """Render a compare report as HTML, Markdown or JSON."""
    if fmt is Format.JSON:
        return report.model_dump_json(indent=2) + "\n"
    template = "compare.html.j2" if fmt is Format.HTML else "compare.md.j2"
    return (
        _env(html=fmt is Format.HTML).get_template(template).render(report=report, Verdict=Verdict)
    )


CSV_COLUMNS = (
    "path",
    "new_path",
    "verdict",
    "old_status",
    "new_status",
    "old_final_url",
    "new_final_url",
    "old_redirects",
    "new_redirects",
    "old_title",
    "new_title",
    "old_canonical",
    "new_canonical",
    "old_ms",
    "new_ms",
    "issues",
)


def _safe(value: object) -> str:
    """Neutralize spreadsheet formula injection from remote, untrusted text."""
    text = "" if value is None else str(value)
    return f"'{text}" if text[:1] in {"=", "+", "-", "@", "\t", "\r"} else text


def _row(result: UrlResult) -> list[str]:
    return [
        _safe(v)
        for v in (
            result.path,
            result.new_path,
            result.verdict.value,
            result.old.status,
            result.new.status,
            result.old.final_url,
            result.new.final_url,
            len(result.old.chain),
            len(result.new.chain),
            result.old.title,
            result.new.title,
            result.old.canonical,
            result.new.canonical,
            result.old.elapsed_ms,
            result.new.elapsed_ms,
            ";".join(i.code for i in result.issues),
        )
    ]


def compare_csv(report: CompareReport) -> str:
    """Export one row per URL, including URLs with no differences."""
    buffer = io.StringIO()
    writer = csv.writer(buffer, lineterminator="\n")
    writer.writerow(CSV_COLUMNS)
    for result in report.results:
        writer.writerow(_row(result))
    return buffer.getvalue()
