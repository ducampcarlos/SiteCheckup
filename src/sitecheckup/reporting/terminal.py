"""Rich terminal summaries."""

from __future__ import annotations

from rich import box
from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.text import Text

from sitecheckup.audit.models import AuditReport, Status
from sitecheckup.compare.models import CompareReport, Level, Verdict

SEVERITY_STYLE = {"high": "bold red", "medium": "bold yellow", "low": "cyan", "info": "dim"}
GRADE_STYLE = {"A": "bold green", "B": "green", "C": "yellow", "D": "bold yellow", "F": "bold red"}
VERDICT_STYLE = {Verdict.BLOCKING: "bold red", Verdict.WARNING: "yellow", Verdict.OK: "green"}


def _shorten(text: str, width: int) -> str:
    return text if len(text) <= width else text[: width - 1] + "…"


def render_audit_terminal(report: AuditReport, console: Console, *, verbose: bool = False) -> None:
    """Print the score panel and a table of failed findings."""
    counts = report.counts()
    grade_style = GRADE_STYLE[report.grade]
    header = Text.assemble(
        ("Target  ", "dim"),
        (report.target, "bold"),
        "\n",
        ("Score   ", "dim"),
        (f"{report.score}/100  ", "bold"),
        (f"grade {report.grade}", grade_style),
        "\n",
        ("Issues  ", "dim"),
        "  ".join(f"{n} {sev}" for sev, n in counts.items()),
        "\n",
        ("Run     ", "dim"),
        f"{report.requests_made} requests"
        + (", WordPress detected" if report.wordpress_detected else "")
        + (", stopped at request cap" if report.truncated else ""),
    )
    console.print(Panel(header, title="SiteCheckup audit", border_style=grade_style, expand=False))

    failures = report.failures
    if failures:
        table = Table(box=box.SIMPLE_HEAD, expand=False, show_lines=False, pad_edge=False)
        table.add_column("Severity")
        table.add_column("Check", no_wrap=True)
        table.add_column("What we saw", overflow="fold", max_width=62)
        for finding in failures:
            style = SEVERITY_STYLE[finding.severity.value]
            detail = Text(_shorten(finding.evidence or finding.title, 140))
            if verbose:
                detail.append(f"\nFix: {finding.remediation}", style="dim")
            table.add_row(Text(finding.severity.value.upper(), style=style), finding.id, detail)
        console.print(table)
    else:
        console.print("[green]No findings.[/green]")

    passed = sum(1 for f in report.findings if f.status is Status.PASS)
    skipped = sum(1 for f in report.findings if f.status is Status.SKIPPED)
    errors = sum(1 for f in report.findings if f.status is Status.ERROR)
    console.print(
        f"[dim]{passed} passed, {len(failures)} failed, {skipped} not applicable"
        + (f", {errors} errored" if errors else "")
        + ". Passive automated checks only; not a substitute for a penetration test.[/dim]"
    )


def render_compare_terminal(report: CompareReport, console: Console, *, limit: int = 40) -> None:
    """Print the Blocking / Warnings / OK summary and the problem URLs."""
    counts = report.counts()
    summary = Text.assemble(
        ("Old  ", "dim"),
        (report.old_base, "bold"),
        "\n",
        ("New  ", "dim"),
        (report.new_base, "bold"),
        "\n",
        ("URLs ", "dim"),
        f"{len(report.results)} compared (source: {report.source}, {report.requests_made} requests"
        + (", stopped at request cap" if report.truncated else "")
        + ")\n",
        (f"{counts['blocking']} blocking", VERDICT_STYLE[Verdict.BLOCKING]),
        "   ",
        (f"{counts['warning']} warnings", VERDICT_STYLE[Verdict.WARNING]),
        "   ",
        (f"{counts['ok']} ok", VERDICT_STYLE[Verdict.OK]),
    )
    border = "red" if counts["blocking"] else "yellow" if counts["warning"] else "green"
    console.print(Panel(summary, title="SiteCheckup compare", border_style=border, expand=False))

    for issue in report.site_issues:
        console.print(f"[yellow]Site-wide:[/yellow] {issue.code}: {issue.message}")
    problems = report.by_verdict(Verdict.BLOCKING) + report.by_verdict(Verdict.WARNING)
    if problems:
        table = Table(box=box.SIMPLE_HEAD, expand=False, pad_edge=False)
        table.add_column("Verdict")
        table.add_column("Path", overflow="fold", max_width=34)
        table.add_column("Old→New", no_wrap=True)
        table.add_column("Issues", overflow="fold", max_width=60)
        for result in problems[:limit]:
            issues = "\n".join(f"{i.code}" for i in result.issues if i.level is not Level.INFO)
            table.add_row(
                Text(result.verdict.value.upper(), style=VERDICT_STYLE[result.verdict]),
                result.path,
                f"{result.old.status}→{result.new.status}",
                issues,
            )
        console.print(table)
        if len(problems) > limit:
            console.print(
                f"[dim]… and {len(problems) - limit} more (see --format/--csv output)[/dim]"
            )
    else:
        console.print("[green]No differences that need attention.[/green]")
