"""Command-line interface: ``sitecheckup audit | compare | checks``."""

from __future__ import annotations

import sys
from enum import StrEnum
from pathlib import Path
from typing import Annotated

import typer
from rich import box
from rich.console import Console
from rich.table import Table

from sitecheckup import __version__
from sitecheckup.audit.base import all_checks
from sitecheckup.audit.runner import TargetUnreachable, run_audit
from sitecheckup.compare.engine import compare_sites
from sitecheckup.compare.pathmap import PathMapError, load_path_map
from sitecheckup.compare.sources import crawl, read_urls_file, sitemap_urls
from sitecheckup.guard import PERMISSION_MESSAGE, InvalidTarget, normalize_target
from sitecheckup.http import DEFAULT_RATE, DEFAULT_TIMEOUT, PoliteClient, RequestBudgetExceeded
from sitecheckup.models import Severity
from sitecheckup.reporting.render import Format, compare_csv, render_audit, render_compare
from sitecheckup.reporting.terminal import (
    SEVERITY_STYLE,
    render_audit_terminal,
    render_compare_terminal,
)

EXIT_THRESHOLD = 1
EXIT_USAGE = 2
EXIT_RUNTIME = 3

app = typer.Typer(
    name="sitecheckup",
    help="Passive website audit and post-migration comparison. Only for sites you own or are authorized to test.",
    no_args_is_help=True,
    add_completion=False,
    pretty_exceptions_show_locals=False,
)

out = Console()
err = Console(stderr=True)

PermissionOpt = Annotated[
    bool,
    typer.Option(
        "--i-have-permission",
        help="Confirm you own the target(s) or are explicitly authorized to test them. Required.",
    ),
]
FormatOpt = Annotated[
    Format | None,
    typer.Option(
        "--format", "-f", help="html, json or md. Without --output the report goes to stdout."
    ),
]
OutputOpt = Annotated[
    Path | None,
    typer.Option(
        "--output",
        "-o",
        help="Write the report to this file (format inferred from the extension if --format is omitted).",
    ),
]
RateOpt = Annotated[
    float, typer.Option(help="Maximum requests per second (0 disables throttling).", min=0)
]
TimeoutOpt = Annotated[float, typer.Option(help="Per-request timeout in seconds.", min=0.5)]


class AuditFailOn(StrEnum):
    """Values accepted by ``audit --fail-on``."""

    NONE = "none"
    INFO = "info"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"


class CompareFailOn(StrEnum):
    """Values accepted by ``compare --fail-on``."""

    NONE = "none"
    WARNING = "warning"
    BLOCKING = "blocking"


def _version_callback(value: bool) -> None:
    if value:
        typer.echo(f"sitecheckup {__version__}")
        raise typer.Exit


@app.callback()
def main(
    version: Annotated[
        bool,
        typer.Option(
            "--version",
            callback=_version_callback,
            is_eager=True,
            help="Show the version and exit.",
        ),
    ] = False,
) -> None:
    """SiteCheckup: passive security audit and migration validator."""


def _require_permission(confirmed: bool) -> None:
    if not confirmed:
        err.print(PERMISSION_MESSAGE, markup=False, highlight=False)
        raise typer.Exit(EXIT_USAGE)


def _target(url: str) -> str:
    try:
        return normalize_target(url)
    except InvalidTarget as exc:
        err.print(f"[red]error:[/red] {exc}")
        raise typer.Exit(EXIT_USAGE) from exc


def _resolve_format(fmt: Format | None, output: Path | None) -> Format | None:
    if fmt or not output:
        return fmt
    suffix = {".html": Format.HTML, ".htm": Format.HTML, ".json": Format.JSON, ".md": Format.MD}
    inferred = suffix.get(output.suffix.lower())
    if inferred is None:
        err.print(
            "[red]error:[/red] cannot infer the format from the file extension; pass --format."
        )
        raise typer.Exit(EXIT_USAGE)
    return inferred


def _write(path: Path, text: str) -> None:
    try:
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(text, encoding="utf-8")
    except OSError as exc:
        err.print(f"[red]error:[/red] cannot write {path}: {exc}")
        raise typer.Exit(EXIT_RUNTIME) from exc
    err.print(f"[dim]Wrote {path}[/dim]")


@app.command(
    epilog=(
        "Examples:\n\n"
        "  sitecheckup audit https://example.com --i-have-permission\n\n"
        "  sitecheckup audit https://example.com --i-have-permission -o report.html\n\n"
        "  sitecheckup audit https://example.com --i-have-permission -f json --fail-on high\n\n"
        "Exit codes: 0 ok, 1 findings at/above --fail-on, 2 usage or missing permission, 3 target unreachable."
    )
)
def audit(
    url: Annotated[str, typer.Argument(help="Site to audit, e.g. https://example.com")],
    i_have_permission: PermissionOpt = False,
    format: FormatOpt = None,
    output: OutputOpt = None,
    fail_on: Annotated[
        AuditFailOn,
        typer.Option(help="Exit with code 1 if a finding is at or above this severity."),
    ] = AuditFailOn.NONE,
    skip: Annotated[
        list[str] | None,
        typer.Option(help="Check ID to skip (repeatable). See 'sitecheckup checks'."),
    ] = None,
    rate: RateOpt = DEFAULT_RATE,
    timeout: TimeoutOpt = DEFAULT_TIMEOUT,
    max_requests: Annotated[
        int, typer.Option(help="Hard cap on requests for this run.", min=1)
    ] = 150,
    verbose: Annotated[
        bool, typer.Option("--verbose", "-v", help="Show remediation in the terminal table.")
    ] = False,
) -> None:
    """Run a passive security and hygiene audit of one site.

    Sends ordinary GET requests only (a few dozen, rate-limited). Never sends
    payloads, never modifies the target. Not a substitute for a penetration test.
    """
    _require_permission(i_have_permission)
    target = _target(url)
    fmt = _resolve_format(format, output)
    unknown = set(skip or []) - {c.id for c in all_checks()}
    if unknown:
        err.print(f"[red]error:[/red] unknown check id(s): {', '.join(sorted(unknown))}")
        raise typer.Exit(EXIT_USAGE)

    try:
        with (
            PoliteClient(
                allowed_sites=[target], rate=rate, timeout=timeout, max_requests=max_requests
            ) as client,
            err.status("Starting audit…") as status,
        ):
            report = run_audit(
                target,
                client,
                skip=set(skip or []),
                on_check=lambda c: status.update(f"Running {c.id}"),
            )
    except TargetUnreachable as exc:
        err.print(f"[red]error:[/red] {exc}")
        raise typer.Exit(EXIT_RUNTIME) from exc

    if fmt and not output:
        sys.stdout.write(render_audit(report, fmt))
    else:
        if fmt and output:
            _write(output, render_audit(report, fmt))
        render_audit_terminal(report, out, verbose=verbose)
    if fail_on is not AuditFailOn.NONE and report.exceeds(Severity(fail_on.value)):
        raise typer.Exit(EXIT_THRESHOLD)


@app.command(
    epilog=(
        "Examples:\n\n"
        "  sitecheckup compare https://old.example.com https://new.example.com --i-have-permission\n\n"
        "  sitecheckup compare OLD NEW --i-have-permission --urls-file urls.txt --path-map map.csv --csv results.csv\n\n"
        "URL sources, in order: --urls-file, the old site's sitemap.xml, then a shallow crawl (or force it with --crawl). "
        "Exit codes: 0 ok, 1 issues at/above --fail-on, 2 usage or missing permission, 3 runtime error."
    )
)
def compare(
    old_url: Annotated[str, typer.Argument(help="The existing (old) site.")],
    new_url: Annotated[str, typer.Argument(help="The migrated (new) site.")],
    i_have_permission: PermissionOpt = False,
    urls_file: Annotated[
        Path | None,
        typer.Option(help="Text file with one path or URL per line.", exists=True, dir_okay=False),
    ] = None,
    path_map: Annotated[
        Path | None,
        typer.Option(
            help="CSV of intentional URL changes: old_path,new_path.", exists=True, dir_okay=False
        ),
    ] = None,
    use_crawl: Annotated[
        bool, typer.Option("--crawl", help="Skip the sitemap and crawl the old site.")
    ] = False,
    max_pages: Annotated[int, typer.Option(help="Maximum number of URLs to compare.", min=1)] = 100,
    csv_path: Annotated[
        Path | None, typer.Option("--csv", help="Write one CSV row per URL to this file.")
    ] = None,
    format: FormatOpt = None,
    output: OutputOpt = None,
    fail_on: Annotated[
        CompareFailOn, typer.Option(help="Exit with code 1 if any URL is at this level or worse.")
    ] = CompareFailOn.BLOCKING,
    rate: RateOpt = DEFAULT_RATE,
    timeout: TimeoutOpt = DEFAULT_TIMEOUT,
    max_requests: Annotated[
        int, typer.Option(help="Hard cap on requests for this run.", min=1)
    ] = 1000,
) -> None:
    """Compare an old site with its migrated replacement, URL by URL.

    Reports what broke: missing pages, redirect chains and loops, changed status
    codes, titles, descriptions, canonicals, noindex, headers and response times.
    """
    _require_permission(i_have_permission)
    old_base, new_base = _target(old_url).rstrip("/"), _target(new_url).rstrip("/")
    fmt = _resolve_format(format, output)
    try:
        mapping = load_path_map(path_map) if path_map else {}
    except PathMapError as exc:
        err.print(f"[red]error:[/red] {exc}")
        raise typer.Exit(EXIT_USAGE) from exc

    try:
        with (
            PoliteClient(
                allowed_sites=[old_base, new_base],
                rate=rate,
                timeout=timeout,
                max_requests=max_requests,
            ) as client,
            err.status("Collecting URLs…") as status,
        ):
            if urls_file:
                paths, source = read_urls_file(urls_file, max_pages), f"file {urls_file.name}"
            elif use_crawl:
                paths, source = crawl(client, old_base, max_pages), "crawl"
            else:
                paths, source = sitemap_urls(client, old_base, max_pages), "sitemap"
                if not paths:
                    err.print("[yellow]No usable sitemap.xml; falling back to a crawl.[/yellow]")
                    paths, source = crawl(client, old_base, max_pages), "crawl (no sitemap)"
            if not paths:
                err.print("[red]error:[/red] no URLs to compare.")
                raise typer.Exit(EXIT_RUNTIME)
            total = len(paths)
            done = 0

            def progress(_: object) -> None:
                nonlocal done
                done += 1
                status.update(f"Comparing {done}/{total}")

            report = compare_sites(
                old_base,
                new_base,
                paths,
                client,
                path_map=mapping,
                source=source,
                on_result=progress,
            )
    except RequestBudgetExceeded as exc:
        err.print(f"[red]error:[/red] {exc} Raise --max-requests or lower --max-pages.")
        raise typer.Exit(EXIT_RUNTIME) from exc

    if csv_path:
        _write(csv_path, compare_csv(report))
    if fmt and not output:
        sys.stdout.write(render_compare(report, fmt))
    else:
        if fmt and output:
            _write(output, render_compare(report, fmt))
        render_compare_terminal(report, out)
    if fail_on is not CompareFailOn.NONE and report.needs_attention(
        include_warnings=fail_on is CompareFailOn.WARNING
    ):
        raise typer.Exit(EXIT_THRESHOLD)


@app.command()
def checks() -> None:
    """List every audit check (ID, severity, title). Use IDs with 'audit --skip'."""
    table = Table(box=box.SIMPLE_HEAD, pad_edge=False)
    table.add_column("ID", no_wrap=True)
    table.add_column("Default")
    table.add_column("Category")
    table.add_column("Title", overflow="fold")
    for check in all_checks():
        style = SEVERITY_STYLE[check.severity.value]
        table.add_row(
            check.id, f"[{style}]{check.severity.value}[/{style}]", check.category, check.title
        )
    out.print(table)


if __name__ == "__main__":  # pragma: no cover
    app()
