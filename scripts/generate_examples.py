"""Regenerate docs/examples/ by running SiteCheckup against a running demo lab.

make demo-local      # or: docker compose up -d legacy-site new-site
make report
"""

from __future__ import annotations

import argparse
import io
from pathlib import Path

from rich.console import Console

from sitecheckup.audit.runner import run_audit
from sitecheckup.compare.engine import compare_sites
from sitecheckup.compare.pathmap import load_path_map
from sitecheckup.compare.sources import sitemap_urls
from sitecheckup.http import PoliteClient
from sitecheckup.reporting.render import Format, compare_csv, render_audit, render_compare
from sitecheckup.reporting.terminal import render_audit_terminal, render_compare_terminal

ROOT = Path(__file__).resolve().parent.parent


def recording_console() -> Console:
    """A console that captures output for SVG export."""
    return Console(
        record=True, width=96, file=io.StringIO(), force_terminal=True, color_system="truecolor"
    )


def main() -> None:
    """Run both modes against the lab and write the example files."""
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--legacy", default="http://localhost:8080")
    parser.add_argument("--new", default="http://localhost:8081")
    parser.add_argument(
        "--wordpress", default=None, help="optional URL of the demo WordPress install (audit only)"
    )
    parser.add_argument("--out", type=Path, default=ROOT / "docs" / "examples")
    parser.add_argument("--rate", type=float, default=20.0, help="requests/second (localhost only)")
    args = parser.parse_args()
    out: Path = args.out
    out.mkdir(parents=True, exist_ok=True)

    with PoliteClient(allowed_sites=[args.legacy], rate=args.rate) as client:
        audit = run_audit(args.legacy, client)
    (out / "audit-report.html").write_text(render_audit(audit, Format.HTML), encoding="utf-8")
    (out / "audit-report.json").write_text(render_audit(audit, Format.JSON), encoding="utf-8")
    (out / "audit-report.md").write_text(render_audit(audit, Format.MD), encoding="utf-8")
    console = recording_console()
    console.print("[bold]$ sitecheckup audit http://localhost:8080 --i-have-permission[/bold]")
    render_audit_terminal(audit, console)
    console.save_svg(str(out / "audit-terminal.svg"), title="sitecheckup audit")

    mapping = load_path_map(ROOT / "demo" / "path-map.csv")
    with PoliteClient(
        allowed_sites=[args.legacy, args.new], rate=args.rate, max_requests=1000
    ) as client:
        paths = sitemap_urls(client, args.legacy, 100)
        compare = compare_sites(
            args.legacy, args.new, paths, client, path_map=mapping, source="sitemap"
        )
    (out / "compare-report.html").write_text(render_compare(compare, Format.HTML), encoding="utf-8")
    (out / "compare-report.json").write_text(render_compare(compare, Format.JSON), encoding="utf-8")
    (out / "compare-report.md").write_text(render_compare(compare, Format.MD), encoding="utf-8")
    (out / "compare-results.csv").write_text(compare_csv(compare), encoding="utf-8")
    console = recording_console()
    console.print(
        "[bold]$ sitecheckup compare http://localhost:8080 http://localhost:8081 "
        "--i-have-permission --path-map demo/path-map.csv[/bold]"
    )
    render_compare_terminal(compare, console)
    console.save_svg(str(out / "compare-terminal.svg"), title="sitecheckup compare")

    if args.wordpress:
        with PoliteClient(allowed_sites=[args.wordpress], rate=args.rate) as client:
            wp_audit = run_audit(args.wordpress, client)
        (out / "audit-wordpress-report.md").write_text(
            render_audit(wp_audit, Format.MD), encoding="utf-8"
        )
    print(f"Wrote examples to {out}")


if __name__ == "__main__":
    main()
