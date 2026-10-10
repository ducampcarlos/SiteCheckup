from __future__ import annotations

import json
from pathlib import Path

import httpx
import pytest
from typer.testing import CliRunner

from sitecheckup import __version__
from sitecheckup.cli import app
from tests.conftest import FakeSite

runner = CliRunner()
LAB = "http://localhost:8080"
NEW = "http://localhost:8081"
FAST = ["--rate", "0"]


def lab_home(site: FakeSite, **headers: str) -> None:
    hdrs = [(k.replace("_", "-"), v) for k, v in headers.items()]
    site.html(
        f"{LAB}/",
        "<html><head><title>Lab</title></head><body><h1>Lab</h1></body></html>",
        headers=hdrs,
    )


def test_version() -> None:
    result = runner.invoke(app, ["--version"])
    assert result.exit_code == 0
    assert __version__ in result.output


def test_help_mentions_authorization() -> None:
    result = runner.invoke(app, ["--help"])
    assert result.exit_code == 0
    assert "authorized" in result.output


@pytest.mark.parametrize(
    "args",
    [["audit", LAB], ["compare", LAB, NEW]],
)
def test_refuses_without_permission_flag(site: FakeSite, args: list[str]) -> None:
    result = runner.invoke(app, args)
    assert result.exit_code == 2
    assert "--i-have-permission" in result.output
    assert site.calls == []  # not a single request was sent


@pytest.mark.parametrize("bad", ["ftp://example.com", "http://user:pw@example.com", "http://"])
def test_rejects_invalid_targets(site: FakeSite, bad: str) -> None:
    result = runner.invoke(app, ["audit", bad, "--i-have-permission"])
    assert result.exit_code == 2
    assert site.calls == []


def test_audit_terminal_summary(site: FakeSite) -> None:
    lab_home(site, server="nginx/1.25.0")
    result = runner.invoke(app, ["audit", LAB, "--i-have-permission", *FAST])
    assert result.exit_code == 0
    assert "SiteCheckup audit" in result.output
    assert "headers-server-disclosure" in result.output
    assert "penetration test" in result.output


def test_audit_verbose_shows_remediation(site: FakeSite) -> None:
    lab_home(site)
    result = runner.invoke(app, ["audit", LAB, "--i-have-permission", "-v", *FAST])
    assert "Fix:" in result.output


def test_audit_json_to_stdout_is_machine_readable(site: FakeSite) -> None:
    lab_home(site)
    result = runner.invoke(app, ["audit", LAB, "--i-have-permission", "-f", "json", *FAST])
    assert result.exit_code == 0
    data = json.loads(result.stdout)
    assert data["target"] == LAB
    assert {f["id"] for f in data["findings"]} >= {"headers-csp", "transport-https-redirect"}


@pytest.mark.parametrize(
    ("name", "needle"),
    [("r.html", "<!doctype html>"), ("r.md", "# SiteCheckup audit"), ("r.json", '"findings"')],
)
def test_audit_output_file_format_inferred_from_extension(
    site: FakeSite, tmp_path: Path, name: str, needle: str
) -> None:
    lab_home(site)
    target = tmp_path / "nested" / name
    result = runner.invoke(app, ["audit", LAB, "--i-have-permission", "-o", str(target), *FAST])
    assert result.exit_code == 0
    assert needle in target.read_text()
    assert "SiteCheckup audit" in result.output  # terminal summary still printed


def test_unknown_output_extension_needs_explicit_format(site: FakeSite, tmp_path: Path) -> None:
    result = runner.invoke(
        app, ["audit", LAB, "--i-have-permission", "-o", str(tmp_path / "r.txt")]
    )
    assert result.exit_code == 2
    assert "--format" in result.output


def test_fail_on_threshold(site: FakeSite) -> None:
    lab_home(site)
    base = ["audit", LAB, "--i-have-permission", *FAST]
    assert runner.invoke(app, [*base, "--fail-on", "high"]).exit_code == 1  # plain HTTP is high
    assert runner.invoke(app, [*base, "--fail-on", "none"]).exit_code == 0


def test_fail_on_high_passes_when_only_low_findings(site: FakeSite) -> None:
    lab_home(site)
    result = runner.invoke(
        app,
        [
            "audit",
            LAB,
            "--i-have-permission",
            "--skip",
            "transport-https-redirect",
            "--fail-on",
            "high",
            *FAST,
        ],
    )
    assert result.exit_code == 0


def test_skip_validates_ids(site: FakeSite) -> None:
    lab_home(site)
    result = runner.invoke(app, ["audit", LAB, "--i-have-permission", "--skip", "nope", *FAST])
    assert result.exit_code == 2
    assert "nope" in result.output


def test_unreachable_target_exit_code(site: FakeSite) -> None:
    site.error = httpx.ConnectError("refused")
    result = runner.invoke(app, ["audit", LAB, "--i-have-permission", *FAST])
    assert result.exit_code == 3
    assert "Could not reach" in result.output


def test_bare_hostname_defaults_to_https(site: FakeSite) -> None:
    site.html("https://example.com/", "<html></html>")
    result = runner.invoke(
        app,
        [
            "audit",
            "example.com",
            "--i-have-permission",
            "--skip",
            "transport-tls-certificate",
            *FAST,
        ],
    )
    assert result.exit_code == 0
    assert "https://example.com" in result.output


def test_checks_command_lists_registry() -> None:
    result = runner.invoke(app, ["checks"])
    assert result.exit_code == 0
    assert "exposed-env" in result.output
    assert "wp-xmlrpc" in result.output


# --- compare -----------------------------------------------------------------


def build_pair(site: FakeSite, *, broken: bool) -> None:
    site.add(
        f"{LAB}/sitemap.xml",
        text="<urlset><url><loc>https://x.test/</loc></url><url><loc>https://x.test/a</loc></url></urlset>",
    )
    for base in (LAB, NEW):
        site.html(
            f"{base}/",
            f"<html><head><title>Home</title><link rel='canonical' href='{base}/'></head><h1>Home</h1></html>",
        )
    site.html(f"{LAB}/a", "<html><head><title>A</title></head><h1>A</h1></html>")
    if not broken:
        site.html(f"{NEW}/a", "<html><head><title>A</title></head><h1>A</h1></html>")


def test_compare_clean_migration_exits_zero(site: FakeSite) -> None:
    build_pair(site, broken=False)
    result = runner.invoke(app, ["compare", LAB, NEW, "--i-have-permission", *FAST])
    assert result.exit_code == 0
    assert "2 ok" in result.output
    assert "sitemap" in result.output


def test_compare_blocking_exits_one_and_writes_all_outputs(site: FakeSite, tmp_path: Path) -> None:
    build_pair(site, broken=True)
    csv_file, md_file = tmp_path / "out.csv", tmp_path / "out.md"
    result = runner.invoke(
        app,
        [
            "compare",
            LAB,
            NEW,
            "--i-have-permission",
            "--csv",
            str(csv_file),
            "-o",
            str(md_file),
            *FAST,
        ],
    )
    assert result.exit_code == 1
    assert "missing_on_new" in result.output
    assert "/a,/a,blocking,200,404" in csv_file.read_text()
    assert "## Blocking (1)" in md_file.read_text()


def test_compare_fail_on_none_and_warning(site: FakeSite) -> None:
    build_pair(site, broken=True)
    assert (
        runner.invoke(
            app, ["compare", LAB, NEW, "--i-have-permission", "--fail-on", "none", *FAST]
        ).exit_code
        == 0
    )
    site.html(f"{NEW}/a", "<html><head><title>Changed</title></head><h1>A</h1></html>")
    assert (
        runner.invoke(
            app, ["compare", LAB, NEW, "--i-have-permission", "--fail-on", "blocking", *FAST]
        ).exit_code
        == 0
    )
    assert (
        runner.invoke(
            app, ["compare", LAB, NEW, "--i-have-permission", "--fail-on", "warning", *FAST]
        ).exit_code
        == 1
    )


def test_compare_json_to_stdout(site: FakeSite) -> None:
    build_pair(site, broken=False)
    result = runner.invoke(app, ["compare", LAB, NEW, "--i-have-permission", "-f", "json", *FAST])
    data = json.loads(result.stdout)
    assert len(data["results"]) == 2


def test_compare_urls_file_and_path_map(site: FakeSite, tmp_path: Path) -> None:
    site.html(f"{LAB}/old", "<html><head><title>X</title></head><h1>X</h1></html>")
    site.html(f"{NEW}/new", "<html><head><title>X</title></head><h1>X</h1></html>")
    urls = tmp_path / "urls.txt"
    urls.write_text("/old\n")
    mapping = tmp_path / "map.csv"
    mapping.write_text("/old,/new\n")
    result = runner.invoke(
        app,
        [
            "compare",
            LAB,
            NEW,
            "--i-have-permission",
            "--urls-file",
            str(urls),
            "--path-map",
            str(mapping),
            *FAST,
        ],
    )
    assert result.exit_code == 0
    assert "1 ok" in result.output


def test_compare_bad_path_map(site: FakeSite, tmp_path: Path) -> None:
    mapping = tmp_path / "map.csv"
    mapping.write_text("/only-one\n")
    result = runner.invoke(
        app, ["compare", LAB, NEW, "--i-have-permission", "--path-map", str(mapping)]
    )
    assert result.exit_code == 2
    assert site.calls == []


def test_compare_falls_back_to_crawl_without_sitemap(site: FakeSite) -> None:
    site.html(f"{LAB}/", "<html><head><title>H</title></head><a href='/a'>a</a></html>")
    site.html(f"{LAB}/a", "<html><head><title>A</title></head></html>")
    site.html(f"{NEW}/", "<html><head><title>H</title></head><a href='/a'>a</a></html>")
    site.html(f"{NEW}/a", "<html><head><title>A</title></head></html>")
    result = runner.invoke(app, ["compare", LAB, NEW, "--i-have-permission", *FAST])
    assert result.exit_code == 0
    assert "falling back to a crawl" in result.output
    assert "crawl (no sitemap)" in result.output


def test_compare_crawl_flag_skips_sitemap(site: FakeSite) -> None:
    build_pair(site, broken=False)
    runner.invoke(app, ["compare", LAB, NEW, "--i-have-permission", "--crawl", *FAST])
    assert f"{LAB}/sitemap.xml" not in site.calls


def test_compare_nothing_to_compare(site: FakeSite) -> None:
    result = runner.invoke(app, ["compare", LAB, NEW, "--i-have-permission", *FAST])
    assert result.exit_code == 3
    assert "no URLs" in result.output


def test_compare_request_cap_during_collection(site: FakeSite) -> None:
    result = runner.invoke(
        app, ["compare", LAB, NEW, "--i-have-permission", "--max-requests", "1", *FAST]
    )
    assert result.exit_code == 3
    assert "--max-requests" in result.output


def test_compare_request_cap_truncates_report(site: FakeSite) -> None:
    build_pair(site, broken=False)
    result = runner.invoke(
        app, ["compare", LAB, NEW, "--i-have-permission", "--max-requests", "4", *FAST]
    )
    assert "stopped at request cap" in result.output
