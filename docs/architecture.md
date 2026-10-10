# Architecture

SiteCheckup is a small, layered Python package. Data flows one way: **CLI -> runner/engine -> checks/rules -> models -> renderers**.

```
                     +--------------------+
   sitecheckup ----> |  cli.py (typer)    |  permission guard, option parsing, exit codes
                     +---------+----------+
              audit             |             compare
        +-----------------------+-----------------------+
        v                                               v
 audit/runner.py                                 compare/sources.py   file | sitemap | crawl
   |  AuditContext (cached fetches, parsed page)  compare/engine.py    fetch old + new, snapshot
   |  registry -> Check.run(ctx) -> Outcome       compare/rules.py     pure functions -> Issues
   v                                               v
 AuditReport (+ score)                          CompareReport
        +-----------------------+-----------------------+
                                v
                reporting/ (rich terminal, jinja2 HTML + Markdown, JSON, CSV)

 Everything that touches the network goes through http.PoliteClient.
```

## Modules

| Module | Responsibility |
| --- | --- |
| `http.py` | `PoliteClient`: User-Agent, rate limit, timeout, request budget, byte cap, manual same-site redirect following with chain and loop detection. Network errors are *returned* (`Fetched.error`), never raised, so one flaky URL cannot abort a run. |
| `htmlinfo.py` | Dependency-free extraction of title, meta description, canonical, first `<h1>`, robots meta, generator, links and sub-resources. |
| `tlsinfo.py` | One verified TLS handshake; reports verification failures as data. Injected into the context so tests never open sockets. |
| `guard.py` | Target normalisation and the authorization message. |
| `audit/base.py` | `Check` base class, `Outcome`, and the registry decorator. |
| `audit/context.py` | `AuditContext`: memoised `fetch()`, lazy `homepage`, `page`, `is_wordpress`. |
| `audit/checks/*.py` | The 31 built-in checks, one small class each. |
| `audit/runner.py` | Runs checks, isolates crashes, honours the request cap, computes the score. |
| `audit/scoring.py` | The formula from [scoring.md](scoring.md). |
| `compare/*` | URL sources, path map, engine and rules. |
| `reporting/*` + `templates/` | Terminal summaries and file renderers. |

## Design principles

1. **Passive by construction.** The only network primitive is `PoliteClient.fetch` with GET/HEAD. There is no code path that can send a body ([ADR 0001](adr/0001-passive-only.md)).
2. **Checks are data plus one function.** Metadata (ID, title, severity, description, remediation, references) is declared on the class; `run()` only decides pass/fail and gathers evidence ([ADR 0002](adr/0002-check-registry.md)).
3. **Each URL is fetched once.** `AuditContext.fetch` memoises, so overlapping checks cost nothing.
4. **Pure rules.** Compare rules take two `Snapshot` objects and return issues. They are unit-tested without any HTTP.
5. **No false confidence.** Exposed-file probes need a content signature, not just a 200, so catch-all pages do not produce false positives. Sensitive contents are never stored.
6. **Report what you could not do.** Skipped checks say why, and a run that hit its request cap says so (`truncated`).

## Adding a check

Create a class in a module under `src/sitecheckup/audit/checks/` (or a new module listed in `checks/__init__.py`):

```python
from sitecheckup.audit.base import Check, Outcome, register
from sitecheckup.audit.context import AuditContext
from sitecheckup.models import Severity


@register
class HumansTxt(Check):
    id = "hygiene-humans-txt"  # stable, lower-case, kebab-case; never rename
    title = "humans.txt is published"
    category = "hygiene"
    severity = Severity.INFO
    description = "Why this matters, in one or two sentences."
    remediation = "What to do about it."
    references = ("https://developer.mozilla.org/...",)

    def run(self, ctx: AuditContext) -> Outcome:
        res = ctx.fetch("/humans.txt")  # memoised GET, redirects not followed
        if res.status == 200:
            return Outcome.ok("found")
        return Outcome.fail(f"/humans.txt -> HTTP {res.status}")
```

Rules of thumb: one concern per check; use `ctx.fetch` (never your own HTTP); return `Outcome.skip(reason)` when a check does not apply; override severity per outcome when the evidence justifies it; never put secrets or full response bodies in `evidence`; add a test next to the others using the `site` fixture. Set `wordpress_only = True` to run only when WordPress was detected.

## Check catalogue

Run `sitecheckup checks` for the live list. The WordPress hardening playbook maps these IDs to remediation steps.

## Compare rules

| Code | Level | Meaning |
| --- | --- | --- |
| `missing_on_new` | blocking | Old page is fine, new returns 404/410 |
| `client_error` / `server_error` | blocking | New returns another 4xx / any 5xx |
| `new_unreachable` | blocking | Request to the new site failed |
| `redirect_loop` | blocking | New site redirects in a circle |
| `redirects_to_old_site` | blocking | A redirect sends visitors back to the old host |
| `noindex_added` | blocking | Page is `noindex` (meta or `X-Robots-Tag`) on new but not on old |
| `canonical_points_to_old_host` | blocking | New canonical still names the old host |
| `redirect_chain_long` | warning | More than 2 redirects (configurable) |
| `unexpected_redirect` | warning | Old served the URL directly; new redirects |
| `temporary_redirect` | warning | First hop is 302/303/307 where a permanent move is expected |
| `redirect_target_changed` | warning | Both redirect, to different final pages |
| `external_redirect` | warning | Redirect to a third-party host (not followed) |
| `title_changed` / `title_missing` | warning | Title text differs / disappeared |
| `meta_description_lost`, `h1_lost` | warning | Present on old, absent on new |
| `canonical_missing`, `canonical_host_changed` | warning | Canonical removed / pointing at another host |
| `slower` | warning | New is >= 1.5x slower and >= 500 ms slower |
| `security_header_lost_sitewide` | warning (site-wide) | A tracked header vanished on >= 90% of pages |
| `status_differs`, `fixed_on_new`, `redirect_removed`, `meta_description_changed`, `h1_changed`, `noindex_removed`, `security_header_lost` | info | Worth knowing, not worth failing |

Thresholds live in `CompareSettings` (`compare/rules.py`).

## Testing strategy

* Unit tests per check with an in-memory `FakeSite` served through `respx`; unknown URLs return 404.
* `conftest.py` blocks `socket.connect`, so a test that tries to reach the network fails loudly.
* Pure rule tests for compare; engine and CLI tests run end to end against the fake site.
* The demo lab (`docker compose`) is the integration test you can look at.
