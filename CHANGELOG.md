# Changelog

All notable changes to this project are documented here. The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and the project uses [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.1.0] - 2026-10-10

### Added

- `sitecheckup audit`: passive security and hygiene audit with 31 checks across transport (HTTPS redirect, TLS certificate, HSTS), security headers, cookies, exposed files and paths, WordPress-specific exposure (only when detected) and basic hygiene (robots.txt, security.txt, mixed content, caching).
- Check registry (`@register`) with stable IDs, severities, remediation text and references; `sitecheckup checks` lists them; `--skip` excludes them.
- Documented 0-100 score and A-F grade ([docs/scoring.md](docs/scoring.md)); `--fail-on` for CI gating.
- `sitecheckup compare`: post-migration validator comparing status codes, redirect chains and loops, title, meta description, canonical, `<h1>`, `noindex`, security headers and response times. URL sources: `--urls-file`, sitemap, or robots-aware crawl. `--path-map` for intentional URL changes, `--csv` export, Blocking / Warnings / OK report.
- Reports as terminal summary, self-contained HTML, Markdown and JSON (`--format`, `--output`).
- Safety rails: `--i-have-permission` required, identifiable User-Agent, 2 req/s default rate limit, timeouts, hard request cap, same-site redirects only.
- Demo lab (`docker-compose.yml`, nginx legacy and new sites, optional WordPress + MariaDB), `Makefile`, no-Docker runner, generated examples in `docs/examples/`.
- Documentation: architecture, ADRs, scoring, and playbooks for migration, WordPress hardening, pentest-report response and client/developer communication.
- CI (Python 3.11-3.13: ruff, mypy --strict, pytest with coverage), Docker build job and tag-triggered release build.

[Unreleased]: https://github.com/ducampcarlos/SiteCheckup/compare/v0.1.0...HEAD
[0.1.0]: https://github.com/ducampcarlos/SiteCheckup/releases/tag/v0.1.0
