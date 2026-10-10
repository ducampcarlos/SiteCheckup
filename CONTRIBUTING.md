# Contributing

Thanks for helping make SiteCheckup better. Small, focused pull requests are easiest to review.

## Ground rules

1. **Passive only.** New checks use `GET`/`HEAD` through `AuditContext.fetch` / `PoliteClient`. No payloads, brute force, fuzzing, port scanning, exploitation, or anything that modifies a target. See [ADR 0001](docs/adr/0001-passive-only.md). PRs that cross this line will be declined.
2. **No real data.** Fixtures, examples, docs and tests use invented names and `example.com`, `example.org`, `*.test` or `localhost`. No real client names, domains, findings or screenshots, ever.
3. **No network in tests.** HTTP is mocked with `respx` (see `tests/conftest.py`); sockets are blocked.
4. **English** for code, comments, docs and commit messages.

## Setup

```bash
git clone https://github.com/ducampcarlos/SiteCheckup.git && cd SiteCheckup
make install          # virtualenv, editable install, pre-commit hooks
make test             # pytest + coverage (must stay >= 85%)
make lint             # ruff check, ruff format --check, mypy --strict
```

Python 3.11+ is required; CI runs 3.11, 3.12 and 3.13, so avoid syntax newer than 3.11 (for example PEP 695 generics).

## Adding or changing a check

Follow [Adding a check](docs/architecture.md#adding-a-check). Checklist:

- [ ] Stable, kebab-case `id` prefixed by its category; never rename an existing ID.
- [ ] Title, description, remediation and at least one reference (OWASP, MDN, an RFC).
- [ ] Severity justified; use `Outcome.fail(..., severity)` for graded cases.
- [ ] Skips with a reason when it does not apply (`Outcome.skip`).
- [ ] No secrets or response bodies in `evidence`.
- [ ] Tests for pass, fail and skip paths, plus a false-positive guard for path probes.
- [ ] If it changes what users see, mention it in `CHANGELOG.md` and the relevant playbook.

## Code style

* `ruff` for lint and formatting, `mypy --strict` on `src/`; typed, small functions with docstrings on public APIs.
* Match the surrounding code; prefer clarity over cleverness.
* Keep dependencies minimal. New runtime dependencies need a good reason in the PR description.

## Commits and pull requests

* [Conventional Commits](https://www.conventionalcommits.org/): `feat:`, `fix:`, `docs:`, `test:`, `ci:`, `chore:`, `refactor:`.
* Describe what changed and why; link the issue.
* Update docs and the changelog's `Unreleased` section.
* Regenerate `docs/examples/` with `make report` only if output formats change (and say so).

## Reporting bugs and ideas

Open an issue with the command you ran (redact your target), the version, and what you expected. For security problems in SiteCheckup itself, follow [SECURITY.md](SECURITY.md) instead of opening a public issue.

By contributing you agree your work is licensed under the [MIT License](LICENSE) and that you will follow the [Code of Conduct](CODE_OF_CONDUCT.md).
