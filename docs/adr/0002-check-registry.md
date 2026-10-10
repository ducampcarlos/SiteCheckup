# ADR 0002: A decorator-based check registry

* Status: accepted

## Context

The audit will keep growing: new headers appear, platforms have their own quirks, teams want their own rules. We need adding a check to be a one-file change that cannot break the others, and we need stable identifiers that playbooks, CI `--skip` lists and tickets can refer to.

## Decision

Each check is a small class with declarative metadata (`id`, `title`, `category`, `severity`, `description`, `remediation`, `references`) and one `run(ctx) -> Outcome` method. A `@register` decorator adds it to a registry that validates required metadata and rejects duplicate IDs. The runner iterates the registry, isolates exceptions per check (a crashing check becomes an `error` result, not a crashed run) and skips WordPress checks when WordPress is not detected. Checks read the target through a shared `AuditContext` that memoises fetches.

## Alternatives considered

* **Plain functions in a list:** no place for metadata, harder to document.
* **Entry-point plugins:** the right long-term answer for third-party packages (it is on the roadmap), but heavyweight for the first release. The registry API is the same, so entry points can be layered on later.

## Consequences

* Metadata and logic live together, so reports, `sitecheckup checks` and the playbooks all draw on one source of truth.
* IDs are a public contract: never rename, retire instead.
* Ordering is registration order, which we control explicitly in `checks/__init__.py` so reports read transport -> headers -> cookies -> exposed files -> WordPress -> hygiene.
