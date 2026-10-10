# ADR 0003: Require `--i-have-permission`

* Status: accepted

## Context

Scanning systems you do not own or are not authorized to test can be illegal, and most people who run a tool never read its README. A tool that sends requests to arbitrary hosts at the touch of a key should make the question of authorization impossible to skip.

## Decision

`audit` and `compare` exit with code 2 and a clear message unless `--i-have-permission` is passed. The message states that the flag is a statement about authorization, not a technicality, and points to `SECURITY.md`. The check happens before the URL is parsed and before any request is built, and a test asserts that zero requests are sent without the flag. There is no environment-variable or config-file bypass.

## Consequences

* A small, deliberate bit of friction for every invocation, including CI (put the flag in the pipeline definition, where it documents that someone accepted responsibility).
* It does not *verify* authorization (it cannot), but it makes accidental misuse unlikely and shifts responsibility visibly to the operator.
* Other defaults reinforce the posture: identifiable User-Agent, 2 req/s, hard request cap, same-site redirects only.
