# ADR 0001: Passive-only

* Status: accepted

## Context

Hosting and migration work constantly raises the question "is this site in good shape?", and the honest answer usually needs only what any visitor can see: response headers, the certificate, a handful of well-known paths. Active techniques (injection payloads, brute force, fuzzing, port scans) are a different activity: they can break things, trigger incident response, and need a signed scope. A portfolio-grade open-source tool that anyone can point at a URL must not become a liability for its users or for the author.

## Decision

SiteCheckup only sends ordinary `GET`/`HEAD` requests, reads what comes back, and performs one TLS handshake. Concretely:

* There is a single network primitive (`PoliteClient.fetch`) and it cannot send a request body.
* Exposed-path checks request each path **once** and require a content signature before calling it a finding.
* Contents of sensitive files are never written to a report.
* Redirects are followed only within the same site.
* No vulnerability exploitation, credential guessing, fuzzing, port scanning or bypass of protections, now or in the roadmap.

## Consequences

* Safe to run against production at 2 requests/second.
* Findings are limited to what is observable from outside; the README says plainly that this is not a pentest.
* Some desirable checks (for example "is `xmlrpc.php` accepting `system.multicall`?") are deliberately not implemented. We detect that the endpoint is reachable and recommend blocking it.
