# Security policy

## Authorized use only

SiteCheckup sends real HTTP(S) requests to the sites you point it at. **Use it only on sites you own or have explicit, written authorization to test.** Testing systems without permission may be illegal in your jurisdiction, regardless of how gentle the requests are.

To make this impossible to overlook, `sitecheckup audit` and `sitecheckup compare` refuse to run unless you pass `--i-have-permission`. The flag is a statement that *you* are authorized; the tool cannot verify it. If you run SiteCheckup on behalf of a client, get the scope (hosts, dates, rate limits) in writing first, and respect it.

## What the tool does and does not do

* **Does:** ordinary GET/HEAD requests, reads headers and bodies, inspects the TLS certificate, checks whether a short list of well-known paths exist (one request each), fetches `robots.txt` and `sitemap.xml`, and (in `compare`) crawls same-host pages while honouring `robots.txt`.
* **Does not:** send exploit payloads, guess credentials, brute-force, fuzz, port-scan, follow redirects to other sites, or modify anything on the target.
* **Polite by default:** identifiable User-Agent, 2 requests/second, timeouts, a hard cap on requests per run.
* **Not a penetration test.** A clean report means the checks it performs passed. It says nothing about application logic, authorization flaws, vulnerable plugin versions or anything else it cannot see from outside. Do not present a SiteCheckup report as a security assessment.

## The demo lab is intentionally vulnerable

`docker-compose.yml` and `demo/` start deliberately weak sites that serve **invented** "leaked" files for demonstration. They bind to `127.0.0.1` only. Never expose them to a network, and never reuse the throwaway database password in `docker-compose.yml` anywhere.

## Reporting a vulnerability in SiteCheckup

If you find a security problem in SiteCheckup itself (for example a way to make it send requests to a host the operator did not name, bypass the permission guard or the request cap, leak data into a report, or inject content into the HTML/CSV output), please report it privately through GitHub's **"Report a vulnerability"** button on the repository's Security tab (private vulnerability reporting). Please do not open a public issue.

Include the version (`sitecheckup --version`), what you did, what you expected and what happened. You can expect an acknowledgement within a few days and a fix or a clear answer on timing after triage. Reporters are credited in the changelog unless they prefer otherwise.

Supported versions: the latest release only (the project is pre-1.0).

## Reporting a vulnerability in a site you tested

If SiteCheckup helps you discover a problem in someone else's site, tell the owner through their `security.txt`/contact channel, share only what is needed to reproduce it, and give them reasonable time to fix it. Do not publish details of unfixed issues.
