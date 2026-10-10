# ADR 0005: Parse sitemaps with a regex and use paths only

* Status: accepted

## Context

`compare` needs the old site's URL list. Sitemaps are untrusted XML, and Python's standard XML parsers are vulnerable to entity-expansion attacks unless an extra dependency (`defusedxml`) is added. Sitemaps also frequently name a different host than the one you are testing, for example the production domain while you compare staging copies, and following those absolute URLs would send requests to hosts the operator did not name.

## Decision

Extract `<loc>` values with a bounded regular expression (handling CDATA and whitespace), follow at most 10 child sitemaps from an index, and **keep only the path and query** of each entry. Requests go to the old and new base URLs the operator supplied, never to the host written in the sitemap.

## Consequences

* No XML parser attack surface and no extra dependency.
* Works for the common "sitemap names the production host" situation.
* Exotic sitemap features (extensions such as image or video metadata) are ignored, which is fine because only the URL list is needed.
