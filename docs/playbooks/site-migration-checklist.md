# Site migration checklist

A migration is "done" when nobody can tell it happened: same URLs, same rankings, same behaviour, better hosting. This checklist is organised around the three ways migrations actually go wrong: **lost URLs**, **lost signals** (SEO and security) and **no way back**.

> Scenario used below: *Maple & Crumb*, an invented bakery site, moves from `www.maple-crumb.example` on an old shared server to a new platform at the same domain. Names and numbers are made up.

## 1. Pre-migration inventory (T-4 weeks to T-2 weeks)

- [ ] **Owners and access.** Who owns the domain registrar, DNS, old host, new host, CDN, email? Who can approve downtime? Put names in the ticket, not in people's heads.
- [ ] **Everything that is not "the website".** Mail (MX, SPF, DKIM, DMARC), subdomains, cron jobs, webhooks, payment callbacks, third-party allow-lists that pin the server IP, SSL certificates, `robots.txt`, `sitemap.xml`, `security.txt`, redirects configured outside the app (server config, CDN rules).
- [ ] **URL inventory.** Export every URL that matters from the sitemap, analytics (top pages by traffic), search console (pages with impressions) and server logs. Merge into a single `urls.txt`. This is the input for `sitecheckup compare --urls-file`.
- [ ] **Baseline.** Run the tools against the old site *before* touching anything and keep the output:
  ```bash
  sitecheckup audit https://www.maple-crumb.example --i-have-permission -o baseline-audit.html
  ```
  Note current response times for the ten most important pages. A "slower than before" claim needs a "before".
- [ ] **Freeze window.** Agree when content editing stops, and what happens to orders and form submissions during cutover.
- [ ] **Staging copy.** A full copy of the new site reachable on a private hostname (`new.maple-crumb.test`) that is **blocked from search engines** (HTTP auth is more reliable than `noindex`, which tends to ship to production by accident).

## 2. Redirect mapping

Decide what happens to every old URL **before** launch.

| Situation | Action |
| --- | --- |
| URL is unchanged | Nothing to do; `compare` confirms it |
| URL moves | One 301 straight to the final destination (no chains) |
| Page is retired with a close replacement | 301 to the replacement |
| Page is retired with no replacement | 410 (or 404); do not redirect everything to the homepage |
| Query-string or case variants | Normalise once, at the edge |

Write the intentional changes to `redirects.csv` (`old_path,new_path`); `compare --path-map redirects.csv` treats them as expected. Keep the file in version control: it is the contract between whoever configures the redirects and whoever validates them.

Rules of thumb: redirects at the edge (server or CDN) rather than in application code; permanent redirects (301/308) for permanent moves; at most one hop; test trailing-slash and `http` -> `https` combinations.

## 3. SEO preservation

- [ ] Titles, meta descriptions, `<h1>`, canonical URLs and structured data carried over (or deliberately changed and documented).
- [ ] Canonicals point at the **new** host. A canonical still naming the old host is one of the most common silent failures.
- [ ] No `noindex` on the new site (meta tag or `X-Robots-Tag`), no `Disallow: /` in `robots.txt`.
- [ ] Sitemap regenerated and referenced from `robots.txt`.
- [ ] Analytics and tag manager present and firing.
- [ ] Search Console property verified for the new host (and for the old one, to watch the transition).

## 4. DNS and TTL plan

- [ ] **T-48h:** lower the TTL on the records you will change (for example 3600 -> 300 seconds). Remember the *old* TTL must elapse before the lower value takes effect everywhere.
- [ ] **T-0:** change the records. Keep the old server running and serving the old site.
- [ ] **T+24-72h:** raise the TTL back; keep the old server up until traffic and error logs show it is idle.
- [ ] Verify with queries against several public resolvers, not just your own.
- [ ] Certificates are issued and valid on the new platform *before* the DNS switch (or use DNS-based validation), so there is no window of browser warnings.

## 5. Rollback plan

Write it before you need it. A rollback plan has: a **trigger** ("conversion drops by more than X for Y hours", "checkout returns 5xx", "any blocking `compare` result we cannot fix within 30 minutes"), a **decision owner**, the **exact steps** (restore DNS to the recorded values, re-enable the old site, restore the old database snapshot if writes happened), and a **time estimate**. Take database and file snapshots immediately before cutover and record where they are.

## 6. Cutover day

1. Announce start in the agreed channel (see the [status-update templates](working-with-clients-and-developers.md#status-update-templates)).
2. Final content freeze, take snapshots.
3. Final sync of files and database.
4. Switch DNS (or the CDN origin).
5. Run the post-migration validation below.
6. Announce result; keep the rollback window open for the agreed period.

## 7. Post-migration validation with `compare`

```bash
sitecheckup compare https://old.maple-crumb.example https://www.maple-crumb.example \
  --i-have-permission --urls-file urls.txt --path-map redirects.csv \
  --csv results.csv -o migration-report.html --fail-on warning
```

> Compare against the old site **by its old address** (an `old.` hostname, an IP-pinned origin, or a staging copy), because after the DNS switch the public name points at the new site.

Read the report from the top:

| Result | What to do |
| --- | --- |
| **Blocking** `missing_on_new` | Restore the page or add a redirect. Fix before announcing success. |
| **Blocking** `noindex_added`, `canonical_points_to_old_host` | Search-visibility emergencies; fix immediately. |
| **Blocking** `redirect_loop`, `server_error` | Platform bug; usually a rule conflict. |
| **Warning** `redirect_chain_long`, `unexpected_redirect` | Collapse to a single hop. |
| **Warning** `title_changed`, `meta_description_lost` | Decide whether it was intentional; restore if not. |
| **Warning** `slower` | Check caching, image sizes, origin location. |
| **Site-wide** `security_header_lost_sitewide` | Re-add the header at the server or CDN. |

Then audit the new site and compare with the baseline: the grade should be equal or better.

```bash
sitecheckup audit https://www.maple-crumb.example --i-have-permission -o after-audit.html --fail-on high
```

## 8. After launch

- [ ] Monitor 404s in server logs and Search Console for two to four weeks; add redirects for real traffic you missed.
- [ ] Keep the old site read-only for the agreed period, then decommission it, and **remove its DNS records and certificates** so nothing dangles.
- [ ] Re-run `compare` after a week to catch regressions from content edits.
- [ ] Write down what you would do differently. The next migration's checklist is this one plus those notes.
