# WordPress hardening

A prioritised remediation list for a typical self-hosted WordPress site, mapped to `sitecheckup audit` check IDs so a finding in the report leads straight to an action. Work top to bottom: the order is by risk reduced per hour of effort.

> Scope reminder: this is hygiene for a site you own. It does not replace a penetration test, and `audit` only detects *exposure*; it does not test whether your plugins are vulnerable.

## Priority 0: stop the bleeding (same day)

| Check ID | Problem | Fix |
| --- | --- | --- |
| `exposed-env`, `exposed-backups`, `exposed-git` | Credentials, dumps or source code are downloadable | Delete the files, move backups outside the web root, deny dot-files at the web server. **Rotate every secret that was exposed** (database password, salts and keys in `wp-config.php`, API keys): assume they were read. |
| `wp-debug-log` | `wp-content/debug.log` is public | Delete it; set `WP_DEBUG_LOG` to a path outside the web root or disable it; deny `*.log`. |
| `transport-tls-certificate` | Certificate invalid or about to expire | Reissue/renew now; set up automatic renewal and an expiry alert. |
| `transport-https-redirect` | Site reachable over plain HTTP | Add a site-wide 301 to HTTPS at the server or CDN. |

## Priority 1: close the easy doors (this week)

| Check ID | Problem | Fix |
| --- | --- | --- |
| `wp-user-enumeration-rest`, `wp-user-enumeration-author` | Login names are discoverable | Restrict `/wp-json/wp/v2/users` to authenticated requests and block `?author=N`; make sure display names and author slugs differ from login names. |
| `wp-xmlrpc` | `xmlrpc.php` reachable | Block at the server unless an integration needs it (Jetpack, mobile app). |
| `wp-login-exposed` | Login form is public | Two-factor authentication for every admin and editor, rate limiting/WAF rule on `wp-login.php`, strong unique passwords, no `admin` user. Optionally restrict `/wp-admin` by IP/VPN. |
| `exposed-directory-listing`, `exposed-diagnostics` | Index pages, phpinfo, Adminer | Disable auto-index; delete diagnostic files or put them behind VPN and authentication. |
| `transport-hsts` | No/short HSTS | `Strict-Transport-Security: max-age=31536000; includeSubDomains` after confirming every subdomain works over HTTPS. |

## Priority 2: reduce information leakage and browser-side risk (this month)

| Check ID | Problem | Fix |
| --- | --- | --- |
| `headers-csp` | No or weak Content-Security-Policy | Start in report-only mode, fix violations, then enforce. WordPress themes and plugins often need `'unsafe-inline'` initially; tighten gradually. |
| `headers-clickjacking`, `headers-content-type-options`, `headers-referrer-policy`, `headers-permissions-policy`, `headers-cross-origin` | Missing security headers | Set once at the web server or CDN (not in a plugin that can be disabled). |
| `headers-server-disclosure`, `headers-powered-by` | Version banners | `server_tokens off` / `ServerTokens Prod`, `expose_php = Off`. |
| `wp-version-disclosure`, `wp-readme-license` | Version leaks | Remove the generator tag, block `readme.html` and `license.txt`. This is cosmetic; **patching** is what matters. |
| `wp-plugin-theme-disclosure` | Plugin and theme names visible | Expected for most sites; use it as an *inventory*: remove anything unused, update the rest. |
| `cookies-secure`, `cookies-httponly`, `cookies-samesite` | Cookie flags | Usually set in the framework/plugin config or at the proxy. |
| `hygiene-mixed-content` | `http://` resources on HTTPS pages | Search-replace old URLs in the database (with a serialisation-safe tool such as WP-CLI `search-replace`) and fix hard-coded theme URLs. |
| `hygiene-cache-headers` | Missing or unsafe caching | Cache static assets aggressively; mark anything that sets cookies `private`. |
| `hygiene-security-txt`, `hygiene-robots-txt` | Missing | Publish `/.well-known/security.txt` (Contact, Expires) and a sensible `robots.txt`. |

## Priority 3: keep it that way (ongoing)

These are not things `audit` can see, but they decide whether the list above stays fixed.

- [ ] **Updates:** core, plugins and themes on a schedule (weekly review, same-day for security releases). Enable auto-updates for minor core releases.
- [ ] **Least privilege:** few administrators, editors for editors, a separate low-privilege account for daily work, remove accounts of people who left.
- [ ] **File permissions:** the web server user should not be able to write to code directories; disable the theme/plugin editor with `define('DISALLOW_FILE_EDIT', true);`.
- [ ] **Backups:** automated, offsite, encrypted, and *restore-tested*. A backup you have never restored is a hope.
- [ ] **Monitoring:** uptime, certificate expiry, failed-login spikes, file-change detection.
- [ ] **Staging first:** apply updates to a copy, run `sitecheckup compare` between production and staging to spot regressions, then promote.
- [ ] **Re-audit** after every significant change and quarterly otherwise, and track the score over time.

## Using this in CI or as a recurring check

```bash
sitecheckup audit https://www.example.com --i-have-permission --fail-on high -o audit.html
```

`--fail-on high` makes the job fail only for the issues from Priority 0. Tighten to `medium` once the backlog is clear. Use `--skip wp-login-exposed` for notes you have consciously accepted, and record why in the ticket that accepted them.
