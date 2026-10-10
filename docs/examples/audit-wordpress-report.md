# SiteCheckup audit: http://localhost:8082

- **Grade:** F (45/100)
- **Findings:** 1 high, 4 medium, 8 low, 5 info
- **Requests:** 38 · WordPress detected
- **Generated:** 2026-10-10 02:21 UTC by SiteCheckup 0.1.0

## Findings (18)

### [HIGH] HTTP redirects to HTTPS (`transport-https-redirect`)

**Evidence:** http://localhost:8082/ answered 200 over plain HTTP.

Visitors who type or follow an http:// link should be sent to HTTPS immediately; otherwise traffic and cookies can be read or altered in transit.

**Remediation:** Add a site-wide permanent (301/308) redirect from http:// to https:// at the web server or CDN, then enable HSTS once every subdomain works over HTTPS.

References:
- <https://owasp.org/www-project-secure-headers/>
- <https://cheatsheetseries.owasp.org/cheatsheets/Transport_Layer_Security_Cheat_Sheet.html>

### [MEDIUM] Content-Security-Policy is set and not trivially bypassable (`headers-csp`)

**Evidence:** No Content-Security-Policy header.

CSP limits where scripts and other resources may load from, which is the main browser-side mitigation for cross-site scripting. Policies that allow 'unsafe-inline', 'unsafe-eval' or wildcards for scripts give little protection.

**Remediation:** Start with 'Content-Security-Policy-Report-Only', collect violations, then enforce a policy such as "default-src 'self'; script-src 'self'; object-src 'none'; base-uri 'self'; frame-ancestors 'self'".

References:
- <https://developer.mozilla.org/docs/Web/HTTP/Headers/Content-Security-Policy>
- <https://owasp.org/www-project-secure-headers/#content-security-policy>

### [MEDIUM] Clickjacking protection (X-Frame-Options / frame-ancestors) (`headers-clickjacking`)

**Evidence:** Neither X-Frame-Options nor CSP frame-ancestors is set.

Without framing protection another site can embed this one in an invisible frame and trick users into clicking.

**Remediation:** Send "Content-Security-Policy: frame-ancestors 'self'" (preferred) and/or 'X-Frame-Options: SAMEORIGIN' for older browsers.

References:
- <https://developer.mozilla.org/docs/Web/HTTP/Headers/X-Frame-Options>
- <https://owasp.org/www-project-secure-headers/#x-frame-options>

### [MEDIUM] xmlrpc.php is not reachable (`wp-xmlrpc`)

**Evidence:** /xmlrpc.php answers HTTP 405 with the XML-RPC banner.

xmlrpc.php enables password guessing at scale (system.multicall) and pingback abuse. Most sites do not need it. Only a GET is sent; the endpoint's standard 'POST only' answer is enough to prove it is live.

**Remediation:** Block /xmlrpc.php at the web server or with a hardening plugin, unless a specific integration (such as the mobile app or Jetpack) requires it.

References:
- <https://developer.wordpress.org/advanced-administration/security/hardening/>

### [MEDIUM] REST API does not list users publicly (`wp-user-enumeration-rest`)

**Evidence:** Anonymous request to /?rest_route=/wp/v2/users returned 1 user(s): demoadmin

/wp-json/wp/v2/users (or /?rest_route=/wp/v2/users) returns user slugs (often the login name) to anonymous visitors, giving attackers half of every credential pair.

**Remediation:** Restrict the users endpoint to authenticated requests (a small mu-plugin using the rest_endpoints filter, or your security plugin) and make sure login names differ from public author slugs.

References:
- <https://developer.wordpress.org/advanced-administration/security/hardening/>
- <https://developer.wordpress.org/rest-api/reference/users/>

### [LOW] X-Content-Type-Options: nosniff (`headers-content-type-options`)

**Evidence:** Header missing or wrong value: not set

Stops browsers from guessing content types, which can turn uploads into scripts.

**Remediation:** Send 'X-Content-Type-Options: nosniff' on all responses.

References:
- <https://developer.mozilla.org/docs/Web/HTTP/Headers/X-Content-Type-Options>
- <https://owasp.org/www-project-secure-headers/#x-content-type-options>

### [LOW] Referrer-Policy limits URL leakage (`headers-referrer-policy`)

**Evidence:** No Referrer-Policy header.

The Referer header can leak full URLs (including tokens in query strings) to third parties. A restrictive policy keeps that data on your own origin.

**Remediation:** Send 'Referrer-Policy: strict-origin-when-cross-origin' (or stricter).

References:
- <https://developer.mozilla.org/docs/Web/HTTP/Headers/Referrer-Policy>
- <https://owasp.org/www-project-secure-headers/#referrer-policy>

### [LOW] Permissions-Policy is set (`headers-permissions-policy`)

**Evidence:** No Permissions-Policy header.

Permissions-Policy disables browser features (camera, microphone, geolocation...) the site does not need, limiting the impact of injected or third-party content.

**Remediation:** Send e.g. 'Permissions-Policy: camera=(), microphone=(), geolocation=()'.

References:
- <https://developer.mozilla.org/docs/Web/HTTP/Headers/Permissions-Policy>
- <https://owasp.org/www-project-secure-headers/#permissions-policy>

### [LOW] Server header does not disclose a version (`headers-server-disclosure`)

**Evidence:** Server: Apache/2.4.67 (Debian)

Version banners make it trivial to look up known vulnerabilities for the exact software in use.

**Remediation:** Hide versions: 'server_tokens off;' (nginx), 'ServerTokens Prod' and 'ServerSignature Off' (Apache), or strip the header at the CDN/proxy.

References:
- <https://developer.mozilla.org/docs/Web/HTTP/Headers/Server>
- <https://owasp.org/www-project-web-security-testing-guide/>

### [LOW] No framework banner headers (X-Powered-By and friends) (`headers-powered-by`)

**Evidence:** x-powered-by: PHP/8.3.31

Headers such as X-Powered-By, X-AspNet-Version and X-Generator advertise the technology stack and often its version.

**Remediation:** Remove the headers: 'expose_php = Off' for PHP, 'header_remove("X-Powered-By")', or 'proxy_hide_header X-Powered-By;' in nginx.

References:
- <https://developer.mozilla.org/docs/Web/HTTP/Headers/X-Powered-By>

### [LOW] WordPress version is not disclosed (`wp-version-disclosure`)

**Evidence:** generator meta tag: WordPress 6.9.4

The <meta name='generator'> tag advertises the exact WordPress version, which makes targeted attacks against outdated installs easier.

**Remediation:** Remove the generator tag (remove_action('wp_head', 'wp_generator')) and, more importantly, keep core updated so the version does not matter.

References:
- <https://developer.wordpress.org/advanced-administration/security/hardening/>

### [LOW] readme.html / license.txt are not exposed (`wp-readme-license`)

**Evidence:** Reachable: /readme.html, /license.txt

readme.html shows the installed version and confirms the platform.

**Remediation:** Delete readme.html and license.txt (WordPress restores them on updates, so block them at the server instead).

References:
- <https://developer.wordpress.org/advanced-administration/security/hardening/>

### [LOW] Homepage has sensible cache headers (`hygiene-cache-headers`)

**Evidence:** No Cache-Control, Expires, ETag or Last-Modified header.

Responses without any caching headers are re-downloaded every time; responses that set cookies but are marked public can be cached by shared proxies and leak between users.

**Remediation:** Send an explicit Cache-Control: 'public, max-age=...' for static pages, 'private, no-store' for anything personalised or that sets session cookies.

References:
- <https://developer.mozilla.org/docs/Web/HTTP/Caching>

### [INFO] Cross-origin isolation headers (COOP/CORP/COEP) (`headers-cross-origin`)

**Evidence:** Not set: cross-origin-opener-policy, cross-origin-resource-policy, cross-origin-embedder-policy

Cross-Origin-Opener-Policy, Cross-Origin-Resource-Policy and Cross-Origin-Embedder-Policy isolate the page from other origins. They are defence in depth and not required for every site, so this is informational.

**Remediation:** Consider 'Cross-Origin-Opener-Policy: same-origin' and 'Cross-Origin-Resource-Policy: same-site' if the site does not rely on cross-origin popups or embeds.

References:
- <https://developer.mozilla.org/docs/Web/HTTP/Headers/Cross-Origin-Opener-Policy>
- <https://owasp.org/www-project-secure-headers/#cross-origin-opener-policy>

### [INFO] wp-login.php is reachable from the internet (`wp-login-exposed`)

**Evidence:** /wp-login.php serves the login form to anonymous visitors.

The login page is expected on most sites, but it is the main target of password guessing. This is a note, not a vulnerability.

**Remediation:** Add rate limiting or a WAF rule, enforce strong passwords and two-factor authentication, and consider restricting /wp-admin by IP or VPN for editors.

References:
- <https://developer.wordpress.org/advanced-administration/security/hardening/>

### [INFO] Plugin and theme names are not enumerable from page source (`wp-plugin-theme-disclosure`)

**Evidence:** theme:twentytwentyfive

Asset URLs reveal which plugins and themes are installed. This is detection only: SiteCheckup does not look versions up in vulnerability databases. Exposed versions raise the severity to low.

**Remediation:** Keep every plugin and theme updated and remove unused ones. Hiding names is not a substitute for patching.

References:
- <https://developer.wordpress.org/advanced-administration/security/hardening/>

### [INFO] robots.txt is present (`hygiene-robots-txt`)

**Evidence:** /robots.txt -> HTTP 404

robots.txt tells well-behaved crawlers what to skip and where the sitemap is. It is not an access control: never list secret paths in it.

**Remediation:** Publish /robots.txt with a Sitemap: line and sensible Disallow rules.

References:
- <https://developer.mozilla.org/docs/Glossary/Robots.txt>

### [INFO] security.txt is published (`hygiene-security-txt`)

**Evidence:** No security.txt with a Contact field found.

RFC 9116 security.txt gives researchers a clear, private channel to report problems.

**Remediation:** Publish /.well-known/security.txt with Contact: and Expires: fields.

References:
- <https://www.rfc-editor.org/rfc/rfc9116>
- <https://securitytxt.org/>

## Passed
- No exposed .git directory (`exposed-git`): 2 path(s) checked; none exposed.
- No exposed .env file (`exposed-env`): 2 path(s) checked; none exposed.
- No backup or archive files in the web root (`exposed-backups`): 10 path(s) checked; none exposed.
- Directory listing is disabled (`exposed-directory-listing`): 7 path(s) checked; none exposed.
- No diagnostic or admin-tool leftovers (phpinfo, server-status, Adminer) (`exposed-diagnostics`): 5 path(s) checked; none exposed.
- ?author=N does not reveal usernames (`wp-user-enumeration-author`): /?author=1 -> HTTP 200
- wp-content/debug.log is not exposed (`wp-debug-log`): /wp-content/debug.log -> HTTP 404

## Not applicable
- TLS certificate is valid and not close to expiry (`transport-tls-certificate`): Plain-HTTP target on a non-default port; TLS not applicable.
- HSTS is enabled with a long max-age (`transport-hsts`): Homepage is not served over HTTPS; HSTS is ignored on HTTP.
- Cookies have the Secure flag (`cookies-secure`): The homepage sets no cookies.
- Cookies have the HttpOnly flag (`cookies-httponly`): The homepage sets no cookies.
- Cookies declare SameSite (`cookies-samesite`): The homepage sets no cookies.
- No mixed content on the homepage (`hygiene-mixed-content`): Homepage is not served over HTTPS.

---
*Passive automated checks only; this is not a substitute for a professional penetration test.*
