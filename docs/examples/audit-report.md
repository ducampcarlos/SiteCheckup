# SiteCheckup audit: http://localhost:8080

- **Grade:** F (17/100)
- **Findings:** 3 high, 5 medium, 4 low, 2 info
- **Requests:** 30
- **Generated:** 2026-10-10 02:21 UTC by SiteCheckup 0.1.0

## Findings (14)

### [HIGH] HTTP redirects to HTTPS (`transport-https-redirect`)

**Evidence:** http://localhost:8080/ answered 200 over plain HTTP.

Visitors who type or follow an http:// link should be sent to HTTPS immediately; otherwise traffic and cookies can be read or altered in transit.

**Remediation:** Add a site-wide permanent (301/308) redirect from http:// to https:// at the web server or CDN, then enable HSTS once every subdomain works over HTTPS.

References:
- <https://owasp.org/www-project-secure-headers/>
- <https://cheatsheetseries.owasp.org/cheatsheets/Transport_Layer_Security_Cheat_Sheet.html>

### [HIGH] No exposed .env file (`exposed-env`)

**Evidence:** /.env -> HTTP 200, 88 bytes (contents deliberately not recorded)

Environment files commonly hold database passwords, API keys and app secrets.

**Remediation:** Move the file outside the web root or deny access to it, then rotate every secret it contained: assume it was read.

References:
- <https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/02-Configuration_and_Deployment_Management_Testing/04-Review_Old_Backup_and_Unreferenced_Files_for_Sensitive_Information>

### [HIGH] No backup or archive files in the web root (`exposed-backups`)

**Evidence:** /backup.sql -> HTTP 200, 136 bytes (contents deliberately not recorded)

Database dumps, archives and *.bak copies of configuration files are downloadable by anyone who guesses the name, and often contain credentials or full site content.

**Remediation:** Delete the files, store backups outside the web root, and add a deploy-time check that fails if archives or *.bak/*.old/*~ files appear in the published directory.

References:
- <https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/02-Configuration_and_Deployment_Management_Testing/04-Review_Old_Backup_and_Unreferenced_Files_for_Sensitive_Information>

### [MEDIUM] Content-Security-Policy is set and not trivially bypassable (`headers-csp`)

**Evidence:** No Content-Security-Policy header.

CSP limits where scripts and other resources may load from, which is the main browser-side mitigation for cross-site scripting. Policies that allow 'unsafe-inline', 'unsafe-eval' or wildcards for scripts give little protection.

**Remediation:** Start with 'Content-Security-Policy-Report-Only', collect violations, then enforce a policy such as "default-src 'self'; script-src 'self'; object-src 'none'; base-uri 'self'; frame-ancestors 'self'".

References:
- <https://developer.mozilla.org/docs/Web/HTTP/Headers/Content-Security-Policy>
- <https://owasp.org/www-project-secure-headers/#content-security-policy>

### [MEDIUM] Cookies have the HttpOnly flag (`cookies-httponly`)

**Evidence:** Cookies without HttpOnly: session_hint

HttpOnly hides a cookie from JavaScript, so an XSS bug cannot steal it. Session-like cookie names raise the severity.

**Remediation:** Set HttpOnly on session and authentication cookies.

References:
- <https://developer.mozilla.org/docs/Web/HTTP/Cookies#restrict_access_to_cookies>
- <https://owasp.org/www-community/controls/SecureCookieAttribute>

### [MEDIUM] Cookies declare SameSite (`cookies-samesite`)

**Evidence:** Cookies without a safe SameSite: session_hint

SameSite=Lax or Strict stops browsers attaching the cookie to cross-site requests, reducing cross-site request forgery. SameSite=None requires Secure.

**Remediation:** Set 'SameSite=Lax' (or 'Strict' where possible) on cookies.

References:
- <https://developer.mozilla.org/docs/Web/HTTP/Cookies#samesite_attribute>
- <https://owasp.org/www-community/controls/SecureCookieAttribute>

### [MEDIUM] Directory listing is disabled (`exposed-directory-listing`)

**Evidence:** /uploads/ -> HTTP 200, 270 bytes

Directory indexes reveal file names (backups, exports, uploads) that should not be discoverable.

**Remediation:** Disable auto-indexing ('autoindex off;' in nginx, 'Options -Indexes' in Apache).

References:
- <https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/02-Configuration_and_Deployment_Management_Testing/04-Review_Old_Backup_and_Unreferenced_Files_for_Sensitive_Information>

### [MEDIUM] Homepage has sensible cache headers (`hygiene-cache-headers`)

**Evidence:** Response sets cookies but is publicly cacheable: public, max-age=300

Responses without any caching headers are re-downloaded every time; responses that set cookies but are marked public can be cached by shared proxies and leak between users.

**Remediation:** Send an explicit Cache-Control: 'public, max-age=...' for static pages, 'private, no-store' for anything personalised or that sets session cookies.

References:
- <https://developer.mozilla.org/docs/Web/HTTP/Caching>

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

**Evidence:** Server: nginx/1.27.5

Version banners make it trivial to look up known vulnerabilities for the exact software in use.

**Remediation:** Hide versions: 'server_tokens off;' (nginx), 'ServerTokens Prod' and 'ServerSignature Off' (Apache), or strip the header at the CDN/proxy.

References:
- <https://developer.mozilla.org/docs/Web/HTTP/Headers/Server>
- <https://owasp.org/www-project-web-security-testing-guide/>

### [LOW] No framework banner headers (X-Powered-By and friends) (`headers-powered-by`)

**Evidence:** x-powered-by: PHP/7.4.33

Headers such as X-Powered-By, X-AspNet-Version and X-Generator advertise the technology stack and often its version.

**Remediation:** Remove the headers: 'expose_php = Off' for PHP, 'header_remove("X-Powered-By")', or 'proxy_hide_header X-Powered-By;' in nginx.

References:
- <https://developer.mozilla.org/docs/Web/HTTP/Headers/X-Powered-By>

### [INFO] Cross-origin isolation headers (COOP/CORP/COEP) (`headers-cross-origin`)

**Evidence:** Not set: cross-origin-opener-policy, cross-origin-resource-policy, cross-origin-embedder-policy

Cross-Origin-Opener-Policy, Cross-Origin-Resource-Policy and Cross-Origin-Embedder-Policy isolate the page from other origins. They are defence in depth and not required for every site, so this is informational.

**Remediation:** Consider 'Cross-Origin-Opener-Policy: same-origin' and 'Cross-Origin-Resource-Policy: same-site' if the site does not rely on cross-origin popups or embeds.

References:
- <https://developer.mozilla.org/docs/Web/HTTP/Headers/Cross-Origin-Opener-Policy>
- <https://owasp.org/www-project-secure-headers/#cross-origin-opener-policy>

### [INFO] security.txt is published (`hygiene-security-txt`)

**Evidence:** No security.txt with a Contact field found.

RFC 9116 security.txt gives researchers a clear, private channel to report problems.

**Remediation:** Publish /.well-known/security.txt with Contact: and Expires: fields.

References:
- <https://www.rfc-editor.org/rfc/rfc9116>
- <https://securitytxt.org/>

## Passed
- Clickjacking protection (X-Frame-Options / frame-ancestors) (`headers-clickjacking`): X-Frame-Options: SAMEORIGIN
- X-Content-Type-Options: nosniff (`headers-content-type-options`): nosniff
- No exposed .git directory (`exposed-git`): 2 path(s) checked; none exposed.
- No diagnostic or admin-tool leftovers (phpinfo, server-status, Adminer) (`exposed-diagnostics`): 5 path(s) checked; none exposed.
- robots.txt is present (`hygiene-robots-txt`): 77 bytes

## Not applicable
- TLS certificate is valid and not close to expiry (`transport-tls-certificate`): Plain-HTTP target on a non-default port; TLS not applicable.
- HSTS is enabled with a long max-age (`transport-hsts`): Homepage is not served over HTTPS; HSTS is ignored on HTTP.
- Cookies have the Secure flag (`cookies-secure`): Homepage is served over HTTP, where Secure cannot take effect.
- WordPress version is not disclosed (`wp-version-disclosure`): WordPress was not detected on the homepage.
- xmlrpc.php is not reachable (`wp-xmlrpc`): WordPress was not detected on the homepage.
- REST API does not list users publicly (`wp-user-enumeration-rest`): WordPress was not detected on the homepage.
- ?author=N does not reveal usernames (`wp-user-enumeration-author`): WordPress was not detected on the homepage.
- readme.html / license.txt are not exposed (`wp-readme-license`): WordPress was not detected on the homepage.
- wp-content/debug.log is not exposed (`wp-debug-log`): WordPress was not detected on the homepage.
- wp-login.php is reachable from the internet (`wp-login-exposed`): WordPress was not detected on the homepage.
- Plugin and theme names are not enumerable from page source (`wp-plugin-theme-disclosure`): WordPress was not detected on the homepage.
- No mixed content on the homepage (`hygiene-mixed-content`): Homepage is not served over HTTPS.

---
*Passive automated checks only; this is not a substitute for a professional penetration test.*
