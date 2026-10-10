# Demo lab

Two tiny nginx-served sites for a fictional bakery ("Maple & Crumb"). All content is
invented. Both listen on localhost only.

| Service | URL | Role |
| --- | --- | --- |
| `legacy-site` | http://localhost:8080 | The "old" site. Deliberately weak, so `audit` has findings. |
| `new-site` | http://localhost:8081 | The "migrated" site, with documented regressions for `compare`. |
| `wordpress` + `mariadb` | http://localhost:8082 | Optional (`--profile wordpress`): a default WordPress install for the WordPress checks. |

```bash
docker compose up -d --build legacy-site new-site
sitecheckup audit   http://localhost:8080 --i-have-permission
sitecheckup compare http://localhost:8080 http://localhost:8081 --i-have-permission --path-map demo/path-map.csv
```

No Docker? `make demo-local` starts the same configuration with a locally installed nginx.

## What `audit` should find on the legacy site

| Check ID | Why |
| --- | --- |
| `transport-https-redirect` | The site only speaks plain HTTP. |
| `headers-csp`, `headers-referrer-policy`, `headers-permissions-policy` | Headers not sent. |
| `headers-server-disclosure`, `headers-powered-by` | `Server: nginx/x.y.z` and `X-Powered-By: PHP/7.4.33`. |
| `cookies-httponly`, `cookies-samesite` | `session_hint` cookie without flags (`cookies-secure` is not evaluated over HTTP). |
| `exposed-env`, `exposed-backups` | Fake `/.env` and `/backup.sql` (served from memory; no secrets are stored in the repo). |
| `exposed-directory-listing` | `autoindex on` for `/uploads/`. |
| `hygiene-cache-headers` | `Cache-Control: public` on a response that sets a cookie. |
| `hygiene-security-txt` | No `security.txt`. |

## What `compare` should find (legacy -> new)

| URL | Expected result | Rule |
| --- | --- | --- |
| `/blog/holiday-hours`, `/old-promo` | **Blocking** | `missing_on_new`: pages were not migrated. |
| `/contact` | **Blocking** | `noindex_added`: a staging `noindex` tag shipped. |
| `/menu` | **Blocking** | `canonical_points_to_old_host`. |
| `/specials` | Warning | `redirect_chain_long` (+ `unexpected_redirect`): three hops, `/specials` -> `/offers` -> `/offers/` -> `/deals`. |
| `/about` | Warning | `title_changed`. |
| `/blog/sourdough-basics` | Warning | `meta_description_lost`. |
| `/gallery` | Warning | `slower`: throttled on the new site. |
| `/our-team` | Blocking without the path map, OK with it | Renamed to `/team`. |
| whole site | Warning (site-wide) | `security_header_lost_sitewide`: `X-Frame-Options` was dropped. |

## WordPress profile

```bash
docker compose --profile wordpress up -d
# finish the 5-minute install at http://localhost:8082, then:
sitecheckup audit http://localhost:8082 --i-have-permission
```

The database password in `docker-compose.yml` is a throwaway value for this local lab.
