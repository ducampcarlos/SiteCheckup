# SiteCheckup compare

- **Old:** http://localhost:8080
- **New:** http://localhost:8081
- **URLs compared:** 11 (source: sitemap, 26 requests)
- **Result:** 4 blocking, 4 warnings, 3 ok
- **Generated:** 2026-10-10 02:21 UTC by SiteCheckup 0.1.0

## Site-wide
- **warning** `security_header_lost_sitewide`: x-frame-options was sent on the old site but is missing on the new one (9 of 9 comparable pages).

## Most common issues

| Issue | URLs |
| --- | ---: |
| `missing_on_new` | 2 |
| `canonical_points_to_old_host` | 1 |
| `meta_description_lost` | 1 |
| `noindex_added` | 1 |
| `redirect_chain_long` | 1 |
| `slower` | 1 |
| `title_changed` | 1 |
| `unexpected_redirect` | 1 |

## Blocking (4)

### `/menu` (200 → 200)

- **blocking** `canonical_points_to_old_host`: Canonical still points at the old host: http://localhost:8080/menu
- **info** `security_header_lost`: Security headers present on old but missing on new: x-frame-options

### `/contact` (200 → 200)

- **blocking** `noindex_added`: The new page is marked noindex; it will drop out of search.
- **info** `security_header_lost`: Security headers present on old but missing on new: x-frame-options

### `/blog/holiday-hours` (200 → 404)

- **blocking** `missing_on_new`: Old site returns 200 but the new site returns 404.

### `/old-promo` (200 → 404)

- **blocking** `missing_on_new`: Old site returns 200 but the new site returns 404.

## Warnings (4)

### `/about` (200 → 200)

- **warning** `title_changed`: Title changed: 'About us \| Maple & Crumb' -> 'Our story \| Maple & Crumb'.
- **info** `security_header_lost`: Security headers present on old but missing on new: x-frame-options

### `/specials` (200 → 200)

- **warning** `redirect_chain_long`: 3 redirects before the final page (limit 2): http://localhost:8081/specials -> http://localhost:8081/offers -> http://localhost:8081/offers/ -> http://localhost:8081/deals
- **warning** `unexpected_redirect`: Old site serves the URL directly; the new site redirects (301) to http://localhost:8081/offers.
- **info** `security_header_lost`: Security headers present on old but missing on new: x-frame-options

### `/blog/sourdough-basics` (200 → 200)

- **warning** `meta_description_lost`: Meta description is missing on the new page.
- **info** `security_header_lost`: Security headers present on old but missing on new: x-frame-options

### `/gallery` (200 → 200)

- **info** `security_header_lost`: Security headers present on old but missing on new: x-frame-options
- **warning** `slower`: Slower on the new site: 2 ms -> 2486 ms (+2484 ms).

## OK (3)
- `/` (200 → 200)
- `/blog/` (200 → 200)
- `/our-team` → `/team` (200 → 200)
