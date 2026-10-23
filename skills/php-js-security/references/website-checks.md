# Website (URL) Checks: Passive and Non-Destructive

Run only after the user confirms they own or are authorized to test the site. GET/HEAD only, about 1 request per second, no payloads that change state, no auth brute force.

`scripts/site_probe.sh <url> <scan_dir>` automates steps 1–4. Read its output files, then do 5–7 by hand.

## 1. Transport and TLS
- HTTP redirects to HTTPS (301/308)? HSTS present, with a `max-age` of at least 15552000 and `includeSubDomains`?
- Certificate validity and expiry (`openssl s_client`), TLS 1.0/1.1 still enabled. These are informational unless the site handles credentials over plain HTTP.

## 2. Security headers (on the HTML response)
| Header | Expect | Missing means |
|---|---|---|
| `Content-Security-Policy` | No `unsafe-inline` for scripts; has `object-src 'none'`, `base-uri` | low by itself; raises XSS severity |
| `X-Frame-Options` / CSP `frame-ancestors` | `DENY`/`SAMEORIGIN` | clickjacking (low/medium if there are one-click sensitive actions) |
| `X-Content-Type-Options` | `nosniff` | low |
| `Referrer-Policy` | `strict-origin-when-cross-origin` or stricter | low (higher if tokens appear in URLs) |
| `Permissions-Policy` | present | info |
| `Server` / `X-Powered-By` | no version numbers | info (version disclosure) |

## 3. Cookies
- For each `Set-Cookie`, check `Secure`, `HttpOnly` (session cookies), and `SameSite`. A session cookie without `HttpOnly` combined with any XSS means session theft.

## 4. Exposed files and endpoints (one GET each; record status and size only, do not download large bodies)
```
/.git/HEAD  /.git/config  /.env  /.env.local  /.env.production  /.DS_Store
/composer.json  /composer.lock  /package.json  /vendor/composer/installed.json
/phpinfo.php  /info.php  /test.php  /server-status  /server-info
/wp-config.php.bak  /wp-config.php~  /config.php.bak  /backup.zip  /backup.sql  /db.sql
/.htaccess  /web.config  /robots.txt  /sitemap.xml  /security.txt  /.well-known/security.txt
/_profiler  /telescope  /_ignition/health-check  /horizon  /adminer.php  /phpmyadmin/
/wp-json/wp/v2/users  /xmlrpc.php  /api  /graphql  /swagger.json  /openapi.json  /api-docs
```
- `200` with real content on `.git/`, `.env`, a backup, or `phpinfo` is a finding. Confirm the content type and the first few bytes; do **not** dump secrets into the report (redact).
- A soft-404 that returns 200 for everything: compare against a random path baseline before trusting a 200.
- WordPress: `/wp-json/wp/v2/users` username enumeration is `low`; `xmlrpc.php` with `system.multicall` enabled is `low`/`medium`.

## 5. Client-side JavaScript
- Collect `<script src>` URLs from the homepage and one or two key pages. For each, check the library and version (jQuery, Angular, Bootstrap, lodash, moment) against known-vulnerable versions, and check for SRI on third-party CDNs.
- Fetch first-party bundles and grep for secrets (`sk_live_`, `AKIA`, `AIza` + check whether restricted, `-----BEGIN`, `service_role`), internal hostnames, and `sourceMappingURL` (then check whether the `.map` is served).
- Look for DOM XSS sinks fed by `location`/`postMessage` (see `javascript-checklist.md`). Confirm them in the code; do not fire payloads at production.

## 6. CORS
- Send one GET to an API endpoint with `Origin: https://evil.example`. Reflected `Access-Control-Allow-Origin: https://evil.example` together with `Access-Control-Allow-Credentials: true` is a real issue (high when authenticated data is returned).

## 7. Forms and auth surface (observe only)
- Login, reset, and signup forms: served over HTTPS? CSRF token present? Different error messages for unknown user vs wrong password (enumeration, low)?
- Do not submit credentials or test rate limits on production.

## Correlation with code
If the repository is also in scope, map each live observation to code: the header config location (`.htaccess`, nginx conf, `next.config.js` `headers()`, `vercel.json`/`vercel.ts`, Laravel middleware) and the file that serves an exposed path. Provide the fix in that file.
