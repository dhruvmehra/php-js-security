# PHP2Shell: CVE-2026-109618 / CVE-2026-109619 (disclosed 2026-10-21)

Critical (CVSS v4 9.2) flaws in the PHP runtime itself, not in application code. They can be exploited without authentication against any PHP that serves HTTP: mod_php, PHP-FPM, php-cgi, FrankenPHP, LiteSpeed. Exploitation was seen in the wild from 2026-10-17. Exploitation happens before application code runs, so app-level auth and filtering do not protect against it.

## Affected and fixed versions
| Branch | Fixed in |
|---|---|
| 8.5 | 8.5.12 |
| 8.4 | 8.4.27 |
| 8.3 | 8.3.36 |
| 8.2 | 8.2.35 |
| 7.4–8.1 | Source backports only; check your distro or LTS vendor |
| 5.4–7.3 | EOL, no fix: upgrade the branch |

Distro packages (Debian/Ubuntu/RHEL) may ship the fix without changing the upstream version number. Compare against the distro security advisory, not only the version string.

## What this skill can and cannot tell

- **From the website (url mode):** only a hint. If `X-Powered-By: PHP/x.y.z` reveals an affected version, flag the host as **likely affected (high confidence that patching is needed)**. If no version is shown (common, since `expose_php=Off`), report "PHP detected/suspected, version unknown, verify on the server". **Never** send exploit traffic to confirm.
- **From the server (authoritative):** ask the user to run these and paste the output, or run them in a session on that server:
  - Version of the *web* runtime, not just the CLI: `php-fpm -v` / `php-fpm8.x -v`, `apache2ctl -M | grep php` plus `dpkg -l | grep php` or `rpm -qa | grep php`, a container's `docker exec <c> php -v`.
  - `php -i | grep -E 'session.upload_progress.enabled|memory_limit|fatal_error_backtraces'`
  - Hosting panels (Plesk, cPanel) and managed hosts: check the vendor advisory or ask the provider.
- **From the repo:** check `Dockerfile` (`FROM php:8.x...`), `composer.json` `require.php`/`config.platform.php`, CI images, and IaC for the PHP version that gets deployed.

## Indicators to look for in logs since 2026-10-17
- `PHP Fatal error: Allowed memory size ... exhausted` reported at `Unknown on line 0`
- Apache or PHP-FPM worker `Segmentation fault (11)` or unexpected worker restarts
- Unusually large urlencoded POST requests to arbitrary `.php` URLs
- The web server user starting `sh`/`bash`/`curl`/`wget`

Any of these means: treat it as a potential compromise, not just a patching task. Preserve logs and escalate.

## Remediation
1. Upgrade PHP to a fixed release (or the distro-patched package) and **restart every PHP worker** (FPM pools, Apache).
2. Stopgaps if patching must wait (they reduce, not remove, risk): set `session.upload_progress.enabled=0` (and `fatal_error_backtraces=0` on 8.5) in the main php.ini, restart workers, put sites behind a WAF with PHP2Shell rules (e.g. Cloudflare managed rules), cap request body sizes at the proxy, and restrict public exposure of non-essential PHP apps.

## Report severity
- Confirmed affected version on an internet-facing host: **critical**
- PHP detected but version unknown: **high, needs verification** (list it under proof gaps with the exact server commands above)
