# php-js-security

A [Claude Code](https://claude.com/claude-code) skill that finds security vulnerabilities in **PHP and JavaScript/TypeScript code** and does **non-destructive checks of websites you own**, including every subdomain. It also checks whether you're affected by **PHP2Shell (CVE-2026-109618 / CVE-2026-109619)**.

Ask in plain English, e.g. *"scan this repo"* or *"scan example.com and its subdomains"*. You get a report with severity ratings, file:line or URL evidence, and fixes written for your framework.

---

## Install

**Option A: just for you**
```bash
git clone <this-repo-url> ~/.claude/skills/php-js-security
```

**Option B: for everyone working in a repository.** Commit the skill into the repo:
```bash
mkdir -p .claude/skills
git clone <this-repo-url> .claude/skills/php-js-security
rm -rf .claude/skills/php-js-security/.git
git add .claude/skills/php-js-security && git commit -m "Add php-js-security skill"
```

Start a new Claude Code session after installing. Check that it's loaded by typing `/php-js-security`.

**Requirements:** Claude Code, Python 3.8+ (standard library only), `bash`, `curl`, `openssl`. Optional tools that are used if already installed (the skill never installs anything): `composer`, `npm`/`pnpm`/`yarn`, `semgrep`, `psalm`, `phpstan`.

---

## Usage

Open Claude Code (inside your repo if you want code scanned) and ask:

| What you want | Say |
|---|---|
| Scan a whole codebase | `/php-js-security scan this repo` |
| Scan one folder | `/php-js-security scan app/Http` |
| Review your changes before merging | `/php-js-security scan my diff against main` |
| Scan a website and all subdomains | `/php-js-security scan example.com and its subdomains` |
| PHP2Shell check | `/php-js-security are we affected by PHP2Shell on example.com?` |
| Code and website together | `/php-js-security scan this repo and example.com` |

Results appear in the chat. The full report is saved to `~/security-scans/<target>/<date-time>/report.md`.

---

## What it checks

### Code (repo / path / diff)
Claude reads the code and traces untrusted input to dangerous operations, then confirms each finding before reporting it.

- **PHP:** SQL injection, command injection / RCE, `eval`/`unserialize`, file inclusion and path traversal, XSS (including Blade `{!! !!}` / Twig `|raw`), missing authorization / IDOR, mass assignment, CSRF, SSRF, file upload, XXE, weak password hashing, loose `==` comparisons, hardcoded secrets, debug/config exposure, and vulnerable Composer packages. Covers Laravel, Symfony, WordPress, and plain PHP.
- **JavaScript/TypeScript:** SQL/NoSQL/command/code injection, prototype pollution, path traversal, SSRF, auth/JWT mistakes, missing authorization in Express/Next.js routes and server actions, CORS misconfiguration, DOM XSS (`innerHTML`, `dangerouslySetInnerHTML`, `v-html`), `postMessage` handling, secrets in client bundles, and vulnerable npm packages.
- **Runtime:** the PHP version deployed by your Dockerfile, `composer.json` and CI, compared with known critical CVEs.

### Website (domain mode)
1. **Find subdomains** from public certificate-transparency logs plus DNS. This sends nothing to your servers.
2. **You confirm the host list.** Nothing is crawled until you approve it.
3. **Crawl each live host:** up to 50 pages per host by default, about 1 request/second, one host at a time.
4. **Check each host for:** exposed `.env` / `.git` / backups / `phpinfo`, security headers, cookie flags, POST forms with no CSRF token, leaked API keys in page source and JS bundles (redacted in the report), third-party scripts without integrity hashes, source maps, CORS reflection, TLS/HTTPS setup, and PHP version banners.
5. **One combined report.** The same issue on several hosts is grouped into one finding.

---

## Safety

The website mode is **look-only by design**:

- It asks you to confirm that you own the domain or have written authorization before it sends any request, and records your answer in the report.
- It only contacts hosts under the domain you confirmed.
- It uses GET/HEAD requests only, follows robots.txt, and never submits forms or logs in. It skips logout links.
- It sends no exploit payloads, brute forcing or load testing.
- It doesn't use found credentials; it reports them redacted.
- It never edits your code during a scan. Fixes are offered at the end and applied only if you ask.

**Only scan websites you own or are explicitly authorized to test.** Unauthorized scanning may be illegal where you live.

Because of these limits, it **cannot confirm** issues like SQL injection on a live site. Those are found by scanning the code. It is not a replacement for a professional penetration test.

---

## PHP2Shell (CVE-2026-109618 / CVE-2026-109619)

These are critical PHP runtime flaws that can be exploited without logging in, disclosed 2026-10-21 and exploited in the wild. You're **safe on these versions or newer: 8.5.12, 8.4.27, 8.3.36, 8.2.35**. PHP 8.1 and older need distro or vendor patches or an upgrade.

Most sites hide their PHP version, so a website scan often can't decide this either way. The authoritative check is on the server:

```bash
php-fpm -v            # or: docker exec <container> php -v
dpkg -l | grep php    # Debian/Ubuntu   (rpm -qa | grep php on RHEL)
```

Paste the output into Claude and the skill will tell you whether you're affected. See [`references/php2shell.md`](references/php2shell.md) for log indicators and temporary mitigations.

---

## How it works

The skill runs four steps and reports a finding only if it survives all of them:

1. **Threat model:** what's valuable, who the attackers are, and where the trust boundaries are.
2. **Discovery:** grep and audit passes to seed leads, then a line-by-line review of high-risk files (split across parallel subagents for large repos).
3. **Validation:** each candidate is traced from untrusted input to the dangerous operation, with a local proof-of-concept where that's cheap. Disproven candidates are dropped.
4. **Severity:** the attack path is written out, counterevidence is checked, and severity follows a strict policy. Missing headers or version banners stay *low* unless they're part of a real attack chain.

## Repository layout

```
SKILL.md                         # Instructions Claude follows
references/
  php-checklist.md               # PHP vulnerability patterns: risky vs. safe code
  javascript-checklist.md        # JS/TS (server + browser) patterns
  website-checks.md              # What the website mode looks at
  severity.md                    # Severity policy
  php2shell.md                   # CVE-2026-109618/109619 guidance
  report-template.md             # Report format
scripts/
  discover_hosts.py              # Subdomain discovery (CT logs + DNS)
  crawl_site.py                  # Polite same-host crawler
  site_probe.sh                  # Headers, TLS, exposed files, CORS for one host
  summarize.py                   # Combines results; flags affected PHP versions
```

The scripts can also be run by hand, e.g. `python3 scripts/crawl_site.py https://example.com ./out --max-pages 20`.

## Customizing

- **Crawl more pages:** ask for it ("crawl up to 200 pages per host"), or change `--max-pages` in `SKILL.md`.
- **Add a new CVE:** add a reference file like `php2shell.md`, link it from `SKILL.md`, and add its fixed versions to `scripts/summarize.py`.
- **Add checks:** extend the checklists in `references/`. Claude reads them at scan time.
