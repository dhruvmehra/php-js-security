# Severity Policy

Assign severity **after** the attack path and counterevidence are written down. Apply it mechanically, and do not re-argue it later.

## Critical (immediate, likely, severe)
Requires a realistic attacker, an in-scope surface (usually unauthenticated or any-user), a clear path, and compromise-level impact:
- RCE: command injection, `eval`/`unserialize` gadget, LFI→RCE, executable upload in the web root
- SQL injection reachable without auth or by any user, exposing or modifying sensitive data
- Authentication bypass or account takeover (predictable reset tokens, JWT `none`, `==` hash compare bypass)
- Trivial IDOR or cross-tenant access to PII/PHI/payment data
- Exposed `.env`/`.git`/DB backup on a live site that contains working secrets
- Credentialed CORS reflection on an endpoint that returns sensitive data

## High
- SQLi or IDOR limited to the same tenant, or requiring an authenticated low-privilege user
- Stored XSS that executes for other users or admins, with session or token access or privileged actions
- SSRF that can reach internal services or cloud metadata
- Arbitrary file read of source code or config without proven secrets (proven secrets make it critical)
- CSRF on password/email change, role change, payments, or deleting others' data, when SameSite, tokens, and JSON-only bodies do not mitigate it
- Valid hardcoded credentials giving meaningful access
- Insecure deserialization without a proven gadget chain
- XXE with attacker-controlled XML
- Mass assignment to `role`/`is_admin`

## Medium
- Reflected XSS with realistic victim delivery and a session impact
- IDOR on low-sensitivity data
- CSRF on moderate actions
- Weak password hashing (md5/sha1) with no other exposure path
- Exploitable prototype pollution with a limited gadget
- Vulnerable dependency whose vulnerable function is actually used, with impact below high

## Low / Informational
- Missing security headers, cookie flags, CSP weaknesses (unless they are the deciding factor in a chain)
- Version banners, `X-Powered-By`, directory listing, stack traces, user enumeration
- Open redirect without a token-leak chain
- Self-XSS, alert-box-only XSS with no sensitive context
- Clickjacking on pages without one-click sensitive actions
- Source maps in production (no secrets)
- Vulnerable dependency where the vulnerable code path is not used ("dependency hygiene")
- Rate-limit observations, TLS configuration nits

## Ignore (drop from the report)
- Disproven, unreachable, test/fixture-only, or dead code
- Requires the attacker to already be admin/root/shell (unless privilege escalation itself is the issue)
- Correctness bugs with no security impact
- Speculative chains ("could be dangerous if combined with …" without the "…")

## Adjusters
Push **up** one level: unauthenticated, 0-click, cross-tenant, mass exploitable, healthcare/payment data, admin victim.
Push **down** one level: requires admin, requires unusual victim interaction, internal-network only (per threat model), strong compensating control.

## High/Critical acceptance test (all must be true)
1. The component is in scope and deployed
2. The attacker is realistic for this product
3. The entry point is reachable from an in-scope surface
4. The exploitation path is concrete, not speculative
5. The impact is major
6. A reputable auditor or bug-bounty triager would accept it at that severity
