# Security Scan Report: <repo or host>

- **Date**: <YYYY-MM-DD>
- **Mode / scope**: <repo | path:<p> | diff:<base>..<head> | url:<https://…>>
- **Revision**: <git rev-parse HEAD, or "working tree (dirty)">
- **Authorization** (url mode): <who confirmed ownership/authorization>
- **Validation methods used**: <static trace | local PoC | passive HTTP>
- **Tools run**: <composer audit, npm audit, semgrep …, or "none available">

## Summary

| Severity | Count |
|---|---|
| Critical | n |
| High | n |
| Medium | n |
| Low | n |

<2–4 sentences: the most important risk and the first thing to fix.>

## Findings

### [SEV] <ID>: <Title> (CWE-<n>)

- **Location**: `path/to/file.php:42` (sink), `routes/web.php:17` (entrypoint)
- **Confidence**: high | medium | low (<static trace only | PoC reproduced>)
- **Auth required**: none | user | admin  • **Exposure**: internet | internal

**Source → control → sink**
`$_GET['id']` (`app/Http/Controllers/OrderController.php:30`) → no cast or binding → `DB::select("… WHERE id = $id")` (`:42`)

**Attack path**
1. …
2. …
3. Impact: …

**Proof**
```
<PoC command/request and observed result, or the exact proof gap>
```

**Counterevidence considered**
<What could have defeated this (middleware, WAF, casts), and why it doesn't.>

**Fix**
```php
// project-idiomatic patch
```

---

## Dependency hygiene
| Package | Installed | Advisory | Vulnerable code used? | Action |
|---|---|---|---|---|

## Website observations (url mode)
| Check | Result | Severity | Fix location |
|---|---|---|---|

## Checked and clean
- <Area / file group>: <what was checked, why it's safe — e.g. "all 23 DB calls in app/Repositories use Eloquent bindings">

## Not covered / proof gaps
- <Areas deferred, tools unavailable, runtime-only questions for the team>
