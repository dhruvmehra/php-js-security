# JavaScript / TypeScript Vulnerability Checklist

Covers both server side (Node, Express, Next.js, Nest, serverless) and client side (React, Vue, Angular, jQuery, vanilla).

**Server sources**: `req.query req.body req.params req.headers req.cookies`, Next.js `searchParams`/`params`/server action args, webhook bodies, WebSocket messages, queue messages.
**Client sources**: `location.hash/search/href`, `document.referrer`, `document.URL`, `window.name`, `postMessage` event data, `localStorage`/`sessionStorage`, URL params read by routers, API responses that echo user data.

---

## Server side

### Injection
- **SQL (CWE-89)**: template strings or `+` concatenation into `query(`, `execute(`, `knex.raw`, `sequelize.query`, `prisma.$queryRawUnsafe`/`$executeRawUnsafe`, `typeorm .query(`. Safe: placeholders (`?`, `$1`), tagged `` prisma.$queryRaw`...` ``, query builders.
- **NoSQL (CWE-943)**: `find(req.body)`, `findOne({ user: req.body.user })` where the body can contain `{"$ne": null}` or `$where`/`$regex`. Safe: cast to string, `mongo-sanitize`, schema validation (zod/joi) before the query.
- **Command (CWE-78)**: `child_process.exec|execSync|spawn(..., {shell:true})` with user input. `execFile`/`spawn` with an args array and no shell is safe if the binary is fixed (watch for argument injection such as `--` flags).
- **Code (CWE-94)**: `eval(`, `new Function(`, `vm.runInNewContext` (not a sandbox), `setTimeout(string)`, `require(userInput)`, `import(userInput)`.
- **Template / SSTI (CWE-1336)**: `ejs.render(userTemplate)`, `pug.compile(user)`, `handlebars.compile(user)`, lodash `_.template(user)`. EJS `<%-` with user data is XSS.

### Prototype pollution (CWE-1321)
- Deep merge, clone, or set helpers with user JSON: `_.merge`, `_.set`, `_.defaultsDeep` (old lodash), `$.extend(true, ...)`, hand-rolled `merge(target, src)` that iterates keys without blocking `__proto__`/`constructor`/`prototype`, `qs` with `allowPrototypes`.
- Impact is real only with a gadget (e.g. a polluted `shell`, `env`, or `outputFunctionName` in EJS, or an options object). Report the gadget along with it.

### Path traversal (CWE-22)
- `fs.readFile|createReadStream|sendFile|res.download|path.join(base, req.*)` without a `path.resolve` + `startsWith(base + path.sep)` check. `path.join` does **not** prevent `../`. `express.static` is fine; custom file servers are suspect.
- Archive extraction (`adm-zip`, `unzipper`, `tar`) without an entry-path check means zip slip.

### SSRF (CWE-918)
- `fetch|axios|got|request|http.get(userUrl)`, image/PDF renderers (puppeteer `page.goto(userUrl)`), webhooks, and link previews. Check for an allowlist, private/metadata IP blocking *after DNS resolution*, and redirect handling.

### AuthN / AuthZ (CWE-287, CWE-862, CWE-639)
- Routes missing auth middleware. Check the router order: `app.use(auth)` registered *after* some routes leaves those routes public.
- Next.js: `middleware.ts` `matcher` that misses API routes; server actions and route handlers without a session check (middleware alone is not authorization); `getServerSideProps` returning other users' data.
- IDOR: `findById(req.params.id)` without an owner or tenant filter.
- JWT: `jwt.decode` used instead of `verify`, `algorithms` not pinned, `none` accepted, secret in the repo or a weak secret, no expiry check.
- Mass assignment: `User.update(req.body)` / `new User(req.body)` that lets users set `role`/`isAdmin`.
- Password storage: plain `crypto.createHash('sha256')` instead of bcrypt/argon2/scrypt. Timing-unsafe token compare (`===` on secrets, use `crypto.timingSafeEqual`).

### Session, cookies, CSRF, CORS
- Cookies set without `httpOnly`, `secure`, `sameSite`. Session secret hardcoded.
- Cookie-authenticated state-changing routes without CSRF protection (no token, `sameSite=none`, accepts form-encoded bodies).
- CORS: `origin: true` or reflecting `req.headers.origin` together with `credentials: true` (credentialed cross-origin reads, high impact). Weak regexes like `/example\.com/` also match `evil-example.com`.

### Other server issues
- ReDoS (CWE-1333): user input matched against nested-quantifier regexes like `(a+)+`. Report only when it is on a hot request path.
- Open redirect: `res.redirect(req.query.next)`.
- Info leak: stack traces returned in responses, `NODE_ENV` not `production`, verbose error handlers.
- Secrets: API keys in source, in `next.config.js` `env`, or in `NEXT_PUBLIC_*`/`VITE_*`/`REACT_APP_*` variables (these ship to the browser).
- Unsafe deserialization: `node-serialize`, `serialize-javascript` output passed to `eval`, `yaml.load` (js-yaml < 4) with untrusted input.

---

## Client side

### DOM XSS (CWE-79)
- Sinks: `innerHTML`, `outerHTML`, `insertAdjacentHTML`, `document.write`, `$(…).html()`, `$(userString)`, `.append(userHTML)`, `eval`, `setTimeout(string)`, `location = userInput` / `href = userInput` (`javascript:` URLs), `srcdoc`, `Range.createContextualFragment`.
- React: `dangerouslySetInnerHTML`, `href={userUrl}` (React does not block `javascript:` in all versions), `ref.current.innerHTML`.
- Vue: `v-html`. Angular: `bypassSecurityTrust*`, `[innerHTML]` is sanitized but bypass calls are not.
- Safe: `textContent`, framework text binding, DOMPurify with a sane config (check that the version is current and no `ADD_TAGS: ['script']`).
- Trace whether the data comes from the URL, `postMessage`, or the API (stored XSS).

### postMessage (CWE-346)
- `addEventListener('message', e => …)` without checking `e.origin` against an exact allowlist, followed by a sink or a privileged action. `postMessage(data, '*')` carrying tokens.

### Token and secret handling
- JWTs or API keys in `localStorage` combined with any XSS means account takeover (raises the severity of XSS).
- Secret keys in client bundles (Stripe `sk_`, AWS keys, service-role Supabase/Firebase admin keys). Publishable keys (`pk_`, Firebase web config) are fine.
- Source maps (`*.js.map`) deployed to production expose source. Usually `low`, unless they reveal secrets.

### Third-party scripts and supply chain
- `<script src>` from CDNs without `integrity=` (SRI). Outdated jQuery (< 3.5 has `htmlPrefilter` XSS), Angular.js 1.x (sandbox escapes), old Bootstrap (< 3.4.1/4.3.1 has data-attribute XSS), lodash < 4.17.21.
- `npm audit`: treat a vulnerability as a finding only if the vulnerable API is used. Prioritize runtime dependencies over devDependencies. Check `postinstall` scripts of unfamiliar packages, and typosquat-looking names.

### Clickjacking and framing
- Pages with sensitive one-click actions and no `frame-ancestors`/`X-Frame-Options` protection. Usually `low`/`medium`.
