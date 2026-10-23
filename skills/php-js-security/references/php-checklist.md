# PHP Vulnerability Checklist

For each family: where to look, the grep seed, what makes it safe, and what makes it a real finding.

**Sources**: `$_GET $_POST $_REQUEST $_COOKIE $_FILES $_SERVER['HTTP_*'|'REQUEST_URI'|'PHP_SELF'|'QUERY_STRING'] file_get_contents('php://input') getallheaders()`. Framework equivalents include `$request->input()`, `$request->get()`, `Request::all()`, route parameters, `$request->query->get()`, and WordPress `$_REQUEST` and `get_query_var`.

## SQL injection (CWE-89)
- Grep: `mysqli_query|mysql_query|->query\(|->exec\(|pg_query|DB::raw|DB::select\(|whereRaw|orderByRaw|selectRaw|havingRaw|->createQuery\(|\$wpdb->(query|get_results|get_row|get_var)\(`
- Real when user input is concatenated or interpolated into SQL text: `"... WHERE id = $id"`, `"... ORDER BY " . $_GET['sort']`.
- Safe: PDO/mysqli prepared statements with bound params, Eloquent/Doctrine query builders with value bindings, `$wpdb->prepare()` used correctly, `(int)` casts.
- Watch: `ORDER BY`/`LIMIT`/column/table names cannot be bound and need an allowlist. `PDO::ATTR_EMULATE_PREPARES` with odd charsets. `$wpdb->prepare` with `%s` inside quotes. `LIKE` wildcards are a correctness issue, not SQLi.

## Command injection / RCE (CWE-78, CWE-94, CWE-95)
- Grep: `exec\(|shell_exec|system\(|passthru|popen|proc_open|pcntl_exec|` + "`" + ` (backticks) |eval\(|assert\(|create_function|preg_replace\(.*/e|call_user_func(_array)?\(\$|\$\w+\(\$` (variable functions)
- Real when user input reaches the command string or callable name. `escapeshellarg` per argument is safe; `escapeshellcmd` on its own is **not** (argument injection, e.g. `--output=`).
- Variable functions or `call_user_func($_GET['cb'])` mean arbitrary function calls.

## File inclusion / path traversal (CWE-98, CWE-22)
- Grep: `(include|require)(_once)?\s*\(?\s*\$|file_get_contents\(\$|fopen\(\$|readfile\(\$|file\(\$|unlink\(\$|copy\(|rename\(|move_uploaded_file|ZipArchive|PharData|->extractTo`
- Real: `include $_GET['page'] . '.php'` (LFI, and RFI if `allow_url_include` is on), `readfile('uploads/' . $_GET['f'])`.
- Safe: `basename()` plus a fixed directory, or a `realpath()` prefix check against an allowlisted base directory.
- Zip slip: archive entry names containing `../` passed to `extractTo` without a per-entry check.
- `phar://` wrappers on any filesystem function that receives user input mean deserialization (PHP < 8).

## Insecure deserialization (CWE-502)
- Grep: `unserialize\(|maybe_unserialize|phar://|__wakeup|__destruct|__toString`
- Real when any user-influenced string (cookie, POST, cached value from user input, DB value written by a user) reaches `unserialize()` without `['allowed_classes' => false]`. Check for gadget chains in `vendor/` (Monolog, Guzzle, Laravel, Symfony are known chains). Use `json_decode` instead.

## XSS (CWE-79)
- Grep: `echo\s+\$|print\s+\$|<\?=\s*\$|printf\(|{!!.*!!}|\|raw|->addHtml|@php echo`
- Real when user-controlled data is output without `htmlspecialchars($x, ENT_QUOTES, 'UTF-8')`, or with the wrong context escaping (HTML-escaped data inside `<script>`, `href="javascript:"`, unquoted attributes, or `style`).
- Blade `{{ }}` and Twig `{{ }}` auto-escape. Look for `{!! !!}`, `|raw`, `@php echo`, `Html::raw`, and `autoescape false`.
- Stored XSS: trace DB fields written by users and rendered to admins (higher impact).
- `$_SERVER['PHP_SELF']` in form actions is classic reflected XSS.

## Authentication and session (CWE-287, CWE-384, CWE-613)
- Weak password storage: `md5(|sha1(|crypt(` on passwords. Use `password_hash`/`password_verify`.
- Loose comparison: `==` on hashes or tokens (`"0e123" == "0e456"` is true). Use `hash_equals` and `===`.
- `strcmp($_POST['pw'], $pw) == 0` can be bypassed with an array input (`pw[]=`).
- No `session_regenerate_id(true)` after login means session fixation.
- Password reset tokens built from `rand()`/`mt_rand()`/`uniqid()`/`time()` are predictable. Use `random_bytes`.
- "Remember me" cookies holding a user id or a predictable value.
- JWT: `firebase/php-jwt` decode without an algorithm allowlist, `none` alg, or a secret hardcoded in the repo.

## Authorization / IDOR (CWE-284, CWE-639, CWE-862)
- For every route or controller that loads a record by id (`find($id)`, `WHERE id = ?`), confirm it also checks ownership, tenant, or role (`where('user_id', auth()->id())`, policies, `can()`, `current_user_can`).
- Admin routes: check that the middleware or group actually applies (Laravel `Route::middleware`, `$this->middleware()` in the constructor, WordPress `current_user_can` and not just `is_admin()`, which only checks for an admin *page*).
- WordPress AJAX: `wp_ajax_nopriv_*` handlers are unauthenticated.
- Mass assignment: `Model::create($request->all())` or `->fill($request->all())` with `$guarded = []`, which lets users set `is_admin`, `role`, or `tenant_id`.

## CSRF (CWE-352)
- State-changing POST routes without a token. In Laravel, check `VerifyCsrfToken::$except`. In WordPress, check for missing `check_admin_referer`/`wp_verify_nonce`. In plain PHP, check for any token at all.
- State changes performed over GET.

## SSRF (CWE-918)
- Grep: `curl_setopt\(.*CURLOPT_URL|file_get_contents\(\$|fopen\(\$.*http|Http::get\(|Guzzle|->request\(|get_headers\(|simplexml_load_file`
- Real when the user controls the URL or host. Check for an allowlist, blocking of private, loopback, and metadata IPs (169.254.169.254), redirect following (`CURLOPT_FOLLOWLOCATION`), and scheme limits (`file://`, `gopher://`, `dict://`).

## File upload (CWE-434)
- Trace `$_FILES` through `move_uploaded_file`. It is real if the extension or MIME type comes from the client (`$_FILES['f']['type']` is attacker-set), the file lands in the web root with its original name or extension, or a `.php`/`.phtml`/`.phar`/`.htaccess` upload is possible.
- Safe: server-side MIME check (`finfo`), extension allowlist, random filename, storage outside the web root or with execution disabled.

## XXE (CWE-611)
- Grep: `simplexml_load_string|DOMDocument|->loadXML|XMLReader|LIBXML_NOENT|libxml_disable_entity_loader`
- Real when parsing user XML with `LIBXML_NOENT`/`LIBXML_DTDLOAD`, or on PHP < 8 without `libxml_disable_entity_loader(true)`.

## Open redirect (CWE-601)
- `header('Location: ' . $_GET['next'])`, `redirect($request->input('url'))`. Usually `low`, unless it is chained into an OAuth token leak.

## Header / mail injection (CWE-93)
- `header("...$input")` with CRLF (older PHP), `mail($to, $subj, $msg, "From: $input")`.

## Crypto and secrets (CWE-321, CWE-327, CWE-330, CWE-798)
- Hardcoded keys, DB passwords, or API tokens in `.php`, `config/*.php`, or a committed `.env`.
- `rand()`/`mt_rand()`/`uniqid()`/`lcg_value()` used for tokens. Use `random_bytes`/`random_int`.
- `openssl_encrypt` with ECB mode or a static IV; `mcrypt_*`.

## Type juggling and logic
- `in_array($x, $list)` without strict mode, `switch` on strings, `array_search` returning `0`, and `==` between user input and stored secrets.
- `extract($_POST)` / `parse_str($q)` without a second argument / `$$var` means variable overwrite.

## Configuration and exposure
- `display_errors=On` in production config, `phpinfo()` reachable, debug routes (`/telescope`, `/_profiler`, `/_ignition`, Laravel `APP_DEBUG=true`).
- `.git`, `.env`, `composer.json`, `*.bak`, `*.swp` inside the web root.
- Old PHP version (EOL) in `composer.json` `require.php` or a Dockerfile.

## PHP runtime version (PHP2Shell and other runtime CVEs)
- Find the PHP version that gets deployed: `Dockerfile` (`FROM php:`), `composer.json` `require.php` / `config.platform.php`, CI images, IaC, `.tool-versions`, hosting config. Compare it with `references/php2shell.md`. A deployed affected branch is **critical**, and the fix is a version bump in that file.

## Dependencies
- Run `composer audit`. A vulnerable package is a finding only if the vulnerable function or feature is used or reachable. Otherwise list it under "dependency hygiene" at `low`/info.
