#!/usr/bin/env bash
# Passive, non-destructive website probe. GET/HEAD only, ~1 req/sec.
# Usage: site_probe.sh <https://site> <out_dir>
# Only run against sites you own or are authorized to test.
set -uo pipefail

URL="${1:?usage: site_probe.sh <url> <out_dir>}"
OUT="${2:?usage: site_probe.sh <url> <out_dir>}"
BASE="${URL%/}"
HOST="$(printf '%s' "$BASE" | sed -E 's#^https?://##; s#/.*$##')"
UA="php-js-security-scan/1.0 (authorized passive check)"
CURL=(curl -sS --max-time 15 -A "$UA")

mkdir -p "$OUT"
pause() { sleep 1; }

echo "== Homepage headers" | tee "$OUT/headers.txt"
"${CURL[@]}" -D - -o "$OUT/home.html" "$BASE/" >> "$OUT/headers.txt" 2>&1
pause

echo "== HTTP -> HTTPS redirect" > "$OUT/transport.txt"
"${CURL[@]}" -o /dev/null -w 'http://%{url_effective} -> %{http_code} %{redirect_url}\n' "http://$HOST/" >> "$OUT/transport.txt" 2>&1
pause

echo "== TLS certificate" >> "$OUT/transport.txt"
echo | openssl s_client -servername "$HOST" -connect "$HOST:443" 2>/dev/null \
  | openssl x509 -noout -subject -issuer -dates >> "$OUT/transport.txt" 2>&1
for v in tls1 tls1_1; do
  if echo | openssl s_client -"$v" -connect "$HOST:443" -servername "$HOST" >/dev/null 2>&1; then
    echo "WARN: $v accepted" >> "$OUT/transport.txt"
  fi
done

echo "== Security header summary" > "$OUT/header-summary.txt"
for h in strict-transport-security content-security-policy x-frame-options x-content-type-options \
         referrer-policy permissions-policy server x-powered-by set-cookie access-control-allow-origin; do
  line="$(grep -i "^$h:" "$OUT/headers.txt" | tr -d '\r')"
  printf '%-28s %s\n' "$h" "${line:-MISSING}" >> "$OUT/header-summary.txt"
done

# Soft-404 baseline
RAND="/does-not-exist-$RANDOM$RANDOM"
BASELINE="$("${CURL[@]}" -o /dev/null -w '%{http_code} %{size_download}' "$BASE$RAND")"
echo "baseline $RAND -> $BASELINE" > "$OUT/exposed-paths.tsv"
pause

PATHS=(
  /.git/HEAD /.git/config /.env /.env.local /.env.production /.DS_Store
  /composer.json /composer.lock /package.json /vendor/composer/installed.json
  /phpinfo.php /info.php /test.php /server-status /server-info
  /wp-config.php.bak /wp-config.php~ /config.php.bak /backup.zip /backup.sql /db.sql
  /.htaccess /web.config /robots.txt /sitemap.xml /.well-known/security.txt
  /_profiler /telescope /_ignition/health-check /horizon /adminer.php /phpmyadmin/
  /wp-json/wp/v2/users /xmlrpc.php /graphql /swagger.json /openapi.json /api-docs
)
printf 'path\tstatus\tbytes\tcontent_type\tfirst_bytes\n' >> "$OUT/exposed-paths.tsv"
for p in "${PATHS[@]}"; do
  tmp="$(mktemp)"
  meta="$("${CURL[@]}" -r 0-2047 -o "$tmp" -w '%{http_code}\t%{size_download}\t%{content_type}' "$BASE$p")"
  # first 40 printable bytes only; never store full bodies (may contain secrets)
  head_bytes="$(head -c 40 "$tmp" | tr -cd '[:print:]' )"
  printf '%s\t%s\t%s\n' "$p" "$meta" "$head_bytes" >> "$OUT/exposed-paths.tsv"
  rm -f "$tmp"
  pause
done

echo "== Script sources" > "$OUT/scripts.txt"
grep -oiE '<script[^>]+src="[^"]+"[^>]*>' "$OUT/home.html" >> "$OUT/scripts.txt" 2>/dev/null

echo "== CORS reflection (single GET)" > "$OUT/cors.txt"
"${CURL[@]}" -D - -o /dev/null -H 'Origin: https://evil.example' "$BASE/" \
  | grep -iE '^access-control-allow-(origin|credentials)' >> "$OUT/cors.txt" 2>&1

echo "Done. Review: $OUT/{header-summary.txt,transport.txt,exposed-paths.tsv,scripts.txt,cors.txt}"
