#!/usr/bin/env python3
"""Polite same-host crawler that records security-relevant observations.

GET only, respects robots.txt, 1 request/sec by default, never submits forms.
Records per page: status, security headers, Set-Cookie flags, PHP/server
version banners, script sources (with SRI), forms (method/action/CSRF-like
field present), inline secret-looking strings (redacted), mixed content.

Usage: crawl_site.py <https://host> <out_dir> [--max-pages 50] [--delay 1.0]
Writes: <out_dir>/<host>/crawl.json
"""
import argparse
import json
import os
import re
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
import urllib.robotparser
from html.parser import HTMLParser

UA = "php-js-security-scan/1.0 (authorized passive check)"
SEC_HEADERS = [
    "strict-transport-security", "content-security-policy", "x-frame-options",
    "x-content-type-options", "referrer-policy", "permissions-policy",
]
BANNER_HEADERS = ["server", "x-powered-by", "x-generator", "x-aspnet-version"]
SKIP_EXT = re.compile(r"\.(png|jpe?g|gif|svg|webp|ico|pdf|zip|gz|mp4|mp3|woff2?|ttf|eot|css)$", re.I)
SECRET_PATTERNS = {
    "aws_access_key": r"AKIA[0-9A-Z]{16}",
    "stripe_secret": r"sk_live_[0-9a-zA-Z]{10,}",
    "private_key": r"-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----",
    "google_api_key": r"AIza[0-9A-Za-z_\-]{35}",
    "supabase_service_role": r"service_role",
    "slack_token": r"xox[baprs]-[0-9A-Za-z\-]{10,}",
}
CSRF_FIELD = re.compile(r"csrf|xsrf|_token|nonce|authenticity", re.I)


class PageParser(HTMLParser):
    def __init__(self):
        super().__init__()
        self.links, self.scripts, self.forms, self.insecure_refs = [], [], [], []
        self._form = None

    def handle_starttag(self, tag, attrs):
        a = dict(attrs)
        if tag == "a" and a.get("href"):
            self.links.append(a["href"])
        elif tag == "script" and a.get("src"):
            self.scripts.append({"src": a["src"], "integrity": bool(a.get("integrity"))})
        elif tag == "form":
            self._form = {"method": (a.get("method") or "get").lower(),
                          "action": a.get("action") or "", "has_csrf_field": False,
                          "has_password": False}
        elif tag == "input" and self._form is not None:
            if CSRF_FIELD.search(a.get("name") or ""):
                self._form["has_csrf_field"] = True
            if (a.get("type") or "").lower() == "password":
                self._form["has_password"] = True
        if tag in ("script", "img", "iframe", "link") and (a.get("src") or a.get("href") or "").startswith("http://"):
            self.insecure_refs.append(a.get("src") or a.get("href"))

    def handle_endtag(self, tag):
        if tag == "form" and self._form is not None:
            self.forms.append(self._form)
            self._form = None


def fetch(url, max_bytes=2_000_000):
    req = urllib.request.Request(url, headers={"User-Agent": UA})
    try:
        with urllib.request.urlopen(req, timeout=15) as r:
            return r.status, r.geturl(), r.headers, r.read(max_bytes)
    except urllib.error.HTTPError as e:
        return e.code, url, e.headers, b""
    except Exception as e:
        return None, url, None, str(e).encode()


def cookie_flags(headers):
    out = []
    for c in headers.get_all("Set-Cookie") or []:
        low = c.lower()
        out.append({"name": c.split("=", 1)[0].strip(),
                    "secure": "secure" in low, "httponly": "httponly" in low,
                    "samesite": (re.search(r"samesite=(\w+)", low) or [None, None])[1]})
    return out


def find_secrets(text):
    hits = []
    for kind, pat in SECRET_PATTERNS.items():
        for m in re.finditer(pat, text):
            v = m.group(0)
            hits.append({"type": kind, "redacted": v[:6] + "…" + str(len(v))})
    return hits


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("start")
    ap.add_argument("out_dir")
    ap.add_argument("--max-pages", type=int, default=50)
    ap.add_argument("--delay", type=float, default=1.0)
    a = ap.parse_args()

    start = a.start if "://" in a.start else "https://" + a.start
    host = urllib.parse.urlparse(start).netloc
    out = os.path.join(a.out_dir, host)
    os.makedirs(out, exist_ok=True)

    robots = urllib.robotparser.RobotFileParser()
    robots.set_url(f"{urllib.parse.urlparse(start).scheme}://{host}/robots.txt")
    try:
        robots.read()
    except Exception:
        robots = None

    queue, seen, pages = [start], set(), []
    scripts_seen = {}
    while queue and len(pages) < a.max_pages:
        url = urllib.parse.urldefrag(queue.pop(0))[0]
        if urllib.parse.urlparse(url).path == "":
            url += "/"
        if url in seen:
            continue
        seen.add(url)
        if robots and not robots.can_fetch(UA, url):
            pages.append({"url": url, "skipped": "robots.txt"})
            continue
        status, final, headers, body = fetch(url)
        time.sleep(a.delay)
        page = {"url": url, "final_url": final, "status": status}
        if headers is None:
            page["error"] = body.decode("utf-8", "replace")[:200]
            pages.append(page)
            continue
        page["missing_headers"] = [h for h in SEC_HEADERS if h not in {k.lower() for k in headers.keys()}]
        page["banners"] = {h: headers.get(h) for h in BANNER_HEADERS if headers.get(h)}
        page["cookies"] = cookie_flags(headers)
        ctype = headers.get("Content-Type", "")
        if "html" in ctype:
            text = body.decode("utf-8", "replace")
            p = PageParser()
            try:
                p.feed(text)
            except Exception:
                pass
            page["forms"] = p.forms
            page["insecure_refs"] = p.insecure_refs[:20]
            page["secrets"] = find_secrets(text)
            gen = re.search(r'<meta[^>]+name=["\']generator["\'][^>]+content=["\']([^"\']+)', text, re.I)
            if gen:
                page["generator"] = gen.group(1)
            for s in p.scripts:
                src = urllib.parse.urljoin(final, s["src"])
                scripts_seen.setdefault(src, {"integrity": s["integrity"], "third_party":
                                              urllib.parse.urlparse(src).netloc != host})
            for href in p.links:
                nxt = urllib.parse.urldefrag(urllib.parse.urljoin(final, href))[0]
                pu = urllib.parse.urlparse(nxt)
                if pu.scheme in ("http", "https") and pu.netloc == host and nxt not in seen \
                        and not SKIP_EXT.search(pu.path) and "logout" not in nxt.lower():
                    queue.append(nxt)
        pages.append(page)

    # Fetch first-party JS bundles once each to look for secrets / source maps.
    for src, meta in list(scripts_seen.items())[:30]:
        if meta["third_party"]:
            continue
        status, _, headers, body = fetch(src)
        time.sleep(a.delay)
        text = body.decode("utf-8", "replace")
        meta["secrets"] = find_secrets(text)
        sm = re.search(r"sourceMappingURL=(\S+)", text[-2000:])
        meta["source_map"] = urllib.parse.urljoin(src, sm.group(1)) if sm else None

    result = {"host": host, "start": start, "pages_crawled": len(pages),
              "queue_remaining": len(queue), "pages": pages, "scripts": scripts_seen}
    with open(os.path.join(out, "crawl.json"), "w") as f:
        json.dump(result, f, indent=2)
    print(f"{host}: {len(pages)} pages, {len(scripts_seen)} scripts -> {out}/crawl.json")


if __name__ == "__main__":
    sys.exit(main())
