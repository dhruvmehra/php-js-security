#!/usr/bin/env python3
"""Passive subdomain discovery for a domain you own.

Sources: public Certificate Transparency logs (crt.sh) plus any hosts passed
with --extra. Each candidate is DNS-resolved and checked with a single HEAD
request per scheme. Only hosts equal to or under the root domain are kept.

Usage: discover_hosts.py <root-domain> <out_dir> [--extra a.example.com,b.example.com]
                         [--max-hosts 50] [--no-probe]
Writes: <out_dir>/hosts.json
"""
import argparse
import json
import socket
import ssl
import sys
import time
import urllib.error
import urllib.request

UA = "php-js-security-scan/1.0 (authorized passive check)"


def in_scope(host, root):
    host = host.lower().rstrip(".")
    return host == root or host.endswith("." + root)


def from_crtsh(root):
    url = f"https://crt.sh/?q=%25.{root}&output=json"
    req = urllib.request.Request(url, headers={"User-Agent": UA})
    try:
        with urllib.request.urlopen(req, timeout=60) as r:
            rows = json.loads(r.read().decode("utf-8", "replace"))
    except (urllib.error.URLError, ValueError, TimeoutError) as e:
        print(f"warn: crt.sh lookup failed: {e}", file=sys.stderr)
        return set()
    names = set()
    for row in rows:
        for name in row.get("name_value", "").splitlines():
            name = name.strip().lower().lstrip("*.")
            if name and in_scope(name, root):
                names.add(name)
    return names


def resolves(host):
    try:
        return sorted({ai[4][0] for ai in socket.getaddrinfo(host, None)})
    except socket.gaierror:
        return []


def head(url):
    req = urllib.request.Request(url, method="HEAD", headers={"User-Agent": UA})
    ctx = ssl.create_default_context()
    try:
        with urllib.request.urlopen(req, timeout=10, context=ctx) as r:
            return r.status, r.geturl()
    except urllib.error.HTTPError as e:
        return e.code, url
    except Exception as e:  # connection refused, TLS error, timeout
        return None, type(e).__name__


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("root")
    ap.add_argument("out_dir")
    ap.add_argument("--extra", default="")
    ap.add_argument("--max-hosts", type=int, default=50)
    ap.add_argument("--no-probe", action="store_true")
    a = ap.parse_args()

    root = a.root.lower().removeprefix("https://").removeprefix("http://").split("/")[0]
    names = {root, "www." + root} | from_crtsh(root)
    for h in filter(None, (x.strip().lower() for x in a.extra.split(","))):
        if in_scope(h, root):
            names.add(h)
        else:
            print(f"skip out-of-scope extra host: {h}", file=sys.stderr)

    hosts = []
    for name in sorted(names)[: a.max_hosts]:
        ips = resolves(name)
        entry = {"host": name, "ips": ips, "https": None, "http": None}
        if ips and not a.no_probe:
            entry["https"] = head(f"https://{name}/")
            time.sleep(1)
            entry["http"] = head(f"http://{name}/")
            time.sleep(1)
        hosts.append(entry)

    if len(names) > a.max_hosts:
        print(f"note: {len(names)} names found, kept first {a.max_hosts}", file=sys.stderr)

    with open(f"{a.out_dir}/hosts.json", "w") as f:
        json.dump({"root": root, "total_names": len(names), "hosts": hosts}, f, indent=2)
    live = [h["host"] for h in hosts if (h["https"] or [None])[0] or (h["http"] or [None])[0]]
    print(f"{len(hosts)} hosts checked, {len(live)} live -> {a.out_dir}/hosts.json")


if __name__ == "__main__":
    main()
