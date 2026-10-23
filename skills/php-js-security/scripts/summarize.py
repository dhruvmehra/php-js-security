#!/usr/bin/env python3
"""Aggregate hosts.json + per-host crawl.json + site_probe output into one
summary.json, and flag PHP versions affected by known advisories.

Usage: summarize.py <scan_dir>
"""
import glob
import json
import os
import re
import sys

# PHP2Shell (CVE-2026-109618 / CVE-2026-109619): fixed in these releases.
PHP_FIXED = {(8, 5): 12, (8, 4): 27, (8, 3): 36, (8, 2): 35}
PUBLIC_BY_DESIGN = {"/robots.txt", "/sitemap.xml", "/.well-known/security.txt"}
PHP_RE = re.compile(r"PHP/(\d+)\.(\d+)\.(\d+)", re.I)


def php_status(banner):
    m = PHP_RE.search(banner or "")
    if not m:
        return None
    major, minor, patch = map(int, m.groups())
    ver = f"{major}.{minor}.{patch}"
    fixed = PHP_FIXED.get((major, minor))
    if fixed is not None:
        vuln = patch < fixed
        note = f"fixed in {major}.{minor}.{fixed}"
    elif (major, minor) > max(PHP_FIXED):
        vuln, note = False, "newer than known affected branches"
    else:
        vuln, note = True, "branch has no official fix (EOL or source backport only)"
    return {"version": ver, "php2shell_affected_by_banner": vuln, "note": note}


def main():
    scan = sys.argv[1]
    hosts = json.load(open(os.path.join(scan, "hosts.json"))) if os.path.exists(
        os.path.join(scan, "hosts.json")) else {"hosts": []}
    summary = {"root": hosts.get("root"), "hosts": []}
    for crawl_path in sorted(glob.glob(os.path.join(scan, "*", "crawl.json"))):
        c = json.load(open(crawl_path))
        hdir = os.path.dirname(crawl_path)
        banners, missing, cookies, forms, secrets = {}, set(), {}, [], []
        for p in c["pages"]:
            for k, v in (p.get("banners") or {}).items():
                banners.setdefault(k, set()).add(v)
            missing.update(p.get("missing_headers") or [])
            for ck in p.get("cookies") or []:
                cookies[ck["name"]] = ck
            for f in p.get("forms") or []:
                if f["method"] == "post" and not f["has_csrf_field"]:
                    forms.append({"page": p["url"], **f})
            for s in p.get("secrets") or []:
                secrets.append({"where": p["url"], **s})
        for src, meta in c["scripts"].items():
            for s in meta.get("secrets") or []:
                secrets.append({"where": src, **s})
        php = [php_status(v) for vs in banners.values() for v in vs]
        exposed = []
        tsv = os.path.join(hdir, "probe", "exposed-paths.tsv")
        if os.path.exists(tsv):
            lines = open(tsv).read().splitlines()
            baseline = lines[0].split("->")[-1].strip().split() if lines else []
            for row in lines[2:]:
                parts = row.split("\t")
                if parts[0] in PUBLIC_BY_DESIGN:
                    continue
                if len(parts) >= 3 and parts[1] == "200" and parts[2] != (baseline[1] if len(baseline) > 1 else ""):
                    exposed.append({"path": parts[0], "bytes": parts[2], "type": parts[3] if len(parts) > 3 else ""})
        summary["hosts"].append({
            "host": c["host"], "pages_crawled": c["pages_crawled"],
            "banners": {k: sorted(v) for k, v in banners.items()},
            "php": [x for x in php if x],
            "missing_security_headers": sorted(missing),
            "weak_cookies": [ck for ck in cookies.values() if not (ck["secure"] and ck["httponly"])],
            "post_forms_without_csrf_field": forms[:20],
            "secrets_found": secrets,
            "third_party_scripts_without_sri": [s for s, m in c["scripts"].items()
                                                if m["third_party"] and not m["integrity"]],
            "scripts": sorted(c["scripts"]),
            "source_maps": [m["source_map"] for m in c["scripts"].values() if m.get("source_map")],
            "exposed_paths_200": exposed,
        })
    with open(os.path.join(scan, "summary.json"), "w") as f:
        json.dump(summary, f, indent=2)
    flagged = [h["host"] for h in summary["hosts"] if any(p["php2shell_affected_by_banner"] for p in h["php"])]
    print(f"{len(summary['hosts'])} hosts summarized -> {scan}/summary.json")
    if flagged:
        print("PHP2Shell-affected version banner on: " + ", ".join(flagged))


if __name__ == "__main__":
    main()
