#!/usr/bin/env python3
"""Vendor the three front-end libraries into static/vendor/ (pinned versions) and record SHA-384 hashes in static/vendor/MANIFEST.json.
  python tools/vendor_assets.py            download (needs internet), hash, write manifest.  REVIEW the manifest hashes against the publisher's own SRI values before release.
  python tools/vendor_assets.py --verify   re-hash local files against the manifest (no network).
When every file in the manifest is present and matches, EXE-SOC automatically serves local copies with integrity= attributes and tightens the CSP to 'self' (no CDN hosts)."""
import os, sys, json, hashlib, base64, urllib.request
ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__))); V = os.path.join(ROOT, "static", "vendor"); MF = os.path.join(V, "MANIFEST.json")
IMG = ["layers.png", "layers-2x.png", "marker-icon.png", "marker-icon-2x.png", "marker-shadow.png"]
ASSETS = {"socket.io.min.js": "https://cdn.socket.io/4.7.5/socket.io.min.js", "chart.umd.min.js": "https://cdn.jsdelivr.net/npm/chart.js@4.4.3/dist/chart.umd.min.js",
          "leaflet.js": "https://unpkg.com/leaflet@1.9.4/dist/leaflet.js", "leaflet.css": "https://unpkg.com/leaflet@1.9.4/dist/leaflet.css"}
ASSETS.update({"images/" + i: "https://unpkg.com/leaflet@1.9.4/dist/images/" + i for i in IMG})
def sri(b): return "sha384-" + base64.b64encode(hashlib.sha384(b).digest()).decode()
def download():
    m = {}
    for name, url in ASSETS.items():
        b = urllib.request.urlopen(url, timeout=30).read(); p = os.path.join(V, name); os.makedirs(os.path.dirname(p), exist_ok=True); open(p, "wb").write(b); m[name] = dict(url=url, sri=sri(b), bytes=len(b)); print("fetched", name, m[name]["sri"])
    json.dump(m, open(MF, "w"), indent=1); print("manifest written; compare these hashes with the publishers' before shipping.")
def verify(quiet=False):
    try: m = json.load(open(MF))
    except Exception: return False
    ok = set(m) >= set(ASSETS)
    for name, e in m.items():
        p = os.path.join(V, name)
        if not os.path.isfile(p) or sri(open(p, "rb").read()) != e["sri"]: ok = False; quiet or print("MISMATCH/MISSING", name)
    return ok
if __name__ == "__main__":
    if "--verify" in sys.argv: ok = verify(); print("OK" if ok else "FAILED"); sys.exit(0 if ok else 1)
    download()
