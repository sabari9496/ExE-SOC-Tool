"""Vulnerability check: installed packages -> free OSV database (api.osv.dev, needs internet). Covers Ubuntu, Debian, Alpine,
Rocky/Alma Linux (and PyPI if enabled). Windows software is listed (inventory) but OSV has no Windows feed, so it is not matched."""
import os, json, math, time, threading, urllib.request, urllib.error
from concurrent.futures import ThreadPoolExecutor
from db import q, x, now, conn

OSV = os.environ.get("SOC_OSV_URL", "https://api.osv.dev/v1")
SUPPORTED = ("Ubuntu", "Debian", "Alpine", "Rocky Linux", "AlmaLinux", "PyPI", "npm")
_running = set(); _lock = threading.Lock()

def _req(path, data=None):
    r = urllib.request.Request(OSV + path, data=json.dumps(data).encode() if data is not None else None, headers={"Content-Type": "application/json"})
    return json.load(urllib.request.urlopen(r, timeout=30))

def cvss3(vec):
    try:
        m = dict(p.split(":") for p in vec.split("/")[1:]); S = m["S"]
        av = {"N": .85, "A": .62, "L": .55, "P": .2}[m["AV"]]; ac = {"L": .77, "H": .44}[m["AC"]]; ui = {"N": .85, "R": .62}[m["UI"]]
        pr = {"N": .85, "L": .68 if S == "C" else .62, "H": .5 if S == "C" else .27}[m["PR"]]; cia = {"H": .56, "L": .22, "N": 0}
        iss = 1 - (1 - cia[m["C"]]) * (1 - cia[m["I"]]) * (1 - cia[m["A"]])
        imp = 6.42 * iss if S == "U" else 7.52 * (iss - .029) - 3.25 * (iss - .02) ** 15
        if imp <= 0: return 0.0
        e = 8.22 * av * ac * pr * ui; s = min(imp + e, 10) if S == "U" else min(1.08 * (imp + e), 10)
        return math.ceil(s * 10) / 10
    except Exception: return None

def _band(sc): return "Critical" if sc >= 9 else "High" if sc >= 7 else "Medium" if sc >= 4 else "Low" if sc > 0 else "Unknown"
WORDS = {"critical": "Critical", "high": "High", "important": "High", "medium": "Medium", "moderate": "Medium", "low": "Low", "negligible": "Low"}

def _severity(d):
    for s in d.get("severity") or []:
        sc = str(s.get("score", ""))
        if sc.startswith("CVSS:3"):
            v = cvss3(sc)
            if v is not None: return _band(v)
        if str(s.get("type", "")).lower() in ("ubuntu", "debian") and sc.lower() in WORDS: return WORDS[sc.lower()]
    ds = str((d.get("database_specific") or {}).get("severity", "")).lower()
    return WORDS.get(ds, "Unknown")

def _detail(vid):
    d = _req("/vulns/" + vid)
    summ = (d.get("summary") or (d.get("details") or "").strip().split("\n")[0])[:300]
    x("INSERT OR REPLACE INTO vuln_cache VALUES(?,?,?,?)", (vid, summ, _severity(d), ", ".join(d.get("aliases") or [])[:300]))

def store_inventory(host, ecosystem, packages):
    rows = []
    for p in packages[:30000]:
        if isinstance(p, dict) and p.get("name"): rows.append((host, str(p["name"])[:200], str(p.get("version", ""))[:100], (p.get("ecosystem") or ecosystem or "")[:60]))
    c = conn()
    try:
        c.execute("DELETE FROM packages WHERE host=?", (host,)); c.executemany("INSERT OR REPLACE INTO packages VALUES(?,?,?,?)", rows); c.commit()
    finally: c.close()
    x("INSERT OR IGNORE INTO vuln_scan(host,ecosystem,packages,vulnerable,last_scan,status) VALUES(?,?,?,?,?,?)", (host, ecosystem, len(rows), 0, None, "queued"))
    x("UPDATE vuln_scan SET ecosystem=?,packages=?,status='queued' WHERE host=?", (ecosystem, len(rows), host))
    threading.Thread(target=check_host, args=(host,), daemon=True).start()

def _status(host, **kw):
    for k, v in kw.items(): x(f"UPDATE vuln_scan SET {k}=? WHERE host=?", (v, host))

def check_host(host):
    with _lock:
        if host in _running: return
        _running.add(host)
    try:
        pk = [p for p in q("SELECT name,version,ecosystem FROM packages WHERE host=?", (host,))]
        sup = [p for p in pk if p["ecosystem"].split(":")[0] in SUPPORTED and p["version"]]
        if not sup:
            x("DELETE FROM vulns WHERE host=?", (host,)); _status(host, vulnerable=0, last_scan=now(), status="inventory only: no free vulnerability feed for this operating system"); return
        found = {}                                             # (name, version) -> [vuln ids]
        for i in range(0, len(sup), 500):
            chunk = sup[i:i + 500]
            res = _req("/querybatch", {"queries": [{"package": {"name": p["name"], "ecosystem": p["ecosystem"]}, "version": p["version"]} for p in chunk]})["results"]
            for p, r in zip(chunk, res):
                ids = [v["id"] for v in (r.get("vulns") or [])]
                if ids: found[(p["name"], p["version"])] = ids
        need = sorted({v for ids in found.values() for v in ids} - {r["vuln_id"] for r in q("SELECT vuln_id FROM vuln_cache")})[:400]
        def get(v):
            try: _detail(v)
            except Exception: pass
        with ThreadPoolExecutor(8) as ex: list(ex.map(get, need))
        cache = {r["vuln_id"]: r for r in q("SELECT * FROM vuln_cache")}
        c = conn(); pending = 0
        try:
            c.execute("DELETE FROM vulns WHERE host=?", (host,))
            for (n, v), ids in found.items():
                for vid in ids:
                    d = cache.get(vid); pending += d is None
                    c.execute("INSERT OR IGNORE INTO vulns(host,package,version,vuln_id,summary,severity,aliases,seen) VALUES(?,?,?,?,?,?,?,?)",
                              (host, n, v, vid, d["summary"] if d else "(details loading, re-check shortly)", d["severity"] if d else "Unknown", d["aliases"] if d else "", now()))
            c.commit()
        finally: c.close()
        _status(host, vulnerable=len(found), last_scan=now(), status="ok" + (f" ({pending} descriptions still loading)" if pending else ""))
    except Exception as e:
        _status(host, status=f"error: cannot query vulnerability database ({str(e)[:100]}); old results kept")
    finally:
        with _lock: _running.discard(host)
