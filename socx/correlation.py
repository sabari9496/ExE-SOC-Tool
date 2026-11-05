"""Correlation / threshold / sequence detections. Runs every SOCX_INTERVAL seconds over the events table (non-invasive: engine.py is untouched here).
Each detector returns findings; emit() turns one finding into ONE alert (merged by engine's dedupe) and the incident layer groups them into stories.
A finding is re-emitted only when NEW matching events appeared (signature = last event id), so a 20-second loop never inflates counts."""
import re, os, threading, time, traceback
from db import q, x, now, setting, setting_num
from .util import *
from . import catalog

SELF = "EXE-SOC"          # channel/prefix of synthetic events produced here; excluded from scanning so we never loop on ourselves
def _ev(sql, args=()): return q(f"SELECT * FROM events WHERE (channel IS NULL OR channel!='{SELF}') AND " + sql, args)

def emit(det_id, host, ip, user, message, severity=None, last_id=0, sig=""):
    """Create/merge an alert for a finding. Returns alert or None (already reported / suppressed)."""
    import engine
    d = next(c for c in catalog.CATALOG if c["id"] == det_id); key = f"fire:{det_id}:{host}:{ip}:{user}:{sig}"
    if int(state_get(key) or 0) >= last_id and last_id: return None
    state_set(key, last_id)
    msg = f"[{det_id}] {message}"
    ev = x("INSERT INTO events(ts,source_ip,dest_ip,host,message,channel,event_id,category,activity,username,status,risk,nflag) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,1)",
           (now(), ip, None, host, msg, SELF, None, "System", d["name"], user, "Failure", severity or d["severity"]))
    return engine._detect(ev, ip, msg, None, host, severity or d["severity"], d["name"], d["tactic"].lower().replace(" ", "_"), d["tactic"].lower().replace(" ", "_"))

# ---------------- threshold detections ----------------
def password_spray():
    out = []; th = setting_num("spray_users", 8, 1, 100000)
    for r in q("SELECT source_ip ip, COUNT(DISTINCT lower(username)) u, COUNT(*) n, MAX(id) mx, MIN(host) host FROM events WHERE event_id IN (4625,4771,4776) AND source_ip IS NOT NULL AND source_ip NOT IN ('-','::1','127.0.0.1') AND username IS NOT NULL AND ts>=? AND (channel IS NULL OR channel!=?) GROUP BY source_ip HAVING u>=?", (ago(10), SELF, th)):
        out.append(("THR-001", r["host"], r["ip"], None, f"Password spraying: {r['n']} failed logons for {r['u']} different accounts from {r['ip']} in 10 min", None, r["mx"], ""))
    return out

def kerberoast():
    out = []; th = setting_num("kerb_spns", 6, 1, 100000); users = {}
    for e in _ev("event_id=4769 AND ts>=?", (ago(10),)):
        t = lower_text(e)
        if "0x17" not in t: continue
        svc = field(e, "ServiceName") or ""
        if not svc or svc.endswith("$") or svc.lower().startswith("krbtgt"): continue
        k = (e.get("username") or field(e, "TargetUserName") or "?", e.get("host")); users.setdefault(k, {"svc": set(), "mx": 0, "ip": e.get("source_ip")})
        users[k]["svc"].add(svc.lower()); users[k]["mx"] = max(users[k]["mx"], e["id"])
    for (u, h), v in users.items():
        if len(v["svc"]) >= th: out.append(("THR-002", h, v["ip"], u, f"{u} requested RC4 service tickets for {len(v['svc'])} different services in 10 min", None, v["mx"], ""))
    return out

def mass_file_change():
    th = setting_num("mass_file_changes", 200, 1, 10000000); out = []
    for r in q("SELECT host, COUNT(*) n, MAX(id) mx FROM events WHERE (category='File' OR message LIKE '%file integrity change%' OR event_id IN (11,23,26)) AND ts>=? AND (channel IS NULL OR channel!=?) AND host IS NOT NULL GROUP BY host HAVING n>=?", (ago(5), SELF, th)):
        out.append(("THR-003", r["host"], None, None, f"{r['n']} file changes on {r['host']} in 5 min (ransomware-like volume)", None, r["mx"], ""))
    return out

DNSQ = re.compile(r"QueryName\W{1,4}([A-Za-z0-9._-]+\.[A-Za-z0-9-]+)", re.I)
def dns_anomaly():
    out = []; doms = {}; nx = {}
    for e in _ev("(event_id=22 OR channel LIKE '%DNS%' OR category='DNS') AND ts>=?", (ago(10),)):
        m = DNSQ.search(e.get("message") or "") or DNSQ.search(e.get("raw") or ""); qn = (field(e, "QueryName") or (m.group(1) if m else "")).lower().rstrip(".")
        if not qn or "." not in qn: continue
        parts = qn.split("."); base = ".".join(parts[-2:]); sub = parts[:-2]; h = e.get("host")
        d = doms.setdefault((h, base), {"subs": set(), "long": 0, "mx": 0}); d["mx"] = max(d["mx"], e["id"])
        if sub: d["subs"].add(".".join(sub))
        if any(len(s) >= 40 for s in sub): d["long"] += 1
        if "9003" in lower_text(e) or "nxdomain" in lower_text(e): nx[h] = nx.get(h, [0, 0]); nx[h][0] += 1; nx[h][1] = max(nx[h][1], e["id"])
    for (h, base), d in doms.items():
        if d["long"] or len(d["subs"]) >= 30: out.append(("THR-004", h, None, None, f"DNS tunneling pattern for {base}: {len(d['subs'])} unique subdomains, {d['long']} very long labels in 10 min", None, d["mx"], base))
    for h, (n, mx) in nx.items():
        if n >= 50: out.append(("THR-004", h, None, None, f"{n} NXDOMAIN answers in 10 min on {h} (possible DGA)", None, mx, "nx"))
    return out

def port_scan():
    out = []
    for r in q("SELECT COALESCE(source_ip,host) src, COUNT(DISTINCT dest_ip) d, MAX(id) mx, MIN(host) host FROM events WHERE dest_ip LIKE '%:%' AND ts>=? AND (channel IS NULL OR channel!=?) GROUP BY src HAVING d>=20", (ago(5), SELF)):
        ports = {p.split(":")[-1] for p in [e["dest_ip"] for e in q("SELECT DISTINCT dest_ip FROM events WHERE COALESCE(source_ip,host)=? AND dest_ip LIKE '%:%' AND ts>=? LIMIT 400", (r["src"], ago(5)))]}
        if len(ports) >= 15: out.append(("THR-005", r["host"], r["src"] if "." in str(r["src"]) else None, None, f"{r['src']} touched {r['d']} destinations / {len(ports)} distinct ports in 5 min", None, r["mx"], ""))
    return out

def anomalous_login():
    """Same user, successful logins from two different COUNTRIES within 60 min (uses cached geo only: no external call here)."""
    import engine; out = []; seen = {}
    for e in _ev("event_id IN (4624) AND username IS NOT NULL AND source_ip IS NOT NULL AND ts>=?", (ago(60),)):
        if is_private(e["source_ip"]): continue
        c = engine.geo_for(e["source_ip"])[0]
        if not c: continue
        s = seen.setdefault(e["username"].lower(), {}); s[c] = max(s.get(c, 0), e["id"])
    for u, cs in seen.items():
        if len(cs) >= 2: out.append(("THR-007", None, None, u, f"{u} logged in from {', '.join(sorted(cs))} within 60 min", None, max(cs.values()), ""))
    return out

# ---------------- sequence detections ----------------
def rdp_chain():
    out = []
    for f in q("SELECT source_ip ip, COUNT(*) n, MIN(ts) t0, MAX(id) mx FROM events WHERE event_id=4625 AND source_ip IS NOT NULL AND source_ip NOT IN ('-','127.0.0.1') AND ts>=? AND (channel IS NULL OR channel!=?) GROUP BY source_ip HAVING n>=5", (ago(30), SELF)):
        ok = [e for e in _ev("event_id=4624 AND source_ip=? AND ts>=?", (f["ip"], f["t0"])) if logon_type(e) == 10]
        if not ok: continue
        lg = ok[0]; host = lg.get("host"); procs = _ev("(event_id=4688 OR (event_id=1 AND channel LIKE '%Sysmon%')) AND host=? AND ts>=?", (host, lg["ts"]))
        ps = [p for p in procs + _ev("event_id IN (4103,4104) AND host=? AND ts>=?", (host, lg["ts"])) if "powershell" in lower_text(p) or p.get("event_id") in (4103, 4104)]
        if not procs and not ps: continue
        stages = f"{f['n']}x4625 -> 4624 type10" + (" -> process start" if procs else "") + (" -> PowerShell" if ps else "")
        last = max([f["mx"], lg["id"]] + [p["id"] for p in procs + ps])
        out.append(("SEQ-001", host, f["ip"], lg.get("username"), f"RDP compromise chain from {f['ip']}: {stages}", "Critical" if ps else "High", last, ""))
    return out

def logclear_chain():
    out = []
    for c in _ev("event_id IN (1102,104) AND ts>=?", (ago(60),)):
        pre = _ev("event_id IN (4672,4624,4720,4728,4732,4698,4697,4688) AND host IS ? AND ts>=? AND ts<=?", (c.get("host"), ago(120), c["ts"]))
        pre = [p for p in pre if p["event_id"] in (4672, 4720, 4728, 4732, 4698, 4697) or (p["event_id"] == 4624 and logon_type(p) in (2, 10, 3)) or (p["event_id"] == 4688 and PROC_RX.search(lower_text(p)))]
        if pre: out.append(("SEQ-002", c.get("host"), c.get("source_ip"), c.get("username") or field(c, "SubjectUserName"), f"Log cleared (event {c['event_id']}) after {len(pre)} preceding privileged/process events on {c.get('host')}", None, c["id"], ""))
    return out

def defender_chain():
    out = []; rows = q("SELECT a.id,a.title,a.category,a.severity,e.hostname host FROM alerts a JOIN endpoints e ON e.id=a.endpoint_id WHERE a.ts>=? AND a.status!='Resolved'", (ago(60),))
    by = {}
    for a in rows: by.setdefault(a["host"], []).append(a)
    for h, al in by.items():
        t = " | ".join(a["title"] for a in al).lower()
        dis = "security tool disabled" in t or "security tool tampering" in t
        proc = any(a["category"] == "process" and a["title"] not in ("Security Tool Tampering Command",) for a in al)
        net = any(a["category"] == "network" or "network connection" in a["title"].lower() for a in al)
        if dis and proc and net: out.append(("SEQ-003", h, None, None, f"On {h}: protection disabled + suspicious process + suspicious network connection within 60 min", None, max(a["id"] for a in al), ""))
    return out

def persistence_after_logon():
    out = []
    for p in _ev("event_id IN (4698,4697,7045) AND ts>=?", (ago(30),)):
        lg = [l for l in _ev("event_id=4624 AND host IS ? AND ts>=? AND ts<=?", (p.get("host"), ago(60), p["ts"])) if (l.get("source_ip") and not is_private(l["source_ip"])) or logon_type(l) == 10]
        if lg: out.append(("SEQ-004", p.get("host"), lg[-1].get("source_ip"), lg[-1].get("username"), f"Persistence (event {p['event_id']}) created on {p.get('host')} {int(minutes_between(lg[-1]['ts'], p['ts']))} min after remote logon from {lg[-1].get('source_ip')}", None, p["id"], ""))
    return out

def lateral_chain():
    out = []
    for lg in _ev("event_id=4624 AND ts>=? AND source_ip IS NOT NULL", (ago(15),)):
        if logon_type(lg) != 3 or not lg["source_ip"] or lg["source_ip"] in ("-", "127.0.0.1", "::1"): continue
        if (lg.get("username") or "").endswith("$") or (lg.get("username") or "").upper() in ("ANONYMOUS LOGON", "-"): continue
        nxt = [p for p in _ev("host IS ? AND ts>=? AND (event_id IN (4688,5140,4103,4104) OR (event_id=1 AND channel LIKE '%Sysmon%'))", (lg.get("host"), lg["ts"])) if re.search(r"wsmprovhost|psexe|winrs|wmiprvse|powershell|wmic|admin\$|\bc\$", lower_text(p))]
        if nxt: out.append(("SEQ-006", lg.get("host"), lg["source_ip"], lg.get("username"), f"{lg.get('username')} logged on remotely from {lg['source_ip']} to {lg.get('host')} then remote execution/share access ({len(nxt)} events)", None, max(p["id"] for p in nxt), ""))
    return out

WEBLOG = re.compile(r'"(GET|POST|HEAD|PUT)\s+(\S+)[^"]*"\s+(\d{3})')
ATTACK_URL = re.compile(r"union\s+select|\.\./|<script|/etc/passwd|cmd=|;\s*(ls|id|whoami|cat)\b|%3cscript|\.(php|asp|aspx|jsp)\?.*(=|%)|shell\.(php|asp)|c99|wso", re.I)
def web_chain():
    out = []; per = {}
    for e in _ev("source_ip IS NOT NULL AND ts>=? AND (message LIKE '%GET %' OR message LIKE '%POST %')", (ago(30),)):
        m = WEBLOG.search(e.get("message") or "")
        if not m: continue
        p = per.setdefault(e["source_ip"], {"404": 0, "exp": 0, "post": 0, "mx": 0, "host": e.get("host")}); meth, url, st = m.groups(); p["mx"] = max(p["mx"], e["id"])
        if st in ("404", "403"): p["404"] += 1
        if ATTACK_URL.search(url) and st.startswith("2"): p["exp"] += 1
        if meth == "POST" and st.startswith("2") and p["exp"]: p["post"] += 1
    for ip, p in per.items():
        if p["404"] >= 20 and p["exp"]:
            shell = q("SELECT 1 FROM alerts WHERE title='Web Server Spawned a Shell' AND ts>=?", (ago(30),), one=True)
            out.append(("SEQ-005", p["host"], ip, None, f"Web attack chain from {ip}: {p['404']} x 404/403 -> {p['exp']} attack URL answered 2xx -> {p['post']} POST" + (" -> web server spawned a shell" if shell else ""), "Critical" if shell else "High", p["mx"], ""))
    return out

def phishing_chain():
    out = []
    for em in q("SELECT a.id FROM alerts a WHERE (a.category='email' OR a.title LIKE '%Phish%') AND a.ts>=?", (ago(60),)):
        ex = q("SELECT a.id,e.hostname h FROM alerts a JOIN endpoints e ON e.id=a.endpoint_id WHERE a.title IN ('Office Application Spawned a Shell','Suspicious PowerShell (encoded command)','Suspicious PowerShell (download and execute)') AND a.ts>=?", (ago(60),))
        if ex: out.append(("SEQ-007", ex[0]["h"], None, None, "Phishing email alert followed by Office/PowerShell execution within 60 min", None, ex[0]["id"], ""))
    return out

DETECTORS = [password_spray, kerberoast, mass_file_change, dns_anomaly, port_scan, anomalous_login, rdp_chain, logclear_chain, defender_chain, persistence_after_logon, lateral_chain, web_chain, phishing_chain]
IMPLEMENTED = {"SEQ-001", "SEQ-002", "SEQ-003", "SEQ-004", "SEQ-005", "SEQ-006", "SEQ-007", "THR-001", "THR-002", "THR-003", "THR-004", "THR-005", "THR-007", "HLT-001", "HLT-002"}

def run_once():
    n = 0; errors = []
    for det in DETECTORS:
        try:
            for f in det():
                if emit(*f[:5], severity=f[5], last_id=f[6], sig=f[7]): n += 1
        except Exception as ex: errors.append(f"{det.__name__}: {ex}"); traceback.print_exc()
    return n, errors

def loop():
    time.sleep(8)
    while True:
        try:
            if setting("socx_enabled", "1") == "1":
                run_once()
                from . import health; health.run_once()
        except Exception: traceback.print_exc()
        time.sleep(int(os.environ.get("SOCX_INTERVAL", "20")))
