"""Detection rules, alert creation, playbooks, geo lookup, host monitor, log tailing."""
import activity
import db as _db
import re, os, sys, time, fnmatch, ipaddress, threading, json, subprocess, urllib.request
from datetime import datetime, timedelta, timezone
from db import q, x, now, setting, setting_num, RANK, conn

_B = os.path.dirname(os.path.abspath(__file__)); sys.path[:0] = [p for p in (_B, os.path.join(_B, "tools")) if p not in sys.path]
emit = lambda *a, **k: None      # replaced by app.py with socketio.emit

RULES = [  # (regex, title, severity, category) - first match wins
 (r"file integrity change", "File Integrity Change", "High", "system"),
 (r"audit log (was )?cleared|event log (was )?cleared", "Audit Log Cleared", "High", "system"),
 (r"new user account created|user account was created", "New User Account Created", "Medium", "system"),
 (r"new service installed|service was installed", "Suspicious Service Installed", "Medium", "system"),
 (r"union\s+select|or\s+1\s*=\s*1|sqlmap|;\s*drop\s+table|'\s*or\s*'", "Possible SQL Injection", "Critical", "web"),
 (r"<script|onerror\s*=|javascript:", "Cross-Site Scripting Attempt", "Medium", "web"),
 (r"\.\./\.\./|/etc/passwd|/etc/shadow", "Path Traversal Attempt", "High", "web"),
 (r"failed password|authentication failure|invalid user|login failed|failed login", "Brute Force Login Attempt", "High", "auth"),
 (r"trojan|malware|ransom|mimikatz|eicar|virus|backdoor", "Malware Detected", "High", "malware"),
 (r"not in the sudoers|not in sudoers|privilege escalation|uac bypass|setuid|su: failed", "Privilege Escalation Attempt", "High", "system"),
 (r"port scan|nmap|syn flood|masscan", "Port Scan Detected", "Medium", "network"),
 (r"unusual dns|dns tunnel|suspicious dns|dga|nxdomain flood", "Unusual DNS Query", "Low", "dns"),
]
COMPILED = [(re.compile(p, re.I), t, s, c) for p, t, s, c in RULES]
BRUTE_RE = next(r for r, t, s, c in COMPILED if t == "Brute Force Login Attempt")   # looked up by name, not position
IP_RE = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")

def is_private(ip):
    try: a = ipaddress.ip_address(ip); return a.is_private or a.is_loopback or a.is_link_local
    except ValueError: return True

def valid_ip(ip):
    try: ipaddress.ip_address(ip); return True
    except (ValueError, TypeError): return False

def geo_for(ip):
    if not ip or is_private(ip):
        return "Internal", setting_num("home_lat", 20.59, -90, 90, float), setting_num("home_lon", 78.96, -180, 180, float)
    c = q("SELECT * FROM geo_cache WHERE ip=?", (ip,), one=True)
    return (c["country"], c["lat"], c["lon"]) if c else (None, None, None)

def _fetch_geo(ip, alert_id):
    try:
        d = json.load(urllib.request.urlopen(f"http://ip-api.com/json/{ip}?fields=status,country,lat,lon", timeout=3))
        if d.get("status") == "success":
            x("INSERT OR REPLACE INTO geo_cache VALUES(?,?,?,?)", (ip, d["country"], d["lat"], d["lon"]))
            x("UPDATE alerts SET country=?,lat=?,lon=? WHERE source_ip=? AND lat IS NULL", (d["country"], d["lat"], d["lon"], ip))
            emit("refresh", {"what": "map"})
    except Exception: pass

AGENT_ACTIONS = {"block_ip", "unblock_ip", "isolate", "release"}
def queue_command(host, action, arg=""):
    """Ask the agent on `host` to enforce something (it only does so when started with --enforce)."""
    if not host or action not in AGENT_ACTIONS or q("SELECT 1 FROM commands WHERE host=? AND action=? AND arg=? AND status='pending'", (host, action, arg), one=True): return
    x("INSERT INTO commands(host,action,arg,status,created) VALUES(?,?,?,'pending',?)", (host, action, arg, now()))

def fanout(action, arg=""):
    for e in q("SELECT hostname FROM endpoints"): queue_command(e["hostname"], action, arg)

def set_isolation(endpoint_id, on):
    x("UPDATE endpoints SET isolated=? WHERE id=?", (1 if on else 0, endpoint_id))
    e = q("SELECT hostname FROM endpoints WHERE id=?", (endpoint_id,), one=True)
    if e: queue_command(e["hostname"], "isolate" if on else "release")

def resync(host):
    """An agent (re)started: re-send the current blocklist and isolation state (firewall rules may not survive a reboot)."""
    for b in q("SELECT ip FROM blocklist"): queue_command(host, "block_ip", b["ip"])
    e = q("SELECT isolated FROM endpoints WHERE hostname=?", (host,), one=True)
    if e and e["isolated"]: queue_command(host, "isolate")

def block_ip(ip, reason, user="system"):
    if not valid_ip(ip) or is_private(ip) or q("SELECT 1 FROM blocklist WHERE ip=?", (ip,), one=True): return False
    x("INSERT INTO blocklist VALUES(?,?,?,?)", (ip, reason, user, now())); fanout("block_ip", ip)
    if setting("firewall_enforce") == "1" and hasattr(os, "geteuid") and os.geteuid() == 0:
        subprocess.run(["iptables", "-I", "INPUT", "-s", ip, "-j", "DROP"], check=False, timeout=5)
    _db.audit_add(user, f"Blocked {ip}: {reason}")
    return True

def unblock_ip(ip):
    x("DELETE FROM blocklist WHERE ip=?", (ip,))
    if valid_ip(ip): fanout("unblock_ip", ip)
    if setting("firewall_enforce") == "1" and valid_ip(ip) and hasattr(os, "geteuid") and os.geteuid() == 0:
        subprocess.run(["iptables", "-D", "INPUT", "-s", ip, "-j", "DROP"], check=False, timeout=5)

def run_playbooks(a, above=0):
    """Run enabled playbooks whose trigger severity is met (and, on escalation, newly reached)."""
    for p in q("SELECT * FROM playbooks WHERE enabled=1"):
        if RANK[a["severity"]] < RANK.get(p["min_severity"], 3) or RANK.get(p["min_severity"], 3) <= above or (p["category"] and p["category"] != a["category"]): continue
        if p["title_like"] and a["title"] not in p["title_like"].split("|"): continue   # playbook is tied to specific rules / one attack
        act = p["action"]
        if act == "block_ip": block_ip(a["source_ip"], f"Playbook: {p['name']}")
        elif act == "create_case" and not q("SELECT 1 FROM case_alerts WHERE alert_id=?", (a["id"],), one=True):
            cid = x("INSERT INTO cases(title,description,priority,status,assignee,created_at) VALUES(?,?,?,?,?,?)",
                    (f"[Auto] {a['title']} from {a['source_ip']}", a["message"], a["severity"] if a["severity"] != "Critical" else "High", "Open", None, now()))
            x("INSERT INTO case_alerts VALUES(?,?)", (cid, a["id"]))
        elif act == "notify": emit("toast", {"severity": a["severity"], "text": str(a["title"])[:80]})
        elif act == "isolate_endpoint" and a["endpoint_id"]: set_isolation(a["endpoint_id"], True)
        x("UPDATE playbooks SET runs=runs+1,last_run=? WHERE id=?", (now(), p["id"]))

FMT = "%Y-%m-%d %H:%M:%S"
def _utc_to_local(t):
    """Windows event time (UTC ISO string) -> this server's local time string, or None."""
    try:
        t = t.strip().rstrip("Z")
        if "." in t: base, frac = t.split(".", 1); t = base + "." + frac[:6]
        return datetime.fromisoformat(t).replace(tzinfo=timezone.utc).astimezone().replace(tzinfo=None).strftime(FMT)
    except Exception: return None

def _s(v, n): return None if v is None else str(v)[:n]
def _i(v):
    try: return int(v)
    except (TypeError, ValueError): return None

_TEXT_FIELDS = ("host", "source_ip", "dest_ip", "channel", "provider", "level", "os", "username", "event_time")
def _clean_item(e):
    """Events come from the network: coerce well-known scalar fields to the types the pipeline assumes (an int/list/dict in 'host' must not crash a whole batch). Non-objects are dropped."""
    if not isinstance(e, dict): return None
    o = dict(e)
    for k in _TEXT_FIELDS:
        v = o.get(k)
        if v is None or isinstance(v, str): continue
        o[k] = str(v) if isinstance(v, (int, float)) and not isinstance(v, bool) else None
    m = o.get("message"); o["message"] = m if isinstance(m, str) else (str(m) if isinstance(m, (int, float)) and not isinstance(m, bool) else "")
    for k in ("event_id", "record_id"):
        v = o.get(k)
        if v is not None and not (isinstance(v, int) and not isinstance(v, bool) and abs(v) < 2 ** 62):
            try: o[k] = int(v) if not isinstance(v, bool) and abs(int(v)) < 2 ** 62 else None
            except (TypeError, ValueError, OverflowError): o[k] = None
    return o

def process_batch(items, reprocess_duplicates=False):
    """Store a batch of events (one fast transaction), then run detection.
    By default duplicate event rows are ignored. Fleet recovery may set reprocess_duplicates=True
    to resume detection for an event persisted before a prior request failed. Existing linked alerts
    are not counted again; events without an alert link are eligible for detection retry.
    Returns one entry per item: the alert dict, or None (no alert / duplicate / log only)."""
    rows = []
    for e in items:
        e = _clean_item(e)
        if e is None: continue
        msg = (e.get("message") or "")[:4000]; ip = e.get("source_ip"); log_only = bool(e.get("log_only"))
        if not ip and not log_only: m = IP_RE.search(msg); ip = m.group() if m else None
        raw = e.get("raw"); raw = raw if isinstance(raw, str) or raw is None else json.dumps(raw, ensure_ascii=False)
        n = activity.normalize(dict(e, message=msg, raw=raw, source_ip=ip, log_only=log_only))
        if n and not ip and n.get("src_ip"): ip = n["src_ip"]
        if n and not n.get("os"): n["os"] = _host_os(e.get("host"))
        rows.append(dict(e=e, ts=_utc_to_local(e.get("event_time") or "") or now(), ip=ip, msg=msg, log_only=log_only, raw=_s(raw, 8000), n=n))
    ids = []
    c = conn()
    try:
        for r in rows:
            e = r["e"]
            cur = c.execute("INSERT OR IGNORE INTO events(ts,source_ip,dest_ip,host,message,channel,event_id,level,provider,record_id,raw,category,activity,username,status,risk,os,nflag) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,1)",
                (r["ts"], r["ip"], _s(e.get("dest_ip"), 200), _s(e.get("host"), 200), r["msg"], _s(e.get("channel"), 200), _i(e.get("event_id")),
                 _s(e.get("level"), 50), _s(e.get("provider"), 200), _i(e.get("record_id")), r["raw"],
                 *((n["category"], _s(n["activity"], 100), _s(n.get("username"), 100), n.get("status"), n["risk"], n.get("os")) if (n := r["n"]) else (None,) * 6)))
            if cur.rowcount:
                ids.append(cur.lastrowid)
            elif reprocess_duplicates and e.get("record_id") is not None:
                existing = c.execute("SELECT id,alert_id FROM events WHERE host IS ? AND channel IS ? AND record_id=? AND ts=?", (_s(e.get("host"), 200), _s(e.get("channel"), 200), _i(e.get("record_id")), r["ts"])).fetchone()
                # Re-run detection only when a persisted event has not yet been linked to an alert.
                ids.append(existing["id"] if existing and not existing["alert_id"] else None)
            else:
                ids.append(None)  # duplicate already stored
        c.commit()
    finally: c.close()
    try:
        import unified                                          # unified normalised store + versioned detections; must never affect legacy ingestion
        unified.on_events([r["e"] | {"raw": r["raw"], "message": r["msg"], "source_ip": r["ip"], "os": (r["n"] or {}).get("os") if r["n"] else None} for r in rows], ids)
    except Exception as _e: print("unified hook error:", _e)
    out = []
    for r, ev in zip(rows, ids):
        e = r["e"]; n = r["n"]
        if ev is None: out.append(None); continue
        al = None
        if not r["log_only"]: al = _detect(ev, r["ip"], r["msg"], e.get("dest_ip"), e.get("host"), e.get("severity"), e.get("title"), e.get("category"))
        elif n and n.get("alert"):                               # suspicious activity found by the activity normalizer
            t, sev, cat, amsg = n["alert"]; al = _detect(ev, r["ip"], amsg, e.get("dest_ip"), e.get("host"), sev, t, cat)
        if n and not al: al = _context_checks(ev, n, r, e)
        if not al: al = _custom_checks(ev, r, e)         # user-defined rules (Detection rules page)
        if al and n and activity.order(al["severity"]) > activity.order(n["risk"]): x("UPDATE events SET risk=? WHERE id=?", (al["severity"], ev))
        out.append(al)
    return out

_OS = {}
def _host_os(host):
    if not host: return None
    if host not in _OS:
        r = q("SELECT os FROM endpoints WHERE hostname=?", (host,), one=True); v = (r or {}).get("os") or ""
        _OS[host] = "Windows" if v.lower().startswith("win") else "Linux" if v else None
        if not _OS[host]: _OS.pop(host); return None
    return _OS[host]

def _in_hours(spec, ts):
    try:
        a, b = spec.split("-"); t = ts[11:16]
        return (a <= t <= b) if a <= b else (t >= a or t <= b)
    except Exception: return True

def _context_checks(ev, n, r, e):
    """Alerts that need history: successful login after many failures, login outside business hours."""
    if n["activity"] not in ("Successful Login", "SSH Login", "Remote Desktop Login", "Interactive Login") or n.get("status") != "Success": return None
    ip = r["ip"]; user = n.get("username") or "?"
    if ip and not ip.startswith(("127.", "::1")):
        try: base = datetime.strptime(r["ts"], FMT)
        except ValueError: base = datetime.now()
        win = (base - timedelta(minutes=10)).strftime(FMT)
        k = q("SELECT COUNT(*) c FROM events WHERE category='Authentication' AND status='Failure' AND source_ip=? AND ts>=? AND ts<=? AND id<?", (ip, win, r["ts"], ev), one=True)["c"]
        if k >= setting_num("brute_threshold", 5, 1, 100000):
            return _detect(ev, ip, f"Successful login for {user} from {ip} after {k} failed attempts in 10 minutes", None, e.get("host"), "Critical", "Successful Login After Multiple Failures", "auth")
    spec = os.environ.get("SOC_BUSINESS_HOURS") or setting("business_hours") or ""
    if spec and n["activity"] in ("SSH Login", "Remote Desktop Login", "Interactive Login") and not _in_hours(spec, r["ts"]) and not (user or "").endswith("$"):
        return _detect(ev, ip, f"Login by {user}{' from ' + ip if ip else ''} outside business hours ({spec})", None, e.get("host"), "Medium", "Login Outside Business Hours", "auth")
    return None

def backfill_activity():
    """Gives events stored before this feature (or by other tools) their activity fields. Runs once in the background, never raises alerts."""
    time.sleep(5)
    while True:
        rows = q("SELECT id,host,message,channel,event_id,provider,raw,source_ip FROM events WHERE nflag IS NULL ORDER BY id DESC LIMIT 2000")
        if not rows: return
        c = conn()
        try:
            for e in rows:
                n = activity.normalize(dict(e, log_only=True))
                if n: c.execute("UPDATE events SET category=?,activity=?,username=?,status=?,risk=?,os=?,nflag=1 WHERE id=?", (n["category"], n["activity"][:100], n.get("username"), n.get("status"), n["risk"], n.get("os") or _host_os(e["host"]), e["id"]))
                else: c.execute("UPDATE events SET nflag=1 WHERE id=?", (e["id"],))
            c.commit()
        finally: c.close()
        time.sleep(0.2)

def _sx(alert_id, ev):
    """EXE-SOC advanced layer hook (risk score, MITRE, whitelist, incident grouping). Failure here must never break detection."""
    try:
        import socx; socx.on_alert(alert_id, ev)
    except Exception as e: print("socx hook error:", e)

def process_event(source_ip, message, dest_ip=None, host=None, severity=None, title=None, category=None):
    """Store one event, apply detection rules, create/merge an alert. Returns alert dict or None."""
    return process_batch([dict(source_ip=source_ip, message=message, dest_ip=dest_ip, host=host, severity=severity, title=title, category=category)])[0]

def _detect(ev, source_ip, message, dest_ip, host, severity, title, category, force_cat=None):
    ts = now()
    hit = next(((t, s, c) for r, t, s, c in COMPILED if r.search(message)), None)
    if not hit and not severity: return None
    t, s, c = hit or (title or "Custom Event", severity, category or "custom")
    if title: t = title
    if severity in RANK: s = severity
    if force_cat: c = force_cat
    note = ""
    if c == "auth" and source_ip:   # brute-force escalation
        win = (datetime.now() - timedelta(minutes=setting_num("brute_window_min", 5, 1, 10080))).strftime("%Y-%m-%d %H:%M:%S")
        n = len([e for e in q("SELECT message FROM events WHERE source_ip=? AND ts>=?", (source_ip, win)) if BRUTE_RE.search(e["message"])])
        if n >= setting_num("brute_threshold", 5, 1, 100000): s, note = "Critical", f"{n} failed logins in {setting('brute_window_min')} min"
    if source_ip and (q("SELECT 1 FROM iocs WHERE value=?", (source_ip,), one=True) or q("SELECT 1 FROM blocklist WHERE ip=?", (source_ip,), one=True)):
        s, note = "Critical", (note + "; " if note else "") + "Source is a known IOC / blocked IP"
    ep = None
    if host: ep = q("SELECT id FROM endpoints WHERE hostname=?", (host,), one=True)
    if not ep and dest_ip: ep = q("SELECT id FROM endpoints WHERE ip=?", (dest_ip.split(":")[0],), one=True)
    eid = ep["id"] if ep else None
    since = (datetime.now() - timedelta(seconds=setting_num("dedupe_seconds", 120, 0, 604800))).strftime("%Y-%m-%d %H:%M:%S")
    dup = q("SELECT * FROM alerts WHERE title=? AND source_ip IS ? AND (source_ip IS NOT NULL OR endpoint_id IS ?) AND status!='Resolved' AND updated>=?", (t, source_ip, eid, since), one=True)
    if dup:
        top = s if RANK[s] > RANK[dup["severity"]] else dup["severity"]
        x("UPDATE alerts SET count=count+1,updated=?,severity=?,note=? WHERE id=?", (ts, top, note or dup["note"], dup["id"]))
        x("UPDATE events SET alert_id=? WHERE id=?", (dup["id"], ev))
        if top != dup["severity"]: run_playbooks(q("SELECT * FROM alerts WHERE id=?", (dup["id"],), one=True), above=RANK[dup["severity"]])
        _sx(dup["id"], ev); emit("refresh", {"what": "alerts"}); return dup
    country, la, lo = geo_for(source_ip)
    aid = x("INSERT INTO alerts(ts,updated,severity,title,category,source_ip,dest_ip,endpoint_id,message,country,lat,lon,note) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?)",
            (ts, ts, s, t, c, source_ip, dest_ip, eid, message, country, la, lo, note))
    x("UPDATE events SET alert_id=? WHERE id=?", (aid, ev))
    a = q("SELECT * FROM alerts WHERE id=?", (aid,), one=True)
    if la is None and setting("geo_lookup") == "1" and os.environ.get("SOC_GEO_ENABLED") == "1" and source_ip:      # sends attacker IPs to a third party: needs BOTH the setting and the operator env opt-in
        threading.Thread(target=_fetch_geo, args=(source_ip, aid), daemon=True).start()
    run_playbooks(a); _sx(aid, ev)
    emit("alert", {"id": a["id"], "severity": a["severity"], "title": str(a["title"])[:80]}); emit("refresh", {"what": "alerts"}); return a      # minimal push: no IPs, messages or raw event data


# ---------------- custom (user-defined) alert rules ----------------
_CR = {"t": 0.0, "rules": []}      # rule cache, reloaded every few seconds and on every change
_CR_HITS = {}                      # (rule_id, ip-or-host) -> [epoch seconds]; in memory like the login lockout state
_CR_RE = {}                        # (rule_id, pattern) -> compiled regex
def custom_rules_changed(): _CR["t"] = 0.0
CR_MAX_INPUT = 2000
def regex_probe(pattern, timeout=2.0):
    """Hard execution limit WITHOUT the optional `regex` module: the pattern is run in a separate interpreter against hostile inputs and killed after `timeout` s.
    Returns '' when it behaves, else a reason. Used when a rule is created/edited/tested (matching later is bounded to CR_MAX_INPUT characters)."""
    import subprocess
    probes = ["a" * 40 + "!", "ab" * 30 + "!", " " * 60 + "x", "0" * 50 + "x", "a" * CR_MAX_INPUT, "a b " * 500, "x" * 30 + "@" * 30]
    code = "import re,sys;p=re.compile(sys.argv[1],re.I);[p.search(s[:%d]) for s in %r]" % (CR_MAX_INPUT, probes)
    try: subprocess.run([sys.executable, "-I", "-c", code, pattern], timeout=timeout, capture_output=True)
    except subprocess.TimeoutExpired: return "pattern is too slow on adversarial input (ReDoS risk); simplify it"
    return ""
def cr_matcher(match_type, pattern):
    """Returns a function(text)->bool. Raises ValueError for a bad regex."""
    if match_type == "regex":
        if len(pattern) > 200: raise ValueError("regex too long (max 200 characters)")
        if re.search(r"\\[1-9]|\(\?[<=!P]", pattern): raise ValueError("backreferences and lookarounds are not allowed")
        if re.search(r"\([^()]*[+*][^()]*\)\s*[+*{]|\([^()]*\|[^()]*\)\s*[+*{]|[+*]\s*[+*]", pattern): raise ValueError("nested/ambiguous quantifiers are not allowed (ReDoS risk)")
        try:
            import regex as _rx2; rx2 = _rx2.compile(pattern, _rx2.I)         # optional: real execution limit when available
            return lambda t: bool(rx2.search((t or "")[:CR_MAX_INPUT], timeout=0.05))
        except ImportError: pass
        except Exception as ex: raise ValueError(f"invalid regex: {ex}")
        try: rx = re.compile(pattern, re.I)
        except re.error as ex: raise ValueError(f"invalid regex: {ex}")
        from security import rxsandbox
        return lambda t: rxsandbox.match(pattern, (t or "")[:CR_MAX_INPUT])      # no `regex` package: matching runs in a killable worker with a hard per-match timeout (security/rxsandbox.py)
    p = pattern.lower(); return lambda t: p in t.lower()
def _cr_rules():
    if time.time() - _CR["t"] > 5:
        _CR["rules"] = q("SELECT * FROM custom_rules WHERE enabled=1 ORDER BY id"); _CR["t"] = time.time()
    return _CR["rules"]
_CR_STRIKES = {}
CR_MAX_STRIKES = 3
def _cr_strike(cr):
    """A rule whose matching exceeded the hard timeout repeatedly is DISABLED (never deleted) and audited, so one bad pattern cannot keep degrading ingestion."""
    k = cr["id"]; _CR_STRIKES[k] = _CR_STRIKES.get(k, 0) + 1
    if _CR_STRIKES[k] >= CR_MAX_STRIKES:
        x("UPDATE custom_rules SET enabled=0 WHERE id=?", (k,)); _CR_STRIKES.pop(k, None); custom_rules_changed()
        try: _db.audit_add("system", f"Custom rule #{k} DISABLED: regex matching exceeded the per-match time limit {CR_MAX_STRIKES} times")
        except Exception: pass

def _custom_checks(ev, r, e):
    """Runs after the built-in rules found nothing. First matching custom rule raises (or merges into) an alert."""
    rules = _cr_rules()
    if not rules: return None
    host = (e.get("host") or ""); msg = r["msg"]; ip = r["ip"]; eid = _i(e.get("event_id"))
    for cr in rules:
        if cr["host_filter"] and not fnmatch.fnmatch(host.lower(), cr["host_filter"].lower()): continue
        if cr["event_id"] and eid != cr["event_id"]: continue
        key = (cr["id"], cr["pattern"])
        if key not in _CR_RE:
            try: _CR_RE[key] = cr_matcher(cr["match_type"], cr["pattern"])
            except ValueError: continue
        try:
            if not _CR_RE[key](msg): continue
        except Exception as ex:
            if type(ex).__name__ == "Timeout": _cr_strike(cr)                    # hard per-match timeout hit: treat as no match, count a strike
            continue
        amsg = msg; th = int(cr["threshold"] or 1)
        if th > 1:                                                   # "N matches from the same source within M minutes"
            w = max(1, int(cr["window_min"] or 5)) * 60; k = (cr["id"], ip or host or "-"); t = time.time()
            hits = [h for h in _CR_HITS.get(k, []) if t - h < w] + [t]
            if len(hits) < th: _CR_HITS[k] = hits; continue
            _CR_HITS.pop(k, None); amsg = f"{msg}  [rule '{cr['name']}': {len(hits)} matches in {cr['window_min']} min]"
        x("UPDATE custom_rules SET hits=hits+1,last_hit=? WHERE id=?", (now(), cr["id"]))
        return _detect(ev, ip, amsg, e.get("dest_ip"), e.get("host"), cr["severity"], cr["name"], cr["category"] or "custom", force_cat=cr["category"] or "custom")
    return None

def endpoint_status(e):
    """Online / At Risk / Offline / Inactive, derived from heartbeat age + open alerts."""
    try: age = (datetime.now() - datetime.strptime(e["last_seen"], "%Y-%m-%d %H:%M:%S")).total_seconds() / 60
    except Exception: age = 10**9
    if age > setting_num("inactive_hours", 24, 1, 87600) * 60: return "Inactive"
    if age > setting_num("offline_minutes", 5, 1, 525600): return "Offline"
    if e.get("isolated") or q("SELECT 1 FROM alerts WHERE endpoint_id=? AND status!='Resolved' AND severity IN ('Critical','High') LIMIT 1", (e["id"],), one=True): return "At Risk"
    return "Online"

def upsert_endpoint(hostname, ip=None, os_=None, cpu=0, ram=0):
    x("""INSERT INTO endpoints(hostname,ip,os,cpu,ram,last_seen,created_at) VALUES(?,?,?,?,?,?,?)
         ON CONFLICT(hostname) DO UPDATE SET ip=COALESCE(?,ip),os=COALESCE(?,os),cpu=?,ram=?,last_seen=?""",
      (hostname, ip, os_, cpu, ram, now(), now(), ip, os_, cpu, ram, now()))

CPU = {"v": 0.0}
def cpu_sampler():
    """The ONLY caller of psutil.cpu_percent. psutil measures since the previous call, so several callers
    (dashboard poll, host monitor, ...) made each other read ~0%. Everyone else reads CPU["v"]."""
    import psutil
    psutil.cpu_percent(None)
    while True:
        time.sleep(2)
        try: CPU["v"] = psutil.cpu_percent(None)
        except Exception: pass

def host_monitor():
    import psutil, platform, socket
    host = socket.gethostname()
    try: ip = socket.gethostbyname(host)
    except Exception: ip = "127.0.0.1"
    while True:
        try: upsert_endpoint(host, ip, f"{platform.system()} {platform.release()}", CPU["v"], psutil.virtual_memory().percent)
        except Exception: pass
        time.sleep(10)

SSH_RE = re.compile(r"(Failed password|Invalid user|authentication failure|Accepted password).*?(\d{1,3}(?:\.\d{1,3}){3})")
def tail_log():
    """Follow the auth log (path from settings) and feed matching lines to the engine."""
    path, pos = None, 0
    while True:
        if LOCAL_COLLECT.is_set(): time.sleep(3); continue
        p = setting("log_file")
        try:
            if p != path or not os.path.exists(p): path, pos = p, (os.path.getsize(p) if os.path.exists(p) else 0)
            if os.path.exists(p) and os.access(p, os.R_OK):
                size = os.path.getsize(p)
                if size < pos: pos = 0
                with open(p, errors="replace") as f:
                    f.seek(pos)
                    for line in f:
                        m = SSH_RE.search(line)
                        if m and "Accepted" not in m.group(1): process_event(m.group(2), line.strip(), dest_ip="localhost")
                    pos = f.tell()
        except Exception: pass
        time.sleep(3)

_last_cmd = [0]
def _local_extras(host, inv):
    """SOC's own computer: software inventory (vulnerability check) and, only if SOC_ENFORCE=1, firewall commands."""
    import vuln
    if inv.due():
        d = inv.collect()
        if d: vuln.store_inventory(host, d["ecosystem"], d["packages"])
    if os.environ.get("SOC_ENFORCE") == "1" and time.time() - _last_cmd[0] > 5:
        _last_cmd[0] = time.time(); import enforce
        for c in q("SELECT id,action,arg FROM commands WHERE host=? AND status='pending' ORDER BY id LIMIT 50", (host,)):
            ok, msg = enforce.execute(c["action"], c["arg"], allow_isolate=False)          # never isolate the SOC server itself
            x("UPDATE commands SET status=?,done_at=?,result=? WHERE id=?", ("done" if ok else "failed", now(), msg[:500], c["id"]))
            _db.audit_add("system", f"{host}: {c['action']} {c['arg']} -> {'ok' if ok else 'FAILED'} {msg[:120]}")

LOCAL_COLLECT = threading.Event()    # set while the built-in full-log collector runs (the old auth.log tail is then skipped, so nothing is counted twice)

def local_logs_loop():
    """Collect THIS computer's logs in-process: Windows Event Log, or Linux/Ubuntu journal + log files. Disable with SOC_LOCAL_LOGS=0."""
    import socket, sys
    sys.path.insert(0, os.path.dirname(os.path.abspath(__file__))); sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "tools"))
    if os.environ.get("SOC_LOCAL_LOGS", os.environ.get("SOC_LOCAL_EVENTLOG", "1")) != "1": return
    sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "tools"))
    import collect
    col = collect.get_collector(cursor_file=os.path.join(os.path.dirname(os.path.abspath(__file__)), ".locallogs_cursor.json")); host = socket.gethostname()
    LOCAL_COLLECT.set()
    import inventory; inv = inventory.Inventory()
    print("  Full log collection is ON for this computer: " + ", ".join(getattr(col, "sources", None) or getattr(col, "channels", [])) + "\n  (needs Administrator on Windows / root on Linux to read the Security / auth / journal logs)")
    while True:
        try:
            t0 = time.time(); items = col.poll(host)
            if items:
                for i in range(0, len(items), 500): process_batch(items[i:i + 500])
                print(f"logs: {len(items)} events stored in {(time.time() - t0) * 1000:.0f} ms")
            col.commit()                       # cursor saved only after the events are in the database
            _local_extras(host, inv)
        except Exception as e: print("log collector error:", e)
        time.sleep(0.2 if col.backlog else col.interval)
win_eventlog_loop = local_logs_loop   # old name kept

def retention_loop():
    while True:
        d = (datetime.now() - timedelta(days=setting_num("retention_days", 90, 1, 36500))).strftime("%Y-%m-%d %H:%M:%S")
        try:
            import unified.store as _us; _us.purge(setting_num("raw_retention_days", 30, 1, 36500), setting_num("retention_days", 90, 1, 36500))
        except Exception as _e: print("unified retention error:", _e)
        x("DELETE FROM events WHERE ts<?", (d,)); x("DELETE FROM commands WHERE created<?", (now(datetime.now() - timedelta(days=7)),)); x("DELETE FROM alerts WHERE ts<? AND status='Resolved'", (d,)); time.sleep(3600)


# MITRE ATT&CK mapping + analyst guidance per detection title
MITRE = {
 "Possible SQL Injection": ("T1190", "Exploit Public-Facing Application", "Initial Access"),
 "Cross-Site Scripting Attempt": ("T1189", "Drive-by Compromise", "Initial Access"),
 "Path Traversal Attempt": ("T1083", "File and Directory Discovery", "Discovery"),
 "Brute Force Login Attempt": ("T1110", "Brute Force", "Credential Access"),
 "Malware Detected": ("T1204", "User Execution", "Execution"),
 "Privilege Escalation Attempt": ("T1068", "Exploitation for Privilege Escalation", "Privilege Escalation"),
 "Port Scan Detected": ("T1046", "Network Service Discovery", "Discovery"),
 "Audit Log Cleared": ("T1070.001", "Indicator Removal: Clear Windows Event Logs", "Defense Evasion"),
 "New User Account Created": ("T1136.001", "Create Account: Local Account", "Persistence"),
 "Suspicious Service Installed": ("T1543.003", "Create or Modify System Process: Windows Service", "Persistence"),
  "File Integrity Change": ("T1565.001", "Data Manipulation: Stored Data Manipulation", "Impact"),
 "Unusual DNS Query": ("T1071.004", "Application Layer Protocol: DNS", "Command and Control"),
 "Suspicious PowerShell (encoded command)": ("T1059.001", "Command and Scripting Interpreter: PowerShell", "Execution"),
 "Suspicious PowerShell (download and execute)": ("T1059.001", "Command and Scripting Interpreter: PowerShell", "Execution"),
 "Suspicious PowerShell Script": ("T1059.001", "Command and Scripting Interpreter: PowerShell", "Execution"),
 "Credential Dumping Attempt": ("T1003", "OS Credential Dumping", "Credential Access"),
 "Reverse Shell Command": ("T1059", "Command and Scripting Interpreter", "Execution"),
 "Remote Script Download and Execute": ("T1105", "Ingress Tool Transfer", "Command and Control"),
 "Suspicious Command (living-off-the-land)": ("T1218", "System Binary Proxy Execution", "Defense Evasion"),
 "Backup / Recovery Destruction Command": ("T1490", "Inhibit System Recovery", "Impact"),
 "Security Tool Tampering Command": ("T1562.001", "Impair Defenses: Disable or Modify Tools", "Defense Evasion"),
 "Security Tool Disabled": ("T1562.001", "Impair Defenses: Disable or Modify Tools", "Defense Evasion"),
 "Log / History Tampering Command": ("T1070", "Indicator Removal", "Defense Evasion"),
 "Local Account Created via Command Line": ("T1136.001", "Create Account: Local Account", "Persistence"),
 "Sensitive File Read (/etc/shadow)": ("T1003.008", "OS Credential Dumping: /etc/passwd and /etc/shadow", "Credential Access"),
 "Process Executed From Temporary Location": ("T1204", "User Execution", "Execution"),
 "Office Application Spawned a Shell": ("T1204.002", "User Execution: Malicious File", "Execution"),
 "Web Server Spawned a Shell": ("T1505.003", "Server Software Component: Web Shell", "Persistence"),
 "Shell Process Network Connection": ("T1071", "Application Layer Protocol", "Command and Control"),
 "Connection To Suspicious Port": ("T1571", "Non-Standard Port", "Command and Control"),
 "Remote Thread Injection": ("T1055", "Process Injection", "Defense Evasion"),
 "Account Locked Out": ("T1110", "Brute Force", "Credential Access"),
 "Successful Login After Multiple Failures": ("T1110", "Brute Force", "Credential Access"),
 "Login Outside Business Hours": ("T1078", "Valid Accounts", "Initial Access"),
}
GUIDE = {
 "web": ["Review web server access logs for the same source IP and payload.", "Confirm WAF / input validation covers the affected URL.", "Check whether any request returned HTTP 200 with abnormal size."],
 "auth": ["Check for a successful login from this IP after the failures.", "Lock or reset the targeted account if a login succeeded.", "Block the IP and enforce MFA / fail2ban."],
 "malware": ["Isolate the endpoint and run a full AV / EDR scan.", "Collect the file hash and search other hosts for it.", "Reset credentials used on the host."],
 "system": ["Review sudo / auth logs for the user involved.", "Verify the user is authorised; revoke access if not."],
 "network": ["Check firewall logs for the scanned port range.", "Block the source and verify exposed services are intended."],
 "process": ["Open the Activity page for this device and user and review what ran before and after.", "Check the full command line and the parent process; kill the process if it is not expected.", "Isolate the endpoint if it looks like an attack, then collect the file and its hash."],
 "persistence": ["Check who installed it and whether the path and file are legitimate.", "Disable and remove the service or task if it is not authorised, then scan the file."],
 "dns": ["Inspect queried domains for DGA / tunnelling patterns.", "Sinkhole or block the domain at the resolver."],
}
