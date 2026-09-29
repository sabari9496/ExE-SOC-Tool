"""Detection rules, alert creation, playbooks, geo lookup, host monitor, log tailing."""
import re, os, time, ipaddress, threading, json, subprocess, urllib.request
from datetime import datetime, timedelta
from db import q, x, now, setting, RANK

emit = lambda *a, **k: None      # replaced by app.py with socketio.emit

RULES = [  # (regex, title, severity, category)
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
IP_RE = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")

def is_private(ip):
    try: a = ipaddress.ip_address(ip); return a.is_private or a.is_loopback or a.is_link_local
    except ValueError: return True

def valid_ip(ip):
    try: ipaddress.ip_address(ip); return True
    except (ValueError, TypeError): return False

def geo_for(ip):
    if not ip or is_private(ip):
        return "Internal", float(setting("home_lat")), float(setting("home_lon"))
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

def block_ip(ip, reason, user="system"):
    if not valid_ip(ip) or is_private(ip) or q("SELECT 1 FROM blocklist WHERE ip=?", (ip,), one=True): return False
    x("INSERT INTO blocklist VALUES(?,?,?,?)", (ip, reason, user, now()))
    if setting("firewall_enforce") == "1" and hasattr(os, "geteuid") and os.geteuid() == 0:
        subprocess.run(["iptables", "-I", "INPUT", "-s", ip, "-j", "DROP"], check=False, timeout=5)
    x("INSERT INTO audit(ts,user,action) VALUES(?,?,?)", (now(), user, f"Blocked {ip}: {reason}"))
    return True

def unblock_ip(ip):
    x("DELETE FROM blocklist WHERE ip=?", (ip,))
    if setting("firewall_enforce") == "1" and valid_ip(ip) and hasattr(os, "geteuid") and os.geteuid() == 0:
        subprocess.run(["iptables", "-D", "INPUT", "-s", ip, "-j", "DROP"], check=False, timeout=5)

def run_playbooks(a, above=0):
    """Run enabled playbooks whose trigger severity is met (and, on escalation, newly reached)."""
    for p in q("SELECT * FROM playbooks WHERE enabled=1"):
        if RANK[a["severity"]] < RANK.get(p["min_severity"], 3) or RANK.get(p["min_severity"], 3) <= above or (p["category"] and p["category"] != a["category"]): continue
        act = p["action"]
        if act == "block_ip": block_ip(a["source_ip"], f"Playbook: {p['name']}")
        elif act == "create_case" and not q("SELECT 1 FROM case_alerts WHERE alert_id=?", (a["id"],), one=True):
            cid = x("INSERT INTO cases(title,description,priority,status,assignee,created_at) VALUES(?,?,?,?,?,?)",
                    (f"[Auto] {a['title']} from {a['source_ip']}", a["message"], a["severity"] if a["severity"] != "Critical" else "High", "Open", None, now()))
            x("INSERT INTO case_alerts VALUES(?,?)", (cid, a["id"]))
        elif act == "notify": emit("toast", {"severity": a["severity"], "text": f"{a['title']} from {a['source_ip']}"})
        elif act == "isolate_endpoint" and a["endpoint_id"]: x("UPDATE endpoints SET isolated=1 WHERE id=?", (a["endpoint_id"],))
        x("UPDATE playbooks SET runs=runs+1,last_run=? WHERE id=?", (now(), p["id"]))

def process_event(source_ip, message, dest_ip=None, host=None, severity=None, title=None, category=None):
    """Store the event, apply detection rules, create/merge an alert. Returns alert dict or None."""
    ts = now(); message = (message or "")[:2000]
    if not source_ip:
        m = IP_RE.search(message); source_ip = m.group() if m else None
    ev = x("INSERT INTO events(ts,source_ip,dest_ip,host,message) VALUES(?,?,?,?,?)", (ts, source_ip, dest_ip, host, message))
    hit = next(((t, s, c) for r, t, s, c in COMPILED if r.search(message)), None)
    if not hit and not severity: return None
    t, s, c = hit or (title or "Custom Event", severity, category or "custom")
    if title: t = title
    if severity in RANK: s = severity
    note = ""
    if c == "auth" and source_ip:   # brute-force escalation
        win = (datetime.now() - timedelta(minutes=int(setting("brute_window_min")))).strftime("%Y-%m-%d %H:%M:%S")
        n = len([e for e in q("SELECT message FROM events WHERE source_ip=? AND ts>=?", (source_ip, win)) if COMPILED[3][0].search(e["message"])])
        if n >= int(setting("brute_threshold")): s, note = "Critical", f"{n} failed logins in {setting('brute_window_min')} min"
    if source_ip and (q("SELECT 1 FROM iocs WHERE value=?", (source_ip,), one=True) or q("SELECT 1 FROM blocklist WHERE ip=?", (source_ip,), one=True)):
        s, note = "Critical", (note + "; " if note else "") + "Source is a known IOC / blocked IP"
    ep = None
    if host: ep = q("SELECT id FROM endpoints WHERE hostname=?", (host,), one=True)
    if not ep and dest_ip: ep = q("SELECT id FROM endpoints WHERE ip=?", (dest_ip.split(":")[0],), one=True)
    eid = ep["id"] if ep else None
    since = (datetime.now() - timedelta(seconds=int(setting("dedupe_seconds")))).strftime("%Y-%m-%d %H:%M:%S")
    dup = q("SELECT * FROM alerts WHERE title=? AND source_ip IS ? AND status!='Resolved' AND updated>=?", (t, source_ip, since), one=True)
    if dup:
        top = s if RANK[s] > RANK[dup["severity"]] else dup["severity"]
        x("UPDATE alerts SET count=count+1,updated=?,severity=?,note=? WHERE id=?", (ts, top, note or dup["note"], dup["id"]))
        x("UPDATE events SET alert_id=? WHERE id=?", (dup["id"], ev))
        if top != dup["severity"]: run_playbooks(q("SELECT * FROM alerts WHERE id=?", (dup["id"],), one=True), above=RANK[dup["severity"]])
        emit("refresh", {"what": "alerts"}); return dup
    country, la, lo = geo_for(source_ip)
    aid = x("INSERT INTO alerts(ts,updated,severity,title,category,source_ip,dest_ip,endpoint_id,message,country,lat,lon,note) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?)",
            (ts, ts, s, t, c, source_ip, dest_ip, eid, message, country, la, lo, note))
    x("UPDATE events SET alert_id=? WHERE id=?", (aid, ev))
    a = q("SELECT * FROM alerts WHERE id=?", (aid,), one=True)
    if la is None and setting("geo_lookup") == "1" and source_ip:
        threading.Thread(target=_fetch_geo, args=(source_ip, aid), daemon=True).start()
    run_playbooks(a)
    emit("alert", a); emit("refresh", {"what": "alerts"}); return a

def endpoint_status(e):
    """Online / At Risk / Offline / Inactive, derived from heartbeat age + open alerts."""
    try: age = (datetime.now() - datetime.strptime(e["last_seen"], "%Y-%m-%d %H:%M:%S")).total_seconds() / 60
    except Exception: age = 10**9
    if age > int(setting("inactive_hours")) * 60: return "Inactive"
    if age > int(setting("offline_minutes")): return "Offline"
    if e.get("isolated") or q("SELECT 1 FROM alerts WHERE endpoint_id=? AND status!='Resolved' AND severity IN ('Critical','High') LIMIT 1", (e["id"],), one=True): return "At Risk"
    return "Online"

def upsert_endpoint(hostname, ip=None, os_=None, cpu=0, ram=0):
    x("""INSERT INTO endpoints(hostname,ip,os,cpu,ram,last_seen,created_at) VALUES(?,?,?,?,?,?,?)
         ON CONFLICT(hostname) DO UPDATE SET ip=COALESCE(?,ip),os=COALESCE(?,os),cpu=?,ram=?,last_seen=?""",
      (hostname, ip, os_, cpu, ram, now(), now(), ip, os_, cpu, ram, now()))

def host_monitor():
    import psutil, platform, socket
    host = socket.gethostname()
    try: ip = socket.gethostbyname(host)
    except Exception: ip = "127.0.0.1"
    psutil.cpu_percent(None)
    while True:
        try: upsert_endpoint(host, ip, f"{platform.system()} {platform.release()}", psutil.cpu_percent(None), psutil.virtual_memory().percent)
        except Exception: pass
        time.sleep(10)

SSH_RE = re.compile(r"(Failed password|Invalid user|authentication failure|Accepted password).*?(\d{1,3}(?:\.\d{1,3}){3})")
def tail_log():
    """Follow the auth log (path from settings) and feed matching lines to the engine."""
    path, pos = None, 0
    while True:
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

def retention_loop():
    while True:
        d = (datetime.now() - timedelta(days=int(setting("retention_days")))).strftime("%Y-%m-%d %H:%M:%S")
        x("DELETE FROM events WHERE ts<?", (d,)); x("DELETE FROM alerts WHERE ts<? AND status='Resolved'", (d,)); time.sleep(3600)


# MITRE ATT&CK mapping + analyst guidance per detection title
MITRE = {
 "Possible SQL Injection": ("T1190", "Exploit Public-Facing Application", "Initial Access"),
 "Cross-Site Scripting Attempt": ("T1189", "Drive-by Compromise", "Initial Access"),
 "Path Traversal Attempt": ("T1083", "File and Directory Discovery", "Discovery"),
 "Brute Force Login Attempt": ("T1110", "Brute Force", "Credential Access"),
 "Malware Detected": ("T1204", "User Execution", "Execution"),
 "Privilege Escalation Attempt": ("T1068", "Exploitation for Privilege Escalation", "Privilege Escalation"),
 "Port Scan Detected": ("T1046", "Network Service Discovery", "Discovery"),
 "Unusual DNS Query": ("T1071.004", "Application Layer Protocol: DNS", "Command and Control"),
}
GUIDE = {
 "web": ["Review web server access logs for the same source IP and payload.", "Confirm WAF / input validation covers the affected URL.", "Check whether any request returned HTTP 200 with abnormal size."],
 "auth": ["Check for a successful login from this IP after the failures.", "Lock or reset the targeted account if a login succeeded.", "Block the IP and enforce MFA / fail2ban."],
 "malware": ["Isolate the endpoint and run a full AV / EDR scan.", "Collect the file hash and search other hosts for it.", "Reset credentials used on the host."],
 "system": ["Review sudo / auth logs for the user involved.", "Verify the user is authorised; revoke access if not."],
 "network": ["Check firewall logs for the scanned port range.", "Block the source and verify exposed services are intended."],
 "dns": ["Inspect queried domains for DGA / tunnelling patterns.", "Sinkhole or block the domain at the resolver."],
}
