"""SQLite layer + schema + demo data."""
import os, sqlite3, secrets, random
from datetime import datetime, timedelta
from werkzeug.security import generate_password_hash

BASE = os.path.dirname(os.path.abspath(__file__))
DB = os.environ.get("SOC_DB", os.path.join(BASE, "soc.db"))
RANK = {"Low": 1, "Medium": 2, "High": 3, "Critical": 4}

def now(dt=None): return (dt or datetime.now()).strftime("%Y-%m-%d %H:%M:%S")

def conn():
    c = sqlite3.connect(DB, timeout=15); c.row_factory = sqlite3.Row
    c.execute("PRAGMA journal_mode=WAL"); c.execute("PRAGMA foreign_keys=ON"); return c

def q(sql, args=(), one=False):
    c = conn()
    try:
        r = c.execute(sql, args).fetchall()
    finally: c.close()
    r = [dict(i) for i in r]
    return (r[0] if r else None) if one else r

def x(sql, args=()):
    c = conn()
    try:
        cur = c.execute(sql, args); c.commit(); return cur.lastrowid
    finally: c.close()

SCHEMA = """
CREATE TABLE IF NOT EXISTS users(id INTEGER PRIMARY KEY, username TEXT UNIQUE NOT NULL, password_hash TEXT NOT NULL, role TEXT NOT NULL DEFAULT 'analyst', active INTEGER DEFAULT 1, created_at TEXT, last_login TEXT);
CREATE TABLE IF NOT EXISTS endpoints(id INTEGER PRIMARY KEY, hostname TEXT UNIQUE NOT NULL, ip TEXT, os TEXT, cpu REAL DEFAULT 0, ram REAL DEFAULT 0, isolated INTEGER DEFAULT 0, last_seen TEXT, created_at TEXT);
CREATE TABLE IF NOT EXISTS events(id INTEGER PRIMARY KEY, ts TEXT, source_ip TEXT, dest_ip TEXT, host TEXT, message TEXT, alert_id INTEGER);
CREATE TABLE IF NOT EXISTS alerts(id INTEGER PRIMARY KEY, ts TEXT, updated TEXT, severity TEXT, title TEXT, category TEXT, source_ip TEXT, dest_ip TEXT, endpoint_id INTEGER, message TEXT, status TEXT DEFAULT 'New', assignee TEXT, count INTEGER DEFAULT 1, country TEXT, lat REAL, lon REAL, resolved_at TEXT, note TEXT);
CREATE TABLE IF NOT EXISTS cases(id INTEGER PRIMARY KEY, title TEXT, description TEXT, priority TEXT DEFAULT 'Medium', status TEXT DEFAULT 'Open', assignee TEXT, created_at TEXT, closed_at TEXT);
CREATE TABLE IF NOT EXISTS case_notes(id INTEGER PRIMARY KEY, case_id INTEGER, author TEXT, note TEXT, ts TEXT);
CREATE TABLE IF NOT EXISTS case_alerts(case_id INTEGER, alert_id INTEGER, PRIMARY KEY(case_id, alert_id));
CREATE TABLE IF NOT EXISTS playbooks(id INTEGER PRIMARY KEY, name TEXT, min_severity TEXT DEFAULT 'High', category TEXT DEFAULT '', action TEXT, enabled INTEGER DEFAULT 1, runs INTEGER DEFAULT 0, last_run TEXT);
CREATE TABLE IF NOT EXISTS blocklist(ip TEXT PRIMARY KEY, reason TEXT, added_by TEXT, ts TEXT);
CREATE TABLE IF NOT EXISTS iocs(id INTEGER PRIMARY KEY, value TEXT UNIQUE, type TEXT DEFAULT 'ip', source TEXT, ts TEXT);
CREATE TABLE IF NOT EXISTS audit(id INTEGER PRIMARY KEY, ts TEXT, user TEXT, action TEXT);
CREATE TABLE IF NOT EXISTS alert_activity(id INTEGER PRIMARY KEY, alert_id INTEGER, ts TEXT, user TEXT, action TEXT);
CREATE INDEX IF NOT EXISTS ix_act_alert ON alert_activity(alert_id);
CREATE INDEX IF NOT EXISTS ix_ev_alert ON events(alert_id); CREATE INDEX IF NOT EXISTS ix_ev_ts ON events(ts);
CREATE TABLE IF NOT EXISTS settings(key TEXT PRIMARY KEY, value TEXT);
CREATE TABLE IF NOT EXISTS geo_cache(ip TEXT PRIMARY KEY, country TEXT, lat REAL, lon REAL);
CREATE INDEX IF NOT EXISTS ix_alert_ts ON alerts(ts); CREATE INDEX IF NOT EXISTS ix_alert_src ON alerts(source_ip);
CREATE INDEX IF NOT EXISTS ix_ev_src ON events(source_ip, ts);
"""
DEFAULTS = {"org_name": "EXE SOC", "home_lat": "20.59", "home_lon": "78.96", "brute_threshold": "5",
            "brute_window_min": "5", "dedupe_seconds": "120", "offline_minutes": "5", "inactive_hours": "24",
            "retention_days": "90", "geo_lookup": "1", "firewall_enforce": "0", "log_file": "/var/log/auth.log"}

def setting(k, default=None):
    r = q("SELECT value FROM settings WHERE key=?", (k,), one=True)
    return r["value"] if r else DEFAULTS.get(k, default)

def init_db():
    c = conn(); c.executescript(SCHEMA)
    for k, v in DEFAULTS.items(): c.execute("INSERT OR IGNORE INTO settings VALUES(?,?)", (k, v))
    c.execute("INSERT OR IGNORE INTO settings VALUES('api_key',?)", (secrets.token_hex(24),))
    if not c.execute("SELECT 1 FROM users").fetchone():
        # One account per role tier (admin > analyst > viewer) so the RBAC
        # hierarchy can be exercised immediately. Each password is
        # env-overridable; admin gets every permission, analyst gets
        # read/write on alerts/cases/endpoints/etc, viewer is read-only.
        seed_users = [
            ("admin",   "admin",   os.environ.get("SOC_ADMIN_PASSWORD", "Admin@123")),
            ("analyst", "analyst", os.environ.get("SOC_ANALYST_PASSWORD", "Analyst@123")),
            ("viewer",  "viewer",  os.environ.get("SOC_VIEWER_PASSWORD", "Viewer@123")),
        ]
        for username, role, pw in seed_users:
            c.execute("INSERT INTO users(username,password_hash,role,created_at) VALUES(?,?,?,?)",
                      (username, generate_password_hash(pw), role, now()))
    if not c.execute("SELECT 1 FROM playbooks").fetchone():
        for n, s, cat, a in [("Auto-block critical brute force", "Critical", "auth", "block_ip"),
                             ("Open case for critical alerts", "Critical", "", "create_case"),
                             ("Notify analysts on high severity", "High", "", "notify"),
                             ("Isolate endpoint on malware", "High", "malware", "isolate_endpoint")]:
            c.execute("INSERT INTO playbooks(name,min_severity,category,action) VALUES(?,?,?,?)", (n, s, cat, a))
    c.commit(); c.close()

DEMO_IPS = [("45.32.156.7","United States",37.77,-122.41),("103.21.244.9","India",19.07,72.87),("185.220.101.10","Germany",50.11,8.68),
            ("5.188.86.77","Russia",55.75,37.61),("177.54.12.3","Brazil",-23.55,-46.63),("41.79.5.2","Nigeria",6.52,3.37),
            ("1.180.44.8","China",39.90,116.40),("203.0.113.50","Australia",-33.86,151.20),("192.168.1.100","Internal",20.59,78.96)]
DEMO_EV = [("Possible SQL Injection","Critical","web","GET /login.php?id=1' OR 1=1--"),("Brute Force Login Attempt","High","auth","Failed password for root"),
           ("Malware Detected","High","malware","Malware detected: Trojan.Win32.Generic"),("Unusual DNS Query","Low","dns","Unusual DNS query to rare TLD"),
           ("Privilege Escalation Attempt","High","system","sudo: user not in sudoers"),("Port Scan Detected","Medium","network","Port scan from remote host"),
           ("Cross-Site Scripting Attempt","Medium","web","GET /search?q=<script>alert(1)</script>")]

def seed_demo():
    """Demo endpoints + ~2 days of alerts so the dashboard looks alive on first run."""
    if q("SELECT 1 FROM alerts LIMIT 1") or q("SELECT 1 FROM endpoints LIMIT 1"): return
    random.seed(7); n = datetime.now()
    oses = ["Windows 11", "Windows 10", "Ubuntu 22.04", "Kali Linux", "macOS 14", "Windows Server 2022"]
    for i in range(1, 25):
        age = random.choice([0]*17 + [30, 30, 90, 3000, 3000, 60*30, 60*40])  # minutes since last seen
        x("INSERT INTO endpoints(hostname,ip,os,cpu,ram,last_seen,created_at) VALUES(?,?,?,?,?,?,?)",
          (f"{random.choice(['DESKTOP','LAPTOP','SRV'])}-{i:02d}{random.choice('ABCDEFGH')}{random.randint(1,9)}", f"10.0.2.{10+i}", random.choice(oses),
           random.randint(5, 70), random.randint(20, 80), now(n - timedelta(minutes=age)), now(n)))
    eps = [e["id"] for e in q("SELECT id FROM endpoints")]
    for i in range(140):
        t, sv, cat, msg = random.choices(DEMO_EV, weights=[3, 6, 3, 2, 3, 3, 2])[0]
        ip, ctry, la, lo = random.choice(DEMO_IPS)
        ts = now(n - timedelta(minutes=random.randint(1, 47 * 60)))
        st = random.choices(["New", "In Progress", "Resolved"], weights=[5, 2, 6])[0]
        aid = x("INSERT INTO alerts(ts,updated,severity,title,category,source_ip,dest_ip,endpoint_id,message,status,country,lat,lon,resolved_at) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
          (ts, ts, sv, t, cat, ip, f"10.0.2.{random.choice([8, 15, 53])}:{random.choice([80, 22, 445, 53])}", random.choice(eps[:4] if sv in ("Critical", "High") else eps), msg, st, ctry, la, lo, ts if st == "Resolved" else None))
        x("INSERT INTO events(ts,source_ip,dest_ip,host,message,alert_id) VALUES(?,?,?,?,?,?)", (ts, ip, "10.0.2.8", "web-01", msg, aid))
    x("INSERT INTO cases(title,description,priority,status,assignee,created_at) VALUES('Investigate repeated SSH brute force','Multiple failed logins from 185.220.101.10','High','Open','admin',?)", (now(),))
    for ip, why in [("185.220.101.10", "Known Tor exit node"), ("5.188.86.77", "Scanner infrastructure")]:
        x("INSERT OR IGNORE INTO iocs(value,type,source,ts) VALUES(?,?,?,?)", (ip, "ip", why, now()))
