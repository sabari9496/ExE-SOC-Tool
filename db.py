"""SQLite layer + schema + demo data."""
import os, sys, sqlite3, secrets, random
from datetime import datetime, timedelta
from werkzeug.security import generate_password_hash

BASE = os.path.dirname(os.path.abspath(__file__))
DB = os.environ.get("SOC_DB", os.path.join(BASE, "soc.db"))
class BadInput(ValueError):
    """Client sent data of the wrong type/shape. The API turns this into HTTP 400 (never a 500)."""

def iarg(v, default=0, lo=-2 ** 62, hi=2 ** 62):
    """Client value -> int clamped to [lo, hi]; anything unusable (abc, None, list, nan, 1e999) -> default. Never raises, never overflows SQLite."""
    try: n = int(v)
    except (TypeError, ValueError, OverflowError): return default
    return max(lo, min(hi, n))

def farg(v, default=0.0, lo=-1e12, hi=1e12):
    try: n = float(v)
    except (TypeError, ValueError, OverflowError): return default
    return default if n != n else max(lo, min(hi, n))

def sarg(v, maxlen=None):
    """Client text -> stripped str. None -> ''. Numbers are stringified; lists/dicts/booleans are rejected with BadInput (HTTP 400)."""
    if v is None: return ""
    if isinstance(v, bool) or not isinstance(v, (str, int, float)): raise BadInput("expected text")
    v = str(v).replace("\x00", "").strip()
    return v[:maxlen] if maxlen else v

def setting_num(k, default, lo=None, hi=None, cast=int):
    """Numeric setting that can never raise: a corrupted/old value in the database falls back to the default and is clamped to [lo, hi]."""
    try: n = cast(setting(k))
    except (TypeError, ValueError, OverflowError): n = default
    if n != n: n = default
    if lo is not None: n = max(lo, n)
    if hi is not None: n = min(hi, n)
    return n

def csv_cell(v):
    """Neutralise spreadsheet formula injection: a cell starting with = + - @ (or tab/CR) is prefixed with an apostrophe."""
    if isinstance(v, str) and v[:1] in ("=", "+", "-", "@", "\t", "\r"): return "'" + v
    return v

RANK = {"Low": 1, "Medium": 2, "High": 3, "Critical": 4}

def now(dt=None): return (dt or datetime.now()).strftime("%Y-%m-%d %H:%M:%S")

def _busy_timeout():
    try: return min(max(float(os.environ.get("SOC_DB_TIMEOUT", "15")), 0.1), 120.0)
    except ValueError: return 15.0

def conn():
    c = sqlite3.connect(DB, timeout=_busy_timeout()); c.row_factory = sqlite3.Row
    c.execute("PRAGMA journal_mode=WAL"); c.execute("PRAGMA foreign_keys=ON"); return c

def q(sql, args=(), one=False):
    c = conn()
    try:
        r = c.execute(sql, args).fetchall()
    finally: c.close()
    r = [dict(i) for i in r]
    return (r[0] if r else None) if one else r

def xc(sql, args=()):
    """Like x() but returns the affected row count (atomic compare-and-set patterns)."""
    c = conn()
    try:
        cur = c.execute(sql, args); c.commit(); return cur.rowcount
    finally: c.close()

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
CREATE TABLE IF NOT EXISTS custom_rules(id INTEGER PRIMARY KEY, name TEXT NOT NULL, description TEXT DEFAULT '', enabled INTEGER DEFAULT 1, match_type TEXT DEFAULT 'contains', pattern TEXT NOT NULL, host_filter TEXT DEFAULT '', event_id INTEGER, severity TEXT DEFAULT 'Medium', category TEXT DEFAULT 'custom', mitre TEXT DEFAULT '', threshold INTEGER DEFAULT 1, window_min INTEGER DEFAULT 5, hits INTEGER DEFAULT 0, last_hit TEXT, created_by TEXT, created_at TEXT);
CREATE TABLE IF NOT EXISTS commands(id INTEGER PRIMARY KEY, host TEXT, action TEXT, arg TEXT, status TEXT DEFAULT 'pending', created TEXT, done_at TEXT, result TEXT);
CREATE INDEX IF NOT EXISTS ix_cmd ON commands(host, status);
CREATE TABLE IF NOT EXISTS packages(host TEXT, name TEXT, version TEXT, ecosystem TEXT, PRIMARY KEY(host, name));
CREATE TABLE IF NOT EXISTS vulns(id INTEGER PRIMARY KEY, host TEXT, package TEXT, version TEXT, vuln_id TEXT, summary TEXT, severity TEXT, aliases TEXT, seen TEXT, UNIQUE(host, package, vuln_id));
CREATE TABLE IF NOT EXISTS vuln_cache(vuln_id TEXT PRIMARY KEY, summary TEXT, severity TEXT, aliases TEXT);
CREATE TABLE IF NOT EXISTS vuln_scan(host TEXT PRIMARY KEY, ecosystem TEXT, packages INTEGER, vulnerable INTEGER, last_scan TEXT, status TEXT);
CREATE TABLE IF NOT EXISTS geo_cache(ip TEXT PRIMARY KEY, country TEXT, lat REAL, lon REAL);
CREATE INDEX IF NOT EXISTS ix_alert_ts ON alerts(ts); CREATE INDEX IF NOT EXISTS ix_alert_src ON alerts(source_ip);
CREATE INDEX IF NOT EXISTS ix_ev_src ON events(source_ip, ts);
"""
DEFAULTS = {"org_name": "EXE SOC", "home_lat": "20.59", "home_lon": "78.96", "brute_threshold": "5",
            "brute_window_min": "5", "dedupe_seconds": "120", "offline_minutes": "5", "inactive_hours": "24",
            "retention_days": "90", "geo_lookup": "0", "firewall_enforce": "0", "log_file": "/var/log/auth.log", "business_hours": ""}

def setting(k, default=None):
    r = q("SELECT value FROM settings WHERE key=?", (k,), one=True)
    v = r["value"] if r else DEFAULTS.get(k, default)
    if isinstance(v, str) and v.startswith("enc1:"):
        from security import crypto
        try: return crypto.decrypt(v, "setting|" + k)
        except crypto.CryptoError: return default           # key missing/wrong: behave as "not set" (fail closed for api_key_ok)
    return v
SECRET_SETTINGS = ("api_key",)
def set_secret_setting(k, v):
    from security import crypto; x("INSERT OR REPLACE INTO settings VALUES(?,?)", (k, crypto.encrypt(v, "setting|" + k)))

def audit_add(user, action):
    """Single chokepoint for audit rows: the row and its tamper-evident chain MAC are written in ONE transaction."""
    from security import auditchain
    c = conn()
    try:
        ts = now(); c.execute("BEGIN IMMEDIATE"); cur = c.execute("INSERT INTO audit(ts,user,action) VALUES(?,?,?)", (ts, user, action))
        auditchain.append(c, cur.lastrowid, ts, user, action); c.commit(); return cur.lastrowid
    except Exception: c.rollback(); raise
    finally: c.close()

EVENT_COLS = {"channel": "TEXT", "event_id": "INTEGER", "level": "TEXT", "provider": "TEXT", "record_id": "INTEGER", "raw": "TEXT",
              "category": "TEXT", "activity": "TEXT", "username": "TEXT", "status": "TEXT", "risk": "TEXT", "os": "TEXT", "nflag": "INTEGER"}

def machine_id():
    """Stable id of THIS computer. Used so a database copied from another PC is never shown as if it were local."""
    try:
        import winreg
        with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Microsoft\Cryptography") as k: return winreg.QueryValueEx(k, "MachineGuid")[0]
    except Exception: pass
    for f in ("/etc/machine-id", "/var/lib/dbus/machine-id"):
        try:
            v = open(f).read().strip()
            if v: return v
        except Exception: pass
    import socket, uuid; return f"{socket.gethostname()}-{uuid.getnode()}"

def _owner(path):
    try:
        import pwd, grp; st = os.stat(path)
        return f"{pwd.getpwuid(st.st_uid).pw_name}:{grp.getgrnam(grp.getgrgid(st.st_gid).gr_name).gr_name} (mode {oct(st.st_mode & 0o777)[2:]})"
    except Exception: return "another user"

def check_access(secret_file=None, need_secret=True):
    """Fail early, in plain English, when the data folder/files belong to a different user. The classic cause is starting the server once with
    sudo and once without: root then owns soc.db / .secret and the next start dies with 'attempt to write a readonly database'. Never deletes or changes anything."""
    folder = os.path.dirname(os.path.abspath(DB)) or "."; bad = []
    if not os.path.isdir(folder): bad.append(f"the database folder {folder} does not exist")
    elif not os.access(folder, os.W_OK | os.X_OK): bad.append(f"the folder {folder} is owned by {_owner(folder)} and is not writable by you (SQLite needs to create the -wal/-shm files there)")
    for f in [DB + e for e in ("", "-wal", "-shm")] + ([secret_file] if secret_file and need_secret else []):
        if os.path.exists(f) and not os.access(f, os.R_OK | (os.W_OK if f != secret_file else 0)):
            bad.append(f"{f} is owned by {_owner(f)} and you cannot {'read' if f == secret_file else 'read and write'} it")
    if not bad: return
    try: import getpass; me = getpass.getuser()
    except Exception: me = "your-user"
    print(f"\nERROR: EXE-SOC cannot use its data files as user '{me}':\n" + "".join(f"  - {b}\n" for b in bad) +
          f"\nWhy: the files were created by a different user, usually by starting the server once with sudo and once without.\n"
          f"Fix (choose ONE and then start it the same way every time):\n"
          f"  sudo chown -R {me}:{me} {folder}        # then start WITHOUT sudo\n"
          f"  or always start it with sudo (and keep the files owned by root)\n"
          f"  or keep the database elsewhere:  SOC_DB=/path/you/own/soc.db\n", file=sys.stderr)
    sys.exit(2)

def guard_foreign_db():
    """If soc.db was created on a different computer, move it aside (never deleted) so this install starts clean."""
    if not os.path.exists(DB) or os.environ.get("SOC_ALLOW_FOREIGN_DB") == "1": return
    try:
        c = sqlite3.connect(DB, timeout=15); r = c.execute("SELECT value FROM settings WHERE key='machine_id'").fetchone(); c.close()
    except Exception: return                     # old/empty db without a stamp: init_db() stamps it
    if r and r[0] != machine_id():
        stamp = datetime.now().strftime("%Y%m%d-%H%M%S")
        for ext in ("", "-wal", "-shm"):
            if os.path.exists(DB + ext): os.replace(DB + ext, f"{DB}.other-machine-{stamp}{ext}")
        print(f"  NOTE: soc.db came from a different computer. It was moved to {DB}.other-machine-{stamp} and a CLEAN database was created.\n")

def _write_initial_credentials(user, pw):
    """One-time bootstrap password -> <db dir>/initial_admin_credentials.txt, mode 0600, created atomically. Never printed/logged."""
    path = os.path.join(os.path.dirname(os.path.abspath(DB)), "initial_admin_credentials.txt")
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "w") as f: f.write(f"username={user}\npassword={pw}\nChange this password at first login, then DELETE this file.\n")
    print(f"  First start: a one-time admin password was written to {path} (read it, change it, delete the file).")

def _init_db_core():
    c = conn(); c.executescript(SCHEMA)
    pb_have = {r[1] for r in c.execute("PRAGMA table_info(playbooks)")}
    for col in ("title_like", "attack", "lib_id", "what"):          # playbook can target specific alert titles (one attack)
        if col not in pb_have: c.execute(f"ALTER TABLE playbooks ADD COLUMN {col} TEXT DEFAULT ''")
    have = {r[1] for r in c.execute("PRAGMA table_info(events)")}
    for col, typ in EVENT_COLS.items():
        if col not in have: c.execute(f"ALTER TABLE events ADD COLUMN {col} {typ}")
    c.executescript("""CREATE INDEX IF NOT EXISTS ix_ev_host ON events(host, id); CREATE INDEX IF NOT EXISTS ix_ev_chan ON events(channel, event_id, id);
        CREATE INDEX IF NOT EXISTS ix_ev_cat ON events(category, id); CREATE INDEX IF NOT EXISTS ix_ev_risk ON events(risk, id); CREATE INDEX IF NOT EXISTS ix_ev_user ON events(username);
        CREATE INDEX IF NOT EXISTS ix_ev_nflag ON events(nflag, id);
        CREATE UNIQUE INDEX IF NOT EXISTS ux_ev_rec ON events(host, channel, record_id, ts) WHERE record_id IS NOT NULL;""")
    c.execute("INSERT OR IGNORE INTO settings VALUES('machine_id',?)", (machine_id(),))
    for k, v in DEFAULTS.items(): c.execute("INSERT OR IGNORE INTO settings VALUES(?,?)", (k, v))
    c.execute("CREATE TABLE IF NOT EXISTS audit_chain(audit_id INTEGER PRIMARY KEY, prev TEXT NOT NULL, mac TEXT NOT NULL)")
    from security import crypto as _cr
    c.execute("INSERT OR IGNORE INTO settings VALUES('api_key',?)", (_cr.encrypt(secrets.token_hex(24), "setting|api_key"),))
    for _k in SECRET_SETTINGS:                                  # migrate legacy plaintext secrets to authenticated encryption
        _r = c.execute("SELECT value FROM settings WHERE key=?", (_k,)).fetchone()
        if _r and _r[0] and not str(_r[0]).startswith("enc1:"): c.execute("UPDATE settings SET value=? WHERE key=?", (_cr.encrypt(_r[0], "setting|" + _k), _k))
    if not c.execute("SELECT 1 FROM users").fetchone():
        # One account per role tier (admin > analyst > viewer) so the RBAC
        # hierarchy can be exercised immediately. Each password is
        # env-overridable; admin gets every permission, analyst gets
        # read/write on alerts/cases/endpoints/etc, viewer is read-only.
        # SECURITY: no well-known default passwords. Default = ONE admin with a random one-time password written to a 0600 file
        # (never printed or logged). Legacy 3-account demo logins only when SOC_ALLOW_DEFAULT_CREDS=1 (local dev/tests; refused when SOC_ENV=production).
        if os.environ.get("SOC_ALLOW_DEFAULT_CREDS") == "1" and os.environ.get("SOC_ENV") != "production":
            seed_users = [("admin", "admin", os.environ.get("SOC_ADMIN_PASSWORD", "Admin@123")),
                          ("analyst", "analyst", os.environ.get("SOC_ANALYST_PASSWORD", "Analyst@123")),
                          ("viewer", "viewer", os.environ.get("SOC_VIEWER_PASSWORD", "Viewer@123"))]
        else:
            seed_users = [("admin", "admin", os.environ.get("SOC_ADMIN_PASSWORD") or None)]
        for username, role, pw in seed_users:
            generated = pw is None
            if generated: pw = secrets.token_urlsafe(18)
            elif len(pw) < 12 and os.environ.get("SOC_ALLOW_DEFAULT_CREDS") != "1": raise SystemExit("SOC_ADMIN_PASSWORD must be at least 12 characters.")
            c.execute("INSERT INTO users(username,password_hash,role,created_at) VALUES(?,?,?,?)", (username, generate_password_hash(pw), role, now()))
            if generated: _write_initial_credentials(username, pw)
    if not c.execute("SELECT 1 FROM playbooks").fetchone():
        for n, s, cat, a in [("Auto-block critical brute force", "Critical", "auth", "block_ip"),
                             ("Open case for critical alerts", "Critical", "", "create_case"),
                             ("Notify analysts on high severity", "High", "", "notify"),
                             ("Isolate endpoint on malware", "High", "malware", "isolate_endpoint")]:
            c.execute("INSERT INTO playbooks(name,min_severity,category,action) VALUES(?,?,?,?)", (n, s, cat, a))
    c.execute("CREATE TABLE IF NOT EXISTS sessions(sid_hash TEXT PRIMARY KEY, username TEXT NOT NULL, created REAL NOT NULL, last_seen REAL NOT NULL, ip TEXT, revoked INTEGER DEFAULT 0)")
    c.execute("CREATE INDEX IF NOT EXISTS ix_sessions_user ON sessions(username)")
    c.commit(); c.close()
    try:
        import socx; socx.init()          # EXE-SOC advanced layer: adds its own tables only
    except Exception as e: print("socx init error:", e)
    try:
        import notify; notify.init()      # e-mail notification tables (new tables only)
    except Exception as e: print("notify init error:", e)
    try:
        import fleet; fleet.init()        # multi-endpoint agents: new tables + agent_id columns on events/alerts
    except Exception as e: print("fleet init error:", e)

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
    x("INSERT OR REPLACE INTO settings VALUES('demo_data','1')")
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


def harden_db_files():
    """SQLite file/dir permissions: DB + WAL/SHM owner-only (0600); production refuses a database directory that other users can write to."""
    if os.name != "posix": return
    d = os.path.dirname(os.path.abspath(DB))
    failed = []
    for suffix in ("", "-wal", "-shm"):
        p = DB + suffix
        if os.path.exists(p):
            try: os.chmod(p, 0o600)
            except OSError as ex: failed.append(f"{p}: {ex.strerror or ex}")
            if os.stat(p).st_mode & 0o077: failed.append(f"{p}: still accessible to other users (mode {oct(os.stat(p).st_mode & 0o777)})")
    if failed:                                    # hardening must FAIL VISIBLY, never pretend to succeed
        msg = "could not restrict database file permissions: " + "; ".join(failed)
        if os.environ.get("SOC_ENV") == "production": sys.exit("ERROR: " + msg)
        print("  WARNING: " + msg, file=sys.stderr)
    mode = os.stat(d).st_mode & 0o777
    if mode & 0o022:
        msg = f"database directory {d} is writable by other users (mode {oct(mode)}); run: chmod 700 {d}"
        if os.environ.get("SOC_ENV") == "production" and os.environ.get("SOC_ALLOW_LOOSE_DB_DIR") != "1": sys.exit("ERROR: " + msg)
        print("  WARNING: " + msg, file=sys.stderr)

def init_db():
    import migrations
    fresh = migrations.is_fresh(DB); migrations.check_compat(DB)          # refuse a database newer than this code BEFORE touching anything
    _init_db_core(); harden_db_files(); migrations.startup(DB, fresh)       # new DB: migrations applied; existing DB: notice only (see docs/PHASE2_DATABASE_PLAN.md)
