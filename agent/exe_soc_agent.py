#!/usr/bin/env python3
"""EXE-SOC Endpoint Agent (Windows 10/11, Ubuntu, Debian).  Visible, consent-based, outbound-only (HTTPS) security telemetry.

  python exe_soc_agent.py enroll --server https://soc.example.com --token <ENROLLMENT_TOKEN> [--ca-bundle ca.pem]
  python exe_soc_agent.py run          # normally started by the service installed by install_linux.sh / install_windows.ps1
  python exe_soc_agent.py status | what-we-collect

NEVER collected: passwords, browser data, keystrokes, screenshots, camera/microphone, file contents, private messages.
The agent executes NO remote commands: it only sends telemetry. TLS certificate verification is always on."""
import argparse, getpass, hashlib, json, os, platform, re, secrets, socket, sqlite3, ssl, subprocess, sys, threading, time
from urllib.parse import urlparse
from datetime import datetime, timezone
HERE = os.path.dirname(os.path.abspath(__file__)); sys.path.insert(0, os.path.join(HERE, "collectors"))
import requests, psutil
from soc_preflight import explain_text, ca_problem, check_server_steps

VERSION = "1.0.0"
WIN = platform.system() == "Windows"
HOME = os.environ.get("EXESOC_AGENT_HOME") or (os.path.join(os.environ.get("ProgramData", r"C:\ProgramData"), "EXE-SOC-Agent") if WIN else "/var/lib/exe-soc-agent")
CONF = os.environ.get("EXESOC_AGENT_CONF") or os.path.join(HOME, "agent.json"); QDB = os.path.join(HOME, "queue.db"); STATUS = os.path.join(HOME, "status.json")     # Linux installer puts CONF in /etc/exe-soc-agent
EXIT_REVOKED, EXIT_CONFIG = 3, 4                  # the systemd unit does NOT restart on these (a revoked/misconfigured agent must not hammer the server in a loop)
HB_S, BATCH = max(5.0, float(os.environ.get("EXESOC_HEARTBEAT_SECONDS", "30"))), 200       # 30 s; the override exists for tests/diagnosis
QUEUE_MAX_ROWS, QUEUE_MAX_MB = int(os.environ.get("EXESOC_QUEUE_ROWS", 50000)), int(os.environ.get("EXESOC_QUEUE_MB", 100))
CONSENT = """EXE-SOC Endpoint Agent - what this does
  COLLECTS : security-relevant logs (Windows Event Log / Linux journal, auth.log, syslog), logons and failed logons, process starts, service and
             scheduled-task/cron changes, account changes, listening ports and connections, file-integrity hashes of configured directories,
             host info (name, OS, IPs), agent health (CPU/RAM/queue).
  NEVER    : passwords, browser data, keystrokes, screenshots, webcam/microphone, file contents, private messages. No remote commands are executed.
  SENT TO  : {server} over HTTPS (certificate verified). You can stop it any time (service stop / uninstall) and the SOC admin can revoke it.
"""

def log(*a): print(datetime.now().strftime("%Y-%m-%d %H:%M:%S"), *a, flush=True)

def secure_dir():
    os.makedirs(HOME, exist_ok=True)
    try:
        if WIN:
            r = subprocess.run(["icacls", HOME, "/inheritance:r", "/grant:r", "SYSTEM:(OI)(CI)F", "Administrators:(OI)(CI)F"], capture_output=True)
            if r.returncode != 0: print("WARNING: could not restrict permissions on the agent data folder (credentials file); run as Administrator.", file=sys.stderr)
        else: os.chmod(HOME, 0o700)
    except Exception: pass

def _user():
    try: return getpass.getuser()
    except Exception: return "this user"

def load_conf():
    """None only when there is no config file. An unreadable or corrupt file is reported, never mistaken for 'not enrolled'."""
    try:
        with open(CONF) as f: return json.load(f)
    except FileNotFoundError: return None
    except PermissionError: sys.exit(f"ERROR: cannot read {CONF} as user '{_user()}' (permission denied). The service user must own it:  sudo chown <service-user> {CONF} && sudo chmod 600 {CONF}")
    except (OSError, ValueError) as e: sys.exit(f"ERROR: {CONF} is unreadable or corrupt ({e.__class__.__name__}). Enroll again with a new token: exe_soc_agent.py enroll --force ...")

def save_conf(c):
    secure_dir(); os.makedirs(os.path.dirname(CONF), exist_ok=True); tmp = CONF + ".tmp"
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)          # credential file: owner-only
    with os.fdopen(fd, "w") as f: json.dump(c, f)
    os.replace(tmp, CONF)
    if not WIN: os.chmod(CONF, 0o600)

def write_status(d):
    """Small health file for the doctor/diagnostics (no secrets). Failure is reported once, never silent."""
    try:
        tmp = STATUS + ".tmp"
        with open(tmp, "w") as f: json.dump(d, f)
        os.replace(tmp, STATUS)
    except OSError as e:
        if not getattr(write_status, "warned", False): write_status.warned = True; log(f"warning: cannot write {STATUS}: {e}")

def check_server(url):
    if url.lower().startswith("https://"): return
    if os.environ.get("EXESOC_ALLOW_HTTP_LOOPBACK") == "1" and re.match(r"http://(127\.0\.0\.1|localhost)(:|/|$)", url.lower()): return   # tests only
    sys.exit("ERROR: the server URL must be https:// (TLS is mandatory).")

def explain(e, server=None):
    """requests/ssl/socket exception -> one clear sentence plus the fix. Raw tracebacks help nobody at 2 a.m."""
    t = str(e)
    if isinstance(e, OSError) and ("CA certificate bundle" in t or "invalid path" in t): return f"The CA bundle file cannot be used: {t[:160]}"
    return explain_text(t if not isinstance(e, requests.exceptions.SSLError) else t + " ssl", urlparse(server or "").hostname, isinstance(e, (requests.exceptions.ConnectTimeout, requests.exceptions.ReadTimeout, socket.timeout)))

def http_hint(code, msg):
    msg = (msg or "")[:200]
    return {401: f"The server rejected the enrollment token ({msg}). Tokens are single-use and expire; ask the SOC admin for a new one (Fleet page > Enrollment tokens).",
            403: f"The server refused this request ({msg}).", 404: "The server answered but has no EXE-SOC API at this address. Check the URL/port (and any reverse-proxy path).",
            429: "Rate limited by the server. Wait a minute and try again.", 400: f"The server rejected the request: {msg}. (If this is about the hostname, choose another one with --name.)"}.get(code, f"Unexpected answer from the server (HTTP {code}): {msg}")

def validate_ca(path):
    """Absolute path, or exit with a clear message. Parses the file so a wrong/empty/garbled bundle is caught before enrollment."""
    if not path: return None
    p = os.path.abspath(path); problem = ca_problem(p)
    if problem: sys.exit("ERROR: " + problem)
    return p

class Client:
    def __init__(self, c):
        self.base = c["server"].rstrip("/"); self.cred = c.get("credential"); self.skey = c.get("signing_key"); self.s = requests.Session()
        self.verify = c.get("ca_bundle") or True                               # True = system trust store (or a private CA file). verify is NEVER False.
    def post(self, path, obj, auth=True, timeout=30):
        h = {"Authorization": f"Bearer {self.cred}", "X-Timestamp": str(int(time.time())), "X-Nonce": secrets.token_urlsafe(16), "Content-Type": "application/json"} if auth else {"Content-Type": "application/json"}
        data = json.dumps(obj, separators=(",", ":")).encode()
        if auth and self.skey:       # HMAC-SHA256 over method, path, timestamp, nonce and the EXACT body bytes (see security/agentsig.py)
            import hashlib, hmac
            canon = "\n".join(("EXESOC-HMAC-SHA256-V1", "POST", path, h["X-Timestamp"], h["X-Nonce"], hashlib.sha256(data).hexdigest()))
            h["X-Signature"] = "v1=" + hmac.new(self.skey.encode(), canon.encode(), hashlib.sha256).hexdigest()
        # Never forward bearer credentials to a different host through an HTTP redirect.
        r = self.s.post(self.base + path, data=data, headers=h, timeout=timeout, verify=self.verify, allow_redirects=False)
        if 300 <= r.status_code < 400:
            raise requests.RequestException(f"SOC endpoint redirected (HTTP {r.status_code}); check the configured HTTPS URL")
        return r

def _distro(ver=False):
    try:
        d = dict(l.strip().split("=", 1) for l in open("/etc/os-release") if "=" in l)
        return d.get("PRETTY_NAME" if ver else "NAME", "").strip('"') or platform.release()
    except Exception: return platform.release()

OS_RELEASE_FILES = ("/etc/os-release", "/usr/lib/os-release")
_ID_RX = re.compile(r"[a-z0-9][a-z0-9._-]{0,39}"); _VER_RX = re.compile(r"[A-Za-z0-9][A-Za-z0-9._~+-]{0,39}")

def parse_os_release(text):
    """KEY=value lines of an os-release file -> dict. Comments/blank/malformed lines are ignored; one pair per line; matching quotes stripped; never raises."""
    out = {}
    for line in str(text)[:8192].splitlines():
        line = line.strip()
        if not line or line.startswith("#") or "=" not in line: continue
        k, v = line.split("=", 1); k = k.strip(); v = v.strip()
        if not re.fullmatch(r"[A-Z_][A-Z0-9_]*", k): continue
        if len(v) >= 2 and v[0] == v[-1] and v[0] in "\"'": v = v[1:-1]
        out[k] = v
    return out

def os_metadata(system=None, read=None):
    """Machine-readable OS facts sent ADDITIONALLY to os/os_version (older servers ignore unknown fields): os_family (windows|linux|darwin), and on Linux distro_id / distro_version
    taken from the ID and VERSION_ID fields of /etc/os-release. Read-only, bounded (8 KB), never raises; a missing or unreadable file simply yields no distro fields."""
    fam = (system or platform.system()).strip().lower(); m = {}
    if fam in ("windows", "linux", "darwin"): m["os_family"] = fam
    if fam == "linux":
        for f in OS_RELEASE_FILES:
            try:
                d = parse_os_release(read(f) if read else open(f, encoding="utf-8", errors="replace").read(8192))
            except Exception: continue
            did = d.get("ID", "").strip().lower(); ver = d.get("VERSION_ID", "").strip()
            if _ID_RX.fullmatch(did): m["distro_id"] = did
            if _VER_RX.fullmatch(ver): m["distro_version"] = ver
            if "distro_id" in m: break
    return m

def host_info():
    ips = [a.address for n in psutil.net_if_addrs().values() for a in n if a.family == socket.AF_INET and not a.address.startswith("127.")]
    return {"hostname": socket.gethostname(), "os": "Windows" if WIN else _distro(), "os_version": (platform.version()[:100] if WIN else _distro(True)), "ips": ips[:8], **os_metadata()}

def read_token(a):
    """Token from --token-file, --token (visible in ps: avoid), EXESOC_ENROLL_TOKEN, or a hidden prompt. Never stored; used once."""
    if a.token_file:
        try:
            with open(a.token_file) as f: t = f.read().strip()
        except OSError as e: sys.exit(f"ERROR: cannot read --token-file {a.token_file}: {e.strerror or e}")
    else: t = a.token or os.environ.get("EXESOC_ENROLL_TOKEN") or ""
    if not t:
        if not sys.stdin.isatty(): sys.exit("ERROR: no enrollment token. Pass --token-file FILE, set EXESOC_ENROLL_TOKEN, or run in a terminal to be asked.")
        t = getpass.getpass("Enrollment token (input hidden): ").strip()
    if not t: sys.exit("ERROR: empty enrollment token.")
    return t

def cmd_enroll(a):
    check_server(a.server); ca = validate_ca(a.ca_bundle); old = load_conf()
    if old and old.get("credential") and not a.force: return print(f"Already enrolled as {old.get('hostname')} ({old.get('agent_id')}); nothing changed. To enroll again (needs a NEW token) use --force.")
    print(CONSENT.format(server=a.server))
    if not a.accept:
        try: ans = input("Type I AGREE to authorize monitoring of this device: ").strip()
        except EOFError: sys.exit("ERROR: no terminal to answer the consent question. Read:  exe_soc_agent.py what-we-collect  and, if the owner of this device agrees, re-run with --accept.")
        if ans != "I AGREE": sys.exit("Not authorized. Nothing was installed or sent.")
    token = read_token(a); h = host_info(); name = a.name or h["hostname"]
    if not re.fullmatch(r"[\w.\- ]{1,100}", name): sys.exit("ERROR: --name may only contain letters, digits, space . _ - (max 100 characters).")
    c = {"server": a.server, "ca_bundle": ca}
    try: secure_dir(); os.makedirs(os.path.dirname(CONF), exist_ok=True); probe = CONF + ".probe"; open(probe, "w").close(); os.remove(probe)      # BEFORE the single-use token is spent
    except OSError as e: sys.exit(f"ERROR: cannot write to {os.path.dirname(CONF)} as user '{_user()}' ({e.strerror or e}). Nothing was sent and the token is NOT used up. Fix the folder owner/permissions and run again.")
    try: r = Client(c).post("/api/agents/register", {"enrollment_token": token, "hostname": name, "os": h["os"], "os_version": h["os_version"], "agent_version": VERSION, **os_metadata()}, auth=False, timeout=20)
    except requests.RequestException as e: sys.exit("Enrollment failed: " + explain(e, a.server) + "  (Nothing was changed; the token was not used up.)")
    if r.status_code != 200:
        try: msg = r.json().get("error")
        except ValueError: msg = r.text[:120]
        sys.exit(f"Enrollment failed (HTTP {r.status_code}): " + http_hint(r.status_code, msg))
    try: d = r.json(); c.update(agent_id=d["agent_id"], credential=d["credential"], signing_key=d.get("signing_key"), hostname=d["hostname"], consent=datetime.now(timezone.utc).isoformat())
    except (ValueError, KeyError): sys.exit("Enrollment failed: the server's answer was not an EXE-SOC enrollment response. Is --server pointing at the SOC?")
    try: save_conf(c)
    except OSError as e: sys.exit(f"ERROR: enrolled, but could NOT save the credential to {CONF} ({e.strerror or e}). The token is now used up: ask the SOC admin to revoke agent {d['agent_id']} and issue a new token.")
    print(f"Enrolled as {d['hostname']} ({d['agent_id']}). Credential stored in {CONF} (owner-only). Start it with: exe_soc_agent.py run (or the installed service).")

def cmd_check_server(a):
    ok = True
    for step, good, detail, fix in check_server_steps(a.server, validate_ca(a.ca_bundle)):
        print(f"  {'PASS' if good else 'FAIL'}  {step:<16} {detail}"); ok = ok and good
        if not good and fix: print(f"        -> {fix}")
    sys.exit(0 if ok else 1)

class Queue:
    """Bounded on-disk FIFO. Oldest events are dropped (and counted) at the row/size cap. uid dedupes locally; the server dedupes again."""
    def __init__(self):
        secure_dir(); self.db = sqlite3.connect(QDB, check_same_thread=False, timeout=30); self.lk = threading.Lock(); self.dropped = 0
        self.db.execute("CREATE TABLE IF NOT EXISTS q(seq INTEGER PRIMARY KEY AUTOINCREMENT, uid TEXT UNIQUE, body TEXT)")
        have = {r[1] for r in self.db.execute("PRAGMA table_info(q)")}
        for col, typ in (("hold_until", "REAL DEFAULT 0"), ("tries", "INTEGER DEFAULT 0")):        # retry state lives in the queue row, so it survives restarts and is written atomically with SQLite
            if col not in have: self.db.execute(f"ALTER TABLE q ADD COLUMN {col} {typ}")
        self.db.execute("CREATE TABLE IF NOT EXISTS dead(seq INTEGER PRIMARY KEY AUTOINCREMENT, uid TEXT, body TEXT, reason TEXT, failed_at TEXT DEFAULT CURRENT_TIMESTAMP)"); self.db.commit()
    def count(self): return self.db.execute("SELECT COUNT(*) FROM q").fetchone()[0]
    def add(self, evs):
        if not evs: return
        with self.lk:
            for e in evs: self.db.execute("INSERT OR IGNORE INTO q(uid,body) VALUES(?,?)", (e["uid"], json.dumps(e, ensure_ascii=False)))
            self.db.commit(); n = self.count(); size = os.path.getsize(QDB) / 1048576 if os.path.exists(QDB) else 0
            if n > QUEUE_MAX_ROWS or size > QUEUE_MAX_MB:
                # Enforce the row cap first; SQLite file size may not shrink after DELETE, so do not repeatedly discard valid queued events based on stale file size.
                cut = max(n - int(QUEUE_MAX_ROWS * 0.9), 0)
                if cut:
                    self.db.execute("INSERT INTO dead(uid,body,reason) SELECT uid,body,'queue row cap exceeded' FROM q ORDER BY seq LIMIT ?", (cut,))
                    self.db.execute("DELETE FROM q WHERE seq IN (SELECT seq FROM q ORDER BY seq LIMIT ?)", (cut,)); self.db.execute("DELETE FROM dead WHERE seq NOT IN (SELECT seq FROM dead ORDER BY seq DESC LIMIT 5000)"); self.db.commit(); self.dropped += cut
                # Reclaim unused pages periodically when physical file growth, rather than live queue rows, is the problem.
                if size > QUEUE_MAX_MB:
                    self.db.execute("PRAGMA wal_checkpoint(TRUNCATE)"); self.db.execute("VACUUM")
    def peek(self, n, exclude=(), now=None):
        """Oldest n ELIGIBLE events. Held events are filtered in SQL (hold_until in the future), so any number of held rows costs nothing and cannot starve newer events;
        reads are always bounded by n + len(exclude). A hold further in the future than MAX_HOLD_S is impossible by design (clock moved backwards): treated as expired.
        A locally corrupt record is moved to the dead-letter table instead of crashing the loop for every later event."""
        t = time.time() if now is None else now; out = []
        with self.lk:
            rows = self.db.execute("SELECT seq,uid,body FROM q WHERE (CASE WHEN typeof(hold_until) IN ('real','integer') THEN hold_until ELSE 0 END) <= ? OR hold_until > ? ORDER BY seq LIMIT ?",
                                   (t, t + MAX_HOLD_S + 5, n + len(exclude))).fetchall()
            for seq, uid, body in rows:
                if uid in exclude: continue
                try: ev = json.loads(body)
                except (ValueError, TypeError):
                    self.db.execute("INSERT INTO dead(uid,body,reason) VALUES(?,?,?)", (uid, body, "corrupt local record")); self.db.execute("DELETE FROM q WHERE seq=?", (seq,)); self.db.commit(); continue
                if not isinstance(ev, dict) or not isinstance(ev.get("uid"), str):
                    self.db.execute("INSERT INTO dead(uid,body,reason) VALUES(?,?,?)", (uid, body, "corrupt local record")); self.db.execute("DELETE FROM q WHERE seq=?", (seq,)); self.db.commit(); continue
                out.append((seq, ev))
                if len(out) >= n: break
        return out
    def hold(self, uids, base, now=None):
        """Persist 'retry later' for these uids (exponential: base*2^tries, capped at MAX_HOLD_S). One transaction."""
        t = time.time() if now is None else now
        with self.lk:
            for u in uids:
                r = self.db.execute("SELECT COALESCE(tries,0) FROM q WHERE uid=?", (u,)).fetchone()
                if r is None: continue
                n = int(r[0]) + 1; self.db.execute("UPDATE q SET tries=?, hold_until=? WHERE uid=?", (n, t + min(base * 2 ** (n - 1), MAX_HOLD_S), u))
            self.db.commit()
    def held(self, now=None):
        t = time.time() if now is None else now; return self.db.execute("SELECT COUNT(*) FROM q WHERE typeof(hold_until) IN ('real','integer') AND hold_until > ? AND hold_until <= ?", (t, t + MAX_HOLD_S + 5)).fetchone()[0]
    def ack(self, seqs):
        with self.lk: self.db.executemany("DELETE FROM q WHERE seq=?", [(s,) for s in seqs]); self.db.commit()

def to_event(e, agent_id):
    """Collector event -> wire event with a stable uid, so a resend after a failure can never create a duplicate. Original event time is preserved."""
    uid = hashlib.sha256(f"{agent_id}|{e.get('channel')}|{e.get('record_id')}|{e.get('event_time')}|{(e.get('message') or '')[:200]}".encode()).hexdigest()[:40]
    keep = ("message", "channel", "event_id", "level", "provider", "record_id", "event_time", "raw", "log_only", "source_ip", "dest_ip")
    out = {k: e.get(k) for k in keep if e.get(k) is not None}; out["uid"] = uid
    for k in ("message", "raw"):
        if isinstance(out.get(k), str) and len(out[k]) > 8000: out[k] = out[k][:8000]                  # the server stores at most 4000/8000 characters anyway; stay far below its 64 KB event limit
    if "event_time" not in out: out["event_time"] = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%f")
    return out

RETRY_BASE_S = float(os.environ.get("EXESOC_RETRY_BASE_SECONDS", "30"))       # wait before re-sending an event the server asked us to retry (doubles per attempt)
MAX_HOLD_S = 900                                                                 # longest single hold: 15 min
MAX_TRIED_PER_FLUSH = 5 * BATCH                                                  # one flush never walks more than this many retried events (bounded work per cycle)

def _ack_lists(reply, batch_uids):
    """Strict acknowledgement parsing. Returns (accepted, duplicate, rejected, retry, reasons) restricted to THIS batch. Raises ValueError when the reply is not a valid
    per-event acknowledgement; then NOTHING may be deleted (HTTP 200 alone proves nothing). Valid means: protocol version known (absent = v1 server, no retry list), each list
    is a list of strings without repeats, every uid acknowledged belongs to this batch, the four outcome lists are mutually exclusive."""
    if not isinstance(reply, dict): raise ValueError("server reply is not a JSON object; no per-event acknowledgement")
    ver = reply.get("ack_version", 1)
    if isinstance(ver, bool) or ver not in (1, 2): raise ValueError(f"unsupported acknowledgement protocol version {str(ver)[:10]!r}; batch retained")
    lists = []
    for k in ("accepted_uids", "duplicate_uids", "rejected_uids", "retry_uids"):
        v = reply.get(k, [] if k == "retry_uids" else None)
        if not isinstance(v, list) or not all(isinstance(u, str) for u in v): raise ValueError(f"server reply lacks a valid per-event acknowledgement list '{k}'; batch retained")
        if len(set(v)) != len(v): raise ValueError(f"'{k}' repeats a uid; batch retained")
        if not set(v) <= batch_uids: raise ValueError(f"'{k}' acknowledges a uid that was not in this batch; batch retained")
        lists.append(set(v))
    for i in range(4):
        for j in range(i + 1, 4):
            if lists[i] & lists[j]: raise ValueError("a uid appears in more than one outcome list; batch retained")
    rs = reply.get("reasons"); rs = {k: str(v)[:60] for k, v in rs.items() if isinstance(k, str) and k in batch_uids} if isinstance(rs, dict) else {}
    return lists[0], lists[1], lists[2], lists[3], rs

def flush_queue(cl, q, st):
    """Send queued events until the queue is empty or only held ('retry later') events remain. Returns True when the server answered at least once.
    Deletes an event ONLY when the server explicitly accepted it or reports it already processed. Rejected events go to the local dead-letter table (kept, counted,
    shown on the dashboard). Events the server could not process yet stay queued with a persisted hold and never block newer events."""
    contact = False; tried = set()
    while len(tried) < MAX_TRIED_PER_FLUSH:
        items = q.peek(BATCH, exclude=tried)
        if not items: return contact
        r = cl.post("/api/events", {"events": [e for _, e in items]}, timeout=60)
        if r.status_code in (401, 403): log("Server rejected this agent. Stopping."); sys.exit(EXIT_REVOKED)
        r.raise_for_status()
        try: reply = r.json()
        except ValueError: reply = None
        uids = {e.get("uid") for _, e in items}
        acc, dup, rej, ret, reasons = _ack_lists(reply, uids)              # ValueError -> caller treats it as a failed upload: backoff, everything retained
        contact = True; done = acc | dup
        q.ack([seq for seq, ev in items if ev.get("uid") in done]); st["sent"] += len(acc)
        rejected = [(seq, ev) for seq, ev in items if ev.get("uid") in rej]
        if rejected:
            with q.lk:
                q.db.executemany("INSERT INTO dead(uid,body,reason) VALUES(?,?,?)", [(ev.get("uid"), json.dumps(ev, ensure_ascii=False), ("server rejected: " + reasons.get(ev.get("uid"), "unspecified"))[:100]) for _, ev in rejected])
                q.db.executemany("DELETE FROM q WHERE seq=?", [(seq,) for seq, _ in rejected]); q.db.commit()
            st["rejected"] += len(rejected); why = sorted({reasons.get(ev.get("uid"), "unspecified") for _, ev in rejected})
            st["rej_msg"] = f"server rejected {len(rejected)} events ({', '.join(why)}); records saved to the local dead-letter queue" + ("; the device clock is probably wrong (events dated in the future)" if "timestamp_in_future" in why else "")
            st["rej_until"] = time.time() + 600; log(st["rej_msg"])
        later = [ev.get("uid") for _, ev in items if ev.get("uid") not in done and ev.get("uid") not in rej]     # asked to retry, or not accounted for at all: kept, never deleted
        if later:
            q.hold(later, RETRY_BASE_S); tried.update(later)
            why = sorted({reasons.get(u, "not acknowledged") for u in later})
            st["rej_msg"] = f"server asked to retry {len(later)} events later ({', '.join(why)}); kept in the queue"; st["rej_until"] = time.time() + 120; log(st["rej_msg"])
    return contact

def cmd_run(a):
    c = load_conf()
    if not c or not c.get("credential"): log("Not enrolled. Run: exe_soc_agent.py enroll --server https://... (token via EXESOC_ENROLL_TOKEN or --token-file)"); sys.exit(EXIT_CONFIG)
    check_server(c["server"])
    if c.get("ca_bundle") and not os.access(c["ca_bundle"], os.R_OK): log(f"CA bundle {c['ca_bundle']} is missing or not readable by user '{_user()}'."); sys.exit(EXIT_CONFIG)
    cl = Client(c); q = Queue(); host = c["hostname"]; aid = c["agent_id"]
    os.environ.setdefault("SOC_WIN_CURSOR", os.path.join(HOME, "winevents_cursor.json")); os.environ.setdefault("SOC_LINUX_CURSOR", os.path.join(HOME, "linuxlogs_cursor.json"))
    import collect; col = collect.get_collector(os.path.join(HOME, "cursor.json"))
    st = dict(sent=0, fail=0, fail_recent=0, last_ok=None, reachable=True, errors=[], rejected=0, rej_until=0, rej_msg=""); start = time.time(); backoff = 1; last_hb = 0
    log(f"EXE-SOC agent {VERSION} started for {host} -> {c['server']}  collectors: {', '.join(getattr(col, 'sources', []))}")
    while True:
        try:
            errs = []
            try: q.add([to_event(e, aid) for e in col.poll(host)]); col.commit()                          # local collection continues while the server is unreachable
            except Exception as e: errs.append(f"collector: {e}"[:120])
            errs += col.problems() if hasattr(col, "problems") else []
            if time.time() < st["rej_until"]: errs.append(st["rej_msg"])
            for m in errs:
                if m not in st["errors"]: log("collector problem:", m)                                      # once per new problem; also sent in the heartbeat -> dashboard
            st["errors"] = errs[:5]
            if time.time() - last_hb >= HB_S:
                last_hb = time.time()
                try:
                    r = cl.post("/api/agents/heartbeat", dict(host_info(), agent_version=VERSION, cpu=psutil.cpu_percent(None), mem=psutil.virtual_memory().percent, events_sent=st["sent"], events_queued=q.count(),
                                upload_failures=st["fail"], upload_failures_recent=st["fail_recent"], last_success=st["last_ok"], server_reachable=st["reachable"], collectors=getattr(col, "sources", []),
                                collector_errors=st["errors"], uptime_s=time.time() - start, dropped=q.dropped), timeout=15)
                    if r.status_code in (401, 403): log("Server rejected this agent (revoked or invalid credential). Stopping."); sys.exit(EXIT_REVOKED)
                    r.raise_for_status(); st["last_ok"] = datetime.now(timezone.utc).isoformat(); st["reachable"] = True
                    write_status(dict(version=VERSION, host=host, agent_id=aid, server=c["server"], heartbeat_ok_at=st["last_ok"], events_sent=st["sent"], events_rejected=st["rejected"], events_queued=q.count(), upload_failures=st["fail"], collectors=list(getattr(col, "sources", [])), collector_errors=st["errors"], user=_user(), pid=os.getpid()))
                except requests.RequestException as e: st["reachable"] = False; log("heartbeat failed:", type(e).__name__)
            if flush_queue(cl, q, st): st["fail_recent"] = 0; st["reachable"] = True; st["last_ok"] = datetime.now(timezone.utc).isoformat(); backoff = 1
        except SystemExit: raise
        except requests.exceptions.SSLError as e:
            st["fail"] += 1; st["fail_recent"] += 1; st["reachable"] = False; backoff = min(backoff * 2, 300); log("TLS certificate validation FAILED (never bypassed):", str(e)[:160])
        except Exception as e:
            st["fail"] += 1; st["fail_recent"] += 1; st["reachable"] = False; backoff = min(backoff * 2, 300); log("upload failed, will retry:", str(e)[:150])
        time.sleep(max(getattr(col, "interval", 2), backoff if st["fail_recent"] else 0) + secrets.randbelow(1000) / 1000)     # exponential backoff + jitter

def cmd_status(a):
    c = load_conf()
    if not c: return print("Not enrolled.")
    print(json.dumps({k: v for k, v in c.items() if k not in ("credential", "signing_key")}, indent=2)); print("queued events:", Queue().count())

def main():
    p = argparse.ArgumentParser(prog="exe_soc_agent"); sp = p.add_subparsers(dest="cmd", required=True)
    e = sp.add_parser("enroll"); e.add_argument("--server", required=True); e.add_argument("--token", help="visible in 'ps'; prefer --token-file or EXESOC_ENROLL_TOKEN"); e.add_argument("--token-file"); e.add_argument("--ca-bundle")
    e.add_argument("--name", help="device name shown in the SOC (default: this computer's hostname)"); e.add_argument("--force", action="store_true", help="enroll again even if already enrolled (needs a NEW token)")
    e.add_argument("--accept", action="store_true", help="skip the typed consent prompt (you have still read what is collected)")
    k = sp.add_parser("check-server", help="test DNS, TCP, TLS certificate and the SOC API without sending any credential"); k.add_argument("--server", required=True); k.add_argument("--ca-bundle")
    sp.add_parser("run"); sp.add_parser("status"); sp.add_parser("what-we-collect")
    a = p.parse_args()
    {"enroll": cmd_enroll, "check-server": cmd_check_server, "run": cmd_run, "status": cmd_status, "what-we-collect": lambda a: print(CONSENT.format(server="your SOC server"))}[a.cmd](a)

if __name__ == "__main__": main()
