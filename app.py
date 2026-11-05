"""EXE SOC backend: REST API + live updates + auth/RBAC. Run: python app.py"""
import os, io, re, csv, sys, json, time, secrets, threading
import envload                      # loads .env (SMTP_*, EMAIL_FROM, SOC_*) before anything reads the environment
import sqlite3, traceback, hashlib
from datetime import datetime, timedelta
from functools import wraps
from flask import Flask, jsonify, request, session, redirect, render_template, Response, g
from werkzeug.exceptions import HTTPException
from werkzeug.routing import IntegerConverter, ValidationError
from werkzeug.security import generate_password_hash, check_password_hash
import psutil
import db, engine, investigate
from security import mfa, crypto, agentsig, throttle
from urllib.parse import urlparse
from db import q, x, now, setting, setting_num, RANK, iarg, farg, sarg, csv_cell, BadInput

try:
    from flask_socketio import SocketIO
    app = Flask(__name__); socketio = SocketIO(app, async_mode="threading", cors_allowed_origins=([o.strip() for o in os.environ.get("SOC_ALLOWED_ORIGINS", "").split(",") if o.strip()] or None))        # unset -> the library default: same-origin only (an empty list is NOT a documented "same-origin" value)
    engine.emit = lambda ev, data=None: socketio.emit(ev, data)
except ImportError:                       # live push disabled, UI falls back to polling
    app = Flask(__name__); socketio = None

class SafeInt(IntegerConverter):
    """<int:id> routes: ids beyond SQLite's 64-bit range are simply 'not found' instead of an OverflowError/500."""
    def to_python(self, value):
        n = int(value)
        if n > 2 ** 63 - 1: raise ValidationError()
        return n
app.url_map.converters["int"] = SafeInt

kf = os.path.join(db.BASE, ".secret")
_S = os.environ.get("SOC_SECRET") or ""
if os.environ.get("SOC_ENV") == "production":
    # fail closed: a production deployment never falls back to a file inside the code tree, and never accepts a short/trivial signing secret
    if len(_S) < 32 or len(set(_S)) < 8: sys.exit("ERROR: SOC_ENV=production requires SOC_SECRET (>= 32 characters, high entropy). Generate: python tools/rotate_secrets.py session-secret --out /root/new-secret.env")
else: db.check_access(kf, need_secret=not os.environ.get("SOC_SECRET"))          # clear message instead of a SQLite/permission traceback (see db.check_access)
if os.environ.get("SOC_ENV") != "production" and not os.path.exists(kf):
    try:
        fd = os.open(kf, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)          # atomic, born 0600 (no world-readable window)
        with os.fdopen(fd, "w") as _f: _f.write(secrets.token_hex(32))
    except OSError:
        if not os.environ.get("SOC_SECRET"): raise
app.secret_key = _S or open(kf).read()
_TP = [p.strip() for p in os.environ.get("SOC_TRUSTED_PROXIES", "").split(",") if p.strip()]
if _TP:
    from werkzeug.middleware.proxy_fix import ProxyFix
    class _TrustedProxyFix:
        """Honour X-Forwarded-* ONLY when the TCP peer is one of SOC_TRUSTED_PROXIES; from anyone else the headers are ignored (no IP spoofing / lockout bypass)."""
        def __init__(self, wsgi): self.wsgi = wsgi; self.fix = ProxyFix(wsgi, x_for=1, x_proto=1, x_host=1)
        def __call__(self, environ, start):
            return (self.fix if environ.get("REMOTE_ADDR") in _TP else self.wsgi)(environ, start)
    app.wsgi_app = _TrustedProxyFix(app.wsgi_app)
_PROD = os.environ.get("SOC_ENV") == "production"        # production: Secure + __Host- cookie always, strict agent-auth defaults, password minimum >= 12
SESSION_IDLE = int(os.environ.get("SOC_SESSION_IDLE_MIN", 30)) * 60; SESSION_ABS = int(os.environ.get("SOC_SESSION_ABS_HOURS", 12)) * 3600
app.config.update(SESSION_COOKIE_HTTPONLY=True, SESSION_COOKIE_SAMESITE="Lax", SESSION_COOKIE_NAME=("__Host-soc" if (_PROD or os.environ.get("SOC_COOKIE_SECURE") == "1") else "session"), JSON_SORT_KEYS=False, MAX_CONTENT_LENGTH=int(os.environ.get("SOC_MAX_BODY_MB", 16)) * 1024 * 1024,
                  SESSION_COOKIE_SECURE=_PROD or bool(os.environ.get("SOC_TLS_CERT")) or os.environ.get("SOC_COOKIE_SECURE") == "1")      # Secure cookie when served over HTTPS (also behind a TLS proxy: SOC_COOKIE_SECURE=1)

ROLES = {"viewer": 1, "analyst": 2, "admin": 3}
MIN_PW = max(12, int(os.environ.get("SOC_MIN_PASSWORD", 12))) if _PROD else int(os.environ.get("SOC_MIN_PASSWORD", 12))          # new passwords; legacy shorter ones still log in until changed
def audit(action, user=None): db.audit_add(user or session.get("user", "system"), action)
def me():
    """Logged-in user name, re-checked against the database on EVERY request: a deleted or deactivated user, a changed role or a changed password
    takes effect immediately. The signed cookie alone is never trusted (it cannot be revoked server-side)."""
    u = session.get("user")
    if not u: return None
    cached = getattr(g, "cur_user", False)
    if cached is not False: return cached
    row = q("SELECT role, active, password_hash FROM users WHERE username=?", (u,), one=True)
    if not row or not row["active"] or session.get("pv") != row["password_hash"][-16:] or not _session_alive(u):
        session.clear(); g.cur_user = None; return None
    session["role"] = row["role"]; g.cur_user = u; return u

def _sid_hash(sid): return hashlib.sha256((sid or "").encode()).hexdigest()
def _session_alive(user):
    """Server-side session record: revocable, idle timeout, absolute timeout. A cookie without a live record is worthless."""
    sid = session.get("sid")
    if not sid: return False
    s = q("SELECT username, created, last_seen, revoked FROM sessions WHERE sid_hash=?", (_sid_hash(sid),), one=True); t = time.time()
    if not s or s["revoked"] or s["username"] != user or t - s["created"] > SESSION_ABS or t - s["last_seen"] > SESSION_IDLE: return False
    if t - s["last_seen"] > 60: x("UPDATE sessions SET last_seen=? WHERE sid_hash=?", (t, _sid_hash(sid)))
    return True
def start_session(u):
    """Rotation: a brand-new random session id on every login (never reuse a pre-login cookie)."""
    session.clear(); sid = secrets.token_urlsafe(32); t = time.time()
    x("INSERT INTO sessions(sid_hash,username,created,last_seen,ip) VALUES(?,?,?,?,?)", (_sid_hash(sid), u["username"], t, t, request.remote_addr))
    x("DELETE FROM sessions WHERE created < ?", (t - SESSION_ABS - 86400,))
    session.update(user=u["username"], role=u["role"], pv=u["password_hash"][-16:], sid=sid, csrf=secrets.token_urlsafe(24))
WS = {}                                  # socket sid -> (username, session-id hash): lets revocation cut LIVE connections, not just new ones
def ws_kick(username=None):
    if not socketio: return
    for sid, (u, _h) in list(WS.items()):
        if username is None or u == username:
            try: socketio.server.disconnect(sid)
            except Exception: pass
            WS.pop(sid, None)
def ws_sweep():
    """Disconnect sockets whose server-side session was revoked/expired or whose account was disabled/deleted (runs every 15 s)."""
    for sid, (u, h) in list(WS.items()):
        s = q("SELECT revoked,created,last_seen FROM sessions WHERE sid_hash=?", (h,), one=True); r = q("SELECT active FROM users WHERE username=?", (u,), one=True); t = time.time()
        if not s or s["revoked"] or not r or not r["active"] or t - s["created"] > SESSION_ABS or t - s["last_seen"] > SESSION_IDLE:
            try: socketio.server.disconnect(sid)
            except Exception: pass
            WS.pop(sid, None)
def revoke_user_sessions(username): x("UPDATE sessions SET revoked=1 WHERE username=?", (username,)); ws_kick(username)

def need(role="viewer"):
    def deco(f):
        @wraps(f)
        def w(*a, **k):
            if not me(): return (jsonify(error="login required"), 401) if request.path.startswith("/api") else redirect("/login")
            if session.get("mfa_setup") and request.path not in ("/mfa-setup", "/logout", "/api/me/mfa"): return (jsonify(error="MFA enrollment required"), 403) if request.path.startswith("/api") else redirect("/mfa-setup")
            if ROLES[session.get("role", "viewer")] < ROLES[role]: return jsonify(error=f"{role} role required"), 403
            if request.method in ("POST", "PUT", "PATCH", "DELETE") and request.headers.get("X-Requested-With") != "fetch" and request.path != "/mfa-setup":   # /mfa-setup verifies its own form CSRF token
                return jsonify(error="missing X-Requested-With header"), 400        # CSRF guard
            return f(*a, **k)
        return w
    return deco

def api_key_ok():
    if not agentsig.legacy_key_on(): return False      # staged migration step 3: shared ingest key disabled entirely (production default: OFF unless explicitly SOC_LEGACY_API_KEY=on)
    k = (request.headers.get("X-API-Key") or "").encode("utf-8", "replace"); s = (setting("api_key") or "").encode("utf-8", "replace")
    ok = bool(s) and secrets.compare_digest(k, s)
    if ok: x("INSERT INTO settings(key,value) VALUES('legacy_key_last_used',?) ON CONFLICT(key) DO UPDATE SET value=excluded.value", (now(),))        # lets /api/agents/auth-status show whether anything still uses the shared key
    return ok                  # bytes compare: a non-ASCII header can no longer raise TypeError (500)
def body():
    """JSON object sent by the client; anything else (list, string, number, invalid JSON) -> {} so handlers can always call .get()."""
    d = request.get_json(silent=True); return d if isinstance(d, dict) else {}

DUMMY_HASH = generate_password_hash("not-a-real-password")           # spent on unknown usernames so login timing does not reveal which accounts exist
INPUT_ERRORS = (BadInput, ValueError, TypeError, AttributeError, KeyError, IndexError, OverflowError, UnicodeError, sqlite3.InterfaceError, sqlite3.ProgrammingError)
def _api(): return request.path.startswith("/api") or request.path.startswith("/socket.io")
@app.errorhandler(HTTPException)
def http_error(e):
    if _api() and e.code and e.code >= 400: return jsonify(error=(e.description if e.code < 500 else "internal error")), e.code
    return e
def malformed(e):
    """Hostile or sloppy client data that slipped past a handler's own checks: answer 400, never 500. Logged with the exact line so the handler can be tightened."""
    where = traceback.extract_tb(e.__traceback__)[-1] if e.__traceback__ else None
    app.logger.warning("malformed request %s %s -> %s: %s (at %s:%s)", request.method, request.path, type(e).__name__, str(e)[:80], os.path.basename(where.filename) if where else "?", where.lineno if where else "?")
    if _api(): return jsonify(error="invalid request data"), 400
    raise e
for _exc in INPUT_ERRORS: app.register_error_handler(_exc, malformed)
@app.errorhandler(sqlite3.IntegrityError)
def conflict(e):
    if _api(): return jsonify(error="conflict: duplicate or invalid reference"), 409
    raise e

CSP = ("default-src 'self'; script-src 'self' https://cdn.socket.io https://cdn.jsdelivr.net https://unpkg.com; style-src 'self' 'unsafe-inline' https://unpkg.com; "
       "img-src 'self' data: https://tile.openstreetmap.org https://*.tile.openstreetmap.org https://unpkg.com; connect-src 'self' ws: wss:; font-src 'self' data:; "
       "frame-ancestors 'none'; base-uri 'self'; form-action 'self'; object-src 'none'")
def _vendored():
    try:
        sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "tools")); import vendor_assets as _v
        return _v.verify(quiet=True) and json.load(open(_v.MF))
    except Exception: return False
VENDOR = _vendored()                    # False -> CDN fallback (open finding: no SRI possible offline); manifest dict -> local verified copies
if VENDOR:
    CSP = (CSP.replace(" https://cdn.socket.io https://cdn.jsdelivr.net https://unpkg.com", "").replace(" https://unpkg.com; connect-src", "; connect-src").replace("style-src 'self' 'unsafe-inline' https://unpkg.com", "style-src 'self' 'unsafe-inline'"))
@app.context_processor
def _vendor_ctx(): return dict(vendor=VENDOR)

@app.after_request
def harden(r):
    h = r.headers
    h.setdefault("Content-Security-Policy", CSP); h.setdefault("X-Frame-Options", "DENY"); h.setdefault("X-Content-Type-Options", "nosniff")
    h.setdefault("Referrer-Policy", "same-origin"); h.setdefault("Permissions-Policy", "geolocation=(), camera=(), microphone=(), payment=()")
    if request.path.startswith("/api") or request.path == "/login": h["Cache-Control"] = "no-store"
    if request.is_secure: h.setdefault("Strict-Transport-Security", "max-age=31536000")
    return r

# ---------------- pages ----------------
PAGES = {"telemetry": "telemetry", "fleet": "fleet", "monitoring-center": "monitoring", "email-notifications": "email", "rules": "rules", "activity": "activity", "vulnerabilities": "vulns", "": "dashboard", "alerts": "alerts", "endpoints": "endpoints", "network": "network", "threat-intel": "intel", "cases": "cases",
         "reports": "reports", "logs": "logs", "search": "search", "playbooks": "playbooks", "settings": "settings", "users": "users",
         "incidents": "incidents", "hunting": "hunting", "detections": "detections", "false-positives": "fpmgmt", "agent-health": "health"}
def make_page(p, name):
    @need()
    def view(): return render_template("dashboard.html" if name == "dashboard" else "page.html", page=name)
    view.__name__ = "page_" + (name or "x"); app.route("/" + p)(view)
for _p, _n in PAGES.items(): make_page(_p, _n)

_FAILS_LK = threading.Lock()      # the dict below is shared by every request thread (gunicorn gthread): all access goes through this lock
fails = {}      # (ip, username) -> [epoch seconds of recent failures]; in memory, cleared when the server restarts
LOGIN_MAX = int(os.environ.get("SOC_LOGIN_MAX", 5)); LOGIN_WINDOW = int(os.environ.get("SOC_LOGIN_WINDOW_MIN", 5)) * 60
def _origin_ok():
    """Policy for credential forms (login CSRF defence). Evaluated from browser-set headers only:
      1. Sec-Fetch-Site 'cross-site' or 'same-site' (a different origin) -> refuse.
      2. Origin present and not 'null' -> scheme, hostname and port must equal this request's (request.scheme / request.host; X-Forwarded-* only via SOC_TRUSTED_PROXIES).
      3. Origin 'null' -> accepted ONLY when the browser itself says Sec-Fetch-Site: same-origin (browsers send 'null' for same-origin form posts under some referrer policies; a sandboxed or foreign page is never same-origin).
      4. No Origin -> accepted only for non-browser clients (no Sec-Fetch-Site) or Sec-Fetch-Site same-origin/none."""
    sfs = (request.headers.get("Sec-Fetch-Site") or "").lower(); o = request.headers.get("Origin")
    if sfs in ("cross-site", "same-site"): return False
    if o is None: return sfs in ("", "same-origin", "none")
    if o == "null": return sfs == "same-origin"
    try: u = urlparse(o); port = u.port
    except ValueError: return False
    if u.scheme not in ("http", "https") or not u.hostname or u.username or u.password or u.path not in ("", "/") or u.query or u.fragment: return False
    mine = urlparse(f"{request.scheme}://{request.host}")
    default = lambda sch: 443 if sch == "https" else 80
    return (u.scheme == mine.scheme and u.hostname.lower() == (mine.hostname or "").lower() and (port or default(u.scheme)) == (mine.port or default(mine.scheme)))

@app.before_request
def _origin_guard():
    """Credential forms are unauthenticated state changers: a cross-site POST (login CSRF) is refused (policy in _origin_ok)."""
    if request.method == "POST" and request.path in ("/login", "/login/mfa", "/mfa-setup") and not _origin_ok(): return "Forbidden (cross-origin form post)", 403

@app.route("/login", methods=["GET", "POST"])
def login():
    err = None
    if request.method == "POST":
        ip = request.remote_addr; t = time.time(); name = request.form.get("username", "").strip()
        key = (ip, name.lower())            # per user AND address: a wrong saved password for one account no longer locks the others
        with _FAILS_LK:
            fl = [i for i in fails.get(key, []) if t - i < LOGIN_WINDOW]
            if fl: fails[key] = fl
            else: fails.pop(key, None)
            ipn = sum(len(v) for k, v in fails.items() if k[0] == ip and any(t - i < LOGIN_WINDOW for i in v))
        u = q("SELECT * FROM users WHERE username=? AND active=1", (name,), one=True)
        acct_block = throttle.blocked("login-acct", name.lower(), LOGIN_MAX * 4, LOGIN_WINDOW) or throttle.blocked("login-ip", ip, LOGIN_MAX * 12, LOGIN_WINDOW)      # persistent, shared by all workers, survives restarts, covers distributed guessing
        if acct_block: err = "Too many attempts. Try again later."
        elif len(fl) >= LOGIN_MAX or ipn >= LOGIN_MAX * 6:     # second limit stops guessing across many usernames
            wait = max(1, int(LOGIN_WINDOW - (t - fl[len(fl) - LOGIN_MAX]))) if len(fl) >= LOGIN_MAX else LOGIN_WINDOW
            err = f"Too many attempts. Try again in {wait // 60 + (1 if wait % 60 else 0)} min."
        elif check_password_hash(u["password_hash"] if u else DUMMY_HASH, request.form.get("password", "")) and u:
            with _FAILS_LK: fails.pop(key, None)            # a good login clears the counter
            g_ = mfa.gate(u)
            if g_ == "challenge": session.clear(); session["mfa_pending"] = u["username"]; session["mfa_t"] = time.time(); session["csrf"] = secrets.token_urlsafe(24); audit("Password OK, MFA challenge", user=u["username"]); return redirect("/login/mfa", code=303)
            start_session(u); session["reauth_at"] = time.time(); x("UPDATE users SET last_login=? WHERE id=?", (now(), u["id"]))
            if g_ == "enroll": session["mfa_setup"] = 1; audit("Logged in (MFA enrollment required)"); return redirect("/mfa-setup", code=303)
            audit("Logged in"); return redirect("/")
        else:
            throttle.hit("login-acct", name.lower()); throttle.hit("login-ip", ip)        # persistent counters FIRST: a failure is always recorded, whatever the in-memory state is
            with _FAILS_LK: fails.setdefault(key, []).append(t); n_fail = len(fails[key])
            err = f"Invalid username or password. ({max(0, LOGIN_MAX - n_fail)} tries left)"
        with _FAILS_LK:
            for k in [k for k, v in fails.items() if not v]: fails.pop(k, None)
    return render_template("login.html", error=err)

@app.route("/healthz")
def healthz():
    """Liveness/readiness for the supervisor / reverse proxy: proves the process answers and the database is readable. Returns NO version, host or configuration data."""
    try: q("SELECT 1", one=True); return jsonify(status="ok"), 200
    except Exception: return jsonify(status="unavailable"), 503

@app.route("/logout", methods=["POST"])
def logout():
    """POST-only + CSRF header (a GET logout can be triggered by any <img src=/logout>). Revokes the server-side session record."""
    if request.headers.get("X-Requested-With") != "fetch" and not (session.get("csrf") and secrets.compare_digest(request.form.get("csrf", ""), session.get("csrf"))): return jsonify(error="missing X-Requested-With header"), 400
    if session.get("sid"): x("UPDATE sessions SET revoked=1 WHERE sid_hash=?", (_sid_hash(session.get("sid")),))
    audit("Logged out"); session.clear(); return redirect("/login", code=303)

# ---------------- dashboard ----------------
def pct(cur, prev): return round((cur - prev) * 100 / prev) if prev else (100 if cur else 0)
@app.route("/api/dashboard")
@need()
def dashboard():
    n = datetime.now(); d1, d2 = now(n - timedelta(hours=24)), now(n - timedelta(hours=48))
    active = "status!='Resolved'"
    cnt = lambda sev, a, b=None: q(f"SELECT COUNT(*) c FROM alerts WHERE {'severity=? AND' if sev else ''} ts>=? {'AND ts<?' if b else ''}", tuple(([sev] if sev else []) + [a] + ([b] if b else [])), one=True)["c"]
    kpi = {}
    for key, sev in [("total", None), ("Critical", "Critical"), ("High", "High"), ("Medium", "Medium"), ("Low", "Low")]:
        total = q(f"SELECT COUNT(*) c FROM alerts WHERE {active}" + (" AND severity=?" if sev else ""), (sev,) if sev else (), one=True)["c"]
        kpi[key] = {"value": total, "delta": pct(cnt(sev, d1), cnt(sev, d2, d1))}
    res_now = q("SELECT COUNT(*) c FROM alerts WHERE status='Resolved'", one=True)["c"]
    res24 = q("SELECT COUNT(*) c FROM alerts WHERE resolved_at>=?", (d1,), one=True)["c"]
    res48 = q("SELECT COUNT(*) c FROM alerts WHERE resolved_at>=? AND resolved_at<?", (d2, d1), one=True)["c"]
    kpi["Resolved"] = {"value": res_now, "delta": pct(res24, res48)}
    buckets = [0] * 24
    for a in q("SELECT ts FROM alerts WHERE ts>=?", (d1,)):
        h = int((n - datetime.strptime(a["ts"], "%Y-%m-%d %H:%M:%S")).total_seconds() // 3600)
        if 0 <= h < 24: buckets[23 - h] += 1
    labels = [(n - timedelta(hours=23 - i)).strftime("%I %p").lstrip("0") for i in range(24)]
    eps = q("SELECT * FROM endpoints"); st = {"Online": 0, "Offline": 0, "At Risk": 0, "Inactive": 0}
    for e in eps: st[engine.endpoint_status(e)] += 1
    pts = q("SELECT severity,title,source_ip,country,lat,lon,ts FROM alerts WHERE lat IS NOT NULL ORDER BY id DESC LIMIT 150")
    cols = ["id", "ts", "severity", "title", "source_ip", "dest_ip", "status"]
    return jsonify(kpi=kpi, severity={s: kpi[s]["value"] for s in ["Critical", "High", "Medium", "Low"]},
        timeline={"labels": labels, "data": buckets},
        top_ips=q(f"SELECT source_ip ip,COUNT(*) c FROM alerts WHERE {active} AND source_ip IS NOT NULL GROUP BY source_ip ORDER BY c DESC LIMIT 5"),
        endpoints={"total": len(eps), **st}, map=pts, home=[setting_num("home_lat", 20.59, -90, 90, float), setting_num("home_lon", 78.96, -180, 180, float)],
        recent=q("SELECT id,ts,severity,title,source_ip FROM alerts ORDER BY id DESC LIMIT 5"),
        events=q(f"SELECT {','.join(cols)} FROM alerts ORDER BY id DESC LIMIT 5"), badge=badge(), system=system())

def badge(): return q("SELECT COUNT(*) c FROM alerts WHERE status='New' AND severity IN ('Critical','High')", one=True)["c"]
def system():
    return {"cpu": engine.CPU["v"], "ram": psutil.virtual_memory().percent, "disk": psutil.disk_usage("/").percent,
            "uptime": int(time.time() - psutil.boot_time()), "load": psutil.getloadavg()[0] if hasattr(psutil, "getloadavg") else 0}
@app.route("/api/system")
@need()
def api_system(): return jsonify(**system(), badge=badge())

@app.route("/api/search")
@need()
def search():
    s = "%" + request.args.get("q", "").strip() + "%"
    if len(s) < 3: return jsonify([])
    r = [{"type": "alert", "id": a["id"], "text": f"{a['title']} · {a['source_ip']}", "url": "/alerts"} for a in q("SELECT id,title,source_ip FROM alerts WHERE title LIKE ? OR source_ip LIKE ? OR message LIKE ? ORDER BY id DESC LIMIT 6", (s, s, s))]
    r += [{"type": "endpoint", "id": e["id"], "text": f"{e['hostname']} · {e['ip']}", "url": "/endpoints"} for e in q("SELECT id,hostname,ip FROM endpoints WHERE hostname LIKE ? OR ip LIKE ? LIMIT 4", (s, s))]
    r += [{"type": "case", "id": c["id"], "text": c["title"], "url": "/cases"} for c in q("SELECT id,title FROM cases WHERE title LIKE ? LIMIT 3", (s,))]
    r += [{"type": "user", "id": u["id"], "text": u["username"], "url": "/users"} for u in q("SELECT id,username FROM users WHERE username LIKE ? LIMIT 3", (s,))]
    return jsonify(r)

# ---------------- alerts ----------------
@app.route("/api/alerts")
@need()
def alerts():
    w, a = ["1=1"], []
    for f in ("status", "severity", "category"):
        if request.args.get(f): w.append(f"al.{f}=?"); a.append(request.args[f])
    if request.args.get("agent_id"): w.append("al.agent_id=?"); a.append(request.args["agent_id"])
    if request.args.get("q"): w.append("(al.title LIKE ? OR al.source_ip LIKE ? OR al.message LIKE ?)"); a += ["%" + request.args["q"] + "%"] * 3
    lim = iarg(request.args.get("limit"), 200, 1, 1000)
    return jsonify(q(f"SELECT al.*,e.hostname endpoint FROM alerts al LEFT JOIN endpoints e ON e.id=al.endpoint_id WHERE {' AND '.join(w)} ORDER BY al.id DESC LIMIT {lim}", a))

@app.route("/api/alerts/<int:i>", methods=["PATCH"])
@need("analyst")
def alert_update(i):
    d = body(); st, asg = d.get("status"), d.get("assignee")
    if st and st not in ("New", "In Progress", "Investigating", "Confirmed", "False Positive", "Resolved"): return jsonify(error="bad status"), 400
    if st: x("UPDATE alerts SET status=?,updated=?,resolved_at=? WHERE id=?", (st, now(), now() if st == "Resolved" else None, i)); audit(f"Alert #{i} → {st}"); x("INSERT INTO alert_activity(alert_id,ts,user,action) VALUES(?,?,?,?)", (i, now(), me(), f"Status set to {st}"))
    if asg is not None: x("UPDATE alerts SET assignee=? WHERE id=?", (asg or None, i)); x("INSERT INTO alert_activity(alert_id,ts,user,action) VALUES(?,?,?,?)", (i, now(), me(), f"Assigned to {asg or 'nobody'}"))
    if socketio: socketio.emit("refresh", {"what": "alerts"})
    return jsonify(ok=True)

@app.route("/api/alerts/<int:i>", methods=["DELETE"])
@need("admin")
def alert_delete(i): x("DELETE FROM alerts WHERE id=?", (i,)); audit(f"Alert #{i} deleted"); return jsonify(ok=True)

@app.route("/api/alerts/<int:i>/case", methods=["POST"])
@need("analyst")
def alert_case(i):
    a = q("SELECT * FROM alerts WHERE id=?", (i,), one=True)
    if not a: return jsonify(error="not found"), 404
    cid = x("INSERT INTO cases(title,description,priority,status,assignee,created_at) VALUES(?,?,?,?,?,?)", (f"{a['title']} from {a['source_ip']}", a["message"], "High" if a["severity"] in ("High", "Critical") else "Medium", "Open", me(), now()))
    x("INSERT INTO case_alerts VALUES(?,?)", (cid, i)); x("UPDATE alerts SET status='In Progress',assignee=? WHERE id=? AND status='New'", (me(), i)); audit(f"Case #{cid} from alert #{i}"); x("INSERT INTO alert_activity(alert_id,ts,user,action) VALUES(?,?,?,?)", (i, now(), me(), f"Case #{cid} created"))
    return jsonify(id=cid)

@app.route("/api/alerts/<int:i>/block", methods=["POST"])
@need("analyst")
def alert_block(i):
    a = q("SELECT source_ip FROM alerts WHERE id=?", (i,), one=True)
    if not a or not engine.block_ip(a["source_ip"], f"Manual block from alert #{i}", me()): return jsonify(error="IP is private, invalid or already blocked"), 400
    return jsonify(ok=True)

# ---------------- ingest (agents / scripts) ----------------
@app.route("/api/ingest", methods=["POST"])
def ingest():
    if not (api_key_ok() or (me() and not session.get("mfa_setup") and ROLES[session.get("role")] >= 2 and request.headers.get("X-Requested-With") == "fetch")): return jsonify(error="unauthorized"), 401
    d = request.get_json(silent=True); items = d if isinstance(d, list) else [d]
    items = [e for e in items[:1000] if isinstance(e, dict) and isinstance(e.get("message"), (str, int, float)) and not isinstance(e.get("message"), bool) and str(e.get("message"))]
    out = [a["id"] if a else None for a in engine.process_batch(items)]
    return jsonify(processed=len(out), alert_ids=out)

@app.route("/api/agent/heartbeat", methods=["POST"])
def heartbeat():
    if not api_key_ok(): return jsonify(error="unauthorized"), 401
    d = body()
    host = sarg(d.get("hostname"), 255)
    if not host: return jsonify(error="hostname required"), 400
    engine.upsert_endpoint(host, sarg(d.get("ip"), 64) or request.remote_addr, sarg(d.get("os"), 100) or None, farg(d.get("cpu"), 0, 0, 100), farg(d.get("ram"), 0, 0, 100))
    if socketio: socketio.emit("refresh", {"what": "endpoints"})
    return jsonify(ok=True)

# ---------------- agent commands (real blocking / isolation) ----------------
@app.route("/api/agent/commands")
def agent_commands():
    if not api_key_ok(): return jsonify(error="unauthorized"), 401
    host = request.args.get("host", "")
    if not host: return jsonify(error="host required"), 400
    if request.args.get("resync") == "1": engine.resync(host)
    rows = q("SELECT id,action,arg FROM commands WHERE host=? AND status='pending' ORDER BY id LIMIT 50", (host,))
    for r in rows: x("UPDATE commands SET status='sent' WHERE id=?", (r["id"],))
    return jsonify(rows)

@app.route("/api/agent/commands/result", methods=["POST"])
def agent_command_result():
    if not api_key_ok(): return jsonify(error="unauthorized"), 401
    d = body(); items = d if isinstance(d, list) else [d]
    for r in items[:100]:
        c = q("SELECT * FROM commands WHERE id=? AND host=?", (r.get("id"), r.get("host")), one=True)
        if not c: continue
        ok = bool(r.get("ok")); x("UPDATE commands SET status=?,done_at=?,result=? WHERE id=?", ("done" if ok else "failed", now(), str(r.get("result", ""))[:500], c["id"]))
        audit(f"{c['host']}: {c['action']} {c['arg']} -> {'ok' if ok else 'FAILED'} {str(r.get('result', ''))[:120]}", "agent")
    return jsonify(ok=True)

@app.route("/api/commands")
@need("analyst")
def commands_list(): return jsonify(q("SELECT * FROM commands ORDER BY id DESC LIMIT 200"))

# ---------------- software inventory + vulnerabilities ----------------
@app.route("/api/agent/inventory", methods=["POST"])
def agent_inventory():
    if not api_key_ok(): return jsonify(error="unauthorized"), 401
    d = body(); host = d.get("hostname")
    if not host or not isinstance(d.get("packages"), list): return jsonify(error="hostname and packages required"), 400
    import vuln; vuln.store_inventory(host, d.get("ecosystem") or "", d["packages"]); return jsonify(ok=True)

@app.route("/api/vulns")
@need()
def vulns_list():
    w, a = ["1=1"], []
    if request.args.get("host"): w.append("host=?"); a.append(request.args["host"])
    return jsonify(dict(scans=q("SELECT * FROM vuln_scan ORDER BY host"), vulns=q(f"SELECT host,package,version,vuln_id,summary,severity,aliases,seen FROM vulns WHERE {' AND '.join(w)} ORDER BY host,package LIMIT 2000", a)))

@app.route("/api/vulns/scan/<host>", methods=["POST"])
@need("analyst")
def vulns_rescan(host):
    import vuln; threading.Thread(target=vuln.check_host, args=(host,), daemon=True).start(); audit(f"Vulnerability re-check requested for {host}"); return jsonify(ok=True)

# ---------------- endpoints ----------------
@app.route("/api/endpoints")
@need()
def endpoints():
    out = []
    for e in q("SELECT * FROM endpoints ORDER BY hostname"):
        e["status"] = engine.endpoint_status(e); e["open_alerts"] = q("SELECT COUNT(*) c FROM alerts WHERE endpoint_id=? AND status!='Resolved'", (e["id"],), one=True)["c"]; out.append(e)
    return jsonify(out)

@app.route("/api/endpoints", methods=["POST"])
@need("analyst")
def endpoint_add():
    d = body()
    host = sarg(d.get("hostname"), 255)
    if not host: return jsonify(error="hostname required"), 400
    engine.upsert_endpoint(host, sarg(d.get("ip"), 64) or None, sarg(d.get("os"), 100) or None); audit(f"Endpoint added: {host}"); return jsonify(ok=True)

@app.route("/api/endpoints/<int:i>", methods=["PATCH", "DELETE"])
@need("analyst")
def endpoint_mod(i):
    if request.method == "DELETE":
        if ROLES[session["role"]] < 3: return jsonify(error="admin role required"), 403
        x("DELETE FROM endpoints WHERE id=?", (i,)); audit(f"Endpoint #{i} deleted")
    else: engine.set_isolation(i, bool(body().get("isolated"))); audit(f"Endpoint #{i} isolation={body().get('isolated')}")
    return jsonify(ok=True)

# ---------------- cases ----------------
@app.route("/api/cases")
@need()
def cases(): return jsonify(q("SELECT c.*,(SELECT COUNT(*) FROM case_notes n WHERE n.case_id=c.id) notes,(SELECT COUNT(*) FROM case_alerts a WHERE a.case_id=c.id) alerts FROM cases c ORDER BY id DESC"))

@app.route("/api/cases", methods=["POST"])
@need("analyst")
def case_add():
    d = body()
    title = sarg(d.get("title"), 300)
    if not title: return jsonify(error="title required"), 400
    pri = sarg(d.get("priority"), 20) or "Medium"
    if pri not in RANK: return jsonify(error="priority must be Low, Medium, High or Critical"), 400
    i = x("INSERT INTO cases(title,description,priority,status,assignee,created_at) VALUES(?,?,?,?,?,?)", (title, sarg(d.get("description"), 5000), pri, "Open", me(), now())); audit(f"Case #{i} created"); return jsonify(id=i)

@app.route("/api/cases/<int:i>")
@need()
def case_get(i):
    c = q("SELECT * FROM cases WHERE id=?", (i,), one=True)
    if not c: return jsonify(error="not found"), 404
    c["notes"] = q("SELECT * FROM case_notes WHERE case_id=? ORDER BY id DESC", (i,)); c["alerts"] = q("SELECT a.id,a.title,a.severity,a.source_ip FROM alerts a JOIN case_alerts ca ON ca.alert_id=a.id WHERE ca.case_id=?", (i,)); return jsonify(c)

@app.route("/api/cases/<int:i>", methods=["PATCH"])
@need("analyst")
def case_update(i):
    d = body()
    if d.get("status") in ("Open", "In Progress", "Closed"): x("UPDATE cases SET status=?,closed_at=? WHERE id=?", (d["status"], now() if d["status"] == "Closed" else None, i)); audit(f"Case #{i} → {d['status']}")
    if d.get("assignee") is not None: x("UPDATE cases SET assignee=? WHERE id=?", (sarg(d["assignee"], 100) or None, i))
    note = sarg(d.get("note"), 2000)
    if note: x("INSERT INTO case_notes(case_id,author,note,ts) VALUES(?,?,?,?)", (i, me(), note, now()))
    return jsonify(ok=True)

@app.route("/api/cases/<int:i>", methods=["DELETE"])
@need("admin")
def case_del(i): x("DELETE FROM cases WHERE id=?", (i,)); x("DELETE FROM case_notes WHERE case_id=?", (i,)); return jsonify(ok=True)

# ---------------- network / threat intel ----------------
@app.route("/api/blocklist")
@need()
def blocklist(): return jsonify(q("SELECT * FROM blocklist ORDER BY ts DESC"))

@app.route("/api/blocklist", methods=["POST"])
@need("analyst")
def block_add():
    d = body()
    if not engine.block_ip(sarg(d.get("ip"), 64), sarg(d.get("reason"), 200) or "Manual", me()): return jsonify(error="Invalid, private or already-blocked IP"), 400
    return jsonify(ok=True)

@app.route("/api/blocklist/<path:ip>", methods=["DELETE"])
@need("analyst")
def block_del(ip): engine.unblock_ip(ip); audit(f"Unblocked {ip}"); return jsonify(ok=True)

@app.route("/api/iocs")
@need()
def iocs(): return jsonify(q("SELECT * FROM iocs ORDER BY id DESC"))

@app.route("/api/iocs", methods=["POST"])
@need("analyst")
def ioc_add():
    d = body(); v = sarg(d.get("value"), 255)
    if not v: return jsonify(error="value required"), 400
    try: x("INSERT INTO iocs(value,type,source,ts) VALUES(?,?,?,?)", (v, "ip" if engine.valid_ip(v) else "domain", sarg(d.get("source"), 100) or "manual", now()))
    except Exception: return jsonify(error="already exists"), 400
    audit(f"IOC added {v}"); return jsonify(ok=True)

@app.route("/api/iocs/<int:i>", methods=["DELETE"])
@need("analyst")
def ioc_del(i): x("DELETE FROM iocs WHERE id=?", (i,)); return jsonify(ok=True)

@app.route("/api/intel/<path:ip>")
@need()
def intel(ip):
    if not engine.valid_ip(ip): return jsonify(error="Enter a valid IPv4/IPv6 address"), 400
    a = q("SELECT COUNT(*) c,MIN(ts) first,MAX(ts) last FROM alerts WHERE source_ip=?", (ip,), one=True)
    sev = q("SELECT severity,COUNT(*) c FROM alerts WHERE source_ip=? GROUP BY severity", (ip,))
    ioc = bool(q("SELECT 1 FROM iocs WHERE value=?", (ip,), one=True)); blocked = bool(q("SELECT 1 FROM blocklist WHERE ip=?", (ip,), one=True))
    score = min(100, sum({"Critical": 30, "High": 15, "Medium": 6, "Low": 2}[s["severity"]] * s["c"] for s in sev) + (40 if ioc else 0) + (10 if blocked else 0))
    ctry, la, lo = engine.geo_for(ip)
    return jsonify(ip=ip, risk_score=score, risk="Critical" if score >= 80 else "High" if score >= 50 else "Medium" if score >= 20 else "Low", alerts=a["c"], first_seen=a["first"], last_seen=a["last"],
                   ioc=ioc, blocked=blocked, country=ctry or "Unknown", private=engine.is_private(ip), by_severity=sev, recent=q("SELECT id,ts,severity,title FROM alerts WHERE source_ip=? ORDER BY id DESC LIMIT 10", (ip,)))

# ---------------- logs / audit ----------------
def _event_filter():
    w, a = ["1=1"], []
    if request.args.get("q", "").strip(): w.append("(message LIKE ? OR source_ip LIKE ? OR host LIKE ? OR provider LIKE ?)"); a += ["%" + request.args["q"].strip() + "%"] * 4
    for f in ("host", "channel", "level"):
        if request.args.get(f): w.append(f"{f}=?"); a.append(request.args[f])
    for col, key, op in (("event_id", "event_id", "="), ("id", "after_id", ">")):
        n = iarg(request.args.get(key), None, 0, 2 ** 62)
        if n is not None: w.append(f"{col}{op}?"); a.append(n)
    return " AND ".join(w), a

@app.route("/api/events")
@need()
def events():
    w, a = _event_filter(); lim = iarg(request.args.get("limit"), 300, 1, 5000)
    return jsonify(q(f"SELECT id,ts,source_ip,dest_ip,host,message,alert_id,channel,event_id,level,provider,record_id FROM events WHERE {w} ORDER BY id DESC LIMIT {lim}", a))

@app.route("/api/events/meta")
@need()
def events_meta():
    return jsonify(hosts=[r["host"] for r in q("SELECT DISTINCT host FROM events WHERE host IS NOT NULL ORDER BY host")],
                   channels=[r["channel"] for r in q("SELECT DISTINCT channel FROM events WHERE channel IS NOT NULL ORDER BY channel")],
                   total=q("SELECT COUNT(*) c FROM events", one=True)["c"], latest_id=(q("SELECT MAX(id) m FROM events", one=True) or {}).get("m") or 0)

@app.route("/api/events/export.csv")
@need("analyst")
def events_export():
    w, a = _event_filter(); rows = q(f"SELECT id,ts,host,channel,event_id,level,provider,source_ip,dest_ip,record_id,message,raw FROM events WHERE {w} ORDER BY id DESC LIMIT 100000", a)
    o = io.StringIO(); cw = csv.writer(o); cw.writerow(["id", "time", "host", "channel", "event_id", "level", "provider", "source_ip", "dest_ip", "record_id", "message", "raw"])
    for r in rows: cw.writerow([csv_cell(r[k]) for k in ("id", "ts", "host", "channel", "event_id", "level", "provider", "source_ip", "dest_ip", "record_id", "message", "raw")])
    audit("Exported event log CSV")
    return Response(o.getvalue(), mimetype="text/csv", headers={"Content-Disposition": "attachment; filename=events.csv"})


# ---------------- endpoint activity ----------------
def _act_where(skip=()):
    a = request.args; w, p = ["e.category IS NOT NULL"], []
    if a.get("q", "").strip(): w.append("(e.message LIKE ? OR e.username LIKE ? OR e.host LIKE ? OR e.source_ip LIKE ? OR e.activity LIKE ?)"); p += ["%" + a["q"].strip() + "%"] * 5
    if a.get("host"): w.append("e.host=?"); p.append(a["host"])
    if a.get("username", "").strip(): w.append("e.username LIKE ?"); p.append("%" + a["username"].strip() + "%")
    if a.get("source_ip", "").strip(): w.append("e.source_ip LIKE ?"); p.append(a["source_ip"].strip() + "%")
    if a.get("activity"): w.append("e.activity LIKE ?"); p.append("%" + a["activity"] + "%")
    if a.get("os"): w.append("e.os=?"); p.append(a["os"])
    if a.get("status"): w.append("e.status=?"); p.append(a["status"])
    if a.get("event_id", "").isdigit(): w.append("e.event_id=?"); p.append(int(a["event_id"]))
    if a.get("severity"): w.append("al.severity=?"); p.append(a["severity"])
    if a.get("minutes", "").isdigit() and int(a["minutes"]) > 0: w.append("e.ts>=?"); p.append((datetime.now() - timedelta(minutes=int(a["minutes"]))).strftime("%Y-%m-%d %H:%M:%S"))
    if a.get("start"): w.append("e.ts>=?"); p.append(a["start"].replace("T", " "))
    if a.get("end"): w.append("e.ts<=?"); p.append(a["end"].replace("T", " "))
    if "cat" not in skip:
        if a.get("category") == "Suspicious": w.append("e.risk IN ('Medium','High','Critical')")
        elif a.get("category"): w.append("e.category=?"); p.append(a["category"])
    if "risk" not in skip and a.get("risk"):
        rs = [r for r in a["risk"].split(",") if r in ("Normal", "Low", "Medium", "High", "Critical")]
        if rs: w.append("e.risk IN (%s)" % ",".join("?" * len(rs))); p += rs
    return " AND ".join(w), p

ACT_COLS = "e.id,e.ts,e.host,e.username,e.source_ip,e.category,e.activity,e.status,e.risk,e.os,e.event_id,e.channel,e.message,e.alert_id,al.severity AS alert_severity,al.title AS alert_title"
ACT_FROM = "FROM events e LEFT JOIN alerts al ON al.id=e.alert_id"

@app.route("/api/activity")
@need()
def activity_list():
    w, p = _act_where(); a = request.args; lim = iarg(a.get("limit"), 100, 1, 2000)
    if a.get("after_id", "").isdigit(): w += " AND e.id>?"; p.append(int(a["after_id"]))
    if a.get("before_id", "").isdigit(): w += " AND e.id<?"; p.append(int(a["before_id"]))
    return jsonify(q(f"SELECT {ACT_COLS} {ACT_FROM} WHERE {w} ORDER BY e.id DESC LIMIT {lim}", p))

@app.route("/api/activity/summary")
@need()
def activity_summary():
    w, p = _act_where(skip=("risk", "cat"))
    risk = {r["risk"]: r["c"] for r in q(f"SELECT e.risk,COUNT(*) c {ACT_FROM} WHERE {w} GROUP BY e.risk", p)}
    cat = {r["category"]: r["c"] for r in q(f"SELECT e.category,COUNT(*) c {ACT_FROM} WHERE {w} GROUP BY e.category", p)}
    return jsonify(risk={k: risk.get(k, 0) for k in ("Critical", "High", "Medium", "Low", "Normal")}, category=cat, total=sum(risk.values()),
                   suspicious=sum(risk.get(k, 0) for k in ("Medium", "High", "Critical")), latest_id=(q("SELECT MAX(id) m FROM events", one=True) or {}).get("m") or 0)

@app.route("/api/activity/meta")
@need()
def activity_meta():
    return jsonify(hosts=[r["host"] for r in q("SELECT DISTINCT host FROM events WHERE category IS NOT NULL AND host IS NOT NULL ORDER BY host")],
                   activities=[r["activity"] for r in q("SELECT activity,COUNT(*) c FROM events WHERE category IS NOT NULL GROUP BY activity ORDER BY c DESC LIMIT 100")],
                   oses=[r["os"] for r in q("SELECT DISTINCT os FROM events WHERE os IS NOT NULL ORDER BY os")])

@app.route("/api/activity/export.csv")
@need("analyst")
def activity_export():
    w, p = _act_where(); rows = q(f"SELECT {ACT_COLS} {ACT_FROM} WHERE {w} ORDER BY e.id DESC LIMIT 100000", p)
    o = io.StringIO(); cw = csv.writer(o); cols = ["id", "ts", "host", "os", "username", "source_ip", "category", "activity", "status", "risk", "event_id", "channel", "alert_severity", "alert_title", "message"]
    cw.writerow(cols)
    for r in rows: cw.writerow([csv_cell(r[c]) for c in cols])
    audit("Exported endpoint activity CSV")
    return Response(o.getvalue(), mimetype="text/csv", headers={"Content-Disposition": "attachment; filename=activity.csv"})

@app.route("/api/activity/<int:i>")
@need()
def activity_detail(i):
    r = q(f"SELECT {ACT_COLS},e.raw,e.provider,e.level,e.dest_ip,e.record_id {ACT_FROM} WHERE e.id=?", (i,), one=True)
    if not r: return jsonify(error="not found"), 404
    try: r["raw"] = json.loads(r["raw"]) if r["raw"] else {}
    except Exception: pass
    r["related"] = q("SELECT id,ts,activity,risk,message FROM events WHERE category IS NOT NULL AND host IS ? AND username IS ? AND id!=? AND ts BETWEEN datetime(?, '-15 minutes') AND datetime(?, '+15 minutes') ORDER BY id DESC LIMIT 15", (r["host"], r["username"], i, r["ts"], r["ts"]))
    return jsonify(r)

@app.route("/api/rules")
@need()
def rules_list():
    import detections
    out = [dict(title=t, severity=sv, category=c, source="Log pattern rule", what="Matches log text: " + r.pattern if hasattr(r, "pattern") else "", mitre=" ".join(engine.MITRE.get(t, ("",))[:2]).strip())
           for r, t, sv, c in engine.COMPILED]
    out += [dict(d, mitre=" ".join(engine.MITRE.get(d["title"], ("",))[:2]).strip()) for d in detections.ACTIVITY_RULES]
    return jsonify(rules=out, custom=q("SELECT * FROM custom_rules ORDER BY id"), thresholds=dict(brute_threshold=setting("brute_threshold"), brute_window_min=setting("brute_window_min"), business_hours=setting("business_hours") or os.environ.get("SOC_BUSINESS_HOURS", "")))

# ---------------- custom alert rules ----------------
def _cr_clean(d):
    """Validate a custom-rule payload. Returns (clean dict, error)."""
    name = sarg(d.get("name"), 100); pat = sarg(d.get("pattern"))
    mt = sarg(d.get("match_type")) or "contains"; sev = sarg(d.get("severity")) or "Medium"
    if not name or not pat: return None, "name and pattern are required"
    if len(pat) > 300: return None, "pattern is too long (max 300 characters)"
    if mt not in ("contains", "regex"): return None, "match_type must be contains or regex"
    if sev not in RANK: return None, "invalid severity"
    try:
        engine.cr_matcher(mt, pat)
        if mt == "regex" and engine.regex_probe(pat): raise ValueError(engine.regex_probe(pat))
    except ValueError as ex: return None, str(ex)
    mitre = sarg(d.get("mitre"), 20).upper()
    if mitre and not __import__("re").fullmatch(r"T\d{4}(\.\d{3})?", mitre): return None, "MITRE id must look like T1110 or T1059.001"
    def num(k, lo, hi, dflt):
        try: return min(hi, max(lo, int(d.get(k) or dflt)))
        except (TypeError, ValueError, OverflowError): return dflt
    eid = iarg(d.get("event_id"), None, 0, 2 ** 31)
    return dict(name=name, description=sarg(d.get("description"), 300), match_type=mt, pattern=pat, host_filter=sarg(d.get("host_filter"), 100),
                event_id=eid, severity=sev, category=((d.get("category") or "custom").strip().lower()[:30] or "custom"), mitre=mitre,
                threshold=num("threshold", 1, 10000, 1), window_min=num("window_min", 1, 1440, 5)), None

@app.route("/api/custom-rules", methods=["POST"])
@need("admin")
def cr_add():
    c, err = _cr_clean(body())
    if err: return jsonify(error=err), 400
    i = x("INSERT INTO custom_rules(name,description,match_type,pattern,host_filter,event_id,severity,category,mitre,threshold,window_min,created_by,created_at) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?)",
          (c["name"], c["description"], c["match_type"], c["pattern"], c["host_filter"], c["event_id"], c["severity"], c["category"], c["mitre"], c["threshold"], c["window_min"], me(), now()))
    engine.custom_rules_changed(); audit(f"Custom rule created: {c['name']}"); return jsonify(ok=True, id=i)

@app.route("/api/custom-rules/<int:i>", methods=["PUT", "PATCH", "DELETE"])
@need("admin")
def cr_mod(i):
    r = q("SELECT * FROM custom_rules WHERE id=?", (i,), one=True)
    if not r: return jsonify(error="not found"), 404
    if request.method == "DELETE": x("DELETE FROM custom_rules WHERE id=?", (i,)); audit(f"Custom rule deleted: {r['name']}")
    elif request.method == "PATCH":
        x("UPDATE custom_rules SET enabled=? WHERE id=?", (1 if body().get("enabled") else 0, i)); audit(f"Custom rule {'enabled' if body().get('enabled') else 'disabled'}: {r['name']}")
    else:
        c, err = _cr_clean(body())
        if err: return jsonify(error=err), 400
        x("UPDATE custom_rules SET name=?,description=?,match_type=?,pattern=?,host_filter=?,event_id=?,severity=?,category=?,mitre=?,threshold=?,window_min=? WHERE id=?",
          (c["name"], c["description"], c["match_type"], c["pattern"], c["host_filter"], c["event_id"], c["severity"], c["category"], c["mitre"], c["threshold"], c["window_min"], i)); audit(f"Custom rule edited: {c['name']}")
    engine.custom_rules_changed(); return jsonify(ok=True)

@app.route("/api/custom-rules/test", methods=["POST"])
@need("admin")
def cr_test():
    """Dry run: how many of the last 2000 stored events would this rule match? Creates nothing."""
    d = body()
    pat = sarg(d.get("pattern"), 300)
    if not pat: return jsonify(error="pattern is required"), 400
    try: m = engine.cr_matcher(sarg(d.get("match_type")) or "contains", pat)
    except ValueError as ex: return jsonify(error=str(ex)), 400
    rows = q("SELECT ts,host,message FROM events ORDER BY id DESC LIMIT 2000"); hit = [r for r in rows if m(r["message"] or "")]
    return jsonify(ok=True, scanned=len(rows), matches=len(hit), examples=[dict(ts=r["ts"], host=r["host"], message=(r["message"] or "")[:200]) for r in hit[:5]])

# ---------------- rule library (ready-made rules mapped to attacks) ----------------
@app.route("/api/rule-library")
@need()
def rl_list():
    import rules_library as RL
    return jsonify(rules=RL.catalog())

@app.route("/api/rule-library/<action>", methods=["POST"])
@need("admin")
def rl_act(action):
    """action: add | remove | enable | disable | add-attack | add-all. Body: {id} or {attack}."""
    import rules_library as RL
    d = body(); rid = sarg(d.get("id"), 100); res = []
    if action == "add": res = [RL.add_rule(rid, me())]
    elif action == "remove": res = [RL.remove_rule(rid)]
    elif action in ("enable", "disable"): res = [RL.set_enabled(rid, action == "enable")]
    elif action == "add-attack": res = RL.add_attack((d.get("attack") or "").strip(), me())
    elif action == "add-all": res = RL.add_all(me())
    else: return jsonify(error="unknown action"), 400
    done = [m for ok, m in res if ok]
    if done: audit(f"Rule library {action}: " + "; ".join(done)[:300])
    return jsonify(ok=bool(done), messages=[m for ok, m in res], changed=len(done))

@app.route("/api/playbook-library")
@need()
def pl_list():
    import rules_library as RL
    return jsonify(playbooks=RL.playbook_catalog())

@app.route("/api/playbook-library/<action>", methods=["POST"])
@need("admin")
def pl_act(action):
    """action: add | remove | add-attack | add-all. Body: {id} or {attack}."""
    import rules_library as RL
    d = body(); pid = sarg(d.get("id"), 100)
    if action == "add": res = [RL.add_playbook(pid)]
    elif action == "remove": res = [RL.remove_playbook(pid)]
    elif action == "add-attack": res = RL.add_playbook_attack((d.get("attack") or "").strip())
    elif action == "add-all": res = RL.add_all_playbooks()
    else: return jsonify(error="unknown action"), 400
    done = [m for ok, m in res if ok]
    if done: audit(f"Playbook library {action}: " + "; ".join(done)[:300])
    return jsonify(ok=bool(done), messages=[m for ok, m in res], changed=len(done))

@app.route("/api/me/notice")
@need()
def my_notice():
    u = q("SELECT password_hash FROM users WHERE username=?", (me(),), one=True)
    default = bool(u) and any(check_password_hash(u["password_hash"], p) for p in ("Admin@123", "Analyst@123", "Viewer@123"))
    return jsonify(default_password=default)

@app.route("/api/audit")
@need("analyst")
def audit_log(): return jsonify(q("SELECT * FROM audit ORDER BY id DESC LIMIT 300"))

# ---------------- playbooks ----------------
ACTIONS = ("block_ip", "create_case", "notify", "isolate_endpoint")
@app.route("/api/playbooks")
@need()
def playbooks(): return jsonify(q("SELECT * FROM playbooks ORDER BY id"))

@app.route("/api/playbooks", methods=["POST"])
@need("admin")
def pb_add():
    d = body()
    if not d.get("name") or d.get("action") not in ACTIONS or d.get("min_severity") not in RANK: return jsonify(error="name, action and min_severity required"), 400
    x("INSERT INTO playbooks(name,min_severity,category,action) VALUES(?,?,?,?)", (d["name"], d["min_severity"], d.get("category", ""), d["action"])); audit(f"Playbook created: {d['name']}"); return jsonify(ok=True)

@app.route("/api/playbooks/<int:i>", methods=["PATCH", "DELETE"])
@need("admin")
def pb_mod(i):
    if request.method == "DELETE": x("DELETE FROM playbooks WHERE id=?", (i,))
    else: x("UPDATE playbooks SET enabled=? WHERE id=?", (1 if body().get("enabled") else 0, i))
    return jsonify(ok=True)

# ---------------- reports ----------------
def rows_since(days): return now(datetime.now() - timedelta(days=days))
@app.route("/api/reports")
@need()
def reports():
    since = rows_since(iarg(request.args.get("days"), 7, 1, 3650))
    g = lambda col: q(f"SELECT {col} k,COUNT(*) c FROM alerts WHERE ts>=? GROUP BY {col} ORDER BY c DESC LIMIT 8", (since,))
    res = q("SELECT ts,resolved_at FROM alerts WHERE resolved_at IS NOT NULL AND ts>=?", (since,))
    mttr = round(sum((datetime.strptime(r["resolved_at"], "%Y-%m-%d %H:%M:%S") - datetime.strptime(r["ts"], "%Y-%m-%d %H:%M:%S")).total_seconds() for r in res) / len(res) / 60) if res else 0
    return jsonify(total=q("SELECT COUNT(*) c FROM alerts WHERE ts>=?", (since,), one=True)["c"], resolved=len(res), mttr_minutes=mttr, by_severity=g("severity"), by_category=g("category"),
                   by_status=g("status"), top_ips=g("source_ip"), daily=q("SELECT substr(ts,1,10) k,COUNT(*) c FROM alerts WHERE ts>=? GROUP BY k ORDER BY k", (since,)))

@app.route("/api/reports/export.csv")
@need()
def export_csv():
    s = io.StringIO(); w = csv.writer(s); w.writerow(["id", "time", "severity", "title", "category", "source_ip", "dest_ip", "status", "assignee", "count"])
    for a in q("SELECT * FROM alerts WHERE ts>=? ORDER BY id DESC", (rows_since(iarg(request.args.get("days"), 7, 1, 3650)),)):
        w.writerow([csv_cell(a[k]) for k in ("id", "ts", "severity", "title", "category", "source_ip", "dest_ip", "status", "assignee", "count")])  # CSV-injection safe
    return Response(s.getvalue(), mimetype="text/csv", headers={"Content-Disposition": "attachment; filename=alerts.csv"})

# ---------------- users / settings ----------------
@app.route("/api/users")
@need("admin")
def users(): return jsonify(q("SELECT id,username,role,active,created_at,last_login FROM users ORDER BY id"))

@app.route("/api/users", methods=["POST"])
@need("admin")
def user_add():
    d = body(); u, p, role = sarg(d.get("username"), 40), d.get("password"), d.get("role")
    if not u.replace("_", "").replace(".", "").isalnum() or not isinstance(p, str) or len(p) < MIN_PW or not isinstance(role, str) or role not in ROLES: return jsonify(error="Valid username, role and a password of 8+ characters are required"), 400
    if q("SELECT 1 FROM users WHERE lower(username)=lower(?)", (u,), one=True): return jsonify(error="username already exists"), 400          # 'Admin' must not coexist with 'admin' (look-alike accounts)
    try: x("INSERT INTO users(username,password_hash,role,created_at) VALUES(?,?,?,?)", (u, generate_password_hash(p), role, now()))
    except sqlite3.IntegrityError: return jsonify(error="username already exists"), 400
    audit(f"User created: {u} ({role})"); return jsonify(ok=True)

@app.route("/api/users/<int:i>", methods=["PATCH", "DELETE"])
@need("admin")
def user_mod(i):
    t = q("SELECT * FROM users WHERE id=?", (i,), one=True)
    if not t: return jsonify(error="not found"), 404
    admins = q("SELECT COUNT(*) c FROM users WHERE role='admin' AND active=1", one=True)["c"]
    if request.method == "DELETE":
        if t["username"] == me() or (t["role"] == "admin" and admins <= 1): return jsonify(error="Cannot delete yourself or the last admin"), 400
        x("DELETE FROM users WHERE id=?", (i,)); audit(f"User deleted: {t['username']}"); return jsonify(ok=True)
    d = body()
    if isinstance(d.get("role"), str) and d["role"] in ROLES:
        if t["role"] == "admin" and d["role"] != "admin" and admins <= 1: return jsonify(error="Cannot demote the last admin"), 400
        x("UPDATE users SET role=? WHERE id=?", (d["role"], i))
    if "active" in d:
        if t["username"] == me() and not d["active"]: return jsonify(error="Cannot disable yourself"), 400
        x("UPDATE users SET active=? WHERE id=?", (1 if d["active"] else 0, i))
    if d.get("username") is not None:
        nu = sarg(d["username"], 41)
        if not nu or not nu.replace("_", "").replace(".", "").isalnum() or len(nu) > 40: return jsonify(error="Username may contain letters, digits, _ and . only (max 40)"), 400
        if nu != t["username"]:
            if q("SELECT 1 FROM users WHERE lower(username)=lower(?) AND id!=?", (nu, i), one=True): return jsonify(error="username already exists"), 400
            x("UPDATE users SET username=? WHERE id=?", (nu, i))
            x("UPDATE alerts SET assignee=? WHERE assignee=?", (nu, t["username"])); x("UPDATE cases SET assignee=? WHERE assignee=?", (nu, t["username"]))   # current ownership follows the rename; history (audit, notes) keeps the old name
            if t["username"] == me(): session["user"] = nu
            audit(f"User renamed: {t['username']} -> {nu}")
    if d.get("password"):
        if not isinstance(d["password"], str) or len(d["password"]) < MIN_PW: return jsonify(error=f"Password must be {MIN_PW}+ characters"), 400
        h = generate_password_hash(d["password"]); x("UPDATE users SET password_hash=? WHERE id=?", (h, i))
        revoke_user_sessions(t["username"])                                         # every session of that user ends at once
        if t["username"] == me(): start_session(dict(username=t["username"], role=t["role"], password_hash=h))   # ...except you: rotated, still signed in
    if d.get("username") is None: audit(f"User updated: {t['username']}")
    return jsonify(ok=True)

@app.route("/api/me/password", methods=["POST"])
@need()
def my_password():
    d = body(); u = q("SELECT * FROM users WHERE username=?", (me(),), one=True)
    cur, new = d.get("current"), d.get("new")
    if not isinstance(cur, str) or not isinstance(new, str) or not check_password_hash(u["password_hash"], cur) or len(new) < MIN_PW: return jsonify(error=f"Current password wrong or new password shorter than {MIN_PW} characters"), 400
    h = generate_password_hash(new); x("UPDATE users SET password_hash=? WHERE id=?", (h, u["id"])); revoke_user_sessions(u["username"]); start_session(dict(username=u["username"], role=u["role"], password_hash=h)); audit("Password changed"); return jsonify(ok=True)       # other sessions of this user end at once

EDITABLE = ["org_name", "home_lat", "home_lon", "brute_threshold", "brute_window_min", "dedupe_seconds", "offline_minutes", "inactive_hours", "retention_days", "geo_lookup", "firewall_enforce", "business_hours", "log_file"]
@app.route("/api/settings")
@need()
def get_settings():
    s = {k: setting(k) for k in EDITABLE}
    if session["role"] == "admin": s["api_key"] = setting("api_key")
    return jsonify(**s, me=me(), role=session["role"])

SETTING_RULES = {"org_name": ("str", 1, 100), "home_lat": ("float", -90, 90), "home_lon": ("float", -180, 180), "brute_threshold": ("int", 1, 100000), "brute_window_min": ("int", 1, 10080),
                 "dedupe_seconds": ("int", 0, 604800), "offline_minutes": ("int", 1, 525600), "inactive_hours": ("int", 1, 87600), "retention_days": ("int", 1, 36500),
                 "geo_lookup": ("bool",), "firewall_enforce": ("bool",), "business_hours": ("hours",), "log_file": ("path", 0, 300)}
def clean_setting(k, v):
    """Validate one setting. The engine and dashboard do arithmetic on these: a typo like retention_days='forever' used to stop log ingestion / kill the retention thread."""
    kind = SETTING_RULES[k]; t = kind[0]
    if t in ("int", "float"):
        ok = not isinstance(v, bool) and (isinstance(v, (int, float)) or (isinstance(v, str) and re.fullmatch(r"\s*-?\d+(\.\d+)?\s*", v)))
        n = (int(float(v)) if t == "int" else float(v)) if ok and float(v) == float(v) and abs(float(v)) < 1e15 else None
        if n is None or not kind[1] <= n <= kind[2] or (t == "int" and isinstance(v, str) and "." in v): raise BadInput(f"{k} must be a {'whole number' if t == 'int' else 'number'} between {kind[1]} and {kind[2]}")
        return str(n)
    if t == "bool":
        if v in (True, 1, "1", "true", "on", "yes"): return "1"
        if v in (False, 0, "0", "false", "off", "no", ""): return "0"
        raise BadInput(f"{k} must be on/off (1 or 0)")
    if t == "hours":
        v = sarg(v, 11)
        if v and not re.fullmatch(r"([01]\d|2[0-3]):[0-5]\d-([01]\d|2[0-3]):[0-5]\d", v): raise BadInput("business_hours must look like 08:00-18:00 (or be empty)")
        return v
    v = sarg(v, kind[2])
    if t == "str" and len(v) < kind[1]: raise BadInput(f"{k} must not be empty")
    return v

@app.route("/api/settings", methods=["PUT"])
@need("admin")
def put_settings():
    d = body(); clean = {}
    try:
        for k, v in d.items():
            if k in EDITABLE: clean[k] = clean_setting(k, v)
    except BadInput as e: return jsonify(error=str(e)), 400                    # all-or-nothing: nothing is saved if one value is invalid
    for k, v in clean.items(): x("INSERT OR REPLACE INTO settings VALUES(?,?)", (k, v))
    audit("Settings updated"); return jsonify(ok=True)

@app.route("/api/settings/regenerate-key", methods=["POST"])
@need("admin")
def regen():
    if not mfa.reauth_ok(): return jsonify(error="recent reauthentication required (POST /api/me/reauth)"), 403
    k = secrets.token_hex(24); db.set_secret_setting("api_key", k); audit("Shared ingest API key regenerated (old key invalid immediately)"); return jsonify(api_key=k)

@app.route("/api/admin/purge", methods=["POST"])
@need("admin")
def purge():
    """Destructive. Requires: admin + CSRF header + recent re-authentication (password, and TOTP when enrolled) + enrolled MFA in production + typed confirmation +
    a protected pre-action backup that is VERIFIED restorable. Any failed safeguard aborts BEFORE deleting; the deletion itself is one transaction; every outcome is audited."""
    d = body(); u = me()
    def refuse(msg, code):
        audit(f"Purge REFUSED: {msg}"); return jsonify(error=msg), code
    if d.get("confirm") != "PURGE ALL ALERTS AND EVENTS": return refuse("confirmation phrase missing", 400)
    if os.environ.get("SOC_ENV") == "production" and not mfa.enabled(u): return refuse("MFA enrollment is required for destructive actions in production", 403)
    if not mfa.reauth_ok(120): return refuse("recent reauthentication required (POST /api/me/reauth, valid 2 min)", 403)
    from security import backup as bk
    try: path = bk.create(db.DB, backup_dir()); info = bk.verify(path)
    except Exception as e: return refuse(f"pre-action backup failed or did not verify ({type(e).__name__}); nothing was deleted", 500)
    c = db.conn()
    try:
        c.execute("BEGIN IMMEDIATE")
        for t in ("alerts", "events", "case_alerts"): c.execute(f"DELETE FROM {t}")
        c.commit()
    except Exception as e: c.rollback(); return refuse(f"purge failed, rolled back ({type(e).__name__})", 500)
    finally: c.close()
    session["reauth_at"] = 0                                    # one reauthentication = one destructive action
    audit(f"All alerts and events purged; verified backup {os.path.basename(path)} ({info['tables']} tables)"); return jsonify(ok=True, backup=os.path.basename(path))

def backup_dir():
    d = os.environ.get("SOC_BACKUP_DIR")
    if not d:
        if os.environ.get("SOC_ENV") == "production": raise RuntimeError("SOC_BACKUP_DIR is required in production")
        d = os.path.join(os.path.dirname(os.path.abspath(db.DB)), "backups")
    return d

@app.route("/api/audit/verify")
@need("admin")
def audit_verify():
    from security import auditchain
    c = db.conn()
    try: return jsonify(auditchain.verify(c))
    finally: c.close()

@app.route("/api/audit/checkpoint", methods=["POST"])
@need("admin")
def audit_checkpoint():
    """Signed chain head. Store it OFF this host (the response is for the operator / tools/audit_checkpoint.py); see docs/AUDIT-INTEGRITY.md."""
    from security import auditchain
    c = db.conn()
    try: rec = auditchain.checkpoint(c, os.environ.get("SOC_AUDIT_CHECKPOINT_DIR"))
    finally: c.close()
    audit("Audit checkpoint created"); return jsonify(rec)

# ---------------- investigation (Splunk-style drill-down) ----------------
@app.route("/api/alerts/<int:i>/detail")
@need()
def alert_detail_api(i):
    d = investigate.alert_detail(i)
    return jsonify(d) if d else (jsonify(error="not found"), 404)

@app.route("/api/investigate/ip/<path:ip>")
@need()
def investigate_ip(ip):
    if not engine.valid_ip(ip): return jsonify(error="Enter a valid IPv4/IPv6 address"), 400
    return jsonify(investigate.ip_profile(ip))

@app.route("/api/alerts/<int:i>/note", methods=["POST"])
@need("analyst")
def alert_note(i):
    t = sarg(body().get("note"), 1000)
    if not t: return jsonify(error="note required"), 400
    x("INSERT INTO alert_activity(alert_id,ts,user,action) VALUES(?,?,?,?)", (i, now(), me(), "Note: " + t)); return jsonify(ok=True)

@app.route("/api/spl")
@need()
def spl():
    try: return jsonify(investigate.run_search(request.args.get("q", ""), request.args.get("earliest")))
    except ValueError as e: return jsonify(error=str(e)), 400
    except Exception: return jsonify(error="Could not parse that search"), 400

# ---------------- boot ----------------
if socketio:
    @socketio.on("connect")
    def _ws_connect(auth=None):
        """Reject the WebSocket handshake unless the caller has a live, server-side-valid session (anonymous, revoked, idle-expired -> refused)."""
        if not me() or session.get("mfa_setup"): return False            # refused: anonymous, revoked, expired, or enrolment-pending sessions
        WS[request.sid] = (session["user"], _sid_hash(session.get("sid"))); return True
    @socketio.on("disconnect")
    def _ws_disconnect(*a): WS.pop(request.sid, None)
    def _ws_loop():
        while True: time.sleep(15); ws_sweep()
    threading.Thread(target=_ws_loop, daemon=True, name="ws-sweep").start()
    @socketio.on("subscribe")
    def _ws_subscribe(*a): return None   # no per-room subscriptions exist; broadcast events carry only {"what": ...} refresh hints, never alert payloads

mfa.register(app, need, audit, start_session, revoke_user_sessions, generate_password_hash)
import socx, socx.api
socx.api.register(app, need, audit, body)
import notify, notify.api
notify.api.register(app, need, audit, body)
import fleet, fleet.api
fleet.api.register(app, need, audit, body, socketio)
import unified, unified.api
unified.init(); unified.api.register(app, need, audit, body)

def supervise(fn):
    """Background workers must not die silently: an unexpected exception is logged and the worker restarts after a pause (a loop that returns normally simply ends)."""
    def run():
        while True:
            try: fn(); return
            except Exception: app.logger.error("background worker %s crashed, restarting in 30 s", getattr(fn, "__name__", fn), exc_info=True); time.sleep(30)
    return run

def start_workers():
    socx.start(); notify.start(); fleet.start((lambda ev, d=None: socketio.emit(ev, d)) if socketio else None)
    for f in (engine.cpu_sampler, engine.host_monitor, engine.tail_log, engine.retention_loop, engine.local_logs_loop, engine.backfill_activity): threading.Thread(target=supervise(f), daemon=True, name=getattr(f, "__name__", "worker")).start()

def set_login():
    """CLI: python app.py --set-login [--user NAME] [--new-user NEWNAME] [--password PW]
    Changes the username and/or password of an existing account (default: the first admin). Works while the server is stopped."""
    import getpass
    argv = sys.argv; opt = lambda k: argv[argv.index(k) + 1] if k in argv and argv.index(k) + 1 < len(argv) else None
    db.init_db()
    target, new_name, pw = opt("--user"), opt("--new-user"), opt("--password")
    row = q("SELECT * FROM users WHERE username=?", (target,), one=True) if target else q("SELECT * FROM users WHERE role='admin' ORDER BY id LIMIT 1", one=True)
    if not row: print("No such user." if target else "No admin user found."); return
    print(f"Account: {row['username']} ({row['role']})")
    if not new_name and not pw:
        new_name = input("New username (Enter = keep): ").strip() or None
        pw = getpass.getpass("New password (Enter = keep): ") or None
        if pw and getpass.getpass("Repeat password: ") != pw: print("Passwords do not match. Nothing changed."); return
    if new_name:
        if not new_name.replace("_", "").replace(".", "").isalnum() or len(new_name) > 40: print("Username may contain letters, digits, _ and . only (max 40). Nothing changed."); return
        if q("SELECT 1 FROM users WHERE lower(username)=lower(?) AND id!=?", (new_name, row["id"]), one=True): print("That username already exists. Nothing changed."); return
    if pw and len(pw) < MIN_PW: print(f"Password must be {MIN_PW}+ characters. Nothing changed."); return
    if not new_name and not pw: print("Nothing to change."); return
    if new_name:
        x("UPDATE users SET username=? WHERE id=?", (new_name, row["id"])); x("UPDATE alerts SET assignee=? WHERE assignee=?", (new_name, row["username"])); x("UPDATE cases SET assignee=? WHERE assignee=?", (new_name, row["username"]))
    if pw: x("UPDATE users SET password_hash=?,active=1 WHERE id=?", (generate_password_hash(pw), row["id"])); revoke_user_sessions(row["username"])
    audit(f"CLI: login changed for {row['username']}" + (f" -> {new_name}" if new_name else "") + (" (password)" if pw else ""), user="cli")
    print("Done. Start the tool and log in with the new details.")

def reset_data():
    """Delete this install's database and secret so it starts completely clean."""
    files = [db.DB + ext for ext in ("", "-wal", "-shm")] + [kf]
    present = [f for f in files if os.path.exists(f)]
    if not present: print("Nothing to reset - already clean."); return
    print("This permanently deletes ALL alerts, events, cases, users, settings and the API key:")
    for f in present: print("   ", f)
    if "--yes" in sys.argv or input("Type YES to continue: ").strip() == "YES":
        from security import backup as bk
        try: bkp = bk.create(db.DB, backup_dir()) if os.path.exists(db.DB) else None; bkp and bk.verify(bkp); print(f"Verified encrypted backup: {bkp}" if bkp else "No database to back up.")
        except Exception as e: sys.exit(f"ABORTED: pre-reset backup failed or did not verify ({type(e).__name__}: {e}). Nothing was deleted.")
        for f in present: os.remove(f)
        print("Reset done. Start the tool again to create a fresh database.")
    else: print("Cancelled.")

def main():
    if "--reset" in sys.argv: return reset_data()
    if "--set-login" in sys.argv: return set_login()
    db.guard_foreign_db()
    try: db.init_db()
    except crypto.CryptoError as e: sys.exit(f"ERROR: encryption keys are not configured correctly: {e}. Generate one with: python -c \"from security import crypto; print('k1:'+crypto.new_key())\" and set SOC_ENC_KEYS (see deploy/env.example).")
    # Clean start by default. Demo data only when explicitly asked (--demo or SOC_DEMO=1).
    if "--demo" in sys.argv or os.environ.get("SOC_DEMO") == "1": db.seed_demo()
    if db.setting("demo_data") == "1": print("  NOTE: this database contains DEMO data. To start clean, stop the tool and run: python app.py --reset\n")
    start_workers()
    import syslogrx; syslogrx.start()
    host = os.environ.get("SOC_HOST", "127.0.0.1"); port = int(os.environ.get("SOC_PORT", 5000))
    cert, key = os.environ.get("SOC_TLS_CERT"), os.environ.get("SOC_TLS_KEY")      # native HTTPS (or terminate TLS in a reverse proxy, see FLEET-GUIDE.md)
    if bool(cert) != bool(key): sys.exit("ERROR: set BOTH SOC_TLS_CERT and SOC_TLS_KEY (or neither).")
    for label, f in (("SOC_TLS_CERT", cert), ("SOC_TLS_KEY", key)):
        if f and not os.access(f, os.R_OK): sys.exit(f"ERROR: {label}={f} does not exist or is not readable by this user. Create it with: python tools/dev_certs.py --name <server-name> --ip <server-ip>")
    tls = {"ssl_context": (cert, key)} if cert and key else {}
    scheme = "https" if tls else "http"                       # the browser MUST use the same scheme as the server: http:// to a TLS port is reset by the server
    print(f"\n  SOC running at {scheme}://{host}:{port}\n"
          f"  First start: the one-time admin password is in initial_admin_credentials.txt next to the database (0600). Change it and delete the file.\n"
          f"  Ingest API key: see Settings → API key\n")
    if tls: print(f"  HTTPS enabled (cert {cert}). Open the dashboard with https:// (plain http:// to this port is reset). Agents use --server {scheme}://<this server's name or IP>:{port}")
    if host in ("127.0.0.1", "localhost", "::1"): print("  NOTE: listening on THIS computer only - remote agents cannot connect. For remote agents set SOC_HOST=0.0.0.0 and enable HTTPS (SOC_TLS_CERT / SOC_TLS_KEY, see tools/dev_certs.py); put them in .env\n")
    elif not tls: print("  WARNING: reachable from the network WITHOUT HTTPS. Agents refuse plain http:// - set SOC_TLS_CERT / SOC_TLS_KEY.\n")
    if os.environ.get("SOC_ENV") == "production":
        sys.exit("ERROR: SOC_ENV=production - the Flask/Werkzeug development server is disabled. Run a WSGI server instead, e.g.\n"
                 "  gunicorn -k gthread --threads 8 -w 1 -b 127.0.0.1:5000 wsgi:app    (behind a TLS reverse proxy; see deploy/README-DEPLOY.md)")
    print("  WARNING: running the Werkzeug DEVELOPMENT server (set SOC_ENV=production and use deploy/ for real deployments).")
    if socketio: socketio.run(app, host=host, port=port, allow_unsafe_werkzeug=True, **tls)
    else: app.run(host=host, port=port, threaded=True, **tls)

if __name__ == "__main__": main()
