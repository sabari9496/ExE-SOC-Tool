"""EXE SOC backend: REST API + live updates + auth/RBAC. Run: python app.py"""
import os, io, csv, sys, time, secrets, threading
from datetime import datetime, timedelta
from functools import wraps
from flask import Flask, jsonify, request, session, redirect, render_template, Response
from werkzeug.security import generate_password_hash, check_password_hash
import psutil
import db, engine, investigate
from db import q, x, now, setting, RANK

try:
    from flask_socketio import SocketIO
    app = Flask(__name__); socketio = SocketIO(app, async_mode="threading", cors_allowed_origins=[])
    engine.emit = lambda ev, data=None: socketio.emit(ev, data)
except ImportError:                       # live push disabled, UI falls back to polling
    app = Flask(__name__); socketio = None

kf = os.path.join(db.BASE, ".secret")
if not os.path.exists(kf): open(kf, "w").write(secrets.token_hex(32)); os.chmod(kf, 0o600)
app.secret_key = os.environ.get("SOC_SECRET") or open(kf).read()
app.config.update(SESSION_COOKIE_HTTPONLY=True, SESSION_COOKIE_SAMESITE="Lax", JSON_SORT_KEYS=False)

ROLES = {"viewer": 1, "analyst": 2, "admin": 3}
def audit(action, user=None): x("INSERT INTO audit(ts,user,action) VALUES(?,?,?)", (now(), user or session.get("user", "system"), action))
def me(): return session.get("user")

def need(role="viewer"):
    def deco(f):
        @wraps(f)
        def w(*a, **k):
            if not me(): return (jsonify(error="login required"), 401) if request.path.startswith("/api") else redirect("/login")
            if ROLES[session.get("role", "viewer")] < ROLES[role]: return jsonify(error=f"{role} role required"), 403
            if request.method in ("POST", "PUT", "PATCH", "DELETE") and request.headers.get("X-Requested-With") != "fetch":
                return jsonify(error="missing X-Requested-With header"), 400        # CSRF guard
            return f(*a, **k)
        return w
    return deco

def api_key_ok(): return secrets.compare_digest(request.headers.get("X-API-Key", ""), setting("api_key"))
def body(): return request.get_json(silent=True) or {}

# ---------------- pages ----------------
PAGES = {"": "dashboard", "alerts": "alerts", "endpoints": "endpoints", "network": "network", "threat-intel": "intel", "cases": "cases",
         "reports": "reports", "logs": "logs", "search": "search", "playbooks": "playbooks", "settings": "settings", "users": "users"}
def make_page(p, name):
    @need()
    def view(): return render_template("dashboard.html" if name == "dashboard" else "page.html", page=name)
    view.__name__ = "page_" + (name or "x"); app.route("/" + p)(view)
for _p, _n in PAGES.items(): make_page(_p, _n)

fails = {}
@app.route("/login", methods=["GET", "POST"])
def login():
    err = None
    if request.method == "POST":
        ip = request.remote_addr; t = time.time()
        fails[ip] = [i for i in fails.get(ip, []) if t - i < 300]
        u = q("SELECT * FROM users WHERE username=? AND active=1", (request.form.get("username", "").strip(),), one=True)
        if len(fails[ip]) >= 5: err = "Too many attempts. Try again in 5 minutes."
        elif u and check_password_hash(u["password_hash"], request.form.get("password", "")):
            session.clear(); session.update(user=u["username"], role=u["role"]); x("UPDATE users SET last_login=? WHERE id=?", (now(), u["id"]))
            audit("Logged in"); return redirect("/")
        else: fails[ip].append(t); err = "Invalid username or password."
    return render_template("login.html", error=err)

@app.route("/logout")
def logout(): audit("Logged out"); session.clear(); return redirect("/login")

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
        endpoints={"total": len(eps), **st}, map=pts, home=[float(setting("home_lat")), float(setting("home_lon"))],
        recent=q("SELECT id,ts,severity,title,source_ip FROM alerts ORDER BY id DESC LIMIT 5"),
        events=q(f"SELECT {','.join(cols)} FROM alerts ORDER BY id DESC LIMIT 5"), badge=badge(), system=system())

def badge(): return q("SELECT COUNT(*) c FROM alerts WHERE status='New' AND severity IN ('Critical','High')", one=True)["c"]
def system():
    return {"cpu": psutil.cpu_percent(None), "ram": psutil.virtual_memory().percent, "disk": psutil.disk_usage("/").percent,
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
    if request.args.get("q"): w.append("(al.title LIKE ? OR al.source_ip LIKE ? OR al.message LIKE ?)"); a += ["%" + request.args["q"] + "%"] * 3
    lim = min(int(request.args.get("limit", 200)), 1000)
    return jsonify(q(f"SELECT al.*,e.hostname endpoint FROM alerts al LEFT JOIN endpoints e ON e.id=al.endpoint_id WHERE {' AND '.join(w)} ORDER BY al.id DESC LIMIT {lim}", a))

@app.route("/api/alerts/<int:i>", methods=["PATCH"])
@need("analyst")
def alert_update(i):
    d = body(); st, asg = d.get("status"), d.get("assignee")
    if st and st not in ("New", "In Progress", "Resolved"): return jsonify(error="bad status"), 400
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
    if not (api_key_ok() or (me() and ROLES[session.get("role")] >= 2 and request.headers.get("X-Requested-With") == "fetch")): return jsonify(error="unauthorized"), 401
    d = body(); items = d if isinstance(d, list) else [d]; out = []
    for e in items[:500]:
        if not e.get("message"): continue
        a = engine.process_event(e.get("source_ip"), e["message"], e.get("dest_ip"), e.get("host"), e.get("severity"), e.get("title"), e.get("category"))
        out.append(a["id"] if a else None)
    return jsonify(processed=len(out), alert_ids=out)

@app.route("/api/agent/heartbeat", methods=["POST"])
def heartbeat():
    if not api_key_ok(): return jsonify(error="unauthorized"), 401
    d = body()
    if not d.get("hostname"): return jsonify(error="hostname required"), 400
    engine.upsert_endpoint(d["hostname"], d.get("ip") or request.remote_addr, d.get("os"), float(d.get("cpu", 0)), float(d.get("ram", 0)))
    if socketio: socketio.emit("refresh", {"what": "endpoints"})
    return jsonify(ok=True)

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
    if not d.get("hostname"): return jsonify(error="hostname required"), 400
    engine.upsert_endpoint(d["hostname"].strip(), d.get("ip"), d.get("os")); audit(f"Endpoint added: {d['hostname']}"); return jsonify(ok=True)

@app.route("/api/endpoints/<int:i>", methods=["PATCH", "DELETE"])
@need("analyst")
def endpoint_mod(i):
    if request.method == "DELETE":
        if ROLES[session["role"]] < 3: return jsonify(error="admin role required"), 403
        x("DELETE FROM endpoints WHERE id=?", (i,)); audit(f"Endpoint #{i} deleted")
    else: x("UPDATE endpoints SET isolated=? WHERE id=?", (1 if body().get("isolated") else 0, i)); audit(f"Endpoint #{i} isolation={body().get('isolated')}")
    return jsonify(ok=True)

# ---------------- cases ----------------
@app.route("/api/cases")
@need()
def cases(): return jsonify(q("SELECT c.*,(SELECT COUNT(*) FROM case_notes n WHERE n.case_id=c.id) notes,(SELECT COUNT(*) FROM case_alerts a WHERE a.case_id=c.id) alerts FROM cases c ORDER BY id DESC"))

@app.route("/api/cases", methods=["POST"])
@need("analyst")
def case_add():
    d = body()
    if not d.get("title"): return jsonify(error="title required"), 400
    i = x("INSERT INTO cases(title,description,priority,status,assignee,created_at) VALUES(?,?,?,?,?,?)", (d["title"], d.get("description", ""), d.get("priority", "Medium"), "Open", me(), now())); audit(f"Case #{i} created"); return jsonify(id=i)

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
    if d.get("assignee") is not None: x("UPDATE cases SET assignee=? WHERE id=?", (d["assignee"] or None, i))
    if d.get("note"): x("INSERT INTO case_notes(case_id,author,note,ts) VALUES(?,?,?,?)", (i, me(), d["note"][:2000], now()))
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
    if not engine.block_ip((d.get("ip") or "").strip(), d.get("reason") or "Manual", me()): return jsonify(error="Invalid, private or already-blocked IP"), 400
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
    d = body(); v = (d.get("value") or "").strip()
    if not v: return jsonify(error="value required"), 400
    try: x("INSERT INTO iocs(value,type,source,ts) VALUES(?,?,?,?)", (v, "ip" if engine.valid_ip(v) else "domain", d.get("source") or "manual", now()))
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
@app.route("/api/events")
@need()
def events():
    s = "%" + request.args.get("q", "") + "%"
    return jsonify(q("SELECT * FROM events WHERE message LIKE ? OR source_ip LIKE ? OR host LIKE ? ORDER BY id DESC LIMIT 300", (s, s, s)))

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
    since = rows_since(int(request.args.get("days", 7)))
    g = lambda col: q(f"SELECT {col} k,COUNT(*) c FROM alerts WHERE ts>=? GROUP BY {col} ORDER BY c DESC LIMIT 8", (since,))
    res = q("SELECT ts,resolved_at FROM alerts WHERE resolved_at IS NOT NULL AND ts>=?", (since,))
    mttr = round(sum((datetime.strptime(r["resolved_at"], "%Y-%m-%d %H:%M:%S") - datetime.strptime(r["ts"], "%Y-%m-%d %H:%M:%S")).total_seconds() for r in res) / len(res) / 60) if res else 0
    return jsonify(total=q("SELECT COUNT(*) c FROM alerts WHERE ts>=?", (since,), one=True)["c"], resolved=len(res), mttr_minutes=mttr, by_severity=g("severity"), by_category=g("category"),
                   by_status=g("status"), top_ips=g("source_ip"), daily=q("SELECT substr(ts,1,10) k,COUNT(*) c FROM alerts WHERE ts>=? GROUP BY k ORDER BY k", (since,)))

@app.route("/api/reports/export.csv")
@need()
def export_csv():
    s = io.StringIO(); w = csv.writer(s); w.writerow(["id", "time", "severity", "title", "category", "source_ip", "dest_ip", "status", "assignee", "count"])
    for a in q("SELECT * FROM alerts WHERE ts>=? ORDER BY id DESC", (rows_since(int(request.args.get("days", 7))),)):
        w.writerow([str(a[k]).lstrip("=+-@") if isinstance(a[k], str) else a[k] for k in ("id", "ts", "severity", "title", "category", "source_ip", "dest_ip", "status", "assignee", "count")])  # CSV-injection safe
    return Response(s.getvalue(), mimetype="text/csv", headers={"Content-Disposition": "attachment; filename=alerts.csv"})

# ---------------- users / settings ----------------
@app.route("/api/users")
@need("admin")
def users(): return jsonify(q("SELECT id,username,role,active,created_at,last_login FROM users ORDER BY id"))

@app.route("/api/users", methods=["POST"])
@need("admin")
def user_add():
    d = body(); u, p = (d.get("username") or "").strip(), d.get("password") or ""
    if not u.replace("_", "").replace(".", "").isalnum() or len(p) < 8 or d.get("role") not in ROLES: return jsonify(error="Valid username, role and a password of 8+ characters are required"), 400
    try: x("INSERT INTO users(username,password_hash,role,created_at) VALUES(?,?,?,?)", (u, generate_password_hash(p), d["role"], now()))
    except Exception: return jsonify(error="username already exists"), 400
    audit(f"User created: {u} ({d['role']})"); return jsonify(ok=True)

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
    if d.get("role") in ROLES:
        if t["role"] == "admin" and d["role"] != "admin" and admins <= 1: return jsonify(error="Cannot demote the last admin"), 400
        x("UPDATE users SET role=? WHERE id=?", (d["role"], i))
    if "active" in d:
        if t["username"] == me() and not d["active"]: return jsonify(error="Cannot disable yourself"), 400
        x("UPDATE users SET active=? WHERE id=?", (1 if d["active"] else 0, i))
    if d.get("password"):
        if len(d["password"]) < 8: return jsonify(error="Password must be 8+ characters"), 400
        x("UPDATE users SET password_hash=? WHERE id=?", (generate_password_hash(d["password"]), i))
    audit(f"User updated: {t['username']}"); return jsonify(ok=True)

@app.route("/api/me/password", methods=["POST"])
@need()
def my_password():
    d = body(); u = q("SELECT * FROM users WHERE username=?", (me(),), one=True)
    if not check_password_hash(u["password_hash"], d.get("current", "")) or len(d.get("new", "")) < 8: return jsonify(error="Current password wrong or new password shorter than 8 characters"), 400
    x("UPDATE users SET password_hash=? WHERE id=?", (generate_password_hash(d["new"]), u["id"])); audit("Password changed"); return jsonify(ok=True)

EDITABLE = ["org_name", "home_lat", "home_lon", "brute_threshold", "brute_window_min", "dedupe_seconds", "offline_minutes", "inactive_hours", "retention_days", "geo_lookup", "firewall_enforce", "log_file"]
@app.route("/api/settings")
@need()
def get_settings():
    s = {k: setting(k) for k in EDITABLE}
    if session["role"] == "admin": s["api_key"] = setting("api_key")
    return jsonify(**s, me=me(), role=session["role"])

@app.route("/api/settings", methods=["PUT"])
@need("admin")
def put_settings():
    for k, v in body().items():
        if k in EDITABLE: x("INSERT OR REPLACE INTO settings VALUES(?,?)", (k, str(v)[:200]))
    audit("Settings updated"); return jsonify(ok=True)

@app.route("/api/settings/regenerate-key", methods=["POST"])
@need("admin")
def regen(): k = secrets.token_hex(24); x("INSERT OR REPLACE INTO settings VALUES('api_key',?)", (k,)); audit("API key regenerated"); return jsonify(api_key=k)

@app.route("/api/admin/purge", methods=["POST"])
@need("admin")
def purge():
    for t in ("alerts", "events", "case_alerts"): x(f"DELETE FROM {t}")
    audit("All alerts and events purged"); return jsonify(ok=True)

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
    t = (body().get("note") or "").strip()[:1000]
    if not t: return jsonify(error="note required"), 400
    x("INSERT INTO alert_activity(alert_id,ts,user,action) VALUES(?,?,?,?)", (i, now(), me(), "Note: " + t)); return jsonify(ok=True)

@app.route("/api/spl")
@need()
def spl():
    try: return jsonify(investigate.run_search(request.args.get("q", ""), request.args.get("earliest")))
    except ValueError as e: return jsonify(error=str(e)), 400
    except Exception: return jsonify(error="Could not parse that search"), 400

# ---------------- boot ----------------
def start_workers():
    for f in (engine.host_monitor, engine.tail_log, engine.retention_loop): threading.Thread(target=f, daemon=True).start()

def main():
    db.init_db()
    if "--no-demo" not in sys.argv and not os.environ.get("SOC_NODEMO"): db.seed_demo()
    start_workers()
    host = os.environ.get("SOC_HOST", "127.0.0.1"); port = int(os.environ.get("SOC_PORT", 5000))
    print(f"\n  SOC running at http://{host}:{port}\n"
          f"  Default logins (change them in Users):\n"
          f"    admin   / {os.environ.get('SOC_ADMIN_PASSWORD', 'Admin@123')}   — full access\n"
          f"    analyst / {os.environ.get('SOC_ANALYST_PASSWORD', 'Analyst@123')} — triage & respond, no user/settings management\n"
          f"    viewer  / {os.environ.get('SOC_VIEWER_PASSWORD', 'Viewer@123')}  — read-only\n"
          f"  Ingest API key: see Settings → API key\n")
    if socketio: socketio.run(app, host=host, port=port, allow_unsafe_werkzeug=True)
    else: app.run(host=host, port=port, threaded=True)

if __name__ == "__main__": main()
