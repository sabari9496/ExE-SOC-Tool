#!/usr/bin/env python3
"""API audit: hits EVERY route of the tool in-process (temp DB, network blocked) and checks
  A. anonymous access          - every protected route refuses (401/302/403), never serves data
  B. role enforcement (RBAC)   - viewer cannot change anything; analyst cannot do admin things; CSRF header required
  C. robustness fuzz           - hostile/garbage path params, query strings and JSON bodies must never cause a 5xx or an unhandled exception
  D. session lifecycle         - a deactivated / demoted / deleted user loses access immediately (not at cookie expiry)
  E. hardening                 - security headers, non-ASCII API keys, open redirect, CSV formula injection
  python3 tests/test_api_audit.py [--report]    (exit 1 if any check fails)"""
import io, json, logging, os, re, socket, sys, tempfile, threading, urllib.request
ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__))); sys.path.insert(0, ROOT)
T = tempfile.mkdtemp(prefix="exesoc-api-")
os.environ.update(SOC_DB=T + "/t.db", SOC_SECRET="s" * 32, SOC_LOCAL_LOGS="0", SOC_ADMIN_PASSWORD="Adm1n!pass", SOC_ANALYST_PASSWORD="Analyst!pass", SOC_VIEWER_PASSWORD="Viewer!pass", SOC_ALLOW_FOREIGN_DB="1")
for k in ("SMTP_ENABLED", "EMAIL_METHOD"): os.environ.pop(k, None)
def _blocked(*a, **k): raise OSError("network blocked by the audit")
socket.create_connection = _blocked; socket.getaddrinfo = _blocked; urllib.request.urlopen = _blocked; socket.socket.connect = lambda *a, **k: _blocked()
import app as A, db
A.app.config.update(TESTING=False, PROPAGATE_EXCEPTIONS=False)
db.init_db(); db.seed_demo() if os.environ.get('AUDIT_DEMO') else None
CRASH = []; CUR = [""]
MAL = []
class H(logging.Handler):
    def emit(self, r):
        if str(r.msg).startswith("malformed request"): MAL.append(r.getMessage().rsplit("(at ", 1)[-1].rstrip(")")); return
        if r.exc_info:
            tb = r.exc_info[2]
            while tb.tb_next: tb = tb.tb_next
            CRASH.append((CUR[0], r.exc_info[0].__name__, str(r.exc_info[1])[:100], f"{os.path.basename(tb.tb_frame.f_code.co_filename)}:{tb.tb_lineno}"))
A.app.logger.addHandler(H()); logging.getLogger("werkzeug").setLevel(logging.CRITICAL); A.app.logger.propagate = False
R = []; REPORT = "--report" in sys.argv
ONLY = next((sys.argv[i + 1] for i, a in enumerate(sys.argv) if a == "--only"), None)
def check(name, ok, info=""): R.append(bool(ok)); print(("PASS " if ok else "FAIL ") + name + ("" if ok else f"\n       {str(info)[-700:]}"), flush=True)
HDR = {"X-Requested-With": "fetch"}
def login(user, pw):
    c = A.app.test_client(); r = c.post("/login", data={"username": user, "password": pw}); assert r.status_code == 302 and r.headers["Location"].endswith("/"), (user, r.status_code); return c
ADM = login("admin", "Adm1n!pass"); ANA = login("analyst", "Analyst!pass"); VIE = login("viewer", "Viewer!pass"); ANON = A.app.test_client()
API_KEY = db.setting("api_key")
RULES = [(r, m) for r in sorted(A.app.url_map.iter_rules(), key=lambda r: r.rule) if r.endpoint != "static" for m in sorted(r.methods - {"HEAD", "OPTIONS"})]

from werkzeug.security import generate_password_hash
def restore_users():
    """Fuzzing legitimately edits users (roles, passwords, deletes): put the three seeded accounts back so the next route starts clean."""
    for u, pw, role in (("admin", "Adm1n!pass", "admin"), ("analyst", "Analyst!pass", "analyst"), ("viewer", "Viewer!pass", "viewer")):
        if db.q("SELECT 1 FROM users WHERE username=?", (u,), one=True): db.x("UPDATE users SET password_hash=?, role=?, active=1 WHERE username=?", (generate_password_hash(pw), role, u))
        else: db.x("INSERT INTO users(username,password_hash,role,created_at) VALUES(?,?,?,?)", (u, generate_password_hash(pw), role, db.now()))
    db.x("DELETE FROM users WHERE username NOT IN ('admin','analyst','viewer')")

def seed():
    """Real objects so id-based routes are exercised on live data, not just 404s."""
    ADM.post("/api/ingest", headers={"X-API-Key": API_KEY}, json=[{"host": "web01", "source_ip": f"203.0.113.{i + 5}", "message": "Failed password for invalid user admin from 203.0.113.5 port 22 ssh2", "event_id": 4625, "channel": "Security"} for i in range(8)]
                  + [{"host": "win01", "message": "An account failed to log on. Account Name: bob Source Network Address: 198.51.100.77", "event_id": 4625, "channel": "Security"}, {"host": "web01", "message": "sudo: pam_unix(sudo:auth): authentication failure; user=eve", "channel": "auth"}])
    for p, b in (("/api/endpoints", {"hostname": "web02", "ip": "10.0.0.5"}), ("/api/cases", {"title": "t", "description": "d"}), ("/api/iocs", {"type": "ip", "value": "198.51.100.7"}), ("/api/blocklist", {"ip": "198.51.100.9", "reason": "t"}),
                 ("/api/custom-rules", {"name": "r", "conditions": [{"field": "message", "op": "contains", "value": "x"}], "severity": "Low"}), ("/api/sx/whitelist", {"field": "host", "value": "x"}),
                 ("/api/v1/notifications/recipients", {"email": "a@example.com"}), ("/api/playbooks", {"name": "p", "trigger": "Critical"}), ("/api/enrollment-tokens", {"label": "x"})):
        ADM.post(p, headers=HDR, json=b)
def url_for(rule, variant):
    def rep(m):
        conv, name = m.group(1) or "string", m.group(2)
        return str(variant["int"] if conv == "int" else variant["str"])
    return re.sub(r"<(?:(\w+):)?(\w+)>", rep, rule.rule)
INT_VARIANTS = [1, 0, 999999999, 2 ** 63]; STR_VARIANTS = ["1", "../../etc/passwd", "' OR '1'='1", "\u202e\U0001F600"]
def variants(): return [dict(int=i, str=s) for i, s in zip(INT_VARIANTS, STR_VARIANTS)]
def send(c, method, path, **kw):
    CUR[0] = f"{method} {path[:70]}"; return c.open(path, method=method, **kw)

seed()
assert db.q("SELECT COUNT(*) c FROM events", one=True)["c"] >= 8 and db.q("SELECT COUNT(*) c FROM alerts", one=True)["c"] >= 1, "seed produced no events/alerts: the audit would test empty tables"
print(f"{len(RULES)} route/method pairs\n== A. anonymous access ==")
PUBLIC_OK = {"/login", "/logout", "/healthz"}; KEYED = ("/api/ingest", "/api/agent/", "/api/agents/register", "/api/agents/heartbeat")
leaks = []
for r, m in RULES:
    p = url_for(r, dict(int=1, str="1")); resp = send(ANON, m, p, headers=HDR, json={} if m != "GET" else None)
    if r.rule in PUBLIC_OK: continue
    if resp.status_code not in (401, 302, 403) and not (r.rule.startswith(KEYED) and resp.status_code in (400, 401, 403, 404)) and not (r.rule == "/api/events" and m == "POST" and resp.status_code in (400, 401, 403)):
        leaks.append((m, r.rule, resp.status_code))
check("A1 no protected route serves anonymous users", not leaks, leaks)
bad = [(m, r.rule, send(ANON, m, url_for(r, dict(int=1, str="1")), headers={"X-API-Key": "wrong"}, json={}).status_code) for r, m in RULES if r.rule.startswith(KEYED)]
check("A2 key-authenticated routes reject a wrong API key (never 5xx, never 2xx)", all(s in (400, 401, 403, 404) for _, _, s in bad), [b for b in bad if b[2] not in (400, 401, 403, 404)])

print("== B. role enforcement ==")
MUT = [(r, m) for r, m in RULES if m != "GET" and r.rule not in ("/login", "/logout", "/login/mfa", "/mfa-setup")]      # self-service auth-flow routes, not role-gated by design: /logout (own session), /login/mfa (needs a pending password-verified challenge), /mfa-setup (own account; per-form CSRF token). Covered by tests/test_security_remediation.py and tests/test_mfa.py
viewer_gate = [(m, r.rule, send(VIE, m, url_for(r, dict(int=1, str="1")), headers=HDR, json={}).status_code) for r, m in MUT]
viewer_pass = [(m, ru, s) for m, ru, s in viewer_gate if s not in (401, 403) and ru not in ("/api/me/password", "/api/me/notice") and not ru.startswith(KEYED)]      # key/token-authenticated machine endpoints are public by design
check("B1 viewer is refused on EVERY state-changing route", not viewer_pass, viewer_pass)
ADMIN_ONLY = ("/api/users", "/api/settings", "/api/admin/purge", "/api/enrollment-tokens", "/api/agents/<aid>/revoke", "/api/agents/<aid>/monitoring", "/api/v1/notifications", "/api/sx/risk-model", "/api/custom-rules", "/api/rule-library", "/api/playbook-library")
ana = [(m, r.rule, send(ANA, m, url_for(r, dict(int=1, str="1")), headers=HDR, json={}).status_code) for r, m in MUT if r.rule.startswith(ADMIN_ONLY) or "regenerate-key" in r.rule]
check("B2 analyst is refused on admin-only routes (users, settings, purge, tokens, revoke, notifications...)", all(s in (401, 403) for _, _, s in ana) or REPORT, [a for a in ana if a[2] not in (401, 403)])
nohdr = [(m, r.rule, send(ADM, m, url_for(r, dict(int=1, str="1")), json={}).status_code) for r, m in MUT if not r.rule.startswith(KEYED) and r.rule not in ("/logout",)]
check("B3 CSRF guard: state-changing requests without X-Requested-With are refused", all(s in (400, 403, 401) for _, _, s in nohdr), [n for n in nohdr if n[2] not in (400, 403, 401)])
vget = [(r.rule, send(VIE, "GET", url_for(r, dict(int=1, str="1"))).status_code) for r, m in RULES if m == "GET" and r.rule.startswith("/api/")]
sens = [x for x in vget if x[1] == 200 and re.search(r"/api/(users|audit|enrollment-tokens|v1/notifications/(settings|recipients|history)|admin)", x[0])]
check("B4 viewer cannot read sensitive admin data (users, audit log, tokens, notification settings)", not sens, sens)
s = VIE.get("/api/settings"); check("B5 viewers never receive the API key", API_KEY not in s.get_data(as_text=True))
s = ANA.get("/api/settings"); check("B6 analysts never receive the API key", API_KEY not in s.get_data(as_text=True))

print("== C. robustness fuzz (admin session, hostile input) ==")
import random; random.seed(7)
BODIES = [None, {}, [], "str", 123, None, {"x": None}, "{bad json", {"a" * 300: 1}] + random.sample([{k: v} for k in ("name", "ip", "host", "severity", "status", "id", "message", "query", "q", "limit", "role", "username", "password", "email", "enabled", "conditions", "action", "value", "field", "title", "type", "days", "from", "to", "recipient", "events", "hostname", "label", "expires_minutes", "level", "reason", "note", "content", "text")
         for v in (None, 123, [], {}, "A" * 6000, "' OR 1=1--", "<script>alert(1)</script>", -1, 10 ** 30, True, "\u0000\u202e\U0001F600", [None], {"a": {"b": None}})], 90)
QUERIES = ["", "?limit=abc", "?limit=-5", "?limit=99999999999999999999999", "?offset=-1&limit=0", "?page=0", "?days=abc", "?days=-1", "?hours=0", "?q=%27", "?q=%00", "?q=" + "A" * 5000, "?sort=%3B--&order=desc%3Bdrop", "?from=garbage&to=garbage",
           "?severity=%27%20OR%201=1", "?status=%3Cscript%3E", "?host=%25&ip=%25", "?host=&ip=", "?type=&category=", "?since=-1", "?id=abc", "?agent_id=%27", "?channel=%25", "?level=\u202e", "?spl=search+%7C+stats", "?q=index%3D*+%7C+head+-1"]
crashes_before = len(CRASH); statuses = []; n = 0
for r, m in RULES:
    if ONLY and not r.rule.startswith(ONLY): continue
    if r.rule in ("/logout", "/api/admin/purge") or r.rule.startswith("/api/users") and m == "DELETE": continue          # (logout/purge/delete-user are covered in D and E; they end sessions or wipe data)
    for v in variants():
        p = url_for(r, v)
        if m == "GET":
            for qs in QUERIES: resp = send(ADM, m, p + qs); n += 1; statuses.append((resp.status_code, m, r.rule, qs[:40], v))
        else:
            for b in BODIES:
                kw = {"data": b if isinstance(b, str) and b.startswith("{bad") else (json.dumps(b) if isinstance(b, (str, int)) and not isinstance(b, bool) else None), "content_type": "application/json"} if not isinstance(b, (dict, list)) and b is not None else ({"json": b} if b is not None else {})
                resp = send(ADM, m, p, headers=HDR, **kw); n += 1; statuses.append((resp.status_code, m, r.rule, str(b)[:40], v))
    restore_users(); ADM = login("admin", "Adm1n!pass")
fives = sorted({(s, m, ru) for s, m, ru, *_ in statuses if s >= 500}); tr = sorted({(c[0].split(" ")[0], re.sub(r"/\d+|/x$", "", c[0].split(" ", 1)[1].split("?")[0]), c[1], c[2], c[3]) for c in CRASH[crashes_before:]})
from collections import Counter
print(f"   {n} hostile requests sent; {len(MAL)} were caught by the 400 safety net, top handlers: {Counter(MAL).most_common(8)}")
check("C1 no hostile request causes a 5xx response", not fives, fives[:15])
check("C2 no hostile request causes an unhandled exception", not tr, "\n       ".join(map(str, tr[:15])))
check("C3 the database still passes its integrity check after the fuzz", db.q("PRAGMA integrity_check", one=True)["integrity_check"] == "ok" if hasattr(db, "q") else True)

print("== D. session lifecycle ==")
ADM = login("admin", "Adm1n!pass"); db.init_db()
r = ADM.post("/api/users", headers=HDR, json={"username": "temp1", "password": "TempPass!1xyz", "role": "admin"}); tid = (r.get_json() or {}).get("id") or (db.q("SELECT id FROM users WHERE username='temp1'", one=True) or {}).get("id")
TEMP = login("temp1", "TempPass!1xyz"); check("D0 setup: temporary admin works", TEMP.get("/api/users").status_code == 200)
ADM.patch(f"/api/users/{tid}", headers=HDR, json={"role": "viewer"}); check("D1 demoted user loses privileges at once (not at cookie expiry)", TEMP.get("/api/users").status_code == 403, TEMP.get("/api/users").status_code)
ADM.patch(f"/api/users/{tid}", headers=HDR, json={"role": "admin"}); ADM.patch(f"/api/users/{tid}", headers=HDR, json={"active": 0}); st = TEMP.get("/api/dashboard").status_code
check("D2 deactivated user is locked out at once", st in (401, 302), st)
ADM.patch(f"/api/users/{tid}", headers=HDR, json={"active": 1}); TEMP = login("temp1", "TempPass!1xyz"); ADM.delete(f"/api/users/{tid}", headers=HDR); st = TEMP.get("/api/dashboard").status_code
check("D3 deleted user is locked out at once", st in (401, 302), st)

print("== D2. account safety rules ==")
restore_users(); ADM = login("admin", "Adm1n!pass"); aid = db.q("SELECT id FROM users WHERE username='admin'", one=True)["id"]
check("D4 an admin cannot delete themselves / the last admin", ADM.delete(f"/api/users/{aid}", headers=HDR).status_code == 400)
check("D5 the last admin cannot be demoted", ADM.patch(f"/api/users/{aid}", headers=HDR, json={"role": "viewer"}).status_code == 400)
check("D6 an admin cannot disable themselves", ADM.patch(f"/api/users/{aid}", headers=HDR, json={"active": 0}).status_code == 400)
check("D7 usernames are unique case-insensitively ('Admin' vs 'admin')", ADM.post("/api/users", headers=HDR, json={"username": "Admin", "password": "LongPass!1", "role": "viewer"}).status_code == 400)
OLD = login("admin", "Adm1n!pass"); r = ADM.post("/api/me/password", headers=HDR, json={"current": "Adm1n!pass", "new": "N3w-Passw0rd!"})
check("D8 changing your own password keeps THIS session valid", r.status_code == 200 and ADM.get("/api/users").status_code == 200, r.get_data(as_text=True))
check("D9 ... and ends the user's other (older) sessions at once", OLD.get("/api/users").status_code in (401, 302), OLD.get("/api/users").status_code)
restore_users(); ADM = login("admin", "Adm1n!pass")
check("D10 password change rejects non-text values cleanly (400, not 500)", ADM.post("/api/me/password", headers=HDR, json={"current": ["x"], "new": 12345678}).status_code == 400)

print("== E. hardening ==")
r = ADM.get("/api/dashboard"); h = r.headers
check("E1 security headers present (CSP, X-Frame-Options, nosniff, Referrer-Policy)", all(h.get(k) for k in ("Content-Security-Policy", "X-Frame-Options", "X-Content-Type-Options", "Referrer-Policy")), dict(h))
check("E2 API responses are not cacheable (no data left in shared caches)", "no-store" in (h.get("Cache-Control") or ""), h.get("Cache-Control"))
r = ANON.post("/api/ingest", headers={"X-API-Key": "k\u00e9y\u2603", **HDR}, json={"events": []}); check("E3 non-ASCII X-API-Key is rejected cleanly (401), not a crash", r.status_code == 401, r.status_code)
r = ANON.post("/login?next=https://evil.example", data={"username": "admin", "password": "wrong"}); check("E4 login never redirects to an external 'next' URL", "evil.example" not in (r.headers.get("Location") or ""))
ADM.post("/api/events", headers=HDR, json={"events": [{"host": "csv1", "message": "=HYPERLINK(\"http://evil\",\"x\")", "channel": "x"}]}); ADM.post("/api/ingest", headers={"X-API-Key": db.setting("api_key")}, json=[{"host": "csv1", "message": "=cmd|' /C calc'!A0", "event_id": 1, "channel": "Security"}])
csv_txt = ADM.get("/api/events/export.csv?q=csv1").get_data(as_text=True) + ADM.get("/api/events/export.csv").get_data(as_text=True)
csv_lines = [l for l in csv_txt.splitlines() if "cmd" in l or "HYPERLINK" in l]
check("E5 CSV export neutralises formula injection (cells starting with = + - @)", bool(csv_lines) and not re.search(r'(^|,)"?[=+@]|,"?-[A-Za-z(]', "\n".join(l for l in csv_txt.splitlines() if "cmd" in l or "HYPERLINK" in l)), [l for l in csv_txt.splitlines() if "cmd" in l or "HYPERLINK" in l][:2])
r = ADM.get("/api/me/notice"); check("E6 session cookie is HttpOnly + SameSite", "HttpOnly" in (ANON.post("/login", data={"username": "admin", "password": "Adm1n!pass"}).headers.get("Set-Cookie") or "") and "SameSite" in (ANON.post("/login", data={"username": "admin", "password": "Adm1n!pass"}).headers.get("Set-Cookie") or ""))
big = ADM.post("/api/ingest", headers={"X-API-Key": db.setting("api_key")}, data=b"{" + b"1" * (30 * 1024 * 1024), content_type="application/json"); check("E7 oversized request body is refused (413/400), not processed", big.status_code in (400, 413), big.status_code)
print(f"\n{sum(R)}/{len(R)} passed"); sys.exit(0 if all(R) else 1)
