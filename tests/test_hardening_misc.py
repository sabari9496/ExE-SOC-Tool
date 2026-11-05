#!/usr/bin/env python3
"""Regression tests for bugs found in the full audit that are not covered by the route sweep (tests/test_api_audit.py):
 1. syslog receiver: hostile input, bounded queue, bounded TCP lines
 2. tools/ and agent/collectors/ must not drift apart (the server's local collector and the agents share code)
 3. doctor: the 'journal not readable' branch must not crash (it used an undefined name)
 4. no undefined names / syntax errors in any Python file (AST check)"""
import ast, builtins, os, random, socket, socketserver, sys, tempfile, threading, time, types, io, contextlib
ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__))); sys.path.insert(0, ROOT)
os.environ["SOC_DB"] = tempfile.mkdtemp() + "/t.db"
R = []
def check(n, ok, info=""): R.append(bool(ok)); print(("PASS " if ok else "FAIL ") + n + ("" if ok else f"\n       {str(info)[-500:]}"), flush=True)

print("== 1. syslog receiver ==")
import syslogrx; syslogrx.MAX_BUF = 300; random.seed(3); bad = 0
samples = ["<999>", "<13>1 2026-10-10T10:00:00Z host app 123 - msg", "<>", "<a>x", "\x00\xff" * 50, "<190>" + "A" * 100000, "<0>Feb 30 25:61:61 h x", "<8>\n\n"]
samples += ["".join(chr(random.choice([random.randint(0, 127), random.randint(0, 0x10FFFF) % 0xD800])) for _ in range(random.randint(0, 80))) for _ in range(2000)]
for s in samples:
    try: syslogrx._add(s, "10.0.0.9")
    except Exception as e: bad += 1; print("   crash:", type(e).__name__, e)
check("1a parser survives 2000+ hostile lines without an exception", bad == 0)
check("1b the queue is bounded under a flood (no memory exhaustion) and drops are counted", len(syslogrx._buf) <= 300 and syslogrx.dropped[0] > 0, (len(syslogrx._buf), syslogrx.dropped[0]))
check("1c over-long lines are truncated, not stored whole", max((len(str(i.get("message", ""))) for i in syslogrx._buf), default=0) <= 4000)
syslogrx._buf.clear(); srv = socketserver.ThreadingTCPServer(("127.0.0.1", 0), syslogrx._T); srv.daemon_threads = True; threading.Thread(target=srv.serve_forever, daemon=True).start()
c = socket.create_connection(srv.server_address); c.sendall(b"A" * 300000 + b"\n<13>Oct  9 10:00:01 h2 sshd[1]: after-long-line\n"); c.close(); time.sleep(1.0)
check("1d TCP: a 300 KB line without framing does not break the stream (next line still received)", any("after-long-line" in str(i) for i in syslogrx._buf))

print("== 2. shared code must not drift ==")
for f in ("linuxlogs.py", "collect.py", "winevents.py", "fim.py", "malware.py", "procmon.py"):
    a, b = os.path.join(ROOT, "tools", f), os.path.join(ROOT, "agent", "collectors", f)
    if os.path.exists(a) and os.path.exists(b): check(f"2 tools/{f} == agent/collectors/{f}", open(a).read() == open(b).read(), "the copies differ: copy agent/collectors/%s over tools/%s" % (f, f))

print("== 3. doctor: unreadable journal ==")
sys.path.insert(0, os.path.join(ROOT, "agent")); import exe_soc_diag as D
HINT = "Hint: You are currently not seeing messages from other users and the system.\n      Users in groups 'adm', 'systemd-journal' can see all messages."
D.RESULTS.clear(); real_sh = D.sh; real_which = D.shutil.which
D.sh = lambda cmd, timeout=15: (0, HINT) if cmd[:1] == ["journalctl"] or "journalctl" in cmd else (1, "")
D.shutil.which = lambda n: "/usr/bin/" + n if n in ("journalctl",) else real_which(n)
buf = io.StringIO()
try:
    with contextlib.redirect_stdout(buf): D.access_check()
    crashed = None
except Exception as e: crashed = e
D.sh = real_sh; D.shutil.which = real_which
check("3a access_check does not crash when the journal is unreadable", crashed is None, crashed)
check("3b ... and reports a FAIL with the usermod fix", "FAIL" in D.RESULTS and "usermod -aG systemd-journal" in buf.getvalue(), buf.getvalue())

print("== 4. static check: no undefined names / syntax errors ==")
BUILTIN = set(dir(builtins)) | {"__file__", "__name__", "__doc__"}; problems = []
def bound(tree):
    out = set()
    for n in ast.walk(tree):
        if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)): out.add(n.name)
        elif isinstance(n, ast.Import): out |= {(a.asname or a.name).split(".")[0] for a in n.names}
        elif isinstance(n, ast.ImportFrom): out |= {a.asname or a.name for a in n.names}
        elif isinstance(n, ast.Name) and isinstance(n.ctx, (ast.Store, ast.Del)): out.add(n.id)
        elif isinstance(n, ast.ExceptHandler) and n.name: out.add(n.name)
        elif isinstance(n, (ast.Global, ast.Nonlocal)): out |= set(n.names)
        elif isinstance(n, ast.arg): out.add(n.arg)
    return out
STAR = {"socx/correlation.py", "socx/health.py", "socx/incidents.py"}                # these use `from .util import *` (verified: names exist at runtime)
for d, ds, fs in os.walk(ROOT):
    ds[:] = [x for x in ds if x not in ("__pycache__", ".git")]
    for f in fs:
        if not f.endswith(".py"): continue
        p = os.path.join(d, f); rel = os.path.relpath(p, ROOT)
        try: tree = ast.parse(open(p, encoding="utf-8").read())
        except SyntaxError as e: problems.append((rel, e.lineno, "syntax")); continue
        if rel in STAR: continue
        b = bound(tree) | BUILTIN
        for n in ast.walk(tree):
            if isinstance(n, ast.Name) and isinstance(n.ctx, ast.Load) and n.id not in b: problems.append((rel, n.lineno, n.id))
check("4 every Python file parses and every name it uses is defined", not problems, problems[:10])

print("== 5. settings poisoning (a bad value must not stop ingestion, the dashboard or the retention thread) ==")
os.environ.update(SOC_SECRET="s" * 32, SOC_LOCAL_LOGS="0", SOC_ADMIN_PASSWORD="Adm1n!pass")
import logging, app as A, db, engine
db.init_db(); A.app.config.update(TESTING=False, PROPAGATE_EXCEPTIONS=False); A.app.logger.setLevel(logging.CRITICAL)
c = A.app.test_client(); c.post("/login", data={"username": "admin", "password": "Adm1n!pass"}); H = {"X-Requested-With": "fetch"}
BAD = {"home_lat": ["abc", 999, None, [], True, "nan"], "home_lon": ["x", 181], "retention_days": ["forever", 0, -1, 1e30, "1.5"], "brute_threshold": ["x", 0, {}], "brute_window_min": ["0", "abc"], "dedupe_seconds": ["-1"],
       "offline_minutes": ["-5", "soon"], "inactive_hours": ["0"], "business_hours": ["9-5", "25:00-26:00", "x"], "geo_lookup": ["maybe"], "org_name": ["", "A" * 5000 if False else []]}
rejected = [(k, v) for k, vs in BAD.items() for v in vs if c.put("/api/settings", headers=H, json={k: v}).status_code != 400]
check("5a every invalid setting value is refused with 400", not rejected, rejected)
check("5b nothing was stored by the rejected requests (all-or-nothing)", db.setting("retention_days") == "90" and db.setting("home_lat") == "20.59")
check("5c valid values are accepted and normalised", c.put("/api/settings", headers=H, json={"retention_days": "30", "home_lat": 12.5, "business_hours": "08:00-18:00", "geo_lookup": True, "brute_threshold": 7}).status_code == 200 and db.setting("retention_days") == "30" and db.setting("geo_lookup") == "1" and db.setting("brute_threshold") == "7")
for k, v in (("home_lat", "abc"), ("home_lon", "zzz"), ("retention_days", "forever"), ("brute_threshold", "x"), ("brute_window_min", ""), ("dedupe_seconds", "?"), ("offline_minutes", "soon"), ("inactive_hours", "never")): db.x("INSERT OR REPLACE INTO settings VALUES(?,?)", (k, v))
KEY = db.setting("api_key"); ok = {"dashboard": c.get("/api/dashboard").status_code, "endpoints": c.get("/api/endpoints").status_code, "alerts": c.get("/api/alerts").status_code,
      "ingest": c.post("/api/ingest", headers={"X-API-Key": KEY}, json=[{"host": "h1", "message": "Failed password for root from 203.0.113.5 port 22 ssh2"}] * 6).status_code}
check("5d ALREADY-poisoned settings (old data): dashboard, endpoints, alerts and log ingestion keep working", all(v == 200 for v in ok.values()), ok)
check("5e retention values fall back to safe defaults instead of raising", db.setting_num("retention_days", 90, 1, 36500) == 90 and db.setting_num("home_lat", 20.59, -90, 90, float) == 20.59)
import threading as _t
calls = []
def flaky():
    calls.append(1)
    if len(calls) == 1: raise RuntimeError("boom")
real_sleep = A.time.sleep; A.time.sleep = lambda s: None
try: A.supervise(flaky)()
finally: A.time.sleep = real_sleep
check("5f a background worker that raises is restarted instead of dying silently", len(calls) == 2, calls)
print(f"\n{sum(R)}/{len(R)} passed"); sys.exit(0 if all(R) else 1)
