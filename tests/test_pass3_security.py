#!/usr/bin/env python3
"""Pass 3 regression tests (in-process, temp DB, synthetic data, no network). Run: python tests/test_pass3_security.py
Socket.IO items here are UNIT-LEVEL with a stub server object (flask-socketio is not installable offline) and are NOT runtime verification."""
import os, sys, re, json, time, secrets, tempfile, subprocess, unittest, random, stat
ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__))); sys.path.insert(0, ROOT)
T = tempfile.mkdtemp()
for k in list(os.environ):
    if k.startswith("SOC_") or k in ("EMAIL_METHOD",): os.environ.pop(k, None)
os.environ.update(SOC_DB=T + "/t.db", SOC_SECRET=secrets.token_hex(32), SOC_LOCAL_LOGS="0", SOC_ALLOW_FOREIGN_DB="1")
import db, app as A, fleet
from security import agentsig, throttle
db.init_db(); H = {"X-Requested-With": "fetch"}
CRED = dict(l.split("=", 1) for l in open(T + "/initial_admin_credentials.txt").read().splitlines() if "=" in l)
PW = "a-long-test-password-1"
def admin():
    c = A.app.test_client(); r = c.post("/login", data={"username": CRED["username"], "password": CRED["password"]}); assert r.status_code in (302, 303), r.status_code; return c
ADM = admin()
def mkuser(n, role): db.x("INSERT INTO users(username,password_hash,role,created_at) VALUES(?,?,?,?)", (n, A.generate_password_hash(PW), role, db.now()))
def enroll(host):
    tok = ADM.post("/api/enrollment-tokens", json={"label": host}, headers=H).get_json()["token"]
    r = A.app.test_client().post("/api/agents/register", json={"enrollment_token": tok, "hostname": host, "os": "Linux", "os_version": "x", "agent_version": "1"}); assert r.status_code == 200, r.data; return r.get_json()
def signed(ag, path, raw, **kw):
    ts = str(int(time.time())); nonce = secrets.token_urlsafe(16)
    h = {"Authorization": "Bearer " + ag["credential"], "X-Timestamp": ts, "X-Nonce": nonce, "Content-Type": "application/json", "X-Signature": agentsig.sign(ag["signing_key"], "POST", path, ts, nonce, raw)}
    return A.app.test_client().post(path, data=raw, headers=h)
def js(o): return json.dumps(o, separators=(",", ":")).encode()
def sub_run(code, **env):
    e = {k: v for k, v in os.environ.items() if not k.startswith("SOC_")}; e.update(env)
    return subprocess.run([sys.executable, "-W", "ignore", "-c", f"import sys;sys.path.insert(0,{ROOT!r});" + code], env=e, capture_output=True, text=True, timeout=120, cwd=ROOT)

class Agents(unittest.TestCase):
    @classmethod
    def setUpClass(c): c.a = enroll("p3-host-a")
    def test_01_malformed_json_types_never_500(self):
        for hb in ({"collectors": {"a": 1}, "ips": "1.2.3.4", "collector_errors": 5, "cpu": "x"}, {"collectors": "abc", "ips": 7}, {"ips": [{"x": 1}], "collectors": [None, 3]}):
            self.assertEqual(signed(self.a, "/api/agents/heartbeat", js(hb)).status_code, 200, hb)
        for ev in ({"events": [{"uid": "u1", "message": "m", "event_id": {"a": 1}}, {"uid": "u2", "message": "m", "event_id": [1], "level": {"x": 1}}, {"uid": "u3", "message": "m", "event_id": True, "source_ip": ["1.1.1.1"]}]},):
            r = signed(self.a, "/api/events", js(ev)); self.assertEqual(r.status_code, 200, r.data); self.assertEqual(r.get_json()["accepted"], 3)
        for raw in (b"[1,2,3]", b'"str"', b"null", b"{bad json", b"\xff\xfe"):
            self.assertLess(signed(self.a, "/api/agents/heartbeat", raw).status_code, 500, raw)
    def test_02_oversized_body_refused(self):
        r = signed(self.a, "/api/events", js({"events": [{"uid": "big", "message": "x" * 2_100_000}]})); self.assertEqual(r.status_code, 413)
    def test_03_rotate_credential_needs_recent_reauth_and_kills_old_credential(self):
        ag = enroll("p3-host-rot"); c = admin(); aid = ag["agent_id"]
        with c.session_transaction() as s: s["reauth_at"] = time.time() - 4000
        r = c.post(f"/api/agents/{aid}/rotate-credential", headers=H); self.assertEqual(r.status_code, 403, "stale reauthentication must be refused")
        self.assertEqual(signed(ag, "/api/agents/heartbeat", js({"cpu": 1})).status_code, 200, "refused rotation must not have touched the credential")
        with c.session_transaction() as s: s["reauth_at"] = time.time()
        r = c.post(f"/api/agents/{aid}/rotate-credential", headers=H); self.assertEqual(r.status_code, 200); new = r.get_json()
        self.assertEqual(signed(ag, "/api/agents/heartbeat", js({"cpu": 1})).status_code, 403, "the OLD credential must be rejected after rotation")
        self.assertEqual(signed(new | {"credential": new["credential"]}, "/api/agents/heartbeat", js({"cpu": 1})).status_code, 200, "the NEW credential works")
    def test_04_auth_status_readiness_and_no_secret_leak(self):
        r = ADM.get("/api/agents/auth-status"); txt = r.get_data(as_text=True); j = r.get_json()
        self.assertNotIn(self.a["signing_key"], txt); self.assertNotIn(self.a["credential"].split(".", 1)[1], txt); self.assertNotIn("sign_key_enc", txt); self.assertNotIn("secret_hash", txt)
        self.assertIn("legacy_api_key", j); self.assertIn("ready_for_legacy_off", j)
    def test_05_empty_fleet_is_not_ready_for_hmac_required(self):
        o = sub_run("import tempfile,os;T=tempfile.mkdtemp();os.environ.update(SOC_DB=T+'/x.db',SOC_SECRET='ab12'*16,SOC_LOCAL_LOGS='0',SOC_ALLOW_FOREIGN_DB='1');import db,app as A;db.init_db()\n"
                    "d=dict(l.split('=',1) for l in open(T+'/initial_admin_credentials.txt').read().splitlines() if '=' in l);c=A.app.test_client();c.post('/login',data={'username':d['username'],'password':d['password']})\n"
                    "print(c.get('/api/agents/auth-status').get_json()['ready_for_hmac_required'])")
        self.assertEqual(o.stdout.strip().splitlines()[-1], "False", o.stderr[-300:])
    def test_06_unsigned_requests_never_accepted_after_first_signature(self):
        ag = enroll("p3-ratchet"); self.assertEqual(signed(ag, "/api/agents/heartbeat", js({"cpu": 1})).status_code, 200)
        ts = str(int(time.time())); r = A.app.test_client().post("/api/agents/heartbeat", data=js({"cpu": 1}), headers={"Authorization": "Bearer " + ag["credential"], "X-Timestamp": ts, "X-Nonce": secrets.token_urlsafe(16), "Content-Type": "application/json"})
        self.assertEqual(r.status_code, 401, "downgrade to an unsigned request must be refused")

class ProductionDefaults(unittest.TestCase):
    def test_01_agent_auth_defaults_and_fail_closed(self):
        old = {k: os.environ.get(k) for k in ("SOC_ENV", "SOC_AGENT_AUTH", "SOC_LEGACY_API_KEY")}
        try:
            for k in old: os.environ.pop(k, None)
            self.assertEqual((agentsig.mode(), agentsig.legacy_key_on()), ("permissive", True), "development default stays compatible")
            os.environ["SOC_ENV"] = "production"; self.assertEqual((agentsig.mode(), agentsig.legacy_key_on()), ("hmac-required", False), "production default is strict")
            os.environ["SOC_AGENT_AUTH"] = "permissive"; os.environ["SOC_LEGACY_API_KEY"] = "on"; self.assertEqual((agentsig.mode(), agentsig.legacy_key_on()), ("permissive", True), "explicit migration opt-in is honoured")
            os.environ["SOC_AGENT_AUTH"] = "hmac-requird"; os.environ["SOC_LEGACY_API_KEY"] = "onn"; self.assertEqual((agentsig.mode(), agentsig.legacy_key_on()), ("hmac-required", False), "typos fail CLOSED")
        finally:
            for k, v in old.items(): os.environ.pop(k, None) if v is None else os.environ.__setitem__(k, v)
    def test_02_production_cookie_flags_and_password_floor(self):
        o = sub_run("import os,tempfile;T=tempfile.mkdtemp();import db,app as A;print(A.app.config['SESSION_COOKIE_SECURE'],A.app.config['SESSION_COOKIE_NAME'],A.app.config['SESSION_COOKIE_HTTPONLY'],A.app.config['SESSION_COOKIE_SAMESITE'],A.MIN_PW)",
                    SOC_ENV="production", SOC_SECRET=secrets.token_hex(32), SOC_ENC_KEYS="k1:" + "A" * 43, SOC_DB=T + "/p.db", SOC_ALLOW_FOREIGN_DB="1", SOC_MIN_PASSWORD="4", SOC_LOCAL_LOGS="0")
        self.assertEqual(o.stdout.strip(), "True __Host-soc True Lax 12", o.stderr[-300:])
    def test_03_production_refuses_weak_or_missing_session_secret(self):
        kf = os.path.join(ROOT, ".secret"); before = (os.path.exists(kf), os.path.getmtime(kf) if os.path.exists(kf) else None)
        for sec in ("", "short", "a" * 40, "ab" * 16):
            o = sub_run("import app", SOC_ENV="production", SOC_SECRET=sec, SOC_ENC_KEYS="k1:" + "A" * 43, SOC_DB=T + "/q.db", SOC_ALLOW_FOREIGN_DB="1")
            self.assertNotEqual(o.returncode, 0, f"production must refuse SOC_SECRET={sec!r}"); self.assertIn("SOC_SECRET", o.stdout + o.stderr)
        self.assertEqual(before, (os.path.exists(kf), os.path.getmtime(kf) if os.path.exists(kf) else None), "production start-up must never create or touch a .secret file in the code tree")
    def test_04_database_files_owner_only_and_loose_dir_refused_in_production(self):
        self.assertEqual(stat.S_IMODE(os.stat(T + "/t.db").st_mode), 0o600)
        d = tempfile.mkdtemp(); os.chmod(d, 0o777)
        o = sub_run("import db;db.init_db()", SOC_ENV="production", SOC_SECRET=secrets.token_hex(32), SOC_ENC_KEYS="k1:" + "A" * 43, SOC_DB=d + "/l.db", SOC_ALLOW_FOREIGN_DB="1", SOC_ADMIN_PASSWORD="a-very-long-admin-password-1")
        self.assertNotEqual(o.returncode, 0); self.assertIn("writable by other users", o.stdout + o.stderr)
    def test_05_healthz_is_minimal(self):
        r = A.app.test_client().get("/healthz"); self.assertEqual((r.status_code, r.get_json()), (200, {"status": "ok"}))

class Auth(unittest.TestCase):
    def test_01_account_wide_throttle_across_addresses_persists_in_db(self):
        mkuser("victim1", "viewer"); c = A.app.test_client()
        for i in range(20): c.post("/login", data={"username": "victim1", "password": "wrong-pw-x"}, environ_base={"REMOTE_ADDR": f"10.9.{i // 200}.{i % 200 + 1}"})
        self.assertGreaterEqual(throttle.count("login-acct", "victim1", 300), 20, "failures are stored in SQLite, not process memory")
        r = c.post("/login", data={"username": "victim1", "password": PW}, environ_base={"REMOTE_ADDR": "10.77.7.7"}); self.assertIn(b"Too many attempts", r.data, "correct password from a NEW address is still blocked during distributed guessing")
        throttle.clear("login-acct", "victim1"); throttle.clear("login-ip", "10.77.7.7")
    def test_02_no_account_enumeration(self):
        mkuser("realuser", "viewer"); c = A.app.test_client(); throttle.clear("login-ip", "127.0.0.1")
        a = c.post("/login", data={"username": "realuser", "password": "bad-pass-zz"}, environ_base={"REMOTE_ADDR": "10.50.0.1"}).get_data(as_text=True)
        b = c.post("/login", data={"username": "nosuchuser", "password": "bad-pass-zz"}, environ_base={"REMOTE_ADDR": "10.50.0.2"}).get_data(as_text=True)
        norm = lambda s: re.sub(r"\s+", " ", re.search(r'class="[^"]*err[^"]*"[^>]*>([^<]*)', s).group(1) if re.search(r'class="[^"]*err[^"]*"[^>]*>([^<]*)', s) else s)
        self.assertEqual(norm(a), norm(b))
    def test_03_user_creation_enforces_password_floor(self):
        r = ADM.post("/api/users", headers=H, json={"username": "shortpw", "password": "12345678", "role": "viewer"}); self.assertEqual(r.status_code, 400)
        r = ADM.post("/api/users", headers=H, json={"username": "okpw1", "password": "a-long-enough-pass-9", "role": "viewer"}); self.assertEqual(r.status_code, 200)
    def test_04_session_id_rotates_and_password_change_ends_old_sessions(self):
        mkuser("rot1", "viewer"); c1 = A.app.test_client(); c1.post("/login", data={"username": "rot1", "password": PW})
        with c1.session_transaction() as s: sid1 = s["sid"]
        c2 = A.app.test_client(); c2.post("/login", data={"username": "rot1", "password": PW})
        with c2.session_transaction() as s: sid2 = s["sid"]
        self.assertNotEqual(sid1, sid2); self.assertEqual(c1.get("/api/me/notice").status_code, 200)
        r = c2.post("/api/me/password", headers=H, json={"current": PW, "new": "another-long-password-2"}); self.assertIn(r.status_code, (200, 204), r.data)
        self.assertEqual(c1.get("/api/me/notice").status_code, 401, "other sessions end on password change")
    def test_05_self_service_auth_routes_keep_their_own_csrf(self):
        mkuser("csrf1", "viewer"); c = A.app.test_client(); c.post("/login", data={"username": "csrf1", "password": PW})
        self.assertEqual(c.post("/logout").status_code, 400, "logout without header/token must be refused"); self.assertEqual(c.get("/api/me/notice").status_code, 200, "...and must not log the user out")
        self.assertEqual(c.get("/logout").status_code, 405, "GET logout is not allowed")
        self.assertEqual(c.post("/mfa-setup", data={"code": "123456"}).status_code, 400, "mfa-setup POST needs its form token")
        self.assertIn(c.post("/logout", headers=H).status_code, (200, 303)); self.assertEqual(c.get("/api/me/notice").status_code, 401)
    def test_06_mfa_setup_page_escapes_username(self):
        evil = "<img src=x onerror=alert(1)>"
        db.x("INSERT INTO users(username,password_hash,role,created_at) VALUES(?,?,?,?)", (evil, A.generate_password_hash(PW), "analyst", db.now()))
        os.environ["SOC_MFA_REQUIRED"] = "analyst"
        try:
            c = A.app.test_client(); r = c.post("/login", data={"username": evil, "password": PW}); page = c.get("/mfa-setup").get_data(as_text=True)
            self.assertNotIn("<img", page, "raw markup from a username must never reach the page"); self.assertTrue("&lt;img" in page or "%3Cimg" in page)
        finally: os.environ.pop("SOC_MFA_REQUIRED", None)

class Rules(unittest.TestCase):
    def test_01_regex_probe_gives_a_hard_limit_without_the_regex_module(self):
        import engine
        slow = "a*a*a*a*a*a*a*a*a*a*b"                       # passes the structural heuristics, catastrophic in practice
        engine.cr_matcher("regex", slow)                      # no ValueError from the heuristics
        t = time.time(); why = engine.regex_probe(slow, timeout=2.0); dt = time.time() - t
        self.assertIn("too slow", why); self.assertLess(dt, 5, "the probe process is killed at the timeout")
        self.assertEqual(engine.regex_probe(r"failed password for .* from \d+\.\d+"), "")
    def test_02_api_refuses_slow_pattern_but_accepts_normal(self):
        base = {"name": "p3 rule", "match_type": "regex", "severity": "High", "category": "x", "threshold": 1, "window_min": 5, "host_filter": "", "description": "", "mitre": ""}
        r = ADM.post("/api/custom-rules", headers=H, json=base | {"pattern": "a*a*a*a*a*a*a*a*a*a*b"}); self.assertEqual(r.status_code, 400, r.data)
        r = ADM.post("/api/custom-rules", headers=H, json=base | {"pattern": r"mimikatz|sekurlsa"}); self.assertIn(r.status_code, (200, 201), r.data)

class SocketIOUnit(unittest.TestCase):
    """UNIT-LEVEL ONLY (stub server). Real handshake/revocation behaviour is NOT verified here: flask-socketio could not be installed offline."""
    class Stub:
        def __init__(s): s.dropped = []; s.server = s
        def disconnect(s, sid): s.dropped.append(sid)
    def test_01_kick_and_sweep_drop_revoked_expired_and_disabled(self):
        stub = self.Stub(); old = A.socketio; A.socketio = stub
        try:
            for n in ("ws_a", "ws_b", "ws_c", "ws_d"): mkuser(n, "viewer")
            def sess(user, **kw):
                sid = secrets.token_urlsafe(16); h = A._sid_hash(sid); t = time.time()
                db.x("INSERT INTO sessions(sid_hash,username,created,last_seen,ip) VALUES(?,?,?,?,?)", (h, user, kw.get("created", t), kw.get("last_seen", t), "x")); return h
            A.WS.clear(); A.WS.update({"s1": ("ws_a", sess("ws_a")), "s2": ("ws_b", sess("ws_b", last_seen=time.time() - 10 ** 6)), "s3": ("ws_c", sess("ws_c")), "s4": ("ws_d", sess("ws_d"))})
            A.ws_sweep(); self.assertEqual(sorted(stub.dropped), ["s2"], "idle-expired socket dropped, healthy ones kept")
            db.x("UPDATE users SET active=0 WHERE username='ws_c'"); A.ws_sweep(); self.assertIn("s3", stub.dropped)
            A.revoke_user_sessions("ws_a"); self.assertIn("s1", stub.dropped); self.assertNotIn("s4", stub.dropped)
        finally: A.socketio = old; A.WS.clear()

class Notify(unittest.TestCase):
    def test_01_per_recipient_cap(self):
        from notify import policy, config
        for i in range(30): db.x("INSERT INTO notification_history(notification_id,incident_id,incident_code,alert_id,ntype,recipient,subject,severity,ts,status,attempts,next_try) VALUES(?,?,?,?,?,?,?,?,datetime('now','localtime'),'SENT',1,0)", (f"n{i}", None, "", None, "alert", "capped@example.com", "s", "High"))
        self.assertEqual(policy.under_recipient_cap(["capped@example.com", "fresh@example.com"]), ["fresh@example.com"])
    def test_02_retry_delay_is_bounded_with_jitter(self):
        import notify
        vals = [notify.retry_wait(1) for _ in range(200)]
        self.assertTrue(all(30 * 0.75 <= v <= 30 * 1.25 for v in vals)); self.assertGreater(len(set(round(v, 3) for v in vals)), 20, "jitter present")
    def test_03_gmail_auth_refuses_to_print_tokens_by_default(self):
        o = subprocess.run([sys.executable, os.path.join(ROOT, "tools/gmail_auth.py"), "--client-id", "x", "--client-secret", "y", "--no-browser"], capture_output=True, text=True, timeout=30)
        self.assertNotEqual(o.returncode, 0); self.assertIn("Refusing", o.stdout + o.stderr)


class Frontend(unittest.TestCase):
    TEXT_PROPS = ("title", "message", "host", "hostname", "username", "source_ip", "dest_ip", "text", "name", "description", "url", "status", "category", "reason", "email", "assignee", "note", "action", "process", "path", "user", "label", "ip", "severities", "mitre")
    def test_01_no_bare_text_interpolation_in_html_templates(self):
        """Every server-supplied TEXT field interpolated into a template literal must pass through esc() (or be a direct argument of toast(), which writes via textContent)."""
        bad = []
        for f in sorted(os.listdir(os.path.join(ROOT, "static"))):
            if not f.endswith(".js"): continue
            for n, line in enumerate(open(os.path.join(ROOT, "static", f), encoding="utf-8").read().split("\n"), 1):
                for m in re.finditer(r"\$\{\s*([a-z]\w*)\.(%s)\s*\}" % "|".join(self.TEXT_PROPS), line):
                    if "toast(" in line[:m.start()] and "innerHTML" not in line: continue
                    bad.append(f"{f}:{n} ${{{m.group(1)}.{m.group(2)}}}")
        self.assertEqual(bad, [], "unescaped server text reaches an HTML template: " + "; ".join(bad))
    def test_02_dom_sinks_use_textcontent_for_toasts_and_no_eval(self):
        js = "".join(open(os.path.join(ROOT, "static", f), encoding="utf-8").read() for f in os.listdir(os.path.join(ROOT, "static")) if f.endswith(".js"))
        self.assertIn("d.textContent=t", js); self.assertNotRegex(js, r"\beval\s*\(|new Function\s*\(|document\.write\s*\(|javascript:")
    def test_03_esc_and_pill_neutralise_hostile_strings_in_node(self):
        import shutil
        if not shutil.which("node"): self.skipTest("node not installed")
        src = open(os.path.join(ROOT, "static", "app.js"), encoding="utf-8").read()
        esc = re.search(r"^const esc=.*$", src, re.M).group(0); pill = re.search(r"^const pill=.*$", src, re.M).group(0)
        js = esc + "\n" + pill + "\nconst h=[`\"><img src=x onerror=alert(1)>`,`' onmouseover='x`,`</td><script>alert(1)</script>`].map(v=>esc(v)+'|'+pill(v)).join('\\n');console.log(h)"
        out = subprocess.run(["node", "-e", js], capture_output=True, text=True).stdout
        self.assertNotRegex(out, r"<img|<script"); self.assertNotIn('"><', out)
        self.assertEqual(re.findall(r'<span class="pill [^"]*">', out).__len__(), 3, "each pill keeps exactly its own class attribute"); self.assertNotRegex(out, r'class="[^"]*[\s=\']onmouseover')
    def test_04_socket_payloads_are_minimal(self):
        eng = open(os.path.join(ROOT, "engine.py"), encoding="utf-8").read()
        self.assertNotIn('emit("alert", a)', eng, "the full alert row must never be pushed to sockets"); self.assertFalse([l for l in eng.splitlines() if 'emit("toast"' in l and "source_ip" in l], "toast pushes must not carry source IPs")

class Deploy(unittest.TestCase):
    def test_01_systemd_unit_is_sandboxed(self):
        s = open(os.path.join(ROOT, "deploy/soc.service")).read()
        for k in ("NoNewPrivileges=true", "ProtectSystem=strict", "PrivateTmp=true", "ProtectHome=true", "CapabilityBoundingSet=", "RestrictAddressFamilies=", "UMask=0077", "User=exesoc", "-w 1", "127.0.0.1:5000", "SOC_ENV=production"): self.assertIn(k, s, k)
        self.assertNotIn("--reload", s); self.assertNotIn("0.0.0.0", s); self.assertNotIn("app.py", s)
    def test_02_nginx_template_replaces_forwarded_headers_and_supports_websocket(self):
        s = open(os.path.join(ROOT, "deploy/nginx-exe-soc.conf")).read()
        for k in ("return 301 https://", "X-Forwarded-For $remote_addr", "Upgrade $http_upgrade", "ssl_protocols TLSv1.2 TLSv1.3", "server_tokens off", "Strict-Transport-Security", "limit_req"): self.assertIn(k, s, k)
        self.assertNotIn("$proxy_add_x_forwarded_for", s, "must not append to client-supplied X-Forwarded-For")
    def test_03_env_example_has_placeholders_only(self):
        s = open(os.path.join(ROOT, "deploy/env.example")).read()
        for line in s.splitlines():
            if line.startswith(("SOC_SECRET", "SOC_ENC_KEYS")): self.assertIn("<", line)
            self.assertNotRegex(line, r"=[0-9a-f]{40,}$")
        for k in ("SOC_AGENT_AUTH=hmac-required", "SOC_LEGACY_API_KEY=off", "SOC_MFA_REQUIRED"): self.assertIn(k, s)
    def test_04_wsgi_exports_app_and_defaults_to_production(self):
        s = open(os.path.join(ROOT, "wsgi.py")).read(); self.assertIn('setdefault("SOC_ENV", "production")', s); self.assertIn("app = _a.app", s)

if __name__ == "__main__": unittest.main(verbosity=2)
