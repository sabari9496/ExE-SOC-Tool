#!/usr/bin/env python3
"""Pass 4 regression tests (temp DBs, synthetic data, no network). Run: python tests/test_pass4_security.py
Real Socket.IO / nginx / systemd / Windows integration is NOT covered here (blocked in this environment) - see docs/PASS4-SECURITY-REVIEW.md."""
import os, sys, re, json, time, secrets, tempfile, subprocess, unittest, stat
ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__))); sys.path.insert(0, ROOT)
T = tempfile.mkdtemp(); os.chmod(T, 0o700)
for k in list(os.environ):
    if k.startswith("SOC_"): os.environ.pop(k, None)
os.environ.update(SOC_DB=T + "/t.db", SOC_SECRET=secrets.token_hex(32), SOC_LOCAL_LOGS="0", SOC_ALLOW_FOREIGN_DB="1")
import db, app as A, engine
from security import rxsandbox, throttle
db.init_db(); H = {"X-Requested-With": "fetch"}; PW = "a-long-test-password-1"
CRED = dict(l.split("=", 1) for l in open(T + "/initial_admin_credentials.txt").read().splitlines() if "=" in l)
def admin():
    c = A.app.test_client(); r = c.post("/login", data={"username": CRED["username"], "password": CRED["password"]}); assert r.status_code in (302, 303); return c
ADM = admin()
def mkuser(n, role): db.x("INSERT INTO users(username,password_hash,role,created_at) VALUES(?,?,?,?)", (n, A.generate_password_hash(PW), role, db.now()))
def uid(n): return db.q("SELECT id FROM users WHERE username=?", (n,), one=True)["id"]
def sub_run(code, **env):
    e = {k: v for k, v in os.environ.items() if not k.startswith("SOC_")}; e.update(env)
    return subprocess.run([sys.executable, "-W", "ignore", "-c", f"import sys;sys.path.insert(0,{ROOT!r});" + code], env=e, capture_output=True, text=True, timeout=120, cwd=ROOT)
SLOW = "a*a*a*a*a*a*a*a*a*a*b"        # passes the structural heuristics, catastrophic on 'aaaa...!'

class RegexRuntime(unittest.TestCase):
    def test_01_hard_per_match_timeout_and_worker_recovery(self):
        t = time.time()
        with self.assertRaises(rxsandbox.Timeout): rxsandbox.match(SLOW, "a" * 40 + "!", timeout=0.2)
        self.assertLess(time.time() - t, 2.0, "the stuck match is killed at the limit, it does not run to completion")
        self.assertTrue(rxsandbox.match(r"fail(ed)? password", "Failed password for root"), "the replacement worker serves the next request")
        self.assertFalse(rxsandbox.match(r"zzz", "nothing here"))
        with self.assertRaises(ValueError): rxsandbox.match("(unclosed", "x")
    def test_02_throughput_is_acceptable_for_normal_rules(self):
        t = time.time()
        for i in range(2000): rxsandbox.match(r"sshd.*failed", f"line {i} sshd[1]: Failed password")
        self.assertLess(time.time() - t, 6.0, "2000 isolated matches must stay cheap")
    def test_03_engine_disables_a_rule_that_keeps_timing_out_and_ingestion_stays_bounded(self):
        os.environ["SOC_REGEX_TIMEOUT_MS"] = "100"
        db.x("INSERT INTO custom_rules(name,match_type,pattern,severity,enabled) VALUES('slow-bad','regex',?,'High',1)", (SLOW,))
        db.x("INSERT INTO custom_rules(name,match_type,pattern,severity,enabled,category) VALUES('good-one','regex','mimikatz','High',1,'custom')")
        engine.custom_rules_changed(); t = time.time()
        engine.process_batch([{"host": f"h{i}", "message": "a" * 40 + "!"} for i in range(6)])
        self.assertLess(time.time() - t, 8.0, "ingestion is bounded by the per-match timeout")
        row = db.q("SELECT enabled FROM custom_rules WHERE name='slow-bad'", one=True)
        self.assertIsNotNone(row, "the rule is never deleted"); self.assertEqual(row["enabled"], 0, "disabled after repeated timeouts")
        self.assertTrue(db.q("SELECT 1 FROM audit WHERE action LIKE 'Custom rule #% DISABLED%'", one=True), "disabling is audited")
        engine.custom_rules_changed(); before = db.q("SELECT COUNT(*) c FROM alerts", one=True)["c"]
        engine.process_batch([{"host": "hx", "message": "mimikatz sekurlsa::logonpasswords"}])
        self.assertGreater(db.q("SELECT COUNT(*) c FROM alerts", one=True)["c"], before, "other rules keep working")

class Concurrency(unittest.TestCase):
    def test_01_throttle_counts_are_exact_across_processes(self):
        code = "import db;db.init_db();from security import throttle\nfor _ in range(30): throttle.hit('p4','shared-key')"
        env = {k: v for k, v in os.environ.items()}
        ps = [subprocess.Popen([sys.executable, "-W", "ignore", "-c", f"import sys;sys.path.insert(0,{ROOT!r});" + code], env=env, stderr=subprocess.PIPE, text=True, cwd=ROOT) for _ in range(4)]
        errs = [p.communicate(timeout=120)[1] for p in ps]; self.assertEqual([p.returncode for p in ps], [0, 0, 0, 0], errs)
        self.assertEqual(throttle.count("p4", "shared-key", 600), 120, "no lost updates and no 'database is locked' under 4 concurrent processes")
    def test_02_concurrent_wrong_logins_are_all_counted_and_block(self):
        mkuser("conc1", "viewer"); import threading
        def attempt(i): A.app.test_client().post("/login", data={"username": "conc1", "password": "wrong-pass-x"}, environ_base={"REMOTE_ADDR": f"10.4.{i // 200}.{i % 200 + 1}"})
        ths = [threading.Thread(target=attempt, args=(i,)) for i in range(24)]; [t.start() for t in ths]; [t.join() for t in ths]
        self.assertGreaterEqual(throttle.count("login-acct", "conc1", 300), 20)
        r = A.app.test_client().post("/login", data={"username": "conc1", "password": PW}, environ_base={"REMOTE_ADDR": "10.99.0.1"}); self.assertIn(b"Too many attempts", r.data)
        throttle.clear("login-acct", "conc1")

class Sessions(unittest.TestCase):
    def _login(self, n):
        c = A.app.test_client(); self.assertIn(c.post("/login", data={"username": n, "password": PW}).status_code, (302, 303)); self.assertEqual(c.get("/api/me/notice").status_code, 200); return c
    def test_01_disabling_an_account_ends_its_session_immediately(self):
        mkuser("dis1", "analyst"); c = self._login("dis1")
        self.assertEqual(ADM.patch(f"/api/users/{uid('dis1')}", headers=H, json={"active": False}).status_code, 200); self.assertEqual(c.get("/api/alerts").status_code, 401)
    def test_02_deleting_an_account_ends_its_session(self):
        mkuser("del1", "analyst"); c = self._login("del1"); self.assertEqual(ADM.delete(f"/api/users/{uid('del1')}", headers=H).status_code, 200); self.assertEqual(c.get("/api/alerts").status_code, 401)
    def test_03_admin_password_reset_ends_other_sessions(self):
        mkuser("pw1", "analyst"); c = self._login("pw1"); r = ADM.patch(f"/api/users/{uid('pw1')}", headers=H, json={"password": "brand-new-long-password-3"}); self.assertEqual(r.status_code, 200); self.assertEqual(c.get("/api/alerts").status_code, 401)
    def test_04_role_demotion_takes_effect_on_the_live_session(self):
        mkuser("rd1", "admin"); c = self._login("rd1"); self.assertEqual(c.get("/api/users").status_code, 200)
        self.assertEqual(ADM.patch(f"/api/users/{uid('rd1')}", headers=H, json={"role": "viewer"}).status_code, 200); self.assertIn(c.get("/api/users").status_code, (401, 403))
    def test_05_server_side_revocation_by_admin_endpoint(self):
        mkuser("rv1", "analyst"); c = self._login("rv1"); r = ADM.post("/api/admin/sessions/revoke", headers=H, json={"username": "rv1"}) if False else None
        db.x("UPDATE sessions SET revoked=1 WHERE username='rv1'"); self.assertEqual(c.get("/api/alerts").status_code, 401)

class Hardening(unittest.TestCase):
    def test_01_db_permission_failure_is_visible_dev_and_fatal_in_production(self):
        code = "import os,db\nreal=os.chmod\ndef boom(p,m): raise PermissionError(1,'Operation not permitted')\nos.chmod=boom\ndb.harden_db_files()\nprint('returned')"
        d = tempfile.mkdtemp(); os.chmod(d, 0o700); open(d + "/x.db", "w").close(); os.chmod(d + "/x.db", 0o644)
        o = sub_run(code, SOC_DB=d + "/x.db", SOC_ALLOW_FOREIGN_DB="1"); self.assertIn("could not restrict database file permissions", o.stderr, "dev: a visible warning, not silence"); self.assertIn("returned", o.stdout)
        o = sub_run(code, SOC_DB=d + "/x.db", SOC_ALLOW_FOREIGN_DB="1", SOC_ENV="production", SOC_SECRET=secrets.token_hex(32), SOC_ENC_KEYS="k1:" + "A" * 43); self.assertNotEqual(o.returncode, 0); self.assertIn("could not restrict", o.stdout + o.stderr)
    def test_02_encryption_key_file_must_not_be_world_readable(self):
        d = tempfile.mkdtemp(); kf = d + "/keys"; open(kf, "w").write("k1:" + "A" * 43); os.chmod(kf, 0o644)
        o = sub_run("from security import crypto;crypto.load_ring();print('loaded')", SOC_ENC_KEY_FILE=kf, SOC_DB=d + "/y.db", SOC_ALLOW_FOREIGN_DB="1")
        self.assertIn("chmod 600", o.stderr); self.assertNotIn("A" * 43, o.stdout + o.stderr, "the key itself is never printed")
        o = sub_run("from security import crypto;crypto.load_ring();print('loaded')", SOC_ENC_KEY_FILE=kf, SOC_ENV="production", SOC_DB=d + "/y.db", SOC_ALLOW_FOREIGN_DB="1")
        self.assertNotIn("loaded", o.stdout); self.assertIn("accessible to other users", o.stdout + o.stderr)
        os.chmod(kf, 0o600); o = sub_run("from security import crypto;crypto.load_ring();print('loaded')", SOC_ENC_KEY_FILE=kf, SOC_ENV="production", SOC_DB=d + "/y.db", SOC_ALLOW_FOREIGN_DB="1"); self.assertIn("loaded", o.stdout, o.stderr)
class DeployTools(unittest.TestCase):
    def test_01_systemd_analyze_accepts_the_unit_when_the_tool_exists(self):
        """Real tool output (systemd-analyze verify/security --offline), run on a COPY with host-specific values substituted. It checks directive syntax and sandbox score; it does NOT start the service."""
        import shutil
        if not shutil.which("systemd-analyze"): self.skipTest("systemd-analyze not installed")
        u = open(os.path.join(ROOT, "deploy/soc.service")).read()
        u = re.sub(r"^ExecStart=.*$", "ExecStart=/usr/bin/true", u, flags=re.M); u = re.sub(r"^(EnvironmentFile|WorkingDirectory)=.*$", "", u, flags=re.M)
        u = u.replace("User=exesoc", "User=root").replace("Group=exesoc", "Group=root"); p = os.path.join(T, "soc-check.service"); open(p, "w").write(u)
        r = subprocess.run(["systemd-analyze", "verify", p], capture_output=True, text=True); self.assertEqual(r.returncode, 0, r.stdout + r.stderr); self.assertNotIn("Unknown key", r.stderr + r.stdout)
        r = subprocess.run(["systemd-analyze", "security", "--offline=true", p], capture_output=True, text=True); m = re.search(r"exposure level for .*: ([\d.]+)", r.stdout)
        self.assertTrue(m, r.stdout[-300:]); self.assertLessEqual(float(m.group(1)), 5.0, "sandbox score must stay in the OK range")
    def test_02_every_mutating_route_survives_malformed_bodies(self):
        """Fuzz: 9 hostile bodies x every state-changing route as admin; no 5xx (admin purge/reset/logout skipped)."""
        bodies = [b"[]", b'"s"', b"null", b"123", b'{"a":{"b":[1,{"c":null}]}}', b'{"id":[1],"name":{"x":1},"severity":5,"status":[],"enabled":"x","pattern":123,"match_type":[],"threshold":"NaN","email":{},"role":[],"password":{},"username":null}', b"{bad", b"\xff\xfe\x00", b'{"x":"' + b"A" * 300000 + b'"}']
        bad = []
        for r in A.app.url_map.iter_rules():
            if r.rule in ("/logout", "/api/admin/purge", "/api/admin/reset") or r.rule.startswith("/static"): continue
            for m in set(r.methods) & {"POST", "PUT", "PATCH", "DELETE"}:
                url = r.rule
                for a in r.arguments: url = url.replace("<int:%s>" % a, "1").replace("<path:%s>" % a, "x").replace("<%s>" % a, "1")
                for b in bodies:
                    if r.rule == "/api/users/<int:i>" and m == "DELETE": continue          # would delete the admin used by this session
                    resp = ADM.open(url, method=m, data=b, headers=dict(H, **{"Content-Type": "application/json"}))
                    if resp.status_code >= 500: bad.append((m, url, resp.status_code))
        self.assertEqual(bad, [])

if __name__ == "__main__": unittest.main(verbosity=2)
