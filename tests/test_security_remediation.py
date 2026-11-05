"""Regression tests for the security remediation (secure defaults, sessions, logout, ReDoS, proxy trust). Run: python tests/test_security_remediation.py
Uses an isolated temp DB, SOC_ALLOW_DEFAULT_CREDS unset (the secure default)."""
import os, sys, tempfile, time, unittest
ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__))); sys.path.insert(0, ROOT)
T = tempfile.mkdtemp()
for k in ("SOC_ALLOW_DEFAULT_CREDS", "SOC_MIN_PASSWORD", "SOC_ENV", "SOC_ADMIN_PASSWORD"): os.environ.pop(k, None)
os.environ.update(SOC_DB=T + "/t.db", SOC_SECRET="s" * 40, SOC_LOCAL_LOGS="0", SOC_ALLOW_FOREIGN_DB="1", SOC_SESSION_IDLE_MIN="30")
import db, app as A
db.init_db()
H = {"X-Requested-With": "fetch"}
def creds():
    d = dict(l.split("=", 1) for l in open(T + "/initial_admin_credentials.txt").read().splitlines() if "=" in l); return d["username"], d["password"]
def login(c, u, p): return c.post("/login", data={"username": u, "password": p}, follow_redirects=False)

class SecurityRemediation(unittest.TestCase):
    def test_01_no_default_credentials(self):
        c = A.app.test_client()
        for u, p in (("admin", "Admin@123"), ("analyst", "Analyst@123"), ("viewer", "Viewer@123")):
            self.assertNotEqual(login(c, u, p).status_code, 302, f"{u} default password must not work")
        self.assertEqual(db.q("SELECT count(*) n FROM users", one=True)["n"], 1)          # only the bootstrap admin
    def test_02_bootstrap_credentials_file_is_private_and_works(self):
        f = T + "/initial_admin_credentials.txt"
        if os.name == "posix": self.assertEqual(oct(os.stat(f).st_mode & 0o777), "0o600")
        u, p = creds(); self.assertEqual(login(A.app.test_client(), u, p).status_code, 302)
    def test_03_logout_is_post_only_and_revokes_session(self):
        c = A.app.test_client(); u, p = creds(); login(c, u, p)
        self.assertEqual(c.get("/logout").status_code, 405)                              # GET logout refused
        self.assertEqual(c.get("/api/me/notice").status_code, 200)
        cookie = c.get_cookie("session") or c.get_cookie("__Host-soc")
        self.assertEqual(c.post("/logout", data={}).status_code, 400)                    # no CSRF token/header
        self.assertEqual(c.post("/logout", headers=H).status_code, 303)
        self.assertEqual(c.get("/api/me/notice").status_code, 401)
        c2 = A.app.test_client(); c2.set_cookie(cookie.key, cookie.value)                # replay the OLD cookie
        self.assertEqual(c2.get("/api/me/notice").status_code, 401, "revoked session cookie must be dead server-side")
    def test_04_session_rotates_on_login_and_idle_expiry(self):
        c = A.app.test_client(); u, p = creds(); login(c, u, p); s1 = db.q("SELECT sid_hash FROM sessions ORDER BY created DESC LIMIT 1", one=True)["sid_hash"]
        login(c, u, p); s2 = db.q("SELECT sid_hash FROM sessions ORDER BY created DESC LIMIT 1", one=True)["sid_hash"]; self.assertNotEqual(s1, s2)
        db.x("UPDATE sessions SET last_seen=?", (time.time() - 3600,)); self.assertEqual(c.get("/api/me/notice").status_code, 401)
    def test_05_password_change_ends_other_sessions_and_enforces_length(self):
        u, p = creds(); a, b = A.app.test_client(), A.app.test_client(); login(a, u, p); login(b, u, p)
        self.assertEqual(a.post("/api/me/password", json={"current": p, "new": "short"}, headers=H).status_code, 400)
        new = "N3w-long-passphrase!"; self.assertEqual(a.post("/api/me/password", json={"current": p, "new": new}, headers=H).status_code, 200)
        self.assertEqual(a.get("/api/me/notice").status_code, 200); self.assertEqual(b.get("/api/me/notice").status_code, 401)
    def test_06_deactivated_user_loses_session(self):
        a = A.app.test_client(); u = db.q("SELECT username FROM users LIMIT 1", one=True)["username"]
        db.x("INSERT INTO users(username,password_hash,role,created_at) VALUES('tmp',?,'viewer',?)", (A.generate_password_hash("a-long-password-123"), db.now()))
        c = A.app.test_client(); login(c, "tmp", "a-long-password-123"); self.assertEqual(c.get("/api/me/notice").status_code, 200)
        db.x("UPDATE users SET active=0 WHERE username='tmp'"); self.assertEqual(c.get("/api/me/notice").status_code, 401)
    def test_07_redos_patterns_rejected_and_input_bounded(self):
        import engine
        for bad in ("(a+)+$", "(a|aa)+", "(.*)*x", "a" * 201, r"(\w)\1"):
            with self.assertRaises(ValueError): engine.cr_matcher("regex", bad)
        m = engine.cr_matcher("regex", "fail(ed)? password"); t0 = time.time(); self.assertTrue(m("x" * 10 ** 6 + " failed password") is False)   # beyond the 2000-char bound
        self.assertLess(time.time() - t0, 0.5)
    def test_08_forwarded_headers_ignored_without_trusted_proxy(self):
        c = A.app.test_client(); r = c.get("/login", headers={"X-Forwarded-For": "6.6.6.6"}, environ_base={"REMOTE_ADDR": "10.0.0.9"}); self.assertEqual(r.status_code, 200)
        with A.app.test_request_context("/login", headers={"X-Forwarded-For": "6.6.6.6"}, environ_base={"REMOTE_ADDR": "10.0.0.9"}): self.assertEqual(A.request.remote_addr, "10.0.0.9")
    def _prod(self, **extra):
        import subprocess
        from security import crypto
        env = dict(os.environ, SOC_ENV="production", SOC_PORT="5999", SOC_DB=T + "/p%d.db" % time.time_ns(), SOC_LOCAL_LOGS="0", SOC_ALLOW_FOREIGN_DB="1", SOC_BACKUP_DIR=T + "/pb", SOC_SECRET=__import__("secrets").token_hex(32)); env.pop("SOC_ENC_KEYS", None); env.update(extra)      # SOC_SECRET above is valid so these tests still exercise the guards they are about (the SOC_SECRET gate has its own tests in test_pass3_security)
        return subprocess.run([sys.executable, "app.py"], cwd=ROOT, env=env, capture_output=True, text=True, timeout=60)
    def test_09_production_refuses_dev_server(self):
        from security import crypto
        r = self._prod(SOC_ENC_KEYS="k1:" + crypto.new_key()); self.assertNotEqual(r.returncode, 0); self.assertIn("development server is disabled", r.stdout + r.stderr)
    def test_10_production_without_encryption_key_fails_closed_with_clear_message(self):
        r = self._prod(); self.assertNotEqual(r.returncode, 0); self.assertIn("SOC_ENC_KEYS", r.stdout + r.stderr); self.assertNotIn("Traceback", r.stdout + r.stderr)
if __name__ == "__main__": unittest.main(verbosity=2)
