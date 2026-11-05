"""Login origin guard + admin recovery CLI. Temp DB only. Run: python tests/test_login_origin.py"""
import os, sys, tempfile, unittest, io, contextlib
ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__))); sys.path.insert(0, ROOT)
T = tempfile.mkdtemp()
for k in ("SOC_ALLOW_DEFAULT_CREDS", "SOC_ENV", "SOC_MFA_REQUIRED", "SOC_TRUSTED_PROXIES"): os.environ.pop(k, None)
os.environ.update(SOC_DB=T + "/t.db", SOC_SECRET="s" * 40, SOC_LOCAL_LOGS="0", SOC_ALLOW_FOREIGN_DB="1")
import db, app as A
db.init_db(); PW = "a-long-test-password-1"; BASE = "http://127.0.0.1:5000"
def mk(n, role): db.x("INSERT INTO users(username,password_hash,role,created_at) VALUES(?,?,?,?)", (n, A.generate_password_hash(PW), role, db.now()))
mk("ana", "analyst"); mk("vic", "viewer")
def post(c, h=None, user="ana", pw=PW): return c.post("/login", data={"username": user, "password": pw}, headers=h or {}, base_url=BASE)
def cli(*args):
    old = sys.argv; sys.argv = ["app.py", "--set-login", *args]; buf = io.StringIO()
    try:
        with contextlib.redirect_stdout(buf): A.set_login()
    finally: sys.argv = old
    return buf.getvalue()
def users(): return {r["username"]: (r["role"], r["password_hash"], r["active"]) for r in db.q("SELECT username,role,password_hash,active FROM users")}

class T(unittest.TestCase):
    def test_01_same_origin_origin_header_ok(self):
        r = post(A.app.test_client(), {"Origin": BASE}); self.assertEqual(r.status_code, 302); self.assertNotEqual(r.headers["Location"], "/login")
    def test_02_no_referrer_browser_sends_null_but_sec_fetch_same_origin_ok(self):
        r = post(A.app.test_client(), {"Origin": "null", "Sec-Fetch-Site": "same-origin"}); self.assertEqual(r.status_code, 302)
    def test_03_untrusted_origins_refused(self):
        for h in ({"Origin": "https://evil.example"}, {"Origin": "http://127.0.0.1:5001"}, {"Origin": "https://127.0.0.1:5000"}, {"Origin": "http://127.0.0.1.evil.example:5000"},
                  {"Origin": "http://localhost:5000"}, {"Origin": "null"}, {"Origin": "null", "Sec-Fetch-Site": "cross-site"}, {"Origin": BASE, "Sec-Fetch-Site": "cross-site"},
                  {"Origin": BASE, "Sec-Fetch-Site": "same-site"}, {"Origin": "http://user@127.0.0.1:5000"}, {"Origin": "garbage"}, {"Origin": "http://127.0.0.1:99999"}):
            self.assertEqual(post(A.app.test_client(), h).status_code, 403, h)
    def test_04_missing_origin_policy(self):
        self.assertEqual(post(A.app.test_client()).status_code, 302)                                   # non-browser client (no Sec-Fetch-Site)
        self.assertEqual(post(A.app.test_client(), {"Sec-Fetch-Site": "cross-site"}).status_code, 403)
    def test_05_bad_credentials_still_rejected(self):
        r = post(A.app.test_client(), {"Origin": BASE}, pw="wrong-password-123"); self.assertEqual(r.status_code, 200); self.assertIn(b"nvalid", r.data)
    def test_06_header_and_guard_enabled(self):
        r = A.app.test_client().get("/login", base_url=BASE); self.assertEqual(r.headers["Referrer-Policy"], "same-origin")
        self.assertTrue(any(f.__name__ == "_origin_guard" for f in A.app.before_request_funcs[None]))
    def test_07_session_and_logout(self):
        c = A.app.test_client(); post(c, {"Origin": BASE})
        self.assertEqual(c.get("/api/alerts", base_url=BASE, headers={"X-Requested-With": "fetch"}).status_code, 200)
        c.get("/logout", base_url=BASE); c.post("/logout", base_url=BASE, headers={"X-Requested-With": "fetch"})
        self.assertEqual(c.get("/api/alerts", base_url=BASE, headers={"X-Requested-With": "fetch"}).status_code, 401)
    def test_08_cli_rejects_bad_input_and_changes_nothing(self):
        before = users(); admin = [u for u, v in before.items() if v[0] == "admin"][0]
        for a in (("--user", admin, "--new-user", "bad@name"), ("--user", admin, "--password", "short1!"), ("--user", "nobody", "--password", PW + "x")):
            out = cli(*a); self.assertNotIn(PW, out); self.assertEqual(users(), before, a)
    def test_09_cli_valid_reset_updates_only_target(self):
        before = users(); admin = [u for u, v in before.items() if v[0] == "admin"][0]; new = "New-Admin-Passphrase-77"
        out = cli("--user", admin, "--password", new); self.assertIn("Done", out); self.assertNotIn(new, out)
        after = users(); self.assertEqual({k: v for k, v in after.items() if k != admin}, {k: v for k, v in before.items() if k != admin})
        self.assertEqual(after[admin][0], "admin"); self.assertNotEqual(after[admin][1], before[admin][1]); self.assertNotIn(new, after[admin][1])
        c = A.app.test_client(); self.assertEqual(post(c, {"Origin": BASE}, user=admin, pw=new).status_code, 302)
        self.assertEqual(post(A.app.test_client(), {"Origin": BASE}, user=admin, pw="wrong-password-123").status_code, 200)
    def test_10_cli_without_admin_stops(self):
        db.x("UPDATE users SET role='viewer' WHERE role='admin'"); n = len(users())
        self.assertIn("No admin", cli("--password", PW + "zz")); self.assertEqual(len(users()), n)
if __name__ == "__main__": unittest.main(verbosity=1)
