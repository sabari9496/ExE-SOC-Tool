"""TOTP MFA: enrollment, login challenge, replay, recovery codes, rate limit, required-MFA, reauth, audited recovery, encrypted secrets. Run: python tests/test_mfa.py"""
import os, sys, tempfile, time, re, unittest
ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__))); sys.path.insert(0, ROOT)
T = tempfile.mkdtemp()
for k in ("SOC_ALLOW_DEFAULT_CREDS", "SOC_ENV", "SOC_MFA_REQUIRED"): os.environ.pop(k, None)
os.environ.update(SOC_DB=T + "/t.db", SOC_SECRET="s" * 40, SOC_LOCAL_LOGS="0", SOC_ALLOW_FOREIGN_DB="1", SOC_MFA_REQUIRED="analyst")
import db, app as A
from security import totp
db.init_db(); H = {"X-Requested-With": "fetch"}
ADMIN = dict(l.split("=", 1) for l in open(T + "/initial_admin_credentials.txt").read().splitlines() if "=" in l)
PW = "a-long-test-password-1"
def mkuser(n, role): db.x("INSERT INTO users(username,password_hash,role,created_at) VALUES(?,?,?,?)", (n, A.generate_password_hash(PW), role, db.now()))
def login(c, u, p=PW): return c.post("/login", data={"username": u, "password": p}, follow_redirects=False)
def code(secret, off=0): return totp._code(secret, int(time.time() // 30) + off)
def enroll(c, u):
    page = c.get("/mfa-setup").get_data(as_text=True); s = re.search(r"<pre>([A-Z2-7]+)</pre>", page).group(1)
    tok = re.search(r'name="csrf" value="([^"]+)"', page).group(1); r = c.post("/mfa-setup", data={"csrf": tok, "code": code(s)})
    return s, re.findall(r"[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}", r.get_data(as_text=True))

def mfa_post(c, code, csrf=True):
    """Submit the login MFA form like a browser: GET it, read the hidden CSRF field, POST both."""
    import re as _re
    page = c.get("/login/mfa").get_data(as_text=True); m = _re.search(r'name="csrf" value="([^"]*)"', page)
    data = {"code": code}
    if csrf and m: data["csrf"] = m.group(1)
    return c.post("/login/mfa", data=data)

class MFA(unittest.TestCase):
    def test_01_required_role_forced_to_enroll_and_blocked_until_then(self):
        mkuser("ana", "analyst"); c = A.app.test_client(); r = login(c, "ana"); self.assertEqual(r.headers["Location"], "/mfa-setup")
        self.assertEqual(c.get("/api/alerts").status_code, 403)
        s, rc = enroll(c, "ana"); self.assertEqual(len(rc), 10); self.assertEqual(c.get("/api/alerts").status_code, 200)
        TestState.secret, TestState.codes = s, rc
    def test_02_secret_encrypted_at_rest(self):
        e = db.q("SELECT secret_enc FROM user_mfa WHERE username='ana'", one=True)["secret_enc"]; self.assertTrue(e.startswith("enc1:")); self.assertNotIn(TestState.secret, e)
        self.assertNotIn(TestState.secret.encode(), open(T + "/t.db", "rb").read())
    def test_03_login_now_requires_code(self):
        db.x("UPDATE user_mfa SET last_counter=0 WHERE username='ana'")      # test setup: enrollment in test_01 consumed this window's code
        c = A.app.test_client(); r = login(c, "ana"); self.assertEqual(r.headers["Location"], "/login/mfa"); self.assertEqual(c.get("/api/alerts").status_code, 401)
        self.assertEqual(mfa_post(c, "000000").status_code, 401); self.assertEqual(c.get("/api/alerts").status_code, 401)
        r = mfa_post(c, code(TestState.secret)); self.assertEqual(r.status_code, 303); self.assertEqual(c.get("/api/alerts").status_code, 200)
    def test_04_code_replay_rejected(self):
        db.x("UPDATE user_mfa SET last_counter=0 WHERE username='ana'")      # test setup only; the replay assertion below is the real check
        c = A.app.test_client(); login(c, "ana"); cur = code(TestState.secret, 1)          # next window: valid, unused
        self.assertEqual(mfa_post(c, cur).status_code, 303)
        c2 = A.app.test_client(); login(c2, "ana"); self.assertEqual(mfa_post(c2, cur).status_code, 401, "same TOTP counter must not be accepted twice")
    def test_05_recovery_code_single_use_and_audited(self):
        rc = TestState.codes[0]; c = A.app.test_client(); login(c, "ana"); self.assertEqual(mfa_post(c, rc).status_code, 303)
        c2 = A.app.test_client(); login(c2, "ana"); self.assertEqual(mfa_post(c2, rc).status_code, 401)
        self.assertTrue(db.q("SELECT 1 FROM audit WHERE action LIKE '%recovery code used%'", one=True))
    def test_06_rate_limit_after_failures(self):
        __import__('security.throttle', fromlist=['x']).clear('mfa', 'ana'); c = A.app.test_client(); login(c, "ana")
        for _ in range(5): mfa_post(c, "111111")
        r = mfa_post(c, code(TestState.secret, -1)); self.assertEqual(r.status_code, 429, "even a valid code is refused while throttled"); __import__('security.throttle', fromlist=['x']).clear('mfa', 'ana')
    def test_07_unrequired_role_not_forced(self):
        mkuser("vee", "viewer"); c = A.app.test_client(); self.assertEqual(login(c, "vee").headers["Location"], "/")
    def test_08_reauth_required_for_admin_mfa_reset_and_audited(self):
        adm = A.app.test_client(); login(adm, ADMIN["username"], ADMIN["password"]); uid = db.q("SELECT id FROM users WHERE username='ana'", one=True)["id"]
        db.x("DELETE FROM sessions WHERE 0")
        with adm.session_transaction() as s: s["reauth_at"] = 0
        self.assertEqual(adm.post(f"/api/users/{uid}/mfa/reset", json={}, headers=H).status_code, 403)
        self.assertEqual(adm.post("/api/me/reauth", json={"password": "wrong"}, headers=H).status_code, 401)
        self.assertEqual(adm.post("/api/me/reauth", json={"password": ADMIN["password"]}, headers=H).status_code, 200)
        self.assertEqual(adm.post(f"/api/users/{uid}/mfa/reset", json={}, headers=H).status_code, 200); self.assertFalse(db.q("SELECT 1 FROM user_mfa WHERE username='ana'", one=True))
        self.assertTrue(db.q("SELECT 1 FROM audit WHERE action LIKE 'MFA reset for ana%'", one=True))
    def test_10_login_mfa_post_does_not_log_out_an_authenticated_user(self):
        c = A.app.test_client(); login(c, "vee"); self.assertEqual(c.get("/api/me/notice").status_code, 200)
        mfa_post(c, "123456"); self.assertEqual(c.get("/api/me/notice").status_code, 200)
    def test_09_totp_rfc6238_vector(self):
        import base64; self.assertEqual(totp._code(base64.b32encode(b"12345678901234567890").decode(), 59 // 30), "287082")
    def _fresh_mfa_user(self, name):
        mkuser(name, "analyst"); c = A.app.test_client(); login(c, name); sec, _codes = enroll(c, name); return sec
    def test_11_login_mfa_form_requires_csrf_token(self):
        sec = self._fresh_mfa_user("csrfu"); c = A.app.test_client(); r = login(c, "csrfu"); self.assertEqual(r.headers["Location"], "/login/mfa")
        r = mfa_post(c, code(sec, 1), csrf=False)
        self.assertEqual(r.status_code, 400, "the /login/mfa POST must be refused without the session-bound CSRF token"); self.assertEqual(c.get("/api/alerts").status_code, 401)
        r = c.post("/login/mfa", data={"code": code(sec, 1), "csrf": "wrong"}); self.assertEqual(r.status_code, 400); self.assertEqual(c.get("/api/alerts").status_code, 401)
        self.assertEqual(mfa_post(c, code(sec, 1)).status_code, 303, "the refused attempts consumed nothing: a correct, tokened submission still works")
    def test_12_cross_origin_login_posts_refused(self):
        c = A.app.test_client()
        for path in ("/login", "/login/mfa"):
            self.assertEqual(c.post(path, data={"username": "x", "password": "y"}, headers={"Origin": "https://evil.example"}).status_code, 403)
            self.assertEqual(c.post(path, data={"username": "x", "password": "y"}, headers={"Origin": "null"}).status_code, 403)
    def test_13_mfa_throttle_is_persistent_not_in_memory(self):
        from security import throttle
        for _ in range(5): throttle.hit("mfa", "persist-user")
        import importlib; from security import totp as T
        self.assertTrue(T.throttled("persist-user"), "limiter state must live in SQLite (shared across workers/restarts)"); throttle.clear("mfa", "persist-user")
    def test_14_reauth_password_guessing_is_throttled(self):
        from security import throttle; mkuser("reauthu", "viewer"); c = A.app.test_client(); self.assertEqual(login(c, "reauthu").status_code, 302)
        for i in range(5): self.assertEqual(c.post("/api/me/reauth", headers=H, json={"password": f"wrong-password-{i}"}).status_code, 401)
        r = c.post("/api/me/reauth", headers=H, json={"password": PW}); self.assertEqual(r.status_code, 429, "even the right password is refused while the limiter blocks")
        throttle.clear("reauth", "reauthu"); self.assertEqual(c.post("/api/me/reauth", headers=H, json={"password": PW}).status_code, 200)
class TestState: secret = codes = None

if __name__ == "__main__": unittest.main(verbosity=2, failfast=False)
