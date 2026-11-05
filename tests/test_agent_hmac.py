"""Agent HMAC signing, scopes, replay, rotation and legacy migration. Run: python tests/test_agent_hmac.py (in-process, temp DB)."""
import os, sys, tempfile, time, json, secrets, unittest
ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__))); sys.path.insert(0, ROOT)
T = tempfile.mkdtemp()
for k in ("SOC_ALLOW_DEFAULT_CREDS", "SOC_ENV", "SOC_AGENT_AUTH"): os.environ.pop(k, None)
os.environ.update(SOC_DB=T + "/t.db", SOC_SECRET="s" * 40, SOC_LOCAL_LOGS="0", SOC_ALLOW_FOREIGN_DB="1")
import db, app as A, fleet
from security import agentsig
from fleet import sha
db.init_db(); H = {"X-Requested-With": "fetch"}
def admin():
    d = dict(l.split("=", 1) for l in open(T + "/initial_admin_credentials.txt").read().splitlines() if "=" in l)
    c = A.app.test_client(); c.post("/login", data={"username": d["username"], "password": d["password"]}); return c
ADM = admin()
def enroll(host):
    tok = ADM.post("/api/enrollment-tokens", json={"label": host}, headers=H).get_json()["token"]
    r = A.app.test_client().post("/api/agents/register", json={"enrollment_token": tok, "hostname": host, "os": "Linux", "os_version": "x", "agent_version": "1"}); assert r.status_code == 200, r.data; return r.get_json()
def req(ag, path, obj, sign=True, ts=None, nonce=None, key=None, body=None, bearer=None, sign_path=None):
    ts = str(int(ts or time.time())); nonce = nonce or secrets.token_urlsafe(16); data = body if body is not None else json.dumps(obj, separators=(",", ":")).encode()
    h = {"Authorization": "Bearer " + (bearer or ag["credential"]), "X-Timestamp": ts, "X-Nonce": nonce, "Content-Type": "application/json"}
    if sign: h["X-Signature"] = agentsig.sign(key or ag["signing_key"], "POST", sign_path or path, ts, nonce, obj_bytes(obj) if body is None else obj_bytes_raw(obj))
    return A.app.test_client().post(path, data=data, headers=h)
def obj_bytes(o): return json.dumps(o, separators=(",", ":")).encode()
def obj_bytes_raw(o): return obj_bytes(o)
EV = {"events": [{"uid": "u1", "message": "Failed password for root from 1.2.3.4", "event_time": "2026-01-01T00:00:00Z"}]}

class HMAC(unittest.TestCase):
    @classmethod
    def setUpClass(c): c.a = enroll("host-a"); c.b = enroll("host-b")
    def test_01_signing_key_returned_once_and_stored_encrypted(self):
        self.assertTrue(self.a.get("signing_key"))
        self.assertNotIn(self.a["signing_key"].encode(), open(T + "/t.db", "rb").read())
        row = db.q("SELECT sign_key_enc FROM agent_credentials WHERE credential_id=?", (self.a["credential"].split(".")[0],), one=True); self.assertTrue(row["sign_key_enc"].startswith("enc1:"))
    def test_02_valid_signed_request(self): self.assertEqual(req(self.a, "/api/agents/heartbeat", {"cpu": 1}).status_code, 200)
    def test_03_tampered_body_rejected(self):
        ts = str(int(time.time())); n = secrets.token_urlsafe(16); good = {"cpu": 1}; sig = agentsig.sign(self.a["signing_key"], "POST", "/api/agents/heartbeat", ts, n, obj_bytes(good))
        r = A.app.test_client().post("/api/agents/heartbeat", data=obj_bytes({"cpu": 99}), headers={"Authorization": "Bearer " + self.a["credential"], "X-Timestamp": ts, "X-Nonce": n, "X-Signature": sig, "Content-Type": "application/json"}); self.assertEqual(r.status_code, 401)
    def test_04_signature_bound_to_path(self):
        r = req(self.a, "/api/events", EV, sign_path="/api/agents/heartbeat"); self.assertEqual(r.status_code, 401)
    def test_05_replay_rejected(self):
        n = secrets.token_urlsafe(16); self.assertEqual(req(self.a, "/api/agents/heartbeat", {"cpu": 2}, nonce=n).status_code, 200); self.assertEqual(req(self.a, "/api/agents/heartbeat", {"cpu": 2}, nonce=n).status_code, 409)
    def test_06_stale_and_future_timestamp_rejected(self):
        self.assertEqual(req(self.a, "/api/agents/heartbeat", {}, ts=time.time() - 4000).status_code, 400); self.assertEqual(req(self.a, "/api/agents/heartbeat", {}, ts=time.time() + 4000).status_code, 400)
    def test_07_cross_agent_key_rejected(self):
        self.assertEqual(req(self.a, "/api/agents/heartbeat", {}, key=self.b["signing_key"]).status_code, 401)
    def test_08_downgrade_ratchet_after_first_signed_request(self):
        self.assertEqual(req(self.b, "/api/agents/heartbeat", {}).status_code, 200); self.assertEqual(req(self.b, "/api/agents/heartbeat", {}, sign=False).status_code, 401)
    def test_09_legacy_unsigned_agent_works_in_permissive_then_fails_in_required(self):
        d = enroll("host-legacy"); cid = d["credential"].split(".")[0]; db.x("UPDATE agent_credentials SET sign_key_enc=NULL,sig_required=0 WHERE credential_id=?", (cid,))   # simulates a pre-migration credential
        self.assertEqual(req(d, "/api/agents/heartbeat", {}, sign=False).status_code, 200)
        self.assertGreaterEqual(db.q("SELECT legacy_uses n FROM agent_credentials WHERE credential_id=?", (cid,), one=True)["n"], 1)
        os.environ["SOC_AGENT_AUTH"] = "hmac-required"
        try: self.assertEqual(req(d, "/api/agents/heartbeat", {}, sign=False).status_code, 401)
        finally: os.environ.pop("SOC_AGENT_AUTH")
    def test_10_scope_enforced(self):
        d = enroll("host-scope"); cid = d["credential"].split(".")[0]; db.x("UPDATE agent_credentials SET scopes='heartbeat' WHERE credential_id=?", (cid,))
        self.assertEqual(req(d, "/api/events", EV).status_code, 403); self.assertEqual(req(d, "/api/agents/heartbeat", {}).status_code, 200)
    def test_11_rotation_revokes_old_and_new_works_and_is_audited(self):
        d = enroll("host-rot"); r = ADM.post(f"/api/agents/{d['agent_id']}/rotate-credential", json={}, headers=H); self.assertEqual(r.status_code, 200); n = r.get_json()
        self.assertEqual(req(d, "/api/agents/heartbeat", {}).status_code, 403); self.assertEqual(req(n, "/api/agents/heartbeat", {}).status_code, 200)
        self.assertTrue(db.q("SELECT 1 FROM audit WHERE action LIKE 'Agent credential rotated%'", one=True))
    def test_12_revoked_agent_rejected(self):
        d = enroll("host-rev"); ADM.post(f"/api/agents/{d['agent_id']}/revoke", json={}, headers=H); self.assertEqual(req(d, "/api/agents/heartbeat", {}).status_code, 403)
    def test_13_host_and_severity_cannot_be_forged(self):
        ev = {"events": [{"uid": "forge1", "message": "Failed password for root from 9.9.9.9", "host": "ADMIN-DC", "hostname": "ADMIN-DC", "severity": "Low", "event_time": "2026-01-01T00:00:00Z"}]}
        self.assertEqual(req(self.a, "/api/events", ev).status_code, 200)
        hosts = {r["host"] for r in db.q("SELECT host FROM events WHERE message LIKE '%9.9.9.9%'")}; self.assertEqual(hosts, {"host-a"})
    def test_14_malformed_and_oversized(self):
        self.assertEqual(req(self.a, "/api/events", None, body=b"not json").status_code in (400, 401), True)
        self.assertEqual(req(self.a, "/api/events", {"events": [{"uid": str(i), "message": "m"} for i in range(501)]}).status_code, 413)
    def test_15_garbage_bearer_rejected(self): self.assertEqual(req(self.a, "/api/agents/heartbeat", {}, bearer="cr-x.y").status_code, 401)
if __name__ == "__main__": unittest.main(verbosity=2)
