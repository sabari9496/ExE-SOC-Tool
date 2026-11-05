"""Field encryption + key rotation, audit chain tamper evidence, encrypted backups + restore drill, secure purge, legacy ingest-key controls. Run: python tests/test_data_protection.py"""
import os, sys, tempfile, time, json, sqlite3, subprocess, unittest, glob
ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__))); sys.path.insert(0, ROOT)
T = tempfile.mkdtemp()
for k in ("SOC_ALLOW_DEFAULT_CREDS", "SOC_ENV", "SOC_LEGACY_API_KEY", "SOC_ENC_KEYS"): os.environ.pop(k, None)
os.environ.update(SOC_DB=T + "/t.db", SOC_SECRET="s" * 40, SOC_LOCAL_LOGS="0", SOC_ALLOW_FOREIGN_DB="1", SOC_BACKUP_DIR=T + "/bk")
import db, app as A, engine
from security import crypto, auditchain, backup as bk
db.init_db(); H = {"X-Requested-With": "fetch"}
ADMIN = dict(l.split("=", 1) for l in open(T + "/initial_admin_credentials.txt").read().splitlines() if "=" in l)
def adm():
    c = A.app.test_client(); c.post("/login", data={"username": ADMIN["username"], "password": ADMIN["password"]}); return c
def audit_conn(): return db.conn()
class Crypto(unittest.TestCase):
    def test_01_roundtrip_context_binding_and_tamper(self):
        t = crypto.encrypt("secret-value", "ctx|a"); self.assertEqual(crypto.decrypt(t, "ctx|a"), "secret-value")
        with self.assertRaises(crypto.CryptoError): crypto.decrypt(t, "ctx|b")
        bad = t[:-3] + ("AAA" if not t.endswith("AAA") else "BBB")
        with self.assertRaises(crypto.CryptoError): crypto.decrypt(bad, "ctx|a")
    def test_02_ingest_key_encrypted_at_rest_but_works(self):
        raw = sqlite3.connect(T + "/t.db").execute("SELECT value FROM settings WHERE key='api_key'").fetchone()[0]; self.assertTrue(raw.startswith("enc1:"))
        k = db.setting("api_key"); self.assertEqual(len(k), 48); self.assertNotIn(k, raw)
        r = A.app.test_client().post("/api/ingest", headers={"X-API-Key": k}, json={"events": []}); self.assertNotEqual(r.status_code, 401)
        self.assertEqual(A.app.test_client().post("/api/ingest", headers={"X-API-Key": "wrong"}, json={}).status_code, 401)
    def test_03_key_rotation_reencrypts_and_old_values_still_readable_until_rotated(self):
        old_primary = crypto.primary_kid(); before = sqlite3.connect(T + "/t.db").execute("SELECT value FROM settings WHERE key='api_key'").fetchone()[0]; k = db.setting("api_key")
        out = T + "/newring.env"; subprocess.check_call([sys.executable, ROOT + "/tools/rotate_secrets.py", "enc-key", "--out", out], env=dict(os.environ), stdout=subprocess.DEVNULL)
        self.assertEqual(oct(os.stat(out).st_mode & 0o777), "0o600"); ring = open(out).read().split("=", 1)[1].strip()
        os.environ["SOC_ENC_KEYS"] = ring; crypto.reset_ring(); self.assertNotEqual(crypto.primary_kid(), old_primary)
        self.assertEqual(db.setting("api_key"), k, "old ciphertext must still decrypt with the old key kept in the ring")
        subprocess.check_call([sys.executable, ROOT + "/tools/rotate_secrets.py", "reencrypt"], env=dict(os.environ), stdout=subprocess.DEVNULL)
        after = sqlite3.connect(T + "/t.db").execute("SELECT value FROM settings WHERE key='api_key'").fetchone()[0]; self.assertNotEqual(before, after); self.assertIn(":" + crypto.primary_kid() + ":", after[:12]); self.assertEqual(db.setting("api_key"), k)
        db.audit_add("t", "after key rotation"); c = audit_conn(); self.assertTrue(auditchain.verify(c)["ok"], "audit chain must survive encryption-key rotation"); c.close()
    def test_04_missing_key_fails_closed(self):
        saved = os.environ.get("SOC_ENC_KEYS"); os.environ["SOC_ENC_KEYS"] = "zz:" + crypto.new_key(); crypto.reset_ring()
        try: self.assertIsNone(db.setting("api_key")); self.assertEqual(A.app.test_client().post("/api/ingest", headers={"X-API-Key": ""}, json={}).status_code, 401)
        finally: (os.environ.__setitem__("SOC_ENC_KEYS", saved) if saved else os.environ.pop("SOC_ENC_KEYS", None)); crypto.reset_ring()
    def test_05_legacy_key_kill_switch(self):
        k = db.setting("api_key"); os.environ["SOC_LEGACY_API_KEY"] = "off"
        try: self.assertEqual(A.app.test_client().post("/api/ingest", headers={"X-API-Key": k}, json={"events": []}).status_code, 401)
        finally: os.environ.pop("SOC_LEGACY_API_KEY")
class Chain(unittest.TestCase):
    def setUp(self): [db.audit_add("t", f"event {i}") for i in range(5)]
    def test_01_verifies_clean(self): c = audit_conn(); v = auditchain.verify(c); c.close(); self.assertTrue(v["ok"], v)
    def test_02_edit_detected(self):
        i = db.q("SELECT id FROM audit ORDER BY id DESC LIMIT 1 OFFSET 2", one=True)["id"]; orig = db.q("SELECT action FROM audit WHERE id=?", (i,), one=True)["action"]
        db.x("UPDATE audit SET action='tampered' WHERE id=?", (i,)); c = audit_conn(); v = auditchain.verify(c); c.close(); self.assertFalse(v["ok"]); self.assertEqual(v["first_bad"], i)
        db.x("UPDATE audit SET action=? WHERE id=?", (orig, i))
    def test_03_delete_detected(self):
        i = db.q("SELECT id FROM audit ORDER BY id DESC LIMIT 1 OFFSET 1", one=True)["id"]; row = db.q("SELECT * FROM audit WHERE id=?", (i,), one=True)
        db.x("DELETE FROM audit WHERE id=?", (i,)); c = audit_conn(); v = auditchain.verify(c); c.close(); self.assertFalse(v["ok"])
        db.x("INSERT INTO audit(id,ts,user,action) VALUES(?,?,?,?)", (row["id"], row["ts"], row["user"], row["action"]))
    def test_04_injected_row_detected(self):
        i = db.x("INSERT INTO audit(ts,user,action) VALUES(?,?,?)", (db.now(), "attacker", "forged entry")); c = audit_conn(); v = auditchain.verify(c); c.close(); self.assertFalse(v["ok"])
        db.x("DELETE FROM audit WHERE id=?", (i,))
    def test_05_checkpoint_detects_truncation_and_history_rewrite(self):
        c = audit_conn(); rec = auditchain.checkpoint(c, T + "/ckpt"); self.assertTrue(auditchain.verify_checkpoint(rec, c)[0]); c.close()
        saved_chain = db.q("SELECT * FROM audit_chain")
        # attacker with DB write access but WITHOUT the key rewrites the tail with a fresh (wrong-MAC) chain
        db.x("DELETE FROM audit_chain WHERE audit_id>(SELECT MAX(audit_id)-2 FROM audit_chain)"); c = audit_conn(); ok, msg = auditchain.verify_checkpoint(rec, c); c.close(); self.assertFalse(ok, msg)
        forged = dict(rec, head="f" * 64); c = audit_conn(); self.assertFalse(auditchain.verify_checkpoint(forged, c)[0]); c.close()
        for r in saved_chain: db.x("INSERT OR REPLACE INTO audit_chain(audit_id,prev,mac) VALUES(?,?,?)", (r["audit_id"], r["prev"], r["mac"]))      # test hygiene: restore the chain
    def test_06_verify_endpoint_admin_only(self):
        self.assertEqual(A.app.test_client().get("/api/audit/verify").status_code, 401)
class Backup(unittest.TestCase):
    def test_01_create_verify_restore_drill_and_permissions(self):
        p = bk.create(db.DB, T + "/bk"); self.assertEqual(oct(os.stat(p).st_mode & 0o777), "0o600"); self.assertNotIn(b"SQLite format", open(p, "rb").read()[:100])
        self.assertTrue(bk.verify(p)["ok"]); t = tempfile.mkdtemp(); out = bk.restore(p, t + "/r.db"); c = sqlite3.connect(out); self.assertGreaterEqual(c.execute("SELECT COUNT(*) FROM users").fetchone()[0], 1); self.assertEqual(c.execute("PRAGMA integrity_check").fetchone()[0], "ok"); c.close()
        with self.assertRaises(bk.BackupError): bk.restore(p, t + "/r.db")                      # never overwrite
    def test_02_tamper_and_wrong_key_detected(self):
        p = bk.create(db.DB, T + "/bk"); s = open(p).read(); open(p, "w").write(s[:-4] + ("AAAA" if not s.endswith("AAAA") else "BBBB"))
        with self.assertRaises(bk.BackupError): bk.verify(p)
        p2 = bk.create(db.DB, T + "/bk"); saved = os.environ.get("SOC_ENC_KEYS"); ring_file = os.path.join(os.path.dirname(os.path.abspath(db.DB)), ".soc_enc_key"); os.environ["SOC_ENC_KEYS"] = "zz:" + crypto.new_key(); crypto.reset_ring()
        try:
            with self.assertRaises(bk.BackupError): bk.verify(p2)
        finally:
            (os.environ.__setitem__("SOC_ENC_KEYS", saved) if saved else os.environ.pop("SOC_ENC_KEYS", None)); crypto.reset_ring()
    def test_03_rotation_keeps_newest_and_never_deletes_last_good(self):
        d = T + "/rot"; ps = []
        for _ in range(4): ps.append(bk.create(db.DB, d)); time.sleep(1.05)
        self.assertEqual(len(bk.rotate(d, 2)), 2); self.assertEqual(len(glob.glob(d + "/soc-*.db.enc")), 2)
        for f in glob.glob(d + "/soc-*.db.enc"): open(f, "w").write("garbage")
        with self.assertRaises(bk.BackupError): bk.rotate(d, 1)
class Purge(unittest.TestCase):
    def setUp(self):
        db.x("INSERT INTO endpoints(hostname) VALUES('p-host')") if False else None
        db.x("INSERT INTO events(ts,host,message) VALUES(?,?,?)", (db.now(), "p", "purge-me"))
        self.c = adm()
    def n(self): return db.q("SELECT COUNT(*) n FROM events", one=True)["n"]
    def test_01_refused_without_confirmation_or_reauth_and_nothing_deleted(self):
        n = self.n()
        self.assertEqual(self.c.post("/api/admin/purge", json={}, headers=H).status_code, 400)
        with self.c.session_transaction() as s: s["reauth_at"] = 0
        r = self.c.post("/api/admin/purge", json={"confirm": "PURGE ALL ALERTS AND EVENTS"}, headers=H); self.assertEqual(r.status_code, 403); self.assertEqual(self.n(), n)
        self.assertEqual(A.app.test_client().post("/api/admin/purge", json={"confirm": "PURGE ALL ALERTS AND EVENTS"}, headers=H).status_code, 401)
        self.assertTrue(db.q("SELECT 1 FROM audit WHERE action LIKE 'Purge REFUSED%'", one=True))
    def test_02_fails_closed_when_backup_fails(self):
        n = self.n(); saved = os.environ["SOC_BACKUP_DIR"]; open(T + "/notadir", "w").write("x"); os.environ["SOC_BACKUP_DIR"] = T + "/notadir/sub"
        try: r = self.c.post("/api/admin/purge", json={"confirm": "PURGE ALL ALERTS AND EVENTS"}, headers=H); self.assertEqual(r.status_code, 500); self.assertEqual(self.n(), n)
        finally: os.environ["SOC_BACKUP_DIR"] = saved
    def test_03_production_requires_mfa(self):
        os.environ["SOC_ENV"] = "production"
        try: r = self.c.post("/api/admin/purge", json={"confirm": "PURGE ALL ALERTS AND EVENTS"}, headers=H); self.assertEqual(r.status_code, 403); self.assertIn("MFA", r.get_json()["error"])
        finally: os.environ.pop("SOC_ENV")
    def test_04_success_makes_verified_backup_audits_and_reauth_is_single_use(self):
        r = self.c.post("/api/admin/purge", json={"confirm": "PURGE ALL ALERTS AND EVENTS"}, headers=H); self.assertEqual(r.status_code, 200, r.data); self.assertEqual(self.n(), 0)
        b = os.path.join(T, "bk", r.get_json()["backup"]); self.assertTrue(bk.verify(b)["ok"])
        t = tempfile.mkdtemp(); out = bk.restore(b, t + "/x.db"); self.assertGreaterEqual(sqlite3.connect(out).execute("SELECT COUNT(*) FROM events").fetchone()[0], 1, "restored backup must contain the pre-purge data")
        self.assertTrue(db.q("SELECT 1 FROM audit WHERE action LIKE 'All alerts and events purged; verified backup%'", one=True))
        self.assertEqual(self.c.post("/api/admin/purge", json={"confirm": "PURGE ALL ALERTS AND EVENTS"}, headers=H).status_code, 403, "second purge needs a fresh reauthentication")
if __name__ == "__main__": unittest.main(verbosity=2)
