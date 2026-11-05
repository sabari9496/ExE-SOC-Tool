#!/usr/bin/env python3
"""Operational drills executed for real against a scratch database with synthetic data: credential rotation (old rejected, new accepted, nothing printed, 0600 output, audited),
encrypted backup create/verify/tamper/restore/drill. Never touches a real SOC database. Run: python tests/test_ops_drills.py"""
import os, sys, re, json, stat, secrets, tempfile, subprocess, unittest
ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__))); T = tempfile.mkdtemp(); os.chmod(T, 0o700)
PY = sys.executable
RING = T + "/ring.env"
ENV = {k: v for k, v in os.environ.items() if not k.startswith("SOC_")}
ENV.update(SOC_DB=T + "/d.db", SOC_SECRET=secrets.token_hex(32), SOC_LOCAL_LOGS="0", SOC_ALLOW_FOREIGN_DB="1", SOC_LEGACY_API_KEY="on", SOC_BACKUP_DIR=T + "/bk")
def run(args, env=None, code=None):
    return subprocess.run([PY, "-W", "ignore"] + args if code is None else [PY, "-W", "ignore", "-c", f"import sys;sys.path.insert(0,{ROOT!r});" + code], env=env or ENV, capture_output=True, text=True, timeout=180, cwd=ROOT)
class Drills(unittest.TestCase):
    @classmethod
    def setUpClass(c):
        r = run(["tools/rotate_secrets.py", "enc-key", "--out", RING]); assert r.returncode == 0, r.stderr
        ENV["SOC_ENC_KEYS"] = open(RING).read().strip().split("=", 1)[1]
        r = run([], code="import db;db.init_db()"); assert r.returncode == 0, r.stderr
    def test_01_enc_key_generation_is_silent_and_0600(self):
        r = run(["tools/rotate_secrets.py", "enc-key", "--out", T + "/ring2.env"]); self.assertEqual(r.returncode, 0)
        self.assertEqual(stat.S_IMODE(os.stat(T + "/ring2.env").st_mode), 0o600); key = open(T + "/ring2.env").read().split("=", 1)[1].split(",")[0].split(":", 1)[1].strip()
        self.assertNotIn(key, r.stdout + r.stderr, "the new key must never be printed")
    def test_02_ingest_key_rotation_old_rejected_new_accepted_audited(self):
        probe = ("import os,json,db,app as A;db.init_db();c=A.app.test_client();k=os.environ['PROBE_KEY'];"
                 "r=c.post('/api/ingest',headers={'X-API-Key':k},json=[{'message':'drill','host':'drillhost'}]);print(r.status_code)")
        old = run([], code="import db;from security import crypto;print(crypto.decrypt(db.q(\"SELECT value FROM settings WHERE key='api_key'\",one=True)['value'],'setting|api_key'))").stdout.strip()
        self.assertTrue(old); e = dict(ENV, PROBE_KEY=old); self.assertEqual(run([], env=e, code=probe).stdout.strip().splitlines()[-1], "200", "the current key works before rotation")
        out = T + "/ingest.env"; r = run(["tools/rotate_secrets.py", "ingest-key", "--out", out]); self.assertEqual(r.returncode, 0, r.stderr)
        new = open(out).read().strip().split("=", 1)[1]; self.assertNotIn(new, r.stdout + r.stderr); self.assertNotIn(old, r.stdout + r.stderr); self.assertEqual(stat.S_IMODE(os.stat(out).st_mode), 0o600)
        self.assertEqual(run([], env=dict(ENV, PROBE_KEY=old), code=probe).stdout.strip().splitlines()[-1], "401", "the OLD key must be rejected")
        self.assertEqual(run([], env=dict(ENV, PROBE_KEY=new), code=probe).stdout.strip().splitlines()[-1], "200", "the NEW key must work")
        a = run([], code="import db;print([r['action'] for r in db.q(\"SELECT action FROM audit WHERE action LIKE '%ingest API key rotated%'\")])").stdout
        self.assertIn("rotated", a); self.assertNotIn(new, a); self.assertNotIn(old, a)
    def test_03_session_secret_rotation_invalidates_existing_cookies(self):
        login = ("import db,app as A;db.init_db();d=dict(l.split('=',1) for l in open(os.path.dirname(os.environ['SOC_DB'])+'/initial_admin_credentials.txt').read().splitlines() if '=' in l);"
                 "c=A.app.test_client();c.post('/login',data={'username':d['username'],'password':d['password']});ck=c.get_cookie(A.app.config['SESSION_COOKIE_NAME']);print(ck.value)")
        creds = T + "/initial_admin_credentials.txt"; self.assertTrue(os.path.exists(creds))
        cookie = run([], code="import os;" + login).stdout.strip().splitlines()[-1]
        use = ("import os,db,app as A;c=A.app.test_client();c.set_cookie(A.app.config['SESSION_COOKIE_NAME'],os.environ['PROBE_COOKIE']);print(c.get('/api/me/notice').status_code)")
        self.assertEqual(run([], env=dict(ENV, PROBE_COOKIE=cookie), code=use).stdout.strip().splitlines()[-1], "200", "cookie valid with the original SOC_SECRET")
        out = T + "/sess.env"; r = run(["tools/rotate_secrets.py", "session-secret", "--out", out]); self.assertEqual(r.returncode, 0)
        newsec = open(out).read().strip().split("=", 1)[1]; self.assertNotIn(newsec, r.stdout + r.stderr)
        self.assertEqual(run([], env=dict(ENV, PROBE_COOKIE=cookie, SOC_SECRET=newsec), code=use).stdout.strip().splitlines()[-1], "401", "after rotating SOC_SECRET the old cookie must be rejected")
    def test_04_encrypted_backup_verify_tamper_restore_drill(self):
        r = run(["tools/backup.py", "create"]); self.assertEqual(r.returncode, 0, r.stdout + r.stderr)
        files = sorted(f for f in os.listdir(T + "/bk") if f.endswith(".db.enc")); self.assertTrue(files); f = os.path.join(T + "/bk", files[-1])
        self.assertNotIn(b"SQLite format 3", open(f, "rb").read(32), "backup must be encrypted"); self.assertEqual(stat.S_IMODE(os.stat(f).st_mode), 0o600)
        self.assertEqual(run(["tools/backup.py", "verify", f]).returncode, 0)
        os.makedirs(T + "/tamper", mode=0o700, exist_ok=True); bad = os.path.join(T + "/tamper", os.path.basename(f)); b = bytearray(open(f, "rb").read()); b[len(b) // 2] = (b[len(b) // 2] + 1) % 256 if chr(b[len(b) // 2]) != "=" else ord("A"); open(bad, "wb").write(b); os.chmod(bad, 0o600)
        v = run(["tools/backup.py", "verify", bad]); self.assertNotEqual(v.returncode, 0, "a modified ciphertext (same file name, NO manifest to catch it) must be detected by the authenticated encryption itself")
        mf = os.path.join(T + "/tamper", os.path.basename(f) + ".sha256"); open(mf, "w").write(open(f + ".sha256").read()); v = run(["tools/backup.py", "verify", bad]); self.assertIn("manifest hash mismatch", v.stdout + v.stderr)
        to = T + "/restored.db"; r = run(["tools/backup.py", "restore", f, "--to", to]); self.assertEqual(r.returncode, 0, r.stdout + r.stderr)
        self.assertNotEqual(run(["tools/backup.py", "restore", f, "--to", to]).returncode, 0, "restore never overwrites")
        self.assertNotEqual(run(["tools/backup.py", "restore", f, "--to", ENV["SOC_DB"]]).returncode, 0, "restore refuses the live database path")
        usable = run([], env=dict(ENV, SOC_DB=to), code="import db;print(db.q('SELECT COUNT(*) c FROM users',one=True)['c'])"); self.assertEqual(usable.stdout.strip().splitlines()[-1], "1", "the restored copy opens and contains the data")
        d = run(["tools/backup.py", "drill"]); self.assertEqual(d.returncode, 0, d.stdout + d.stderr); self.assertIn("users", d.stdout)
if __name__ == "__main__": unittest.main(verbosity=2)
