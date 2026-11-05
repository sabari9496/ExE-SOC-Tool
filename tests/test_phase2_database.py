"""Phase 2: migrations, backup/restore, startup policy. Temporary databases only; synthetic data. Run: python tests/test_phase2_database.py"""
import os, sys, tempfile, json, time, hashlib, hmac, secrets, sqlite3, subprocess, threading, unittest, shutil, io, contextlib, stat
ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__))); sys.path.insert(0, ROOT)
T = tempfile.mkdtemp()
for k in ("SOC_ALLOW_DEFAULT_CREDS", "SOC_ENV", "SOC_AUTO_MIGRATE", "SOC_AGENT_AUTH"): os.environ.pop(k, None)
os.environ.update(SOC_DB=T + "/t.db", SOC_SECRET="s" * 40, SOC_LOCAL_LOGS="0", SOC_ALLOW_FOREIGN_DB="1")
import db, app as A, engine, fleet.api as FA, migrations as M, dbbackup as B, migrate as MG
db.init_db(); BASE = "http://127.0.0.1:5000"; H = {"X-Requested-With": "fetch", "Origin": BASE}
FA.LIMITS.update(events=(10 ** 6, 60), heartbeat=(10 ** 6, 60), ip=(10 ** 6, 60), register=(10 ** 6, 60))
ADMIN = dict(l.split("=", 1) for l in open(T + "/initial_admin_credentials.txt").read().splitlines() if "=" in l)

# ---- seed the main temp DB with representative synthetic data (users, agent, events, alert, ledger, quarantine) ----
adm = A.app.test_client(); assert adm.post("/login", data={"username": ADMIN["username"], "password": ADMIN["password"]}, headers={"Origin": BASE}, base_url=BASE).status_code == 302
db.x("INSERT INTO users(username,password_hash,role,created_at) VALUES(?,?,?,?)", ("ana", A.generate_password_hash("a-long-test-password-1"), "analyst", db.now()))
tok = adm.post("/api/enrollment-tokens", json={"label": "t"}, headers=H, base_url=BASE).get_json()["token"]
reg = A.app.test_client().post("/api/agents/register", json={"enrollment_token": tok, "hostname": "seed-host", "os": "Linux", "os_version": "t", "agent_version": "1"}, base_url=BASE).get_json()
def post_events(evs):
    data = json.dumps({"events": evs}, separators=(",", ":")).encode(); ts = str(int(time.time())); n = secrets.token_urlsafe(12)
    canon = "\n".join(("EXESOC-HMAC-SHA256-V1", "POST", "/api/events", ts, n, hashlib.sha256(data).hexdigest()))
    h = {"Authorization": "Bearer " + reg["credential"], "X-Timestamp": ts, "X-Nonce": n, "Content-Type": "application/json", "X-Signature": "v1=" + hmac.new(reg["signing_key"].encode(), canon.encode(), hashlib.sha256).hexdigest()}
    return A.app.test_client().post("/api/events", data=data, headers=h, base_url=BASE).get_json()
def mkev(i, msg, **k): d = dict(uid=hashlib.sha256(f"seed{i}".encode()).hexdigest()[:40], message=msg, channel="syn", record_id=1000 + i, event_time=time.strftime("%Y-%m-%dT%H:%M:%S", time.gmtime()), log_only=False); d.update(k); return d
post_events([mkev(1, "mimikatz.exe sekurlsa::logonpasswords"), mkev(2, "ordinary event two"), mkev(3, "", )])             # 2 stored (1 alert), 1 quarantined (bad message)
SEED = T + "/t.db"
TABLES = ("users", "events", "alerts", "agents", "agent_credentials", "agent_event_ids", "event_quarantine", "audit", "settings", "endpoints")
def snap(path, tables=TABLES, cols=None):
    c = sqlite3.connect(f"file:{path}?mode=ro", uri=True); out = {}
    try:
        for t in tables:
            try:
                have = [r[1] for r in c.execute(f"PRAGMA table_info({t})")]; use = [x for x in (cols or {}).get(t, have) if x in have]
                if not use: continue
                out[t] = hashlib.sha256(repr(sorted(c.execute(f"SELECT {','.join(use)} FROM {t}").fetchall(), key=repr)).encode()).hexdigest(), c.execute(f"SELECT COUNT(*) FROM {t}").fetchone()[0]
            except sqlite3.Error: pass
    finally: c.close()
    return out
def fhash(p): return hashlib.sha256(open(p, "rb").read()).hexdigest()
def seed_copy(name, legacy=False):
    """Copy of the seeded DB (via the online-backup API). legacy=True strips everything Phase 1/2 added, i.e. a pass6-baseline-shaped database."""
    p = os.path.join(T, name); src = sqlite3.connect(SEED); dst = sqlite3.connect(p); src.backup(dst); src.close()
    if legacy:
        dst.execute("DROP TABLE IF EXISTS event_quarantine"); dst.execute("DROP TABLE IF EXISTS schema_migrations")
        for i in ("ix_aev_status_ts", "ix_quar_created", "ix_quar_agent"): dst.execute(f"DROP INDEX IF EXISTS {i}")
        dst.execute("ALTER TABLE agent_event_ids RENAME TO _old"); dst.execute("CREATE TABLE agent_event_ids(agent_id TEXT NOT NULL, uid TEXT NOT NULL, ts TEXT, PRIMARY KEY(agent_id, uid)) WITHOUT ROWID")
        dst.execute("INSERT INTO agent_event_ids SELECT agent_id,uid,ts FROM _old"); dst.execute("DROP TABLE _old")
    dst.commit(); dst.close(); return p
def cli(mod, *args):
    o, e = io.StringIO(), io.StringIO()
    with contextlib.redirect_stdout(o), contextlib.redirect_stderr(e): rc = mod.main(list(args))
    return rc, o.getvalue() + e.getvalue()

class Migrations(unittest.TestCase):
    def test_01_fresh_initialisation_applies_all_and_matches_fleet_schema(self):
        p = T + "/fresh.db"; old = db.DB; db.DB = p
        try: db.init_db()
        finally: db.DB = old
        r = M.inspect(p); self.assertEqual([x["version"] for x in r["recorded"]], [1, 2, 3, 4]); self.assertEqual((r["pending"], r["problems"]), ([], []))
        c = sqlite3.connect(p); self.assertGreaterEqual(c.execute("SELECT COUNT(*) FROM users").fetchone()[0], 1); c.close()
        a, b_ = sqlite3.connect(T + "/ga.db"), sqlite3.connect(T + "/gb.db")                                              # migration DDL must equal the fleet bootstrap DDL
        from fleet.schema import SCHEMA, ALTERS
        a.executescript(SCHEMA); [a.execute(f"ALTER TABLE {t} ADD COLUMN {c_} {ty}") for t, cols in ALTERS.items() for c_, ty in cols if t in ("agent_event_ids",) and c_ not in {r[1] for r in a.execute("PRAGMA table_info(agent_event_ids)")}]
        for t in ("agents", "events", "alerts"): pass
        b_.execute("CREATE TABLE users(x)"); [b_.execute(f"CREATE TABLE {t}(x)") for t in M.CORE_TABLES if t != "users"]; b_.commit(); M._m2(b_)
        for t in ("agent_event_ids", "event_quarantine"): self.assertEqual({(r[1], r[2].upper()) for r in a.execute(f"PRAGMA table_info({t})")}, {(r[1], r[2].upper()) for r in b_.execute(f"PRAGMA table_info({t})")}, t)
    def test_02_legacy_database_migrates_without_data_loss_and_plan_is_read_only(self):
        p = seed_copy("legacy.db", legacy=True); before = snap(p, cols={"agent_event_ids": ["agent_id", "uid", "ts"]}); h0, m0 = fhash(p), os.stat(p).st_mtime
        r = M.plan(p); self.assertEqual(r["pending"], [1, 2, 3, 4]); self.assertFalse(r["tracked"]); self.assertEqual((fhash(p), os.stat(p).st_mtime), (h0, m0), "plan/inspect never writes")
        rc, out = cli(MG, "plan", "--db", p); self.assertEqual(rc, 0); self.assertIn("read-only", out); self.assertEqual(fhash(p), h0)
        self.assertEqual(M.apply(p), [1, 2, 3, 4]); after = snap(p, cols={"agent_event_ids": ["agent_id", "uid", "ts"]})
        for t in ("users", "events", "alerts", "agents", "agent_credentials", "agent_event_ids", "audit", "settings", "endpoints"): self.assertEqual(after[t], before[t], f"{t} unchanged")
        c = sqlite3.connect(p); self.assertEqual(c.execute("PRAGMA integrity_check").fetchone()[0], "ok"); self.assertEqual(c.execute("SELECT COUNT(*) FROM users WHERE role='admin'").fetchone()[0], 1); self.assertIn("attempts", {x[1] for x in c.execute("PRAGMA table_info(agent_event_ids)")})
        self.assertGreaterEqual(c.execute("SELECT COUNT(*) FROM events").fetchone()[0], 2); self.assertEqual(c.execute("SELECT COUNT(*) FROM alerts").fetchone()[0] >= 1, True); c.close()
    def test_03_phase1_database_upgrade_keeps_quarantine_and_ledger(self):
        p = seed_copy("phase1.db"); c = sqlite3.connect(p); c.execute("DROP TABLE IF EXISTS schema_migrations"); c.commit(); c.close(); before = snap(p); self.assertEqual(before["event_quarantine"][1], 1)
        M.apply(p); self.assertEqual(snap(p, ("users", "events", "alerts", "agents", "agent_event_ids", "event_quarantine")), {k: v for k, v in before.items() if k in ("users", "events", "alerts", "agents", "agent_event_ids", "event_quarantine")})
    def test_04_rerun_is_a_noop(self):
        p = seed_copy("rerun.db"); M.apply(p); c = sqlite3.connect(p); a1 = c.execute("SELECT * FROM schema_migrations ORDER BY version").fetchall(); c.close(); h = snap(p)
        self.assertEqual(M.apply(p), []); c = sqlite3.connect(p); self.assertEqual(c.execute("SELECT * FROM schema_migrations ORDER BY version").fetchall(), a1, "applied_at not rewritten"); c.close(); self.assertEqual(snap(p), h)
    def test_05_failed_migration_rolls_back_and_is_retryable(self):
        p = seed_copy("fail.db", legacy=True); orig = list(M.MIGRATIONS)
        def boom(c): c.execute("CREATE INDEX ix_aev_status_ts ON agent_event_ids(status, ts)"); raise RuntimeError("injected")
        M.MIGRATIONS[2] = orig[2][:3] + (boom,) + orig[2][4:]
        try:
            with self.assertRaises(M.MigrationError) as cm: M.apply(p)
            self.assertIn("rolled back", str(cm.exception))
            c = sqlite3.connect(p); self.assertEqual([r[0] for r in c.execute("SELECT version FROM schema_migrations")], [1, 2]); self.assertNotIn("ix_aev_status_ts", {r[0] for r in c.execute("SELECT name FROM sqlite_master WHERE type='index'")}, "partial DDL rolled back"); c.close()
            M.MIGRATIONS[2] = orig[2][:3] + (lambda c: None,) + orig[2][4:]
            with self.assertRaises(M.MigrationError) as cm: M.apply(p)
            self.assertIn("post-condition", str(cm.exception))
        finally: M.MIGRATIONS[:] = orig
        self.assertEqual(M.apply(p), [3, 4]); self.assertEqual(M.inspect(p)["problems"], [])
    def test_06_process_killed_mid_migration_recovers(self):
        p = seed_copy("kill.db", legacy=True); h = snap(p, cols={"agent_event_ids": ["agent_id", "uid", "ts"]})
        code = f"import sys,os; sys.path.insert(0,{ROOT!r}); import migrations as M\ndef die(c): c.execute('CREATE INDEX ix_aev_status_ts ON agent_event_ids(status, ts)'); os._exit(5)\nM.MIGRATIONS[2]=M.MIGRATIONS[2][:3]+(die,)+M.MIGRATIONS[2][4:]\nM.apply({p!r})"
        self.assertEqual(subprocess.run([sys.executable, "-c", code]).returncode, 5)
        c = sqlite3.connect(p); self.assertEqual(c.execute("PRAGMA integrity_check").fetchone()[0], "ok"); self.assertEqual([r[0] for r in c.execute("SELECT version FROM schema_migrations")], [1, 2], "version 3 not recorded"); c.close()
        self.assertEqual(M.apply(p), [3, 4]); self.assertEqual(snap(p, cols={"agent_event_ids": ["agent_id", "uid", "ts"]})["users"], h["users"])
    def test_07_missing_object_is_detected_and_repaired(self):
        p = seed_copy("repair.db"); M.apply(p); c = sqlite3.connect(p); c.execute("DROP INDEX ix_aev_status_ts"); c.commit(); c.close()
        self.assertTrue(M.inspect(p)["problems"]); self.assertEqual(M.apply(p), [3]); self.assertEqual(M.inspect(p)["problems"], [])
    def test_08_unknown_newer_version_and_checksum_mismatch_refused(self):
        p = seed_copy("new.db"); M.apply(p); c = sqlite3.connect(p); c.execute("INSERT INTO schema_migrations VALUES(99,'future','x','2030-01-01T00:00:00Z')"); c.commit(); c.close()
        with self.assertRaises(M.SchemaTooNew) as cm: M.apply(p)
        self.assertIn("newer", str(cm.exception)); rc, out = cli(MG, "status", "--db", p); self.assertEqual(rc, 2); self.assertIn("newer", out)
        old = db.DB; db.DB = p
        try:
            with self.assertRaises(M.SchemaTooNew): db.init_db()
        finally: db.DB = old
        q = seed_copy("ck.db"); M.apply(q); c = sqlite3.connect(q); c.execute("UPDATE schema_migrations SET checksum='tampered' WHERE version=2"); c.commit(); c.close()
        with self.assertRaises(M.ChecksumMismatch): M.apply(q)
    def test_09_concurrent_processes_apply_each_migration_once(self):
        p = seed_copy("conc.db", legacy=True); code = f"import sys; sys.path.insert(0,{ROOT!r}); import migrations as M; print(M.apply({p!r}))"
        ps = [subprocess.Popen([sys.executable, "-c", code], stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True) for _ in range(6)]; outs = [x.communicate(timeout=120) for x in ps]
        self.assertEqual([x.returncode for x in ps], [0] * 6, [o[1][-200:] for o in outs]); applied = [v for o in outs for v in json.loads(o[0].strip().splitlines()[-1])]
        self.assertEqual(sorted(applied), [1, 2, 3, 4], "each migration applied by exactly one process"); c = sqlite3.connect(p); self.assertEqual(c.execute("SELECT COUNT(*) FROM schema_migrations").fetchone()[0], 4); c.close()
    def test_10_migration_waits_for_a_write_lock_instead_of_failing(self):
        p = seed_copy("lock.db", legacy=True); lk = sqlite3.connect(p, timeout=1, isolation_level=None); lk.execute("BEGIN IMMEDIATE"); res = {}
        th = threading.Thread(target=lambda: res.update(r=M.apply(p))); th.start(); time.sleep(1.0); self.assertTrue(th.is_alive(), "blocked by the writer, not crashed"); lk.execute("COMMIT"); lk.close(); th.join(60); self.assertEqual(res["r"], [1, 2, 3, 4])
    def test_11_startup_policy_existing_db_not_migrated_implicitly(self):
        p = seed_copy("startup.db", legacy=True); old = db.DB; db.DB = p
        try:
            self.assertFalse(M.is_fresh(p)); e = io.StringIO()
            with contextlib.redirect_stderr(e): db.init_db()
            self.assertIn("NOTICE", e.getvalue()); self.assertEqual(M.inspect(p)["recorded"], [], "existing database untouched by startup")
            os.environ["SOC_AUTO_MIGRATE"] = "1"; db.init_db(); self.assertEqual([x["version"] for x in M.inspect(p)["recorded"]], [1, 2, 3, 4])
        finally: db.DB = old; os.environ.pop("SOC_AUTO_MIGRATE", None)
    def test_12_cli_requires_approval_and_takes_verified_backup_first(self):
        p = seed_copy("cli.db", legacy=True); bd = T + "/premig"; h = fhash(p)
        rc, out = cli(MG, "apply", "--db", p); self.assertEqual(rc, 3); self.assertEqual(fhash(p), h, "no --yes: nothing changed")
        rc, out = cli(MG, "apply", "--db", p, "--backup-dir", bd, "--yes"); self.assertEqual(rc, 0, out); self.assertIn("verified backup", out); bk = [f for f in os.listdir(bd) if f.endswith(".db")]; self.assertEqual(len(bk), 1)
        self.assertEqual(B.verify(os.path.join(bd, bk[0]))["schema_version"], None, "backup holds the PRE-migration state"); self.assertEqual(cli(MG, "status", "--db", p)[0], 0)
        self.assertEqual(cli(MG, "apply", "--db", T + "/nope.db", "--yes")[0], 2); rc, out = cli(MG, "apply", "--db", T + "/empty.db"); self.assertEqual(rc, 2)

class Backup(unittest.TestCase):
    def test_01_backup_is_consistent_while_writing_and_passes_integrity(self):
        p = seed_copy("live.db"); stop = threading.Event(); n = [0]
        def writer():
            c = sqlite3.connect(p, timeout=30); c.execute("PRAGMA journal_mode=WAL")
            while not stop.is_set(): c.execute("INSERT INTO settings(key,value) VALUES(?,?)", (f"k{n[0]}", "v")); c.commit(); n[0] += 1
            c.close()
        th = threading.Thread(target=writer); th.start(); time.sleep(0.2)
        try: o = B.create(p, T + "/bk1")
        finally: stop.set(); th.join()
        self.assertEqual(o["verify"]["integrity"], "ok"); self.assertGreaterEqual(o["verify"]["tables"], 40)
        files = os.listdir(T + "/bk1"); self.assertEqual(sorted(f.split(".", 1)[1] for f in files), ["db", "db.json"], "only the database + metadata: no .secret, no sidecars, no partial files")
        meta = json.load(open(o["path"] + ".json")); self.assertEqual(set(meta), {"format", "created_utc", "sha256", "bytes", "sqlite_version", "tables", "schema_version", "source_name"}); self.assertNotIn(T, json.dumps(meta), "no absolute paths in metadata")
        if os.name == "posix": self.assertEqual(stat.S_IMODE(os.stat(o["path"]).st_mode), 0o600); self.assertEqual(stat.S_IMODE(os.stat(o["path"] + ".json").st_mode), 0o600)
        c = sqlite3.connect(o["path"]); self.assertEqual(c.execute("PRAGMA integrity_check").fetchone()[0], "ok"); c.close()
    def test_02_corruption_and_tampering_detected(self):
        o = B.create(seed_copy("c1.db"), T + "/bk2"); bad = T + "/bk2/tamper.db"; shutil.copy(o["path"], bad); shutil.copy(o["path"] + ".json", bad + ".json")
        with open(bad, "r+b") as f: f.seek(4096 * 3); f.write(b"\xff" * 64)
        with self.assertRaises(B.BackupError) as cm: B.verify(bad)
        self.assertIn("checksum", str(cm.exception)); os.remove(bad + ".json")                                                     # without metadata the SQLite integrity check must still catch real corruption
        try: r = B.verify(bad); self.assertNotEqual(r["integrity"], "ok")
        except B.BackupError: pass
        junk = T + "/bk2/junk.db"; open(junk, "wb").write(b"not a database" * 100)
        with self.assertRaises(B.BackupError): B.verify(junk)
        with self.assertRaises(B.BackupError): B.verify(T + "/bk2/missing.db")
        empty = T + "/bk2/empty.db"; sqlite3.connect(empty).execute("CREATE TABLE x(a)").connection.close()
        with self.assertRaises(B.BackupError): B.verify(empty)
    def test_03_restore_to_new_destination_preserves_data(self):
        src = seed_copy("c2.db"); o = B.create(src, T + "/bk3"); dest = T + "/restored.db"; r = B.restore(o["path"], dest)
        self.assertEqual(r["verify"]["integrity"], "ok"); self.assertEqual(snap(dest), snap(src)); self.assertFalse(os.path.exists(dest + ".restoring"))
        if os.name == "posix": self.assertEqual(stat.S_IMODE(os.stat(dest).st_mode), 0o600)
    def test_04_overwrite_is_refused_without_explicit_authorisation(self):
        src = seed_copy("c3.db"); o = B.create(src, T + "/bk4"); dest = seed_copy("existing.db"); h = fhash(dest)
        with self.assertRaises(B.BackupError) as cm: B.restore(o["path"], dest)
        self.assertIn("refusing", str(cm.exception)); self.assertEqual(fhash(dest), h)
        with self.assertRaises(B.BackupError) as cm: B.restore(o["path"], dest, overwrite=True)
        self.assertIn("--backup-existing-to", str(cm.exception)); self.assertEqual(fhash(dest), h)
        with self.assertRaises(B.BackupError): B.restore(o["path"], o["path"], overwrite=True, backup_existing_to=T + "/x")
        self.assertEqual(cli(B, "restore", o["path"], "--to", dest)[0], 2); self.assertEqual(fhash(dest), h)
    def test_05_authorised_overwrite_backs_up_current_db_and_sets_sidecars_aside(self):
        o = B.create(seed_copy("c4.db"), T + "/bk5"); dest = seed_copy("existing2.db"); h = fhash(dest); open(dest + "-wal", "wb").write(b"stale"); open(dest + "-shm", "wb").write(b"stale")
        r = B.restore(o["path"], dest, overwrite=True, backup_existing_to=T + "/bk5safety"); self.assertEqual(B.verify(r["previous_backup"])["integrity"], "ok")
        self.assertEqual(snap(r["previous_backup"], ("users",)), snap(T + "/existing2.db", ("users",)))
        self.assertFalse(os.path.exists(dest + "-wal")); self.assertTrue([f for f in os.listdir(T) if f.startswith("existing2.db-wal.replaced-")], "old sidecar renamed, not deleted")
        c = sqlite3.connect(dest); self.assertEqual(c.execute("PRAGMA integrity_check").fetchone()[0], "ok"); c.close()
    def test_06_failed_restore_leaves_destination_untouched(self):
        o = B.create(seed_copy("c5.db"), T + "/bk6"); bad = T + "/bk6/bad.db"; shutil.copy(o["path"], bad); shutil.copy(o["path"] + ".json", bad + ".json")
        with open(bad, "r+b") as f: f.seek(5000); b0 = f.read(32); f.seek(5000); f.write(bytes(x ^ 0xFF for x in b0))
        dest = seed_copy("existing3.db"); h = fhash(dest)
        with self.assertRaises(B.BackupError): B.restore(bad, dest, overwrite=True, backup_existing_to=T + "/bk6safety")
        self.assertEqual(fhash(dest), h); self.assertFalse(os.path.exists(dest + ".restoring"))
        with self.assertRaises(B.BackupError): B.restore(bad, T + "/newdest.db"); self.assertFalse(os.path.exists(T + "/newdest.db"))
    def test_07_backup_cli(self):
        p = seed_copy("c6.db"); rc, out = cli(B, "backup", "--db", p, "--dest", T + "/bk7"); self.assertEqual(rc, 0, out); f = [x for x in os.listdir(T + "/bk7") if x.endswith(".db")][0]
        self.assertEqual(cli(B, "verify", T + "/bk7/" + f)[0], 0); self.assertEqual(cli(B, "restore", T + "/bk7/" + f, "--to", T + "/cli-restored.db")[0], 0); self.assertEqual(cli(B, "backup", "--db", T + "/nope.db", "--dest", T + "/bk7")[0], 2)
        self.assertEqual(snap(T + "/cli-restored.db"), snap(p))

if __name__ == "__main__": unittest.main(verbosity=1)
