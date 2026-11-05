"""Stage 2: Monitoring Center. Temp databases, synthetic agents/alerts/events, deterministic clock for state boundaries.
Real-host behaviour (a real Windows / Ubuntu machine) is NOT covered here: see docs/MONITORING_CENTER.md for the manual verification plan.
Run: python tests/test_monitoring_center.py"""
import os, sys, json, time, sqlite3, shutil, subprocess, unittest, contextlib, shutil
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import test_phase1_review as P
from test_phase1_review import db, A, T, ROOT, count
import migrations as M
import fleet.osmeta as OM, fleet.status as ST, fleet.config as CFG, fleet.monitoring as MON
import exe_soc_agent as AG
from datetime import datetime, timedelta
FMT = "%Y-%m-%d %H:%M:%S"; BASE = P.BASE; H = P.H
def ts(secs_ago=0): return (datetime.now() - timedelta(seconds=secs_ago)).strftime(FMT)

class Ag(P.Agent):
    """Real enrollment through the real endpoint, with a custom register payload; signed requests like the real agent."""
    def __init__(self, host, **payload):
        tok = P._adm.post("/api/enrollment-tokens", json={"label": "t"}, headers=H, base_url=BASE).get_json()["token"]
        b = dict(enrollment_token=tok, hostname=host, os="Linux", os_version="t", agent_version="1.0.0"); b.update(payload)
        r = A.app.test_client().post("/api/agents/register", json=b, base_url=BASE).get_json()
        self.id, self.cred, self.skey, self.hostname = r["agent_id"], r["credential"], r["signing_key"], r["hostname"]; self.c = A.app.test_client()
    def hb(self, **extra): return self.post("/api/agents/heartbeat", dict(dict(agent_version="1.0.0", os_version="t"), **extra))
def row(aid): return dict(db.q("SELECT * FROM agents WHERE id=?", (aid,), one=True))
def set_times(aid, hb=None, reg=3600, first="unset", last_event=None, health=None, status=None):
    sets, v = ["registered_at=?"], [ts(reg)]
    if hb is not None: sets.append("last_heartbeat=?"); v.append(ts(hb))
    if first != "unset": sets.append("first_heartbeat_at=?"); v.append(first)
    if last_event is not None: sets.append("last_event_at=?"); v.append(ts(last_event))
    if health is not None: sets.append("health=?"); v.append(json.dumps(health))
    if status: sets.append("status=?"); v.append(status)
    db.x(f"UPDATE agents SET {','.join(sets)} WHERE id=?", v + [aid])
def mkalert(aid, sev, secs_ago=60):
    db.x("INSERT INTO alerts(ts,updated,severity,title,category,status,count,agent_id) VALUES(?,?,?,?,?,?,?,?)", (ts(secs_ago), ts(secs_ago), sev, f"synthetic {sev}", "Authentication", "New", 1, aid))
def mkevents(aid, host, n, secs_ago=60):
    c = db.conn(); c.executemany("INSERT INTO events(ts,host,message,agent_id,record_id,channel) VALUES(?,?,?,?,?,?)", [(ts(secs_ago), host, f"synthetic {i}", aid, 9000000 + i + abs(hash(aid)) % 100000, "syn") for i in range(n)]); c.commit(); c.close()
def get(c, path, **kw): return c.get(path, base_url=BASE, headers={"X-Requested-With": "fetch"}, **kw)
@contextlib.contextmanager
def use_db(path):
    old = db.DB; db.DB = path
    try: yield
    finally: db.DB = old
def ids(resp): return {i["id"] for i in resp.get_json()["items"]}
ANA, VIE = P.login("analyst1", "a-long-test-password-1"), P.login("viewer1", "a-long-test-password-1")
ADM = P._adm

class OsClassification(unittest.TestCase):
    def test_01_matrix(self):
        C = OM.classify
        cases = [(("windows", None, "Windows"), "windows", "os_family"), (("linux", "ubuntu", "Ubuntu"), "ubuntu", "os_release_id"), (("linux", "UBUNTU ", None), "ubuntu", "os_release_id"),
                 (("linux", "debian", "Debian GNU/Linux"), "linux", "os_release_id"), (("linux", "linuxmint", "Linux Mint"), "linux", "os_release_id"), (("linux", "rhel", None), "linux", "os_release_id"),
                 (("linux", None, "Ubuntu"), "ubuntu", "legacy_os_name"), (("linux", None, "5.15.0-91-generic"), "linux", "family_only"), (("linux", "ubuntu; DROP TABLE", "Ubuntu"), "ubuntu", "legacy_os_name"),
                 (("linux", "bad id with spaces", "Debian GNU/Linux"), "linux", "family_only"), ((None, None, "Ubuntu"), "ubuntu", "legacy_os_name"), ((None, None, "ubuntu"), "ubuntu", "legacy_os_name"),
                 ((None, None, "Windows"), "windows", "legacy_os_name"), ((None, None, "Debian GNU/Linux"), "linux", "legacy_os_name"), ((None, None, "Fedora Linux"), "linux", "legacy_os_name"),
                 ((None, None, "Rocky Linux"), "linux", "legacy_os_name"), ((None, None, "AlmaLinux"), "linux", "legacy_os_name"), ((None, None, "5.15.0-91-generic"), "unknown", "unclassified"),
                 ((None, None, ""), "unknown", "unclassified"), ((None, None, None), "unknown", "unclassified"), (("darwin", None, "macOS"), "unknown", "os_family"), ((None, None, 12345), "unknown", "unclassified"),
                 (("freebsd", "ubuntu", "Ubuntu"), "ubuntu", "legacy_os_name"), (("linux", ["ubuntu"], {"a": 1}), "linux", "family_only")]
        for args, cls, by in cases:
            r = C(*args); self.assertEqual((r["os_class"], r["classified_by"]), (cls, by), args)
        self.assertEqual(C("linux", "ubuntu")["distro_id"], "ubuntu"); self.assertEqual(C("linux", None, "5.15.0")["distro_id"], "unknown"); self.assertIsNone(C("windows")["distro_id"])
        self.assertNotEqual(C("linux", "linuxmint", "Linux Mint")["os_class"], "ubuntu", "a derivative with its own ID is not Ubuntu")
    def test_02_validators(self):
        self.assertEqual(OM.clean_distro_id("a" * 40), "a" * 40); self.assertIsNone(OM.clean_distro_id("a" * 41)); self.assertIsNone(OM.clean_distro_id("")); self.assertIsNone(OM.clean_distro_id(None)); self.assertIsNone(OM.clean_distro_id("-x"))
        self.assertEqual(OM.clean_distro_version("22.04"), "22.04"); self.assertEqual(OM.clean_distro_version("9~beta+1"), "9~beta+1"); self.assertIsNone(OM.clean_distro_version("22.04; x")); self.assertIsNone(OM.clean_distro_version("v" * 41))
        self.assertEqual(OM.clean_family(" Linux "), "linux"); self.assertIsNone(OM.clean_family("plan9")); self.assertIsNone(OM.clean_family(["linux"]))
    def test_03_classify_has_no_hostname_input(self):
        import inspect; self.assertEqual(list(inspect.signature(OM.classify).parameters), ["os_family", "distro_id", "os_name"])

class AgentOsMetadata(unittest.TestCase):
    UBUNTU = 'PRETTY_NAME="Ubuntu 22.04.4 LTS"\nNAME="Ubuntu"\nVERSION_ID="22.04"\nID=ubuntu\nID_LIKE=debian\n'
    def test_01_parse(self):
        d = AG.parse_os_release(self.UBUNTU); self.assertEqual((d["ID"], d["VERSION_ID"], d["NAME"]), ("ubuntu", "22.04", "Ubuntu"))
        d = AG.parse_os_release("# comment\n\nID='debian'\nbad line\nlower=x\nVERSION_ID=12\n=novalue\nID_LIKE=\n"); self.assertEqual(d, {"ID": "debian", "VERSION_ID": "12", "ID_LIKE": ""})
        self.assertEqual(AG.parse_os_release(None), {}); self.assertEqual(AG.parse_os_release("\x00\xff garbage"), {}); self.assertLessEqual(len(AG.parse_os_release("A=" + "x" * 100000).get("A", "")), 8192)
    def test_02_metadata(self):
        r = lambda text: (lambda f: text)
        self.assertEqual(AG.os_metadata("Linux", read=r(self.UBUNTU)), {"os_family": "linux", "distro_id": "ubuntu", "distro_version": "22.04"})
        self.assertEqual(AG.os_metadata("Linux", read=r('ID=debian\nVERSION_ID="12"\n')), {"os_family": "linux", "distro_id": "debian", "distro_version": "12"})
        self.assertEqual(AG.os_metadata("Linux", read=r('ID=linuxmint\nID_LIKE="ubuntu debian"\nVERSION_ID="21"\n'))["distro_id"], "linuxmint")
        self.assertEqual(AG.os_metadata("Linux", read=r('ID=Ubuntu\n'))["os_family"], "linux"); self.assertNotIn("distro_id", AG.os_metadata("Linux", read=r('ID="has space"\n')), "invalid id dropped")
        self.assertEqual(AG.os_metadata("Linux", read=r('NAME=NoIdHere\n')), {"os_family": "linux"})
        def boom(f): raise OSError("unreadable")
        self.assertEqual(AG.os_metadata("Linux", read=boom), {"os_family": "linux"}, "missing/unreadable file: family only, never an exception")
        seen = []; self.assertEqual(AG.os_metadata("Linux", read=lambda f: (seen.append(f), (_ for _ in ()).throw(OSError()) if f == "/etc/os-release" else "ID=fedora\n")[1])["distro_id"], "fedora"); self.assertEqual(seen, ["/etc/os-release", "/usr/lib/os-release"])
        self.assertEqual(AG.os_metadata("Windows"), {"os_family": "windows"}); self.assertEqual(AG.os_metadata("Darwin"), {"os_family": "darwin"}); self.assertEqual(AG.os_metadata("Plan9"), {})
    def test_03_host_info_keeps_old_fields_and_adds_new_ones(self):
        h = AG.host_info(); self.assertTrue({"hostname", "os", "os_version", "ips"} <= set(h)); self.assertEqual(h["os_family"], "linux" if sys.platform.startswith("linux") else h["os_family"])

class StatusStates(unittest.TestCase):
    NOW = datetime(2026, 11, 1, 12, 0, 0)
    def st(self, hb_age, health=None, **kw):
        a = dict(status="active", registered_at=(self.NOW - timedelta(days=1)).strftime(FMT), last_heartbeat=(self.NOW - timedelta(seconds=hb_age)).strftime(FMT), health=health or {}); a.update(kw)
        return ST.endpoint_state(a, self.NOW, th=(90, 300))["state"]
    def test_01_boundaries(self):
        for age, want in ((0, "online"), (89, "online"), (90, "online"), (91, "degraded"), (299, "degraded"), (300, "degraded"), (301, "offline"), (80000, "offline")): self.assertEqual(self.st(age), want, age)
        self.assertEqual(self.st(-30), "online", "a heartbeat slightly in the future (clock skew) is not an error")
    def test_02_degraded_reasons(self):
        self.assertEqual(self.st(10, {"upload_failures_recent": 2}), "online"); self.assertEqual(self.st(10, {"upload_failures_recent": 3}), "degraded")
        self.assertEqual(self.st(10, {"events_queued": 5000}), "online"); self.assertEqual(self.st(10, {"events_queued": 5001}), "degraded")
        self.assertEqual(self.st(10, {"collector_errors": ["x"]}), "degraded"); self.assertEqual(self.st(10, {"collector_errors": []}), "online")
        self.assertEqual(self.st(10, json.dumps({"upload_failures_recent": 9})), "degraded", "health stored as JSON text"); self.assertEqual(self.st(10, "not json{"), "online"); self.assertEqual(self.st(10, "[1,2]"), "online")
        self.assertEqual(self.st(10, {"events_queued": "many"}), "online", "garbage values never raise"); self.assertEqual(self.st(400, {"upload_failures_recent": 9}), "offline", "offline wins over degraded")
        r = ST.endpoint_state(dict(status="active", registered_at="2026-10-01 00:00:00", last_heartbeat=self.NOW.strftime(FMT), health={"events_queued": 6000, "collector_errors": ["x"]}), self.NOW, th=(90, 300)); self.assertIn("6000", r["reason"]); self.assertIn("collector", r["reason"])
    def test_03_never_connected_and_revoked(self):
        reg = (self.NOW - timedelta(days=2)).strftime(FMT)
        nc = dict(status="active", registered_at=reg, last_heartbeat=reg, first_heartbeat_at=None, last_event_at=None)
        self.assertEqual(ST.endpoint_state(nc, self.NOW, (90, 300))["state"], "never_connected", "still never connected after two days")
        self.assertEqual(ST.endpoint_state(dict(nc, first_heartbeat_at=reg), self.NOW, (90, 300))["state"], "offline"); self.assertEqual(ST.endpoint_state(dict(nc, last_event_at=reg), self.NOW, (90, 300))["state"], "offline")
        self.assertEqual(ST.endpoint_state(dict(nc, last_heartbeat=(self.NOW - timedelta(seconds=5)).strftime(FMT)), self.NOW, (90, 300))["state"], "online", "legacy row: heartbeat later than enrollment")
        self.assertEqual(ST.endpoint_state(dict(nc, last_heartbeat=None, first_heartbeat_at=reg), self.NOW, (90, 300))["state"], "offline"); self.assertEqual(ST.endpoint_state(dict(nc, last_heartbeat="garbage", registered_at="garbage"), self.NOW, (90, 300))["state"], "never_connected")
        self.assertEqual(ST.endpoint_state(dict(nc, status="revoked"), self.NOW, (90, 300))["state"], "revoked"); self.assertEqual(ST.endpoint_state(dict(status="revoked", last_heartbeat=self.NOW.strftime(FMT), registered_at=reg), self.NOW, (90, 300))["state"], "revoked")
        self.assertEqual(set(ST.STATES), {"never_connected", "online", "degraded", "offline", "revoked"})
    def test_04_thresholds_configurable_and_strict(self):
        def th(**e):
            with P_env(**e): return ST.thresholds()
        self.assertEqual(th(SOC_AGENT_ONLINE_SECONDS=None, SOC_AGENT_OFFLINE_SECONDS=None), (90, 300)); self.assertEqual(th(SOC_AGENT_ONLINE_SECONDS="30", SOC_AGENT_OFFLINE_SECONDS="120"), (30, 120)); self.assertEqual(th(SOC_AGENT_ONLINE_SECONDS="15", SOC_AGENT_OFFLINE_SECONDS="30"), (15, 30))
        self.assertEqual(th(SOC_AGENT_ONLINE_SECONDS="3600", SOC_AGENT_OFFLINE_SECONDS="86400"), (3600, 86400)); self.assertEqual(th(SOC_AGENT_ONLINE_SECONDS=" 45 "), (45, 300))
        for k, bad in (("SOC_AGENT_ONLINE_SECONDS", "14"), ("SOC_AGENT_ONLINE_SECONDS", "3601"), ("SOC_AGENT_ONLINE_SECONDS", "abc"), ("SOC_AGENT_ONLINE_SECONDS", "3_0"), ("SOC_AGENT_ONLINE_SECONDS", "+30"), ("SOC_AGENT_ONLINE_SECONDS", "30.5"),
                       ("SOC_AGENT_OFFLINE_SECONDS", "29"), ("SOC_AGENT_OFFLINE_SECONDS", "86401"), ("SOC_AGENT_OFFLINE_SECONDS", "x")):
            with self.assertRaises(CFG.ConfigError, msg=(k, bad)) as cm: th(**{k: bad})
            self.assertIn(k, str(cm.exception))
        with self.assertRaises(CFG.ConfigError) as cm: th(SOC_AGENT_ONLINE_SECONDS="300", SOC_AGENT_OFFLINE_SECONDS="300")
        self.assertIn("greater", str(cm.exception))
        with P_env(SOC_AGENT_ONLINE_SECONDS="30", SOC_AGENT_OFFLINE_SECONDS="120"):
            for age, want in ((30, "online"), (31, "degraded"), (120, "degraded"), (121, "offline")):
                a = dict(status="active", registered_at=(self.NOW - timedelta(days=1)).strftime(FMT), last_heartbeat=(self.NOW - timedelta(seconds=age)).strftime(FMT)); self.assertEqual(ST.endpoint_state(a, self.NOW)["state"], want, age)
    def test_05_invalid_threshold_stops_startup(self):
        d = os.path.join(T, "thr"); os.makedirs(d, exist_ok=True); e = {k: v for k, v in os.environ.items() if not k.startswith("SOC_AGENT_")}; e.update(SOC_DB=d + "/s.db", SOC_SECRET="s" * 40, SOC_ALLOW_FOREIGN_DB="1", SOC_LOCAL_LOGS="0", SOC_AGENT_OFFLINE_SECONDS="5")
        r = subprocess.run([sys.executable, "-W", "ignore", "-c", f"import sys; sys.path.insert(0,{ROOT!r}); import app; print('IMPORTED')"], cwd=d, env=e, capture_output=True, text=True, timeout=60)
        self.assertNotEqual(r.returncode, 0); self.assertIn("SOC_AGENT_OFFLINE_SECONDS", r.stderr); self.assertNotIn("IMPORTED", r.stdout)
    def test_06_existing_agent_status_function_is_unchanged(self):
        import fleet; mk = lambda age, **k: dict(dict(status="active", last_heartbeat=(datetime.now() - timedelta(seconds=age)).strftime(FMT), health="{}"), **k)
        self.assertEqual((fleet.agent_status(mk(10)), fleet.agent_status(mk(150)), fleet.agent_status(mk(400)), fleet.agent_status(mk(10, status="revoked"))), ("online", "warning", "offline", "revoked"), "pre-existing vocabulary and thresholds untouched ('warning' = new 'degraded')")
        self.assertEqual((fleet.ONLINE_S, fleet.OFFLINE_S), ST.thresholds())

import contextlib
@contextlib.contextmanager
def P_env(**kw):
    old = {k: os.environ.get(k) for k in kw}
    for k, v in kw.items(): os.environ.pop(k, None) if v is None else os.environ.__setitem__(k, v)
    try: yield
    finally:
        for k, v in old.items(): os.environ.pop(k, None) if v is None else os.environ.__setitem__(k, v)

V4_COLS = ("os_family", "distro_id", "distro_version", "environment", "tags", "first_heartbeat_at")
def degrade_to_v3(path):
    """Make a copy of the database look like it was before migration v4 (no new columns/indexes, v4 not recorded)."""
    c = sqlite3.connect(path)
    for i in ("ix_agents_family", "ix_agents_env", "ix_agents_hb", "ix_alert_agent_ts"): c.execute(f"DROP INDEX IF EXISTS {i}")
    for col in V4_COLS: c.execute(f"ALTER TABLE agents DROP COLUMN {col}")
    c.execute("DELETE FROM schema_migrations WHERE version=4"); c.commit(); c.close()
def copy_main(name):
    p = os.path.join(T, name); s = sqlite3.connect(db.DB); d = sqlite3.connect(p); s.backup(d); s.close(); d.close(); return p
def snap_cols(path, table, cols):
    c = sqlite3.connect(path); c.row_factory = sqlite3.Row
    try: return sorted((tuple(r) for r in c.execute(f"SELECT {','.join(cols)} FROM {table}")), key=repr)
    finally: c.close()

class MigrationV4(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.a1 = Ag("mig-connected", os_family="linux", distro_id="ubuntu"); cls.a2 = Ag("mig-never"); set_times(cls.a1.id, hb=10, reg=7200); set_times(cls.a2.id, hb=3600, reg=3600)   # a2: last_heartbeat == registered_at
        db.x("UPDATE agents SET last_heartbeat=registered_at WHERE id=?", (cls.a2.id,))
    def test_01_fresh_database_is_migrated_at_creation(self):
        p = os.path.join(T, "fresh4.db")
        with use_db(p): db.init_db()
        r = M.inspect(p); self.assertEqual([x["version"] for x in r["recorded"]], [1, 2, 3, 4]); self.assertEqual((r["pending"], r["problems"]), ([], []))
        c = sqlite3.connect(p); self.assertTrue(set(V4_COLS) <= {x[1] for x in c.execute("PRAGMA table_info(agents)")}); self.assertTrue({"ix_agents_family", "ix_agents_env", "ix_agents_hb", "ix_alert_agent_ts"} <= {x[0] for x in c.execute("SELECT name FROM sqlite_master WHERE type='index'")}); c.close()
    def test_02_existing_database_migrates_without_changing_data(self):
        p = copy_main("v3a.db"); degrade_to_v3(p); old_cols = [r[1] for r in sqlite3.connect(p).execute("PRAGMA table_info(agents)")]
        before = {t: snap_cols(p, t, [r[1] for r in sqlite3.connect(p).execute(f"PRAGMA table_info({t})")]) for t in ("agents", "users", "alerts", "events", "agent_event_ids", "event_quarantine")}
        h0 = os.path.getsize(p); pl = M.plan(p); self.assertEqual(pl["pending"], [4]); self.assertEqual(M.apply(p), [4]); self.assertEqual(M.inspect(p)["problems"], [])
        for t, rows in before.items():
            cols = [r[1] for r in sqlite3.connect(p).execute(f"PRAGMA table_info({t})") if r[1] in (old_cols if t == "agents" else [x[1] for x in sqlite3.connect(p).execute(f"PRAGMA table_info({t})")])]
            self.assertEqual(snap_cols(p, t, [r[1] for r in sqlite3.connect(p).execute(f"PRAGMA table_info({t})") if r[1] not in V4_COLS]), rows, t + " unchanged")
        c = sqlite3.connect(p); c.row_factory = sqlite3.Row
        fh = {r["id"]: r["first_heartbeat_at"] for r in c.execute("SELECT id,first_heartbeat_at FROM agents")}; c.close()
        self.assertIsNotNone(fh[self.a1.id], "agent that reported after enrollment: backfilled"); self.assertIsNone(fh[self.a2.id], "never-connected agent stays unset")
        self.assertEqual(M.apply(p), [], "re-run is a no-op"); self.assertEqual(sqlite3.connect(p).execute("PRAGMA integrity_check").fetchone()[0], "ok")
    def test_03_failed_and_killed_migration_leave_the_database_usable(self):
        p = copy_main("v3b.db"); degrade_to_v3(p); orig = list(M.MIGRATIONS)
        def boom(c): c.execute("ALTER TABLE agents ADD COLUMN os_family TEXT"); raise RuntimeError("injected")
        M.MIGRATIONS[3] = orig[3][:3] + (boom,) + orig[3][4:]
        try:
            with self.assertRaises(M.MigrationError): M.apply(p)
        finally: M.MIGRATIONS[:] = orig
        c = sqlite3.connect(p); self.assertNotIn("os_family", {x[1] for x in c.execute("PRAGMA table_info(agents)")}, "rolled back"); self.assertEqual(c.execute("SELECT COUNT(*) FROM schema_migrations WHERE version=4").fetchone()[0], 0); c.close()
        code = (f"import sys,os; sys.path.insert(0,{ROOT!r}); import migrations as M\ndef die(c): c.execute('ALTER TABLE agents ADD COLUMN environment TEXT'); os._exit(5)\nM.MIGRATIONS[3]=M.MIGRATIONS[3][:3]+(die,)+M.MIGRATIONS[3][4:]\nM.apply({p!r})")
        self.assertEqual(subprocess.run([sys.executable, "-c", code]).returncode, 5); c = sqlite3.connect(p); self.assertEqual(c.execute("PRAGMA integrity_check").fetchone()[0], "ok"); self.assertNotIn("environment", {x[1] for x in c.execute("PRAGMA table_info(agents)")}); c.close()
        self.assertEqual(M.apply(p), [4]); self.assertEqual(M.inspect(p)["problems"], [])
    def test_04_missing_column_after_record_is_detected_and_repaired(self):
        p = copy_main("v4rep.db"); c = sqlite3.connect(p); c.execute("DROP INDEX ix_agents_env"); c.commit(); c.close(); self.assertTrue(M.inspect(p)["problems"]); self.assertEqual(M.apply(p), [4]); self.assertEqual(M.inspect(p)["problems"], [])
    def test_05_unmigrated_database_is_not_changed_at_startup_and_apis_say_so(self):
        p = copy_main("v3c.db"); degrade_to_v3(p)
        with use_db(p):
            import io; e = io.StringIO()
            with contextlib.redirect_stderr(e): db.init_db()
            self.assertIn("NOTICE", e.getvalue()); self.assertEqual(M.inspect(p)["recorded"][-1]["version"], 3, "existing database is not migrated implicitly"); self.assertFalse(MON.schema_ready())
            for path in ("/api/monitoring/overview", "/api/monitoring/endpoints", f"/api/monitoring/endpoints/{self.a1.id}"):
                r = get(ADM, path); self.assertEqual(r.status_code, 409, path); self.assertIn("migrate.py", r.get_json()["hint"]); self.assertNotIn("items", r.get_json())
            r = ADM.post(f"/api/monitoring/endpoints/{self.a1.id}/meta", json={"environment": "x"}, headers=H, base_url=BASE); self.assertEqual(r.status_code, 409)
            self.assertEqual(self.a1.hb(os_family="linux", distro_id="ubuntu").status_code, 200, "agents keep working against an unmigrated database")
            self.assertEqual(ADM.get("/api/agents", base_url=BASE, headers=H).status_code, 200, "existing fleet API unaffected")
            self.assertNotIn("os_family", {x[1] for x in sqlite3.connect(p).execute("PRAGMA table_info(agents)")})
            self.assertEqual(Ag("compat-unmigrated", os_family="linux", distro_id="debian").hostname, "compat-unmigrated", "enrollment works too")
    def test_06_existing_migration_tests_see_four_versions(self):
        self.assertEqual(M.LATEST, 4); self.assertEqual([m[1] for m in M.MIGRATIONS][-1], "stage2_endpoint_metadata")

class MonitoringApi(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        mk = lambda host, **p: Ag(host, **p)
        cls.win = mk("win-01", os="Windows", os_version="10.0.19045", os_family="windows"); cls.ub = mk("host-ub1", os_family="linux", distro_id="ubuntu", distro_version="22.04", os="Ubuntu")
        cls.deb = mk("ubuntu-prod-01", os_family="linux", distro_id="debian", distro_version="12", os="Debian GNU/Linux")     # hostname says ubuntu, metadata says debian
        cls.mint = mk("mint-01", os_family="linux", distro_id="linuxmint", distro_version="21", os="Linux Mint"); cls.legU = mk("legacy-u", os="Ubuntu"); cls.legD = mk("legacy-d", os="Debian GNU/Linux")
        cls.unk = mk("ubuntu-lookalike", os="5.4.0-91-generic"); cls.nev = mk("never-1", os_family="linux", distro_id="ubuntu"); cls.rev = mk("revoked-1", os_family="windows", os="Windows")
        cls.deg = mk("degraded-1", os_family="linux", distro_id="debian"); cls.off = mk("offline-1", os_family="windows", os="Windows"); cls.fam = mk("noid-linux", os_family="linux", os="5.15.0")
        for a in (cls.win, cls.ub, cls.deb, cls.mint, cls.legU, cls.legD, cls.unk, cls.fam): set_times(a.id, hb=10, first=ts(3000))
        set_times(cls.nev.id, hb=3600, reg=3600); db.x("UPDATE agents SET last_heartbeat=registered_at WHERE id=?", (cls.nev.id,)); set_times(cls.rev.id, hb=10, first=ts(3000), status="revoked")
        set_times(cls.deg.id, hb=200, first=ts(3000)); set_times(cls.off.id, hb=4000, first=ts(9000)); cls.all = [cls.win, cls.ub, cls.deb, cls.mint, cls.legU, cls.legD, cls.unk, cls.nev, cls.rev, cls.deg, cls.off, cls.fam]
        mkalert(cls.win.id, "High", 120); mkalert(cls.win.id, "High", 90); mkalert(cls.ub.id, "Critical", 60); mkalert(cls.deb.id, "Low", 30); mkalert(cls.win.id, "Medium", 86400 * 3)    # last one outside the default 24 h window
        mkevents(cls.win.id, "win-01", 5, 100); mkevents(cls.ub.id, "host-ub1", 3, 100); mkevents(cls.win.id, "win-01", 2, 86400 * 3)
        db.x("UPDATE agents SET ip='10.1.2.3', ips=? WHERE id=?", (json.dumps(["10.1.2.3", "fe80::1"]), cls.win.id)); db.x("UPDATE agents SET environment='production', tags=? WHERE id=?", (json.dumps(["web", "dmz"]), cls.win.id)); db.x("UPDATE agents SET environment='staging' WHERE id=?", (cls.ub.id,))
    def lst(self, c=None, **q):
        p = dict(limit=200); p.update(q); return get(c or VIE, "/api/monitoring/endpoints?" + "&".join(f"{k}={v}" for k, v in p.items()))
    def test_01_authorization(self):
        anon = A.app.test_client(); aid = self.win.id
        for path in ("/api/monitoring/overview", "/api/monitoring/endpoints", f"/api/monitoring/endpoints/{aid}"): self.assertEqual(get(anon, path).status_code, 401, path)
        self.assertEqual(anon.post(f"/api/monitoring/endpoints/{aid}/meta", json={"environment": "x"}, headers=H, base_url=BASE).status_code, 401)
        for who, c in (("viewer", VIE), ("analyst", ANA), ("admin", ADM)):
            for path in ("/api/monitoring/overview", "/api/monitoring/endpoints", f"/api/monitoring/endpoints/{aid}"): self.assertEqual(get(c, path).status_code, 200, (who, path))
        for who, c in (("viewer", VIE), ("analyst", ANA)): self.assertEqual(c.post(f"/api/monitoring/endpoints/{aid}/meta", json={"environment": "hacked"}, headers=H, base_url=BASE).status_code, 403, who)
        self.assertEqual(db.q("SELECT environment FROM agents WHERE id=?", (aid,), one=True)["environment"], "production", "forbidden edit changed nothing")
        self.assertEqual(ADM.post(f"/api/monitoring/endpoints/{aid}/meta", json={"environment": "production"}, base_url=BASE).status_code, 400, "CSRF guard: X-Requested-With required")
        bearer = A.app.test_client().get("/api/monitoring/endpoints", headers={"Authorization": "Bearer " + self.win.cred, "X-Requested-With": "fetch"}, base_url=BASE); self.assertIn(bearer.status_code, (401, 403), "an agent credential is not a user session")
    def test_02_classification_in_the_api(self):
        by = lambda os_: {i["hostname"] for i in self.lst(os=os_).get_json()["items"] if i["id"] in {a.id for a in self.all}}
        self.assertEqual(by("ubuntu"), {"host-ub1", "legacy-u", "never-1"}, "Ubuntu tab: verified ubuntu ids and the legacy exact-name case only"); self.assertEqual(by("windows"), {"win-01", "revoked-1", "offline-1"})
        self.assertEqual(by("linux"), {"ubuntu-prod-01", "mint-01", "legacy-d", "degraded-1", "noid-linux"}, "other distributions; the host NAMED ubuntu-prod-01 is Debian; Mint is not Ubuntu"); self.assertEqual(by("unknown"), {"ubuntu-lookalike"}, "hostname-lookalike with no metadata stays unknown")
        it = {i["hostname"]: i for i in self.lst().get_json()["items"]}
        self.assertEqual((it["host-ub1"]["classified_by"], it["legacy-u"]["classified_by"], it["noid-linux"]["distro_id"], it["noid-linux"]["classified_by"], it["win-01"]["distro_id"]), ("os_release_id", "legacy_os_name", "unknown", "family_only", None))
        self.assertEqual(it["ubuntu-lookalike"]["os_class"], "unknown"); self.assertEqual(it["ubuntu-prod-01"]["distro_version"], "12")
        self.assertEqual(sum(len(by(c)) for c in ("ubuntu", "windows", "linux", "unknown")), len(self.all), "every endpoint is in exactly one section")
    def test_03_states_in_the_api(self):
        st = {i["hostname"]: i["state"] for i in self.lst().get_json()["items"]}
        self.assertEqual((st["win-01"], st["never-1"], st["revoked-1"], st["degraded-1"], st["offline-1"]), ("online", "never_connected", "revoked", "degraded", "offline"))
        r = {i["hostname"]: i for i in self.lst().get_json()["items"]}; self.assertIn("no heartbeat", r["offline-1"]["state_reason"]); self.assertIn("enrolled", r["never-1"]["state_reason"]); self.assertEqual(set(self.lst(state="never_connected,revoked").get_json()["items"][i]["state"] for i in range(self.lst(state="never_connected,revoked").get_json()["total"])), {"never_connected", "revoked"})
    def test_04_overview_matches_the_data(self):
        o = get(VIE, "/api/monitoring/overview").get_json(); items = self.lst().get_json()["items"]
        self.assertEqual(o["totals"]["endpoints"], len(items)); self.assertEqual(sum(o["totals"]["by_state"].values()), len(items))
        for c in ("windows", "linux", "ubuntu", "unknown"): self.assertEqual(o["classes"][c]["total"], sum(1 for i in items if i["os_class"] == c), c); self.assertEqual(sum(o["classes"][c]["by_state"].values()), o["classes"][c]["total"])
        self.assertEqual(o["classes"]["windows"]["alerts_in_window"].get("High"), 2); self.assertEqual(o["classes"]["ubuntu"]["alerts_in_window"].get("Critical"), 1); self.assertNotIn("Medium", o["classes"]["windows"]["alerts_in_window"], "3-day-old alert is outside the 24 h window")
        self.assertEqual(o["classes"]["windows"]["events_in_window"], 5); self.assertEqual(o["classes"]["ubuntu"]["events_in_window"], 3)
        self.assertEqual(o["thresholds"]["online_seconds"], 90); self.assertEqual(o["thresholds"]["offline_seconds"], 300); self.assertEqual(o["cloud"], dict(state="NOT_CONFIGURED", implemented=False, connectors=0, message=o["cloud"]["message"])); self.assertIn("No cloud", o["cloud"]["message"])
        o7 = get(VIE, "/api/monitoring/overview?since=7d").get_json(); self.assertEqual(o7["classes"]["windows"]["alerts_in_window"].get("Medium"), 1); self.assertEqual(o7["classes"]["windows"]["events_in_window"], 7)
    def test_05_empty_database_shows_honest_empty_states(self):
        p = copy_main("empty.db"); c = sqlite3.connect(p)
        for t in ("agents", "alerts", "events", "agent_heartbeats", "agent_credentials"): c.execute(f"DELETE FROM {t}")
        c.commit(); c.close()
        with use_db(p):
            o = get(VIE, "/api/monitoring/overview").get_json(); self.assertEqual(o["totals"]["endpoints"], 0); self.assertTrue(all(v["total"] == 0 and v["events_in_window"] == 0 and v["alerts_in_window"] == {} for v in o["classes"].values())); self.assertEqual(o["cloud"]["state"], "NOT_CONFIGURED")
            e = self.lst().get_json(); self.assertEqual((e["total"], e["items"]), (0, []))
    def test_06_filters(self):
        w = self.win.id
        self.assertEqual(ids(self.lst(q="WIN-0")) & {a.id for a in self.all}, {w}, "hostname substring, case-insensitive"); self.assertEqual(ids(self.lst(q="ubuntu")) & {a.id for a in self.all}, {self.deb.id, self.unk.id}, "q matches hostnames only: not classification")
        self.assertEqual(ids(self.lst(ip="10.1.2.3")) & {a.id for a in self.all}, {w}); self.assertEqual(ids(self.lst(ip="fe80:0:0:0:0:0:0:1")) & {a.id for a in self.all}, {w}, "IPv6 normalised"); self.assertEqual(ids(self.lst(ip="10.1.2.4")) & {a.id for a in self.all}, set())
        self.assertEqual(ids(self.lst(severity="High")) & {a.id for a in self.all}, {w}); self.assertEqual(ids(self.lst(severity="critical")) & {a.id for a in self.all}, {self.ub.id}); self.assertEqual(ids(self.lst(severity="Medium")) & {a.id for a in self.all}, set(), "outside the default window")
        self.assertEqual(ids(self.lst(severity="Medium", since="7d")) & {a.id for a in self.all}, {w}); self.assertEqual(ids(self.lst(env="Production")) & {a.id for a in self.all}, {w}); self.assertEqual(ids(self.lst(tag="dmz")) & {a.id for a in self.all}, {w})
        self.assertEqual(ids(self.lst(os="windows", state="online", severity="High", env="production", tag="web", ip="10.1.2.3", q="win")) & {a.id for a in self.all}, {w}, "all filters combine (AND)"); self.assertEqual(ids(self.lst(os="ubuntu", severity="High")) & {a.id for a in self.all}, set())
        x = self.lst(since="2020-01-01", until="2020-01-02").get_json(); self.assertTrue(all(i["alerts_in_window"]["total"] == 0 and i["events_in_window"] == 0 for i in x["items"]), "explicit absolute window")
        j = self.lst(limit=3, offset=0).get_json(); k = self.lst(limit=3, offset=3).get_json(); self.assertEqual((len(j["items"]), j["total"]), (3, len(self.lst().get_json()["items"]))); self.assertFalse({i["id"] for i in j["items"]} & {i["id"] for i in k["items"]})
        names = [i["hostname"].lower() for i in self.lst(sort="hostname").get_json()["items"]]; self.assertEqual(names, sorted(names)); s = [i["state"] for i in self.lst(sort="state").get_json()["items"]]; self.assertEqual(s, sorted(s, key=ST.STATES.index))
        self.assertEqual(self.lst(sort="alerts").get_json()["items"][0]["id"], w)
    def test_07_invalid_input_is_rejected_not_executed(self):
        evil = ["os=windows' OR '1'='1", "os=foo", "state=bad", "state=online,bad", "state=a,b,c,d,e,f", "ip=999.1.1.1", "ip=10.0.0.1;DROP", "severity=Severe", "since=yesterday", "since=24x", "until=2020-13-45", "limit=abc", "offset=-1", "sort=password", f"q={'x' * 101}", "env=%3Cscript%3E", "tag=UPPER%20CASE", "since=2020-01-02&until=2020-01-01", "since=2000-01-01&until=2026-01-01", "since=99999d"]
        for qs in evil: self.assertEqual(get(VIE, "/api/monitoring/endpoints?" + qs).status_code, 400, qs)
        self.assertEqual(get(VIE, "/api/monitoring/overview?since=bad").status_code, 400); self.assertEqual(get(VIE, f"/api/monitoring/endpoints/{self.win.id}?since=bad").status_code, 400)
        self.assertEqual(get(VIE, "/api/monitoring/endpoints?q=%27%3B%20DROP%20TABLE%20agents%3B--").status_code, 200, "q is matched in code, never placed in SQL"); self.assertGreaterEqual(count("SELECT COUNT(*) n FROM agents"), len(self.all))
        self.assertEqual(self.lst(limit=100000).get_json()["limit"], 200, "limit is capped")
    def test_07b_truncation_is_reported_not_silent(self):
        o, e = get(VIE, "/api/monitoring/overview").get_json(), self.lst().get_json(); self.assertEqual((o["truncated"], e["truncated"]), (False, False))
        old = MON.MAX_AGENTS; MON.MAX_AGENTS = 5
        try: o, e = get(VIE, "/api/monitoring/overview").get_json(), self.lst().get_json()
        finally: MON.MAX_AGENTS = old
        self.assertEqual((o["truncated"], e["truncated"], o["max_endpoints"], o["totals"]["endpoints"], len(e["items"])), (True, True, 5, 5, 5))
    def test_08_detail(self):
        r = get(VIE, f"/api/monitoring/endpoints/{self.win.id}").get_json(); self.assertEqual((r["hostname"], r["os_class"], r["environment"], r["tags"]), ("win-01", "windows", "production", ["web", "dmz"])); self.assertTrue({"heartbeats", "alerts", "events_in_window", "state_reason"} <= set(r)); self.assertEqual(len(r["alerts"]), 3)
        self.assertEqual(get(VIE, "/api/monitoring/endpoints/ag-doesnotexist").status_code, 404)
        for banned in ("credential", "secret", "sign_key", "secret_hash", "token"): self.assertNotIn(banned, json.dumps(r).lower(), "no credential material in API output")
    def test_09_metadata_edit_is_validated_and_audited(self):
        a = Ag("meta-1", os_family="linux", distro_id="debian"); path = f"/api/monitoring/endpoints/{a.id}/meta"; post = lambda b: ADM.post(path, json=b, headers=H, base_url=BASE)
        n0 = count("SELECT COUNT(*) n FROM audit"); r = post({"environment": " Production-EU ", "tags": ["Web", "web", "dmz", "role:db"]}); self.assertEqual((r.status_code, r.get_json()["environment"], r.get_json()["tags"]), (200, "Production-EU", ["web", "dmz", "role:db"]), "trimmed, lower-cased, de-duplicated")
        au = db.q("SELECT * FROM audit ORDER BY id DESC LIMIT 1", one=True); self.assertEqual(count("SELECT COUNT(*) n FROM audit"), n0 + 1); self.assertIn("Endpoint metadata updated", au["action"]); self.assertIn(a.id, au["action"]); self.assertIn("Production-EU", au["action"]); self.assertEqual(au["user"] if "user" in au.keys() else au["username"], P.ADMIN["username"])
        self.assertEqual(post({"tags": ["only"]}).get_json()["environment"], "Production-EU", "omitted field is left alone"); self.assertEqual(row(a.id)["tags"], json.dumps(["only"]))
        r = post({"environment": ""}); self.assertEqual(r.get_json()["environment"], None); self.assertIsNone(row(a.id)["environment"]); r = post({"tags": None}); self.assertEqual(r.get_json()["tags"], [])
        for bad in ({}, [], "x", {"environment": "<script>"}, {"environment": "x" * 33}, {"environment": 5}, {"environment": "-lead"}, {"tags": "web"}, {"tags": ["a"] * 11 and [str(i) for i in range(11)]}, {"tags": ["bad tag"]}, {"tags": [1]}, {"tags": [""]}, {"tags": ["x" * 33]}, {"tags": [{"a": 1}]}, {"unrelated": 1}):
            before = row(a.id); self.assertEqual(post(bad).status_code, 400, bad); self.assertEqual(row(a.id)["tags"], before["tags"])
        self.assertEqual(count("SELECT COUNT(*) n FROM audit"), n0 + 4, "rejected edits are not audited as changes"); self.assertEqual(ADM.post("/api/monitoring/endpoints/ag-nope/meta", json={"environment": "x"}, headers=H, base_url=BASE).status_code, 404)
    def test_10_heartbeat_and_registration_metadata(self):
        a = Ag("hb-1", os_family="linux", distro_id="ubuntu", distro_version="24.04"); r = row(a.id); self.assertEqual((r["os_family"], r["distro_id"], r["distro_version"], r["first_heartbeat_at"]), ("linux", "ubuntu", "24.04", None))
        db.x("UPDATE agents SET registered_at=?,last_heartbeat=? WHERE id=?", (ts(600), ts(600), a.id)); self.assertEqual(self.lst(q="hb-1").get_json()["items"][0]["state"], "never_connected")
        self.assertEqual(a.hb().status_code, 200); r1 = row(a.id); self.assertIsNotNone(r1["first_heartbeat_at"]); self.assertEqual((r1["os_family"], r1["distro_id"]), ("linux", "ubuntu"), "a legacy-style heartbeat (no OS fields) does not erase stored metadata")
        self.assertEqual(self.lst(q="hb-1").get_json()["items"][0]["state"], "online"); time.sleep(1.1); a.hb(distro_id="ubuntu'; DROP TABLE agents; --", os_family="plan9", distro_version="x" * 99); r2 = row(a.id)
        self.assertEqual((r2["first_heartbeat_at"], r2["distro_id"], r2["os_family"], r2["distro_version"]), (r1["first_heartbeat_at"], "ubuntu", "linux", "24.04"), "first heartbeat time is kept; invalid values ignored")
        a.hb(distro_id="debian", distro_version="12"); self.assertEqual(row(a.id)["distro_id"], "debian", "a valid update (distribution changed) is accepted"); self.assertEqual(self.lst(q="hb-1").get_json()["items"][0]["os_class"], "linux")
        old = Ag("legacy-reg"); r = row(old.id); self.assertEqual((r["os_family"], r["distro_id"]), (None, None), "agent protocol compatibility: old agents register without the new fields")
        g = Ag("garbage-reg", os_family={"x": 1}, distro_id=["a"], distro_version=12); r = row(g.id); self.assertEqual((r["os_family"], r["distro_id"], r["distro_version"]), (None, None, None))
    def test_11_existing_pages_and_apis_unchanged(self):
        r = ADM.get("/api/agents", base_url=BASE, headers=H); self.assertEqual(r.status_code, 200); one = [x for x in r.get_json() if x["hostname"] == "win-01"][0]; self.assertEqual(one["state"], "online"); self.assertIn("health", one)
        for path in ("/fleet", "/endpoints", "/alerts", "/"): self.assertEqual(ADM.get(path, base_url=BASE).status_code, 200, path)
    def test_12_page_navigation_and_assets(self):
        r = ADM.get("/monitoring-center", base_url=BASE); self.assertEqual(r.status_code, 200); html = r.get_data(as_text=True); self.assertIn("/monitoring-center", html); self.assertIn("Monitoring Center", html); self.assertIn("/static/monitoring.js", html)
        anon = A.app.test_client().get("/monitoring-center", base_url=BASE); self.assertIn(anon.status_code, (301, 302, 401)); js = ADM.get("/static/monitoring.js", base_url=BASE); self.assertEqual(js.status_code, 200)
        src = open(ROOT + "/static/monitoring.js", encoding="utf-8").read()
        for tab in ("Overview", "Windows", "Linux", "Ubuntu", "Cloud"): self.assertIn(f"'{tab}'", src)
        import re as _re; self.assertEqual(_re.findall(r"\son[a-z]+=\\?[\"']", src), [], "no inline event-handler attributes in generated HTML (CSP)")
        for banned in ("javascript:", "eval(", "document.write", "Function("): self.assertNotIn(banned, src, banned)
        self.assertIn("window.SOCX_FLEET.detail", src); self.assertIn("window.SOCX_FLEET={detail}", open(ROOT + "/static/fleet.js", encoding="utf-8").read())
        self.assertNotIn("setInterval(()=>{if(!document.hidden&&$('#drawer').hidden&&$('#mc_body'))show", "x"); self.assertIn("document.hidden", src)
        if shutil.which("node"): self.assertEqual(subprocess.run(["node", "--check", ROOT + "/static/monitoring.js"]).returncode, 0)
        else: self.skipTest("node not installed: JavaScript syntax not machine-checked")
        for k in ("NOT_CONFIGURED",): self.assertNotIn("Connected", src.replace("Never connected", ""), "no hardcoded success state in the UI")
if __name__ == "__main__": unittest.main(verbosity=1)
