"""Phase 2 retention/replay review. Deterministic clock (ledger ages are set directly, no sleeps), temp DBs, synthetic events.
Run: python tests/test_retention_review.py"""
import os, sys, json, time, sqlite3, hashlib, threading, subprocess, unittest, io, contextlib
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import test_phase1_review as P                     # shared harness: temp DB, signed Agent client, ev(), child(); importing runs no tests of that module
from test_phase1_review import db, A, engine, FA, AG, Agent, ev, count, ledger, ALERT_MSG, ROOT, T, new_queue, st
import migrations as M, dbbackup as B
from datetime import datetime, timedelta
FMT = "%Y-%m-%d %H:%M:%S"; ISO = "%Y-%m-%dT%H:%M:%S"
def ago(days, **k): return (datetime.utcnow() - timedelta(days=days, **k)).strftime(ISO)
def age_ledger(aid, days): db.x("UPDATE agent_event_ids SET ts=? WHERE agent_id=? AND status='processed'", ((datetime.now() - timedelta(days=days)).strftime(FMT), aid))
def alerts_of(a): return count("SELECT COUNT(*) n FROM alerts WHERE endpoint_id=(SELECT endpoint_id FROM agents WHERE id=?)", a.id)
def events_of(host): return count("SELECT COUNT(*) n FROM events WHERE host=?", host)
def env(**kw):
    class Ctx:
        def __enter__(s): s.old = {k: os.environ.get(k) for k in kw}; [os.environ.__setitem__(k, v) if v is not None else os.environ.pop(k, None) for k, v in kw.items()]
        def __exit__(s, *a): [os.environ.__setitem__(k, v) if v is not None else os.environ.pop(k, None) for k, v in s.old.items()]
    return Ctx()
def quiet(f, *a, **k):
    o = io.StringIO()
    with contextlib.redirect_stdout(o): r = f(*a, **k)
    return r, o.getvalue()

class Config(unittest.TestCase):
    def test_01_default_range_and_strict_validation(self):
        with env(SOC_DEDUP_RETENTION_DAYS=None): self.assertEqual(FA.dedup_days(), 30)
        with env(SOC_DEDUP_RETENTION_DAYS=""): self.assertEqual(FA.dedup_days(), 30)
        for ok in ("7", "30", "90", "3650"):
            with env(SOC_DEDUP_RETENTION_DAYS=ok): self.assertEqual(FA.dedup_days(), int(ok))
        for bad in ("6", "1", "0", "-5", "3651", "abc", "30.5", "1e2", "14 days"):
            with env(SOC_DEDUP_RETENTION_DAYS=bad):
                with self.assertRaises(FA.ConfigError, msg=bad) as cm: FA.dedup_days()
                self.assertIn("SOC_DEDUP_RETENTION_DAYS", str(cm.exception)); self.assertIn("7", str(cm.exception))
    def test_02_stale_guard_is_off_by_default_and_strict(self):
        with env(SOC_REJECT_STALE_EVENTS=None): self.assertFalse(FA.stale_guard_on())
        with env(SOC_REJECT_STALE_EVENTS="0"): self.assertFalse(FA.stale_guard_on())
        with env(SOC_REJECT_STALE_EVENTS="1"): self.assertTrue(FA.stale_guard_on())
        for bad in ("true", "yes", "2", "on"):
            with env(SOC_REJECT_STALE_EVENTS=bad):
                with self.assertRaises(FA.ConfigError): FA.stale_guard_on()
    def test_03_startup_validation_fails_clearly(self):
        r = subprocess.run([sys.executable, "-c", f"import sys; sys.path.insert(0,{ROOT!r}); import fleet.config as C; C.validate_config()"], env=dict(os.environ, SOC_DEDUP_RETENTION_DAYS="3"), capture_output=True, text=True)
        self.assertNotEqual(r.returncode, 0); self.assertIn("SOC_DEDUP_RETENTION_DAYS", r.stderr)
        r = subprocess.run([sys.executable, "-c", f"import sys; sys.path.insert(0,{ROOT!r}); import fleet.config as C; C.validate_config(); print('ok')"], env={k: v for k, v in os.environ.items() if k not in ("SOC_DEDUP_RETENTION_DAYS", "SOC_REJECT_STALE_EVENTS")}, capture_output=True, text=True); self.assertIn("ok", r.stdout)

class Lifecycle(unittest.TestCase):
    def test_01_boundaries_with_the_default_window(self):
        a = Agent("r-bound"); now_dt = datetime.now().replace(microsecond=0); cut = now_dt - timedelta(days=30); c = db.conn()
        for k, t in (("before", cut - timedelta(seconds=1)), ("at", cut), ("after", cut + timedelta(seconds=1))): c.execute("INSERT INTO agent_event_ids(agent_id,uid,ts,status) VALUES(?,?,?,'processed')", (a.id, "rb-" + k, t.strftime(FMT)))
        c.commit(); c.close(); self.assertEqual(FA.purge_dedup(now_dt=now_dt), 1); self.assertEqual({r["uid"] for r in db.q("SELECT uid FROM agent_event_ids WHERE agent_id=?", (a.id,))}, {"rb-at", "rb-after"})
    def test_02_offline_agent_delivery_and_replay_before_and_after_cleanup(self):
        a = Agent("r-offline"); old = ago(20); al = ev(1, ALERT_MSG, log_only=False, event_time=old); be = ev(2, "benign delayed event", log_only=False, event_time=old)
        j = a.post("/api/events", {"events": [al, be]}).json(); self.assertEqual(sorted(j["accepted_uids"]), sorted([al["uid"], be["uid"]]), "a legitimately delayed (20 day old) event is accepted by default")
        n_ev, n_al = events_of("r-offline"), alerts_of(a)
        self.assertEqual(sorted(a.post("/api/events", {"events": [al, be]}).json()["duplicate_uids"]), sorted([al["uid"], be["uid"]]), "repeat before cleanup -> ledger duplicate")
        age_ledger(a.id, 29); FA.purge_dedup(); self.assertEqual(ledger(a.id, al["uid"])[0], "processed", "29 days old: still inside the 30 day window")
        age_ledger(a.id, 31); FA.purge_dedup(); self.assertIsNone(ledger(a.id, al["uid"]), "31 days: ledger record purged")
        calls = {"n": 0}; real = engine._detect
        def counting(*x, **k): calls["n"] += 1; return real(*x, **k)
        engine._detect = counting
        try: j = a.post("/api/events", {"events": [al, be]}).json()
        finally: engine._detect = real
        self.assertEqual(sorted(j["accepted_uids"]), sorted([al["uid"], be["uid"]]), "ledger no longer vouches -> processed again (documented)")
        self.assertEqual((events_of("r-offline"), alerts_of(a)), (n_ev, n_al), "but no duplicate event row and no duplicate alert (events row + alert link survive)")
        self.assertEqual(calls["n"], 1, "documented limitation: the benign replay is re-run through detection once; the alerting one is not (it is linked to its alert)")
    def test_03_agent_queue_with_lost_ack_survives_restart_and_purge(self):
        a = Agent("r-queue"); q = new_queue(); e = ev(1, ALERT_MSG, log_only=False, event_time=ago(3)); q.add([e]); a.post("/api/events", {"events": [e]})      # server processed it; the ack was 'lost'
        q.hold([e["uid"]], 600); q.db.close(); q2 = AG.Queue(); self.assertEqual((q2.count(), q2.held()), (1, 1)); n_ev, n_al = events_of("r-queue"), alerts_of(a)
        age_ledger(a.id, 40); FA.purge_dedup(); q2.db.execute("UPDATE q SET hold_until=0"); q2.db.commit(); AG.flush_queue(a, q2, st())
        self.assertEqual(q2.count(), 0, "agent finally gets an accepted ack and drains"); self.assertEqual((events_of("r-queue"), alerts_of(a)), (n_ev, n_al))
    def test_04_modified_timestamp_replays(self):
        a = Agent("r-mod"); e = ev(1, ALERT_MSG, log_only=False, event_time=ago(5)); a.post("/api/events", {"events": [e]}); n_ev = events_of("r-mod")
        m = dict(e, event_time=ago(4)); self.assertEqual(a.post("/api/events", {"events": [m]}).json()["duplicate_uids"], [e["uid"]], "inside the window the ledger keys on uid, so a changed timestamp is still a duplicate")
        self.assertEqual(events_of("r-mod"), n_ev)
        age_ledger(a.id, 31); FA.purge_dedup(); j = a.post("/api/events", {"events": [m]}).json(); self.assertEqual(j["accepted_uids"], [e["uid"]])
        self.assertEqual(events_of("r-mod"), n_ev + 1, "VERIFIED LIMITATION: after the window a replay with a modified timestamp is a new event (unique index includes the timestamp)")
        u2 = dict(e, uid="x" * 40); age_ledger(a.id, 31); FA.purge_dedup(); a.post("/api/events", {"events": [u2]}); self.assertEqual(events_of("r-mod"), n_ev + 1, "a changed uid with the SAME timestamp is caught by the unique index")
    def test_05_replay_beyond_event_retention_can_duplicate_alert(self):
        a = Agent("r-gap"); e = ev(1, ALERT_MSG, log_only=False, event_time=ago(1)); a.post("/api/events", {"events": [e]}); self.assertEqual(alerts_of(a), 1)
        db.x("DELETE FROM events WHERE host='r-gap'"); db.x("UPDATE alerts SET updated='2020-01-01 00:00:00' WHERE endpoint_id=(SELECT endpoint_id FROM agents WHERE id=?)", (a.id,)); age_ledger(a.id, 31); FA.purge_dedup()
        a.post("/api/events", {"events": [e]}); self.assertEqual(events_of("r-gap"), 1); self.assertEqual(alerts_of(a), 2, "VERIFIED LIMITATION: once BOTH the ledger record and the events row are gone (event retention job), a replay raises a new alert")
    def test_06_clock_skew_and_stale_guard(self):
        a = Agent("r-skew"); ok, bad = ev(1, event_time=(datetime.utcnow() + timedelta(minutes=9)).strftime(ISO)), ev(2, event_time=(datetime.utcnow() + timedelta(minutes=11)).strftime(ISO))
        j = a.post("/api/events", {"events": [ok, bad]}).json(); self.assertEqual((j["accepted_uids"], j["reasons"][bad["uid"]]), ([ok["uid"]], "timestamp_in_future"))
        e28, e30, lie = ev(3, event_time=ago(28)), ev(4, event_time=ago(30)), ev(5, event_time=ago(0))
        with env(SOC_REJECT_STALE_EVENTS="1"):
            j = a.post("/api/events", {"events": [e28, e30, lie]}).json()
            self.assertEqual(sorted(j["accepted_uids"]), sorted([e28["uid"], lie["uid"]])); self.assertEqual(j["reasons"][e30["uid"]], "timestamp_too_old")
            self.assertEqual(count("SELECT COUNT(*) n FROM event_quarantine WHERE uid=?", e30["uid"]), 1, "refused events are kept (quarantine), never silently dropped")
        e31 = ev(6, event_time=ago(40)); self.assertEqual(a.post("/api/events", {"events": [e31]}).json()["accepted_uids"], [e31["uid"]], "guard off (default): a 40 day old legitimate event is accepted")
    def test_07_evidence_survives_cleanup_and_only_processed_rows_are_purged(self):
        a = Agent("r-evid"); a.post("/api/events", {"events": [ev(1, ALERT_MSG, log_only=False), dict(ev(2), message="")]}); c = db.conn()
        for u, s_ in (("dead1", "dead"), ("pend1", "pending"), ("proc1", "processing")): c.execute("INSERT INTO agent_event_ids(agent_id,uid,ts,status) VALUES(?,?,'2000-01-01 00:00:00',?)", (a.id, u, s_))
        c.execute("INSERT INTO incidents(title,severity,status,created) VALUES('t','High','Open',?)", (db.now(),)) if "created" in {r[1] for r in c.execute("PRAGMA table_info(incidents)")} else None; c.commit(); c.close()
        tabs = ("event_quarantine", "alerts", "incidents", "incident_alerts", "audit", "cases", "events", "users")
        h = lambda: {t: hashlib.sha256(repr(sorted((tuple(r) for r in db.conn().execute(f"SELECT * FROM {t}").fetchall()), key=repr)).encode()).hexdigest() for t in tabs}
        before = h(); self.assertGreaterEqual(FA.purge_dedup(now_dt=datetime.now() + timedelta(days=3000)), 1); self.assertEqual(h(), before, "quarantine/alerts/incidents/audit/events untouched by dedupe cleanup")
        self.assertEqual({r["uid"] for r in db.q("SELECT uid FROM agent_event_ids WHERE agent_id=? AND status<>'processed'", (a.id,))}, {"dead1", "pend1", "proc1"} | {r["uid"] for r in db.q("SELECT uid FROM agent_event_ids WHERE agent_id=? AND status='dead'", (a.id,))})

class CleanupSafety(unittest.TestCase):
    def test_01_cleanup_keeps_up_with_ingestion_volume(self):
        a = Agent("c-volume"); c = db.conn(); old = (datetime.now() - timedelta(days=60)).strftime(FMT)
        c.executemany("INSERT INTO agent_event_ids(agent_id,uid,ts,status) VALUES(?,?,?,'processed')", [(a.id, f"vol-{i}", old) for i in range(30000)]); c.commit(); c.close()
        FA._last_purge[0] = 0; FA.maybe_purge(sync=True)
        self.assertEqual(count("SELECT COUNT(*) n FROM agent_event_ids WHERE agent_id=?", a.id), 0, "one scheduled run clears a backlog far larger than one batch (was: 5000 per 10 minutes = ~8 events/s ceiling)")
        c = db.conn(); c.executemany("INSERT INTO agent_event_ids(agent_id,uid,ts,status) VALUES(?,?,?,'processed')", [(a.id, f"cap-{i}", old) for i in range(100)]); c.commit(); c.close()
        self.assertEqual(FA.purge_dedup(limit=10, max_batches=2), 20, "bounded: at most limit x max_batches rows per call"); self.assertEqual(FA.purge_dedup(limit=10, max_batches=100), 80)
    def test_02_busy_database_is_reported_not_swallowed_and_nothing_is_deleted(self):
        a = Agent("c-busy"); c = db.conn(); c.execute("INSERT INTO agent_event_ids(agent_id,uid,ts,status) VALUES(?,?,?,'processed')", (a.id, "busy-1", "2000-01-01 00:00:00")); c.commit(); c.close()
        lock = sqlite3.connect(db.DB, timeout=5, isolation_level=None); lock.execute("BEGIN IMMEDIATE")
        try:
            with env(SOC_DB_TIMEOUT="0.2"): n, out = quiet(FA.purge_dedup)
        finally: lock.execute("ROLLBACK"); lock.close()
        self.assertEqual(n, 0); self.assertIn("busy", out.lower()); self.assertIn("busy", (FA.last_purge["error"] or "").lower()); self.assertIsNotNone(ledger(a.id, "busy-1"))
        self.assertGreaterEqual(FA.purge_dedup(), 1); self.assertIsNone(FA.last_purge["error"], "a later successful run clears the error"); self.assertIsNone(ledger(a.id, "busy-1"))
    def test_03_runtime_config_error_is_logged_and_recorded(self):
        with env(SOC_DEDUP_RETENTION_DAYS="3"):
            FA._last_purge[0] = 0; _, out = quiet(FA.maybe_purge, True)
            self.assertIn("SOC_DEDUP_RETENTION_DAYS", out); self.assertIn("SOC_DEDUP_RETENTION_DAYS", FA.last_purge["error"] or "")
    def test_04_cleanup_concurrent_with_ingestion_loses_nothing(self):
        a = Agent("c-conc"); stop = threading.Event(); errs = []; deleted = [0]
        def cleaner():
            while not stop.is_set():
                try: deleted[0] += FA.purge_dedup(now_dt=datetime.now() + timedelta(days=400), limit=25)         # aggressive: even fresh 'processed' rows are expired
                except Exception as e: errs.append(repr(e))
        th = threading.Thread(target=cleaner); th.start(); outs = []
        try:
            for b in range(10): outs.append(a.post("/api/events", {"events": [ev(100 * b + i, f"conc {b}-{i}") for i in range(20)]}).json())
        finally: stop.set(); th.join()
        self.assertEqual(errs, []); self.assertEqual(sum(len(o["accepted_uids"]) for o in outs), 200); self.assertEqual(events_of("c-conc"), 200, "every event stored exactly once while cleanup hammered the ledger")
        self.assertEqual(count("SELECT COUNT(*) n FROM agent_event_ids WHERE agent_id=? AND status IN ('processing','pending')", a.id), 0)
    def test_05_interrupted_cleanup_rolls_back_and_recovers(self):
        a = Agent("c-kill"); c = db.conn(); old = (datetime.now() - timedelta(days=60)).strftime(FMT)
        c.executemany("INSERT INTO agent_event_ids(agent_id,uid,ts,status) VALUES(?,?,?,'processed')", [(a.id, f"kill-{i}", old) for i in range(300)]); c.commit(); c.close()
        code = (f"import os,sys,sqlite3; sys.path.insert(0,{ROOT!r}); sys.path.insert(0,{ROOT + '/tests'!r}); import test_phase1_review as P; import fleet.api as FA\n"
                "class K(sqlite3.Connection):\n    def commit(self): os._exit(7)          # the process dies at COMMIT time of the first purge batch\n"
                "FA.conn = lambda: sqlite3.connect(P.db.DB, timeout=5, factory=K); FA.purge_dedup(limit=100, max_batches=3)")
        r = subprocess.run([sys.executable, "-W", "ignore", "-c", code], env=os.environ.copy(), capture_output=True, text=True, timeout=120); self.assertEqual(r.returncode, 7, r.stderr[-300:])
        self.assertEqual(count("SELECT COUNT(*) n FROM agent_event_ids WHERE agent_id=?", a.id), 300, "killed mid-batch: nothing half-deleted"); self.assertEqual(db.conn().execute("PRAGMA integrity_check").fetchone()[0], "ok")
        self.assertEqual(FA.purge_dedup(limit=1000, max_batches=2), 300); e = ev(9, "after restart"); self.assertEqual(a.post("/api/events", {"events": [e]}).json()["accepted_uids"], [e["uid"]], "ingestion works after the interrupted cleanup")
    def test_06_backup_restore_roundtrip_keeps_retention_state(self):
        a = Agent("c-bk"); a.post("/api/events", {"events": [ev(1, ALERT_MSG, log_only=False), dict(ev(2), message="")]}); o = B.create(db.DB, T + "/rbk"); dest = T + "/rbk-restored.db"; B.restore(o["path"], dest)
        c1, c2 = sqlite3.connect(db.DB), sqlite3.connect(dest)
        for t in ("agent_event_ids", "event_quarantine", "alerts", "events"): self.assertEqual(c1.execute(f"SELECT COUNT(*) FROM {t}").fetchone(), c2.execute(f"SELECT COUNT(*) FROM {t}").fetchone(), t)
        c1.close(); c2.close(); r = M.inspect(dest); self.assertEqual((r["pending"], r["problems"], r["too_new"]), ([], [], []), "restored database is schema-compatible with this version")
        old = db.DB; db.DB = dest
        try: self.assertGreaterEqual(FA.purge_dedup(now_dt=datetime.now() + timedelta(days=400)), 1)
        finally: db.DB = old

def wire(collector_event, agent_id="ag-uid-test"):
    """What a real agent sends: the collector event passed through the real AG.to_event()."""
    return AG.to_event(dict(collector_event), agent_id)
def formula(agent_id, e): return hashlib.sha256(f"{agent_id}|{e.get('channel')}|{e.get('record_id')}|{e.get('event_time')}|{(e.get('message') or '')[:200]}".encode()).hexdigest()[:40]

class UidProtocol(unittest.TestCase):
    """FACTS under test: the UID is made by the AGENT; the server checks only its format (1-80 chars, no control characters) and never recomputes it from the payload."""
    base = dict(channel="Security", record_id=424242, event_time="2026-10-01T10:00:00", message="user bob logged in from 10.0.0.5", log_only=False)
    def test_01_agent_uid_formula_is_exactly_as_documented(self):
        e = dict(self.base); self.assertEqual(wire(e)["uid"], formula("ag-uid-test", e)); self.assertEqual(wire(e)["uid"], wire(dict(e))["uid"], "stable: the same collector event always gets the same uid")
        for k, v in (("channel", "System"), ("record_id", 1), ("event_time", "2026-10-01T10:00:01"), ("message", "different")): self.assertNotEqual(wire(dict(e, **{k: v}))["uid"], wire(e)["uid"], k)
        self.assertNotEqual(AG.to_event(dict(e), "ag-other")["uid"], wire(e)["uid"], "agent id is part of the uid")
        self.assertEqual(wire(dict(e, message="x" * 200 + "A"))["uid"], wire(dict(e, message="x" * 200 + "B"))["uid"], "only the first 200 characters of the message are hashed (so two events identical in everything else but beyond char 200 share a uid)")
        self.assertEqual(len(wire(e)["uid"]), 40)
    def test_02_server_validates_uid_format_only_not_its_binding_to_the_payload(self):
        a = Agent("u-proto"); e = ev(1, "synthetic payload", event_time=ago(1)); self.assertNotEqual(e["uid"], formula(a.id, e))
        self.assertEqual(a.post("/api/events", {"events": [e]}).json()["accepted_uids"], [e["uid"]], "NOT SUPPORTED by the protocol: a uid that does not match the payload is accepted")
        n = count("SELECT COUNT(*) n FROM agent_event_ids WHERE agent_id=?", a.id)
        for bad in ("", "x" * 81, "bad\x00uid", "bad\nuid", None, 12345, ["a"]):
            j = a.post("/api/events", {"events": [dict(ev(2), uid=bad)]}).json(); self.assertEqual((j["accepted_uids"], j["duplicate_uids"], j["retry_uids"], j["rejected_uids"]), ([], [], [], []), repr(bad)); self.assertEqual(j["rejected"], 1)
        self.assertEqual(count("SELECT COUNT(*) n FROM agent_event_ids WHERE agent_id=?", a.id), n, "events with an invalid uid never touch the ledger or the events table")
    def test_03_normal_resend_of_the_same_agent_event_is_a_duplicate(self):
        a = Agent("u-resend"); w = wire(dict(self.base, record_id=777001, event_time=ago(2)), a.id); self.assertEqual(a.post("/api/events", {"events": [w]}).json()["accepted_uids"], [w["uid"]])
        n = events_of("u-resend"); again = wire(dict(self.base, record_id=777001, event_time=ago(2)), a.id); self.assertEqual(again, w, "an identical re-collection produces an identical wire event")
        self.assertEqual(a.post("/api/events", {"events": [again]}).json()["duplicate_uids"], [w["uid"]]); self.assertEqual(events_of("u-resend"), n)
    def test_04_agent_generated_event_with_a_different_timestamp_is_a_different_event(self):
        a = Agent("u-newts"); w1 = wire(dict(self.base, record_id=777002, event_time=ago(2)), a.id); w2 = wire(dict(self.base, record_id=777002, event_time=ago(2, seconds=-5)), a.id); self.assertNotEqual(w1["uid"], w2["uid"])
        for window in ("inside", "after"):
            if window == "after": age_ledger(a.id, 31); FA.purge_dedup()
            before = events_of("u-newts"); j = a.post("/api/events", {"events": [w1, w2]}).json()
            if window == "inside": self.assertEqual(sorted(j["accepted_uids"]), sorted([w1["uid"], w2["uid"]])); self.assertEqual(events_of("u-newts") - before, 2, "two distinct events: NOT detected as a replay (a different timestamp is a different event)")
            else: self.assertEqual(sorted(j["accepted_uids"]), sorted([w1["uid"], w2["uid"]])); self.assertEqual(events_of("u-newts") - before, 0, "after the window both are re-accepted by the ledger path but the unique index (same ts) keeps the rows unique")

class ReplayMatrix(unittest.TestCase):
    """The six scenarios documented in docs/DEDUPLICATION_RETENTION.md section 3 (default window 30 days)."""
    def setUp(self): self.a = Agent("rm-" + os.urandom(3).hex()); self.h = db.q("SELECT hostname FROM agents WHERE id=?", (self.a.id,), one=True)["hostname"]
    def n(self): return events_of(self.h), alerts_of(self.a)
    def old_alert_state(self): db.x("UPDATE alerts SET updated='2020-01-01 00:00:00' WHERE endpoint_id=(SELECT endpoint_id FROM agents WHERE id=?)", (self.a.id,))
    def test_s1_identical_replay_while_ledger_entry_exists(self):
        e = ev(1, ALERT_MSG, log_only=False, event_time=ago(2)); self.a.post("/api/events", {"events": [e]}); n = self.n(); j = self.a.post("/api/events", {"events": [e]}).json()
        self.assertEqual((j["duplicate_uids"], j["accepted_uids"]), ([e["uid"]], [])); self.assertEqual(self.n(), n)
    def test_s2_ledger_purged_event_row_remains(self):
        e = ev(1, ALERT_MSG, log_only=False, event_time=ago(2)); self.a.post("/api/events", {"events": [e]}); n = self.n(); age_ledger(self.a.id, 31); FA.purge_dedup(); self.old_alert_state()
        self.assertEqual(self.a.post("/api/events", {"events": [e]}).json()["accepted_uids"], [e["uid"]]); self.assertEqual(self.n(), n, "event row and its alert link survive: no duplicate event, no duplicate alert (even with an old alert)")
    def test_s3_ledger_entry_and_event_row_both_gone(self):
        al, be = ev(1, ALERT_MSG, log_only=False, event_time=ago(2)), ev(2, "benign event", log_only=False, event_time=ago(2)); self.a.post("/api/events", {"events": [al, be]}); n = self.n()
        db.x("DELETE FROM events WHERE host=?", (self.h,)); age_ledger(self.a.id, 31); FA.purge_dedup(); self.old_alert_state(); j = self.a.post("/api/events", {"events": [al, be]}).json(); self.assertEqual(len(j["accepted_uids"]), 2)
        self.assertEqual(self.n(), (n[0], n[1] + 1), "both events are re-created; the alerting one raises a NEW alert (merge window passed); the benign one raises none")
    def test_s4_timestamp_changed_uid_regenerated(self):
        w1 = wire(dict(channel="Security", record_id=555001, event_time=ago(3), message=ALERT_MSG, log_only=False), self.a.id); w2 = wire(dict(channel="Security", record_id=555001, event_time=ago(3, seconds=-9), message=ALERT_MSG, log_only=False), self.a.id)
        self.assertNotEqual(w1["uid"], w2["uid"]); self.a.post("/api/events", {"events": [w1]}); n = self.n(); self.a.post("/api/events", {"events": [w2]}); self.assertEqual(self.n()[0], n[0] + 1, "treated as a new, distinct event: the server cannot know it is a replay")
    def test_s5_timestamp_changed_original_uid_retained(self):
        e = ev(1, "benign", log_only=False, event_time=ago(5)); self.a.post("/api/events", {"events": [e]}); n = self.n(); m = dict(e, event_time=ago(4))
        self.assertEqual(self.a.post("/api/events", {"events": [m]}).json()["duplicate_uids"], [e["uid"]]); self.assertEqual(self.n(), n, "inside the window: the ledger keys on the uid, so the modified payload is dropped")
        age_ledger(self.a.id, 31); FA.purge_dedup(); self.assertEqual(self.a.post("/api/events", {"events": [m]}).json()["accepted_uids"], [e["uid"]]); self.assertEqual(self.n()[0], n[0] + 1, "after the window: a new event row (the unique index includes the timestamp)")
    def test_s6_previously_benign_event_processed_again(self):
        e = ev(1, "benign again", log_only=False, event_time=ago(2)); self.a.post("/api/events", {"events": [e]}); n = self.n(); age_ledger(self.a.id, 31); FA.purge_dedup(); calls = {"n": 0}; real = engine._detect
        engine._detect = lambda *x, **k: (calls.__setitem__("n", calls["n"] + 1), real(*x, **k))[1]
        try: self.a.post("/api/events", {"events": [e]})
        finally: engine._detect = real
        self.assertEqual((calls["n"], self.n()), (1, n), "detection ran once more (no alert link exists for a benign event); no new row, no alert")

class StartupValidation(unittest.TestCase):
    def run_py(self, args, **envv):
        d = os.path.join(T, "start-" + os.urandom(3).hex()); os.makedirs(d); e = {k: v for k, v in os.environ.items() if not k.startswith("SOC_DEDUP") and not k.startswith("SOC_REJECT")}
        e.update(SOC_DB=d + "/s.db", SOC_SECRET="s" * 40, SOC_ALLOW_FOREIGN_DB="1", SOC_LOCAL_LOGS="0", **envv); return subprocess.run([sys.executable, "-W", "ignore"] + args, cwd=d, env=e, capture_output=True, text=True, timeout=60)
    def test_01_python_app_py_refuses_to_start_on_a_bad_value(self):
        r = self.run_py([ROOT + "/app.py"], SOC_DEDUP_RETENTION_DAYS="3"); self.assertNotEqual(r.returncode, 0); self.assertIn("SOC_DEDUP_RETENTION_DAYS", r.stderr); self.assertNotIn("Running on", r.stdout + r.stderr, "the server never started listening")
        r = self.run_py([ROOT + "/app.py"], SOC_REJECT_STALE_EVENTS="true"); self.assertNotEqual(r.returncode, 0); self.assertIn("SOC_REJECT_STALE_EVENTS", r.stderr)
    def test_02_importing_app_as_gunicorn_does_fails_on_a_bad_value_and_succeeds_on_valid_ones(self):
        code = f"import sys; sys.path.insert(0,{ROOT!r}); import app; print('IMPORTED')"
        for bad in ("6", "abc", "", " ", "3_0", "+30", "0x1e", "30.0", "\u0663\u0660", "99999999"):
            if bad.strip() == "": continue                                    # empty/blank = unset = default (covered in Config)
            r = self.run_py(["-c", code], SOC_DEDUP_RETENTION_DAYS=bad); self.assertNotEqual(r.returncode, 0, repr(bad)); self.assertIn("SOC_DEDUP_RETENTION_DAYS", r.stderr, repr(bad)); self.assertNotIn("IMPORTED", r.stdout)
        for good in ("7", "30", "3650", " 45 "):
            r = self.run_py(["-c", code], SOC_DEDUP_RETENTION_DAYS=good); self.assertEqual(r.returncode, 0, (good, r.stderr[-300:])); self.assertIn("IMPORTED", r.stdout)
        r = self.run_py(["-c", code]); self.assertEqual(r.returncode, 0); self.assertIn("IMPORTED", r.stdout)
    def test_03_strict_integer_parsing(self):
        for bad in ("3_0", "+30", "-30", "0x1e", "1e2", "30.0", "\u0663\u0660", "\uff13\uff10", "99999999", "thirty"):
            with env(SOC_DEDUP_RETENTION_DAYS=bad):
                with self.assertRaises(FA.ConfigError, msg=repr(bad)): FA.dedup_days()
        for good, v in ((" 30 ", 30), ("30\n", 30), ("007", 7), ("3650", 3650), ("07", 7)):
            with env(SOC_DEDUP_RETENTION_DAYS=good): self.assertEqual(FA.dedup_days(), v, repr(good))

class CleanupFailureAndScheduling(unittest.TestCase):
    def seed(self, aid, n_old, n_pending=0):
        c = db.conn(); old = (datetime.now() - timedelta(days=90)).strftime(FMT)
        c.executemany("INSERT INTO agent_event_ids(agent_id,uid,ts,status) VALUES(?,?,?,'processed')", [(aid, f"cf-{os.urandom(4).hex()}-{i}", old) for i in range(n_old)])
        c.executemany("INSERT INTO agent_event_ids(agent_id,uid,ts,status) VALUES(?,?,?,'pending')", [(aid, f"cfp-{os.urandom(4).hex()}-{i}", old) for i in range(n_pending)]); c.commit(); c.close()
    def tearDown(self): FA.conn = P.db.conn if False else FA_CONN
    def test_01_exception_midway_keeps_committed_batches_records_them_and_deletes_no_unprocessed_row(self):
        a = Agent("cf-partial"); self.seed(a.id, 50, 10); real = FA.conn; calls = {"n": 0}
        class W:
            def __init__(s): s.c = real()
            def execute(s, sql, *p):
                if sql.startswith("DELETE FROM agent_event_ids"):
                    calls["n"] += 1
                    if calls["n"] == 2: raise RuntimeError("injected failure on batch 2")
                return s.c.execute(sql, *p)
            def __getattr__(s, k): return getattr(s.c, k)
        FA.conn = W
        try:
            with self.assertRaises(RuntimeError): FA.purge_dedup(limit=10, max_batches=5)
        finally: FA.conn = real
        self.assertEqual((FA.last_purge["deleted"], "RuntimeError" in FA.last_purge["error"]), (10, True), "last_purge reflects what really happened: one batch committed, then the failure")
        self.assertEqual(count("SELECT COUNT(*) n FROM agent_event_ids WHERE agent_id=? AND status='processed'", a.id), 40); self.assertEqual(count("SELECT COUNT(*) n FROM agent_event_ids WHERE agent_id=? AND status='pending'", a.id), 10)
        self.assertEqual(FA.purge_dedup(limit=100, max_batches=5), 40); self.assertIsNone(FA.last_purge["error"]); self.assertEqual(count("SELECT COUNT(*) n FROM agent_event_ids WHERE agent_id=? AND status='pending'", a.id), 10, "unprocessed rows never deleted")
    def test_02_failure_at_commit_rolls_the_batch_back(self):
        a = Agent("cf-commit"); self.seed(a.id, 30); real = FA.conn
        class W:
            def __init__(s): s.c = real()
            def commit(s): raise sqlite3.OperationalError("disk I/O error")
            def __getattr__(s, k): return getattr(s.c, k)
        FA.conn = W
        try: n, out = quiet(FA.purge_dedup, limit=10, max_batches=3)
        finally: FA.conn = real
        self.assertEqual(n, 0); self.assertEqual(count("SELECT COUNT(*) n FROM agent_event_ids WHERE agent_id=?", a.id), 30, "nothing deleted when the commit fails"); self.assertTrue(FA.last_purge["error"]); self.assertIn("purge skipped", out)
        self.assertEqual(FA.purge_dedup(limit=100), 30)
    def idle(self):
        for _ in range(100):
            if not FA._purge_lock.locked() and not any(t.name == "dedup-purge" for t in threading.enumerate()): return
            time.sleep(0.05)
        self.fail("a cleanup thread never finished")
    def test_03a_throttle_one_run_per_interval(self):
        self.idle(); real, calls = FA.purge_dedup, {"n": 0}
        def slow(**k): calls["n"] += 1; time.sleep(0.3); return 0
        FA.purge_dedup = slow
        try:
            FA._last_purge[0] = 0
            for _ in range(40): FA.maybe_purge()                              # the first call starts a run and stamps the time; the other 39 are inside the 10 minute interval
            self.idle(); self.assertEqual(calls["n"], 1); FA._last_purge[0] = time.time() - 601; FA.maybe_purge(); self.idle(); self.assertEqual(calls["n"], 2, "runs again once the interval has passed")
        finally: FA.purge_dedup = real; self.idle()
    def test_03b_lock_prevents_overlapping_runs_even_if_the_throttle_is_bypassed(self):
        self.idle(); real, calls = FA.purge_dedup, {"n": 0, "live": 0, "max_live": 0}
        def slow(**k):
            calls["n"] += 1; calls["live"] += 1; calls["max_live"] = max(calls["max_live"], calls["live"]); time.sleep(0.5); calls["live"] -= 1; return 0
        FA.purge_dedup = slow; threads = []
        try:
            for _ in range(40): FA._last_purge[0] = 0; FA.maybe_purge(); threads.append(sum(1 for t in threading.enumerate() if t.name == "dedup-purge"))     # test-only: force the throttle open each time
            self.assertLessEqual(max(threads), 1, "never more than one cleanup thread"); self.idle(); self.assertEqual((calls["n"], calls["max_live"]), (1, 1), "40 forced attempts while one run was active produced exactly one run, never two at once")
            self.assertEqual(sum(1 for t in threading.enumerate() if t.name == "dedup-purge"), 0, "no thread left behind")
        finally: FA.purge_dedup = real; self.idle(); FA._last_purge[0] = time.time()
    def test_04_failed_run_is_retried_after_about_a_minute_not_ten(self):
        self.idle(); real = FA.purge_dedup
        def failing(**k): FA.last_purge.update(at="x", deleted=0, error="database busy/locked"); return 0
        FA.purge_dedup = failing
        try:
            FA._last_purge[0] = 0; FA.maybe_purge(sync=True); age = time.time() - FA._last_purge[0]; self.assertTrue(539 <= age <= 545, age)
            calls = {"n": 0}; FA.purge_dedup = lambda **k: (calls.__setitem__("n", calls["n"] + 1), FA.last_purge.update(error=None), 0)[2]
            FA.maybe_purge(sync=True); self.assertEqual(calls["n"], 0, "too early (about 60 s remain)"); FA._last_purge[0] -= 61; FA.maybe_purge(sync=True); self.assertEqual(calls["n"], 1, "retried after the shortened interval")
        finally: FA.purge_dedup = real; FA.last_purge["error"] = None
    def test_05_slow_cleanup_does_not_block_the_ingest_request(self):
        self.idle(); a = Agent("cf-nonblock"); real = FA.purge_dedup; FA.purge_dedup = lambda **k: time.sleep(1.5) or 0
        try:
            FA._last_purge[0] = 0; e = ev(1, "x"); t0 = time.time(); j = a.post("/api/events", {"events": [e]}).json(); dt = time.time() - t0
            self.assertEqual(j["accepted_uids"], [e["uid"]]); self.assertLess(dt, 1.0, f"request took {dt:.2f}s while a 1.5 s cleanup ran in the background"); self.idle()
        finally: FA.purge_dedup = real
FA_CONN = FA.conn

if __name__ == "__main__": unittest.main(verbosity=1)
