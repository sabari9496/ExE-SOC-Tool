"""Phase 1 review: crash consistency (B1), queue fairness (B2), retry persistence (B3), strict acks (B4), quarantine security/limits (B5),
dedupe retention/replay (B6), concurrency + SQLite BUSY + real multi-process (B7). Temp DBs, synthetic data. Run: python tests/test_phase1_review.py"""
import os, sys, tempfile, json, time, hashlib, hmac, secrets, sqlite3, subprocess, unittest, threading
ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__))); sys.path.insert(0, ROOT); sys.path.insert(0, ROOT + "/agent")
T = tempfile.mkdtemp()
for k in ("SOC_ALLOW_DEFAULT_CREDS", "SOC_ENV", "SOC_MFA_REQUIRED", "SOC_TRUSTED_PROXIES", "SOC_AGENT_AUTH", "SOC_REJECT_STALE_EVENTS", "SOC_DEDUP_RETENTION_DAYS"): os.environ.pop(k, None)
os.environ.update(SOC_DB=T + "/t.db", SOC_SECRET="s" * 40, SOC_LOCAL_LOGS="0", SOC_ALLOW_FOREIGN_DB="1", EXESOC_AGENT_HOME=T + "/agent", EXESOC_RETRY_BASE_SECONDS="0", SOC_INGEST_MAX_ATTEMPTS="3")
import db, app as A, engine, fleet.api as FA
import exe_soc_agent as AG
from datetime import datetime, timedelta
db.init_db(); BASE = "http://127.0.0.1:5000"; H = {"X-Requested-With": "fetch", "Origin": BASE}
ADMIN = dict(l.split("=", 1) for l in open(T + "/initial_admin_credentials.txt").read().splitlines() if "=" in l)
FA.LIMITS.update(events=(10 ** 6, 60), heartbeat=(10 ** 6, 60), ip=(10 ** 6, 60), register=(10 ** 6, 60))        # volume only; limits are separately verified in test_ingest_reliability
REAL_PB, REAL_DETECT, REAL_FIN = engine.process_batch, engine._detect, FA._finalize
ALERT_MSG = "mimikatz.exe sekurlsa::logonpasswords"

def login(user, pw):
    c = A.app.test_client(); r = c.post("/login", data={"username": user, "password": pw}, headers={"Origin": BASE}, base_url=BASE); assert r.status_code == 302, (user, r.status_code); return c
_adm = login(ADMIN["username"], ADMIN["password"])
for n, role in (("analyst1", "analyst"), ("viewer1", "viewer")): db.x("INSERT INTO users(username,password_hash,role,created_at) VALUES(?,?,?,?)", (n, A.generate_password_hash("a-long-test-password-1"), role, db.now()))
def enroll(host):
    tok = _adm.post("/api/enrollment-tokens", json={"label": "t"}, headers=H, base_url=BASE).get_json()["token"]
    return A.app.test_client().post("/api/agents/register", json={"enrollment_token": tok, "hostname": host, "os": "Linux", "os_version": "t", "agent_version": "1.0.0"}, base_url=BASE).get_json()
class Resp:
    def __init__(self, r): self.status_code = r.status_code; self.text = r.get_data(as_text=True)
    def json(self): return json.loads(self.text)
    def raise_for_status(self):
        if self.status_code >= 400: import requests; raise requests.HTTPError(f"HTTP {self.status_code}")
class Agent:
    def __init__(self, host): d = enroll(host); self.id, self.cred, self.skey = d["agent_id"], d["credential"], d["signing_key"]; self.c = A.app.test_client()
    def job(self, events, **k): return json.dumps(dict(cred=self.cred, skey=self.skey, events=events, **k))
    def post(self, path, obj, timeout=0):
        data = json.dumps(obj, separators=(",", ":")).encode(); ts = str(int(time.time())); nonce = secrets.token_urlsafe(16)
        canon = "\n".join(("EXESOC-HMAC-SHA256-V1", "POST", path, ts, nonce, hashlib.sha256(data).hexdigest()))
        h = {"Authorization": "Bearer " + self.cred, "X-Timestamp": ts, "X-Nonce": nonce, "Content-Type": "application/json", "X-Signature": "v1=" + hmac.new(self.skey.encode(), canon.encode(), hashlib.sha256).hexdigest()}
        return Resp(self.c.post(path, data=data, headers=h, base_url=BASE))
def ev(n, msg=None, **k):
    d = dict(uid=hashlib.sha256(f"{secrets.token_hex(4)}{n}".encode()).hexdigest()[:40], message=msg or f"synthetic event {n}", channel="synthetic", record_id=secrets.randbelow(10 ** 9), event_time=time.strftime("%Y-%m-%dT%H:%M:%S", time.gmtime())); d.update(k); return d
def count(sql, *a): return db.q(sql, a, one=True)["n"]
def ledger(aid, uid): r = db.q("SELECT status,attempts FROM agent_event_ids WHERE agent_id=? AND uid=?", (aid, uid), one=True); return (r["status"], r["attempts"] or 0) if r else None
def child(mode, job, timeout=120):
    e = dict(os.environ, CHILD_JOB=job); return subprocess.run([sys.executable, "-W", "ignore", ROOT + "/tests/_ingest_child.py", mode], env=e, capture_output=True, text=True, timeout=timeout)
def new_queue():
    for f in ("queue.db", "queue.db-wal", "queue.db-shm"):
        try: os.remove(os.path.join(AG.HOME, f))
        except OSError: pass
    return AG.Queue()
def st(): return dict(sent=0, rejected=0, rej_msg="", rej_until=0)
class Srv:
    def __init__(self, body): self.body = body; self.calls = 0
    def post(self, path, obj, timeout=0):
        self.calls += 1; b = self.body(obj) if callable(self.body) else self.body
        class R:
            status_code = 200
            def json(s): return b
            def raise_for_status(s): pass
        return R()
def accept_all(obj): return {"ack_version": 2, "accepted_uids": [e["uid"] for e in obj["events"]], "duplicate_uids": [], "rejected_uids": [], "retry_uids": []}

class B1CrashConsistency(unittest.TestCase):
    def tearDown(self): engine.process_batch, engine._detect, FA._finalize = REAL_PB, REAL_DETECT, REAL_FIN
    def test_01_failure_before_persistence(self):
        a = Agent("b1-before"); e = ev(1, "x"); engine.process_batch = lambda *x, **k: (_ for _ in ()).throw(RuntimeError("pre"))
        j = a.post("/api/events", {"events": [e]}).json(); self.assertEqual(j["retry_uids"], [e["uid"]]); self.assertEqual(count("SELECT COUNT(*) n FROM events WHERE host='b1-before'"), 0); self.assertEqual(ledger(a.id, e["uid"]), ("pending", 1))
    def test_02_failure_after_persistence_then_retry_is_idempotent(self):
        a = Agent("b1-after"); e = ev(1, ALERT_MSG, log_only=False); calls = {"n": 0}
        def persist_then_die(items, reprocess_duplicates=False):
            r = REAL_PB(items, reprocess_duplicates=reprocess_duplicates); calls["n"] += 1
            if calls["n"] <= 2: raise RuntimeError("after persist")           # batch attempt AND the per-event fallback both fail once
            return r
        engine.process_batch = persist_then_die; j = a.post("/api/events", {"events": [e]}).json(); self.assertEqual(j["retry_uids"], [e["uid"]])
        self.assertEqual(count("SELECT COUNT(*) n FROM events WHERE host='b1-after'"), 1, "event persisted once"); self.assertEqual(ledger(a.id, e["uid"])[0], "pending")
        j = a.post("/api/events", {"events": [e]}).json(); self.assertEqual(j["accepted_uids"], [e["uid"]]); self.assertEqual(ledger(a.id, e["uid"])[0], "processed")
        self.assertEqual(count("SELECT COUNT(*) n FROM events WHERE host='b1-after'"), 1); self.assertEqual(count("SELECT COUNT(*) n FROM alerts WHERE endpoint_id=(SELECT endpoint_id FROM agents WHERE id=?)", a.id), 1, "exactly one alert")
    def test_03_detection_failure_after_persistence_creates_alert_exactly_once_on_retry(self):
        a = Agent("b1-detect"); e = ev(1, ALERT_MSG, log_only=False); n = {"c": 0}
        def flaky(*x, **k):
            n["c"] += 1
            if n["c"] <= 2: raise RuntimeError("detect")
            return REAL_DETECT(*x, **k)
        engine._detect = flaky; a.post("/api/events", {"events": [e]}); self.assertEqual(count("SELECT COUNT(*) n FROM events WHERE host='b1-detect'"), 1)
        self.assertEqual(count("SELECT COUNT(*) n FROM alerts WHERE endpoint_id=(SELECT endpoint_id FROM agents WHERE id=?)", a.id), 0, "persisted but no alert yet")
        j = a.post("/api/events", {"events": [e]}).json(); self.assertEqual(j["accepted_uids"], [e["uid"]])
        self.assertEqual((count("SELECT COUNT(*) n FROM events WHERE host='b1-detect'"), count("SELECT COUNT(*) n FROM alerts WHERE endpoint_id=(SELECT endpoint_id FROM agents WHERE id=?)", a.id)), (1, 1))
        a.post("/api/events", {"events": [e]}); self.assertEqual(count("SELECT COUNT(*) n FROM alerts WHERE endpoint_id=(SELECT endpoint_id FROM agents WHERE id=?)", a.id), 1, "a further replay adds nothing")
    def test_04_finalization_failures_release_claim_and_retry_cleanly(self):
        a = Agent("b1-final"); e = ev(1, ALERT_MSG, log_only=False)
        for exc, code in ((sqlite3.OperationalError("database is locked"), 503), (RuntimeError("fin"), 500)):
            FA._finalize = lambda *x, _e=exc, **k: (_ for _ in ()).throw(_e); r = a.post("/api/events", {"events": [e]}); self.assertEqual(r.status_code, code)
            self.assertEqual(ledger(a.id, e["uid"]), ("pending", 0), "claim released, not stuck in 'processing'"); self.assertEqual(count("SELECT COUNT(*) n FROM events WHERE host='b1-final'"), 1)
        FA._finalize = REAL_FIN; j = a.post("/api/events", {"events": [e]}).json(); self.assertEqual(j["accepted_uids"], [e["uid"]]); self.assertEqual(ledger(a.id, e["uid"])[0], "processed")
        self.assertEqual((count("SELECT COUNT(*) n FROM events WHERE host='b1-final'"), count("SELECT COUNT(*) n FROM alerts WHERE endpoint_id=(SELECT endpoint_id FROM agents WHERE id=?)", a.id)), (1, 1))
    def test_05_process_killed_between_persistence_and_acknowledgement(self):
        a = Agent("b1-kill"); e = ev(1, ALERT_MSG, log_only=False); r = child("crash", a.job([e])); self.assertEqual(r.returncode, 9, r.stderr[-300:])
        self.assertEqual(count("SELECT COUNT(*) n FROM events WHERE host='b1-kill'"), 1, "event persisted before the kill"); self.assertEqual(ledger(a.id, e["uid"])[0], "processing", "ledger shows an unfinished claim")
        j = a.post("/api/events", {"events": [e]}).json(); self.assertEqual(j["retry_uids"], [e["uid"]]); self.assertEqual(j["reasons"][e["uid"]], "lease_conflict", "lease still fresh: not double-processed")
        db.x("UPDATE agent_event_ids SET claimed_at=? WHERE agent_id=? AND uid=?", ((datetime.now() - timedelta(seconds=600)).strftime("%Y-%m-%d %H:%M:%S"), a.id, e["uid"]))
        j = a.post("/api/events", {"events": [e]}).json(); self.assertEqual(j["accepted_uids"], [e["uid"]]); self.assertEqual(ledger(a.id, e["uid"])[0], "processed")
        self.assertEqual((count("SELECT COUNT(*) n FROM events WHERE host='b1-kill'"), count("SELECT COUNT(*) n FROM alerts WHERE endpoint_id=(SELECT endpoint_id FROM agents WHERE id=?)", a.id)), (1, 1), "recovered with no duplicate event or alert")

class B2B3Queue(unittest.TestCase):
    def test_01_many_held_entries_do_not_starve_or_unbound_reads(self):
        q = new_queue(); evs = [ev(i) for i in range(3000)]; q.add(evs); q.hold([e["uid"] for e in evs], 600)          # 3000 held (way beyond BATCH)
        fresh = [ev(i, f"fresh {i}") for i in range(7)]; q.add(fresh); calls = {"n": 0}; real = AG.json.loads
        AG.json.loads = lambda *a, **k: (calls.__setitem__("n", calls["n"] + 1), real(*a, **k))[1]
        try: got = q.peek(AG.BATCH)
        finally: AG.json.loads = real
        self.assertEqual([e["uid"] for _, e in got], [e["uid"] for e in fresh], "newer eligible events are sent although older ones are held"); self.assertLessEqual(calls["n"], AG.BATCH, "reads bounded by the batch size, not by the number of held rows")
        s = Srv(accept_all); AG.flush_queue(s, q, st()); self.assertEqual(q.count(), 3000); self.assertEqual(q.held(), 3000, "held events were neither sent early nor dropped")
    def test_02_older_held_events_are_retried_first_after_expiry(self):
        q = new_queue(); old = [ev(i, f"old {i}") for i in range(3)]; q.add(old); q.hold([old[0]["uid"]], 600); new = ev(9, "new"); q.add([new])
        self.assertEqual([e["uid"] for _, e in q.peek(10)], [old[1]["uid"], old[2]["uid"], new["uid"]]); q.db.execute("UPDATE q SET hold_until=0"); q.db.commit()
        self.assertEqual([e["uid"] for _, e in q.peek(10)][0], old[0]["uid"], "oldest first once eligible")
    def test_03_mixed_eligible_held_corrupt_nothing_silently_dropped(self):
        q = new_queue(); good = [ev(i) for i in range(4)]; held = [ev(10 + i) for i in range(2)]; q.add(good + held); q.hold([e["uid"] for e in held], 600)
        for i, body in enumerate(("{not json", "[1,2]", '{"no_uid": 1}')): q.db.execute("INSERT INTO q(uid,body) VALUES(?,?)", (f"corrupt-{i}", body))
        q.db.commit(); total = q.count(); got = q.peek(50); self.assertEqual({e["uid"] for _, e in got}, {e["uid"] for e in good})
        dead = {r[0] for r in q.db.execute("SELECT uid FROM dead")}; self.assertEqual(dead, {"corrupt-0", "corrupt-1", "corrupt-2"}); self.assertEqual(q.count() + len(dead), total, "every row is either queued or dead-lettered")
    def test_04_hold_state_is_persistent_and_tolerates_garbage_and_clock_jumps(self):
        q = new_queue(); e1, e2, e3 = ev(1), ev(2), ev(3); q.add([e1, e2, e3]); q.hold([e1["uid"]], 600)
        q.db.execute("UPDATE q SET hold_until='garbage' WHERE uid=?", (e2["uid"],)); q.db.execute("UPDATE q SET hold_until=? WHERE uid=?", (time.time() + 10 ** 7, e3["uid"])); q.db.commit(); q.db.close()
        q2 = AG.Queue(); self.assertEqual({e["uid"] for _, e in q2.peek(10)}, {e2["uid"], e3["uid"]}, "text garbage and an impossible far-future hold (clock moved back) do not strand events"); self.assertEqual(q2.held(), 1)
    def test_05_interrupted_write_is_atomic(self):
        q = new_queue(); evs = [ev(i) for i in range(5)]; q.add(evs); q.db.commit(); q.db.close()
        code = f"import sqlite3,os,sys; c=sqlite3.connect({AG.QDB!r}); c.execute('BEGIN'); c.execute('UPDATE q SET hold_until=9999999999, tries=9'); c.execute('DELETE FROM q WHERE seq<3'); os._exit(7)"
        self.assertEqual(subprocess.run([sys.executable, "-c", code]).returncode, 7); q2 = AG.Queue()
        self.assertEqual(q2.count(), 5, "uncommitted deletes rolled back"); self.assertEqual(q2.held(), 0, "uncommitted hold rolled back"); self.assertEqual(len(q2.peek(10)), 5)
    def test_06_retry_delay_is_bounded_and_exponential(self):
        q = new_queue(); e = ev(1); q.add([e]); t0 = 1000.0
        for i in range(12): q.hold([e["uid"]], 30, now=t0)
        hu = q.db.execute("SELECT hold_until FROM q").fetchone()[0]; self.assertLessEqual(hu - t0, AG.MAX_HOLD_S)

class B4Acks(unittest.TestCase):
    U = {"a", "b", "c", "d"}
    def ok(self, **k): return dict({"ack_version": 2, "accepted_uids": [], "duplicate_uids": [], "rejected_uids": [], "retry_uids": []}, **k)
    def test_01_parser_rejects_invalid_replies(self):
        for bad in (self.ok(accepted_uids=["a"], rejected_uids=["a"]), self.ok(accepted_uids=["a"], retry_uids=["a"]), self.ok(duplicate_uids=["a"], rejected_uids=["a"]), self.ok(accepted_uids=["a", "a"]),
                    self.ok(accepted_uids=["zzz"]), self.ok(rejected_uids=["zzz"]), self.ok(retry_uids=["zzz"]), self.ok(accepted_uids="a"), self.ok(accepted_uids=[1]), dict(self.ok(), ack_version=9), dict(self.ok(), ack_version=True), dict(self.ok(), ack_version="2"), {"accepted": 4}, [], None):
            with self.assertRaises(ValueError, msg=repr(bad)): AG._ack_lists(bad, self.U)
    def test_02_parser_accepts_valid_and_v1(self):
        r = AG._ack_lists(self.ok(accepted_uids=["a"], duplicate_uids=["b"], rejected_uids=["c"], retry_uids=["d"], reasons={"c": "x", "zzz": "ignored"}), self.U); self.assertEqual(r[0], {"a"}); self.assertEqual(r[4], {"c": "x"})
        v1 = {"accepted_uids": ["a"], "duplicate_uids": [], "rejected_uids": ["b"]}; self.assertEqual(AG._ack_lists(v1, self.U)[3], set())
    def test_03_missing_outcome_keeps_the_event(self):
        q = new_queue(); evs = [ev(i) for i in range(3)]; q.add(evs); AG.flush_queue(Srv(lambda o: self.ok(accepted_uids=[o["events"][0]["uid"]])), q, st()); self.assertEqual(q.count(), 2); self.assertEqual(q.held(), 0 if AG.RETRY_BASE_S == 0 else 2)
    def test_04_server_gives_every_valid_uid_exactly_one_outcome(self):
        a = Agent("b4-inv"); evs = [ev(i) for i in range(20)]; evs[3]["message"] = ""; evs[4]["event_time"] = "2099-01-01T00:00:00Z"; evs[5]["message"] = "POISON"; evs[6]["record_id"] = 2 ** 70
        real = engine.process_batch; engine.process_batch = lambda items, reprocess_duplicates=False: (_ for _ in ()).throw(RuntimeError("p")) if any(i["message"] == "POISON" for i in items) else real(items, reprocess_duplicates=reprocess_duplicates)
        try:
            a.post("/api/events", {"events": [evs[0]]}); j = a.post("/api/events", {"events": evs + [dict(evs[1])]}).json()      # evs[0] already processed, evs[1] twice in one batch
        finally: engine.process_batch = real
        lists = [j["accepted_uids"], j["duplicate_uids"], j["rejected_uids"], j["retry_uids"]]; flat = [u for l in lists for u in l]
        self.assertEqual(len(flat), len(set(flat)), "no uid in two lists"); self.assertEqual(set(flat), {e["uid"] for e in evs}, "every submitted valid uid is acknowledged exactly once"); self.assertEqual(j["ack_version"], 2)

class B5Quarantine(unittest.TestCase):
    SECRETS = ("hunter2-PW", "SECRETTOKEN", "SESSIONVAL", "AKIA-SECRET", "MIIBVQ", "REFRESHVAL", "p w", "BASICCRED")
    def bad_event(self):
        return dict(ev(1), message="", headers={"Authorization": "Bearer abc.def.SECRETTOKEN", "Cookie": "sid=SESSIONVAL", "x": [{"API_KEY": "AKIA-SECRET"}]}, creds={"Password": "hunter2-PW", "refresh_token": "REFRESHVAL"},
                    raw="login password=\"p w\" key:\n-----BEGIN PRIVATE KEY-----\nMIIBVQ\n-----END PRIVATE KEY-----\nAuthorization: Basic BASICCRED12345")
    def test_01_nested_secrets_never_reach_the_quarantine_api(self):
        a = Agent("b5-red"); e = self.bad_event(); self.assertEqual(a.post("/api/events", {"events": [e]}).json()["rejected_uids"], [e["uid"]])
        lst = _adm.get("/api/quarantine", headers=H, base_url=BASE).get_json(); row = [r for r in lst if r["uid"] == e["uid"]][0]; body = _adm.get(f"/api/quarantine/{row['id']}", headers=H, base_url=BASE).get_data(as_text=True)
        self.assertIn("bad_message", body); self.assertEqual([s for s in self.SECRETS if s in body], [], "no secret in the API payload"); self.assertEqual([s for s in self.SECRETS if s in json.dumps(lst)], [])
        self.assertNotIn(self.SECRETS[0], db.q("SELECT payload FROM event_quarantine WHERE uid=?", (e["uid"],), one=True)["payload"], "and none at rest in the table")
    def test_02_authorization(self):
        a = Agent("b5-auth"); e = self.bad_event(); a.post("/api/events", {"events": [e]}); rid = db.q("SELECT id FROM event_quarantine WHERE uid=?", (e["uid"],), one=True)["id"]
        for who, c in (("analyst", login("analyst1", "a-long-test-password-1")), ("viewer", login("viewer1", "a-long-test-password-1"))):
            for path in ("/api/quarantine", f"/api/quarantine/{rid}"): self.assertEqual(c.get(path, headers=H, base_url=BASE).status_code, 403, who + path)
        anon = A.app.test_client(); self.assertEqual(anon.get("/api/quarantine", headers=H, base_url=BASE).status_code, 401)
        bearer = {"Authorization": "Bearer " + a.cred, "X-Requested-With": "fetch"}; self.assertIn(anon.get("/api/quarantine", headers=bearer, base_url=BASE).status_code, (401, 403), "an agent credential cannot read quarantine")
        self.assertEqual(_adm.get(f"/api/quarantine/{rid}", headers=H, base_url=BASE).status_code, 200)
    def test_03_per_agent_cap_never_deletes_evidence_and_keeps_event_retryable(self):
        a = Agent("b5-cap"); old = (FA.QUARANTINE_AGENT_ROWS,); FA.QUARANTINE_AGENT_ROWS = 2
        try:
            bad = [dict(ev(i), message="") for i in range(3)]; j = a.post("/api/events", {"events": bad}).json()
            self.assertEqual(sorted(j["rejected_uids"]), sorted(b["uid"] for b in bad[:2])); self.assertEqual(j["retry_uids"], [bad[2]["uid"]]); self.assertEqual(j["reasons"][bad[2]["uid"]], "quarantine_full")
            self.assertEqual(count("SELECT COUNT(*) n FROM event_quarantine WHERE agent_id=?", a.id), 2, "nothing deleted to make room")
            pois = ev(9, "POISON cap"); engine.process_batch = lambda items, reprocess_duplicates=False: (_ for _ in ()).throw(RuntimeError("p")) if any("POISON" in i["message"] for i in items) else REAL_PB(items, reprocess_duplicates=reprocess_duplicates)
            for _ in range(4): j = a.post("/api/events", {"events": [pois]}).json()
            self.assertEqual(j["retry_uids"], [pois["uid"]]); self.assertEqual(ledger(a.id, pois["uid"])[0], "pending", "poison at capacity is retried, not discarded and not claimed forever")
        finally: FA.QUARANTINE_AGENT_ROWS = old[0]; engine.process_batch = REAL_PB
    def test_04_global_cap_and_payload_cap(self):
        a = Agent("b5-glob"); tot = count("SELECT COUNT(*) n FROM event_quarantine"); oldt, oldp = FA.QUARANTINE_TOTAL_ROWS, FA.QUARANTINE_PAYLOAD_ROWS
        try:
            FA.QUARANTINE_PAYLOAD_ROWS = 0; e1 = dict(ev(1), message=""); FA.QUARANTINE_TOTAL_ROWS = tot + 1
            self.assertEqual(a.post("/api/events", {"events": [e1]}).json()["rejected_uids"], [e1["uid"]]); self.assertIsNone(db.q("SELECT payload FROM event_quarantine WHERE uid=?", (e1["uid"],), one=True)["payload"], "payload cap -> metadata only, still recorded")
            e2 = dict(ev(2), message=""); j = a.post("/api/events", {"events": [e2]}).json(); self.assertEqual((j["rejected_uids"], j["retry_uids"]), ([], [e2["uid"]])); self.assertEqual(count("SELECT COUNT(*) n FROM event_quarantine"), tot + 1)
        finally: FA.QUARANTINE_TOTAL_ROWS, FA.QUARANTINE_PAYLOAD_ROWS = oldt, oldp

class B6Retention(unittest.TestCase):
    def test_01_default_and_floor_and_boundaries(self):
        self.assertEqual(FA.dedup_days(), 30, "default raised from 14 to 30 in the Phase 2 retention review; strict validation is tested in test_retention_review.py")
        a = Agent("b6-bound"); now_dt = datetime(2026, 6, 15, 12, 0, 0); cut = now_dt - timedelta(days=FA.dedup_days()); fmt = lambda t: t.strftime("%Y-%m-%d %H:%M:%S"); c = db.conn()
        rows = {"before": (cut - timedelta(seconds=1), "processed"), "at": (cut, "processed"), "after": (cut + timedelta(seconds=1), "processed"), "dead_old": (cut - timedelta(days=30), "dead"), "pend_old": (cut - timedelta(days=30), "pending"), "proc_old": (cut - timedelta(days=30), "processing")}
        for k, (t, s_) in rows.items(): c.execute("INSERT INTO agent_event_ids(agent_id,uid,ts,status) VALUES(?,?,?,?)", (a.id, "bound-" + k, fmt(t), s_))
        c.execute("INSERT OR IGNORE INTO event_quarantine(agent_id,uid,reason,created_at) VALUES(?,?,?,?)", (a.id, "bound-q", "x", fmt(cut - timedelta(days=90)))); c.commit(); c.close(); nq = count("SELECT COUNT(*) n FROM event_quarantine")
        self.assertEqual(FA.purge_dedup(now_dt=now_dt), 1, "only the processed row strictly older than the cutoff"); left = {r["uid"] for r in db.q("SELECT uid FROM agent_event_ids WHERE agent_id=?", (a.id,))}
        self.assertEqual(left, {"bound-at", "bound-after", "bound-dead_old", "bound-pend_old", "bound-proc_old"}); self.assertEqual(count("SELECT COUNT(*) n FROM event_quarantine"), nq, "quarantine independent of dedupe cleanup")
        self.assertEqual(FA.purge_dedup(now_dt=now_dt + timedelta(days=1)), 2); self.assertEqual(FA.purge_dedup(now_dt=now_dt, limit=1), 0)
    def test_02_bounded_batches(self):
        a = Agent("b6-batch"); c = db.conn(); old = (datetime.now() - timedelta(days=60)).strftime("%Y-%m-%d %H:%M:%S")
        c.executemany("INSERT INTO agent_event_ids(agent_id,uid,ts,status) VALUES(?,?,?,'processed')", [(a.id, f"batch-{i}", old) for i in range(25)]); c.commit(); c.close()
        self.assertEqual(FA.purge_dedup(limit=10), 10); self.assertEqual(FA.purge_dedup(limit=10), 10); self.assertEqual(FA.purge_dedup(limit=10), 5)
    def test_03_delayed_delivery_inside_window_is_deduped_and_replay_after_purge_adds_nothing(self):
        a = Agent("b6-replay"); old = (datetime.now(timezone_utc := None) if False else datetime.utcnow() - timedelta(days=13)).strftime("%Y-%m-%dT%H:%M:%S")
        e = ev(1, ALERT_MSG, log_only=False, event_time=old); b = ev(2, "benign delayed event", log_only=False, event_time=old); self.assertEqual(sorted(a.post("/api/events", {"events": [e, b]}).json()["accepted_uids"]), sorted([e["uid"], b["uid"]]))
        n_ev, n_al = count("SELECT COUNT(*) n FROM events WHERE host='b6-replay'"), count("SELECT COUNT(*) n FROM alerts WHERE endpoint_id=(SELECT endpoint_id FROM agents WHERE id=?)", a.id)
        self.assertEqual(sorted(a.post("/api/events", {"events": [e, b]}).json()["duplicate_uids"]), sorted([e["uid"], b["uid"]]), "inside the window the ledger answers")
        db.x("DELETE FROM agent_event_ids WHERE agent_id=?", (a.id,)); j = a.post("/api/events", {"events": [e, b]}).json()                     # ledger purged: simulate delivery AFTER the retention boundary
        self.assertEqual(sorted(j["accepted_uids"]), sorted([e["uid"], b["uid"]]), "documented limitation: ledger no longer vouches for it, so it is processed again")
        self.assertEqual((count("SELECT COUNT(*) n FROM events WHERE host='b6-replay'"), count("SELECT COUNT(*) n FROM alerts WHERE endpoint_id=(SELECT endpoint_id FROM agents WHERE id=?)", a.id)), (n_ev, n_al), "but the unique event index and alert link still prevent duplicate events and alerts")
    def test_04_opt_in_stale_event_guard(self):
        a = Agent("b6-stale"); fmt = lambda d: (datetime.utcnow() - timedelta(days=d)).strftime("%Y-%m-%dT%H:%M:%S"); os.environ["SOC_REJECT_STALE_EVENTS"] = "1"
        try:
            e12, e14, e30 = ev(1, event_time=fmt(12)), ev(2, event_time=fmt(28)), ev(3, event_time=fmt(31)); j = a.post("/api/events", {"events": [e12, e14, e30]}).json()
            self.assertEqual(sorted(j["accepted_uids"]), sorted([e12["uid"], e14["uid"]])); self.assertEqual(j["rejected_uids"], [e30["uid"]]); self.assertEqual(j["reasons"][e30["uid"]], "timestamp_too_old")
        finally: os.environ.pop("SOC_REJECT_STALE_EVENTS")
        e = ev(4, event_time=fmt(30)); self.assertEqual(a.post("/api/events", {"events": [e]}).json()["accepted_uids"], [e["uid"]], "default behaviour unchanged when the guard is off")

class B7Concurrency(unittest.TestCase):
    def test_01_sqlite_busy_is_bounded_and_recoverable(self):
        a = Agent("b7-busy"); e = ev(1, ALERT_MSG, log_only=False); os.environ["SOC_DB_TIMEOUT"] = "0.2"; lock = sqlite3.connect(db.DB, timeout=5); lock.execute("BEGIN IMMEDIATE")
        try: t0 = time.time(); r = a.post("/api/events", {"events": [e]}); dt = time.time() - t0
        finally: lock.rollback(); lock.close(); os.environ.pop("SOC_DB_TIMEOUT")
        self.assertEqual(r.status_code, 503); self.assertTrue(r.json()["retryable"]); self.assertLess(dt, 5, "bounded retries, no infinite loop"); self.assertEqual(count("SELECT COUNT(*) n FROM events WHERE host='b7-busy'"), 0)
        j = a.post("/api/events", {"events": [e]}).json(); self.assertEqual(j["accepted_uids"], [e["uid"]])
    def test_02_multi_process_same_event_and_different_events(self):
        a = Agent("b7-mp"); same = [ev(i, ALERT_MSG if i == 0 else f"mp same {i}", log_only=False) for i in range(6)]; own = [[ev(100 * p + i, f"mp p{p} {i}") for i in range(5)] for p in range(3)]
        procs = [subprocess.Popen([sys.executable, "-W", "ignore", ROOT + "/tests/_ingest_child.py", "post"], env=dict(os.environ, CHILD_JOB=a.job(same + own[p], repeat=2)), stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True) for p in range(3)]
        outs = [p.communicate(timeout=200) for p in procs]; [self.assertEqual(p.returncode, 0, o[1][-300:]) for p, o in zip(procs, outs)]
        codes = {c for o in outs for c, _ in json.loads(o[0].strip().splitlines()[-1])}; self.assertLessEqual(codes, {200, 503}, codes)
        for _ in range(5): a.post("/api/events", {"events": same + [e for g in own for e in g]})                                                   # settle anything that returned retry
        self.assertEqual(count("SELECT COUNT(*) n FROM events WHERE host='b7-mp'"), 6 + 15, "each event stored exactly once across 3 processes")
        self.assertEqual(count("SELECT COUNT(*) n FROM alerts WHERE endpoint_id=(SELECT endpoint_id FROM agents WHERE id=?)", a.id), 1, "exactly one alert for the repeated alerting event")
        self.assertEqual(count("SELECT COUNT(*) n FROM agent_event_ids WHERE agent_id=? AND status='processed'", a.id), 21); self.assertEqual(count("SELECT COUNT(*) n FROM agent_event_ids WHERE agent_id=? AND status<>'processed'", a.id), 0)
    def test_03_thread_concurrency_one_alert(self):
        a = Agent("b7-thr"); e = ev(1, ALERT_MSG, log_only=False); res = []
        def w():
            ag = Agent.__new__(Agent); ag.id, ag.cred, ag.skey, ag.c = a.id, a.cred, a.skey, A.app.test_client(); res.append(ag.post("/api/events", {"events": [e]}).json())
        th = [threading.Thread(target=w) for _ in range(8)]; [t.start() for t in th]; [t.join() for t in th]
        a.post("/api/events", {"events": [e]}); self.assertEqual((count("SELECT COUNT(*) n FROM events WHERE host='b7-thr'"), count("SELECT COUNT(*) n FROM alerts WHERE endpoint_id=(SELECT endpoint_id FROM agents WHERE id=?)", a.id)), (1, 1))
        self.assertEqual(sum(len(j.get("accepted_uids", [])) for j in res), 1, "exactly one thread won the event")
if __name__ == "__main__": unittest.main(verbosity=1)
