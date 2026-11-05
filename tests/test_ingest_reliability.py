"""Phase 1: ingestion reliability. Real server code (Flask test client) + the real agent queue/flush loop, temp DB, synthetic events only.
Run: python tests/test_ingest_reliability.py"""
import os, sys, tempfile, json, time, hashlib, hmac, secrets, sqlite3, threading, unittest, importlib
ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__))); sys.path.insert(0, ROOT); sys.path.insert(0, ROOT + "/agent")
T = tempfile.mkdtemp()
for k in ("SOC_ALLOW_DEFAULT_CREDS", "SOC_ENV", "SOC_MFA_REQUIRED", "SOC_TRUSTED_PROXIES", "SOC_AGENT_AUTH"): os.environ.pop(k, None)
os.environ.update(SOC_DB=T + "/t.db", SOC_SECRET="s" * 40, SOC_LOCAL_LOGS="0", SOC_ALLOW_FOREIGN_DB="1", EXESOC_AGENT_HOME=T + "/agent", EXESOC_RETRY_BASE_SECONDS="0", SOC_INGEST_MAX_ATTEMPTS="3")
import db, app as A, engine, fleet.api as FA
import exe_soc_agent as AG
db.init_db(); BASE = "http://127.0.0.1:5000"; H = {"X-Requested-With": "fetch", "Origin": BASE}
ADMIN = dict(l.split("=", 1) for l in open(T + "/initial_admin_credentials.txt").read().splitlines() if "=" in l)
REAL_LIMITS = dict(FA.LIMITS); FA.LIMITS.update(events=(10 ** 6, 60), heartbeat=(10 ** 6, 60), ip=(10 ** 6, 60), register=(10 ** 6, 60))     # volume tests only; restored + verified in the last test
REAL_PB = engine.process_batch

def admin():
    c = A.app.test_client(); r = c.post("/login", data={"username": ADMIN["username"], "password": ADMIN["password"]}, headers={"Origin": BASE}, base_url=BASE); assert r.status_code == 302, r.status_code; return c
_adm = admin()
def enroll(host):
    tok = _adm.post("/api/enrollment-tokens", json={"label": "t"}, headers=H, base_url=BASE).get_json()["token"]
    return A.app.test_client().post("/api/agents/register", json={"enrollment_token": tok, "hostname": host, "os": "Linux", "os_version": "t", "agent_version": "1.0.0"}, base_url=BASE).get_json()
class Agent:
    """Signs requests exactly like exe_soc_agent.Client, but talks to the in-process server."""
    def __init__(self, host): d = enroll(host); self.id, self.cred, self.skey = d["agent_id"], d["credential"], d["signing_key"]; self.c = A.app.test_client()
    def post(self, path, obj, timeout=0, sign=True, nonce=None, key=None, ts=None):
        data = json.dumps(obj, separators=(",", ":")).encode(); ts = str(ts or int(time.time())); nonce = nonce or secrets.token_urlsafe(16)
        h = {"Authorization": "Bearer " + self.cred, "X-Timestamp": ts, "X-Nonce": nonce, "Content-Type": "application/json"}
        if sign:
            canon = "\n".join(("EXESOC-HMAC-SHA256-V1", "POST", path, ts, nonce, hashlib.sha256(data).hexdigest()))
            h["X-Signature"] = "v1=" + hmac.new((key or self.skey).encode(), canon.encode(), hashlib.sha256).hexdigest()
        return Resp(self.c.post(path, data=data, headers=h, base_url=BASE))
class Resp:
    def __init__(self, r): self.r = r; self.status_code = r.status_code; self.text = r.get_data(as_text=True)
    def json(self): return json.loads(self.text)
    def raise_for_status(self):
        if self.status_code >= 400: import requests; raise requests.HTTPError(f"HTTP {self.status_code}")
def ev(n, msg=None, **k): return dict(uid=hashlib.sha256(f"{secrets.token_hex(4)}{n}".encode()).hexdigest()[:40], message=msg or f"synthetic event {n}", channel="synthetic", record_id=secrets.randbelow(10 ** 9), event_time=time.strftime("%Y-%m-%dT%H:%M:%S", time.gmtime()), **k)
def count(sql, *a): return db.q(sql, a, one=True)["n"]
def new_queue():
    importlib.reload(AG) if False else None
    for f in ("queue.db", "queue.db-wal", "queue.db-shm"):
        try: os.remove(os.path.join(AG.HOME, f))
        except OSError: pass
    return AG.Queue()
def st(): return dict(sent=0, rejected=0, rej_msg="", rej_until=0)
def pump(cl, q, s, rounds=8):
    for _ in range(rounds):
        try: cl_ok = AG.flush_queue(cl, q, s)
        except Exception: pass
        if q.count() == 0: break
def poison_patch(marker="POISON"):
    def f(items, reprocess_duplicates=False):
        if any(marker in str(i.get("message")) for i in items): raise RuntimeError("boom: secret-looking password=hunter2")
        return REAL_PB(items, reprocess_duplicates=reprocess_duplicates)
    return f

class Ingest(unittest.TestCase):
    def tearDown(self): engine.process_batch = REAL_PB

    def test_01_poison_event_does_not_block_valid_events(self):
        a = Agent("h-poison"); q = new_queue(); s = st(); evs = [ev(1), ev(2, "POISON pill"), ev(3), ev(4)]; q.add(evs); engine.process_batch = poison_patch()
        pump(a, q, s)
        self.assertEqual(q.count(), 0, "queue must drain")
        self.assertEqual(count("SELECT COUNT(*) n FROM events WHERE host='h-poison'"), 3, "all three valid events stored")
        self.assertEqual(count("SELECT COUNT(*) n FROM event_quarantine WHERE agent_id=?", a.id), 1)
        self.assertEqual(q.db.execute("SELECT COUNT(*) FROM dead").fetchone()[0], 1, "poison event dead-lettered locally, not lost")
        qr = db.q("SELECT * FROM event_quarantine WHERE agent_id=?", (a.id,), one=True); self.assertEqual(qr["attempts"], 3); self.assertNotIn("hunter2", qr["payload"] or ""); self.assertTrue(qr["payload"])
        self.assertEqual(count("SELECT COUNT(*) n FROM agent_event_ids WHERE agent_id=? AND status='dead'", a.id), 1)
    def test_02_quarantined_uid_is_rejected_deterministically_on_redelivery(self):
        a = Agent("h-redeliver"); e = ev(1, "POISON x"); engine.process_batch = poison_patch()
        for _ in range(3): a.post("/api/events", {"events": [e]})
        r = a.post("/api/events", {"events": [e]}).json(); self.assertEqual(r["rejected_uids"], [e["uid"]]); self.assertEqual(r["reasons"][e["uid"]], "quarantined")
    def test_03_completely_malformed_batch(self):
        a = Agent("h-bad"); self.assertEqual(a.post("/api/events", {"events": "nope"}).status_code, 400); self.assertEqual(a.post("/api/events", {"events": {"a": 1}}).status_code, 400)
        r = a.post("/api/events", {"events": ["x", 5, None, [], {"message": "no uid"}, {"uid": "x" * 81, "message": "m"}]}); j = r.json()
        self.assertEqual(r.status_code, 200); self.assertEqual(j["rejected"], 6); self.assertEqual((j["accepted_uids"], j["retry_uids"]), ([], []))
        self.assertEqual(count("SELECT COUNT(*) n FROM events WHERE host='h-bad'"), 0)
    def test_04_mixed_valid_and_invalid_batch(self):
        a = Agent("h-mixed"); ok1, ok2 = ev(1), ev(2); bad = [dict(ev(3), message=""), dict(ev(4), event_time="not-a-date"), dict(ev(5), event_time="2099-01-01T00:00:00Z"), dict(ev(6), message="x" * 70000),
                                                           dict(ev(7), record_id=2 ** 70), dict(ev(8), event_id=2 ** 70), dict(ev(9), message=123), dict(ev(10), cpu=float("nan"))]
        j = a.post("/api/events", {"events": [ok1] + bad + [ok2]}).json()
        self.assertEqual(sorted(j["accepted_uids"]), sorted([ok1["uid"], ok2["uid"]])); self.assertEqual(sorted(j["rejected_uids"]), sorted(b["uid"] for b in bad))
        self.assertEqual(j["reasons"][bad[2]["uid"]], "timestamp_in_future"); self.assertEqual(j["reasons"][bad[1]["uid"]], "bad_timestamp"); self.assertEqual(j["reasons"][bad[3]["uid"]], "event_too_large")
        self.assertEqual(j["reasons"][bad[7]["uid"]], "non_finite_number"); self.assertEqual(count("SELECT COUNT(*) n FROM events WHERE host='h-mixed'"), 2); self.assertEqual(count("SELECT COUNT(*) n FROM event_quarantine WHERE agent_id=?", a.id), len(bad))
    def test_05_duplicate_delivery_is_idempotent(self):
        a = Agent("h-dup"); e = ev(1, "Failed password for root from 203.0.113.9 port 22 ssh2", log_only=False)
        r1 = a.post("/api/events", {"events": [e]}).json(); n_ev = count("SELECT COUNT(*) n FROM events WHERE host='h-dup'"); n_al = count("SELECT COUNT(*) n FROM alerts")
        r2 = a.post("/api/events", {"events": [e, e]}).json(); self.assertEqual(r1["accepted_uids"], [e["uid"]]); self.assertEqual(r2["duplicate_uids"], [e["uid"]]); self.assertEqual(r2["accepted_uids"], [])
        self.assertEqual((count("SELECT COUNT(*) n FROM events WHERE host='h-dup'"), count("SELECT COUNT(*) n FROM alerts")), (n_ev, n_al))
    def test_06_in_batch_duplicate_never_acked_before_success(self):
        a = Agent("h-inbatch"); e = ev(1, "POISON twin"); engine.process_batch = poison_patch(); j = a.post("/api/events", {"events": [e, dict(e)]}).json()
        self.assertEqual(j["retry_uids"], [e["uid"]]); self.assertEqual((j["accepted_uids"], j["duplicate_uids"]), ([], []))
    def test_07_temporary_database_failure_is_retried_not_counted(self):
        a = Agent("h-dbbusy"); e = ev(1); calls = {"n": 0}
        def flaky(items, reprocess_duplicates=False):
            calls["n"] += 1
            if calls["n"] <= 1: raise sqlite3.OperationalError("database is locked")
            return REAL_PB(items, reprocess_duplicates=reprocess_duplicates)
        engine.process_batch = flaky; r = a.post("/api/events", {"events": [e]}); self.assertEqual(r.status_code, 503); self.assertTrue(r.json()["retryable"])
        row = db.q("SELECT status,attempts FROM agent_event_ids WHERE agent_id=? AND uid=?", (a.id, e["uid"]), one=True); self.assertEqual((row["status"], row["attempts"] or 0), ("pending", 0))
        r = a.post("/api/events", {"events": [e]}).json(); self.assertEqual(r["accepted_uids"], [e["uid"]]); self.assertEqual(count("SELECT COUNT(*) n FROM event_quarantine WHERE agent_id=?", a.id), 0)
    def test_08_network_interruption_keeps_queue_then_recovers(self):
        import requests
        a = Agent("h-net"); q = new_queue(); s = st(); q.add([ev(i) for i in range(5)]); fails = {"n": 2}; real = a.post
        class Flaky:
            def post(self_, *x, **k):
                if fails["n"]: fails["n"] -= 1; raise requests.ConnectionError("down")
                return real(*x, **k)
        for _ in range(2):
            with self.assertRaises(requests.ConnectionError): AG.flush_queue(Flaky(), q, s)
            self.assertEqual(q.count(), 5)
        AG.flush_queue(Flaky(), q, s); self.assertEqual(q.count(), 0); self.assertEqual(count("SELECT COUNT(*) n FROM events WHERE host='h-net'"), 5)
    def test_09_signature_and_replay(self):
        a = Agent("h-sig"); e = ev(1)
        self.assertEqual(a.post("/api/events", {"events": [e]}, key="wrong" * 8).status_code, 401)
        self.assertEqual(a.post("/api/events", {"events": [e]}, sign=False).status_code, 401, "signing is ratcheted on after the first signed use")  if a.post("/api/events", {"events": []}).status_code == 200 else None
        n = secrets.token_urlsafe(16); self.assertEqual(a.post("/api/events", {"events": [ev(2)]}, nonce=n).status_code, 200); self.assertEqual(a.post("/api/events", {"events": [ev(3)]}, nonce=n).status_code, 409)
        self.assertEqual(a.post("/api/events", {"events": [ev(4)]}, ts=int(time.time()) - 4000).status_code, 400)
        self.assertEqual(count("SELECT COUNT(*) n FROM events WHERE host='h-sig' AND message LIKE '%event 1'"), 0, "rejected requests store nothing")
    def test_10_partial_and_missing_acknowledgements_delete_only_confirmed(self):
        q = new_queue(); s = st(); evs = [ev(i) for i in range(5)]; q.add(evs)
        class Srv:
            def __init__(self, body, code=200): self.body, self.code = body, code
            def post(self, *a, **k): return Fake(self.code, self.body)
        class Fake:
            def __init__(self, code, body): self.status_code, self.body = code, body
            def json(self):
                if isinstance(self.body, Exception): raise self.body
                return self.body
            def raise_for_status(self): pass
        u = [e["uid"] for e in evs]
        AG.flush_queue(Srv({"accepted_uids": [u[0]], "duplicate_uids": [u[1]], "rejected_uids": [u[2]], "retry_uids": [u[3]], "reasons": {u[2]: "bad_timestamp"}}), q, s)
        left = [r[0] for r in q.db.execute("SELECT uid FROM q")]; self.assertEqual(sorted(left), sorted([u[3], u[4]]), "accepted+duplicate deleted, rejected dead-lettered, retry+unaccounted kept")
        self.assertEqual(q.db.execute("SELECT COUNT(*) FROM dead").fetchone()[0], 1); self.assertEqual(s["sent"], 1)
        for bad in ({}, {"ok": True}, [], "ok", None, {"accepted_uids": u, "duplicate_uids": []}, {"accepted_uids": "x", "duplicate_uids": [], "rejected_uids": []}, ValueError("not json")):
            with self.assertRaises(ValueError): AG.flush_queue(Srv(bad), q, s)
            self.assertEqual(q.count(), 2, f"HTTP 200 without per-event ack must delete nothing: {bad!r}")
        with self.assertRaises(ValueError): AG.flush_queue(Srv({"accepted_uids": ["unknown-uid-not-in-batch"], "duplicate_uids": [], "rejected_uids": []}), q, s)
        self.assertEqual(q.count(), 2, "an acknowledgement for a uid that was not in the batch invalidates the reply; nothing is deleted")
    def test_11_lease_conflict_only_delays_that_event_and_stale_lease_recovers(self):
        a = Agent("h-lease"); e1, e2, e3 = ev(1), ev(2), ev(3); c = db.conn()
        c.execute("INSERT INTO agent_event_ids(agent_id,uid,ts,status,claimed_at,attempts) VALUES(?,?,?,'processing',?,0)", (a.id, e2["uid"], db.now(), db.now())); c.commit(); c.close()
        r = a.post("/api/events", {"events": [e1, e2, e3]}); self.assertEqual(r.status_code, 200); j = r.json()
        self.assertEqual(j["retry_uids"], [e2["uid"]]); self.assertEqual(j["reasons"][e2["uid"]], "lease_conflict"); self.assertEqual(sorted(j["accepted_uids"]), sorted([e1["uid"], e3["uid"]]))
        old = db.now(__import__("datetime").datetime.now() - __import__("datetime").timedelta(seconds=600)); db.x("UPDATE agent_event_ids SET claimed_at=? WHERE agent_id=? AND uid=?", (old, a.id, e2["uid"]))
        self.assertEqual(a.post("/api/events", {"events": [e2]}).json()["accepted_uids"], [e2["uid"]])
    def test_12_concurrent_ingestion_loses_and_duplicates_nothing(self):
        a = Agent("h-conc"); evs = [ev(i) for i in range(40)]; res = []; lk = threading.Lock()
        def worker():
            cl = A.app.test_client(); ag = Agent.__new__(Agent); ag.id, ag.cred, ag.skey, ag.c = a.id, a.cred, a.skey, cl
            for _ in range(3):
                j = ag.post("/api/events", {"events": evs}).json() if True else None
                with lk: res.append(j)
        th = [threading.Thread(target=worker) for _ in range(6)]; [t.start() for t in th]; [t.join() for t in th]
        self.assertEqual(count("SELECT COUNT(*) n FROM events WHERE host='h-conc'"), 40, "each event stored exactly once")
        for j in res: self.assertEqual(len(j["accepted_uids"]) + len(j["duplicate_uids"]) + len(j["retry_uids"]) + len(j["rejected_uids"]), 40, "every uid has exactly one outcome")
        done = set(u for j in res for u in j["accepted_uids"] + j["duplicate_uids"]); j = a.post("/api/events", {"events": evs}).json(); done |= set(j["accepted_uids"] + j["duplicate_uids"])
        self.assertEqual(done, {e["uid"] for e in evs}); self.assertEqual(count("SELECT COUNT(*) n FROM agent_event_ids WHERE agent_id=? AND status='processed'", a.id), 40)
        self.assertEqual(sum(len(j["accepted_uids"]) for j in res), len({u for j in res for u in j["accepted_uids"]}), "no uid accepted twice")
    def test_13_restart_recovery_pending_and_dead_letter_survive(self):
        a = Agent("h-restart"); q = new_queue(); s = st(); q.add([ev(1), ev(2, "POISON r"), ev(3)]); engine.process_batch = poison_patch(); AG.RETRY_BASE_S = 60.0
        try: AG.flush_queue(a, q, s)                                                          # poison now 'pending' on the server and HELD on the agent for 60 s
        finally: AG.RETRY_BASE_S = 0.0
        self.assertEqual(q.count(), 1); self.assertEqual(q.held(), 1, "retry hold is persisted"); q.db.close()
        q2 = AG.Queue(); self.assertEqual(q2.count(), 1, "pending event survives an agent restart"); self.assertEqual(q2.held(), 1, "the hold survives the restart too"); self.assertEqual(q2.peek(10), [], "held event is not re-sent early")
        q2.db.execute("UPDATE q SET hold_until=0"); q2.db.commit(); pump(a, q2, s)            # hold expired -> retried until quarantined
        self.assertEqual(q2.count(), 0); self.assertEqual(q2.db.execute("SELECT COUNT(*) FROM dead").fetchone()[0], 1); q2.db.close()
        self.assertEqual(AG.Queue().db.execute("SELECT COUNT(*) FROM dead").fetchone()[0], 1, "dead-letter record survives another restart")
        engine.process_batch = REAL_PB; self.assertEqual(count("SELECT COUNT(*) n FROM events WHERE host='h-restart'"), 2)
    def test_14_local_corrupt_record_does_not_block_queue(self):
        a = Agent("h-corrupt"); q = new_queue(); s = st(); q.add([ev(1), ev(2)]); q.db.execute("UPDATE q SET body='{not json' WHERE seq=(SELECT MIN(seq) FROM q)"); q.db.commit()
        pump(a, q, s); self.assertEqual(q.count(), 0); self.assertEqual(q.db.execute("SELECT reason FROM dead").fetchone()[0], "corrupt local record"); self.assertEqual(count("SELECT COUNT(*) n FROM events WHERE host='h-corrupt'"), 1)
    def test_15_dead_letter_message_names_the_clock(self):
        a = Agent("h-clock"); q = new_queue(); s = st(); q.add([dict(ev(1), event_time="2099-01-01T00:00:00Z")]); pump(a, q, s)
        self.assertIn("rejected", s["rej_msg"]); self.assertIn("clock", s["rej_msg"]); self.assertEqual(s["rejected"], 1)
    def test_16_security_controls_unchanged(self):
        b = Agent("h-rl"); FA.LIMITS.update(REAL_LIMITS); r = A.app.test_client().post("/api/events", json={"events": []}, base_url=BASE); self.assertEqual(r.status_code, 401)
        r = A.app.test_client().get("/api/quarantine", base_url=BASE, headers={"X-Requested-With": "fetch"}); self.assertEqual(r.status_code, 401)
        self.assertEqual(_adm.get("/api/quarantine", base_url=BASE, headers=H).status_code, 200)
        codes = {b.post("/api/events", {"events": []}).status_code for _ in range(REAL_LIMITS["events"][0] + 5)}; self.assertIn(429, codes, "per-agent rate limit still enforced")
if __name__ == "__main__": unittest.main(verbosity=1)
