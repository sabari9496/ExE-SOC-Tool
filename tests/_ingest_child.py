"""Helper process for tests (real separate OS process, same SQLite file). Usage: _ingest_child.py MODE   (reads JSON job from env CHILD_JOB)
MODE post: sign + POST the events N times through the real Flask app.  MODE crash: same, but the process is killed (os._exit) right after events are persisted."""
import os, sys, json, time, hmac, hashlib, secrets
ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__))); sys.path.insert(0, ROOT)
job = json.loads(os.environ["CHILD_JOB"]); mode = sys.argv[1]
import db, app as A, engine
if mode == "crash":
    real = engine._detect
    def die(*a, **k): os._exit(9)                 # events are already committed at this point; ledger still 'processing'
    engine._detect = die
c = A.app.test_client(); out = []
for _ in range(job.get("repeat", 1)):
    data = json.dumps({"events": job["events"]}, separators=(",", ":")).encode(); ts = str(int(time.time())); nonce = secrets.token_urlsafe(16)
    canon = "\n".join(("EXESOC-HMAC-SHA256-V1", "POST", "/api/events", ts, nonce, hashlib.sha256(data).hexdigest()))
    h = {"Authorization": "Bearer " + job["cred"], "X-Timestamp": ts, "X-Nonce": nonce, "Content-Type": "application/json", "X-Signature": "v1=" + hmac.new(job["skey"].encode(), canon.encode(), hashlib.sha256).hexdigest()}
    r = c.post("/api/events", data=data, headers=h, base_url="http://127.0.0.1:5000"); out.append([r.status_code, r.get_json(silent=True)])
print(json.dumps(out))
