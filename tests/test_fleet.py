"""End-to-end fleet test over REAL TLS (private CA). Run: python tests/test_fleet.py   (starts its own server on a temp DB, port 5443)"""
import os, sys, time, json, subprocess, tempfile, secrets, shutil, hashlib
ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__))); T = tempfile.mkdtemp(); PORT = 5443; B = f"https://localhost:{PORT}"
subprocess.check_call([sys.executable, os.path.join(ROOT, "tools/dev_certs.py"), "--out", T + "/certs", "--name", "localhost"], stdout=subprocess.DEVNULL)
CA = T + "/certs/ca.pem"
env = dict(os.environ, SOC_DB=T + "/t.db", SOC_PORT=str(PORT), SOC_TLS_CERT=T + "/certs/server.pem", SOC_TLS_KEY=T + "/certs/server.key", SOC_LOCAL_LOGS="0", SOC_SECRET="x" * 32, SOC_ALLOW_FOREIGN_DB="1")
srv = subprocess.Popen([sys.executable, "app.py"], cwd=ROOT, env=env, stdout=open(T + "/srv.log", "w"), stderr=subprocess.STDOUT)
import requests; R = []
def check(name, ok, info=""): R.append(ok); print(("PASS " if ok else "FAIL ") + name, info if not ok else "")
try:
    for _ in range(40):
        try: requests.get(B + "/login", verify=CA, timeout=1); break
        except Exception: time.sleep(0.5)
    admin = requests.Session(); admin.trust_env = False; admin.verify = CA; admin.headers["X-Requested-With"] = "fetch"
    admin.post(B + "/login", data={"username": "admin", "password": "Admin@123"}, allow_redirects=False)
    viewer = requests.Session(); viewer.trust_env = False; viewer.verify = CA; viewer.headers["X-Requested-With"] = "fetch"; viewer.post(B + "/login", data={"username": "viewer", "password": "Viewer@123"}, allow_redirects=False)
    check("viewer cannot create enrollment token", viewer.post(B + "/api/enrollment-tokens", json={}).status_code == 403)
    tok = admin.post(B + "/api/enrollment-tokens", json={"label": "friend-pc", "expires_minutes": 30}).json()["token"]
    check("token stored hashed (no plaintext in DB)", tok.encode() not in open(T + "/t.db", "rb").read())
    sys.path.insert(0, ROOT + "/agent"); import exe_soc_agent as A
    def enroll(token, host="WIN-FRIEND"):
        r = requests.post(B + "/api/agents/register", json={"enrollment_token": token, "hostname": host, "os": "Windows", "os_version": "10.0.22631", "agent_version": "1.0.0"}, verify=CA); return r
    r = enroll(tok); check("Windows enrollment", r.status_code == 200, r.text); d = r.json()
    check("token is single-use", enroll(tok).status_code == 401)
    t2 = admin.post(B + "/api/enrollment-tokens", json={"label": "ubuntu"}).json()["token"]; r2 = enroll(t2, "ubuntu-pc"); check("Ubuntu enrollment (2nd endpoint)", r2.status_code == 200); d2 = r2.json()
    t3 = admin.post(B + "/api/enrollment-tokens", json={"label": "x"}).json(); tid = [t for t in admin.get(B + "/api/enrollment-tokens").json() if t["label"] == "x"][0]["id"]
    admin.post(B + f"/api/enrollment-tokens/{tid}/revoke", json={}); check("revoked token rejected", enroll(t3["token"], "h3").status_code == 401)
    check("bad enrollment token", enroll("exe-bogus").status_code == 401)
    C = A.Client({"server": B, "credential": d["credential"], "ca_bundle": CA}); C2 = A.Client({"server": B, "credential": d2["credential"], "ca_bundle": CA})
    check("heartbeat", C.post("/api/agents/heartbeat", {"agent_version": "1.0.0", "cpu": 12, "mem": 40, "events_queued": 0}).status_code == 200)
    bad = A.Client({"server": B, "credential": d["credential"][:-3] + "xxx", "ca_bundle": CA}); check("invalid credential rejected", bad.post("/api/agents/heartbeat", {}).status_code == 401)
    h = C.hdr if hasattr(C, "hdr") else None
    hd = {"Authorization": "Bearer " + d["credential"], "X-Timestamp": str(int(time.time())), "X-Nonce": "replaynonce12345"}
    a1 = requests.post(B + "/api/agents/heartbeat", json={}, headers=hd, verify=CA).status_code; a2 = requests.post(B + "/api/agents/heartbeat", json={}, headers=hd, verify=CA).status_code
    check("replayed request rejected", a1 == 200 and a2 == 409, (a1, a2))
    old = dict(hd, **{"X-Timestamp": str(int(time.time()) - 3600), "X-Nonce": "oldnonce123456789"}); check("stale timestamp rejected", requests.post(B + "/api/agents/heartbeat", json={}, headers=old, verify=CA).status_code == 400)
    ev = lambda i, ip="203.0.113.9": {"uid": f"u{i}", "message": f"Failed password for invalid user admin from {ip} port 22 ssh2", "channel": "linux/auth", "record_id": 1000 + i, "event_time": time.strftime("%Y-%m-%dT%H:%M:%S", time.gmtime(time.time() - 60 + i)), "log_only": False, "source_ip": ip}
    batch = [ev(i) for i in range(8)]
    r = C2.post("/api/events", {"events": batch}); check("event ingest", r.status_code == 200 and r.json()["accepted"] == 8, r.text)
    r = C2.post("/api/events", {"events": batch}); check("duplicate events ignored", r.json()["duplicates"] == 8, r.text)
    import sqlite3
    with sqlite3.connect(T + "/t.db") as db: db.execute("UPDATE agent_event_ids SET status='pending' WHERE agent_id=? AND uid='u0'", (d2["agent_id"],))
    r = C2.post("/api/events", {"events": [batch[0]]})
    with sqlite3.connect(T + "/t.db") as db: state = db.execute("SELECT status FROM agent_event_ids WHERE agent_id=? AND uid='u0'", (d2["agent_id"],)).fetchone()[0]
    check("pending event retry recovers and finalizes", r.status_code == 200 and r.json()["accepted"] == 1 and state == "processed", (r.status_code, state, r.text))
    time.sleep(0.3); ag = admin.get(B + "/api/agents").json(); check("dashboard lists both agents", len(ag) == 2 and {a["state"] for a in ag} == {"online"}, ag)
    u = [a for a in ag if a["hostname"] == "ubuntu-pc"][0]; check("agent_id tagged events", u["event_count"] == 8, u["event_count"])
    al = admin.get(B + "/api/alerts", params={"agent_id": u["id"]}).json(); check("brute-force alert created & merged (not 8 alerts)", 1 <= len(al) <= 2 and max(a["count"] for a in al) >= 5, [(a["title"], a["count"]) for a in al])
    check("per-agent events API + filter", len(admin.get(B + f"/api/agents/{u['id']}/events", params={"q": "Failed password"}).json()) == 8)
    check("no secrets in agent API", "secret" not in json.dumps(ag).lower() and d["credential"].split(".")[1] not in json.dumps(ag))
    check("viewer cannot revoke", viewer.post(B + f"/api/agents/{u['id']}/revoke", json={}).status_code == 403)
    admin.post(B + f"/api/agents/{u['id']}/revoke", json={}); check("revoked agent rejected", C2.post("/api/events", {"events": [ev(99)]}).status_code == 403)
    check("other agent unaffected", C.post("/api/agents/heartbeat", {}).status_code == 200)
    try: requests.get(B + "/login", timeout=3); check("TLS: unknown CA rejected", False)
    except requests.exceptions.SSLError: check("TLS: unknown CA rejected (verification on)", True)
    check("audit trail records enroll/revoke", sum(1 for a in admin.get(B + "/api/audit").json() if "enrolled" in a["action"] or "revoked" in a["action"]) >= 3)
finally:
    srv.terminate(); shutil.rmtree(T, ignore_errors=True)
print(f"\n{sum(R)}/{len(R)} passed"); sys.exit(0 if all(R) else 1)
