#!/usr/bin/env python3
"""Regression test for: "the agent installs and the heartbeat is accepted, but no logs arrive". Run as root:  sudo python3 tests/test_log_visibility.py
Runs the REAL agent as an unprivileged user against a real TLS server (temp DB) with a stand-in `journalctl` (denied / working modes).
Checks that (1) when the journal cannot be read the reason shows up on the DASHBOARD (agent health) and in status.json, not only in a local log,
(2) logs flow when it can, incl. first-run backfill, (3) events the server refuses are reported instead of silently dropped, (4) a crashing collector is reported."""
import json, os, shutil, subprocess, sys, tempfile, time
ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if os.geteuid() != 0: sys.exit("run as root (needs to run the agent as an unprivileged user)")
T = tempfile.mkdtemp(prefix="exesoc-lv-"); os.chmod(T, 0o755); PORT = 5681; B = f"https://localhost:{PORT}"; R = []
def check(n, ok, info=""): R.append(bool(ok)); print(("PASS " if ok else "FAIL ") + n + ("" if ok else f"\n       {str(info)[-500:]}"), flush=True)
def sh(c, **k): p = subprocess.run(c, capture_output=True, text=True, **k); return p.returncode, p.stdout + p.stderr
def wait_for(fn, t=45, step=0.5):
    end = time.time() + t
    while time.time() < end:
        try:
            r = fn()
            if r: return r
        except Exception: pass
        time.sleep(step)
if subprocess.run(["id", "soctest"], capture_output=True).returncode: sh(["useradd", "-m", "soctest"])
# stand-in journalctl (real semantics: -n, --after-cursor, --since) + state dir the unprivileged user can write
J = T + "/jb"; os.makedirs(J); os.chmod(J, 0o777); open(J + "/journal.jsonl", "w").close(); os.chmod(J + "/journal.jsonl", 0o666)
open(J + "/journalctl", "w").write(open(os.path.join(ROOT, "tests", "fake_journalctl.py")).read()); os.chmod(J + "/journalctl", 0o755)
def mode(m): open(J + "/mode", "w").write(m)
def add(n, text="line"):
    k = sum(1 for _ in open(J + "/journal.jsonl")) + 1
    with open(J + "/journal.jsonl", "a") as f:
        for i in range(n): f.write(json.dumps({"__CURSOR": f"s=a;i={k + i}", "__REALTIME_TIMESTAMP": str(int(time.time() * 1e6)), "MESSAGE": f"{text} {k + i}", "SYSLOG_IDENTIFIER": "sshd", "PRIORITY": "6"}) + "\n")
made_journal_dir = not os.path.isdir("/run/systemd/journal")
if made_journal_dir: os.makedirs("/run/systemd/journal")                      # makes linuxlogs.journal_available() true in a sandbox without systemd
sh([sys.executable, ROOT + "/tools/dev_certs.py", "--out", T + "/certs", "--name", "localhost"]); os.chmod(T + "/certs", 0o755); CA = T + "/certs/ca.pem"
env = dict(os.environ, SOC_DB=T + "/t.db", SOC_PORT=str(PORT), SOC_TLS_CERT=T + "/certs/server.pem", SOC_TLS_KEY=T + "/certs/server.key", SOC_LOCAL_LOGS="0", SOC_SECRET="x" * 32, SOC_ALLOW_FOREIGN_DB="1")
srv = subprocess.Popen([sys.executable, "-W", "ignore", "app.py"], cwd=ROOT, env=env, stdout=open(T + "/srv.log", "w"), stderr=subprocess.STDOUT, start_new_session=True)
import requests
agent = None
try:
    for _ in range(60):
        try: requests.get(B + "/login", verify=CA, timeout=1); break
        except Exception: time.sleep(0.5)
    s = requests.Session(); s.trust_env = False; s.verify = CA; s.headers["X-Requested-With"] = "fetch"; s.post(B + "/login", data={"username": "admin", "password": "Admin@123"}, allow_redirects=False)
    A = T + "/agent"; shutil.copytree(ROOT + "/agent", A, ignore=shutil.ignore_patterns("__pycache__")); sh(["chmod", "-R", "a+rX", T])
    def start_agent(tag, extra=None, files=None):
        global agent
        if agent: agent.terminate(); agent.wait(); agent = None
        H = f"{T}/home-{tag}"; os.makedirs(H, exist_ok=True); shutil.chown(H, "soctest"); os.chmod(H, 0o700)
        tok = s.post(B + "/api/enrollment-tokens", json={"label": tag, "expires_minutes": 30}).json()["token"]
        e = dict(os.environ, PATH=J + ":" + os.environ["PATH"], EXESOC_AGENT_HOME=H, EXESOC_AGENT_CONF=H + "/agent.json", EXESOC_HEARTBEAT_SECONDS="5", SOC_FIM="0", SOC_MALWARE="0", SOC_ACTIVITY="0", **(extra or {}))
        if files: e["SOC_LINUX_FILES"] = files
        r = subprocess.run(["runuser", "-u", "soctest", "--", sys.executable, "-W", "ignore", A + "/exe_soc_agent.py", "enroll", "--accept", "--server", B, "--ca-bundle", CA, "--token", tok, "--name", tag], env=e, capture_output=True, text=True)
        assert r.returncode == 0, r.stdout + r.stderr
        agent = subprocess.Popen(["runuser", "-u", "soctest", "--", sys.executable, "-W", "ignore", A + "/exe_soc_agent.py", "run"], env=e, stdout=open(f"{T}/agent-{tag}.log", "w"), stderr=subprocess.STDOUT, start_new_session=True)
        aid = json.load(open(H + "/agent.json"))["agent_id"]; return aid, H, e
    def health(aid): return s.get(B + f"/api/agents/{aid}").json()
    def evcount(aid): return next(a for a in s.get(B + "/api/agents").json() if a["id"] == aid)["event_count"]

    print("== 1. journal NOT readable by the agent user (the reported symptom) ==")
    mode("denied"); add(3, "hidden"); aid, H, e = start_agent("denied")
    h = wait_for(lambda: (lambda x: x if x["health"].get("collector_errors") else None)(health(aid)))
    check("1a heartbeat is healthy (as reported) ...", h and h["last_heartbeat"], h)
    check("1b ... AND the dashboard now shows WHY there are no logs (needs systemd-journal group)", h and any("systemd-journal" in m for m in h["health"]["collector_errors"]), h and h["health"])
    check("1c nothing was collected (as expected) and status.json carries the same message", evcount(aid) == 0 and any("systemd-journal" in m for m in json.load(open(H + "/status.json"))["collector_errors"]))
    check("1d agent log says it once, with the fix", "collector problem:" in open(f"{T}/agent-denied.log").read() and "usermod -aG systemd-journal" in open(f"{T}/agent-denied.log").read(), open(f"{T}/agent-denied.log").read()[-300:])
    mode("denied_rc1"); aid2, H2, e2 = start_agent("denied2"); h = wait_for(lambda: (lambda x: x if x["health"].get("collector_errors") else None)(health(aid2)))
    check("1e hard permission error (rc=1) is reported too", h and any("insufficient permissions" in m or "permission" in m for m in h["health"]["collector_errors"]), h and h["health"])

    print("== 2. journal readable: logs flow, first-run backfill, problem clears ==")
    mode("ok"); open(J + "/journal.jsonl", "w").close(); add(3, "recent"); aid, H, e = start_agent("ok", {"SOC_LINUX_BACKFILL_MINUTES": "10"})
    check("2a first-run backfill: recent journal lines appear on the dashboard immediately", wait_for(lambda: evcount(aid) >= 3, 40), evcount(aid))
    n0 = evcount(aid); add(4, "live"); check("2b new journal lines keep arriving", wait_for(lambda: evcount(aid) >= n0 + 4, 40), evcount(aid))
    check("2c no problem is reported while everything works", health(aid)["health"].get("collector_errors") == [], health(aid)["health"])
    evs = s.get(B + f"/api/agents/{aid}/events?limit=50").json(); check("2d events carry host and message", any("live" in x["message"] and x["host"] == "ok" for x in evs), evs[:2])

    print("== 3. the server refuses events: no more silent loss ==")
    lg = T + "/future.log"; open(lg, "w").close(); os.chmod(lg, 0o644); aid, H, e = start_agent("rej", {"SOC_LINUX_JOURNAL": "0"}, files=lg); time.sleep(3)
    with open(lg, "a") as f: f.write(f"2099-01-01T00:00:00Z host sshd[1]: Failed password for root from 203.0.113.5 port 22 ssh2\n")
    h = wait_for(lambda: (lambda x: x if any("rejected" in m for m in x["health"].get("collector_errors", [])) else None)(health(aid)), 40)
    check("3a refused events are reported on the dashboard with the likely cause (clock)", h and any("clock" in m for m in h["health"]["collector_errors"]), h and h["health"])
    check("3b status.json counts them", bool(wait_for(lambda: (json.load(open(H + "/status.json")).get("events_rejected", 0) >= 1) or None, 30)), "status.json never showed events_rejected >= 1 within 30 s")

    print("== 4. a crashing collector is reported (unit level) ==")
    sys.path.insert(0, ROOT + "/agent/collectors"); import collect
    class Boom:
        interval = 2
        def poll(self, host): raise OSError("disk exploded")
        def commit(self): pass
    mc = collect.MultiCollector([Boom()], ["x"]); mc.poll("h"); check("4a exception becomes a reported problem", any("disk exploded" in m for m in mc.problems()), mc.problems())
finally:
    if agent: agent.terminate()
    srv.terminate()
    if made_journal_dir: shutil.rmtree("/run/systemd", ignore_errors=True)
    shutil.rmtree(T, ignore_errors=True)
print(f"\n{sum(R)}/{len(R)} passed"); sys.exit(0 if all(R) else 1)
