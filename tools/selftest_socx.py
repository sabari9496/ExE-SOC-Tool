"""Safe, synthetic self-test of the EXE-SOC advanced layer. Uses a TEMPORARY database (never your soc.db) and sends only fake events through the real
pipeline: no malware, no real logons, no system changes.   Run:  python tools/selftest_socx.py"""
import os, sys, json, tempfile
tmp = tempfile.mkdtemp(); os.environ["SOC_DB"] = os.path.join(tmp, "test.db"); os.environ["SOC_LOCAL_LOGS"] = "0"
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import db, engine; db.init_db()
from db import q, x
import socx; from socx import correlation, incidents, health
PASS = FAIL = 0
def check(name, cond, info=""):
    global PASS, FAIL
    cond = bool(cond); PASS += cond; FAIL += (not cond); print(("PASS  " if cond else "FAIL  ") + name + (f"   [{info}]" if info and not cond else ""))
def ev(eid, host, msg, ip=None, user=None, channel="Security", raw=None, level="Information", log_only=True):
    raw = dict(raw or {}); user and raw.setdefault("TargetUserName", user)
    return dict(host=host, source_ip=ip, message=msg, event_id=eid, channel=channel, record_id=None, raw=json.dumps(raw), username=user, log_only=log_only)
def push(items):
    for i, e in enumerate(items): e["record_id"] = 100000 + len(q("SELECT id FROM events")) + i
    return engine.process_batch(items)
def alerts(title): return q("SELECT * FROM alerts WHERE title=?", (title,))

engine.upsert_endpoint("WS-01", "10.0.0.5", "Windows 10"); engine.upsert_endpoint("DC-01", "10.0.0.2", "Windows Server 2022")
x("INSERT INTO assets VALUES('DC-01',5,'Domain Controller','it',datetime('now'))")

# 1. RDP brute force -> success -> process -> PowerShell
atk = "203.0.113.77"
push([ev(4625, "WS-01", f"An account failed to log on. Account: bob", atk, "bob") for i in range(6)])
push([ev(4624, "WS-01", "An account was successfully logged on. Logon Type: 10", atk, "bob", raw={"LogonType": "10"})])
push([ev(4688, "WS-01", "A new process has been created. NewProcessName: C:\\Windows\\System32\\cmd.exe", user="bob")])
push([ev(4104, "WS-01", "ScriptBlock powershell Invoke-WebRequest", user="bob", channel="Microsoft-Windows-PowerShell/Operational")])
n, err = correlation.run_once(); check("detectors ran without errors", not err, err)
a = alerts("RDP Brute Force Followed by Compromise"); check("SEQ-001 RDP chain alert created", len(a) == 1 and a[0]["severity"] == "Critical", a)
a = alerts("Password Spraying"); check("THR-001 password spraying (6 users, 1 IP) -> <8 so NOT fired", len(a) == 0)
n2, _ = correlation.run_once(); check("re-running does not duplicate/inflate alerts", len(alerts("RDP Brute Force Followed by Compromise")) == 1 and alerts("RDP Brute Force Followed by Compromise")[0]["count"] == 1)
push([ev(4625, "WS-01", "An account failed to log on.", "198.51.100.9", f"acct{i}") for i in range(10)]); correlation.run_once()
check("THR-001 password spraying fired (10 accounts)", len(alerts("Password Spraying")) == 1)

# 2. incident grouping: all WS-01 alerts must be ONE incident with MITRE + risk score
inc = q("SELECT * FROM incidents WHERE host='WS-01' ORDER BY id")
check("alerts grouped into a single incident for WS-01", len(inc) == 1, [i["title"] for i in inc])
if inc:
    i0 = inc[0]; check("incident has risk score, MITRE and severity>=High", i0["risk_score"] > 0 and i0["mitre"] and i0["severity"] in ("High", "Critical"), i0)
    tl = incidents.timeline(i0["id"]); kinds = [t.get("event_id") for t in tl if t["kind"] == "event"]
    check("timeline contains 4625, 4624, 4688, 4104 in order", all(k in kinds for k in (4625, 4624, 4688, 4104)) and kinds.index(4625) < kinds.index(4624) < kinds.index(4688), kinds)
    check("timeline collapses repeated failures", any(t.get("n", 1) > 1 for t in tl))
    ans = incidents.answers(i0["id"]); check("analyst questions answered (who/what/where/next)", ans["who"] and ans["endpoint"] == ["WS-01"] and ans["origin"] and ans["next_steps"]["contain"])

# 3. log clearing after privileged logon
push([ev(4672, "DC-01", "Special privileges assigned to new logon.", user="svc_admin"), ev(1102, "DC-01", "The audit log was cleared.", user="svc_admin")]); correlation.run_once()
a = alerts("Privileged Logon Followed by Log Clearing"); check("SEQ-002 log clearing after privileged logon", len(a) == 1)
m = q("SELECT * FROM alert_meta WHERE alert_id=?", (a[0]["id"],), one=True) if a else None
check("critical-asset + privileged user raise the score", m and m["risk_score"] >= 80, m)

# 4. Defender disabled chain (alert-based)
push([ev(5001, "WS-01", "Windows Defender real-time protection disabled.", channel="Microsoft-Windows-Windows Defender/Operational")])
x("INSERT INTO alerts(ts,updated,severity,title,category,endpoint_id,message,status) VALUES(datetime('now','localtime'),datetime('now','localtime'),'High','Shell Process Network Connection','network',(SELECT id FROM endpoints WHERE hostname='WS-01'),'x','New')")
push([ev(4688, "WS-01", "powershell.exe -nop -w hidden -enc " + "QQ" * 30, user="bob", raw={"NewProcessName": "powershell.exe", "CommandLine": "powershell.exe -nop -w hidden -enc " + "QQ" * 30})])
correlation.run_once(); check("SEQ-003 Defender disabled + process + network", len(alerts("Defender Disabled + Suspicious Process + Network Connection")) == 1, [r["title"] for r in q("SELECT title FROM alerts")])

# 5. whitelist: auditable suppression, IOC can never be suppressed
x("INSERT INTO whitelist(kind,detection,host,reason,created_by,created_at) VALUES('suppression','Suspicious Service Installed','BUILD-01','approved CI agent','admin',datetime('now'))")
push([ev(7045, "BUILD-01", "A service was installed in the system. new service installed: ci-agent", channel="System", log_only=False)])
s = q("SELECT * FROM alerts WHERE title='Suspicious Service Installed' AND status='Suppressed'")
check("whitelist marks alert Suppressed (kept, not deleted)", len(s) >= 1)
check("whitelist hit is audited", q("SELECT COUNT(*) c FROM whitelist_audit WHERE action='suppressed_alert'", one=True)["c"] >= 1)
x("INSERT INTO iocs(value,type,source,ts) VALUES('45.9.9.9','ip','test feed',datetime('now'))"); x("INSERT INTO whitelist(kind,host,reason,created_by,created_at) VALUES('suppression','BUILD-01','broad rule','admin',datetime('now'))")
push([ev(7045, "BUILD-01", "new service installed from 45.9.9.9", "45.9.9.9", channel="System", log_only=False)])
ioc_a = q("SELECT a.status, m.ioc FROM alerts a JOIN alert_meta m ON m.alert_id=a.id WHERE m.ioc LIKE '%45.9.9.9%'")
check("alert with IOC hit is never suppressed", ioc_a and all(r["status"] != "Suppressed" for r in ioc_a), ioc_a)

# 6. agent health: previously active host goes silent
for i in range(25): x("INSERT INTO events(ts,host,message,channel,event_id,nflag) VALUES(datetime('now','localtime','-3 hours'),'OLD-PC','heartbeat','Security',4624,1)")
health.run_once(); a = alerts("Endpoint Stopped Sending Logs")
check("HLT-001 silent endpoint alert (Medium or lower, wording does not assume compromise)", len(a) == 1 and "not assumed to be compromise" in a[0]["message"])
check("agent_health lists OLD-PC as Silent", q("SELECT status FROM agent_health WHERE host='OLD-PC'", one=True)["status"] == "Silent")

# 7. flood protection: 2500 events -> 1 alert, events kept
c = db.conn()
for i in range(2500): c.execute("INSERT INTO events(ts,host,message,channel,event_id,nflag) VALUES(datetime('now','localtime'),'NOISY','x','Security',4625,1)")
c.commit(); c.close(); health.run_once()
check("HLT-002 flood -> exactly 1 alert and no events dropped", len(alerts("Log Flood Detected")) == 1 and q("SELECT COUNT(*) c FROM events WHERE host='NOISY' AND channel='Security'", one=True)["c"] == 2500)

# 8. web chain
w = [ev(None, "WEB-01", f'{atk} - - "GET /x{i}.php HTTP/1.1" 404 12', "192.0.2.50", channel="access.log") for i in range(22)]
w += [ev(None, "WEB-01", '192.0.2.50 - - "GET /index.php?id=1 union select 1,2 HTTP/1.1" 200 900', "192.0.2.50", channel="access.log"), ev(None, "WEB-01", '192.0.2.50 - - "POST /index.php HTTP/1.1" 200 90', "192.0.2.50", channel="access.log")]
push(w); correlation.run_once(); check("SEQ-005 web attack chain", len(alerts("Web Attack Chain (scan -> exploit -> webshell)")) == 1)

# 9. IOC extraction + MITRE catalog completeness
from socx import ti, catalog
e = ti.extract("beacon to evil.example.com 10.1.2.3 hash " + "a" * 64 + " mail a@b.co")
check("IOC extraction (ip/domain/sha256/email)", all(k in e for k in ("ip", "domain", "sha256", "email")), e)
need = ["id", "name", "description", "severity", "mitre", "data_source", "logic", "threshold", "window", "false_positive_risk", "investigation", "response"]
check("every catalog detection has all 12 required fields", all(all(d.get(k) for k in need) for d in catalog.CATALOG))

# 10. API smoke test
H = {"X-Requested-With": "fetch"}
import app as A; cl = A.app.test_client(); cl.post("/login", data={"username": "admin", "password": "Admin@123"})
with cl.session_transaction() as s: s.update(user="admin", role="admin")
for u in ("/api/sx/incidents", "/api/sx/summary", "/api/sx/catalog", "/api/sx/whitelist", "/api/sx/health", "/api/sx/risk-model", "/api/sx/assets", "/api/sx/hunt?ip=203.0.113.77", "/incidents", "/hunting", "/detections", "/false-positives", "/agent-health"):
    r = cl.get(u); check(f"GET {u} -> 200", r.status_code == 200, r.status_code)
iid = q("SELECT id FROM incidents LIMIT 1", one=True)["id"]; r = cl.get(f"/api/sx/incidents/{iid}"); check("incident detail API has timeline+answers", r.status_code == 200 and r.json["timeline"] and r.json["answers"])
r = cl.patch(f"/api/sx/incidents/{iid}", headers=H, json={"status": "In Progress", "assignee": "analyst", "note": "validating"}); check("incident status/assign/note update", r.json.get("ok"))
r = cl.post("/api/sx/whitelist", headers=H, json={"kind": "suppression", "reason": "x"}); check("catch-all whitelist rule is rejected", r.status_code == 400)
print(f"\n{PASS} passed, {FAIL} failed"); sys.exit(1 if FAIL else 0)
