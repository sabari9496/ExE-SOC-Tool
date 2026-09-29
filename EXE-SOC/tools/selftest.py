#!/usr/bin/env python3
"""End-to-end self-test. Start the SOC on an EMPTY database first, then:
   python tools/selftest.py [--server http://127.0.0.1:5000] [--admin-pass Admin@123]
Do not run against production data: it creates test alerts, cases and blocklist entries."""
import argparse, sys, time, requests
a = argparse.ArgumentParser(); a.add_argument("--server", default="http://127.0.0.1:5000")
a.add_argument("--admin-pass", default="Admin@123"); a.add_argument("--analyst-pass", default="Analyst@123"); a.add_argument("--viewer-pass", default="Viewer@123")
o = a.parse_args(); S = o.server.rstrip("/"); H = {"X-Requested-With": "fetch"}
res = []
def check(name, cond, extra=""):
    res.append(bool(cond)); print(("  PASS  " if cond else "  FAIL  ") + name + (f"  [{extra}]" if extra and not cond else ""))
def login(u, p):
    s = requests.Session(); r = s.post(S + "/login", data={"username": u, "password": p}, allow_redirects=False); return s, r
def J(r):
    try: return r.json()
    except Exception: return {}

print("\n[1] Auth & roles")
adm, r = login("admin", o.admin_pass); check("admin login", r.status_code == 302)
ana, r = login("analyst", o.analyst_pass); check("analyst login", r.status_code == 302)
vw, r = login("viewer", o.viewer_pass); check("viewer login", r.status_code == 302)
check("anonymous API blocked", requests.get(S + "/api/alerts").status_code == 401)
check("viewer cannot modify (403)", vw.post(S + "/api/cases", headers=H, json={"title": "x"}).status_code == 403)
check("viewer cannot read users (403)", vw.get(S + "/api/users").status_code == 403)
check("analyst cannot read users (403)", ana.get(S + "/api/users").status_code == 403)
check("admin reads users", adm.get(S + "/api/users").status_code == 200)
check("CSRF guard (missing header -> 400)", adm.post(S + "/api/cases", json={"title": "x"}).status_code == 400)
KEY = J(adm.get(S + "/api/settings")).get("api_key"); check("API key visible to admin", bool(KEY))
check("bad API key rejected", requests.post(S + "/api/ingest", headers={"X-API-Key": "nope"}, json={"message": "x"}).status_code == 401)
K = {"X-API-Key": KEY}

print("\n[2] Detection rules (ingest -> alert)")
rules = [("GET /login.php?id=1' OR 1=1--", "Possible SQL Injection", "Critical", "9.9.9.1"),
         ("GET /s?q=<script>alert(1)</script>", "Cross-Site Scripting Attempt", "Medium", "9.9.9.2"),
         ("GET /../../etc/passwd", "Path Traversal Attempt", "High", "9.9.9.3"),
         ("Malware detected: Trojan.Win32.Generic", "Malware Detected", "High", "9.9.9.4"),
         ("sudo: user not in sudoers file", "Privilege Escalation Attempt", "High", "9.9.9.5"),
         ("Port scan detected from host", "Port Scan Detected", "Medium", "9.9.9.6"),
         ("Unusual DNS query to rare TLD", "Unusual DNS Query", "Low", "9.9.9.7")]
for msg, title, sev, ip in rules:
    requests.post(S + "/api/ingest", headers=K, json={"source_ip": ip, "message": msg, "dest_ip": "10.0.2.8:80"})
al = {x["source_ip"]: x for x in J(adm.get(S + "/api/alerts?limit=500")) if isinstance(x, dict)}
for msg, title, sev, ip in rules:
    x = al.get(ip); check(f"rule: {title}", x and x["title"] == title and x["severity"] == sev, str(x and (x["title"], x["severity"])))
r = J(requests.post(S + "/api/ingest", headers=K, json={"message": "nothing interesting here", "source_ip": "9.9.9.8"})); check("benign event creates no alert", r.get("alert_ids") == [None])
r = requests.post(S + "/api/ingest", headers=K, json=[{"source_ip": "9.9.9.9", "message": "Failed password for root"}] * 3); check("batch ingest", J(r).get("processed") == 3)

print("\n[3] De-duplication & brute-force escalation")
x = [i for i in J(adm.get(S + "/api/alerts?limit=500")) if i["source_ip"] == "9.9.9.9"]
check("identical alerts merge (1 alert, count 3)", len(x) == 1 and x[0]["count"] == 3, str([(i["id"], i["count"]) for i in x]))
for _ in range(6): requests.post(S + "/api/ingest", headers=K, json={"source_ip": "9.9.9.10", "message": "Failed password for admin from 9.9.9.10"})
x = [i for i in J(adm.get(S + "/api/alerts?limit=500")) if i["source_ip"] == "9.9.9.10"]
check("brute force escalates to Critical", x and x[0]["severity"] == "Critical" and "failed logins" in (x[0]["note"] or ""), str(x and x[0]["severity"]))

print("\n[4] Threat intel, blocklist & playbooks")
check("critical brute-force auto-blocked by playbook", any(b["ip"] == "9.9.9.10" for b in J(adm.get(S + "/api/blocklist"))))
check("critical alert auto-opens a case", any("[Auto]" in c["title"] for c in J(adm.get(S + "/api/cases"))))
check("add IOC", J(ana.post(S + "/api/iocs", headers=H, json={"value": "9.9.9.20", "source": "selftest"})).get("ok"))
requests.post(S + "/api/ingest", headers=K, json={"source_ip": "9.9.9.20", "message": "Port scan detected"})
x = [i for i in J(adm.get(S + "/api/alerts?limit=500")) if i["source_ip"] == "9.9.9.20"]
check("IOC hit escalates to Critical", x and x[0]["severity"] == "Critical")
check("private IP cannot be blocked", ana.post(S + "/api/blocklist", headers=H, json={"ip": "192.168.1.5"}).status_code == 400)
check("manual block + unblock", J(ana.post(S + "/api/blocklist", headers=H, json={"ip": "9.9.9.30", "reason": "t"})).get("ok") and ana.delete(S + "/api/blocklist/9.9.9.30", headers=H).status_code == 200)
check("intel lookup", J(adm.get(S + "/api/intel/9.9.9.10")).get("alerts", 0) >= 1)
check("invalid IP rejected", adm.get(S + "/api/intel/notanip").status_code == 400)

print("\n[5] Investigation drill-down")
aid = al["9.9.9.1"]["id"]; d = J(adm.get(S + f"/api/alerts/{aid}/detail"))
check("alert detail: alert + events", d.get("alert", {}).get("id") == aid and len(d.get("events", [])) >= 1)
check("alert detail: MITRE mapping", (d.get("mitre") or {}).get("id") == "T1190")
check("alert detail: recommended actions", len(d.get("recommended", [])) >= 1)
check("alert detail: embedded IP profile", (d.get("ip") or {}).get("ip") == "9.9.9.1")
p = J(adm.get("%s/api/investigate/ip/9.9.9.10" % S)); check("IP profile: risk, events, MITRE", p.get("risk_score", 0) > 0 and p.get("events", 0) >= 6 and p.get("mitre"))
check("IP profile: blocked flag", bool(p.get("blocked")))
check("alert note + activity log", J(ana.post(S + f"/api/alerts/{aid}/note", headers=H, json={"note": "selftest"})).get("ok") and any("selftest" in a["action"] for a in J(adm.get(S + f"/api/alerts/{aid}/detail"))["activity"]))
check("status change (analyst)", J(ana.patch(S + f"/api/alerts/{aid}", headers=H, json={"status": "Resolved"})).get("ok"))
check("404 for missing alert", adm.get(S + "/api/alerts/999999/detail").status_code == 404)

print("\n[6] SPL search")
def spl(q): return adm.get(S + "/api/spl", params={"q": q})
r = J(spl('index=events "failed password" | stats count by source_ip | sort -count | head 3')); check("stats/sort/head", r.get("rows") and r["rows"][0]["source_ip"] == "9.9.9.10")
check("alerts filter + table", J(spl("index=alerts severity=Critical | table id title")).get("columns") == ["id", "title"])
check("wildcard", J(spl("index=events source_ip=9.9.9.* | head 2")).get("rows"))
check("top", J(spl("index=alerts | top severity")).get("columns") == ["severity", "count", "percent"])
check("timechart", J(spl("index=events | timechart span=1h")).get("columns") == ["time", "count"])
check("bad index -> 400", spl("index=x").status_code == 400); check("bad field -> 400", spl("index=alerts nofield=1").status_code == 400)
check("bad command -> 400", spl("index=alerts | drop").status_code == 400)
check("SQL injection attempt is harmless", spl("index=alerts title=\"x' OR '1'='1\"").status_code == 200 and not J(spl("index=alerts title=\"x' OR '1'='1\"")).get("rows"))

print("\n[7] Endpoints, cases, reports, settings")
check("agent heartbeat", requests.post(S + "/api/agent/heartbeat", headers=K, json={"hostname": "TEST-PC", "os": "Linux", "cpu": 12, "ram": 34}).status_code == 200)
e = [i for i in J(adm.get(S + "/api/endpoints")) if i["hostname"] == "TEST-PC"]; check("endpoint appears Online", e and e[0]["status"] == "Online")
check("isolate endpoint", ana.patch(S + f"/api/endpoints/{e[0]['id']}", headers=H, json={"isolated": True}).status_code == 200 and [i for i in J(adm.get(S + "/api/endpoints")) if i["hostname"] == "TEST-PC"][0]["status"] == "At Risk")
c = J(ana.post(S + "/api/cases", headers=H, json={"title": "selftest case", "priority": "High"})).get("id"); check("create case", c)
ana.patch(S + f"/api/cases/{c}", headers=H, json={"note": "hello", "status": "In Progress"}); cd = J(adm.get(S + f"/api/cases/{c}")); check("case note + status", cd.get("status") == "In Progress" and len(cd.get("notes", [])) == 1)
check("alert -> case", J(ana.post(S + f"/api/alerts/{aid}/case", headers=H)).get("id"))
rp = J(adm.get(S + "/api/reports?days=7")); check("reports totals", rp.get("total", 0) >= 10 and rp.get("by_severity"))
csv = adm.get(S + "/api/reports/export.csv"); check("CSV export", csv.status_code == 200 and "text/csv" in csv.headers.get("content-type", ""))
check("dashboard API", J(adm.get(S + "/api/dashboard")).get("kpi", {}).get("total"))
check("global search", len(J(adm.get(S + "/api/search?q=9.9.9"))) > 0)
check("audit trail recorded", len(J(adm.get(S + "/api/audit"))) > 5); check("viewer blocked from audit", vw.get(S + "/api/audit").status_code == 403)
check("update setting", J(adm.put(S + "/api/settings", headers=H, json={"retention_days": "90"})).get("ok"))
check("create user (admin)", J(adm.post(S + "/api/users", headers=H, json={"username": "st_user", "password": "Sup3rsecret!", "role": "viewer"})).get("ok"))
check("weak password rejected", adm.post(S + "/api/users", headers=H, json={"username": "st2", "password": "123", "role": "viewer"}).status_code == 400)
print("\n[8] Pages render")
for pg in ["", "alerts", "endpoints", "network", "threat-intel", "cases", "reports", "search", "logs", "playbooks", "settings", "users"]:
    check(f"page /{pg}", adm.get(f"{S}/{pg}").status_code == 200)
print("\n[9] Login lockout (last, uses this machine's IP)")
for _ in range(6): requests.post(S + "/login", data={"username": "admin", "password": "wrong"})
check("lockout after repeated failures", "Too many" in requests.post(S + "/login", data={"username": "admin", "password": o.admin_pass}).text)
print(f"\n{sum(res)}/{len(res)} checks passed"); sys.exit(0 if all(res) else 1)
