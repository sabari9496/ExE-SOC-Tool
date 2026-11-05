"""Incident management: groups related alerts into ONE attack story and builds the investigation timeline."""
import json, re
from db import q, x, now, setting, setting_num, RANK
from .util import *
from . import catalog, risk

KILL = ["Initial Access", "Execution", "Persistence", "Privilege Escalation", "Defense Evasion", "Credential Access", "Discovery", "Lateral Movement", "Command and Control", "Exfiltration", "Impact"]
OPEN = ("New", "In Progress", "Contained")

def _window(): return setting_num("incident_window_min", 60, 1, 10080)

def find_open(host, ip, user, ts):
    cut = ago(_window())
    for col, v in (("host", host), ("source_ip", ip), ("username", user)):
        if not v or (col == "source_ip" and is_private(v) and not host): continue
        r = q(f"SELECT * FROM incidents WHERE status IN ('New','In Progress','Contained') AND {col}=? AND last_seen>=? ORDER BY id DESC LIMIT 1", (v, cut), one=True)
        if r: return r
    # an incident that already contains an alert for the same host/IP also matches (host may differ in alias form)
    return None

def attach(alert_id, host, ip, user, severity):
    """Create or extend an incident for this alert. Low alerts only join an existing incident (they never open one: keeps noise out)."""
    if q("SELECT 1 FROM incident_alerts WHERE alert_id=?", (alert_id,), one=True):
        inc = q("SELECT i.* FROM incidents i JOIN incident_alerts ia ON ia.incident_id=i.id WHERE ia.alert_id=?", (alert_id,), one=True)
        if inc: recompute(inc["id"]); return inc["id"]
    inc = find_open(host, ip, user, now())
    if not inc:
        if RANK.get(severity, 1) < RANK["Medium"]: return None
        iid = x("INSERT INTO incidents(title,severity,status,host,username,source_ip,first_seen,last_seen,created,updated) VALUES('New incident',?,'New',?,?,?,?,?,?,?)", (severity, host, user, ip, now(), now(), now(), now()))
    else: iid = inc["id"]
    x("INSERT OR IGNORE INTO incident_alerts VALUES(?,?)", (iid, alert_id)); recompute(iid); return iid

def recompute(iid):
    inc = q("SELECT * FROM incidents WHERE id=?", (iid,), one=True)
    if not inc: return
    al = q("SELECT a.*, en.hostname hostname, m.risk_score rs, m.tactic, m.mitre, m.username uname, m.first_seen mf, m.last_seen ml FROM alerts a JOIN incident_alerts ia ON ia.alert_id=a.id LEFT JOIN endpoints en ON en.id=a.endpoint_id LEFT JOIN alert_meta m ON m.alert_id=a.id WHERE ia.incident_id=? AND a.status!='Suppressed' ORDER BY a.ts", (iid,))
    if not al: return
    tactics = [t for t in KILL if any((a["tactic"] or "") == t for a in al)]
    stages = len(tactics) or 1; score, det = risk.score_incident([a["rs"] or 0 for a in al], stages)
    sev = risk.severity_for(score); top = max(al, key=lambda a: RANK.get(a["severity"], 1))
    if RANK[top["severity"]] > RANK.get(sev, 1): sev = top["severity"]                  # an incident is never rated below its worst alert
    mitre = sorted({a["mitre"] for a in al if a["mitre"]}); cnt = sum(a["count"] or 1 for a in al)
    host = inc["host"] or next((a["hostname"] for a in al if a.get("hostname")), None)
    users = [a["uname"] for a in al if a["uname"]]; user = inc["username"] or (users[0] if users else None)
    title = f"{' → '.join(tactics[:4]) or top['title']}" + (f" on {host}" if host else "") + (f" ({user})" if user else "")
    summary = f"{len(al)} alert(s), {cnt} event(s) across {stages} attack stage(s): " + ", ".join(dict.fromkeys(a["title"] for a in al))
    first = min((a["mf"] or a["ts"]) for a in al); last = max((a["ml"] or a["updated"] or a["ts"]) for a in al)
    x("UPDATE incidents SET title=?,severity=?,risk_score=?,mitre=?,tactics=?,summary=?,score_detail=?,event_count=?,alert_count=?,first_seen=?,last_seen=?,username=?,updated=? WHERE id=?",
      (title[:200], sev, score, ",".join(mitre), ",".join(tactics), summary[:600], json.dumps(det), cnt, len(al), first, last, user, now(), iid))

INTERESTING = (4624, 4625, 4672, 4648, 4688, 4104, 4103, 4698, 4697, 7045, 1102, 104, 4720, 4728, 4732, 4756, 4768, 4769, 4771, 4776, 5140, 5001, 5010, 1116, 1, 3, 8, 10, 11, 13, 22)
def timeline(iid):
    inc = q("SELECT * FROM incidents WHERE id=?", (iid,), one=True)
    if not inc: return None
    al = q("SELECT a.*, en.hostname hostname, m.tactic, m.mitre, m.risk_score, m.reason, m.process, m.command_line, m.parent_process, m.ioc FROM alerts a JOIN incident_alerts ia ON ia.alert_id=a.id LEFT JOIN endpoints en ON en.id=a.endpoint_id LEFT JOIN alert_meta m ON m.alert_id=a.id WHERE ia.incident_id=? ORDER BY a.ts", (iid,))
    t0 = (parse(inc["first_seen"]) or datetime.now()) - timedelta(minutes=30); t1 = (parse(inc["last_seen"]) or datetime.now()) + timedelta(minutes=10)
    hosts = {inc["host"]} - {None} | {h["hostname"] for h in q("SELECT DISTINCT e.hostname FROM endpoints e JOIN alerts a ON a.endpoint_id=e.id JOIN incident_alerts ia ON ia.alert_id=a.id WHERE ia.incident_id=?", (iid,))}
    ips = {inc["source_ip"]} - {None}; ips |= {a["source_ip"] for a in al if a["source_ip"]}
    cond, args = [], [t0.strftime(FMT), t1.strftime(FMT)]
    if hosts: cond.append(f"host IN ({','.join('?'*len(hosts))})"); args += list(hosts)
    if ips: cond.append(f"source_ip IN ({','.join('?'*len(ips))})"); args += list(ips)
    cond.append("alert_id IN (SELECT alert_id FROM incident_alerts WHERE incident_id=?)"); args.append(iid)
    evs = q(f"SELECT id,ts,host,source_ip,username,event_id,channel,activity,risk,message,alert_id FROM events WHERE ts>=? AND ts<=? AND ({' OR '.join(cond)}) ORDER BY ts, id LIMIT 1500", args)
    items = []
    for e in evs:
        keep = e["alert_id"] or (e["event_id"] in INTERESTING and ((e["risk"] or "Normal") != "Normal" or e["event_id"] in (4624, 4625, 4672, 1102, 4698, 4697, 7045, 4104, 22, 3) or PROC_RX.search(e["message"] or "")))
        if keep and (e["channel"] != "EXE-SOC"): items.append(dict(kind="event", ts=e["ts"], event_id=e["event_id"], what=e["activity"] or "Event", host=e["host"], user=e["username"], ip=e["source_ip"], risk=e["risk"], alert_id=e["alert_id"], text=(e["message"] or "")[:300]))
    for a in al: items.append(dict(kind="alert", ts=a["ts"], alert_id=a["id"], what=a["title"], host=a.get("hostname"), severity=a["severity"], tactic=a["tactic"], mitre=a["mitre"], risk=a["risk_score"], text=(a["reason"] or a["message"] or "")[:300], count=a["count"]))
    items.sort(key=lambda i: (i["ts"], 0 if i["kind"] == "event" else 1))
    # collapse long runs of the same event (e.g. 10,000 failed logons) into one aggregated row
    out = []
    for i in items:
        p = out[-1] if out else None
        if p and p["kind"] == "event" == i["kind"] and p["what"] == i["what"] and p["host"] == i["host"] and p["ip"] == i["ip"] and p["user"] == i["user"]:
            p["n"] = p.get("n", 1) + 1; p["last_ts"] = i["ts"]
        else: out.append(i)
    return out[:600]

def answers(iid):
    """The 'final objective' questions answered from stored data."""
    inc = q("SELECT * FROM incidents WHERE id=?", (iid,), one=True)
    if not inc: return None
    al = q("SELECT a.id, a.source_ip, a.title, m.username, m.ioc FROM alerts a JOIN incident_alerts ia ON ia.alert_id=a.id LEFT JOIN alert_meta m ON m.alert_id=a.id WHERE ia.incident_id=?", (iid,))
    tactic = (inc["tactics"].split(",")[-1] if inc["tactics"] else "default"); pb = catalog.playbook_for(tactic if tactic in catalog.IR else (inc["tactics"].split(",")[0] if inc["tactics"] else "default"))
    hosts = sorted({x_ for x_ in [inc["host"]] if x_}); users = sorted({a["username"] for a in al if a.get("username")} | ({inc["username"]} if inc["username"] else set()))
    ips = sorted({a["source_ip"] for a in al if a.get("source_ip")}); iocs = [a["ioc"] for a in al if a.get("ioc")]
    other_hosts = [r["host"] for r in q("SELECT DISTINCT host FROM events WHERE source_ip IN (%s) AND host IS NOT NULL" % ",".join("?" * len(ips)), ips)] if ips else []
    return {"who": users or ["unknown"], "what": inc["summary"], "endpoint": hosts, "origin": ips, "when": f"{inc['first_seen']} → {inc['last_seen']}",
            "mitre": inc["mitre"].split(",") if inc["mitre"] else [], "severity": inc["severity"], "risk_score": inc["risk_score"], "malicious_or_legit": ("Likely malicious" if inc["risk_score"] >= 60 else "Needs analyst validation" if inc["risk_score"] >= 30 else "Probably benign/low confidence"),
            "other_affected": sorted(set(other_hosts) - set(hosts)), "iocs": iocs, "next_steps": pb}
