"""Decides WHETHER and TO WHOM an alert/incident e-mail goes: severity policy, notification types, per-type severity floors, per-recipient severities,
one e-mail per incident per window (rate limit + deduplication) and a global hourly cap."""
import re, time
from db import q, x, now, RANK
from . import config

RK = {"Info": 0, "Low": 1, "Medium": 2, "High": 3, "Critical": 4}
def rank(s): return RK.get(s, RANK.get(s, 0))
def top(a, b): return a if rank(a) >= rank(b) else b

def classify(alert, meta, inc, first_in_incident):
    """-> notification type. Specific types win over generic ones."""
    title = (alert.get("title") or "").lower(); det = (re.match(r"^\[([A-Z]{3}-\d{3})\]", alert.get("message") or "") or [None, ""])[1]
    if det == "HLT-001" or "stopped sending logs" in title or "agent offline" in title: return "agent_offline"
    if (meta or {}).get("ioc") or "ioc" in title.split() or "known-bad" in title or "threat intel" in title: return "ioc"
    if det == "THR-006" or "outbound" in title: return "large_outbound"
    if det.startswith("SEQ-"): return "new_incident" if first_in_incident else "high_alert"
    if det in ("THR-005", "THR-004") or "port scan" in title or "network discovery" in title: return "network_attack"
    if det in ("THR-001", "THR-002", "THR-007") or any(k in title for k in ("brute force", "password spray", "multiple failures", "failed login", "kerberoast", "lockout", "impossible")): return "auth_attack"
    return "new_incident" if (first_in_incident and inc) else "high_alert"

def effective_severity(ntype, alert, inc):
    sev = alert.get("severity") or "Low"
    if ntype in ("new_incident",) and inc: sev = top(sev, inc.get("severity") or sev)
    floor = {"agent_offline": "floor_agent_offline", "network_attack": "floor_network_attack"}.get(ntype)
    return top(sev, config.get(floor) or "Low") if floor else sev

def severity_enabled(sev): return config.on("sev_" + str(sev).lower())

def recipients_for(severity, levels=(1,)):
    out = []
    for r in q("SELECT * FROM notification_recipients WHERE enabled=1 ORDER BY id"):
        if r["level"] not in levels and not (max(levels) >= 2 and r["level"] >= 2 and 2 in levels): continue
        sv = [s for s in (r["severities"] or "").split(",") if s]
        if sv and severity not in sv: continue
        out.append(r["email"])
    return out

def decide(alert_id, iid):
    """-> dict(ntype, severity, key, update, occurrences, recipients) or (None, reason)."""
    if not config.on("enabled"): return None, "disabled"
    a = q("SELECT * FROM alerts WHERE id=?", (alert_id,), one=True)
    if not a or a.get("status") == "Suppressed": return None, "suppressed by whitelist"          # whitelisted alerts never e-mail
    meta = q("SELECT * FROM alert_meta WHERE alert_id=?", (alert_id,), one=True) or {}
    inc = q("SELECT * FROM incidents WHERE id=?", (iid,), one=True) if iid else None
    first = bool(inc) and q("SELECT COUNT(*) c FROM incident_alerts WHERE incident_id=?", (iid,), one=True)["c"] == 1
    ntype = classify(a, meta, inc, first)
    if not config.on("type_" + ntype): return None, f"type {ntype} disabled"
    sev = effective_severity(ntype, a, inc)
    if not severity_enabled(sev): return None, f"severity {sev} not enabled"
    key = f"INC:{iid}" if iid else f"ALR:{a['title']}:{a.get('endpoint_id')}:{a.get('source_ip')}"
    occ = (inc or {}).get("event_count") if inc else a.get("count"); occ = occ or 1
    d = q("SELECT * FROM notification_dedupe WHERE key=?", (key,), one=True); window = config.num("rate_limit_min", 15) * 60; t = time.time(); update = False
    if d:
        within = t - d["last_sent"] < window; worse = rank(sev) > rank(d["severity"])
        if within and not worse:
            x("UPDATE notification_dedupe SET suppressed=suppressed+1,occurrences_last=? WHERE key=?", (occ, key)); return None, "rate limited (one e-mail per incident per window)"
        if not within and not worse:
            if not config.on("send_updates") or occ <= d["occurrences_last"]: return None, "no new activity since the last e-mail"
            update = True
        if worse: update = True
    cap = config.num("max_per_hour", 60)
    if cap and q("SELECT COUNT(DISTINCT notification_id) c FROM notification_history WHERE ts>=datetime('now','localtime','-1 hour') AND ntype!='test'", one=True)["c"] >= cap:
        if d: x("UPDATE notification_dedupe SET suppressed=suppressed+1 WHERE key=?", (key,))
        return None, "hourly e-mail cap reached"
    rec = recipients_for(sev)
    rec = under_recipient_cap(rec)
    if not rec: return None, "no enabled recipient for this severity (or the per-recipient hourly cap was reached)"
    return dict(ntype=ntype, severity=sev, key=key, update=update, occurrences=occ, recipients=rec, incident_id=iid), "ok"

def under_recipient_cap(rec):
    """Per-recipient flood protection (in addition to the global hourly cap): drop recipients that already received max_per_recipient_hour messages in the last hour."""
    pcap = config.num("max_per_recipient_hour", 30)
    if not pcap: return list(rec)
    return [e for e in rec if q("SELECT COUNT(*) c FROM notification_history WHERE recipient=? AND ts>=datetime('now','localtime','-1 hour') AND ntype!='test'", (e,), one=True)["c"] < pcap]

def record_sent(key, iid, alert_id, sev, occ):
    t = time.time(); d = q("SELECT 1 FROM notification_dedupe WHERE key=?", (key,), one=True)
    if d: x("UPDATE notification_dedupe SET last_sent=?,severity=?,sent_count=sent_count+1,occurrences_last=? WHERE key=?", (t, sev, occ, key))
    else: x("INSERT INTO notification_dedupe(key,incident_id,alert_id,first_sent,last_sent,severity,sent_count,suppressed,occurrences_last) VALUES(?,?,?,?,?,?,1,0,?)", (key, iid, alert_id, t, t, sev, occ))
