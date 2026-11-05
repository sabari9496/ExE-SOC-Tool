"""EXE-SOC advanced layer (incidents, correlation, risk, false-positive management, agent health, hunting).
Integrates with the existing app through three tiny hooks: socx.init(), socx.on_alert(), socx.start() and one Flask blueprint."""
import json, threading, traceback
from db import q, x, now, conn
from .schema import SCHEMA
from . import catalog, risk, fp, incidents, ti
from .util import field as _field

def init():
    c = conn(); c.executescript(SCHEMA)
    for k, (m, t) in catalog.MITRE.items(): c.execute("INSERT OR IGNORE INTO mitre_map VALUES(?,?,?)", (k, m, t))
    c.commit(); c.close()

def _ctx(ev):
    r = q("SELECT * FROM events WHERE id=?", (ev,), one=True) or {}
    f = lambda *n: _field(r, *n) if r else None
    return r, dict(username=(r.get("username") or f("TargetUserName", "SubjectUserName", "User")), process=f("NewProcessName", "Image", "ProcessName"),
                   command_line=f("CommandLine"), parent=f("ParentProcessName", "ParentImage", "ParentProcess"), host=r.get("host"),
                   text=((r.get("message") or "") + " " + (f("CommandLine") or "")), event_id=r.get("event_id"), channel=r.get("channel"))

def on_alert(alert_id, ev):
    """Called by engine._detect for every new OR merged alert. Never raises."""
    try:
        a = q("SELECT a.*, e.hostname hostname FROM alerts a LEFT JOIN endpoints e ON e.id=a.endpoint_id WHERE a.id=?", (alert_id,), one=True)
        if not a: return
        r, c = _ctx(ev); host = a["hostname"] or c["host"]; mitre, tactic = catalog.MITRE.get(a["title"], ("", ""))
        iocs = ti.lookup((a["message"] or "") + " " + (a["source_ip"] or "") + " " + (c["text"] or ""))
        meta = q("SELECT * FROM alert_meta WHERE alert_id=?", (alert_id,), one=True)
        if not meta or meta.get("suppressed_by") is None:
            rule = None if iocs else fp.match(a, dict(c, host=host))
            if rule and not (meta and meta.get("suppressed_by")):
                fp.hit(rule, dict(a, hostname=host)); x("UPDATE alerts SET status='Suppressed',note=? WHERE id=?", (f"Suppressed by whitelist rule #{rule['id']} ({rule['kind']}): {rule['reason']}", alert_id))
                x("INSERT OR REPLACE INTO alert_meta(alert_id,detection_id,mitre,tactic,username,suppressed_by,first_seen,last_seen) VALUES(?,?,?,?,?,?,?,?)", (alert_id, a["title"], mitre, tactic, c["username"], rule["id"], a["ts"], now())); return
        ok_after_fail = a["title"] == "Successful Login After Multiple Failures"
        score, detail = risk.score_alert(a["severity"], tactic, host, c["username"], bool(iocs), a["count"] or 1, ok_after_fail)
        reason = (a["note"] or "") or (a["message"] or "")[:300]
        x("""INSERT INTO alert_meta(alert_id,detection_id,mitre,tactic,risk_score,score_detail,ioc,username,process,command_line,parent_process,event_id,data_source,reason,first_seen,last_seen)
             VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?) ON CONFLICT(alert_id) DO UPDATE SET risk_score=excluded.risk_score,score_detail=excluded.score_detail,ioc=excluded.ioc,
             last_seen=excluded.last_seen,reason=excluded.reason""",
          (alert_id, a["title"], mitre, tactic, score, json.dumps(detail), "; ".join(f"{i['type']}:{i['value']} ({i['source']})" for i in iocs), c["username"], c["process"], c["command_line"], c["parent"],
           c["event_id"], c["channel"], reason, a["ts"], now()))
        iid = incidents.attach(alert_id, host, a["source_ip"], c["username"], a["severity"])
        try:
            import notify; notify.on_alert(alert_id, iid)          # e-mail layer: queued and sent asynchronously, can never affect detection
        except Exception: traceback.print_exc()
    except Exception: traceback.print_exc()

def start():
    from .correlation import loop
    threading.Thread(target=loop, daemon=True).start()
