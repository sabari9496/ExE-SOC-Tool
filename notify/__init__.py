"""EXE-SOC e-mail notification layer. Independent and asynchronous: detection only calls on_alert(), which puts a tiny job in memory and returns.
A worker thread decides, renders and sends. If SMTP is down the alert, incident and dashboard are unaffected."""
import random
import re, time, threading, traceback
from datetime import datetime
from db import q, x, now, conn
from .schema import SCHEMA
from . import config, policy, render, smtpx

_TRIG = {}; _LOCK = threading.Lock(); _WAKE = threading.Event(); _LAST_ERR = {"msg": ""}
SYNC = False        # tests may set True to process inline

def init():
    c = conn(); c.executescript(SCHEMA); c.commit(); c.close()

def on_alert(alert_id, iid):
    """Hook called after an alert was stored and attached to an incident. Never raises, never blocks."""
    try:
        with _LOCK:
            if len(_TRIG) > 5000: return
            _TRIG[alert_id] = iid
        _WAKE.set()
        if SYNC: process_now()
    except Exception: traceback.print_exc()

def _nid():
    n = q("SELECT COALESCE(MAX(id),0)+1 n FROM notification_history", one=True)["n"]; return f"NTF-{datetime.now():%Y%m%d}-{n:06d}"

def enqueue(ntype, severity, recipients, subj, html_, text_, iid=None, alert_id=None, occ=1, incident_code=""):
    nid = _nid()
    for r in recipients:
        x("INSERT INTO notification_history(notification_id,incident_id,incident_code,alert_id,ntype,recipient,subject,severity,ts,status,attempts,next_try,body_html,body_text,occurrences) VALUES(?,?,?,?,?,?,?,?,?,'QUEUED',0,0,?,?,?)",
          (nid, iid, incident_code, alert_id, ntype, r, subj, severity, now(), html_, text_, occ))
    return nid

def handle_trigger(alert_id, iid):
    d, why = policy.decide(alert_id, iid)
    if not d: return None
    c = render.gather(alert_id, iid, d["ntype"], d["severity"], d["occurrences"]); subj = render.subject(c, d["update"]); h, t = render.body(c, config.get("base_url"), d["update"])
    inc = c["inc"]; nid = enqueue(d["ntype"], d["severity"], d["recipients"], subj, h, t, iid, alert_id, d["occurrences"], render.code(inc["id"], inc.get("created")) if inc else "")
    policy.record_sent(d["key"], iid, alert_id, d["severity"], d["occurrences"]); return nid

def retry_wait(attempts):
    """Bounded delay list (config retry_delays) with +-25% jitter, so a provider outage does not produce synchronized retry storms."""
    dl = _delays(); base = dl[min(attempts - 1, len(dl) - 1)] if dl else 30
    return base * (0.75 + random.random() * 0.5)

def _delays():
    try: return [int(v) for v in config.get("retry_delays").split(",") if v]
    except ValueError: return [30, 120, 300]

def deliver(row, cfg=None):
    """One delivery attempt for a history row. Updates its status. Never raises."""
    cfg = cfg or config.smtp_config(); attempts = row["attempts"] + 1; maxa = max(1, config.num("max_attempts", 4))
    try:
        smtpx.send(cfg, row["recipient"], row["subject"], row["body_html"] or "", row["body_text"] or "")
        x("UPDATE notification_history SET status='SENT',attempts=?,sent_at=?,error=NULL,body_html=NULL,body_text=NULL WHERE id=?", (attempts, now(), row["id"])); return True
    except smtpx.NotifyError as e:
        msg = smtpx.safe(e.message, cfg); _LAST_ERR["msg"] = msg
        if e.permanent or attempts >= maxa: x("UPDATE notification_history SET status='FAILED',attempts=?,error=?,next_try=0 WHERE id=?", (attempts, msg, row["id"]))
        else:
            wait = retry_wait(attempts)
            x("UPDATE notification_history SET status='RETRYING',attempts=?,error=?,next_try=? WHERE id=?", (attempts, msg, time.time() + wait, row["id"]))
        print(f"notify: delivery to {row['recipient']} failed (attempt {attempts}): {msg}")
    except Exception as e:                                    # never let a bug here reach the detection engine
        msg = smtpx.safe(f"internal error: {e.__class__.__name__}", cfg); x("UPDATE notification_history SET status='FAILED',attempts=?,error=? WHERE id=?", (attempts, msg, row["id"]))
    return False

def send_due(limit=25):
    n = 0
    for row in q("SELECT * FROM notification_history WHERE status IN ('QUEUED','RETRYING') AND next_try<=? ORDER BY id LIMIT ?", (time.time(), limit)):
        deliver(row); n += 1
    return n

def check_escalations():
    """Escalate to level-2+ recipients when a notified incident is still unacknowledged (status New and nobody assigned). Uses the existing incident status only."""
    if not config.on("escalation_enabled") or not config.on("enabled"): return 0
    mins = config.num("escalation_min", 15); done = 0; floor = config.get("escalation_min_severity") or "Critical"
    for d in q("SELECT * FROM notification_dedupe WHERE key LIKE 'INC:%' AND first_sent<=?", (time.time() - mins * 60,)):
        inc = q("SELECT * FROM incidents WHERE id=?", (d["incident_id"],), one=True)
        if not inc or inc["status"] != "New" or inc["assignee"] or policy.rank(inc["severity"]) < policy.rank(floor): continue
        if q("SELECT 1 FROM notification_escalation WHERE incident_id=?", (inc["id"],), one=True): continue
        rec = policy.recipients_for(inc["severity"], levels=(2,))
        x("INSERT OR IGNORE INTO notification_escalation VALUES(?,?,2)", (inc["id"], now()))
        if not rec: continue
        a = q("SELECT a.id FROM alerts a JOIN incident_alerts ia ON ia.alert_id=a.id WHERE ia.incident_id=? ORDER BY a.id DESC LIMIT 1", (inc["id"],), one=True)
        if not a: continue
        c = render.gather(a["id"], inc["id"], "escalation", inc["severity"], inc["event_count"]); h, t = render.body(c, config.get("base_url"))
        t = f"No analyst acknowledged this incident within {mins} minutes (status still New, nobody assigned).\n\n" + t; h = h.replace("<div style='padding:18px 22px'>", f"<div style='padding:18px 22px'><p style='background:#fff4e5;padding:8px;border-left:4px solid #d9480f'><b>No analyst acknowledged this incident within {mins} minutes</b> (status still New, nobody assigned).</p>", 1)
        enqueue("escalation", inc["severity"], rec, render.subject(c), h, t, inc["id"], a["id"], inc["event_count"], render.code(inc["id"], inc.get("created"))); done += 1
    return done

def process_now():
    """Drain triggers, run due deliveries and escalations once. The worker calls this in a loop; tests call it directly."""
    with _LOCK: jobs = list(_TRIG.items()); _TRIG.clear()
    for aid, iid in jobs:
        try: handle_trigger(aid, iid)
        except Exception: traceback.print_exc()
    try: check_escalations()
    except Exception: traceback.print_exc()
    return send_due()

def worker():
    while True:
        try: process_now()
        except Exception: traceback.print_exc()
        _WAKE.wait(2); _WAKE.clear()

def start():
    threading.Thread(target=worker, daemon=True, name="notify").start()

def status():
    st = {r["status"]: r["c"] for r in q("SELECT status,COUNT(*) c FROM notification_history WHERE ts>=datetime('now','localtime','-1 day') GROUP BY status")}
    failed = st.get("FAILED", 0); retry = st.get("RETRYING", 0); queued = st.get("QUEUED", 0)
    problems = config.validate_smtp() if config.on("enabled") else []
    state = "DISABLED" if not config.on("enabled") else "NOT CONFIGURED" if problems else "DEGRADED" if (failed or retry) else "OK"
    last = q("SELECT sent_at FROM notification_history WHERE status='SENT' ORDER BY id DESC LIMIT 1", one=True)
    le = q("SELECT error,recipient,ts FROM notification_history WHERE status IN ('FAILED','RETRYING') ORDER BY id DESC LIMIT 1", one=True)
    return dict(state=state, enabled=config.on("enabled"), method=config.method(), gmail=config.gmail_status(), failed_24h=failed, retrying=retry, queued=queued, sent_24h=st.get("SENT", 0), problems=problems,
                suppressed=q("SELECT COALESCE(SUM(suppressed),0) c FROM notification_dedupe", one=True)["c"], last_sent=(last or {}).get("sent_at"), last_error=smtpx.safe((le or {}).get("error") or ""),
                message=(f"{failed} email notification(s) failed" if failed else f"{retry} email notification(s) could not be delivered yet (retrying)" if retry else "Email notifications working" if state == "OK" else ""),
                password_configured=bool(config.password()) if config.method() != "gmail_api" else all(config.gmail_status().values()))
