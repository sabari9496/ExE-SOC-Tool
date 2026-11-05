"""EXE-SOC unified telemetry layer: normalised events (Windows Security, Sysmon, Linux), versioned detections, correlation, explorer API.
Hooks into the existing pipeline with ONE call (engine.process_batch -> unified.on_events). Failure here can never break legacy ingestion/detection."""
import json, time, traceback
from db import q, x, now
from . import store, normalize, rules
from .rules import RULES, DbHist, evaluate

_CFG = {"t": 0.0, "cfg": {}, "allow": []}
def init(): store.init()
def config_changed(): _CFG["t"] = 0.0
def _cfg():
    if time.time() - _CFG["t"] > 5:
        cfg = {}
        for r in q("SELECT * FROM u_rule_cfg"):
            try: p = json.loads(r["params"] or "{}")
            except Exception: p = {}
            cfg[r["rule_id"]] = {"enabled": None if r["enabled"] is None else bool(r["enabled"]), "params": p if isinstance(p, dict) else {}}
        _CFG.update(t=time.time(), cfg=cfg, allow=q("SELECT * FROM u_allowlist"))
    return _CFG["cfg"], _CFG["allow"]

def on_events(items, db_ids):
    """items: ingest dicts (as stored by engine.process_batch); db_ids: legacy events.id or None (duplicate/not stored). Never raises."""
    try:
        norms, ids = [], []
        for it, dbid in zip(items, db_ids):
            n = normalize.normalize_item(it) if dbid is not None else None
            norms.append(n); ids.append(dbid)
        if not any(norms): return []
        rows = store.insert_many(norms, ids)
        out = []; cfg, allow = _cfg(); hist = DbHist()
        for n, rid, dbid in zip(norms, rows, ids):
            if n is None or rid is None or not n.get("timestamp"): continue
            ev = dict(n, id=rid, extra=dict(n.get("extra") or {}))
            for h in evaluate(ev, hist, cfg, allow): out.append(_raise(h, ev, dbid))
        return [o for o in out if o]
    except Exception: traceback.print_exc(); return []

def _raise(h, ev, legacy_id):
    import engine
    r = RULES[h["rule_id"]]; evid = [e["id"] for e in h["evidence"] if e.get("id")][-200:]
    ip = ev.get("source_ip") if ev.get("source_ip") and not str(ev["source_ip"]).startswith(("127.", "::1")) else None
    msg = f"[{h['rule_id']} v{h['version']}] {h['summary']} (confidence {h['confidence']:.2f})"
    al = engine._detect(legacy_id, ip, msg, ev.get("destination_ip"), ev.get("host"), h["severity"], r["name"], "detection")
    if not al: return None
    aid = al["id"]; old = q("SELECT * FROM u_alert_evidence WHERE alert_id=?", (aid,), one=True)
    if old:
        try: prev = json.loads(old["evidence_ids"] or "[]")
        except Exception: prev = []
        evid = sorted(set(prev) | set(evid))[-500:]                      # aggregation never discards earlier supporting events
    first = (old or {}).get("first_seen") or ev["timestamp"]
    x("""INSERT INTO u_alert_evidence(alert_id,rule_id,rule_version,confidence,summary,evidence_ids,fp_notes,steps,mitre,first_seen,last_seen,host,account,event_ids) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?)
         ON CONFLICT(alert_id) DO UPDATE SET confidence=MAX(confidence,excluded.confidence),summary=excluded.summary,evidence_ids=excluded.evidence_ids,last_seen=excluded.last_seen""",
      (aid, h["rule_id"], h["version"], h["confidence"], h["summary"], json.dumps(evid), r["false_positives"], json.dumps(r["steps"]), r["mitre"], first, ev["timestamp"], ev.get("host"),
       ev.get("target_username") or ev.get("username"), json.dumps(sorted({e.get("event_id") for e in h["evidence"] if e.get("event_id") is not None}))))
    if evid: x("UPDATE norm_events SET rule_name=? WHERE id IN (%s)" % ",".join("?" * len(evid)), [r["name"]] + evid)
    return aid
