"""Persistence for unified events: insert with duplicate control, collector state, telemetry-gap flags, queries. Parameterised SQL only."""
import json, sqlite3
from datetime import datetime, timezone, timedelta
from db import conn, q, x, now
from .schema import SCHEMA
from .normalize import dedupe_key

COLS = ["schema_version", "dedupe_key", "event_db_id", "event_id", "event_record_id", "timestamp", "ingested_at", "host", "hostname", "platform", "source", "channel", "provider", "username",
        "subject_user", "target_username", "logon_type", "logon_id", "source_ip", "source_port", "destination_ip", "destination_port", "protocol", "process_id", "process_guid",
        "process_name", "image", "command_line", "parent_process_id", "parent_process_guid", "parent_process_name", "current_directory", "hashes", "integrity_level", "dns_query_name",
        "file_path", "target_filename", "registry_key", "registry_value", "service_name", "task_name", "group_name", "rule_name", "raw_event", "collector_name", "extra", "activity"]
ROW_SQL = "INSERT OR IGNORE INTO norm_events(" + ",".join(COLS) + ") VALUES(" + ",".join("?" * len(COLS)) + ")"
def utcnow(): return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z"

def init():
    c = conn()
    try: c.executescript(SCHEMA); c.commit()
    finally: c.close()

def insert_many(norms, db_ids=None):
    """-> list of (norm_event_row_id | None if duplicate). Single transaction; a bad row never loses the others (error recorded in collector_state)."""
    db_ids = db_ids or [None] * len(norms); out = []; ts = utcnow()
    c = conn()
    try:
        for n, dbid in zip(norms, db_ids):
            if n is None: out.append(None); continue
            n = dict(n); n["dedupe_key"] = dedupe_key(n); n["ingested_at"] = ts; n["event_db_id"] = dbid
            ex = n.get("extra") or {}; n["extra"] = json.dumps({k: v for k, v in ex.items() if v not in (None, "")}, ensure_ascii=False)
            if not n.get("timestamp"): n["timestamp"] = ts          # absent source time: ingestion time is used and flagged, never silently passed off as the event time
            if not (n.get("timestamp") == ts): pass
            else: n["extra"] = json.dumps({**json.loads(n["extra"]), "timestamp_source": "ingest_time"})
            try:
                cur = c.execute(ROW_SQL, [n.get(k) for k in COLS]); out.append(cur.lastrowid if cur.rowcount else None)
            except sqlite3.Error as e:
                out.append(None); _err(c, n, str(e))
        c.commit()
    finally: c.close()
    _state(norms, out)
    return out

def _err(c, n, msg):
    c.execute("INSERT INTO collector_state(host,source,channel,parse_errors,last_error,last_ingest_ts) VALUES(?,?,?,1,?,?) ON CONFLICT(host,source,channel) DO UPDATE SET parse_errors=parse_errors+1,last_error=excluded.last_error",
              (n.get("host") or "?", n.get("source") or "?", n.get("channel") or "", msg[:300], utcnow()))

def _state(norms, ids):
    agg = {}
    for n, i in zip(norms, ids):
        if n is None or i is None: continue
        k = (n.get("host") or "?", n.get("source") or "?", n.get("channel") or "")
        a = agg.setdefault(k, [0, 0, ""]); a[0] += 1; a[1] = max(a[1], n.get("event_record_id") or 0); a[2] = max(a[2], n.get("timestamp") or "")
    c = conn(); ts = utcnow()
    try:
        for (h, s, ch), (cnt, rid, ets) in agg.items():
            c.execute("""INSERT INTO collector_state(host,source,channel,last_record_id,last_event_ts,last_ingest_ts,events_total) VALUES(?,?,?,?,?,?,?)
                         ON CONFLICT(host,source,channel) DO UPDATE SET last_record_id=MAX(COALESCE(last_record_id,0),excluded.last_record_id),
                         last_event_ts=MAX(COALESCE(last_event_ts,''),excluded.last_event_ts),last_ingest_ts=excluded.last_ingest_ts,events_total=events_total+excluded.events_total""",
                      (h, s, ch, rid or None, ets, ts, cnt))
        for n, i in zip(norms, ids):                                    # telemetry gaps that change what detections can see
            if n is None or i is None: continue
            h = n.get("host") or "?"
            if n.get("source") == "windows_security" and n.get("event_id") == 4688 and not (n.get("command_line")) and not (n.get("extra") or {}).get("cmdline_field_present"):
                _flag(c, h, "cmdline_audit_missing", "Event 4688 without a CommandLine field: enable 'Include command line in process creation events' (see docs).", ts)
            if n.get("source") == "windows_security" and n.get("event_id") == 4688 and (n.get("extra") or {}).get("cmdline_field_present") and not n.get("command_line"):
                _flag(c, h, "cmdline_audit_empty", "Event 4688 CommandLine field is present but empty: command-line auditing is probably disabled.", ts)
        c.commit()
    finally: c.close()

def _flag(c, host, flag, detail, ts):
    c.execute("INSERT INTO telemetry_flags(host,flag,detail,first_seen,last_seen) VALUES(?,?,?,?,?) ON CONFLICT(host,flag) DO UPDATE SET last_seen=excluded.last_seen,hits=hits+1", (host, flag, detail, ts, ts))

def get(i): return q("SELECT * FROM norm_events WHERE id=?", (i,), one=True)
def get_many(ids):
    ids = [int(i) for i in ids][:500]
    return q("SELECT * FROM norm_events WHERE id IN (%s) ORDER BY timestamp" % ",".join("?" * len(ids)), ids) if ids else []

FILTERS = {"host": "host", "platform": "platform", "source": "source", "event_id": "event_id", "username": "username", "source_ip": "source_ip", "destination_ip": "destination_ip",
           "process_name": "process_name", "rule_name": "rule_name", "logon_id": "logon_id", "process_guid": "process_guid", "activity": None}
def _where(a):
    w, p = [], []
    for k, col in FILTERS.items():
        v = a.get(k)
        if v in (None, ""): continue
        if k == "event_id":
            try: n_ = int(v)
            except ValueError: w.append("0")
            else: w.append("event_id=?"); p.append(n_)
        elif k == "username": w.append("(username=? COLLATE NOCASE OR target_username=? COLLATE NOCASE OR subject_user=? COLLATE NOCASE)"); p += [v, v, v]
        elif k == "activity": w.append("activity=?"); p.append(v)
        elif k in ("process_name", "host"): w.append(f"{col}=? COLLATE NOCASE"); p.append(v)
        else: w.append(f"{col}=?"); p.append(v)
    if a.get("since"): w.append("timestamp>=?"); p.append(a["since"])
    if a.get("until"): w.append("timestamp<=?"); p.append(a["until"])
    if a.get("text"):
        t = "%" + str(a["text"]).replace("%", "").replace("_", "") + "%"
        w.append("(command_line LIKE ? OR target_filename LIKE ? OR dns_query_name LIKE ? OR registry_key LIKE ? OR image LIKE ? OR extra LIKE ?)"); p += [t] * 6
    return (" WHERE " + " AND ".join(w)) if w else "", p

LIST_COLS = "id,event_id,event_record_id,timestamp,host,platform,source,channel,username,subject_user,target_username,logon_type,logon_id,source_ip,source_port,destination_ip,destination_port,protocol,process_id,process_guid,process_name,command_line,parent_process_name,dns_query_name,target_filename,registry_key,service_name,task_name,group_name,rule_name,activity,extra"
def search(a, limit=100, offset=0, cols=LIST_COLS):
    wh, p = _where(a)
    rows = q(f"SELECT {cols} FROM norm_events{wh} ORDER BY timestamp DESC, id DESC LIMIT ? OFFSET ?", p + [limit, offset])
    total = q(f"SELECT COUNT(*) c FROM norm_events{wh}", p, one=True)["c"]
    return rows, total

def purge(raw_days=30, days=90):
    """Retention: raw_event blanked after raw_days (normalised fields kept); rows deleted after days. Returns (blanked, deleted). Existing alerts/evidence rows are never touched."""
    from datetime import timedelta
    f = lambda d: (datetime.now(timezone.utc) - timedelta(days=d)).strftime("%Y-%m-%dT%H:%M:%S")
    c = conn()
    try:
        b = c.execute("UPDATE norm_events SET raw_event=NULL WHERE raw_event IS NOT NULL AND timestamp<?", (f(raw_days),)).rowcount
        keep = c.execute("SELECT evidence_ids FROM u_alert_evidence").fetchall()
        protected = set()
        for (e,) in keep:
            try: protected.update(json.loads(e or "[]"))
            except Exception: pass
        d = 0
        for (i,) in c.execute("SELECT id FROM norm_events WHERE timestamp<? LIMIT 20000", (f(days),)).fetchall():
            if i not in protected: c.execute("DELETE FROM norm_events WHERE id=?", (i,)); d += 1
        c.commit(); return b, d
    finally: c.close()
