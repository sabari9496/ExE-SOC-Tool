"""Monitoring Center APIs (read-only, plus audited endpoint tag/environment editing).

GET  /api/monitoring/overview                 viewer+   counts per OS class and state, alerts in the window, Cloud status
GET  /api/monitoring/endpoints                viewer+   filters: os, state, q (hostname), ip, severity, since, until, env, tag, sort, limit, offset
GET  /api/monitoring/endpoints/<id>           viewer+   one endpoint with recent heartbeats and alerts
POST /api/monitoring/endpoints/<id>/meta      admin     {environment, tags}; validated; audited

Everything shown is derived from stored data at request time (state = fleet.status.endpoint_state, class = fleet.osmeta.classify). Nothing is hardcoded or simulated.
Requires migration v4 (agents.os_family ...). On a database that has not been migrated the endpoints answer 409 with instructions instead of failing or showing zeros.
Time values are the server's local time (the existing stored format), see docs/MONITORING_CENTER.md."""
import json, re, ipaddress
from datetime import datetime, timedelta
from flask import jsonify, request
from db import q, x, now
from . import osmeta, status as st

CLASSES = ("windows", "linux", "ubuntu", "unknown")
LABELS = {"windows": "Windows", "linux": "Linux (other distributions)", "ubuntu": "Ubuntu", "unknown": "Unclassified"}
SEVERITIES = ("Critical", "High", "Medium", "Low", "Normal")
SORTS = ("hostname", "last_heartbeat", "state", "alerts")
ENV_RX, TAG_RX = re.compile(r"[A-Za-z0-9][A-Za-z0-9 _.-]{0,31}"), re.compile(r"[a-z0-9][a-z0-9_.:-]{0,31}")
REL_RX = re.compile(r"([0-9]{1,4})([mhd])")
MAX_WINDOW_DAYS, MAX_AGENTS = 366, 5000
COLS = ("id,endpoint_id,hostname,device_name,os,os_version,ip,ips,agent_version,registered_at,last_heartbeat,last_event_at,first_heartbeat_at,status,monitoring,events_total,health,"
        "os_family,distro_id,distro_version,environment,tags")

class BadParam(ValueError): pass

def schema_ready():
    """True once migration v4 has added the Monitoring Center columns to `agents`."""
    return {"os_family", "distro_id", "distro_version", "environment", "tags", "first_heartbeat_at"} <= {r["name"] for r in q("PRAGMA table_info(agents)")}

def _time(v, now_dt, default):
    if v is None or str(v).strip() == "": return default
    v = str(v).strip(); m = REL_RX.fullmatch(v)
    if m: return now_dt - timedelta(**{{"m": "minutes", "h": "hours", "d": "days"}[m.group(2)]: int(m.group(1))})
    for f in ("%Y-%m-%dT%H:%M:%S", "%Y-%m-%d %H:%M:%S", "%Y-%m-%d"):
        try: return datetime.strptime(v, f)
        except ValueError: pass
    raise BadParam("since/until must be like 15m, 24h, 7d or YYYY-MM-DD[ HH:MM:SS] (server local time)")

def window(args, now_dt):
    until = _time(args.get("until"), now_dt, now_dt); since = _time(args.get("since"), now_dt, until - timedelta(hours=24))
    if since >= until: raise BadParam("since must be earlier than until")
    if (until - since) > timedelta(days=MAX_WINDOW_DAYS): raise BadParam(f"time window is limited to {MAX_WINDOW_DAYS} days")
    return since, until

def _list(v):
    try: r = json.loads(v) if isinstance(v, str) else v
    except ValueError: return []
    return r if isinstance(r, list) else []

def _agents():
    """-> (rows, truncated). At most MAX_AGENTS endpoints are processed per request; if there are more the response says so (truncated=true) instead of silently showing a partial fleet."""
    rows = [dict(r) for r in q(f"SELECT {COLS} FROM agents ORDER BY hostname LIMIT {MAX_AGENTS + 1}")]
    return rows[:MAX_AGENTS], len(rows) > MAX_AGENTS

def _alert_counts(since, until):
    out = {}
    for r in q("SELECT agent_id,severity,COUNT(*) n FROM alerts WHERE agent_id IS NOT NULL AND ts>=? AND ts<=? GROUP BY agent_id,severity", (since.strftime(st.FMT), until.strftime(st.FMT))):
        d = out.setdefault(r["agent_id"], {}); d[r["severity"]] = d.get(r["severity"], 0) + r["n"]
    return out

def _event_counts(since, until, ids=None):
    sql, p = "SELECT agent_id,COUNT(*) n FROM events WHERE agent_id IS NOT NULL AND ts>=? AND ts<=?", [since.strftime(st.FMT), until.strftime(st.FMT)]
    if ids is not None:
        if not ids: return {}
        sql += " AND agent_id IN (%s)" % ",".join("?" * len(ids)); p += list(ids)
    return {r["agent_id"]: r["n"] for r in q(sql + " GROUP BY agent_id", p)}

def _decorate(a, now_dt, th, alerts):
    c = osmeta.classify(a.get("os_family"), a.get("distro_id"), a.get("os")); s = st.endpoint_state(a, now_dt, th)
    try: h = json.loads(a.get("health") or "{}")
    except ValueError: h = {}
    if not isinstance(h, dict): h = {}
    al = alerts.get(a["id"], {})
    return dict(id=a["id"], endpoint_id=a.get("endpoint_id"), hostname=a["hostname"], device_name=a.get("device_name"), os_class=c["os_class"], classified_by=c["classified_by"], os=a.get("os"), os_version=a.get("os_version"),
                os_family=a.get("os_family"), distro_id=c["distro_id"], distro_version=a.get("distro_version"), agent_version=a.get("agent_version"), ip=a.get("ip"), ips=[str(i) for i in _list(a.get("ips"))][:8],
                state=s["state"], state_reason=s["reason"], age_seconds=s["age_s"], registered_at=a.get("registered_at"), first_heartbeat_at=a.get("first_heartbeat_at"), last_heartbeat=a.get("last_heartbeat"),
                last_event_at=a.get("last_event_at"), monitoring=a.get("monitoring"), environment=a.get("environment"), tags=[str(t) for t in _list(a.get("tags"))][:10], events_total=a.get("events_total") or 0,
                alerts_in_window=dict(total=sum(al.values()), by_severity=al),
                health=dict(events_queued=h.get("events_queued"), upload_failures_recent=h.get("upload_failures_recent"), collector_errors=[str(e) for e in _list(h.get("collector_errors"))][:5], cpu=h.get("cpu"), mem=h.get("mem")))

def cloud_summary():
    """Honest Cloud status. No connector framework exists in this version, so the state is NOT_CONFIGURED and nothing is shown as monitored."""
    if q("SELECT 1 FROM sqlite_master WHERE type='table' AND name='cloud_connectors'", one=True) is None:
        return dict(state="NOT_CONFIGURED", implemented=False, connectors=0, message="No cloud connector framework is installed in this version (planned for a later stage). No cloud data is collected or shown.")
    return dict(state="NOT_CONFIGURED", implemented=True, connectors=0, message="Cloud connector storage exists but no connector status is reported by this version.")

def _filters(args):
    f = {}
    o = (args.get("os") or "").strip().lower()
    if o and o not in CLASSES: raise BadParam("os must be one of: " + ", ".join(CLASSES))
    f["os"] = o
    states = [s.strip().lower() for s in (args.get("state") or "").split(",") if s.strip()]
    if any(s not in st.STATES for s in states) or len(states) > 5: raise BadParam("state must be a comma list of: " + ", ".join(st.STATES))
    f["states"] = set(states)
    f["q"] = (args.get("q") or "").strip().lower()
    if len(f["q"]) > 100: raise BadParam("q is limited to 100 characters")
    ip = (args.get("ip") or "").strip()
    if ip:
        try: f["ip"] = str(ipaddress.ip_address(ip))
        except ValueError: raise BadParam("ip must be a valid IPv4/IPv6 address")
    sev = (args.get("severity") or "").strip().capitalize()
    if sev and sev not in SEVERITIES: raise BadParam("severity must be one of: " + ", ".join(SEVERITIES))
    f["severity"] = sev
    env = (args.get("env") or "").strip()
    if env and not ENV_RX.fullmatch(env): raise BadParam("invalid env")
    f["env"] = env.casefold()
    tag = (args.get("tag") or "").strip().lower()
    if tag and not TAG_RX.fullmatch(tag): raise BadParam("invalid tag")
    f["tag"] = tag
    return f

def _match(r, f):
    if f["os"] and r["os_class"] != f["os"]: return False
    if f["states"] and r["state"] not in f["states"]: return False
    if f["q"] and f["q"] not in (r["hostname"] or "").lower() and f["q"] not in (r["device_name"] or "").lower(): return False
    if f.get("ip"):
        ok = False
        for c in [r["ip"]] + r["ips"]:
            try: ok = ok or str(ipaddress.ip_address(str(c))) == f["ip"]
            except ValueError: pass
        if not ok: return False
    if f["severity"] and not r["alerts_in_window"]["by_severity"].get(f["severity"]): return False
    if f["env"] and (r["environment"] or "").casefold() != f["env"]: return False
    if f["tag"] and f["tag"] not in r["tags"]: return False
    return True

def _intarg(v, d, lo, hi):
    if v is None or v == "": return d
    if not re.fullmatch(r"[0-9]{1,7}", str(v)): raise BadParam("limit/offset must be whole numbers")
    return min(max(int(v), lo), hi)

def _clean_meta(b):
    out = {}
    if "environment" in b:
        e = b["environment"]
        if e is None or (isinstance(e, str) and e.strip() == ""): out["environment"] = None
        elif isinstance(e, str) and ENV_RX.fullmatch(e.strip()): out["environment"] = e.strip()
        else: raise BadParam("environment must be 1-32 characters: letters, digits, space, _ . -")
    if "tags" in b:
        t = b["tags"]
        if t is None: t = []
        if not isinstance(t, list) or len(t) > 10: raise BadParam("tags must be a list of at most 10 items")
        seen = []
        for i in t:
            i = i.strip().lower() if isinstance(i, str) else None
            if not i or not TAG_RX.fullmatch(i): raise BadParam("each tag must be 1-32 characters: lowercase letters, digits, _ . : -")
            if i not in seen: seen.append(i)
        out["tags"] = seen
    if not out: raise BadParam("nothing to update: send environment and/or tags")
    return out

def register(bp, need, audit, body, deny):
    def guard():
        if not schema_ready(): return jsonify(error="database migration v4 is pending (Monitoring Center needs it)", hint="back up, then run: python migrate.py plan, then python migrate.py apply --yes"), 409
    def ctx():
        n = datetime.now(); return n, st.thresholds()

    @bp.route("/api/monitoring/overview")
    @need()
    def mon_overview():
        g = guard()
        if g: return g
        try: n, th = ctx(); since, until = window(request.args, n)
        except BadParam as e: return deny(str(e), 400)
        agents, trunc = _agents(); alerts = _alert_counts(since, until); rows = [_decorate(a, n, th, alerts) for a in agents]; ev = _event_counts(since, until)
        zero = lambda: {s: 0 for s in st.STATES}; classes = {c: dict(label=LABELS[c], total=0, by_state=zero(), alerts_in_window={}, events_in_window=0) for c in CLASSES}; tot = zero()
        for r in rows:
            k = classes[r["os_class"]]; k["total"] += 1; k["by_state"][r["state"]] += 1; tot[r["state"]] += 1; k["events_in_window"] += ev.get(r["id"], 0)
            for s, c in r["alerts_in_window"]["by_severity"].items(): k["alerts_in_window"][s] = k["alerts_in_window"].get(s, 0) + c
        return jsonify(generated_at=n.strftime(st.FMT), window=dict(since=since.strftime(st.FMT), until=until.strftime(st.FMT), timezone="server local time"),
                       thresholds=dict(online_seconds=th[0], offline_seconds=th[1], degraded_queue_over=st.QUEUE_DEGRADED, degraded_upload_failures=st.UPLOAD_FAIL_DEGRADED),
                       totals=dict(endpoints=len(rows), by_state=tot), truncated=trunc, max_endpoints=MAX_AGENTS, classes=classes, cloud=cloud_summary())

    @bp.route("/api/monitoring/endpoints")
    @need()
    def mon_endpoints():
        g = guard()
        if g: return g
        try:
            n, th = ctx(); since, until = window(request.args, n); f = _filters(request.args); limit = _intarg(request.args.get("limit"), 50, 1, 200); offset = _intarg(request.args.get("offset"), 0, 0, 100000)
            sort = (request.args.get("sort") or "hostname").strip().lower()
            if sort not in SORTS: raise BadParam("sort must be one of: " + ", ".join(SORTS))
        except BadParam as e: return deny(str(e), 400)
        agents, trunc = _agents(); alerts = _alert_counts(since, until); rows = [r for r in (_decorate(a, n, th, alerts) for a in agents) if _match(r, f)]
        if sort == "hostname": rows.sort(key=lambda r: (r["hostname"] or "").casefold())
        elif sort == "last_heartbeat": rows.sort(key=lambda r: r["last_heartbeat"] or "", reverse=True)
        elif sort == "state": rows.sort(key=lambda r: (st.STATES.index(r["state"]), (r["hostname"] or "").casefold()))
        else: rows.sort(key=lambda r: -r["alerts_in_window"]["total"])
        page = rows[offset:offset + limit]; ev = _event_counts(since, until, [r["id"] for r in page])
        for r in page: r["events_in_window"] = ev.get(r["id"], 0)
        return jsonify(total=len(rows), truncated=trunc, max_endpoints=MAX_AGENTS, limit=limit, offset=offset, window=dict(since=since.strftime(st.FMT), until=until.strftime(st.FMT), timezone="server local time"), items=page)

    @bp.route("/api/monitoring/endpoints/<aid>")
    @need()
    def mon_endpoint(aid):
        g = guard()
        if g: return g
        a = q(f"SELECT {COLS} FROM agents WHERE id=?", (aid,), one=True)
        if not a: return deny("not found", 404)
        try: n, th = ctx(); since, until = window(request.args, n)
        except BadParam as e: return deny(str(e), 400)
        r = _decorate(dict(a), n, th, _alert_counts(since, until)); r["events_in_window"] = _event_counts(since, until, [aid]).get(aid, 0)
        r["heartbeats"] = q("SELECT ts,cpu,mem,events_queued,upload_failures FROM agent_heartbeats WHERE agent_id=? ORDER BY id DESC LIMIT 60", (aid,))[::-1]
        r["alerts"] = q("SELECT id,ts,updated,severity,title,category,source_ip,status,count FROM alerts WHERE agent_id=? ORDER BY id DESC LIMIT 50", (aid,))
        return jsonify(r)

    @bp.route("/api/monitoring/endpoints/<aid>/meta", methods=["POST"])
    @need("admin")
    def mon_meta(aid):
        g = guard()
        if g: return g
        a = q("SELECT id,hostname,environment,tags FROM agents WHERE id=?", (aid,), one=True)
        if not a: return deny("not found", 404)
        b = body()
        try: m = _clean_meta(b if isinstance(b, dict) else {})
        except BadParam as e: return deny(str(e), 400)
        sets, vals = [], []
        if "environment" in m: sets.append("environment=?"); vals.append(m["environment"])
        if "tags" in m: sets.append("tags=?"); vals.append(json.dumps(m["tags"]))
        x(f"UPDATE agents SET {','.join(sets)} WHERE id=?", vals + [aid])
        old_tags = [str(t) for t in _list(a["tags"])]
        audit(f"Endpoint metadata updated: {a['hostname']} ({aid}); environment {a['environment']!r} -> {m.get('environment', a['environment'])!r}; tags {old_tags} -> {m.get('tags', old_tags)}")
        return jsonify(ok=True, environment=m.get("environment", a["environment"]), tags=m.get("tags", old_tags))
