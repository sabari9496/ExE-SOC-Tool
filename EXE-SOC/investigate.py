"""Investigation layer: full alert / IP context and a Splunk-style (SPL-lite) search engine."""
import re, shlex
from collections import Counter
from datetime import datetime, timedelta
from db import q, now, RANK
import engine

FMT = "%Y-%m-%d %H:%M:%S"
PORT_RE = re.compile(r":(\d{1,5})$")

def ip_profile(ip):
    """Everything we know about one IP: reputation, timeline, targets, tactics, raw events."""
    a = q("SELECT COUNT(*) c,MIN(ts) first,MAX(ts) last,COALESCE(SUM(count),0) hits FROM alerts WHERE source_ip=?", (ip,), one=True)
    ev = q("SELECT COUNT(*) c,MIN(ts) first,MAX(ts) last FROM events WHERE source_ip=?", (ip,), one=True)
    sev = q("SELECT severity,COUNT(*) c FROM alerts WHERE source_ip=? GROUP BY severity", (ip,))
    cats = q("SELECT category k,COUNT(*) c FROM alerts WHERE source_ip=? GROUP BY category ORDER BY c DESC", (ip,))
    titles = q("SELECT title k,COUNT(*) c FROM alerts WHERE source_ip=? GROUP BY title ORDER BY c DESC", (ip,))
    status = q("SELECT status k,COUNT(*) c FROM alerts WHERE source_ip=? GROUP BY status", (ip,))
    ioc = q("SELECT * FROM iocs WHERE value=?", (ip,), one=True)
    blk = q("SELECT * FROM blocklist WHERE ip=?", (ip,), one=True)
    score = min(100, sum({"Critical": 30, "High": 15, "Medium": 6, "Low": 2}[s["severity"]] * s["c"] for s in sev) + (40 if ioc else 0) + (10 if blk else 0))
    ctry, la, lo = engine.geo_for(ip)
    dests = Counter(); ports = Counter()
    for r in q("SELECT dest_ip FROM events WHERE source_ip=? AND dest_ip IS NOT NULL", (ip,)) + q("SELECT dest_ip FROM alerts WHERE source_ip=? AND dest_ip IS NOT NULL", (ip,)):
        d = r["dest_ip"]; m = PORT_RE.search(d)
        dests[d.rsplit(":", 1)[0] if m else d] += 1
        if m: ports[m.group(1)] += 1
    since = now(datetime.now() - timedelta(hours=24)); buckets = [0] * 24; n = datetime.now()
    for r in q("SELECT ts FROM events WHERE source_ip=? AND ts>=?", (ip, since)):
        h = int((n - datetime.strptime(r["ts"], FMT)).total_seconds() // 3600)
        if 0 <= h < 24: buckets[23 - h] += 1
    mitre = []
    for t in titles:
        m = engine.MITRE.get(t["k"])
        if m: mitre.append({"id": m[0], "name": m[1], "tactic": m[2], "alert": t["k"], "count": t["c"]})
    hosts = q("SELECT host k,COUNT(*) c FROM events WHERE source_ip=? AND host IS NOT NULL GROUP BY host ORDER BY c DESC LIMIT 8", (ip,))
    return dict(ip=ip, private=engine.is_private(ip), country=ctry or "Unknown", lat=la, lon=lo,
        risk_score=score, risk="Critical" if score >= 80 else "High" if score >= 50 else "Medium" if score >= 20 else "Low",
        ioc=ioc, blocked=blk, alerts=a["c"], total_hits=a["hits"], events=ev["c"],
        first_seen=min([t for t in (a["first"], ev["first"]) if t], default=None), last_seen=max([t for t in (a["last"], ev["last"]) if t], default=None),
        by_severity=sev, by_category=cats, by_title=titles, by_status=status,
        targets=[{"k": k, "c": c} for k, c in dests.most_common(8)], ports=[{"k": k, "c": c} for k, c in ports.most_common(8)], hosts=hosts,
        timeline=buckets, mitre=mitre,
        alert_list=q("SELECT id,ts,severity,title,status,count FROM alerts WHERE source_ip=? ORDER BY id DESC LIMIT 25", (ip,)),
        raw_events=q("SELECT id,ts,dest_ip,host,message,alert_id FROM events WHERE source_ip=? ORDER BY id DESC LIMIT 50", (ip,)),
        cases=q("SELECT DISTINCT c.id,c.title,c.status FROM cases c JOIN case_alerts ca ON ca.case_id=c.id JOIN alerts a ON a.id=ca.alert_id WHERE a.source_ip=?", (ip,)))

def alert_detail(i):
    a = q("SELECT al.*,e.hostname endpoint,e.ip endpoint_ip,e.os endpoint_os,e.isolated endpoint_isolated FROM alerts al LEFT JOIN endpoints e ON e.id=al.endpoint_id WHERE al.id=?", (i,), one=True)
    if not a: return None
    ip = a["source_ip"]
    events = q("SELECT id,ts,source_ip,dest_ip,host,message FROM events WHERE alert_id=? ORDER BY id", (i,))
    ctx = []
    if ip:   # surrounding activity from the same IP within +/- 30 min of the alert
        t = datetime.strptime(a["ts"], FMT)
        ctx = q("SELECT id,ts,dest_ip,host,message,alert_id FROM events WHERE source_ip=? AND ts BETWEEN ? AND ? ORDER BY id LIMIT 100",
                (ip, now(t - timedelta(minutes=30)), now(t + timedelta(minutes=30))))
    m = engine.MITRE.get(a["title"])
    sev_actions = ["Assign the alert to an analyst and start a case."] if a["status"] == "New" else []
    a["blocked"] = bool(ip and q("SELECT 1 FROM blocklist WHERE ip=?", (ip,), one=True))
    a["ioc"] = bool(ip and q("SELECT 1 FROM iocs WHERE value=?", (ip,), one=True))
    return dict(alert=a, events=events, context=ctx,
        mitre=({"id": m[0], "name": m[1], "tactic": m[2], "url": "https://attack.mitre.org/techniques/" + m[0].replace(".", "/")} if m else None),
        ip=ip_profile(ip) if ip else None,
        related_ip=q("SELECT id,ts,severity,title,status FROM alerts WHERE source_ip=? AND id!=? ORDER BY id DESC LIMIT 10", (ip, i)) if ip else [],
        related_endpoint=q("SELECT id,ts,severity,title,source_ip FROM alerts WHERE endpoint_id=? AND id!=? ORDER BY id DESC LIMIT 10", (a["endpoint_id"], i)) if a["endpoint_id"] else [],
        cases=q("SELECT c.id,c.title,c.status FROM cases c JOIN case_alerts ca ON ca.case_id=c.id WHERE ca.alert_id=?", (i,)),
        activity=q("SELECT ts,user,action FROM alert_activity WHERE alert_id=? ORDER BY id DESC", (i,)),
        recommended=sev_actions + engine.GUIDE.get(a["category"], ["Investigate the source and affected asset."]))

# ---------------- SPL-lite search ----------------
# Example:  index=events source_ip=185.* message="failed password" | stats count by source_ip | sort -count | head 10
FIELDS = {"events": {"source_ip", "dest_ip", "host", "message", "ts", "alert_id"},
          "alerts": {"source_ip", "dest_ip", "title", "severity", "category", "status", "assignee", "country", "message", "ts", "count", "id"}}
NUMERIC = {"count", "id", "alert_id"}

def _where(terms, fields):
    w, a = [], []
    for t in terms:
        neg = t.startswith("NOT "); t = t[4:] if neg else t
        m = re.match(r"^(\w+)(!=|>=|<=|=|>|<)(.*)$", t, re.S)
        if m:
            f, op, v = m.groups()
            if f not in fields: raise ValueError(f"unknown field '{f}' (available: {', '.join(sorted(fields))})")
            if f in NUMERIC and op in ("=", "!=", ">", "<", ">=", "<="):
                w.append(f"{f}{op}?"); a.append(float(v)); continue
            if op in (">", "<", ">=", "<=") and f == "ts": w.append(f"ts{op}?"); a.append(v); continue
            if "*" in v: w.append(f"{f} {'NOT ' if op == '!=' else ''}LIKE ?"); a.append(v.replace("*", "%"))
            else: w.append(f"{f}{'!=' if op == '!=' else '='}?"); a.append(v)
        else:   # free text: search all text columns
            cols = [c for c in ("source_ip", "dest_ip", "host", "message", "title") if c in fields]
            w.append(f"({' OR '.join(c + ' LIKE ?' for c in cols)})"); a += [f"%{t}%"] * len(cols)
    return w, a

def run_search(query, earliest_min=None):
    parts = [p.strip() for p in query.split("|")]
    first = shlex.split(parts[0]) if parts[0] else []
    index = "events"; terms = []; buf = []
    for tok in first:
        if tok.startswith("index="): index = tok[6:]
        elif tok == "NOT": buf.append("NOT")
        else: terms.append(("NOT " if buf else "") + tok); buf = []
    if index not in FIELDS: raise ValueError("index must be 'events' or 'alerts'")
    fields = FIELDS[index]; w, a = _where(terms, fields)
    if earliest_min: w.append("ts>=?"); a.append(now(datetime.now() - timedelta(minutes=int(earliest_min))))
    rows = q(f"SELECT * FROM {index} WHERE {' AND '.join(w) or '1=1'} ORDER BY id DESC LIMIT 5000", a)
    cols = None; total = len(rows); note = None
    for cmd in parts[1:]:
        tk = cmd.split(); name = (tk[0] if tk else "").lower()
        if name == "stats":
            m = re.match(r"^stats\s+count(?:\s+as\s+(\w+))?(?:\s+by\s+(.+))?$", cmd, re.I)
            if not m: raise ValueError("use: stats count [by field1,field2]")
            alias, by = m.group(1) or "count", [b.strip() for b in re.split(r"[,\s]+", m.group(2) or "") if b.strip()]
            for b in by:
                if b not in fields: raise ValueError(f"unknown field '{b}'")
            g = Counter(tuple(r.get(b) for b in by) for r in rows)
            rows = [{**dict(zip(by, k)), alias: c} for k, c in g.most_common()]; cols = by + [alias]
        elif name == "top":
            if len(tk) < 2 or tk[1] not in fields: raise ValueError("use: top <field>")
            g = Counter(r.get(tk[1]) for r in rows); tot = sum(g.values()) or 1
            rows = [{tk[1]: k, "count": c, "percent": round(c * 100 / tot, 1)} for k, c in g.most_common(10)]; cols = [tk[1], "count", "percent"]
        elif name == "timechart":
            span = 60
            m = re.search(r"span=(\d+)([mhd])", cmd)
            if m: span = int(m.group(1)) * {"m": 1, "h": 60, "d": 1440}[m.group(2)]
            g = Counter()
            for r in rows:
                try: t = datetime.strptime(r["ts"], FMT)
                except Exception: continue
                b = int((t - datetime(2000, 1, 1)).total_seconds() // 60 // span * span)
                g[(datetime(2000, 1, 1) + timedelta(minutes=b)).strftime("%Y-%m-%d %H:%M")] += 1
            rows = [{"time": k, "count": g[k]} for k in sorted(g)]; cols = ["time", "count"]
        elif name == "sort":
            f = (tk[1] if len(tk) > 1 else "").lstrip("+-"); desc = len(tk) > 1 and tk[1].startswith("-")
            if rows and f not in rows[0]: raise ValueError(f"cannot sort by '{f}'")
            rows.sort(key=lambda r: (r.get(f) is None, r.get(f) if isinstance(r.get(f), (int, float)) else str(r.get(f))), reverse=desc)
        elif name == "head":
            rows = rows[:int(tk[1]) if len(tk) > 1 and tk[1].isdigit() else 10]
        elif name == "table":
            cols = [c.strip(",") for c in tk[1:]]; rows = [{c: r.get(c) for c in cols} for r in rows]
        elif name == "dedup":
            f = tk[1] if len(tk) > 1 else ""; seen = set(); out = []
            for r in rows:
                if r.get(f) not in seen: seen.add(r.get(f)); out.append(r)
            rows = out
        else: raise ValueError(f"unknown command '{name}' (supported: stats, top, timechart, sort, head, table, dedup)")
    return dict(index=index, total=total, rows=rows[:1000], columns=cols or (sorted(rows[0].keys()) if rows else []), truncated=len(rows) > 1000)
