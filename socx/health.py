"""Forwarder / agent health + log-flood protection. A silent host is NOT assumed compromised: the alert is Medium with a plain 'could be failure' explanation."""
import os
from db import q, x, now, setting, setting_num
from .util import *

def run_once():
    from .correlation import emit, SELF
    silent_min = setting_num("agent_silent_minutes", 30, 1, 525600); out = []
    hb = {e["hostname"]: e for e in q("SELECT hostname,last_seen FROM endpoints")}
    stats = {r["host"]: r for r in q("SELECT host, MAX(ts) last_event, SUM(ts>=?) n10, COUNT(*) n24, MAX(id) mx FROM events WHERE host IS NOT NULL AND ts>=? AND (channel IS NULL OR channel!=?) GROUP BY host", (ago(10), ago(24 * 60), SELF))}
    for h in set(hb) | set(stats):
        s = stats.get(h); last_ev = s["last_event"] if s else None; last_hb = hb.get(h, {}).get("last_seen")
        base = (s["n24"] / 144.0) if s else 0           # average events per 10 minutes over the last 24h
        newest = max([t for t in (last_ev, last_hb) if t] or [None]) if (last_ev or last_hb) else None
        status = "Active"
        if newest and minutes_between(newest, now()) > silent_min: status = "Silent"
        if not newest: status = "Never seen"
        x("INSERT OR REPLACE INTO agent_health(host,last_event,last_heartbeat,events_10m,baseline_rate,status,silent_alerted,updated) VALUES(?,?,?,?,?,?,(SELECT silent_alerted FROM agent_health WHERE host=?),?)",
          (h, last_ev, last_hb, (s["n10"] if s else 0) or 0, round(base, 1), status, h, now()))
        # silent only if it was clearly active before (>= 20 events in the last 24h) and is not already reported for this silence
        if status == "Silent" and s and s["n24"] >= 20 and not q("SELECT 1 FROM agent_health WHERE host=? AND silent_alerted IS NOT NULL AND silent_alerted>=?", (h, ago(24 * 60)), one=True):
            if emit("HLT-001", h, None, None, f"{h} sent no events/heartbeat for {int(minutes_between(newest, now()))} min (normally ~{round(base)} events per 10 min). Possible agent failure, network issue or logging failure - not assumed to be compromise.", last_id=s["mx"], sig="silent"):
                x("UPDATE agent_health SET silent_alerted=? WHERE host=?", (now(), h))
        if status == "Active": x("UPDATE agent_health SET silent_alerted=NULL WHERE host=?", (h,))
    th = setting_num("flood_events_per_min", 2000, 1, 100000000)
    for r in q("SELECT host, COUNT(*) n, MAX(id) mx FROM events WHERE ts>=? AND host IS NOT NULL AND (channel IS NULL OR channel!=?) GROUP BY host HAVING n>=?", (ago(1), SELF, th)):
        top = q("SELECT event_id, COUNT(*) c FROM events WHERE host=? AND ts>=? GROUP BY event_id ORDER BY c DESC LIMIT 3", (r["host"], ago(1)))
        emit("HLT-002", r["host"], None, None, f"{r['n']} events/min from {r['host']} (threshold {th}). Top event IDs: " + ", ".join(f"{t['event_id']}x{t['c']}" for t in top) + ". Events are kept and aggregated, not dropped.", last_id=r["mx"], sig="flood")

def overview():
    rows = q("SELECT * FROM agent_health ORDER BY CASE status WHEN 'Silent' THEN 0 ELSE 1 END, host")
    ep = {e["hostname"]: e for e in q("SELECT hostname,cpu,ram,os,isolated FROM endpoints")}
    pend = {r["host"]: r["c"] for r in q("SELECT host, COUNT(*) c FROM commands WHERE status='pending' GROUP BY host")}
    import shutil
    du = shutil.disk_usage(os.path.dirname(os.path.abspath(__file__)))
    for r in rows:
        e = ep.get(r["host"], {}); r.update(cpu=e.get("cpu"), ram=e.get("ram"), os=e.get("os"), isolated=e.get("isolated"), queue=pend.get(r["host"], 0), connection="Connected" if r["status"] == "Active" else "No data")
    return {"agents": rows, "server_disk_used_pct": round(du.used * 100 / du.total, 1), "note": "Per-agent disk usage is not reported by the current agent; shown for the SOC server only."}
