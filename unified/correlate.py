"""Evidence-based cross-source correlation. Every link records WHY it exists, whether it is OBSERVED (shared hard identifier such as logon_id / process_guid)
or INFERRED (heuristic), the window used and a confidence. Events are never linked just because they are close in time."""
import json
from db import q, x
from .rules import epoch
from .store import utcnow

DEFAULTS = dict(fail_window_s=600, skew_s=5, dns_net_s=10, max_events=3000)
def _lid(v): return (v or "").lower() or None
def _exe(e): return ((e.get("image") or e.get("process_name") or "").replace("/", "\\").split("\\")[-1]).lower()

def link_events(evs, cfg=None):
    """evs: list of normalised event dicts (with 'id', 'timestamp', 'extra' dict). -> list of links dict(from,to,reason,basis,confidence,window_s)."""
    c = {**DEFAULTS, **(cfg or {})}; L = []; seen = set()
    def add(a, b, reason, basis, conf, win=0):
        if a["id"] == b["id"] or (a["id"], b["id"]) in seen: return
        seen.add((a["id"], b["id"])); L.append(dict(**{"from": a["id"], "to": b["id"]}, reason=reason, basis=basis, confidence=round(min(conf, 0.99), 2), window_s=win))
    evs = sorted(evs, key=lambda e: (e.get("timestamp") or "", e["id"]))
    by_host = {}
    for e in evs: by_host.setdefault(e.get("host"), []).append(e)
    for host, es in by_host.items():
        logons = [e for e in es if e["source"] == "windows_security" and e["event_id"] == 4624]
        fails = [e for e in es if e["source"] == "windows_security" and e["event_id"] == 4625]
        priv = [e for e in es if e["source"] == "windows_security" and e["event_id"] == 4672]
        s4688 = [e for e in es if e["source"] == "windows_security" and e["event_id"] == 4688]
        sm = [e for e in es if e["source"] == "sysmon"]
        s1 = [e for e in sm if e["event_id"] == 1]
        for lg in logons:                                              # 4625 -> 4624: same account (+ same source address raises confidence)
            t = epoch(lg["timestamp"]); prev = [f for f in fails if f.get("target_username") == lg.get("target_username") and 0 <= t - epoch(f["timestamp"]) <= c["fail_window_s"]][-20:]
            for f in prev:
                same_ip = bool(lg.get("source_ip")) and lg.get("source_ip") == f.get("source_ip")
                add(f, lg, f"failed logon preceded success for account {lg.get('target_username')}" + (" from the same source address" if same_ip else " (source address differs or unknown)"), "inferred", 0.85 if same_ip else 0.55, c["fail_window_s"])
            lid = _lid(lg.get("logon_id"))
            if not lid: continue
            for p in priv:
                if _lid(p.get("logon_id")) == lid and epoch(p["timestamp"]) >= t - 2: add(lg, p, f"special privileges assigned to the same logon_id {lid}", "observed", 0.95)
            for pr in s4688:
                if _lid(pr.get("logon_id")) == lid and epoch(pr["timestamp"]) >= t - 2: add(lg, pr, f"process created under the same logon_id {lid}", "observed", 0.95)
            for sp in s1:
                if _lid(sp.get("logon_id")) == lid and epoch(sp["timestamp"]) >= t - 2: add(lg, sp, f"Sysmon process runs under the same LogonId {lid}", "observed", 0.9)
        used = set()
        for pr in s4688:                                               # 4688 <-> Sysmon 1: image + (pid | command line) + time; one-to-one
            best = None
            for sp in s1:
                if sp["id"] in used or _exe(sp) != _exe(pr) or not _exe(pr): continue
                dt = abs(epoch(sp["timestamp"]) - epoch(pr["timestamp"]))
                if dt > c["skew_s"]: continue
                pid = pr.get("process_id") is not None and pr.get("process_id") == sp.get("process_id")
                cmd = bool(pr.get("command_line")) and pr.get("command_line") == sp.get("command_line")
                if not (pid or cmd): continue
                score = (2 if pid else 0) + (1 if cmd else 0) - dt / 100
                if best is None or score > best[0]: best = (score, sp, pid, cmd, dt)
            if best:
                _, sp, pid, cmd, dt = best; used.add(sp["id"])
                add(pr, sp, "same image" + (", same PID" if pid else "") + (", same command line" if cmd else "") + f", {dt:.1f}s apart (PID reuse excluded by the time bound)", "inferred", 0.9 if (pid and cmd) else 0.75 if pid else 0.6, c["skew_s"])
        by_guid = {}
        for e in sm:
            if e.get("process_guid"): by_guid.setdefault(e["process_guid"], []).append(e)
        for g, grp in by_guid.items():
            root = next((e for e in grp if e["event_id"] == 1), None)
            for e in grp:
                if root and e is not root and e["event_id"] in (3, 5, 7, 8, 10, 11, 12, 13, 14, 22, 23, 26): add(root, e, f"same Sysmon ProcessGuid {g}", "observed", 0.97)
            for e in grp:
                pg = e.get("parent_process_guid")
                if pg and pg in by_guid:
                    par = next((p for p in by_guid[pg] if p["event_id"] == 1), None)
                    if par: add(par, e, "child's ParentProcessGuid equals parent's ProcessGuid", "observed", 0.98)
            dns = [e for e in grp if e["event_id"] == 22]; nets = [e for e in grp if e["event_id"] == 3]
            for d in dns:
                for n in nets:
                    dt = epoch(n["timestamp"]) - epoch(d["timestamp"])
                    if 0 <= dt <= c["dns_net_s"]:
                        hit = n.get("destination_ip") and n["destination_ip"] in ((d.get("extra") or {}).get("query_results") or "")
                        add(d, n, "DNS answer contains the connection's destination IP" if hit else f"same process, connection {dt:.1f}s after the DNS query", "observed" if hit else "inferred", 0.85 if hit else 0.5, c["dns_net_s"])
    return L

def component(evs, links, seeds):
    adj = {}
    for l in links: adj.setdefault(l["from"], set()).add(l["to"]); adj.setdefault(l["to"], set()).add(l["from"])
    seen = set(seeds); st = list(seeds)
    while st:
        for n in adj.get(st.pop(), ()):
            if n not in seen: seen.add(n); st.append(n)
    return [e for e in evs if e["id"] in seen], [l for l in links if l["from"] in seen and l["to"] in seen]

def _load(rows):
    for r in rows:
        try: r["extra"] = json.loads(r.get("extra") or "{}") if isinstance(r.get("extra"), str) else (r.get("extra") or {})
        except Exception: r["extra"] = {}
    return rows

def timeline_for_events(seed_ids, host, pad_s=900, persist=True, cfg=None):
    """Timeline around supporting events. Returns dict(nodes, links, confidence, summary, note)."""
    seeds = [int(i) for i in seed_ids][:500]
    if not seeds: return dict(nodes=[], links=[], confidence=0, summary="no evidence", note="")
    rng = q("SELECT MIN(timestamp) a, MAX(timestamp) b FROM norm_events WHERE id IN (%s)" % ",".join("?" * len(seeds)), seeds, one=True)
    from datetime import datetime, timedelta, timezone
    f = lambda s, d: (datetime.strptime(s[:19], "%Y-%m-%dT%H:%M:%S") + timedelta(seconds=d)).strftime("%Y-%m-%dT%H:%M:%S")
    if not rng or not rng["a"]: return dict(nodes=[], links=[], confidence=0, summary="evidence not found", note="")
    evs = _load(q("SELECT * FROM norm_events WHERE host=? AND timestamp>=? AND timestamp<=? ORDER BY timestamp LIMIT ?", (host, f(rng["a"], -pad_s), f(rng["b"], pad_s) + "\uffff", (cfg or DEFAULTS)["max_events"] if cfg else DEFAULTS["max_events"])))
    ids = {e["id"] for e in evs}; missing = [s for s in seeds if s not in ids]
    if missing: evs += _load(q("SELECT * FROM norm_events WHERE id IN (%s)" % ",".join("?" * len(missing)), missing))
    links = link_events(evs, cfg); nodes, ls = component(evs, links, [s for s in seeds])
    conf = round(sum(l["confidence"] for l in ls) / len(ls), 2) if ls else 0.0
    srcs = sorted({n["source"] for n in nodes})
    out = dict(nodes=[{k: n.get(k) for k in ("id", "timestamp", "source", "event_id", "activity", "username", "target_username", "process_name", "command_line", "source_ip", "destination_ip", "destination_port", "dns_query_name", "target_filename", "logon_id", "process_guid", "rule_name")} for n in nodes],
               links=ls, confidence=conf, summary=f"{len(nodes)} events from {', '.join(srcs)} linked by {len(ls)} relationship(s)",
               note="Links marked 'observed' share a hard identifier; 'inferred' links are heuristic. Missing telemetry is not filled in: absent steps mean no supporting event was collected.")
    if persist and ls:
        cid = x("INSERT INTO u_correlations(created,host,anchor,window_s,confidence,summary) VALUES(?,?,?,?,?,?)", (utcnow(), host, ",".join(map(str, seeds[:20])), pad_s, conf, out["summary"]))
        for l in ls: x("INSERT INTO u_corr_links VALUES(?,?,?,?,?,?)", (cid, l["from"], l["to"], l["reason"], l["basis"], l["confidence"]))
        out["correlation_id"] = cid
    return out
