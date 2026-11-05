"""REST API for the unified layer. Registered once from app.py with the app's own need()/audit()/body() helpers (same RBAC, CSRF and error handling as every other route).
viewer: summaries + normalised events (no raw)   analyst: raw events, export, timelines, status changes   admin: rule tuning, allow-lists"""
import io, csv, json
from flask import jsonify, request, Response
from db import q, x, now, iarg, sarg, csv_cell, BadInput
from . import store, rules, correlate, config_changed
from .store import utcnow

STATUSES = ("New", "Investigating", "Confirmed", "False Positive", "Resolved", "In Progress")
def register(app, need, audit, body):
    def me():
        from flask import session; return session.get("user", "system")

    def args(): return {k: sarg(request.args.get(k), 300) for k in list(store.FILTERS) + ["since", "until", "text"]}

    @app.route("/api/u/events")
    @need()
    def u_events():
        rows, total = store.search(args(), iarg(request.args.get("limit"), 100, 1, 500), iarg(request.args.get("offset"), 0, 0, 10 ** 9))
        for r in rows:
            try: r["extra"] = json.loads(r["extra"] or "{}")
            except Exception: r["extra"] = {}
        return jsonify(total=total, rows=rows)

    @app.route("/api/u/events/<int:i>")
    @need("analyst")
    def u_event(i):
        r = store.get(i)
        if not r: return jsonify(error="not found"), 404
        try: r["extra"] = json.loads(r["extra"] or "{}")
        except Exception: r["extra"] = {}
        return jsonify(r)                                                # raw_event is plain text: the UI must render it with textContent/esc()

    @app.route("/api/u/events/export.csv")
    @need("analyst")
    def u_export():
        rows, _ = store.search(args(), 50000, 0, cols=store.LIST_COLS.replace(",extra", ""))
        buf = io.StringIO(); w = csv.writer(buf)
        if rows: w.writerow(rows[0].keys())
        for r in rows: w.writerow([csv_cell(v) for v in r.values()])
        audit(f"Exported {len(rows)} unified events"); return Response(buf.getvalue(), mimetype="text/csv", headers={"Content-Disposition": "attachment; filename=exe-soc-events.csv"})

    @app.route("/api/u/meta")
    @need()
    def u_meta():
        return jsonify(hosts=[r["host"] for r in q("SELECT DISTINCT host FROM norm_events ORDER BY host LIMIT 500")], sources=[r["source"] for r in q("SELECT DISTINCT source FROM norm_events")],
                       platforms=[r["platform"] for r in q("SELECT DISTINCT platform FROM norm_events")], rules=[dict(id=k, name=v["name"]) for k, v in rules.RULES.items()],
                       event_ids=[r["event_id"] for r in q("SELECT DISTINCT event_id FROM norm_events WHERE event_id IS NOT NULL ORDER BY event_id")])

    @app.route("/api/u/overview")
    @need()
    def u_overview():
        hrs = iarg(request.args.get("hours"), 24, 1, 720)
        from datetime import datetime, timedelta, timezone
        since = (datetime.now(timezone.utc) - timedelta(hours=hrs)).strftime("%Y-%m-%dT%H:%M:%S")
        one = lambda s, a=(): q(s, a, one=True)["c"]
        return jsonify(hours=hrs, events=one("SELECT COUNT(*) c FROM norm_events WHERE timestamp>=?", (since,)),
            endpoints=one("SELECT COUNT(*) c FROM endpoints"), hosts_reporting=one("SELECT COUNT(DISTINCT host) c FROM norm_events WHERE timestamp>=?", (since,)),
            by_source=q("SELECT source k, COUNT(*) n FROM norm_events WHERE timestamp>=? GROUP BY source ORDER BY n DESC", (since,)),
            by_event_id=q("SELECT source, event_id k, COUNT(*) n FROM norm_events WHERE timestamp>=? AND event_id IS NOT NULL GROUP BY source,event_id ORDER BY n DESC LIMIT 15", (since,)),
            over_time=q("SELECT substr(timestamp,1,13) h, COUNT(*) n FROM norm_events WHERE timestamp>=? GROUP BY h ORDER BY h", (since,)),
            auth=q("SELECT activity k, COUNT(*) n FROM norm_events WHERE timestamp>=? AND activity IN ('logon_success','logon_failure','ssh_auth_success','ssh_auth_failure','account_lockout') GROUP BY activity", (since,)),
            top_hosts=q("SELECT host k, COUNT(*) n FROM norm_events WHERE timestamp>=? GROUP BY host ORDER BY n DESC LIMIT 10", (since,)),
            alerts_by_severity=q("SELECT a.severity k, COUNT(*) n FROM alerts a JOIN u_alert_evidence u ON u.alert_id=a.id GROUP BY a.severity"),
            recent=q("SELECT a.id,a.ts,a.severity,a.title,a.status,u.host,u.account,u.confidence,u.rule_id FROM alerts a JOIN u_alert_evidence u ON u.alert_id=a.id ORDER BY a.id DESC LIMIT 10"))

    @app.route("/api/u/health")
    @need()
    def u_health():
        from datetime import datetime, timezone
        rows = q("SELECT * FROM collector_state ORDER BY host,source"); nowt = datetime.now(timezone.utc)
        for r in rows:
            try: r["lag_s"] = max(0, int((nowt - datetime.strptime(r["last_event_ts"][:19], "%Y-%m-%dT%H:%M:%S").replace(tzinfo=timezone.utc)).total_seconds()))
            except Exception: r["lag_s"] = None
            try: r["silent_s"] = int((nowt - datetime.strptime(r["last_ingest_ts"][:19], "%Y-%m-%dT%H:%M:%S").replace(tzinfo=timezone.utc)).total_seconds())
            except Exception: r["silent_s"] = None
        return jsonify(collectors=rows, telemetry_gaps=q("SELECT * FROM telemetry_flags ORDER BY last_seen DESC"),
                       sysmon_hosts=[r["host"] for r in q("SELECT DISTINCT host FROM norm_events WHERE source='sysmon'")],
                       windows_hosts_without_sysmon=[r["host"] for r in q("SELECT DISTINCT host FROM norm_events WHERE source='windows_security' AND host NOT IN (SELECT host FROM norm_events WHERE source='sysmon')")],
                       note="lag_s = now - newest event time seen; silent_s = time since the collector last delivered anything. Large silent_s means a telemetry gap.")

    # ---- rules ----
    def rule_view(r, c):
        return dict(id=r["id"], name=r["name"], version=r["version"], description=r["description"], sources=r["sources"], event_ids=r["event_ids"], activities=r["activities"], severity=r["severity"], confidence=r["confidence"],
                    mitre=r["mitre"], steps=r["steps"], false_positives=r["false_positives"], evidence_fields=r["evidence_fields"], default_params=r["params"], params={**r["params"], **(c.get("params") or {})},
                    enabled=(c.get("enabled") if c.get("enabled") is not None else True), test_cases=len(r["tests"]))

    @app.route("/api/u/rules")
    @need()
    def u_rules():
        from . import _cfg
        cfg, _ = _cfg(); return jsonify([rule_view(r, cfg.get(k) or {}) for k, r in rules.RULES.items()])

    @app.route("/api/u/rules/<rid>", methods=["PATCH"])
    @need("admin")
    def u_rule_set(rid):
        r = rules.RULES.get(rid)
        if not r: return jsonify(error="unknown rule"), 404
        d = body(); old = q("SELECT * FROM u_rule_cfg WHERE rule_id=?", (rid,), one=True) or {}
        en = old.get("enabled") if "enabled" not in d else (1 if d["enabled"] else 0)
        params = json.loads(old.get("params") or "{}") if old else {}
        if "params" in d:
            if not isinstance(d["params"], dict): raise BadInput("params must be an object")
            for k, v in d["params"].items():
                if k not in r["params"]: return jsonify(error=f"unknown parameter {k}"), 400
                dv = r["params"][k]
                if isinstance(dv, bool) or not isinstance(v, type(dv)) and not (isinstance(dv, (int, float)) and isinstance(v, (int, float)) and not isinstance(v, bool)): return jsonify(error=f"{k}: wrong type"), 400
                if isinstance(dv, (int, float)) and not (0 <= v <= 10 ** 7): return jsonify(error=f"{k}: out of range"), 400
                if isinstance(dv, list) and (len(v) > 500 or not all(isinstance(i, (str, int)) for i in v)): return jsonify(error=f"{k}: invalid list"), 400
                if isinstance(dv, str) and len(v) > 500: return jsonify(error=f"{k}: too long"), 400
                params[k] = v
        x("INSERT INTO u_rule_cfg(rule_id,enabled,params,updated,updated_by) VALUES(?,?,?,?,?) ON CONFLICT(rule_id) DO UPDATE SET enabled=excluded.enabled,params=excluded.params,updated=excluded.updated,updated_by=excluded.updated_by",
          (rid, en, json.dumps(params), now(), me())); config_changed(); audit(f"Detection rule {rid} tuned"); return jsonify(ok=True)

    @app.route("/api/u/rules/selftest")
    @need("analyst")
    def u_rule_selftest():
        res = []
        for rid, r in rules.RULES.items():
            for t in r["tests"]:
                try: ok = bool(rules.run_case(rid, json.loads(json.dumps(t, default=lambda o: o))) ) == t["expect"] if False else bool(rules.run_case(rid, dict(t, events=[dict(e) for e in t["events"]]))) == t["expect"]
                except Exception: ok = False
                res.append(dict(rule=rid, case=t["name"], expect=t["expect"], passed=ok))
        return jsonify(passed=sum(r["passed"] for r in res), total=len(res), results=res)

    @app.route("/api/u/allowlist")
    @need("analyst")
    def u_allow(): return jsonify(q("SELECT * FROM u_allowlist ORDER BY id DESC"))

    @app.route("/api/u/allowlist", methods=["POST"])
    @need("admin")
    def u_allow_add():
        d = body(); f, v, rid = sarg(d.get("field"), 60), sarg(d.get("value"), 300), sarg(d.get("rule_id"), 20) or None
        if f not in (set(store.COLS) - {"raw_event", "extra"}) | {"granted_access", "target_server"} or not v: return jsonify(error="invalid field or value"), 400
        if rid and rid not in rules.RULES: return jsonify(error="unknown rule"), 400
        i = x("INSERT INTO u_allowlist(rule_id,field,value,reason,created,created_by) VALUES(?,?,?,?,?,?)", (rid, f, v, sarg(d.get("reason"), 300), now(), me())); config_changed(); audit(f"Allow-list {f}={v} for {rid or 'all rules'}"); return jsonify(ok=True, id=i)

    @app.route("/api/u/allowlist/<int:i>", methods=["DELETE"])
    @need("admin")
    def u_allow_del(i): x("DELETE FROM u_allowlist WHERE id=?", (i,)); config_changed(); audit(f"Allow-list entry {i} removed"); return jsonify(ok=True)

    # ---- alerts: evidence + status ----
    @app.route("/api/u/alerts/<int:i>")
    @need()
    def u_alert(i):
        a = q("SELECT * FROM alerts WHERE id=?", (i,), one=True); u = q("SELECT * FROM u_alert_evidence WHERE alert_id=?", (i,), one=True)
        if not a or not u: return jsonify(error="no unified evidence for this alert"), 404
        ids = json.loads(u["evidence_ids"] or "[]"); evs = store.get_many(ids[-200:])
        for e in evs: e.pop("raw_event", None); e["extra"] = json.loads(e["extra"] or "{}") if isinstance(e.get("extra"), str) else e.get("extra")
        return jsonify(alert=a, rule=dict(id=u["rule_id"], version=u["rule_version"], mitre=u["mitre"], confidence=u["confidence"]), summary=u["summary"], first_seen=u["first_seen"], last_seen=u["last_seen"], host=u["host"], account=u["account"],
                       steps=json.loads(u["steps"] or "[]"), false_positive_considerations=u["fp_notes"], evidence_ids=ids, evidence=evs, event_ids=json.loads(u["event_ids"] or "[]"),
                       history=q("SELECT * FROM u_status_history WHERE alert_id=? ORDER BY id", (i,)), notes=a.get("note"))

    @app.route("/api/u/alerts/<int:i>/timeline")
    @need("analyst")
    def u_alert_timeline(i):
        u = q("SELECT * FROM u_alert_evidence WHERE alert_id=?", (i,), one=True)
        if not u: return jsonify(error="not found"), 404
        return jsonify(correlate.timeline_for_events(json.loads(u["evidence_ids"] or "[]")[-100:], u["host"], iarg(request.args.get("pad"), 900, 60, 86400)))

    @app.route("/api/u/alerts/<int:i>/status", methods=["POST"])
    @need("analyst")
    def u_alert_status(i):
        d = body(); st = sarg(d.get("status"), 30); note = sarg(d.get("note"), 1000)
        a = q("SELECT status FROM alerts WHERE id=?", (i,), one=True)
        if not a: return jsonify(error="not found"), 404
        if st not in STATUSES: return jsonify(error="bad status"), 400
        x("UPDATE alerts SET status=?,updated=?,resolved_at=? WHERE id=?", (st, now(), now() if st in ("Resolved", "False Positive") else None, i))
        x("INSERT INTO u_status_history(alert_id,ts,user,old_status,new_status,note) VALUES(?,?,?,?,?,?)", (i, now(), me(), a["status"], st, note))
        audit(f"Alert #{i} {a['status']} -> {st}"); return jsonify(ok=True)

    @app.route("/api/u/timeline")
    @need("analyst")
    def u_timeline():
        host = sarg(request.args.get("host"), 200); ids = [iarg(v, 0) for v in (request.args.get("ids") or "").split(",") if v.strip()][:100]
        if not host or not ids: return jsonify(error="host and ids required"), 400
        return jsonify(correlate.timeline_for_events(ids, host, iarg(request.args.get("pad"), 900, 60, 86400)))
