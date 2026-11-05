"""Flask blueprint: /api/sx/* . Uses the app's existing login/role decorator and audit trail (passed in by register())."""
import json
from flask import Blueprint, jsonify, request
from db import q, x, now, RANK, iarg, sarg
from . import catalog, risk, fp, incidents, correlation, health

bp = Blueprint("socx", __name__, url_prefix="/api/sx")

def register(app, need, audit, body):
    @bp.route("/incidents")
    @need()
    def inc_list():
        st = request.args.get("status", ""); sv = request.args.get("severity", "")
        sql, a = "SELECT * FROM incidents WHERE 1=1", []
        if st: sql += " AND status=?"; a.append(st)
        if sv: sql += " AND severity=?"; a.append(sv)
        return jsonify(q(sql + " ORDER BY CASE severity WHEN 'Critical' THEN 4 WHEN 'High' THEN 3 WHEN 'Medium' THEN 2 ELSE 1 END DESC, last_seen DESC LIMIT 300", a))

    @bp.route("/incidents/<int:i>")
    @need()
    def inc_get(i):
        inc = q("SELECT * FROM incidents WHERE id=?", (i,), one=True)
        if not inc: return jsonify(error="not found"), 404
        inc["score_detail"] = json.loads(inc["score_detail"] or "{}")
        return jsonify(incident=inc, timeline=incidents.timeline(i), answers=incidents.answers(i),
                       alerts=q("SELECT a.id,a.ts,a.severity,a.title,a.count,a.status,m.mitre,m.risk_score,m.reason,m.process,m.command_line,m.parent_process,m.ioc,m.event_id,m.data_source,m.first_seen,m.last_seen FROM alerts a JOIN incident_alerts ia ON ia.alert_id=a.id LEFT JOIN alert_meta m ON m.alert_id=a.id WHERE ia.incident_id=? ORDER BY a.ts", (i,)),
                       notes=q("SELECT * FROM incident_notes WHERE incident_id=? ORDER BY id", (i,)))

    @bp.route("/incidents/<int:i>", methods=["PATCH"])
    @need("analyst")
    def inc_update(i):
        b = body(); ok = {"New", "In Progress", "Contained", "Resolved", "False Positive", "Closed"}
        if "status" in b:
            if not isinstance(b["status"], str) or b["status"] not in ok: return jsonify(error="bad status"), 400
            x("UPDATE incidents SET status=?,closed_at=? WHERE id=?", (b["status"], now() if b["status"] in ("Resolved", "False Positive", "Closed") else None, i)); audit(f"Incident #{i} status -> {b['status']}")
        if "assignee" in b: who = sarg(b["assignee"], 100) or None; x("UPDATE incidents SET assignee=? WHERE id=?", (who, i)); audit(f"Incident #{i} assigned to {who}")
        if b.get("note"): x("INSERT INTO incident_notes(incident_id,author,note,ts) VALUES(?,?,?,?)", (i, request.environ.get("REMOTE_USER") or __import__("flask").session.get("user"), b["note"][:2000], now()))
        return jsonify(ok=True)

    @bp.route("/summary")
    @need()
    def summary():
        c = lambda sql, a=(): q(sql, a, one=True)["c"]
        return jsonify(open_incidents=c("SELECT COUNT(*) c FROM incidents WHERE status IN ('New','In Progress','Contained')"),
            critical=c("SELECT COUNT(*) c FROM incidents WHERE severity='Critical' AND status IN ('New','In Progress','Contained')"),
            high=c("SELECT COUNT(*) c FROM incidents WHERE severity='High' AND status IN ('New','In Progress','Contained')"),
            suppressed=c("SELECT COUNT(*) c FROM alerts WHERE status='Suppressed'"), silent_agents=c("SELECT COUNT(*) c FROM agent_health WHERE status='Silent'"),
            compromised_hosts=[r["host"] for r in q("SELECT DISTINCT host FROM incidents WHERE severity IN ('Critical','High') AND status IN ('New','In Progress','Contained') AND host IS NOT NULL")],
            top_mitre=q("SELECT mitre k, COUNT(*) c FROM alert_meta WHERE mitre!='' AND suppressed_by IS NULL GROUP BY mitre ORDER BY c DESC LIMIT 8"))

    @bp.route("/catalog")
    @need()
    def cat():
        return jsonify([dict(d, status="active" if d["id"] in correlation.IMPLEMENTED else "needs data feed") for d in catalog.CATALOG])

    @bp.route("/playbook/<path:tactic>")
    @need()
    def pb(tactic): return jsonify(catalog.playbook_for(tactic))

    # ---- false positives ----
    @bp.route("/whitelist")
    @need()
    def wl_list(): return jsonify(rules=q("SELECT * FROM whitelist ORDER BY id DESC"), kinds=fp.KINDS, audit=q("SELECT * FROM whitelist_audit ORDER BY id DESC LIMIT 200"))

    @bp.route("/whitelist", methods=["POST"])
    @need("admin")
    def wl_add():
        b = body(); k = b.get("kind")
        if k not in fp.KINDS or not (b.get("reason") or "").strip(): return jsonify(error="kind and a reason are required"), 400
        if not any(b.get(f) for f in ("host", "username", "source_ip", "pattern")): return jsonify(error="a rule needs at least one of host / username / source_ip / pattern (no catch-all rules)"), 400
        if k == "maintenance_window" and not (b.get("starts") and b.get("expires")): return jsonify(error="maintenance window needs start and end (YYYY-MM-DD HH:MM:SS)"), 400
        u = __import__("flask").session.get("user")
        i = x("INSERT INTO whitelist(kind,detection,host,username,source_ip,pattern,starts,expires,reason,created_by,created_at) VALUES(?,?,?,?,?,?,?,?,?,?,?)",
              (k, b.get("detection") or "*", b.get("host", ""), b.get("username", ""), b.get("source_ip", ""), b.get("pattern", ""), b.get("starts") or None, b.get("expires") or None, b["reason"], u, now()))
        fp.audit(i, "created", u, json.dumps(b)[:400]); audit(f"Whitelist rule #{i} created ({k})"); return jsonify(ok=True, id=i)

    @bp.route("/whitelist/<int:i>", methods=["PATCH", "DELETE"])
    @need("admin")
    def wl_mod(i):
        u = __import__("flask").session.get("user")
        if request.method == "DELETE": x("UPDATE whitelist SET enabled=0 WHERE id=?", (i,)); fp.audit(i, "disabled(delete)", u, "rule disabled, history kept")     # never hard-delete: auditable
        else: x("UPDATE whitelist SET enabled=? WHERE id=?", (1 if body().get("enabled") else 0, i)); fp.audit(i, "enabled" if body().get("enabled") else "disabled", u, "")
        return jsonify(ok=True)

    # ---- assets / risk / health ----
    @bp.route("/assets")
    @need()
    def assets():
        return jsonify(q("SELECT e.hostname, COALESCE(a.criticality,2) criticality, COALESCE(a.role,'') role, COALESCE(a.owner,'') owner FROM endpoints e LEFT JOIN assets a ON a.hostname=e.hostname ORDER BY e.hostname"))

    @bp.route("/assets", methods=["POST"])
    @need("admin")
    def asset_set():
        b = body(); c = iarg(b.get("criticality"), 2, 1, 5); host = sarg(b.get("hostname"), 255)
        if not host: return jsonify(error="hostname required"), 400
        x("INSERT OR REPLACE INTO assets VALUES(?,?,?,?,?)", (host, c, sarg(b.get("role"), 100), sarg(b.get("owner"), 100), now())); audit(f"Asset {host} criticality {c}"); return jsonify(ok=True)

    @bp.route("/risk-model")
    @need()
    def rm_get(): return jsonify(risk.model())

    @bp.route("/risk-model", methods=["PUT"])
    @need("admin")
    def rm_put():
        m = body()
        if not isinstance(m, dict): return jsonify(error="bad"), 400
        risk.save_model(m); audit("Risk model updated"); return jsonify(ok=True, model=risk.model())

    @bp.route("/health")
    @need()
    def hl(): return jsonify(health.overview())

    @bp.route("/run", methods=["POST"])
    @need("admin")
    def run_now():
        n, err = correlation.run_once(); health.run_once(); return jsonify(ok=True, new_alerts=n, errors=err)

    @bp.route("/hunt")
    @need()
    def hunt():
        f = {k: request.args.get(k, "").strip() for k in ("process", "user", "ip", "domain", "hash", "cmd", "event_id", "host")}
        sql, a = "SELECT id,ts,host,username,source_ip,event_id,channel,activity,risk,message,alert_id FROM events WHERE (channel IS NULL OR channel!='EXE-SOC')", []
        def like(col, v): nonlocal sql; sql += f" AND {col} LIKE ?"; a.append(f"%{v}%")
        if f["process"]: sql += " AND (message LIKE ? OR raw LIKE ?)"; a += [f"%{f['process']}%"] * 2
        if f["user"]: like("username", f["user"])
        if f["ip"]: sql += " AND (source_ip LIKE ? OR dest_ip LIKE ?)"; a += [f"%{f['ip']}%"] * 2
        if f["domain"]: sql += " AND (message LIKE ? OR raw LIKE ?)"; a += [f"%{f['domain']}%"] * 2
        if f["hash"]: sql += " AND (message LIKE ? OR raw LIKE ?)"; a += [f"%{f['hash']}%"] * 2
        if f["cmd"]: sql += " AND (message LIKE ? OR raw LIKE ?)"; a += [f"%{f['cmd']}%"] * 2
        if f["host"]: like("host", f["host"])
        if f["event_id"].isdigit(): sql += " AND event_id=?"; a.append(int(f["event_id"]))
        return jsonify(q(sql + " ORDER BY id DESC LIMIT 300", a))

    app.register_blueprint(bp)
