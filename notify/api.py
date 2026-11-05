"""REST API /api/v1/notifications/*  (existing login, roles, CSRF header and audit trail). SMTP settings, recipients and test e-mails: admin only. Viewing settings/history: analyst."""
import re, json
from flask import Blueprint, jsonify, request
from db import q, x, now, iarg, sarg
from . import config, render, smtpx, deliver, enqueue, status, policy
import notify as N

bp = Blueprint("notify", __name__, url_prefix="/api/v1/notifications")
PROVIDERS = [  # VERIFY IN CURRENT PROVIDER DOCUMENTATION: providers change their SMTP rules (app passwords, SMTP AUTH, API-key usernames)
 {"id": "gmail", "name": "Gmail / Google Workspace", "host": "smtp.gmail.com", "port": 587, "security": "starttls", "note": "Needs 2-step verification and an App Password (or a Workspace SMTP relay). Username is the full address."},
 {"id": "m365", "name": "Microsoft 365", "host": "smtp.office365.com", "port": 587, "security": "starttls", "note": "SMTP AUTH must be enabled for the mailbox; some tenants require OAuth instead (not supported here). Sender must be that mailbox."},
 {"id": "outlook", "name": "Outlook.com", "host": "smtp-mail.outlook.com", "port": 587, "security": "starttls", "note": "Uses an app password. Verify current requirements."},
 {"id": "ses", "name": "Amazon SES", "host": "email-smtp.<region>.amazonaws.com", "port": 587, "security": "starttls", "note": "Replace <region>. Username/password are SES SMTP credentials; the sender must be verified."},
 {"id": "sendgrid", "name": "SendGrid", "host": "smtp.sendgrid.net", "port": 587, "security": "starttls", "note": "Username is the word apikey, password is the API key."},
 {"id": "ssl465", "name": "Generic SMTP over SSL/TLS", "host": "", "port": 465, "security": "ssl", "note": "Implicit TLS on port 465."},
 {"id": "generic", "name": "Generic SMTP with STARTTLS", "host": "", "port": 587, "security": "starttls", "note": "Default."}]

def register(app, need, audit, body):
    def vrec(d, partial=False):
        out = {}
        if "email" in d or not partial:
            em = (d.get("email") or "").strip().lower()
            if not config.EMAIL_RX.match(em) or len(em) > 254: return None, "invalid email address"
            out["email"] = em
        if "name" in d: out["name"] = re.sub(r"[\r\n<>]", "", str(d.get("name") or ""))[:80]
        if "enabled" in d: out["enabled"] = 1 if d["enabled"] in (True, 1, "1", "true") else 0
        if "level" in d:
            if str(d["level"]) not in ("1", "2", "3"): return None, "level must be 1, 2 or 3"
            out["level"] = iarg(d["level"], 1, 1, 3)
        if "severities" in d:
            sv = d["severities"] if isinstance(d["severities"], list) else [s for s in str(d["severities"]).split(",") if s]
            if any(s not in config.SEVERITIES for s in sv): return None, "unknown severity"
            out["severities"] = ",".join(sv)
        return out, ""

    @bp.route("/settings")
    @need("analyst")
    def get_settings():
        return jsonify(settings=config.all_settings(), types=config.TYPES, severities=config.SEVERITIES, smtp_problems=config.validate_smtp() if (config.get("smtp_host") or config.method() == "gmail_api") else ["SMTP host is not set"], status=status(), providers=PROVIDERS, methods=list(config.METHODS), gmail=config.gmail_status(),
                       password_note="The SMTP password is never shown or stored. Set SMTP_PASSWORD (or SMTP_PASSWORD_FILE) in the server environment. For the Gmail API set GMAIL_CLIENT_ID, GMAIL_CLIENT_SECRET and GMAIL_REFRESH_TOKEN the same way.")

    @bp.route("/settings", methods=["PUT"])
    @need("admin")
    def put_settings():
        d = body(); ok, err = config.set_values({k: v for k, v in d.items() if not (config.ENV.get(k) and config.all_settings()[k]["locked"])} if isinstance(d, dict) else {})
        if not ok: return jsonify(error=err), 400
        audit("Changed email notification settings: " + ", ".join(sorted(k for k in d if "pass" not in k.lower()))[:200]); return jsonify(ok=True)

    @bp.route("/status")
    @need("analyst")
    def get_status(): return jsonify(status())

    @bp.route("/providers")
    @need("analyst")
    def providers(): return jsonify(PROVIDERS)

    @bp.route("/recipients")
    @need("analyst")
    def list_rec(): return jsonify(q("SELECT id,email,name,enabled,severities,level,created_by,created FROM notification_recipients ORDER BY id"))

    @bp.route("/recipients", methods=["POST"])
    @need("admin")
    def add_rec():
        v, err = vrec(body())
        if err: return jsonify(error=err), 400
        if q("SELECT 1 FROM notification_recipients WHERE email=?", (v["email"],), one=True): return jsonify(error="that recipient already exists"), 409
        from flask import session
        i = x("INSERT INTO notification_recipients(email,name,enabled,severities,level,created_by,created) VALUES(?,?,?,?,?,?,?)", (v["email"], v.get("name", ""), v.get("enabled", 1), v.get("severities", ""), v.get("level", 1), session.get("user"), now()))
        audit(f"Added notification recipient {v['email']}"); return jsonify(id=i)

    @bp.route("/recipients/<int:i>", methods=["PATCH"])
    @need("admin")
    def upd_rec(i):
        v, err = vrec(body(), partial=True)
        if err: return jsonify(error=err), 400
        if not q("SELECT 1 FROM notification_recipients WHERE id=?", (i,), one=True): return jsonify(error="not found"), 404
        for k, val in v.items(): x(f"UPDATE notification_recipients SET {k}=? WHERE id=?", (val, i))
        audit(f"Changed notification recipient #{i}: " + ", ".join(v)); return jsonify(ok=True)

    @bp.route("/recipients/<int:i>", methods=["DELETE"])
    @need("admin")
    def del_rec(i):
        r = q("SELECT email FROM notification_recipients WHERE id=?", (i,), one=True)
        if not r: return jsonify(error="not found"), 404
        x("DELETE FROM notification_recipients WHERE id=?", (i,)); audit(f"Removed notification recipient {r['email']}"); return jsonify(ok=True)

    def do_test(to):
        cfg = config.smtp_config(); subj, h, t = render.test_message(to); nid = enqueue("test", "Info", [to], subj, h, t)
        row = q("SELECT * FROM notification_history WHERE notification_id=? AND recipient=?", (nid, to), one=True)
        try:
            smtpx.send(cfg, to, subj, h, t, timeout=12)
            x("UPDATE notification_history SET status='SENT',attempts=1,sent_at=?,body_html=NULL,body_text=NULL WHERE id=?", (now(), row["id"])); audit(f"Sent test email to {to}")
            return jsonify(ok=True, message=f"Test email sent successfully to {to}")
        except smtpx.NotifyError as e:
            msg = smtpx.safe(e.message, cfg); x("UPDATE notification_history SET status='FAILED',attempts=1,error=?,body_html=NULL,body_text=NULL WHERE id=?", (msg, row["id"])); audit(f"Test email to {to} failed: {e.kind}")
            return jsonify(ok=False, message=f"Email failed: {msg}"), 200

    @bp.route("/test", methods=["POST"])
    @need("admin")
    def test():
        to = sarg(body().get("recipient"), 254).lower()
        if not to:
            r = q("SELECT email FROM notification_recipients WHERE enabled=1 ORDER BY id LIMIT 1", one=True); to = r["email"] if r else ""
        if not config.EMAIL_RX.match(to): return jsonify(ok=False, message="Enter a valid recipient (or add a recipient first)"), 400
        return do_test(to)

    @bp.route("/recipients/<int:i>/test", methods=["POST"])
    @need("admin")
    def test_rec(i):
        r = q("SELECT email FROM notification_recipients WHERE id=?", (i,), one=True)
        return do_test(r["email"]) if r else (jsonify(error="not found"), 404)

    @bp.route("/history")
    @need("analyst")
    def history():
        a = request.args; w, p = ["1=1"], []
        if a.get("status") in ("SENT", "FAILED", "RETRYING", "QUEUED"): w.append("status=?"); p.append(a["status"])
        if a.get("recipient"): w.append("recipient=?"); p.append(a["recipient"].lower())
        if a.get("incident_id", "").isdigit(): w.append("incident_id=?"); p.append(int(a["incident_id"]))
        lim = iarg(a.get("limit"), 200, 1, 1000)
        rows = q(f"SELECT id,notification_id,incident_id,incident_code,alert_id,ntype,recipient,subject,severity,ts,sent_at,status,attempts,error,occurrences FROM notification_history WHERE {' AND '.join(w)} ORDER BY id DESC LIMIT {lim}", p)
        return jsonify(rows=rows, status=status())

    @bp.route("/history/<int:i>/retry", methods=["POST"])
    @need("admin")
    def retry(i):
        r = q("SELECT * FROM notification_history WHERE id=?", (i,), one=True)
        if not r or r["status"] != "FAILED" or not r["body_html"]: return jsonify(error="only a failed notification that still has its content can be retried"), 400
        x("UPDATE notification_history SET status='QUEUED',attempts=0,next_try=0,error=NULL WHERE id=?", (i,)); audit(f"Retry of notification #{i}"); N._WAKE.set(); return jsonify(ok=True)

    app.register_blueprint(bp)
