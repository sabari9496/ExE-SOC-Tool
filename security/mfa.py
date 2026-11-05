"""TOTP MFA web layer: enrollment, login challenge, recovery codes, required-MFA enforcement, recent re-authentication."""
import time, json, os, secrets
from markupsafe import escape
from . import throttle
from flask import request, session, jsonify, redirect, render_template_string
from werkzeug.security import check_password_hash
from db import q, x, now
from . import totp
PAGE = """<!doctype html><meta charset=utf-8><title>EXE-SOC MFA</title><body style="font-family:sans-serif;max-width:560px;margin:40px auto">
<h2>{{ title }}</h2>{% if msg %}<p style="color:#b00"><b>{{ msg }}</b></p>{% endif %}{{ body|safe }}</body>"""
def required_roles():
    raw = os.environ.get("SOC_MFA_REQUIRED", "admin,analyst" if os.environ.get("SOC_ENV") == "production" else "")
    roles = {r.strip().lower() for r in raw.split(",") if r.strip()}
    allowed = {"admin", "analyst", "viewer"}
    if roles - allowed:
        if os.environ.get("SOC_ENV") == "production": raise RuntimeError("SOC_MFA_REQUIRED contains unknown role(s); refusing unsafe MFA configuration")
        roles &= allowed
    if os.environ.get("SOC_ENV") == "production" and not roles:
        raise RuntimeError("SOC_MFA_REQUIRED must include at least one valid role in production")
    return roles
def ensure(): x("CREATE TABLE IF NOT EXISTS user_mfa(username TEXT PRIMARY KEY, secret_enc TEXT NOT NULL, enabled INTEGER DEFAULT 0, last_counter INTEGER DEFAULT 0, recovery TEXT DEFAULT '[]', created TEXT)")
def row(u): return q("SELECT * FROM user_mfa WHERE username=?", (u,), one=True)
def enabled(u): r = row(u); return bool(r and r["enabled"])
def _check_code(user, code):
    """TOTP (replay-proof) or one-time recovery code. Returns 'totp' | 'recovery' | None. Rate limited per user."""
    r = row(user)
    if not r or not r["enabled"] or totp.throttled(user): return None
    secret = totp.dec_secret(r["secret_enc"], user); c = totp.verify(secret, code, r["last_counter"] or 0)
    if c is not None:
        from db import xc
        if xc("UPDATE user_mfa SET last_counter=? WHERE username=? AND last_counter<?", (c, user, c)) != 1: totp.note_fail(user); return None      # atomic compare-and-set: a counter is accepted once, even under concurrent requests
        totp.clear_fails(user); return "totp"
    hashes = {totp.hash_code(code or ""), totp.hash_code_legacy(code or "")}
    # Consume a recovery code atomically. The previous read/modify/write sequence let two concurrent requests reuse the same code.
    from db import conn
    c = conn()
    try:
        c.execute("BEGIN IMMEDIATE")
        fresh = c.execute("SELECT recovery FROM user_mfa WHERE username=? AND enabled=1", (user,)).fetchone()
        rec = json.loads((fresh[0] if fresh else "[]") or "[]")
        matched = next((item for item in rec if item in hashes), None)
        if matched:
            rec.remove(matched)
            c.execute("UPDATE user_mfa SET recovery=? WHERE username=?", (json.dumps(rec), user)); c.commit()
            totp.clear_fails(user); return "recovery"
        c.rollback()
    finally: c.close()
    totp.note_fail(user); return None
def gate(u):
    """After a correct password: 'challenge' (MFA enrolled), 'enroll' (required but not enrolled) or 'ok'."""
    if enabled(u["username"]): return "challenge"
    return "enroll" if u["role"] in required_roles() else "ok"
def reauth_ok(max_age=300): return time.time() - session.get("reauth_at", 0) <= max_age
def register(app, need, audit, start_session, revoke_sessions, generate_hash):
    ensure()
    def page(title, body, msg=None, code=200): return render_template_string(PAGE, title=title, body=body, msg=msg), code
    def _form(action, fields, btn):
        return f'<form method="post" action="{action}"><input type="hidden" name="csrf" value="{session.get("csrf","")}">' + "".join(f'<p>{l}<br><input name="{n}" {t} autocomplete="off" style="width:100%"></p>' for l, n, t in fields) + f'<button>{btn}</button></form>'
    @app.route("/login/mfa", methods=["GET", "POST"])
    def login_mfa():
        u = session.get("mfa_pending")
        if not u: return redirect("/login")                      # nothing pending: do NOT touch an existing authenticated session (no logout-CSRF)
        if time.time() - session.get("mfa_t", 0) > 300: session.clear(); return redirect("/login")
        if request.method == "POST":
            if not session.get("csrf") or not secrets.compare_digest(request.form.get("csrf", ""), session["csrf"]): audit("MFA form rejected (CSRF token)", user=u); return page("Two-factor code", "<p>Request rejected. <a href=/login>Start again</a>.</p>", code=400)
            if totp.throttled(u): audit("MFA throttled", user=u); return page("Two-factor code", "<p>Too many attempts. Wait 5 minutes.</p>", code=429)
            kind = _check_code(u, request.form.get("code", ""))
            if kind:
                user = q("SELECT * FROM users WHERE username=? AND active=1", (u,), one=True)
                if not user: session.clear(); return redirect("/login")
                start_session(user); session["reauth_at"] = time.time(); x("UPDATE users SET last_login=? WHERE id=?", (now(), user["id"]))
                audit("Logged in (MFA)" if kind == "totp" else "Logged in (MFA recovery code used)", user=u); return redirect("/", code=303)
            audit("MFA failed", user=u); return page("Two-factor code", _form("/login/mfa", [("Authenticator code or recovery code", "code", "")], "Verify"), "Invalid code.", 401)
        return page("Two-factor code", _form("/login/mfa", [("Authenticator code or recovery code", "code", "")], "Verify"))
    @app.route("/mfa-setup", methods=["GET", "POST"])
    @need()
    def mfa_setup():
        u = session["user"]
        if request.method == "POST":
            if not session.get("csrf") or request.form.get("csrf") != session["csrf"]: return page("MFA", "", "CSRF check failed", 400)
            if request.form.get("code") is not None and row(u) and not enabled(u):
                r = row(u); c = totp.verify(totp.dec_secret(r["secret_enc"], u), request.form["code"], 0)
                if c is None: return page("Enable MFA", "<p>Wrong code.</p>", "Invalid code", 401)
                codes = totp.new_recovery_codes(); x("UPDATE user_mfa SET enabled=1,last_counter=?,recovery=?,created=? WHERE username=?", (c, json.dumps([totp.hash_code(k) for k in codes]), now(), u))
                session.pop("mfa_setup", None); session["reauth_at"] = time.time(); audit("MFA enabled")
                return page("MFA enabled", "<p>Save these one-time recovery codes now; they are shown only once:</p><pre>" + "\n".join(codes) + "</pre><p><a href=/>Continue</a></p>")
        if not enabled(u):
            r = row(u); s = totp.new_secret() if not r else totp.dec_secret(r["secret_enc"], u)
            if not r: x("INSERT INTO user_mfa(username,secret_enc,enabled,created) VALUES(?,?,0,?)", (u, totp.enc_secret(s, u), now()))
            return page("Enable two-factor authentication", f"<p>Add this key to your authenticator app (manual entry, TOTP, 6 digits, 30 s):</p><pre>{escape(s)}</pre><p><small>{escape(totp.uri(s, u))}</small></p>" + _form("/mfa-setup", [("Current code", "code", "")], "Confirm"))
        return page("MFA", "<p>MFA is enabled for your account.</p>")
    @app.route("/api/me/mfa")
    @need()
    def mfa_status(): return jsonify(enabled=enabled(session["user"]), required=session["role"] in required_roles(), recovery_codes_left=len(json.loads((row(session["user"]) or {"recovery": "[]"})["recovery"] or "[]")))
    @app.route("/api/me/reauth", methods=["POST"])
    @need()
    def reauth():
        d = request.get_json(silent=True) or {}; u = session["user"]; row_u = q("SELECT password_hash FROM users WHERE username=?", (u,), one=True)
        if throttle.blocked("reauth", u, 5, 300): audit("Reauthentication throttled"); return jsonify(error="too many attempts; wait 5 minutes"), 429      # a hijacked session must not be able to brute-force the password here
        if not isinstance(d.get("password"), str) or not check_password_hash(row_u["password_hash"], d["password"]): throttle.hit("reauth", u); audit("Reauthentication failed"); return jsonify(error="reauthentication failed"), 401
        if enabled(u) and not _check_code(u, d.get("code") if isinstance(d.get("code"), str) else ""): audit("Reauthentication failed (MFA)"); return jsonify(error="reauthentication failed"), 401
        session["reauth_at"] = time.time(); audit("Reauthenticated"); return jsonify(ok=True, valid_seconds=300)
    @app.route("/api/users/<int:i>/mfa/reset", methods=["POST"])
    @need("admin")
    def mfa_reset(i):
        """Audited recovery: an admin (freshly re-authenticated) removes a locked-out user's MFA; the user must re-enroll; their sessions end. Admins cannot reset their own MFA here."""
        t = q("SELECT username FROM users WHERE id=?", (i,), one=True)
        if not t: return jsonify(error="not found"), 404
        if t["username"] == session["user"]: return jsonify(error="use another admin to reset your own MFA"), 403
        if not reauth_ok(): return jsonify(error="recent reauthentication required (POST /api/me/reauth)"), 403
        x("DELETE FROM user_mfa WHERE username=?", (t["username"],)); revoke_sessions(t["username"]); audit(f"MFA reset for {t['username']} by admin"); return jsonify(ok=True)
