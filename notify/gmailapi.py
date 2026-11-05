"""Gmail API delivery: OAuth2 refresh-token flow + users.messages.send over HTTPS (no SMTP port, no app password).
Credentials (GMAIL_CLIENT_ID / GMAIL_CLIENT_SECRET / GMAIL_REFRESH_TOKEN, or the *_FILE variants) come only from the server environment or .env.
They are never stored in the database, never returned by the API and are redacted from every error message. The access token lives in memory only.
Errors are mapped to the same NotifyError(kind, message, permanent) used for SMTP, so queueing, retry/backoff and the dashboard behave identically."""
import base64, hashlib, threading, time
import requests
from .smtpx import NotifyError, build, safe

TOKEN_URL = "https://oauth2.googleapis.com/token"
SEND_URL = "https://gmail.googleapis.com/gmail/v1/users/me/messages/send"
SCOPE = "https://www.googleapis.com/auth/gmail.send"
_CACHE = {}; _LOCK = threading.Lock()
RATE_REASONS = ("ratelimitexceeded", "userratelimitexceeded", "dailylimitexceeded", "quotaexceeded", "backenderror")

def _key(g): return hashlib.sha256((g["client_id"] + "|" + g["refresh_token"]).encode()).hexdigest()

def _detail(r):
    """-> (reason, message) from a Google JSON error body (token endpoint or API)."""
    try: j = r.json()
    except ValueError: return "", ""
    e = j.get("error") if isinstance(j, dict) else None
    if isinstance(e, dict):
        errs = e.get("errors") or [{}]
        return str(errs[0].get("reason") or e.get("status") or ""), str(e.get("message") or "")
    return str(e or ""), str((j or {}).get("error_description") or "") if isinstance(j, dict) else ""

def _post(cfg, url, timeout, what, **kw):
    try: return requests.post(url, timeout=timeout, **kw)
    except requests.Timeout: raise NotifyError("timeout", f"Connection to Google ({what}) timed out", False)
    except requests.exceptions.SSLError as e: raise NotifyError("tls", safe(f"TLS error talking to Google ({what}): {e.__class__.__name__}", cfg), False)
    except requests.RequestException as e: raise NotifyError("connect", safe(f"Cannot reach Google ({what}): {e.__class__.__name__}", cfg), False)

def access_token(cfg, timeout=15, force=False):
    g = cfg["gmail"]; k = _key(g)
    with _LOCK:
        c = _CACHE.get(k)
        if c and not force and c[1] > time.time() + 60: return c[0]
    r = _post(cfg, TOKEN_URL, timeout, "token endpoint", data={"client_id": g["client_id"], "client_secret": g["client_secret"], "refresh_token": g["refresh_token"], "grant_type": "refresh_token"})
    if r.status_code != 200:
        reason, desc = _detail(r)
        if r.status_code in (400, 401):
            hint = " Run tools/gmail_auth.py again (refresh tokens expire after 7 days while the Google OAuth app is in Testing mode, and when access is revoked)." if reason == "invalid_grant" else " Check GMAIL_CLIENT_ID and GMAIL_CLIENT_SECRET." if reason in ("invalid_client", "unauthorized_client") else ""
            raise NotifyError("auth", safe(f"Gmail authorisation failed ({reason or r.status_code}: {desc}).{hint}", cfg), True)
        raise NotifyError("gmail", f"Google token endpoint replied {r.status_code}", False)
    try: j = r.json(); tok = j["access_token"]; exp = time.time() + int(j.get("expires_in", 3600))
    except (ValueError, KeyError, TypeError): raise NotifyError("gmail", "Google returned an unexpected token response", False)
    with _LOCK: _CACHE[k] = (tok, exp)
    return tok

def forget_token(cfg):
    with _LOCK: _CACHE.pop(_key(cfg["gmail"]), None)

def send(cfg, to, subject, html, text, timeout=15):
    msg = build(cfg, to, subject, html, text); raw = base64.urlsafe_b64encode(msg.as_bytes()).decode()
    for attempt in (1, 2):
        tok = access_token(cfg, timeout, force=(attempt == 2))
        r = _post(cfg, SEND_URL, timeout, "Gmail API", json={"raw": raw}, headers={"Authorization": "Bearer " + tok})
        if r.status_code == 401 and attempt == 1: forget_token(cfg); continue        # expired/revoked access token: refresh once and retry
        break
    sc = r.status_code
    if sc == 200: return
    reason, message = _detail(r); info = safe(f"Gmail API replied {sc} ({reason}): {message}", cfg)
    if sc == 401: raise NotifyError("auth", safe("Gmail rejected the access token after a refresh. Run tools/gmail_auth.py again.", cfg), True)
    if sc == 403:
        if reason.lower() in RATE_REASONS: raise NotifyError("gmail", info, False)
        if reason in ("accessNotConfigured", "SERVICE_DISABLED"): raise NotifyError("config", safe("The Gmail API is not enabled for this Google Cloud project. Enable it in the Google Cloud console.", cfg), True)
        if "insufficient" in reason.lower() or reason == "ACCESS_TOKEN_SCOPE_INSUFFICIENT": raise NotifyError("auth", safe("The token lacks the gmail.send permission. Run tools/gmail_auth.py again and approve it.", cfg), True)
        raise NotifyError("gmail", info, True)
    if sc == 429 or sc >= 500: raise NotifyError("gmail", info, False)
    raise NotifyError("refused" if sc == 400 else "gmail", info, True)
