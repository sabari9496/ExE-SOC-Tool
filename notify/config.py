"""Settings. Non-secret values live in the database (editable on the dashboard); an environment variable of the same purpose always wins and is shown as locked.
The SMTP password is read ONLY from the environment (SMTP_PASSWORD) or from a file named by SMTP_PASSWORD_FILE (for Docker/Kubernetes secrets). It is never stored, returned or logged."""
import os, re
from db import q, x

SEVERITIES = ["Critical", "High", "Medium", "Low", "Info"]
TYPES = {"new_incident": "New critical/high incident", "high_alert": "High / critical alert", "ioc": "IOC detection", "agent_offline": "Agent offline", "large_outbound": "Large outbound transfer",
         "network_attack": "Network attack", "auth_attack": "Authentication attack"}
DEFAULTS = {"enabled": "0", "email_method": "smtp", "smtp_host": "", "smtp_port": "587", "smtp_security": "starttls", "smtp_username": "", "email_from": "", "base_url": "",
            "sev_critical": "1", "sev_high": "1", "sev_medium": "0", "sev_low": "0", "sev_info": "0",
            "rate_limit_min": "15", "max_per_hour": "60", "max_per_recipient_hour": "30", "max_attempts": "4", "retry_delays": "30,120,300", "send_updates": "1",
            "escalation_enabled": "0", "escalation_min": "15", "escalation_min_severity": "Critical", "floor_agent_offline": "High", "floor_network_attack": "High"}
DEFAULTS.update({f"type_{t}": "1" for t in TYPES})
ENV = {"enabled": "SMTP_ENABLED", "email_method": "EMAIL_METHOD", "smtp_host": "SMTP_HOST", "smtp_port": "SMTP_PORT", "smtp_security": "SMTP_SECURITY", "smtp_username": "SMTP_USERNAME", "email_from": "EMAIL_FROM", "base_url": "SOC_BASE_URL"}
EMAIL_RX = re.compile(r"^[A-Za-z0-9._%+'-]{1,64}@[A-Za-z0-9-]+(\.[A-Za-z0-9-]+)+$")
HOST_RX = re.compile(r"^[A-Za-z0-9]([A-Za-z0-9.-]{0,251}[A-Za-z0-9])?$")
TRUE = ("1", "true", "yes", "on")
METHODS = ("smtp", "gmail_api")

def _stored():
    return {r["key"]: r["value"] for r in q("SELECT key,value FROM notification_settings")}

def get(key):
    e = ENV.get(key)
    if e and os.environ.get(e) not in (None, ""): return os.environ[e]
    return _stored().get(key, DEFAULTS.get(key, ""))

def on(key): return str(get(key)).strip().lower() in TRUE
def num(key, default):
    try: return int(float(get(key)))
    except (TypeError, ValueError): return default

def password():
    p = os.environ.get("SMTP_PASSWORD")
    if p: return p
    f = os.environ.get("SMTP_PASSWORD_FILE")
    if f:
        try: return open(f, encoding="utf-8").read().strip()
        except OSError: return ""
    return ""

def _secret(name):
    """Secret from NAME or from the file named by NAME_FILE (Docker/Kubernetes secrets). Never stored, returned or logged."""
    v = os.environ.get(name)
    if v: return v.strip()
    f = os.environ.get(name + "_FILE")
    if f:
        try:
            with open(f, encoding="utf-8") as fh: return fh.read().strip()
        except OSError: return ""
    return ""

def gmail_creds():
    return {"client_id": _secret("GMAIL_CLIENT_ID"), "client_secret": _secret("GMAIL_CLIENT_SECRET"), "refresh_token": _secret("GMAIL_REFRESH_TOKEN")}

def gmail_status():
    """Present/absent only, never the values."""
    return {k: bool(v) for k, v in gmail_creds().items()}

def method(): return (get("email_method") or "smtp").strip().lower()

def all_settings():
    st = _stored(); out = {}
    for k, d in DEFAULTS.items():
        env = ENV.get(k); locked = bool(env and os.environ.get(env) not in (None, ""))
        out[k] = {"value": get(k), "source": "environment" if locked else "dashboard", "locked": locked}
    return out

def smtp_config():
    return {"host": get("smtp_host").strip(), "port": num("smtp_port", 587), "security": get("smtp_security").strip().lower() or "starttls", "username": get("smtp_username").strip(),
            "password": password(), "from": get("email_from").strip(), "method": method(), "gmail": gmail_creds(), "allow_insecure": os.environ.get("SMTP_ALLOW_INSECURE") == "1"}

def validate_smtp(cfg=None):
    """-> list of problems (empty = valid). The password is only reported as present/absent."""
    c = cfg or smtp_config(); bad = []
    m = c.get("method", "smtp")
    if m not in METHODS: return ["Email method must be smtp or gmail_api"]
    if m == "gmail_api":
        g = c.get("gmail") or {}
        for k, envname in (("client_id", "GMAIL_CLIENT_ID"), ("client_secret", "GMAIL_CLIENT_SECRET"), ("refresh_token", "GMAIL_REFRESH_TOKEN")):
            if not g.get(k): bad.append(f"{envname} is not set in the server environment (run tools/gmail_auth.py)")
        if not EMAIL_RX.match(c["from"] or ""): bad.append("Sender email (EMAIL_FROM) must be the Gmail address you authorised (or one of its aliases)")
        return bad
    if not c["host"] or not HOST_RX.match(c["host"]): bad.append("SMTP host is missing or invalid")
    if not (1 <= int(c["port"] or 0) <= 65535): bad.append("SMTP port must be between 1 and 65535")
    if c["security"] not in ("starttls", "ssl", "none"): bad.append("SMTP security must be starttls, ssl or none")
    if c["security"] == "none" and c["host"] not in ("localhost", "127.0.0.1", "::1") and not c["allow_insecure"]: bad.append("Unencrypted SMTP is only allowed for localhost (or set SMTP_ALLOW_INSECURE=1)")
    if not EMAIL_RX.match(c["from"] or ""): bad.append("Sender email (EMAIL_FROM) is missing or invalid")
    if c["username"] and not c["password"]: bad.append("SMTP username is set but SMTP_PASSWORD is not set in the environment")
    return bad

def set_values(values):
    """Validate and save dashboard-editable settings. Returns (ok, error)."""
    clean = {}
    for k, v in values.items():
        if k in ("smtp_password", "password", "SMTP_PASSWORD"): return False, "The SMTP password cannot be set here. Set the SMTP_PASSWORD environment variable (or SMTP_PASSWORD_FILE) on the server."
        if k not in DEFAULTS: return False, f"unknown setting {k}"
        v = str(v).strip() if not isinstance(v, bool) else ("1" if v else "0")
        if "\r" in v or "\n" in v or len(v) > 300: return False, f"invalid value for {k}"
        if k in ("enabled", "send_updates", "escalation_enabled") or k.startswith(("sev_", "type_")): v = "1" if v.lower() in TRUE else "0"
        elif k == "smtp_port" and not (v.isdigit() and 1 <= int(v) <= 65535): return False, "SMTP port must be 1-65535"
        elif k == "email_method" and v.lower() not in METHODS: return False, "Email method must be smtp or gmail_api"
        elif k == "smtp_security" and v.lower() not in ("starttls", "ssl", "none"): return False, "SMTP security must be starttls, ssl or none"
        elif k == "smtp_host" and v and not HOST_RX.match(v): return False, "invalid SMTP host"
        elif k in ("email_from",) and v and not EMAIL_RX.match(v): return False, "invalid sender email"
        elif k == "base_url" and v and not re.match(r"^https?://[^\s/]+[^\s]*$", v): return False, "base URL must start with http:// or https://"
        elif k in ("rate_limit_min", "max_per_hour", "max_per_recipient_hour", "max_attempts", "escalation_min") and not (v.isdigit() and 0 <= int(v) <= 100000): return False, f"{k} must be a number"
        elif k == "retry_delays" and not re.match(r"^\d{1,5}(,\d{1,5}){0,8}$", v): return False, "retry delays must be seconds separated by commas, for example 30,120,300"
        elif k in ("escalation_min_severity", "floor_agent_offline", "floor_network_attack") and v not in ("Critical", "High", "Medium", "Low"): return False, f"{k} must be Critical, High, Medium or Low"
        clean[k] = v.lower() if k in ("smtp_security", "email_method") else v
    for k, v in clean.items(): x("INSERT OR REPLACE INTO notification_settings VALUES(?,?)", (k, v))
    return True, ""
