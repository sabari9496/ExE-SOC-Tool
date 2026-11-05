"""SMTP delivery (STARTTLS, SSL/TLS, or none for localhost relays). Errors are mapped to short messages that never contain the password."""
import smtplib, ssl, socket
from email.message import EmailMessage
from email.utils import formatdate, make_msgid
from . import config

class NotifyError(Exception):
    def __init__(self, kind, message, permanent=False): super().__init__(message); self.kind, self.message, self.permanent = kind, message, permanent

def safe(text, cfg=None):
    t = str(text).replace("\r", " ").replace("\n", " ")
    g = (cfg or {}).get("gmail") or config.gmail_creds()
    for sec in ((cfg or {}).get("password") or config.password(), g.get("client_secret"), g.get("refresh_token")):
        if sec and len(sec) >= 3: t = t.replace(sec, "********")
    return t[:300]

def build(cfg, to, subject, html, text):
    for v in (to, subject, cfg["from"]):
        if "\r" in v or "\n" in v: raise NotifyError("invalid", "Header injection attempt blocked", True)
    m = EmailMessage(); m["From"] = cfg["from"]; m["To"] = to; m["Subject"] = subject; m["Date"] = formatdate(localtime=True); m["Message-ID"] = make_msgid(domain=cfg["from"].split("@")[-1])
    m["X-EXE-SOC"] = "notification"; m["Auto-Submitted"] = "auto-generated"
    m.set_content(text or "EXE-SOC notification"); m.add_alternative(html, subtype="html"); return m

def send(cfg, to, subject, html, text, timeout=15):
    bad = config.validate_smtp(cfg)
    if bad: raise NotifyError("config", "; ".join(bad), True)
    if cfg.get("method") == "gmail_api":
        from . import gmailapi; return gmailapi.send(cfg, to, subject, html, text, timeout)
    msg = build(cfg, to, subject, html, text); s = None
    try:
        ctx = ssl.create_default_context()
        if cfg["security"] == "ssl": s = smtplib.SMTP_SSL(cfg["host"], cfg["port"], timeout=timeout, context=ctx)
        else:
            s = smtplib.SMTP(cfg["host"], cfg["port"], timeout=timeout); s.ehlo()
            if cfg["security"] == "starttls": s.starttls(context=ctx); s.ehlo()
        if cfg["username"]:
            if cfg["security"] == "none" and not cfg["allow_insecure"] and cfg["host"] not in ("localhost", "127.0.0.1", "::1"): raise NotifyError("config", "Refusing to send the SMTP password over an unencrypted connection", True)
            s.login(cfg["username"], cfg["password"])
        s.send_message(msg)
    except NotifyError: raise
    except smtplib.SMTPAuthenticationError as e: raise NotifyError("auth", f"SMTP authentication failed ({e.smtp_code}). Check the username and password (many providers need an app password).", True)
    except smtplib.SMTPNotSupportedError as e: raise NotifyError("config", safe(f"The server does not support what was requested ({e}). Check the SMTP security setting (starttls / ssl).", cfg), True)
    except smtplib.SMTPSenderRefused as e: raise NotifyError("refused", f"The server refused the sender address ({e.smtp_code})", permanent=e.smtp_code >= 500)
    except smtplib.SMTPRecipientsRefused as e:
        codes = [c for c, _ in e.recipients.values()]; raise NotifyError("refused", f"The server refused the recipient address ({codes[0] if codes else '?'})", permanent=not codes or min(codes) >= 500)
    except smtplib.SMTPResponseException as e:
        raise NotifyError("smtp", safe(f"SMTP server replied {e.smtp_code}", cfg), permanent=500 <= e.smtp_code < 600)
    except smtplib.SMTPException as e: raise NotifyError("smtp", safe(f"SMTP error: {e}", cfg), False)
    except ssl.SSLError as e: raise NotifyError("tls", safe(f"TLS error: {e}. Check the SMTP port and security setting.", cfg), False)
    except (socket.timeout, TimeoutError): raise NotifyError("timeout", f"Connection to {cfg['host']}:{cfg['port']} timed out", False)
    except (ConnectionError, OSError, socket.gaierror) as e: raise NotifyError("connect", safe(f"Cannot connect to {cfg['host']}:{cfg['port']} ({e.__class__.__name__})", cfg), False)
    finally:
        try:
            if s: s.quit()
        except Exception: pass
