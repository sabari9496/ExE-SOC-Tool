#!/usr/bin/env python3
"""One-time helper: authorise EXE-SOC to send e-mail through the Gmail API and print (or save) the refresh token.

Before running it, in Google Cloud console:  create a project -> enable "Gmail API" -> OAuth consent screen -> create an
OAuth client of type "Desktop app" (download its JSON, or copy the client ID and secret).
Add the sending Gmail address as a Test user while the app is in Testing mode (or publish the app so the token does not expire after 7 days).

Usage:
  python tools/gmail_auth.py --credentials client_secret_xxx.json            # prints GMAIL_* lines
  python tools/gmail_auth.py --credentials client_secret_xxx.json --write    # also saves them into ./.env (chmod 600)
  python tools/gmail_auth.py --client-id ID --client-secret SECRET --no-browser
  python tools/gmail_auth.py --check                                         # verify the saved credentials still work
Only the gmail.send scope is requested: EXE-SOC can send mail but cannot read your mailbox."""
import os, sys, json, base64, hashlib, secrets, argparse, getpass, threading, webbrowser, urllib.parse
from http.server import BaseHTTPRequestHandler, HTTPServer
ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__))); sys.path.insert(0, ROOT)
import requests
AUTH_URL = "https://accounts.google.com/o/oauth2/v2/auth"
TOKEN_URL = "https://oauth2.googleapis.com/token"
SCOPE = "https://www.googleapis.com/auth/gmail.send"

def pkce():
    v = base64.urlsafe_b64encode(secrets.token_bytes(48)).decode().rstrip("=")
    return v, base64.urlsafe_b64encode(hashlib.sha256(v.encode()).digest()).decode().rstrip("=")

def auth_url(client_id, redirect, state, challenge, login_hint=None):
    q = {"client_id": client_id, "redirect_uri": redirect, "response_type": "code", "scope": SCOPE, "access_type": "offline", "prompt": "consent",
         "state": state, "code_challenge": challenge, "code_challenge_method": "S256"}
    if login_hint: q["login_hint"] = login_hint
    return AUTH_URL + "?" + urllib.parse.urlencode(q)

def exchange(client_id, client_secret, code, redirect, verifier, token_url=None):
    r = requests.post(token_url or TOKEN_URL, data={"client_id": client_id, "client_secret": client_secret, "code": code, "redirect_uri": redirect,
                      "grant_type": "authorization_code", "code_verifier": verifier}, timeout=20)
    j = r.json() if r.content else {}
    if r.status_code != 200 or not j.get("refresh_token"):
        why = j.get("error_description") or j.get("error") or f"HTTP {r.status_code}"
        if r.status_code == 200: why = "Google returned no refresh token. Remove EXE-SOC at https://myaccount.google.com/permissions and run this again."
        raise SystemExit("Authorisation failed: " + str(why))
    return j["refresh_token"]

def upsert_env(path, values):
    """Set KEY=VALUE lines in a .env file, replacing existing ones, keeping everything else."""
    lines = []
    if os.path.exists(path):
        with open(path, encoding="utf-8") as fh: lines = fh.read().splitlines()
    done = set(); out = []
    for ln in lines:
        k = ln.split("=", 1)[0].strip().replace("export ", "", 1) if "=" in ln and not ln.lstrip().startswith("#") else None
        if k in values: out.append(f"{k}={values[k]}"); done.add(k)
        else: out.append(ln)
    out += [f"{k}={v}" for k, v in values.items() if k not in done]
    with open(path, "w", encoding="utf-8") as fh: fh.write("\n".join(out) + "\n")
    try: os.chmod(path, 0o600)
    except OSError: pass

def wait_for_code(port, state, timeout=300):
    box = {}
    class H(BaseHTTPRequestHandler):
        def log_message(self, *a): pass
        def do_GET(self):
            q = urllib.parse.parse_qs(urllib.parse.urlparse(self.path).query)
            if "code" in q and q.get("state", [""])[0] == state: box["code"] = q["code"][0]; msg = "EXE-SOC is authorised. You can close this tab."
            else: box["error"] = q.get("error", ["invalid response"])[0]; msg = "Authorisation was not completed. Return to the terminal."
            self.send_response(200); self.send_header("Content-Type", "text/plain; charset=utf-8"); self.end_headers(); self.wfile.write(msg.encode())
    srv = HTTPServer(("127.0.0.1", port), H); srv.timeout = 1; end = __import__("time").time() + timeout
    while not box and __import__("time").time() < end: srv.handle_request()
    srv.server_close(); return box

def main():
    ap = argparse.ArgumentParser(description="Authorise EXE-SOC to send e-mail via the Gmail API")
    ap.add_argument("--credentials", help="OAuth client JSON downloaded from Google Cloud (Desktop app)")
    ap.add_argument("--client-id"); ap.add_argument("--client-secret"); ap.add_argument("--login-hint", help="the Gmail address you will sign in with")
    ap.add_argument("--no-browser", action="store_true", help="print the URL instead of opening a browser"); ap.add_argument("--port", type=int, default=0)
    ap.add_argument("--write", action="store_true", help="save the values into .env next to app.py"); ap.add_argument("--env-file", default=os.path.join(ROOT, ".env"))
    ap.add_argument("--print-secrets", action="store_true", help="DISCOURAGED: print the refresh token to the terminal (it ends up in scrollback/logs). Default is --write to a 0600 file.")
    ap.add_argument("--check", action="store_true", help="only verify that the saved credentials can obtain an access token")
    a = ap.parse_args()
    if not (a.write or a.print_secrets or a.check):
        raise SystemExit("Refusing to continue: the refresh token would be printed to the terminal. Use --write (saves to a 0600 .env file, recommended) or pass --print-secrets explicitly.")
    if a.check:
        import envload; envload.load(a.env_file)
        from notify import config, gmailapi
        cfg = config.smtp_config(); bad = [p for p in config.validate_smtp({**cfg, "method": "gmail_api"}) if "GMAIL" in p]
        if bad: raise SystemExit("Missing: " + "; ".join(bad))
        gmailapi.access_token(cfg); print("OK: Google accepted the refresh token."); return
    cid, csec = a.client_id, a.client_secret
    if a.credentials:
        j = json.load(open(a.credentials, encoding="utf-8")); j = j.get("installed") or j.get("web") or j; cid, csec = j["client_id"], j["client_secret"]
    cid = cid or input("OAuth client ID: ").strip(); csec = csec or getpass.getpass("OAuth client secret: ").strip()
    verifier, challenge = pkce(); state = secrets.token_urlsafe(16)
    probe = HTTPServer(("127.0.0.1", a.port), BaseHTTPRequestHandler); port = probe.server_address[1]; probe.server_close()
    redirect = f"http://127.0.0.1:{port}"; url = auth_url(cid, redirect, state, challenge, a.login_hint)
    print("\nOpen this address, sign in with the Gmail account that will SEND the alerts and approve 'Send email on your behalf':\n\n" + url + "\n")
    if not a.no_browser: webbrowser.open(url)
    print("Waiting for Google to redirect back (5 minutes)...")
    box = wait_for_code(port, state)
    if "code" not in box: raise SystemExit("Not authorised: " + box.get("error", "timed out"))
    vals = {"EMAIL_METHOD": "gmail_api", "GMAIL_CLIENT_ID": cid, "GMAIL_CLIENT_SECRET": csec, "GMAIL_REFRESH_TOKEN": exchange(cid, csec, box["code"], redirect, verifier)}
    if a.write:
        upsert_env(a.env_file, vals); print(f"\nSaved to {a.env_file}. Also set EMAIL_FROM to the Gmail address you just authorised, SMTP_ENABLED=true, then restart EXE-SOC.")
    else:
        print("\nAdd these to the server environment or to .env (keep them secret, never commit them):\n"); [print(f"{k}={v}") for k, v in vals.items()]
        print("\nAlso set EMAIL_FROM=<the Gmail address you authorised> and SMTP_ENABLED=true, then restart EXE-SOC.")

if __name__ == "__main__": main()
