"""Minimal in-process mock of Google's OAuth token endpoint and Gmail users.messages.send (localhost only, no real mail).
Modes: ok, invalid_grant, invalid_client, send_401_once, rate_limit, server_error, insufficient_scope, api_disabled, bad_request."""
import json, threading, base64
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs

class _H(BaseHTTPRequestHandler):
    def log_message(self, *a): pass
    def out(self, code, obj): b = json.dumps(obj).encode(); self.send_response(code); self.send_header("Content-Type", "application/json"); self.send_header("Content-Length", str(len(b))); self.end_headers(); self.wfile.write(b)
    def err(self, code, reason, msg, status=""): self.out(code, {"error": {"code": code, "message": msg, "status": status, "errors": [{"reason": reason, "message": msg}]}})
    def do_POST(self):
        S = self.server; raw = self.rfile.read(int(self.headers.get("Content-Length") or 0))
        if self.path == "/token":
            f = {k: v[0] for k, v in parse_qs(raw.decode()).items()}; S.token_requests.append(f)
            if S.mode == "invalid_grant": return self.out(400, {"error": "invalid_grant", "error_description": "Token has been expired or revoked."})
            if S.mode == "invalid_client": return self.out(401, {"error": "invalid_client", "error_description": "The OAuth client was not found."})
            S.n_tokens += 1; return self.out(200, {"access_token": f"ya29.mock-{S.n_tokens}", "expires_in": 3599, "token_type": "Bearer"})
        if self.path == "/send":
            auth = self.headers.get("Authorization", ""); S.send_requests.append(dict(auth=auth, body=json.loads(raw or b"{}")))
            if S.mode == "send_401_once" and S.n_tokens < 2: return self.err(401, "authError", "Invalid Credentials", "UNAUTHENTICATED")
            if S.mode == "rate_limit": return self.err(403, "rateLimitExceeded", "Rate Limit Exceeded")
            if S.mode == "server_error": return self.err(500, "backendError", "Backend Error")
            if S.mode == "insufficient_scope": return self.err(403, "insufficientPermissions", "Request had insufficient authentication scopes.")
            if S.mode == "api_disabled": return self.err(403, "accessNotConfigured", "Gmail API has not been used in project")
            if S.mode == "bad_request": return self.err(400, "invalidArgument", "Invalid To header")
            data = base64.urlsafe_b64decode(S.send_requests[-1]["body"]["raw"] + "==").decode(errors="replace"); S.messages.append(dict(auth=auth, data=data))
            return self.out(200, {"id": "mock1", "threadId": "mock1", "labelIds": ["SENT"]})
        self.out(404, {})

class MockGmail:
    def __init__(self, mode="ok"):
        self.srv = ThreadingHTTPServer(("127.0.0.1", 0), _H); self.srv.mode = mode; self.srv.messages = []; self.srv.token_requests = []; self.srv.send_requests = []; self.srv.n_tokens = 0
        self.port = self.srv.server_address[1]; self.token_url = f"http://127.0.0.1:{self.port}/token"; self.send_url = f"http://127.0.0.1:{self.port}/send"
        threading.Thread(target=self.srv.serve_forever, daemon=True).start()
    mode = property(lambda s: s.srv.mode, lambda s, v: setattr(s.srv, "mode", v))
    messages = property(lambda s: s.srv.messages); token_requests = property(lambda s: s.srv.token_requests); send_requests = property(lambda s: s.srv.send_requests)
    def stop(self): self.srv.shutdown(); self.srv.server_close()
