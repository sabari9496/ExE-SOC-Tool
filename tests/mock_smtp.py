"""Minimal in-process SMTP server for tests (plain text, localhost only). Modes: ok, auth_fail, drop, temp_fail, reject_rcpt."""
import socketserver, threading, base64

class _H(socketserver.StreamRequestHandler):
    def w(self, s): self.wfile.write((s + "\r\n").encode()); self.wfile.flush()
    def handle(self):
        S = self.server; S.connections += 1
        if S.mode == "drop": return
        self.w("220 mock ESMTP"); frm, rcpt, user, pw = "", [], None, None
        while True:
            line = self.rfile.readline()
            if not line: return
            c = line.decode(errors="replace").strip(); u = c.upper()
            if u.startswith(("EHLO", "HELO")): self.w("250-mock\r\n250-AUTH PLAIN LOGIN\r\n250 8BITMIME")
            elif u.startswith("AUTH"):
                if S.mode == "auth_fail": self.w("535 5.7.8 Authentication credentials invalid"); continue
                parts = c.split()
                if parts[1].upper() == "PLAIN":
                    tok = parts[2] if len(parts) > 2 else (self.w("334 ") or self.rfile.readline().decode().strip())
                    _, user, pw = base64.b64decode(tok).decode().split("\x00")
                else:
                    self.w("334 VXNlcm5hbWU6"); user = base64.b64decode(self.rfile.readline().strip()).decode(); self.w("334 UGFzc3dvcmQ6"); pw = base64.b64decode(self.rfile.readline().strip()).decode()
                if (S.user, S.password) != (None, None) and (user, pw) != (S.user, S.password): self.w("535 5.7.8 Authentication credentials invalid")
                else: self.w("235 2.7.0 Authentication successful")
            elif u.startswith("MAIL FROM"):
                if S.mode == "temp_fail": self.w("451 4.3.0 Temporary failure, try again later"); continue
                frm = c; self.w("250 OK")
            elif u.startswith("RCPT TO"):
                if S.mode == "reject_rcpt": self.w("550 5.1.1 No such user"); continue
                rcpt.append(c.split(":", 1)[1].strip(" <>")); self.w("250 OK")
            elif u == "DATA":
                self.w("354 End data with <CR><LF>.<CR><LF>"); buf = []
                while True:
                    l = self.rfile.readline()
                    if l in (b".\r\n", b""): break
                    buf.append(l.decode(errors="replace"))
                S.messages.append(dict(frm=frm, to=rcpt, data="".join(buf), user=user, password=pw)); rcpt = []; self.w("250 OK queued")
            elif u == "QUIT": self.w("221 Bye"); return
            else: self.w("250 OK")

class MockSMTP(socketserver.ThreadingTCPServer):
    allow_reuse_address = True; daemon_threads = True
    def __init__(self, mode="ok", user=None, password=None):
        super().__init__(("127.0.0.1", 0), _H); self.mode, self.user, self.password = mode, user, password; self.messages = []; self.connections = 0
        threading.Thread(target=self.serve_forever, daemon=True).start()
    @property
    def port(self): return self.server_address[1]
    def stop(self): self.shutdown(); self.server_close()
