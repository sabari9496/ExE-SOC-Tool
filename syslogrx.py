"""Optional syslog receiver (UDP + TCP) so routers, firewalls, switches, appliances and cloud forwarders can send logs to the SOC.
Off by default. Enable: SOC_SYSLOG_PORT=5514 (use 514 only as root). SOC_SYSLOG_BIND defaults to 0.0.0.0. Only clear security lines feed the
detection rules; everything else is stored as a plain log."""
import os, re, sys, socket, threading, time, socketserver
sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "tools"))
_buf = []; _lk = threading.Lock(); dropped = [0]
MAX_BUF = int(os.environ.get("SOC_SYSLOG_MAX_QUEUE", 50000))      # a flood must not exhaust memory: beyond this, new lines are dropped and counted
MAX_LINE = 8192; IDLE_S = 60                                        # longest accepted line / idle TCP connection timeout

def _parse(line, addr):
    line = line.strip()
    m = re.match(r"^<(\d{1,3})>", line); pri = int(m.group(1)) if m else None
    if m: line = line[m.end():]
    line = re.sub(r"^1 ", "", line)                                            # RFC 5424 version
    host = None
    m = re.match(r"^(?:\d{4}-\d\d-\d\dT\S+|[A-Z][a-z]{2}\s+\d+ \d\d:\d\d:\d\d)\s+(\S+)\s", line)
    if m: host = m.group(1)
    return pri, host or addr, line

def _add(line, addr):
    import linuxlogs
    line = line[:MAX_LINE]
    if not line.strip(): return
    pri, host, msg = _parse(line, addr)
    it = linuxlogs._item(host, "syslog", msg, linuxlogs.parse_ts(msg), None, linuxlogs.PRIO.get(str(pri % 8), "") if pri is not None else "", "", {"from": addr})
    with _lk:
        if len(_buf) < MAX_BUF: _buf.append(it)
        else:
            dropped[0] += 1
            if dropped[0] in (1, 1000, 100000): print(f"syslog: queue full ({MAX_BUF}), dropping lines (dropped so far: {dropped[0]}). Raise SOC_SYSLOG_MAX_QUEUE or reduce the sender's rate.")

class _U(socketserver.BaseRequestHandler):
    def handle(self): _add(self.request[0].decode("utf-8", "replace"), self.client_address[0])
class _T(socketserver.StreamRequestHandler):
    def handle(self):
        self.request.settimeout(IDLE_S)
        try:
            while True:
                raw = self.rfile.readline(MAX_LINE + 1)                 # bounded read: a sender that never sends a newline cannot grow memory
                if not raw: break
                if len(raw) > MAX_LINE and not raw.endswith(b"\n"):
                    while True:                                          # discard the rest of an over-long line
                        rest = self.rfile.readline(MAX_LINE)
                        if not rest or rest.endswith(b"\n"): break
                _add(raw.decode("utf-8", "replace"), self.client_address[0])
        except (socket.timeout, OSError): pass

def _flush():
    import engine
    while True:
        time.sleep(0.5)
        with _lk: items = _buf[:]; del _buf[:]
        for i in range(0, len(items), 500):
            try: engine.process_batch(items[i:i + 500])
            except Exception as e: print("syslog store error:", e)

def start():
    port = int(os.environ.get("SOC_SYSLOG_PORT", "0") or 0)
    if not port: return
    bind = os.environ.get("SOC_SYSLOG_BIND", "127.0.0.1")
    import ipaddress
    try: _ip = ipaddress.ip_address(bind); _safe = _ip.is_loopback or (_ip.is_private and not _ip.is_unspecified)
    except ValueError: _safe = False
    if not _safe and os.environ.get("SOC_SYSLOG_ALLOW_ANY") != "1":
        print(f"syslog: REFUSING to listen on {bind}: syslog (UDP/TCP) is unauthenticated, so only loopback or a specific private address is allowed. Set SOC_SYSLOG_BIND=<private IP> (and firewall it), or SOC_SYSLOG_ALLOW_ANY=1 to accept the risk."); return
    try:
        socketserver.ThreadingUDPServer.allow_reuse_address = socketserver.ThreadingTCPServer.allow_reuse_address = True
        for cls, h in ((socketserver.ThreadingUDPServer, _U), (socketserver.ThreadingTCPServer, _T)):
            s = cls((bind, port), h); s.daemon_threads = True; threading.Thread(target=s.serve_forever, daemon=True).start()
        threading.Thread(target=_flush, daemon=True).start()
        print(f"  Syslog receiver listening on {bind}:{port} (UDP+TCP)")
    except Exception as e: print(f"  Syslog receiver could not start on port {port}: {e}")
