"""Process and network activity monitor (needs psutil). Reports NEW processes and NEW network connections / listening ports on this computer.
It polls every few seconds, so a process that starts and ends between two polls can be missed; for a complete record enable Windows process-creation
auditing (tools/enable_windows_auditing.bat) or Sysmon, and on Linux auditd (tools/enable_linux_auditing.sh) - those are collected too.
Settings: SOC_ACTIVITY=0 (off), SOC_PROC_INTERVAL (seconds, 2), SOC_NET_DEDUPE_MIN (report the same process->address:port again only after N minutes, 60)."""
import os, sys, json, time, queue, platform, threading
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from bgscan import iso, rid
try: import psutil
except ImportError: psutil = None

SYS = platform.system(); OSN = "Windows" if SYS == "Windows" else "Linux" if SYS == "Linux" else SYS
POLL = max(1.0, float(os.environ.get("SOC_PROC_INTERVAL", "2"))); DEDUPE = float(os.environ.get("SOC_NET_DEDUPE_MIN", "60")) * 60
MAX_PER_POLL = 300

class ActivityMonitor:
    interval = POLL; backlog = False
    def __init__(self):
        self.q = queue.Queue(maxsize=20000); self.me = os.getpid(); self.seen = None; self.listen = None; self.recent = {}
        if psutil is None: print("activity monitor: psutil not installed (pip install psutil), process/network monitoring is off"); return
        threading.Thread(target=self._loop, daemon=True, name="procmon").start()
    def _put(self, it):
        try: self.q.put_nowait(it)
        except queue.Full: pass
    def _loop(self):
        while True:
            try: self._procs()
            except Exception as e: print("procmon:", e)
            try: self._net()
            except Exception as e: print("netmon:", e)
            time.sleep(POLL)
    def _procs(self):
        cur = {}
        for p in psutil.process_iter(["pid", "ppid", "name", "exe", "cmdline", "username", "create_time"]):
            i = p.info; cur[(i["pid"], i["create_time"])] = i
        if self.seen is None: self.seen = set(cur); return                          # first pass = baseline, nothing reported
        new = [k for k in cur if k not in self.seen]; self.seen = set(cur)
        if not new: return
        byp = {k[0]: v for k, v in cur.items()}
        def mine(pid):
            for _ in range(8):
                if pid == self.me: return True
                pid = (byp.get(pid) or {}).get("ppid")
                if not pid: return False
            return False
        for k in new[:MAX_PER_POLL]:
            i = cur[k]
            if mine(i["pid"]): continue                                              # our own helpers (journalctl, wevtutil, iptables, clamscan...)
            par = byp.get(i["ppid"]) or {}; cmd = " ".join(i["cmdline"] or [])[:1500]; exe = i["exe"] or i["name"] or ""
            raw = {"pid": i["pid"], "ppid": i["ppid"], "name": i["name"], "exe": exe, "cmdline": cmd, "parent": par.get("exe") or par.get("name") or "", "user": i["username"], "os": OSN}
            self._put({"message": f"Process started: {cmd or exe} (user {i['username'] or '?'}, parent {par.get('name') or '?'})"[:1500], "channel": "process", "event_id": None, "level": "Information", "provider": "EXESOC-ACTIVITY",
                       "record_id": rid("proc", i["pid"], i["create_time"]), "event_time": iso(i["create_time"]), "raw": json.dumps(raw), "log_only": True, "source_ip": None})
    def _net(self):
        try: conns = psutil.net_connections(kind="inet")
        except (psutil.AccessDenied, OSError): return
        first = self.listen is None; now = time.time(); lis = set()
        for c in conns:
            try:
                if c.status == "LISTEN" and c.laddr: lis.add((c.laddr.ip, c.laddr.port, c.pid)); continue
                if c.status != "ESTABLISHED" or not c.raddr: continue
                name = user = ""
                if c.pid:
                    try: pr = psutil.Process(c.pid); name = pr.name(); user = pr.username()
                    except Exception: pass
                key = (name, c.raddr.ip, c.raddr.port)
                if first: self.recent[key] = now; continue
                if now - self.recent.get(key, 0) < DEDUPE: continue
                self.recent[key] = now
                self._put(self._it("Outbound Connection", c, name, user, f"Connection: {name or 'unknown'} (pid {c.pid}) -> {c.raddr.ip}:{c.raddr.port}", c.raddr.ip))
            except Exception: continue
        if not first:
            for l in lis - self.listen:
                name = ""
                try: name = psutil.Process(l[2]).name() if l[2] else ""
                except Exception: pass
                self._put({"message": f"New listening port {l[1]}: {name or 'unknown'} (pid {l[2]}) on {l[0]}", "channel": "network", "event_id": None, "level": "Information", "provider": "EXESOC-ACTIVITY", "record_id": rid("listen", l[0], l[1], l[2], int(now)),
                           "event_time": iso(), "raw": json.dumps({"kind": "New Listening Port", "name": name, "pid": l[2], "lport": l[1], "laddr": l[0], "os": OSN}), "log_only": True, "source_ip": None})
        self.listen = lis
        if len(self.recent) > 50000: self.recent = {k: v for k, v in self.recent.items() if now - v < DEDUPE}
    def _it(self, kind, c, name, user, msg, rip):
        return {"message": msg, "channel": "network", "event_id": None, "level": "Information", "provider": "EXESOC-ACTIVITY", "record_id": rid("net", c.pid, c.laddr.port if c.laddr else 0, rip, c.raddr.port, int(time.time())), "event_time": iso(), "dest_ip": rip, "source_ip": None, "log_only": True,
                "raw": json.dumps({"kind": kind, "name": name, "pid": c.pid, "laddr": c.laddr.ip if c.laddr else "", "lport": c.laddr.port if c.laddr else 0, "raddr": rip, "rport": c.raddr.port, "user": user, "os": OSN})}
    def poll(self, host):
        out = []
        while len(out) < 5000:
            try: it = self.q.get_nowait()
            except queue.Empty: break
            it["host"] = host; out.append(it)
        return out
    def commit(self): pass
