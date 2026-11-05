"""Base for scanners that run in a background thread and hand their findings to the normal collector loop
(poll() returns them, commit() saves the scanner state only after the SOC accepted the events)."""
import os, json, time, queue, threading, hashlib
from datetime import datetime, timezone

def machine_id():
    for f in ("/etc/machine-id", "/var/lib/dbus/machine-id"):
        try:
            v = open(f).read().strip()
            if v: return v
        except Exception: pass
    try:
        import winreg
        with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Microsoft\Cryptography") as k: return winreg.QueryValueEx(k, "MachineGuid")[0]
    except Exception: pass
    import socket; return socket.gethostname()

def iso(ts=None): return datetime.fromtimestamp(ts if ts is not None else time.time(), timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%fZ")
def rid(*parts): return int(hashlib.sha1("|".join(map(str, parts)).encode()).hexdigest()[:15], 16)

class BackgroundScanner:
    name = "scanner"; interval = 300; backlog = False
    def __init__(self, state_file):
        self.state_file = state_file; self.mid = machine_id(); self.state = self._load(); self.q = queue.Queue(); self.inflight = None; self.done = threading.Event()
        threading.Thread(target=self._loop, daemon=True, name=self.name).start()
    def _load(self):
        try:
            d = json.load(open(self.state_file))
            if d.get("machine") == self.mid: return d.get("state")
        except Exception: pass
        return None
    def scan(self, state):                      # -> (items, new_state)
        raise NotImplementedError
    def _loop(self):
        time.sleep(3)
        while True:
            try:
                items, new = self.scan(self.state)
                if items or new != self.state:
                    self.done.clear(); self.q.put((items, new)); self.done.wait(300)      # wait until delivered + committed
            except Exception as e: print(f"{self.name}: scan error: {e}")
            time.sleep(self.interval)
    def poll(self, host):
        out = []
        while True:
            try: items, new = self.q.get_nowait()
            except queue.Empty: break
            for i in items: i["host"] = host
            out += items; self.inflight = new
        return out
    def commit(self):
        if self.inflight is None: return
        try:
            tmp = self.state_file + ".tmp"
            with open(tmp, "w") as f: json.dump({"machine": self.mid, "state": self.inflight}, f)
            os.replace(tmp, self.state_file); self.state = self.inflight; self.inflight = None; self.done.set()
        except Exception as e: print(f"{self.name}: could not save state: {e}")
