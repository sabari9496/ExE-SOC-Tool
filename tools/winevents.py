"""Windows Event Log collector (no extra dependencies: uses the built-in wevtutil).

Collects EVERY event from the configured channels (not just a few IDs), in real time:
  * every poll drains all waiting events (oldest first, in batches) before sleeping
  * each event is sent with its full text, channel, event id, level, provider, record id and original time
  * a small set of high-confidence events (failed logons, new accounts, admin group changes, log cleared,
    new service, Defender detections) are turned into text the SOC detection rules understand; every other
    event is stored as a plain log line (log_only) so it can never create a false alert
  * the read position (cursor) is saved to disk only AFTER the server accepted the events, so a crash or restart
    neither loses nor (thanks to the server-side duplicate guard) duplicates events
Reading the Security log requires Administrator."""
import subprocess, re, os, time, json, locale, sys
import xml.etree.ElementTree as ET

NS = "{http://schemas.microsoft.com/win/2004/08/events/event}"
LOGON_TYPES = {"2": "interactive", "3": "network", "4": "batch", "5": "service", "7": "unlock", "8": "network-cleartext", "10": "RDP", "11": "cached"}
# channel -> event ids that feed the detection rules (everything else is stored as a plain log)
WATCH = {"Security": [4625, 4720, 4728, 4732, 4756, 1102], "System": [7045, 104],
         "Microsoft-Windows-Windows Defender/Operational": [1116, 1117]}
QUERY = "*[System[(" + " or ".join(f"EventID={i}" for i in sorted({i for v in WATCH.values() for i in v})) + ")]]"   # kept for compatibility

DEFAULT_CHANNELS = ["Security", "System", "Application", "Microsoft-Windows-Windows Defender/Operational",
                    "Microsoft-Windows-PowerShell/Operational", "Microsoft-Windows-Sysmon/Operational"]
CHANNELS = [c.strip() for c in os.environ.get("SOC_WIN_CHANNELS", "").split(",") if c.strip()] or DEFAULT_CHANNELS
BATCH_SIZE = int(os.environ.get("SOC_WIN_BATCH", "300"))            # events per wevtutil call
MAX_BATCHES = int(os.environ.get("SOC_WIN_MAX_BATCHES", "20"))      # max calls per channel per cycle (cap = BATCH_SIZE*MAX_BATCHES)
BACKFILL_MIN = int(os.environ.get("SOC_WIN_BACKFILL_MINUTES", "0")) # on the very first run, also collect this many past minutes (0 = start from now)
INTERVAL = float(os.environ.get("SOC_WIN_INTERVAL", "2"))           # seconds to sleep when everything is drained
ERR_BACKOFF = 60                                                    # seconds before retrying a channel that errored
CURSOR_FILE = os.environ.get("SOC_WIN_CURSOR", os.path.join(os.path.dirname(os.path.abspath(__file__)), ".winevents_cursor.json"))
MSG_MAX, RAW_MAX = 4000, 8000

def machine_id():
    try:
        import winreg
        with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Microsoft\Cryptography") as k: return winreg.QueryValueEx(k, "MachineGuid")[0]
    except Exception: pass
    import socket; return socket.gethostname()

# ---------------- parsing ----------------
def _data(ev):
    d = {}; extra = []
    for n in ev.iter(NS + "Data"):
        v = (n.text or "")
        if n.get("Name"): d[n.get("Name")] = v
        elif v: extra.append(v)
    ud = ev.find(NS + "UserData")
    if ud is not None:
        for child in list(ud):
            for n in child.iter():
                if n is not child and (n.text or "").strip(): d[n.tag.split("}")[-1]] = n.text.strip()
    if extra: d["_data"] = " | ".join(extra)
    return d

def format_event(ev, channel=None):
    """Return (source_ip, message) for a parsed <Event> that feeds the detection rules, or None."""
    sysn = ev.find(NS + "System")
    if sysn is None: return None
    eid = int(sysn.findtext(NS + "EventID", "0") or 0)
    if channel is not None and eid not in WATCH.get(channel, []): return None
    d = _data(ev)
    ip = d.get("IpAddress") or d.get("SourceNetworkAddress") or ""
    ip = ip if re.match(r"^\d{1,3}(\.\d{1,3}){3}$", ip) else None
    if eid == 4625:
        lt = LOGON_TYPES.get(d.get("LogonType", ""), d.get("LogonType", "?"))
        return ip, f"Failed login for user {d.get('TargetUserName','?')} from {ip or 'local'} logon type {lt} (Windows event 4625)"
    if eid == 4720:
        return None, f"New user account created: {d.get('TargetUserName','?')} by {d.get('SubjectUserName','?')} (Windows event 4720)"
    if eid in (4728, 4732, 4756):
        grp = d.get("TargetUserName", "?")
        if grp.lower() in ("administrators", "domain admins", "enterprise admins", "schema admins"):
            return None, f"Privilege escalation: member {d.get('MemberName','?')} added to {grp} by {d.get('SubjectUserName','?')} (Windows event {eid})"
        return None
    if eid in (1102, 104):
        return None, f"Audit log cleared by {d.get('SubjectUserName') or d.get('Channel') or 'unknown'} (Windows event {eid})"
    if eid == 7045:
        return None, f"New service installed: {d.get('ServiceName','?')} path {d.get('ImagePath','?')} (Windows event 7045)"
    if eid in (1116, 1117):
        verb = "detected" if eid == 1116 else "action taken"
        return None, f"Malware {verb}: {d.get('Threat Name') or d.get('ThreatName') or '?'} path {d.get('Path') or d.get('Process Name') or '?'} (Windows Defender event {eid})"
    return None

def _clean(s): return re.sub(r"\s+", " ", (s or "")).strip()

def make_record(ev, channel):
    """Full structured record for one <Event>: (record_id, item-dict for /api/ingest)."""
    sysn = ev.find(NS + "System")
    if sysn is None: return None
    rid = int(sysn.findtext(NS + "EventRecordID", "0") or 0)
    eid = int(sysn.findtext(NS + "EventID", "0") or 0)
    prov = (sysn.find(NS + "Provider").get("Name") if sysn.find(NS + "Provider") is not None else "") or ""
    tc = sysn.find(NS + "TimeCreated"); etime = tc.get("SystemTime") if tc is not None else None
    ri = ev.find(NS + "RenderingInfo"); d = _data(ev)
    rendered = _clean(ri.findtext(NS + "Message")) if ri is not None else ""
    level = ""
    if ri is not None:
        kws = [k.text for k in ri.iter(NS + "Keyword") if k.text]
        level = next((k for k in kws if "Audit" in k), "") or _clean(ri.findtext(NS + "Level"))
    if not level: level = {"1": "Critical", "2": "Error", "3": "Warning", "4": "Information", "5": "Verbose", "0": "Information"}.get(sysn.findtext(NS + "Level", ""), "")
    cur = format_event(ev, channel)
    if cur:
        ip, msg = cur; log_only = False
        raw = dict(d); raw["_rendered"] = rendered
    else:
        ip = d.get("IpAddress") or d.get("SourceNetworkAddress") or d.get("ClientAddress") or ""
        ip = ip if re.match(r"^\d{1,3}(\.\d{1,3}){3}$", ip) else None
        msg = rendered or (f"{prov} EventID {eid}: " + "; ".join(f"{k}={v}" for k, v in d.items() if v))
        raw = d; log_only = True
    return rid, {"source_ip": ip, "message": msg[:MSG_MAX], "channel": channel, "event_id": eid, "level": level, "provider": prov[:200],
                 "record_id": rid, "event_time": etime, "raw": json.dumps(raw, ensure_ascii=False)[:RAW_MAX], "log_only": log_only}

def parse_records(text, channel):
    try: root = ET.fromstring("<Events>" + re.sub(r"<\?xml[^>]*\?>", "", text) + "</Events>")
    except ET.ParseError as e: raise RuntimeError(f"could not parse wevtutil output ({e}); cursor not advanced")
    out = []
    for ev in root.findall(NS + "Event"):
        r = make_record(ev, channel)
        if r: out.append(r)
    return out

# ---------------- wevtutil ----------------
def _decode(b):
    try: return b.decode("utf-8")
    except UnicodeDecodeError: return b.decode(locale.getpreferredencoding(False) or "cp1252", errors="replace")

def _run(channel, xpath, count, newest_first, fmt="xml"):
    cmd = ["wevtutil", "qe", channel, "/q:" + xpath, "/c:%d" % count, "/rd:" + ("true" if newest_first else "false"), "/f:" + fmt]
    p = subprocess.run(cmd, capture_output=True, timeout=60)
    if p.returncode != 0:
        err = _decode(p.stderr or b"").strip() or "wevtutil failed"
        raise RuntimeError(err + (" (run as Administrator to read the Security log)" if "denied" in err.lower() else ""))
    return _decode(p.stdout)

def query(channel, count=BATCH_SIZE, after=0):
    """Events in `channel` with RecordID > after, OLDEST first (fully rendered). Returns [(record_id, item)]."""
    return parse_records(_run(channel, "*[System[EventRecordID>%d]]" % after, count, False, "RenderedXml"), channel)

def latest_record_id(channel):
    m = re.search(r"<EventRecordID>(\d+)</EventRecordID>", _run(channel, "*", 1, True))
    return int(m.group(1)) if m else 0

def first_record_since(channel, minutes):
    m = re.search(r"<EventRecordID>(\d+)</EventRecordID>", _run(channel, "*[System[TimeCreated[timediff(@SystemTime)<=%d]]]" % (minutes * 60000), 1, False))
    return int(m.group(1)) if m else 0

class Collector:
    """Per-channel RecordID cursor. poll() drains every waiting batch (oldest first) up to a per-channel cap.
    Call commit() once the returned events were accepted by the server; only then is the cursor saved to disk."""
    interval = INTERVAL
    def __init__(self, cursor_file=None, channels=None):
        self.channels = channels or CHANNELS; self.cursor_file = CURSOR_FILE if cursor_file is None else cursor_file
        self.last = {}; self.committed = {}; self.backlog = False; self.stats = {}; self.retry_at = {}; self.err = {}
        self.mid = machine_id(); self._load()
    def _load(self):
        try:
            d = json.load(open(self.cursor_file))
            if d.get("machine") == self.mid: self.last = {k: int(v) for k, v in d.get("cursors", {}).items()}; self.committed = dict(self.last)
        except Exception: pass
    def commit(self):
        if self.last == self.committed or not self.cursor_file: return
        try:
            tmp = self.cursor_file + ".tmp"
            with open(tmp, "w") as f: json.dump({"machine": self.mid, "cursors": self.last}, f)
            os.replace(tmp, self.cursor_file); self.committed = dict(self.last)
        except Exception as e: print(f"eventlog: could not save cursor: {e}")
    def _drain(self, ch, host, out):
        latest = latest_record_id(ch); cur = self.last.get(ch)
        if cur is None:                                   # first run on this machine: start from now (optionally with a backfill)
            cur = latest
            if BACKFILL_MIN > 0:
                first = first_record_since(ch, BACKFILL_MIN)
                if first: cur = first - 1
            self.last[ch] = cur
        elif latest < cur:                                # the log was cleared and record ids restarted
            print(f"eventlog {ch}: log was cleared/reset (saved {cur} > newest {latest}); reading from the start of the new log")
            cur = self.last[ch] = 0
        if latest <= cur: return 0, 0                     # nothing new (one cheap call)
        events = batches = 0
        while batches < MAX_BATCHES:
            recs = query(ch, BATCH_SIZE, cur); batches += 1; events += len(recs)
            for rid, item in recs: item["host"] = host; out.append(item)
            if recs: cur = self.last[ch] = max(cur, max(rid for rid, _ in recs))     # cursor moves only after the batch parsed cleanly
            if len(recs) < BATCH_SIZE: break               # channel drained
        else: self.backlog = True                          # cap reached: more is waiting, come back right away
        return events, batches
    def poll(self, host):
        out = []; self.backlog = False
        for ch in self.channels:
            if time.time() < self.retry_at.get(ch, 0): continue
            t0 = time.time(); ev = ba = 0
            try:
                ev, ba = self._drain(ch, host, out); self.err.pop(ch, None)
            except Exception as e:                        # cursor stays at the last good batch -> retried later
                msg = str(e)
                if "sysmon" in ch.lower() and ("could not be found" in msg.lower() or "not found" in msg.lower() or "1060" in msg):
                    msg = "Sysmon channel not found: Sysmon is not installed (or not configured). Verify with sysmon_status(); install a signed Sysmon you obtained and verified yourself (see docs/UNIFIED-TELEMETRY.md). Nothing is downloaded automatically."
                elif "sysmon" in ch.lower() and "denied" in msg.lower(): msg = "Access denied reading the Sysmon Operational log: run the agent as Administrator or add its service account to 'Event Log Readers'."
                if msg != self.err.get(ch): print(f"eventlog {ch}: {msg}")
                self.err[ch] = msg
                self.retry_at[ch] = time.time() + (600 if "could not be found" in msg.lower() else ERR_BACKOFF)
            ms = (time.time() - t0) * 1000; self.stats[ch] = (ev, ba, ms)
            if ev: print(f"eventlog {ch}: {ev} events in {ba} batch(es), {ms:.0f} ms" + (" [backlog cap hit]" if self.backlog else ""))
        return out


def sysmon_status():
    """Read-only check (never installs or changes anything): is Sysmon installed/running and does the Operational channel exist and have events?
    -> dict(installed, running, service, channel_exists, readable, latest_record_id, note)"""
    r = dict(installed=False, running=False, service=None, channel_exists=False, readable=False, latest_record_id=0, note="")
    for svc in ("Sysmon64", "Sysmon"):
        try:
            p = subprocess.run(["sc", "query", svc], capture_output=True, timeout=15); out = _decode(p.stdout or b"")
            if p.returncode == 0 and "SERVICE_NAME" in out: r.update(installed=True, service=svc, running="RUNNING" in out); break
        except Exception as e: r["note"] = f"service query failed: {e}"
    ch = "Microsoft-Windows-Sysmon/Operational"
    try:
        p = subprocess.run(["wevtutil", "gl", ch], capture_output=True, timeout=15); r["channel_exists"] = p.returncode == 0
        if p.returncode == 0:
            try: r["latest_record_id"] = latest_record_id(ch); r["readable"] = True
            except Exception as e: r["note"] = str(e)[:200]
    except Exception as e: r["note"] = (r["note"] + " " + str(e))[:200]
    if not r["installed"]: r["note"] = r["note"] or "Sysmon service not found: Sysmon telemetry is unavailable on this host."
    elif not r["running"]: r["note"] = "Sysmon is installed but not running."
    elif not r["channel_exists"]: r["note"] = "Operational channel missing."
    elif not r["readable"]: r["note"] = r["note"] or "Channel exists but cannot be read (permissions) or is empty."
    return r
