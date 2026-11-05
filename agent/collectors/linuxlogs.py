"""Linux / Ubuntu / Debian / RHEL / macOS log collector (standard library only).

Collects EVERYTHING the system logs, in real time:
  * systemd journal (journalctl) when available - this covers sshd, sudo, su, kernel, services, cron, ufw ...
  * otherwise the classic files: auth.log / secure, syslog / messages, kern.log
  * plus web-server / audit / firewall / fail2ban files when they exist (nginx, apache, auditd, ufw, fail2ban)
Every line is stored as a log. Only well-defined security lines (failed logins, sudo denials, new users, admin group
changes, and attack patterns in web logs) are sent to the detection rules; everything else is log_only, so ordinary
system noise can never create a false alert.
Same safety design as the Windows collector: drain all waiting lines per cycle (capped), cursor saved only after the
server accepted the events, server ignores duplicates. Reading the journal / auth logs needs root (or membership of the
'systemd-journal' and 'adm' groups)."""
import os, re, sys, time, json, shutil, hashlib, threading, subprocess
from datetime import datetime, timezone, timedelta

BATCH = int(os.environ.get("SOC_LINUX_BATCH", "500"))
MAX_BATCHES = int(os.environ.get("SOC_LINUX_MAX_BATCHES", "20"))          # cap = BATCH*MAX_BATCHES lines per source per cycle
INTERVAL = float(os.environ.get("SOC_LINUX_INTERVAL", "2"))
BACKFILL_MIN = int(os.environ.get("SOC_LINUX_BACKFILL_MINUTES", "0"))     # journal only: also load N past minutes on the very first run
ERR_BACKOFF = 60
CURSOR_FILE = os.environ.get("SOC_LINUX_CURSOR", os.path.join(os.path.dirname(os.path.abspath(__file__)), ".linuxlogs_cursor.json"))
SYSTEM_FILES = ["/var/log/auth.log", "/var/log/secure", "/var/log/syslog", "/var/log/messages", "/var/log/kern.log", "/var/log/system.log"]
EXTRA_FILES = ["/var/log/nginx/access.log", "/var/log/nginx/error.log", "/var/log/apache2/access.log", "/var/log/apache2/error.log",
               "/var/log/httpd/access_log", "/var/log/httpd/error_log", "/var/log/audit/audit.log", "/var/log/ufw.log", "/var/log/fail2ban.log"]
KEEP = ("_PID", "_UID", "_GID", "_COMM", "_EXE", "_CMDLINE", "_SYSTEMD_UNIT", "_TRANSPORT", "_HOSTNAME", "SYSLOG_IDENTIFIER", "SYSLOG_FACILITY", "PRIORITY", "_BOOT_ID")
PRIO = {"0": "Emergency", "1": "Alert", "2": "Critical", "3": "Error", "4": "Warning", "5": "Notice", "6": "Information", "7": "Debug"}
MSG_MAX, RAW_MAX = 4000, 8000
IP = r"(\d{1,3}(?:\.\d{1,3}){3})"

def machine_id():
    for f in ("/etc/machine-id", "/var/lib/dbus/machine-id"):
        try:
            v = open(f).read().strip()
            if v: return v
        except Exception: pass
    import socket, uuid; return f"{socket.gethostname()}-{uuid.getnode()}"

# ---------------- which lines feed the detection rules ----------------
AUTH_FAIL = re.compile(r"Failed password|Invalid user|authentication failure", re.I)
SUDO_DENY = re.compile(r"not in the sudoers|not in sudoers", re.I)
NEW_USER = re.compile(r"useradd\S*\s.*new user: name=([^,\s]+)", re.I | re.S)
ADMIN_GRP = re.compile(r"add '([^']+)' to (?:shadow )?group '(sudo|wheel|admin|root)'|user (\S+) added by (\S+) to group (sudo|wheel|admin)", re.I)
WEB_ATTACK = re.compile(r"union\s+select|or\s+1\s*=\s*1|sqlmap|<script|onerror\s*=|\.\./\.\./|/etc/passwd|/etc/shadow|nmap|masscan", re.I)

def classify(msg, ident="", path=""):
    """-> (source_ip, message_for_rules) when the line is a security event the rules should see, else None."""
    full = f"{ident} {msg}"
    m = re.search(r"(?:from|rhost=|client: |^)\s*" + IP, msg)
    ip = m.group(1) if m else None
    if AUTH_FAIL.search(msg): return ip, msg
    if SUDO_DENY.search(msg): return ip, msg
    m = NEW_USER.search(full)
    if m: return None, f"New user account created: {m.group(1)} (Linux useradd)"
    m = ADMIN_GRP.search(msg)
    if m: return None, f"Privilege escalation: member {m.group(1) or m.group(3)} added to {m.group(2) or m.group(5)} (Linux group change)"
    if re.search(r"(access|error)[_.]log|nginx|apache|httpd", path + " " + ident) and WEB_ATTACK.search(msg): return ip, msg
    return None

def _iso(dt): return dt.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%fZ")

def parse_ts(line):
    """Best-effort timestamp of a log line -> UTC ISO string, or None."""
    try:
        m = re.match(r"^(\d{4}-\d\d-\d\d)[T ](\d\d:\d\d:\d\d)(\.\d+)?(Z|[+-]\d\d:?\d\d)?", line)
        if m:
            d, t, fr, tz = m.groups(); base = datetime.strptime(f"{d} {t}", "%Y-%m-%d %H:%M:%S") + timedelta(microseconds=int((fr or ".0")[1:7].ljust(6, "0")))
            if tz:
                tz = "+00:00" if tz == "Z" else tz if ":" in tz else tz[:3] + ":" + tz[3:]
                sign = 1 if tz[0] == "+" else -1; off = timedelta(hours=int(tz[1:3]), minutes=int(tz[4:6])) * sign
                return _iso(base.replace(tzinfo=timezone(off)))
            return _iso(base.astimezone())
        m = re.search(r"\[(\d\d/[A-Za-z]{3}/\d{4}:\d\d:\d\d:\d\d [+-]\d{4})\]", line)
        if m: return _iso(datetime.strptime(m.group(1), "%d/%b/%Y:%H:%M:%S %z"))
        m = re.match(r"^(\d{4}/\d\d/\d\d \d\d:\d\d:\d\d)", line)
        if m: return _iso(datetime.strptime(m.group(1), "%Y/%m/%d %H:%M:%S").astimezone())
        m = re.search(r"msg=audit\((\d+)\.(\d+):", line)
        if m: return _iso(datetime.fromtimestamp(int(m.group(1)) + int(m.group(2)) / 1000.0, timezone.utc))
        m = re.match(r"^([A-Z][a-z]{2})\s+(\d{1,2}) (\d\d:\d\d:\d\d)", line)
        if m:
            now = datetime.now(); d = datetime.strptime(f"{now.year} {m.group(1)} {m.group(2)} {m.group(3)}", "%Y %b %d %H:%M:%S")
            if d > now + timedelta(days=1): d = d.replace(year=now.year - 1)
            return _iso(d.astimezone())
    except Exception: pass
    return None

def _txt(v):
    if isinstance(v, list):
        try: return bytes(v).decode("utf-8", "replace")
        except Exception: return ""
    return v if isinstance(v, str) else ("" if v is None else str(v))

def _item(host, channel, msg, etime, rid, level, provider, raw):
    msg = msg.rstrip("\r\n")
    c = classify(msg, provider, channel)
    if c: ip, cmsg = c; log_only = False
    else:
        ip, cmsg, log_only = None, msg, True
        m = re.search(r"(?:from|rhost=|client: )\s*" + IP, msg)          # keep an IP for searching, without ever alerting
        if m: ip = m.group(1)
    return {"host": host, "source_ip": ip, "message": cmsg[:MSG_MAX], "channel": channel, "level": level, "provider": (provider or "")[:200],
            "record_id": rid, "event_time": etime or _iso(datetime.now(timezone.utc)), "raw": json.dumps(raw, ensure_ascii=False)[:RAW_MAX], "log_only": log_only}

def journal_available():
    return bool(shutil.which("journalctl")) and (os.path.isdir("/run/systemd/journal") or os.path.isdir("/var/log/journal"))

class Collector:
    interval = INTERVAL
    def __init__(self, cursor_file=None, files=None, use_journal=None):
        self.cursor_file = CURSOR_FILE if cursor_file is None else cursor_file
        self.journal = journal_available() if use_journal is None else use_journal
        if os.environ.get("SOC_LINUX_JOURNAL") == "0": self.journal = False
        env = [f.strip() for f in os.environ.get("SOC_LINUX_FILES", "").split(",") if f.strip()]
        self.files = files or env or (EXTRA_FILES if self.journal else SYSTEM_FILES + EXTRA_FILES)
        self.sources = (["journald"] if self.journal else []) + list(self.files)
        self.last = {}; self.committed = {}; self.backlog = False; self.stats = {}; self.retry_at = {}; self.err = {}; self.notes = {}; self.mid = machine_id(); self._load()
    def _load(self):
        try:
            d = json.load(open(self.cursor_file))
            if d.get("machine") == self.mid: self.last = d.get("cursors", {}); self.committed = json.loads(json.dumps(self.last))
        except Exception: pass
    def commit(self):
        if self.last == self.committed or not self.cursor_file: return
        try:
            tmp = self.cursor_file + ".tmp"
            with open(tmp, "w") as f: json.dump({"machine": self.mid, "cursors": self.last}, f)
            os.replace(tmp, self.cursor_file); self.committed = json.loads(json.dumps(self.last))
        except Exception as e: print(f"logs: could not save cursor: {e}")

    # ---- journald ----
    def _journalctl(self, args, limit):
        p = subprocess.Popen(["journalctl", "-o", "json", "--no-pager"] + args, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        t = threading.Timer(60, p.kill); t.start(); lines = []
        try:
            for raw in p.stdout:
                lines.append(raw)
                if len(lines) >= limit: break
        finally:
            if len(lines) >= limit: p.kill()
            p.wait(); t.cancel()
        err = (p.stderr.read() or b"").decode("utf-8", "replace").strip()
        if not lines and p.returncode not in (0, None) and p.returncode > 0: raise RuntimeError(err or f"journalctl exit {p.returncode}")
        if "not seeing messages" in err:
            self.notes["journald"] = "journald: this user sees only its OWN messages, not the system's: it must be in group systemd-journal (or adm)"
            if self.err.get("hint") != err: self.err["hint"] = err; print("journald: " + self.notes["journald"] + "  (fix: sudo usermod -aG systemd-journal <agent user>, then restart the agent)")
        elif lines: self.notes.pop("journald", None)
        return lines
    def _journal_drain(self, host, out):
        cur = self.last.get("journald"); events = batches = 0
        if cur is None:                                          # first run on this machine
            if BACKFILL_MIN > 0: args = ["--since=-%dmin" % BACKFILL_MIN]
            else:
                l = self._journalctl(["-n", "1"], 1)
                if not l: self.notes["journald"] = "journald returned no entries at all: the agent user probably cannot read the system journal (needs group systemd-journal)"; return 0, 0
                self.last["journald"] = json.loads(l[0])["__CURSOR"]; return 0, 0
        else: args = ["--after-cursor=" + cur]
        while batches < MAX_BATCHES:
            try: lines = self._journalctl(args, BATCH)
            except RuntimeError as e:
                if "cursor" in str(e).lower():                    # journal was rotated/vacuumed: continue from now
                    print("journald: saved position no longer exists (journal rotated); continuing from now"); self.last.pop("journald", None); return events, batches
                raise
            batches += 1; n = 0
            for raw in lines:
                try: e = json.loads(raw)
                except ValueError: continue
                cur = e["__CURSOR"]; n += 1
                ts = datetime.fromtimestamp(int(e.get("__REALTIME_TIMESTAMP", "0")) / 1e6, timezone.utc)
                ident = _txt(e.get("SYSLOG_IDENTIFIER") or e.get("_COMM"))
                out.append(_item(host, "journald", _txt(e.get("MESSAGE")), _iso(ts), int(hashlib.sha1(cur.encode()).hexdigest()[:15], 16),
                                 PRIO.get(_txt(e.get("PRIORITY")), ""), ident, {k: _txt(e[k]) for k in KEEP if k in e}))
            events += n
            if n: self.last["journald"] = cur; args = ["--after-cursor=" + cur]
            if len(lines) < BATCH: break
        else: self.backlog = True
        return events, batches

    # ---- plain files ----
    def _file_drain(self, path, host, out):
        try: st = os.stat(path)
        except FileNotFoundError: return 0, 0
        cur = self.last.get(path)
        if cur is None: self.last[path] = {"inode": st.st_ino, "offset": st.st_size}; return 0, 0     # start from now
        if cur["inode"] != st.st_ino or st.st_size < cur["offset"]: cur = self.last[path] = {"inode": st.st_ino, "offset": 0}   # rotated
        if st.st_size <= cur["offset"]: return 0, 0
        events = batches = 0; ch = "file:" + path; ident = os.path.basename(path)
        with open(path, "rb") as f:
            while batches < MAX_BATCHES:
                f.seek(cur["offset"]); pos = cur["offset"]; lines = []
                while len(lines) < BATCH:
                    ln = f.readline(65536)
                    if not ln or (not ln.endswith(b"\n") and len(ln) < 65536): break    # incomplete last line: wait for the rest
                    lines.append((pos, ln)); pos += len(ln)
                batches += 1
                for off, ln in lines:
                    s = ln.decode("utf-8", "replace").rstrip("\r\n")
                    if s.strip(): out.append(_item(host, ch, s, parse_ts(s), off, "", ident, {"file": path}))
                events += len(lines)
                if lines: cur["offset"] = pos
                if len(lines) < BATCH: break
            else: self.backlog = True
        return events, batches

    def problems(self):
        """Short, human-readable reasons why a log source is not delivering. Sent in every heartbeat so the DASHBOARD shows them (not just the local service log)."""
        out = []
        for src, e in self.err.items():
            if src == "hint": continue
            name = "journald" if src == "journald" else os.path.basename(src)
            out.append(f"{name}: " + ("permission denied - agent user needs group adm/systemd-journal (or --full-file-read)" if e == "perm" else str(e)))
        if "journald" in self.notes and not any(p.startswith("journald") for p in out): out.append(self.notes["journald"])
        return [p[:120] for p in out]
    def poll(self, host):
        out = []; self.backlog = False
        for src in self.sources:
            if time.time() < self.retry_at.get(src, 0): continue
            t0 = time.time(); ev = ba = 0
            try:
                ev, ba = self._journal_drain(host, out) if src == "journald" else self._file_drain(src, host, out); self.err.pop(src, None)
            except PermissionError:
                if self.err.get(src) != "perm": print(f"logs {src}: permission denied - the agent user needs group adm (log files) or systemd-journal (journal); installer option --full-file-read grants read-only access to everything")
                self.err[src] = "perm"; self.retry_at[src] = time.time() + ERR_BACKOFF
            except Exception as e:
                if str(e) != self.err.get(src): print(f"logs {src}: {e}")
                self.err[src] = str(e); self.retry_at[src] = time.time() + ERR_BACKOFF
            ms = (time.time() - t0) * 1000; self.stats[src] = (ev, ba, ms)
            if ev: print(f"logs {src}: {ev} events in {ba} batch(es), {ms:.0f} ms" + (" [backlog cap hit]" if self.backlog else ""))
        return out
