"""File Integrity Monitoring: fingerprints (SHA-256) important files and reports created / modified / deleted / permission-changed files.
First run builds the baseline silently (no alerts). Changes to critical files (accounts, sudoers, ssh, cron, systemd units, hosts, startup, scheduled tasks;
system binaries when no package update is running) raise an alert; every other change is stored as a plain log (channel 'fim').
Settings: SOC_FIM=0 (off), SOC_FIM_PATHS (paths separated by os.pathsep, replaces the defaults), SOC_FIM_EXCLUDE (comma globs), SOC_FIM_INTERVAL (seconds, 300),
SOC_FIM_FULL_HOURS (re-hash everything even if the timestamp is unchanged, 24)."""
import os, re, sys, glob, time, hashlib, fnmatch, platform, ntpath
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from bgscan import BackgroundScanner, iso, rid

WIN = platform.system() == "Windows"
INTERVAL = max(30, int(os.environ.get("SOC_FIM_INTERVAL", "300"))); FULL_H = float(os.environ.get("SOC_FIM_FULL_HOURS", "24"))
MAX_FILES = 300000; MAX_HASH = 200 * 1024 * 1024
if WIN:
    R = os.environ.get("SystemRoot", r"C:\Windows")
    DEFAULT = [(R + r"\System32\drivers\etc", True), (R + r"\System32\Tasks", True), (R + r"\System32", False),
               (os.environ.get("ProgramData", r"C:\ProgramData") + r"\Microsoft\Windows\Start Menu\Programs\Startup", True)]
    EXCL = ["*.log", "*.tmp", "*.etl", "*.evtx"]
    CRIT = [r"\drivers\etc\hosts", r"\start menu\programs\startup", "\\system32\\tasks\\"]
else:
    DEFAULT = [(p, True) for p in ("/etc", "/bin", "/sbin", "/usr/bin", "/usr/sbin", "/usr/local/bin", "/usr/local/sbin", "/root/.ssh", "/var/spool/cron")] + [(p, True) for p in glob.glob("/home/*/.ssh")]
    EXCL = ["/etc/mtab", "/etc/resolv.conf", "/etc/machine-id", "/etc/ld.so.cache", "/etc/adjtime", "/etc/alternatives/*", "/etc/ssl/certs/*", "/etc/apparmor.d/cache/*",
            "/etc/cups/*", "/etc/lvm/cache/*", "*.swp", "*.dpkg-*", "*.tmp", "/etc/.pwd.lock", "/etc/passwd-", "/etc/shadow-", "/etc/group-", "/etc/gshadow-"]
    CRIT = ["/etc/passwd", "/etc/shadow", "/etc/group", "/etc/gshadow", "/etc/sudoers", "/etc/ssh/", "/etc/cron", "/etc/systemd/system", "/etc/hosts", "/etc/ld.so.preload",
            "/etc/pam.d/", "/etc/rc.local", "/etc/init.d/", "/etc/profile", "/var/spool/cron", "/.ssh/"]
    BINDIRS = ("/bin/", "/sbin/", "/usr/bin/", "/usr/sbin/", "/usr/local/bin/", "/usr/local/sbin/")
    PKGDBS = ["/var/lib/dpkg/status", "/var/lib/rpm/rpmdb.sqlite", "/var/lib/rpm/Packages", "/lib/apk/db/installed"]

def paths():
    env = os.environ.get("SOC_FIM_PATHS", "").strip()
    return [(p, True) for p in env.split(os.pathsep) if p] if env else DEFAULT
def excludes(): return EXCL + [e.strip() for e in os.environ.get("SOC_FIM_EXCLUDE", "").split(",") if e.strip()]

def pkg_activity(within):
    if WIN: return False
    return any(os.path.exists(p) and time.time() - os.path.getmtime(p) < within for p in PKGDBS)

def critical(path, action, pkg_busy):
    p = path if not WIN else path.lower()
    if any((c in p if c.startswith("/.") or WIN else p.startswith(c)) for c in CRIT): return True
    if p.endswith("/authorized_keys"): return True
    if not WIN and p.startswith(BINDIRS) and not pkg_busy: return True          # binary changed / added outside a package update
    return False

# ---- Windows built-in scheduled tasks: Windows itself rewrites these files (licensing, telemetry, updates), so a hash change alone is NOT critical ----
TASK_DIR = "\\system32\\tasks\\microsoft\\windows\\"
RISKY_BIN = {"powershell.exe", "pwsh.exe", "cmd.exe", "wscript.exe", "cscript.exe", "mshta.exe", "regsvr32.exe", "rundll32.exe", "bitsadmin.exe", "certutil.exe", "wmic.exe", "msiexec.exe", "curl.exe"}
RISKY_ARGS = re.compile(r"https?://|-enc\b|-encodedcommand|frombase64|downloadstring|\\temp\\|\\users\\|\\appdata\\|\\programdata\\|\\public\\|\\downloads\\|iex\b", re.I)

def builtin_task_ok(path, action):
    """True only when a MODIFIED file under Tasks\\Microsoft\\Windows is a normal Windows task: every action runs a binary inside %SystemRoot%
    (or Windows Defender / Windows Kits), that binary is not a shell/script host/LOLBin and the arguments contain no download/encoded/temp/user-path pattern.
    Anything unreadable, unparsable, new (CREATED), deleted or suspicious stays CRITICAL."""
    if not WIN or action != "MODIFIED" or TASK_DIR not in path.lower(): return False
    try:
        import xml.etree.ElementTree as ET
        raw = open(path, "rb").read(200000)
        txt = raw.decode("utf-16", "ignore") if raw[:2] in (b"\xff\xfe", b"\xfe\xff") else raw.decode("utf-8", "ignore")
        root = ET.fromstring(txt.lstrip("\ufeff"))
        ns = root.tag.split("}")[0] + "}" if root.tag.startswith("{") else ""
        cmds = [(c.findtext(ns + "Command") or "", c.findtext(ns + "Arguments") or "") for c in root.iter(ns + "Exec")]
        if not cmds: return False                                   # COM-handler / empty tasks: cannot verify, stay critical
        win = os.environ.get("SystemRoot", r"C:\Windows").lower(); pf = (os.environ.get("ProgramFiles", r"C:\Program Files")).lower()
        for cmd, args in cmds:
            c = os.path.expandvars(cmd.strip().strip('"')).lower().replace("/", "\\")
            if not (c.startswith(win + "\\") or c.startswith(pf + "\\windows defender\\") or c.startswith(pf + "\\windows kits\\")): return False
            if ntpath.basename(c) in RISKY_BIN or RISKY_ARGS.search(args or "") or RISKY_ARGS.search(c): return False
        return True
    except Exception: return False

def sha256(p):
    h = hashlib.sha256()
    with open(p, "rb") as f:
        for b in iter(lambda: f.read(1 << 20), b""): h.update(b)
    return h.hexdigest()

class FimScanner(BackgroundScanner):
    name = "fim"; interval = INTERVAL
    def scan(self, state):
        old = (state or {}).get("files"); first = old is None; full = first or time.time() - (state or {}).get("last_full", 0) > FULL_H * 3600
        new = {}; ex = excludes(); n = 0
        for root, rec in paths():
            stack = [root]
            while stack and n < MAX_FILES:
                d = stack.pop()
                try: it = list(os.scandir(d))
                except (OSError, PermissionError): continue
                for e in it:
                    fp = e.path
                    if any(fnmatch.fnmatch(fp, g) for g in ex): continue
                    try:
                        st = e.stat(follow_symlinks=False)
                        if e.is_dir(follow_symlinks=False):
                            if rec: stack.append(fp)
                            continue
                        n += 1; prev = (old or {}).get(fp)
                        if e.is_symlink(): h = "link:" + os.readlink(fp)
                        elif not e.is_file(follow_symlinks=False): continue
                        elif prev and not full and prev[1] == st.st_size and prev[2] == st.st_mtime_ns: h = prev[0]
                        elif st.st_size > MAX_HASH: h = "size:%d" % st.st_size
                        else:
                            try: h = sha256(fp)
                            except (OSError, PermissionError): h = "unreadable"
                        new[fp] = [h, st.st_size, st.st_mtime_ns, st.st_mode & 0o7777, getattr(st, "st_uid", 0)]
                    except OSError: continue
        ns = {"files": new, "last_full": time.time() if full else (state or {}).get("last_full", 0), "built": (state or {}).get("built") or time.time()}
        if first: return [], ns                                     # baseline only
        busy = pkg_activity(2 * INTERVAL + 1800); ch = []
        for p, v in new.items():
            o = old.get(p)
            if o is None: ch.append(("CREATED", p, None, v, 1))
            elif o[0] != v[0]: ch.append(("MODIFIED", p, o, v, 2))
            elif o[3] != v[3] or o[4] != v[4]: ch.append(("PERMISSIONS", p, o, v, 4))
        ch += [("DELETED", p, old[p], None, 3) for p in old if p not in new]
        items = []; alerts = 0
        for act, p, o, v, eid in ch:
            crit = critical(p, act, busy); expected = crit and builtin_task_ok(p, act)
            if expected: crit = False                                # recorded as a normal log (never dropped), just not an alert
            can_alert = crit and alerts < 25; alerts += can_alert
            oh = (o[0][:12] if o else "-"); nh = (v[0][:12] if v else "-")
            msg = f"File integrity change: {act} {p}" + (" (CRITICAL file)" if crit else (" (expected: built-in Windows task, action verified inside %SystemRoot%)" if expected else "")) + (f" sha256 {oh} -> {nh}" if act in ("MODIFIED", "CREATED") else "") + (f" size {o[1]} -> {v[1]}" if o and v and o[1] != v[1] else "")
            items.append({"source_ip": None, "message": msg, "channel": "fim", "event_id": eid, "level": "Warning" if crit else "Information", "provider": "EXESOC-FIM",
                          "record_id": rid(p, act, nh, v[2] if v else 0, o[0] if o else ""), "event_time": iso(v[2] / 1e9 if v else None),
                          "raw": '{"path": %s, "action": "%s", "old_sha256": "%s", "new_sha256": "%s"}' % (__import__("json").dumps(p), act, o[0] if o else "", v[0] if v else ""), "log_only": not can_alert})
        if len(ch) > 200:
            items.append({"source_ip": None, "message": f"File integrity scan: {len(ch)} files changed in one scan (package update, software install or tampering)", "channel": "fim", "event_id": 0,
                          "level": "Information", "provider": "EXESOC-FIM", "record_id": rid("mass", time.time()), "event_time": iso(), "raw": "{}", "log_only": True})
        if items: print(f"fim: {len(ch)} change(s) found, {alerts} alert-worthy")
        return items, ns
