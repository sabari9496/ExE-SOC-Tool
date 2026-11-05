"""Activity normalizer: turns any stored event (Windows Event Log, Linux journal/files, FIM, malware scan, syslog, process and network monitor)
into a standard endpoint ACTIVITY: category, activity name, user, status, risk and (only for really suspicious things) an alert suggestion.
Pure functions, no database access. Unrecognised events return None (they stay in the Logs page only).
Categories: User, Process, File, Network, Authentication, Privilege, System.   Risk: Normal < Low < Medium < High < Critical."""
import re, json

RISKS = ["Normal", "Low", "Medium", "High", "Critical"]
CATEGORIES = ["User", "Process", "File", "Network", "Authentication", "Privilege", "System"]
ADMIN_GROUPS = ("administrators", "domain admins", "enterprise admins", "schema admins", "sudo", "wheel", "admin", "root")

# ---------------- suspicious command / process patterns ----------------
CMD_RULES = [
 (r"mimikatz|sekurlsa|lsadump::|procdump.{0,60}lsass|comsvcs\.dll.{0,40}minidump|reg(\.exe)?\s+save\s+hklm\\(sam|security|system)|ntdsutil.{0,40}ifm", "Credential Dumping Attempt", "Critical"),
 (r"vssadmin(\.exe)?\s+delete\s+shadows|wbadmin\s+delete\s+(catalog|backup)|bcdedit.{0,60}(recoveryenabled\s+no|bootstatuspolicy\s+ignoreallfailures)", "Backup / Recovery Destruction Command", "Critical"),
 (r"bash\s+-i\s*>&\s*/dev/tcp/|/dev/tcp/\d{1,3}\.|\bnc(at)?\b.{0,40}\s-(e|c)\s*\S*(sh|bash|cmd)|socat.{0,60}exec:|python[\d.]*\s+-c\s+.{0,120}socket.{0,120}(connect|subprocess|pty)|perl\s+-e\s+.{0,80}socket|php\s+-r\s+.{0,60}fsockopen|mkfifo\s+/tmp/\S+.{0,40}\bnc\b", "Reverse Shell Command", "Critical"),
 (r"(powershell|pwsh)(\.exe)?\b.{0,200}\s-(e|ec|enc|encodedcommand)\s+[A-Za-z0-9+/=]{20,}", "Suspicious PowerShell (encoded command)", "High"),
 (r"(iex|invoke-expression)\b.{0,200}(downloadstring|downloadfile|net\.webclient|invoke-webrequest|\biwr\b)|downloadstring\s*\(|frombase64string.{0,120}(iex|invoke-expression)|-w(indowstyle)?\s+hidden.{0,120}(http|iex)", "Suspicious PowerShell (download and execute)", "High"),
 (r"certutil.{0,60}-(urlcache|decode)|bitsadmin.{0,60}/transfer|mshta(\.exe)?\s+(https?:|vbscript:|javascript:)|regsvr32.{0,60}/i:https?:|rundll32.{0,40}javascript:|wmic.{0,40}process\s+call\s+create", "Suspicious Command (living-off-the-land)", "High"),
 (r"(curl|wget)\b[^|;]{0,200}\|\s*(sudo\s+)?(ba|z)?sh\b|base64\s+(-d|--decode)[^|]{0,100}\|\s*(ba)?sh\b", "Remote Script Download and Execute", "High"),
 (r"net1?(\.exe)?\s+localgroup\s+administrators\s+\S+\s+/add|net1?(\.exe)?\s+user\s+\S+\s+\S+\s+/add", "Local Account Created via Command Line", "High"),
 (r"set-mppreference.{0,60}disable(realtimemonitoring|behaviormonitoring|ioavprotection)|sc(\.exe)?\s+(stop|config)\s+(windefend|sense|wdnissvc)|netsh.{0,20}advfirewall\s+set\s+\w+\s+state\s+off", "Security Tool Tampering Command", "High"),
 (r"\b(cat|less|more|head|tail|cp|scp|base64|strings)\b[^|;&]{0,60}\s/etc/shadow\b", "Sensitive File Read (/etc/shadow)", "High"),
 (r"\bwevtutil(\.exe)?\s+cl\b|clear-eventlog|\bunset\s+histfile\b|history\s+-c\b|\bshred\b.{0,40}/var/log|>\s*/var/log/(auth\.log|syslog|secure|messages)\b", "Log / History Tampering Command", "High"),
]
CMD_RX = [(re.compile(p, re.I), t, s) for p, t, s in CMD_RULES]
TMP_EXE = re.compile(r"^(/tmp/|/var/tmp/|/dev/shm/)|\\(temp|downloads|public|appdata\\local\\temp)\\[^\\]*\.(exe|scr|bat|cmd|ps1|vbs|js|jse|wsf|hta|dll)$", re.I)
OFFICE = ("winword.exe", "excel.exe", "powerpnt.exe", "outlook.exe", "onenote.exe")
SHELLS = ("cmd.exe", "powershell.exe", "pwsh.exe", "wscript.exe", "cscript.exe", "mshta.exe", "sh", "bash", "dash", "zsh", "nc", "ncat", "python", "python3", "perl")
WEBSRV = ("nginx", "apache2", "httpd", "php-fpm", "php-fpm8", "php", "tomcat", "java", "w3wp.exe")
BAD_PORTS = {4444, 1337, 31337, 6667, 6697, 5555, 9001, 12345, 2323}
SUSP_PS = re.compile(r"-enc(odedcommand)?\s|frombase64string|downloadstring|invoke-mimikatz|invoke-expression|\biex\b|net\.webclient|amsiutils|-nop\b.*-w(indowstyle)?\s+hidden|add-mppreference\s+-exclusion", re.I)

def _j(raw):
    if isinstance(raw, dict): return raw
    try:
        d = json.loads(raw) if raw else {}
        return d if isinstance(d, dict) else {}
    except Exception: return {}

def _base(p): return re.split(r"[\\/]", p or "")[-1].lower()
def _user(u):
    u = (u or "").strip()
    return u.split("\\")[-1] if u and u not in ("-", "N/A") else None
def _t(s, n=300): return (s or "")[:n]

def _cmd_check(exe, cmd, parent, user, host):
    """-> (title, severity, why) or None for a started process."""
    line = f"{exe or ''} {cmd or ''}".strip()
    for rx, t, s in CMD_RX:
        if rx.search(line): return t, s, _t(line, 200)
    b, pb = _base(exe), _base(parent)
    if pb in OFFICE and b in SHELLS: return "Office Application Spawned a Shell", "High", f"{pb} -> {b}"
    if pb in WEBSRV and b in SHELLS: return "Web Server Spawned a Shell", "High", f"{pb} -> {b}"
    if exe and TMP_EXE.search(exe): return "Process Executed From Temporary Location", "Medium", _t(exe, 200)
    return None

# ---------------- Windows tables ----------------
# (category, activity, status, risk)
SEC = {4624: ("Authentication", "Successful Login", "Success", "Normal"), 4625: ("Authentication", "Failed Login", "Failure", "Medium"),
 4634: ("Authentication", "Logoff", "Success", "Normal"), 4647: ("Authentication", "Logoff", "Success", "Normal"), 4648: ("Authentication", "Login With Explicit Credentials", "Success", "Low"),
 4672: ("Privilege", "Special Privileges Assigned", "Success", "Normal"), 4720: ("User", "User Created", "Success", "Medium"), 4722: ("User", "User Enabled", "Success", "Low"),
 4723: ("User", "Password Change", "Success", "Low"), 4724: ("User", "Password Reset", "Success", "Medium"), 4725: ("User", "User Disabled", "Success", "Low"), 4726: ("User", "User Deleted", "Success", "Medium"),
 4738: ("User", "User Modified", "Success", "Low"), 4740: ("Authentication", "Account Locked Out", "Failure", "Medium"), 4767: ("User", "Account Unlocked", "Success", "Low"),
 4728: ("Privilege", "Group Member Added", "Success", "Low"), 4732: ("Privilege", "Group Member Added", "Success", "Low"), 4756: ("Privilege", "Group Member Added", "Success", "Low"),
 4729: ("Privilege", "Group Member Removed", "Success", "Low"), 4733: ("Privilege", "Group Member Removed", "Success", "Low"), 4757: ("Privilege", "Group Member Removed", "Success", "Low"),
 4727: ("Privilege", "Group Created", "Success", "Low"), 4731: ("Privilege", "Group Created", "Success", "Low"), 4754: ("Privilege", "Group Created", "Success", "Low"),
 4688: ("Process", "Process Started", "Success", "Normal"), 4697: ("System", "Service Installed", "Success", "Medium"), 4698: ("System", "Scheduled Task Created", "Success", "Medium"),
 4699: ("System", "Scheduled Task Deleted", "Success", "Low"), 4700: ("System", "Scheduled Task Enabled", "Success", "Low"), 4701: ("System", "Scheduled Task Disabled", "Success", "Low"), 4702: ("System", "Scheduled Task Updated", "Success", "Low"),
 4719: ("System", "Audit Policy Changed", "Success", "Medium"), 1102: ("System", "Audit Log Cleared", "Success", "High"), 4768: ("Authentication", "Kerberos Ticket Request", "Success", "Normal"),
 4771: ("Authentication", "Kerberos Pre-Authentication Failed", "Failure", "Medium"), 4776: ("Authentication", "Credential Validation", "Success", "Normal"),
 4778: ("Authentication", "Remote Session Reconnected", "Success", "Low"), 4779: ("Authentication", "Remote Session Disconnected", "Success", "Normal"),
 5140: ("Network", "Network Share Accessed", "Success", "Low"), 4946: ("System", "Firewall Rule Added", "Success", "Medium"), 4947: ("System", "Firewall Rule Modified", "Success", "Medium"), 4948: ("System", "Firewall Rule Deleted", "Success", "Medium")}
SYS = {7045: ("System", "Service Installed", "Success", "Medium"), 7036: ("System", "Service State Changed", "Success", "Normal"), 7040: ("System", "Service Start Type Changed", "Success", "Low"),
 7031: ("System", "Service Crashed", "Failure", "Low"), 7034: ("System", "Service Crashed", "Failure", "Low"), 6005: ("System", "System Startup", "Success", "Normal"), 6006: ("System", "System Shutdown", "Success", "Normal"),
 6008: ("System", "Unexpected Shutdown", "Failure", "Low"), 1074: ("System", "Shutdown / Restart Initiated", "Success", "Low"), 41: ("System", "Unexpected Reboot", "Failure", "Low"), 104: ("System", "Audit Log Cleared", "Success", "High")}
DEF = {1116: ("System", "Malware Detected", "Failure", "High"), 1006: ("System", "Malware Detected", "Failure", "High"), 1117: ("System", "Malware Action Taken", "Success", "Medium"), 1007: ("System", "Malware Action Taken", "Success", "Medium"),
 5001: ("System", "Real-time Protection Disabled", "Failure", "High"), 5010: ("System", "Antivirus Scanning Disabled", "Failure", "High"), 5012: ("System", "Antivirus Scanning Disabled", "Failure", "High"),
 1121: ("System", "Attack Surface Rule Blocked", "Failure", "Medium"), 2001: ("System", "Antivirus Update Failed", "Failure", "Low")}
LOGON_T = {"2": "Interactive Login", "10": "Remote Desktop Login", "7": "Workstation Unlock", "11": "Cached Interactive Login", "3": "Network Login", "5": "Service Login", "4": "Batch Login", "8": "Network Cleartext Login", "9": "Login With New Credentials"}

def _win(ch, eid, d, msg, prov, ip):
    lc = ch.lower(); ev = None
    if lc == "security" and eid in SEC: ev = SEC[eid]
    elif lc == "system" and eid in SYS: ev = SYS[eid]
    elif "defender" in lc and eid in DEF: ev = DEF[eid]
    elif lc == "application" and (prov or "").lower() == "msiinstaller" and eid in (11707, 11724, 1033): ev = ("System", "Software Installed" if eid != 11724 else "Software Removed", "Success", "Low")
    elif lc == "application" and eid in (1000, 1001): ev = ("System", "Application Error", "Failure", "Normal")
    elif "powershell" in lc and eid == 4104: ev = ("Process", "PowerShell Script Block", "Success", "Low")
    elif "sysmon" in lc and eid in (1, 3, 8, 10, 11, 13, 22, 23): ev = {1: ("Process", "Process Started", "Success", "Normal"), 3: ("Network", "Network Connection", "Success", "Normal"), 8: ("Process", "Remote Thread Created", "Success", "Medium"),
        10: ("Process", "Process Memory Accessed", "Success", "Normal"), 11: ("File", "File Created", "Success", "Normal"), 13: ("System", "Registry Value Set", "Success", "Normal"), 22: ("Network", "DNS Query", "Success", "Normal"), 23: ("File", "File Deleted", "Success", "Low")}[eid]
    if not ev: return None
    cat, act, st, risk = ev; user = _user(d.get("TargetUserName") if eid in (4624, 4625, 4740, 4720, 4722, 4723, 4724, 4725, 4726, 4738, 4767, 4768, 4771, 4776) else (d.get("SubjectUserName") or d.get("TargetUserName")))
    alert = None; ip = ip or None
    if eid == 4624:
        lt = d.get("LogonType", ""); act = LOGON_T.get(lt, act)
        if lt == "10": risk = "Low"
        if user and user.endswith("$"): risk = "Normal"
    elif eid == 4625: act = "Failed Login" + (" (unknown user)" if d.get("SubStatus") == "0xc0000064" else "")
    elif eid == 4776: user = _user(d.get("TargetUserName")); 
    if eid == 4776 and d.get("Status", "0x0") not in ("0x0", ""): st, risk, act = "Failure", "Medium", "Credential Validation Failed"
    if eid in (4728, 4732, 4756):
        g = (d.get("TargetUserName") or "").lower(); user = _user(d.get("MemberName", "").split(",")[0].replace("CN=", "")) or user
        if g in ADMIN_GROUPS: act, risk = "Admin Added", "High"
    if eid in (4697, 7045):
        path = d.get("ServiceFileName") or d.get("ImagePath") or ""; user = _user(d.get("SubjectUserName")) or user
        if TMP_EXE.search(path) or re.search(r"powershell|cmd\.exe\s*/c|%comspec%", path, re.I): risk = "High"; alert = ("Suspicious Service Installed", "High", "persistence", f"Service installed with suspicious path: {_t(path)}")
    if eid == 4688 or (eid == 1 and "sysmon" in lc):
        exe = d.get("NewProcessName") or d.get("Image") or ""; cmd = d.get("CommandLine") or ""; par = d.get("ParentProcessName") or d.get("ParentImage") or ""
        user = _user(d.get("User") or d.get("SubjectUserName")); act = "Process Started"
        r = _cmd_check(exe, cmd, par, user, None)
        if r: risk = r[1]; alert = (r[0], r[1], "process", f"{r[0]}: {r[2]}" + (f" (user {user})" if user else ""))
    if "powershell" in lc and eid == 4104:
        txt = d.get("ScriptBlockText") or msg or ""
        if SUSP_PS.search(txt): risk = "High"; alert = ("Suspicious PowerShell Script", "High", "process", "Suspicious PowerShell script block: " + _t(txt, 200))
    if "sysmon" in lc and eid == 3:
        ip = ip or d.get("DestinationIp"); user = _user(d.get("User")); img = d.get("Image") or ""
        if _base(img) in SHELLS and ip and not re.match(r"^(10\.|192\.168\.|172\.(1[6-9]|2\d|3[01])\.|127\.|169\.254\.)", ip): risk = "High"; alert = ("Shell Process Network Connection", "High", "network", f"{_base(img)} connected to {ip}:{d.get('DestinationPort','?')}")
    if "sysmon" in lc and eid == 10 and "lsass.exe" in (d.get("TargetImage") or "").lower(): act, risk = "LSASS Memory Accessed", "High"; alert = ("Credential Dumping Attempt", "High", "process", f"{_base(d.get('SourceImage'))} accessed LSASS memory")
    if "sysmon" in lc and eid == 8: alert = ("Remote Thread Injection", "Medium", "process", f"{_base(d.get('SourceImage'))} created a remote thread in {_base(d.get('TargetImage'))}")
    if "sysmon" in lc and eid == 11: user = _user(d.get("User")); act = "File Created"
    if eid == 4740: alert = ("Account Locked Out", "Medium", "auth", f"Account {user} was locked out" + (f" (caller {d.get('TargetDomainName')})" if d.get("TargetDomainName") else ""))
    if eid in (4946, 4947, 4948): risk = "Medium"
    if "defender" in lc and eid in (5001, 5010, 5012): alert = ("Security Tool Disabled", "High", "system", f"Windows Defender protection disabled (event {eid})")
    return dict(category=cat, activity=act, status=st, risk=risk, username=user, alert=alert, src_ip=ip)

# ---------------- Linux / syslog text ----------------
IPR = r"(\d{1,3}(?:\.\d{1,3}){3})"
def _lin(msg, ident, ch, d):
    m = msg; ident = (ident or "").lower(); ip = None
    mi = re.search(r"(?:from|rhost=|rhost =)\s*" + IPR, m); ip = mi.group(1) if mi else None
    r = None
    if (x := re.search(r"Accepted (password|publickey|keyboard-interactive\S*) for (\S+) from " + IPR, m)):
        u = x.group(2); r = ("Authentication", "SSH Login", "Success", "Medium" if u == "root" else "Normal", u, x.group(3))
    elif (x := re.search(r"Failed (\S+) for (?:invalid user )?(\S+) from " + IPR, m)): r = ("Authentication", "Failed Login", "Failure", "Medium", x.group(2), x.group(3))
    elif (x := re.search(r"Invalid user (\S*) from " + IPR, m)): r = ("Authentication", "Login Attempt (invalid user)", "Failure", "Medium", x.group(1), x.group(2))
    elif "authentication failure" in m.lower():
        u = re.search(r"(?:user|ruser)=(\S+)", m); r = ("Authentication", "Failed Login" if "sudo" not in ident else "Failed sudo Authentication", "Failure", "Medium", u.group(1) if u else None, ip)
    elif (x := re.search(r"sudo:?\s+(\S+) : .*?COMMAND=(.*)$", f"{ident}: {m}")) or (ident == "sudo" and (x := re.search(r"(\S+) : .*?COMMAND=(.*)$", m))):
        if "NOT in sudoers" in m or "not allowed" in m.lower(): r = ("Privilege", "Sudo Denied", "Failure", "High", x.group(1), None)
        else: r = ("Privilege", "Sudo Command", "Success", "Medium", x.group(1), None)
    elif re.search(r"not in the sudoers|NOT in sudoers", m): u = re.match(r"(\S+) :", m); r = ("Privilege", "Sudo Denied", "Failure", "High", u.group(1) if u else None, None)
    elif (x := re.search(r"\(to (\S+)\) (\S+) on", m)) and ident in ("su", "su-l"): r = ("Privilege", "Switch User", "Success", "Medium", x.group(2), None)
    elif ident.startswith("su") and re.search(r"FAILED SU|authentication failure", m): r = ("Privilege", "Failed Switch User", "Failure", "High", None, None)
    elif (x := re.search(r"new user: name=([^,\s]+)", m)): r = ("User", "User Created", "Success", "Medium", x.group(1), None)
    elif (x := re.search(r"delete user '([^']+)'|userdel.*?'([^']+)'", m)): r = ("User", "User Deleted", "Success", "Medium", x.group(1) or x.group(2), None)
    elif (x := re.search(r"password changed for (\S+)", m)): r = ("User", "Password Change", "Success", "Low", x.group(1), None)
    elif (x := re.search(r"add '([^']+)' to (?:shadow )?group '([^']+)'", m)) or (x := re.search(r"user (\S+) added by \S+ to group (\S+)", m)):
        a = x.group(2).lower() in ADMIN_GROUPS; r = ("Privilege", "Admin Added" if a else "Group Member Added", "Success", "High" if a else "Low", x.group(1), None)
    elif ident in ("cron", "crond") and (x := re.search(r"\((\S+)\) CMD \((.*)\)", m)): r = ("Process", "Cron Job Executed", "Success", "Normal", x.group(1), None)
    elif re.search(r"session opened for user (\S+)", m) and "pam" in m: x = re.search(r"session opened for user (\S+)", m); r = ("Authentication", "Session Opened", "Success", "Normal", x.group(1).split("(")[0], None)
    elif re.search(r"session closed for user (\S+)", m) and "pam" in m: x = re.search(r"session closed for user (\S+)", m); r = ("Authentication", "Session Closed", "Success", "Normal", x.group(1), None)
    elif (x := re.search(r"(Started|Stopped|Starting|Stopping) (.+?)\.?$", m)) and ident == "systemd": r = ("System", "Service " + ("Started" if x.group(1).startswith("Start") else "Stopped"), "Success", "Normal", None, None)
    elif ident == "systemd" and re.search(r"Failed with result|entered failed state|Failed to start", m): r = ("System", "Service Failed", "Failure", "Low", None, None)
    elif re.search(r"\[UFW (BLOCK|ALLOW)\]", m):
        s = re.search(r"SRC=" + IPR, m); dpt = re.search(r"DPT=(\d+)", m); r = ("Network", "Firewall " + re.search(r"UFW (\w+)", m).group(1).title(), "Failure" if "BLOCK" in m else "Success", "Low" if "BLOCK" in m else "Normal", None, s.group(1) if s else ip)
    elif ident == "kernel" and re.search(r"new (high|full|low)[- ]?speed USB device|New USB device found|usb \d+-\d+: Product", m, re.I): r = ("System", "USB Device Connected", "Success", "Low", None, None)
    elif ident == "kernel" and re.search(r"Out of memory|Killed process", m): r = ("System", "Out Of Memory", "Failure", "Low", None, None)
    elif ident in ("kernel",) and re.search(r"segfault", m): r = ("System", "Application Crash", "Failure", "Low", None, None)
    elif ident == "systemd-logind" and (x := re.search(r"New session \S+ of user (\S+)", m)): r = ("Authentication", "Session Opened", "Success", "Normal", x.group(1), None)
    elif "type=EXECVE" in m: args = re.findall(r'a\d+="([^"]*)"', m); r = ("Process", "Process Started", "Success", "Normal", None, None); d = {"cmdline": " ".join(args)}
    elif "type=USER_CMD" in m: x = re.search(r'cmd=([0-9A-F]+|"[^"]*")', m); r = ("Privilege", "Sudo Command", "Success", "Medium", (re.search(r'acct="([^"]*)"', m) or [None, None])[1], None)
    if not r: return None
    cat, act, st, risk, user, rip = r; ip = rip or ip; alert = None
    if act == "Admin Added": alert = None                      # existing 'Privilege Escalation' rule alerts on it
    return dict(category=cat, activity=act, status=st, risk=risk, username=user, alert=alert, src_ip=ip, _d=d)

def normalize(item):
    """item: dict with message, channel, event_id, provider, raw, source_ip, host -> activity dict or None."""
    try: return _normalize(item)
    except Exception: return None

def _normalize(it):
    ch = it.get("channel") or ""; msg = it.get("message") or ""; eid = it.get("event_id"); d = _j(it.get("raw")); prov = it.get("provider") or ""; ip = it.get("source_ip")
    out = None
    if ch in ("process", "network"): out = _agent(ch, d, ip)
    elif ch == "fim": out = _fim(it, d)
    elif ch == "malware": out = dict(category="File", activity="Malware Detected", status="Failure", risk="Critical", username=None, alert=None, src_ip=None)
    elif eid is not None and ch and not ch.startswith(("file:", "journald", "syslog")): out = _win(ch, int(eid), d, msg, prov, ip); osn = "Windows"
    elif ch.startswith("file:") and re.search(r"(access|error)[_.]log$|nginx|apache|httpd", ch):
        out = None
        if not it.get("log_only", True): out = dict(category="Network", activity="Web Attack Request", status="Failure", risk="High", username=None, alert=None, src_ip=ip)
    else: out = _lin(msg, prov or ch.replace("file:", "").split("/")[-1], ch, d)
    if not out: return None
    out.pop("_d", None)
    out["os"] = "Windows" if (eid is not None and not ch.startswith(("file:", "journald", "syslog", "fim", "malware", "process", "network"))) or d.get("os") == "Windows" else ("Linux" if ch.startswith(("file:", "journald", "syslog")) or d.get("os") == "Linux" else d.get("os") or None)
    if out["category"] == "Process" and out["activity"] == "Process Started" and not out.get("alert") and ch.startswith(("file:", "journald")):
        r = _cmd_check(None, d.get("cmdline"), None, out.get("username"), None)
        if r: out["risk"] = r[1]; out["alert"] = (r[0], r[1], "process", f"{r[0]}: {r[2]}")
    return out

def _agent(ch, d, ip):
    if ch == "process":
        exe, cmd, par, user = d.get("exe") or d.get("name") or "", d.get("cmdline") or "", d.get("parent") or "", _user(d.get("user"))
        out = dict(category="Process", activity="Process Started", status="Success", risk="Normal", username=user, alert=None, src_ip=None)
        r = _cmd_check(exe, cmd, par, user, None)
        if r: out["risk"] = r[1]; out["alert"] = (r[0], r[1], "process", f"{r[0]}: {r[2]}" + (f" (user {user}, parent {par})" if user else ""))
        return out
    act = d.get("kind") or "Outbound Connection"; port = int(d.get("rport") or 0); rip = d.get("raddr"); name = (d.get("name") or "").lower()
    out = dict(category="Network", activity=act, status="Success", risk="Normal", username=_user(d.get("user")), alert=None, src_ip=rip)
    if act == "New Listening Port": out["risk"] = "Low" if int(d.get("lport") or 0) < 1024 or int(d.get("lport") or 0) in BAD_PORTS else "Normal"; out["src_ip"] = None
    elif rip and not re.match(r"^(10\.|192\.168\.|172\.(1[6-9]|2\d|3[01])\.|127\.|169\.254\.|fe80|::1|fc|fd)", rip):
        if name in [s.lower() for s in SHELLS] or name.rstrip(".exe") in ("bash", "sh", "nc", "ncat", "powershell", "cmd"):
            out["risk"] = "High"; out["alert"] = ("Shell Process Network Connection", "High", "network", f"{d.get('name')} (pid {d.get('pid')}) connected to {rip}:{port}")
        elif port in BAD_PORTS: out["risk"] = "Medium"; out["alert"] = ("Connection To Suspicious Port", "Medium", "network", f"{d.get('name')} connected to {rip}:{port}")
    return out

def _fim(it, d):
    act = {"CREATED": "File Created", "MODIFIED": "File Modified", "DELETED": "File Deleted", "PERMISSIONS": "File Permissions Changed"}.get(d.get("action", ""), "File Changed")
    crit = "(CRITICAL file)" in (it.get("message") or "")
    return dict(category="File", activity=act, status="Success", risk="High" if crit else "Low", username=None, alert=None, src_ip=None)

def order(r): return RISKS.index(r) if r in RISKS else 0
