"""Rule library: ready-made triggering rules, each mapped to the ATTACK it detects.

Nothing here runs by itself. A rule only starts raising alerts after you ADD it
(it is copied into the custom_rules table, which the engine already evaluates):

    python rules_library.py list                    # all rules grouped by attack
    python rules_library.py add R012                # add one rule
    python rules_library.py add-attack "Brute Force"  # add every rule for one attack
    python rules_library.py add-all                 # add everything
    python rules_library.py remove R012             # remove it again

Or from code / the API:  rules_library.add_rule("R012"), POST /api/rule-library/add

PLAYBOOKS (automatic response) work the same way, one playbook per attack:
    python rules_library.py pb-list                 # playbooks, with the attack and the rules that trigger each
    python rules_library.py pb-add P003             # add one playbook
    python rules_library.py pb-add-attack Ransomware
    python rules_library.py pb-add-all
    python rules_library.py pb-remove P003
A library playbook fires ONLY for the alerts of its own attack (the detection rules listed in it),
at or above its trigger severity. Actions: block_ip, create_case, notify, isolate_endpoint.

To define a NEW rule, append one R(...) line to LIBRARY below. To define a NEW playbook, append one PB(...) line to PLAYBOOKS.
Fields: id, attack, mitre, name, match ("contains" | "regex"), pattern, severity,
        category, threshold (N matches), window_min (within M minutes), event_id, what.
Custom rules run only when no built-in rule fired for the same event, so attacks the
built-ins already catch (plain SSH "Failed password", nmap/masscan, SQL "union select",
XSS "<script") are NOT repeated here; this library covers what they miss.
"""
import re

def R(id, attack, mitre, name, match, pattern, severity, category, what, threshold=1, window_min=5, event_id=None):
    return dict(id=id, attack=attack, mitre=mitre, name=name, match_type=match, pattern=pattern, severity=severity,
                category=category, what=what, threshold=threshold, window_min=window_min, event_id=event_id)

TAG = "[LIB:%s] "   # prefix stored in the rule description so library rules can be found/removed later

LIBRARY = [
    # ---- Brute force / password attacks -------------------------------------------------
    R("R002", "Brute Force", "T1110.003", "Password Spraying", "regex", r"(logon failure|failed logon|4625).*(unknown user name or bad password|0xC000006A)", "High", "auth",
      "Windows logon failures with bad password, repeated from one source.", threshold=10, window_min=10),
    R("R003", "Brute Force", "T1110.001", "RDP Brute Force", "regex", r"(logon type:?\s*10|ts_logon|rdp).*(fail|denied)", "High", "auth",
      "Repeated failed Remote Desktop logins.", threshold=5, window_min=5),
    # ---- Web application attacks ---------------------------------------------------------
    R("R010", "SQL Injection", "T1190", "SQLi - Time-Based / Blind", "regex", r"sleep\(\d+\)|benchmark\(|waitfor\s+delay|pg_sleep", "Critical", "web",
      "Blind SQL injection payloads in a request."),
    R("R011", "SQL Injection", "T1190", "SQLi - Information Schema Probe", "regex", r"information_schema|sqlite_master|xp_cmdshell|load_file\(", "Critical", "web",
      "Attacker enumerating the database."),
    R("R012", "Command Injection", "T1190", "Web Command Injection", "regex", r"(;|\||`|\$\()\s*(cat|ls|id|whoami|wget|curl|nc|bash|sh)\b", "Critical", "web",
      "Shell command appended to a web request."),
    R("R013", "Log4Shell / JNDI Injection", "T1190", "Log4Shell JNDI Lookup", "regex", r"\$\{jndi:(ldap|rmi|dns|ldaps)", "Critical", "web",
      "CVE-2021-44228 exploitation attempt."),
    R("R014", "Local / Remote File Inclusion", "T1190", "File Inclusion Attempt", "regex", r"(include|file|page|path)=(https?://|php://|file://|expect://|data://)", "High", "web",
      "LFI/RFI wrappers in a parameter."),
    R("R015", "Web Scanner / Recon", "T1595.002", "Vulnerability Scanner User-Agent", "regex", r"nikto|sqlmap|acunetix|nessus|wpscan|dirbuster|gobuster|nuclei|zgrab", "Medium", "web",
      "Known scanner user-agent in web logs."),
    R("R016", "Web Shell", "T1505.003", "Web Shell Access", "regex", r"(c99|r57|wso|b374k|china ?chopper)\.(php|asp|jsp)|cmd=(whoami|id|ls|dir)", "Critical", "web",
      "Request to a known web shell or with a command parameter."),
    R("R017", "Server-Side Request Forgery", "T1190", "SSRF to Cloud Metadata", "regex", r"169\.254\.169\.254|metadata\.google\.internal", "High", "web",
      "Request trying to reach the cloud metadata service."),
    R("R018", "Cross-Site Scripting", "T1189", "XSS - Encoded Payload", "regex", r"%3cscript|&#x3c;script|<svg[^>]*onload|<img[^>]*onerror", "Medium", "web",
      "Encoded or alternate-tag XSS payload."),
    # ---- Reconnaissance / discovery ------------------------------------------------------
    R("R020", "Port Scan", "T1046", "Firewall Block Burst (Scan)", "regex", r"(ufw block|dropped|deny).*(src=|from )", "Medium", "network",
      "Many firewall drops from the same source.", threshold=20, window_min=2),
    R("R021", "Account Discovery", "T1087", "User / Group Enumeration Command", "regex", r"\b(net user|net group|net localgroup|getent passwd|cat /etc/passwd|whoami /all)\b", "Low", "process",
      "Commands used to list accounts."),
    R("R022", "Network Discovery", "T1018", "Network Recon Tool Run", "regex", r"\b(arp-scan|netdiscover|fping|zmap|rustscan|unicornscan)\b", "Medium", "process",
      "Scanning tool executed on a host."),
    # ---- Execution -----------------------------------------------------------------------
    R("R030", "Malicious Script Execution", "T1059.005", "WScript / CScript Running Script", "regex", r"\b(wscript|cscript)(\.exe)?\b.*\.(vbs|vbe|js|jse|wsf)", "High", "process",
      "Windows Script Host running a script file."),
    R("R031", "Malicious Script Execution", "T1059.001", "PowerShell Execution Policy Bypass", "regex", r"powershell.*(-ep|-executionpolicy)\s+bypass|-nop\b.*-w\s+hidden", "High", "process",
      "PowerShell started with policy bypass or hidden window."),
    R("R032", "Scheduled Task Abuse", "T1053.005", "Scheduled Task Created", "regex", r"schtasks(\.exe)?\s+/create|4698|crontab -[el]?.*\*", "Medium", "persistence",
      "New scheduled task or cron entry, a common persistence method."),
    # ---- Persistence ---------------------------------------------------------------------
    R("R040", "Registry Run Key Persistence", "T1547.001", "Run Key Modified", "regex", r"(currentversion\\run(once)?|reg add .*\\run\b)", "High", "persistence",
      "Program added to a Windows startup registry key."),
    R("R041", "SSH Key Persistence", "T1098.004", "authorized_keys Modified", "regex", r"authorized_keys", "High", "persistence",
      "SSH authorized_keys touched, may add attacker access."),
    R("R042", "Account Manipulation", "T1098", "User Added to Admin Group", "regex", r"(added to|member of).*(administrators|sudo|wheel)|usermod -a?G? ?(sudo|wheel)", "High", "persistence",
      "A user gained admin rights."),
    # ---- Privilege escalation ------------------------------------------------------------
    R("R050", "Privilege Escalation", "T1548.003", "Sudo Abuse / Shell via Sudo", "regex", r"sudo:.*COMMAND=.*(/bin/(ba)?sh|/bin/su\b|vi |vim |find .* -exec)", "High", "system",
      "Root shell obtained through sudo."),
    R("R051", "Privilege Escalation", "T1548.001", "SUID Bit Set", "regex", r"chmod\s+(u\+s|[2467]\d{3})\b", "High", "system",
      "SUID/SGID set on a file, used for privilege escalation."),
    # ---- Credential access ---------------------------------------------------------------
    R("R060", "Credential Dumping", "T1003.001", "LSASS Memory Dump", "regex", r"(procdump|comsvcs\.dll.*minidump|rundll32.*lsass|sekurlsa|lsass\.dmp)", "Critical", "process",
      "Attempt to dump credentials from LSASS."),
    R("R061", "Credential Dumping", "T1003.002", "SAM / SYSTEM Hive Export", "regex", r"reg(\.exe)?\s+save\s+hk(lm|ey_local_machine)\\(sam|system|security)", "Critical", "process",
      "Registry hives exported to steal password hashes."),
    R("R062", "Kerberoasting", "T1558.003", "Kerberos RC4 Service Ticket Request", "regex", r"4769.*0x17|rubeus|invoke-kerberoast", "High", "auth",
      "Service ticket with weak encryption, typical of Kerberoasting."),
    # ---- Defense evasion -----------------------------------------------------------------
    R("R070", "Log Tampering", "T1070.002", "Linux Log Wiped", "regex", r"(rm|shred|truncate|>)\s+.*(/var/log/|\.bash_history|auth\.log|wtmp|lastlog)", "High", "system",
      "System logs deleted or emptied."),
    R("R071", "Disable Security Tools", "T1562.004", "Firewall Disabled", "regex", r"(ufw disable|systemctl (stop|disable) (ufw|firewalld|iptables)|netsh .*firewall.*state off|iptables -F)", "High", "system",
      "Host firewall switched off or flushed."),
    R("R072", "Disable Security Tools", "T1562.001", "AV / EDR Service Stopped", "regex", r"(stop|disable|kill).*(defender|windefend|clamav|clamd|falcon|sentinel|auditd)", "High", "system",
      "Security agent service stopped."),
    # ---- Lateral movement ----------------------------------------------------------------
    R("R080", "Lateral Movement", "T1021.002", "PsExec / Remote Service Execution", "regex", r"psexe(c|svc)|\\admin\$|sc(\.exe)?\s+\\\\\S+\s+create", "High", "process",
      "Remote execution over SMB admin shares."),
    R("R081", "Lateral Movement", "T1021.006", "WinRM Remote Command", "regex", r"winrm|enter-pssession|invoke-command\s+-computername", "Medium", "process",
      "Remote PowerShell session to another host."),
    # ---- Command and control / exfiltration ----------------------------------------------
    R("R090", "Command and Control", "T1572", "Tunnel / Proxy Tool", "regex", r"\b(ngrok|chisel|plink -R|ssh .* -R \d+:|frpc|iodine|dnscat)\b", "High", "network",
      "Tunnelling tool used to hide traffic."),
    R("R091", "Data Exfiltration", "T1048", "Large Archive Before Upload", "regex", r"(7z|zip|tar|rar)\s+.*(-p|-czf|a )\s*\S+.*(/home|documents|\\users)", "Medium", "process",
      "Data compressed, possibly staged for exfiltration."),
    R("R092", "Data Exfiltration", "T1567.002", "Upload to Cloud Storage Tool", "regex", r"\b(rclone|megacmd|mega-put)\b|transfer\.sh|file\.io|anonfiles", "High", "network",
      "Upload tool or anonymous file host used."),
    # ---- Impact (ransomware, DoS) --------------------------------------------------------
    R("R100", "Ransomware", "T1486", "Ransom Note / Encrypted Extension", "regex", r"(how_to_decrypt|readme_to_restore|decrypt_instructions|\.(locked|encrypted|crypt|lockbit|wncry))\b", "Critical", "malware",
      "Ransom note or encrypted-file extension seen."),
    R("R101", "Ransomware", "T1490", "Shadow Copy Deleted", "regex", r"vssadmin.*delete shadows|wmic shadowcopy delete|bcdedit.*recoveryenabled\s+no|wbadmin delete", "Critical", "process",
      "Backups removed before encryption."),
    R("R102", "Denial of Service", "T1498", "HTTP Request Flood", "regex", r"\"(GET|POST) ", "High", "web",
      "Very many web requests from one IP.", threshold=200, window_min=1),
    # ---- Cryptomining --------------------------------------------------------------------
    R("R110", "Cryptomining", "T1496", "Miner Process / Pool Connection", "regex", r"xmrig|minerd|stratum\+tcp|cpuminer|nicehash|monero", "High", "malware",
      "Cryptominer running or connecting to a mining pool."),
]

BY_ID = {r["id"]: r for r in LIBRARY}


def validate():
    """Sanity check the library itself: unique ids, valid regex, valid MITRE id. Returns list of problems."""
    bad, seen = [], set()
    for r in LIBRARY:
        if r["id"] in seen: bad.append(f"{r['id']}: duplicate id")
        seen.add(r["id"])
        if not re.fullmatch(r"T\d{4}(\.\d{3})?", r["mitre"]): bad.append(f"{r['id']}: bad MITRE id {r['mitre']}")
        if r["match_type"] == "regex":
            try: re.compile(r["pattern"], re.I)
            except re.error as ex: bad.append(f"{r['id']}: bad regex ({ex})")
        if r["severity"] not in ("Critical", "High", "Medium", "Low"): bad.append(f"{r['id']}: bad severity")
    return bad


# ---------------------------------------------------------------- database functions
def _db():
    from db import q, x, now
    return q, x, now


def _changed():
    try:
        import engine; engine.custom_rules_changed()
    except Exception: pass


def installed():
    """{library id: custom_rules row} for library rules already added."""
    q, _, _ = _db()
    out = {}
    for row in q("SELECT * FROM custom_rules WHERE description LIKE '[LIB:%'"):
        m = re.match(r"\[LIB:(R\d+)\]", row["description"])
        if m: out[m.group(1)] = row
    return out


def catalog():
    """Library with an 'added' / 'enabled' flag per rule, grouped data for the UI."""
    have = installed()
    return [dict(r, added=r["id"] in have, enabled=bool(have[r["id"]]["enabled"]) if r["id"] in have else False,
                 hits=have[r["id"]]["hits"] if r["id"] in have else 0,
                 playbooks=[p["id"] for p in PLAYBOOKS if r["name"] in pb_titles(p)]) for r in LIBRARY]


def add_rule(rule_id, user="system", enabled=True):
    """Copy one library rule into custom_rules. Returns (ok, message)."""
    r = BY_ID.get(rule_id.upper())
    if not r: return False, f"unknown rule {rule_id}"
    if r["id"] in installed(): return False, f"{r['id']} already added"
    q, x, now = _db()
    x("INSERT INTO custom_rules(name,description,enabled,match_type,pattern,host_filter,event_id,severity,category,mitre,threshold,window_min,created_by,created_at) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
      (r["name"], (TAG % r["id"]) + f"{r['attack']}: {r['what']}", 1 if enabled else 0, r["match_type"], r["pattern"], "", r["event_id"],
       r["severity"], r["category"], r["mitre"], r["threshold"], r["window_min"], user, now()))
    _changed(); return True, f"{r['id']} {r['name']} added ({r['attack']}, {r['mitre']})"


def add_attack(attack, user="system"):
    """Add every library rule for one attack (case-insensitive, partial match ok)."""
    hits = [r for r in LIBRARY if attack.lower() in r["attack"].lower()]
    if not hits: return [(False, f"no rules for attack '{attack}'")]
    return [add_rule(r["id"], user) for r in hits]


def add_all(user="system"):
    return [add_rule(r["id"], user) for r in LIBRARY]


def remove_rule(rule_id):
    q, x, _ = _db()
    row = installed().get(rule_id.upper())
    if not row: return False, f"{rule_id} is not added"
    x("DELETE FROM custom_rules WHERE id=?", (row["id"],)); _changed(); return True, f"{rule_id} removed"


def set_enabled(rule_id, on):
    q, x, _ = _db()
    row = installed().get(rule_id.upper())
    if not row: return False, f"{rule_id} is not added"
    x("UPDATE custom_rules SET enabled=? WHERE id=?", (1 if on else 0, row["id"])); _changed()
    return True, f"{rule_id} {'enabled' if on else 'disabled'}"


# ================================================================ PLAYBOOK LIBRARY
# One PB(...) = one automatic response for one attack.
#   attacks : attack names from LIBRARY above (all their detection rules trigger this playbook)
#   builtin : titles of built-in detections that also trigger it
#   action  : block_ip | create_case | notify | isolate_endpoint
# block_ip is used only for attacks that come from OUTSIDE (web attacks, scans, brute force).
# Attacks that happen ON a host use isolate_endpoint / create_case instead, so you never block your own machine.
def PB(id, attack, name, action, min_severity, attacks, builtin, what):
    return dict(id=id, attack=attack, name=name, action=action, min_severity=min_severity, attacks=attacks, builtin=builtin, what=what)

PLAYBOOKS = [
    PB("P001", "Web Attacks", "Block IP: web exploitation", "block_ip", "High",
       ["SQL Injection", "Command Injection", "Log4Shell / JNDI Injection", "Local / Remote File Inclusion", "Server-Side Request Forgery"],
       ["Possible SQL Injection", "Path Traversal Attempt"], "Blocks the attacker IP after an exploitation attempt on a web application."),
    PB("P002", "Web Attacks", "Open case: web exploitation", "create_case", "High",
       ["SQL Injection", "Command Injection", "Log4Shell / JNDI Injection", "Local / Remote File Inclusion", "Server-Side Request Forgery"],
       ["Possible SQL Injection", "Path Traversal Attempt"], "Opens a case so an analyst checks whether the attack succeeded."),
    PB("P003", "Brute Force", "Block IP: brute force", "block_ip", "High",
       ["Brute Force"], ["Brute Force Login Attempt", "Successful Login After Multiple Failures"], "Blocks the source of repeated failed logins or a login that succeeded after many failures."),
    PB("P004", "Brute Force", "Open case: login after failures", "create_case", "Critical",
       [], ["Successful Login After Multiple Failures"], "A login that worked after many failures may be a compromised account; opens a case."),
    PB("P005", "Recon / Scanning", "Block IP: scanner or port scan", "block_ip", "Medium",
       ["Port Scan", "Web Scanner / Recon"], ["Port Scan Detected"], "Blocks hosts that scan your ports or run web vulnerability scanners."),
    PB("P006", "Denial of Service", "Block IP: request flood", "block_ip", "High",
       ["Denial of Service"], [], "Blocks the source of an HTTP request flood. Spoofed sources can be wrong, review the blocklist."),
    PB("P007", "Web Shell", "Isolate endpoint: web shell", "isolate_endpoint", "High",
       ["Web Shell"], ["Web Server Spawned a Shell"], "Cuts the web server off the network when a web shell is used."),
    PB("P008", "Web Shell", "Open case: web shell", "create_case", "High",
       ["Web Shell"], ["Web Server Spawned a Shell"], "Opens a case for investigation of the web shell."),
    PB("P009", "Ransomware", "Isolate endpoint: ransomware", "isolate_endpoint", "High",
       ["Ransomware"], ["Backup / Recovery Destruction Command"], "Isolates the host at the first ransomware sign to stop it spreading."),
    PB("P010", "Ransomware", "Notify analysts: ransomware", "notify", "High",
       ["Ransomware"], ["Backup / Recovery Destruction Command"], "Live pop-up for analysts."),
    PB("P011", "Credential Theft", "Isolate endpoint: credential dumping", "isolate_endpoint", "Critical",
       ["Credential Dumping"], ["Credential Dumping Attempt"], "Isolates the host where credentials are being dumped."),
    PB("P012", "Credential Theft", "Open case: credential theft", "create_case", "High",
       ["Credential Dumping", "Kerberoasting"], ["Credential Dumping Attempt", "Sensitive File Read (/etc/shadow)"], "Opens a case; passwords on that host should be reset."),
    PB("P013", "Defense Evasion", "Open case: log or security tool tampering", "create_case", "High",
       ["Log Tampering", "Disable Security Tools"], ["Audit Log Cleared", "Log / History Tampering Command", "Security Tool Tampering Command", "Security Tool Disabled"],
       "Someone hiding their tracks or switching off protection; opens a case."),
    PB("P014", "Defense Evasion", "Notify analysts: log or security tool tampering", "notify", "High",
       ["Log Tampering", "Disable Security Tools"], ["Audit Log Cleared", "Log / History Tampering Command", "Security Tool Tampering Command", "Security Tool Disabled"],
       "Live pop-up for analysts."),
    PB("P015", "Persistence / Privilege Escalation", "Open case: persistence or privilege escalation", "create_case", "High",
       ["Registry Run Key Persistence", "SSH Key Persistence", "Account Manipulation", "Privilege Escalation", "Scheduled Task Abuse"],
       ["New User Account Created", "Local Account Created via Command Line", "Suspicious Service Installed", "Privilege Escalation Attempt"],
       "The attacker is setting up a way to stay or gain admin rights."),
    PB("P016", "Command and Control / Exfiltration", "Isolate endpoint: C2 or data exfiltration", "isolate_endpoint", "High",
       ["Command and Control", "Data Exfiltration"], ["Reverse Shell Command", "Shell Process Network Connection", "Connection To Suspicious Port"],
       "Cuts a host that talks to an attacker or uploads data."),
    PB("P017", "Command and Control / Exfiltration", "Open case: C2 or data exfiltration", "create_case", "High",
       ["Command and Control", "Data Exfiltration"], ["Reverse Shell Command", "Shell Process Network Connection", "Connection To Suspicious Port", "Remote Script Download and Execute"],
       "Opens a case to find what was sent and to where."),
    PB("P018", "Lateral Movement", "Open case: lateral movement", "create_case", "High",
       ["Lateral Movement"], ["Remote Thread Injection"], "Attacker moving between hosts; opens a case."),
    PB("P019", "Malicious Execution", "Notify analysts: malicious script or command", "notify", "High",
       ["Malicious Script Execution"], ["Suspicious PowerShell (encoded command)", "Suspicious PowerShell (download and execute)", "Suspicious PowerShell Script",
        "Suspicious Command (living-off-the-land)", "Office Application Spawned a Shell"], "Live pop-up for suspicious scripts and commands."),
    PB("P020", "Malware / Cryptomining", "Isolate endpoint: malware or cryptominer", "isolate_endpoint", "High",
       ["Cryptomining"], ["Malware Detected"], "Isolates a host with malware or a coin miner."),
]
PB_BY_ID = {p["id"]: p for p in PLAYBOOKS}


def pb_titles(p):
    """Alert titles that trigger a playbook: its library rule names + built-in titles."""
    t = [r["name"] for r in LIBRARY if r["attack"] in p["attacks"]] + list(p["builtin"])
    return list(dict.fromkeys(t))


def validate_playbooks():
    bad, seen = [], set(); attacks = {r["attack"] for r in LIBRARY}
    for p in PLAYBOOKS:
        if p["id"] in seen: bad.append(f"{p['id']}: duplicate id")
        seen.add(p["id"])
        if p["action"] not in ("block_ip", "create_case", "notify", "isolate_endpoint"): bad.append(f"{p['id']}: bad action")
        if p["min_severity"] not in ("Critical", "High", "Medium", "Low"): bad.append(f"{p['id']}: bad severity")
        for a in p["attacks"]:
            if a not in attacks: bad.append(f"{p['id']}: unknown attack '{a}'")
        if not pb_titles(p): bad.append(f"{p['id']}: no rules trigger it")
    return bad


def playbooks_installed():
    q, _, _ = _db()
    return {r["lib_id"]: r for r in q("SELECT * FROM playbooks WHERE lib_id!='' AND lib_id IS NOT NULL")}


def playbook_catalog():
    have = playbooks_installed()
    return [dict(p, titles=pb_titles(p), added=p["id"] in have, enabled=bool(have[p["id"]]["enabled"]) if p["id"] in have else False,
                 runs=have[p["id"]]["runs"] if p["id"] in have else 0) for p in PLAYBOOKS]


def add_playbook(pid):
    p = PB_BY_ID.get(pid.upper())
    if not p: return False, f"unknown playbook {pid}"
    if p["id"] in playbooks_installed(): return False, f"{p['id']} already added"
    _, x, _ = _db()
    x("INSERT INTO playbooks(name,min_severity,category,action,title_like,attack,lib_id,what) VALUES(?,?,?,?,?,?,?,?)",
      (p["name"], p["min_severity"], "", p["action"], "|".join(pb_titles(p)), p["attack"], p["id"], p["what"]))
    return True, f"{p['id']} {p['name']} added ({p['action']} for {p['attack']})"


def add_playbook_attack(attack):
    hits = [p for p in PLAYBOOKS if attack.lower() in p["attack"].lower()]
    if not hits: return [(False, f"no playbooks for attack '{attack}'")]
    return [add_playbook(p["id"]) for p in hits]


def add_all_playbooks():
    return [add_playbook(p["id"]) for p in PLAYBOOKS]


def remove_playbook(pid):
    row = playbooks_installed().get(pid.upper())
    if not row: return False, f"{pid} is not added"
    _, x, _ = _db(); x("DELETE FROM playbooks WHERE id=?", (row["id"],)); return True, f"{pid} removed"


# ---------------------------------------------------------------- command line
if __name__ == "__main__":
    import sys
    a = sys.argv[1:]; cmd = a[0] if a else "list"
    import db; db.guard_foreign_db(); db.init_db()
    probs = validate() + validate_playbooks()
    if probs: print("Library problems:\n  " + "\n  ".join(probs)); sys.exit(1)
    if cmd == "list":
        have = installed(); last = None
        for r in sorted(LIBRARY, key=lambda r: (r["attack"], r["id"])):
            if r["attack"] != last: print(f"\n== {r['attack']} =="); last = r["attack"]
            print(f"  [{'x' if r['id'] in have else ' '}] {r['id']}  {r['severity']:<8} {r['mitre']:<10} {r['name']}")
    elif cmd == "add" and len(a) > 1:
        for i in a[1:]: print(add_rule(i, "cli")[1])
    elif cmd == "add-attack" and len(a) > 1:
        for ok, m in add_attack(" ".join(a[1:]), "cli"): print(m)
    elif cmd == "add-all":
        for ok, m in add_all("cli"): print(m)
    elif cmd == "remove" and len(a) > 1:
        for i in a[1:]: print(remove_rule(i)[1])
    elif cmd == "pb-list":
        have = playbooks_installed()
        for p in PLAYBOOKS:
            print(f"[{'x' if p['id'] in have else ' '}] {p['id']}  {p['attack']:<36} {p['min_severity']:<8}+ {p['action']:<17} {p['name']}")
            print(f"        triggered by: {', '.join(pb_titles(p))}")
    elif cmd == "pb-add" and len(a) > 1:
        for i in a[1:]: print(add_playbook(i)[1])
    elif cmd == "pb-add-attack" and len(a) > 1:
        for ok, m in add_playbook_attack(" ".join(a[1:])): print(m)
    elif cmd == "pb-add-all":
        for ok, m in add_all_playbooks(): print(m)
    elif cmd == "pb-remove" and len(a) > 1:
        for i in a[1:]: print(remove_playbook(i)[1])
    else: print(__doc__)
