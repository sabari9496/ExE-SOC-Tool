"""Versioned, explainable, tunable detection rules.  Each rule = metadata + match(ev, hist, params) -> None | dict(summary, evidence=[events], [severity], [confidence]).
No organisation-specific values are hard-coded: lists (expected admins, sensitive groups, allowed creators ...) are parameters with neutral defaults, editable via /api/u/rules.
`hist` gives access to earlier normalised events (MemHist for tests, DbHist in production). Every rule ships positive and negative test cases (see tests/test_unified.py)."""
import re, ipaddress, math, fnmatch
from datetime import datetime, timezone
import activity as _act            # reuse the existing command-line / parent-child pattern library instead of duplicating it

RULES = {}
BASE = "2024-05-01T10:00:00.000Z"
def epoch(ts):
    try: return datetime.strptime(ts[:19], "%Y-%m-%dT%H:%M:%S").replace(tzinfo=timezone.utc).timestamp() + (float("0" + ts[19:].rstrip("Z")) if len(ts) > 19 else 0)
    except Exception: return 0.0

class MemHist:
    def __init__(self, events): self.events = events
    def recent(self, ev, seconds, same_host=True, **flt):
        t = epoch(ev["timestamp"]); out = []
        for e in self.events:
            et = epoch(e.get("timestamp") or "")
            if not (t - seconds <= et <= t + 0.001): continue
            if same_host and e.get("host") != ev.get("host"): continue
            if all((e.get(k) in v) if isinstance(v, (tuple, list, set)) else (e.get(k) == v) for k, v in flt.items()): out.append(e)
        return sorted(out, key=lambda e: e["timestamp"])

class DbHist:
    COLS = {"event_id", "source", "activity", "source_ip", "target_username", "username", "process_guid", "logon_id", "destination_ip", "process_name", "subject_user", "group_name"}
    def recent(self, ev, seconds, same_host=True, **flt):
        from db import q
        from datetime import timedelta
        t = datetime.strptime(ev["timestamp"][:19], "%Y-%m-%dT%H:%M:%S"); lo = (t - timedelta(seconds=seconds)).strftime("%Y-%m-%dT%H:%M:%S")
        w = ["timestamp>=?", "timestamp<=?"]; p = [lo, ev["timestamp"][:19] + "\uffff"]
        if same_host: w.append("host=?"); p.append(ev.get("host"))
        for k, v in flt.items():
            assert k in self.COLS, k
            if isinstance(v, (tuple, list, set)): w.append(f"{k} IN ({','.join('?' * len(v))})"); p += list(v)
            else: w.append(f"{k}=?"); p.append(v)
        rows = q("SELECT * FROM norm_events WHERE " + " AND ".join(w) + " ORDER BY timestamp LIMIT 5000", p)
        import json
        for r in rows:
            try: r["extra"] = json.loads(r["extra"] or "{}")
            except Exception: r["extra"] = {}
        return rows

def rule(id, name, desc, sources, event_ids=None, activities=None, severity="Medium", confidence=0.5, mitre="", steps=(), fp="", params=None, evidence=(), version="1.0.0", tests=()):
    def deco(fn):
        RULES[id] = dict(id=id, name=name, description=desc, sources=tuple(sources), event_ids=tuple(event_ids) if event_ids else None, activities=tuple(activities) if activities else None,
                         severity=severity, confidence=confidence, mitre=mitre, steps=list(steps), false_positives=fp, params=dict(params or {}), evidence_fields=list(evidence), version=version,
                         tests=list(tests), match=fn, enabled=True)
        return fn
    return deco

def E(source, eid=None, t=0, host="H1", **f):
    """Test-event builder (offset seconds from BASE)."""
    from .normalize import blank, to_utc
    n = blank(); n.update(source=source, event_id=eid, host=host, hostname=host, id=f.pop("id", None))
    n["timestamp"] = to_utc(epoch(BASE) + t); n.update(f); return n
SEC, SYS, AUTH, AUD = "windows_security", "sysmon", "linux_auth", "linux_auditd"
def _pub(ip):
    try: a = ipaddress.ip_address(ip); return not (a.is_private or a.is_loopback or a.is_link_local or a.is_multicast or a.is_unspecified)
    except Exception: return False
def _ev(*es): return [e for e in es if e]
def _basename(p): return re.split(r"[\\/]", p or "")[-1].lower()

# ================= authentication =================
P_FAIL = dict(threshold=5, window_s=300)
@rule("UA-001", "Repeated failed logons", "Multiple failed Windows logons (4625) from the same source (or against the same account when no address) in a short window.", [SEC], [4625], severity="Medium", confidence=0.55,
      mitre="T1110 Brute Force", params=P_FAIL, evidence=["event_id", "target_username", "source_ip", "logon_type", "extra.status", "extra.sub_status"],
      steps=["Check whether the source address is a known scanner, jump host or misconfigured service.", "Review the Status/SubStatus (0xC000006A wrong password vs 0xC0000064 unknown user).", "Look for a 4624 from the same source afterwards (rule UA-002).", "Check whether the account is locked (4740)."],
      fp="Expired service-account passwords, mapped drives and scheduled tasks with stale credentials produce bursts of 4625 from one host.",
      tests=[dict(name="5 failures from one IP", events=[E(SEC, 4625, i, source_ip="9.9.9.9", target_username="bob") for i in range(5)], expect=True),
             dict(name="4 failures (below threshold)", events=[E(SEC, 4625, i, source_ip="9.9.9.9", target_username="bob") for i in range(4)], expect=False),
             dict(name="5 failures outside the window", events=[E(SEC, 4625, i * 120, source_ip="9.9.9.9", target_username="bob") for i in range(5)], expect=False)])
def ua001(ev, h, p):
    key = {"source_ip": ev["source_ip"]} if ev.get("source_ip") else {"target_username": ev.get("target_username")}
    ws = h.recent(ev, p["window_s"], event_id=4625, source=SEC, **key)
    if len(ws) < p["threshold"]: return None
    users = {w.get("target_username") for w in ws}
    return dict(summary=f"{len(ws)} failed logons within {p['window_s']}s from {ev.get('source_ip') or 'local/unknown source'} against {len(users)} account(s)", evidence=ws,
                severity="High" if len(users) >= 5 else None, confidence=0.7 if len(users) >= 5 else None)
RULES["UA-001"]["match"] = ua001

@rule("UA-002", "Successful logon after multiple failures", "A successful logon (4624) for an account that had repeated failures (4625) shortly before, ideally from the same address.", [SEC], [4624], severity="High", confidence=0.6,
      mitre="T1110 Brute Force / T1078 Valid Accounts", params=dict(fail_threshold=5, window_s=600, ignore_logon_types=["0", "5"]), evidence=["event_id", "target_username", "source_ip", "logon_type", "logon_id"],
      steps=["Confirm with the user whether they mistyped their password.", "Review activity under the new logon_id (4672, 4688, Sysmon 1).", "Check the source address reputation and geography."],
      fp="Users who mistype a password several times and then succeed; password-manager retries.",
      tests=[dict(name="5 failures then success same user+ip", events=[E(SEC, 4625, i, source_ip="9.9.9.9", target_username="bob") for i in range(5)] + [E(SEC, 4624, 10, source_ip="9.9.9.9", target_username="bob", logon_type="3")], expect=True),
             dict(name="success with no failures", events=[E(SEC, 4624, 10, source_ip="9.9.9.9", target_username="bob", logon_type="3")], expect=False),
             dict(name="service logon type ignored", events=[E(SEC, 4625, i, target_username="svc") for i in range(5)] + [E(SEC, 4624, 10, target_username="svc", logon_type="5")], expect=False)])
def ua002(ev, h, p):
    if str(ev.get("logon_type")) in p["ignore_logon_types"] or not ev.get("target_username"): return None
    f = h.recent(ev, p["window_s"], event_id=4625, source=SEC, target_username=ev["target_username"])
    if len(f) < p["fail_threshold"]: return None
    same_ip = bool(ev.get("source_ip")) and any(w.get("source_ip") == ev["source_ip"] for w in f)
    return dict(summary=f"Logon success for {ev['target_username']} after {len(f)} failures in {p['window_s']}s" + (" from the same source address" if same_ip else " (source differs or unknown)"),
                evidence=f + [ev], confidence=0.8 if same_ip else 0.5)
RULES["UA-002"]["match"] = ua002

@rule("UA-003", "Explicit-credential logons to multiple targets", "One account used explicit credentials (4648) against several different servers in a short window.", [SEC], [4648], severity="Medium", confidence=0.4,
      mitre="T1078 Valid Accounts / T1550 Use Alternate Authentication Material", params=dict(distinct_targets=3, window_s=600, ignore_processes=["winlogon.exe", "consent.exe"]),
      evidence=["subject_user", "target_username", "extra.target_server", "process_name"], steps=["Identify the process that used the credentials.", "Check whether the actor is an administrator doing legitimate remote work."],
      fp="Administrators using runas, RDP clients, backup and management tools legitimately use explicit credentials.",
      tests=[dict(name="3 distinct targets", events=[E(SEC, 4648, i, subject_user="adm", target_username="svc", process_name="x.exe", extra={"target_server": f"srv{i}"}) for i in range(3)], expect=True),
             dict(name="single target", events=[E(SEC, 4648, i, subject_user="adm", target_username="svc", process_name="x.exe", extra={"target_server": "srv1"}) for i in range(3)], expect=False)])
def ua003(ev, h, p):
    if (ev.get("process_name") or "").lower() in p["ignore_processes"]: return None
    ws = h.recent(ev, p["window_s"], event_id=4648, source=SEC, subject_user=ev.get("subject_user")); tg = {(w.get("extra") or {}).get("target_server") for w in ws} - {None, "localhost"}
    if len(tg) < p["distinct_targets"]: return None
    return dict(summary=f"{ev.get('subject_user')} used explicit credentials against {len(tg)} different targets in {p['window_s']}s", evidence=ws)
RULES["UA-003"]["match"] = ua003

@rule("UA-004", "Account lockout", "A user account was locked out (4740).", [SEC], [4740], severity="Medium", confidence=0.7, mitre="T1110 Brute Force", params={}, evidence=["target_username", "extra.caller_computer"],
      steps=["Identify the caller computer in the event.", "Look for 4625 events for the account just before the lockout."], fp="Stale cached credentials on a phone or mapped drive are the most common cause.",
      tests=[dict(name="lockout", events=[E(SEC, 4740, 0, target_username="bob", extra={"caller_computer": "PC9"})], expect=True), dict(name="other event", events=[E(SEC, 4624, 0)], expect=False)])
def ua004(ev, h, p): return dict(summary=f"Account {ev.get('target_username')} locked out (caller: {(ev.get('extra') or {}).get('caller_computer') or 'unknown'})", evidence=[ev])
RULES["UA-004"]["match"] = ua004

@rule("UA-005", "Unusual privileged remote session", "A remote logon (type 3/10) that was assigned special privileges (4672) for an account outside the configured expected-privileged list. Inactive until a baseline list is configured.", [SEC], [4672],
      severity="Medium", confidence=0.4, mitre="T1078 Valid Accounts", params=dict(expected_privileged=[], window_s=60, remote_types=["3", "10"]), evidence=["username", "logon_id", "source_ip", "logon_type"],
      steps=["Verify the account should hold administrative rights.", "Review processes started under this logon_id."], fp="Without a baseline many legitimate admin logons look unusual; configure expected_privileged first.",
      tests=[dict(name="remote priv logon, unlisted account", params=dict(expected_privileged=["alice"]), events=[E(SEC, 4624, 0, target_username="bob", logon_id="0x1", logon_type="10", source_ip="9.9.9.9"), E(SEC, 4672, 1, username="bob", subject_user="bob", logon_id="0x1")], expect=True),
             dict(name="listed account", params=dict(expected_privileged=["bob"]), events=[E(SEC, 4624, 0, target_username="bob", logon_id="0x1", logon_type="10"), E(SEC, 4672, 1, username="bob", logon_id="0x1")], expect=False),
             dict(name="no baseline configured", events=[E(SEC, 4624, 0, target_username="bob", logon_id="0x1", logon_type="10"), E(SEC, 4672, 1, username="bob", logon_id="0x1")], expect=False)])
def ua005(ev, h, p):
    u = (ev.get("username") or "").lower()
    if not p["expected_privileged"] or not u or u.endswith("$") or u in [x.lower() for x in p["expected_privileged"]]: return None
    lg = [e for e in h.recent(ev, p["window_s"], event_id=4624, source=SEC, logon_id=ev.get("logon_id")) if str(e.get("logon_type")) in p["remote_types"]]
    if not lg: return None
    return dict(summary=f"Remote privileged logon for {ev.get('username')} (type {lg[-1].get('logon_type')}) from {lg[-1].get('source_ip') or 'unknown'}", evidence=lg + [ev])
RULES["UA-005"]["match"] = ua005

@rule("UA-006", "Authentication failures from one source across multiple hosts", "The same source address failed to authenticate (4625) on several different hosts.", [SEC], [4625], severity="High", confidence=0.65,
      mitre="T1110.003 Password Spraying / T1021 Remote Services", params=dict(distinct_hosts=3, window_s=600), evidence=["host", "source_ip", "target_username"],
      steps=["Identify the source host.", "Check whether a vulnerability scanner or inventory tool is expected."], fp="Authenticated vulnerability scanners and inventory tools.",
      tests=[dict(name="3 hosts", events=[E(SEC, 4625, i, host=f"H{i}", source_ip="9.9.9.9") for i in range(3)], expect=True), dict(name="1 host", events=[E(SEC, 4625, i, source_ip="9.9.9.9") for i in range(3)], expect=False)])
def ua006(ev, h, p):
    if not ev.get("source_ip"): return None
    ws = h.recent(ev, p["window_s"], same_host=False, event_id=4625, source=SEC, source_ip=ev["source_ip"])
    hs = {w["host"] for w in ws}
    return dict(summary=f"{ev['source_ip']} failed authentication on {len(hs)} hosts in {p['window_s']}s", evidence=ws) if len(hs) >= p["distinct_hosts"] else None
RULES["UA-006"]["match"] = ua006

@rule("UA-007", "Repeated Kerberos pre-auth / NTLM validation failures", "Repeated 4771 or failed 4776 events (domain-controller telemetry required).", [SEC], [4771, 4776], severity="Medium", confidence=0.5, mitre="T1110 / T1558.003",
      params=dict(threshold=10, window_s=300), evidence=["event_id", "target_username", "source_ip", "extra.status"], steps=["Confirm the events come from a domain controller.", "Check the source workstation."],
      fp="Clock skew, expired passwords and legacy NTLM applications.",
      tests=[dict(name="10 kerberos failures", events=[E(SEC, 4771, i, target_username="bob", source_ip="9.9.9.9") for i in range(10)], expect=True),
             dict(name="successful NTLM validations", events=[E(SEC, 4776, i, target_username="bob", extra={"status": "0x0"}) for i in range(10)], expect=False)])
def ua007(ev, h, p):
    if ev["event_id"] == 4776 and (ev.get("extra") or {}).get("status") in ("0x0", "0"): return None
    ws = [w for w in h.recent(ev, p["window_s"], event_id=(4771, 4776), source=SEC, **({"source_ip": ev["source_ip"]} if ev.get("source_ip") else {"target_username": ev.get("target_username")})) if not (w["event_id"] == 4776 and (w.get("extra") or {}).get("status") in ("0x0", "0"))]
    return dict(summary=f"{len(ws)} Kerberos/NTLM failures in {p['window_s']}s", evidence=ws) if len(ws) >= p["threshold"] else None
RULES["UA-007"]["match"] = ua007

# ================= Linux =================
@rule("LX-001", "Repeated SSH failures", "Repeated failed SSH authentication from one address.", [AUTH], activities=["ssh_auth_failure", "ssh_invalid_user"], severity="Medium", confidence=0.55, mitre="T1110 Brute Force",
      params=P_FAIL, evidence=["source_ip", "target_username"], steps=["Check /var/log/auth.log (or journalctl -u ssh) for the address.", "Consider fail2ban or firewall rules after analyst review."], fp="Misconfigured automation, internet background scanning (low impact if password auth is disabled).",
      tests=[dict(name="5 failures", events=[E(AUTH, None, i, activity="ssh_auth_failure", source_ip="1.2.3.4", target_username="root") for i in range(5)], expect=True),
             dict(name="2 failures", events=[E(AUTH, None, i, activity="ssh_auth_failure", source_ip="1.2.3.4", target_username="root") for i in range(2)], expect=False)])
def lx001(ev, h, p):
    if not ev.get("source_ip"): return None
    ws = h.recent(ev, p["window_s"], source=AUTH, activity=("ssh_auth_failure", "ssh_invalid_user"), source_ip=ev["source_ip"])
    return dict(summary=f"{len(ws)} SSH failures from {ev['source_ip']} in {p['window_s']}s", evidence=ws) if len(ws) >= p["threshold"] else None
RULES["LX-001"]["match"] = lx001

@rule("LX-002", "SSH success after repeated failures", "Successful SSH login from an address that failed repeatedly before.", [AUTH], activities=["ssh_auth_success"], severity="High", confidence=0.7, mitre="T1110 / T1078",
      params=dict(fail_threshold=5, window_s=600), evidence=["source_ip", "target_username"], steps=["Review the session (last, journalctl _SYSTEMD_UNIT=ssh.service).", "Check sudo and new-process activity after login."], fp="Legitimate user retyping a password or key passphrase.",
      tests=[dict(name="failures then success", events=[E(AUTH, None, i, activity="ssh_auth_failure", source_ip="1.2.3.4") for i in range(5)] + [E(AUTH, None, 9, activity="ssh_auth_success", source_ip="1.2.3.4", target_username="u")], expect=True),
             dict(name="success only", events=[E(AUTH, None, 9, activity="ssh_auth_success", source_ip="1.2.3.4")], expect=False)])
def lx002(ev, h, p):
    if not ev.get("source_ip"): return None
    ws = h.recent(ev, p["window_s"], source=AUTH, activity=("ssh_auth_failure", "ssh_invalid_user"), source_ip=ev["source_ip"])
    return dict(summary=f"SSH login for {ev.get('target_username')} from {ev['source_ip']} after {len(ws)} failures", evidence=ws + [ev]) if len(ws) >= p["fail_threshold"] else None
RULES["LX-002"]["match"] = lx002

@rule("LX-003", "Sudo / su privilege-escalation failures", "sudo denials (user not in sudoers) or repeated sudo/su authentication failures.", [AUTH], activities=["sudo_denied", "sudo_auth_failure", "su_failure"], severity="Medium", confidence=0.5, mitre="T1548.003 Sudo and Sudo Caching",
      params=dict(threshold=3, window_s=600), evidence=["subject_user", "command_line"], steps=["Ask the user what they were attempting.", "Review commands run by the account."], fp="Users mistyping passwords; a sudoers misconfiguration.",
      tests=[dict(name="not in sudoers", events=[E(AUTH, None, 0, activity="sudo_denied", subject_user="joe")], expect=True), dict(name="1 sudo auth failure", events=[E(AUTH, None, 0, activity="sudo_auth_failure", subject_user="joe")], expect=False)])
def lx003(ev, h, p):
    if ev["activity"] == "sudo_denied": return dict(summary=f"{ev.get('subject_user')} attempted sudo but is not permitted", evidence=[ev])
    ws = h.recent(ev, p["window_s"], source=AUTH, activity=("sudo_auth_failure", "su_failure", "sudo_denied"))
    return dict(summary=f"{len(ws)} sudo/su failures in {p['window_s']}s", evidence=ws) if len(ws) >= p["threshold"] else None
RULES["LX-003"]["match"] = lx003

@rule("LX-004", "Audit subsystem tampering (Linux)", "auditd daemon stopped/aborted or audit rules removed/audit disabled.", [AUD], activities=["audit_daemon_end", "audit_daemon_abort", "audit_config_change"], severity="High", confidence=0.5, mitre="T1562.001 Impair Defenses",
      params={}, evidence=["extra.audit_type", "extra.op", "extra.message"], steps=["Confirm whether an administrator changed audit configuration.", "Preserve /var/log/audit before rotation."], fp="Planned auditd restarts, package upgrades and log rotation also emit DAEMON_END / CONFIG_CHANGE.",
      tests=[dict(name="audit disabled", events=[E(AUD, None, 0, activity="audit_config_change", extra={"message": "type=CONFIG_CHANGE msg=audit(1.1:2): audit_enabled=0 old=1", "op": ""})], expect=True),
             dict(name="rule added", events=[E(AUD, None, 0, activity="audit_config_change", extra={"message": "type=CONFIG_CHANGE op=add_rule key=x", "op": "add_rule"})], expect=False)])
def lx004(ev, h, p):
    ex = ev.get("extra") or {}; m = ex.get("message") or ""
    if ev["activity"] == "audit_config_change" and not (re.search(r"audit_enabled=0", m) or ex.get("op") in ("remove_rule",) or "op=remove_rule" in m): return None
    return dict(summary=f"Audit subsystem change: {ev['activity']}", evidence=[ev])
RULES["LX-004"]["match"] = lx004

@rule("LX-005", "Linux account created / privileged group membership", "New local user or a user added to an administrative group (sudo, wheel, admin, root).", [AUTH], activities=["user_created", "group_member_added"], severity="Medium", confidence=0.5, mitre="T1136.001 / T1098",
      params=dict(sensitive_groups=["sudo", "wheel", "admin", "root", "adm", "docker"]), evidence=["target_username", "group_name"], steps=["Confirm change ticket.", "Review who ran useradd/usermod (auditd EXECVE)."], fp="Normal provisioning and configuration management.",
      tests=[dict(name="added to sudo", events=[E(AUTH, None, 0, activity="group_member_added", target_username="x", group_name="sudo")], expect=True), dict(name="added to staff", events=[E(AUTH, None, 0, activity="group_member_added", target_username="x", group_name="staff")], expect=False),
             dict(name="user created", events=[E(AUTH, None, 0, activity="user_created", target_username="x")], expect=True)])
def lx005(ev, h, p):
    if ev["activity"] == "group_member_added" and (ev.get("group_name") or "").lower() not in p["sensitive_groups"]: return None
    return dict(summary=f"{ev['activity'].replace('_', ' ')}: {ev.get('target_username')}" + (f" -> {ev.get('group_name')}" if ev.get("group_name") else ""), evidence=[ev], severity="High" if ev["activity"] == "group_member_added" else None)
RULES["LX-005"]["match"] = lx005

# ================= process / execution =================
def _cmd_hit(ev):
    line = f"{ev.get('image') or ''} {ev.get('command_line') or ''}".strip()
    for rx, t, s in _act.CMD_RX:
        if rx.search(line): return t, s
@rule("PX-001", "Suspicious command line", "Process creation (4688 or Sysmon 1) whose command line matches a known suspicious pattern (encoded PowerShell, LOLBin download, credential dumping, log tampering ...). Needs command-line auditing.", [SEC, SYS], [4688, 1],
      severity="High", confidence=0.65, mitre="T1059 Command and Scripting Interpreter", params={}, evidence=["image", "command_line", "parent_process_name", "username", "process_guid"],
      steps=["Decode/inspect the command line.", "Pivot to Sysmon 3/22/11 for the same process_guid.", "Identify the parent chain and the logon_id."], fp="Admin scripts and software deployment tools can use encoded PowerShell or certutil legitimately.",
      tests=[dict(name="encoded powershell", events=[E(SYS, 1, 0, image="C:\\Windows\\System32\\powershell.exe", command_line="powershell.exe -enc SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQAIABOAGUAdA==")], expect=True),
             dict(name="benign notepad", events=[E(SYS, 1, 0, image="C:\\Windows\\notepad.exe", command_line="notepad.exe a.txt")], expect=False)])
def px001(ev, h, p):
    r = _cmd_hit(ev)
    return dict(summary=f"Suspicious command line: {r[0]}", evidence=[ev], severity=r[1] if r[1] in ("High", "Critical") else "High") if r else None
RULES["PX-001"]["match"] = px001

@rule("PX-002", "Unexpected parent-child process", "Office application or web server spawned a shell/interpreter.", [SEC, SYS], [4688, 1], severity="High", confidence=0.6, mitre="T1204.002 / T1505.003", params={},
      evidence=["parent_process_name", "process_name", "command_line"], steps=["Locate the document/web request that triggered it.", "Check child process network activity."], fp="Office macros in legitimate automation; web apps that shell out by design.",
      tests=[dict(name="word->powershell", events=[E(SYS, 1, 0, process_name="powershell.exe", parent_process_name="WINWORD.EXE")], expect=True), dict(name="explorer->notepad", events=[E(SYS, 1, 0, process_name="notepad.exe", parent_process_name="explorer.exe")], expect=False)])
def px002(ev, h, p):
    pn, cn = (ev.get("parent_process_name") or "").lower(), (ev.get("process_name") or "").lower()
    if cn in _act.SHELLS and (pn in _act.OFFICE or pn in _act.WEBSRV): return dict(summary=f"{pn} spawned {cn}", evidence=[ev])
RULES["PX-002"]["match"] = px002

@rule("PX-003", "Process executed from a temporary / user-writable location", "Process image located in Temp, Downloads, Public or /tmp style paths.", [SEC, SYS], [4688, 1], severity="Medium", confidence=0.35, mitre="T1204 User Execution",
      params=dict(ignore_images=[]), evidence=["image", "parent_process_name", "username"], steps=["Hash and reputation-check the binary.", "Find how it arrived (Sysmon 11)."], fp="Installers and updaters routinely run from Temp.",
      tests=[dict(name="exe in temp", events=[E(SYS, 1, 0, image="C:\\Users\\a\\AppData\\Local\\Temp\\x.exe")], expect=True), dict(name="system32", events=[E(SYS, 1, 0, image="C:\\Windows\\System32\\cmd.exe")], expect=False)])
def px003(ev, h, p):
    im = ev.get("image") or ""
    return dict(summary=f"Process started from user-writable path: {im[:160]}", evidence=[ev]) if _act.TMP_EXE.search(im) and im.lower() not in [i.lower() for i in p["ignore_images"]] else None
RULES["PX-003"]["match"] = px003

# ================= network / DNS =================
@rule("NW-001", "High-volume repeated connections to one destination", "Many outbound connections from one process to the same destination:port. Byte counts are NOT available, so this does not indicate data exfiltration by itself.", [SYS], [3],
      severity="Low", confidence=0.3, mitre="T1071 Application Layer Protocol", params=dict(threshold=50, window_s=600), evidence=["process_name", "destination_ip", "destination_port"], steps=["Identify the process and destination.", "Check whether the pattern is regular (beaconing) or a normal service."],
      fp="Browsers, update clients, monitoring agents and chat apps connect repeatedly.", tests=[dict(name="50 connections", events=[E(SYS, 3, i, process_guid="{g}", destination_ip="9.9.9.9", destination_port=443) for i in range(50)], expect=True),
      dict(name="5 connections", events=[E(SYS, 3, i, process_guid="{g}", destination_ip="9.9.9.9", destination_port=443) for i in range(5)], expect=False)])
def nw001(ev, h, p):
    if not ev.get("destination_ip"): return None
    ws = [w for w in h.recent(ev, p["window_s"], event_id=3, source=SYS, destination_ip=ev["destination_ip"], process_guid=ev.get("process_guid")) if w.get("destination_port") == ev.get("destination_port")]
    return dict(summary=f"{len(ws)} connections from {ev.get('process_name')} to {ev['destination_ip']}:{ev.get('destination_port')} in {p['window_s']}s (no byte counts available)", evidence=ws[-200:]) if len(ws) >= p["threshold"] else None
RULES["NW-001"]["match"] = nw001

@rule("NW-002", "Script interpreter / LOLBin connecting to a public address", "A scripting engine or living-off-the-land binary opened a connection to a public IP address.", [SYS], [3], severity="Medium", confidence=0.4, mitre="T1105 / T1218",
      params=dict(processes=["powershell.exe", "pwsh.exe", "wscript.exe", "cscript.exe", "mshta.exe", "rundll32.exe", "regsvr32.exe", "certutil.exe", "bitsadmin.exe"]), evidence=["process_name", "destination_ip", "destination_port", "command_line"],
      steps=["Review the process's command line (Sysmon 1 same process_guid).", "Check the destination's ownership and the DNS name (Sysmon 22)."], fp="Admin scripts, package managers and patching via PowerShell.",
      tests=[dict(name="powershell to public ip", events=[E(SYS, 3, 0, process_name="powershell.exe", destination_ip="8.8.4.4", destination_port=443, extra={"Initiated": "true"})], expect=True),
             dict(name="powershell to private ip", events=[E(SYS, 3, 0, process_name="powershell.exe", destination_ip="10.1.1.1", destination_port=443)], expect=False), dict(name="chrome to public", events=[E(SYS, 3, 0, process_name="chrome.exe", destination_ip="8.8.4.4")], expect=False)])
def nw002(ev, h, p):
    if (ev.get("process_name") or "").lower() in p["processes"] and _pub(ev.get("destination_ip")) and (ev.get("extra") or {}).get("Initiated", "true") != "false":
        return dict(summary=f"{ev['process_name']} connected to public address {ev['destination_ip']}:{ev.get('destination_port')}", evidence=[ev])
RULES["NW-002"]["match"] = nw002

def _entropy(s):
    return -sum((c / len(s)) * math.log2(c / len(s)) for c in (s.count(ch) for ch in set(s))) if s else 0
@rule("DNS-001", "Suspicious DNS query pattern", "Many distinct sub-domains under one parent domain, or very long high-entropy query names (possible tunnelling / DGA). Unfamiliar is NOT malicious.", [SYS], [22], severity="Low", confidence=0.3, mitre="T1071.004 DNS",
      params=dict(distinct_labels=30, window_s=300, long_name=70, entropy=3.8), evidence=["dns_query_name", "process_name"], steps=["Identify the querying process.", "Review domain age/reputation with threat intel."], fp="CDNs, anti-virus cloud lookups and tracking domains use many sub-domains.",
      tests=[dict(name="30 subdomains", events=[E(SYS, 22, i, dns_query_name=f"a{i}x.example.org") for i in range(30)], expect=True), dict(name="repeat same name", events=[E(SYS, 22, i, dns_query_name="www.example.org") for i in range(30)], expect=False),
             dict(name="long random name", events=[E(SYS, 22, 0, dns_query_name="q8f3k2z9x1c7v5b0n4m6l2j8h1g3d5s7a9p0o2i4u6y8t1r3e5w7q9z2x4c6v8b0n2m4k6j8h1g3d5.example.org")], expect=True)])
def dns001(ev, h, p):
    n = (ev.get("dns_query_name") or "").lower().rstrip(".")
    if not n: return None
    if len(n) >= p["long_name"] and _entropy(n.split(".")[0]) >= p["entropy"]: return dict(summary=f"Long high-entropy DNS name ({len(n)} chars)", evidence=[ev])
    par = ".".join(n.split(".")[-2:]); ws = [w for w in h.recent(ev, p["window_s"], event_id=22, source=SYS) if (w.get("dns_query_name") or "").lower().endswith("." + par)]
    d = {w["dns_query_name"].lower() for w in ws}
    return dict(summary=f"{len(d)} distinct sub-domains of {par} queried in {p['window_s']}s", evidence=ws[-200:]) if len(d) >= p["distinct_labels"] else None
RULES["DNS-001"]["match"] = dns001

# ================= file / registry / injection =================
@rule("FR-001", "Executable or script created in a sensitive location", "Executable/script written to Startup, Temp, Public, ProgramData or /tmp-style paths by a process that is not an expected installer.", [SYS], [11], severity="Medium", confidence=0.4,
      mitre="T1105 / T1547.001", params=dict(extensions=[".exe", ".dll", ".scr", ".bat", ".cmd", ".ps1", ".vbs", ".js", ".hta", ".lnk"], allowed_creators=["msiexec.exe", "trustedinstaller.exe", "tiworker.exe", "setup.exe"],
      path_regex=r"\\startup\\|\\appdata\\local\\temp\\|\\users\\public\\|\\programdata\\|\\windows\\temp\\"), evidence=["target_filename", "process_name", "process_guid"],
      steps=["Hash the file and check reputation.", "Check if the same process_guid then made network connections (FR-003)."], fp="Software installers and updaters write executables to Temp/ProgramData legitimately.",
      tests=[dict(name="exe in startup", events=[E(SYS, 11, 0, target_filename="C:\\Users\\a\\AppData\\Roaming\\Microsoft\\Windows\\Start Menu\\Programs\\Startup\\x.exe", process_name="winword.exe")], expect=True),
             dict(name="txt in temp", events=[E(SYS, 11, 0, target_filename="C:\\Users\\a\\AppData\\Local\\Temp\\a.txt", process_name="x.exe")], expect=False), dict(name="msiexec", events=[E(SYS, 11, 0, target_filename="C:\\Windows\\Temp\\a.exe", process_name="msiexec.exe")], expect=False)])
def fr001(ev, h, p):
    f = (ev.get("target_filename") or "").lower()
    if f.endswith(tuple(p["extensions"])) and re.search(p["path_regex"], f) and (ev.get("process_name") or "").lower() not in p["allowed_creators"]:
        return dict(summary=f"{ev.get('process_name')} created {ev['target_filename'][:160]}", evidence=[ev])
RULES["FR-001"]["match"] = fr001

RX_RUN = re.compile(r"\\currentversion\\(run|runonce)(ex)?\\|\\winlogon\\(shell|userinit)|\\image file execution options\\", re.I)
@rule("FR-002", "Startup registry persistence", "Value set under Run/RunOnce, Winlogon Shell/Userinit or Image File Execution Options.", [SYS], [13], severity="Medium", confidence=0.5, mitre="T1547.001 Registry Run Keys",
      params={}, evidence=["registry_key", "registry_value", "process_name"], steps=["Check what the value launches.", "Correlate with the creating process (Sysmon 1)."], fp="Many applications register auto-start entries on install.",
      tests=[dict(name="Run key", events=[E(SYS, 13, 0, registry_key="HKU\\S-1\\Software\\Microsoft\\Windows\\CurrentVersion\\Run\\Upd", registry_value="C:\\Users\\a\\AppData\\Local\\Temp\\a.exe")], expect=True),
             dict(name="unrelated key", events=[E(SYS, 13, 0, registry_key="HKU\\S-1\\Software\\Foo\\Bar", registry_value="1")], expect=False)])
def fr002(ev, h, p):
    if RX_RUN.search(ev.get("registry_key") or ""):
        bad = _act.TMP_EXE.search(ev.get("registry_value") or "") or re.search(r"powershell|cmd\.exe|wscript|mshta", ev.get("registry_value") or "", re.I)
        return dict(summary=f"Startup registry value set: {ev['registry_key'][-100:]}", evidence=[ev], severity="High" if bad else None, confidence=0.65 if bad else None)
RULES["FR-002"]["match"] = fr002

@rule("FR-003", "File creation followed by network activity from the same process", "A process created an executable/script and then opened a network connection (same process_guid).", [SYS], [3], severity="Medium", confidence=0.55, mitre="T1105 Ingress Tool Transfer",
      params=dict(window_s=120, extensions=[".exe", ".dll", ".scr", ".bat", ".ps1", ".vbs", ".js", ".hta"]), evidence=["process_guid", "target_filename", "destination_ip"], steps=["Hash the created file.", "Review the connection destination and DNS."], fp="Downloaders and updaters.",
      tests=[dict(name="file then net same guid", events=[E(SYS, 11, 0, process_guid="{a}", target_filename="C:\\x\\a.exe"), E(SYS, 3, 30, process_guid="{a}", destination_ip="9.9.9.9", destination_port=443)], expect=True),
             dict(name="different guid", events=[E(SYS, 11, 0, process_guid="{a}", target_filename="C:\\x\\a.exe"), E(SYS, 3, 30, process_guid="{b}", destination_ip="9.9.9.9")], expect=False),
             dict(name="no executable", events=[E(SYS, 11, 0, process_guid="{a}", target_filename="C:\\x\\a.txt"), E(SYS, 3, 30, process_guid="{a}", destination_ip="9.9.9.9")], expect=False)])
def fr003(ev, h, p):
    if not ev.get("process_guid") or not _pub(ev.get("destination_ip")): return None
    fs = [w for w in h.recent(ev, p["window_s"], event_id=11, source=SYS, process_guid=ev["process_guid"]) if (w.get("target_filename") or "").lower().endswith(tuple(p["extensions"]))]
    return dict(summary=f"{ev.get('process_name')} created {len(fs)} executable/script file(s) then connected to {ev['destination_ip']}", evidence=fs + [ev]) if fs else None
RULES["FR-003"]["match"] = fr003

LSASS_MASKS = ("0x1010", "0x1410", "0x1438", "0x143a", "0x1fffff", "0x1f0fff", "0x1f1fff", "0x1f3fff", "0x40", "0x0040")
@rule("PI-001", "Suspicious access to LSASS", "A process opened lsass.exe with credential-dumping style access rights (Sysmon 10).", [SYS], [10], severity="High", confidence=0.6, mitre="T1003.001 LSASS Memory",
      params=dict(allowed_sources=["wininit.exe", "csrss.exe", "services.exe", "svchost.exe", "lsm.exe", "msmpeng.exe", "werfault.exe", "vmtoolsd.exe", "taskmgr.exe"], masks=list(LSASS_MASKS)),
      evidence=["image", "extra.target_image", "extra.granted_access"], steps=["Identify the source process and parent.", "Check for dump files (Sysmon 11) and EDR/AV alerts."], fp="Security products, backup agents and Task Manager access LSASS; allow-list them after review.",
      tests=[dict(name="unknown proc, 0x1fffff", events=[E(SYS, 10, 0, image="C:\\Users\\a\\x.exe", process_name="x.exe", extra={"target_image": "C:\\Windows\\System32\\lsass.exe", "granted_access": "0x1FFFFF"})], expect=True),
             dict(name="allowed source", events=[E(SYS, 10, 0, image="C:\\Windows\\System32\\svchost.exe", process_name="svchost.exe", extra={"target_image": "C:\\Windows\\System32\\lsass.exe", "granted_access": "0x1FFFFF"})], expect=False),
             dict(name="benign mask", events=[E(SYS, 10, 0, image="C:\\x.exe", process_name="x.exe", extra={"target_image": "C:\\Windows\\System32\\lsass.exe", "granted_access": "0x1000"})], expect=False)])
def pi001(ev, h, p):
    ex = ev.get("extra") or {}
    if _basename(ex.get("target_image")) != "lsass.exe" or (ev.get("process_name") or "").lower() in p["allowed_sources"]: return None
    if (ex.get("granted_access") or "").lower() not in p["masks"]: return None
    return dict(summary=f"{ev.get('process_name')} opened LSASS with access {ex.get('granted_access')}", evidence=[ev])
RULES["PI-001"]["match"] = pi001

@rule("PI-002", "Remote thread created in another process", "CreateRemoteThread (Sysmon 8) from a process not in the allow-list.", [SYS], [8], severity="High", confidence=0.5, mitre="T1055 Process Injection",
      params=dict(allowed_sources=["csrss.exe", "wininit.exe", "services.exe", "msmpeng.exe", "werfault.exe"]), evidence=["image", "extra.target_image"], steps=["Identify both processes.", "Inspect the target for injected modules (Sysmon 7)."], fp="Debuggers, AV/EDR and some accessibility tools.",
      tests=[dict(name="unknown injector", events=[E(SYS, 8, 0, process_name="x.exe", image="C:\\x.exe", extra={"target_image": "C:\\Windows\\explorer.exe"})], expect=True), dict(name="allowed", events=[E(SYS, 8, 0, process_name="csrss.exe", extra={"target_image": "C:\\Windows\\explorer.exe"})], expect=False)])
def pi002(ev, h, p):
    if (ev.get("process_name") or "").lower() in p["allowed_sources"]: return None
    return dict(summary=f"{ev.get('process_name')} created a remote thread in {_basename((ev.get('extra') or {}).get('target_image'))}", evidence=[ev])
RULES["PI-002"]["match"] = pi002

@rule("PI-003", "Unsigned module loaded from a user-writable path", "Sysmon 7 image load: unsigned DLL from Temp/AppData/Public.", [SYS], [7], severity="Medium", confidence=0.3, mitre="T1574 Hijack Execution Flow", params=dict(path_regex=r"\\appdata\\|\\temp\\|\\users\\public\\"),
      evidence=["file_path", "process_name", "extra.Signed"], steps=["Hash the module.", "Check for DLL side-loading next to a signed host executable."], fp="Portable and developer tools. High volume: enable only if Sysmon image-load filtering is configured.",
      tests=[dict(name="unsigned temp dll", events=[E(SYS, 7, 0, file_path="C:\\Users\\a\\AppData\\Local\\Temp\\a.dll", process_name="x.exe", extra={"Signed": "false"})], expect=True),
             dict(name="signed", events=[E(SYS, 7, 0, file_path="C:\\Users\\a\\AppData\\Local\\Temp\\a.dll", process_name="x.exe", extra={"Signed": "true"})], expect=False)])
def pi003(ev, h, p):
    if (ev.get("extra") or {}).get("Signed", "").lower() == "false" and re.search(p["path_regex"], (ev.get("file_path") or "").lower()): return dict(summary=f"{ev.get('process_name')} loaded unsigned {ev['file_path'][-120:]}", evidence=[ev])
RULES["PI-003"]["match"] = pi003

# ================= accounts / persistence / audit =================
@rule("AC-001", "Account lifecycle change", "User account created, enabled, disabled, deleted, or password change/reset attempted.", [SEC], [4720, 4722, 4723, 4724, 4725, 4726], severity="Low", confidence=0.5, mitre="T1136 / T1098",
      params=dict(medium_events=[4720, 4724, 4726]), evidence=["subject_user", "target_username", "event_id"], steps=["Confirm a change request exists.", "Check the actor's logon (4624) and session activity."], fp="Routine administration and HR on/off-boarding.",
      tests=[dict(name="created", events=[E(SEC, 4720, 0, subject_user="adm", target_username="newu")], expect=True), dict(name="logon", events=[E(SEC, 4624, 0)], expect=False)])
def ac001(ev, h, p): return dict(summary=f"{ev['activity']}: {ev.get('target_username')} by {ev.get('subject_user')}", evidence=[ev], severity="Medium" if ev["event_id"] in p["medium_events"] else None)
RULES["AC-001"]["match"] = ac001

@rule("AC-002", "Sensitive group membership change", "Member added to an administrative/sensitive group (4728/4732/4756).", [SEC], [4728, 4732, 4756], severity="High", confidence=0.75, mitre="T1098 Account Manipulation",
      params=dict(sensitive_groups=["administrators", "domain admins", "enterprise admins", "schema admins", "account operators", "backup operators", "server operators", "remote desktop users"]), evidence=["group_name", "target_username", "subject_user", "extra.group_scope"],
      steps=["Verify the change request.", "Review the actor's recent logons and processes."], fp="Planned administrative delegation.",
      tests=[dict(name="added to Administrators", events=[E(SEC, 4732, 0, group_name="Administrators", target_username="bob", subject_user="adm", extra={"group_scope": "local"})], expect=True),
             dict(name="added to Users", events=[E(SEC, 4732, 0, group_name="Users", target_username="bob")], expect=False)])
def ac002(ev, h, p):
    if (ev.get("group_name") or "").lower() in p["sensitive_groups"]: return dict(summary=f"{ev.get('target_username')} added to {ev['group_name']} ({(ev.get('extra') or {}).get('group_scope')}) by {ev.get('subject_user')}", evidence=[ev])
RULES["AC-002"]["match"] = ac002

@rule("PS-001", "Service installed", "A new service was installed (4697). Higher confidence when the binary is in a user-writable path or launches a shell.", [SEC], [4697], severity="Medium", confidence=0.5, mitre="T1543.003 Windows Service",
      params={}, evidence=["service_name", "file_path", "subject_user"], steps=["Hash the service binary.", "Review Sysmon 1/11 for the installer."], fp="Software installs and drivers.",
      tests=[dict(name="svc in temp", events=[E(SEC, 4697, 0, service_name="x", file_path="C:\\Users\\a\\AppData\\Local\\Temp\\s.exe")], expect=True)])
def ps001(ev, h, p):
    bad = _act.TMP_EXE.search(ev.get("file_path") or "") or re.search(r"cmd\.exe|powershell|mshta|wscript", ev.get("file_path") or "", re.I)
    return dict(summary=f"Service {ev.get('service_name')} installed: {(ev.get('file_path') or '')[:160]}", evidence=[ev], severity="High" if bad else None, confidence=0.7 if bad else None)
RULES["PS-001"]["match"] = ps001

@rule("PS-002", "Scheduled task created or modified", "Scheduled task created/updated (4698/4702); Medium when the task content looks suspicious.", [SEC], [4698, 4702], severity="Low", confidence=0.4, mitre="T1053.005 Scheduled Task",
      params={}, evidence=["task_name", "subject_user", "extra.task_content"], steps=["Read the task action.", "Check the creator and time against change windows."], fp="Many applications and updaters create scheduled tasks.",
      tests=[dict(name="encoded ps task", events=[E(SEC, 4698, 0, task_name="\\U", subject_user="a", extra={"task_content": "<Exec><Command>powershell.exe</Command><Arguments>-enc SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQAIABOAGUAdA==</Arguments></Exec>"})], expect=True),
             dict(name="non-task", events=[E(SEC, 4624, 0)], expect=False)])
def ps002(ev, h, p):
    c = (ev.get("extra") or {}).get("task_content") or ""
    bad = any(rx.search(c.replace("<Command>", " ").replace("<Arguments>", " ")) for rx, _, _ in _act.CMD_RX) or re.search(r"\\temp\\|\\appdata\\", c, re.I)
    return dict(summary=f"Scheduled task {ev.get('task_name')} {'created' if ev['event_id'] == 4698 else 'updated'} by {ev.get('subject_user')}", evidence=[ev], severity="Medium" if bad else None, confidence=0.6 if bad else None)
RULES["PS-002"]["match"] = ps002

@rule("PS-003", "Security audit log cleared", "The Security log was cleared (1102). Investigation priority: preserve surrounding events; a clear does not by itself prove compromise.", [SEC], [1102], severity="High", confidence=0.8, mitre="T1070.001 Clear Windows Event Logs",
      params={}, evidence=["subject_user", "event_id"], steps=["Identify the actor and logon_id.", "Collect events before/after the clear from SIEM and forwarded copies.", "Check for wevtutil/Clear-EventLog (4688/Sysmon 1)."], fp="Planned maintenance or imaging.",
      tests=[dict(name="1102", events=[E(SEC, 1102, 0, subject_user="adm")], expect=True), dict(name="4624", events=[E(SEC, 4624, 0)], expect=False)])
def ps003(ev, h, p): return dict(summary=f"Security audit log cleared by {ev.get('subject_user') or 'unknown'}", evidence=[ev])
RULES["PS-003"]["match"] = ps003

@rule("PS-004", "Audit policy changed", "System audit policy changed (4719).", [SEC], [4719], severity="Medium", confidence=0.5, mitre="T1562.002 Disable Windows Event Logging", params={}, evidence=["subject_user", "extra.changes"],
      steps=["Compare to expected GPO.", "Check actor."], fp="Group Policy refreshes and baseline hardening.", tests=[dict(name="4719", events=[E(SEC, 4719, 0, subject_user="adm")], expect=True), dict(name="4720", events=[E(SEC, 4720, 0)], expect=False)])
def ps004(ev, h, p): return dict(summary=f"Audit policy changed by {ev.get('subject_user')}", evidence=[ev])
RULES["PS-004"]["match"] = ps004

# ================= runtime =================
def applicable(r, ev):
    return ev.get("source") in r["sources"] and (r["event_ids"] is None or ev.get("event_id") in r["event_ids"]) and (r["activities"] is None or ev.get("activity") in r["activities"])
def allowlisted(ev, rule_id, entries):
    for a in entries:
        if a.get("rule_id") not in (None, "", rule_id): continue
        v = ev.get(a["field"]); v = (ev.get("extra") or {}).get(a["field"]) if v is None else v
        if v is not None and fnmatch.fnmatch(str(v).lower(), str(a["value"]).lower()): return a
    return None
def evaluate(ev, hist, cfg=None, allow=()):
    """-> list of hits [dict(rule_id, rule_name, version, severity, confidence, summary, evidence, ...)]. cfg: {rule_id: {enabled, params}}. Never raises."""
    hits = []
    for rid, r in RULES.items():
        c = (cfg or {}).get(rid) or {}
        if c.get("enabled") is False or not r["enabled"] and c.get("enabled") is not True: continue
        if not applicable(r, ev) or allowlisted(ev, rid, allow): continue
        try: res = r["match"](ev, hist, {**r["params"], **(c.get("params") or {})})
        except Exception: continue
        if res: hits.append(dict(rule_id=rid, rule_name=r["name"], version=r["version"], severity=res.get("severity") or r["severity"], confidence=res.get("confidence") or r["confidence"], summary=res["summary"], evidence=res["evidence"], mitre=r["mitre"]))
    return hits

def run_case(rid, case):
    r = RULES[rid]; evs = case["events"]; cur = evs[-1]; cur = dict(cur, extra=cur.get("extra") or {})
    for e in evs: e.setdefault("extra", {}); e.setdefault("activity", e.get("activity"))
    cfg = {rid: {"params": case["params"]}} if case.get("params") else {}
    return [h for h in evaluate(cur, MemHist(evs), cfg) if h["rule_id"] == rid]
