"""Pure normalisation: stored/ingested events -> unified schema dict. No DB access. Never invents fields: absent source fields stay None.
Entry points: normalize_item(item)  (what /api/ingest items look like: channel,event_id,provider,record_id,event_time,host,message,raw)
              parse_event_xml(xml)  (a single <Event> from wevtutil / EvtRender)."""
import re, json, hashlib
import xml.etree.ElementTree as ET
from datetime import datetime, timezone
from .schema import SCHEMA_VERSION
from .redact import redact

NS = "{http://schemas.microsoft.com/win/2004/08/events/event}"
SYSMON_CH = "microsoft-windows-sysmon/operational"
SEC_GROUP_SCOPE = {4728: "global", 4729: "global", 4732: "local", 4733: "local", 4756: "universal", 4757: "universal"}
SEC_ACTIVITY = {4624: "logon_success", 4625: "logon_failure", 4634: "logoff", 4647: "user_logoff", 4648: "explicit_credentials", 4740: "account_lockout",
 4768: "kerberos_tgt_request", 4769: "kerberos_service_ticket", 4771: "kerberos_preauth_failed", 4776: "ntlm_credential_validation",
 4688: "process_created", 4689: "process_terminated", 4672: "special_privileges_assigned", 4673: "privileged_service_called", 4674: "privileged_object_operation",
 4720: "account_created", 4722: "account_enabled", 4723: "password_change_attempt", 4724: "password_reset_attempt", 4725: "account_disabled", 4726: "account_deleted",
 4728: "group_member_added", 4729: "group_member_removed", 4732: "group_member_added", 4733: "group_member_removed", 4756: "group_member_added", 4757: "group_member_removed",
 1102: "audit_log_cleared", 4719: "audit_policy_changed", 4697: "service_installed", 4698: "task_created", 4699: "task_deleted", 4700: "task_enabled", 4701: "task_disabled", 4702: "task_updated"}
SYSMON_ACTIVITY = {1: "process_created", 3: "network_connection", 5: "process_terminated", 7: "image_loaded", 8: "create_remote_thread", 10: "process_access", 11: "file_created",
 12: "registry_object", 13: "registry_value_set", 14: "registry_rename", 22: "dns_query", 23: "file_delete_archived", 26: "file_delete_detected"}

# ---------- helpers ----------
def _s(v, n=2000):
    if v is None: return None
    v = str(v).replace("\x00", "").strip()
    return v[:n] if v and v not in ("-",) else None
def _int(v):
    try:
        s = str(v).strip()
        return int(s, 16) if s.lower().startswith("0x") else int(s)
    except (TypeError, ValueError): return None
def _ip(v):
    v = _s(v)
    if not v: return None
    v = v.replace("::ffff:", "")
    return None if v in ("::1", "127.0.0.1", "::", "0.0.0.0", "-") and False else v
def _base(p): return re.split(r"[\\/]", p or "")[-1] or None
def _user(u):
    u = _s(u)
    return u if u else None

def to_utc(ts):
    """ISO / Sysmon UtcTime / epoch -> 'YYYY-MM-DDTHH:MM:SS.mmmZ' (UTC). Unparseable -> None (never guessed)."""
    if ts is None or ts == "": return None
    try:
        if isinstance(ts, (int, float)): return datetime.fromtimestamp(float(ts), timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z"
        s = str(ts).strip().replace(" UTC", "")
        m = re.match(r"^(\d{4}-\d\d-\d\d)[T ](\d\d:\d\d:\d\d)(?:\.(\d+))?\s*(Z|[+-]\d\d:?\d\d)?$", s)
        if not m: return None
        d, t, fr, tz = m.groups()
        dt = datetime.strptime(f"{d} {t}", "%Y-%m-%d %H:%M:%S")
        us = int((fr or "0")[:6].ljust(6, "0"))
        dt = dt.replace(microsecond=us, tzinfo=timezone.utc)
        if tz and tz != "Z":
            sign = 1 if tz[0] == "+" else -1; tz = tz.replace(":", "")
            from datetime import timedelta
            dt = dt - sign * timedelta(hours=int(tz[1:3]), minutes=int(tz[3:5]))
        return dt.strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z"
    except Exception: return None

def blank():
    return dict(schema_version=SCHEMA_VERSION, event_id=None, event_record_id=None, timestamp=None, host=None, hostname=None, platform=None, source=None, channel=None, provider=None,
                username=None, subject_user=None, target_username=None, logon_type=None, logon_id=None, source_ip=None, source_port=None, destination_ip=None, destination_port=None,
                protocol=None, process_id=None, process_guid=None, process_name=None, image=None, command_line=None, parent_process_id=None, parent_process_guid=None,
                parent_process_name=None, current_directory=None, hashes=None, integrity_level=None, dns_query_name=None, file_path=None, target_filename=None, registry_key=None,
                registry_value=None, service_name=None, task_name=None, group_name=None, rule_name=None, raw_event=None, collector_name=None, extra={}, activity=None)

# ---------- Windows ----------
def _xml_data(ev):
    d = {}
    for n in ev.iter(NS + "Data"):
        if n.get("Name"): d[n.get("Name")] = n.text or ""
    ud = ev.find(NS + "UserData")
    if ud is not None:
        for child in list(ud):
            for n in child.iter():
                if n is not child and (n.text or "").strip(): d[n.tag.split("}")[-1]] = n.text.strip()
    return d

def parse_event_xml(xml, host=None, collector="wevtutil"):
    """Single <Event> XML -> normalised dict, or None when malformed / not an event. Raw XML is retained (bounded, redacted)."""
    try: ev = ET.fromstring(re.sub(r"<\?xml[^>]*\?>", "", xml or "").strip())
    except ET.ParseError: return None
    sysn = ev.find(NS + "System")
    if sysn is None: return None
    prov = sysn.find(NS + "Provider"); tc = sysn.find(NS + "TimeCreated")
    comp = sysn.findtext(NS + "Computer")
    n = from_windows(dict(event_id=_int(sysn.findtext(NS + "EventID")), record_id=_int(sysn.findtext(NS + "EventRecordID")), channel=sysn.findtext(NS + "Channel"),
                          provider=prov.get("Name") if prov is not None else None, event_time=tc.get("SystemTime") if tc is not None else None,
                          host=host or comp, version=_int(sysn.findtext(NS + "Version"))), _xml_data(ev))
    if n: n["raw_event"] = redact(xml, 8000); n["collector_name"] = collector
    return n

def from_windows(meta, d):
    ch = (meta.get("channel") or "").strip(); chl = ch.lower(); eid = _int(meta.get("event_id"))
    if eid is None: return None
    n = blank(); n.update(event_id=eid, event_record_id=_int(meta.get("record_id")), channel=ch or None, provider=_s(meta.get("provider"), 200), platform="windows",
                          host=_s(meta.get("host"), 200), timestamp=to_utc(meta.get("event_time")))
    n["hostname"] = n["host"]
    g = lambda *k: next((v for kk in k if (v := _s(d.get(kk))) is not None), None)
    n["extra"] = {k: _s(v, 500) for k, v in d.items() if v not in (None, "") and k in _KEEP_EXTRA}
    if meta.get("version") is not None: n["extra"]["event_version"] = meta["version"]
    if chl == SYSMON_CH or (meta.get("provider") or "").lower() == "microsoft-windows-sysmon":
        n["source"] = "sysmon"; n["activity"] = SYSMON_ACTIVITY.get(eid)
        ut = to_utc(d.get("UtcTime"))
        if ut: n["timestamp"] = ut
        u = g("User"); n.update(username=u, process_guid=g("ProcessGuid"), process_id=_int(d.get("ProcessId")), image=g("Image"), command_line=redact(g("CommandLine")),
                                current_directory=g("CurrentDirectory"), hashes=g("Hashes"), integrity_level=g("IntegrityLevel"), logon_id=g("LogonId"),
                                parent_process_guid=g("ParentProcessGuid"), parent_process_id=_int(d.get("ParentProcessId")))
        n["process_name"] = _base(n["image"]); n["parent_process_name"] = _base(g("ParentImage"))
        if g("ParentImage"): n["extra"]["parent_image"] = g("ParentImage")
        if eid == 3: n.update(protocol=g("Protocol"), source_ip=_ip(g("SourceIp")), source_port=_int(d.get("SourcePort")), destination_ip=_ip(g("DestinationIp")), destination_port=_int(d.get("DestinationPort")))
        if eid == 3 and g("DestinationHostname"): n["dns_query_name"] = g("DestinationHostname")
        if eid == 22: n["dns_query_name"] = g("QueryName"); n["extra"]["query_results"] = g("QueryResults")
        if eid in (11, 23, 26): n["target_filename"] = g("TargetFilename"); n["file_path"] = n["target_filename"]
        if eid in (12, 13, 14): n.update(registry_key=g("TargetObject"), registry_value=redact(g("Details", "NewName")))
        if eid == 7: n["file_path"] = g("ImageLoaded")
        if eid in (8, 10):
            n["image"] = g("SourceImage"); n["process_name"] = _base(n["image"]); n["process_guid"] = g("SourceProcessGuid", "SourceProcessGUID"); n["process_id"] = _int(d.get("SourceProcessId"))
            n["extra"].update(target_image=g("TargetImage"), target_process_guid=g("TargetProcessGuid", "TargetProcessGUID"), granted_access=g("GrantedAccess"))
            n["file_path"] = g("TargetImage")
        n["username"] = _user(n["username"]); n["target_username"] = None
        return n
    if chl != "security" and eid not in (1102,): 
        n["source"] = "windows_" + (re.sub(r"[^a-z0-9]+", "_", chl.split("/")[0].replace("microsoft-windows-", "")) or "other"); n["activity"] = None
        return n
    n["source"] = "windows_security"; n["activity"] = SEC_ACTIVITY.get(eid)
    n["subject_user"] = g("SubjectUserName"); n["target_username"] = g("TargetUserName")
    if eid in (4624, 4625, 4634, 4647, 4648, 4768, 4769, 4771, 4776): n["username"] = n["target_username"]
    else: n["username"] = n["subject_user"]
    if eid == 4776: n["target_username"] = g("TargetUserName"); n["username"] = n["target_username"]; n["extra"]["workstation"] = g("Workstation")
    if eid in (4624, 4625, 4634, 4647): n["logon_type"] = g("LogonType"); n["logon_id"] = g("TargetLogonId")
    if eid in (4648, 4672, 4688, 4689, 4673, 4674): n["logon_id"] = g("SubjectLogonId")
    if eid in (4624, 4625, 4648, 4768, 4769, 4771): n["source_ip"] = _ip(g("IpAddress")); n["source_port"] = _int(d.get("IpPort"))
    if eid in (4624, 4625): n["source_ip"] = n["source_ip"] or _ip(g("SourceNetworkAddress")); n["process_name"] = _base(g("ProcessName")); n["extra"]["logon_process"] = g("LogonProcessName"); n["extra"]["auth_package"] = g("AuthenticationPackageName"); n["extra"]["workstation"] = g("WorkstationName")
    if eid == 4625: n["extra"].update(status=g("Status"), sub_status=g("SubStatus"))
    if eid == 4648: n["process_name"] = _base(g("ProcessName")); n["image"] = g("ProcessName"); n["extra"]["target_server"] = g("TargetServerName")
    if eid == 4672: n["extra"]["privileges"] = g("PrivilegeList")
    if eid == 4688:
        n["process_id"] = _int(d.get("NewProcessId")); n["image"] = g("NewProcessName"); n["process_name"] = _base(n["image"])
        n["command_line"] = redact(g("CommandLine")); n["parent_process_id"] = _int(d.get("ProcessId")); pn = g("ParentProcessName")
        n["parent_process_name"] = _base(pn); n["integrity_level"] = g("MandatoryLabel")
        if pn: n["extra"]["parent_image"] = pn
        n["extra"]["token_elevation"] = g("TokenElevationType"); n["target_username"] = g("TargetUserName")
        n["extra"]["cmdline_field_present"] = "CommandLine" in d
    if eid == 4689: n["process_id"] = _int(d.get("ProcessId")); n["image"] = g("ProcessName"); n["process_name"] = _base(n["image"])
    if eid == 4740: n["extra"]["caller_computer"] = g("TargetDomainName")
    if eid in (4768, 4769, 4771): n["service_name"] = g("ServiceName"); n["extra"].update(status=g("Status"), ticket_encryption=g("TicketEncryptionType"))
    if eid in SEC_GROUP_SCOPE:
        n["group_name"] = g("TargetUserName"); n["target_username"] = g("MemberName", "MemberSid"); n["extra"].update(group_scope=SEC_GROUP_SCOPE[eid], group_sid=g("TargetSid")); n["username"] = n["subject_user"]
    if eid in (4720, 4722, 4723, 4724, 4725, 4726): n["username"] = n["subject_user"]
    if eid == 1102: n["subject_user"] = g("SubjectUserName"); n["username"] = n["subject_user"]
    if eid == 4719: n["extra"].update(category=g("CategoryId"), subcategory=g("SubcategoryId"), changes=g("AuditPolicyChanges"))
    if eid == 4697: n["service_name"] = g("ServiceName"); n["file_path"] = g("ServiceFileName"); n["extra"]["service_type"] = g("ServiceType")
    if eid in (4698, 4699, 4700, 4701, 4702): n["task_name"] = g("TaskName"); n["extra"]["task_content"] = redact(g("TaskContent"), 1500)
    return n

_KEEP_EXTRA = {"Status", "SubStatus", "TokenElevationType", "PrivilegeList", "Signed", "Initiated", "EventType", "GrantedAccess", "CallTrace"}

# ---------- Linux ----------
IPR = r"(\d{1,3}(?:\.\d{1,3}){3}|[0-9a-fA-F:]{3,39})"
def from_linux(item, d=None):
    """Linux journal / auth.log / auditd line -> unified event. Source-specific semantics are preserved in `activity`/`extra`; NO Windows event ids are fabricated (event_id stays None)."""
    msg = item.get("message") or ""; prov = (item.get("provider") or "").lower(); ch = item.get("channel") or ""
    n = blank(); n.update(platform="linux", host=_s(item.get("host"), 200), channel=ch or None, provider=_s(item.get("provider"), 200), event_record_id=_int(item.get("record_id")),
                          timestamp=to_utc(item.get("event_time")), raw_event=redact(item.get("raw") if isinstance(item.get("raw"), str) else json.dumps(item.get("raw") or {}), 8000))
    n["hostname"] = n["host"]; n["extra"] = {}
    chl = ch.lower()
    if "audit" in chl or prov == "auditd" or msg.startswith("type="): n["source"] = "linux_auditd"
    elif "ufw" in chl or "UFW BLOCK" in msg or "UFW ALLOW" in msg or "[UFW" in msg: n["source"] = "linux_firewall"
    elif prov in ("sshd", "sudo", "su", "login", "useradd", "usermod", "groupadd", "passwd", "gdm-password", "polkitd", "systemd-logind", "cron", "pkexec") or chl.endswith(("auth.log", "secure")): n["source"] = "linux_auth"
    else: n["source"] = "linux_journal"
    m = re.search(r"Failed (\w+) for (?:invalid user )?(\S+) from " + IPR + r"(?: port (\d+))?", msg)
    if m: n.update(activity="ssh_auth_failure", target_username=m.group(2), source_ip=m.group(3), source_port=_int(m.group(4))); n["extra"]["method"] = m.group(1)
    m = m or None
    if not n["activity"]:
        m = re.search(r"Invalid user (\S+) from " + IPR + r"(?: port (\d+))?", msg)
        if m: n.update(activity="ssh_invalid_user", target_username=m.group(1), source_ip=m.group(2), source_port=_int(m.group(3)))
    if not n["activity"]:
        m = re.search(r"Accepted (\w+) for (\S+) from " + IPR + r"(?: port (\d+))?", msg)
        if m: n.update(activity="ssh_auth_success", target_username=m.group(2), source_ip=m.group(3), source_port=_int(m.group(4))); n["extra"]["method"] = m.group(1)
    if not n["activity"] and prov == "sudo":
        m = re.match(r"\s*(\S+)\s*:\s*(.*)", msg)
        if m:
            n["subject_user"] = m.group(1); body = m.group(2)
            cmd = re.search(r"COMMAND=(.*)$", body); run = re.search(r"USER=(\S+)", body)
            if cmd: n["command_line"] = redact(cmd.group(1)); 
            if run: n["target_username"] = run.group(1)
            if re.search(r"not in the sudoers|user NOT in sudoers", body, re.I): n["activity"] = "sudo_denied"
            elif re.search(r"incorrect password|authentication failure", body, re.I): n["activity"] = "sudo_auth_failure"
            elif cmd: n["activity"] = "sudo_command"
    if not n["activity"] and prov in ("su", "su-l"):
        m = re.search(r"(?:FAILED SU|authentication failure).*?(?:\(to (\S+)\))?\s*(\S+)? on", msg, re.I)
        if re.search(r"FAILED SU|authentication failure", msg, re.I): n["activity"] = "su_failure"
        elif re.search(r"session opened for user (\S+)", msg): n["activity"] = "su_success"; n["target_username"] = re.search(r"session opened for user (\S+)", msg).group(1)
    if not n["activity"] and prov in ("useradd", "usermod", "groupadd", "passwd"):
        if re.search(r"new user: name=(\S+?),", msg): n["activity"] = "user_created"; n["target_username"] = re.search(r"new user: name=(\S+?),", msg).group(1)
        elif re.search(r"add '(\S+)' to (?:shadow )?group '(\S+)'", msg): a = re.search(r"add '(\S+)' to (?:shadow )?group '(\S+)'", msg); n.update(activity="group_member_added", target_username=a.group(1), group_name=a.group(2))
    if n["source"] == "linux_auditd" and not n["activity"]:
        t = re.match(r"type=(\w+)", msg)
        if t:
            ty = t.group(1); kv = dict(re.findall(r'(\w+)=("[^"]*"|\S+)', msg)); kv = {k: v.strip('"') for k, v in kv.items()}
            n["extra"]["audit_type"] = ty; n["activity"] = "audit_" + ty.lower()
            n["process_id"] = _int(kv.get("pid")); n["parent_process_id"] = _int(kv.get("ppid")); n["process_name"] = _s(kv.get("comm")); n["image"] = _s(kv.get("exe"))
            n["username"] = _s(kv.get("acct") or kv.get("auid")) if kv.get("acct") or kv.get("auid") not in (None, "4294967295", "unset") else None
            if ty in ("CONFIG_CHANGE", "DAEMON_END", "DAEMON_ABORT", "DAEMON_CONFIG"): n["extra"]["op"] = _s(kv.get("op")) 
            if ty == "EXECVE": n["command_line"] = redact(" ".join(v for k, v in sorted(kv.items()) if re.fullmatch(r"a\d+", k)))
            if ty == "SYSCALL": n["extra"]["syscall"] = _s(kv.get("syscall")); n["extra"]["key"] = _s(kv.get("key"))
            if kv.get("addr") and re.match(r"\d", kv["addr"]): n["source_ip"] = kv["addr"]
    if n["source"] == "linux_firewall":
        kv = dict(re.findall(r"(\w+)=(\S*)", msg))
        n.update(activity="firewall_" + ("block" if "BLOCK" in msg or "DROP" in msg else "event"), source_ip=_s(kv.get("SRC")), destination_ip=_s(kv.get("DST")), protocol=_s(kv.get("PROTO")),
                 source_port=_int(kv.get("SPT")), destination_port=_int(kv.get("DPT")))
    if not n["source_ip"] and item.get("source_ip"): n["source_ip"] = _s(item.get("source_ip"), 64)
    n["username"] = n["username"] or n["target_username"] or n["subject_user"]
    n["extra"]["message"] = redact(msg, 1000)
    return n

# ---------- dispatcher ----------
def normalize_item(item):
    """Ingest item -> unified dict or None (None = nothing to normalise; the event stays in the legacy events table only). Never raises."""
    try:
        if not isinstance(item, dict): return None
        raw = item.get("raw"); d = raw if isinstance(raw, dict) else None
        if d is None and isinstance(raw, str) and raw.strip().startswith("{"):
            try: d = json.loads(raw)
            except Exception: d = None
        ch = (item.get("channel") or "").lower()
        eid = item.get("event_id")
        os_ = (item.get("os") or "").lower()
        is_win = bool(eid is not None and (ch in ("security", "system", "application") or "microsoft-windows" in ch or os_.startswith("win"))) and not (os_ == "linux")
        if is_win and isinstance(d, dict):
            n = from_windows(dict(event_id=eid, record_id=item.get("record_id"), channel=item.get("channel"), provider=item.get("provider"), event_time=item.get("event_time"), host=item.get("host")), d)
            if n:
                n["raw_event"] = redact(json.dumps(d, ensure_ascii=False), 8000); n["collector_name"] = "winevents"
            return n
        if ch and (ch == "journald" or ch.startswith("/") ) or os_ == "linux":
            n = from_linux(item); n["collector_name"] = "linuxlogs"; return n
        return None
    except Exception: return None

def dedupe_key(n):
    if n.get("event_record_id") is not None and n.get("channel"):
        base = f"{n['host']}|{n['source']}|{n['channel']}|{n['event_record_id']}|{n['event_id']}"
    else:
        base = "|".join(str(n.get(k)) for k in ("host", "source", "event_id", "timestamp", "username", "source_ip", "process_guid", "process_id", "command_line", "target_filename", "activity")) + "|" + str((n.get("extra") or {}).get("message"))
    return hashlib.sha1(base.encode("utf-8", "replace")).hexdigest()
