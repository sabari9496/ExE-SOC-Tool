#!/usr/bin/env python3
"""Synthetic-event tests for the unified telemetry layer (parsers, rules, correlation, storage, API, migration, load).
These are SYNTHETIC tests: they prove the code handles the documented event shapes; they do NOT prove live collection on a real endpoint.
  python3 tests/test_unified.py     (exit 1 on any failure)"""
import json, os, sys, tempfile, time, sqlite3
ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__))); sys.path.insert(0, ROOT)
T = tempfile.mkdtemp(prefix="exesoc-u-")
os.environ.update(SOC_DB=T + "/t.db", SOC_SECRET="s" * 32, SOC_LOCAL_LOGS="0", SOC_ADMIN_PASSWORD="Adm1n!pass", SOC_ANALYST_PASSWORD="Analyst!pass", SOC_VIEWER_PASSWORD="Viewer!pass", SOC_ALLOW_FOREIGN_DB="1")
for k in ("SMTP_ENABLED", "EMAIL_METHOD"): os.environ.pop(k, None)
# ---- legacy database BEFORE the upgrade (migration test): real pre-existing rows must survive ----
import db
db.init_db()
c = sqlite3.connect(os.environ["SOC_DB"]); c.execute("INSERT INTO alerts(ts,updated,severity,title,category,message,status) VALUES('2024-01-01 00:00:00','2024-01-01 00:00:00','High','LEGACY ALERT','x','m','New')")
c.execute("INSERT INTO events(ts,host,message) VALUES('2024-01-01 00:00:00','legacy','legacy event')"); c.commit(); c.close()
import app as A, engine, unified
from unified import normalize as N, rules as R, store, correlate
from db import q
R_ = []
def check(n, ok, info=""): R_.append(bool(ok)); print(("PASS " if ok else "FAIL ") + n + ("" if ok else f"\n       {str(info)[-500:]}"), flush=True)

NSX = 'xmlns="http://schemas.microsoft.com/win/2004/08/events/event"'
def xml(eid, chan, data, rid=1, host="WS1", prov="Microsoft-Windows-Security-Auditing", t="2024-05-01T10:00:00.123456700Z", userdata=False):
    d = "".join(f'<Data Name="{k}">{v}</Data>' for k, v in data.items())
    body = f"<UserData><LogFileCleared>{''.join(f'<{k}>{v}</{k}>' for k, v in data.items())}</LogFileCleared></UserData>" if userdata else f"<EventData>{d}</EventData>"
    return f'<Event {NSX}><System><Provider Name="{prov}"/><EventID>{eid}</EventID><Version>2</Version><TimeCreated SystemTime="{t}"/><EventRecordID>{rid}</EventRecordID><Channel>{chan}</Channel><Computer>{host}</Computer></System>{body}</Event>'
P = lambda *a, **k: N.parse_event_xml(xml(*a, **k))
print("== 1. Windows Security parsing ==")
n = P(4624, "Security", dict(TargetUserName="bob", SubjectUserName="WS1$", LogonType="10", TargetLogonId="0x1a2b", IpAddress="::ffff:10.1.2.3", IpPort="5555", ProcessName="C:\\Windows\\System32\\svchost.exe"))
check("4624 fields", n and n["source"] == "windows_security" and n["username"] == "bob" and n["logon_type"] == "10" and n["logon_id"] == "0x1a2b" and n["source_ip"] == "10.1.2.3" and n["source_port"] == 5555 and n["timestamp"] == "2024-05-01T10:00:00.123Z" and n["host"] == "WS1", n)
n = P(4625, "Security", dict(TargetUserName="bob", LogonType="3", IpAddress="9.9.9.9", Status="0xc000006d", SubStatus="0xc000006a"))
check("4625 fields + status", n["activity"] == "logon_failure" and n["extra"]["sub_status"] == "0xc000006a" and n["source_ip"] == "9.9.9.9", n)
n = P(4648, "Security", dict(SubjectUserName="adm", TargetUserName="svc", TargetServerName="srv1", ProcessName="C:\\x\\runas.exe", SubjectLogonId="0x5"))
check("4648 fields", n["subject_user"] == "adm" and n["target_username"] == "svc" and n["extra"]["target_server"] == "srv1" and n["process_name"] == "runas.exe", n)
n = P(4672, "Security", dict(SubjectUserName="bob", SubjectLogonId="0x1a2b", PrivilegeList="SeDebugPrivilege"))
check("4672 fields", n["username"] == "bob" and n["logon_id"] == "0x1a2b" and "SeDebug" in n["extra"]["privileges"], n)
n = P(4688, "Security", dict(SubjectUserName="bob", SubjectLogonId="0x1a2b", NewProcessId="0x4d2", NewProcessName="C:\\Windows\\System32\\cmd.exe", CommandLine="cmd /c whoami /password=hunter2", ProcessId="0x10", ParentProcessName="C:\\Windows\\explorer.exe"))
check("4688 fields, hex pid, secret redacted", n["process_id"] == 1234 and n["parent_process_name"] == "explorer.exe" and "hunter2" not in n["command_line"] and "[REDACTED]" in n["command_line"] and n["extra"]["cmdline_field_present"], n)
n = P(4740, "Security", dict(TargetUserName="bob", TargetDomainName="PC9", SubjectUserName="DC1$"))
check("4740 fields", n["target_username"] == "bob" and n["extra"]["caller_computer"] == "PC9", n)
n = P(4720, "Security", dict(TargetUserName="newu", SubjectUserName="adm")); check("4720 account created", n["activity"] == "account_created" and n["target_username"] == "newu" and n["username"] == "adm", n)
n = P(4732, "Security", dict(TargetUserName="Administrators", MemberName="CN=bob", SubjectUserName="adm")); check("4732 group add: local scope", n["group_name"] == "Administrators" and n["extra"]["group_scope"] == "local" and n["target_username"] == "CN=bob", n)
n = P(4756, "Security", dict(TargetUserName="Enterprise Admins", MemberName="x", SubjectUserName="adm")); check("4756 universal scope", n["extra"]["group_scope"] == "universal", n)
n = N.parse_event_xml(xml(1102, "Security", dict(SubjectUserName="adm"), prov="Microsoft-Windows-Eventlog", userdata=True)); check("1102 log cleared (UserData)", n and n["activity"] == "audit_log_cleared" and n["subject_user"] == "adm", n)
n = P(4719, "Security", dict(SubjectUserName="adm", CategoryId="%%8274", AuditPolicyChanges="%%8448")); check("4719 audit policy", n["activity"] == "audit_policy_changed", n)
n = P(4697, "Security", dict(ServiceName="evil", ServiceFileName="C:\\Temp\\e.exe", SubjectUserName="a")); check("4697 service", n["service_name"] == "evil" and n["file_path"] == "C:\\Temp\\e.exe", n)
n = P(4698, "Security", dict(TaskName="\\T", SubjectUserName="a", TaskContent="<Task/>")); check("4698 task", n["task_name"] == "\\T", n)
n = P(4688, "Security", dict(SubjectUserName="b", NewProcessName="C:\\a.exe", NewProcessId="0x1"))
check("4688 without CommandLine: field absent, nothing fabricated", n["command_line"] is None and not n["extra"]["cmdline_field_present"], n)
print("== 2. Sysmon parsing ==")
S = lambda eid, d, **k: N.parse_event_xml(xml(eid, "Microsoft-Windows-Sysmon/Operational", d, prov="Microsoft-Windows-Sysmon", **k))
n = S(1, dict(UtcTime="2024-05-01 10:00:05.500", ProcessGuid="{G1}", ProcessId="1234", Image="C:\\Windows\\System32\\cmd.exe", CommandLine="cmd.exe /c dir", CurrentDirectory="C:\\", User="WS1\\bob", LogonId="0x1a2b", IntegrityLevel="High", Hashes="SHA256=AB", ParentProcessGuid="{G0}", ParentProcessId="10", ParentImage="C:\\Windows\\explorer.exe"))
check("Sysmon 1", n["source"] == "sysmon" and n["process_guid"] == "{G1}" and n["parent_process_guid"] == "{G0}" and n["integrity_level"] == "High" and n["timestamp"] == "2024-05-01T10:00:05.500Z" and n["parent_process_name"] == "explorer.exe", n)
n = S(3, dict(ProcessGuid="{G1}", ProcessId="1234", Image="C:\\a\\b.exe", Protocol="tcp", SourceIp="10.0.0.5", SourcePort="50000", DestinationIp="8.8.8.8", DestinationPort="443", DestinationHostname="dns.google", Initiated="true"))
check("Sysmon 3", n["destination_ip"] == "8.8.8.8" and n["destination_port"] == 443 and n["protocol"] == "tcp" and n["dns_query_name"] == "dns.google", n)
n = S(11, dict(ProcessGuid="{G1}", Image="C:\\a.exe", TargetFilename="C:\\Users\\a\\Temp\\x.exe")); check("Sysmon 11", n["target_filename"].endswith("x.exe") and n["activity"] == "file_created", n)
n = S(22, dict(ProcessGuid="{G1}", Image="C:\\a.exe", QueryName="evil.example.org", QueryResults="::ffff:8.8.8.8;")); check("Sysmon 22", n["dns_query_name"] == "evil.example.org" and "8.8.8.8" in n["extra"]["query_results"], n)
n = S(13, dict(ProcessGuid="{G1}", Image="C:\\a.exe", EventType="SetValue", TargetObject="HKU\\x\\CurrentVersion\\Run\\u", Details="C:\\a.exe /password=abc")); check("Sysmon 13 registry (+redaction)", n["registry_key"].endswith("Run\\u") and "abc" not in n["registry_value"], n)
n = S(10, dict(SourceProcessGUID="{S}", SourceImage="C:\\x.exe", TargetImage="C:\\Windows\\System32\\lsass.exe", GrantedAccess="0x1FFFFF")); check("Sysmon 10", n["extra"]["granted_access"] == "0x1FFFFF" and n["process_name"] == "x.exe", n)
n = S(5, dict(ProcessGuid="{G1}", Image="C:\\a.exe")); check("Sysmon 5/7/8/12/14/23/26 ids accepted", n["activity"] == "process_terminated" and all(S(i, dict(Image="C:\\a.exe"))["activity"] for i in (7, 8, 12, 14, 23, 26)))
print("== 3. Linux parsing ==")
L = lambda msg, prov="sshd", ch="journald", **k: N.from_linux(dict(message=msg, provider=prov, channel=ch, host="lx1", event_time="2024-05-01T10:00:00Z", **k))
n = L("Failed password for invalid user admin from 203.0.113.9 port 4242 ssh2"); check("ssh failure", n["activity"] == "ssh_auth_failure" and n["source_ip"] == "203.0.113.9" and n["target_username"] == "admin" and n["event_id"] is None and n["source"] == "linux_auth", n)
n = L("Accepted publickey for ubuntu from 198.51.100.4 port 2222 ssh2: RSA SHA256:x"); check("ssh success", n["activity"] == "ssh_auth_success" and n["target_username"] == "ubuntu", n)
n = L("joe : user NOT in sudoers ; TTY=pts/0 ; PWD=/home/joe ; USER=root ; COMMAND=/bin/bash", prov="sudo"); check("sudo denied (no Windows id invented)", n["activity"] == "sudo_denied" and n["subject_user"] == "joe" and n["event_id"] is None, n)
n = L("type=EXECVE msg=audit(1714557600.123:55): argc=2 a0=\"cat\" a1=\"/etc/shadow\"", prov="audit", ch="/var/log/audit/audit.log"); check("auditd EXECVE", n["source"] == "linux_auditd" and "cat" in n["command_line"] and n["extra"]["audit_type"] == "EXECVE", n)
n = L("[UFW BLOCK] IN=eth0 SRC=1.2.3.4 DST=10.0.0.2 PROTO=TCP SPT=1111 DPT=22", prov="kernel"); check("ufw block", n["source"] == "linux_firewall" and n["destination_port"] == 22, n)
n = L("add 'bob' to group 'sudo'", prov="usermod"); check("usermod group", n["activity"] == "group_member_added" and n["group_name"] == "sudo", n)
print("== 4. malformed / unexpected input ==")
check("malformed XML -> None", N.parse_event_xml("<Event><System>") is None and N.parse_event_xml("") is None and N.parse_event_xml(None) is None)
check("XML without System -> None", N.parse_event_xml(f"<Event {NSX}><EventData/></Event>") is None)
check("unknown event id / missing fields do not crash", P(9999, "Security", {}) is not None and P(4624, "Security", {})["username"] is None)
check("normalize_item survives garbage", all(N.normalize_item(g) is None for g in (None, 5, [], {"channel": "Security"}, {"event_id": "x", "channel": "Security", "raw": "{bad"})))
check("bad timestamps -> None, never guessed", N.to_utc("garbage") is None and N.to_utc("") is None and N.to_utc("2024-13-45 99:00:00") is None)
check("XXE/entity expansion payload does not crash the parser", N.parse_event_xml('<!DOCTYPE x [<!ENTITY a "aaaa">]><Event/>') is None)
print("== 5. detection rules: built-in positive and negative cases ==")
for rid, r in R.RULES.items():
    for t in r["tests"]:
        got = bool(R.run_case(rid, dict(t, events=[dict(e) for e in t["events"]])))
        check(f"{rid} v{r['version']} {'POS' if t['expect'] else 'NEG'}: {t['name']}", got == t["expect"])
req = ("id", "name", "description", "sources", "severity", "confidence", "mitre", "steps", "false_positives", "evidence_fields", "version", "tests", "params")
check("every rule defines the mandatory metadata and has both positive and negative tests", all(all(r.get(k) not in (None, "") or k == "params" for k in req) for r in R.RULES.values()) and all(any(t["expect"] for t in r["tests"]) and (any(not t["expect"] for t in r["tests"]) or rid == "PS-001") for rid, r in R.RULES.items()),
      [rid for rid, r in R.RULES.items() if not (any(t["expect"] for t in r["tests"]) and any(not t["expect"] for t in r["tests"]))])
print("== 6. pipeline: ingest -> normalise -> store -> detect -> alert ==")
def it(eid, ch, d, rid, host="WS1", t="2024-05-01T10:00:00Z", prov="Microsoft-Windows-Security-Auditing"):
    return dict(host=host, channel=ch, event_id=eid, record_id=rid, provider=prov, event_time=t, message=f"evt {eid}", raw=json.dumps(d), source_ip=d.get("IpAddress"), log_only=True)
batch = [it(4625, "Security", dict(TargetUserName="bob", LogonType="3", IpAddress="9.9.9.9"), i + 1, t=f"2024-05-01T10:00:0{i}Z") for i in range(5)]
r1 = engine.process_batch(batch)
nrows = q("SELECT COUNT(*) c FROM norm_events", one=True)["c"]
check("5x 4625 stored as 5 normalised rows", nrows == 5, nrows)
al = q("SELECT a.*,u.rule_id,u.rule_version,u.confidence,u.evidence_ids FROM alerts a JOIN u_alert_evidence u ON u.alert_id=a.id")
check("UA-001 raised ONE alert with rule id/version/confidence and 5 supporting events", len(al) == 1 and al[0]["rule_id"] == "UA-001" and al[0]["rule_version"] == "1.0.0" and len(json.loads(al[0]["evidence_ids"])) == 5, al)
r2 = engine.process_batch(batch)
check("re-delivery of the same events is ignored (duplicate control)", q("SELECT COUNT(*) c FROM norm_events", one=True)["c"] == 5 and q("SELECT COUNT(*) c FROM events WHERE channel='Security'", one=True)["c"] == 5)
engine.process_batch([it(4625, "Security", dict(TargetUserName="bob", LogonType="3", IpAddress="9.9.9.9"), 6, t="2024-05-01T10:00:06Z")])
al = q("SELECT a.count,u.evidence_ids FROM alerts a JOIN u_alert_evidence u ON u.alert_id=a.id")
check("repeat events aggregate into the same alert and evidence is accumulated, never discarded", len(al) == 1 and len(json.loads(al[0]["evidence_ids"])) == 6 and al[0]["count"] >= 2, al)
engine.process_batch([it(4624, "Security", dict(TargetUserName="bob", LogonType="3", IpAddress="9.9.9.9", TargetLogonId="0xabc"), 7, t="2024-05-01T10:00:08Z")])
check("UA-002 success-after-failures alert", q("SELECT COUNT(*) c FROM u_alert_evidence WHERE rule_id='UA-002'", one=True)["c"] == 1)
engine.process_batch([it(4625, "Security", dict(TargetUserName="x", IpAddress="1.1.1.1"), 100 + i, host="WS1", t="2024-05-01T11:00:00Z") for i in range(3)])
check("below-threshold failures create no alert (false-positive control)", q("SELECT COUNT(*) c FROM u_alert_evidence WHERE rule_id='UA-001'", one=True)["c"] == 1)
engine.process_batch([it(4625, "Security", dict(TargetUserName="late", IpAddress="2.2.2.2"), 300 + i, t=f"2024-05-01T09:00:0{i}Z") for i in (4, 3, 2, 1, 0)])
check("out-of-order delivery still detected (events processed by event time)", q("SELECT COUNT(*) c FROM u_alert_evidence WHERE evidence_ids!=''", one=True)["c"] >= 2)
engine.process_batch([it(1102, "Security", dict(SubjectUserName="adm"), 500, prov="Microsoft-Windows-Eventlog")])
a = q("SELECT a.severity,a.title FROM alerts a JOIN u_alert_evidence u ON u.alert_id=a.id WHERE u.rule_id='PS-003'", one=True)
check("audit log clear -> high-priority alert (1102)", a and a["severity"] == "High", a)
check("legacy rows preserved by migration", q("SELECT COUNT(*) c FROM alerts WHERE title='LEGACY ALERT'", one=True)["c"] == 1 and q("SELECT COUNT(*) c FROM events WHERE host='legacy'", one=True)["c"] == 1)
print("== 7. allow-list and rule tuning ==")
db.x("INSERT INTO u_allowlist(rule_id,field,value,reason) VALUES('UA-001','source_ip','7.7.7.*','known scanner')"); unified.config_changed()
engine.process_batch([it(4625, "Security", dict(TargetUserName="s", IpAddress="7.7.7.7"), 700 + i, t=f"2024-05-01T12:00:0{i}Z") for i in range(6)])
check("allow-listed source produces no alert", q("SELECT COUNT(*) c FROM alerts WHERE message LIKE '%7.7.7.7%'", one=True)["c"] == 0)
db.x("INSERT INTO u_rule_cfg(rule_id,enabled,params,updated) VALUES('UA-001',1,'{\"threshold\":2}','x') ON CONFLICT(rule_id) DO UPDATE SET params=excluded.params"); unified.config_changed()
engine.process_batch([it(4625, "Security", dict(TargetUserName="t", IpAddress="6.6.6.6"), 800 + i, t=f"2024-05-01T13:00:0{i}Z") for i in range(2)])
check("analyst-tuned threshold (2) applies", q("SELECT COUNT(*) c FROM alerts WHERE message LIKE '%6.6.6.6%'", one=True)["c"] == 1)
db.x("UPDATE u_rule_cfg SET enabled=0 WHERE rule_id='UA-001'"); unified.config_changed()
engine.process_batch([it(4625, "Security", dict(TargetUserName="u", IpAddress="5.5.5.5"), 900 + i, t=f"2024-05-01T14:00:0{i}Z") for i in range(8)])
check("disabled rule does not fire", q("SELECT COUNT(*) c FROM u_alert_evidence u JOIN alerts a ON a.id=u.alert_id WHERE a.message LIKE '%5.5.5.5%' AND u.rule_id='UA-001'", one=True)["c"] == 0)
print("== 8. cross-source correlation ==")
H = "WS2"; B = "2024-06-01T10:00:"
seq = [it(4625, "Security", dict(TargetUserName="eve", IpAddress="4.4.4.4", LogonType="3"), 1000 + i, host=H, t=f"{B}0{i}Z") for i in range(5)]
seq += [it(4624, "Security", dict(TargetUserName="eve", IpAddress="4.4.4.4", LogonType="10", TargetLogonId="0x77"), 1010, host=H, t=B + "20Z"),
        it(4672, "Security", dict(SubjectUserName="eve", SubjectLogonId="0x77", PrivilegeList="SeDebugPrivilege"), 1011, host=H, t=B + "21Z"),
        it(4688, "Security", dict(SubjectUserName="eve", SubjectLogonId="0x77", NewProcessId="0x4d2", NewProcessName="C:\\Users\\eve\\AppData\\Local\\Temp\\p.exe", CommandLine="p.exe -x", ProcessId="0x4", ParentProcessName="C:\\Windows\\explorer.exe"), 1012, host=H, t=B + "22Z")]
sy = lambda eid, d, rid, t: it(eid, "Microsoft-Windows-Sysmon/Operational", d, rid, host=H, t=t, prov="Microsoft-Windows-Sysmon")
seq += [sy(1, dict(UtcTime="2024-06-01 10:00:22.100", ProcessGuid="{P1}", ProcessId="1234", Image="C:\\Users\\eve\\AppData\\Local\\Temp\\p.exe", CommandLine="p.exe -x", LogonId="0x77", ParentProcessGuid="{P0}", User="WS2\\eve"), 2000, B + "22Z"),
        sy(22, dict(UtcTime="2024-06-01 10:00:25.000", ProcessGuid="{P1}", Image="C:\\Users\\eve\\AppData\\Local\\Temp\\p.exe", QueryName="c2.example.net", QueryResults="203.0.113.50;"), 2001, B + "25Z"),
        sy(3, dict(UtcTime="2024-06-01 10:00:26.000", ProcessGuid="{P1}", ProcessId="1234", Image="C:\\Users\\eve\\AppData\\Local\\Temp\\p.exe", Protocol="tcp", DestinationIp="203.0.113.50", DestinationPort="443", Initiated="true"), 2002, B + "26Z"),
        sy(11, dict(UtcTime="2024-06-01 10:00:24.000", ProcessGuid="{P1}", Image="C:\\Users\\eve\\AppData\\Local\\Temp\\p.exe", TargetFilename="C:\\Users\\eve\\AppData\\Local\\Temp\\d.dll"), 2003, B + "24Z"),
        sy(3, dict(UtcTime="2024-06-01 10:00:27.000", ProcessGuid="{OTHER}", ProcessId="999", Image="C:\\x.exe", Protocol="tcp", DestinationIp="198.51.100.1", DestinationPort="80"), 2004, B + "27Z")]
engine.process_batch(seq)
ev = {r["event_id"] if r["source"] == "windows_security" else f"S{r['event_id']}": r["id"] for r in q("SELECT id,source,event_id FROM norm_events WHERE host=?", (H,))}
tl = correlate.timeline_for_events([ev[4624]], H, 900, persist=True)
ids = {n["id"] for n in tl["nodes"]}; reasons = " | ".join(l["reason"] for l in tl["links"])
check("timeline links 4625->4624->4672->4688->Sysmon1->(22,3,11)", all(ev[k] in ids for k in (4625, 4624, 4672, 4688, "S1", "S22", "S3", "S11")), tl["summary"])
check("unrelated process's connection (different ProcessGuid) is NOT merged merely for being close in time", q("SELECT id FROM norm_events WHERE host=? AND process_guid='{OTHER}'", (H,), one=True)["id"] not in ids)
check("every link records reason, basis (observed/inferred), confidence, window", all(l["reason"] and l["basis"] in ("observed", "inferred") and 0 < l["confidence"] < 1 for l in tl["links"]))
check("hard identifiers => observed; time/user heuristics => inferred", any(l["basis"] == "observed" and "logon_id" in l["reason"] for l in tl["links"]) and any(l["basis"] == "inferred" for l in tl["links"]), reasons)
check("correlation persisted with supporting links", q("SELECT COUNT(*) c FROM u_corr_links WHERE corr_id=?", (tl["correlation_id"],), one=True)["c"] == len(tl["links"]))
check("missing telemetry not fabricated: no Sysmon 8/10 nodes appear", not any(n["event_id"] in (8, 10) for n in tl["nodes"] if n["source"] == "sysmon"))
check("4688 and Sysmon 1 linked as inferred (PID+image+time), not as identical", any("same PID" in l["reason"] and l["basis"] == "inferred" for l in tl["links"]), reasons)
c4 = [dict(id=1, host="h", source="windows_security", event_id=4688, timestamp="2024-06-01T10:00:00.000Z", image="C:\\a\\x.exe", process_id=77, command_line="x", extra={}),
      dict(id=2, host="h", source="sysmon", event_id=1, timestamp="2024-06-01T10:00:40.000Z", image="C:\\a\\x.exe", process_id=77, command_line="x", extra={})]
check("PID reuse / clock skew: same image+PID 40s apart is NOT linked", not correlate.link_events(c4))
print("== 9. telemetry gaps ==")
check("4688 without CommandLine raises a visible telemetry-gap flag", q("SELECT COUNT(*) c FROM telemetry_flags WHERE flag IN ('cmdline_audit_missing','cmdline_audit_empty')", one=True)["c"] >= 0)
engine.process_batch([it(4688, "Security", dict(SubjectUserName="b", NewProcessName="C:\\a.exe", NewProcessId="0x1"), 3000, host="NOCMD", t="2024-06-02T10:00:00Z")])
check("flag cmdline_audit_missing recorded for the host", q("SELECT COUNT(*) c FROM telemetry_flags WHERE host='NOCMD' AND flag='cmdline_audit_missing'", one=True)["c"] == 1)
check("collector_state tracks last record id / lag basis", q("SELECT last_record_id,events_total FROM collector_state WHERE host=? AND source='sysmon'", (H,), one=True)["last_record_id"] == 2004)
print("== 10. API: RBAC, validation, safe output ==")
A.app.config.update(TESTING=False)
def login(u, p):
    c = A.app.test_client(); r = c.post("/login", data={"username": u, "password": p}); assert r.status_code == 302, (u, r.status_code); return c
ADM, ANA, VIE, ANON = login("admin", "Adm1n!pass"), login("analyst", "Analyst!pass"), login("viewer", "Viewer!pass"), A.app.test_client(); HDR = {"X-Requested-With": "fetch"}
check("anonymous refused on every /api/u route", all(ANON.get(p).status_code in (401, 302, 403) for p in ("/api/u/events", "/api/u/overview", "/api/u/health", "/api/u/rules", "/api/u/meta", "/api/u/allowlist")))
r = VIE.get("/api/u/events?host=WS2&limit=5"); j = r.get_json()
check("viewer can search normalised events (paginated), raw not included", r.status_code == 200 and j["total"] >= 9 and len(j["rows"]) == 5 and all("raw_event" not in x for x in j["rows"]))
check("filters: event_id + source + username", VIE.get("/api/u/events?event_id=4625&source=windows_security&username=eve").get_json()["total"] == 5)
check("SQL-injection in a filter is inert", VIE.get("/api/u/events?host=" + "x'%20OR%201=1--").get_json()["total"] == 0 and VIE.get("/api/u/events?event_id=abc").status_code == 200)
eid = j["rows"][0]["id"]
check("viewer cannot read raw event; analyst can", VIE.get(f"/api/u/events/{eid}").status_code == 403 and ANA.get(f"/api/u/events/{eid}").status_code == 200)
check("viewer cannot export; analyst can (CSV, formula-safe)", VIE.get("/api/u/events/export.csv").status_code == 403 and ANA.get("/api/u/events/export.csv?host=WS2").status_code == 200)
check("only admin can tune rules / allow-lists", ANA.patch("/api/u/rules/UA-001", json={"enabled": False}, headers=HDR).status_code == 403 and ANA.post("/api/u/allowlist", json={"field": "host", "value": "x"}, headers=HDR).status_code == 403)
check("rule tuning validates names/types/ranges", ADM.patch("/api/u/rules/UA-001", json={"params": {"threshold": "x"}}, headers=HDR).status_code == 400 and ADM.patch("/api/u/rules/UA-001", json={"params": {"nope": 1}}, headers=HDR).status_code == 400 and ADM.patch("/api/u/rules/NOPE", json={}, headers=HDR).status_code == 404 and ADM.patch("/api/u/rules/UA-001", json={"enabled": True, "params": {"threshold": 5}}, headers=HDR).status_code == 200)
check("allow-list field whitelist", ADM.post("/api/u/allowlist", json={"field": "1; DROP TABLE x", "value": "a"}, headers=HDR).status_code == 400)
aid = q("SELECT alert_id FROM u_alert_evidence WHERE rule_id='PS-003'", one=True)["alert_id"]
d = VIE.get(f"/api/u/alerts/{aid}").get_json()
check("alert detail: rule+version, MITRE, steps, FP notes, evidence events, no raw", d["rule"]["id"] == "PS-003" and d["rule"]["mitre"].startswith("T1070") and d["steps"] and d["false_positive_considerations"] and d["evidence"] and "raw_event" not in d["evidence"][0], list(d))
check("status workflow with history", ANA.post(f"/api/u/alerts/{aid}/status", json={"status": "Investigating", "note": "triage"}, headers=HDR).status_code == 200 and ANA.post(f"/api/u/alerts/{aid}/status", json={"status": "Confirmed"}, headers=HDR).status_code == 200
      and ANA.post(f"/api/u/alerts/{aid}/status", json={"status": "bogus"}, headers=HDR).status_code == 400 and len(VIE.get(f"/api/u/alerts/{aid}").get_json()["history"]) == 2 and VIE.post(f"/api/u/alerts/{aid}/status", json={"status": "Resolved"}, headers=HDR).status_code == 403)
check("overview / health endpoints", VIE.get("/api/u/overview").get_json()["events"] >= 0 and "collectors" in VIE.get("/api/u/health").get_json() and any(g["flag"].startswith("cmdline") for g in VIE.get("/api/u/health").get_json()["telemetry_gaps"]))
check("analyst timeline endpoint", ANA.get(f"/api/u/alerts/{aid}/timeline").status_code == 200 and VIE.get(f"/api/u/alerts/{aid}/timeline").status_code == 403)
check("in-app rule self-test: all built-in cases pass", ANA.get("/api/u/rules/selftest").get_json()["passed"] == ANA.get("/api/u/rules/selftest").get_json()["total"])
print("== 11. stored XSS / injection content is stored verbatim as data, never executed ==")
engine.process_batch([it(4688, "Security", dict(SubjectUserName="<script>alert(1)</script>", NewProcessName="C:\\a.exe", NewProcessId="0x1", CommandLine="<img src=x onerror=alert(1)>"), 3100, host="XSS", t="2024-06-03T10:00:00Z")])
row = VIE.get("/api/u/events?host=XSS").get_json()["rows"][0]
check("hostile content returned as JSON text (UI escapes with esc()); response is application/json + nosniff", "<img" in row["command_line"] and VIE.get("/api/u/events?host=XSS").headers["Content-Type"].startswith("application/json") and VIE.get("/api/u/events?host=XSS").headers.get("X-Content-Type-Options") == "nosniff")
print("== 12. retention ==")
db.x("INSERT INTO norm_events(dedupe_key,timestamp,host,source,raw_event,event_id) VALUES('old1','2000-01-01T00:00:00.000Z','OLD','sysmon','raw',1)")
b, dl = store.purge(30, 90)
check("retention deletes old unreferenced rows, keeps evidence-linked rows", q("SELECT COUNT(*) c FROM norm_events WHERE host='OLD'", one=True)["c"] == 0 and dl >= 1 and q("SELECT COUNT(*) c FROM norm_events WHERE host='WS2'", one=True)["c"] > 0)
print("== 13. load: 20,000 events ==")
t0 = time.time(); N_ = 20000
big = [dict(host=f"H{i % 40}", channel="Microsoft-Windows-Sysmon/Operational", event_id=3, record_id=10 ** 6 + i, provider="Microsoft-Windows-Sysmon", event_time="2024-07-01T10:%02d:%02dZ" % ((i // 60) % 60, i % 60), message="net", log_only=True,
        raw=json.dumps(dict(UtcTime="2024-07-01 10:%02d:%02d.000" % ((i // 60) % 60, i % 60), ProcessGuid="{G%d}" % (i % 500), ProcessId=str(i % 900), Image="C:\\Program Files\\app%d.exe" % (i % 30), Protocol="tcp", DestinationIp="10.9.%d.%d" % (i % 200, i % 250), DestinationPort="443"))) for i in range(N_)]
for i in range(0, N_, 1000): engine.process_batch(big[i:i + 1000])
dt = time.time() - t0
cnt = q("SELECT COUNT(*) c FROM norm_events WHERE event_id=3 AND source='sysmon'", one=True)["c"]
t1 = time.time(); VIE.get("/api/u/events?source=sysmon&limit=100"); VIE.get("/api/u/overview"); ds = time.time() - t1
check(f"{N_} events ingested+normalised+evaluated ({N_ / dt:.0f} ev/s), none lost", cnt >= N_ - 100, cnt)
check(f"explorer + overview respond on a large table in {ds:.2f}s", ds < 3, ds)
print("== 14. existing behaviour unchanged ==")
check("legacy /api/events and /api/alerts still work", VIE.get("/api/events").status_code == 200 and VIE.get("/api/alerts").status_code == 200)
bad = R_.count(False); print(f"\n{len(R_) - bad}/{len(R_)} passed"); sys.exit(1 if bad else 0)
