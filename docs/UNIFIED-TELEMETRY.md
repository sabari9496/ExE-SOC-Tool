# EXE-SOC unified telemetry layer (Windows Security · Sysmon · Linux)

Added on top of the existing EXE-SOC; nothing was removed or replaced. New code lives in `unified/`, `static/unified.js`, `tests/test_unified.py`.
Existing tables, users, routes, collectors, fleet/socx/notify modules and the dashboard are unchanged (small, additive hooks only — see "What changed").

## 1. What it does
`engine.process_batch` (the single ingestion point used by agents, `/api/ingest`, fleet and the local collectors) now also calls `unified.on_events`, which
1. **normalises** each Windows Security / Sysmon / Linux event into the unified schema (`norm_events`, schema_version 1) – source-specific fields kept, nothing fabricated, UTC timestamps, secrets redacted;
2. **stores** it with duplicate control (unique key on host+source+channel+record id, or a content hash when no record id exists) and updates per-collector state (last record id, newest event time, lag, errors);
3. **evaluates 30 versioned detection rules** (68 built-in positive/negative test cases) and raises alerts through the existing alert pipeline, so dedup, playbooks, socx incidents/risk and the e-mail layer all apply;
4. keeps the **evidence**: `u_alert_evidence` lists every supporting event id (aggregation only adds evidence);
5. offers **correlation timelines** (`/api/u/alerts/<id>/timeline`) with reason, observed/inferred, confidence and window per link.

Failure in this layer is caught and logged; legacy ingestion and detection continue.

## 2. Sources and fields
| source | produced from |
|---|---|
| `windows_security` | channel `Security` (4624 4625 4634 4647 4648 4740 4768 4769 4771 4776 4688 4689 4672 4673 4674 4720–4726 4728 4729 4732 4733 4756 4757 1102 4719 4697 4698–4702) |
| `sysmon` | `Microsoft-Windows-Sysmon/Operational` (1 3 5 7 8 10 11 12 13 14 22 23 26) |
| `linux_auth` / `linux_journal` / `linux_auditd` / `linux_firewall` | existing Linux agent (journald or auth.log, audit.log, ufw.log) |

Linux events keep `event_id = NULL` and a source-specific `activity` (e.g. `ssh_auth_failure`, `audit_execve`); they are never mapped to Windows or Sysmon IDs.
Fields: see `unified/schema.py` (all fields from the specification; extra source-specific values go to `extra` JSON).
The Windows collector (`agent/collectors/winevents.py`, wevtutil, RecordID cursor saved only after the server accepted a batch) already collects every event of every configured channel including Sysmon; it was not rewritten. `parse_event_xml()` parses raw `<Event>` XML (also used by tests) – the live collector forwards the structured `EventData` fields, which are used by field name, not by localised text.

## 3. Windows prerequisites (check, do not assume)
**Audit policy** (elevated prompt; inspect first, then change deliberately):
```
auditpol /get /category:*
auditpol /set /subcategory:"Logon" /success:enable /failure:enable
auditpol /set /subcategory:"Process Creation" /success:enable
auditpol /set /subcategory:"Special Logon" /success:enable
auditpol /set /subcategory:"User Account Management" /success:enable /failure:enable
auditpol /set /subcategory:"Security Group Management" /success:enable /failure:enable
auditpol /set /subcategory:"Security System Extension" /success:enable
auditpol /set /subcategory:"Other Policy Change Events" /success:enable   :: 4719 is under "Audit Policy Change"
auditpol /set /subcategory:"Audit Policy Change" /success:enable
auditpol /set /subcategory:"Other Object Access Events" /success:enable    :: 4698-4702 scheduled tasks
```
Command-line capture for 4688 (otherwise the field is absent and PX-001/PX-003 cannot see arguments – the dashboard shows a *telemetry gap*):
`HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\System\Audit` → `ProcessCreationIncludeCmdLine_Enabled` = 1 (or GPO *Include command line in process creation events*).
Kerberos/NTLM events (4768 4769 4771 4776) exist only on **domain controllers**; workstations will legitimately show none. 4624/4625 field layouts differ slightly between Windows versions (version 0/2); the parser reads by field name and tolerates missing fields. Reading `Security` requires Administrator or *Event Log Readers* (not enough for Security on some builds – use the agent service account with Administrator or the Security log ACL).

**Sysmon** is *not* downloaded or installed by EXE-SOC. Obtain it from Microsoft Sysinternals, verify the signature (`Get-AuthenticodeSignature`), then:
```
sc query Sysmon64                      :: installed and RUNNING?
wevtutil gl Microsoft-Windows-Sysmon/Operational
Sysmon64.exe -c                        :: shows the active configuration; back it up before changing: Sysmon64.exe -c > sysmon-backup.xml
```
`winevents.sysmon_status()` performs the same read-only checks. Use a maintained community configuration and filter noisy events (7 image-load, 10 process-access, 3, 22 are high-volume). Rules PI-003/PI-001 assume you filter 7/10 at the Sysmon level.

## 4. Linux
Existing agent (`agent/install_linux.sh`, see `LINUX-AGENT-GUIDE.md`) detects journald vs classic files. For auditd telemetry install and enable `auditd` and add rules (`tools/enable_linux_auditing.sh` – read it first). Needed privileges: root, or membership of `systemd-journal` and `adm`. Do not chmod log files or the DB directory.

## 5. Detection rules
List and tune in the UI (**Telemetry → Detection rules**) or `GET/PATCH /api/u/rules`. Each rule has id, name, version, sources/event ids, severity, confidence, MITRE mapping, evidence fields, investigation steps, false-positive notes, parameters (threshold/window/lists), enable switch and built-in tests (`GET /api/u/rules/selftest`).
UA-001..007 authentication (default 5 failures / 300 s – adjustable), LX-001..005 Linux, PX-001..003 process, NW-001..002 network, DNS-001, FR-001..003 file/registry, PI-001..003 injection/image-load, AC-001..002 accounts/groups, PS-001..004 persistence & audit tampering (1102 → High).
No IP, user or host is hard-coded. Lists such as `expected_privileged` (UA-005), `sensitive_groups`, `allowed_sources`, `allowed_creators` are empty/neutral or generic defaults you should review. **Allow-lists**: `POST /api/u/allowlist` `{rule_id|null, field, value}` (glob, case-insensitive) – admin only.
A rule is a statement of suspicion, not proof: severities/confidences are deliberately modest and every rule documents its false positives.

## 6. Correlation
Links are made only from evidence: shared `logon_id` (4624→4672→4688/Sysmon 1: *observed*), Sysmon `ProcessGuid`/`ParentProcessGuid` (*observed*), DNS answer = connection destination (*observed*), 4625→4624 same account (+ same IP) (*inferred*), 4688↔Sysmon 1 same image + PID/command line within 5 s (*inferred*; one-to-one; PID reuse excluded by the time bound). Events that merely occur close in time are not merged; missing telemetry yields a shorter chain, never an invented one.

## 7. API (all use existing session/RBAC/CSRF rules)
viewer: `GET /api/u/events|meta|overview|health|rules`, `/api/u/alerts/<id>` · analyst: raw event `/api/u/events/<id>`, `/api/u/events/export.csv` (formula-safe, audited), `/api/u/timeline`, `/api/u/alerts/<id>/timeline`, `POST /api/u/alerts/<id>/status` (New, Investigating, Confirmed, False Positive, Resolved + note + history) · admin: `PATCH /api/u/rules/<id>`, allow-list add/delete.

## 8. Retention, performance
`retention_days` (existing setting, default 90) deletes old normalised rows that are not evidence of an alert; `raw_retention_days` (default 30) blanks the stored raw text only. Indexes cover host/time, source/event id, user, IPs, logon id, process guid/pid. Synthetic load: 20,000 Sysmon events ingested, normalised and evaluated at ~820 events/s in the test sandbox (single thread, SQLite WAL).

## 9. E-mail
Unchanged existing module (`EMAIL-NOTIFICATION-GUIDE.md`): SMTP/Gmail settings from environment/UI, TLS, severity filter, cooldown/dedup, retries, honest delivery status, admin-only test mail. Rule-based alerts flow through it automatically (socx → notify).

## 10. Troubleshooting
* No Windows events: Telemetry → Collector health (silent/lag), agent log, run as Administrator, `wevtutil qe Security /c:1 /f:xml`.
* "Telemetry gaps: cmdline_audit_*": enable command-line auditing (section 3).
* No Sysmon rows: `sysmon_status()`; the Sysmon channel error is surfaced in the agent's collector errors.
* TLS/certificate errors: never disable verification; see README/FLEET-GUIDE (`tools/dev_certs.py` for lab CAs).
* Duplicates after restart: expected to be ignored (unique key); check `collector_state`.

## 11. Backup / rollback / removal
`cp soc.db soc.db.bak` (stop server first) – the migration is additive (`CREATE TABLE/INDEX IF NOT EXISTS`). Roll back with `git revert`/checkout of the commit before "unified telemetry"; extra tables are harmless and can be dropped: `norm_events, collector_state, telemetry_flags, u_*`. Agent removal and credential revocation: `agent/uninstall_linux.sh`, and *Revoke* on the Remote agents page.

## 12. What changed in existing files
`engine.py` (one try/except hook after the legacy insert; one retention call), `app.py` (registration, `/telemetry` page, extra alert statuses), `templates/base.html` (nav + script), `agent/collectors/winevents.py` + `tools/winevents.py` (Sysmon status helper and clearer Sysmon errors; kept identical).

## 13. Test status and honest limits
* `python3 tests/test_unified.py` – 144 synthetic checks (parsers, malformed/hostile input, 68 rule cases, pipeline, dedup, out-of-order, allow-list, tuning, correlation, RBAC, XSS-as-data, retention, 20k load, legacy-data preservation).
* Existing suites re-run: test_api_audit 29/29, test_hardening_misc 19/19, test_fleet 23/23, test_linux_agent 64/64, test_log_visibility 12/12, notify/installer/certs OK, selftest_socx 38/38. `tools/selftest.py` needs a running server on :5000 (fails identically on the untouched baseline).
* **Not validated live**: no real Windows or Linux endpoint, Sysmon, auditd or SMTP server was available. All parsing is verified against synthetic events built from the documented field names; run a pilot on an authorised endpoint before relying on it.
* **Not implemented / partial**: baseline-driven "unusual successful logon" (only the UA-005 configured-list variant); unexpected process execution by privileged accounts; Linux scheduled-job/service-change rules (auditd config tampering and account/group changes are covered; the existing FIM events stay in the legacy pipeline); network anomaly rules are limited to the three above (no byte counts → no exfiltration claims); live raw-XML retention (collector forwards structured fields); no new rate limiting on `/api/ingest`; no automatic response actions were added (by design).
