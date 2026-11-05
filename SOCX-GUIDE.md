# EXE-SOC Advanced Layer (`socx/`) – Incidents, Correlation, Risk, False-Positive Management

Adds attack-story incidents, sequence/threshold detections, configurable risk scoring, auditable whitelists, agent-health and log-flood protection **on top of** your existing app. Nothing existing was removed or rewritten.

## 1. What changed in existing files (and what could break)
| File | Before | Change | Why | Risk / how to test |
|---|---|---|---|---|
| `engine.py` | `_detect()` creates/merges alerts | +`_sx()` helper and 2 one-line calls (new alert, merged alert) | give every alert MITRE, risk score, IOC check, whitelist check, incident link | Wrapped in try/except: a failure only prints `socx hook error`, detection continues. Run `python tools/selftest_socx.py` |
| `db.py` | `init_db()` builds schema | calls `socx.init()` at the end | creates the NEW tables only (`CREATE IF NOT EXISTS`) | Existing tables untouched. Delete nothing; restart |
| `app.py` | 16 pages, one `start_workers()` | +5 page routes, registers `/api/sx/*` blueprint, starts the correlation thread | new pages/API | Open `/incidents` |
| `templates/base.html` | menu | +5 menu items, loads `socx.js` | navigation | – |
| `static/app.js` | page table | 1 line: merges `window.SOCX_PAGES` into `PAGES` | new pages use your existing helpers | – |

New: `socx/` (schema, risk, catalog, correlation, incidents, fp, ti, health, api), `static/socx.js`, `tools/selftest_socx.py`.

## 2. Install / run
```bash
cd EXE-SOC
./run.sh                      # Windows: run.bat as Administrator  (no new pip packages needed)
python tools/selftest_socx.py # 38 checks on a TEMP database (does not touch soc.db)
```
Menu: **Investigate → Incidents, Threat hunting** · **Respond → Detection library, False positives, Agent health**.

## 3. How it works
`raw log → activity normalizer (existing) → existing rules → alert → socx.on_alert → {MITRE, IOC lookup, whitelist check, risk score} → incident (grouped by host/IP/user within 60 min)`
In parallel every 20 s (`SOCX_INTERVAL`) `socx/correlation.py` scans recent events for sequences/thresholds and raises ONE alert per finding (re-fires only when new matching events arrive).

### Detections (see Detection library page for the full 12-field metadata of each)
SEQ-001 RDP brute-force→logon type 10→process→PowerShell · SEQ-002 privileged logon→log cleared · SEQ-003 Defender disabled+suspicious process+network · SEQ-004 remote logon→new task/service · SEQ-005 404 scan→attack URL 200→POST→web shell · SEQ-006 remote logon→remote execution/ADMIN$ · SEQ-007 phishing alert→Office/PowerShell · THR-001 password spraying · THR-002 Kerberoasting · THR-003 mass file changes · THR-004 DNS tunneling/NXDOMAIN · THR-005 port scan · THR-007 anomalous country login · HLT-001 silent endpoint · HLT-002 log flood.
Existing rules (brute force, encoded PowerShell, LSASS/mimikatz, shadow-copy deletion, new service, log cleared…) now also carry MITRE + risk score.

**Honest status:** THR-006 (large outbound transfer) is listed as *needs data feed* – it needs byte counts from firewall/NetFlow/VPN logs, which your collectors do not send yet. Firewall/IDS/VPN/cloud/email/Linux-auditd *parsers* are not part of this phase; the correlation rules work on whatever normalized events (event_id, host, user, IP, message/raw) arrive, so they become active as those feeds are added.

### Risk model (Agent health page → editable JSON, or `PUT /api/sx/risk-model`)
Alert score = severity base + tactic bonus + privileged user + host criticality (1-5) + known IOC + vulnerable host + success-after-failures + frequency (log-scaled). Incident score = highest alert + 10 per additional distinct kill-chain stage (capped). Incident severity = from thresholds (85/60/30), never below its worst alert. Every score stores its breakdown ("Why this score").

### False positives
Types: trusted admin, approved software/service/task, known scanner, vulnerability scanner, maintenance window, suppression. A matching alert is **kept**, set to `Suppressed`, linked to the rule, counted and written to the audit trail. Rules are never hard-deleted (only disabled). Catch-all rules (no host/user/IP/pattern) are rejected. **An alert with a threat-intel hit can never be suppressed.**

### Log flood
Events are never dropped. 10,000 identical failures = existing alert merge (count×N) + one incident + collapsed timeline row; >2000 events/min on a host raises a single HLT-002 alert.

## 4. API (all need login; writes need analyst/admin + `X-Requested-With: fetch`)
`GET /api/sx/incidents[?status=&severity=]`, `GET|PATCH /api/sx/incidents/<id>`, `GET /api/sx/summary`, `GET /api/sx/catalog`, `GET|POST /api/sx/whitelist`, `PATCH|DELETE /api/sx/whitelist/<id>`, `GET|POST /api/sx/assets`, `GET|PUT /api/sx/risk-model`, `GET /api/sx/health`, `GET /api/sx/hunt?process=&user=&ip=&domain=&hash=&cmd=&event_id=&host=`, `POST /api/sx/run` (admin, run detectors now).
Settings you can add in the `settings` table: `spray_users`(8), `kerb_spns`(6), `mass_file_changes`(200), `agent_silent_minutes`(30), `flood_events_per_min`(2000), `incident_window_min`(60), `socx_enabled`(1).

## 5. Safe test plan  ⚠ lab first
**Automatic (zero risk):** `python tools/selftest_socx.py` – synthetic events, temp DB.
**Live tests** – no malware/exploits. ⚠ = may lock an account / change security settings / add volume; use a lab VM.

| Test | Action | Expected Windows event | Expected detection / severity | Dashboard result |
|---|---|---|---|---|
| Failed logins ⚠ (can lock account) | 6 wrong passwords for a TEST user | 4625 ×6 (4740 if lockout) | Brute Force (High→Critical at threshold) | Alerts + Incident |
| RDP chain ⚠ lab only | 6 bad RDP passwords, then correct RDP login, run `whoami` then `powershell -c Get-Date` | 4625×6, 4624 type 10, 4688, 4104 | SEQ-001 Critical | One incident, timeline 4625→4624→4688→4104 |
| Test admin ⚠ | `net user socxtest P@ss123! /add`, add to Administrators, then delete | 4720, 4732, 4726 | New user / admin group (Medium-High) | Incident, MITRE T1136 |
| Benign PowerShell | `powershell -c "Get-Process"` | 4688 / 4104 | none (context scoring, no keyword-only alert) | Activity only |
| Benign scheduled task | `schtasks /create /tn SocxTest /tr notepad.exe /sc once /st 23:59` then delete | 4698 | Medium; SEQ-004 only if after a remote logon | Activity / Incident |
| Test service ⚠ | `sc create SocxTest binPath= C:\Windows\System32\notepad.exe` then `sc delete SocxTest` | 4697/7045 | Service installed (Medium) | Alert |
| EICAR | create the standard EICAR text file | Defender 1116 | Malware Detected High | Alert, endpoint |
| Log clear ⚠ disables evidence | after a privileged logon, `wevtutil cl Application` (use a lab; or `Security` only on a VM) | 104 / 1102 | SEQ-002 High-Critical | Incident |
| DNS | `nslookup aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa.example.test` | Sysmon 22 | THR-004 Medium | Alert |
| Silent agent ⚠ | stop the agent 35 min | none | HLT-001 Medium, wording "not assumed compromise" | Agent health = Silent |
| Flood ⚠ fills queue | **do not** run on production; use selftest | – | HLT-002 Low | Alert |

## 6. Troubleshooting
* New pages empty → no alerts yet; run the selftest or generate a test above. `POST /api/sx/run` forces a scan.
* `socx hook error` in console → send the line; detection still works.
* No SEQ alerts from real Windows data → check **Logs** that `event_id`, `username` and `source_ip` are populated (needs auditing: `tools/enable_windows_auditing.bat`, and Sysmon for process/DNS/network).
* Too many incidents → raise `incident_window_min` down (30) or add whitelist rules; tune `risk_model` thresholds.
* Vendor products (Splunk/Wazuh APIs) are **not** called anywhere; nothing needs "VERIFY IN CURRENT PRODUCT DOCUMENTATION".

## 7. FIM change: built-in Windows scheduled tasks (added after a real false positive)
`tools/fim.py` no longer raises a CRITICAL alert when a file under `System32\Tasks\Microsoft\Windows\` is **MODIFIED** and the task XML is verifiably normal: every action runs a binary inside `%SystemRoot%` (or Windows Defender / Windows Kits), the binary is not a shell/script host/LOLBin (powershell, cmd, wscript, mshta, rundll32, ...), and the arguments contain no http/encoded/temp/user-path pattern.
It is still **recorded** as a normal log line marked `(expected: built-in Windows task...)`, never dropped. CREATED, DELETED, unreadable, unparsable, COM-handler or suspicious tasks stay CRITICAL.
Restart the agent/collector for it to take effect. Existing alerts are not changed.
Optional extra: add the whitelist rule on the False positives page (type Approved scheduled task, detection `File Integrity Change`, host `Instructor-ExE`, reason required).
