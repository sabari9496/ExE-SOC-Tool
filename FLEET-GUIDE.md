# EXE-SOC Remote Endpoint Monitoring (Fleet) Guide

## 1. What was found in the existing project (Phase 1)
Flask + Flask-SocketIO (threading) backend, SQLite (`soc.db`, WAL), server-rendered Jinja pages + vanilla JS (`static/*.js`), session login with roles viewer/analyst/admin and an `X-Requested-With: fetch` CSRF guard.
Existing pieces reused: `engine.process_batch` (storage + dedupe + detection + alert merge ×count), `activity.py` normalizer, `socx` (incidents/MITRE) and `notify` (SMTP e-mail with severity policy, rate limits, history) packages, the `audit` table, the collectors in `tools/` (Windows Event Log, Linux journal/files, FIM, process/network monitor, malware scan). The old shared-API-key agent (`tools/agent.py`) is untouched and still works.

## 2. Architecture
```
Friend PC (Windows/Ubuntu/Debian) -> EXE-SOC agent (outbound only)
   -> HTTPS/TLS (cert verified) -> EXE-SOC backend (fleet/ blueprint: auth, rate limit, replay + timestamp checks, sanitize)
   -> engine.process_batch (existing detection) -> SQLite -> Socket.IO "fleet"/"refresh" events -> Dashboard "Remote agents"
```
No inbound connection to the endpoint is ever required. The agent runs **no remote commands**.

## 3. Files
Created: `fleet/{__init__,schema,api}.py`, `static/fleet.js`, `agent/exe_soc_agent.py`, `agent/install_linux.sh`, `agent/install_windows.ps1`, `agent/requirements.txt`, `agent/collectors/*` (copies of the proven `tools/` collectors), `tools/dev_certs.py`, `tests/test_fleet.py`, this guide.
Modified (small, additive): `app.py` (register fleet blueprint, `/fleet` page, `agent_id` filter on `GET /api/alerts`, optional native TLS via `SOC_TLS_CERT`/`SOC_TLS_KEY`, start offline watcher), `db.py` (calls `fleet.init()`), `templates/base.html` (menu entry + script).

## 4. Database changes (additive migration, runs automatically at start; no data is dropped)
New tables: `agents`, `agent_credentials`, `enrollment_tokens`, `agent_heartbeats`, `agent_event_ids` (duplicate ledger), `agent_nonces` (replay protection).
New columns: `events.agent_id`, `alerts.agent_id`.
Indexes: agents(status,last_heartbeat), agents(hostname), heartbeats(agent_id,ts), events(agent_id,id / agent_id,ts / risk,ts), alerts(agent_id,id / severity,ts / status,ts).
Reused existing tables (not duplicated): `events`, `alerts` (with count merging), `audit` (= audit_logs), `notify` tables (= notification_settings; SMTP password stays in environment only).

## 5. API
Agent routes (header `Authorization: Bearer <credential_id>.<secret>`, `X-Timestamp`, `X-Nonce`):
| Route | Purpose |
|---|---|
| `POST /api/agents/register` | body `{enrollment_token, hostname, os, os_version, agent_version}` -> `{agent_id, credential, heartbeat_seconds}` (credential shown once) |
| `POST /api/agents/heartbeat` | health: cpu, mem, events_sent/queued, upload_failures, last_success, collectors |
| `POST /api/events` | `{events:[{uid,message,channel,event_id,event_time,record_id,raw,log_only,source_ip}]}` max 500; duplicates ignored by `uid`; original `event_time` preserved |

Dashboard routes (login + role; POST needs `X-Requested-With: fetch`):
`GET /api/agents`, `GET /api/agents/<id>`, `GET /api/agents/<id>/events` (filters: severity, category, username, source, event_id, rule, from, to, q, limit), `GET /api/alerts?agent_id=` , `POST /api/agents/<id>/revoke` (admin), `POST /api/agents/<id>/monitoring` (admin, pause/resume), `POST /api/enrollment-tokens` (admin), `GET /api/enrollment-tokens` (admin), `POST /api/enrollment-tokens/<id>/revoke` (admin).
Secrets (credential hash, token hash) are never returned by any GET.

## 6. Security design
- Enrollment token: 256-bit random, stored as SHA-256 only, expires (default 60 min, max 7 d), single-use (atomic claim), revocable, never in agent code; shown once.
- Agent credential: 256-bit secret, only SHA-256 stored, constant-time compare, per-agent revocation (instant 403). Agent stores it in `agent.json` mode 0600 inside a 0700 dir (Windows: ACL restricted to SYSTEM + Administrators).
- Replay/timestamp: +-5 min clock window, one-time nonces. Duplicate events blocked by `uid` ledger and the engine's own unique index.
- Rate limits per IP and per agent, 2 MB body cap, 500 events/batch, field truncation, control-character stripping, `password=/token=/Authorization` redaction before storage.
- TLS: agent refuses `http://` (except an explicit loopback test flag) and always verifies; a private CA is trusted via `--ca-bundle`, never `verify=False`.
- RBAC: enroll/revoke/token = admin; viewing = any logged-in user; email config unchanged (admin). All admin actions go to the audit table.
- Not implemented on purpose: keylogging, credential/browser data, screenshots, webcam/mic, stealth, remote command execution. The agent is a visible service and requires typed consent.
- Known limits: bearer secrets rely on TLS (no mutual-TLS); put the server behind a reverse proxy/VPN for internet use; `X-Forwarded-For` is not trusted by default (set up ProxyFix if you add a proxy, otherwise rate limits see the proxy IP).

## 7. Server deployment and TLS (Phase: certificates)
Local/LAN development certificates:
```bash
# Debian/Ubuntu/Kali: use the project's virtual environment (system pip is blocked by PEP 668)
.venv/bin/pip install cryptography      # Windows: .venv\Scripts\pip install cryptography
.venv/bin/python tools/dev_certs.py --name soc.lan --ip 192.168.1.50      # writes certs/ca.pem, server.pem, server.key
export SOC_HOST=0.0.0.0 SOC_TLS_CERT=certs/server.pem SOC_TLS_KEY=certs/server.key
./run.sh            # Windows: set the variables, then python app.py
```
Give only `certs/ca.pem` to friends (`--ca-bundle`). Never share `ca.key`/`server.key`.
Internet: use a real certificate (e.g. Caddy/nginx + Let's Encrypt) in front of `127.0.0.1:5000`, or a VPN (WireGuard/Tailscale) so the server is never publicly exposed. Cloudflare Tunnel / SSH reverse tunnel also work (outbound only from your side). Do not port-forward plain HTTP; firewall everything except 443.
Server open ports: 443 only (agents connect outbound to it).

## 8. Enrollment procedure
1. Admin: **Remote agents -> Enroll endpoint**, set label/expiry, copy the token and the ready-made command.
2. Send the token (and `ca.pem` if using a private CA) to the device owner over a private channel.
3. Owner copies the `agent/` folder and runs the installer; reads the consent text and types `I AGREE`.
4. Server verifies the token, assigns `ag-xxxxxxxx`, returns the credential; the agent stores it and starts.
5. The endpoint appears on the dashboard within ~30 s.

## 9. Windows setup (Windows 10/11)
Install Python 3.9+ (tick **Add python.exe to PATH**). Copy the whole `agent` folder and `ca.pem` to the PC. Open **PowerShell as Administrator** (the prompt must start with `PS`; `.ps1` files do not run in the old Command Prompt):
```powershell
cd "C:\path\to\EXE-SOC\agent"                       # quotes are required when the path has spaces
Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass
.\install_windows.ps1 -Server https://192.168.1.50:5000 -Token "TOKEN" -CaBundle "..\certs\ca.pem"
```
Notes: the script is inside `agent\`; a token must follow `-Token`; in PowerShell run scripts as `.\name` and set variables with `$env:NAME="value"` (not `set NAME=value`). Check: `Get-ScheduledTask "EXE-SOC Agent"`. Remove: `.\install_windows.ps1 -Uninstall`.
For richer telemetry run `tools\enable_windows_auditing.bat` once (process creation, logon, task/service auditing).
Server on Windows (PowerShell): `$env:SOC_HOST="0.0.0.0"; $env:SOC_TLS_CERT="certs\server.pem"; $env:SOC_TLS_KEY="certs\server.key"; .\run.bat`. Keep the project outside OneDrive (e.g. `C:\EXE-SOC`): sync can lock `soc.db`.

## 10. Ubuntu / Debian setup
`sudo ./install_linux.sh --server https://soc.lan:5000 --ca-bundle ./ca.pem --token-file token.txt --accept-consent` - full Kali/Ubuntu/Debian guide, diagnostics and uninstall: **[LINUX-AGENT-GUIDE.md](LINUX-AGENT-GUIDE.md)** (the agent runs as an unprivileged service account, not root).
Uses the systemd journal when available, otherwise `/var/log/auth.log|secure`, `syslog|messages` (Debian minimal images often lack rsyslog; the journal collector covers that - install `rsyslog` or enable persistent journald if the journal is empty). Optional `tools/enable_linux_auditing.sh`. Logs: `journalctl -u exe-soc-agent -f`. Remove: `sudo ./install_linux.sh --uninstall`.
Manual run (no service): `python3 exe_soc_agent.py enroll ...` then `sudo python3 exe_soc_agent.py run`.

## 11. Dashboard usage
Menu **Monitor -> Remote agents**: status dots (🟢 heartbeat <=90 s, 🟡 90 s-5 min / upload failures / backlog >5000 / collector errors, 🔴 >5 min silent, ⛔ revoked), alert/event counts, queue, CPU/RAM. Click a row: host info, health, merged alerts (×count; open the alert for its underlying events), filterable event timeline (severity, category = auth/process/network/file, username, source, rule, date, text). Existing Alerts/Activity/Logs/Search pages also show agent data (host = endpoint name). An "Endpoint Agent Offline" alert is raised once when an agent goes silent.

## 12. Detections (existing engine, applied to every agent event)
Failed/brute-force logins, success-after-failures, SSH brute force, sudo abuse/denied, encoded/suspicious PowerShell, living-off-the-land and reverse-shell commands, new user/admin group change, privilege escalation, scheduled task created/changed, suspicious service install, SSH-key/cron persistence, malware hash/IOC matches, FIM changes, new listening port, port scan, DNS anomalies, log tampering. Custom rules: **Detection rules** page (admin).

## 13. Email alerts
Use **Email notifications** (admin): SMTP host/port/security, sender, recipients, severity thresholds, on/off, test mail. Password only via environment (`SMTP_PASSWORD` or `SMTP_PASSWORD_FILE`), see `.env.example`. Agent alerts flow through the same pipeline automatically (one mail per incident per window, with occurrence count).

## 14. Testing
Automated (real TLS, private CA): `python tests/test_fleet.py` -> 23 checks: viewer denied, token hashed/single-use/revoked/invalid, Windows+Ubuntu enrollment, heartbeat, invalid credential, replay, stale timestamp, ingest, duplicates, agent tagging, alert merge, filters, no secrets exposed, revoke, TLS unknown-CA rejection, audit. Existing `python -m unittest tests.test_notify` still passes (44 tests).
Manual:
1. Enroll a Windows and an Ubuntu VM; both show 🟢.
2. Ubuntu: `for i in 1 2 3 4 5 6; do ssh wrong@localhost; done` (wrong passwords) -> "Brute Force" alert with ×count; Windows: lock-screen 5 wrong passwords -> 4625 events.
3. Offline: stop the network 5 min -> 🔴 + "Endpoint Agent Offline"; reconnect -> queued events upload, original timestamps kept, no duplicates.
4. Revoke from the dashboard -> agent logs "Server rejected this agent" and stops.
5. Use a wrong CA / hostname -> agent logs "TLS certificate validation FAILED" and sends nothing.
6. Email: configure SMTP (or `tests/mock_smtp.py`), trigger a Critical alert.

## 15. Troubleshooting
| Symptom | Fix |
|---|---|
| `Missing Authority Key Identifier` (Kali / Python 3.13+) | Fixed in this version: `dev_certs.py` now adds key identifiers. Re-run `dev_certs.py` on the server, restart it, and copy the NEW `ca.pem` to every agent (old certs cannot be repaired). |
| `CERTIFICATE_VERIFY_FAILED` | Pass `--ca-bundle ca.pem`; the URL host must be in the cert (`--name`/`--ip` in dev_certs). |
| `timestamp outside allowed window` | Fix the endpoint clock (NTP). |
| Enrollment 401 | Token expired/used/revoked: create a new one. |
| `ModuleNotFoundError: soc_preflight` (Windows installer) | Fixed in this version: `install_windows.ps1` now copies `soc_preflight.py` and `exe_soc_diag.py`. Use the updated installer. |
| Windows shows no Security events | Run as Administrator; run `enable_windows_auditing.bat`. |
| Linux no auth events | Run with sudo; Debian: install rsyslog or use the journal. |
| 🟡 warning | Upload failures/backlog: check connectivity and TLS; see the agent health card. |
| Queue full | The oldest events are dropped and counted ("dropped") - restore connectivity. |
| Agent stopped with "rejected" | The agent was revoked; enroll again with a new token. |
