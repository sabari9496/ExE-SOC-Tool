# EXE SOC

A lightweight Security Operations Center (SOC) monitoring platform built with Flask and SQLite. It collects logs from servers and agents, detects suspicious activity with rule-based detection, and gives analysts a live dashboard to investigate and respond.

Everything on the dashboard is computed from real data stored in `soc.db`.

## Features
- **Live dashboard** – alert counts, severity breakdown, 24 h timeline, top attacking IPs, threat map, endpoint health, system resources
- **Detection rules** – SQL injection, XSS, path traversal, brute force, malware keywords, privilege escalation, port scans, DNS anomalies
- **Automatic escalation** – repeated failed logins and IOC / blocklist hits become Critical; repeated identical alerts merge (count ×N)
- **Investigation drawer** – click any alert or IP for triggering raw events, ±30 min surrounding activity, MITRE ATT&CK technique, recommended actions, endpoint context, analyst notes and a full IP profile (risk score, first/last seen, targeted hosts and ports, 24 h activity)
- **SPL-style search** – `index=events "failed password" | stats count by source_ip | sort -count | head 10`
- **Playbooks** – auto-block IPs, open cases, notify analysts, isolate endpoints
- **Cases, IOCs, blocklist, reports (CSV export), audit trail**
- **Role-based access** – viewer, analyst, admin
- **Endpoint agent** – heartbeat plus log forwarding
- **Remote authorized endpoints (new)** – enrollment tokens, per-agent credentials over HTTPS, Windows/Ubuntu/Debian agent, offline queue, per-endpoint dashboard. See [FLEET-GUIDE.md](FLEET-GUIDE.md); Linux agent install, diagnostics and troubleshooting: [LINUX-AGENT-GUIDE.md](LINUX-AGENT-GUIDE.md)

## Screenshots
_Add screenshots of the dashboard and the alert drawer here (`docs/dashboard.png`, `docs/alert-drawer.png`)._

## Quick start
```bash
git clone https://github.com/sabari9496/ExE-SOC-Tool.git
cd ExE-SOC-Tool
./run.sh                 # creates .venv, installs deps, starts on http://127.0.0.1:5000 with a CLEAN database
./run.sh --demo          # optional: fill it with fake alerts/endpoints to try the UI
```
A fresh install starts **empty**. Demo data only appears if you pass `--demo` (or set `SOC_DEMO=1`).

**Moving to another machine?** Copy the code only. Never copy `soc.db` or `.secret`; they contain that system's alerts, users, passwords and API key. If a copied folder already shows old data, stop the tool and run:
```bash
python app.py --reset        # asks for confirmation; add --yes to skip the prompt
```
This deletes `soc.db` (+ `-wal`/`-shm`) and `.secret` so the next start is completely fresh.
Requires Python 3.9+. Default logins (**change them before real use**):

| User | Password | Role |
|---|---|---|
| admin | `Admin@123` | full access |
| analyst | `Analyst@123` | triage and respond |
| viewer | `Viewer@123` | read-only |

Override before the first run with `SOC_ADMIN_PASSWORD`, `SOC_ANALYST_PASSWORD`, `SOC_VIEWER_PASSWORD`.
Other env vars: `SOC_HOST` (default 127.0.0.1), `SOC_PORT`, `SOC_DB`, `SOC_SECRET`.

## Full real-time logs: Windows, Linux, Ubuntu (no fake data)
On Windows, `run.bat` (right-click, **Run as administrator**) starts the SOC and also collects **every event** of this computer in real time from: Security, System, Application, Windows Defender, PowerShell and Sysmon (channels that do not exist are skipped). Nothing is simulated.
- Every event is stored with its full text, device, channel, event ID, level, provider and original time. See them in **Logs** (filter by device / channel / event ID, live view, CSV export) or in **Search** (`index=events host=PC1 event_id=4625 | stats count by source_ip`).
- Alerts only come from the detection rules. Curated events (failed logons, new accounts, admin group changes, log cleared, new service, Defender detections) feed the rules; all other events are stored as plain logs and can never create an alert.
- Other Windows PCs: run `python tools/agent.py --server http://SOC-IP:5000 --key API_KEY --eventlog` as Administrator on each one. Every event carries its device name, and each PC keeps its own read position.
- Nothing is lost or duplicated: the read position is saved only after the SOC accepted the events, and the SOC ignores an event it already has (same device + channel + record ID + time). Restarting the agent or the server continues where it stopped.
- **Old data never follows the code to another PC.** `soc.db` is stamped with the computer it was created on. If it is started on a different computer it is moved aside (`soc.db.other-machine-...`, not deleted) and a clean database is created. Set `SOC_ALLOW_FOREIGN_DB=1` to disable this.

**Linux / Ubuntu / Debian / RHEL** (macOS log files also work): start with `sudo ./run.sh` (root is needed to read the journal and `auth.log`; alternatively add the user to the `systemd-journal` and `adm` groups). The SOC then collects, in real time, the whole **systemd journal** (sshd, sudo, su, kernel, services, cron, ufw ...). Without systemd it reads `/var/log/auth.log` or `secure`, `syslog` or `messages`, `kern.log`. It also follows nginx/apache access and error logs, `audit.log`, `ufw.log` and `fail2ban.log` when they exist. Only clear security lines reach the detection rules (failed SSH/PAM logins, sudo denials, new users, admin/sudo group changes, attack patterns in web logs; rules unchanged). Every other line is stored as a plain log, so system noise can never raise an alert.

Remote Linux or Windows machines: `sudo python3 tools/agent.py --server http://SOC-IP:5000 --key API_KEY --collect` (on Windows run the same command from an Administrator prompt). `--collect` picks the right collector for the operating system.

Linux settings: `SOC_LINUX_FILES` (comma list, replaces the default files), `SOC_LINUX_JOURNAL=0` (ignore journald), `SOC_LINUX_INTERVAL` (2), `SOC_LINUX_BATCH` (500), `SOC_LINUX_MAX_BATCHES` (20), `SOC_LINUX_BACKFILL_MINUTES` (journal only, 0 = start from now), `SOC_LOCAL_LOGS=0` (turn built-in collection off).

Windows settings (environment variables): `SOC_LOCAL_EVENTLOG` (1/0, default 1 on Windows), `SOC_WIN_CHANNELS` (comma list), `SOC_WIN_INTERVAL` (seconds when idle, default 2), `SOC_WIN_BATCH` (300), `SOC_WIN_MAX_BATCHES` (20 = at most 6000 events per channel per cycle), `SOC_WIN_BACKFILL_MINUTES` (0 = start from now; e.g. 60 also loads the last hour on the very first run), `SOC_WIN_CURSOR` (cursor file). Retention (Settings, default 90 days) deletes old events; lower it if the disk fills.

## The interface (menu)

The menu is grouped by what you do: **Monitor** (Dashboard, Alerts, Activity, Endpoints, Network), **Investigate** (Logs, Search, Cases, Threat Intelligence, Vulnerabilities), **Respond** (Playbooks, Detection rules) and **Manage** (Reports, Settings, Email notifications, Users).
- **Endpoints, Add computer (agent)** opens the same command generator.
- **Detection rules** lists every rule that can raise an alert with its severity, category, MITRE ATT&CK technique and what it detects, plus the current thresholds.
- **Settings** now includes the business-hours field for the after-hours login alert.
- A banner reminds anyone still using a default password to change it.
- Alerts from the newer rules also show their MITRE technique and recommended next steps in the alert detail.

## Endpoint Activity (menu: Activity)

Every event that arrives (Windows Event Log, Linux journal and log files, file integrity, malware scan, syslog, process and network monitor) is turned into a standard **activity**: category (User, Process, File, Network, Authentication, Privilege, System), activity name, user, status (Success / Failure), device, operating system, source IP and a **risk** (Normal, Low, Medium, High, Critical). The original log is kept untouched and is still in **Logs**.

RAW LOGS -> NORMALIZED ACTIVITIES -> DETECTION -> ALERTS -> INVESTIGATION / CASE. A normal activity is only shown on the Activity page. An **alert** is created only when a detection rule fires; the risk of the activity is then raised to the severity of that alert.

The Activity page has: risk counters (click to filter), category tabs (All, Suspicious, User, Process, File, Network, Authentication, Privilege, System), search, filters (device, username, source IP, activity, risk, alert severity, time range, event ID, operating system, status), **Live monitoring** (new rows appear within 2 seconds), **Auto refresh** (10/30/60 s), Load more, **Export CSV**, and a detail panel per activity (full message, event data, linked alert, related activity of the same user within 15 minutes).

**What becomes an alert (besides the older rules: brute force, new user, admin added, log cleared, malware, web attacks, FIM):** encoded or download-and-execute PowerShell, living-off-the-land commands (certutil, bitsadmin, mshta, regsvr32 ...), credential dumping (mimikatz, LSASS access, SAM save), reverse shell commands, remote script download and execute, backup/shadow-copy destruction, security tool tampering, log or history tampering, local admin created from the command line, reading /etc/shadow, a process started from a temp location (/tmp, Downloads, Temp), an Office application or web server spawning a shell, a shell program connecting to the internet, connections to suspicious ports, suspicious services installed, account lockouts, Defender disabled, and a **successful login after many failed attempts** (same IP, last 10 minutes). Optional: **login outside business hours** (off by default; set `SOC_BUSINESS_HOURS=08:00-18:00` or the `business_hours` setting).

**Collecting the activity.** Logins, logoffs, accounts, groups, services, scheduled tasks, firewall changes, sudo/su, cron and SSH come from the normal collectors. Run **`tools/enable_windows_auditing.bat`** once as Administrator on each Windows PC: it turns on process-creation auditing (with command line), logon and account auditing and PowerShell script-block logging, which Windows does not log by default. For process, network and file activity on Windows, Sysmon (free from Microsoft) is read automatically too. The agent and the built-in collector also watch **new processes and new network connections / listening ports** every 2 seconds (`SOC_ACTIVITY=0` turns that off, `SOC_PROC_INTERVAL`, `SOC_NET_DEDUPE_MIN`). Polling can miss a process that lives less than 2 seconds; for a complete record on Linux run `sudo tools/enable_linux_auditing.sh` (auditd, optional, creates many log lines). File activity comes from file integrity monitoring (watched folders only). Network activity is limited to connections and listening ports of this computer.

Old events stored before this feature are classified in the background after the first start.

## Protection features (real, not simulated)

**Real blocking and isolation.** Blocking an IP or isolating an endpoint in the dashboard is sent to the agent on that computer, which applies it to the real firewall (Linux `iptables`/`ip6tables`, Windows `netsh advfirewall`) and reports the result (see *Endpoints -> Response actions*). Start the agent with `--enforce` as root/Administrator:
`sudo python3 tools/agent.py --server http://SOC-IP:5000 --key API_KEY --collect --enforce`
The SOC computer itself enforces blocks only when started with `SOC_ENFORCE=1` (as root/Administrator) and it never isolates itself. Safety: the SOC server, loopback and the computer's own addresses can never be blocked; isolation always keeps the SOC server reachable (add your admin PC with `SOC_ISOLATE_ALLOW="203.0.113.5,10.0.0.0/24"` on the agent, otherwise you lose remote access such as SSH/RDP to that machine while it is isolated). Rules are re-applied when the agent restarts.

**File integrity monitoring (FIM).** `--collect` / built-in collection fingerprints (SHA-256) system files and reports created / modified / deleted / permission-changed files as logs (channel `fim`). The first run builds a baseline silently. Changes to critical files (accounts, sudoers, ssh, cron, systemd units, hosts, startup items, scheduled tasks, and system binaries when no package update is running) raise a *File Integrity Change* alert. Settings: `SOC_FIM=0`, `SOC_FIM_PATHS`, `SOC_FIM_EXCLUDE`, `SOC_FIM_INTERVAL` (300 s), `SOC_FIM_FULL_HOURS` (24).

**Malware scanning.** New and changed files in risky folders (temp, downloads, home, web roots, startup) are scanned with ClamAV (`clamdscan`/`clamscan`, install `clamav` for full signature coverage), Windows Defender (its detections arrive through the Event Log) and a built-in scanner (EICAR test file, PHP/JSP web-shell patterns, your own SHA-256 list in `tools/malware_hashes.txt`). Detections raise *Malware Detected* alerts. Test it by saving the standard EICAR test string in a file under `/tmp`. Settings: `SOC_MALWARE=0`, `SOC_MALWARE_PATHS`, `SOC_MALWARE_INTERVAL`, `SOC_MALWARE_FULL_HOURS`, `SOC_MALWARE_HASHES`. Files are not deleted or quarantined.

**Vulnerability scanning.** Installed software is listed every 6 hours (`SOC_INVENTORY_HOURS`) and checked against the free OSV database (needs internet on the SOC server): Ubuntu, Debian, Alpine, Rocky/Alma Linux. See the *Vulnerabilities* page. Windows software is listed but cannot be matched (no free feed). `SOC_INVENTORY=0` turns it off.

**Other log sources (syslog).** Routers, firewalls, switches, appliances and cloud forwarders can send syslog to the SOC: start with `SOC_SYSLOG_PORT=5514` (UDP + TCP, off by default). Direct cloud connectors (AWS, Azure, Microsoft 365) and clustering are not included.

## Running on Windows
```bat
run.bat
```
In **PowerShell** type `.\run.bat` (PowerShell does not run programs from the current folder without `.\`) and set variables with `$env:SOC_ADMIN_PASSWORD="..."`. Prefer a folder outside OneDrive (e.g. `C:\EXE-SOC`).
`run.bat` creates the virtual environment, installs the dependencies and starts the server (Python 3.9+ required, tick "Add to PATH"). Set `SOC_ADMIN_PASSWORD`, `SOC_ANALYST_PASSWORD` and `SOC_VIEWER_PASSWORD` first (`set VAR=value`). IP blocking is recorded in the tool only, because iptables does not exist on Windows.

**Windows Event Log collection** – on each Windows PC or server, open an **Administrator** terminal:
```bat
pip install psutil requests
python tools\agent.py --server http://SOC_SERVER:5000 --key API_KEY --eventlog
```
It uses the built-in `wevtutil` and forwards: failed logons (4625), new user accounts (4720), members added to Administrators / Domain Admins (4728, 4732, 4756), cleared audit logs (1102, 104) and new services (7045). On start it only records its starting point, so old history is not flooded into the SOC. This collector was tested with sample event XML, not yet on a live Windows machine.

## Change a login from the command line
Stop the tool, then run (works on Windows, Linux and macOS; the account defaults to the first admin):
```
python app.py --set-login                                   # asks for the new username and password (password is hidden)
python app.py --set-login --new-user sabari --password "Str0ng#Pass1"
python app.py --set-login --user analyst --password "N3w#Passw0rd"   # another account
```
Username: letters, digits, `_` and `.` only. Password: 8+ characters. Also re-enables the account and is logged in the audit trail. Typing `--password` on the command line leaves it in your shell history, so prefer the prompt on shared machines. Inside the tool, admins can also use Users > Rename / Reset password.

## Roles
viewer = read only · analyst = triage alerts, cases, block IPs, IOCs, isolate endpoints · admin = users, playbooks, settings, purge.

## How data gets in
1. **Ingest API** – `POST /api/ingest` with header `X-API-Key` (Settings → API key):
   ```bash
   curl -X POST http://127.0.0.1:5000/api/ingest -H "X-API-Key: KEY" -H "Content-Type: application/json" \
        -d '{"source_ip":"1.2.3.4","message":"Failed password for root"}'
   ```
   Body is one event or a list: `{"source_ip","message","dest_ip","host"}`.
2. **Agent** – `python tools/agent.py --server URL --key KEY [--follow /var/log/auth.log]` (needs `psutil`, `requests`)
3. **Log tail** – the server follows the file set in Settings → "Auth log" (default `/var/log/auth.log`; needs read permission, e.g. add the service user to the `adm` group)
4. **Demo** – `python tools/simulate.py --key KEY` streams random attacks so you can watch the dashboard move

## Detection and response
- Regex rules with severity and category; brute force escalates to Critical after N failures in M minutes (Settings)
- Blocking records the IP; enable *Enforce with iptables* in Settings (root required) to actually drop traffic
- Playbooks run automatically and are editable in the UI

## Custom alert rules (Detection rules page)
Admins can add their own alert rules under **Detection rules > Custom alert rules**. Each rule has: name, match type (**text contains** or **regex**), pattern, optional host filter (wildcards, e.g. `SRV-*`) and Windows event ID, severity, category, optional MITRE ID (e.g. `T1110`), and an optional threshold ("fire after N matches from the same IP/host within M minutes"). **Test on recent logs** counts how many of the last 2000 stored logs a rule would match, without creating alerts.
- Built-in rules run first; a custom rule fires only when no built-in rule raised an alert for that event. Custom rules see every stored log line, including plain logs.
- Custom alerts use the normal pipeline: dedupe (count xN), IOC/blocklist escalation, playbooks, cases, investigation drawer.
- Threshold counters are kept in memory and reset when the server restarts. Rules are admin-only; changes are written to the audit trail.
- API: `GET /api/rules` (field `custom`), `POST /api/custom-rules`, `PUT|PATCH|DELETE /api/custom-rules/<id>`, `POST /api/custom-rules/test`.

## Search (SPL-style)
`index=events|alerts field=value "free text" | stats count by f | top f | timechart span=1h | sort -f | head N | table a b | dedup f`
Operators: `= != > < *` wildcard, `NOT`.

## API summary
`/api/dashboard /api/alerts /api/alerts/<id>/detail /api/investigate/ip/<ip> /api/spl /api/endpoints /api/cases /api/blocklist /api/iocs /api/intel/<ip> /api/events /api/audit /api/playbooks /api/reports /api/reports/export.csv /api/users /api/settings /api/search /api/system`
State-changing browser calls need header `X-Requested-With: fetch` (CSRF guard); ingest and heartbeat use the API key instead.

## Testing
Start on an empty database, then run the 76 automated checks:
```bash
SOC_DB=/tmp/test.db ./run.sh                # terminal 1
python tools/selftest.py                    # terminal 2
```
Never run the self-test against production data. It covers auth/RBAC, detection rules, dedupe, escalation, playbooks, IOCs, drill-down, SPL, cases, reports, pages and login lockout.

## Deploying on a server
- Keep `SOC_HOST=127.0.0.1` and put nginx or Caddy in front with **HTTPS**; pass WebSocket headers (`Upgrade`, `Connection "upgrade"`, `Host`) so live push works
- Run as a normal user under systemd; run only **one** instance (workers and lockout state are in memory)
- Set your own passwords, and make sure `soc.db` / `.secret` were not copied from another machine
- The UI loads Chart.js, Leaflet and Socket.IO from public CDNs; without internet the charts and map will be blank
- IP geolocation calls ip-api.com over HTTP; turn it off in Settings if that is a concern
- Back up `soc.db` regularly

## Security notes
Passwords are hashed (scrypt), login locks out after 5 failures in 5 minutes, session cookies are HttpOnly + SameSite, CSV export neutralises formula injection, and HTML output is escaped. Never commit `soc.db`, `.secret` or `.env` (already in `.gitignore`).

## Limitations
Detection is pattern-based, so it recognises known attack text rather than unusual behaviour. It does not yet receive syslog, read Windows Event Logs, or inspect network traffic (use Suricata or Zeek and forward their logs). SQLite suits small to medium log volumes. This is a monitoring aid, not a replacement for a commercial SIEM.

## Legal
Only monitor networks and systems you are authorised to monitor, and make sure users are informed according to your organisation's policy.

## License
Add a license file (for example MIT) before making the repository public.

## Rule library and playbook library
`rules_library.py` holds ready-made **detection rules** (R001...) and **response playbooks** (P001...), each mapped to the attack it covers and (for rules) a MITRE technique. Nothing is active until you add it: use the "Rule library" card on **Detection rules**, the "Playbook library" card on **Playbooks**, or the command line (`python rules_library.py list | add R013 | add-attack "Ransomware" | pb-list | pb-add P009 | pb-add-attack Ransomware`). A library playbook runs only for the alerts of its own attack, at or above its trigger severity. To create your own, append an `R(...)` or `PB(...)` line in `rules_library.py`. API: `/api/rule-library`, `/api/playbook-library` (admin POST actions: add, remove, add-attack, add-all).

## Locked out of the login page
The lockout is per username and address (default 5 wrong tries in 5 minutes, the message shows the time left) and a good login clears it. It is kept in memory, so **restarting the server clears it at once**. Tune it with `SOC_LOGIN_MAX` and `SOC_LOGIN_WINDOW_MIN`. If you forgot the password, stop the server and run `python app.py --set-login --password NewPassword1` (add `--user NAME` for a non-admin account). A database created earlier keeps its old passwords, so `Admin@123` only works on a fresh install or a database made without `SOC_ADMIN_PASSWORD`.


## Advanced layer (incidents, correlation, risk, false-positive management)
See **SOCX-GUIDE.md**. New menu pages: Incidents, Threat hunting, Detection library, False positives, Agent health. Self-test: `python tools/selftest_socx.py`.

## Email notifications
See **EMAIL-NOTIFICATION-GUIDE.md**. Menu: Manage, Email notifications. Settings come from the server environment (SMTP_*) or the dashboard; the password only from `SMTP_PASSWORD` / `SMTP_PASSWORD_FILE`. Tests: `python -m unittest tests.test_notify -v`. Delivery by SMTP or by the **Gmail API** (OAuth, set up once with `python tools/gmail_auth.py --write`); put the settings in `.env`, which is loaded automatically.
