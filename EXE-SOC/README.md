<<<<<<< HEAD
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

## Screenshots
_Add screenshots of the dashboard and the alert drawer here (`docs/dashboard.png`, `docs/alert-drawer.png`)._

## Quick start
```bash
git clone https://github.com/sabari9496/ExE-SOC-Tool.git
cd ExE-SOC-Tool
./run.sh                 # creates .venv, installs deps, starts on http://127.0.0.1:5000
./run.sh --no-demo       # start with an empty database (recommended for real use)
```
Requires Python 3.9+. Default logins (**change them before real use**):

| User | Password | Role |
|---|---|---|
| admin | `Admin@123` | full access |
| analyst | `Analyst@123` | triage and respond |
| viewer | `Viewer@123` | read-only |

Override before the first run with `SOC_ADMIN_PASSWORD`, `SOC_ANALYST_PASSWORD`, `SOC_VIEWER_PASSWORD`.
Other env vars: `SOC_HOST` (default 127.0.0.1), `SOC_PORT`, `SOC_DB`, `SOC_SECRET`.

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

## Search (SPL-style)
`index=events|alerts field=value "free text" | stats count by f | top f | timechart span=1h | sort -f | head N | table a b | dedup f`
Operators: `= != > < *` wildcard, `NOT`.

## API summary
`/api/dashboard /api/alerts /api/alerts/<id>/detail /api/investigate/ip/<ip> /api/spl /api/endpoints /api/cases /api/blocklist /api/iocs /api/intel/<ip> /api/events /api/audit /api/playbooks /api/reports /api/reports/export.csv /api/users /api/settings /api/search /api/system`
State-changing browser calls need header `X-Requested-With: fetch` (CSRF guard); ingest and heartbeat use the API key instead.

## Testing
Start on an empty database, then run the 76 automated checks:
```bash
SOC_DB=/tmp/test.db ./run.sh --no-demo      # terminal 1
python tools/selftest.py                    # terminal 2
```
Never run the self-test against production data. It covers auth/RBAC, detection rules, dedupe, escalation, playbooks, IOCs, drill-down, SPL, cases, reports, pages and login lockout.

## Deploying on a server
- Keep `SOC_HOST=127.0.0.1` and put nginx or Caddy in front with **HTTPS**; pass WebSocket headers (`Upgrade`, `Connection "upgrade"`, `Host`) so live push works
- Run as a normal user under systemd; run only **one** instance (workers and lockout state are in memory)
- Set your own passwords and use `--no-demo`
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
=======
# ExE-SOC-Tool
Lightweight open-source SOC monitoring platform built with Flask and SQLite. Ingests logs via API, agents and syslog-style feeds, detects attacks with rules, and shows live alerts, threat map, cases and playbooks. Splunk-style drill-down on any alert or IP, plus a built-in SPL-like search.
>>>>>>> c1c1ab62a6e125185ac116a6c6f233343e9cd1e7
