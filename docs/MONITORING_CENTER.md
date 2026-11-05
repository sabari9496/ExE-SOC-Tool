# Monitoring Center (Stage 2)

Labels: **[CODE]** read in the source · **[TEST]** shown by an automated test · **[UNVERIFIED]** not tested here (needs a real host or browser).
Everything the page shows is derived from stored data when you open it. No metric, state or "connected" flag is hardcoded or simulated.

## 1. What was added
Navigation entry **Monitoring Center** (`/monitoring-center`) with five tabs: **Overview, Windows, Linux, Ubuntu, Cloud**. The Windows/Linux/Ubuntu tabs list endpoints with filters; clicking a row opens the existing endpoint detail from *Remote agents* (the same drawer, shared through `window.SOCX_FLEET.detail`). The Cloud tab shows **NOT CONFIGURED**: no cloud connector framework exists in this version, so nothing is monitored and no cloud or demo data is displayed.
Unchanged: the existing pages, `/api/agents` (still reports its original `online / warning / offline / revoked`; `warning` = the new `degraded`), agent enrollment and event protocol, authentication and all security controls.

## 2. Endpoint states (single definition: `fleet/status.py`)
| State | Meaning |
|---|---|
| `revoked` | the agent credential was revoked (highest precedence) |
| `never_connected` | enrolled, but no heartbeat or event was ever received after enrollment (a heartbeat time equal to the enrollment time does not count) |
| `offline` | last heartbeat older than the **offline** limit |
| `degraded` | heartbeat within the offline limit, **and** at least one of: heartbeat older than the **online** limit; 3 or more recent upload failures; more than 5 000 queued events; collector errors reported |
| `online` | heartbeat within the online limit and none of the above |
Boundaries **[TEST StatusStates.test_01]**: age equal to the online limit is still `online`; one second more is `degraded`; age equal to the offline limit is still `degraded`; one second more is `offline`. A heartbeat slightly in the future (clock skew) is treated as age 0.
**Thresholds** (configurable, validated at startup, shown on the Overview page): `SOC_AGENT_ONLINE_SECONDS` default 90 (15-3600), `SOC_AGENT_OFFLINE_SECONDS` default 300 (30-86400); offline must be greater than online; only plain digits are accepted. An invalid value stops `app.py` / `wsgi:app` with an `ERROR:` message naming the variable **[TEST StatusStates.test_04/05]**.
The pre-existing `agent_status()` keeps its old behaviour **[TEST StatusStates.test_06]**; it now reads its two limits from the same central settings. Note one deliberate difference: `agent_status()` still shows a just-enrolled agent as online for 90 s; only the Monitoring Center reports `never_connected`.

## 3. Operating-system classification (`fleet/osmeta.py`)
Source of truth: the **agent** reads `/etc/os-release` (`ID`, `VERSION_ID`) and reports `os_family` (windows/linux/darwin), `distro_id`, `distro_version` as **additional** fields (older servers ignore them; older agents simply do not send them) **[CODE agent `os_metadata()`]**. **The hostname is never used** (the classifier has no hostname input **[TEST OsClassification.test_03]**; a host *named* `ubuntu-prod-01` reporting Debian is Linux, a host named `ubuntu-lookalike` with no metadata is Unclassified **[TEST MonitoringApi.test_02]**).
| Reported | Class (tab) | Distribution shown |
|---|---|---|
| `os_family=windows` | windows | - |
| linux + `distro_id=ubuntu` | **ubuntu** (Ubuntu tab only) | ubuntu |
| linux + any other id (debian, rhel, linuxmint ...) | linux | that id. Linux Mint is **not** Ubuntu even though its `ID_LIKE` lists ubuntu |
| linux, no usable id | linux | `unknown` ("distribution unknown") |
| legacy agent (no `os_family`), `os` exactly "Windows" / "Ubuntu" | windows / ubuntu | marked `legacy_os_name` ("limited metadata") |
| legacy agent, `os` a Linux name ("Debian GNU/Linux", "Fedora Linux", "Rocky Linux" ...) | linux | `unknown` |
| anything else (a bare kernel string, macOS, nothing) | **unknown** (Overview "Unclassified" only) | - |
Values are validated on the server (`distro_id` lower-case `[a-z0-9._-]` up to 40 characters, `distro_version` up to 40, family from a fixed list); invalid values are ignored, never stored and never cause an error **[TEST MonitoringApi.test_10]**.
**Limitation:** the OS facts are *reported by an authenticated agent*; the server cannot independently verify them, so a compromised agent could misreport its class. They are as trustworthy as the agent itself.

## 4. Database migration v4 (additive)
`agents` gains nullable `os_family, distro_id, distro_version, environment, tags, first_heartbeat_at`, plus indexes `ix_agents_family`, `ix_agents_env`, `ix_agents_hb`, `ix_alert_agent_ts`. `first_heartbeat_at` is back-filled **only** where the agent clearly reported after enrollment (`last_heartbeat > registered_at`); no existing value is changed.
- **Fresh database:** migrations 1-4 are applied at creation **[TEST MigrationV4.test_01]**.
- **Existing database:** *not* changed at startup (a notice is printed). Run `python migrate.py plan --db <file>` (read-only), take a backup, then `python migrate.py apply --db <file> --yes` (it takes and verifies its own backup first). Verified on a copy of a v3 database: data in `agents, users, alerts, events, ledger, quarantine` identical before and after, re-run is a no-op, a failed or killed migration rolls back and can be retried **[TEST MigrationV4.test_02/03/04]**.
- **Until it is applied:** the three read endpoints and the edit endpoint answer **409** with a hint (the page shows "Monitoring Center is not ready", no numbers). Agents keep registering and sending heartbeats; the new OS fields are simply not stored. Existing pages and `/api/agents` keep working **[TEST MigrationV4.test_05]**.
- Rollback: restore the pre-migration backup (see `DATABASE_BACKUP_AND_RECOVERY.md`). Older code ignores the extra columns.

## 5. APIs (all read-only except the edit)
| Endpoint | Role | Notes |
|---|---|---|
| `GET /api/monitoring/overview?since=&until=` | viewer, analyst, admin | totals, per-class state counts, alerts and events in the window, thresholds, Cloud status |
| `GET /api/monitoring/endpoints` | viewer+ | filters below; `limit` 1-200 (default 50), `offset`, `sort=hostname|last_heartbeat|state|alerts` |
| `GET /api/monitoring/endpoints/<id>` | viewer+ | one endpoint, last 60 heartbeats, last 50 alerts (no credential fields) |
| `POST /api/monitoring/endpoints/<id>/meta` | **admin only** | `{environment, tags}`; validated; CSRF header required; **audited** |
Filters (AND-combined) **[TEST MonitoringApi.test_06/07]**: `os` (windows, linux, ubuntu, unknown), `state` (comma list), `q` (hostname substring, case-insensitive, matched in code, never put in SQL), `ip` (valid IPv4/IPv6, exact, IPv6 normalised), `severity` (endpoints with at least one alert of that severity **in the window**), `since`/`until` (`15m`, `24h`, `7d` or `YYYY-MM-DD[ HH:MM:SS]`, server local time, window at most 366 days, default last 24 h), `env`, `tag`. Anything invalid returns 400 and nothing is executed. "Alerts / events in window" count alerts by first-seen time and events by event time for that endpoint.
Editing rules: environment 1-32 characters (letters, digits, space, `_ . -`) or empty to clear; up to 10 tags, lower-cased, de-duplicated, 1-32 characters of `a-z 0-9 _ . : -`. Each change writes an audit entry with actor, endpoint, old and new values; rejected edits write nothing **[TEST MonitoringApi.test_01/09]**.
Fleet size: at most 5 000 endpoints are processed per request; beyond that the response has `truncated: true` and the page shows a "Partial view" banner **[TEST test_07b]**.

## 6. Security implications
New read endpoints expose only what the existing viewer-level `/api/agents` already exposes (no credentials, hashes or keys; tested). The only new write is admin-only, validated, CSRF-protected and audited. No new dependency, no new secret, no new outbound connection, no change to authentication, MFA, CSRF, headers or the agent protocol (additive optional fields only; old agents tested). The page escapes every dynamic value, uses no inline event handlers (CSP) and no `eval` **[TEST test_12]**. A wrong retention/threshold setting stops startup instead of being silently ignored.

## 7. Limitations (honest list)
1. **Real hosts: UNVERIFIED.** No Windows or Ubuntu machine was available. The agent's os-release handling, the API and the states are tested with fixtures and synthetic agents only; see section 8.
2. **Browser UI: UNVERIFIED in a real browser.** Checked: JavaScript syntax (`node --check`), served assets, navigation entry, absence of inline handlers/eval. Not checked: layout, clicks, the edit drawer, auto-refresh.
3. Refresh is a 30-second poll while the tab is visible; no WebSocket push for this page.
4. OS facts are self-reported (see section 3). Times are server-local (known item F-08).
5. Filtering is done in Python over at most 5 000 endpoints; **performance has not been benchmarked**.
6. Cloud shows NOT CONFIGURED because no connector exists yet (Stage 4). Per-source "unavailable log source" status, machine re-enrollment control and the minimum agent version check are Stage 3.
7. `first_heartbeat_at` for pre-existing agents is an approximation (their last heartbeat).

## 8. Manual verification plan (run on authorized machines; mark each result in your own test log)
**Prerequisite:** migration v4 applied on the server (`python migrate.py status --db soc.db` shows version 4); an administrator account; the updated agent (it sends the new fields).
**A. Ubuntu host** (expected: appears in the **Ubuntu** tab only)
1. On the host: `grep -E '^(ID|VERSION_ID)=' /etc/os-release` -> expect `ID=ubuntu` and a version.
2. Create an enrollment token (Remote agents), install and enroll the agent with the repository's Linux installer.
3. Within about a minute open Monitoring Center > Ubuntu: the host is listed, state **Online**, OS column `ubuntu <version>`, agent version shown; it must **not** be in the Linux tab. `GET /api/monitoring/endpoints?os=ubuntu` shows `classified_by: os_release_id`.
4. `sudo systemctl stop <agent service>`: after more than 90 s the state becomes **Degraded** (heartbeat too old), after more than 300 s **Offline** (defaults). Start it again: **Online**.
5. Revoke the agent in Remote agents: state **Revoked**.
**B. Other Linux** (Debian/Fedora/Mint...): `ID=` is not `ubuntu` -> appears in the **Linux** tab with that ID; a host whose `/etc/os-release` is missing or has no `ID=` appears in Linux with "distribution unknown".
**C. Windows host** (expected: **Windows** tab): enroll with the Windows installer; state Online within about a minute, OS column shows the Windows version; stop the scheduled task / service as in the Windows guide to see Degraded then Offline; restart for Online. Record whether the host really appears under no other tab.
**D. Never connected:** enroll an agent and stop it immediately, before its first heartbeat (heartbeats are sent about every 30 s): it shows **Never connected** and stays so until it first reports.
**E. Legacy agent:** an agent not yet updated shows "(limited metadata)"; an Ubuntu one is still listed under Ubuntu (by its reported `os` name), a Debian one under Linux with "distribution unknown".
**F. Editing:** as admin click Edit on an endpoint, set environment `production` and tags `web, dmz`, Save: values appear in the row; the Activity/audit log has an "Endpoint metadata updated" entry; as analyst/viewer the Edit button is absent and a direct POST returns 403.
**G. Filters:** combine state + hostname + severity + window; the count in the header changes accordingly and "Clear" restores the full list.
**H. Unmigrated safety (optional, on a copy):** point a test server at a copy of the old database without applying v4: Monitoring Center shows "not ready"; Remote agents and agents keep working.
