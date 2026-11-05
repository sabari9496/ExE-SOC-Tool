# EXE-SOC full audit: bugs found and fixed

Method: AST static analysis of every Python file; node/bash syntax checks; an in-process sweep of **all 130 routes** (anonymous, per role, and ~28,000 hostile requests with garbage ids, query strings and JSON bodies, on a database with real events/alerts); manual review of auth, settings, user management, the syslog receiver, collectors and the front-end; then regression of every test suite. `tests/test_api_audit.py` and `tests/test_hardening_misc.py` keep these checks permanent.

## Bugs fixed

| # | Severity | Bug | Fix |
|---|---|---|---|
| 1 | **High** | **Settings poisoning.** `PUT /api/settings` stored any text. `home_lat="abc"` or `brute_threshold="x"` made **all log ingestion fail** and broke the dashboard; `retention_days="forever"` killed the retention thread silently (data never purged). | Validation on write (types, ranges, `HH:MM-HH:MM`, all-or-nothing); tolerant reads (`setting_num`) so already-bad values recover; unvalidated socx thresholds also tolerant. |
| 2 | **High** | **Revoked access persisted.** Role/active state lived only in the signed cookie: a deleted, deactivated or demoted user (or one whose password was reset after a compromise) kept full access until the cookie expired. | `me()` re-checks the user row on every request (exists, active, current role, password stamp). Changing your own password keeps your session; all others end at once. |
| 3 | High | **~40 handlers crashed (HTTP 500) on non-object JSON or wrong types** (`"str"`, `123`, `[]`, `{"title": ["x"]}`), including cases, endpoints, blocklist, IOCs, custom rules, notifications test, users, incidents, assets. | `body()` always returns a dict; `sarg/iarg/farg` helpers; central 400 handler (`BadInput`, type/value errors, SQLite bind errors) with the offending line logged. |
| 4 | Medium | Ids beyond SQLite's range (`/api/x/99999999999999999999`) raised `OverflowError` (500) on every `<int:id>` route. | `SafeInt` URL converter: out-of-range ids are 404. |
| 5 | Medium | `?limit=abc`, `?days=x`, `expires_minutes="x"` etc. raised `ValueError` (500); **a negative `limit` meant "no limit"** in SQLite (full data dump). | `iarg` clamps every limit/offset/days to a sane range. |
| 6 | Medium | `/api/ingest` and fleet event ingestion crashed on events whose fields were numbers/lists/objects. | `engine._clean_item` coerces/drops per field; non-objects ignored. |
| 7 | Medium | A non-ASCII `X-API-Key` header raised `TypeError` (500) in `compare_digest`. | Bytes comparison; empty key can never match. |
| 8 | Medium | **CSV formula injection** in events, activity and reports exports (`=cmd|...` opens as a formula in Excel). | `csv_cell` neutralises `= + - @` cells. |
| 9 | Medium | No security headers; session cookie not `Secure` over HTTPS; API responses cacheable. | CSP (strict script policy: the single inline `onclick` was converted), X-Frame-Options, nosniff, Referrer-Policy, Permissions-Policy, HSTS over TLS, `Cache-Control: no-store` on API, `Secure` cookie with TLS (or `SOC_COOKIE_SECURE=1`). |
| 10 | Medium | Syslog receiver: unbounded memory queue (UDP flood) and unbounded TCP line length / no idle timeout. | Queue cap (`SOC_SYSLOG_MAX_QUEUE`, drops counted), 8 KB lines, 60 s idle timeout; parser fuzzed with 3,000+ inputs. |
| 11 | Medium | Background workers (retention, host monitor, log tail, activity backfill...) died silently on any exception. | `supervise()` logs and restarts them. |
| 12 | Medium | `tools/linuxlogs.py` and `tools/collect.py` were stale copies of the agent's collectors (server-side collection missed fixes). | Synced; `tests/test_hardening_misc.py` fails if they ever differ again. |
| 13 | Medium | Doctor (`exe_soc_diag.py`): the "journal not readable" branch used an undefined name (`SVC`) and would crash exactly when needed. | Fixed + regression test. |
| 14 | Low | Usernames unique only case-sensitively on creation (`Admin` next to `admin`). | Case-insensitive check. |
| 15 | Low | Login timing revealed whether a username exists. | Dummy hash check for unknown users. |
| 16 | Low | JSON endpoints returned HTML error pages; request bodies unlimited. | JSON errors on `/api`; `SOC_MAX_BODY_MB` (default 16). |
| 17 | Low | Front-end: a few enum fields interpolated without `esc()`. | Escaped (defence in depth; all record text was already escaped). |

## Checked and found sound
SQL is parameterised everywhere (the four string-built statements use internal constants); no `shell=True`/`os.system`/`eval`; enforcement uses argument lists plus `ipaddress` validation (no command injection); the vulnerability checker only calls the fixed OSV URL (no SSRF); RBAC is enforced on every state-changing route (viewer refused on all, analyst refused on admin routes); CSRF header required on every mutating route; DB connections are always closed; login lockout works.

## Known limitations (not changed)
- The UI loads Chart.js, Socket.IO and Leaflet from public CDNs without Subresource Integrity hashes (cannot fetch them to hash here): vendor them into `static/` for an air-gapped or high-assurance deployment. The CSP restricts scripts to those exact hosts.
- Syslog (UDP/TCP) is unauthenticated by nature: the sender's hostname is whatever the packet claims. Restrict the port with a firewall.
- Sessions are cookie-based; rotate `SOC_SECRET` to invalidate every session at once.
- Not run here: real browsers (the CSP was reasoned from the code, not rendered), real systemd/Kali, the Windows agent at runtime.
