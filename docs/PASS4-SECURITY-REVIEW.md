# Pass 4: Security Verification and Release Readiness

Date: 2026-10-17 · Branch `remediation-pass3` · Pass 3 commit `13edc2e` · Pass 4 code commit `5d41162` (this document is added in a docs-only commit after it; the tests below ran on `5d41162`).
Environment: Ubuntu sandbox, Python 3.12.3, Flask 3.1.3, Werkzeug 3.1.7, cryptography 46.0.6, requests 2.33.1, psutil 7.2.2, systemd 255 tools, Node. **No network. Not installed: flask-socketio, gunicorn, regex, nginx, pip-audit, Bandit, PowerShell/Windows, a browser. systemd is not running (`is-system-running`: offline).**

**Release recommendation: NOT production-ready.** See section 3.

## 1. Baseline (Pass 3 commit, untouched)
Working tree clean. All 18 suites exit 0: pass3 31, security_remediation 10, agent_hmac 15, mfa 14, data_protection 18, hardening_round2 6, ops_drills 4, static_security 6, hardening_misc 19/19, log_visibility 12/12, fleet 23/23, unified 144/144, notify 59, api_audit 29/29, linux_agent 64/64, installer_umask / dev_certs / windows_installer exit 0. Pass 3 results were reproducible; the findings below were found by review and new tests *behind* those passing suites.

## 2. Findings (severity, evidence, fix, test)

| ID | Sev | Finding and evidence | Fix | Test | Status |
|---|---|---|---|---|---|
| P4-01 | High | **Login failure counter race.** A concurrent-login test (24 threads, one account) produced `KeyError` in `login()` (app.py) and recorded only 7 of 24 failures: the shared in-memory dict was cleaned by another thread between insert and append, so concurrent guessing both errored and under-counted (gunicorn runs 8 threads). | One lock around every access to the dict; persistent SQLite counters are written first so a failure is always recorded | `Concurrency.test_02`, `test_01` (4 processes x 30 writes = exactly 120, no lock errors) | FIXED AND VERIFIED (threads + processes on one host) |
| P4-02 | High | **No hard runtime regex limit** without the optional `regex` package (creation-time probe only). A stored pattern like `a*a*a*a*a*a*a*a*a*a*b` runs unbounded in the ingest thread. | `security/rxsandbox.py`: matching in a killable worker, per-match timeout (default 100 ms, `SOC_REGEX_TIMEOUT_MS`), memory cap on POSIX, worker respawn; `engine` counts strikes and **disables** (never deletes) a rule after 3 timeouts with an audit entry; `regex` package still used when installed | `RegexRuntime.test_01..03` (kill < 2 s, recovery, 2000 matches < 6 s, rule disabled + audited, other rules keep firing) | FIXED AND VERIFIED (limits: POSIX memory cap only; one worker serialises matches) |
| P4-03 | Medium | DB/WAL/SHM `chmod` failures were silently ignored. | Failures and still-open modes are reported; fatal in production | `Hardening.test_01` | FIXED AND VERIFIED |
| P4-04 | Medium | `SOC_ENC_KEY_FILE` / dev key file accepted with group/world-readable mode. | Production refuses; development warns (never prints the key) | `Hardening.test_02` | FIXED AND VERIFIED |
| P4-05 | High (install) | `cryptography` is imported by `security/` and `tools/` but was **not in requirements.txt**: a fresh install would fail at start. | Declared; `requirements-prod.txt` (gunicorn, simple-websocket, optional regex) added, unpinned and unhashed on purpose | `test_static_security.test_07` | FIXED AND VERIFIED |
| P4-06 | Info | Error handling: 612 hostile requests (9 bodies x every state-changing route, admin session) gave **0 server errors**. | none needed | `DeployTools.test_02` | VERIFIED |
| P4-07 | Info | Account disable, delete, admin password reset and role demotion end/alter a live session immediately. | none needed | `Sessions.test_01..05` | VERIFIED (HTTP sessions; sockets see Section 3) |
| P4-08 | Info | `systemd-analyze verify` exit 0 and `security --offline` exposure 3.9 (OK) on a copy of `deploy/soc.service` with host-specific values substituted. This checks syntax/sandbox score, **not** a service start. | none | `DeployTools.test_01` | VERIFIED (static) |

## 3. Release-blocker checklist

| Item | State | Evidence needed to close |
|---|---|---|
| Rotate the exposed session secret / shared ingest key / encryption keys on the real system | **OPEN (operator)** | Old key returns 401, old cookies rejected, audit entries present (procedure below) |
| Finish legacy-agent migration (`SOC_AGENT_AUTH=hmac-required`, `SOC_LEGACY_API_KEY=off`) | **OPEN (operator)** | `GET /api/agents/auth-status`: `ready_for_hmac_required` true and `ready_for_legacy_off` true |
| Real Flask-SocketIO handshake, origin check, revoked/disabled-session disconnect | **BLOCKED** (flask-socketio not installable offline); unit tests use a stub only | Run `tests/test_pass3_security.py` + a real client test on a networked host |
| nginx TLS + WebSocket proxying, trusted-proxy behaviour | **BLOCKED** (nginx absent) | `nginx -t`, TLS handshake, `/socket.io/` upgrade, forged `X-Forwarded-*` ignored |
| systemd start / restart / permissions / health check | **NOT RUN** (systemd not running); unit syntax verified | `systemctl start`, kill -9 restart, `curl /healthz` |
| Windows installer + agent (install, upgrade, uninstall, reinstall, network errors) | **BLOCKED** (no Windows) | Run `agent/install_windows.ps1` on a test host |
| Linux agent on a real distribution | **PARTIAL**: `test_linux_agent` (64 checks) exercises the real installer against a fake systemctl and a real TLS test server | Install/uninstall on a VM with real systemd |
| `pip-audit`, Bandit, hash-locked requirements | **NOT RUN / BLOCKED** (tools absent, no network). `pip check`: no broken requirements. No hashes were generated or invented | Run on a networked machine, review, commit the lock |
| Vendored frontend assets + CSP tightening | **BLOCKED** (needs download) | `tools/vendor_assets.py`, then confirm `csp()` has no CDN hosts |
| Browser-side XSS / dashboard walkthrough | **NOT RUN** (no browser). Static scan + node `esc()`/`pill()` tests ran | Manual/Playwright run with hostile strings |
| Concurrency / rate limiting | **CLOSED** for one host (threads and processes) | Multi-host needs a shared limiter database |
| Regex runtime limit | **CLOSED** (P4-02) | - |

## 4. Operator instructions (no secret values; run on the real host after a verified backup)
1. Backup: `python tools/backup.py create` then `python tools/backup.py verify <file>`; keep `SOC_ENC_KEYS` copies off-host.
2. Session secret: `python tools/rotate_secrets.py session-secret --out /root/new-secret.env`; put the value in `/etc/exe-soc/env`; restart. All dashboard sessions end.
3. Shared ingest key: `python tools/rotate_secrets.py ingest-key --out /root/new-ingest.env` (only matters while `SOC_LEGACY_API_KEY=on`); confirm the old key returns 401.
4. Encryption keys: `python tools/rotate_secrets.py enc-key --out /root/ring.env` (new key first, old keys kept after it), restart, run the documented `reencrypt` step (docs/MIGRATION-AND-ROTATION.md), keep old keys until no backup needs them.
5. Legacy agents: set `SOC_AGENT_AUTH=permissive` and `SOC_LEGACY_API_KEY=on` explicitly, enrol each host as a signed fleet agent, watch `/api/agents/auth-status`, then remove both overrides (production defaults are strict).
6. Remove the old `.secret` / key files from every copy of the archive. Never reinstate a rotated value.

## 5. Rollback (preserves database integrity, never restores compromised credentials)
Stop the service; keep the current DB (move aside, do not delete); restore the pre-upgrade backup only if data is damaged, using `python tools/backup.py restore <file> --to <new path>` and `PRAGMA integrity_check`; start the previous code. Schema changes are additive (`throttle` table, settings rows). Do **not** restore old secrets: if a rollback needs the previous behaviour for agents, use `SOC_AGENT_AUTH=permissive` / `SOC_LEGACY_API_KEY=on` with the *rotated* key.

## 6. Changed files (Pass 4)
`app.py` (login counter lock) · `engine.py` (sandboxed matching, strikes) · `security/rxsandbox.py` (new) · `db.py` (visible permission failures) · `security/crypto.py` (key-file mode) · `requirements.txt`, `requirements-prod.txt` · `tests/test_pass4_security.py` (new), `tests/test_static_security.py` (+1) · this document.

## 7. Commands actually executed (final)
`python3 tests/<suite>.py` for the 19 suites (legacy suites with `SOC_ALLOW_DEFAULT_CREDS=1 SOC_MIN_PASSWORD=8`); a 612-request fuzz script; `systemd-analyze verify|security --offline=true`; `pip check`; `pip download flask-socketio` (failed: no network).
Final results on `5d41162`: pass4 14, pass3 31, security_remediation 10, agent_hmac 15, mfa 14, data_protection 18, hardening_round2 6, ops_drills 4, static_security 7, hardening_misc 19/19, log_visibility 12/12, fleet 23/23, unified 144/144, notify 59, api_audit 29/29, linux_agent 64/64, installer_umask / dev_certs / windows_installer exit 0. No fixture was changed in Pass 4.
