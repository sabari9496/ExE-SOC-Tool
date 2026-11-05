# EXE-SOC remediation report — pass 2 (honest status)

**NOT production-ready.** Release-blocking items remain open or unexercised (see §4–5). Nothing here was run in a real staging deployment.
Evidence base: the supplied tree only (no phase diffs/final report were in the upload). Branches: `remediation/security-hardening` (pass 1) → `remediation/pass2`; backups of both starting states exist outside the tree. Sandbox limits: **no network** (cannot install flask-socketio, gunicorn, regex, pip-audit, bandit, or download vendored assets), no root/systemd/nginx, no browser, no Windows.

## 1. Test evidence (exact; "P" = assertions passed)
| Suite | Result | Notes |
|---|---|---|
| test_security_remediation | **10/10 pass** | secure defaults, sessions, logout, ReDoS, proxy trust, prod dev-server refusal, prod fails closed without keys |
| test_agent_hmac (new) | **15/15 pass** | signing, tamper, path-binding, replay, stale/future ts, cross-agent, downgrade ratchet, legacy migration, scopes, rotation, revoke, forged host/severity, malformed |
| test_mfa (new) | **10/10 pass** | enrollment forced, encrypted secret, replay, recovery codes single-use, throttle, reauth, audited admin reset, RFC 6238 vector, no logout-CSRF |
| test_data_protection (new) | **18/18 pass** | AES-GCM + context binding, key rotation (+audit chain survives), fail-closed on missing key, backups (tamper/wrong-key/restore/rotation), purge safeguards, audit chain edit/delete/inject/truncate, checkpoints |
| test_hardening_round2 (new) | **6/6 pass** | pill() injection (node), syslog bind policy, geo default, Windows installer (static), vendor-manifest tamper detection, CDN-fallback flag |
| test_api_audit | **29/29 pass** | run alone (28k-request fuzz completes) |
| test_unified | **144/144 pass** | |
| test_fleet | **23/23 pass** | |
| test_hardening_misc | **19/19 pass** | |
| test_log_visibility | **12/12 pass (alone, 2 runs)**; 11/12 once when 10 suites ran in parallel (3b: timing) | **flaky under load**, not investigated further |
| test_linux_agent | **64/64 pass** (rerun alone); first parallel run 62P/1F (G4 compares live-server DB file hash — **fragile under load**) | pass on rerun; fragility noted |
| test_notify | **59/59 pass** (263 s) | |
| test_installer_umask / test_dev_certs / test_windows_installer | **1 / 1 / 2 pass** | Windows test is static (no PowerShell) |
| **Socket.IO tests / connect handler** | **BLOCKED** | flask-socketio not installable offline; handler is **untested code** |
| Static analysis, dependency audit, browser/CSP tests, nginx/gunicorn/systemd run, Windows agent run, staging deployment | **NOT EXECUTED** | |
Legacy suites need `SOC_ALLOW_DEFAULT_CREDS=1 SOC_MIN_PASSWORD=8` (they log in with the old demo passwords); the new suites run with secure defaults. Test edits: `/logout`, `/login/mfa`, `/mfa-setup` exempted from the "viewer refused" and "needs CSRF header" sweeps (self-service auth-flow routes; each covered by its own tests). A real bug found by that sweep (POST /login/mfa logging out an authenticated user) was **fixed**, not exempted, and has a regression test.

## 2. Remediation matrix
| # | Finding | Status | Evidence |
|---|---|---|---|
| 1 | Default credentials Admin@123 etc. | **Fixed** | test_security_remediation |
| 2 | Session revocation/rotation/idle+absolute expiry, POST logout, CSRF | **Fixed** | same |
| 3 | Proxy header trust | **Fixed** | same (untrusted path); trusted-proxy path untested |
| 4 | Shared ingest key plaintext in DB | **Fixed** (AES-GCM at rest, regen needs reauth, kill switch `SOC_LEGACY_API_KEY=off`) | test_data_protection |
| 5 | Packaged `.secret`, exposed legacy keys | **Partially fixed** — file removed, new atomic 0600 creation, rotation tooling. **Rotation by you is still required → open until done** | tools/rotate_secrets.py (CLI tested for enc-key/reencrypt only) |
| 6 | Agent HMAC signing (method, path+query, ts, nonce, body), scopes, rotation, replay, ratchet, staged legacy migration | **Fixed** (server + reference agent) | test_agent_hmac. Real Linux agent signing path exercised by test_linux_agent run; Windows agent unexercised |
| 7 | Agent host/severity forgery | **Fixed/verified** (server takes host from enrolled identity; severity ignored) | test_agent_hmac #13 |
| 8 | Legacy `/api/agent/*` + `/api/ingest` key routes | **Partially fixed** — controllable/disablable, migration documented; **still on by default** | docs/MIGRATION-AND-ROTATION.md |
| 9 | TOTP MFA (enroll, challenge, recovery codes, replay, throttle, required roles, audited reset) | **Fixed** | test_mfa. Limits: throttle is in-memory/per-process; no QR (manual key); TOTP not required by default outside production |
| 10 | Field encryption + key rotation | **Fixed for api_key, TOTP secrets, agent signing keys**; other DB fields (e.g. notification config) not classified/encrypted → **partial** | test_data_protection |
| 11 | Tamper-evident audit chain + signed checkpoints | **Fixed (detection)**; **off-host storage not automated → partial** | test_data_protection; see docs/AUDIT-INTEGRITY.md |
| 12 | Purge/reset safeguards | **Fixed** (reauth ≤2 min incl. TOTP, prod MFA required, typed confirm, verified encrypted backup, fail closed, single-use reauth, audit). CLI `--reset` backs up first, aborts on failure. | test_data_protection. CLI path itself not run |
| 13 | Encrypted backups, integrity, rotation, restore drill | **Fixed** (synthetic-data drill passes) ; off-host copy and scheduling = operator task | test_data_protection, tools/backup.py |
| 14 | ReDoS in custom rules | **Partially fixed** (heuristics + 2000-char input cap; hard timeout only if `regex` installed) | test_security_remediation |
| 15 | `pill()` attribute injection | **Fixed** | node-executed test. **Wider XSS review of all templates/JS: NOT done** |
| 16 | Syslog | **Fixed (policy)**: default loopback, refuses 0.0.0.0/public without explicit opt-in. Unauthenticated protocol → residual | test_hardening_round2 |
| 17 | Geo enrichment | **Fixed**: off by default, needs setting **and** `SOC_GEO_ENABLED=1` | static test |
| 18 | CDN scripts, CSP, SRI | **Open/partial**: `tools/vendor_assets.py` + auto-tightened CSP + SRI implemented and unit-tested, but assets **could not be downloaded here**; repo still uses CDN fallback | test_hardening_round2 #5/#6 |
| 19 | Socket.IO auth/revocation | **Implemented, UNVERIFIED** (blocked) | — |
| 20 | Notification dedupe/flood | **Existing** dedupe + hourly cap + bounded retries pass test_notify; **per-recipient/per-channel caps not implemented → open** | test_notify |
| 21 | Gmail OAuth | **Unchanged/unverified**: gmail.send only, PKCE+state present, 0600 env file; tool prints tokens to terminal without `--write`; mocked tests pass | test_notify |
| 22 | Windows installer ACL/token | **Fixed in code** (ACL before SYSTEM task, token via env not argv, ACL failure no longer silent); **not executed on Windows** | static test |
| 23 | Production runtime (gunicorn/systemd/nginx/TLS/WebSocket/firewall) | **Written, NOT run** | deploy/*, docs/DEPLOYMENT.md |
| 24 | Hash-pinned dependency lock | **Open/BLOCKED** (no network; no hashes fabricated) | — |
| 25 | Static analysis / dependency CVE scan / browser tests | **Not executed** | — |

## 3. Changed files (pass 1 + 2)
New: `security/{crypto,totp,mfa,auditchain,agentsig,backup}.py`, `wsgi.py`, `tools/{rotate_secrets,backup,vendor_assets}.py`, `deploy/{soc.service,nginx-exe-soc.conf,env.example}`, `docs/{DEPLOYMENT,MIGRATION-AND-ROTATION,BACKUP-RESTORE,AUDIT-INTEGRITY}.md`, tests `test_{security_remediation,agent_hmac,mfa,data_protection,hardening_round2}.py`.
Modified: `app.py` (sessions, logout, MFA/reauth hooks, purge, audit endpoints, CSP/vendor, proxies, socket auth, startup guards), `db.py` (no default creds, encrypted settings, `audit_add`, new tables, geo default), `engine.py` (ReDoS limits, chained audit, geo gate), `fleet/api.py` + `fleet/schema.py` (signing, scopes, rotation, auth-status), `agent/exe_soc_agent.py` (signing client, ACL warning), `agent/install_windows.ps1`, `syslogrx.py`, `static/app.js` (pill), `templates/base.html`, `.env.example`, `.gitignore`, `tests/test_api_audit.py` (documented exemptions). Removed: `.secret`.
DB migrations (automatic, additive): tables `sessions`, `audit_chain`, `user_mfa`; `agent_credentials` columns `sign_key_enc, scopes, sig_required, last_used, legacy_uses`; `settings.api_key` re-encrypted in place; `settings.audit_key_kid`.

## 4. Residual-risk register (evidence needed to close)
| ID | Risk | Close with |
|---|---|---|
| R-1 | Release-blocking: exposed `SOC_SECRET`/ingest key remain valid until you rotate | Run docs/MIGRATION-AND-ROTATION.md §A; show old values rejected |
| R-2 | Shared ingest key and legacy agent routes enabled by default | Migrate agents; `SOC_AGENT_AUTH=hmac-required`, `SOC_LEGACY_API_KEY=off`; `auth-status` ready=true |
| R-3 | Socket.IO handler untested | Install flask-socketio; test anon/revoked/expired connect, origin rejection |
| R-4 | Production stack never run | Staging run of gunicorn+nginx+TLS; WebSocket + polling fallback; header capture |
| R-5 | CDN scripts without SRI | `python tools/vendor_assets.py` online, review hashes, commit, browser CSP test |
| R-6 | Audit chain defeatable by attacker with DB+key ring | Off-host WORM checkpoints + scheduled verification |
| R-7 | Encryption-key custody/recovery | Offsite key escrow + documented restore drill with keys only from escrow |
| R-8 | MFA throttle/rate limiters are per-process memory; login throttle not account-wide persistent | Persistent limiter or single-worker acceptance |
| R-9 | No hash-pinned lock, no CVE scan | `pip-compile --generate-hashes` online, `pip-audit`, review |
| R-10 | Syslog/UDP unauthenticated | Keep off or private+firewall; or TLS/RELP + mTLS |
| R-11 | Other XSS sinks, per-recipient notification caps, Gmail token handling, other sensitive columns unreviewed | Full JS/template review, tests, field inventory |
| R-12 | Windows agent/installer unexecuted; agent signing on Windows unexercised | Run on a Windows VM |
| R-13 | ReDoS only heuristic w/o `regex` module | Install `regex`; test with catastrophic patterns timing |
| R-14 | Two suites are load-sensitive (log_visibility 3b, linux_agent G4) | Make hash/timing checks robust |
| R-15 | SQLite file/dir permissions & WAL/retention not audited this pass | Staging audit; retention policy decision |
