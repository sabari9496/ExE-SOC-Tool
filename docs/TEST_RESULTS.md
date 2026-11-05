# Test results (Stage 2: Monitoring Center)

Environment: Python 3.12.3, isolated Linux container, temporary databases/directories, synthetic data. Machine-readable evidence: `docs/test-evidence/summary.json` and `summary.md`.
Method: `python tests/run_all.py run ... --out DIR` then `summarize` (each suite in its own process; counts parsed from the suites' own output; suites and individual tests counted separately). Run in four bounded batches because one call is limited to about 300 s.

## Baseline before Stage 2 (uploaded project, same runner)
25 suites, **586 individual tests**: 586 passed, 0 failed, 0 skipped, no timeouts.

## After Stage 2
**26 suites** (PASS 26, FAIL 0, TIMEOUT 0, unparsed 0); **617 individual tests**: 617 passed, 0 failed, 0 skipped.
**Difference to the baseline (+1 suite, +31 tests):** the new suite `test_monitoring_center` (31 tests). No existing suite changed its test count.
Existing-test edits: `tests/test_phase2_database.py`, 8 lines, only the expected migration version lists (`[1,2,3]` -> `[1,2,3,4]`, `[3]` -> `[3,4]`, row count 3 -> 4) because migration v4 now exists; no assertion weakened or removed.
| Suite | Status | Tests | Passed | Failed | Skipped | Seconds |
|---|---|---|---|---|---|---|
| test_agent_hmac | PASS | 15 | 15 | 0 | 0 | 9.1 |
| test_api_audit | PASS | 29 | 29 | 0 | 0 | 230.2 |
| test_data_protection | PASS | 18 | 18 | 0 | 0 | 19.0 |
| test_dev_certs | PASS | 1 | 1 | 0 | 0 | 1.2 |
| test_fleet | PASS | 24 | 24 | 0 | 0 | 13.0 |
| test_hardening_misc | PASS | 19 | 19 | 0 | 0 | 13.5 |
| test_hardening_round2 | PASS | 6 | 6 | 0 | 0 | 3.3 |
| test_ingest_reliability | PASS | 16 | 16 | 0 | 0 | 15.9 |
| test_installer_umask | PASS | 1 | 1 | 0 | 0 | 0.4 |
| test_linux_agent | PASS | 64 | 64 | 0 | 0 | 155.8 |
| test_log_visibility | PASS | 12 | 12 | 0 | 0 | 24.0 |
| test_login_origin | PASS | 10 | 10 | 0 | 0 | 10.8 |
| test_mfa | PASS | 14 | 14 | 0 | 0 | 26.2 |
| test_monitoring_center | PASS | 31 | 31 | 0 | 0 | 19.8 |
| test_notify | PASS | 59 | 59 | 0 | 0 | 90.7 |
| test_ops_drills | PASS | 4 | 4 | 0 | 0 | 26.7 |
| test_pass3_security | PASS | 31 | 31 | 0 | 0 | 40.7 |
| test_pass4_security | PASS | 14 | 14 | 0 | 0 | 36.8 |
| test_pass5_security | PASS | 6 | 6 | 0 | 0 | 0.4 |
| test_phase1_review | PASS | 26 | 26 | 0 | 0 | 19.0 |
| test_phase2_database | PASS | 19 | 19 | 0 | 0 | 11.9 |
| test_retention_review | PASS | 35 | 35 | 0 | 0 | 32.8 |
| test_security_remediation | PASS | 10 | 10 | 0 | 0 | 25.7 |
| test_static_security | PASS | 7 | 7 | 0 | 0 | 6.5 |
| test_unified | PASS | 144 | 144 | 0 | 0 | 39.1 |
| test_windows_installer | PASS | 2 | 2 | 0 | 0 | 1.1 |

## New suite: what it covers (31 tests)
OS classification matrix incl. Ubuntu/Mint/Debian/unknown/legacy and injection-style values; agent os-release parsing and fallbacks (fixtures); state boundaries with an injected clock (online/degraded/offline at the exact limits, never_connected variants, revoked precedence, degraded reasons, configurable thresholds, invalid thresholds stop startup, the old `agent_status` unchanged); migration v4 on a fresh database, on a copy of a v3 database (data identical, back-fill rule), failed and killed migration, repair, unmigrated-database behaviour (409 hints, agents unaffected); API authorization (anonymous, viewer, analyst, admin, agent credential, CSRF header), classification and states through the API, overview equals the data, empty database shows zeros and Cloud NOT_CONFIGURED, all filters and their combination, pagination and sorting, 20 invalid/injection inputs rejected, detail view without credential fields, metadata edit validation and audit, registration/heartbeat metadata handling and old-agent compatibility, truncation reporting, page/nav/asset checks.
Mutation checks (control deliberately broken, the matching test had to fail; files restored): Mint treated as Ubuntu; online boundary off by one; never_connected rule removed; viewer allowed to edit; unmigrated guard removed; environment validation removed; heartbeat overwriting stored OS data; v4 back-fill touching never-connected agents: each failed the expected test.

## Not executed (not claimed)
Real Windows and Ubuntu hosts (UNVERIFIED; manual plan in `docs/MONITORING_CENTER.md` section 8); a real browser (only JavaScript syntax with `node --check`, served assets and static checks); Socket.IO paths (`flask_socketio` not installed); multi-worker deployment; load/performance of the new filters; any cloud provider. Skipped tests: none reported.
