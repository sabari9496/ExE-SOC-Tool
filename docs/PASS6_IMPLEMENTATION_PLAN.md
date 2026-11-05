# PASS6 implementation plan (living document)

Baseline: `EXE-SOC-pass6-login-fix.zip` (git baseline commit on branch `baseline`; work on `phase1-ingestion-reliability`). Entry point `app.py`; fleet API `fleet/api.py`; agent `agent/exe_soc_agent.py`. Login fix (`_origin_ok`, `tests/test_login_origin.py`) is untouched.

## Phase 0 baseline (verified)
- `compileall` OK; every test file runs (see `docs/TEST_RESULTS.md`). Dependency note: `flask_socketio` is not installed in the review environment (the app falls back to plain Flask), so Socket.IO paths are BLOCKED/NOT RUN.
- Tests that need the dev login (`fleet`, `hardening_misc`, ...) require `SOC_ALLOW_DEFAULT_CREDS=1`; the product itself does not seed default passwords outside that opt-in.
- Pre-existing failure: `log_visibility` 3a (dashboard hint about clock). Fixed in Phase 1 (see below).

## Phase 1: ingestion reliability (DONE, see test results)
Problems (from the audit, confirmed by code): F-01 poison event blocks an agent forever; F-03 HTTP 200 without per-event acks deleted the whole batch; F-04 clock-ahead events dead-lettered with no explanation; F-06 one leased uid returned 409 for the whole batch; in-batch duplicate uids were acknowledged before the first copy succeeded.

Changes:
1. **Server `POST /api/events` (protocol v2, reply has `ack_version: 2`)**: each event gets exactly one outcome: `accepted_uids`, `duplicate_uids`, `rejected_uids` (permanent), `retry_uids` (temporary); `reasons` maps uid to a stable code. Old reply keys and counts are kept.
2. **Validation before processing** (`validate_event`): uid 1-80 chars no control chars; non-empty string message; total event <= 64 KB; timestamp parseable and not > 10 min in the future; ids that would overflow storage; non-finite numbers. Wrongly typed `event_id`/`record_id` are still tolerated (old contract).
3. **Per-event isolation**: the batch is processed together; if it raises, each event is retried alone. A temporary SQLite error (busy/locked) returns 503 and releases claims **without** counting an attempt. Any other exception counts an attempt; after `SOC_INGEST_MAX_ATTEMPTS` (default 5) the event is quarantined.
4. **Quarantine** (`event_quarantine` table, additive): reason, attempts, redacted + size-bounded payload (first 5000 per agent keep payload). Ledger status `dead` makes re-delivery a deterministic `rejected: quarantined`. Admin read endpoints: `GET /api/quarantine`, `GET /api/quarantine/<id>`. Replay UI is Phase 11 (nothing is deleted meanwhile).
5. **Lease conflicts** only delay the affected event (`retry`, reason `lease_conflict`); a lease older than 120 s is reclaimed.
6. **In-batch duplicates** share the first copy's outcome and are never acknowledged early.
7. **Agent**: strict acknowledgement (`_ack_lists`): a reply without all three per-event lists deletes nothing and counts as a failed upload; unknown uids are ignored; `retry_uids` and unaccounted events stay queued with exponential hold (30 s doubling, max 15 min) **and no longer block newer events**; a locally corrupt queue row is dead-lettered instead of crashing the loop; rejected events keep their reason in the local dead-letter table and the dashboard message names the likely clock problem.
8. Delivery remains **at-least-once** with idempotent server processing. Not exactly-once.

Compatibility: agents from this version require a server with protocol v2 (pass6 and later send the per-event lists already). Older agents keep working against the new server.

Risks / not done: concurrency was tested with threads on one process, not multiple gunicorn workers; the 14-day ledger purge (F-05) was revisited in Phase 2 (now 30 days by default, configurable; replay limits documented in docs/DEDUPLICATION_RETENTION.md) and UTC storage (F-08) is still open (Phase 4); dead-letter replay UI is Phase 11; Windows/macOS behaviour untested.

## Phase 1 review (DONE; findings verified in code and by tests, see docs/TEST_RESULTS.md)
- B5 (security, **fixed**): `sanitize()` leaked every nested secret (`{'password': ...}`, `Authorization: Bearer ...`, cookies, PEM keys) into quarantine payloads. Now structural recursive redaction + stronger text scrubbing; payload verified through the API; quarantine endpoints admin-only (analyst/viewer/agent/anonymous refused).
- B5 limits: per-agent and global row caps and a payload cap. At a cap nothing is deleted; the event stays retryable on the agent (`quarantine_full`) and a log line asks the operator to act.
- B2/B3 (**fixed**): retry holds were in memory and `peek()` read `batch + held` rows. Holds are now persisted in the queue row (atomic, restart-safe, capped 15 min, tolerant of garbage/clock jumps); held rows are filtered in SQL so reads stay bounded and cannot starve newer events.
- B4 (**fixed**): the agent parser now requires exactly-once, mutually exclusive outcomes, known uids only, no repeats, supported protocol version; the server returns exactly one outcome per valid uid in the tested cases (anything unclassified becomes retry).
- B7 (**fixed**): a locked database during agent authentication returned HTTP 500; now a retryable 503. `BEGIN IMMEDIATE` has bounded retry/backoff; busy timeout configurable.
- B1 (**verified**, no data-corruption defect found): failures before/after persistence, in detection, in finalization and a real process kill leave no duplicate event or alert and a recoverable ledger (tests). Residual: events/alerts are committed before the ledger, recovery is by idempotent retry, not one atomic transaction.
- B6: documented and made configurable (see PHASE2 plan); operator decision still open.

## Phase 2 database safety (DONE in the isolated copy; not applied to any real database)
Migration framework (`migrations.py`, `migrate.py`; versions 1-3), configurable dedupe retention + bounded purge + opt-in stale-event guard, `dbbackup.py`, docs. Details: docs/PHASE2_DATABASE_PLAN.md, docs/DATABASE_BACKUP_AND_RECOVERY.md.
Not done / open: operator decision on retention window and stale guard; Windows/macOS verification; multi-worker verification beyond 3 processes; replay UI for quarantine (Phase 11); UTC storage (F-08, Phase 4); legacy shared-key path (Phase 3).

## Phase 2 retention review (code fixes and tests DONE; see docs/DEDUPLICATION_RETENTION.md and docs/TEST_RESULTS.md)
Verified and fixed: invalid retention settings did not stop the real application (now validated at import, under gunicorn and `python app.py`); strict integer parsing; cleanup records its real partial result and retries a failed run after about a minute. Default window 30 days (range 7-3650), stale-event rejection off. Verified and documented, **not** fixed (need protocol decisions): the server does not bind the uid to the payload; modified-timestamp replays after the ledger window; replay after both ledger and event row are gone. Cleanup rate on production data, multi-worker behaviour, Windows/macOS: **unverified**. Phase 3 NOT started.

## Stage 2: Monitoring Center (implemented and tested; see docs/MONITORING_CENTER.md)
Tabs Overview/Windows/Linux/Ubuntu/Cloud, os-release based classification (Ubuntu only in the Ubuntu tab), five documented endpoint states with configurable thresholds, migration v4, read APIs with filters, admin-only audited tag/environment editing, honest Cloud NOT CONFIGURED. **Real Windows/Ubuntu hosts and a real browser: UNVERIFIED** (manual plan in the document). Stage 3 (agent security, machine re-enrollment with admin approval, per-source collector status) and Stage 4 (cloud connectors) are NOT started.

## Next (not started)
Phase 2 database/migrations; Phase 3 auth + legacy shared-key path; Phase 4 detection; Phase 5 agents/installers; Phases 6-13 as in the roadmap.
