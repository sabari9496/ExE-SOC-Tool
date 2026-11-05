# Phase 2 plan: database and migration safety

Status: plan written BEFORE Phase 2 code. Facts below were checked against the code (`db.py`, `fleet/schema.py`, `fleet/__init__.py`, `engine.py`, `security/backup.py`) and a freshly initialised temp database. Nothing here was run against a real `soc.db`.

## 1. Tables (44 after `db.init_db()` on an empty database)
Core (`db.py` SCHEMA): users, sessions, settings, audit, audit_chain, endpoints, events, alerts, alert_meta, alert_activity, commands, blocklist, whitelist, whitelist_audit, iocs, mitre_map, assets, cases, case_alerts, case_notes, incidents, incident_alerts, incident_notes, custom_rules, playbooks, geo_cache, packages, vulns, vuln_cache, vuln_scan, sx_state.
Fleet (`fleet/schema.py`, applied by `fleet/__init__.py`): agents, agent_credentials, enrollment_tokens, agent_heartbeats, agent_health, agent_nonces, **agent_event_ids** (dedupe/lease ledger), **event_quarantine** (Phase 1).
Notifications (`notify/schema.py`): notification_settings, notification_recipients, notification_history, notification_dedupe, notification_escalation.
Created lazily on first use (not in the 44): `unified/store.py` (normalised events, allow-list), `security/throttle.py`, `security/mfa.py`. Their names were not inventoried exhaustively; the migration framework only touches tables it names.

## 2-3. Versioning, path, startup
No schema version existed (`PRAGMA user_version` = 0, no migrations table). The path is `SOC_DB` (default `<project>/soc.db`), read once in `db.py`; CLI (`--set-login`) and workers import the same module, so they use the same file. Startup (`init_db`) runs `CREATE TABLE IF NOT EXISTS` + idempotent `ALTER TABLE ADD COLUMN` + `CREATE INDEX IF NOT EXISTS` on every start, i.e. the schema already self-upgrades additively without any record of it.

## 4. Write and delete paths that matter
Ingest: `fleet/api.py` claim (BEGIN IMMEDIATE) -> `engine.process_batch` (events committed, then detection/alerts, each its own commit) -> `_finalize` (ledger -> processed). Deletes: engine retention loop (events older than `retention_days`=90, resolved alerts, commands>7d); `unified.store.purge`; sessions; throttle; nonces (2x skew); heartbeats (keep 2880/agent); **agent_event_ids processed rows (dedupe retention)**; admin deletes of alerts/cases/users/endpoints; admin "reset data" (`app.py` ~905, pre-existing, not changed). Quarantine rows are never deleted by any job.

## 5-6. Transactions, connection settings
`db.conn()` = one connection per call, **WAL on every connect**, `foreign_keys=ON`, busy timeout 15 s. Phase 2 makes the timeout configurable (`SOC_DB_TIMEOUT`, default 15, range 0.1-120) and leaves WAL/synchronous unchanged. Ingest is deliberately NOT one transaction: events/alerts are committed by the engine before the ledger is finalised. Recovery strategy (tested in Phase 1 review): ledger stays `processing` then `pending`; a retry re-runs idempotently thanks to the unique event index `ux_ev_rec` and the alert link; a stale lease (120 s) is reclaimed.

## 7. Startup-time schema change policy (Phase 2 decision)
- New/empty database: all migrations applied automatically.
- Existing database: **not migrated automatically**. Startup records nothing, prints a clear notice if migrations are pending, and keeps working (Phase 2 migrations are additive indexes/metadata only). Operator runs `python migrate.py plan` (read-only) then `python migrate.py apply --yes` (takes and verifies a backup first). `SOC_AUTO_MIGRATE=1` opts in to automatic apply.
- A database whose recorded version is newer than the code, or whose applied migration checksum differs, is **refused** with an actionable error.

## 8-9. Phase 1 storage and deduplication retention (FINAL; evidence and labels in docs/DEDUPLICATION_RETENTION.md)
`agent_event_ids` keeps one row per event uid: `processed` (purged after the window), `processing`/`pending`/`dead` (never purged). `event_quarantine` is independent and never purged by the ledger cleanup.
**Decision:** default window **30 days** (was 14), valid 7-3650, strict validation (an invalid value stops the application at import time, under gunicorn and `python app.py`), stale-event rejection stays **off**. Reasoning: a longer window only keeps ledger rows longer (no event loss), needs no wire/API or schema change or new migration, and costs about 219 bytes/event (measured on synthetic rows). It is **not** a replay guarantee: the replay horizon is conditional and scenarios 3-5 in the retention document can still create duplicate events (and, for scenario 3, a duplicate alert). The server checks only the format of the uid, not its binding to the payload.
Cleanup: scheduled runs do up to 20 batches of 5 000 rows within a 2 s budget (checked between batches), per process at most every 10 minutes (60 s after a failure), one at a time, on a background thread; failures are logged and kept in `fleet.api.last_purge` with the real partial count. The achievable rate on production data is **unverified**.
Open operator decisions: whether to enable `SOC_REJECT_STALE_EVENTS=1` (client timestamps, clock skew); the events `retention_days`; whether to fund the future items listed in the retention document (server-side uid binding, agent-side event TTL, compact permanent ledger).

## 10. Migrations
1 `baseline_pass6`: validates required core tables exist; no change. 2 `phase1_ingest_quarantine`: `event_quarantine` (+indexes) and `agent_event_ids.attempts/last_error` if missing. 3 `phase2_ledger_indexes`: `ix_aev_status_ts`, `ix_quar_created`. All idempotent, each in its own transaction, recorded in `schema_migrations(version, name, checksum, applied_at)`. Concurrency: `BEGIN IMMEDIATE` (single SQLite writer) + re-check inside the lock.

Migration 4 `stage2_endpoint_metadata` (Stage 2, additive): nullable `agents.os_family/distro_id/distro_version/environment/tags/first_heartbeat_at`, back-fill of `first_heartbeat_at` only for agents that clearly reported, indexes `ix_agents_family`, `ix_agents_env`, `ix_agents_hb`, `ix_alert_agent_ts`. See docs/MONITORING_CENTER.md section 4.

## 11. Backup / restore
`dbbackup.py`: SQLite online-backup API (consistent under WAL), mode 0600 file, `PRAGMA integrity_check` + table-presence check on the copy, sidecar metadata JSON (no row contents), SHA-256. Restore goes to a NEW destination; overwriting needs `--overwrite` AND a verified backup of the destination; never touches the live path implicitly. `.secret` is never read or copied (agent signing keys inside the DB stay encrypted by it, so protect that file separately). Existing `security/backup.py` (encrypted backups) is untouched.

## 12. Risks and rollback
Rollback = restore the pre-migration backup (verified) into a new file, point `SOC_DB` at it. Migrations are additive, so older code still runs on a migrated DB (extra indexes/tables are ignored), but recorded versions make newer-than-code detection possible.
Risks: SQLite single-writer limit (multi-process tested with 3 processes only); Windows file-locking behaviour of backup/restore untested; WAL sidecar files must not be copied by hand.

## 13. Required before real deployment
Run `migrate.py plan` on a COPY of the real database; verify backup restores; run the full suite; operator approval for `apply`.
