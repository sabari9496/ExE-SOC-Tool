# Deduplication retention, delayed events and replay

Labels used below: **[CODE]** read in the source; **[TEST]** demonstrated by an automated test (name given); **[ASSUMPTION]** reasoning not proven by a test; **[UNVERIFIED]** not tested here. Nothing in this document is a guarantee beyond what its label says.
All tests use temporary databases and synthetic events; ledger ages are set directly (no sleeps). Evidence of the last run: `docs/test-evidence/summary.md`.

## 1. Event UID: exact behaviour
- **[CODE]** The agent builds the uid in `agent/exe_soc_agent.py: to_event()`:
  `uid = sha256(f"{agent_id}|{channel}|{record_id}|{event_time}|{message[:200]}")[:40]` (hex). Only the **first 200 characters** of the message are hashed. `event_time` is the collector's value; if the collector gave none, the uid is computed with `None` and the wire timestamp is filled in afterwards (so such events, from `bgscan`/`collect`, would get the same uid but a new timestamp if collected again: **[UNVERIFIED]** hypothesis from reading the code, not tested).
- **[CODE][TEST UidProtocol.test_01]** The formula is stable for the same collector event and changes with channel, record id, timestamp, message start and agent id.
- **[CODE][TEST UidProtocol.test_02]** The **server checks only the uid's format** (a string of 1-80 characters, no control characters). It does **not** recompute the uid from the payload, so a uid that does not match its payload is accepted. Invalid uids (empty, 81 characters, control characters, non-strings) are counted as rejected and are never acknowledged by uid and never touch the ledger or the events table.
- Binding the uid to the payload would be a new protocol rule (older agents, tests and other senders use other uids). **Not implemented; future decision.**

## 2. Two different things people call a "timestamp replay"
| Case | What it is | Result |
|---|---|---|
| **A. Normal agent-generated event with a different timestamp** | the collector produces another event time, so `to_event` produces a **different uid** | treated as a **different event**; stored as a new row. It cannot be recognised as a replay. [TEST UidProtocol.test_04, ReplayMatrix.s4] |
| **B. Modified payload that keeps the original uid** | someone (or a bug) changes `event_time` but sends the old uid | **inside the ledger window:** dropped as a duplicate (the ledger keys on the uid). **After the ledger entry is purged:** accepted as a **new event row** (the unique index includes the timestamp). [TEST ReplayMatrix.s5, Lifecycle.test_04] |
| Normal resend of an identical event | same collector event re-sent from the queue | identical wire event, duplicate. [TEST UidProtocol.test_03] |
Timestamp modification is therefore **not always detected**; it is detected only in case B while the ledger entry exists.

## 3. Event lifecycle
1. **[CODE]** Agent queue: local SQLite, bounded by rows (50 000) and size (100 MB), **not by age**; retry holds persisted, at most 15 minutes each.
2. **[CODE]** Server claim: ledger row `agent_event_ids(agent_id, uid)` becomes `processing`.
3. **[CODE]** `engine.process_batch`: event row via `INSERT OR IGNORE` on `ux_ev_rec`, a **partial** unique index on `(host, channel, record_id, ts) WHERE record_id IS NOT NULL` (the server always sets a record id for agent events); detection runs; an alert is linked to its event and an identical alert inside `dedupe_seconds` (120 s) is merged.
4. **[CODE]** Ledger row becomes `processed`; acknowledgement; the agent deletes the event.
5. **[CODE]** Cleanup: the ledger purge removes only `processed` rows older than the window. A separate engine job removes `events` older than the `retention_days` setting (default 90) and resolved alerts. Quarantine rows, incidents and audit records are not touched by the ledger purge.

## 4. The six replay scenarios (default ledger window 30 days)
| # | Scenario | Result | Evidence |
|---|---|---|---|
| 1 | Identical event replayed while its ledger entry exists | duplicate; no new event, no new alert | TEST ReplayMatrix.s1 |
| 2 | Ledger entry purged, event row still present | accepted again, but **no duplicate event row and no duplicate alert** (the unique index and the alert link still apply, even with an old alert) | TEST ReplayMatrix.s2, Lifecycle.test_02 |
| 3 | Ledger entry **and** event row deleted | event re-created; an alerting event raises a **new alert** once the 120 s merge window has passed; a benign one raises none | TEST ReplayMatrix.s3, Lifecycle.test_05 |
| 4 | Timestamp changed, uid regenerated | a different event; not recognised | TEST ReplayMatrix.s4 |
| 5 | Timestamp changed, original uid kept | duplicate inside the window; **new event row** after the ledger entry is purged | TEST ReplayMatrix.s5 |
| 6 | A previously benign event processed again | detection runs once more (no alert link exists for a benign event); no new row, no alert | TEST ReplayMatrix.s6 |
**[ASSUMPTION]** Brute-force style rules count rows in the events table, so scenario 2/6 re-detection does not inflate counts (read from `engine._detect`; the tests assert no new alerts, not every rule).

## 5. Replay-protection horizon: conditional, not a guarantee
For **identical** events (same uid and same timestamp), duplicates are suppressed by: the ledger while its entry exists (`SOC_DEDUP_RETENTION_DAYS`), and after that by the events row and its alert link **while that row exists** (`retention_days`). So the horizon for that one case is roughly the larger of the two settings **[TEST scenarios 1-3]**. It does **not** cover scenarios 4 and 5 after the ledger window, or a replay after both records are gone. No finite window can be proven sufficient: the agent queue has no age limit, so an agent offline longer than any window can still deliver. Request-level replay (signed timestamp + nonce) is separate and is not affected by these settings.

## 6. Configuration
| Setting | Default | Valid | Behaviour |
|---|---|---|---|
| `SOC_DEDUP_RETENTION_DAYS` | 30 | plain ASCII digits, 7-3650, surrounding whitespace ignored; unset or empty = default | anything else is an error (no clamping). `3_0`, `+30`, `-30`, `1e2`, `30.0`, non-ASCII digits, more than 6 digits are refused. [TEST Config.test_01, StartupValidation.test_03] |
| `SOC_REJECT_STALE_EVENTS` | off | `1` on; unset, empty, `0` off | any other value is an error. **Stays off.** [TEST Config.test_02] |
When on, the stale guard refuses events older than (window - 1) days; refused events are kept in quarantine. The timestamp is supplied by the agent, so clock skew (a clock far behind makes good events look stale; one ahead can hide old ones) and a dishonest agent affect it; **it is not a substitute for server-side replay protection**. [TEST Lifecycle.test_06]
**Where validation runs [CODE][TEST StartupValidation.test_01/02]:** when the fleet API is registered, which happens at import of `app.py`, i.e. under `gunicorn wsgi:app` and under `python app.py`, before any request is served. An invalid value exits with `ERROR: ...` naming the variable. A previous version of this document claimed startup validation that did not work: `db.init_db()` wraps `fleet.init()` in a try/except that only prints, so the server kept running. This was fixed by validating in `fleet.api.register`. Side effect: `python app.py --set-login` also imports the app and is blocked until the variable is corrected. At runtime an invalid value makes the cleanup log an error and record it in `last_purge`.

## 7. Cleanup behaviour
- **[CODE]** `purge_dedup`: up to `max_batches` batches of `limit` rows (scheduled run: 20 x 5 000), each batch its own short transaction (`DELETE ... WHERE (agent_id,uid) IN (SELECT ... status='processed' AND ts<cutoff LIMIT n)`), stopping early when a batch is not full or the 2 s budget (checked **between** batches; a batch is never interrupted) is used.
- **[CODE]** `maybe_purge`: at most once per 10 minutes **per process** (60 s after a failed run), non-blocking lock so two runs never overlap, a daemon thread so the request is not delayed. Several workers each schedule their own run; SQLite serialises the deletes **[UNVERIFIED]** beyond the thread and killed-process tests).
- **[TEST CleanupFailureAndScheduling]** an exception on batch 2 keeps batch 1 committed, records `deleted=10` and the error in `fleet.api.last_purge`, deletes no unprocessed row, and a later run finishes; a failing commit rolls the batch back; 40 rapid scheduling attempts start one run and never two at once; no thread is left behind; a failed run is retried after about a minute; a 1.5 s cleanup does not delay an ingest request beyond 1 s.
- **[TEST CleanupSafety]** busy database: logged, nothing deleted, error recorded then cleared by the next success; cleanup concurrent with ingestion stored 200 of 200 events once; a process killed at COMMIT rolled back and ingestion worked afterwards; quarantine, alerts, incidents, audit, cases, events and users were byte-identical before and after a purge with a far-future clock; only `processed` rows are ever deleted.
- **Rate: [UNVERIFIED] on production-like data.** Arithmetic only: one run can delete at most 20 x 5 000 = 100 000 rows; the earlier design (one batch per run) was 5 000 per 10 minutes. Test-specific evidence: one run cleared 30 000 synthetic expired rows; a 5 000-row batch took about 22 ms on 200 000 synthetic rows in this container. These are not a guaranteed production rate.
- Ledger timestamps are server **local** time (naive), not UTC (known item F-08); a large clock jump forward can make rows look expired early, one backward keeps them longer. [ASSUMPTION]

## 8. Storage (measured here, synthetic rows)
Ledger about 219 bytes per event including indexes; events table about 435 bytes per event (short messages). At 1 event/s a 30-day ledger is roughly 0.57 GB; at 10 events/s about 5.7 GB (arithmetic from the measured size). Real sizes depend on message length and id lengths. [UNVERIFIED on production data]

## 9. Backup and restore implications
- **[TEST CleanupSafety.test_06]** A backup taken after these changes restores cleanly: row counts of the ledger, quarantine, alerts and events match, migrations report nothing pending, and the purge runs on the restored copy. No schema change was made in this review.
- **Restoring an OLDER database [ASSUMPTION, reasoning from the code]:** the server returns to the state at backup time. Events accepted after that moment are gone from the server, and because agents delete an event once acknowledged they will **not** be resent, so that data is lost up to the age of the backup. Events the server processed but whose acknowledgement was lost are still on the agent and will be re-sent and processed as new (their ledger and event rows are gone too). Quarantine rows created after the backup are lost; the agent keeps its own dead-letter copy (up to 5 000). Ledger rows older than the window are removed by the first purge after the restore. A restored database does not "remember" events newer than the backup, so replay protection for that period is rebuilt from scratch.
- Stop the application before replacing a live database; see `DATABASE_BACKUP_AND_RECOVERY.md`.

## 10. Residual risks and recommended future work
1. Server does not bind the uid to the payload; first 200 characters only are hashed (events identical up to character 200 in every other field share a uid). Future: verify the uid server-side (needs a protocol/compatibility plan).
2. Scenarios 3, 4 and 5 can create duplicate events, and 3 a duplicate alert. Future: an agent-side event TTL so the maximum offline period is defined, and/or a compact permanent ledger (size not measured).
3. Replay identity independent of the timestamp (for example host + channel + record id) was rejected for now because record ids can restart after a log is cleared on some platforms (**[UNVERIFIED]** platform behaviour), which could refuse legitimate events.
4. Cleanup rate on production data and behaviour with several gunicorn workers: not measured.
5. Ledger time is local, not UTC.
6. Windows, macOS, Socket.IO, multi-worker and load runs were not executed.
