# EXE-SOC Pass 6 — Ingestion Recovery Patch

Date: 2026-10-22
Scope: Phase 1 only (agent event ingestion recovery). This is a development artifact, not a production-readiness certification.

## Changes

- Added `status` and `claimed_at` fields to `agent_event_ids`. Existing ledger rows migrate as `processed`; new IDs are claimed as `processing`, and recoverable failures return them to `pending`.
- The fleet ingestion endpoint claims IDs as `processing`, returns ordinary failures to `pending`, and finalizes successful events as `processed`. Ledger finalization, endpoint event attribution, and fleet counters are committed together in one transaction.
- Failed processing no longer deletes the deduplication ledger entries. A retry of the same UID can resume processing using the agent's still-queued payload. SQLite `BEGIN IMMEDIATE` serializes claims, and a stale processing lease can be reclaimed after 120 seconds following a hard process stop.
- The engine gained an opt-in `reprocess_duplicates=True` path used only by fleet recovery. It can resume detection for a matching persisted event when that event has not yet been linked to an alert. The default duplicate behavior for other callers is unchanged.
- Added an integration-test scenario to `tests/test_fleet.py` that marks one ingested UID pending and verifies a retry finalizes it.
- Existing project files and the original uploaded ZIP were left unchanged; changes are in a separate working copy.

## Security and reliability notes

- The design retains at-least-once delivery semantics. Detection retries can revisit a persisted event when its alert link is absent; alert correlation reduces duplicate alert creation, but an interruption in the narrow interval between alert creation and event-to-alert linking can still cause duplicate alert-count increments. This is not exactly-once processing.
- The event-ID ledger does not store event payloads. Recovery relies on the agent retaining and resending unacknowledged payloads, consistent with the current agent acknowledgement protocol.
- SQLite concurrency across multiple application worker processes was not runtime-tested. Before multi-worker production use, test concurrent retries and consider a durable transactional inbox/outbox architecture.
- The patch does not add cloud connectors, macOS collection, or address unrelated audit findings.

## Validation performed

- `py_compile` passed for `fleet/api.py`, `fleet/schema.py`, `engine.py`, and the edited fleet test.
- Full application integration test `tests/test_fleet.py` could not run because the environment lacks Flask (`ModuleNotFoundError: No module named 'flask'`). No dependencies were installed.
- The application was not deployed, no live services were changed, and no production database was accessed.

## Next required verification

Run `python tests/test_fleet.py` in the project's supported virtual environment with its reviewed dependencies installed. Then add failure-injection coverage for crashes after event persistence, during detection, and before status finalization; validate the migration against a copy of a real pre-migration database; and test concurrent requests.
