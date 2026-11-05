# Database backup, restore and recovery

Tools: `dbbackup.py` (backup/verify/restore) and `migrate.py` (status/plan/apply). Both use only the Python standard library. Replace `python` with `python3` on Linux/macOS. Commands marked READ-ONLY never change a database.

## Backup (online, safe while the app runs, WAL aware)
```
python dbbackup.py backup --db soc.db --dest backups          # writes backups/exesoc-<UTC>.db + .json (mode 0600). Source opened READ-ONLY
python dbbackup.py verify backups\exesoc-<UTC>.db             # READ-ONLY: SHA-256 vs metadata, PRAGMA integrity_check, core tables present
```
The backup uses SQLite's online-backup API, so a consistent snapshot is taken even while the application writes (tested with a concurrent writer). Do NOT copy `soc.db` by hand while the app runs: the `-wal`/`-shm` files hold committed data. Metadata contains only checksum, size, table count, schema version, UTC time, file name (no paths, no row contents).

## What a backup does and does not contain
Contains the whole database: users and password hashes, sessions, audit, agent credentials (agent signing keys are stored ENCRYPTED with the key derived from `SOC_SECRET`/`.secret`), events, alerts, incidents, quarantine. Does **not** contain `.secret`, TLS keys or any file outside the database; the tool never reads them. Consequences: keep the backup as protected as the database (it holds password hashes); without the matching `.secret` the restored agent keys cannot be decrypted, so back up `.secret` separately and more strictly (never in the same place). The file is created 0600 on Linux/macOS; on Windows only the read-only flag is honoured, so store backups in a folder whose ACL allows only the service account and administrators.

## Restore (always to a new file by default)
```
python dbbackup.py restore backups\exesoc-<UTC>.db --to restored.db       # refuses if restored.db exists
```
Verify first, then restore into a temporary file, verify again, then move into place. Any error leaves the destination exactly as it was; nothing is restored automatically after an error. To make a restored copy live: stop the application, then point `SOC_DB` at `restored.db` (preferred), or replace the live file deliberately:
```
python dbbackup.py restore backups\exesoc-<UTC>.db --to soc.db --overwrite --backup-existing-to safety   # STOP THE APP FIRST
```
`--overwrite` is refused unless `--backup-existing-to` is given; the current database is backed up AND verified before anything is replaced; old `-wal`/`-shm` files are renamed to `*.replaced-<UTC>` (never reused, never deleted).

## Migrations
```
python migrate.py status --db soc.db                      # READ-ONLY
python migrate.py plan   --db soc.db                      # READ-ONLY, lists what apply would do
python migrate.py apply  --db soc.db --yes --backup-dir backups-premigrate   # LIVE: backs up + verifies first; aborts if the backup fails
```
Always try `plan`/`apply` on a COPY first. New databases are migrated automatically at first start; existing ones only print a notice (or use `SOC_AUTO_MIGRATE=1`). A database newer than the code, or with a tampered migration record, is refused (exit code 2). A failed migration rolls back that step only and is safe to re-run; `apply` also repairs a missing index/table of an already-recorded migration.

## Rollback
Migrations 1-4 only add tables, columns and indexes, so older code keeps working on a migrated database. To roll back fully: stop the app, restore the `backups-premigrate` backup taken by `apply` into a new file, set `SOC_DB` to it, start the app (it will report the migrations as pending again).

## Recovery checklist after a crash
1. Stop the app. 2. `python dbbackup.py backup --db soc.db --dest rescue` (works on a WAL database that was not shut down cleanly). 3. `python dbbackup.py verify` the result. 4. If integrity fails, restore the latest good backup to a new file. 5. Quarantined and `pending` events are retried automatically by agents; nothing in the ledger needs manual repair (stale `processing` rows are reclaimed after 120 s).

## Limitations (not verified here)
Windows file locking during backup/restore, network drives, and backups of databases over a few GB (online backup holds a read transaction; run during quiet periods). No built-in encryption of backups here (the older `security/backup.py` produces encrypted backups; it is unchanged).

## Compatibility with the retention behaviour, and restoring an older database
- **Verified (test CleanupSafety.test_06):** a backup taken with this version restores into a new file; row counts of `agent_event_ids`, `event_quarantine`, `alerts` and `events` match; `migrate.py status` on the restored file reports nothing pending; the ledger purge runs on it. No schema change or migration was added in the retention review (versions 1-3 at that time; migration 4 was added in Stage 2, see MONITORING_CENTER.md).
- **Configuration:** the retention settings are read from the environment, not stored in the database. A restored database starts under whatever `SOC_DEDUP_RETENTION_DAYS` is set; an invalid value stops the application at start regardless of the database.
- **Restoring an older backup (reasoning from the code, not a measured drill):** the server goes back to the backup moment. Events accepted after it are gone from the server and, because agents delete an event once it is acknowledged, they are not re-sent: that data is lost up to the age of the backup. Events whose acknowledgement was lost are still on the agent and will be processed again as new events. Quarantine rows created after the backup are lost (the agent keeps its own dead-letter copy, up to 5 000). Ledger rows older than the window are removed by the first purge. Duplicate protection for the period after the backup is rebuilt from scratch. See `DEDUPLICATION_RETENTION.md` section 9.
- Take the backup before upgrading and keep it until the new version has run through at least one full ledger window if you may need to roll back; stop the application before replacing a live database.
