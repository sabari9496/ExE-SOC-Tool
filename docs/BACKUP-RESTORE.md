# Backups, restore, drills
- `python tools/backup.py create` → `<SOC_BACKUP_DIR>/soc-<UTC>-<pid>.db.enc` (AES-256-GCM, mode 0600, `.sha256` manifest, SQLite online-backup snapshot). The encryption key is **not** in the backup: store `SOC_ENC_KEYS` separately and off-host.
- `verify FILE` decrypts into a scratch dir, runs `PRAGMA integrity_check`. `rotate --keep 14` keeps newest 14 and refuses to delete anything if no backup verifies.
- **Restore**: stop service → `python tools/backup.py restore FILE --to /var/lib/exe-soc/soc.restored.db` (refuses to overwrite) → move into place, `chown exesoc`, `chmod 600` → start → `GET /api/audit/verify`.
- **Drill**: `python tools/backup.py drill` (creates, restores into a temp dir, counts users/alerts/events/audit, deletes). Schedule weekly (systemd timer/cron as `exesoc`).
- Purge (`/api/admin/purge`) and `python app.py --reset` create **and verify** a backup first and abort without deleting if that fails. Purge additionally needs: typed confirmation, reauthentication ≤2 min (password + TOTP if enrolled), MFA enrolled in production.
- Residual: backups are only as private as the key custody; no off-host copy is automated (copy `.enc` files with your own tooling).
