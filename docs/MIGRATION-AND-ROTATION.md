# Migration and secret rotation
## A. Exposed secrets (the zip contained `.secret` and the DB ingest key) — do all, in order
1. Take a verified backup: `python tools/backup.py create`.
2. **Session/cookie secret**: `python tools/rotate_secrets.py session-secret --out /root/new-secret.env`, put `SOC_SECRET=` in `/etc/exe-soc/env`, restart. All users are logged out (intended). Delete the old `.secret` file everywhere it was copied; shred the file with the new value after use.
3. **Shared ingest key**: `python tools/rotate_secrets.py ingest-key --out /root/new-ingest.env` (or admin UI + reauth). The old key is dead immediately → legacy agents using `/api/agent/*` and `/api/ingest` stop until updated. Do step B first for those hosts.
4. **Encryption key**: `rotate_secrets.py enc-key --out ring.env` → set `SOC_ENC_KEYS` (new first, old kept) → restart → `rotate_secrets.py reencrypt`. Keep old keys: they decrypt old backups and anchor the audit chain.
5. Anything that was ever in a repo/zip (SMTP password, Gmail client secret/refresh token) must be rotated **at the provider**; deleting from source does not revoke it.
## B. Staged legacy → per-agent migration
1. Stage 0 (default): `SOC_AGENT_AUTH=permissive`, `SOC_LEGACY_API_KEY=on`. Old agents keep working.
2. Enroll each endpoint (admin → enrollment token → `exe_soc_agent.py enroll`): the new agent gets a bearer credential **and a signing key** and signs every request (HMAC-SHA256 over method, path+query, timestamp, nonce, body hash).
   Existing fleet-enrolled agents without a signing key: `POST /api/agents/<id>/rotate-credential` (admin) → copy `credential`+`signing_key` into the agent config (`agent.json`) → restart agent.
3. Watch `GET /api/agents/auth-status` (`legacy_uses`, `sig_required`). Once every active agent has `sig_required=1`: set `SOC_AGENT_AUTH=hmac-required`.
4. When no host uses `/api/agent/*` or `/api/ingest` with the shared key: `SOC_LEGACY_API_KEY=off`.
5. Rollback: set the variables back to `permissive` / `on`.
## C. Users
Existing installs still containing Admin@123/Analyst@123/Viewer@123 are flagged by `/api/me/notice`: change them. Admins and analysts are forced to enroll TOTP when `SOC_MFA_REQUIRED` (default in production). Lost authenticator: another admin (recently re-authenticated) uses `POST /api/users/<id>/mfa/reset` — audited, user's sessions end.
