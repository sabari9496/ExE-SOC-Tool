# EXE-SOC deployment (Linux staging/production) — NOT yet exercised in staging
Status: files are written and unit-tested only where noted in REMEDIATION-REPORT.md. **Gunicorn, systemd, nginx, TLS and WebSocket behaviour have not been run by the author** (no network/root in the build sandbox). Treat this as a checklist to execute and record evidence for in staging.

1. **Account**: `useradd --system --home /opt/exe-soc --shell /usr/sbin/nologin exesoc`; `install -d -o exesoc -g exesoc -m 0700 /var/lib/exe-soc /var/backups/exe-soc`; code root-owned, read-only to `exesoc`.
2. **Install**: `python3 -m venv /opt/exe-soc/.venv && /opt/exe-soc/.venv/bin/pip install -r requirements.txt gunicorn` (use the hash-pinned lock once generated — see Residual Risks R-9).
3. **Config**: `install -m 0600 -o root -g exesoc deploy/env.example /etc/exe-soc/env`, fill values (see `.env.example`). `SOC_DB=/var/lib/exe-soc/soc.db`. Generate `SOC_ENC_KEYS` and store a copy off-host (losing it = TOTP secrets, agent signing keys, backups unrecoverable).
4. **Service**: `cp deploy/soc.service /etc/systemd/system/`, `systemctl daemon-reload && systemctl enable --now soc`. Single gunicorn worker (in-process state/background threads), `gthread`. Socket.IO runs in threading mode: WebSocket upgrade needs `simple-websocket`; if absent the client falls back to long-polling (verify in staging).
5. **TLS / proxy**: `deploy/nginx-exe-soc.conf` (TLS 1.2+, WebSocket upgrade headers). App listens on 127.0.0.1 only; `SOC_TRUSTED_PROXIES=127.0.0.1` so `X-Forwarded-*` is honoured only from nginx. Add HSTS at nginx once HTTPS is confirmed.
6. **Firewall** (example, ufw): `ufw default deny incoming; ufw allow 22/tcp; ufw allow 443/tcp`. Do NOT expose 5000 or syslog (514/5514). Syslog stays off; if needed bind to a private address and allow only the sender subnet.
7. **First login**: read `/var/lib/exe-soc/initial_admin_credentials.txt`, log in, change password, **enroll MFA** (`/mfa-setup`), delete the file.
8. **Verify** (record outputs): `curl -I https://soc…/login` (headers, Secure cookie); WebSocket connects only when logged in; `python tests/test_security_remediation.py` etc. on a staging copy; `python tools/backup.py drill`; `GET /api/audit/verify`.
9. **Logs/rotation**: journald handles service logs; set `SystemMaxUse` and logrotate for nginx.
10. **Windows server deployment**: not supported/tested for the server; use Linux. Windows is supported for the **agent** (installer sets ACLs on `%ProgramFiles%\EXE-SOC-Agent`, token passed via environment, SYSTEM task) — **not executed here**.

## Rollback
Stop service → restore previous code tree → restore DB from `tools/backup.py restore FILE --to NEW.db` (service stopped, then move into place, owner exesoc 0600) → start. The new `sessions`, `audit_chain`, `user_mfa` tables and `agent_credentials` columns are additive and ignored by old code; old code cannot read `enc1:` values (api_key would be unusable) — **restore the matching DB backup when rolling back code**.
