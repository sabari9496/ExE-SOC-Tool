# Pass 3 changes (verification round) - read before upgrading

## Behaviour changes (breaking for some deployments)
| Change | Who is affected | What to do |
|---|---|---|
| `SOC_ENV=production` (also the default under `wsgi.py`) now defaults to `SOC_AGENT_AUTH=hmac-required` and `SOC_LEGACY_API_KEY=off`. Unknown values fail closed to the strict setting. | Production installs that still have unsigned/legacy agents | **Before upgrading**, set `SOC_AGENT_AUTH=permissive` and/or `SOC_LEGACY_API_KEY=on` explicitly, finish the migration (docs/MIGRATION-AND-ROTATION.md), then remove the overrides. `GET /api/agents/auth-status` shows readiness and when the shared key was last used. |
| Production requires `SOC_SECRET` (>= 32 chars, not trivially repetitive) and never creates `.secret`. | Anyone relying on the file fallback in production | Generate with `tools/rotate_secrets.py session-secret --out FILE`. |
| Production: session cookie is `Secure` + `__Host-soc`; `SOC_MIN_PASSWORD` cannot go below 12; DB directory must not be writable by others. | All production installs | Serve over HTTPS; `chmod 700` the DB directory. |
| `/login/mfa` needs the session-bound CSRF token; cross-origin POSTs to `/login`, `/login/mfa`, `/mfa-setup` are refused. | Custom scripts posting to those forms | Use the form (GET first, send its `csrf` field) from the same origin. |
| Login, MFA and re-authentication limits are now persistent in SQLite (account-wide + per-IP), not process memory. | Operators | Table `throttle` is created automatically. A shared database is needed if you ever run more than one host. |
| `rotate-credential` (agents) requires recent re-authentication (`POST /api/me/reauth`). | Automation that rotates agent credentials | Re-authenticate first. |
| Socket.IO pushes carry only alert id/severity/title (<= 80 chars); no IPs, messages or raw data. Live sockets are dropped when a session is revoked/expired or the account is disabled. | Custom dashboards | Fetch details via the REST API. |
| `tools/gmail_auth.py` refuses to print the refresh token unless `--print-secrets` is given. | Operators | Use `--write` (0600 file). |
| `user creation` enforces `SOC_MIN_PASSWORD` (was a fixed 8). | Admins creating users | - |

## New settings
`SOC_AGENT_AUTH`, `SOC_LEGACY_API_KEY` (production defaults above), `max_per_recipient_hour` (notification setting, default 30), `SOC_ALLOWED_ORIGINS` (Socket.IO; unset = library default same-origin).

## New endpoints
`GET /healthz` (unauthenticated, returns only `{"status":"ok"}`).

## Limits that remain (see the final report)
Socket.IO runtime behaviour, gunicorn/nginx/systemd, Windows installer execution, dependency vulnerability scan and hash-locked requirements could not be verified in the offline test environment.
