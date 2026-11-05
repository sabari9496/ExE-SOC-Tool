# EXE-SOC email notification guide

Email is an extra, independent notification channel. If email fails, detection, alerts, incidents and the dashboard keep working.

## 1. Architecture

```
Events -> Detection -> SOCX correlation -> Alert -> Incident -> Risk score -> Severity
                                                       |
                                          notify.on_alert()   (puts a tiny job in memory, returns at once)
                                                       v
                         Email worker thread:  policy (severity, type, rate limit, dedupe) -> render -> outbox table
                                                       v
                                          SMTP (STARTTLS / SSL)  -> analyst inbox
                         failures -> RETRYING with delays -> FAILED   (all logged, never blocking detection)
```

* Code: package `notify/` (config, policy, render, smtpx, api) plus 4 small hooks (`socx/__init__.py`, `db.py`, `app.py`, `base.html`).
* Tables (new only): `notification_settings`, `notification_recipients`, `notification_history` (also the retry outbox), `notification_dedupe`, `notification_escalation`.
* One email per **incident**, not per event: 500 failed logins = one incident = one email, with `Occurrences: 500`.
* Whitelisted (false-positive) alerts never send email. The incident status system is the existing SOCX one (nothing new).

> **Easiest way:** copy `.env.example` to `.env` in the EXE-SOC folder, fill in the SMTP values (including `SMTP_PASSWORD`) and start the server. `.env` is loaded automatically at startup; real environment variables still win. `.env` is git-ignored.

## Gmail API (alternative to SMTP)

Sends through Google's HTTPS API with OAuth2 instead of SMTP: no app password and no outbound SMTP port. Queueing, retry/backoff, rate limits, escalation, history and the dashboard are identical; only the delivery step differs.

**One-time Google setup**
1. Google Cloud console: create a project and enable the **Gmail API**.
2. OAuth consent screen: add the sending Gmail address as a **Test user**. In Testing mode the refresh token expires after 7 days, so publish the app (or use a Workspace-internal app) for permanent use.
3. Credentials: create an OAuth client of type **Desktop app** and download its JSON.
4. On the server run `python tools/gmail_auth.py --credentials client_secret_xxx.json --write`. A browser opens, you approve *Send email on your behalf*, and `EMAIL_METHOD`, `GMAIL_CLIENT_ID`, `GMAIL_CLIENT_SECRET` and `GMAIL_REFRESH_TOKEN` are saved to `.env` (permissions 600). Without `--write` they are only printed.
5. In `.env` also set `EMAIL_FROM=<that Gmail address>` and `SMTP_ENABLED=true`, restart, then use **Send Test Email**. `python tools/gmail_auth.py --check` verifies the saved token without sending anything.

Only the `gmail.send` scope is requested: EXE-SOC can send mail but cannot read the mailbox. The sender must be the authorised account or one of its verified aliases (Gmail rewrites any other From address). Gmail limits sending (about 500 per day for free accounts, about 2,000 for Workspace), which the hourly cap keeps well inside.

**Security.** Client secret and refresh token live only in the server environment / `.env` / `*_FILE`; they are never stored in the database, returned by the API, shown on the dashboard (only present/absent) or written to logs, errors or the audit trail. The short-lived access token is kept in memory only.

**Errors.** Temporary problems (rate limit, Google 5xx, network) retry with the normal backoff. Permanent ones fail at once with a clear message: revoked/expired refresh token (`invalid_grant`, run `gmail_auth.py` again), wrong client ID/secret, Gmail API not enabled, missing `gmail.send` permission, or a rejected address.

## 2. SMTP setup (generic)

1. Set the secrets and server in the **server environment** (see section 6), or fill host/port/security/sender on **Email notifications** in the dashboard.
2. The password can only come from `SMTP_PASSWORD` or a file named by `SMTP_PASSWORD_FILE`. It is never stored, shown, logged or returned by the API.
3. Open **Email notifications**, add a recipient, switch **Email notifications ON**, press **Send Test Email**.

Security modes: `starttls` (default, port 587), `ssl` (port 465), `none` (only for a relay on localhost or when `SMTP_ALLOW_INSECURE=1`; the password is never sent over an unencrypted remote connection).

## 3. Gmail / Google Workspace
Host `smtp.gmail.com`, port 587, STARTTLS. Needs 2-step verification and an **App Password** (or a Workspace SMTP relay); username = full address. **VERIFY IN CURRENT PRODUCT DOCUMENTATION** (Google changes its rules for less-secure access and app passwords).

## 4. Microsoft 365
Host `smtp.office365.com`, port 587, STARTTLS. **SMTP AUTH must be enabled** for the sending mailbox and the sender must be that mailbox. Some tenants disable basic authentication and require OAuth, which EXE-SOC does **not** support. **VERIFY IN CURRENT PRODUCT DOCUMENTATION.**

## 5. Other providers
Amazon SES (`email-smtp.<region>.amazonaws.com`, verified sender), SendGrid (username `apikey`), generic SSL on 465. The dashboard has a provider preset list; every preset must be checked against the provider's current documentation.

## 6. Environment variables
| Variable | Meaning |
|---|---|
| `SMTP_ENABLED` | `true` turns notifications on (overrides the dashboard switch) |
| `SMTP_HOST`, `SMTP_PORT`, `SMTP_SECURITY` | server, port, `starttls` / `ssl` / `none` |
| `SMTP_USERNAME`, `EMAIL_FROM` | login and sender address |
| `SMTP_PASSWORD` or `SMTP_PASSWORD_FILE` | password (only here, never in the database) |
| `SOC_BASE_URL` | for the "View Incident in EXE-SOC" link; omitted when empty |
| `SMTP_ALLOW_INSECURE=1` | allow `none` security to a non-local server (not recommended) |

A value set in the environment is shown as locked on the dashboard. Linux example: `sudo env SMTP_PASSWORD='...' SMTP_HOST=smtp.example.com ... ./run.sh`. Windows: `set SMTP_PASSWORD=...` in the same Administrator prompt before `run.bat`. Do not commit `.env` files (see `.env.example`).

## 7. Dashboard (menu: Manage, Email notifications)
Status (OK / DEGRADED / DISABLED / NOT CONFIGURED), SMTP settings, severity boxes (default Critical and High on, Medium optional, Low and Info off), notification types, limits, escalation, recipients, **Send Test Email**, and the delivery history.

## 8. Recipients
Add, enable/disable, remove, test per recipient. Each recipient has a **level** (1 = normal alerts, 2 and 3 = escalation only) and optional **severities** (empty = follow the global policy). Addresses are validated (no header injection).

## 9. Severity and types
An email is sent only if the severity box is on **and** the type is on. Types: new critical/high incident, high/critical alert, IOC detection, agent offline, large outbound transfer, network attack, authentication attack. Specific types win over generic ones. Two types have a notification floor (default High) so they match the policy: agent offline and network attack (Settings values `floor_agent_offline`, `floor_network_attack`); the alert itself keeps its own severity.

## 10. Rate limiting
Default: one email per incident per **15 minutes**, and at most **60 emails per hour** in total. Further events only raise the occurrence counter (shown as "rate-limited" on the status line).

## 11. Deduplication
The key is the incident ID (or, without an incident, detection + endpoint + source IP). A higher severity (for example High to Critical) is allowed through immediately. After the window, a short **UPDATE** email is sent only if there was new activity (switchable).

## 12. Retry
Attempt 1 immediately, then after 30 s, 2 min and 5 min (configurable, up to 4 attempts). Temporary errors (connection, timeout, 4xx) retry; permanent ones (authentication failed, address refused, bad configuration) fail at once and are logged. A failed email can be retried from the history. Sending runs in the worker thread, never in the detection path.

## 13. Escalation
Optional. If a notified incident is still **New** with nobody assigned after N minutes (default 15) and is at least the chosen severity, recipients with level 2 or 3 get one escalation email. "Acknowledged" means the incident status is no longer New or an analyst is assigned. Nothing is escalated automatically otherwise.

## 14. Troubleshooting
| Problem | Check |
|---|---|
| Status NOT CONFIGURED | the listed problems (host, sender, password not set) |
| `authentication failed (535)` | username, app password, SMTP AUTH enabled |
| `Cannot connect` / timeout | host, port, firewall, security mode (587 = starttls, 465 = ssl) |
| TLS error | wrong port/mode pairing, or an inspected network |
| No email for an alert | severity box off, type off, rate limit, whitelisted alert, no enabled recipient for that severity, hourly cap |
| Status DEGRADED | failures in the last 24 hours; see the history |

## 15. Security
TLS by default; password only in the environment or a secret file; never logged, stored or returned (errors are redacted); emails contain only investigation data, secrets in log text (`password=`, `token=`, keys, cookies) are masked and all values are HTML-escaped; recipient and header validation; only an administrator can change SMTP settings, recipients or send tests; analysts can view settings and history; every change is in the audit trail; responses are guidance only and never executed automatically.

## 16. Testing and logs
```
python -m unittest tests.test_notify -v     # 44 tests, local mock SMTP server only, nothing real is sent
python tools/selftest.py                    # existing EXE-SOC checks (server running)
python tools/selftest_socx.py               # SOCX checks (server running)
```
Delivery log: **Email notifications, Notification history** or `GET /api/v1/notifications/history` (time, incident, type, severity, recipient, status SENT / FAILED / RETRYING, tries, error).

API: `GET/PUT /api/v1/notifications/settings`, `GET /status`, `GET /providers`, `POST /test`, `GET /history`, `POST /history/<id>/retry`, `GET/POST /recipients`, `PATCH/DELETE /recipients/<id>`, `POST /recipients/<id>/test`.
