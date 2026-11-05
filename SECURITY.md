# Security Policy

EXE-SOC is **pre-release beta software** and is not declared production-ready. See `docs/KNOWN-LIMITATIONS.md`.

## Reporting a vulnerability
Do not open a public issue. Report privately to the maintainer contact (OWNER TO FILL IN before publication: a monitored security mailbox or the host's private vulnerability reporting). Include affected version/commit, reproduction steps and impact. Never include real credentials or production telemetry.
Target response times (owner to confirm): acknowledgement within 5 working days, status update within 30 days.

## Supported versions
Only the latest tagged beta receives fixes.

## Deployment baseline
Run with `SOC_ENV=production` behind a TLS reverse proxy (`deploy/nginx-exe-soc.conf`), with `SOC_SECRET`, `SOC_ENC_KEYS` and `SOC_BACKUP_DIR` set, `SOC_AGENT_AUTH=hmac-required` and `SOC_LEGACY_API_KEY=off`. Never set `SOC_ALLOW_DEFAULT_CREDS` outside tests. See `docs/DEPLOYMENT.md`.
