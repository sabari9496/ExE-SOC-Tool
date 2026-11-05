# EXE-SOC Linux agent guide (Kali, Ubuntu, Debian)

Install the agent only on computers you are authorised to monitor, with the owner's consent. The agent is visible (a normal systemd service), outbound-only (HTTPS to your SOC), executes no remote commands, and TLS verification is never disabled.

## 1. What was wrong (evidence)

I could not see your original error text, so this lists what I **reproduced or confirmed in the source**, and what I could not. Run `sudo ./install_linux.sh --check-only --server https://SOC:5000 --ca-bundle ca.pem` and, after installing, `sudo exe-soc-agent-diag` to see which one hits you.

| # | Problem | Status | Evidence |
|---|---|---|---|
| S1 | **SQLite permission error** on the server | Reproduced | Start the server with `sudo` once (root creates `soc.db` and `.secret`), then without: `sqlite3.OperationalError: attempt to write a readonly database`. Not a code bug: file ownership. |
| S2 | **Browser "connection reset"** | Reproduced | Server with TLS + browser/curl on `http://`: `Connection reset by peer`. Server without TLS + `https://`: `wrong version number`. The old banner always printed `http://…` even with TLS on. |
| S3 | **Remote agents cannot connect** | Confirmed (source + test) | `SOC_HOST` defaults to `127.0.0.1`: only local connections are accepted; agents get `Connection refused`. |
| I1 | Installer **crashes without a terminal** | Reproduced | `EOFError` at the consent prompt (ssh -T, Ansible, `curl \| bash`). |
| I2 | Re-running the installer **fails and wastes the token** | Reproduced | Second run: `enrollment token invalid, expired, revoked or already used`; `set -e` aborts before the service step. |
| I3 | Service ran as **root**, token on the command line | Confirmed (unit file, source) | No `User=`; `--token` visible in `ps`. |
| I4 | **Raw Python tracebacks** for refused/untrusted/mismatched connections | Reproduced | No actionable message; nothing validated before enrollment. |
| I5 | `Restart=always` + agent `exit(3)` when revoked = **restart loop** hammering the server | Confirmed (source); loop not run under real systemd | |
| I6 | A failed `pip` left a **half-installed** `/opt/exe-soc-agent` | Reproduced | |
| I7 | `python3 -c "import venv"` does not prove `python3 -m venv` works (Debian needs `python3-venv`/ensurepip) | **Not reproduced** (this Ubuntu has ensurepip); known Debian/Kali behaviour | The installer now creates a throwaway venv to prove it. |
| P | Agent/server **protocol mismatch** | **Ruled out** | Existing 23-check fleet test and the new tests enroll, heartbeat and ingest correctly over real TLS. |

## 2. Files changed

| File | Change |
|---|---|
| `agent/install_linux.sh` | Rewritten: prerequisite checks before any change, server/CA/TLS validation before enrollment, unprivileged service user, venv (no `sudo pip`), idempotent, rollback, migration from the old layout, `--check-only`. Original saved in `backup_before_linux_fix/`. |
| `agent/uninstall_linux.sh` | New: removes only agent resources (marker-protected). |
| `agent/exe_soc_agent.py` | Plain-language errors, token via file/env/hidden prompt, `--name`, `--force`, no overwrite of an existing enrollment, write check **before** the single-use token is spent, `check-server`, `status.json` health file, exit codes 3/4 (no restart), unreadable config no longer reported as "not enrolled". Windows code paths unchanged. |
| `agent/soc_preflight.py` | New, standard-library only: DNS → TCP → TLS (verified) → API checks with fixes. |
| `agent/exe_soc_diag.py` | New diagnostics (`exe-soc-agent-diag`). |
| `app.py`, `db.py` | Startup banner shows the real scheme and warns when loopback-only; TLS file checks; `db.check_access()` turns the SQLite/`.secret` ownership trap into a clear message with the exact `chown`. |
| `run.sh` | Detects mixed sudo/non-sudo ownership and missing `python3-venv` with the fix. |
| `tests/test_linux_agent.py`, `tests/fake_systemctl.py` | New tests (64 checks). |
| `FLEET-GUIDE.md`, `README.md`, `.env.example` | Pointers / updated command. |

## 3. Prepare the SOC server (once)

```bash
python tools/dev_certs.py --name soc.lan --ip 192.168.1.50      # IP/name agents will use -> certs/ca.pem, server.pem, server.key
# put these in .env (loaded automatically) or export them:
SOC_HOST=0.0.0.0
SOC_TLS_CERT=certs/server.pem
SOC_TLS_KEY=certs/server.key
./run.sh            # ALWAYS the same way: always with sudo, or never. Open https://192.168.1.50:5000 (https!)
sudo ufw allow 5000/tcp     # if a firewall is active
```
The agent must use a name/IP that is **in the certificate** (`--name/--ip` above). In the dashboard: **Fleet → Enrollment tokens → create** (single use, expires). Copy the token to a file on the endpoint: `(umask 077; nano token.txt)`.

## 4. Install on Kali / Ubuntu / Debian

Copy the `agent/` folder and `ca.pem` to the endpoint, then:

```bash
sudo apt update && sudo apt install -y python3 python3-venv python3-pip      # or add --install-prereqs below
cd agent
sudo ./install_linux.sh --server https://192.168.1.50:5000 --ca-bundle ./ca.pem --token-file ./token.txt --accept-consent
```
`--accept-consent` means you read `python3 exe_soc_agent.py what-we-collect` and the device owner agrees. In an interactive terminal you can omit it and type `I AGREE` instead.

What it does (each privileged step is printed first): checks OS/Python/venv; validates the server, port, CA and TLS **before changing anything**; creates the system user `exe-soc-agent` (no login shell); installs code to `/opt/exe-soc-agent` (root-owned; the agent cannot edit its own code); config to `/etc/exe-soc-agent` (credential 0600); state to `/var/lib/exe-soc-agent` (0700); enrolls once; installs and starts the service; waits for the first heartbeat.

Validate only (changes nothing, works without sudo): `./install_linux.sh --check-only --server https://192.168.1.50:5000 --ca-bundle ./ca.pem`

**Options:** `--host H --port P` (instead of `--server`), `--name NAME`, `--install-prereqs` (runs `apt-get`), `--system-packages` (use `python3-requests python3-psutil` from apt, no pip/internet), `--full-file-read` (see §8), `--force-reenroll` (new token; old credential backed up), `--no-service` (containers), `--token`/`EXESOC_ENROLL_TOKEN` (the token on the command line is visible in `ps`; prefer the file). Offline pip: set `PIP_NO_INDEX=1 PIP_FIND_LINKS=/path/to/wheels`.

**Manual enrollment command** (what the installer runs for you, as root):
```bash
sudo env EXESOC_AGENT_HOME=/var/lib/exe-soc-agent EXESOC_AGENT_CONF=/etc/exe-soc-agent/agent.json EXESOC_ENROLL_TOKEN="$(cat token.txt)" \
  /opt/exe-soc-agent/venv/bin/python /opt/exe-soc-agent/exe_soc_agent.py enroll --server https://192.168.1.50:5000 --ca-bundle /etc/exe-soc-agent/ca.pem
```
Re-running the installer is safe: it keeps the credential (no new token), updates code, rewrites the unit only if changed and restarts once.

## 5. Service commands

```bash
sudo systemctl status exe-soc-agent --no-pager     sudo journalctl -u exe-soc-agent -f
sudo systemctl stop exe-soc-agent                  sudo systemctl start exe-soc-agent       sudo systemctl restart exe-soc-agent
sudo systemctl disable --now exe-soc-agent         # stop and do not start at boot
```
Settings (collectors on/off, extra log files) live in `/etc/exe-soc-agent/agent.env`, then `sudo systemctl restart exe-soc-agent`.

## 6. Uninstall

```bash
sudo ./install_linux.sh --uninstall          # or: sudo ./uninstall_linux.sh   (add --keep-data to keep config/state)
```
Removes only the service, `/opt/exe-soc-agent`, `/etc/exe-soc-agent`, `/var/lib/exe-soc-agent`, the diag command and the account (only if the installer created it). It refuses to delete `/opt/exe-soc-agent` if it lacks the installer's marker, and never touches the SOC database or certificates. Then press **Revoke** for the agent on the Fleet page.

## 7. Diagnostics

```bash
sudo exe-soc-agent-diag                                  # OS, Python/venv, imports, config, CA, DNS/TCP/TLS/API, auth+heartbeat, service, logs, collector access
sudo exe-soc-agent-diag --send-test-event                # + one harmless labelled test event (checks ingestion)
EXESOC_DASH_PASSWORD='…' sudo -E exe-soc-agent-diag --dashboard-user admin     # + confirms the dashboard shows this agent online
python3 agent/soc_preflight.py --server https://SOC:5000 --ca-bundle ca.pem     # before installing: connectivity only
```
Output is redacted: credentials, tokens, passwords and private keys are never printed. Other useful commands:
```bash
sudo ss -ltnp | grep 5000                 # on the SOC: must show 0.0.0.0:5000 or its LAN IP, not 127.0.0.1
nc -vz 192.168.1.50 5000                  # from the endpoint: firewall/route
openssl s_client -connect 192.168.1.50:5000 -CAfile /etc/exe-soc-agent/ca.pem </dev/null | head
sudo ufw status verbose                   # firewall; server log = terminal/journal where app.py runs
```
| Symptom | Meaning / fix |
|---|---|
| Service fails `status=203/EXEC` | The agent's venv was created root-only because of a restrictive umask (e.g. `umask 077` in your shell). Fixed in this installer (it sets `umask 022`). Quick repair: `sudo chmod -R a+rX /opt/exe-soc-agent; sudo systemctl reset-failed exe-soc-agent; sudo systemctl restart exe-soc-agent`. |
| `Connection refused` | Server down, wrong port, firewall, or `SOC_HOST` is still `127.0.0.1`. |
| `Connection reset` / `not speaking HTTPS` | HTTP/HTTPS mismatch: start the server with `SOC_TLS_CERT/KEY`; use `https://` everywhere. |
| `certificate is not valid for 'x'` | Use a name/IP listed in the cert, or recreate it with `dev_certs.py --name … --ip …`. |
| `not trusted` / `signature failure` | Wrong or regenerated `ca.pem`: copy the server's current one. |
| `token … already used` | Tokens are single use: create a new one. |
| `attempt to write a readonly database` (server) | Files owned by another user; the new message shows the `chown`. |
| Agent **Online but no logs** | Open the dashboard > Fleet > the agent: **collector errors** now state the reason (also in `sudo exe-soc-agent-diag`). Most common: the service user cannot read the journal - `sudo usermod -aG systemd-journal exe-soc-agent && sudo systemctl restart exe-soc-agent`. A quiet machine can also log nothing for minutes (collection starts "from now"; new installs load the last 10 minutes, `SOC_LINUX_BACKFILL_MINUTES` in `/etc/exe-soc-agent/agent.env`). Test the pipeline: `logger -p auth.notice "exe-soc test"`, `sudo exe-soc-agent-diag --send-test-event`. "server rejected N events" = wrong clock/timezone. |
| Agent shows Offline | `sudo exe-soc-agent-diag`, then `journalctl -u exe-soc-agent -n 50`; check the endpoint clock (`timedatectl`), events dated >10 min in the future are rejected. |

## 8. Privileges (least privilege)

The service runs as `exe-soc-agent` with `NoNewPrivileges`, no capabilities, `ProtectSystem=full`, `ProtectHome=read-only`, `UMask=0077`, and only the groups `systemd-journal` and `adm` (journal, `auth.log`, `syslog`). It does not run as root. Consequence, reported by the doctor: files readable only by root (`/etc/shadow`, `/etc/sudoers`, `/root/.ssh`, `/var/log/audit/audit.log`) cannot be hashed/read, so file-integrity monitoring and auditd collection of those are blind. If you need them, install with `--full-file-read`: this adds only `CAP_DAC_READ_SEARCH` (read-only access to all files, no write, no root). Your decision; default is off.

## 9. Test results

`sudo python3 tests/test_linux_agent.py` → **64/64 passed** (Ubuntu 24.04, Python 3.12, real TLS server on a temporary DB). Covers: server startup (banner scheme, loopback warning, http→TLS reset, SQLite ownership message, `run.sh`, missing TLS file); enrollment CLI (invalid token, unwritable config does not burn the token, no overwrite, consent without terminal, `--force`); installer failures that must change nothing (non-root, missing server/token/consent, invalid port, `http://`, bad DNS name, server down, missing/invalid/wrong CA, SAN mismatch, plain-HTTP server, pip failure with rollback, invalid token with rollback, invalid name); installation (system user, unit content, `systemd-analyze verify`, modes/ownership, agent cannot edit its code, token stored nowhere, dashboard online); telemetry (a log line on the endpoint → SOC events → brute-force alert); restart; re-run idempotency and no duplicates; different-server refusal; doctor (healthy, ingestion, dashboard, no secrets leaked, CA problem pinpointed); revoke = exit 3 and no restart; uninstall (`--keep-data`, full, unrelated files and server DB/certs untouched, idempotent, refuses unmarked folder); upgrade from the old installer keeping the credential.
Regression: `tests/test_fleet.py` 23/23, `tools/selftest_socx.py` 38/38, `tools/selftest.py` 92/92, `tests.test_notify` 59/59; `install_windows.ps1` and `winevents.py` byte-identical; agent still resolves the Windows paths.

**NOT tested (do these on a real host before relying on it):** a real systemd (the test uses a stand-in that runs the generated unit as its User/Groups; sandboxing directives, `SupplementaryGroups`, `StateDirectory`, **reboot persistence** and boot ordering are unverified; the unit does pass `systemd-analyze verify`); **Kali** (only Ubuntu 24.04 ran); real `journald`/`auth.log` collection (tests use a log file via `SOC_LINUX_FILES`); `--install-prereqs` (apt); pip downloading from PyPI (no network: the pip *failure* path is tested, success used `--system-packages`); `--full-file-read` at runtime; FIM, malware-scan, process/network and auditd collectors (existing code, not re-tested or claimed here); Python versions other than 3.12; the Windows agent at runtime.

## 10. Remaining limitations

- Tenant/organisation id is not supported by the server API, so it was not added.
- Console-only logs: the agent writes to journald (no log files). Dev certs are for private networks; use a real CA or a reverse proxy for anything exposed.
- The enrollment token is single-use: a failure after the server accepted it (very rare: disk full while saving) needs a new token; the installer checks writability first to avoid this.
