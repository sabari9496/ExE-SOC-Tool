#!/usr/bin/env bash
# EXE-SOC Linux agent installer - Kali, Ubuntu, Debian.  Visible systemd service "exe-soc-agent" (no hidden persistence).
#
#   sudo ./install_linux.sh --server https://SOC-IP:5000 --ca-bundle ca.pem --token-file token.txt --accept-consent
#   sudo ./install_linux.sh --check-only --server https://SOC-IP:5000 --ca-bundle ca.pem       # validate only, change nothing
#   sudo ./install_linux.sh --uninstall                                                        # remove the agent (see uninstall_linux.sh)
# Only install on computers you are authorised to monitor, with the owner's consent.
#
# What it does (root is needed because it must create a system user, write /opt, /etc, /var/lib and install a systemd unit):
#   1. checks prerequisites and validates server, port, CA and TLS - BEFORE changing anything
#   2. creates the unprivileged system user "exe-soc-agent" (no login shell) and installs code into /opt/exe-soc-agent (venv, no sudo pip)
#   3. enrolls once (single-use token; credential stored 0600 in /etc/exe-soc-agent) - skipped on re-runs, so credentials are never overwritten
#   4. installs + starts the hardened service and waits for the first heartbeat
set -euo pipefail
# A restrictive caller umask (e.g. 077) would make the venv and other created directories root-only, so the unprivileged service user
# could not execute its own Python (systemd status=203/EXEC).  Fix the umask for everything this installer creates.
umask 022

APP=/opt/exe-soc-agent; CONF_DIR=/etc/exe-soc-agent; STATE_DIR=/var/lib/exe-soc-agent; SVC=exe-soc-agent; SVC_USER=exe-soc-agent
UNIT=/etc/systemd/system/$SVC.service; CONF=$CONF_DIR/agent.json; ENVF=$CONF_DIR/agent.env; WRAP=/usr/local/sbin/exe-soc-agent-diag; MARK=$APP/.installed-by-exe-soc
SELF_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
INSTALLER_VERSION=2

say()  { printf '%s\n' "$*"; }
step() { printf '\n==> %s\n' "$*"; }
ok()   { printf '    OK   %s\n' "$*"; }
warn() { printf '    WARN %s\n' "$*" >&2; }
die()  { printf '\nERROR: %s\n' "$1" >&2; [ -n "${2:-}" ] && printf '  Fix: %s\n' "$2" >&2; exit "${3:-1}"; }

usage() { sed -n '2,12p' "$0" | sed 's/^# \{0,1\}//'; cat <<'EOF'

Options
  --server URL            https://HOST[:PORT] of the SOC server           (or --host H --port P)
  --ca-bundle FILE        the SOC's ca.pem (private CA); omit if the certificate is publicly trusted
  --token-file FILE       file containing the one-time enrollment token   (best; or env EXESOC_ENROLL_TOKEN; --token TEXT is visible in 'ps')
  --name NAME             device name shown in the SOC (default: this computer's hostname)
  --accept-consent        you have read `exe_soc_agent.py what-we-collect` and the device owner agrees (required when there is no terminal)
  --install-prereqs       run apt-get to install python3-venv / python3-pip if they are missing (Debian/Ubuntu/Kali)
  --system-packages       use the distro's python3-requests / python3-psutil instead of pip (offline-friendly)
  --full-file-read        grant the service read-only access to ALL files (CAP_DAC_READ_SEARCH) so file-integrity monitoring and auditd logs of root-only files work
  --force-reenroll        enroll again with a NEW token (the old credential is backed up)
  --no-service            install and enroll but do not create the systemd service (containers)
  --check-only            run prerequisite + server checks and exit without changing anything
  --uninstall [--keep-data]   remove the agent
EOF
}

# ---------------------------------------------------------------- arguments
SERVER=""; HOST=""; PORT=""; CA=""; TOKEN_FILE=""; TOKEN="${EXESOC_ENROLL_TOKEN:-}"; NAME=""; ACCEPT=0; PREREQS=0; SYSPKG=0; FULLREAD=0; REENROLL=0; NOSERVICE=0; CHECKONLY=0; UNINSTALL=0; KEEPDATA=0
need_val() { [ $# -ge 2 ] && [ -n "$2" ] || die "option $1 needs a value" "run $0 --help"; }
while [ $# -gt 0 ]; do case "$1" in
  --server) need_val "$@"; SERVER="$2"; shift 2;;        --host) need_val "$@"; HOST="$2"; shift 2;;      --port) need_val "$@"; PORT="$2"; shift 2;;
  --ca-bundle) need_val "$@"; CA="$2"; shift 2;;         --token-file) need_val "$@"; TOKEN_FILE="$2"; shift 2;;   --token) need_val "$@"; TOKEN="$2"; shift 2;;
  --name) need_val "$@"; NAME="$2"; shift 2;;            --accept-consent|--accept) ACCEPT=1; shift;;     --install-prereqs) PREREQS=1; shift;;
  --system-packages) SYSPKG=1; shift;;                   --full-file-read) FULLREAD=1; shift;;           --force-reenroll) REENROLL=1; shift;;
  --no-service) NOSERVICE=1; shift;;                     --check-only) CHECKONLY=1; shift;;              --uninstall) UNINSTALL=1; shift;;
  --keep-data) KEEPDATA=1; shift;;                       -h|--help) usage; exit 0;;                      *) die "unknown option: $1" "run $0 --help";;
esac; done

# ---------------------------------------------------------------- uninstall
if [ "$UNINSTALL" = 1 ]; then
  U="$SELF_DIR/uninstall_linux.sh"; [ -f "$U" ] || U="$APP/uninstall.sh"
  [ -f "$U" ] || die "uninstall_linux.sh not found next to this script or in $APP" "run it from the agent folder"
  UA=(); [ "$KEEPDATA" = 1 ] && UA+=(--keep-data); exec bash "$U" ${UA[@]+"${UA[@]}"}
fi

# ---------------------------------------------------------------- 1. prerequisites (NOTHING is changed in this section)
step "Checking prerequisites (no changes yet)"
[ "$(id -u)" = 0 ] || [ "$CHECKONLY" = 1 ] || die "this installer must run as root (it creates a system user, writes /opt, /etc and /var/lib, and installs a systemd unit)" "sudo $0 ...   (do not use 'sudo pip'; the installer builds its own virtual environment)"

OS_NAME="unknown"; OS_FAMILY=""
if [ -r /etc/os-release ]; then OS_NAME=$(. /etc/os-release; printf '%s' "${PRETTY_NAME:-$NAME}"); OS_FAMILY=$(. /etc/os-release; printf '%s %s' "${ID:-}" "${ID_LIKE:-}"); fi
case " $OS_FAMILY " in *" debian "*|*" ubuntu "*|*" kali "*) ok "OS: $OS_NAME (Debian family)";; *) warn "OS: $OS_NAME is not Debian/Ubuntu/Kali - untested; continuing, but apt-based prerequisite install is unavailable";; esac
[ "$(uname -s)" = Linux ] || die "this installer is for Linux (Windows: use install_windows.ps1)"
if [ "$NOSERVICE" = 0 ] && [ "$CHECKONLY" = 0 ] && [ ! -d /run/systemd/system ] && [ "${EXESOC_ASSUME_SYSTEMD:-}" != 1 ]; then
  die "systemd is not running here (container / WSL1 / chroot?), so the service cannot be installed" "use --no-service to install and enroll without a service, or run on a systemd host"; fi

command -v python3 >/dev/null 2>&1 || { [ "$PREREQS" = 1 ] || die "python3 is not installed" "sudo apt install python3 python3-venv python3-pip     (or add --install-prereqs)"; }
APT_NEEDED=""
if command -v python3 >/dev/null 2>&1; then
  python3 -c 'import sys; sys.exit(0 if sys.version_info >= (3, 8) else 1)' || die "Python $(python3 -c 'import platform;print(platform.python_version())') is too old (3.8 or newer is required)" "use a newer distribution or install a newer python3"
  ok "Python $(python3 -c 'import platform;print(platform.python_version())')"
  # `import venv` succeeds on Debian even without the python3-venv package; only actually creating one proves ensurepip is present.
  TMPV=$(mktemp -d); if python3 -m venv "$TMPV/t" >/dev/null 2>&1 && [ -x "$TMPV/t/bin/pip" ]; then ok "python3 -m venv works (ensurepip present)"; else APT_NEEDED="$APT_NEEDED python3-venv python3-pip"; fi; rm -rf "$TMPV"
  if [ "$SYSPKG" = 1 ]; then python3 -c 'import requests, psutil' >/dev/null 2>&1 && ok "system python3-requests / python3-psutil present" || APT_NEEDED="$APT_NEEDED python3-requests python3-psutil"; fi
else APT_NEEDED="python3 python3-venv python3-pip"; fi
if [ -n "$APT_NEEDED" ]; then
  case " $OS_FAMILY " in *" debian "*|*" ubuntu "*|*" kali "*) :;; *) die "missing prerequisites:$APT_NEEDED" "install them with your package manager and re-run";; esac
  if [ "$PREREQS" = 1 ] && [ "$CHECKONLY" = 0 ]; then
    step "Installing prerequisites with apt (privileged operation, requested by --install-prereqs):$APT_NEEDED"
    DEBIAN_FRONTEND=noninteractive apt-get update -qq && DEBIAN_FRONTEND=noninteractive apt-get install -y -qq $APT_NEEDED >/dev/null || die "apt-get failed" "check your network/apt sources, then run: sudo apt-get install -y$APT_NEEDED"
    ok "installed:$APT_NEEDED"
  else die "missing prerequisites:$APT_NEEDED" "sudo apt install$APT_NEEDED      (or re-run this installer with --install-prereqs)"; fi
fi

# --- inputs
[ -z "$SERVER" ] && [ -n "$HOST" ] && SERVER="https://$HOST${PORT:+:$PORT}"
[ -n "$PORT" ] && ! [[ "$PORT" =~ ^[0-9]+$ && "$PORT" -ge 1 && "$PORT" -le 65535 ]] && die "invalid port '$PORT' (1-65535)"
OLD_CONF=$STATE_DIR/agent.json            # location used by the previous installer
CUR_CONF=""; for f in "$CONF" "$OLD_CONF"; do [ -z "$CUR_CONF" ] && [ -f "$f" ] && grep -q '"credential"' "$f" 2>/dev/null && CUR_CONF="$f"; done
ENROLLED=0; [ -n "$CUR_CONF" ] && ENROLLED=1
if [ "$ENROLLED" = 1 ] && [ "$REENROLL" = 0 ]; then
  EXISTING_SERVER=$(python3 -c 'import json,sys; print(json.load(open(sys.argv[1])).get("server",""))' "$CUR_CONF" 2>/dev/null || true)
  [ -z "$SERVER" ] && SERVER="$EXISTING_SERVER"
  [ -n "$EXISTING_SERVER" ] && [ "${SERVER%/}" != "${EXISTING_SERVER%/}" ] && die "this computer is already enrolled to $EXISTING_SERVER (you asked for $SERVER)" "add --force-reenroll with a NEW token to move it to a different SOC"
  ok "already enrolled (credential kept, no new token needed)"; [ "$CUR_CONF" = "$OLD_CONF" ] && ok "found a credential from the previous installer: it will be migrated, not replaced"
fi
[ -n "$SERVER" ] || die "no SOC server given" "--server https://SOC-IP:5000   (see --help)"
SERVER="${SERVER%/}"
[[ "$SERVER" =~ ^https:// ]] || die "the server URL must start with https:// (got '$SERVER'); TLS is mandatory" "start the SOC with SOC_TLS_CERT/SOC_TLS_KEY and use https://"
if [ -n "$NAME" ]; then [[ "$NAME" =~ ^[A-Za-z0-9._\ -]{1,100}$ ]] || die "--name may only contain letters, digits, space . _ - (max 100)"; fi
[ -z "$CA" ] || CA=$(readlink -f "$CA" 2>/dev/null || echo "$CA")
[ -z "$TOKEN" ] || [ -n "${EXESOC_ENROLL_TOKEN:-}" ] || warn "--token is visible to other users in 'ps'; prefer --token-file or EXESOC_ENROLL_TOKEN"
if [ "$CHECKONLY" = 0 ] && { [ "$ENROLLED" = 0 ] || [ "$REENROLL" = 1 ]; }; then
  if [ -n "$TOKEN_FILE" ]; then [ -r "$TOKEN_FILE" ] || die "cannot read --token-file $TOKEN_FILE"; TOKEN=$(tr -d '[:space:]' < "$TOKEN_FILE"); fi
  if [ -z "$TOKEN" ] && [ -t 0 ]; then read -r -s -p "Enrollment token (input hidden): " TOKEN; echo; fi
  [ -n "$TOKEN" ] || die "no enrollment token" "create one in the SOC (Fleet > Enrollment tokens) and pass --token-file FILE (or set EXESOC_ENROLL_TOKEN)"
  [ -t 0 ] || [ "$ACCEPT" = 1 ] || [ "$CHECKONLY" = 1 ] || die "there is no terminal to ask for consent" "read: python3 $SELF_DIR/exe_soc_agent.py what-we-collect   then re-run with --accept-consent (only if the device owner agrees)"
fi

# --- server, port, CA, TLS: validated with the standard library BEFORE anything is installed
step "Validating the SOC server $SERVER"
PF_ARGS=(--server "$SERVER"); [ -n "$CA" ] && PF_ARGS+=(--ca-bundle "$CA")
if ! python3 "$SELF_DIR/soc_preflight.py" "${PF_ARGS[@]}"; then die "the SOC server check failed (details above). Nothing was installed and the token was not used." "fix the item marked FAIL, or run:  python3 $SELF_DIR/soc_preflight.py ${PF_ARGS[*]}"; fi
if [ "$CHECKONLY" = 1 ]; then step "Check-only: all checks passed. Nothing was changed."; exit 0; fi

# ---------------------------------------------------------------- 2. install (system changes start here)
FRESH=0; [ -e "$MARK" ] || FRESH=1; CREATED_USER=0; DONE=0; KEEP=0
# Data that existed BEFORE this run (e.g. kept by a previous "--uninstall --keep-data") must survive a failed reinstall: rollback removes only what this run created (P5-06).
STATE_PRE=0; [ -e "$STATE_DIR" ] && STATE_PRE=1; CONF_PRE=0; [ -e "$CONF_DIR" ] && CONF_PRE=1
rollback() {
  [ "$DONE" = 0 ] || return 0
  if [ "$KEEP" = 1 ]; then printf '\nThe agent is enrolled but setup did not finish. Nothing was removed (the one-time token is already used).\nFix the problem shown above and re-run THE SAME command (it will reuse the stored credential), or run: sudo %s --uninstall\n' "$0" >&2; return 0; fi
  if [ "$FRESH" = 1 ]; then
    printf '\nInstallation failed - rolling back what this run created.\n' >&2
    systemctl disable --now "$SVC" >/dev/null 2>&1 || true; rm -f "$UNIT" "$WRAP"; systemctl daemon-reload >/dev/null 2>&1 || true
    [ -n "$APP" ] && rm -rf -- "$APP"; [ "$CONF_PRE" = 1 ] || [ -f "$CONF" ] || rm -rf -- "$CONF_DIR"; [ "$STATE_PRE" = 1 ] || rm -rf -- "$STATE_DIR"
    [ "$CREATED_USER" = 1 ] && userdel "$SVC_USER" >/dev/null 2>&1 || true
  fi
}
trap rollback EXIT

cat <<EOF

Privileged operations this installer is about to perform:
  - create system user '$SVC_USER' (no login shell, no home directory contents)         [if missing]
  - write program files to $APP, config to $CONF_DIR, state to $STATE_DIR
  - install the systemd service '$SVC' ($UNIT) and the helper $WRAP
  - the service runs as '$SVC_USER'$( [ "$FULLREAD" = 1 ] && echo " with read-only access to all files (--full-file-read)" || echo " in groups systemd-journal/adm only (no root)" )
EOF

step "Creating the service account"
if id "$SVC_USER" >/dev/null 2>&1; then
  [ "$(getent passwd "$SVC_USER" | cut -d: -f6)" = "$STATE_DIR" ] || die "a user named '$SVC_USER' already exists but is not an EXE-SOC agent account" "remove or rename that user, then re-run"
  ok "user $SVC_USER already exists"
else
  NOLOGIN=$(command -v nologin || echo /usr/sbin/nologin)
  useradd --system --user-group --home-dir "$STATE_DIR" --no-create-home --shell "$NOLOGIN" --comment "EXE-SOC endpoint agent" "$SVC_USER" || die "useradd failed"
  CREATED_USER=1; ok "created system user $SVC_USER"
fi
SVC_GROUP=$(id -gn "$SVC_USER")
GROUPS_LIST=""; for g in systemd-journal adm; do getent group "$g" >/dev/null 2>&1 && GROUPS_LIST="$GROUPS_LIST $g"; done; GROUPS_LIST="${GROUPS_LIST# }"

step "Installing program files into $APP"
install -d -m 0755 -o root -g root "$APP" "$CONF_DIR"
install -d -m 0700 -o "$SVC_USER" -g "$SVC_GROUP" "$STATE_DIR"
for f in exe_soc_agent.py exe_soc_diag.py soc_preflight.py requirements.txt; do [ -f "$SELF_DIR/$f" ] || die "$SELF_DIR/$f is missing - run the installer from the full agent folder"; install -m 0644 -o root -g root "$SELF_DIR/$f" "$APP/$f"; done
rm -rf "$APP/collectors"; install -d -m 0755 -o root -g root "$APP/collectors"
for f in "$SELF_DIR"/collectors/*.py "$SELF_DIR"/collectors/*.txt; do [ -f "$f" ] && install -m 0644 -o root -g root "$f" "$APP/collectors/$(basename "$f")"; done
[ -f "$SELF_DIR/uninstall_linux.sh" ] && install -m 0755 -o root -g root "$SELF_DIR/uninstall_linux.sh" "$APP/uninstall.sh"
printf 'installer_version=%s\ncreated_user=%s\ninstalled_at=%s\n' "$INSTALLER_VERSION" "$CREATED_USER" "$(date -u +%FT%TZ)" > "$MARK.tmp"
[ -f "$MARK" ] && grep -q '^created_user=1' "$MARK" && sed -i 's/^created_user=0/created_user=1/' "$MARK.tmp"      # re-runs must not forget that WE created the account
mv "$MARK.tmp" "$MARK"; chmod 0644 "$MARK"
ok "files installed (owned by root: the agent cannot modify its own code)"

step "Preparing the Python environment (virtual environment, no 'sudo pip')"
PY="$APP/venv/bin/python"; VENV_ARGS=(); [ "$SYSPKG" = 1 ] && VENV_ARGS+=(--system-site-packages)
if [ -x "$PY" ] && "$PY" -c 'import sys' >/dev/null 2>&1; then ok "reusing the existing virtual environment"; else rm -rf "$APP/venv"; python3 -m venv "${VENV_ARGS[@]}" "$APP/venv" || die "could not create the virtual environment" "sudo apt install python3-venv python3-pip   (or --install-prereqs)"; ok "virtual environment created"; fi
PIPLOG=$(mktemp); if "$PY" -m pip install --disable-pip-version-check -q -r "$APP/requirements.txt" >"$PIPLOG" 2>&1; then ok "dependencies installed (requests, psutil)"; rm -f "$PIPLOG"
else tail -5 "$PIPLOG" >&2; rm -f "$PIPLOG"; die "pip could not install the dependencies" "check the network/proxy (PIP_INDEX_URL, https_proxy), or for offline use: --system-packages after 'sudo apt install python3-requests python3-psutil'"; fi
"$PY" -c 'import requests, psutil' || die "the installed environment cannot import requests/psutil"
"$PY" -m compileall -q "$APP/exe_soc_agent.py" "$APP/exe_soc_diag.py" "$APP/soc_preflight.py" "$APP/collectors" >/dev/null 2>&1 || true

step "Writing configuration"
if [ ! -f "$CONF" ] && [ "$CUR_CONF" = "$OLD_CONF" ] && [ "$REENROLL" = 0 ]; then       # upgrade from the old layout: keep the existing credential
  python3 - "$OLD_CONF" "$CONF" "$CONF_DIR/ca.pem" <<'PYEOF' || die "could not migrate the old credential" "re-run with --force-reenroll and a new token"
import json, os, shutil, sys
old, new, ca = sys.argv[1:4]; c = json.load(open(old))
if c.get("ca_bundle") and os.path.isfile(c["ca_bundle"]): shutil.copyfile(c["ca_bundle"], ca); os.chmod(ca, 0o644); c["ca_bundle"] = ca
fd = os.open(new, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
with os.fdopen(fd, "w") as f: json.dump(c, f)
PYEOF
  rm -f "$OLD_CONF"; ok "credential migrated to $CONF"
fi
if [ -n "$CA" ]; then [ "$CA" = "$CONF_DIR/ca.pem" ] || install -m 0644 -o root -g root "$CA" "$CONF_DIR/ca.pem"; CA_FOR_AGENT="$CONF_DIR/ca.pem"; ok "CA bundle stored at $CONF_DIR/ca.pem"
elif [ "$ENROLLED" = 1 ] && [ "$REENROLL" = 0 ]; then CA_FOR_AGENT=$("$PY" -c 'import json,sys; print(json.load(open(sys.argv[1])).get("ca_bundle") or "")' "$CONF" 2>/dev/null || true)
else CA_FOR_AGENT=""; fi
if [ ! -f "$ENVF" ]; then
  cat > "$ENVF" <<EOF
# EXE-SOC agent settings (no secrets here). Edit, then: sudo systemctl restart $SVC
EXESOC_AGENT_HOME=$STATE_DIR
EXESOC_AGENT_CONF=$CONF
# Optional collectors (1 = on, 0 = off):
#SOC_FIM=0
#SOC_MALWARE=0
#SOC_ACTIVITY=0
# Extra/other log files to read (comma-separated), and journald on/off:
#SOC_LINUX_FILES=/var/log/auth.log,/var/log/syslog
#SOC_LINUX_JOURNAL=1
# On the very first start also load the last N minutes of the journal, so the dashboard shows logs immediately (0 = start from now):
SOC_LINUX_BACKFILL_MINUTES=10
EOF
  chmod 0644 "$ENVF"; ok "wrote $ENVF"
else ok "$ENVF kept"; fi

# ---------------------------------------------------------------- 3. enrollment (once)
AGENT_ENV=(EXESOC_AGENT_HOME="$STATE_DIR" EXESOC_AGENT_CONF="$CONF")
if [ "$ENROLLED" = 0 ] || [ "$REENROLL" = 1 ]; then
  step "Enrolling this computer with $SERVER"
  [ "$REENROLL" = 1 ] && [ -f "$CONF" ] && { cp -p "$CONF" "$CONF.bak-$(date +%Y%m%d-%H%M%S)"; ok "previous credential backed up"; }
  EN=(enroll --server "$SERVER"); [ -n "$CA_FOR_AGENT" ] && EN+=(--ca-bundle "$CA_FOR_AGENT"); [ -n "$NAME" ] && EN+=(--name "$NAME"); [ "$ACCEPT" = 1 ] && EN+=(--accept); [ "$REENROLL" = 1 ] && EN+=(--force)
  # the token travels in the environment of this one process (not in argv, so not visible in 'ps'); it is never stored
  if ! ( export EXESOC_ENROLL_TOKEN="$TOKEN"; exec env "${AGENT_ENV[@]}" "$PY" "$APP/exe_soc_agent.py" "${EN[@]}" ); then die "enrollment did not complete (message above)" "if it says the token is used/expired, create a new one in the SOC"; fi
  [ -f "$CONF" ] || die "enrollment finished without creating $CONF"
  FRESH=0; KEEP=1; unset TOKEN
fi
KEEP=1
chown "$SVC_USER:$SVC_GROUP" "$CONF"; chmod 0600 "$CONF"; chmod 0755 "$CONF_DIR"; ok "credential file $CONF: owner $SVC_USER, mode 0600"

# ---------------------------------------------------------------- 4. service
if [ "$NOSERVICE" = 1 ]; then DONE=1; step "--no-service: files installed and enrolled; no service created."; say "Run it manually:  sudo -u $SVC_USER env $(printf '%s ' "${AGENT_ENV[@]}")$PY $APP/exe_soc_agent.py run"; exit 0; fi
step "Installing the systemd service"
CAPS=""; [ "$FULLREAD" = 1 ] && CAPS="CAP_DAC_READ_SEARCH"
NEW_UNIT=$(mktemp)
cat > "$NEW_UNIT" <<UNITEOF
[Unit]
Description=EXE-SOC Endpoint Agent (security telemetry, outbound HTTPS only)
Documentation=man:systemd.service(5)
After=network-online.target
Wants=network-online.target
StartLimitIntervalSec=300
StartLimitBurst=5

[Service]
Type=simple
User=$SVC_USER
Group=$SVC_GROUP
${GROUPS_LIST:+SupplementaryGroups=$GROUPS_LIST}
WorkingDirectory=$APP
EnvironmentFile=$ENVF
Environment=PYTHONUNBUFFERED=1 PYTHONDONTWRITEBYTECODE=1
ExecStart=$PY $APP/exe_soc_agent.py run
Restart=on-failure
RestartSec=10
# exit 3 = the SOC revoked this agent, exit 4 = configuration problem: restarting cannot fix either, so do not loop
RestartPreventExitStatus=3 4
StateDirectory=$SVC
StateDirectoryMode=0700
UMask=0077
NoNewPrivileges=yes
CapabilityBoundingSet=$CAPS
AmbientCapabilities=$CAPS
ProtectSystem=full
ProtectHome=read-only
ProtectKernelModules=yes
ProtectKernelTunables=yes
ProtectControlGroups=yes
RestrictSUIDSGID=yes
LockPersonality=yes

[Install]
WantedBy=multi-user.target
UNITEOF
CHANGED=1; cmp -s "$NEW_UNIT" "$UNIT" 2>/dev/null && CHANGED=0
if [ "$CHANGED" = 1 ]; then install -m 0644 -o root -g root "$NEW_UNIT" "$UNIT"; systemctl daemon-reload; ok "unit written: $UNIT"; else ok "unit unchanged"; fi; rm -f "$NEW_UNIT"
cat > "$WRAP.tmp" <<WRAPEOF
#!/bin/sh
# EXE-SOC agent diagnostics (installed by install_linux.sh). Usage: sudo exe-soc-agent-diag [--send-test-event] [--dashboard-user NAME]
set -a; . $ENVF; set +a
exec $PY $APP/exe_soc_diag.py "\$@"
WRAPEOF
chmod 0755 "$WRAP.tmp"; mv "$WRAP.tmp" "$WRAP"; ok "diagnostic command: sudo exe-soc-agent-diag"
systemctl enable "$SVC" >/dev/null 2>&1 || systemctl enable "$SVC"; T0=$(date +%s); systemctl restart "$SVC"; ok "service enabled (starts at boot) and started"

step "Waiting for the first heartbeat (up to 45 s)"
STATUS_F="$STATE_DIR/status.json"; GOOD=0
for _ in $(seq 1 45); do
  if systemctl is-active --quiet "$SVC" && [ -f "$STATUS_F" ] && [ "$(stat -c %Y "$STATUS_F")" -ge "$T0" ]; then GOOD=1; break; fi
  systemctl is-failed --quiet "$SVC" && break; sleep 1
done
if [ "$GOOD" = 1 ]; then ok "service is active and the server accepted the first heartbeat"; DONE=1
  PROBS=$("$PY" -c 'import json,sys; print("\n".join(json.load(open(sys.argv[1])).get("collector_errors") or []))' "$STATUS_F" 2>/dev/null || true)
  if [ -n "$PROBS" ]; then warn "the agent runs, but a log source is NOT delivering:"; printf '         - %s\n' "$PROBS" >&2; warn "run: sudo exe-soc-agent-diag    (explains each problem and the fix; the same message is shown on the dashboard's agent page)"; fi
else systemctl --no-pager --lines=15 status "$SVC" >&2 || true; die "the service did not deliver a heartbeat" "run: sudo exe-soc-agent-diag      (and: sudo journalctl -u $SVC -n 50 --no-pager)"; fi

cat <<EOF

Installed.  Status : sudo systemctl status $SVC --no-pager        Logs  : sudo journalctl -u $SVC -f
            Stop   : sudo systemctl stop $SVC                      Start : sudo systemctl start $SVC          Restart: sudo systemctl restart $SVC
            Doctor : sudo exe-soc-agent-diag [--send-test-event]  Remove: sudo $0 --uninstall   (then 'Revoke' this agent on the SOC Fleet page)
EOF
