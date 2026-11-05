#!/usr/bin/env bash
# EXE-SOC Linux agent uninstaller. Removes ONLY the agent's own resources:
#   the systemd service + unit, /opt/exe-soc-agent, /etc/exe-soc-agent, /var/lib/exe-soc-agent, the 'exe-soc-agent' account (only if the installer created it)
#   and /usr/local/sbin/exe-soc-agent-diag.
# It NEVER touches the SOC server: soc.db, .secret, certs/ and ca.key are not in any path used here.
#
#   sudo ./uninstall_linux.sh                 remove everything the agent installed
#   sudo ./uninstall_linux.sh --keep-data     keep /etc/exe-soc-agent and /var/lib/exe-soc-agent (credential, queue, file-integrity baseline)
# Afterwards, open the SOC dashboard > Fleet and press "Revoke" for this agent so its credential stops working.
set -euo pipefail
APP=/opt/exe-soc-agent; CONF_DIR=/etc/exe-soc-agent; STATE_DIR=/var/lib/exe-soc-agent; SVC=exe-soc-agent; SVC_USER=exe-soc-agent
UNIT=/etc/systemd/system/$SVC.service; WRAP=/usr/local/sbin/exe-soc-agent-diag; MARK=$APP/.installed-by-exe-soc
KEEP=0; for a in "$@"; do case "$a" in --keep-data) KEEP=1;; -h|--help) sed -n '2,10p' "$0" | sed 's/^# \{0,1\}//'; exit 0;; *) echo "unknown option: $a" >&2; exit 1;; esac; done
[ "$(id -u)" = 0 ] || { echo "ERROR: run as root: sudo $0" >&2; exit 1; }

removed=(); kept=()
# safety: only delete $APP when it carries the installer's marker (so a wrong/renamed folder is never wiped)
CREATED_USER=0
if [ -e "$APP" ] && [ ! -f "$MARK" ]; then echo "ERROR: $APP exists but is not marked as an EXE-SOC agent install ($MARK missing). Refusing to delete it." >&2; exit 1; fi
[ -f "$MARK" ] && grep -q '^created_user=1' "$MARK" && CREATED_USER=1

if command -v systemctl >/dev/null 2>&1; then
  if systemctl list-unit-files "$SVC.service" 2>/dev/null | grep -q "$SVC" || [ -f "$UNIT" ]; then
    systemctl disable --now "$SVC" >/dev/null 2>&1 || true; removed+=("service $SVC (stopped, disabled)"); fi
fi
if [ -f "$UNIT" ]; then rm -f -- "$UNIT"; removed+=("$UNIT"); fi
if command -v systemctl >/dev/null 2>&1; then systemctl daemon-reload >/dev/null 2>&1 || true; systemctl reset-failed "$SVC" >/dev/null 2>&1 || true; fi
if [ -f "$WRAP" ] && grep -q 'exe_soc_diag.py' "$WRAP"; then rm -f -- "$WRAP"; removed+=("$WRAP"); fi
if [ -d "$APP" ]; then rm -rf -- "${APP:?}"; removed+=("$APP"); fi
if [ "$KEEP" = 1 ]; then for d in "$CONF_DIR" "$STATE_DIR"; do [ -d "$d" ] && kept+=("$d (--keep-data)"); done
else for d in "$CONF_DIR" "$STATE_DIR"; do if [ -d "$d" ]; then rm -rf -- "${d:?}"; removed+=("$d"); fi; done; fi
if [ "$CREATED_USER" = 1 ] && id "$SVC_USER" >/dev/null 2>&1; then userdel "$SVC_USER" >/dev/null 2>&1 && removed+=("system user $SVC_USER") || echo "WARN: could not remove user $SVC_USER" >&2
elif id "$SVC_USER" >/dev/null 2>&1; then kept+=("user $SVC_USER (it was not created by this installer)"); fi

echo "EXE-SOC agent uninstall finished."
if [ ${#removed[@]} -gt 0 ]; then echo "Removed:"; printf '  - %s\n' "${removed[@]}"; else echo "Nothing to remove: the agent was not installed."; fi
[ ${#kept[@]} -gt 0 ] && { echo "Kept:"; printf '  - %s\n' "${kept[@]}"; }
echo "Not touched: everything else on this computer (and any SOC server database or certificates)."
echo "Next: on the SOC dashboard > Fleet, Revoke this agent so its credential can no longer be used."
