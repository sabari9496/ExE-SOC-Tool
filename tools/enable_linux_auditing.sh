#!/bin/sh
# OPTIONAL: installs auditd and logs every program execution, so EXE-SOC sees even very short-lived processes. Run with sudo.
# (Without it EXE-SOC still sees processes by polling every 2 seconds.)  It creates a lot of log lines on busy servers.
set -e
[ "$(id -u)" = 0 ] || { echo "Run with sudo"; exit 1; }
if command -v apt-get >/dev/null; then apt-get install -y auditd; elif command -v dnf >/dev/null; then dnf install -y audit; elif command -v yum >/dev/null; then yum install -y audit; fi
cat > /etc/audit/rules.d/exesoc.rules <<'RULES'
-a always,exit -F arch=b64 -S execve -k exesoc_exec
-a always,exit -F arch=b32 -S execve -k exesoc_exec
RULES
augenrules --load 2>/dev/null || auditctl -R /etc/audit/rules.d/exesoc.rules
systemctl enable --now auditd 2>/dev/null || true
echo "auditd is logging program executions to /var/log/audit/audit.log (collected automatically by EXE-SOC)."
