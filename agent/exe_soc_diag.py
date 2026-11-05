#!/usr/bin/env python3
"""EXE-SOC agent doctor: finds out WHY an agent is not installed, not connecting, or not showing on the dashboard.

  sudo exe-soc-agent-diag                                   # all checks (installed by install_linux.sh)
  sudo exe-soc-agent-diag --send-test-event                 # also sends ONE harmless, clearly-labelled test event
  EXESOC_DASH_PASSWORD=... sudo -E exe-soc-agent-diag --dashboard-user admin     # also confirm the dashboard sees this agent
  python3 exe_soc_diag.py --server https://SOC:5000 --ca-bundle ca.pem            # before enrolling: connectivity only

Read-only except: one authenticated heartbeat (harmless), and the optional test event. Secrets (credential, token, passwords, private keys) are never printed:
every line that comes from a log, a server answer or the config goes through redact()."""
import argparse, json, os, platform, re, shutil, subprocess, sys, time
HERE = os.path.dirname(os.path.abspath(__file__)); sys.path.insert(0, HERE)
SERVICE = "exe-soc-agent"; SVC_USER = "exe-soc-agent"
RX = [re.compile(r"cr-[0-9a-f]{12}\.[A-Za-z0-9_-]{20,}"), re.compile(r"exe-[A-Za-z0-9_-]{20,}"), re.compile(r"(?i)(bearer\s+)\S+"),
      re.compile(r"(?i)((?:password|passwd|token|secret|credential|api[_-]?key)\s*[=:]\s*)\S+"), re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----.*?(?:-----END [A-Z ]*PRIVATE KEY-----|$)", re.S)]
RESULTS = []

def redact(t):
    t = str(t)
    for r in RX: t = r.sub(lambda m: (m.group(1) if m.lastindex else "") + "[REDACTED]", t)
    return t

def out(status, name, detail="", fix=""):
    RESULTS.append(status); print(f"[{status}] {name}" + (f": {redact(detail)}" if detail else ""))
    if fix: print(f"       -> {redact(fix)}")

def sh(cmd, timeout=15):
    try:
        p = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout); return p.returncode, (p.stdout + p.stderr).strip()
    except FileNotFoundError: return 127, f"{cmd[0]}: not installed"
    except subprocess.TimeoutExpired: return 124, "timed out"

def os_info():
    try: d = dict(l.strip().split("=", 1) for l in open("/etc/os-release") if "=" in l)
    except OSError: d = {}
    name = d.get("PRETTY_NAME", "").strip('"') or platform.platform(); fam = (d.get("ID", "") + " " + d.get("ID_LIKE", "")).lower()
    ok = any(x in fam for x in ("debian", "ubuntu", "kali"))
    out("PASS" if ok else "WARN", "Linux distribution", f"{name} / kernel {platform.release()} / {platform.machine()}", "" if ok else "Only Debian-family systems (Kali, Ubuntu, Debian) are tested; others may work but are unsupported.")

def py_info():
    v = sys.version_info; venv = sys.prefix != getattr(sys, "base_prefix", sys.prefix)
    out("PASS" if v >= (3, 8) else "FAIL", "Python", f"{v.major}.{v.minor}.{v.micro} at {sys.executable}; virtual environment: {'yes' if venv else 'NO'}; running as uid {os.geteuid()}",
        "" if v >= (3, 8) else "Python 3.8 or newer is required.")
    if not venv: out("WARN", "Virtual environment", "not running inside a venv", "The installer uses /opt/exe-soc-agent/venv. Do not 'sudo pip install' system-wide (PEP 668).")

def deps():
    for m in ("requests", "psutil"):
        try: mod = __import__(m); out("PASS", f"import {m}", getattr(mod, "__version__", "ok"))
        except Exception as e: out("FAIL", f"import {m}", f"{e.__class__.__name__}: {e}", f"Re-run the installer (it rebuilds the venv):  sudo ./install_linux.sh ...   (venv: /opt/exe-soc-agent/venv)")

def config_check(A):
    p = A.CONF
    if not os.path.exists(p): out("FAIL", "Agent configuration", f"{p} does not exist", "This computer is not enrolled. Run the installer with --server/--token-file (see LINUX-AGENT-GUIDE.md)."); return None
    try: st = os.stat(p); mode = oct(st.st_mode & 0o777)[2:]
    except OSError as e: out("FAIL", "Agent configuration", str(e)); return None
    try: c = A.load_conf()
    except SystemExit as e: out("FAIL", "Agent configuration", str(e), "Run this tool with sudo (the file is owner-only)." if not os.geteuid() == 0 else ""); return None
    miss = [k for k in ("server", "agent_id", "credential", "hostname") if not (c or {}).get(k)]
    if miss: out("FAIL", "Agent configuration", f"missing fields: {', '.join(miss)}", "Enroll again (needs a new token): installer with --force-reenroll."); return None
    out("PASS" if st.st_mode & 0o077 == 0 else "FAIL", "Config file permissions", f"{p} mode {mode}, credential present (not shown)", "" if st.st_mode & 0o077 == 0 else f"chmod 600 {p}  (the credential must be owner-only)")
    out("PASS" if c["server"].lower().startswith("https://") else "FAIL", "Server URL", f"{c['server']} as agent '{c['hostname']}' ({c['agent_id']})", "" if c["server"].lower().startswith("https://") else "TLS is mandatory: use https://")
    return c

def ca_check(c):
    ca = c.get("ca_bundle")
    if not ca: out("PASS", "CA bundle", "none configured: using the system trust store (works for a public or enterprise-CA certificate)"); return
    if not os.path.isfile(ca): out("FAIL", "CA bundle", f"{ca} missing", "Copy the SOC's ca.pem there, or re-run the installer with --ca-bundle."); return
    try: import ssl; ssl.create_default_context(cafile=ca); n = open(ca).read().count("BEGIN CERTIFICATE"); out("PASS", "CA bundle", f"{ca}: {n} certificate(s), readable by uid {os.geteuid()}")
    except Exception as e: out("FAIL", "CA bundle", f"{ca}: {e.__class__.__name__}", "Use the ca.pem from the SOC (not server.pem / server.key).")

def connectivity(A, server, ca):
    ok = True
    for step, good, detail, fix in A.check_server_steps(server, ca): out("PASS" if good else "FAIL", f"Connectivity - {step}", detail, "" if good else fix); ok = ok and good
    return ok

def auth_and_heartbeat(A, c):
    """Authenticated heartbeat: proves the credential works, the clock is right and the server accepts this agent's payload."""
    cl = A.Client(c)
    try: r = cl.post("/api/agents/heartbeat", dict(A.host_info(), agent_version=A.VERSION, cpu=0, mem=0, events_queued=0, collectors=["diagnostic"]), timeout=15)
    except Exception as e: out("FAIL", "Authentication / heartbeat", A.explain(e, c["server"]) if hasattr(A, "explain") else str(e)); return False
    try: body = r.json()
    except ValueError: body = r.text[:200]
    if r.status_code == 200: out("PASS", "Authentication / heartbeat", f"HTTP 200, the server accepted this agent's credential (answer: {body})"); return True
    hint = {401: "The server does not know this credential (agent deleted, or the server DB was reset). Re-enroll with a new token.", 403: "The agent was REVOKED by the SOC admin. Ask them to issue a new token, then reinstall with --force-reenroll.",
            400: "Server rejected the request - if it mentions the timestamp, fix this computer's clock (timedatectl set-ntp true).", 429: "Rate limited; wait a minute."}.get(r.status_code, "See the server log.")
    out("FAIL", "Authentication / heartbeat", f"HTTP {r.status_code}: {body}", hint); return False

def service_check():
    if not shutil.which("systemctl"): out("SKIP", "systemd service", "systemctl not found (container?)"); return
    rc, act = sh(["systemctl", "is-active", SERVICE]); rc2, en = sh(["systemctl", "is-enabled", SERVICE])
    out("PASS" if act == "active" else "FAIL", f"Service {SERVICE}", f"active={act}, enabled={en}", "" if act == "active" else f"sudo systemctl status {SERVICE} --no-pager ; sudo journalctl -u {SERVICE} -n 50 --no-pager ; then: sudo systemctl restart {SERVICE}")
    rc, show = sh(["systemctl", "show", SERVICE, "-p", "User", "-p", "MainPID", "-p", "NRestarts", "-p", "ExecMainStatus", "-p", "Result"]); 
    if rc == 0: vals = dict(l.split("=", 1) for l in show.splitlines() if "=" in l); out("PASS" if vals.get("User") not in ("", "root", None) else "WARN", "Service identity", ", ".join(f"{k}={v}" for k, v in vals.items()), "" if vals.get("User") not in ("", "root", None) else "The service runs as root; the installer normally uses the unprivileged 'exe-soc-agent' user.")
    rc, logs = sh(["journalctl", "-u", SERVICE, "-n", "12", "--no-pager", "-o", "short-iso"])
    if rc == 0 and logs: print("       recent log lines (redacted):"); [print("         " + redact(l)[:200]) for l in logs.splitlines()[-12:]]
    elif rc != 0: out("WARN", "Service log", logs[:150], "Run with sudo, or add your user to the systemd-journal group.")

def status_file(A):
    p = A.STATUS
    try: d = json.load(open(p)); age = time.time() - os.stat(p).st_mtime
    except FileNotFoundError: out("FAIL", "Agent heartbeat status", f"{p} not found: the service has never completed a heartbeat", "Check the service log above (sudo journalctl -u exe-soc-agent -n 50)."); return
    except Exception as e: out("FAIL", "Agent heartbeat status", f"{p}: {e.__class__.__name__}", "Run with sudo."); return
    out("PASS" if age <= 90 else "WARN", "Agent heartbeat status", f"last successful heartbeat {int(age)}s ago; queued={d.get('events_queued')}, sent={d.get('events_sent')}, running as '{d.get('user')}'", "" if age <= 90 else "Older than 90 s: the service is stopped, stuck or cannot reach the server.")
    out("PASS" if d.get("collectors") else "WARN", "Collectors running", ", ".join(d.get("collectors") or []) or "none reported")
    for e in d.get("collector_errors") or []: out("WARN", "Log source problem (also shown on the dashboard)", e)
    if d.get("events_rejected"): out("WARN", "Server rejected events", f"{d['events_rejected']} event(s) were refused by the SOC", "Usually a wrong clock/timezone on this computer (events dated >10 min in the future are refused): timedatectl; sudo timedatectl set-ntp true")
    if d.get("events_sent") == 0 and age > 120: out("WARN", "No events delivered yet", "0 events sent since the service started", "A quiet machine can take minutes to log something. Test the pipeline now:  sudo exe-soc-agent-diag --send-test-event   (and  logger -p auth.notice test)")

def access_check():
    """What can the SERVICE actually read? Tested as the service user WITH the groups the systemd unit grants (adm, systemd-journal), because that is what the running agent has.
    No collector is claimed to work if it cannot read its source."""
    user = SVC_USER if os.geteuid() == 0 and sh(["id", "-u", SVC_USER])[0] == 0 else None
    grp = [x for g in ("systemd-journal", "adm") if sh(["getent", "group", g])[0] == 0 for x in ("-G", g)]
    def as_svc(cmd):
        if user and shutil.which("runuser"): return sh(["runuser", "-u", user, "-g", user] + grp + ["--"] + cmd)
        return sh(cmd)
    who = f"service user '{user}' (+groups {', '.join(grp[1::2]) or 'none'})" if user else f"uid {os.geteuid()}"
    for f, why in (("/var/log/auth.log", "SSH/sudo/login events (group adm)"), ("/var/log/syslog", "system log (group adm)"), ("/var/log/audit/audit.log", "auditd events (root only unless configured)"), ("/etc/shadow", "file-integrity monitoring of root-only files (needs --full-file-read)")):
        if os.path.exists(f):
            ok = as_svc(["test", "-r", f"{f}"])[0] == 0; out("PASS" if ok else "WARN", f"Read access {f}", f"{who} {'can' if ok else 'CANNOT'} read it - {why}", "" if ok else "Not an error if you do not need it. To grant read-only access to root-only files re-run the installer with --full-file-read.")
    if shutil.which("journalctl"):
        rc, txt = as_svc(["journalctl", "-n", "1", "-o", "json", "--no-pager"])
        if "not seeing messages" in txt: out("FAIL", "Read access systemd journal", f"{who} sees only its OWN messages, so NO system logs will be collected",
                                              f"sudo usermod -aG systemd-journal {SVC_USER} && sudo systemctl restart {SERVICE}   (the unit normally grants this via SupplementaryGroups: check `systemctl cat {SERVICE}` and that the group exists)")
        elif "No journal files" in txt and rc != 0: out("FAIL", "Read access systemd journal", f"{who}: {redact(txt)[:120]}", f"sudo usermod -aG systemd-journal {SVC_USER} && sudo systemctl restart {SERVICE}")
        elif "__CURSOR" in txt: out("PASS", "Read access systemd journal", f"{who} can read the system journal (latest entry visible)")
        elif rc == 0: out("WARN", "Read access systemd journal", "journal is readable but empty", "The agent then relies on log files (auth.log/syslog) if they exist.")
        else: out("WARN", "Read access systemd journal", redact(txt)[:120])
    elif not any(os.path.exists(f) for f in ("/var/log/auth.log", "/var/log/syslog", "/var/log/messages")): out("FAIL", "Log sources", "no journalctl and no auth.log/syslog/messages: there is nothing for the agent to read", "Install rsyslog (sudo apt install rsyslog) or use a systemd system.")

def send_test_event(A, c):
    from datetime import datetime, timezone
    e = A.to_event({"message": f"EXE-SOC diagnostic test event from {c['hostname']} (safe to ignore)", "channel": "exe-soc-diag", "level": "Information", "provider": "exe-soc-diag", "log_only": True,
                    "event_time": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%f")}, c["agent_id"]); e["record_id"] = int(time.time())
    try: r = A.Client(c).post("/api/events", {"events": [e]}, timeout=20)
    except Exception as ex: out("FAIL", "Telemetry ingestion", A.explain(ex, c["server"])); return False
    ok = r.status_code == 200 and (r.json().get("accepted") == 1)
    out("PASS" if ok else "FAIL", "Telemetry ingestion", f"HTTP {r.status_code}: {redact(r.text[:160])}", "" if ok else "The server did not accept the test event; check the server log."); return ok

def dashboard_check(A, c, user):
    import requests
    pw = os.environ.get("EXESOC_DASH_PASSWORD") or ""
    if not pw: out("SKIP", "Dashboard visibility", "set EXESOC_DASH_PASSWORD (and use sudo -E) to let the doctor log in and look", "Or open the dashboard > Fleet: this agent should be 'Online'."); return
    s = requests.Session(); s.trust_env = False; s.verify = c.get("ca_bundle") or True; s.headers["X-Requested-With"] = "fetch"
    try:
        s.post(c["server"].rstrip("/") + "/login", data={"username": user, "password": pw}, allow_redirects=False, timeout=15); r = s.get(c["server"].rstrip("/") + "/api/agents", timeout=15)
        if r.status_code != 200: out("FAIL", "Dashboard visibility", f"could not read /api/agents (HTTP {r.status_code}): wrong dashboard user/password?"); return
        me = next((a for a in r.json() if a.get("id") == c["agent_id"]), None)
    except Exception as e: out("FAIL", "Dashboard visibility", A.explain(e, c["server"])); return
    if not me: out("FAIL", "Dashboard visibility", f"agent {c['agent_id']} is not in the SOC's agent list", "The server database may have been reset: re-enroll."); return
    out("PASS" if me.get("state") == "online" else "WARN", "Dashboard visibility", f"listed as '{me.get('hostname')}', state={me.get('state')}, events stored={me.get('event_count')}, last heartbeat {me.get('last_heartbeat')}", "" if me.get("state") == "online" else "Not 'online': heartbeat older than 90 s or the agent reports problems (see the checks above).")

def hints(server):
    u = server or "https://SOC-SERVER:5000"; host = re.sub(r"^https?://|/.*$", "", u); h, _, port = host.partition(":"); port = port or "443"
    print(f"""
Useful commands
  agent (this computer):
    sudo systemctl status {SERVICE} --no-pager        sudo journalctl -u {SERVICE} -f        sudo systemctl restart {SERVICE}
    sudo ls -l /etc/exe-soc-agent /var/lib/exe-soc-agent        nc -vz {h} {port}        sudo ufw status verbose
    openssl s_client -connect {h}:{port} -servername {h} -CAfile /etc/exe-soc-agent/ca.pem </dev/null | head -20
  SOC server:
    sudo ss -ltnp | grep {port}                 (must show 0.0.0.0:{port} or the server's LAN IP, NOT 127.0.0.1)
    sudo ufw allow {port}/tcp                    (or your firewall's equivalent)         server log: the terminal / service journal where app.py runs""")

def main(argv=None):
    ap = argparse.ArgumentParser(description="EXE-SOC agent diagnostics"); ap.add_argument("--server"); ap.add_argument("--ca-bundle"); ap.add_argument("--send-test-event", action="store_true")
    ap.add_argument("--dashboard-user", help="SOC dashboard user (password from EXESOC_DASH_PASSWORD)"); a = ap.parse_args(argv)
    print(f"EXE-SOC agent diagnostics  ({time.strftime('%Y-%m-%d %H:%M:%S')})\n")
    os_info(); py_info(); deps()
    try: import exe_soc_agent as A
    except Exception as e: out("FAIL", "Import agent", f"{e.__class__.__name__}: {e}", "Reinstall the agent."); return 1
    c = config_check(A) if not a.server else None
    if c: ca_check(c)
    server = a.server or (c or {}).get("server"); ca = a.ca_bundle or (c or {}).get("ca_bundle")
    reach = connectivity(A, server, ca) if server else (out("SKIP", "Connectivity", "no server known (not enrolled and no --server given)"), False)[1]
    if c and reach:
        if auth_and_heartbeat(A, c):
            if a.send_test_event: send_test_event(A, c)
            else: out("SKIP", "Telemetry ingestion", "run with --send-test-event to send one harmless labelled event")
            if a.dashboard_user: dashboard_check(A, c, a.dashboard_user)
            else: out("SKIP", "Dashboard visibility", "use --dashboard-user NAME with EXESOC_DASH_PASSWORD, or open dashboard > Fleet")
    if not a.server: service_check(); status_file(A); access_check()
    hints(server)
    bad = RESULTS.count("FAIL"); print(f"\nSummary: {RESULTS.count('PASS')} passed, {RESULTS.count('WARN')} warnings, {bad} failed, {RESULTS.count('SKIP')} skipped"); return 1 if bad else 0

if __name__ == "__main__": sys.exit(main())
