#!/usr/bin/env python3
"""Linux agent installer / enrollment / diagnostics / server-startup tests.   Run as root on a disposable Linux box or container:  sudo python3 tests/test_linux_agent.py

Real: TLS server (private CA, temp DB, own port), the real installer + uninstaller + agent + doctor, real user creation, real files under /opt /etc /var/lib.
Stand-in: systemctl (tests/fake_systemctl.py) - it runs the unit file the installer wrote as the unit's User/Group. NOT covered here: systemd itself (sandboxing
directives, boot ordering, reboot persistence), real journald/auth.log on Kali/Ubuntu, apt-get, pip downloads without network. See LINUX-AGENT-GUIDE.md > Test results."""
import hashlib, http.server, json, os, shutil, ssl, subprocess, sys, tempfile, threading, time, datetime, ipaddress, pwd
ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if os.geteuid() != 0: sys.exit("run as root (the installer creates a system user and writes /opt, /etc, /var/lib)")
T = tempfile.mkdtemp(prefix="exesoc-lt-"); os.chmod(T, 0o755); PORT = 5651; B = f"https://localhost:{PORT}"
AG = os.path.join(T, "agent"); shutil.copytree(os.path.join(ROOT, "agent"), AG, ignore=shutil.ignore_patterns("__pycache__")); INST = AG + "/install_linux.sh"; UNINST = AG + "/uninstall_linux.sh"
FS = T + "/fakesystemd"; BIN = T + "/bin"; os.makedirs(BIN); open(BIN + "/systemctl", "w").write(f'#!/bin/sh\nexec python3 {ROOT}/tests/fake_systemctl.py "$@"\n'); os.chmod(BIN + "/systemctl", 0o755)
ENV = dict(os.environ, PATH=BIN + ":" + os.environ["PATH"], EXESOC_ASSUME_SYSTEMD="1", PIP_RETRIES="0", FAKE_SYSTEMD_STATE=FS, PIP_DEFAULT_TIMEOUT="3")
ENV.pop("EXESOC_ENROLL_TOKEN", None)
APP, CONFD, STATED, UNIT, WRAP = "/opt/exe-soc-agent", "/etc/exe-soc-agent", "/var/lib/exe-soc-agent", "/etc/systemd/system/exe-soc-agent.service", "/usr/local/sbin/exe-soc-agent-diag"
R = []
def check(name, ok, info=""):
    R.append(bool(ok)); print(("PASS " if ok else "FAIL ") + name + ("" if ok else f"\n       {str(info)[-600:]}"), flush=True)
def sh(cmd, env=None, user=None, stdin="", timeout=180, cwd=None):
    if user: cmd = ["runuser", "-u", user, "--"] + cmd
    p = subprocess.run(cmd, env=env or ENV, input=stdin, capture_output=True, text=True, timeout=timeout, cwd=cwd); return p.returncode, p.stdout + p.stderr
def user_exists(u="exe-soc-agent"):
    try: pwd.getpwnam(u); return True
    except KeyError: return False
def no_changes(): return not any(os.path.exists(p) for p in (APP, CONFD, STATED, UNIT, WRAP)) and not user_exists()
def wait_for(fn, t=40, step=0.5):
    end = time.time() + t
    while time.time() < end:
        try:
            r = fn()
            if r: return r
        except Exception: pass
        time.sleep(step)
    return None
def wipe():
    if os.path.exists(UNINST): sh(["bash", UNINST], timeout=60)
    for p in (APP, CONFD, STATED, UNIT, WRAP): shutil.rmtree(p, ignore_errors=True) if os.path.isdir(p) else (os.path.exists(p) and os.remove(p))
    if user_exists(): sh(["userdel", "exe-soc-agent"])
    shutil.rmtree(FS, ignore_errors=True)
def sha(p): return hashlib.sha256(open(p, "rb").read()).hexdigest()
def dbfp(p):
    """Stable fingerprint of the LIVE server DB: integrity_check result + user count (a byte hash of a WAL database changes at every checkpoint, which made this check flaky)."""
    import sqlite3; c = sqlite3.connect("file:" + p + "?mode=ro", uri=True, timeout=10)
    try: return (c.execute("PRAGMA integrity_check").fetchone()[0], c.execute("SELECT COUNT(*) FROM users").fetchone()[0])
    finally: c.close()

if not user_exists("soctest"): sh(["useradd", "-m", "soctest"])
sh(["python3", ROOT + "/tools/dev_certs.py", "--out", T + "/certs", "--name", "localhost"]); sh(["python3", ROOT + "/tools/dev_certs.py", "--out", T + "/otherca", "--name", "localhost"]); CA = T + "/certs/ca.pem"
os.chmod(T + "/certs", 0o755)
srvenv = dict(os.environ, SOC_DB=T + "/t.db", SOC_PORT=str(PORT), SOC_TLS_CERT=T + "/certs/server.pem", SOC_TLS_KEY=T + "/certs/server.key", SOC_LOCAL_LOGS="0", SOC_SECRET="x" * 32, SOC_ALLOW_FOREIGN_DB="1")
srv = subprocess.Popen([sys.executable, "-W", "ignore", "app.py"], cwd=ROOT, env=srvenv, stdout=open(T + "/srv.log", "w"), stderr=subprocess.STDOUT, start_new_session=True)
import requests; requests.packages.urllib3.disable_warnings()
def mk_session():
    s = requests.Session(); s.trust_env = False; s.verify = CA; s.headers["X-Requested-With"] = "fetch"; return s
admin = mk_session(); cleanup_extra = []
try:
    for _ in range(60):
        try: requests.get(B + "/login", verify=CA, timeout=1); break
        except Exception: time.sleep(0.5)
    admin.post(B + "/login", data={"username": "admin", "password": "Admin@123"}, allow_redirects=False)
    n_tok = [0]
    def new_token():
        n_tok[0] += 1; label = f"lt{n_tok[0]}"; t = admin.post(B + "/api/enrollment-tokens", json={"label": label, "expires_minutes": 30}).json()["token"]; return t, label
    def tok_state(label): return next((x["state"] for x in admin.get(B + "/api/enrollment-tokens").json() if x["label"] == label), None)
    def tokfile(t): p = T + "/token.txt"; open(p, "w").write(t + "\n"); os.chmod(p, 0o644); return p
    def agents(): return admin.get(B + "/api/agents").json()
    SRV = ["--server", B, "--ca-bundle", CA]
    def inst(*a, tok=None, **kw):
        args = list(a) + (["--token-file", tokfile(tok)] if tok else []); return sh(["bash", INST] + args, **kw)

    print("== A. server startup (independent of the agent) ==")
    log = open(T + "/srv.log").read()
    check("A1 banner shows https:// when TLS is on", f"SOC running at https://127.0.0.1:{PORT}" in log, log[-400:])
    check("A2 banner warns that 127.0.0.1 is local-only (remote agents cannot connect)", "listening on THIS computer only" in log)
    try: requests.get(f"http://localhost:{PORT}/login", timeout=4); reset = False
    except requests.exceptions.RequestException: reset = True
    check("A3 plain http:// to the TLS port is refused/reset (documented cause of browser 'connection reset')", reset)
    d = tempfile.mkdtemp(dir=T); os.chmod(d, 0o755); shutil.copytree(ROOT, d + "/s", ignore=shutil.ignore_patterns("__pycache__", "soc.db*", ".secret", ".venv", "certs")); sh(["python3", "-W", "ignore", "app.py"], cwd=d + "/s", env=dict(os.environ, SOC_PORT="5659", SOC_LOCAL_LOGS="0"), timeout=8) if False else None
    # create the files as root exactly like `sudo ./run.sh`, then start as another user
    pr = subprocess.Popen([sys.executable, "-W", "ignore", "app.py"], cwd=d + "/s", env=dict(os.environ, SOC_PORT="5659", SOC_LOCAL_LOGS="0"), stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, start_new_session=True)
    wait_for(lambda: os.path.exists(d + "/s/soc.db") and os.path.exists(d + "/s/.secret"), 20); time.sleep(2); pr.terminate(); pr.wait(); sh(["chmod", "-R", "a+rX", d])
    rc, out = sh([sys.executable, "-W", "ignore", "app.py"], user="soctest", cwd=d + "/s", env=dict(os.environ, SOC_PORT="5660", SOC_LOCAL_LOGS="0"), timeout=20)
    check("A4 root-created DB then non-root start: clear message + fix, no traceback", rc == 2 and "chown -R soctest" in out and "Traceback" not in out and "readonly database" not in out, out[-500:])
    rc, out = sh(["bash", ROOT + "/run.sh"], user="soctest", cwd=d + "/s", timeout=20); check("A5 run.sh as non-root over root-owned files stops with the same fix", rc == 2 and "chown -R soctest" in out, out[-400:])
    cc = dict(os.environ, SOC_PORT="5661", SOC_LOCAL_LOGS="0", SOC_DB=d + "/x.db", SOC_TLS_CERT="/nonexistent.pem", SOC_TLS_KEY="/nonexistent.key", SOC_SECRET="y" * 32)
    rc, out = sh([sys.executable, "-W", "ignore", "app.py"], cwd=ROOT, env=cc, timeout=20); check("A6 missing TLS cert file: clear message", rc != 0 and "SOC_TLS_CERT" in out and "dev_certs.py" in out and "Traceback" not in out, out[-300:])

    print("== B. agent enrollment CLI ==")
    tk, lb = new_token(); AH = T + "/ah"; ae = dict(ENV, EXESOC_AGENT_HOME=AH, EXESOC_AGENT_CONF=AH + "/conf/agent.json"); AGPY = [sys.executable, "-W", "ignore", AG + "/exe_soc_agent.py"]
    rc, out = sh(AGPY + ["enroll", "--accept", "--server", B, "--ca-bundle", CA, "--token", "exe-bogus"], env=ae); check("B1 invalid token: clear message, no traceback", rc != 0 and "rejected the enrollment token" in out and "Traceback" not in out, out)
    os.makedirs(T + "/rodir", exist_ok=True); os.chmod(T + "/rodir", 0o755); ro = dict(ae, EXESOC_AGENT_HOME=T + "/rodir/h", EXESOC_AGENT_CONF=T + "/rodir/h/agent.json")
    rc, out = sh(AGPY + ["enroll", "--accept", "--server", B, "--ca-bundle", CA, "--token", tk], env=ro, user="soctest"); check("B2 unwritable config folder: fails BEFORE the single-use token is spent", rc != 0 and "NOT used up" in out and tok_state(lb) == "active", out)
    rc, out = sh(AGPY + ["enroll", "--accept", "--server", B, "--ca-bundle", CA, "--token", tk, "--name", "lt-box.01"], env=ae); check("B3 successful enrollment with --name", rc == 0 and "Enrolled as lt-box.01" in out, out)
    c1 = json.load(open(AH + "/conf/agent.json")); check("B4 credential file is owner-only (0600) and token not stored", oct(os.stat(AH + "/conf/agent.json").st_mode & 0o777) == "0o600" and tk not in open(AH + "/conf/agent.json").read())
    tk2, lb2 = new_token(); rc, out = sh(AGPY + ["enroll", "--accept", "--server", B, "--ca-bundle", CA, "--token", tk2], env=ae)
    check("B5 enrolling again does NOT overwrite the credential and does not spend the new token", rc == 0 and "Already enrolled" in out and json.load(open(AH + "/conf/agent.json")) == c1 and tok_state(lb2) == "active", out)
    rc, out = sh(AGPY + ["enroll", "--server", B, "--ca-bundle", CA, "--token", tk2, "--force"], env=ae, stdin=""); check("B6 no terminal and no --accept: clear consent message (no EOFError traceback)", rc != 0 and "no terminal" in out and "EOFError" not in out, out)
    rc, out = sh(AGPY + ["enroll", "--accept", "--server", B, "--ca-bundle", CA, "--token-file", tokfile(tk2), "--force"], env=ae); check("B7 --force re-enrolls with a new token (token via file)", rc == 0 and json.load(open(AH + "/conf/agent.json"))["agent_id"] != c1["agent_id"], out)
    rc, out = sh(AGPY + ["run"], env=dict(ae, EXESOC_AGENT_CONF=AH + "/none.json"), timeout=20); check("B8 `run` without enrollment exits with the configuration code 4", rc == 4 and "Not enrolled" in out, out)

    print("== C. installer: failures must change NOTHING and not burn the token ==")
    wipe(); tk, lb = new_token(); good_args = SRV + ["--accept-consent", "--system-packages"]
    rc, out = sh(["bash", INST, "--check-only"] + SRV, user="soctest"); check("C1 --check-only works for a normal user and changes nothing", rc == 0 and "Nothing was changed" in out and no_changes(), out)
    rc, out = sh(["bash", INST] + good_args, user="soctest", stdin=""); check("C2 non-root refused with the sudo explanation", rc != 0 and "must run as root" in out and no_changes(), out)
    rc, out = inst("--accept-consent", tok=tk); check("C3 no server given", rc != 0 and "no SOC server" in out and no_changes(), out)
    rc, out = inst(*SRV, "--accept-consent"); check("C4 no token (no terminal)", rc != 0 and "no enrollment token" in out and no_changes(), out)
    rc, out = inst(*SRV, tok=tk); check("C5 no consent flag (no terminal)", rc != 0 and "no terminal to ask for consent" in out and no_changes(), out)
    rc, out = inst("--host", "localhost", "--port", "99999", "--accept-consent", tok=tk); check("C6 invalid port", rc != 0 and "invalid port" in out and no_changes(), out)
    rc, out = inst("--server", f"http://localhost:{PORT}", "--ca-bundle", CA, "--accept-consent", tok=tk); check("C7 http:// refused (TLS mandatory)", rc != 0 and "https://" in out and no_changes(), out)
    rc, out = inst("--server", f"https://no-such-host.invalid:{PORT}", "--accept-consent", tok=tk); check("C8 invalid server name (DNS)", rc != 0 and "Cannot resolve" in out and no_changes(), out)
    rc, out = inst("--server", "https://localhost:5999", "--ca-bundle", CA, "--accept-consent", tok=tk); check("C9 server unavailable / wrong port", rc != 0 and "Connection refused" in out and "SOC_HOST=0.0.0.0" in out and no_changes(), out)
    rc, out = inst("--server", B, "--ca-bundle", T + "/nope.pem", "--accept-consent", tok=tk); check("C10 CA bundle missing", rc != 0 and "CA bundle not found" in out and no_changes(), out)
    rc, out = inst("--server", B, "--ca-bundle", T + "/certs/server.key", "--accept-consent", tok=tk); check("C11 CA bundle is not a certificate", rc != 0 and "not a valid PEM" in out and no_changes(), out)
    rc, out = inst("--server", B, "--ca-bundle", T + "/otherca/ca.pem", "--accept-consent", tok=tk); check("C12 wrong CA -> TLS verification failure (never bypassed)", rc != 0 and "not trusted" in out and no_changes(), out)
    rc, out = inst("--server", B, "--accept-consent", tok=tk); check("C13 private CA but no --ca-bundle -> TLS verification failure", rc != 0 and "not trusted" in out and no_changes(), out)
    # hostname mismatch + plain-http server (stdlib servers)
    from cryptography import x509; from cryptography.x509.oid import NameOID; from cryptography.hazmat.primitives import hashes, serialization; from cryptography.hazmat.primitives.asymmetric import ec
    k = ec.generate_private_key(ec.SECP256R1()); nm = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "other.example")]); now = datetime.datetime.now(datetime.timezone.utc)
    crt = (x509.CertificateBuilder().subject_name(nm).issuer_name(nm).public_key(k.public_key()).serial_number(x509.random_serial_number()).not_valid_before(now - datetime.timedelta(minutes=5)).not_valid_after(now + datetime.timedelta(days=30))
           .add_extension(x509.SubjectAlternativeName([x509.DNSName("other.example")]), False).add_extension(x509.BasicConstraints(ca=True, path_length=None), True).sign(k, hashes.SHA256()))
    open(T + "/mm.pem", "wb").write(crt.public_bytes(serialization.Encoding.PEM)); open(T + "/mm.key", "wb").write(k.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()))
    class H(http.server.BaseHTTPRequestHandler):
        def do_GET(self): self.send_response(200); self.end_headers(); self.wfile.write(b"ok")
        def log_message(self, *a): pass
    s1 = http.server.HTTPServer(("127.0.0.1", 5655), H); ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER); ctx.load_cert_chain(T + "/mm.pem", T + "/mm.key"); s1.socket = ctx.wrap_socket(s1.socket, server_side=True)
    s2 = http.server.HTTPServer(("127.0.0.1", 5656), H)
    for s in (s1, s2): threading.Thread(target=s.serve_forever, daemon=True).start()
    rc, out = inst("--server", "https://localhost:5655", "--ca-bundle", T + "/mm.pem", "--accept-consent", tok=tk); check("C14 certificate not valid for the name used (SAN mismatch)", rc != 0 and "not valid for 'localhost'" in out and "dev_certs.py" in out and no_changes(), out)
    rc, out = inst("--server", "https://localhost:5656", "--ca-bundle", CA, "--accept-consent", tok=tk); check("C15 server runs plain HTTP on that port (HTTP/HTTPS mismatch)", rc != 0 and "not speaking HTTPS" in out and no_changes(), out)
    check("C16 the enrollment token was never spent by any of the failures above", tok_state(lb) == "active")
    rc, out = inst(*SRV, "--accept-consent", "--system-packages", tok="exe-bogus-token-value"); check("C17 invalid token: clear message and everything rolled back", rc != 0 and "rejected the enrollment token" in out and "rolling back" in out and no_changes(), out)
    tk3, lb3 = new_token(); rc, out = inst(*SRV, "--accept-consent", tok=tk3)          # no --system-packages: pip needs a network
    if rc != 0: check("C18 dependency (pip) failure: actionable message and full rollback", "pip could not install" in out and "--system-packages" in out and no_changes() and tok_state(lb3) == "active", out)
    else: check("C18 pip succeeded (network available): pip path works", os.path.exists(APP + "/venv/bin/pip")); wipe(); tk3, lb3 = new_token()
    rc, out = inst(*SRV, "--accept-consent", "--system-packages", "--name", "bad/name", tok=tk3); check("C19 invalid --name rejected before any change", rc != 0 and "--name may only" in out and no_changes(), out)

    print("== D. installation, service, least privilege ==")
    wipe(); tk, lb = new_token(); rc, out = inst(*SRV, "--accept-consent", "--system-packages", "--name", "lt-linux-1", tok=tk)
    check("D1 install succeeds and the first heartbeat is confirmed", rc == 0 and "server accepted the first heartbeat" in out, out)
    ent = pwd.getpwnam("exe-soc-agent") if user_exists() else None
    check("D2 dedicated service user: system account, no login shell, not root", bool(ent) and ent.pw_uid != 0 and ent.pw_uid < 1000 and ent.pw_shell.endswith("nologin"))
    unit = open(UNIT).read() if os.path.exists(UNIT) else ""
    check("D3 unit: User=exe-soc-agent, non-root, hardened, no restart loop on revoke/config errors", all(x in unit for x in ("User=exe-soc-agent", "RestartPreventExitStatus=3 4", "NoNewPrivileges=yes", "Restart=on-failure", "WantedBy=multi-user.target", "WorkingDirectory=/opt/exe-soc-agent")) and "User=root" not in unit and "CAP_DAC_READ_SEARCH" not in unit, unit)
    rc, out = sh(["systemd-analyze", "verify", UNIT]); check("D4 unit file passes systemd-analyze verify", rc == 0 and "Unknown key" not in out and "Failed" not in out, out) if shutil.which("systemd-analyze") else print("SKIP D4 systemd-analyze not installed")
    st = os.stat(CONFD + "/agent.json"); check("D5 credential file: owner exe-soc-agent, mode 0600", st.st_uid == ent.pw_uid and oct(st.st_mode & 0o777) == "0o600")
    check("D6 state dir 0700 owned by the service user; program dir owned by root", os.stat(STATED).st_uid == ent.pw_uid and oct(os.stat(STATED).st_mode & 0o777) == "0o700" and os.stat(APP).st_uid == 0)
    rc, _ = sh(["test", "-w", APP + "/exe_soc_agent.py"], user="exe-soc-agent"); check("D7 the agent cannot modify its own code", rc != 0)
    leak = subprocess.run(["grep", "-rIl", tk, CONFD, APP, STATED, "/etc/systemd/system"], capture_output=True, text=True).stdout.strip(); check("D8 enrollment token is not stored anywhere", leak == "", leak)
    cr = json.load(open(CONFD + "/agent.json")); aid = cr["agent_id"]
    me = wait_for(lambda: next((a for a in agents() if a["id"] == aid and a["state"] == "online"), None)); check("D9 dashboard lists the agent as online with the chosen name", me and me["hostname"] == "lt-linux-1", me)
    stj = json.load(open(STATED + "/status.json")); check("D10 service process runs as exe-soc-agent (status file) and reports collectors", stj["user"] == "exe-soc-agent" and len(stj["collectors"]) > 0, stj)
    check("D11 token consumed exactly once", tok_state(lb) == "used")

    print("== E. telemetry, restart, re-run ==")
    lg = T + "/auth_test.log"; open(lg, "w").write(""); os.chmod(lg, 0o644)
    envf = open(CONFD + "/agent.env").read() + f"SOC_LINUX_FILES={lg}\nSOC_LINUX_JOURNAL=0\nSOC_FIM=0\nSOC_MALWARE=0\nSOC_ACTIVITY=0\n"; open(CONFD + "/agent.env", "w").write(envf)
    pid0 = stj["pid"]; sh(["systemctl", "restart", "exe-soc-agent"])
    check("E1 service restart: new process, same credential, heartbeat resumes", wait_for(lambda: json.load(open(STATED + "/status.json"))["pid"] != pid0 and (time.time() - os.stat(STATED + "/status.json").st_mtime) < 20, 40) and json.load(open(CONFD + "/agent.json"))["agent_id"] == aid)
    time.sleep(4); ev0 = next(a for a in agents() if a["id"] == aid)["event_count"]
    with open(lg, "a") as f:
        for i in range(6): f.write(f"{time.strftime('%b %e %H:%M:%S')} lt-linux-1 sshd[200{i}]: Failed password for invalid user admin from 203.0.113.9 port 4{i}42 ssh2\n")      # current time: the server rejects events dated >10 min in the future
    got = wait_for(lambda: next(a for a in agents() if a["id"] == aid)["event_count"] > ev0, 45)
    check("E2 telemetry: log lines written on the endpoint arrive on the SOC dashboard", got, next(a for a in agents() if a["id"] == aid)); evs = admin.get(B + f"/api/agents/{aid}/events?limit=50").json()
    check("E3 events carry the right host and content", any("Failed password" in e["message"] and e["host"] == "lt-linux-1" for e in evs), evs[:2])
    check("E4 brute-force detection raised an alert for that endpoint", wait_for(lambda: next(a for a in agents() if a["id"] == aid)["alert_count"] >= 1, 30))
    sc, cs = sha(CONFD + "/agent.json"), sha(UNIT); rc, out = inst(*SRV, "--accept-consent", "--system-packages")
    check("E5 re-running the installer (no token): succeeds, credential and unit unchanged", rc == 0 and "already enrolled" in out and sha(CONFD + "/agent.json") == sc and sha(UNIT) == cs, out)
    n_units = len([f for f in os.listdir("/etc/systemd/system") if f.startswith("exe-soc-agent")]); n_ag = len([a for a in agents() if a["id"] == aid])
    check("E6 re-run created no duplicates (one unit, one account, one agent entry)", n_units == 1 and n_ag == 1 and len([p for p in pwd.getpwall() if p.pw_name == "exe-soc-agent"]) == 1)
    check("E7 service still active after re-run and the account is still recorded as installer-created", sh(["systemctl", "is-active", "--quiet", "exe-soc-agent"])[0] == 0 and "created_user=1" in open(APP + "/.installed-by-exe-soc").read())
    rc, out = inst("--server", "https://localhost:5999", "--ca-bundle", CA, "--accept-consent"); check("E8 re-run pointing at a different server is refused (no silent re-enroll)", rc != 0 and "already enrolled" in out and sha(CONFD + "/agent.json") == sc, out)
    check("E9 service is enabled for boot (reboot itself NOT testable here)", os.path.exists(FS + "/exe-soc-agent.enabled") and "WantedBy=multi-user.target" in unit)

    print("== F. diagnostics ==")
    secret = cr["credential"].split(".", 1)[1]; rc, out = sh([WRAP, "--send-test-event", "--dashboard-user", "admin"], env=dict(ENV, EXESOC_DASH_PASSWORD="Admin@123"))
    check("F1 doctor passes on a healthy install (no FAIL), incl. ingestion + dashboard visibility", rc == 0 and "0 failed" in out and "[PASS] Telemetry ingestion" in out and "[PASS] Dashboard visibility" in out, out)
    check("F2 doctor output never contains the credential, token or password", secret not in out and tk not in out and "Admin@123" not in out and "BEGIN" not in out)
    check("F3 doctor shows the service identity and heartbeat age", "User=exe-soc-agent" in out and "Agent heartbeat status" in out)
    os.rename(CA, CA + ".bak"); shutil.copy(T + "/otherca/ca.pem", CA); sh(["cp", CA, CONFD + "/ca.pem"]); rc, out = sh([WRAP]); shutil.copy(CA + ".bak", CA); sh(["cp", CA, CONFD + "/ca.pem"]); os.remove(CA + ".bak")
    check("F4 doctor pinpoints a TLS/CA problem with the fix", rc == 1 and "[FAIL] Connectivity - TLS certificate" in out and "not trusted" in out, out[-700:])

    print("== G. revoke, uninstall, migration ==")
    admin.post(B + f"/api/agents/{aid}/revoke", json={}); ok = wait_for(lambda: open(FS + "/exe-soc-agent.exit").read().strip() == "3", 45); time.sleep(4)
    check("G1 revoked agent exits with code 3 and is NOT restarted (no restart loop)", ok and sh(["systemctl", "is-active", "--quiet", "exe-soc-agent"])[0] != 0, open(FS + "/exe-soc-agent.log").read()[-300:])
    os.makedirs("/opt/exe-soc-unrelated", exist_ok=True); open("/opt/exe-soc-unrelated/keep.txt", "w").write("x"); open("/etc/exe-soc-unrelated.conf", "w").write("x"); h0 = (dbfp(T + "/t.db"), sha(T + "/certs/server.key"), sha(CA))
    rc, out = sh(["bash", INST, "--uninstall", "--keep-data"]); check("G2 uninstall --keep-data removes service/program but keeps config and state", rc == 0 and not os.path.exists(APP) and not os.path.exists(UNIT) and not os.path.exists(WRAP) and os.path.isdir(CONFD) and os.path.isdir(STATED), out)
    rc, out = sh(["bash", UNINST]); check("G3 full uninstall removes every agent resource incl. the account", rc == 0 and not any(os.path.exists(p) for p in (APP, CONFD, STATED, UNIT, WRAP)) and not user_exists(), out)
    check("G4 unrelated files are preserved; server DB and certificates are untouched", os.path.exists("/opt/exe-soc-unrelated/keep.txt") and os.path.exists("/etc/exe-soc-unrelated.conf") and h0 == (dbfp(T + "/t.db"), sha(T + "/certs/server.key"), sha(CA)))
    rc, out = sh(["bash", UNINST]); check("G5 uninstall is idempotent (second run is clean)", rc == 0 and "Nothing to remove" in out, out)
    os.makedirs(APP); open(APP + "/precious.txt", "w").write("x"); rc, out = sh(["bash", UNINST]); check("G6 uninstall refuses to delete a folder it did not install", rc != 0 and os.path.exists(APP + "/precious.txt") and "Refusing" in out, out); shutil.rmtree(APP)
    shutil.rmtree("/opt/exe-soc-unrelated"); os.remove("/etc/exe-soc-unrelated.conf")
    # upgrade from the previous installer's layout: credential in /var/lib/exe-soc-agent/agent.json must be migrated, not burned
    tk, lb = new_token(); oldca = T + "/oldca.pem"; shutil.copy(CA, oldca); oe = dict(ENV, EXESOC_AGENT_HOME=STATED); os.environ.pop("EXESOC_AGENT_CONF", None)
    rc, out = sh(AGPY + ["enroll", "--accept", "--server", B, "--ca-bundle", oldca, "--token", tk], env=oe); old_id = json.load(open(STATED + "/agent.json"))["agent_id"] if rc == 0 else None
    rc, out = inst(*SRV, "--accept-consent", "--system-packages")
    check("G7 upgrade: credential from the old installer is migrated (no new token needed) and the agent comes online", rc == 0 and "migrated" in out and json.load(open(CONFD + "/agent.json"))["agent_id"] == old_id and not os.path.exists(STATED + "/agent.json") and wait_for(lambda: next((a for a in agents() if a["id"] == old_id and a["state"] == "online"), None)), out)
    sh(["bash", UNINST]); wipe()
finally:
    try: wipe()
    except Exception: pass
    srv.terminate()
    shutil.rmtree(T, ignore_errors=True)
print(f"\n{sum(R)}/{len(R)} passed"); sys.exit(0 if all(R) else 1)
