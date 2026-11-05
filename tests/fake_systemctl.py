#!/usr/bin/env python3
"""Test stand-in for systemctl (this sandbox has no systemd as PID 1). It reads the REAL unit file the installer wrote and runs ExecStart as the unit's
User=/Group=/SupplementaryGroups= with its EnvironmentFile=, honouring Restart=on-failure and RestartPreventExitStatus=. It does NOT test systemd itself
(sandboxing directives, boot ordering, reboot persistence): those need a real systemd host."""
import os, sys, time, subprocess, signal
ST = os.environ.get("FAKE_SYSTEMD_STATE", "/tmp/exesoc-fake-systemd"); os.makedirs(ST, exist_ok=True); UD = "/etc/systemd/system"
def unitfile(n): return f"{UD}/{n}.service"
def parse(n):
    d = {}
    for l in open(unitfile(n)):
        l = l.strip()
        if "=" in l and not l.startswith(("#", "[")): k, v = l.split("=", 1); d.setdefault(k, []).append(v)
    return d
def rd(n, ext):
    try: return open(f"{ST}/{n}.{ext}").read().strip()
    except OSError: return ""
def alive(pid):
    try: os.kill(int(pid), 0); return open(f"/proc/{pid}/stat").read().split()[2] != "Z"
    except (OSError, ValueError, IndexError): return False
def stop(n):
    sup = rd(n, "sup")
    for f in (sup, rd(n, "pid")):
        if f and alive(f):
            try: os.kill(int(f), signal.SIGTERM)
            except OSError: pass
    for _ in range(50):
        if not alive(rd(n, "pid")) and not alive(sup): break
        time.sleep(0.1)
    try: u = parse(n)["User"][0]; subprocess.run(["pkill", "-TERM", "-u", u], capture_output=True); time.sleep(0.3)      # real systemd kills the whole cgroup, not just the main PID
    except (OSError, KeyError): pass
def start(n):
    stop(n); open(f"{ST}/{n}.exit", "w").write("")
    subprocess.Popen([sys.executable, __file__, "_supervise", n], stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, start_new_session=True)
    for _ in range(50):
        if alive(rd(n, "pid")): break
        time.sleep(0.1)
def supervise(n):
    open(f"{ST}/{n}.sup", "w").write(str(os.getpid())); u = parse(n); tries = 0
    env = {"PATH": os.environ.get("PATH", "/usr/bin:/bin"), "HOME": "/nonexistent"}
    for ef in u.get("EnvironmentFile", []):
        for l in open(ef.lstrip("-")):
            l = l.strip()
            if l and not l.startswith("#") and "=" in l: k, v = l.split("=", 1); env[k] = v
    for e in u.get("Environment", []):
        for kv in e.split(): k, v = kv.split("=", 1); env[k] = v
    prevent = {int(x) for x in " ".join(u.get("RestartPreventExitStatus", [])).split() if x.isdigit()}
    while True:
        cmd = ["runuser", "-u", u["User"][0]] + (["-g", u["Group"][0]] if u.get("Group") else [])
        for g in " ".join(u.get("SupplementaryGroups", [])).split(): cmd += ["-G", g]
        cmd += ["--", "env"] + [f"{k}={v}" for k, v in env.items()] + u["ExecStart"][0].split()
        log = open(f"{ST}/{n}.log", "ab"); p = subprocess.Popen(cmd, cwd=u.get("WorkingDirectory", ["/"])[0], stdout=log, stderr=subprocess.STDOUT)
        open(f"{ST}/{n}.pid", "w").write(str(p.pid)); rc = p.wait(); open(f"{ST}/{n}.exit", "w").write(str(rc))
        if rc == 0 or rc < 0 or rc in prevent or "on-failure" not in " ".join(u.get("Restart", [])) or tries >= 4: break
        tries += 1; time.sleep(1)
def main():
    a = [x for x in sys.argv[1:] if not x.startswith("--")]; flags = [x for x in sys.argv[1:] if x.startswith("--")]
    if not a: return 0
    c, n = a[0], (a[1] if len(a) > 1 else "").replace(".service", "")
    if c == "_supervise": return supervise(n)
    with open(f"{ST}/calls.log", "a") as f: f.write(" ".join(sys.argv[1:]) + "\n")
    if c in ("daemon-reload", "reset-failed"): return 0
    if c == "enable": open(f"{ST}/{n}.enabled", "w").write("1"); return 0
    if c == "disable":
        try: os.remove(f"{ST}/{n}.enabled")
        except OSError: pass
        if "--now" in flags: stop(n)
        return 0
    if c in ("start", "restart"):
        if not os.path.exists(unitfile(n)): print(f"Unit {n}.service not found.", file=sys.stderr); return 5
        start(n); return 0
    if c == "stop": stop(n); return 0
    if c == "is-active":
        s = "active" if alive(rd(n, "pid")) else "inactive"
        if "--quiet" not in flags: print(s)
        return 0 if s == "active" else 3
    if c == "is-enabled": e = os.path.exists(f"{ST}/{n}.enabled"); print("enabled" if e else "disabled"); return 0 if e else 1
    if c == "is-failed":
        f = rd(n, "exit") not in ("", "0") and not alive(rd(n, "pid")); return 0 if f else 1
    if c == "list-unit-files": print(f"{n}.service enabled" if os.path.exists(unitfile(n)) else ""); return 0
    if c == "show":
        u = parse(n) if os.path.exists(unitfile(n)) else {}; print(f"User={(u.get('User') or [''])[0]}\nMainPID={rd(n, 'pid')}\nNRestarts=0\nExecMainStatus={rd(n, 'exit') or 0}\nResult=success"); return 0
    if c == "status": print(f"* {n}.service - fake\n   Active: {'active (running)' if alive(rd(n, 'pid')) else 'inactive'}"); return 0
    return 0
sys.exit(main())
