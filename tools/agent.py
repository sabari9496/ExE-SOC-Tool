#!/usr/bin/env python3
"""Tiny endpoint agent: heartbeat every 30 s, can forward a text log file and collect ALL logs of the computer (Windows Event Log / Linux journal + /var/log).
  python tools/agent.py --server http://SOC:5000 --key API_KEY [--follow /var/log/auth.log] [--collect] [--enforce]
Needs: pip install psutil requests      (--collect needs Administrator on Windows / root on Linux)"""
import argparse, platform, socket, sys, time, os
import requests, psutil
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

a = argparse.ArgumentParser(); a.add_argument("--server", required=True); a.add_argument("--key", required=True)
a.add_argument("--enforce", action="store_true", help="really apply block-IP / isolate commands from the SOC (needs root/Administrator)")
a.add_argument("--follow", help="text log file to forward"); a.add_argument("--eventlog", "--collect", dest="eventlog", action="store_true", help="collect ALL logs of this computer: Windows Event Log, or Linux journal + /var/log files")
o = a.parse_args(); H = {"X-API-Key": o.key}; host = socket.gethostname(); server = o.server.rstrip("/")
if not server.startswith("https://") and os.environ.get("SOC_ALLOW_INSECURE_LEGACY_AGENT") != "1":
    sys.exit("Refusing to start the legacy agent over plaintext HTTP. Use the signed agent in agent/exe_soc_agent.py with HTTPS. Temporary lab-only exception: set SOC_ALLOW_INSECURE_LEGACY_AGENT=1 explicitly.")
f = open(o.follow, errors="replace") if o.follow else None
if f: f.seek(0, 2)
col = None
if o.eventlog:
    import collect; col = collect.get_collector()
    print("Full log collection enabled: " + ", ".join(getattr(col, "sources", None) or getattr(col, "channels", [])) + "  (run as Administrator / root)")
inv = None
if col:
    import inventory; inv = inventory.Inventory()
if o.enforce:
    import enforce; enforce.set_soc_server(server)
    print("Enforcement ENABLED: this computer will apply block/isolate commands from the SOC." + ("" if enforce.is_admin() else "  WARNING: not root/Administrator - commands will fail."))
last_cmd = 0; resync = "1"
def do_commands():
    global resync
    cmds = requests.get(server + "/api/agent/commands", headers=H, params={"host": host, "resync": resync}, timeout=10).json(); resync = "0"
    res = []
    for c in cmds:
        ok, msg = enforce.execute(c["action"], c.get("arg") or "")
        print(f"command {c['action']} {c.get('arg','')}: {'ok' if ok else 'FAILED'} - {msg}"); res.append({"id": c["id"], "host": host, "ok": ok, "result": msg})
    if res: requests.post(server + "/api/agent/commands/result", headers=H, timeout=10, json=res)
pending = []; last_hb = 0
while True:
    try:
        if time.time() - last_hb > 15:
            requests.post(server + "/api/agent/heartbeat", headers=H, timeout=5, json={"hostname": host, "os": f"{platform.system()} {platform.release()}", "cpu": psutil.cpu_percent(None), "ram": psutil.virtual_memory().percent}); last_hb = time.time()
        batch = []
        if f: batch += [{"message": l.strip(), "host": host} for l in f.readlines() if l.strip()]
        if col: batch += col.poll(host)
        pending += batch                                   # unsent events are kept and retried; the server ignores duplicates
        while pending:
            requests.post(server + "/api/ingest", headers=H, timeout=30, json=pending[:500]).raise_for_status(); del pending[:500]
        if col: col.commit()                               # cursor saved only after the server accepted everything
        if inv and inv.due():
            d = inv.collect()
            if d: requests.post(server + "/api/agent/inventory", headers=H, timeout=60, json={"hostname": host, "ecosystem": d["ecosystem"], "packages": d["packages"]})
        if o.enforce and time.time() - last_cmd > 5: last_cmd = time.time(); do_commands()
    except Exception as e: print("agent error:", e)
    time.sleep(0.2 if (col and col.backlog) else (col.interval if col else 5 if f else 30))
