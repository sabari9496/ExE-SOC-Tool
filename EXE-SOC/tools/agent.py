#!/usr/bin/env python3
"""Tiny endpoint agent: sends a heartbeat every 30 s and can forward log lines.
  python tools/agent.py --server http://SOC:5000 --key API_KEY [--follow /var/log/auth.log]
Needs: pip install psutil requests"""
import argparse, json, platform, socket, time, requests, psutil
a = argparse.ArgumentParser(); a.add_argument("--server", required=True); a.add_argument("--key", required=True); a.add_argument("--follow")
o = a.parse_args(); H = {"X-API-Key": o.key}; host = socket.gethostname()
f = open(o.follow, errors="replace") if o.follow else None
if f: f.seek(0, 2)
while True:
    try:
        requests.post(o.server + "/api/agent/heartbeat", headers=H, timeout=5, json={"hostname": host, "os": f"{platform.system()} {platform.release()}", "cpu": psutil.cpu_percent(None), "ram": psutil.virtual_memory().percent})
        if f:
            lines = [l.strip() for l in f.readlines() if l.strip()]
            if lines: requests.post(o.server + "/api/ingest", headers=H, timeout=5, json=[{"message": l, "host": host} for l in lines])
    except Exception as e: print("agent error:", e)
    time.sleep(30 if not f else 5)
