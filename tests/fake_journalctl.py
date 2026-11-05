#!/usr/bin/env python3
# Test stand-in for journalctl: reads journal.jsonl next to this file; file 'mode' = ok | denied | denied_rc1
import sys, json, os, time
mode = open(os.path.join(os.path.dirname(os.path.abspath(__file__)), "mode")).read().strip() if os.path.exists(os.path.join(os.path.dirname(os.path.abspath(__file__)), "mode")) else "ok"
a = sys.argv[1:]
if mode == "denied": sys.stderr.write("Hint: You are currently not seeing messages from other users and the system.\n      Users in groups 'adm', 'systemd-journal' can see all messages.\nPass -q to turn off this notice.\n"); sys.exit(0)
if mode == "denied_rc1": sys.stderr.write("No journal files were opened due to insufficient permissions.\n"); sys.exit(1)
L = [json.loads(l) for l in open(os.path.join(os.path.dirname(os.path.abspath(__file__)), "journal.jsonl"))] if os.path.exists(os.path.join(os.path.dirname(os.path.abspath(__file__)), "journal.jsonl")) else []
cur = next((x.split("=", 1)[1] for x in a if x.startswith("--after-cursor=")), None); since = next((x for x in a if x.startswith("--since=")), None)
if cur: L = [e for e in L if int(e["__CURSOR"].split("=")[-1]) > int(cur.split("=")[-1])]
if since: m = int(since.split("-")[-1].replace("min", "")); L = [e for e in L if int(e["__REALTIME_TIMESTAMP"]) / 1e6 >= time.time() - m * 60]
if "-n" in a: L = L[-int(a[a.index("-n") + 1]):]
for e in L: sys.stdout.write(json.dumps(e) + "\n"); sys.stdout.flush()
