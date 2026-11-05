#!/usr/bin/env python3
"""Send realistic attack events to a running SOC so you can watch the dashboard update live.
  python tools/simulate.py --server http://127.0.0.1:5000 --key API_KEY"""
import argparse, random, time, requests
a = argparse.ArgumentParser(); a.add_argument("--server", default="http://127.0.0.1:5000"); a.add_argument("--key", required=True); o = a.parse_args()
IPS = ["45.32.156.7", "103.21.244.9", "185.220.101.10", "5.188.86.77", "177.54.12.3", "41.79.5.2", "1.180.44.8", "203.0.113.50"]
MSG = ["Failed password for root from {ip}", "GET /login.php?id=1' OR 1=1--", "Malware detected: Trojan.Win32.Generic", "Unusual DNS query to rare TLD",
       "sudo: user not in sudoers file", "Port scan detected from {ip}", "GET /search?q=<script>alert(1)</script>", "GET /../../etc/passwd"]
while True:
    ip = random.choice(IPS); m = random.choice(MSG).format(ip=ip)
    r = requests.post(o.server + "/api/ingest", headers={"X-API-Key": o.key}, json={"source_ip": ip, "message": m, "dest_ip": f"10.0.2.{random.randint(10, 30)}:{random.choice([22, 80, 443])}"})
    print(r.status_code, ip, m); time.sleep(random.uniform(1, 4))
