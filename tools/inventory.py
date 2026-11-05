"""Installed-software inventory of THIS computer (for vulnerability checking). Standard library only."""
import os, re, sys, json, time, shutil, subprocess, platform

def _out(cmd, t=120):
    try: return subprocess.run(cmd, capture_output=True, text=True, timeout=t).stdout
    except Exception: return ""

def _osrel():
    d = {}
    try:
        for l in open("/etc/os-release"):
            if "=" in l: k, v = l.strip().split("=", 1); d[k] = v.strip('"')
    except Exception: pass
    return d

def _ecosystem(o):
    i, v = o.get("ID", ""), o.get("VERSION_ID", "")
    if i == "ubuntu": return f"Ubuntu:{v}" + (":LTS" if v.endswith(".04") and int(v.split(".")[0]) % 2 == 0 else "")
    if i == "debian": return f"Debian:{v.split('.')[0]}"
    if i == "alpine": return "Alpine:v" + ".".join(v.split(".")[:2])
    if i == "rocky": return f"Rocky Linux:{v.split('.')[0]}"
    if i == "almalinux": return f"AlmaLinux:{v.split('.')[0]}"
    return ""

class Inventory:
    def __init__(self): self.every = float(os.environ.get("SOC_INVENTORY_HOURS", "6")) * 3600; self.last = 0
    def due(self): return os.environ.get("SOC_INVENTORY", "1") != "0" and time.time() - self.last >= self.every
    def collect(self):
        """-> {"ecosystem": str, "packages": [{"name","version"}]} or None"""
        self.last = time.time(); pk = {}
        if platform.system() == "Windows": return self._windows()
        o = _osrel(); eco = _ecosystem(o)
        if shutil.which("dpkg-query"):
            for l in _out(["dpkg-query", "-W", "-f", "${source:Package}\t${source:Version}\t${db:Status-Abbrev}\n"]).splitlines():
                p = l.split("\t")
                if len(p) == 3 and p[2].startswith("ii"): pk[(p[0], p[1])] = 1
        elif shutil.which("rpm"):
            for l in _out(["rpm", "-qa", "--qf", "%{NAME}\t%{VERSION}-%{RELEASE}\n"]).splitlines():
                p = l.split("\t")
                if len(p) == 2: pk[(p[0], p[1])] = 1
        elif shutil.which("apk"):
            for l in _out(["apk", "info", "-v"]).splitlines():
                m = re.match(r"^(.*)-(\d[^-]*-r\d+)$", l.strip())
                if m: pk[(m.group(1), m.group(2))] = 1
        out = [{"name": n, "version": v} for n, v in pk]
        if os.environ.get("SOC_INVENTORY_PIP") == "1":       # off by default: distro-patched python packages give false positives
            try:
                for p in json.loads(_out([sys.executable, "-m", "pip", "list", "--format=json"])): out.append({"name": p["name"], "version": p["version"], "ecosystem": "PyPI"})
            except Exception: pass
        return {"ecosystem": eco, "packages": out} if out else None
    def _windows(self):
        ps = ("Get-ItemProperty HKLM:\\Software\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\*,HKLM:\\Software\\WOW6432Node\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\* "
              "| Where-Object DisplayName | Select-Object DisplayName,DisplayVersion | ConvertTo-Json -Compress")
        try: rows = json.loads(_out(["powershell", "-NoProfile", "-Command", ps]) or "[]")
        except Exception: rows = []
        if isinstance(rows, dict): rows = [rows]
        out = [{"name": r["DisplayName"], "version": r.get("DisplayVersion") or ""} for r in rows if r.get("DisplayName")]
        return {"ecosystem": "Windows", "packages": out} if out else None
