"""REAL enforcement on the machine this runs on: block / unblock an IP and isolate / release the whole computer.
Linux: iptables / ip6tables (own chains EXESOC-BLOCK and EXESOC-ISOLATE).   Windows: netsh advfirewall (rules named EXESOC-...).
Needs root / Administrator. Safety rules: never blocks loopback, this computer's own addresses or the SOC server, and isolation
always keeps the SOC server reachable (plus anything in SOC_ISOLATE_ALLOW, e.g. your admin PC: "203.0.113.5,10.0.0.0/24")."""
import os, re, socket, ipaddress, platform, subprocess, shutil
from urllib.parse import urlparse

WIN = platform.system() == "Windows"
SOC_IPS = set()

def set_soc_server(url_or_host):
    """Remember the SOC server address(es); they are never blocked and stay reachable during isolation."""
    h = urlparse(url_or_host if "://" in url_or_host else "//" + url_or_host).hostname or url_or_host
    try:
        for r in socket.getaddrinfo(h, None): SOC_IPS.add(r[4][0].split("%")[0])
    except Exception: pass

def is_admin():
    if WIN:
        try:
            import ctypes; return bool(ctypes.windll.shell32.IsUserAnAdmin())
        except Exception: return False
    return hasattr(os, "geteuid") and os.geteuid() == 0

def _local_ips():
    ips = {"127.0.0.1", "::1"}
    try:
        import psutil
        for a in psutil.net_if_addrs().values():
            for s in a:
                if s.family in (socket.AF_INET, socket.AF_INET6): ips.add(s.address.split("%")[0])
    except Exception: pass
    return ips

def _run(cmd):
    try: p = subprocess.run(cmd, capture_output=True, text=True, timeout=30); return p.returncode, (p.stdout + p.stderr).strip()
    except FileNotFoundError: return 127, f"{cmd[0]} not found"
    except Exception as e: return 1, str(e)

def _valid(ip):
    try: a = ipaddress.ip_address(ip)
    except ValueError: return None
    if a.is_loopback or a.is_unspecified or a.is_multicast or ip in SOC_IPS or ip in _local_ips(): return None
    return a

def _allow_list():
    out = list(SOC_IPS)
    for t in os.environ.get("SOC_ISOLATE_ALLOW", "").split(","):
        t = t.strip()
        try:
            if t: ipaddress.ip_network(t, strict=False); out.append(t)
        except ValueError: pass
    return out

# ---------------- Linux ----------------
def _ipt(v6): return "ip6tables" if v6 else "iptables"

def _lin_hook(v6, chain, hooks=("INPUT", "OUTPUT", "FORWARD")):
    t = _ipt(v6)
    for h in hooks:
        if _run([t, "-w", "-C", h, "-j", chain])[0] != 0: _run([t, "-w", "-I", h, "1", "-j", chain])

def _lin_block(ip, on):
    v6 = ":" in ip; t = _ipt(v6)
    if not shutil.which(t): return False, f"{t} not found (install iptables)"
    _run([t, "-w", "-N", "EXESOC-BLOCK"]); _lin_hook(v6, "EXESOC-BLOCK")
    for flag in ("-s", "-d"):
        exists = _run([t, "-w", "-C", "EXESOC-BLOCK", flag, ip, "-j", "DROP"])[0] == 0
        if on and not exists: rc, o = _run([t, "-w", "-A", "EXESOC-BLOCK", flag, ip, "-j", "DROP"]); 
        elif not on and exists: rc, o = _run([t, "-w", "-D", "EXESOC-BLOCK", flag, ip, "-j", "DROP"])
        else: continue
        if rc != 0: return False, o
    return True, ("blocked " if on else "unblocked ") + ip

def _lin_isolate(on):
    for v6 in (False, True):
        t = _ipt(v6)
        if not shutil.which(t): continue
        if on:
            _run([t, "-w", "-N", "EXESOC-ISOLATE"]); _run([t, "-w", "-F", "EXESOC-ISOLATE"])
            _run([t, "-w", "-A", "EXESOC-ISOLATE", "-i", "lo", "-j", "ACCEPT"]); _run([t, "-w", "-A", "EXESOC-ISOLATE", "-o", "lo", "-j", "ACCEPT"])
            for a in _allow_list():
                if (":" in a) != v6: continue
                _run([t, "-w", "-A", "EXESOC-ISOLATE", "-s", a, "-j", "ACCEPT"]); _run([t, "-w", "-A", "EXESOC-ISOLATE", "-d", a, "-j", "ACCEPT"])
            _run([t, "-w", "-A", "EXESOC-ISOLATE", "-j", "DROP"])
            _lin_hook(v6, "EXESOC-ISOLATE")                    # hooked last, so the rules are complete before they take effect
        else:
            for h in ("INPUT", "OUTPUT", "FORWARD"):
                while _run([t, "-w", "-C", h, "-j", "EXESOC-ISOLATE"])[0] == 0: _run([t, "-w", "-D", h, "-j", "EXESOC-ISOLATE"])
            _run([t, "-w", "-F", "EXESOC-ISOLATE"]); _run([t, "-w", "-X", "EXESOC-ISOLATE"])
    return True, "isolated (only the SOC server stays reachable)" if on else "released from isolation"

# ---------------- Windows ----------------
def _nsh(*a): return _run(["netsh", "advfirewall"] + list(a))

def _win_block(ip, on):
    name = f"EXESOC-BLOCK {ip}"; exists = _nsh("firewall", "show", "rule", f"name={name}")[0] == 0
    if on and not exists:
        for d in ("in", "out"):
            rc, o = _nsh("firewall", "add", "rule", f"name={name}", f"dir={d}", "action=block", f"remoteip={ip}")
            if rc != 0: return False, o
    elif not on and exists: _nsh("firewall", "delete", "rule", f"name={name}")
    return True, ("blocked " if on else "unblocked ") + ip

def _win_isolate(on):
    _nsh("firewall", "delete", "rule", "name=EXESOC-ISOLATE-ALLOW")
    if on:
        for a in _allow_list():
            for d in ("in", "out"): _nsh("firewall", "add", "rule", "name=EXESOC-ISOLATE-ALLOW", f"dir={d}", "action=allow", f"remoteip={a}")
        rc, o = _nsh("set", "allprofiles", "firewallpolicy", "blockinbound,blockoutbound")
        return (rc == 0), ("isolated (only the SOC server stays reachable)" if rc == 0 else o)
    rc, o = _nsh("set", "allprofiles", "firewallpolicy", "blockinbound,allowoutbound")
    return (rc == 0), ("released from isolation" if rc == 0 else o)

def execute(action, arg="", allow_isolate=True):
    """-> (ok, message)"""
    if not is_admin(): return False, "needs root / Administrator"
    if action in ("block_ip", "unblock_ip"):
        if not _valid(arg): return False, f"refused: {arg} is invalid, local, loopback or the SOC server"
        on = action == "block_ip"; return (_win_block if WIN else _lin_block)(arg, on)
    if action in ("isolate", "release"):
        if not allow_isolate: return False, "refused: never isolate the SOC server itself"
        on = action == "isolate"
        if on and not _allow_list(): return False, "refused: SOC server address unknown, isolation would lock this machine out"
        return (_win_isolate if WIN else _lin_isolate)(on)
    return False, f"unknown action {action}"
