#!/usr/bin/env python3
"""Server/CA preflight using ONLY the Python standard library, so the installer can validate everything BEFORE it changes the system
(no venv or 'requests' exists yet). The agent's `check-server` and the doctor reuse this same code. Never sends a credential. TLS verification is never disabled.

  python3 soc_preflight.py --server https://SOC:5000 [--ca-bundle ca.pem]      exit 0 = all steps passed"""
import argparse, http.client, socket, ssl, sys, time
from urllib.parse import urlparse

def explain_text(t, host, timeout=False):
    """Error text -> one clear sentence plus the fix."""
    low = str(t).lower(); host = host or "the server"
    if timeout or "timed out" in low: return f"Timed out talking to {host}. Check the IP/port, routing and any firewall between this computer and the SOC (on the server: ss -ltnp | grep <port>)."
    if "mismatch" in low or "not valid for" in low or "doesn't match" in low: return f"TLS: the server's certificate is not valid for '{host}'. Connect using a name/IP that is in the certificate, or recreate it on the server:  python tools/dev_certs.py --name <name> --ip {host}  (then copy the new ca.pem here)."
    if "signature failure" in low or "bad signature" in low: return "TLS: the server's certificate was not issued by the CA you gave (a regenerated or different ca.pem?), so it is not trusted. Copy the server's CURRENT ca.pem here (--ca-bundle); verification is never turned off."
    if "unable to get local issuer" in low or "self-signed" in low or "self signed" in low or "unknown ca" in low: return "TLS: the server's certificate is not trusted. Give this computer the SOC's CA file with --ca-bundle /path/ca.pem (verification is never turned off)."
    if "expired" in low: return "TLS: the server's certificate (or the CA) has expired. Create a new one on the server and copy the new ca.pem here."
    if "wrong version number" in low or "unexpected eof" in low or "record layer" in low or "http request" in low or "unknown protocol" in low: return f"TLS: {host} is not speaking HTTPS on that port. Check the port, and that the server was started with SOC_TLS_CERT / SOC_TLS_KEY (plain-http servers are refused)."
    if "certificate" in low or "ssl" in low: return f"TLS error: {str(t)[:160]}. Check --ca-bundle and that the certificate matches '{host}'."
    if "name or service not known" in low or "temporary failure in name resolution" in low or "nodename nor servname" in low or "getaddrinfo" in low: return f"Cannot resolve the name '{host}'. Use the server's IP address or fix DNS / /etc/hosts."
    if "refused" in low: return f"Connection refused by {host}. Is the SOC server running on this port and listening on a network address (SOC_HOST=0.0.0.0 - the default 127.0.0.1 accepts local connections only)?"
    if "reset by peer" in low or "connection aborted" in low: return f"Connection reset by {host}. Usually an HTTP/HTTPS mismatch or a firewall/proxy dropping the connection. The server must run with TLS and the URL must be https://."
    if "unreachable" in low or "no route" in low: return f"No route to {host}. Check the IP address and the network/VPN."
    return f"Cannot talk to the server: {str(t)[:160]}"

def ca_problem(path):
    """None if the CA bundle is usable, else the problem in plain English."""
    import os
    if not os.path.isfile(path): return f"CA bundle not found: {path}"
    if not os.access(path, os.R_OK): return f"CA bundle {path} is not readable by this user."
    try: ssl.create_default_context(cafile=path)
    except (ssl.SSLError, OSError, ValueError) as e: return f"{path} is not a valid PEM CA certificate file ({e.__class__.__name__}). Use the ca.pem created by tools/dev_certs.py (NOT server.pem / server.key)."
    return None

def check_server_steps(server, ca=None):
    """Ordered checks -> [(step, ok, detail, fix)], stopping at the first failure."""
    out = []
    def add(step, ok, detail="", fix=""): out.append((step, ok, detail, fix)); return ok
    u = urlparse(server or ""); host = u.hostname
    try: port = u.port or 443
    except ValueError: port = 0
    if not add("server URL", u.scheme == "https" and bool(host) and 0 < port < 65536, f"{server}", "Use https://HOST[:PORT] with a port between 1 and 65535 (TLS is mandatory; http:// is refused)."): return out
    if ca:
        p = ca_problem(ca)
        if p: add("CA bundle", False, p, "Use the ca.pem from the SOC server."); return out
        add("CA bundle", True, ca)
    else: add("CA bundle", True, "system trust store (no --ca-bundle given)")
    try: addrs = sorted({a[4][0] for a in socket.getaddrinfo(host, port, type=socket.SOCK_STREAM)}); add("DNS", True, ", ".join(addrs[:3]))
    except OSError as e: add("DNS", False, str(e)[:100], explain_text(e, host)); return out
    try: socket.create_connection((host, port), timeout=6).close(); add("TCP connect", True, f"{host}:{port}")
    except OSError as e: add("TCP connect", False, str(e)[:100], explain_text(e, host, isinstance(e, socket.timeout))); return out
    try:
        ctx = ssl.create_default_context(cafile=ca) if ca else ssl.create_default_context()           # verification ON (CERT_REQUIRED + hostname check)
        with socket.create_connection((host, port), timeout=6) as raw, ctx.wrap_socket(raw, server_hostname=host) as t:
            days = int((ssl.cert_time_to_seconds(t.getpeercert()["notAfter"]) - time.time()) // 86400)
            add("TLS certificate", True, f"{t.version()}, verified for '{host}', expires in {days} days" + ("  (RENEW SOON)" if days < 14 else ""))
    except (ssl.SSLError, OSError) as e: add("TLS certificate", False, str(e)[:120], explain_text(e, host, isinstance(e, socket.timeout))); return out
    try:
        with socket.create_connection((host, port), timeout=8) as raw, ctx.wrap_socket(raw, server_hostname=host) as t:
            c = http.client.HTTPSConnection(host, port, timeout=8, context=ctx); c.sock = t; c.request("GET", "/login", headers={"Host": u.netloc, "User-Agent": "exe-soc-preflight"}); st = c.getresponse().status
        good = st in (200, 302, 401); add("EXE-SOC web/API", good, f"GET /login -> HTTP {st}", "" if good else "The server answered but this does not look like EXE-SOC. Check the URL/port (and any reverse-proxy path).")
    except (ssl.SSLError, OSError, http.client.HTTPException) as e: add("EXE-SOC web/API", False, e.__class__.__name__, explain_text(e, host, isinstance(e, socket.timeout)))
    return out

def main(argv=None):
    ap = argparse.ArgumentParser(); ap.add_argument("--server", required=True); ap.add_argument("--ca-bundle"); a = ap.parse_args(argv); ok = True
    for step, good, detail, fix in check_server_steps(a.server, a.ca_bundle):
        print(f"  {'PASS' if good else 'FAIL'}  {step:<16} {detail}"); ok = ok and good
        if not good and fix: print(f"        -> {fix}")
    return 0 if ok else 1

if __name__ == "__main__": sys.exit(main())
