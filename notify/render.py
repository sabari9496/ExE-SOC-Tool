"""Builds the email subject, HTML and plain-text bodies from stored alert / incident data. EVERY value is HTML-escaped (log content is attacker-controlled) and secrets are masked."""
import re, json, html
from datetime import datetime
from db import q
from socx import catalog

LABELS = {"new_incident": "New Incident", "high_alert": "Security Alert", "ioc": "IOC Match Detected", "agent_offline": "Agent Offline", "large_outbound": "Possible Large Outbound Transfer",
          "network_attack": "Possible Network Scan Detected", "auth_attack": "Authentication Attack Detected", "escalation": "ESCALATION - incident not acknowledged", "test": "Test email"}
TECH = {"T1110": "Brute Force", "T1110.003": "Password Spraying", "T1078": "Valid Accounts", "T1021": "Remote Services", "T1021.001": "Remote Desktop Protocol", "T1059": "Command and Scripting Interpreter",
        "T1059.001": "PowerShell", "T1053": "Scheduled Task/Job", "T1053.005": "Scheduled Task", "T1543.003": "Windows Service", "T1547.001": "Registry Run Keys", "T1070.001": "Clear Windows Event Logs",
        "T1562.001": "Disable or Modify Tools", "T1003": "OS Credential Dumping", "T1558.003": "Kerberoasting", "T1190": "Exploit Public-Facing Application", "T1046": "Network Service Discovery",
        "T1048": "Exfiltration Over Alternative Protocol", "T1486": "Data Encrypted for Impact", "T1136": "Create Account", "T1098": "Account Manipulation", "T1071.004": "DNS", "T1505.003": "Web Shell"}
SECRET_RX = re.compile(r"(?i)\b(password|passwd|pwd|secret|token|api[_-]?key|authorization|cookie|session(id)?)\b(\s*[=:]\s*|\s+)(\"[^\"]*\"|'[^']*'|\S+)")
CTRL_RX = re.compile(r"[\x00-\x08\x0b-\x1f\x7f]")
SEV_COLOR = {"Critical": "#b3122a", "High": "#d9480f", "Medium": "#b7791f", "Low": "#2b6cb0", "Info": "#4a5568"}

def clean(v, n=400):
    if v is None: return ""
    t = CTRL_RX.sub("", str(v)); t = SECRET_RX.sub(lambda m: m.group(1) + m.group(3) + "[REDACTED]", t)
    return t[:n] + ("..." if len(t) > n else "")

def code(inc_id, created=None):
    d = (created or datetime.now().strftime("%Y-%m-%d"))[:10].replace("-", "")
    return f"INC-{d}-{int(inc_id):05d}"

def _raw(ev):
    try:
        d = json.loads((ev or {}).get("raw") or "{}"); return {k.lower(): v for k, v in d.items()} if isinstance(d, dict) else {}
    except Exception: return {}

def gather(alert_id, iid, ntype, severity, occurrences=None):
    a = q("SELECT * FROM alerts WHERE id=?", (alert_id,), one=True) or {}
    m = q("SELECT * FROM alert_meta WHERE alert_id=?", (alert_id,), one=True) or {}
    inc = q("SELECT * FROM incidents WHERE id=?", (iid,), one=True) if iid else None
    ep = q("SELECT * FROM endpoints WHERE id=?", (a.get("endpoint_id"),), one=True) if a.get("endpoint_id") else None
    host = (ep or {}).get("hostname") or (inc or {}).get("host")
    ev = q("SELECT * FROM events WHERE alert_id=? ORDER BY id DESC LIMIT 1", (alert_id,), one=True) or {}
    r = _raw(ev); g = lambda *k: next((str(r[x_.lower()]) for x_ in k if r.get(x_.lower()) not in (None, "", "-")), "")
    related = q("SELECT a.id,a.severity,a.title,a.count FROM alerts a JOIN incident_alerts ia ON ia.alert_id=a.id WHERE ia.incident_id=? ORDER BY a.id DESC LIMIT 8", (iid,)) if iid else []
    tactic = m.get("tactic") or (inc or {}).get("tactics", "").split(",")[-1] or ""
    try: factors = json.loads((inc or {}).get("score_detail") or m.get("score_detail") or "{}")
    except Exception: factors = {}
    mitre = [t for t in ((inc or {}).get("mitre") or m.get("mitre") or "").split(",") if t]
    det_id = (re.match(r"^\[([A-Z]{3}-\d{3})\]", a.get("message") or "") or [None, ""])[1]
    user = m.get("username") or (inc or {}).get("username") or ""
    from socx import risk
    priv = "Administrative account" if user and (user.lower() in [x_.lower() for x_ in risk.model().get("admin_names", [])] or user.lower().endswith(("admin", "administrator"))) else ("Standard account" if user else "")
    lt = {"2": "Interactive", "3": "Network", "4": "Batch", "5": "Service", "7": "Unlock", "8": "NetworkCleartext", "9": "NewCredentials", "10": "RemoteInteractive (RDP)", "11": "CachedInteractive"}.get(g("LogonType"), g("LogonType"))
    if not lt and re.search(r"Accepted (password|publickey)|Failed password", a.get("message") or ""): lt = "SSH " + ("public key" if "publickey" in (a.get("message") or "") else "password")
    return dict(ntype=ntype, severity=severity, alert=a, meta=m, inc=inc, ep=ep, host=host, related=related, det_id=det_id, user=user, priv=priv, auth=lt, mitre=mitre, tactic=tactic, factors=factors,
                score=(inc or {}).get("risk_score") if inc else m.get("risk_score"), occurrences=occurrences or ((inc or {}).get("event_count") if inc else a.get("count")) or 1,
                net=dict(src=a.get("source_ip") or ev.get("source_ip") or "", dst=a.get("dest_ip") or ev.get("dest_ip") or g("DestinationIp", "raddr"), sport=g("SourcePort", "lport"), dport=g("DestinationPort", "rport", "dpt"),
                         proto=g("Protocol", "proto"), sent=g("BytesSent", "bytes_sent", "bytes"), recv=g("BytesReceived", "bytes_received")),
                process=m.get("process") or g("NewProcessName", "Image"), cmd=m.get("command_line") or g("CommandLine"), parent=m.get("parent_process") or g("ParentProcessName", "ParentImage"),
                playbook=catalog.playbook_for(tactic if tactic in catalog.IR else "default"), ioc=m.get("ioc") or "")

def subject(c, update=False):
    sev = c["severity"].upper(); inc = c["inc"]; a = c["alert"]
    title = (inc or {}).get("title") if c["ntype"] in ("new_incident", "escalation") and inc else (a.get("title") or "Security alert")
    if c["ntype"] == "agent_offline": title = f"{LABELS['agent_offline']}: {c['host'] or 'unknown host'}"
    elif c["ntype"] in ("ioc", "large_outbound", "network_attack", "auth_attack"): title = f"{LABELS[c['ntype']]}: {a.get('title') or ''}".rstrip(": ")
    prefix = {"new_incident": "New Incident: ", "escalation": "ESCALATION - not acknowledged: "}.get(c["ntype"], "") + ("UPDATE: " if update else "")
    return CTRL_RX.sub("", f"[{sev}] EXE-SOC — {prefix}{clean(title, 140)}").replace("\r", " ").replace("\n", " ")[:200]

def _rows(pairs, esc=html.escape):
    return "".join(f"<tr><td style='padding:3px 12px 3px 0;color:#555;white-space:nowrap;vertical-align:top'>{esc(k)}</td><td style='padding:3px 0;color:#111'>{esc(str(v))}</td></tr>" for k, v in pairs if v not in (None, "", []))

def link(c, base):
    if not base: return ""
    base = base.rstrip("/")
    if c["ntype"] == "agent_offline": return base + "/agent-health"
    return f"{base}/incidents?open={c['inc']['id']}" if c["inc"] else f"{base}/alerts"

def body(c, base_url="", update=False):
    a, inc, e = c["alert"], c["inc"], html.escape
    sev = c["severity"]; first = (inc or {}).get("first_seen") or c["meta"].get("first_seen") or a.get("ts"); last = (inc or {}).get("last_seen") or c["meta"].get("last_seen") or a.get("updated")
    ref = code(inc["id"], inc.get("created")) if inc else ""
    det = f"{c['det_id']} — {a.get('title')}" if c["det_id"] else a.get("title")
    n = c["net"]; ep = c["ep"] or {}
    sections = [("Alert summary", [("Severity", sev.upper()), ("Detection", det), ("Status", (inc or a).get("status")), ("First seen", first), ("Last seen", last), ("Occurrences", c["occurrences"])]),
        ("Endpoint", [("Agent ID", f"EP-{ep['id']:04d}" if ep.get("id") else ""), ("Hostname", c["host"]), ("Operating system", ep.get("os")), ("IP address", ep.get("ip"))]),
        ("Network", [("Source IP", n["src"]), ("Destination IP", n["dst"]), ("Source port", n["sport"]), ("Destination port", n["dport"]), ("Protocol", n["proto"]), ("Bytes sent", n["sent"]), ("Bytes received", n["recv"])]),
        ("User", [("Username", c["user"]), ("Privilege", c["priv"]), ("Authentication type", c["auth"])]),
        ("Detection", [("Rule", det), ("Reason", clean(c["meta"].get("reason") or a.get("note") or "", 400)), ("Evidence", clean(a.get("message"), 500)), ("Process", clean(c["process"], 200)), ("Command line", clean(c["cmd"], 300)), ("Parent process", clean(c["parent"], 200)), ("IOC", clean(c["ioc"], 200))]),
        ("MITRE ATT&CK", [(t, TECH.get(t, "")) for t in c["mitre"]] + ([("Tactic", c["tactic"])] if c["tactic"] else [])),
        ("Risk", [("Risk score", f"{c['score']}/100" if c["score"] is not None else ""), ("Risk factors", "; ".join(f"{k}: {v}" for k, v in c["factors"].items() if isinstance(v, (int, float, str)))[:400])]),
        ("Incident", [("Incident ID", ref), ("Incident title", (inc or {}).get("title")), ("Related alerts", "; ".join(f"#{r['id']} {r['severity']} {clean(r['title'], 60)} x{r['count']}" for r in c["related"])), ("Occurrences", c["occurrences"] if inc else "")])]
    steps = [(k.capitalize(), v) for k, v in c["playbook"].items()]
    url = link(c, base_url); color = SEV_COLOR.get(sev, "#333")
    h = [f"<html><body style='margin:0;background:#f3f5f8;font-family:Segoe UI,Arial,sans-serif'><div style='max-width:680px;margin:0 auto;background:#fff'>",
         f"<div style='background:{color};color:#fff;padding:16px 22px'><div style='font-size:12px;letter-spacing:1px'>EXE-SOC SECURITY {'UPDATE' if update else 'ALERT'}</div><div style='font-size:20px;font-weight:bold;margin-top:4px'>{e(sev.upper())} — {e(LABELS.get(c['ntype'], ''))}</div>",
         f"<div style='margin-top:4px'>{e(clean((inc or a).get('title'), 160))}</div></div><div style='padding:18px 22px'>"]
    t = [f"EXE-SOC SECURITY {'UPDATE' if update else 'ALERT'}", f"Severity: {sev.upper()}", f"Risk Score: {c['score']}" if c["score"] is not None else "", ""]
    for title, pairs in sections:
        if not any(v not in (None, "", []) for _, v in pairs): continue
        h.append(f"<h3 style='margin:16px 0 6px;font-size:14px;color:{color};border-bottom:1px solid #e2e8f0;padding-bottom:3px'>{e(title)}</h3><table style='font-size:13px;border-collapse:collapse'>{_rows(pairs)}</table>")
        t += [title.upper()] + [f"  {k}: {v}" for k, v in pairs if v not in (None, "", [])] + [""]
    h.append(f"<h3 style='margin:16px 0 6px;font-size:14px;color:{color};border-bottom:1px solid #e2e8f0;padding-bottom:3px'>Recommended actions (guidance only)</h3><ol style='font-size:13px;padding-left:20px;margin:6px 0'>" + "".join(f"<li style='margin:3px 0'><b>{e(k)}:</b> {e(v)}</li>" for k, v in steps) + "</ol>")
    t += ["RECOMMENDED ACTIONS (guidance only)"] + [f"  {i}. {k}: {v}" for i, (k, v) in enumerate(steps, 1)] + [""]
    if url:
        h.append(f"<p style='margin:18px 0'><a href='{e(url)}' style='background:{color};color:#fff;padding:9px 16px;text-decoration:none;border-radius:4px;font-size:14px'>{'View Incident in EXE-SOC' if inc else 'Open EXE-SOC'}</a></p>"); t += [f"EXE-SOC Dashboard: {url}", ""]
    h.append("<p style='font-size:11px;color:#777;margin-top:20px'>Automatic message from EXE-SOC. The recommended actions are guidance only: EXE-SOC takes no response action automatically. No passwords or tokens are included in this message.</p></div></div></body></html>")
    return "".join(h), "\n".join(x_ for x_ in t if x_ is not None)

def test_message(who):
    h = f"<html><body style='font-family:Arial,sans-serif'><h2>EXE-SOC test email</h2><p>This is a test message from EXE-SOC. If you can read this, email notifications can reach <b>{html.escape(who)}</b>.</p><p style='color:#777;font-size:12px'>No action is needed.</p></body></html>"
    return "[TEST] EXE-SOC — Test email", h, f"EXE-SOC test email\n\nIf you can read this, email notifications can reach {who}.\nNo action is needed."
