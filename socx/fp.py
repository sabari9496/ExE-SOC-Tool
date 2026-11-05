"""False-positive management. Nothing is silently ignored: a matching alert is kept, marked status='Suppressed', linked to the rule that matched,
the rule's hit counter is raised and an audit row is written. Alerts with a threat-intel (IOC) hit can NEVER be suppressed."""
import fnmatch, re
from db import q, x, now
KINDS = {"trusted_admin": "Trusted administrator (username)", "approved_software": "Approved software (pattern in command/process)",
         "approved_service": "Approved service (pattern)", "approved_task": "Approved scheduled task (pattern)", "known_scanner": "Known scanner (source IP)",
         "vuln_scanner": "Vulnerability scanner (source IP)", "maintenance_window": "Maintenance window (host + start/end)", "suppression": "Generic suppression rule"}

def audit(rule_id, action, user, detail): x("INSERT INTO whitelist_audit(ts,rule_id,action,user,detail) VALUES(?,?,?,?,?)", (now(), rule_id, action, user or "system", detail[:500]))

def _m(pat, val): return not pat or bool(val) and fnmatch.fnmatch(str(val).lower(), pat.lower())

def match(alert, ctx):
    """-> first matching ENABLED, in-time rule or None. ctx: username, host, text (message+command line)."""
    t = now()
    for r in q("SELECT * FROM whitelist WHERE enabled=1 ORDER BY id"):
        if r["detection"] not in ("*", "", alert["title"]): continue
        if r["starts"] and t < r["starts"]: continue
        if r["expires"] and t > r["expires"]: continue
        if r["kind"] == "maintenance_window" and not (r["starts"] and r["expires"]): continue      # a window must be bounded
        if not _m(r["host"], ctx.get("host")): continue
        if not _m(r["username"], (ctx.get("username") or "").split("\\")[-1]): continue
        if r["source_ip"] and not _m(r["source_ip"], alert.get("source_ip")): continue
        if r["pattern"]:
            try:
                if not re.search(r["pattern"], ctx.get("text") or "", re.I): continue
            except re.error: continue
        if r["kind"] in ("trusted_admin",) and not r["username"]: continue
        if r["kind"] in ("known_scanner", "vuln_scanner") and not r["source_ip"]: continue
        if r["kind"] in ("approved_software", "approved_service", "approved_task") and not r["pattern"]: continue
        return r
    return None

def hit(rule, alert):
    x("UPDATE whitelist SET hits=hits+1,last_hit=? WHERE id=?", (now(), rule["id"]))
    audit(rule["id"], "suppressed_alert", "system", f"Alert #{alert['id']} '{alert['title']}' host={alert.get('hostname') or ''} ip={alert.get('source_ip') or ''} by rule {rule['kind']} ({rule['reason']})")
