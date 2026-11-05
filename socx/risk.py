"""Configurable risk model. Weights live in settings key 'risk_model' (JSON) so an admin can tune them without code changes."""
import json
from db import q, setting, x

DEFAULT_MODEL = {
  "severity_base": {"Low": 10, "Medium": 25, "High": 45, "Critical": 65},
  "tactic_bonus": {"Credential Access": 15, "Defense Evasion": 12, "Persistence": 12, "Lateral Movement": 12, "Impact": 18, "Exfiltration": 15,
                   "Execution": 6, "Privilege Escalation": 10, "Command and Control": 12, "Initial Access": 8, "Discovery": 2},
  "privileged_user": 15, "host_criticality_per_level": 5, "known_ioc": 30, "vulnerable_host": 8, "auth_success_after_failures": 20,
  "frequency_per_doubling": 4, "frequency_cap": 12, "correlation_per_stage": 10, "correlation_cap": 40, "incident_cap": 100,
  "thresholds": {"Critical": 85, "High": 60, "Medium": 30, "Low": 1},
  "admin_names": ["administrator", "admin", "root", "domain admin", "svc_admin"],
}

def model():
    try:
        m = json.loads(setting("risk_model", "") or "{}")
    except Exception: m = {}
    out = json.loads(json.dumps(DEFAULT_MODEL))
    for k, v in m.items():
        if isinstance(v, dict) and isinstance(out.get(k), dict): out[k].update(v)
        else: out[k] = v
    return out

def save_model(m): x("INSERT OR REPLACE INTO settings VALUES('risk_model',?)", (json.dumps(m),))

def severity_for(score, m=None):
    m = m or model()
    for sev in ("Critical", "High", "Medium", "Low"):
        if score >= m["thresholds"][sev]: return sev
    return "Low"

def host_criticality(host):
    r = q("SELECT criticality FROM assets WHERE hostname=?", (host,), one=True) if host else None
    return r["criticality"] if r else 2

def is_privileged(user, m):
    u = (user or "").lower().split("\\")[-1]
    return bool(u) and (u in m["admin_names"] or u.endswith("$") is False and u.startswith("adm"))

def score_alert(sev, tactic="", host=None, user=None, ioc=False, count=1, auth_success_after_fail=False, extra=0):
    """-> (score 0..100, detail dict explaining every contribution)."""
    m = model(); d = {"severity": m["severity_base"].get(sev, 10)}
    d["tactic"] = m["tactic_bonus"].get(tactic, 0)
    if is_privileged(user, m): d["privileged_user"] = m["privileged_user"]
    crit = host_criticality(host) - 2
    if crit > 0: d["host_criticality"] = crit * m["host_criticality_per_level"]
    if ioc: d["known_ioc"] = m["known_ioc"]
    if auth_success_after_fail: d["auth_success_after_failures"] = m["auth_success_after_failures"]
    if count > 1:
        import math; d["frequency"] = min(m["frequency_cap"], int(math.log2(count) * m["frequency_per_doubling"]))
    if host and q("SELECT 1 FROM vulns WHERE host=? AND severity IN ('CRITICAL','HIGH','Critical','High') LIMIT 1", (host,), one=True): d["vulnerable_host"] = m["vulnerable_host"]
    if extra: d["extra"] = extra
    return min(100, sum(d.values())), d

def score_incident(alert_scores, stages):
    """Highest alert dominates; every additional distinct attack stage adds correlation confidence (capped)."""
    m = model()
    if not alert_scores: return 0, {}
    top = max(alert_scores); corr = min(m["correlation_cap"], max(0, stages - 1) * m["correlation_per_stage"])
    return min(m["incident_cap"], top + corr), {"highest_alert": top, "correlation_confidence": corr, "distinct_stages": stages}
