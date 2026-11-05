"""Endpoint health states: the single, documented definition (docs/MONITORING_CENTER.md). Pure functions, deterministic with an injected clock.

States (precedence from the top):
  revoked          the agent credential was revoked.
  never_connected  enrolled, but no heartbeat or event has ever been received after enrollment.
  offline          last heartbeat older than OFFLINE seconds.
  degraded         heartbeat is recent enough (<= OFFLINE) but at least one problem: heartbeat older than ONLINE seconds; 3+ recent upload failures; more than 5 000 queued events; collector errors reported.
  online           heartbeat within ONLINE seconds and none of the above.
Boundaries: age == ONLINE is still online; age == OFFLINE is still degraded (strictly greater switches), exactly like the pre-existing agent_status().
Thresholds: SOC_AGENT_ONLINE_SECONDS (default 90, 15-3600) and SOC_AGENT_OFFLINE_SECONDS (default 300, 30-86400); offline must be greater than online. Invalid values stop startup."""
import os, re, json
from datetime import datetime
from .config import ConfigError

DEFAULT_ONLINE_S, DEFAULT_OFFLINE_S = 90, 300
QUEUE_DEGRADED, UPLOAD_FAIL_DEGRADED = 5000, 3
STATES = ("never_connected", "online", "degraded", "offline", "revoked")
FMT = "%Y-%m-%d %H:%M:%S"

def _env_int(name, default, lo, hi):
    raw = os.environ.get(name)
    if raw is None or raw.strip() == "": return default
    r = raw.strip()
    v = int(r) if re.fullmatch(r"[0-9]{1,6}", r) else None
    if v is None or not (lo <= v <= hi): raise ConfigError(f"{name} must be a whole number of seconds from {lo} to {hi} (default {default}); got {r[:20]!r}.")
    return v

def thresholds():
    """-> (online_s, offline_s). Raises ConfigError on invalid settings."""
    on = _env_int("SOC_AGENT_ONLINE_SECONDS", DEFAULT_ONLINE_S, 15, 3600); off = _env_int("SOC_AGENT_OFFLINE_SECONDS", DEFAULT_OFFLINE_S, 30, 86400)
    if off <= on: raise ConfigError(f"SOC_AGENT_OFFLINE_SECONDS ({off}) must be greater than SOC_AGENT_ONLINE_SECONDS ({on}).")
    return on, off

def _parse(s):
    try: return datetime.strptime(str(s), FMT)
    except (TypeError, ValueError): return None

def endpoint_state(a, now=None, th=None):
    """a: mapping with status, registered_at, last_heartbeat, last_event_at, first_heartbeat_at (optional), health (JSON text or dict). -> dict(state, reason, age_s)."""
    on, off = th or thresholds(); now = now or datetime.now()
    if (a.get("status") or "") == "revoked": return dict(state="revoked", reason="credential revoked", age_s=None)
    hb, reg = _parse(a.get("last_heartbeat")), _parse(a.get("registered_at"))
    connected = bool(a.get("first_heartbeat_at")) or bool(a.get("last_event_at")) or bool(hb and reg and hb > reg)
    if not connected: return dict(state="never_connected", reason="enrolled but no heartbeat or event received since enrollment", age_s=None)
    if hb is None: return dict(state="offline", reason="no valid heartbeat time recorded", age_s=None)
    age = max(0.0, (now - hb).total_seconds())
    if age > off: return dict(state="offline", reason=f"no heartbeat for {int(age)} s (limit {off} s)", age_s=int(age))
    h = a.get("health") or {}
    if not isinstance(h, dict):
        try: h = json.loads(h)
        except (TypeError, ValueError): h = {}
    if not isinstance(h, dict): h = {}
    issues = []
    if age > on: issues.append(f"heartbeat {int(age)} s old (online limit {on} s)")
    try:
        if (h.get("upload_failures_recent") or 0) >= UPLOAD_FAIL_DEGRADED: issues.append(f"{int(h['upload_failures_recent'])} recent upload failures")
        if (h.get("events_queued") or 0) > QUEUE_DEGRADED: issues.append(f"{int(h['events_queued'])} events queued")
    except (TypeError, ValueError): pass
    if h.get("collector_errors"): issues.append("collector errors reported")
    return dict(state="degraded", reason="; ".join(issues), age_s=int(age)) if issues else dict(state="online", reason="heartbeat within limit, no problems reported", age_s=int(age))
