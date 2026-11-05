"""EXE-SOC fleet layer: authorized remote endpoint agents -> HTTPS -> this server (enrollment, auth, ingest, health).
Hooks into the existing app with fleet.init() and fleet.api.register(...). Reuses engine.process_batch for detection."""
import hashlib, secrets, time
from db import q, x, now, conn
from .schema import SCHEMA, ALTERS, INDEXES

# Heartbeat policy (agent sends every 30 s): Online <= 90 s, Warning <= 5 min or unhealthy, Offline beyond that.
from .status import thresholds as _thresholds, DEFAULT_ONLINE_S, DEFAULT_OFFLINE_S
from .config import ConfigError as _CfgErr
try: ONLINE_S, OFFLINE_S = _thresholds()                          # central, configurable (docs/MONITORING_CENTER.md)
except _CfgErr: ONLINE_S, OFFLINE_S = DEFAULT_ONLINE_S, DEFAULT_OFFLINE_S   # invalid env: fleet.api.register() stops startup with a clear message

def init():
    from .config import validate_config
    validate_config()                                   # fail at startup, clearly, on a bad retention setting
    c = conn(); c.executescript(SCHEMA)
    for t, cols in ALTERS.items():
        have = {r[1] for r in c.execute(f"PRAGMA table_info({t})")}
        for n, typ in cols:
            if n not in have: c.execute(f"ALTER TABLE {t} ADD COLUMN {n} {typ}")
    c.executescript(INDEXES); c.commit(); c.close()

def sha(s): return hashlib.sha256(s.encode()).hexdigest()

def agent_status(a):
    """online / warning / offline / revoked from heartbeat age and agent-reported health."""
    if a["status"] == "revoked": return "revoked"
    try:
        from datetime import datetime
        age = (datetime.now() - datetime.strptime(a["last_heartbeat"], "%Y-%m-%d %H:%M:%S")).total_seconds()
    except Exception: return "offline"
    if age > OFFLINE_S: return "offline"
    import json
    try: h = json.loads(a.get("health") or "{}")
    except Exception: h = {}
    if age > ONLINE_S or h.get("upload_failures_recent", 0) >= 3 or (h.get("events_queued") or 0) > 5000 or h.get("collector_errors"): return "warning"
    return "online"

_DOWN = set()
def watcher_loop(emit=None):
    """Raise ONE 'Agent Offline' alert when an agent goes silent (and clear the flag when it returns). Runs every 30 s."""
    import engine
    while True:
        try:
            for a in q("SELECT id,hostname,last_heartbeat,status,health FROM agents WHERE status!='revoked'"):
                st = agent_status(a)
                if st == "offline" and a["id"] not in _DOWN:
                    _DOWN.add(a["id"])
                    engine.process_event(None, f"Endpoint agent offline: no heartbeat from {a['hostname']} since {a['last_heartbeat']}", host=a["hostname"], severity="Medium", title="Endpoint Agent Offline", category="system")
                    x("UPDATE alerts SET agent_id=? WHERE endpoint_id=(SELECT endpoint_id FROM agents WHERE id=?) AND agent_id IS NULL", (a["id"], a["id"]))
                    if emit: emit("refresh", {"what": "endpoints"})
                elif st != "offline": _DOWN.discard(a["id"])
        except Exception as e: print("fleet watcher:", e)
        time.sleep(30)

def start(emit=None):
    import threading; threading.Thread(target=watcher_loop, args=(emit,), daemon=True).start()
