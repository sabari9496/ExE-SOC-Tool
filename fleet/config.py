"""Retention/replay configuration for the fleet ingest path. No project imports (usable from startup checks and subprocesses).
Invalid values FAIL CLEARLY (ConfigError) instead of being silently clamped or ignored."""
import os, re

class ConfigError(ValueError): pass

MIN_DEDUP_DAYS, DEFAULT_DEDUP_DAYS, MAX_DEDUP_DAYS = 7, 30, 3650

def dedup_days():
    """SOC_DEDUP_RETENTION_DAYS: whole days a processed-event ledger record is kept (default 30, valid 7-3650). Unset/empty = default. Anything else invalid raises."""
    raw = os.environ.get("SOC_DEDUP_RETENTION_DAYS")
    if raw is None or raw.strip() == "": return DEFAULT_DEDUP_DAYS
    r = raw.strip()
    v = int(r) if re.fullmatch(r"[0-9]{1,6}", r) else None          # ASCII digits only: int() alone would also accept "3_0", "+30" and non-ASCII digits
    if v is None or not (MIN_DEDUP_DAYS <= v <= MAX_DEDUP_DAYS):
        raise ConfigError(f"SOC_DEDUP_RETENTION_DAYS must be a whole number of days from {MIN_DEDUP_DAYS} to {MAX_DEDUP_DAYS} (default {DEFAULT_DEDUP_DAYS}); got {raw.strip()[:20]!r}. "
                          f"Values below {MIN_DEDUP_DAYS} would let events from agents that were offline over a long weekend be processed twice.")
    return v

def stale_guard_on():
    """SOC_REJECT_STALE_EVENTS: '1' = refuse events older than the ledger window minus one day (kept in quarantine). Unset, empty or '0' = off (default). Anything else raises."""
    raw = os.environ.get("SOC_REJECT_STALE_EVENTS", "").strip()
    if raw in ("", "0"): return False
    if raw == "1": return True
    raise ConfigError(f"SOC_REJECT_STALE_EVENTS must be 1 (on) or 0/unset (off); got {raw[:20]!r}.")

def validate_config():
    """Called at startup: a bad setting stops the application with a clear message before any event is processed."""
    dedup_days(); stale_guard_on()
    from .status import thresholds; thresholds()                 # SOC_AGENT_ONLINE_SECONDS / SOC_AGENT_OFFLINE_SECONDS
