"""Persistent (SQLite) attempt limiter shared by every worker/process and surviving restarts. Used for login (account-wide + per-IP), MFA/recovery codes and re-authentication.
Keys are hashed-free plain strings (usernames/IPs); rows older than 24 h are purged. Blocking is based on the number of recorded failures inside a sliding window.
Limits: the table lives in the same SQLite file, so a multi-host deployment needs a shared database or a shared limiter (documented in docs/DEPLOYMENT.md)."""
import time, threading
_READY = set(); _LK = threading.Lock()
def _ensure():
    import db
    if db.DB in _READY: return
    with _LK:
        db.x("CREATE TABLE IF NOT EXISTS throttle(scope TEXT NOT NULL, k TEXT NOT NULL, ts REAL NOT NULL)"); db.x("CREATE INDEX IF NOT EXISTS ix_throttle ON throttle(scope,k,ts)"); _READY.add(db.DB)
def count(scope, k, window):
    import db; _ensure(); return db.q("SELECT COUNT(*) c FROM throttle WHERE scope=? AND k=? AND ts>?", (scope, str(k)[:120], time.time() - window), one=True)["c"]
def hit(scope, k):
    import db; _ensure(); t = time.time(); db.x("INSERT INTO throttle(scope,k,ts) VALUES(?,?,?)", (scope, str(k)[:120], t))
    if int(t) % 50 == 0: db.x("DELETE FROM throttle WHERE ts<?", (t - 86400,))
def blocked(scope, k, limit, window): return count(scope, k, window) >= limit
def clear(scope, k):
    import db; _ensure(); db.x("DELETE FROM throttle WHERE scope=? AND k=?", (scope, str(k)[:120]))
