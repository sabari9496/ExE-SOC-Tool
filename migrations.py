"""Version-tracked, additive SQLite migrations for EXE-SOC.

Rules: every migration is idempotent and runs in its own BEGIN IMMEDIATE transaction (SQLite DDL is transactional), so a failure rolls that migration back and
nothing is half-applied. Applied versions are recorded in schema_migrations (version, name, checksum, applied_at). BEGIN IMMEDIATE takes SQLite's single writer lock, and the applied
list is re-read inside it, so two processes can never apply the same migration twice. A database recorded as NEWER than this code, or whose applied checksum differs, is refused.
inspect()/plan() never write (read-only connection). No migration drops, renames or rewrites existing data."""
import os, sqlite3, hashlib, sys
from datetime import datetime, timezone

class MigrationError(Exception): pass
class SchemaTooNew(MigrationError): pass
class ChecksumMismatch(MigrationError): pass
class SchemaInvalid(MigrationError): pass

CORE_TABLES = ("users", "events", "alerts", "audit", "settings", "endpoints")
def _cols(c, t): return {r[1] for r in c.execute(f"PRAGMA table_info({t})")}
def _tables(c): return {r[0] for r in c.execute("SELECT name FROM sqlite_master WHERE type='table'")}
def _indexes(c): return {r[0] for r in c.execute("SELECT name FROM sqlite_master WHERE type='index'")}

LEDGER_COLS = (("status", "TEXT NOT NULL DEFAULT 'processed'"), ("claimed_at", "TEXT"), ("attempts", "INTEGER DEFAULT 0"), ("last_error", "TEXT"))

def _m1(c):
    missing = [t for t in CORE_TABLES if t not in _tables(c)]
    if missing: raise SchemaInvalid("core tables missing (" + ", ".join(missing) + "): this is not an EXE-SOC database, or the application has never initialised it. Start the application once on a NEW database, or restore a backup.")
def _chk1(c): return [f"core table {t} missing" for t in CORE_TABLES if t not in _tables(c)]

def _m2(c):
    c.execute("CREATE TABLE IF NOT EXISTS agent_event_ids(agent_id TEXT NOT NULL, uid TEXT NOT NULL, ts TEXT, status TEXT NOT NULL DEFAULT 'processed', claimed_at TEXT, attempts INTEGER DEFAULT 0, last_error TEXT, PRIMARY KEY(agent_id, uid)) WITHOUT ROWID")
    have = _cols(c, "agent_event_ids")
    for col, typ in LEDGER_COLS:
        if col not in have: c.execute(f"ALTER TABLE agent_event_ids ADD COLUMN {col} {typ}")
    c.execute("CREATE TABLE IF NOT EXISTS event_quarantine(id INTEGER PRIMARY KEY, agent_id TEXT NOT NULL, uid TEXT NOT NULL, reason TEXT NOT NULL, attempts INTEGER DEFAULT 0, payload TEXT, created_at TEXT NOT NULL, replayed_at TEXT, UNIQUE(agent_id, uid))")
    c.execute("CREATE INDEX IF NOT EXISTS ix_quar_agent ON event_quarantine(agent_id, id)")
def _chk2(c):
    t = _tables(c); p = [f"table {x} missing" for x in ("agent_event_ids", "event_quarantine") if x not in t]
    if "agent_event_ids" in t: p += [f"agent_event_ids.{col} missing" for col, _ in LEDGER_COLS if col not in _cols(c, "agent_event_ids")]
    return p

def _m3(c):
    c.execute("CREATE INDEX IF NOT EXISTS ix_aev_status_ts ON agent_event_ids(status, ts)")
    c.execute("CREATE INDEX IF NOT EXISTS ix_quar_created ON event_quarantine(created_at)")
def _chk3(c): return [f"index {i} missing" for i in ("ix_aev_status_ts", "ix_quar_created") if i not in _indexes(c)]


V4_COLS = (("os_family", "TEXT"), ("distro_id", "TEXT"), ("distro_version", "TEXT"), ("environment", "TEXT"), ("tags", "TEXT"), ("first_heartbeat_at", "TEXT"))
V4_INDEXES = (("ix_agents_family", "agents", "os_family, distro_id"), ("ix_agents_env", "agents", "environment"), ("ix_agents_hb", "agents", "last_heartbeat"), ("ix_alert_agent_ts", "alerts", "agent_id, ts"))

def _m4(c):
    t = _tables(c)
    if "agents" in t:
        have = _cols(c, "agents")
        for col, typ in V4_COLS:
            if col not in have: c.execute(f"ALTER TABLE agents ADD COLUMN {col} {typ}")
        # only fills the NEW column, never touches existing data: first known heartbeat = last heartbeat for agents that clearly reported after enrollment
        c.execute("UPDATE agents SET first_heartbeat_at=last_heartbeat WHERE first_heartbeat_at IS NULL AND last_heartbeat IS NOT NULL AND registered_at IS NOT NULL AND last_heartbeat>registered_at")
    for name, table, cols in V4_INDEXES:
        if table in t and all(x in _cols(c, table) for x in (y.strip() for y in cols.split(","))): c.execute(f"CREATE INDEX IF NOT EXISTS {name} ON {table}({cols})")
def _chk4(c):
    t = _tables(c); p = []
    if "agents" in t: p += [f"agents.{col} missing" for col, _ in V4_COLS if col not in _cols(c, "agents")]
    for name, table, cols in V4_INDEXES:
        if table in t and all(x in _cols(c, table) for x in (y.strip() for y in cols.split(","))) and name not in _indexes(c): p.append(f"index {name} missing")
    return p

# (version, name, spec, function, check, description). `spec` feeds the checksum: change it only by adding a NEW migration, never by editing an applied one.
MIGRATIONS = [
    (1, "baseline_pass6", "v1:core-tables-present", _m1, _chk1, "Verify the core EXE-SOC tables exist (no change to data or schema)."),
    (2, "phase1_ingest_quarantine", "v1:event_quarantine+ledger(attempts,last_error)", _m2, _chk2, "Create event_quarantine; add agent_event_ids.attempts/last_error (and the ledger itself on very old databases) if missing."),
    (3, "phase2_ledger_indexes", "v1:ix_aev_status_ts+ix_quar_created", _m3, _chk3, "Add indexes that keep the dedupe purge and quarantine listing bounded."),
    (4, "stage2_endpoint_metadata", "v1:agents.os_family,distro_id,distro_version,environment,tags,first_heartbeat_at+ix_agents_family,ix_agents_env,ix_agents_hb,ix_alert_agent_ts", _m4, _chk4,
     "Monitoring Center: add nullable agents.os_family/distro_id/distro_version/environment/tags/first_heartbeat_at, backfill first_heartbeat_at for agents that clearly reported, add filter indexes. Additive; no existing value is changed."),
]
LATEST = MIGRATIONS[-1][0]
def checksum(m): return hashlib.sha256(f"{m[0]}|{m[1]}|{m[2]}".encode()).hexdigest()[:32]
def _utc(): return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")

def _ro(path): return sqlite3.connect(f"file:{os.path.abspath(path)}?mode=ro", uri=True, timeout=10)
def _rw(path):
    c = sqlite3.connect(path, timeout=30, isolation_level=None); c.execute("PRAGMA busy_timeout=30000"); return c      # autocommit: transactions are explicit below

def is_fresh(path):
    """True when there is nothing to protect: no file, empty file, or no users table."""
    if not os.path.exists(path) or os.path.getsize(path) == 0: return True
    try: c = _ro(path)
    except sqlite3.Error: return False
    try: return "users" not in _tables(c)
    except sqlite3.Error: return False
    finally: c.close()

def inspect(path):
    """Read-only report: {exists, recorded, pending, too_new, mismatches, problems}."""
    r = dict(exists=os.path.exists(path), recorded=[], pending=[m[0] for m in MIGRATIONS], too_new=[], mismatches=[], problems=[], tracked=False)
    if not r["exists"] or os.path.getsize(path) == 0: r["exists"] = False; return r
    c = _ro(path)
    try:
        if "schema_migrations" not in _tables(c): return r
        r["tracked"] = True; rows = c.execute("SELECT version,name,checksum,applied_at FROM schema_migrations ORDER BY version").fetchall(); known = {m[0]: m for m in MIGRATIONS}
        r["recorded"] = [dict(version=v, name=n, applied_at=a) for v, n, _, a in rows]; r["pending"] = [v for v in known if v not in {x[0] for x in rows}]
        for v, n, ck, a in rows:
            if v not in known: r["too_new"].append(v)
            elif ck != checksum(known[v]): r["mismatches"].append(v)
        for v, *_ in rows:
            if v in known: r["problems"] += [f"migration {v}: {p}" for p in known[v][4](c)]
    finally: c.close()
    return r

def check_compat(path):
    """Refuse to run against a database this code does not understand. Called at every startup, before anything is changed."""
    r = inspect(path)
    if r["too_new"]: raise SchemaTooNew(f"database schema version {max(r['too_new'])} is newer than this application supports (max {LATEST}). Upgrade the application or restore a matching backup; do not run an older build against a newer database.")
    if r["mismatches"]: raise ChecksumMismatch(f"applied migration(s) {r['mismatches']} do not match this application's definition (the database or the code was modified). Restore a verified backup or use the matching application version.")
    return r

def plan(path):
    r = inspect(path); info = {m[0]: m for m in MIGRATIONS}
    r["actions"] = [dict(version=v, name=info[v][1], does=info[v][5]) for v in r["pending"]]; return r

def apply(path, log=lambda s: None):
    """Apply pending migrations (and re-run idempotent ones whose post-conditions fail). Returns list of applied/repaired versions. Raises MigrationError."""
    check_compat(path)
    if not os.path.exists(path): raise MigrationError(f"database file not found: {os.path.basename(path)}")
    c = _rw(path); done = []
    try:
        c.execute("BEGIN IMMEDIATE"); c.execute("CREATE TABLE IF NOT EXISTS schema_migrations(version INTEGER PRIMARY KEY, name TEXT NOT NULL, checksum TEXT NOT NULL, applied_at TEXT NOT NULL)"); c.execute("COMMIT")
        for m in MIGRATIONS:
            v, name, _, fn, chk, _d = m
            try:
                c.execute("BEGIN IMMEDIATE")
                row = c.execute("SELECT checksum FROM schema_migrations WHERE version=?", (v,)).fetchone()      # re-read INSIDE the writer lock: another process may have applied it
                if row and not chk(c): c.execute("COMMIT"); continue
                if row and row[0] != checksum(m): raise ChecksumMismatch(f"migration {v} checksum differs")
                fn(c); bad = chk(c)
                if bad: raise MigrationError("post-condition failed: " + "; ".join(bad))
                if not row: c.execute("INSERT INTO schema_migrations(version,name,checksum,applied_at) VALUES(?,?,?,?)", (v, name, checksum(m), _utc()))
                c.execute("COMMIT"); done.append(v); log(f"{'repaired' if row else 'applied'} {v} {name}")
            except MigrationError: _rb(c); raise
            except Exception as e:
                _rb(c); raise MigrationError(f"migration {v} ({name}) failed: {type(e).__name__}: {str(e)[:200]}. This migration was rolled back; earlier ones are recorded. Fix the cause and re-run; it is safe to retry.") from None
    finally: c.close()
    return done
def _rb(c):
    try: c.execute("ROLLBACK")
    except sqlite3.Error: pass

def startup(path, fresh):
    """Called by db.init_db(). New database -> apply everything. Existing database -> never migrated implicitly (SOC_AUTO_MIGRATE=1 opts in); a notice is printed instead."""
    r = inspect(path)
    if not (r["pending"] or r["problems"]): return
    if fresh or os.environ.get("SOC_AUTO_MIGRATE") == "1": apply(path); return
    print(f"  NOTICE: {len(r['pending'])} database migration(s) pending (additive only). Review with `python migrate.py plan`, back up, then `python migrate.py apply --yes`. The application keeps running without them.", file=sys.stderr)
