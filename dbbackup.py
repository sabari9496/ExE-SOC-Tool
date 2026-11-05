"""Safe SQLite backup / verify / restore for EXE-SOC. Uses SQLite's online-backup API (consistent snapshot while the app is writing, WAL included).
Never reads or copies .secret or any key file. Restore NEVER touches the live database unless explicitly told to AND a verified backup of the destination is taken first.
  python dbbackup.py backup  --db soc.db --dest backups/            -> backups/exesoc-YYYYmmddTHHMMSSZ.db (+ .json metadata, mode 0600)
  python dbbackup.py verify  backups/exesoc-....db
  python dbbackup.py restore backups/exesoc-....db --to restored.db  (new file; refuses to overwrite)
  python dbbackup.py restore backups/x.db --to soc.db --overwrite --backup-existing-to safety/   (stop the application first)"""
import os, sys, json, sqlite3, hashlib, argparse, time
from datetime import datetime, timezone

class BackupError(Exception): pass
CORE = ("users", "events", "alerts", "audit", "settings", "endpoints")

def _sha(path):
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for b in iter(lambda: f.read(1 << 20), b""): h.update(b)
    return h.hexdigest()
def _utc(): return datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
def _chmod(p):
    try: os.chmod(p, 0o600)                       # best effort: on Windows only the read-only flag is honoured; use folder ACLs there (see docs)
    except OSError: pass
def _fsync(path):
    fd = os.open(path, os.O_RDONLY)
    try: os.fsync(fd)
    finally: os.close(fd)

def verify(path, require_core=True):
    """Integrity + structure check on a database file, READ-ONLY. Returns {ok, tables, integrity, schema_version}. Row contents are never printed."""
    if not os.path.isfile(path): raise BackupError("backup file not found")
    meta = path + ".json"
    if os.path.exists(meta):
        try: exp = json.load(open(meta))["sha256"]
        except (ValueError, KeyError): raise BackupError("backup metadata unreadable")
        if _sha(path) != exp: raise BackupError("checksum mismatch: the backup file changed after it was created")
    try: c = sqlite3.connect(f"file:{os.path.abspath(path)}?mode=ro", uri=True, timeout=10)
    except sqlite3.Error as e: raise BackupError(f"cannot open: {type(e).__name__}")
    try:
        ic = c.execute("PRAGMA integrity_check").fetchone()[0]
        tabs = {r[0] for r in c.execute("SELECT name FROM sqlite_master WHERE type='table'")}
        if ic != "ok": raise BackupError(f"integrity_check failed: {str(ic)[:80]}")
        miss = [t for t in CORE if t not in tabs]
        if require_core and miss: raise BackupError("expected tables missing: " + ", ".join(miss))
        ver = c.execute("SELECT MAX(version) FROM schema_migrations").fetchone()[0] if "schema_migrations" in tabs else None
        return dict(ok=True, tables=len(tabs), integrity=ic, schema_version=ver)
    except sqlite3.Error as e: raise BackupError(f"verification failed: {type(e).__name__}")
    finally: c.close()

def create(db_path, dest_dir):
    """Consistent online backup of db_path into dest_dir. Source is opened READ-ONLY. Returns {path, sha256, bytes, verify}."""
    if not os.path.isfile(db_path): raise BackupError("source database not found")
    os.makedirs(dest_dir, mode=0o700, exist_ok=True); out = os.path.join(dest_dir, f"exesoc-{_utc()}.db")
    if os.path.exists(out): raise BackupError("backup name already exists; retry in a second")
    tmp = out + ".partial"
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600); os.close(fd)
    src = dst = None
    try:
        src = sqlite3.connect(f"file:{os.path.abspath(db_path)}?mode=ro", uri=True, timeout=30); dst = sqlite3.connect(tmp)
        src.backup(dst); dst.execute("PRAGMA journal_mode=DELETE"); dst.close(); dst = None; src.close(); src = None
        _fsync(tmp); v = verify(tmp); os.replace(tmp, out); _chmod(out)
        sha = _sha(out); meta = dict(format=1, created_utc=_utc(), sha256=sha, bytes=os.path.getsize(out), sqlite_version=sqlite3.sqlite_version, tables=v["tables"], schema_version=v["schema_version"], source_name=os.path.basename(db_path))
        with open(out + ".json", "w") as f: json.dump(meta, f, indent=1)
        _chmod(out + ".json"); return dict(path=out, sha256=sha, bytes=meta["bytes"], verify=v)
    except Exception:
        for x in (src, dst):
            try: x and x.close()
            except Exception: pass
        try: os.remove(tmp)
        except OSError: pass
        raise

def restore(backup_path, dest, overwrite=False, backup_existing_to=None):
    """Restore into `dest`. By default dest must NOT exist. With overwrite=True a verified backup of the existing dest is taken first (backup_existing_to is required);
    old -wal/-shm sidecars are renamed aside (never reused, never deleted). Any error leaves dest exactly as it was."""
    info = verify(backup_path)
    exists = os.path.exists(dest)
    if exists and not overwrite: raise BackupError("destination exists; refusing to overwrite (use a new file, or --overwrite with --backup-existing-to)")
    if exists and not backup_existing_to: raise BackupError("--overwrite requires --backup-existing-to so the current database is backed up and verified first")
    if os.path.abspath(dest) == os.path.abspath(backup_path): raise BackupError("destination is the backup itself")
    d = os.path.dirname(os.path.abspath(dest)) or "."; os.makedirs(d, exist_ok=True); tmp = dest + ".restoring"
    safety = None
    try:
        if exists: safety = create(dest, backup_existing_to)             # verified (integrity + checksum) BEFORE anything is replaced
        fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600); os.close(fd)
        s = sqlite3.connect(f"file:{os.path.abspath(backup_path)}?mode=ro", uri=True); t = sqlite3.connect(tmp)
        try: s.backup(t); t.execute("PRAGMA journal_mode=DELETE")
        finally: t.close(); s.close()
        verify(tmp); _fsync(tmp); _chmod(tmp)
        if exists:
            stamp = _utc()
            for ext in ("-wal", "-shm"):
                if os.path.exists(dest + ext): os.replace(dest + ext, f"{dest}{ext}.replaced-{stamp}")
        os.replace(tmp, dest); return dict(restored=dest, verify=verify(dest), previous_backup=safety["path"] if safety else None)
    except Exception:
        try: os.remove(tmp)
        except OSError: pass
        raise

def main(argv=None):
    ap = argparse.ArgumentParser(prog="dbbackup.py"); sp = ap.add_subparsers(dest="cmd", required=True)
    b = sp.add_parser("backup"); b.add_argument("--db", default=os.environ.get("SOC_DB") or os.path.join(os.path.dirname(os.path.abspath(__file__)), "soc.db")); b.add_argument("--dest", required=True)
    v = sp.add_parser("verify"); v.add_argument("file")
    r = sp.add_parser("restore"); r.add_argument("file"); r.add_argument("--to", required=True); r.add_argument("--overwrite", action="store_true"); r.add_argument("--backup-existing-to")
    a = ap.parse_args(argv)
    try:
        if a.cmd == "backup": o = create(a.db, a.dest); print(f"backup OK: {o['path']}  ({o['bytes']} bytes, sha256 {o['sha256'][:16]}..., tables={o['verify']['tables']}, integrity={o['verify']['integrity']})")
        elif a.cmd == "verify": o = verify(a.file); print(f"verify OK: tables={o['tables']} integrity={o['integrity']} schema_version={o['schema_version']}")
        else: o = restore(a.file, a.to, a.overwrite, a.backup_existing_to); print(f"restore OK: {o['restored']} (tables={o['verify']['tables']}); previous database backed up to: {o['previous_backup'] or 'n/a (new file)'}")
    except BackupError as e: print(f"FAILED: {e}", file=sys.stderr); return 2
    return 0
if __name__ == "__main__": sys.exit(main())
