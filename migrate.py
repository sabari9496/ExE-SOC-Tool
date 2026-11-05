#!/usr/bin/env python3
"""EXE-SOC database migrations.   python migrate.py status|plan|apply [--db PATH] [--backup-dir DIR] [--yes]
status / plan are READ-ONLY. apply on a database that already holds data needs --yes (operator approval) and first takes AND verifies a backup in --backup-dir; if the
backup fails, nothing is migrated. Never run against a database you have not backed up elsewhere; try it on a copy first."""
import os, sys, argparse, sqlite3
HERE = os.path.dirname(os.path.abspath(__file__)); sys.path.insert(0, HERE)
import migrations, dbbackup

def _has_data(path):
    try:
        c = sqlite3.connect(f"file:{os.path.abspath(path)}?mode=ro", uri=True)
        try: return c.execute("SELECT COUNT(*) FROM users").fetchone()[0] > 0
        finally: c.close()
    except sqlite3.Error: return False

def main(argv=None):
    ap = argparse.ArgumentParser(prog="migrate.py"); ap.add_argument("cmd", choices=("status", "plan", "apply")); ap.add_argument("--db", default=os.environ.get("SOC_DB") or os.path.join(HERE, "soc.db"))
    ap.add_argument("--backup-dir"); ap.add_argument("--yes", action="store_true", help="operator approval to migrate a database that contains data"); a = ap.parse_args(argv)
    try:
        migrations.check_compat(a.db)                                      # a database newer than this code (or with a tampered migration record) is refused for every command
        r = migrations.plan(a.db) if a.cmd != "apply" else None
        if a.cmd in ("status", "plan"):
            print(f"database: {os.path.basename(a.db)}  exists={r['exists']}  tracked={r['tracked']}  code_latest={migrations.LATEST}")
            print("recorded: " + (", ".join(f"{x['version']}:{x['name']}" for x in r["recorded"]) or "none")); print("pending:  " + (", ".join(map(str, r["pending"])) or "none"))
            for x in r.get("actions", []): print(f"  would apply {x['version']} {x['name']}: {x['does']}")
            for p in r["problems"]: print("  PROBLEM:", p)
            print("(read-only: nothing was changed)"); return 1 if r["problems"] else 0
        if not os.path.exists(a.db): print("FAILED: database file not found", file=sys.stderr); return 2
        if _has_data(a.db):
            if not a.yes: print("This database contains data. Re-run with --yes after you have read `plan` and have a safe copy. Nothing was changed.", file=sys.stderr); return 3
            bdir = a.backup_dir or os.path.join(os.path.dirname(os.path.abspath(a.db)), "backups-premigrate"); b = dbbackup.create(a.db, bdir)
            print(f"verified backup before migrating: {b['path']} (integrity={b['verify']['integrity']})")
        done = migrations.apply(a.db, log=lambda s: print("  " + s)); print("applied/repaired: " + (", ".join(map(str, done)) or "nothing to do")); return 0
    except (migrations.MigrationError, dbbackup.BackupError) as e: print(f"FAILED: {e}", file=sys.stderr); return 2
if __name__ == "__main__": sys.exit(main())
