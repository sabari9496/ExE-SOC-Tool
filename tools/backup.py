#!/usr/bin/env python3
"""Encrypted backups: create | verify FILE | restore FILE --to NEWPATH | rotate [--keep N] | drill. Dir: SOC_BACKUP_DIR (default <db dir>/backups). Keys are NOT included: keep SOC_ENC_KEYS backed up separately."""
import os, sys, argparse, tempfile, shutil
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import db
from security import backup as bk
D = os.environ.get("SOC_BACKUP_DIR") or os.path.join(os.path.dirname(os.path.abspath(db.DB)), "backups")
a = argparse.ArgumentParser(); s = a.add_subparsers(dest="c", required=True); s.add_parser("create"); s.add_parser("drill"); v = s.add_parser("verify"); v.add_argument("file")
r_ = s.add_parser("restore"); r_.add_argument("file"); r_.add_argument("--to", required=True); ro = s.add_parser("rotate"); ro.add_argument("--keep", type=int, default=14); r = a.parse_args()
try:
    if r.c == "create": p = bk.create(db.DB, D); print("created", p, bk.verify(p))
    elif r.c == "verify": print(bk.verify(r.file))
    elif r.c == "restore": print("restored to", bk.restore(r.file, r.to), "(swap into place only with the service stopped; see docs/BACKUP-RESTORE.md)")
    elif r.c == "rotate": print("removed", bk.rotate(D, r.keep))
    elif r.c == "drill":
        p = bk.create(db.DB, D); t = tempfile.mkdtemp(prefix="soc-drill-"); out = bk.restore(p, os.path.join(t, "restored.db")); import sqlite3
        c = sqlite3.connect(out); n = {k: c.execute(f"SELECT COUNT(*) FROM {k}").fetchone()[0] for k in ("users", "alerts", "events", "audit")}; c.close(); shutil.rmtree(t); print("restore drill OK:", n)
except bk.BackupError as e: sys.exit(f"FAILED: {e}")
