"""Encrypted, verifiable SQLite backups (AES-256-GCM via the key ring; keys are NOT in the backup). File: <dir>/soc-YYYYmmdd-HHMMSS.db.enc (0600) + .sha256 manifest.
create() uses the SQLite online-backup API (consistent snapshot, safe while running). verify() decrypts into a scratch dir, runs PRAGMA integrity_check and counts tables.
restore() ALWAYS targets a path you choose (never overwrites the live DB by itself). rotate() keeps the newest N and refuses to delete the only verified backup."""
import os, sqlite3, time, hashlib, tempfile, glob, shutil
from . import crypto
class BackupError(Exception): pass
def _dir(d): os.makedirs(d, mode=0o700, exist_ok=True); return d
def create(db_path, dest_dir):
    _dir(dest_dir); name = time.strftime("soc-%Y%m%d-%H%M%S", time.gmtime()) + f"-{os.getpid()}.db.enc"; out = os.path.join(dest_dir, name)
    fd, tmp = tempfile.mkstemp(suffix=".db", dir=dest_dir); os.close(fd)
    try:
        src = sqlite3.connect(db_path, timeout=30); dst = sqlite3.connect(tmp)
        try: src.backup(dst)
        finally: dst.close(); src.close()
        enc = crypto.encrypt_bytes(open(tmp, "rb").read(), "backup|" + name)
    finally:
        if os.path.exists(tmp): os.remove(tmp)
    fd = os.open(out + ".part", os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "w") as f: f.write(enc); f.flush(); os.fsync(f.fileno())
    os.replace(out + ".part", out)                                                  # atomic publish
    with open(out + ".sha256", "w") as f: f.write(hashlib.sha256(enc.encode()).hexdigest() + "  " + name + "\n")
    os.chmod(out + ".sha256", 0o600); return out
def verify(path, scratch_dir=None):
    """-> dict(ok, tables, integrity). Raises BackupError on any failure (tampering, wrong key, corruption)."""
    name = os.path.basename(path); enc = open(path).read(); mf = path + ".sha256"
    if os.path.exists(mf) and open(mf).read().split()[0] != hashlib.sha256(enc.encode()).hexdigest(): raise BackupError("manifest hash mismatch (file modified)")
    try: raw = crypto.decrypt_bytes(enc, "backup|" + name)
    except Exception as e: raise BackupError(str(e))
    d = scratch_dir or tempfile.mkdtemp(prefix="soc-verify-"); os.makedirs(d, mode=0o700, exist_ok=True); p = os.path.join(d, "verify.db")
    with open(p, "wb") as f: f.write(raw)
    c = sqlite3.connect(p)
    try:
        ic = c.execute("PRAGMA integrity_check").fetchone()[0]; n = c.execute("SELECT COUNT(*) FROM sqlite_master WHERE type='table'").fetchone()[0]
        if ic != "ok" or n == 0: raise BackupError(f"integrity_check={ic}, tables={n}")
        users = c.execute("SELECT COUNT(*) FROM users").fetchone()[0] if c.execute("SELECT 1 FROM sqlite_master WHERE name='users'").fetchone() else 0
    finally: c.close()
    if scratch_dir is None: shutil.rmtree(d, ignore_errors=True)
    return dict(ok=True, tables=n, users=users, integrity=ic)
def restore(path, target):
    """Decrypt+verify, then write to `target` (must not exist). Caller decides how to swap it into place (see docs/BACKUP-RESTORE.md)."""
    if os.path.exists(target): raise BackupError("restore target already exists; refusing to overwrite")
    verify(path); name = os.path.basename(path); raw = crypto.decrypt_bytes(open(path).read(), "backup|" + name)
    fd = os.open(target, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, "wb") as f: f.write(raw)
    return target
def rotate(dest_dir, keep=14):
    files = sorted(glob.glob(os.path.join(dest_dir, "soc-*.db.enc")), reverse=True); removed = []
    good = None
    for f in files:
        try: verify(f); good = f; break
        except BackupError: continue
    if good is None: raise BackupError("no verifiable backup present; refusing to delete anything")
    for f in files[keep:]:
        for p in (f, f + ".sha256"):
            if os.path.exists(p): os.remove(p)
        removed.append(f)
    return removed
