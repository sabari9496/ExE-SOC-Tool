#!/usr/bin/env python3
"""Secret rotation helper. NEVER prints secret values: new secrets are written to a 0600 file you name.
  enc-key  --out FILE   new encryption key prepended to the key ring (old keys kept for decryption). Put FILE's SOC_ENC_KEYS line in the server environment, restart, then run `reencrypt`.
  reencrypt             re-encrypt every encrypted DB field (api_key, TOTP secrets, agent signing keys) with the primary key, one transaction, verified.
  session-secret --out FILE   new SOC_SECRET (cookie signing). Applying it logs every user out.
  ingest-key --out FILE       new shared ingest key (stored encrypted); the old key stops working immediately.
Run against a COPY first (SOC_DB=...). Take a verified backup before `reencrypt` (python tools/backup.py create)."""
import os, sys, argparse, secrets
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import db
from security import crypto
def w(path, text):
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, "w") as f: f.write(text + "\n"); f.flush(); os.fsync(f.fileno())
def preflight(path):
    """Refuse BEFORE changing anything if the output file cannot be created (P5-01: a late failure used to leave a rotated, undelivered key)."""
    if os.path.lexists(path): sys.exit(f"refusing: {path} already exists (choose a new --out; nothing was changed)")
    d = os.path.dirname(os.path.abspath(path))
    if not os.path.isdir(d) or not os.access(d, os.W_OK): sys.exit(f"refusing: cannot write in {d} (nothing was changed)")
FIELDS = [("settings", "key", "value", lambda k: "setting|" + k, "key='api_key'"), ("user_mfa", "username", "secret_enc", lambda k: "totp|" + k, "1=1"), ("agent_credentials", "credential_id", "sign_key_enc", lambda k: "agentkey|" + k, "sign_key_enc IS NOT NULL")]
def reencrypt():
    c = db.conn(); n = 0
    try:
        c.execute("BEGIN IMMEDIATE")
        for t, pk, col, ctx, where in FIELDS:
            try: rows = c.execute(f"SELECT {pk},{col} FROM {t} WHERE {where}").fetchall()
            except Exception: continue
            for k, v in rows:
                if crypto.is_encrypted(v) and crypto.needs_rotation(v):
                    nv = crypto.rotate(v, ctx(k)); assert crypto.decrypt(nv, ctx(k)) == crypto.decrypt(v, ctx(k)); c.execute(f"UPDATE {t} SET {col}=? WHERE {pk}=?", (nv, k)); n += 1
        c.commit()
    except Exception: c.rollback(); raise
    finally: c.close()
    print(f"re-encrypted {n} field(s) with key '{crypto.primary_kid()}'. Old keys must stay in the ring: backups and the audit chain still reference them.")
def main():
    a = argparse.ArgumentParser(); s = a.add_subparsers(dest="cmd", required=True)
    for n in ("enc-key", "session-secret", "ingest-key"): s.add_parser(n).add_argument("--out", required=True)
    s.add_parser("reencrypt"); r = a.parse_args()
    if getattr(r, "out", None): preflight(r.out)
    if r.cmd == "enc-key":
        ring = crypto.load_ring(); kid = "k" + str(max([int(k[1:]) for k, _ in ring if k[1:].isdigit()] + [0]) + 1)
        old = ",".join(k + ":" + crypto._b64e(v) for k, v in ring); w(r.out, f"SOC_ENC_KEYS={kid}:{crypto.new_key()},{old}"); print(f"wrote new key ring to {r.out} (mode 0600). New primary id: {kid}")
    elif r.cmd == "session-secret": w(r.out, f"SOC_SECRET={secrets.token_hex(32)}"); print(f"wrote new SOC_SECRET to {r.out} (mode 0600); applying it ends all sessions.")
    elif r.cmd == "ingest-key":
        k = secrets.token_hex(24); w(r.out, f"INGEST_KEY={k}")
        try: db.set_secret_setting("api_key", k); db.audit_add("cli", "Shared ingest API key rotated (CLI)")
        except Exception as ex:                      # never leave a key file that was not applied (P5-01)
            try: os.unlink(r.out)
            except OSError: pass
            sys.exit(f"rotation FAILED ({type(ex).__name__}); the output file was removed and the stored key is unchanged")
        print(f"new ingest key written to {r.out} (mode 0600); old key is dead.")
    else: reencrypt()
if __name__ == "__main__": main()
