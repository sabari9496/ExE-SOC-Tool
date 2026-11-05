"""Tamper-evident audit log: each row's chain MAC = HMAC(key, prev_mac || id || ts || user || action). The key is derived from the encryption key ring (outside the DB),
so an attacker with ONLY database write access cannot recompute the chain. LIMIT (documented): an attacker holding the DB AND the key can rewrite everything;
that is what the off-host signed checkpoints are for - ship them to a place the SOC host cannot modify (WORM bucket, remote syslog, another host)."""
import hmac, hashlib, json, os, time
from . import crypto
GENESIS = "0" * 64
def _kid(c):
    r = c.execute("SELECT value FROM settings WHERE key='audit_key_kid'").fetchone()
    if r: return r[0]
    k = crypto.primary_kid(); c.execute("INSERT OR IGNORE INTO settings VALUES('audit_key_kid',?)", (k,)); return k
def _mac(prev, rid, ts, user, action, kid): return hmac.new(crypto.mac_key("audit-chain", kid), f"{prev}|{rid}|{ts}|{user}|{action}".encode(), hashlib.sha256).hexdigest()
def ensure(x): x("CREATE TABLE IF NOT EXISTS audit_chain(audit_id INTEGER PRIMARY KEY, prev TEXT NOT NULL, mac TEXT NOT NULL)")
def append(c, rid, ts, user, action):
    """c = open sqlite connection inside the same transaction as the audit INSERT."""
    r = c.execute("SELECT mac FROM audit_chain ORDER BY audit_id DESC LIMIT 1").fetchone(); prev = r[0] if r else GENESIS
    c.execute("INSERT INTO audit_chain(audit_id,prev,mac) VALUES(?,?,?)", (rid, prev, _mac(prev, rid, ts, user, action, _kid(c))))
def verify(c):
    """-> dict(ok, checked, first_bad, unchained). Detects edited, deleted (gap) and reordered rows among chained entries."""
    prev = GENESIS; n = 0; unchained = 0; kid = _kid(c)
    rows = c.execute("SELECT a.id,a.ts,a.user,a.action,h.prev,h.mac FROM audit a LEFT JOIN audit_chain h ON h.audit_id=a.id ORDER BY a.id").fetchall()
    started = False
    for rid, ts, user, action, p, m in rows:
        if m is None:
            if started: return dict(ok=False, checked=n, first_bad=rid, reason="row without chain entry after chain start (injected row)")
            unchained += 1; continue
        started = True
        if p != prev or not hmac.compare_digest(m, _mac(prev, rid, ts, user, action, kid)): return dict(ok=False, checked=n, first_bad=rid, reason="chain mismatch (row edited, deleted or reordered)")
        prev = m; n += 1
    if c.execute("SELECT COUNT(*) FROM audit_chain WHERE audit_id NOT IN (SELECT id FROM audit)").fetchone()[0]: return dict(ok=False, checked=n, first_bad=None, reason="audit rows deleted (orphan chain entries)")
    return dict(ok=True, checked=n, head=prev, unchained=unchained)
def checkpoint(c, out_dir=None):
    """Signed head record. Written to out_dir (should be an off-host/remote mount or shipped by tools/audit_checkpoint.py). Returns the record."""
    v = verify(c); rec = dict(ts=time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()), head=v.get("head", GENESIS), count=v.get("checked", 0), chain_ok=v["ok"])
    rec["kid"] = _kid(c); rec["sig"] = hmac.new(crypto.mac_key("audit-checkpoint", rec["kid"]), json.dumps({k: rec[k] for k in ("ts", "head", "count", "chain_ok")}, sort_keys=True).encode(), hashlib.sha256).hexdigest()
    if out_dir:
        os.makedirs(out_dir, exist_ok=True)
        with open(os.path.join(out_dir, "audit-checkpoints.jsonl"), "a") as f: f.write(json.dumps(rec) + "\n")
    return rec
def verify_checkpoint(rec, c):
    """Compare a stored (off-host) checkpoint with the live DB: signature valid AND the live chain still contains that head at that position."""
    exp = hmac.new(crypto.mac_key("audit-checkpoint", rec.get("kid")), json.dumps({k: rec[k] for k in ("ts", "head", "count", "chain_ok")}, sort_keys=True).encode(), hashlib.sha256).hexdigest()
    if not hmac.compare_digest(exp, rec.get("sig", "")): return False, "checkpoint signature invalid"
    r = c.execute("SELECT 1 FROM audit_chain WHERE mac=?", (rec["head"],)).fetchone() if rec["head"] != GENESIS else (1,)
    return (True, "head present in live chain") if r else (False, "checkpoint head missing from live chain: history was rewritten or truncated")
