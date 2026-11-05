"""Fleet REST API. Analyst/admin routes use the existing login + role + CSRF header (need()). Agent routes use per-agent bearer credentials.
Agent auth:  Authorization: Bearer <credential_id>.<secret>   X-Timestamp: <unix seconds>   X-Nonce: <random>
  - only SHA-256(secret) is stored; secrets are shown to the agent once at enrollment and never returned by any GET.
  - timestamp must be within +-5 min; a nonce can be used once (replay protection); per-agent + per-IP rate limits."""
import re, json, time, secrets, threading, hmac, math, sqlite3
from collections import defaultdict, deque
from datetime import datetime, timedelta, timezone
from functools import wraps
from flask import Blueprint, jsonify, request
from db import q, x, now, conn, iarg
import engine, fleet
import os
from security import agentsig, crypto
from fleet import sha, agent_status

bp = Blueprint("fleet", __name__)
MAX_BATCH, MAX_BODY = 500, 2_000_000
SKEW = 300
MAX_ATTEMPTS = max(1, int(os.environ.get("SOC_INGEST_MAX_ATTEMPTS", 5)))     # processing failures per event before it is quarantined
MAX_EVENT_BYTES, LEASE_S = 65536, 120
def _envint(name, default, lo, hi):
    try: return min(max(int(os.environ.get(name, default)), lo), hi)
    except ValueError: return default
QUARANTINE_PAYLOAD_ROWS = _envint("SOC_QUARANTINE_PAYLOAD_ROWS", 5000, 0, 10 ** 7)   # rows per agent that keep a (redacted) payload; beyond that only metadata is kept
QUARANTINE_AGENT_ROWS = _envint("SOC_QUARANTINE_AGENT_ROWS", 20000, 1, 10 ** 7)      # hard per-agent row cap
QUARANTINE_TOTAL_ROWS = _envint("SOC_QUARANTINE_TOTAL_ROWS", 200000, 1, 10 ** 8)     # hard global row cap. At a cap nothing is deleted: the event stays retryable on the agent ("quarantine_full")

from .config import ConfigError, dedup_days, stale_guard_on, validate_config
from . import osmeta
from .monitoring import schema_ready as v4_ready, register as register_monitoring   # noqa: E402  (strict settings live in fleet/config.py)
UID_RX = re.compile(r"[^\x00-\x1f\x7f]{1,80}")                       # same contract as before (any non-empty id up to 80 chars), minus control characters; longer ids are rejected, never truncated
_RL = defaultdict(deque); _RL_LOCK = threading.Lock()
LIMITS = {"register": (10, 60), "heartbeat": (12, 60), "events": (60, 60), "ip": (300, 60)}     # (requests, seconds)
_KEYS = r"(?:password|passwd|pwd|secret|token|access[_-]?token|refresh[_-]?token|api[_-]?key|apikey|authorization|cookie|set-cookie|session(?:[_-]?id)?|private[_-]?key|credential|signing[_-]?key|sign[_-]?key)"
SECRET_RX = re.compile(r"(?i)([\"']?" + _KEYS + r"[\"']?\s*[=:]\s*)(bearer\s+\S+|basic\s+\S+|\"[^\"]*\"|'[^']*'|[^\s,;}\]]+)")
BEARER_RX = re.compile(r"(?i)\b(bearer|basic)\s+[A-Za-z0-9._~+/=-]{8,}")
PEM_RX = re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----.*?(?:-----END [A-Z ]*PRIVATE KEY-----|$)", re.S)
SENSITIVE_KEY_RX = re.compile(r"(?i)" + _KEYS)
CTRL_RX = re.compile(r"[\x00-\x08\x0b\x0c\x0e-\x1f]")

def _scrub(t):
    t = PEM_RX.sub("[REDACTED PRIVATE KEY]", CTRL_RX.sub("", t))
    return BEARER_RX.sub(r"\1 [REDACTED]", SECRET_RX.sub(r"\1[REDACTED]", t))

def sanitize(v, n=4000):
    """Strip control characters and redact credential-looking values before anything is stored or logged. Containers are redacted structurally (see redact_obj)."""
    if v is None: return None
    if isinstance(v, (dict, list, tuple)): v = json.dumps(redact_obj(v), ensure_ascii=False, default=str)
    return _scrub(str(v))[:n]

def redact_obj(v, depth=0):
    """Structural redaction for nested payloads: any value under a credential-like key (any case, any depth) is replaced; strings are scrubbed. Bounded depth/width."""
    if depth > 6: return "[TRUNCATED]"
    if isinstance(v, dict):
        return {str(k)[:100]: ("[REDACTED]" if SENSITIVE_KEY_RX.search(str(k)) else redact_obj(x, depth + 1)) for k, x in list(v.items())[:200]}
    if isinstance(v, (list, tuple)): return [redact_obj(x, depth + 1) for x in list(v)[:200]]
    if isinstance(v, str): return _scrub(v)[:4000]
    return v

def limited(key, kind):
    n, win = LIMITS[kind]; t = time.time()
    with _RL_LOCK:
        d = _RL[(kind, key)]
        while d and d[0] < t - win: d.popleft()
        if len(d) >= n: return True
        d.append(t); return False

def iso_ok(ts):
    """Parse an agent event time (UTC ISO). Reject unparsable or far-future times; old times are fine (offline queue)."""
    try:
        d = datetime.fromisoformat(str(ts).strip().replace("Z", "+00:00"))
        if d.tzinfo is None: d = d.replace(tzinfo=timezone.utc)
        return None if d > datetime.now(timezone.utc) + timedelta(minutes=10) else d
    except Exception: return None

def begin_immediate(c, tries=3):
    """BEGIN IMMEDIATE with bounded retry + backoff (connection timeout already waits SOC_DB_TIMEOUT). False = still busy: caller answers 503 and the agent retries later."""
    for i in range(tries):
        try: c.execute("BEGIN IMMEDIATE"); return True
        except sqlite3.OperationalError:
            if i < tries - 1: time.sleep(0.05 * 2 ** i + secrets.randbelow(50) / 1000)
    return False

def _finalize(aid, host, endpoint_id, good, ok):
    """Mark events processed + counters, in ONE transaction. Raises on failure (caller releases the claims). Events/alerts were already committed by the engine; a failure
    here leaves the ledger 'pending' so the retry re-runs idempotently (unique event index, alert link) instead of double-counting."""
    okset = set(ok); c = conn()
    try:
        for item in good:
            if item["uid"] not in okset: continue
            event_ts = engine._utc_to_local(item.get("event_time") or "") or now()
            c.execute("UPDATE events SET agent_id=? WHERE host IS ? AND channel IS ? AND record_id=? AND ts=? AND agent_id IS NULL", (aid, host, item.get("channel"), item["record_id"], event_ts))
        c.execute("UPDATE alerts SET agent_id=? WHERE endpoint_id=? AND agent_id IS NULL", (aid, endpoint_id))
        c.executemany("UPDATE agent_event_ids SET status='processed',claimed_at=NULL,ts=?,last_error=NULL WHERE agent_id=? AND uid=? AND status='processing'", [(now(), aid, u) for u in ok])
        c.execute("UPDATE agents SET events_total=events_total+?,last_event_at=? WHERE id=?", (len(ok), now(), aid))
        c.commit()
    except Exception: c.rollback(); raise
    finally: c.close()

_last_purge = [0.0]; _purge_lock = threading.Lock()
last_purge = {"at": None, "deleted": 0, "error": None}        # visible state of the cleanup job (never silent)
def purge_dedup(days=None, now_dt=None, limit=5000, max_batches=1, budget_s=None):
    """Delete processed-event ledger rows older than the retention window: up to `max_batches` batches of `limit` rows, each batch its own short transaction (so a crash or lock
    loses nothing and never leaves a half-deleted state), stopping early when a batch is not full or `budget_s` seconds are used. Only status='processed' is ever removed: 'dead',
    'pending', 'processing' rows, event_quarantine, alerts, incidents and audit are untouched. Errors are logged and recorded in `last_purge`, never swallowed. Returns rows deleted."""
    total = 0; t0 = time.time(); err = None
    try:
        cutoff = ((now_dt or datetime.now()) - timedelta(days=days or dedup_days())).strftime("%Y-%m-%d %H:%M:%S")      # may raise ConfigError: recorded below like any other failure
        for _ in range(max(1, max_batches)):
            c = conn()
            try:
                cur = c.execute("DELETE FROM agent_event_ids WHERE (agent_id,uid) IN (SELECT agent_id,uid FROM agent_event_ids WHERE status='processed' AND ts<? LIMIT ?)", (cutoff, limit)); c.commit(); n = cur.rowcount
            except sqlite3.OperationalError as e:
                c.rollback(); err = f"database busy/locked ({type(e).__name__}); cleanup will retry"; print(f"fleet: dedup purge skipped: {err}"); break
            except Exception: c.rollback(); raise
            finally: c.close()
            total += n
            if n < limit or (budget_s is not None and time.time() - t0 >= budget_s): break
    except Exception as e:                                       # committed batches stay committed; record exactly what happened, then let the caller see the failure
        last_purge.update(at=datetime.now().strftime("%Y-%m-%d %H:%M:%S"), deleted=total, error=f"{type(e).__name__}: {str(e)[:160]}"); raise
    last_purge.update(at=datetime.now().strftime("%Y-%m-%d %H:%M:%S"), deleted=total, error=err); return total

def maybe_purge(sync=False):
    """At most once per 10 minutes per process (60 s after a failed run), never more than one cleanup at a time (non-blocking lock), on a daemon thread so the request is not delayed.
    A run does up to 20 batches of 5 000 rows and stops after 2 s: that is a LIMIT per run, not a measured production rate."""
    if time.time() - _last_purge[0] < 600 or not _purge_lock.acquire(blocking=False): return
    _last_purge[0] = time.time()
    def run():
        try: purge_dedup(max_batches=20, budget_s=2.0)
        except Exception as e: print(f"fleet: dedup purge failed: {type(e).__name__}: {str(e)[:160]}")           # last_purge already holds the partial result + error
        finally:
            if last_purge["error"]: _last_purge[0] = time.time() - 540                                          # failed/skipped run: retry in about 60 s instead of 10 minutes
            _purge_lock.release()
    if sync: run()
    else:
        try: threading.Thread(target=run, daemon=True, name="dedup-purge").start()
        except Exception: _purge_lock.release(); raise

def validate_event(e):
    """-> (reason, parsed_time). reason is None when the event is acceptable. Pure function; reasons are stable machine codes shown to the agent."""
    m = e.get("message")
    if not isinstance(m, str) or not m.strip(): return "bad_message", None
    try:
        if len(json.dumps(e, default=str)) > MAX_EVENT_BYTES: return "event_too_large", None
    except (TypeError, ValueError): return "bad_event", None
    for k in ("event_id", "record_id"):                      # wrongly typed ids are tolerated (ignored, as before); only values that would break storage are refused
        v = e.get(k)
        if isinstance(v, int) and not isinstance(v, bool) and abs(v) >= 2 ** 62: return "bad_" + k, None
    for v in e.values():
        if isinstance(v, float) and not math.isfinite(v): return "non_finite_number", None
    ts = e.get("event_time")
    if ts is None or ts == "": return None, datetime.now(timezone.utc)
    if not isinstance(ts, str): return "bad_timestamp", None
    try:
        t = datetime.fromisoformat(ts.strip().replace("Z", "+00:00"))
        if t.tzinfo is None: t = t.replace(tzinfo=timezone.utc)
    except (ValueError, OverflowError): return "bad_timestamp", None
    if t > datetime.now(timezone.utc) + timedelta(minutes=10): return "timestamp_in_future", None
    if stale_guard_on() and t < datetime.now(timezone.utc) - timedelta(days=dedup_days() - 1): return "timestamp_too_old", None   # opt-in replay guard: never accept an event the duplicate ledger can no longer vouch for
    return None, t

def deny(msg, code=401): return jsonify(error=msg), code

def agent_auth(f):
    @wraps(f)
    def w(*a, **k):
        ip = request.remote_addr or "?"
        if limited(ip, "ip"): return deny("rate limited", 429)
        try: request.max_content_length = MAX_BODY                  # also bounds chunked uploads that carry no Content-Length
        except Exception: pass
        if (request.content_length or 0) > MAX_BODY: return deny("body too large", 413)
        h = request.headers.get("Authorization", "")
        if not h.startswith("Bearer ") or "." not in h[7:]: return deny("unauthorized")
        cid, secret = h[7:].split(".", 1)
        row = q("SELECT c.*, a.status astatus FROM agent_credentials c JOIN agents a ON a.id=c.agent_id WHERE c.credential_id=?", (cid,), one=True)
        # constant-time compare even when the credential is unknown, so timing does not reveal valid ids
        good = hmac.compare_digest(sha(secret), row["secret_hash"] if row else "0" * 64)
        if not row or not good: return deny("unauthorized")
        if row["revoked_at"] or row["astatus"] == "revoked": return deny("credential revoked", 403)
        try: ts = float(request.headers.get("X-Timestamp", ""))
        except (ValueError, TypeError, OverflowError): return deny("bad timestamp", 400)
        if not math.isfinite(ts): return deny("bad timestamp", 400)
        if abs(time.time() - ts) > SKEW: return deny("timestamp outside allowed window (check the device clock)", 400)
        nonce = request.headers.get("X-Nonce", "")
        if not (8 <= len(nonce) <= 64) or not re.fullmatch(r"[A-Za-z0-9_-]+", nonce): return deny("bad nonce", 400)
        # ---- scopes: a credential may only call what it was granted (default heartbeat + events:write) ----
        need_scope = agentsig.scope_for(request.path); granted = set((row["scopes"] or "heartbeat,events:write").split(","))
        if need_scope and need_scope not in granted: return deny("credential lacks scope " + need_scope, 403)
        # ---- request signing (HMAC-SHA256 over method, path+query, timestamp, nonce, exact body) ----
        mode = agentsig.mode(); sig = request.headers.get("X-Signature", "")
        if sig:
            if not row["sign_key_enc"]: return deny("credential has no signing key; rotate it (admin)", 401)
            try: key = agentsig.unseal(row["sign_key_enc"], cid)
            except crypto.CryptoError: return deny("server cannot verify signature (key unavailable)", 503)
            target = request.full_path.rstrip("?") if request.query_string else request.path
            if not agentsig.check(key, sig, request.method, target, request.headers.get("X-Timestamp", ""), nonce, request.get_data(cache=True)): return deny("bad signature")
            if not row["sig_required"]: x("UPDATE agent_credentials SET sig_required=1 WHERE credential_id=?", (cid,))        # downgrade ratchet
        elif mode == "hmac-required" or row["sig_required"]: return deny("signed requests required (HMAC)", 401)
        else: x("UPDATE agent_credentials SET legacy_uses=COALESCE(legacy_uses,0)+1,last_used=? WHERE credential_id=?", (now(), cid))
        # replay protection AFTER the signature is verified (P5-08): a forged request that merely repeats an observed nonce must not burn it and make the genuine request fail with 409
        c = conn()
        try:
            c.execute("DELETE FROM agent_nonces WHERE ts<?", (time.time() - SKEW * 2,))
            try: c.execute("INSERT INTO agent_nonces(nonce,ts) VALUES(?,?)", (row["agent_id"] + nonce, time.time())); c.commit()
            except Exception: return deny("replayed request", 409)
        finally: c.close()
        kind = "events" if request.path.endswith("/events") else "heartbeat"
        if limited(row["agent_id"], kind): return deny("rate limited", 429)
        request.agent_id = row["agent_id"]; return f(*a, **k)
    return w

def register(app, need, audit, body, socketio=None):
    try: validate_config()                                       # runs at import time, i.e. under gunicorn AND `python app.py`, before any request is served
    except ConfigError as e: raise SystemExit(f"ERROR: {e}")     # db.init_db() swallows fleet.init() errors (prints only), so this is the check that really stops startup
    def push(what, **d):
        if socketio:
            try: socketio.emit("refresh", {"what": "endpoints"}); socketio.emit("fleet", dict(what=what, **d))
            except Exception: pass

    # ---------- enrollment tokens (admin) ----------
    @bp.route("/api/enrollment-tokens", methods=["POST"])
    @need("admin")
    def tok_create():
        d = body(); mins = iarg(d.get("expires_minutes") or 60, 60, 5, 7 * 24 * 60)
        t = "exe-" + secrets.token_urlsafe(32)           # shown ONCE; only its hash is stored
        exp = (datetime.now() + timedelta(minutes=mins)).strftime("%Y-%m-%d %H:%M:%S")
        label = sanitize(d.get("label") or "", 80)
        x("INSERT INTO enrollment_tokens(token_hash,label,created_by,created_at,expires_at) VALUES(?,?,?,?,?)", (sha(t), label, _me(), now(), exp))
        audit(f"Enrollment token created ({label or 'no label'}, expires {exp})")
        return jsonify(token=t, expires_at=exp, note="Copy it now: it cannot be shown again. Single use.")

    @bp.route("/api/enrollment-tokens")
    @need("admin")
    def tok_list():
        rows = q("SELECT id,label,created_by,created_at,expires_at,used_at,used_by_agent,revoked_at FROM enrollment_tokens ORDER BY id DESC LIMIT 100")
        for r in rows: r["state"] = "revoked" if r["revoked_at"] else "used" if r["used_at"] else "expired" if r["expires_at"] < now() else "active"
        return jsonify(rows)

    @bp.route("/api/enrollment-tokens/<int:i>/revoke", methods=["POST"])
    @need("admin")
    def tok_revoke(i):
        x("UPDATE enrollment_tokens SET revoked_at=?,revoked_by=? WHERE id=? AND revoked_at IS NULL AND used_at IS NULL", (now(), _me(), i))
        audit(f"Enrollment token #{i} revoked"); return jsonify(ok=True)

    def _me():
        from flask import session; return session.get("user", "system")

    # ---------- agent enrollment ----------
    @bp.route("/api/agents/register", methods=["POST"])
    def agent_register():
        ip = request.remote_addr or "?"
        if limited(ip, "register"): return deny("rate limited", 429)
        d = body(); tok = d.get("enrollment_token") or ""
        if not isinstance(tok, str) or len(tok) > 200: return deny("invalid enrollment token")
        host = sanitize(d.get("hostname") or "", 100); osn = sanitize(d.get("os") or "", 40)
        if not host or not re.fullmatch(r"[\w.\- ]{1,100}", host): return deny("invalid hostname", 400)
        c = conn()
        try:
            # atomic single-use claim: only one request can flip used_at from NULL
            cur = c.execute("UPDATE enrollment_tokens SET used_at=? WHERE token_hash=? AND used_at IS NULL AND revoked_at IS NULL AND expires_at>=?", (now(), sha(tok), now()))
            if cur.rowcount != 1: c.rollback(); return deny("enrollment token invalid, expired, revoked or already used")
            aid = "ag-" + secrets.token_hex(8); cid = "cr-" + secrets.token_hex(6); secret = secrets.token_urlsafe(32); skey = agentsig.new_signing_key()
            name = host
            if c.execute("SELECT 1 FROM endpoints WHERE hostname=?", (name,)).fetchone() or c.execute("SELECT 1 FROM agents WHERE hostname=?", (name,)).fetchone(): name = f"{host}-{aid[-4:]}"
            c.execute("INSERT INTO agents(id,hostname,device_name,os,os_version,ip,agent_version,registered_at,last_heartbeat,credential_id,enrolled_by) VALUES(?,?,?,?,?,?,?,?,?,?,?)",
                      (aid, name, host, osn, sanitize(d.get("os_version"), 120), ip, sanitize(d.get("agent_version"), 20), now(), now(), cid,
                       (c.execute("SELECT created_by FROM enrollment_tokens WHERE token_hash=?", (sha(tok),)).fetchone() or [None])[0]))
            c.execute("INSERT INTO agent_credentials(credential_id,agent_id,secret_hash,created_at,sign_key_enc,scopes) VALUES(?,?,?,?,?,?)", (cid, aid, sha(secret), now(), agentsig.seal(skey, cid), "heartbeat,events:write"))
            c.execute("UPDATE enrollment_tokens SET used_by_agent=? WHERE token_hash=?", (aid, sha(tok)))
            c.commit()
        finally: c.close()
        engine.upsert_endpoint(name, ip, f"{osn} {sanitize(d.get('os_version'), 60) or ''}".strip())
        x("UPDATE agents SET endpoint_id=(SELECT id FROM endpoints WHERE hostname=?) WHERE id=?", (name, aid))
        if v4_ready(): x("UPDATE agents SET os_family=?,distro_id=?,distro_version=? WHERE id=?", (osmeta.clean_family(d.get("os_family")), osmeta.clean_distro_id(d.get("distro_id")), osmeta.clean_distro_version(d.get("distro_version")), aid))
        audit(f"Agent enrolled: {name} ({aid}) from {ip}", user="system"); push("enrolled", agent_id=aid)
        return jsonify(agent_id=aid, credential=f"{cid}.{secret}", signing_key=skey, hostname=name, heartbeat_seconds=30, server_time=int(time.time()))

    # ---------- heartbeat ----------
    @bp.route("/api/agents/heartbeat", methods=["POST"])
    @agent_auth
    def agent_hb():
        d = body(); aid = request.agent_id
        def num(k, hi=10**12):
            try: return max(0, min(float(d.get(k) or 0), hi))
            except (TypeError, ValueError): return 0
        h = {k: num(k) for k in ("cpu", "mem", "events_sent", "events_queued", "upload_failures", "upload_failures_recent")}
        lst = lambda v, n: v[:n] if isinstance(v, list) else []              # untrusted JSON: a dict/string/number must not raise (500) or be sliced as text
        h.update(last_success=sanitize(d.get("last_success"), 30), server_reachable=bool(d.get("server_reachable", True)), collectors=[sanitize(c, 60) for c in lst(d.get("collectors"), 20)],
                 collector_errors=[sanitize(c, 120) for c in lst(d.get("collector_errors"), 5)], uptime_s=num("uptime_s"), dropped=num("dropped"))
        ips = [sanitize(i, 45) for i in lst(d.get("ips"), 8)]
        a = q("SELECT hostname FROM agents WHERE id=?", (aid,), one=True)
        x("UPDATE agents SET last_heartbeat=?,agent_version=?,os_version=COALESCE(?,os_version),ip=?,ips=?,health=? WHERE id=?",
          (now(), sanitize(d.get("agent_version"), 20), sanitize(d.get("os_version"), 120), request.remote_addr, json.dumps(ips), json.dumps(h), aid))
        x("INSERT INTO agent_heartbeats(agent_id,ts,cpu,mem,events_sent,events_queued,upload_failures,last_success,version,ip) VALUES(?,?,?,?,?,?,?,?,?,?)",
          (aid, now(), h["cpu"], h["mem"], h["events_sent"], h["events_queued"], h["upload_failures"], h["last_success"], sanitize(d.get("agent_version"), 20), request.remote_addr))
        x("DELETE FROM agent_heartbeats WHERE agent_id=? AND id NOT IN (SELECT id FROM agent_heartbeats WHERE agent_id=? ORDER BY id DESC LIMIT 2880)", (aid, aid))
        if v4_ready(): x("UPDATE agents SET os_family=COALESCE(?,os_family),distro_id=COALESCE(?,distro_id),distro_version=COALESCE(?,distro_version),first_heartbeat_at=COALESCE(first_heartbeat_at,?) WHERE id=?",
                         (osmeta.clean_family(d.get("os_family")), osmeta.clean_distro_id(d.get("distro_id")), osmeta.clean_distro_version(d.get("distro_version")), now(), aid))
        engine.upsert_endpoint(a["hostname"], request.remote_addr, None, h["cpu"], h["mem"])
        push("heartbeat", agent_id=aid)
        return jsonify(ok=True, server_time=int(time.time()))

    # ---------- event ingestion (agent) ----------
    # Protocol v2 (reply carries ack_version=2). Every event in a batch gets exactly one outcome, reported by uid:
    #   accepted_uids   persisted + detection ran + ledger finalized      -> agent may delete
    #   duplicate_uids  already processed earlier                         -> agent may delete
    #   rejected_uids   permanently invalid / quarantined (kept in event_quarantine, reason in `reasons`) -> agent moves to its dead-letter queue
    #   retry_uids      temporary problem (lease conflict, database busy, processing error below the attempt limit) -> agent keeps it and retries later
    # An event that makes processing raise is retried up to SOC_INGEST_MAX_ATTEMPTS requests, then quarantined, so one poison event can never block the others.
    def release(aid, uids, err=None):
        """Give claimed events back (status 'pending') after a temporary failure. Never raises."""
        if not uids: return
        c = conn()
        try:
            c.executemany("UPDATE agent_event_ids SET status='pending',claimed_at=NULL,last_error=COALESCE(?,last_error) WHERE agent_id=? AND uid=? AND status='processing'", [(err, aid, u) for u in uids]); c.commit()
        except Exception: c.rollback()
        finally: c.close()

    def quarantine(c, aid, uid, reason, attempts, ev, dead=True):
        """Keep a permanently failed event (redacted, size-bounded) so it can be investigated. Returns False when a capacity cap is reached: NOTHING is deleted
        to make room, the caller must leave the event retryable instead. status 'dead' makes any re-delivery a deterministic rejection."""
        if not c.execute("SELECT 1 FROM event_quarantine WHERE agent_id=? AND uid=?", (aid, uid)).fetchone():
            per = c.execute("SELECT COUNT(*), COALESCE(SUM(payload IS NOT NULL),0) FROM event_quarantine WHERE agent_id=?", (aid,)).fetchone()
            if per[0] >= QUARANTINE_AGENT_ROWS or c.execute("SELECT COUNT(*) FROM event_quarantine").fetchone()[0] >= QUARANTINE_TOTAL_ROWS:
                print(f"ingest: quarantine capacity reached (agent={aid}); event stays retryable on the agent. Operator action needed (see docs)."); return False
            payload = None
            if per[1] < QUARANTINE_PAYLOAD_ROWS:
                try: payload = json.dumps(redact_obj(ev if isinstance(ev, dict) else {"raw": str(ev)}), ensure_ascii=False)[:16000]
                except Exception: payload = None
            c.execute("INSERT OR IGNORE INTO event_quarantine(agent_id,uid,reason,attempts,payload,created_at) VALUES(?,?,?,?,?,?)", (aid, uid, reason[:80], attempts, payload, now()))
        if dead: c.execute("INSERT INTO agent_event_ids(agent_id,uid,ts,status,claimed_at,attempts,last_error) VALUES(?,?,?,'dead',NULL,?,?) ON CONFLICT(agent_id,uid) DO UPDATE SET status='dead',claimed_at=NULL,attempts=excluded.attempts,last_error=excluded.last_error", (aid, uid, now(), attempts, reason[:80]))
        return True

    @bp.route("/api/events", methods=["POST"])
    @agent_auth
    def agent_events():
        aid = request.agent_id; d = body(); items = d.get("events") if isinstance(d, dict) else d
        if not isinstance(items, list): return deny("events must be a list", 400)
        if len(items) > MAX_BATCH: return deny(f"max {MAX_BATCH} events per request", 413)
        a = q("SELECT hostname,endpoint_id FROM agents WHERE id=?", (aid,), one=True)
        host = a["hostname"]; results = {}; anon = 0; good = []
        c = conn()
        try:
            # ---- A. validate + claim (one short transaction; BEGIN IMMEDIATE serializes claims across connections) ----
            if not begin_immediate(c): c.close(); return jsonify(error="database busy; retry", retryable=True), 503
            for e in items:
                uid = e.get("uid") if isinstance(e, dict) else None
                if not (isinstance(uid, str) and UID_RX.fullmatch(uid)): anon += 1; continue          # cannot be acknowledged by uid; counted only
                if uid in results: continue                                                          # same uid twice in one batch: it shares the first one's outcome (never acked early)
                reason, t = validate_event(e)
                if reason: results[uid] = ("rejected", reason) if quarantine(c, aid, uid, reason, 0, e, dead=False) else ("retry", "quarantine_full"); continue
                row = c.execute("SELECT status,claimed_at,attempts FROM agent_event_ids WHERE agent_id=? AND uid=?", (aid, uid)).fetchone()
                if row and row["status"] == "processed": results[uid] = ("duplicate", None); continue
                if row and row["status"] == "dead": results[uid] = ("rejected", "quarantined"); continue
                if row and row["status"] == "processing":
                    try: age = (datetime.now() - datetime.strptime(row["claimed_at"], "%Y-%m-%d %H:%M:%S")).total_seconds()
                    except (TypeError, ValueError): age = 10 ** 9
                    if age < LEASE_S: results[uid] = ("retry", "lease_conflict"); continue          # another request holds it: only THIS event waits
                if row: c.execute("UPDATE agent_event_ids SET status='processing',claimed_at=?,ts=? WHERE agent_id=? AND uid=?", (now(), now(), aid, uid))
                else: c.execute("INSERT INTO agent_event_ids(agent_id,uid,ts,status,claimed_at,attempts) VALUES(?,?,?,'processing',?,0)", (aid, uid, now(), now()))
                rid = e.get("record_id")
                good.append(dict(uid=uid, message=sanitize(e["message"]), host=host, channel=sanitize(e.get("channel"), 100), event_id=(e.get("event_id") if isinstance(e.get("event_id"), int) and not isinstance(e.get("event_id"), bool) else sanitize(e.get("event_id"), 40) if isinstance(e.get("event_id"), str) else None), level=sanitize(e.get("level"), 40),
                                 provider=sanitize(e.get("provider"), 100), record_id=rid if isinstance(rid, int) and not isinstance(rid, bool) else int(sha(uid)[:12], 16), event_time=t.strftime("%Y-%m-%dT%H:%M:%S.%f"),
                                 raw=sanitize(e.get("raw"), 8000), log_only=bool(e.get("log_only", True)), source_ip=sanitize(e.get("source_ip"), 45), dest_ip=sanitize(e.get("dest_ip"), 60),
                                 severity=None, title=None, category=None))
                results[uid] = ("claimed", None)
            c.commit()
        except Exception:
            c.rollback(); raise
        finally: c.close()

        # ---- B. process, isolating failures per event ----
        alerts, ok = [], []
        if good:
            try:
                alerts = [al for al in engine.process_batch(good, reprocess_duplicates=True) if al]; ok = [g["uid"] for g in good]
            except Exception as ex:
                if isinstance(ex, sqlite3.OperationalError): release(aid, [g["uid"] for g in good], "database busy"); return jsonify(error="database busy; retry", retryable=True), 503
                print(f"ingest: batch failed ({type(ex).__name__}); isolating per event, agent={aid}")      # class only: messages can echo event content
                for g in good:
                    uid = g["uid"]
                    try: alerts += [al for al in engine.process_batch([g], reprocess_duplicates=True) if al]; ok.append(uid)
                    except Exception as ex2:
                        if isinstance(ex2, sqlite3.OperationalError): results[uid] = ("retry", "database_busy"); release(aid, [uid], "database busy"); continue
                        cc = conn()
                        try:
                            att = (cc.execute("SELECT attempts FROM agent_event_ids WHERE agent_id=? AND uid=?", (aid, uid)).fetchone() or [0])[0] or 0; att += 1; err = type(ex2).__name__
                            if att >= MAX_ATTEMPTS and quarantine(cc, aid, uid, "processing_failed:" + err, att, g): results[uid] = ("rejected", "processing_failed")
                            elif att >= MAX_ATTEMPTS: cc.execute("UPDATE agent_event_ids SET status='pending',claimed_at=NULL,attempts=?,last_error=? WHERE agent_id=? AND uid=?", (att, "quarantine_full", aid, uid)); results[uid] = ("retry", "quarantine_full")
                            else: cc.execute("UPDATE agent_event_ids SET status='pending',claimed_at=NULL,attempts=?,last_error=? WHERE agent_id=? AND uid=?", (att, err, aid, uid)); results[uid] = ("retry", "processing_error")
                            cc.commit()
                        except Exception: cc.rollback(); results[uid] = ("retry", "database_busy"); release(aid, [uid])
                        finally: cc.close()
        # ---- C. finalize the successful ones durably in ONE transaction (module-level _finalize) ----
        if ok:
            try: _finalize(aid, host, a["endpoint_id"], good, ok)
            except Exception as ex:
                release(aid, ok, "finalize failed")
                if isinstance(ex, sqlite3.OperationalError): return jsonify(error="database busy; retry", retryable=True), 503
                raise
            for u in ok: results[u] = ("accepted", None)
            push("events", agent_id=aid, count=len(ok), alerts=len(alerts))
            maybe_purge()
        for u, (st_, _) in list(results.items()):                          # invariant: every valid uid ends with exactly one explicit outcome; anything unclassified is retryable, never silently "delivered"
            if st_ == "claimed": results[u] = ("retry", "unclassified"); release(aid, [u])
        by = lambda st: [u for u, (s_, _) in results.items() if s_ == st]
        acc, dup, rej, ret = by("accepted"), by("duplicate"), by("rejected"), by("retry")
        reasons = {u: r for u, (s_, r) in results.items() if r and s_ in ("rejected", "retry")}
        return jsonify(ack_version=2, accepted=len(acc), duplicates=len(dup), rejected=len(rej) + anon, retry=len(ret), alerts=len(alerts),
                       accepted_uids=acc, duplicate_uids=dup, rejected_uids=rej, retry_uids=ret, reasons=reasons)

    @bp.errorhandler(sqlite3.OperationalError)
    def _db_busy(e):
        """A locked/busy database anywhere in a fleet request (auth, nonce write, heartbeat, ingest) is temporary: answer 503 + retryable so the agent backs off and retries. Details are never returned."""
        if any(w in str(e).lower() for w in ("locked", "busy")): return jsonify(error="database busy; retry", retryable=True), 503
        print(f"fleet: database error ({type(e).__name__})"); return jsonify(error="internal error"), 500

    @bp.route("/api/quarantine")
    @need("admin")
    def quarantine_list():
        """Events the server could not process (invalid, or failed MAX attempts). Metadata only; /api/quarantine/<id> shows the redacted payload."""
        return jsonify(q("SELECT id,agent_id,uid,reason,attempts,created_at,replayed_at FROM event_quarantine ORDER BY id DESC LIMIT ?", (iarg(request.args.get("limit"), 200, 1, 1000),)))

    @bp.route("/api/quarantine/<int:i>")
    @need("admin")
    def quarantine_get(i):
        r = q("SELECT * FROM event_quarantine WHERE id=?", (i,), one=True)
        return jsonify(r) if r else deny("not found", 404)

    # ---------- dashboard-facing reads (login required; secrets never included) ----------
    PUB = "id,hostname,device_name,os,os_version,ip,ips,agent_version,registered_at,last_heartbeat,last_event_at,status,monitoring,credential_id,enrolled_by,events_total,health"
    def view(a):
        a["state"] = agent_status(a)
        try: a["health"] = json.loads(a.get("health") or "{}")
        except Exception: a["health"] = {}
        try: a["ips"] = json.loads(a.get("ips") or "[]")
        except Exception: a["ips"] = []
        a["alert_count"] = q("SELECT COUNT(*) c FROM alerts WHERE agent_id=?", (a["id"],), one=True)["c"]
        a["open_alerts"] = q("SELECT COUNT(*) c FROM alerts WHERE agent_id=? AND status NOT IN ('Resolved','Suppressed')", (a["id"],), one=True)["c"]
        a["event_count"] = q("SELECT COUNT(*) c FROM events WHERE agent_id=?", (a["id"],), one=True)["c"]
        return a

    @bp.route("/api/agents")
    @need()
    def agents_list():
        return jsonify([view(a) for a in q(f"SELECT {PUB} FROM agents ORDER BY hostname")])

    @bp.route("/api/agents/<aid>")
    @need()
    def agent_get(aid):
        a = q(f"SELECT {PUB} FROM agents WHERE id=?", (aid,), one=True)
        if not a: return deny("not found", 404)
        a = view(a); a["heartbeats"] = q("SELECT ts,cpu,mem,events_queued,upload_failures FROM agent_heartbeats WHERE agent_id=? ORDER BY id DESC LIMIT 60", (aid,))[::-1]
        a["alerts"] = q("SELECT id,ts,updated,severity,title,category,source_ip,message,status,count FROM alerts WHERE agent_id=? ORDER BY id DESC LIMIT 50", (aid,))
        return jsonify(a)

    @bp.route("/api/agents/<aid>/events")
    @need()
    def agent_events_get(aid):
        w, a = ["agent_id=?"], [aid]; g = request.args.get
        for param, col in (("severity", "risk"), ("category", "category"), ("username", "username"), ("source", "channel"), ("event_id", "event_id")):
            if g(param): w.append(f"{col}=?"); a.append(g(param))
        if g("from"): w.append("ts>=?"); a.append(g("from"))
        if g("to"): w.append("ts<=?"); a.append(g("to"))
        if g("rule"): w.append("alert_id IN (SELECT id FROM alerts WHERE title=?)"); a.append(g("rule"))
        if g("q"): w.append("message LIKE ?"); a.append("%" + g("q") + "%")
        lim = iarg(g("limit"), 200, 1, 1000)
        return jsonify(q(f"SELECT id,ts,host,channel,event_id,level,provider,category,activity,username,status,risk,source_ip,dest_ip,message,alert_id FROM events WHERE {' AND '.join(w)} ORDER BY id DESC LIMIT {lim}", a))

    @bp.route("/api/agents/<aid>/revoke", methods=["POST"])
    @need("admin")
    def agent_revoke(aid):
        if not q("SELECT 1 FROM agents WHERE id=?", (aid,), one=True): return deny("not found", 404)
        x("UPDATE agent_credentials SET revoked_at=?,revoked_by=? WHERE agent_id=? AND revoked_at IS NULL", (now(), _me(), aid))
        x("UPDATE agents SET status='revoked',monitoring='stopped' WHERE id=?", (aid,))
        audit(f"Agent revoked: {aid}"); push("revoked", agent_id=aid); return jsonify(ok=True)

    @bp.route("/api/agents/<aid>/rotate-credential", methods=["POST"])
    @need("admin")
    def agent_rotate(aid):
        """Issue a NEW bearer secret + signing key (shown once) and revoke the old credential. Staged legacy migration: run this per agent, put the new
        values in the agent config (agent re-enroll file), then set SOC_AGENT_AUTH=hmac-required when no unsigned use remains (GET /api/agents/auth-status)."""
        a = q("SELECT id,status FROM agents WHERE id=?", (aid,), one=True)
        if not a or a["status"] == "revoked": return deny("not found or revoked", 404)
        from security import mfa as _mfa
        if not _mfa.reauth_ok(): return deny("recent reauthentication required (POST /api/me/reauth)", 403)
        cid = "cr-" + secrets.token_hex(6); secret = secrets.token_urlsafe(32); skey = agentsig.new_signing_key(); c = conn()
        try:
            c.execute("UPDATE agent_credentials SET revoked_at=?,revoked_by=? WHERE agent_id=? AND revoked_at IS NULL", (now(), _me() + " (rotated)", aid))
            c.execute("INSERT INTO agent_credentials(credential_id,agent_id,secret_hash,created_at,sign_key_enc,scopes) VALUES(?,?,?,?,?,?)", (cid, aid, sha(secret), now(), agentsig.seal(skey, cid), "heartbeat,events:write"))
            c.execute("UPDATE agents SET credential_id=? WHERE id=?", (cid, aid)); c.commit()
        finally: c.close()
        audit(f"Agent credential rotated: {aid} (old credential revoked)"); return jsonify(agent_id=aid, credential=f"{cid}.{secret}", signing_key=skey, note="shown once")

    @bp.route("/api/agents/auth-status")
    @need("admin")
    def agents_auth_status():
        rows = q("SELECT a.id,a.hostname,c.sign_key_enc IS NOT NULL signing,c.sig_required,COALESCE(c.legacy_uses,0) legacy_uses FROM agents a JOIN agent_credentials c ON c.agent_id=a.id WHERE c.revoked_at IS NULL AND a.status!='revoked'")
        lk = q("SELECT value FROM settings WHERE key='legacy_key_last_used'", one=True)
        return jsonify(mode=agentsig.mode(), legacy_api_key="on" if agentsig.legacy_key_on() else "off", legacy_key_last_used=(lk or {}).get("value"), agents=rows,
                       ready_for_hmac_required=bool(rows) and all(r["sig_required"] for r in rows),          # an empty fleet is NOT "ready" (vacuous truth would invite a premature switch)
                       ready_for_legacy_off=(lk is None))                                                      # the shared key has never been used (or was never used since this counter exists)

    @bp.route("/api/agents/<aid>/monitoring", methods=["POST"])
    @need("admin")
    def agent_monitoring(aid):
        m = "paused" if body().get("paused") else "active"
        x("UPDATE agents SET monitoring=? WHERE id=? AND status!='revoked'", (m, aid)); audit(f"Agent {aid} monitoring={m}"); return jsonify(ok=True)

    register_monitoring(bp, need, audit, body, deny)
    app.register_blueprint(bp)
