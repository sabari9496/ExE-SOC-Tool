"""RFC 6238 TOTP (SHA-1, 6 digits, 30 s) with replay prevention, recovery codes and attempt limiting. Secrets are stored encrypted (security.crypto)."""
import hmac, hashlib, struct, time, secrets, base64, threading
from . import crypto
STEP, DIGITS, WINDOW = 30, 6, 1
_LOCK = threading.Lock(); _FAILS = {}
MAX_FAILS, LOCK_SECONDS = 5, 300
def new_secret(): return base64.b32encode(secrets.token_bytes(20)).decode().rstrip("=")
def _code(secret, counter):
    key = base64.b32decode(secret + "=" * (-len(secret) % 8), casefold=True)
    h = hmac.new(key, struct.pack(">Q", counter), hashlib.sha1).digest(); o = h[-1] & 15
    return str((struct.unpack(">I", h[o:o + 4])[0] & 0x7fffffff) % 10 ** DIGITS).zfill(DIGITS)
def uri(secret, user, issuer="EXE-SOC"):
    from urllib.parse import quote
    return f"otpauth://totp/{quote(issuer)}:{quote(str(user))}?secret={secret}&issuer={quote(issuer)}&digits={DIGITS}&period={STEP}"
def verify(secret, code, last_counter=0, now=None):
    """Returns the matched counter (> last_counter) or None. A counter can never be accepted twice (replay prevention)."""
    code = (code or "").strip().replace(" ", "")
    if not (code.isdigit() and len(code) == DIGITS): return None
    c0 = int((now if now is not None else time.time()) // STEP); hit = None
    for c in range(c0 - WINDOW, c0 + WINDOW + 1):
        if hmac.compare_digest(_code(secret, c), code) and c > last_counter: hit = c
    return hit
def throttled(user, now=None):
    """Persistent (SQLite) limiter: survives restarts and is shared by all workers. Covers TOTP codes AND recovery codes (same counter)."""
    from . import throttle; return throttle.blocked("mfa", user, MAX_FAILS, LOCK_SECONDS)
def note_fail(user):
    from . import throttle; throttle.hit("mfa", user)
def clear_fails(user):
    from . import throttle; throttle.clear("mfa", user)
def new_recovery_codes(n=10): return ["-".join(secrets.token_hex(2) for _ in range(3)) for _ in range(n)]
def hash_code(code):
    # HMAC prevents offline guessing of short recovery codes from a stolen database; derive from a purpose-specific application key.
    key = crypto.mac_key("mfa-recovery")
    return hmac.new(key, ("exe-soc-recovery|" + code.strip().lower()).encode(), hashlib.sha256).hexdigest()
def hash_code_legacy(code):
    # Compatibility for recovery codes issued before the keyed-hash upgrade; each is upgraded naturally when consumed/reissued.
    return hashlib.sha256(("exe-soc-rc|" + code.strip().lower()).encode()).hexdigest()
def enc_secret(secret, user): return crypto.encrypt(secret, f"totp|{user}")
def dec_secret(tok, user): return crypto.decrypt(tok, f"totp|{user}")
