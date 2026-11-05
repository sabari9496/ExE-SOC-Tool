"""Authenticated field encryption (AES-256-GCM) with a rotatable key ring.
Keys live OUTSIDE the database: SOC_ENC_KEYS="kid2:<b64url 32B>,kid1:<b64url 32B>" (first = primary, others decrypt-only), or SOC_ENC_KEY_FILE.
Dev convenience only (never when SOC_ENV=production): a key file <db dir>/.soc_enc_key is auto-created 0600.
Ciphertext format: enc1:<kid>:<b64url(nonce||ct||tag)>; the context string is bound as AAD so a value cannot be moved to another field/row.
RECOVERY: losing every key = encrypted fields (TOTP secrets, agent signing keys) are unrecoverable; back keys up separately from DB backups."""
import os, base64, hmac, hashlib, secrets, threading
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
PREFIX = "enc1:"; _lock = threading.Lock(); _ring = None

class CryptoError(Exception): pass
def _b64d(s): return base64.urlsafe_b64decode(s + "=" * (-len(s) % 4))
def _b64e(b): return base64.urlsafe_b64encode(b).decode().rstrip("=")
def new_key(): return _b64e(secrets.token_bytes(32))

def _parse(spec):
    ring = []
    for part in [p.strip() for p in spec.replace("\n", ",").split(",") if p.strip()]:
        kid, _, k = part.partition(":"); kb = _b64d(k)
        if not kid or len(kb) != 32: raise CryptoError("each key must be 'kid:<base64url of 32 bytes>'")
        ring.append((kid, kb))
    if not ring: raise CryptoError("empty key ring")
    return ring

def _check_key_file_mode(path):
    """A key file readable by other users is a disclosed key: refuse in production, warn loudly elsewhere."""
    import sys
    if os.name != "posix": return
    m = os.stat(path).st_mode & 0o077
    if m:
        msg = f"encryption key file {path} is accessible to other users (mode {oct(os.stat(path).st_mode & 0o777)}); run: chmod 600 {path}"
        if os.environ.get("SOC_ENV") == "production": raise CryptoError(msg)
        print("  WARNING: " + msg, file=sys.stderr)

def load_ring(force=False):
    global _ring
    with _lock:
        if _ring is not None and not force: return _ring
        spec = os.environ.get("SOC_ENC_KEYS")
        if not spec and os.environ.get("SOC_ENC_KEY_FILE"):
            _check_key_file_mode(os.environ["SOC_ENC_KEY_FILE"]); spec = open(os.environ["SOC_ENC_KEY_FILE"]).read()
        if not spec:
            if os.environ.get("SOC_ENV") == "production": raise CryptoError("SOC_ENC_KEYS or SOC_ENC_KEY_FILE is required in production")
            import db; path = os.path.join(os.path.dirname(os.path.abspath(db.DB)), ".soc_enc_key")
            if not os.path.exists(path):
                fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
                with os.fdopen(fd, "w") as f: f.write("k1:" + new_key())
            _check_key_file_mode(path); spec = open(path).read()
        _ring = _parse(spec); return _ring

def reset_ring(): global _ring; _ring = None
def encrypt(plain, context):
    kid, key = load_ring()[0]; n = secrets.token_bytes(12)
    return PREFIX + kid + ":" + _b64e(n + AESGCM(key).encrypt(n, plain.encode() if isinstance(plain, str) else plain, context.encode()))
def is_encrypted(v): return isinstance(v, str) and v.startswith(PREFIX)
def decrypt(token, context):
    if not is_encrypted(token): raise CryptoError("not an encrypted value")
    kid, _, b = token[len(PREFIX):].partition(":"); raw = _b64d(b)
    for k, key in load_ring():
        if k == kid:
            try: return AESGCM(key).decrypt(raw[:12], raw[12:], context.encode()).decode()
            except Exception: raise CryptoError("decryption failed (wrong key, wrong context or tampered data)")
    raise CryptoError(f"key id '{kid}' is not in the key ring")
def needs_rotation(token): return is_encrypted(token) and token[len(PREFIX):].split(":", 1)[0] != load_ring()[0][0]
def rotate(token, context): return encrypt(decrypt(token, context), context)
def primary_kid(): return load_ring()[0][0]
def mac_key(purpose, kid=None):
    """Derived HMAC key for `purpose` from ring key `kid` (default primary). Audit MACs pin their kid (settings.audit_key_kid) so encryption-key rotation never breaks the chain;
    KEEP that key in the ring (decrypt/verify-only) until you deliberately re-anchor the chain."""
    ring = dict(load_ring()); key = ring.get(kid) if kid else load_ring()[0][1]
    if key is None: raise CryptoError(f"key id '{kid}' missing from key ring")
    return hmac.new(key, b"exe-soc|" + purpose.encode(), hashlib.sha256).digest()

def encrypt_bytes(b, context):
    kid, key = load_ring()[0]; n = secrets.token_bytes(12)
    return PREFIX + kid + ":" + _b64e(n + AESGCM(key).encrypt(n, b, context.encode()))
def decrypt_bytes(token, context):
    kid, _, b = token[len(PREFIX):].partition(":"); raw = _b64d(b)
    for k, key in load_ring():
        if k == kid:
            try: return AESGCM(key).decrypt(raw[:12], raw[12:], context.encode())
            except Exception: raise CryptoError("decryption failed (wrong key, wrong context or tampered data)")
    raise CryptoError(f"key id '{kid}' is not in the key ring")
