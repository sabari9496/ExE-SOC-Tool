"""Per-agent request signing. Canonical string (UTF-8, '\\n'-joined):
   EXESOC-HMAC-SHA256-V1 / METHOD / path?query / X-Timestamp / X-Nonce / sha256hex(exact body bytes)
Signature header:  X-Signature: v1=<hex HMAC-SHA256(signing_key, canonical)>.  The signing key is separate from the bearer secret, shown once at enrollment/rotation,
and stored ONLY encrypted (AES-GCM, security.crypto) on the server. Mode SOC_AGENT_AUTH: permissive (default; unsigned legacy agents accepted+counted, signed ones enforced
and ratcheted: once an agent has sent a valid signature its credential refuses unsigned requests) | hmac-required (unsigned always refused)."""
import hmac, hashlib, secrets
from . import crypto
VERSION = "EXESOC-HMAC-SHA256-V1"
SCOPES = {"heartbeat", "events:write"}
def canonical(method, target, ts, nonce, body): return "\n".join((VERSION, method.upper(), target, str(ts), nonce, hashlib.sha256(body or b"").hexdigest()))
def sign(key, method, target, ts, nonce, body): return "v1=" + hmac.new(key.encode(), canonical(method, target, ts, nonce, body).encode(), hashlib.sha256).hexdigest()
def check(key, header, method, target, ts, nonce, body): return hmac.compare_digest(sign(key, method, target, ts, nonce, body), header or "")
import os
def _prod(): return os.environ.get("SOC_ENV") == "production"
def mode():
    """Effective SOC_AGENT_AUTH. Unset: 'permissive' for development, 'hmac-required' in production (a fresh production install has no unsigned agents; an operator who is still
    migrating must say so explicitly with SOC_AGENT_AUTH=permissive). Any unknown value fails CLOSED to 'hmac-required'."""
    v = (os.environ.get("SOC_AGENT_AUTH") or "").strip().lower()
    if v in ("permissive", "hmac-required"): return v
    return "hmac-required" if (v or _prod()) else "permissive"
def legacy_key_on():
    """Effective SOC_LEGACY_API_KEY (shared ingest key). Unset: on for development, OFF in production. Unknown values fail closed (off)."""
    v = (os.environ.get("SOC_LEGACY_API_KEY") or "").strip().lower()
    if v in ("on", "off"): return v == "on"
    return not (v or _prod())
def new_signing_key(): return secrets.token_urlsafe(32)
def seal(key, cid): return crypto.encrypt(key, f"agentkey|{cid}")
def unseal(tok, cid): return crypto.decrypt(tok, f"agentkey|{cid}")
def scope_for(path):
    return "events:write" if path.endswith("/events") else "heartbeat" if path.endswith("/heartbeat") else None
