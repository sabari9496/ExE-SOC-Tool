"""Secret redaction applied to command lines / raw text BEFORE storage (the original event stays on the endpoint)."""
import re
_PATTERNS = [
    (re.compile(r"(?i)(\b(?:password|passwd|pwd|secret|token|api[_-]?key|apikey|authorization|bearer)\b\s*[=:]\s*)(\"[^\"]*\"|'[^']*'|\S+)"), r"\1[REDACTED]"),
    (re.compile(r"(?i)(\s-{1,2}(?:p|pw|pass|password|passwd|token|secret|key)\s+)(\"[^\"]*\"|'[^']*'|\S+)"), r"\1[REDACTED]"),
    (re.compile(r"(?i)(net(?:1)?(?:\.exe)?\s+user\s+\S+\s+)(\S+)(\s+/add)"), r"\1[REDACTED]\3"),
    (re.compile(r"(?i)(://[^/\s:@]+:)([^@/\s]+)(@)"), r"\1[REDACTED]\3"),
    (re.compile(r"\b(AKIA[0-9A-Z]{16}|gh[pousr]_[A-Za-z0-9]{30,}|xox[baprs]-[A-Za-z0-9-]{10,})\b"), "[REDACTED]"),
]
def redact(s, limit=4000):
    if not s: return s
    s = str(s)[:limit * 4]
    for rx, rep in _PATTERNS: s = rx.sub(rep, s)
    return s[:limit]
