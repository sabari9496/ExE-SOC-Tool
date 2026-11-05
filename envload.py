"""Tiny .env loader (no extra dependency). Reads KEY=VALUE lines from .env next to this file and puts them in os.environ.
Real environment variables always win. Supports comments, quotes, `export KEY=...`, and ignores placeholder values like <set-this>.
Imported first by app.py so SMTP_*, EMAIL_FROM, SOC_* values are visible to the rest of the program."""
import os, re

def load(path=None):
    path = path or os.path.join(os.path.dirname(os.path.abspath(__file__)), ".env")
    if not os.path.isfile(path): return 0
    n = 0
    try:
        with open(path, encoding="utf-8-sig") as fh: lines = fh.read().splitlines()
    except OSError: return 0
    for raw in lines:
        line = raw.strip()
        if not line or line.startswith("#"): continue
        if line.lower().startswith("export "): line = line[7:].strip()
        if "=" not in line: continue
        k, v = line.split("=", 1); k, v = k.strip(), v.strip()
        if not re.match(r"^[A-Za-z_][A-Za-z0-9_]*$", k): continue
        if len(v) >= 2 and v[0] == v[-1] and v[0] in "\"'": v = v[1:-1]
        else: v = re.split(r"\s+#", v, 1)[0].strip()          # inline comment on unquoted values
        if re.fullmatch(r"<[^<>]*>", v): continue              # untouched placeholder from .env.example
        if v == "" or os.environ.get(k) not in (None, ""): continue
        os.environ[k] = v; n += 1
    return n

load()
