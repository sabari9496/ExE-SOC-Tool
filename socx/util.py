import json, re
from datetime import datetime, timedelta
from db import q, x, now, setting

FMT = "%Y-%m-%d %H:%M:%S"
def ago(minutes): return (datetime.now() - timedelta(minutes=minutes)).strftime(FMT)
def parse(ts):
    try: return datetime.strptime(ts, FMT)
    except Exception: return None
def minutes_between(a, b):
    pa, pb = parse(a), parse(b)
    return abs((pb - pa).total_seconds()) / 60 if pa and pb else 9999

def rawj(row):
    try:
        d = json.loads(row.get("raw") or "{}"); return d if isinstance(d, dict) else {}
    except Exception: return {}

def field(row, *names):
    """Case-insensitive field from the stored raw JSON, falling back to 'Name: value' / 'Name=value' in the message."""
    d = {k.lower(): v for k, v in rawj(row).items()}
    for n in names:
        v = d.get(n.lower())
        if v not in (None, "", "-"): return str(v)
    msg = row.get("message") or ""
    for n in names:
        m = re.search(rf"{re.escape(n)}\W{{1,4}}([^\s,;|]+)", msg, re.I)
        if m and m.group(1) not in ("-",): return m.group(1)
    return None

def logon_type(row):
    v = field(row, "LogonType", "Logon Type")
    return int(v) if v and v.isdigit() else None

def is_private(ip):
    from engine import is_private as p
    return p(ip) if ip else True

def state_get(k):
    r = q("SELECT value FROM sx_state WHERE key=?", (k,), one=True); return r["value"] if r else None
def state_set(k, v): x("INSERT OR REPLACE INTO sx_state VALUES(?,?,?)", (k, str(v), now()))

def lower_text(row): return ((row.get("message") or "") + " " + (row.get("raw") or "")).lower()
PROC_RX = re.compile(r"powershell|pwsh|cmd\.exe|wscript|cscript|mshta|rundll32|regsvr32|certutil|bitsadmin|schtasks|\bsc\.exe|psexe|winrs|wmic|wsmprovhost|wmiprvse", re.I)
