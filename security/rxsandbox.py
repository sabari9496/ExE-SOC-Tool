"""Per-match hard timeout for custom-rule regexes WITHOUT the optional `regex` package.

Python's `re` cannot be interrupted, so matching runs in a separate worker process that is KILLED when one match exceeds the limit
(SOC_REGEX_TIMEOUT_MS, default 100 ms). The worker has a memory cap (POSIX RLIMIT_AS) and never sees anything except (pattern, text) pairs.
A timeout raises Timeout; the engine treats it as "no match", counts a strike for the rule and disables the rule after repeated strikes (never deletes it).
Cost: one pipe round-trip per match (tens of microseconds); the worker is started lazily and reused. Thread-safe (one request at a time)."""
import os, sys, json, queue, threading, subprocess
class Timeout(Exception): pass
_CODE = r'''
import sys, json, re
try:
    import resource; resource.setrlimit(resource.RLIMIT_AS, (512*1024*1024, 512*1024*1024))
except Exception: pass
cache = {}
sys.stdout.write("ready\n"); sys.stdout.flush()     # handshake: the parent starts the per-match clock only after interpreter start-up (P5-02)
for line in sys.stdin:
    try:
        d = json.loads(line); p = d["p"]
        if p not in cache:
            if len(cache) > 256: cache.clear()
            cache[p] = re.compile(p, re.I)
        out = {"m": bool(cache[p].search(d["t"]))}
    except Exception as e:
        out = {"e": type(e).__name__}
    sys.stdout.write(json.dumps(out) + "\n"); sys.stdout.flush()
'''
_LOCK = threading.Lock(); _P = None; _Q = None
START_TIMEOUT_S = 10.0
def timeout_s(): return max(0.01, float(os.environ.get("SOC_REGEX_TIMEOUT_MS", "100")) / 1000.0)
def _spawn():
    global _P, _Q
    _P = subprocess.Popen([sys.executable, "-I", "-c", _CODE], stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, text=True, bufsize=1)
    q = queue.Queue(); _Q = q
    def reader(p=_P, q=q):
        for line in p.stdout: q.put(line)
        q.put(None)
    threading.Thread(target=reader, daemon=True, name="rx-reader").start()
    try: first = q.get(timeout=START_TIMEOUT_S)      # cold start must NOT count against the per-match limit: a loaded host would otherwise strike (and eventually disable) healthy rules
    except queue.Empty: first = None
    if first is None or first.strip() != "ready": _kill(); raise Timeout("worker failed to start")
def _kill():
    global _P, _Q
    if _P is not None:
        try: _P.kill()
        except Exception: pass
        try: _P.wait(timeout=2)
        except Exception: pass
    _P = _Q = None
def match(pattern, text, timeout=None):
    """True/False, or raises Timeout when the worker exceeded the limit (it is killed and replaced). ValueError for an invalid pattern."""
    with _LOCK:
        for attempt in (0, 1):
            if _P is None or _P.poll() is not None: _kill(); _spawn()
            try:
                _P.stdin.write(json.dumps({"p": pattern, "t": text}) + "\n"); _P.stdin.flush()
            except (BrokenPipeError, OSError):
                _kill()
                if attempt == 0: continue
                raise Timeout("worker unavailable")
            try: line = _Q.get(timeout=timeout if timeout is not None else timeout_s())
            except queue.Empty: _kill(); raise Timeout(f"match exceeded {int((timeout if timeout is not None else timeout_s()) * 1000)} ms")
            if line is None:
                _kill()
                if attempt == 0: continue
                raise Timeout("worker died (memory/CPU limit)")
            r = json.loads(line)
            if "e" in r:
                if r["e"] == "error": raise ValueError("invalid regex")
                raise ValueError(r["e"])
            return r["m"]
def shutdown():
    with _LOCK: _kill()
