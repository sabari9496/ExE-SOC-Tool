#!/usr/bin/env python3
"""Reproducible test runner + aggregator. Runs each tests/test_*.py as its OWN process (temp DB per suite), captures real output, parses counts, and writes one JSON per suite.
No numbers are typed in by hand: totals come only from what the suites printed.
  python tests/run_all.py run [--only a,b] [--skip a,b] [--workers 4] [--timeout 280] [--out test-results]
  python tests/run_all.py summarize [--out test-results]      -> test-results/summary.json + summary.md (suite count and individual-test count kept separate)
Parsing: unittest suites ('Ran N tests', 'OK' / 'FAILED (failures=..)' / '(skipped=..)'); check-style suites ('N/M passed'). Anything else is reported UNPARSED, never guessed.
A timeout is reported as TIMEOUT, a non-zero exit with no summary as FAIL. Windows/macOS/Socket.IO/multi-worker suites do not exist here and are listed as NOT RUN by summarize."""
import os, re, sys, json, time, glob, argparse, tempfile, subprocess
from concurrent.futures import ThreadPoolExecutor
HERE = os.path.dirname(os.path.abspath(__file__)); ROOT = os.path.dirname(HERE)

def parse(text, rc):
    t = text.replace("\r", "")
    m = re.search(r"^Ran (\d+) tests? in", t, re.M)
    if m:
        n = int(m.group(1)); sk = re.search(r"skipped=(\d+)", t.split("Ran ")[-1]); fl = re.search(r"failures=(\d+)", t.split("Ran ")[-1]); er = re.search(r"errors=(\d+)", t.split("Ran ")[-1]); xf = re.search(r"expected failures=(\d+)", t.split("Ran ")[-1])
        failed = (int(fl.group(1)) if fl else 0) + (int(er.group(1)) if er else 0); skipped = int(sk.group(1)) if sk else 0
        return dict(kind="unittest", tests=n, passed=n - failed - skipped, failed=failed, skipped=skipped, expected_failures=int(xf.group(1)) if xf else 0, status="PASS" if rc == 0 and failed == 0 else "FAIL")
    ms = re.findall(r"^(\d+)/(\d+) passed\s*$", t, re.M)
    if ms:
        a, b = int(ms[-1][0]), int(ms[-1][1]); return dict(kind="checks", tests=b, passed=a, failed=b - a, skipped=0, expected_failures=0, status="PASS" if rc == 0 and a == b else "FAIL")
    return dict(kind="unparsed", tests=None, passed=None, failed=None, skipped=None, expected_failures=None, status="PASS(unparsed)" if rc == 0 else "FAIL")

def run_one(name, timeout, out):
    path = os.path.join(HERE, name + ".py"); tmp = tempfile.mkdtemp(prefix="exesoc-test-"); t0 = time.time()
    env = dict(os.environ, SOC_DB=os.path.join(tmp, "t.db"), SOC_ALLOW_DEFAULT_CREDS="1", PYTHONDONTWRITEBYTECODE="1")
    try: p = subprocess.run([sys.executable, path], cwd=ROOT, env=env, capture_output=True, text=True, timeout=timeout); rc, text, to = p.returncode, p.stdout + "\n" + p.stderr, False
    except subprocess.TimeoutExpired as e: rc, text, to = 124, ((e.stdout or b"").decode(errors="replace") if isinstance(e.stdout, bytes) else (e.stdout or "")), True
    r = dict(suite=name, rc=rc, seconds=round(time.time() - t0, 1), timeout_s=timeout)
    r.update(dict(kind="timeout", tests=None, passed=None, failed=None, skipped=None, expected_failures=None, status="TIMEOUT") if to else parse(text, rc))
    r["tail"] = [l[:200] for l in text.strip().splitlines()[-3:]]          # last 3 lines only (logs may hold temp paths); full logs are not stored
    os.makedirs(out, exist_ok=True); json.dump(r, open(os.path.join(out, name + ".json"), "w"), indent=1); return r

def summarize(out):
    rs = [json.load(open(f)) for f in sorted(glob.glob(os.path.join(out, "test_*.json")))]
    tot = lambda k: sum(r[k] or 0 for r in rs if r["status"] in ("PASS", "FAIL"))
    s = dict(suites=len(rs), suites_pass=sum(r["status"] == "PASS" for r in rs), suites_fail=sum(r["status"] == "FAIL" for r in rs), suites_timeout=sum(r["status"] == "TIMEOUT" for r in rs), suites_unparsed=sum(r["kind"] == "unparsed" for r in rs),
             individual_tests=tot("tests"), individual_passed=tot("passed"), individual_failed=tot("failed"), individual_skipped=tot("skipped"), python=sys.version.split()[0], suites_detail=rs)
    json.dump(s, open(os.path.join(out, "summary.json"), "w"), indent=1)
    L = ["| Suite | Status | Tests | Passed | Failed | Skipped | Seconds |", "|---|---|---|---|---|---|---|"] + [f"| {r['suite']} | {r['status']} | {r['tests'] if r['tests'] is not None else '-'} | {r['passed'] if r['passed'] is not None else '-'} | {r['failed'] if r['failed'] is not None else '-'} | {r['skipped'] if r['skipped'] is not None else '-'} | {r['seconds']} |" for r in rs]
    L.append(f"\nSuites: {s['suites']} (PASS {s['suites_pass']}, FAIL {s['suites_fail']}, TIMEOUT {s['suites_timeout']}, unparsed {s['suites_unparsed']}). Individual tests (sum of per-suite counts as printed by the suites): {s['individual_tests']} (passed {s['individual_passed']}, failed {s['individual_failed']}, skipped {s['individual_skipped']}).")
    open(os.path.join(out, "summary.md"), "w").write("\n".join(L) + "\n"); print("\n".join(L)); return s

if __name__ == "__main__":
    ap = argparse.ArgumentParser(); ap.add_argument("cmd", choices=("run", "summarize")); ap.add_argument("--only", default=""); ap.add_argument("--skip", default=""); ap.add_argument("--workers", type=int, default=4)
    ap.add_argument("--timeout", type=int, default=280); ap.add_argument("--out", default=os.path.join(ROOT, "test-results")); a = ap.parse_args()
    if a.cmd == "summarize": r = summarize(a.out); sys.exit(0 if r["suites_fail"] + r["suites_timeout"] == 0 else 1)
    names = sorted(os.path.basename(f)[:-3] for f in glob.glob(os.path.join(HERE, "test_*.py"))); only = {x if x.startswith("test_") else "test_" + x for x in a.only.split(",") if x}; skip = {x if x.startswith("test_") else "test_" + x for x in a.skip.split(",") if x}
    names = [n for n in names if (not only or n in only) and n not in skip]
    with ThreadPoolExecutor(a.workers) as ex:
        for r in ex.map(lambda n: run_one(n, a.timeout, a.out), names): print(f"{r['suite']:28} {r['status']:8} tests={r['tests']} rc={r['rc']} {r['seconds']}s", flush=True)
