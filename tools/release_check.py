#!/usr/bin/env python3
"""Pre-publication hygiene scan. READ-ONLY: never modifies, deletes or rewrites anything and NEVER prints a matched secret value (file:line / commit id / rule name only).
  python tools/release_check.py [--root DIR] [--history]
Checks: (1) files that must not ship (runtime secrets, DBs, keys, certificates, admin-credential files); (2) well-known secret patterns in text files;
(3) example configs that would leave permissive authentication enabled in production; (4) with --history and a .git directory: the same patterns in every commit
(`git log -G`), reported by commit id only. A clean working tree does NOT prove history is clean; a secret found in history must be ROTATED, not just removed.
Exit 0 = nothing found, 1 = findings, 2 = could not scan. This is a first filter, not a replacement for a dedicated scanner (gitleaks / trufflehog) run on a networked machine."""
import os, re, sys, argparse, subprocess

FORBIDDEN_NAMES = {".secret", ".env", "initial_admin_credentials.txt"}
FORBIDDEN_SUFFIX = (".db", ".db-wal", ".db-shm", ".sqlite", ".sqlite3", ".pem", ".key", ".p12", ".pfx", ".crt")
SKIP_DIRS = {".git", "__pycache__", ".venv", "node_modules", "certs"}
PATTERNS = {
    "private-key-block": re.compile(r"-----BEGIN (?:RSA |EC |DSA |OPENSSH |ENCRYPTED |)PRIVATE KEY-----"),
    "aws-access-key-id": re.compile(r"\bAKIA[0-9A-Z]{16}\b"),
    "github-token": re.compile(r"\bgh[pousr]_[A-Za-z0-9]{30,}\b"),
    "slack-token": re.compile(r"\bxox[baprs]-[A-Za-z0-9-]{10,}\b"),
    "google-api-key": re.compile(r"\bAIza[0-9A-Za-z_\-]{30,}\b"),
    "google-oauth-refresh": re.compile(r"\b1//[0-9A-Za-z_\-]{40,}\b"),
    "assigned-hex-secret": re.compile(r"(?i)\b(?:secret|api[_-]?key|token|password|passwd)\b\s*[:=]\s*['\"]?[0-9a-f]{40,}['\"]?"),
}
PERMISSIVE_IN_EXAMPLE = re.compile(r"^\s*SOC_(AGENT_AUTH\s*=\s*permissive|LEGACY_API_KEY\s*=\s*on)\b", re.I | re.M)
TEXT_SKIP_SUFFIX = (".png", ".jpg", ".gif", ".ico", ".pdf", ".zip", ".gz", ".pyc", ".woff", ".woff2", ".db")


def walk(root):
    for dp, dn, fn in os.walk(root):
        dn[:] = [d for d in dn if d not in SKIP_DIRS]
        for f in fn:
            yield os.path.join(dp, f)


def scan_tree(root):
    out = []
    for p in walk(root):
        rel = os.path.relpath(p, root); name = os.path.basename(p)
        if name in FORBIDDEN_NAMES or name.endswith(FORBIDDEN_SUFFIX):
            out.append(("forbidden-file", rel, "")); continue
        if name.endswith(TEXT_SKIP_SUFFIX): continue
        try:
            if os.path.getsize(p) > 2_000_000: continue
            txt = open(p, "r", encoding="utf-8", errors="ignore").read()
        except OSError:
            continue
        if rel.startswith("tests" + os.sep): continue         # fixtures use synthetic values
        for i, line in enumerate(txt.splitlines(), 1):
            for rule, rx in PATTERNS.items():
                if rx.search(line) and "<" not in line.split("=", 1)[-1][:2]:   # placeholders like <set-this> are fine
                    out.append(("secret-pattern:" + rule, rel, str(i)))
        if "example" in name and PERMISSIVE_IN_EXAMPLE.search(txt):
            out.append(("insecure-example-default", rel, ""))
    return out


def scan_history(root):
    if not os.path.isdir(os.path.join(root, ".git")): return None
    out = []
    for rule, rx in PATTERNS.items():
        r = subprocess.run(["git", "-C", root, "log", "--all", "--format=%h", "-G", rx.pattern], capture_output=True, text=True)
        if r.returncode != 0: return "git-error"
        for h in r.stdout.split():
            out.append(("history:" + rule, "commit " + h, ""))
    for n in sorted(FORBIDDEN_NAMES):
        r = subprocess.run(["git", "-C", root, "log", "--all", "--format=%h", "--", n, "**/" + n], capture_output=True, text=True)
        for h in r.stdout.split(): out.append(("history:forbidden-file", f"{n} in commit {h}", ""))
    return out


def main():
    a = argparse.ArgumentParser(); a.add_argument("--root", default=os.path.dirname(os.path.dirname(os.path.abspath(__file__)))); a.add_argument("--history", action="store_true")
    r = a.parse_args()
    if not os.path.isdir(r.root): print("root not found", file=sys.stderr); return 2
    f = scan_tree(r.root)
    if r.history:
        h = scan_history(r.root)
        if h is None: print("history: NOT SCANNED (no .git directory here)")
        elif h == "git-error": print("history: NOT SCANNED (git failed)", file=sys.stderr); return 2
        else: f += h
    for kind, where, line in f: print(f"FINDING {kind}: {where}" + (f":{line}" if line else ""))
    print(f"{len(f)} finding(s). Values are never printed. Rotate any real credential that appears; do not merely delete it.")
    return 1 if f else 0


if __name__ == "__main__":
    sys.exit(main())
