#!/usr/bin/env bash
# Setup + start (Kali/Debian safe: uses a virtual environment).  Start it the SAME way every time (always with sudo, or never).
set -e; cd "$(dirname "$0")"
[ "$(id -u)" = 0 ] || echo "NOTE: not root - the journal / auth.log may be unreadable. Use: sudo ./run.sh (or add your user to the systemd-journal and adm groups)."
# Files created by a different user (sudo one time, no sudo the next) cause 'attempt to write a readonly database' and pip permission errors.
if [ "$(id -u)" != 0 ]; then
  bad=""; for f in . .venv .secret soc.db soc.db-wal soc.db-shm; do [ -e "$f" ] && [ ! -w "$f" ] && bad="$bad $f"; done
  if [ -n "$bad" ]; then
    echo "ERROR: you ($(id -un)) cannot write to:$bad  (they belong to another user, usually root from an earlier 'sudo ./run.sh')." >&2
    echo "Fix:  sudo chown -R $(id -un):$(id -gn) \"$PWD\"     then run ./run.sh again (without sudo)   -  or always use sudo ./run.sh" >&2; exit 2
  fi
fi
if [ ! -d .venv ]; then
  python3 -m venv .venv || { rm -rf .venv; echo "ERROR: could not create a virtual environment. On Debian/Ubuntu/Kali install it with:  sudo apt install python3-venv python3-pip" >&2; exit 1; }
fi
.venv/bin/pip install -q -r requirements.txt
.venv/bin/python app.py "$@"
