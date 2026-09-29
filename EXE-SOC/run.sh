#!/usr/bin/env bash
# Setup + start (Kali/Debian safe: uses a virtual environment)
set -e; cd "$(dirname "$0")"
[ -d .venv ] || python3 -m venv .venv
.venv/bin/pip install -q -r requirements.txt
.venv/bin/python app.py "$@"
