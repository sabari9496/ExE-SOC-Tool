# Known limitations and supported platforms
**Status: beta candidate at best; NOT production-ready.**
- Server: Linux behind nginx + TLS is the intended deployment. Windows server hosting is untested.
- Agents: Linux (systemd) tested with a fake systemctl only; Windows agent/installer NOT runtime-tested.
- One gunicorn worker only (in-process state). Multi-host rate limiting is not supported.
- Each Socket.IO connection holds a worker thread (`--threads 8` in the sample unit). Not load-tested; raise threads or limit dashboards.
- Regex worker (`security/rxsandbox.py`): hard timeout + kill on all platforms; memory cap (RLIMIT_AS) POSIX only. On Windows there is no memory cap: install the `regex` package or restrict who can create custom rules.
- Front-end: fallback loads scripts from CDNs without SRI until `tools/vendor_assets.py` is run and reviewed. The map loads tiles from openstreetmap.org (viewer IPs are sent to that host).
- Dependencies are unpinned and unhashed; `pip-audit` and Bandit have not been run.
- Real Socket.IO, nginx/TLS/WebSocket, systemd and browser XSS tests have not been run (see PASS5 review).
