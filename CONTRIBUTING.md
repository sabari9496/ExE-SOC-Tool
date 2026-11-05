# Contributing
1. Never commit secrets, databases, certificates, `.env` files or real telemetry. Run `python tools/release_check.py` before every push.
2. Security fixes need a regression test that fails before the fix. Label static-only tests as static.
3. Run the suites in `tests/` (`python3 tests/<suite>.py`, legacy suites with `SOC_ALLOW_DEFAULT_CREDS=1 SOC_MIN_PASSWORD=8`). `tests/test_linux_agent.py` needs root on a disposable Linux box.
4. Do not weaken authentication, CSRF, TLS, rate limiting or agent signing to make a test pass.
5. Report security issues privately (see SECURITY.md), not in public issues.
6. Contribution licensing terms are pending the owner's licence decision (docs/LICENSE-OPTIONS.md).
