# EXE-SOC Pass 5 remediation notes

This is a scratch-copy remediation of the uploaded Pass 4 archive. The original ZIP was not modified. No `.secret` contents were opened or copied.

## Changes applied

- Set example defaults to require signed/HMAC agent requests and disable the shared legacy ingest key.
- Hardened Linux installer rollback so it does not remove pre-existing state/configuration on a failed reinstall.
- Hardened the Windows installer to check virtual-environment and dependency-install exit codes; moved enrollment token handoff to the child process environment; removed the broad `pythonw` process kill and targets only processes launched from the EXE-SOC install folder during uninstall; supports retaining data.
- Disabled automatic HTTP redirect following for authenticated agent requests.
- Improved agent event acknowledgements to account for accepted, duplicate, and rejected event UIDs; rejected events are saved to a local bounded dead-letter queue rather than silently discarded. Server processing failure attempts to release deduplication IDs so the agent can retry.
- Fixed non-finite agent authentication timestamps (`NaN`/infinity) and moved nonce consumption after signature validation.
- Made MFA recovery-code consumption atomic against concurrent reuse; new recovery codes use a purpose-specific keyed hash while preserving compatibility with already-issued legacy hashes.
- Validate production MFA role configuration and fail closed for unknown/empty required-role configuration.
- Hardened secret rotation output preflight and failure handling.
- Updated third-party asset URL pinning and Nginx redirect/default-server hardening from the reviewed Pass 5 patch.
- Added `tools/release_check.py`, security/release documentation, and static regression checks.
- Added a plaintext-HTTP refusal to the legacy `tools/agent.py` unless the operator explicitly opts into a lab-only exception with `SOC_ALLOW_INSECURE_LEGACY_AGENT=1`.

## Tests performed

Passed:
- `python -m compileall -q .`
- `bash -n agent/install_linux.sh`
- `python tests/test_windows_installer.py` (2 tests)
- `python tests/test_static_security.py` (7 tests)
- `python tests/test_pass5_security.py` (6 static regression checks)
- `python tools/release_check.py --root .` (0 findings)
- ZIP integrity check on the final archive

Not completed / environment limitation:
- `tests/test_agent_hmac.py` and other Flask-backed tests could not start because `werkzeug` is not installed in this execution environment. Dependencies were not downloaded or installed.
- No real Windows host, Linux disposable VM, TLS reverse proxy, or remote endpoint was available. Install/uninstall behavior and live event delivery still need deployment testing before production use.
- No networked dependency vulnerability scan (`pip-audit`/equivalent) was possible. Dependency pinning and broader production review remain outstanding.

## Important deployment notes

- This is not a claim of zero bugs or production certification. Run the full suite in the project's supported virtual environment and test on disposable Windows and Linux hosts before deployment.
- The new signed agent does not execute remote block/isolation commands. The legacy agent has that optional enforcement feature; do not enable it unless you intentionally require and authorize that behavior.
- Migrate existing legacy agents before enforcing `SOC_AGENT_AUTH=hmac-required` and turning `SOC_LEGACY_API_KEY=off` on a live deployment, or those older agents will stop authenticating.
