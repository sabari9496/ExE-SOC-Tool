"""Regression checks for the Pass 5 hardening changes (static checks; no live endpoint/device needed)."""
from pathlib import Path
import unittest
ROOT = Path(__file__).resolve().parents[1]

def read(path):
    return (ROOT / path).read_text(encoding="utf-8")

class Pass5Security(unittest.TestCase):
    def test_agent_refuses_redirects_and_accounts_for_each_event(self):
        s = read("agent/exe_soc_agent.py")
        self.assertIn("allow_redirects=False", s)
        self.assertIn("accepted_uids", s)
        self.assertIn("duplicate_uids", s)
        self.assertIn("rejected_uids", s)
        self.assertIn("CREATE TABLE IF NOT EXISTS dead", s)

    def test_server_rejects_non_finite_timestamps_and_returns_event_ids(self):
        s = read("fleet/api.py")
        self.assertIn("math.isfinite(ts)", s)
        self.assertIn("accepted_uids=acc", s)
        self.assertIn("duplicate_uids=dup", s)
        self.assertIn("rejected_uids=rej", s)

    def test_mfa_recovery_consumption_is_atomic_and_legacy_compatible(self):
        s = read("security/mfa.py")
        t = read("security/totp.py")
        self.assertIn("BEGIN IMMEDIATE", s)
        self.assertIn("hash_code_legacy", s)
        self.assertIn('crypto.mac_key("mfa-recovery")', t)

    def test_legacy_agent_rejects_plaintext_by_default(self):
        s = read("tools/agent.py")
        self.assertIn('not server.startswith("https://")', s)
        self.assertIn("SOC_ALLOW_INSECURE_LEGACY_AGENT", s)

    def test_windows_uninstaller_targets_only_agent_folder_and_checks_installs(self):
        s = read("agent/install_windows.ps1")
        self.assertNotIn('Stop-Process -Name pythonw', s)
        self.assertIn('StartsWith("$Dest\\"', s)
        self.assertIn("$LASTEXITCODE -ne 0", s)

    def test_production_example_defaults_to_signed_agents(self):
        s = read(".env.example")
        self.assertIn("SOC_AGENT_AUTH=hmac-required", s)
        self.assertIn("SOC_LEGACY_API_KEY=off", s)

if __name__ == "__main__":
    unittest.main(verbosity=2)
