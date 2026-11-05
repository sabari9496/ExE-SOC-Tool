"""pill() XSS, syslog bind policy, geo default, Windows installer hardening (static), vendored-asset verification. Run: python tests/test_hardening_round2.py"""
import os, sys, io, json, shutil, subprocess, tempfile, unittest, contextlib, importlib
ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__))); sys.path.insert(0, ROOT); sys.path.insert(0, ROOT + "/tools")
T = tempfile.mkdtemp(); os.environ.update(SOC_DB=T + "/t.db", SOC_SECRET="s" * 40, SOC_LOCAL_LOGS="0", SOC_ALLOW_FOREIGN_DB="1")
class Round2(unittest.TestCase):
    def test_01_pill_class_cannot_break_out_of_attribute(self):
        if not shutil.which("node"): self.skipTest("node not installed")
        src = open(ROOT + "/static/app.js").read(); line = [l for l in src.splitlines() if l.startswith("const pill=")][0]
        js = "const esc=s=>String(s).replace(/[&<>\"']/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;','\"':'&quot;',\"'\":'&#39;'}[c]));" + line.split("//")[0] + "\nconsole.log(pill(process.argv[1]));"
        out = subprocess.run(["node", "-e", js, '" onmouseover="alert(1)" x="y'], capture_output=True, text=True).stdout
        self.assertEqual(out.count('"'), 2, out)      # only the class attribute's own quotes; payload quotes are entity-escaped in the text node
        self.assertNotIn('" onmouseover', out); self.assertIn('class="pill s-onmouseoveralert1xy"', out)
    def test_02_syslog_refuses_public_bind_and_defaults_to_loopback(self):
        import syslogrx
        for bind, expect_refuse in (("0.0.0.0", True), ("8.8.8.8", True), ("not-an-ip", True), ("127.0.0.1", False), ("10.1.2.3", False)):
            os.environ.update(SOC_SYSLOG_PORT="0", SOC_SYSLOG_BIND=bind); os.environ.pop("SOC_SYSLOG_ALLOW_ANY", None)
            os.environ["SOC_SYSLOG_PORT"] = "65099" if not expect_refuse else "65098"; buf = io.StringIO()
            with contextlib.redirect_stdout(buf):
                try: syslogrx.start()
                except Exception: pass
            self.assertEqual("REFUSING" in buf.getvalue(), expect_refuse, f"{bind}: {buf.getvalue()[:120]}")
        os.environ.pop("SOC_SYSLOG_BIND"); self.assertIn('"SOC_SYSLOG_BIND", "127.0.0.1"', open(ROOT + "/syslogrx.py").read())
    def test_03_geo_lookup_off_by_default_and_needs_env(self):
        import db; self.assertEqual(db.DEFAULTS["geo_lookup"], "0"); self.assertIn('os.environ.get("SOC_GEO_ENABLED") == "1"', open(ROOT + "/engine.py").read())
    def test_04_windows_installer_acl_and_token_handling(self):
        ps = open(ROOT + "/agent/install_windows.ps1", encoding="utf-8").read()
        self.assertIn("icacls $Dest /inheritance:r", ps); self.assertIn('"Users:(OI)(CI)RX"', ps); self.assertNotIn('"--token", $Token', ps); self.assertIn("$env:EXESOC_ENROLL_TOKEN = $Token", ps)
        self.assertLess(ps.index("icacls $Dest"), ps.index("Register-ScheduledTask"), "ACLs must be applied before the SYSTEM task is registered")
    def test_05_vendor_manifest_verification_detects_tamper(self):
        import vendor_assets as v; old = (v.V, v.MF); d = tempfile.mkdtemp(); v.V = d; v.MF = d + "/MANIFEST.json"
        try:
            self.assertFalse(v.verify(quiet=True)); m = {}
            for n in v.ASSETS:
                p = os.path.join(d, n); os.makedirs(os.path.dirname(p), exist_ok=True); open(p, "wb").write(b"content " + n.encode()); m[n] = dict(sri=v.sri(b"content " + n.encode()))
            json.dump(m, open(v.MF, "w")); self.assertTrue(v.verify(quiet=True))
            open(os.path.join(d, "leaflet.js"), "wb").write(b"evil"); self.assertFalse(v.verify(quiet=True), "modified vendored file must fail verification")
        finally: v.V, v.MF = old
    def test_06_cdn_fallback_is_flagged_when_not_vendored(self):
        import app as A; self.assertFalse(A.VENDOR, "repo ships without vendored assets (network needed): CDN fallback is an OPEN finding")
if __name__ == "__main__": unittest.main(verbosity=2)
