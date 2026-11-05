"""Regression: install_windows.ps1 must copy every local module the agent imports.
(Bug: exe_soc_agent.py imported soc_preflight.py but the installer did not copy it -> ModuleNotFoundError on Windows.)
Run:  python tests/test_windows_installer.py"""
import ast, os, re, shutil, subprocess, sys, tempfile, unittest

AGENT = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "agent")
PS1 = open(os.path.join(AGENT, "install_windows.ps1"), encoding="utf-8").read()


def local_imports(fname):
    tree = ast.parse(open(os.path.join(AGENT, fname), encoding="utf-8").read())
    mods = set()
    for n in ast.walk(tree):
        names = [n.module] if isinstance(n, ast.ImportFrom) and n.module else [a.name for a in n.names] if isinstance(n, ast.Import) else []
        for m in names:
            top = m.split(".")[0]
            if os.path.isfile(os.path.join(AGENT, top + ".py")):
                mods.add(top + ".py")
    return mods


class WindowsInstaller(unittest.TestCase):
    def test_every_local_import_is_copied(self):
        need = local_imports("exe_soc_agent.py") | {"exe_soc_agent.py", "requirements.txt"}
        for f in sorted(need):
            self.assertIn('"%s"' % f, PS1, "install_windows.ps1 does not copy %s" % f)
        self.assertIn("collectors", PS1)

    def test_agent_starts_from_copied_files_only(self):
        listed = re.findall(r'"([A-Za-z0-9_]+\.(?:py|txt))"', PS1.split("Copy-Item")[0] + PS1)
        d = tempfile.mkdtemp()
        try:
            for f in set(listed):
                if os.path.isfile(os.path.join(AGENT, f)):
                    shutil.copy(os.path.join(AGENT, f), d)
            shutil.copytree(os.path.join(AGENT, "collectors"), os.path.join(d, "collectors"))
            r = subprocess.run([sys.executable, os.path.join(d, "exe_soc_agent.py"), "--help"], capture_output=True, text=True, cwd=d)
            self.assertEqual(r.returncode, 0, r.stderr)
        finally:
            shutil.rmtree(d, ignore_errors=True)


if __name__ == "__main__":
    unittest.main(verbosity=2)
