"""Regression: install_linux.sh must set its own umask (a caller umask of 077 made the venv root-only -> systemd 203/EXEC).
Run:  python tests/test_installer_umask.py"""
import os, re, unittest
SH = open(os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "agent", "install_linux.sh"), encoding="utf-8").read()

class Umask(unittest.TestCase):
    def test_umask_set_before_any_work(self):
        m = re.search(r"^umask 022$", SH, re.M); self.assertTrue(m, "install_linux.sh must run 'umask 022'")
        self.assertLess(m.start(), SH.index("python3 -m venv"), "umask must be set before the venv is created")

if __name__ == "__main__":
    unittest.main(verbosity=2)
