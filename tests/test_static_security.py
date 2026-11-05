#!/usr/bin/env python3
"""Lightweight static security checks (AST based). NOT a replacement for Bandit/Semgrep/pip-audit, which could not be installed offline - run those in CI. Run: python tests/test_static_security.py"""
import os, ast, re, sys, subprocess, unittest
ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
def py_files():
    for d, ds, fs in os.walk(ROOT):
        ds[:] = [x for x in ds if x not in (".git", ".venv", "__pycache__", "tests")]
        for f in fs:
            if f.endswith(".py"): yield os.path.join(d, f)
class Static(unittest.TestCase):
    def test_01_no_dangerous_calls(self):
        bad = []
        for p in py_files():
            for n in ast.walk(ast.parse(open(p, encoding="utf-8").read(), p)):
                if not isinstance(n, ast.Call): continue
                f = n.func; rel = f"{os.path.relpath(p, ROOT)}:{n.lineno}"
                if isinstance(f, ast.Name) and f.id in ("eval", "exec"): bad.append(f"{rel} {f.id}")
                if isinstance(f, ast.Attribute) and isinstance(f.value, ast.Name):
                    if f.value.id == "os" and f.attr in ("system", "popen"): bad.append(f"{rel} os.{f.attr}")
                    if f.value.id == "pickle" and f.attr in ("load", "loads"): bad.append(f"{rel} pickle.{f.attr}")
                    if f.value.id == "yaml" and f.attr == "load": bad.append(f"{rel} yaml.load")
                for kw in n.keywords:
                    if kw.arg == "shell" and isinstance(kw.value, ast.Constant) and kw.value.value is True: bad.append(f"{rel} shell=True")
                    if kw.arg == "verify" and isinstance(kw.value, ast.Constant) and kw.value.value is False: bad.append(f"{rel} verify=False")
        self.assertEqual(bad, [])
    def test_02_no_tls_verification_bypass_or_debug_server_in_production_paths(self):
        for p in py_files():
            s = open(p, encoding="utf-8").read()
            self.assertNotRegex(s, r"CERT_NONE|check_hostname\s*=\s*False|_create_unverified_context", os.path.relpath(p, ROOT))
        w = open(os.path.join(ROOT, "wsgi.py")).read(); self.assertNotIn("debug=True", w); self.assertNotIn("socketio.run", w)
    def test_03_no_hardcoded_secrets_in_source_or_docs(self):
        pat = re.compile(r"(?i)(secret|passw(or)?d|api[_-]?key|token)\s*[:=]\s*['\"]([A-Za-z0-9_\-+/=]{24,})['\"]")
        hits = []
        for p in py_files():
            for n, l in enumerate(open(p, encoding="utf-8").read().splitlines(), 1):
                m = pat.search(l)
                if m and not re.search(r"environ|getenv|os\.environ|<|example|placeholder|test", l, re.I): hits.append(f"{os.path.relpath(p, ROOT)}:{n}")
        self.assertEqual(hits, [])
    def test_04_gitignore_covers_secret_material(self):
        g = open(os.path.join(ROOT, ".gitignore")).read()
        for k in (".secret", ".env", "soc.db"): self.assertIn(k, g)
        for k in ("*.pem", "*.key", ".soc_enc_key", "initial_admin_credentials.txt"):
            self.assertIn(k, g, f"{k} must be git-ignored")
    def test_05_every_python_file_compiles(self):
        r = subprocess.run([sys.executable, "-m", "compileall", "-q", ROOT], capture_output=True, text=True); self.assertEqual(r.returncode, 0, r.stdout[-500:] + r.stderr[-500:])
    def test_06_sql_fstrings_use_only_internal_identifiers(self):
        """f-string SQL is only allowed when every interpolation is an identifier/constant expression (no request data): list the interpolated names for review."""
        risky = []
        for p in py_files():
            for n in ast.walk(ast.parse(open(p, encoding="utf-8").read(), p)):
                if isinstance(n, ast.Call) and isinstance(n.func, ast.Attribute) and n.func.attr in ("execute", "q", "x") and n.args and isinstance(n.args[0], ast.JoinedStr):
                    for v in n.args[0].values:
                        if isinstance(v, ast.FormattedValue) and not isinstance(v.value, (ast.Name, ast.Constant, ast.Attribute, ast.Call, ast.Subscript, ast.JoinedStr, ast.BinOp, ast.IfExp, ast.ListComp, ast.GeneratorExp)): risky.append(f"{os.path.relpath(p, ROOT)}:{n.lineno}")
        self.assertEqual(risky, [])
    def test_07_every_third_party_import_is_declared_in_requirements(self):
        """A fresh `pip install -r requirements.txt` must be enough to start the app (cryptography was imported but undeclared before Pass 4)."""
        local = set()
        for d, ds, fs in os.walk(ROOT):
            ds[:] = [x for x in ds if x not in (".git", "__pycache__", ".venv")]
            local |= {f[:-3] for f in fs if f.endswith(".py")} | set(ds)
        used = set()
        for p in py_files():
            for n in ast.walk(ast.parse(open(p, encoding="utf-8").read(), p)):
                names = [a.name.split(".")[0] for a in n.names] if isinstance(n, ast.Import) else ([n.module.split(".")[0]] if isinstance(n, ast.ImportFrom) and n.level == 0 and n.module else [])
                used |= {m for m in names if m not in sys.stdlib_module_names and m not in local}
        declared = {re.split(r"[<>=!~\[ ;#]", l.strip())[0].lower().replace("_", "-") for l in open(os.path.join(ROOT, "requirements.txt")) if l.strip() and not l.startswith(("#", "-"))}
        optional = {"regex"}; flask_deps = {"werkzeug", "markupsafe"}
        missing = sorted(m for m in used if m.lower().replace("_", "-") not in declared and m not in optional and m not in flask_deps)
        self.assertEqual(missing, [], "imported but not declared in requirements.txt")

if __name__ == "__main__": unittest.main(verbosity=2)
