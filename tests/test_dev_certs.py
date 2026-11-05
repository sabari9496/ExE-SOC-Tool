"""Regression: dev certificates must pass STRICT verification (default in Python 3.13+, e.g. Kali/Debian 13).
Bug: certs lacked Subject/Authority Key Identifier -> 'Missing Authority Key Identifier' on Python 3.13+.
Run:  python tests/test_dev_certs.py"""
import os, socket, ssl, subprocess, sys, tempfile, threading, unittest
ROOT = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..")


class DevCerts(unittest.TestCase):
    def test_strict_verification(self):
        d = tempfile.mkdtemp()
        subprocess.run([sys.executable, os.path.join(ROOT, "tools", "dev_certs.py"), "--name", "soc.lan", "--ip", "127.0.0.1", "--out", d], check=True, capture_output=True)
        sctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER); sctx.load_cert_chain(os.path.join(d, "server.pem"), os.path.join(d, "server.key"))
        srv = socket.socket(); srv.bind(("127.0.0.1", 0)); srv.listen(1); port = srv.getsockname()[1]
        def run():
            try: c, _ = srv.accept(); sctx.wrap_socket(c, server_side=True).close()
            except Exception: pass
        threading.Thread(target=run, daemon=True).start()
        ctx = ssl.create_default_context(cafile=os.path.join(d, "ca.pem")); ctx.verify_flags |= ssl.VERIFY_X509_STRICT
        with socket.create_connection(("127.0.0.1", port)) as c, ctx.wrap_socket(c, server_hostname="127.0.0.1") as t:
            self.assertTrue(t.version())
        srv.close()


if __name__ == "__main__":
    unittest.main(verbosity=2)
