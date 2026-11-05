#!/usr/bin/env python3
"""Create a private development CA + server certificate (needs: pip install cryptography).  Certificates include Subject/Authority Key Identifiers (needed by Python 3.13+ strict verification). Nothing here disables verification:
agents are told to trust ONLY this CA via  --ca-bundle certs/ca.pem.
  python tools/dev_certs.py --name soc.lan --ip 192.168.1.50 [--out certs]"""
import argparse, datetime, ipaddress, os
from cryptography import x509
from cryptography.x509.oid import NameOID, ExtendedKeyUsageOID
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec

def key(): return ec.generate_private_key(ec.SECP256R1())
def pem(k): return k.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption())
a = argparse.ArgumentParser(); a.add_argument("--name", default="localhost", help="DNS name agents will use"); a.add_argument("--ip", action="append", default=["127.0.0.1"]); a.add_argument("--out", default="certs"); a.add_argument("--days", type=int, default=365)
o = a.parse_args(); os.makedirs(o.out, exist_ok=True); now = datetime.datetime.now(datetime.timezone.utc)
ck = key(); cn = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "EXE-SOC Dev CA")])
ca = (x509.CertificateBuilder().subject_name(cn).issuer_name(cn).public_key(ck.public_key()).serial_number(x509.random_serial_number()).not_valid_before(now - datetime.timedelta(minutes=5))
      .not_valid_after(now + datetime.timedelta(days=o.days)).add_extension(x509.BasicConstraints(ca=True, path_length=0), True)
      .add_extension(x509.KeyUsage(False, False, False, False, False, True, True, False, False), True)
      .add_extension(x509.SubjectKeyIdentifier.from_public_key(ck.public_key()), False).sign(ck, hashes.SHA256()))
sk = key(); san = [x509.DNSName(o.name), x509.DNSName("localhost")] + [x509.IPAddress(ipaddress.ip_address(i)) for i in dict.fromkeys(o.ip)]
sc = (x509.CertificateBuilder().subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, o.name)])).issuer_name(cn).public_key(sk.public_key()).serial_number(x509.random_serial_number())
      .not_valid_before(now - datetime.timedelta(minutes=5)).not_valid_after(now + datetime.timedelta(days=o.days)).add_extension(x509.SubjectAlternativeName(san), False)
      .add_extension(x509.ExtendedKeyUsage([ExtendedKeyUsageOID.SERVER_AUTH]), False).add_extension(x509.BasicConstraints(ca=False, path_length=None), True)
      .add_extension(x509.SubjectKeyIdentifier.from_public_key(sk.public_key()), False)
      .add_extension(x509.AuthorityKeyIdentifier.from_issuer_public_key(ck.public_key()), False).sign(ck, hashes.SHA256()))
w = lambda n, b: (open(os.path.join(o.out, n), "wb").write(b), os.chmod(os.path.join(o.out, n), 0o600 if "key" in n else 0o644))
w("ca.pem", ca.public_bytes(serialization.Encoding.PEM)); w("server.pem", sc.public_bytes(serialization.Encoding.PEM)); w("server.key", pem(sk)); w("ca.key", pem(ck))
print(f"Created in {o.out}/: ca.pem (give to agents: --ca-bundle), server.pem + server.key (server: SOC_TLS_CERT / SOC_TLS_KEY). Keep ca.key private.")
