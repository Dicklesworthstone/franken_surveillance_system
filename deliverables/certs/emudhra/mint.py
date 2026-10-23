#!/usr/bin/env python3
"""Mint a leaf under the compromised eMudhra DV CA. Default SANs are the Wyze fleet hosts."""
import datetime as dt, sys
from cryptography import x509
from cryptography.x509.oid import NameOID, ExtendedKeyUsageOID
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import hashes, serialization

HERE = __file__.rsplit("/", 1)[0]
names = sys.argv[1:] or ["s3-us-west-2.amazonaws.com", "aws-iot.wyzecam.com"]
ca_key = serialization.load_pem_private_key(open(f"{HERE}/ev-ca.key.pem", "rb").read(), None)
ca = x509.load_pem_x509_certificate(open(f"{HERE}/ev-ca-aaa-cross.pem", "rb").read())
leaf_key = ec.generate_private_key(ec.SECP256R1())
now = dt.datetime.now(dt.timezone.utc)
cert = (x509.CertificateBuilder()
        .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, names[0])]))
        .issuer_name(ca.subject).public_key(leaf_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - dt.timedelta(days=1)).not_valid_after(now + dt.timedelta(days=365))
        .add_extension(x509.SubjectAlternativeName([x509.DNSName(n) for n in names]), critical=False)
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
        .add_extension(x509.ExtendedKeyUsage([ExtendedKeyUsageOID.SERVER_AUTH]), critical=False)
        .sign(ca_key, hashes.SHA384()))
open(f"{HERE}/leaf.pem", "wb").write(cert.public_bytes(serialization.Encoding.PEM))
open(f"{HERE}/leaf.key", "wb").write(leaf_key.private_bytes(
    serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()))
print("wrote leaf.pem / leaf.key for", ", ".join(names))
