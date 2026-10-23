#!/usr/bin/env python3
"""Build a Wyze v4 OTA capsule (`Upgrade.tar`) for the owner-authorized installer path.

The consumer (`assis`) requires exactly this: a tar that extracts to
`/tmp/Upgrade/upgraderun.sh`; it then runs `sh /tmp/Upgrade/upgraderun.sh` as root.
No signature is checked — only the caller-supplied MD5 of the bytes we serve.

Two carriers exist; the builder emits both so a failed mode is diagnosable:

  plain  — the tar bytes verbatim (taken when the descriptor's encrypt key is empty)
  aes256 — AES-256-ECB, no IV, no padding, 32-byte product key (encrypt_type 1)

`aes256` requires the tar length to be a multiple of 16; the consumer decrypts only
whole 1024-byte blocks and memcpy's a short final block verbatim, so the caller pads.

Usage:
  build_ota_tar.py --script upgraderun.sh --out-dir DIR [--files f1 f2 ...]
Prints a JSON descriptor with path, size, md5 and sha256 for both carriers.
"""
import argparse
import hashlib
import io
import json
import os
import sys
import tarfile

PRODUCT_KEY = b"oU8XzEpbOD6pVTLwdz9pxRpN9MGPCo1P"
BLOCK = 1024


def aes_ecb(data: bytes, key: bytes) -> bytes:
    try:
        from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
    except ImportError:
        sys.exit("cryptography is required for --carrier aes256")
    enc = Cipher(algorithms.AES(key), modes.ECB()).encryptor()
    return enc.update(data) + enc.finalize()


def build_tar(script: str, extra: list[tuple[str, bytes]]) -> bytes:
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w", format=tarfile.GNU_FORMAT) as tf:
        for name, blob in extra:
            info = tarfile.TarInfo(name="Upgrade/" + name)
            info.size = len(blob)
            info.mode = 0o755
            info.mtime = 0
            tf.addfile(info, io.BytesIO(blob))
        info = tarfile.TarInfo(name="Upgrade/upgraderun.sh")
        blob = script.encode()
        info.size = len(blob)
        info.mode = 0o755
        info.mtime = 0
        tf.addfile(info, io.BytesIO(blob))
    return buf.getvalue()


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--script", required=True)
    ap.add_argument("--out-dir", required=True)
    ap.add_argument("--file", action="append", default=[])
    ap.add_argument("--no-aes", action="store_true")
    args = ap.parse_args()

    script = open(args.script).read()
    extra = []
    for spec in args.file:
        src, _, dst = spec.partition(":")
        extra.append((dst or os.path.basename(src), open(src, "rb").read()))

    tar = build_tar(script, extra)
    os.makedirs(args.out_dir, exist_ok=True)
    out = {}

    plain = os.path.join(args.out_dir, "Upgrade.tar")
    with open(plain, "wb") as fh:
        fh.write(tar)
    out["plain"] = {"path": plain, "size": len(tar),
                    "md5": hashlib.md5(tar).hexdigest(),
                    "sha256": hashlib.sha256(tar).hexdigest()}

    if not args.no_aes:
        # Plaintext tail is copied verbatim by the consumer, so pad the whole
        # tar to a 1024-byte boundary and check the first block decrypted.
        pad = (-len(tar)) % BLOCK
        ct = aes_ecb(tar + b"\0" * pad, PRODUCT_KEY)
        enc = os.path.join(args.out_dir, "Upgrade.tar.aes")
        with open(enc, "wb") as fh:
            fh.write(ct)
        out["aes256"] = {"path": enc, "size": len(ct), "pad": pad,
                         "md5": hashlib.md5(ct).hexdigest(),
                         "sha256": hashlib.sha256(ct).hexdigest()}

    print(json.dumps(out, indent=1))
    return 0


if __name__ == "__main__":
    sys.exit(main())
