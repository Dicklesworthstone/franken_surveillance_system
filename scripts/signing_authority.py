#!/usr/bin/env python3
"""scripts/signing_authority.py — separated build/signing authority for release
artifacts (FSS-191, bead fss-x4a.26.11).

architecture/local_qualification.toml mandates `signing_separate_from_build =
true`: the principal that BUILT an artifact must never be the principal that
SIGNS it. This module enforces that separation over minisign (Ed25519):

  * the release manifest names its builder identity;
  * signing requires a caller-named signer identity and a caller-supplied
    minisign secret-key path (the key is never read into this process's
    output, logs, or the repo);
  * builder == signer is a typed refusal (`same_authority`), not a warning;
  * the detached signature binds the manifest's exact digest;
  * verification re-computes the digest and checks the minisign signature
    against the registered public key.

Typed outcomes (stable identities, never parse prose): signed,
same_authority_refused, unavailable (minisign or key missing), verify_failed,
usage_error. Exit codes: 0 signed/verified, 1 refused/failed, 2 usage error.
"""

import argparse
import hashlib
import json
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

SCHEMA = "fss.signing_authority.v1"


def _emit(state: str, **fields) -> int:
    payload = {"schema": SCHEMA, "state": state, **fields}
    print(json.dumps(payload, sort_keys=True))
    return {"signed": 0, "verified": 0}.get(state, 1) if state not in ("signed", "verified") else 0


def _manifest_digest(manifest_path: Path) -> str:
    return "sha256:" + hashlib.sha256(manifest_path.read_bytes()).hexdigest()


def _builder_identity(manifest_path: Path) -> str | None:
    try:
        data = json.loads(manifest_path.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return None
    value = data.get("builder") or data.get("builtBy") or data.get("builderIdentity")
    return value if isinstance(value, str) and value else None


def _minisign_sign(secret_key: Path, payload: bytes) -> bytes | None:
    with tempfile.NamedTemporaryFile() as tmp:
        tmp.write(payload)
        tmp.flush()
        proc = subprocess.run(
            ["minisign", "-s", str(secret_key), "-Sm", tmp.name],
            capture_output=True,
            timeout=30,
        )
        if proc.returncode != 0:
            return None
        sig_path = Path(tmp.name + ".minisig")
        try:
            return sig_path.read_bytes()
        finally:
            sig_path.unlink(missing_ok=True)


def _minisign_verify(public_key: str, payload: bytes, signature: bytes) -> bool:
    with tempfile.TemporaryDirectory() as td:
        td_path = Path(td)
        msg = td_path / "msg"
        msg.write_bytes(payload)
        sig = td_path / "msg.minisig"
        sig.write_bytes(signature)
        proc = subprocess.run(
            ["minisign", "-Vm", str(msg), "-P", public_key],
            capture_output=True,
            timeout=30,
        )
        return proc.returncode == 0


def cmd_sign(args: argparse.Namespace) -> int:
    if shutil.which("minisign") is None:
        return _emit("unavailable", detail="minisign not installed on this host")
    if not args.key.is_file():
        return _emit("unavailable", detail="secret key path unreadable")
    digest = _manifest_digest(args.manifest)
    builder = _builder_identity(args.manifest)
    if builder is None:
        return _emit("usage_error", detail="manifest has no builder identity field")
    if builder == args.signer:
        return _emit(
            "same_authority_refused",
            detail="builder and signer identities coincide; signing_separate_from_build forbids this",
        )
    payload = json.dumps(
        {"manifestDigest": digest, "builder": builder, "signer": args.signer},
        sort_keys=True,
    ).encode()
    signature = _minisign_sign(args.key, payload)
    if signature is None:
        return _emit("unavailable", detail="minisign signing failed")
    args.out.write_bytes(signature)
    return _emit("signed", manifestDigest=digest, builder=builder, signer=args.signer, signature=str(args.out))


def cmd_verify(args: argparse.Namespace) -> int:
    if shutil.which("minisign") is None:
        return _emit("unavailable", detail="minisign not installed on this host")
    digest = _manifest_digest(args.manifest)
    builder = _builder_identity(args.manifest) or ""
    payload = json.dumps(
        {"manifestDigest": digest, "builder": builder, "signer": args.signer},
        sort_keys=True,
    ).encode()
    try:
        signature = args.signature.read_bytes()
    except OSError:
        return _emit("usage_error", detail="signature unreadable")
    if _minisign_verify(args.public_key, payload, signature):
        return _emit("verified", manifestDigest=digest, signer=args.signer)
    return _emit("verify_failed", manifestDigest=digest)


def main() -> int:
    parser = argparse.ArgumentParser(description="FSS-191 separated signing authority")
    sub = parser.add_subparsers(dest="cmd", required=True)
    p_sign = sub.add_parser("sign")
    p_sign.add_argument("--manifest", type=Path, required=True)
    p_sign.add_argument("--signer", required=True, help="signing authority identity")
    p_sign.add_argument("--key", type=Path, required=True, help="minisign secret key path (never logged/copied)")
    p_sign.add_argument("--out", type=Path, required=True, help="detached signature output path")
    p_verify = sub.add_parser("verify")
    p_verify.add_argument("--manifest", type=Path, required=True)
    p_verify.add_argument("--signer", required=True)
    p_verify.add_argument("--public-key", required=True, help="registered minisign public key text")
    p_verify.add_argument("--signature", type=Path, required=True)
    args = parser.parse_args()
    if args.cmd == "sign":
        return cmd_sign(args)
    return cmd_verify(args)


if __name__ == "__main__":
    sys.exit(main())
