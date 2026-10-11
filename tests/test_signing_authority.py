#!/usr/bin/env python3
"""tests/test_signing_authority.py — contract suite for the separated
build/signing authority (FSS-191, bead fss-x4a.26.11).

A throwaway minisign keypair is generated per run in a tempdir; nothing secret
enters the repo, the logs, or the test tree.
"""

import json
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
SCRIPT = REPO / "scripts" / "signing_authority.py"

MINISIGN = shutil.which("minisign") is not None


def _keypair(td: Path) -> tuple[str, Path]:
    proc = subprocess.run(
        ["minisign", "-G", "-W", "-p", str(td / "key.pub"), "-s", str(td / "key")],
        capture_output=True,
        text=True,
        timeout=30,
    )
    assert proc.returncode == 0, proc.stderr[-200:]
    return (td / "key.pub").read_text(encoding="utf-8").splitlines()[-1].strip(), td / "key"


def _manifest(td: Path, builder: str = "builder:release-lane") -> Path:
    m = td / "manifest.json"
    m.write_text(json.dumps({"builder": builder, "artifacts": []}), encoding="utf-8")
    return m


def _run(args: list[str]) -> tuple[int, dict]:
    proc = subprocess.run([sys.executable, str(SCRIPT), *args], capture_output=True, text=True, timeout=30)
    return proc.returncode, json.loads(proc.stdout)


class TestSeparation(unittest.TestCase):
    @unittest.skipUnless(MINISIGN, "minisign not installed")
    def test_sign_and_verify_round_trip(self):
        with tempfile.TemporaryDirectory() as t:
            td = Path(t)
            pub, key = _keypair(td)
            manifest = _manifest(td)
            sig = td / "manifest.json.minisig"
            rc, out = _run(["sign", "--manifest", str(manifest), "--signer", "signer:release-authority",
                            "--key", str(key), "--out", str(sig)])
            self.assertEqual(rc, 0, str(out))
            self.assertEqual(out["state"], "signed")
            self.assertEqual(out["builder"], "builder:release-lane")
            self.assertEqual(out["signer"], "signer:release-authority")
            self.assertTrue(sig.is_file())
            rc, out = _run(["verify", "--manifest", str(manifest), "--signer", "signer:release-authority",
                            "--public-key", pub, "--signature", str(sig)])
            self.assertEqual(rc, 0, str(out))
            self.assertEqual(out["state"], "verified")

    @unittest.skipUnless(MINISIGN, "minisign not installed")
    def test_same_authority_is_refused(self):
        with tempfile.TemporaryDirectory() as t:
            td = Path(t)
            _, key = _keypair(td)
            manifest = _manifest(td, builder="same-identity")
            rc, out = _run(["sign", "--manifest", str(manifest), "--signer", "same-identity",
                            "--key", str(key), "--out", str(td / "sig")])
            self.assertEqual(rc, 1)
            self.assertEqual(out["state"], "same_authority_refused")

    @unittest.skipUnless(MINISIGN, "minisign not installed")
    def test_tampered_manifest_fails_verification(self):
        with tempfile.TemporaryDirectory() as t:
            td = Path(t)
            pub, key = _keypair(td)
            manifest = _manifest(td)
            sig = td / "sig"
            rc, _ = _run(["sign", "--manifest", str(manifest), "--signer", "signer:x",
                          "--key", str(key), "--out", str(sig)])
            self.assertEqual(rc, 0)
            manifest.write_text(json.dumps({"builder": "builder:release-lane", "artifacts": ["tampered"]}), encoding="utf-8")
            rc, out = _run(["verify", "--manifest", str(manifest), "--signer", "signer:x",
                            "--public-key", pub, "--signature", str(sig)])
            self.assertEqual(rc, 1)
            self.assertEqual(out["state"], "verify_failed")

    @unittest.skipUnless(MINISIGN, "minisign not installed")
    def test_wrong_signer_identity_fails_verification(self):
        with tempfile.TemporaryDirectory() as t:
            td = Path(t)
            pub, key = _keypair(td)
            manifest = _manifest(td)
            sig = td / "sig"
            _run(["sign", "--manifest", str(manifest), "--signer", "signer:x",
                  "--key", str(key), "--out", str(sig)])
            rc, out = _run(["verify", "--manifest", str(manifest), "--signer", "signer:someone-else",
                            "--public-key", pub, "--signature", str(sig)])
            self.assertEqual(rc, 1, "the signature binds the exact signer identity")
            self.assertEqual(out["state"], "verify_failed")

    def test_missing_key_is_unavailable_not_crash(self):
        with tempfile.TemporaryDirectory() as t:
            td = Path(t)
            manifest = _manifest(td)
            if MINISIGN:
                rc, out = _run(["sign", "--manifest", str(manifest), "--signer", "signer:x",
                                "--key", str(td / "missing"), "--out", str(td / "sig")])
                self.assertEqual(rc, 1)
                self.assertEqual(out["state"], "unavailable")

    def test_missing_manifest_is_usage_error(self):
        proc = subprocess.run(
            [sys.executable, str(SCRIPT), "sign", "--manifest", "/nonexistent", "--signer", "x",
             "--key", "/nonexistent", "--out", "/tmp/x"],
            capture_output=True, text=True,
        )
        self.assertIn(proc.returncode, (1, 2))


if __name__ == "__main__":
    unittest.main()
