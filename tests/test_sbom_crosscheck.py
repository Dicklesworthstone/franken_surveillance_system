#!/usr/bin/env python3
"""tests/test_sbom_crosscheck.py — contract suite for the SBOM/provenance/
source/license/qualification cross-check (FSS-190, bead fss-x4a.26.10).

Fixtures are synthesized through the real generators in
scripts/release_artifacts.py (cargo_sbom + license_inventory), so the test
exercises the exact production shapes.
"""

import hashlib
import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO / "scripts"))

import release_artifacts  # noqa: E402
import sbom_crosscheck  # noqa: E402

METADATA = {
    "packages": [
        {"name": "alpha", "version": "1.0.0", "id": "alpha-1.0.0", "source": None, "license": "MIT", "license_file": None},
        {"name": "beta", "version": "2.1.0", "id": "beta-2.1.0", "source": "registry+https://example.invalid", "license": "Apache-2.0", "license_file": None},
    ]
}

LOCK = """# Automatically generated
version = 4

[[package]]
name = "alpha"
version = "1.0.0"

[[package]]
name = "beta"
version = "2.1.0"
"""


class _Ctx:
    version = "1.2.3"
    target = "darwin-arm64"
    target_base = "fss-1.2.3-darwin-arm64"
    source_date_epoch = 1_700_000_000
    artifacts = Path("/tmp/unused")


def _bundle(metadata=METADATA, license_override=None):
    sbom = release_artifacts.cargo_sbom(metadata, _Ctx())
    inv = release_artifacts.license_inventory(metadata, _Ctx())
    if license_override:
        for pkg in inv["packages"]:
            pkg["license"] = license_override
    return sbom, inv


def _good_receipt(lock_text: str) -> dict:
    return {
        "status": "passed",
        "cargoLockDigest": "sha256:" + hashlib.sha256(lock_text.encode()).hexdigest(),
    }


class TestAgreement(unittest.TestCase):
    def test_full_agreement_passes(self):
        sbom, inv = _bundle()
        failures = sbom_crosscheck.crosscheck(sbom, inv, LOCK, METADATA, _good_receipt(LOCK))
        self.assertEqual(failures, [], f"unexpected: {failures}")

    def test_sbom_extra_package_fails(self):
        sbom, inv = _bundle()
        sbom["packages"] = sbom["packages"][:1]  # drop one from the SBOM only
        failures = sbom_crosscheck.crosscheck(sbom, inv, LOCK, METADATA, _good_receipt(LOCK))
        self.assertTrue(any("sbom/inventory" in f for f in failures), failures)

    def test_inventory_lock_drift_fails(self):
        sbom, inv = _bundle()
        bad_lock = LOCK + '\n[[package]]\nname = "gamma"\nversion = "9.9.9"\n'
        failures = sbom_crosscheck.crosscheck(sbom, inv, bad_lock, METADATA, None)
        self.assertTrue(any("inventory/lock" in f for f in failures), failures)

    def test_noassertion_license_fails_with_guidance(self):
        sbom, inv = _bundle(license_override="NOASSERTION")
        failures = sbom_crosscheck.crosscheck(sbom, inv, LOCK, METADATA, _good_receipt(LOCK))
        self.assertTrue(any("without a license" in f for f in failures), failures)
        self.assertTrue(any("cannot ship" in f for f in failures), failures)

    def test_wrong_metadata_digest_fails_provenance(self):
        sbom, inv = _bundle()
        other = {"packages": []}
        failures = sbom_crosscheck.crosscheck(sbom, inv, LOCK, other, None)
        self.assertTrue(any("provenance" in f for f in failures), failures)

    def test_failed_or_stale_receipt_fails_qualification_leg(self):
        sbom, inv = _bundle()
        failures = sbom_crosscheck.crosscheck(sbom, inv, LOCK, METADATA, {"status": "failed"})
        self.assertTrue(any("status" in f for f in failures), failures)
        stale = _good_receipt("tampered lock content")
        failures = sbom_crosscheck.crosscheck(sbom, inv, LOCK, METADATA, stale)
        self.assertTrue(any("cargoLockDigest" in f for f in failures), failures)


class TestCli(unittest.TestCase):
    def _write_bundle(self, td: Path):
        sbom, inv = _bundle()
        (td / "sbom.json").write_text(json.dumps(sbom), encoding="utf-8")
        (td / "inv.json").write_text(json.dumps(inv), encoding="utf-8")
        (td / "Cargo.lock").write_text(LOCK, encoding="utf-8")
        (td / "meta.json").write_text(json.dumps(METADATA), encoding="utf-8")
        (td / "receipt.json").write_text(json.dumps(_good_receipt(LOCK)), encoding="utf-8")

    def test_cli_pass_and_fail_exit_codes(self):
        with tempfile.TemporaryDirectory() as t:
            td = Path(t)
            self._write_bundle(td)
            base = [sys.executable, str(REPO / "scripts" / "sbom_crosscheck.py"),
                    "--sbom", str(td / "sbom.json"), "--inventory", str(td / "inv.json"),
                    "--lock", str(td / "Cargo.lock"), "--metadata", str(td / "meta.json"),
                    "--receipt", str(td / "receipt.json")]
            proc = subprocess.run(base, capture_output=True, text=True)
            self.assertEqual(proc.returncode, 0, proc.stdout[-200:])
            report = json.loads(proc.stdout)
            self.assertEqual(report["status"], "passed")
            self.assertEqual(report["sbomPackages"], 2)
            # Tamper the lock and expect failure.
            (td / "Cargo.lock").write_text(LOCK + '\n[[package]]\nname = "gamma"\nversion = "9.9.9"\n', encoding="utf-8")
            proc = subprocess.run(base, capture_output=True, text=True)
            self.assertEqual(proc.returncode, 1)
            self.assertEqual(json.loads(proc.stdout)["status"], "failed")

    def test_cli_missing_file_is_usage_error(self):
        proc = subprocess.run(
            [sys.executable, str(REPO / "scripts" / "sbom_crosscheck.py"),
             "--sbom", "/nonexistent.json", "--inventory", "/nonexistent.json", "--lock", "/nonexistent.lock"],
            capture_output=True, text=True,
        )
        self.assertEqual(proc.returncode, 2)


if __name__ == "__main__":
    unittest.main()
