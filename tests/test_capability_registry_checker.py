from __future__ import annotations

import copy
import json
import shutil
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]

import sys
sys.path.insert(0, str(ROOT / "scripts"))
import capability_registry_checker
from capability_registry_checker import (
    ERR_CAPABILITY_CORRUPT_FILE,
    ERR_CAPABILITY_DIGEST_MISMATCH,
    ERR_CAPABILITY_MISSING_DEFAULT,
    ERR_CAPABILITY_REGISTRY_DRIFT,
    ERR_CAPABILITY_STABLE_ID_REUSED,
    ERR_CAPABILITY_UNKNOWN_PLANE,
    compute_canonical_capability_digest,
    validate_capability_registry,
)


class CapabilityRegistryCheckerTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp_dir = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp_dir.cleanup)
        self.fake_root = Path(self.temp_dir.name)

        # Copy live files
        (self.fake_root / "architecture").mkdir(parents=True, exist_ok=True)
        (self.fake_root / "registries").mkdir(parents=True, exist_ok=True)

        shutil.copyfile(ROOT / "registries/CAPABILITIES.md", self.fake_root / "registries/CAPABILITIES.md")
        if (ROOT / "architecture/capabilities.json").exists():
            shutil.copyfile(ROOT / "architecture/capabilities.json", self.fake_root / "architecture/capabilities.json")

    def _read_json(self) -> dict:
        return json.loads((self.fake_root / "architecture/capabilities.json").read_text(encoding="utf-8"))

    def _write_json(self, data: dict) -> None:
        (self.fake_root / "architecture/capabilities.json").write_text(json.dumps(data, indent=2), encoding="utf-8")

    def test_planted_negative_drift_row_missing_in_json(self) -> None:
        data = self._read_json()
        # Remove first row
        data["capabilities"] = data["capabilities"][1:]
        data["registryDigest"] = compute_canonical_capability_digest(data["capabilities"])
        self._write_json(data)

        res = validate_capability_registry(self.fake_root)
        self.assertFalse(res.passed)
        error_codes = [e.code for e in res.errors]
        self.assertIn(ERR_CAPABILITY_REGISTRY_DRIFT, error_codes)

    def test_planted_negative_drift_row_missing_in_md(self) -> None:
        md_path = self.fake_root / "registries/CAPABILITIES.md"
        lines = md_path.read_text(encoding="utf-8").splitlines()
        # Drop the first capability line
        filtered = [l for l in lines if "CAP-OBSERVE-STATUS-001" not in l]
        md_path.write_text("\n".join(filtered) + "\n", encoding="utf-8")

        res = validate_capability_registry(self.fake_root)
        self.assertFalse(res.passed)
        error_codes = [e.code for e in res.errors]
        self.assertIn(ERR_CAPABILITY_REGISTRY_DRIFT, error_codes)

    def test_planted_negative_drift_capability_mismatch(self) -> None:
        data = self._read_json()
        data["capabilities"][0]["capability"] = "tampered capability description"
        data["registryDigest"] = compute_canonical_capability_digest(data["capabilities"])
        self._write_json(data)

        res = validate_capability_registry(self.fake_root)
        self.assertFalse(res.passed)
        error_codes = [e.code for e in res.errors]
        self.assertIn(ERR_CAPABILITY_REGISTRY_DRIFT, error_codes)

    def test_planted_negative_drift_scope_mismatch(self) -> None:
        data = self._read_json()
        data["capabilities"][0]["scope"] = "tampered scope"
        data["registryDigest"] = compute_canonical_capability_digest(data["capabilities"])
        self._write_json(data)

        res = validate_capability_registry(self.fake_root)
        self.assertFalse(res.passed)
        error_codes = [e.code for e in res.errors]
        self.assertIn(ERR_CAPABILITY_REGISTRY_DRIFT, error_codes)

    def test_planted_negative_drift_plane_mismatch(self) -> None:
        data = self._read_json()
        # Change plane to another valid plane but mismatched with markdown
        data["capabilities"][0]["plane"] = "cognition"
        data["registryDigest"] = compute_canonical_capability_digest(data["capabilities"])
        self._write_json(data)

        res = validate_capability_registry(self.fake_root)
        self.assertFalse(res.passed)
        error_codes = [e.code for e in res.errors]
        self.assertIn(ERR_CAPABILITY_REGISTRY_DRIFT, error_codes)

    def test_planted_negative_drift_default_mismatch(self) -> None:
        data = self._read_json()
        data["capabilities"][0]["defaultRole"] = "tampered default role"
        data["registryDigest"] = compute_canonical_capability_digest(data["capabilities"])
        self._write_json(data)

        res = validate_capability_registry(self.fake_root)
        self.assertFalse(res.passed)
        error_codes = [e.code for e in res.errors]
        self.assertIn(ERR_CAPABILITY_REGISTRY_DRIFT, error_codes)

    def test_planted_negative_unknown_plane(self) -> None:
        data = self._read_json()
        data["capabilities"][0]["plane"] = "invalid_nonexistent_plane"
        data["registryDigest"] = compute_canonical_capability_digest(data["capabilities"])
        self._write_json(data)

        res = validate_capability_registry(self.fake_root)
        self.assertFalse(res.passed)
        error_codes = [e.code for e in res.errors]
        self.assertIn(ERR_CAPABILITY_UNKNOWN_PLANE, error_codes)

    def test_planted_negative_missing_default(self) -> None:
        data = self._read_json()
        data["capabilities"][0]["defaultRole"] = ""
        data["registryDigest"] = compute_canonical_capability_digest(data["capabilities"])
        self._write_json(data)

        res = validate_capability_registry(self.fake_root)
        self.assertFalse(res.passed)
        error_codes = [e.code for e in res.errors]
        self.assertIn(ERR_CAPABILITY_MISSING_DEFAULT, error_codes)

    def test_planted_negative_stable_id_reused(self) -> None:
        data = self._read_json()
        # Duplicate the first ID on the second row
        data["capabilities"][1]["id"] = data["capabilities"][0]["id"]
        data["registryDigest"] = compute_canonical_capability_digest(data["capabilities"])
        self._write_json(data)

        res = validate_capability_registry(self.fake_root)
        self.assertFalse(res.passed)
        error_codes = [e.code for e in res.errors]
        self.assertIn(ERR_CAPABILITY_STABLE_ID_REUSED, error_codes)

    def test_planted_negative_digest_mismatch(self) -> None:
        data = self._read_json()
        data["registryDigest"] = "sha256:0000000000000000000000000000000000000000000000000000000000000000"
        self._write_json(data)

        res = validate_capability_registry(self.fake_root)
        self.assertFalse(res.passed)
        error_codes = [e.code for e in res.errors]
        self.assertIn(ERR_CAPABILITY_DIGEST_MISMATCH, error_codes)

    def test_planted_negative_corrupt_json(self) -> None:
        (self.fake_root / "architecture/capabilities.json").write_text("{corrupt: true", encoding="utf-8")

        res = validate_capability_registry(self.fake_root)
        self.assertFalse(res.passed)
        error_codes = [e.code for e in res.errors]
        self.assertIn(ERR_CAPABILITY_CORRUPT_FILE, error_codes)

    def test_planted_negative_missing_file(self) -> None:
        (self.fake_root / "architecture/capabilities.json").unlink()

        res = validate_capability_registry(self.fake_root)
        self.assertFalse(res.passed)
        error_codes = [e.code for e in res.errors]
        self.assertIn(ERR_CAPABILITY_CORRUPT_FILE, error_codes)

    def test_live_capability_registry_passes(self) -> None:
        res = validate_capability_registry(ROOT)
        self.assertTrue(res.passed, f"Validation failed with errors: {res.errors}")
        self.assertEqual(res.capability_count, 43)
        self.assertTrue(res.registry_digest.startswith("sha256:"))


if __name__ == "__main__":
    unittest.main()
