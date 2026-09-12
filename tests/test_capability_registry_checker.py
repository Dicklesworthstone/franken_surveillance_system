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
    BASELINE_CAPABILITIES,
    CURRENT_GENERATION,
    ERR_CAPABILITY_CORRUPT_FILE,
    ERR_CAPABILITY_DIGEST_MISMATCH,
    ERR_CAPABILITY_MISSING_DEFAULT,
    ERR_CAPABILITY_REGISTRY_DRIFT,
    ERR_CAPABILITY_STABLE_ID_REUSED,
    ERR_CAPABILITY_UNKNOWN_PLANE,
    EXPECTED_FREEZE_DIGESTS,
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

    def test_live_capability_registry_passes(self) -> None:
        """Live repository capability registry passes with exact pinned freeze digest."""
        res = validate_capability_registry(ROOT)
        self.assertTrue(res.passed, f"Validation failed with errors: {res.errors}")
        self.assertEqual(res.capability_count, 43)
        expected = EXPECTED_FREEZE_DIGESTS[CURRENT_GENERATION]
        self.assertEqual(res.registry_digest, expected)
        self.assertEqual(res.registry_digest, "sha256:5056fe20103a6c9a157fdb0e29bf5371384b976e874bf2964ff817fb202f045a")

    def test_planted_negative_drift_row_missing_in_json(self) -> None:
        """Removing a row from JSON fails with drift and digest mismatch."""
        data = self._read_json()
        data["capabilities"] = data["capabilities"][1:]
        data["registryDigest"] = compute_canonical_capability_digest(data)
        self._write_json(data)

        res = validate_capability_registry(self.fake_root)
        self.assertFalse(res.passed)
        error_codes = [e.code for e in res.errors]
        self.assertIn(ERR_CAPABILITY_REGISTRY_DRIFT, error_codes)
        self.assertIn(ERR_CAPABILITY_DIGEST_MISMATCH, error_codes)

    def test_planted_negative_drift_row_missing_in_md(self) -> None:
        """Removing a row from Markdown mirror fails with drift."""
        md_path = self.fake_root / "registries/CAPABILITIES.md"
        lines = md_path.read_text(encoding="utf-8").splitlines()
        filtered = [l for l in lines if "CAP-OBSERVE-STATUS-001" not in l]
        md_path.write_text("\n".join(filtered) + "\n", encoding="utf-8")

        res = validate_capability_registry(self.fake_root)
        self.assertFalse(res.passed)
        error_codes = [e.code for e in res.errors]
        self.assertIn(ERR_CAPABILITY_REGISTRY_DRIFT, error_codes)

    def test_planted_negative_drift_capability_mismatch(self) -> None:
        """Tampering with capability description fails closed."""
        data = self._read_json()
        data["capabilities"][0]["capability"] = "tampered capability description"
        data["registryDigest"] = compute_canonical_capability_digest(data)
        self._write_json(data)

        res = validate_capability_registry(self.fake_root)
        self.assertFalse(res.passed)
        error_codes = [e.code for e in res.errors]
        self.assertIn(ERR_CAPABILITY_REGISTRY_DRIFT, error_codes)
        self.assertIn(ERR_CAPABILITY_DIGEST_MISMATCH, error_codes)

    def test_planted_negative_drift_scope_mismatch(self) -> None:
        """Tampering with scope fails closed."""
        data = self._read_json()
        data["capabilities"][0]["scope"] = "tampered scope"
        data["registryDigest"] = compute_canonical_capability_digest(data)
        self._write_json(data)

        res = validate_capability_registry(self.fake_root)
        self.assertFalse(res.passed)
        error_codes = [e.code for e in res.errors]
        self.assertIn(ERR_CAPABILITY_REGISTRY_DRIFT, error_codes)
        self.assertIn(ERR_CAPABILITY_DIGEST_MISMATCH, error_codes)

    def test_planted_negative_drift_plane_mismatch(self) -> None:
        """Tampering with plane in JSON fails closed."""
        data = self._read_json()
        data["capabilities"][0]["plane"] = "cognition"
        data["registryDigest"] = compute_canonical_capability_digest(data)
        self._write_json(data)

        res = validate_capability_registry(self.fake_root)
        self.assertFalse(res.passed)
        error_codes = [e.code for e in res.errors]
        self.assertIn(ERR_CAPABILITY_REGISTRY_DRIFT, error_codes)
        self.assertIn(ERR_CAPABILITY_DIGEST_MISMATCH, error_codes)

    def test_planted_negative_drift_default_mismatch(self) -> None:
        """Tampering with defaultRole fails closed."""
        data = self._read_json()
        data["capabilities"][0]["defaultRole"] = "tampered default role"
        data["registryDigest"] = compute_canonical_capability_digest(data)
        self._write_json(data)

        res = validate_capability_registry(self.fake_root)
        self.assertFalse(res.passed)
        error_codes = [e.code for e in res.errors]
        self.assertIn(ERR_CAPABILITY_REGISTRY_DRIFT, error_codes)
        self.assertIn(ERR_CAPABILITY_DIGEST_MISMATCH, error_codes)

    def test_planted_negative_self_referential_denial_reason_drift_with_recomputed_digest(self) -> None:
        """Mutating denialReason and recomputing digest fails closed against pinned digest and baseline."""
        data = self._read_json()
        data["capabilities"][0]["denialReason"] = "tampered: ambient authority granted"
        data["registryDigest"] = compute_canonical_capability_digest(data)
        self._write_json(data)

        res = validate_capability_registry(self.fake_root)
        self.assertFalse(res.passed)
        error_codes = [e.code for e in res.errors]
        self.assertIn(ERR_CAPABILITY_REGISTRY_DRIFT, error_codes)
        self.assertIn(ERR_CAPABILITY_DIGEST_MISMATCH, error_codes)

    def test_planted_negative_self_referential_safe_alternative_drift(self) -> None:
        """Mutating safeAlternative and recomputing digest fails closed against baseline and pinned digest."""
        data = self._read_json()
        data["capabilities"][0]["safeAlternative"] = "tampered: bypass checks entirely"
        data["registryDigest"] = compute_canonical_capability_digest(data)
        self._write_json(data)

        res = validate_capability_registry(self.fake_root)
        self.assertFalse(res.passed)
        error_codes = [e.code for e in res.errors]
        self.assertIn(ERR_CAPABILITY_REGISTRY_DRIFT, error_codes)
        self.assertIn(ERR_CAPABILITY_DIGEST_MISMATCH, error_codes)

    def test_planted_negative_missing_denial_reason_or_safe_alternative(self) -> None:
        """Omitting denialReason or safeAlternative fails closed with corrupt file error."""
        data = self._read_json()
        del data["capabilities"][0]["denialReason"]
        data["registryDigest"] = compute_canonical_capability_digest(data)
        self._write_json(data)

        res = validate_capability_registry(self.fake_root)
        self.assertFalse(res.passed)
        error_codes = [e.code for e in res.errors]
        self.assertIn(ERR_CAPABILITY_CORRUPT_FILE, error_codes)

    def test_planted_negative_generation_bump_changes_digest(self) -> None:
        """Altering generation alters digest and fails closed on unpinned generation."""
        data = self._read_json()
        d1 = compute_canonical_capability_digest(data)
        data["generation"] = "gen:fss1:capabilities-v999"
        d2 = compute_canonical_capability_digest(data)
        self.assertNotEqual(d1, d2)

        data["registryDigest"] = d2
        self._write_json(data)

        res = validate_capability_registry(self.fake_root)
        self.assertFalse(res.passed)
        error_codes = [e.code for e in res.errors]
        self.assertIn(ERR_CAPABILITY_CORRUPT_FILE, error_codes)

    def test_planted_negative_top_level_schema_or_protocol_change(self) -> None:
        """Mutating semanticProtocol alters digest and fails closed."""
        data = self._read_json()
        data["semanticProtocol"] = "fss/2"
        data["registryDigest"] = compute_canonical_capability_digest(data)
        self._write_json(data)

        res = validate_capability_registry(self.fake_root)
        self.assertFalse(res.passed)
        error_codes = [e.code for e in res.errors]
        self.assertIn(ERR_CAPABILITY_CORRUPT_FILE, error_codes)
        self.assertIn(ERR_CAPABILITY_DIGEST_MISMATCH, error_codes)

    def test_planted_negative_renumbered_id_in_both_files_fails(self) -> None:
        """Renumbering a capability ID across both JSON and MD fails closed."""
        data = self._read_json()
        for cap in data["capabilities"]:
            if cap["id"] == "CAP-OBSERVE-STATUS-001":
                cap["id"] = "CAP-OBSERVE-STATUS-999"
        data["registryDigest"] = compute_canonical_capability_digest(data)
        self._write_json(data)

        md_path = self.fake_root / "registries/CAPABILITIES.md"
        md_text = md_path.read_text(encoding="utf-8")
        md_text = md_text.replace("CAP-OBSERVE-STATUS-001", "CAP-OBSERVE-STATUS-999")
        md_path.write_text(md_text, encoding="utf-8")

        res = validate_capability_registry(self.fake_root)
        self.assertFalse(res.passed)
        error_codes = [e.code for e in res.errors]
        self.assertIn(ERR_CAPABILITY_REGISTRY_DRIFT, error_codes)
        self.assertIn(ERR_CAPABILITY_DIGEST_MISMATCH, error_codes)

    def test_planted_negative_tombstone_resurrection_fails(self) -> None:
        """Adding a tombstone that overlaps an active capability ID fails closed."""
        data = self._read_json()
        data["tombstones"] = [
            {
                "id": "CAP-OBSERVE-STATUS-001",
                "reason": "superseded",
                "tombstonedAt": "2026-09-01",
            }
        ]
        self._write_json(data)

        res = validate_capability_registry(self.fake_root)
        self.assertFalse(res.passed)
        error_codes = [e.code for e in res.errors]
        self.assertIn(ERR_CAPABILITY_STABLE_ID_REUSED, error_codes)

    def test_planted_negative_unknown_plane(self) -> None:
        """Unknown plane fails closed with ERR_CAPABILITY_UNKNOWN_PLANE."""
        data = self._read_json()
        data["capabilities"][0]["plane"] = "invalid_nonexistent_plane"
        data["registryDigest"] = compute_canonical_capability_digest(data)
        self._write_json(data)

        res = validate_capability_registry(self.fake_root)
        self.assertFalse(res.passed)
        error_codes = [e.code for e in res.errors]
        self.assertIn(ERR_CAPABILITY_UNKNOWN_PLANE, error_codes)

    def test_planted_negative_missing_default(self) -> None:
        """Empty defaultRole fails closed with ERR_CAPABILITY_MISSING_DEFAULT."""
        data = self._read_json()
        data["capabilities"][0]["defaultRole"] = ""
        data["registryDigest"] = compute_canonical_capability_digest(data)
        self._write_json(data)

        res = validate_capability_registry(self.fake_root)
        self.assertFalse(res.passed)
        error_codes = [e.code for e in res.errors]
        self.assertIn(ERR_CAPABILITY_MISSING_DEFAULT, error_codes)

    def test_planted_negative_stable_id_reused(self) -> None:
        """Duplicate capability ID in registry fails closed."""
        data = self._read_json()
        data["capabilities"][1]["id"] = data["capabilities"][0]["id"]
        self._write_json(data)

        res = validate_capability_registry(self.fake_root)
        self.assertFalse(res.passed)
        error_codes = [e.code for e in res.errors]
        self.assertIn(ERR_CAPABILITY_STABLE_ID_REUSED, error_codes)

    def test_planted_negative_digest_mismatch(self) -> None:
        """Tampered registryDigest string fails closed."""
        data = self._read_json()
        data["registryDigest"] = "sha256:0000000000000000000000000000000000000000000000000000000000000000"
        self._write_json(data)

        res = validate_capability_registry(self.fake_root)
        self.assertFalse(res.passed)
        error_codes = [e.code for e in res.errors]
        self.assertIn(ERR_CAPABILITY_DIGEST_MISMATCH, error_codes)

    def test_planted_negative_corrupt_json(self) -> None:
        """Corrupt JSON fails closed."""
        (self.fake_root / "architecture/capabilities.json").write_text("{corrupt: true", encoding="utf-8")

        res = validate_capability_registry(self.fake_root)
        self.assertFalse(res.passed)
        error_codes = [e.code for e in res.errors]
        self.assertIn(ERR_CAPABILITY_CORRUPT_FILE, error_codes)

    def test_planted_negative_missing_file(self) -> None:
        """Missing JSON file fails closed."""
        (self.fake_root / "architecture/capabilities.json").unlink()

        res = validate_capability_registry(self.fake_root)
        self.assertFalse(res.passed)
        error_codes = [e.code for e in res.errors]
        self.assertIn(ERR_CAPABILITY_CORRUPT_FILE, error_codes)

    def test_digest_calculation_empty_or_duplicate_ids_fail_closed(self) -> None:
        """compute_canonical_capability_digest raises ValueError on empty or duplicate IDs."""
        data = self._read_json()
        data_empty = json.loads(json.dumps(data))
        data_empty["capabilities"][0]["id"] = ""
        with self.assertRaises(ValueError):
            compute_canonical_capability_digest(data_empty)

        data_dup = json.loads(json.dumps(data))
        data_dup["capabilities"][1]["id"] = data_dup["capabilities"][0]["id"]
        with self.assertRaises(ValueError):
            compute_canonical_capability_digest(data_dup)


if __name__ == "__main__":
    unittest.main()
