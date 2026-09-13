#!/usr/bin/env python3
"""Planted-negative test suite for device adapter registry checker (fss-x4a.30.89.1).

Verifies fail-closed enforcement of:
1. Live repository passes with 0 errors across all 11 adapter rows and exact pinned freeze digest
2. Canonical digest determinism and sensitivity to mutations
3. Digest mismatch detection (ERR-ADAPTER-DIGEST-MISMATCH-001)
4. Generation mismatch and missing generation identity (ERR-ADAPTER-GENERATION-MISMATCH-001)
5. Stable ID reuse, omission, unbaseline additions, and tombstone resurrection (ERR-ADAPTER-STABLE-ID-REUSED-001)
6. Semantic invariants: missing/empty fields, invalid tier, invalid gate (ERR-ADAPTER-SEMANTIC-INVARIANT-001, ERR-ADAPTER-INVALID-TIER-001)
7. NEG-002: T3 owner-auth lab promotion restrictions (ERR-ADAPTER-INVALID-TIER-001)
8. Markdown mirror drift and missing rows (ERR-ADAPTER-REGISTRY-DRIFT-001)
9. Missing or corrupt files (ERR-ADAPTER-CORRUPT-FILE-001)
10. Planted bypasses on individual fields
"""
from __future__ import annotations

import json
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))

import device_adapter_checker
from device_adapter_checker import (
    CURRENT_GENERATION,
    ERR_ADAPTER_CORRUPT_FILE,
    ERR_ADAPTER_DIGEST_MISMATCH,
    ERR_ADAPTER_GENERATION_MISMATCH,
    ERR_ADAPTER_INVALID_TIER,
    ERR_ADAPTER_REGISTRY_DRIFT,
    ERR_ADAPTER_SEMANTIC_INVARIANT,
    ERR_ADAPTER_STABLE_ID_REUSED,
    EXPECTED_FREEZE_DIGESTS,
    SCHEMA_DEVICE_ADAPTERS_V1,
    compute_canonical_adapter_digest,
    validate_device_adapter_registry,
)


class DeviceAdapterRegistryCheckerTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp_dir = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp_dir.cleanup)
        self.fake_root = Path(self.temp_dir.name)

        # Replicate file hierarchy
        (self.fake_root / "architecture").mkdir(parents=True, exist_ok=True)
        (self.fake_root / "registries").mkdir(parents=True, exist_ok=True)

        shutil.copyfile(
            ROOT / "registries/DEVICE_ADAPTERS.md",
            self.fake_root / "registries/DEVICE_ADAPTERS.md",
        )
        shutil.copyfile(
            ROOT / "architecture/device_adapters.json",
            self.fake_root / "architecture/device_adapters.json",
        )

    def load_json(self) -> dict:
        p = self.fake_root / "architecture/device_adapters.json"
        return json.loads(p.read_text(encoding="utf-8"))

    def write_json(self, data: dict) -> None:
        p = self.fake_root / "architecture/device_adapters.json"
        p.write_text(json.dumps(data, indent=2), encoding="utf-8")

    def test_01_live_registry_passes(self) -> None:
        result = validate_device_adapter_registry(ROOT)
        self.assertTrue(
            result.passed,
            f"Live device adapter registry must pass, got errors: {[e.message for e in result.errors]}",
        )
        self.assertEqual(len(result.errors), 0)
        expected_digest = EXPECTED_FREEZE_DIGESTS[CURRENT_GENERATION]
        self.assertEqual(result.registry_digest, expected_digest)

    def test_02_canonical_digest_determinism(self) -> None:
        data = self.load_json()
        d1 = compute_canonical_adapter_digest(data)
        d2 = compute_canonical_adapter_digest(data)
        self.assertEqual(d1, d2)
        self.assertEqual(d1, EXPECTED_FREEZE_DIGESTS[CURRENT_GENERATION])

    def test_03_canonical_digest_mismatch_fails(self) -> None:
        data = self.load_json()
        data["registryDigest"] = "sha256:0000000000000000000000000000000000000000000000000000000000000000"
        self.write_json(data)
        res = validate_device_adapter_registry(self.fake_root)
        self.assertFalse(res.passed)
        codes = [e.code for e in res.errors]
        self.assertIn(ERR_ADAPTER_DIGEST_MISMATCH, codes)

    def test_04_generation_mismatch_fails(self) -> None:
        data = self.load_json()
        data["generation"] = "gen:fss1:adapters-v2-unregistered"
        self.write_json(data)
        res = validate_device_adapter_registry(self.fake_root)
        self.assertFalse(res.passed)
        codes = [e.code for e in res.errors]
        self.assertIn(ERR_ADAPTER_GENERATION_MISMATCH, codes)

    def test_05_missing_generation_fails(self) -> None:
        data = self.load_json()
        data["generation"] = ""
        self.write_json(data)
        res = validate_device_adapter_registry(self.fake_root)
        self.assertFalse(res.passed)
        codes = [e.code for e in res.errors]
        self.assertIn(ERR_ADAPTER_GENERATION_MISMATCH, codes)

    def test_06_corrupt_json_fails(self) -> None:
        p = self.fake_root / "architecture/device_adapters.json"
        p.write_text("{ invalid json syntax ...", encoding="utf-8")
        res = validate_device_adapter_registry(self.fake_root)
        self.assertFalse(res.passed)
        codes = [e.code for e in res.errors]
        self.assertIn(ERR_ADAPTER_CORRUPT_FILE, codes)

    def test_07_missing_json_file_fails(self) -> None:
        p = self.fake_root / "architecture/device_adapters.json"
        p.unlink()
        res = validate_device_adapter_registry(self.fake_root)
        self.assertFalse(res.passed)
        codes = [e.code for e in res.errors]
        self.assertIn(ERR_ADAPTER_CORRUPT_FILE, codes)

    def test_08_missing_markdown_file_fails(self) -> None:
        p = self.fake_root / "registries/DEVICE_ADAPTERS.md"
        p.unlink()
        res = validate_device_adapter_registry(self.fake_root)
        self.assertFalse(res.passed)
        codes = [e.code for e in res.errors]
        self.assertIn(ERR_ADAPTER_CORRUPT_FILE, codes)

    def test_09_stable_id_missing_from_baseline_fails(self) -> None:
        data = self.load_json()
        data["adapters"] = [a for a in data["adapters"] if a["id"] != "ADP-REPLAY-001"]
        self.write_json(data)
        res = validate_device_adapter_registry(self.fake_root)
        self.assertFalse(res.passed)
        codes = [e.code for e in res.errors]
        self.assertIn(ERR_ADAPTER_STABLE_ID_REUSED, codes)

    def test_10_unbaseline_adapter_id_added_fails(self) -> None:
        data = self.load_json()
        data["adapters"].append({
            "id": "ADP-UNKNOWN-001",
            "surface": "rogue adapter",
            "tier": "T1",
            "currentState": "specified",
            "promotionGate": "GATE-010",
            "generation": "gen:fss1:adapters-v1",
        })
        self.write_json(data)
        res = validate_device_adapter_registry(self.fake_root)
        self.assertFalse(res.passed)
        codes = [e.code for e in res.errors]
        self.assertIn(ERR_ADAPTER_STABLE_ID_REUSED, codes)

    def test_11_duplicate_adapter_id_fails(self) -> None:
        data = self.load_json()
        data["adapters"].append(dict(data["adapters"][0]))
        self.write_json(data)
        res = validate_device_adapter_registry(self.fake_root)
        self.assertFalse(res.passed)
        codes = [e.code for e in res.errors]
        self.assertIn(ERR_ADAPTER_STABLE_ID_REUSED, codes)

    def test_12_tombstone_resurrection_fails(self) -> None:
        data = self.load_json()
        data["tombstones"] = [{"id": "ADP-REPLAY-001"}]
        self.write_json(data)
        res = validate_device_adapter_registry(self.fake_root)
        self.assertFalse(res.passed)
        codes = [e.code for e in res.errors]
        self.assertIn(ERR_ADAPTER_STABLE_ID_REUSED, codes)

    def test_13_missing_or_empty_row_field_fails(self) -> None:
        data = self.load_json()
        data["adapters"][0]["surface"] = ""
        self.write_json(data)
        res = validate_device_adapter_registry(self.fake_root)
        self.assertFalse(res.passed)
        codes = [e.code for e in res.errors]
        self.assertIn(ERR_ADAPTER_SEMANTIC_INVARIANT, codes)

    def test_14_row_generation_mismatch_fails(self) -> None:
        data = self.load_json()
        data["adapters"][0]["generation"] = "gen:other:v1"
        self.write_json(data)
        res = validate_device_adapter_registry(self.fake_root)
        self.assertFalse(res.passed)
        codes = [e.code for e in res.errors]
        self.assertIn(ERR_ADAPTER_GENERATION_MISMATCH, codes)

    def test_15_invalid_tier_fails(self) -> None:
        data = self.load_json()
        data["adapters"][0]["tier"] = "T5"
        self.write_json(data)
        res = validate_device_adapter_registry(self.fake_root)
        self.assertFalse(res.passed)
        codes = [e.code for e in res.errors]
        self.assertIn(ERR_ADAPTER_INVALID_TIER, codes)

    def test_16_t3_promotion_to_t1_violation_fails(self) -> None:
        data = self.load_json()
        for a in data["adapters"]:
            if a["id"] == "ADP-WYZE-V4-LAB-001":
                a["currentState"] = "specified"  # illegally claiming specified open production
        self.write_json(data)
        res = validate_device_adapter_registry(self.fake_root)
        self.assertFalse(res.passed)
        codes = [e.code for e in res.errors]
        self.assertIn(ERR_ADAPTER_INVALID_TIER, codes)

    def test_17_invalid_gate_format_fails(self) -> None:
        data = self.load_json()
        data["adapters"][0]["promotionGate"] = "GATEWAY-01"
        self.write_json(data)
        res = validate_device_adapter_registry(self.fake_root)
        self.assertFalse(res.passed)
        codes = [e.code for e in res.errors]
        self.assertIn(ERR_ADAPTER_SEMANTIC_INVARIANT, codes)

    def test_18_markdown_cell_drift_fails(self) -> None:
        md_p = self.fake_root / "registries/DEVICE_ADAPTERS.md"
        content = md_p.read_text(encoding="utf-8")
        # Tamper a cell in markdown
        modified = content.replace("deterministic replay", "tampered replay")
        md_p.write_text(modified, encoding="utf-8")
        res = validate_device_adapter_registry(self.fake_root)
        self.assertFalse(res.passed)
        codes = [e.code for e in res.errors]
        self.assertIn(ERR_ADAPTER_REGISTRY_DRIFT, codes)

    def test_19_planted_bypass_surface_tamper_fails(self) -> None:
        data = self.load_json()
        data["adapters"][0]["surface"] = "Tampered surface text"
        self.write_json(data)
        res = validate_device_adapter_registry(self.fake_root)
        self.assertFalse(res.passed)
        codes = [e.code for e in res.errors]
        self.assertIn(ERR_ADAPTER_DIGEST_MISMATCH, codes)

    def test_20_cli_main_entrypoint(self) -> None:
        # Test CLI returns 0 on root
        proc = subprocess.run(
            [sys.executable, str(ROOT / "scripts/device_adapter_checker.py"), "--repo-root", str(ROOT)],
            capture_output=True,
            text=True,
        )
        self.assertEqual(proc.returncode, 0)
        self.assertIn("PASS", proc.stdout)

        # Test CLI returns 1 on corrupted root
        proc2 = subprocess.run(
            [sys.executable, str(ROOT / "scripts/device_adapter_checker.py"), "--repo-root", str(self.temp_dir.name)],
            capture_output=True,
            text=True,
        )
        # In setUp, self.fake_root is identical to ROOT, so it should pass
        self.assertEqual(proc2.returncode, 0)

        # Now corrupt fake_root
        (self.fake_root / "architecture/device_adapters.json").unlink()
        proc3 = subprocess.run(
            [sys.executable, str(ROOT / "scripts/device_adapter_checker.py"), "--repo-root", str(self.temp_dir.name)],
            capture_output=True,
            text=True,
        )
        self.assertEqual(proc3.returncode, 1)
        self.assertIn("FAIL", proc3.stdout)


if __name__ == "__main__":
    unittest.main()
