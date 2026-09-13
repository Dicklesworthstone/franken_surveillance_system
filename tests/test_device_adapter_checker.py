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
        self.assertEqual(set(codes), {ERR_ADAPTER_DIGEST_MISMATCH})

    def test_04_generation_mismatch_fails(self) -> None:
        data = self.load_json()
        data["generation"] = "gen:fss1:adapters-v2-unregistered"
        self.write_json(data)
        res = validate_device_adapter_registry(self.fake_root)
        self.assertFalse(res.passed)
        codes = [e.code for e in res.errors]
        self.assertEqual(set(codes), {ERR_ADAPTER_GENERATION_MISMATCH, ERR_ADAPTER_DIGEST_MISMATCH})

    def test_05_missing_generation_fails(self) -> None:
        data = self.load_json()
        data["generation"] = ""
        self.write_json(data)
        res = validate_device_adapter_registry(self.fake_root)
        self.assertFalse(res.passed)
        codes = [e.code for e in res.errors]
        self.assertEqual(set(codes), {ERR_ADAPTER_CORRUPT_FILE, ERR_ADAPTER_GENERATION_MISMATCH})

    def test_06_corrupt_json_fails(self) -> None:
        p = self.fake_root / "architecture/device_adapters.json"
        p.write_text("{ invalid json syntax ...", encoding="utf-8")
        res = validate_device_adapter_registry(self.fake_root)
        self.assertFalse(res.passed)
        codes = [e.code for e in res.errors]
        self.assertEqual(set(codes), {ERR_ADAPTER_CORRUPT_FILE})

    def test_07_missing_json_file_fails(self) -> None:
        p = self.fake_root / "architecture/device_adapters.json"
        p.unlink()
        res = validate_device_adapter_registry(self.fake_root)
        self.assertFalse(res.passed)
        codes = [e.code for e in res.errors]
        self.assertEqual(set(codes), {ERR_ADAPTER_CORRUPT_FILE})

    def test_08_missing_markdown_file_fails(self) -> None:
        p = self.fake_root / "registries/DEVICE_ADAPTERS.md"
        p.unlink()
        res = validate_device_adapter_registry(self.fake_root)
        self.assertFalse(res.passed)
        codes = [e.code for e in res.errors]
        self.assertEqual(set(codes), {ERR_ADAPTER_CORRUPT_FILE})

    def test_09_stable_id_missing_from_baseline_fails(self) -> None:
        data = self.load_json()
        data["adapters"] = [a for a in data["adapters"] if a["id"] != "ADP-REPLAY-001"]
        self.write_json(data)
        res = validate_device_adapter_registry(self.fake_root)
        self.assertFalse(res.passed)
        codes = [e.code for e in res.errors]
        self.assertEqual(set(codes), {ERR_ADAPTER_STABLE_ID_REUSED, ERR_ADAPTER_DIGEST_MISMATCH, ERR_ADAPTER_REGISTRY_DRIFT})

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
        self.assertEqual(set(codes), {ERR_ADAPTER_STABLE_ID_REUSED, ERR_ADAPTER_DIGEST_MISMATCH, ERR_ADAPTER_REGISTRY_DRIFT})

    def test_11_duplicate_adapter_id_fails(self) -> None:
        data = self.load_json()
        data["adapters"].append(dict(data["adapters"][0]))
        self.write_json(data)
        res = validate_device_adapter_registry(self.fake_root)
        self.assertFalse(res.passed)
        codes = [e.code for e in res.errors]
        self.assertEqual(set(codes), {ERR_ADAPTER_STABLE_ID_REUSED, ERR_ADAPTER_CORRUPT_FILE})

    def test_12_tombstone_resurrection_fails(self) -> None:
        data = self.load_json()
        data["tombstones"] = [{"id": "ADP-REPLAY-001"}]
        self.write_json(data)
        res = validate_device_adapter_registry(self.fake_root)
        self.assertFalse(res.passed)
        codes = [e.code for e in res.errors]
        self.assertEqual(set(codes), {ERR_ADAPTER_STABLE_ID_REUSED, ERR_ADAPTER_CORRUPT_FILE})

    def test_13_missing_or_empty_row_field_fails(self) -> None:
        data = self.load_json()
        data["adapters"][0]["surface"] = ""
        self.write_json(data)
        res = validate_device_adapter_registry(self.fake_root)
        self.assertFalse(res.passed)
        codes = [e.code for e in res.errors]
        self.assertEqual(set(codes), {ERR_ADAPTER_SEMANTIC_INVARIANT, ERR_ADAPTER_DIGEST_MISMATCH, ERR_ADAPTER_REGISTRY_DRIFT})

    def test_14_row_generation_mismatch_fails(self) -> None:
        data = self.load_json()
        data["adapters"][0]["generation"] = "gen:other:v1"
        self.write_json(data)
        res = validate_device_adapter_registry(self.fake_root)
        self.assertFalse(res.passed)
        codes = [e.code for e in res.errors]
        self.assertEqual(set(codes), {ERR_ADAPTER_GENERATION_MISMATCH, ERR_ADAPTER_SEMANTIC_INVARIANT, ERR_ADAPTER_DIGEST_MISMATCH})

    def test_15_invalid_tier_fails(self) -> None:
        data = self.load_json()
        data["adapters"][0]["tier"] = "T5"
        self.write_json(data)
        res = validate_device_adapter_registry(self.fake_root)
        self.assertFalse(res.passed)
        codes = [e.code for e in res.errors]
        self.assertEqual(set(codes), {ERR_ADAPTER_INVALID_TIER, ERR_ADAPTER_SEMANTIC_INVARIANT, ERR_ADAPTER_DIGEST_MISMATCH, ERR_ADAPTER_REGISTRY_DRIFT})

    def test_16_t3_promotion_to_t1_violation_fails(self) -> None:
        data = self.load_json()
        for a in data["adapters"]:
            if a["id"] == "ADP-WYZE-V4-LAB-001":
                a["currentState"] = "specified"  # illegally claiming specified open production
        self.write_json(data)
        res = validate_device_adapter_registry(self.fake_root)
        self.assertFalse(res.passed)
        codes = [e.code for e in res.errors]
        self.assertEqual(set(codes), {ERR_ADAPTER_INVALID_TIER, ERR_ADAPTER_SEMANTIC_INVARIANT, ERR_ADAPTER_DIGEST_MISMATCH, ERR_ADAPTER_REGISTRY_DRIFT})

    def test_17_invalid_gate_format_fails(self) -> None:
        data = self.load_json()
        data["adapters"][0]["promotionGate"] = "GATEWAY-01"
        self.write_json(data)
        res = validate_device_adapter_registry(self.fake_root)
        self.assertFalse(res.passed)
        codes = [e.code for e in res.errors]
        self.assertEqual(set(codes), {ERR_ADAPTER_SEMANTIC_INVARIANT, ERR_ADAPTER_DIGEST_MISMATCH, ERR_ADAPTER_REGISTRY_DRIFT})

    def test_18_markdown_cell_drift_fails(self) -> None:
        md_p = self.fake_root / "registries/DEVICE_ADAPTERS.md"
        content = md_p.read_text(encoding="utf-8")
        # Tamper a cell in markdown
        modified = content.replace("deterministic replay", "tampered replay")
        md_p.write_text(modified, encoding="utf-8")
        res = validate_device_adapter_registry(self.fake_root)
        self.assertFalse(res.passed)
        codes = [e.code for e in res.errors]
        self.assertEqual(set(codes), {ERR_ADAPTER_REGISTRY_DRIFT})

    def test_19_planted_bypass_surface_tamper_fails(self) -> None:
        data = self.load_json()
        data["adapters"][0]["surface"] = "Tampered surface text"
        self.write_json(data)
        res = validate_device_adapter_registry(self.fake_root)
        self.assertFalse(res.passed)
        codes = [e.code for e in res.errors]
        self.assertEqual(set(codes), {ERR_ADAPTER_DIGEST_MISMATCH, ERR_ADAPTER_REGISTRY_DRIFT, ERR_ADAPTER_SEMANTIC_INVARIANT})

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

    def test_21_mutant_p1_killing_pinned_digest_mismatch(self) -> None:
        """Kills mutant P1: pinned-digest check disabled."""
        data = self.load_json()
        data["adapters"][0]["surface"] = "New Surface Valid Hash"
        computed = compute_canonical_adapter_digest(data)
        data["registryDigest"] = computed
        self.write_json(data)

        res = validate_device_adapter_registry(self.fake_root)
        self.assertFalse(res.passed)
        codes = [e.code for e in res.errors]
        self.assertIn(ERR_ADAPTER_DIGEST_MISMATCH, codes)
        self.assertTrue(any("pinned baseline freeze digest" in e.message for e in res.errors))

    def test_22_mutant_p3_killing_generation_equals_current(self) -> None:
        """Kills mutant P3: generation == CURRENT_GENERATION check disabled."""
        data = self.load_json()
        data["generation"] = "gen:fss1:adapters-v2-registered"
        self.write_json(data)
        res = validate_device_adapter_registry(self.fake_root)
        self.assertFalse(res.passed)
        codes = [e.code for e in res.errors]
        self.assertIn(ERR_ADAPTER_GENERATION_MISMATCH, codes)
        self.assertTrue(any("expected 'gen:fss1:adapters-v1'" in e.message for e in res.errors))

    def test_23_mutant_p4_killing_baseline_field_check(self) -> None:
        """Kills mutant P4: baseline field invariant check disabled."""
        data = self.load_json()
        data["adapters"][0]["tier"] = "T1"  # AOSU baseline is T3
        self.write_json(data)
        res = validate_device_adapter_registry(self.fake_root)
        self.assertFalse(res.passed)
        self.assertTrue(any("Baseline row field 'tier' modified without generation bump" in e.message for e in res.errors))

    def test_24_mutant_p11_killing_markdown_extra_row(self) -> None:
        """Kills mutant P11: markdown extra row check disabled."""
        md_p = self.fake_root / "registries/DEVICE_ADAPTERS.md"
        content = md_p.read_text(encoding="utf-8")
        extra_row = "| `ADP-EXTRA-001` | extra surface | T1 | specified | `GATE-010` |\n"
        md_p.write_text(content + extra_row, encoding="utf-8")
        res = validate_device_adapter_registry(self.fake_root)
        self.assertFalse(res.passed)
        codes = [e.code for e in res.errors]
        self.assertEqual(set(codes), {ERR_ADAPTER_REGISTRY_DRIFT})
        self.assertTrue(any("Markdown contains adapter 'ADP-EXTRA-001' not in active JSON adapters" in e.message for e in res.errors))

    def test_25_mutant_p13_killing_gate_format(self) -> None:
        """Kills mutant P13: gate format regex check disabled."""
        data = self.load_json()
        data["adapters"][0]["promotionGate"] = "GATEWAY-01"
        self.write_json(data)
        res = validate_device_adapter_registry(self.fake_root)
        self.assertFalse(res.passed)
        self.assertTrue(any("invalid promotion gate format" in e.message for e in res.errors))

    def test_26_mutant_p14_killing_empty_field(self) -> None:
        """Kills mutant P14: empty field validation disabled."""
        data = self.load_json()
        data["adapters"][0]["surface"] = "   "
        self.write_json(data)
        res = validate_device_adapter_registry(self.fake_root)
        self.assertFalse(res.passed)
        self.assertTrue(any("missing or empty field 'surface'" in e.message for e in res.errors))

    def test_27_unknown_top_level_key_rejected(self) -> None:
        """Rejects unknown top-level keys in JSON."""
        data = self.load_json()
        data["extraTopLevel"] = {"credentialMethod": "basic_auth", "discovery": "subnet-scan"}
        self.write_json(data)
        res = validate_device_adapter_registry(self.fake_root)
        self.assertFalse(res.passed)
        self.assertTrue(any("Unknown top-level key: 'extraTopLevel'" in e.message for e in res.errors))

    def test_28_unknown_row_key_rejected(self) -> None:
        """Rejects unknown row keys in adapters."""
        data = self.load_json()
        data["adapters"][0]["bogusKey"] = 1
        self.write_json(data)
        res = validate_device_adapter_registry(self.fake_root)
        self.assertFalse(res.passed)
        self.assertTrue(any("Unknown row key in adapter" in e.message for e in res.errors))

    def test_29_markdown_duplicate_row_first_fails(self) -> None:
        """Rejects duplicate adapter rows in markdown even when placed first."""
        md_p = self.fake_root / "registries/DEVICE_ADAPTERS.md"
        lines = md_p.read_text(encoding="utf-8").splitlines()
        dup_row = "| `ADP-REPLAY-001` | tampered replay | T0 | specified | `GATE-010` |"
        new_lines = []
        for line in lines:
            if line.startswith("| `ADP-REPLAY-001`"):
                new_lines.append(dup_row)
            new_lines.append(line)
        md_p.write_text("\n".join(new_lines) + "\n", encoding="utf-8")
        res = validate_device_adapter_registry(self.fake_root)
        self.assertFalse(res.passed)
        codes = [e.code for e in res.errors]
        self.assertEqual(set(codes), {ERR_ADAPTER_REGISTRY_DRIFT})
        self.assertTrue(any("Duplicate adapter ID in markdown mirror: 'ADP-REPLAY-001'" in e.message for e in res.errors))

    def test_30_markdown_malformed_columns_fails(self) -> None:
        """Rejects short rows (fewer than 5 columns) and extra columns in markdown table."""
        md_p = self.fake_root / "registries/DEVICE_ADAPTERS.md"
        content = md_p.read_text(encoding="utf-8")
        # Short row
        short_md = content + "\n| `ADP-BADSHORT-001` | short | T1 | `GATE-010` |\n"
        md_p.write_text(short_md, encoding="utf-8")
        res = validate_device_adapter_registry(self.fake_root)
        self.assertFalse(res.passed)
        codes = [e.code for e in res.errors]
        self.assertEqual(set(codes), {ERR_ADAPTER_REGISTRY_DRIFT})
        self.assertTrue(any("invalid column count 4" in e.message for e in res.errors))

        # Extra column
        extra_md = content + "\n| `ADP-BADEXTRA-001` | extra | T1 | specified | `GATE-010` | surplus |\n"
        md_p.write_text(extra_md, encoding="utf-8")
        res2 = validate_device_adapter_registry(self.fake_root)
        self.assertFalse(res2.passed)
        codes2 = [e.code for e in res2.errors]
        self.assertEqual(set(codes2), {ERR_ADAPTER_REGISTRY_DRIFT})
        self.assertTrue(any("invalid column count 6" in e.message for e in res2.errors))

    def test_31_string_list_ordering_sensitivity(self) -> None:
        """Verifies that list ordering is preserved and visible to the digest."""
        payload1 = {
            "schema": "fss.device_adapters.v1",
            "asOf": "2026-08-31",
            "semanticProtocol": "fss/1",
            "generation": "gen:fss1:adapters-v1",
            "adapters": [
                {
                    "id": "ADP-AOSU-P1MAX-LAB-001",
                    "surface": "AOSU P1 Max owner-auth lab",
                    "tier": "T3",
                    "currentState": "research target",
                    "promotionGate": "GATE-090",
                    "generation": "gen:fss1:adapters-v1",
                }
            ],
            "tombstones": [],
        }
        d1 = compute_canonical_adapter_digest(payload1)
        payload2 = dict(payload1)
        payload2["adapters"] = list(payload1["adapters"])
        payload2["adapters"].append({
            "id": "ADP-FILE-001",
            "surface": "bounded media import",
            "tier": "T0/T4",
            "currentState": "specified",
            "promotionGate": "GATE-010",
            "generation": "gen:fss1:adapters-v1",
        })
        d2 = compute_canonical_adapter_digest(payload2)
        self.assertNotEqual(d1, d2)

    def test_32_markdown_duplicate_row_with_dashes_fails(self) -> None:
        """Kills mutant N4: duplicate row containing '---' is not skipped and fails closed."""
        md_p = self.fake_root / "registries/DEVICE_ADAPTERS.md"
        content = md_p.read_text(encoding="utf-8")
        dup_row = "| `ADP-REPLAY-001` | replay---variant | T0 | specified | `GATE-010` |\n"
        md_p.write_text(content + dup_row, encoding="utf-8")
        res = validate_device_adapter_registry(self.fake_root)
        self.assertFalse(res.passed)
        codes = [e.code for e in res.errors]
        self.assertEqual(set(codes), {ERR_ADAPTER_REGISTRY_DRIFT})
        self.assertTrue(any("Duplicate adapter ID in markdown mirror: 'ADP-REPLAY-001'" in e.message for e in res.errors))

    def test_33_markdown_rogue_row_with_dashes_fails(self) -> None:
        """Kills mutant N4: rogue row containing '---' is not skipped and fails closed."""
        md_p = self.fake_root / "registries/DEVICE_ADAPTERS.md"
        content = md_p.read_text(encoding="utf-8")
        rogue_row = "| `ADP-ROGUE-001` | rogue---adapter | T0 | specified | `GATE-010` |\n"
        md_p.write_text(content + rogue_row, encoding="utf-8")
        res = validate_device_adapter_registry(self.fake_root)
        self.assertFalse(res.passed)
        codes = [e.code for e in res.errors]
        self.assertEqual(set(codes), {ERR_ADAPTER_REGISTRY_DRIFT})
        self.assertTrue(any("Markdown contains adapter 'ADP-ROGUE-001' not in active JSON adapters" in e.message for e in res.errors))

    def test_34_markdown_rogue_row_with_id_and_surface_in_data_fails(self) -> None:
        """Kills mutant N4: data row containing 'ID' and 'Surface' is not skipped and fails closed."""
        md_p = self.fake_root / "registries/DEVICE_ADAPTERS.md"
        content = md_p.read_text(encoding="utf-8")
        rogue_row = "| `ADP-ROGUE-002` | Camera ID Surface Mapper | T0 | specified | `GATE-010` |\n"
        md_p.write_text(content + rogue_row, encoding="utf-8")
        res = validate_device_adapter_registry(self.fake_root)
        self.assertFalse(res.passed)
        codes = [e.code for e in res.errors]
        self.assertEqual(set(codes), {ERR_ADAPTER_REGISTRY_DRIFT})
        self.assertTrue(any("Markdown contains adapter 'ADP-ROGUE-002' not in active JSON adapters" in e.message for e in res.errors))

    def test_35_markdown_rogue_row_before_table_fails(self) -> None:
        """Rejects rogue pipe row before table header."""
        md_p = self.fake_root / "registries/DEVICE_ADAPTERS.md"
        content = md_p.read_text(encoding="utf-8")
        rogue_md = "| rogue row before table |\n" + content
        md_p.write_text(rogue_md, encoding="utf-8")
        res = validate_device_adapter_registry(self.fake_root)
        self.assertFalse(res.passed)
        codes = [e.code for e in res.errors]
        self.assertEqual(set(codes), {ERR_ADAPTER_REGISTRY_DRIFT})
        self.assertTrue(any("before device adapter table header" in e.message for e in res.errors))

    def test_36_markdown_rogue_row_after_table_fails(self) -> None:
        """Rejects rogue pipe row after table ends."""
        md_p = self.fake_root / "registries/DEVICE_ADAPTERS.md"
        content = md_p.read_text(encoding="utf-8")
        rogue_md = content + "\n## Trailing Section\n\n| rogue row after table |\n"
        md_p.write_text(rogue_md, encoding="utf-8")
        res = validate_device_adapter_registry(self.fake_root)
        self.assertFalse(res.passed)
        codes = [e.code for e in res.errors]
        self.assertEqual(set(codes), {ERR_ADAPTER_REGISTRY_DRIFT})
        self.assertTrue(any("after table end" in e.message for e in res.errors))


if __name__ == "__main__":
    unittest.main()
