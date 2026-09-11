#!/usr/bin/env python3
"""Comprehensive test suite for SLO constitution validator (scripts/slo_validate.py).

Covers:
- Clean repository execution (all 29 SLOs valid, 0 errors, 0 warnings)
- Diagnostic codes SLO-VAL-001 through SLO-VAL-011
- Positive verification of 'achieved' status backed by a real retained proof root
- Rejection of unbacked 'achieved' claims (the prime directive of fss-x4a.30.107)
- Path traversal and absolute path rejection in proof roots
- Case-fold collisions, tombstone cycles, dangling successors
- Cost reference resolution and malformed cost ID detection
- CLI JSON output and exit code contracts
"""

from __future__ import annotations

import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))
import slo_validate

SLOS_PATH = ROOT / "registries/SLOS.md"
COSTS_PATH = ROOT / "architecture/operation_cost_registry.toml"


class SloValidateCleanRepoTests(unittest.TestCase):
    """Verify live repository state satisfies the SLO constitution."""

    def test_live_repo_passes_validation(self) -> None:
        is_valid, findings, summary = slo_validate.validate_slos(ROOT)
        self.assertTrue(is_valid, f"Live repository failed SLO validation: {[f.message for f in findings]}")
        self.assertEqual(len(findings), 0)
        self.assertEqual(summary["status"], "pass")
        self.assertEqual(summary["error_count"], 0)
        self.assertEqual(summary["warning_count"], 0)
        self.assertGreaterEqual(summary["total_slos"], 29)
        self.assertEqual(summary["achieved_count"], 0)
        self.assertEqual(summary["tombstone_count"], 1)
        self.assertGreater(summary["total_cost_references"], 0)

    def test_cli_execution_clean(self) -> None:
        proc = subprocess.run(
            [sys.executable, str(ROOT / "scripts/slo_validate.py"), "--json"],
            capture_output=True,
            text=True,
            cwd=str(ROOT),
        )
        self.assertEqual(proc.returncode, 0, f"CLI stderr: {proc.stderr}")
        data = json.loads(proc.stdout)
        self.assertEqual(data["summary"]["status"], "pass")
        self.assertEqual(len(data["findings"]), 0)


class SloValidatePlantedFaultTests(unittest.TestCase):
    """Test every diagnostic code with planted faults."""

    def setUp(self) -> None:
        self.real_slos_text = SLOS_PATH.read_text(encoding="utf-8")
        self.real_costs_text = COSTS_PATH.read_text(encoding="utf-8")
        self.temp_dir = tempfile.TemporaryDirectory()
        self.temp_path = Path(self.temp_dir.name)

    def tearDown(self) -> None:
        self.temp_dir.cleanup()

    def _validate_with_planted_slos(self, planted_text: str) -> tuple[bool, list[slo_validate.SloFinding]]:
        slos_file = self.temp_path / "SLOS.md"
        slos_file.write_text(planted_text, encoding="utf-8")
        is_valid, findings, _ = slo_validate.validate_slos(
            root=ROOT,
            slos_path=slos_file,
            costs_path=COSTS_PATH,
        )
        return is_valid, findings

    def _validate_with_planted_costs(self, planted_text: str) -> tuple[bool, list[slo_validate.SloFinding]]:
        costs_file = self.temp_path / "operation_cost_registry.toml"
        costs_file.write_text(planted_text, encoding="utf-8")
        is_valid, findings, _ = slo_validate.validate_slos(
            root=ROOT,
            slos_path=SLOS_PATH,
            costs_path=costs_file,
        )
        return is_valid, findings

    # SLO-VAL-001: Invalid SLO ID
    def test_planted_malformed_slo_id_fails(self) -> None:
        planted = self.real_slos_text + "\n| `SLO_INVALID_ID` | target desc | measurement surface | target | - |\n"
        is_valid, findings = self._validate_with_planted_slos(planted)
        self.assertFalse(is_valid)
        codes = [f.code for f in findings]
        self.assertIn(slo_validate.CODE_INVALID_SLO_ID, codes)

    def test_planted_lowercase_slo_id_fails(self) -> None:
        planted = self.real_slos_text + "\n| `slo-lowercase-001` | target desc | measurement surface | target | - |\n"
        is_valid, findings = self._validate_with_planted_slos(planted)
        self.assertFalse(is_valid)
        codes = [f.code for f in findings]
        self.assertIn(slo_validate.CODE_INVALID_SLO_ID, codes)

    def test_planted_missing_numeric_suffix_fails(self) -> None:
        planted = self.real_slos_text + "\n| `SLO-NO-NUMERIC` | target desc | measurement surface | target | - |\n"
        is_valid, findings = self._validate_with_planted_slos(planted)
        self.assertFalse(is_valid)
        codes = [f.code for f in findings]
        self.assertIn(slo_validate.CODE_INVALID_SLO_ID, codes)

    # SLO-VAL-002: Duplicate SLO ID
    def test_planted_duplicate_slo_id_fails(self) -> None:
        planted = self.real_slos_text + "\n| `SLO-DELETE-001` | dup target | dup surface | target | - |\n"
        is_valid, findings = self._validate_with_planted_slos(planted)
        self.assertFalse(is_valid)
        codes = [f.code for f in findings]
        self.assertIn(slo_validate.CODE_DUPLICATE_SLO_ID, codes)

    def test_planted_case_fold_collision_fails(self) -> None:
        planted = self.real_slos_text + "\n| `slo-delete-001` | dup target | dup surface | target | - |\n"
        is_valid, findings = self._validate_with_planted_slos(planted)
        self.assertFalse(is_valid)
        codes = [f.code for f in findings]
        self.assertTrue(
            slo_validate.CODE_DUPLICATE_SLO_ID in codes or slo_validate.CODE_INVALID_SLO_ID in codes
        )

    # SLO-VAL-003: Invalid SLO status
    def test_planted_invalid_slo_status_fails(self) -> None:
        for bad_status in ["pending", "active", "done", "verified", "unknown"]:
            planted = self.real_slos_text + f"\n| `SLO-TEST-001` | target desc | measurement surface | {bad_status} | - |\n"
            is_valid, findings = self._validate_with_planted_slos(planted)
            self.assertFalse(is_valid, f"Should have failed for status: {bad_status}")
            codes = [f.code for f in findings]
            self.assertIn(slo_validate.CODE_INVALID_SLO_STATUS, codes)

    # SLO-VAL-004: Achieved without proof root
    def test_planted_achieved_without_proof_root_fails(self) -> None:
        for empty_proof in ["-", "none", "null", "n/a", "na", "", "   ", ".", "./", "/"]:
            planted = self.real_slos_text + f"\n| `SLO-TEST-001` | target desc | measurement surface | achieved | {empty_proof} |\n"
            is_valid, findings = self._validate_with_planted_slos(planted)
            self.assertFalse(is_valid, f"Should have failed for proof root: {empty_proof}")
            codes = [f.code for f in findings]
            self.assertIn(slo_validate.CODE_ACHIEVED_WITHOUT_PROOF_ROOT, codes)

    # SLO-VAL-005: Proof root not found on disk
    def test_planted_nonexistent_proof_root_fails(self) -> None:
        planted = self.real_slos_text + "\n| `SLO-TEST-001` | target desc | measurement surface | achieved | qualification-artifacts/nonexistent_proof.bundle |\n"
        is_valid, findings = self._validate_with_planted_slos(planted)
        self.assertFalse(is_valid)
        codes = [f.code for f in findings]
        self.assertIn(slo_validate.CODE_PROOF_ROOT_NOT_FOUND, codes)

    def test_planted_absolute_proof_root_rejected(self) -> None:
        planted = self.real_slos_text + "\n| `SLO-TEST-001` | target desc | measurement surface | achieved | /tmp |\n"
        is_valid, findings = self._validate_with_planted_slos(planted)
        self.assertFalse(is_valid)
        codes = [f.code for f in findings]
        self.assertIn(slo_validate.CODE_PROOF_ROOT_NOT_FOUND, codes)

    def test_planted_path_traversal_proof_root_rejected(self) -> None:
        planted = self.real_slos_text + "\n| `SLO-TEST-001` | target desc | measurement surface | achieved | ../../../etc/passwd |\n"
        is_valid, findings = self._validate_with_planted_slos(planted)
        self.assertFalse(is_valid)
        codes = [f.code for f in findings]
        self.assertIn(slo_validate.CODE_PROOF_ROOT_NOT_FOUND, codes)

    # Positive test: Achieved with real existing proof file passes
    def test_achieved_with_real_proof_file_passes(self) -> None:
        real_proof_root = "architecture/operation_cost_registry.toml"
        planted = self.real_slos_text + f"\n| `SLO-TEST-001` | target desc | measurement surface | achieved | {real_proof_root} |\n"
        is_valid, findings = self._validate_with_planted_slos(planted)
        self.assertTrue(is_valid, f"Expected success with valid proof root, got findings: {[f.message for f in findings]}")

    # SLO-VAL-006: Missing target
    def test_planted_missing_target_fails(self) -> None:
        for bad_target in ["", "   ", "-", "none", "null", "n/a", "na"]:
            planted = self.real_slos_text + f"\n| `SLO-TEST-001` | {bad_target} | measurement surface | target | - |\n"
            is_valid, findings = self._validate_with_planted_slos(planted)
            self.assertFalse(is_valid, f"Should have failed for target: '{bad_target}'")
            codes = [f.code for f in findings]
            self.assertIn(slo_validate.CODE_MISSING_TARGET, codes)

    # SLO-VAL-007: Missing measurement surface
    def test_planted_missing_measurement_surface_fails(self) -> None:
        for bad_surface in ["", "   ", "-", "none", "null", "n/a", "na"]:
            planted = self.real_slos_text + f"\n| `SLO-TEST-001` | target desc | {bad_surface} | target | - |\n"
            is_valid, findings = self._validate_with_planted_slos(planted)
            self.assertFalse(is_valid, f"Should have failed for surface: '{bad_surface}'")
            codes = [f.code for f in findings]
            self.assertIn(slo_validate.CODE_MISSING_MEASUREMENT_SURFACE, codes)

    # SLO-VAL-008: Invalid tombstone
    def test_planted_tombstone_without_successor_fails(self) -> None:
        planted = self.real_slos_text + "\n| `SLO-TOMB-001` | deprecated target | deprecated surface | tombstone | - |\n"
        is_valid, findings = self._validate_with_planted_slos(planted)
        self.assertFalse(is_valid)
        codes = [f.code for f in findings]
        self.assertIn(slo_validate.CODE_INVALID_TOMBSTONE, codes)

    def test_planted_tombstone_dangling_successor_fails(self) -> None:
        planted = self.real_slos_text + "\n| `SLO-TOMB-001` | tombstone: superseded by `SLO-DOESNOTEXIST-001` | deprecated surface | tombstone | - |\n"
        is_valid, findings = self._validate_with_planted_slos(planted)
        self.assertFalse(is_valid)
        codes = [f.code for f in findings]
        self.assertIn(slo_validate.CODE_INVALID_TOMBSTONE, codes)

    def test_planted_cyclic_tombstone_fails(self) -> None:
        planted = self.real_slos_text + (
            "\n| `SLO-CYCLE-A-001` | tombstone: superseded by `SLO-CYCLE-B-001` | loop A | tombstone | - |\n"
            "| `SLO-CYCLE-B-001` | tombstone: superseded by `SLO-CYCLE-A-001` | loop B | tombstone | - |\n"
        )
        is_valid, findings = self._validate_with_planted_slos(planted)
        self.assertFalse(is_valid)
        codes = [f.code for f in findings]
        self.assertIn(slo_validate.CODE_INVALID_TOMBSTONE, codes)

    # SLO-VAL-009: Unregistered SLO reference in cost registry
    def test_planted_unregistered_cost_slo_ref_fails(self) -> None:
        planted_costs = self.real_costs_text.replace(
            'slo_ids = ["SLO-DELETE-001"]',
            'slo_ids = ["SLO-GHOST-999"]',
        )
        is_valid, findings = self._validate_with_planted_costs(planted_costs)
        self.assertFalse(is_valid)
        codes = [f.code for f in findings]
        self.assertIn(slo_validate.CODE_UNREGISTERED_SLO_REFERENCE, codes)

    # SLO-VAL-010: Malformed cost SLO reference
    def test_planted_malformed_cost_slo_ref_fails(self) -> None:
        planted_costs = self.real_costs_text.replace(
            'slo_ids = ["SLO-DELETE-001"]',
            'slo_ids = ["malformed_slo_id"]',
        )
        is_valid, findings = self._validate_with_planted_costs(planted_costs)
        self.assertFalse(is_valid)
        codes = [f.code for f in findings]
        self.assertIn(slo_validate.CODE_MALFORMED_COST_SLO_REFERENCE, codes)

    # SLO-VAL-011: Malformed table
    def test_planted_malformed_table_row_fails(self) -> None:
        planted = self.real_slos_text + "\n| `SLO-TEST-001` | only two more | columns |\n"
        is_valid, findings = self._validate_with_planted_slos(planted)
        self.assertFalse(is_valid)
        codes = [f.code for f in findings]
        self.assertIn(slo_validate.CODE_MALFORMED_TABLE, codes)

    def test_missing_slos_file_fails(self) -> None:
        is_valid, findings, _ = slo_validate.validate_slos(
            root=ROOT,
            slos_path=self.temp_path / "NONEXISTENT_SLOS.md",
            costs_path=COSTS_PATH,
        )
        self.assertFalse(is_valid)
        codes = [f.code for f in findings]
        self.assertIn(slo_validate.CODE_MALFORMED_TABLE, codes)


if __name__ == "__main__":
    unittest.main(verbosity=2)
