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
import math
import subprocess
import sys
import tempfile
import tomllib
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))
import slo_validate

SLOS_PATH = ROOT / "registries/SLOS.md"
COSTS_PATH = ROOT / "architecture/operation_cost_registry.toml"
COSTS_MD_PATH = ROOT / "registries/OPERATION_COSTS.md"


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

    def test_planted_temp_or_hidden_proof_root_rejected(self) -> None:
        """SLO validation must fail closed if an achieved SLO references a temporary or hidden receipt file."""
        with tempfile.TemporaryDirectory() as tmpdir:
            temp_root = Path(tmpdir)
            qual_dir = temp_root / "qualification-artifacts/local/run1"
            qual_dir.mkdir(parents=True, exist_ok=True)
            temp_receipt = qual_dir / ".qualification-receipt.json.tmp.12345"
            temp_receipt.write_text(json.dumps({
                "schema": "fss.release_qualification_receipt.v1",
                "receiptId": "local:policy:test1",
                "laneId": "QL-POLICY-001",
                "sourceCommit": "git:abc1234",
                "sourceTree": "git-tree:def5678",
                "siblingClosureDigest": "sha256:0000",
                "toolchain": "nightly",
                "hostIdentity": "host1",
                "target": "Linux",
                "features": [],
                "commands": [{"argv": ["test"], "status": "passed", "outputDigest": "sha256:00"}],
                "status": "passed",
            }), encoding="utf-8")

            planted = self.real_slos_text + f"\n| `SLO-TEST-001` | target desc | measurement surface | achieved | qualification-artifacts/local/run1/{temp_receipt.name} |\n"
            slos_file = self.temp_path / "SLOS.md"
            slos_file.write_text(planted, encoding="utf-8")
            is_valid, findings, _ = slo_validate.validate_slos(
                root=temp_root,
                slos_path=slos_file,
                costs_path=COSTS_PATH,
            )
            self.assertFalse(is_valid, "Referencing a temporary or hidden receipt must fail closed")
            codes = [f.code for f in findings]
            self.assertIn(slo_validate.CODE_ACHIEVED_WITHOUT_PROOF_ROOT, codes)

    # Positive test: Achieved with real existing proof file passes
    def test_achieved_with_real_proof_file_passes(self) -> None:
        proof_dir = ROOT / "qualification-artifacts"
        proof_dir.mkdir(parents=True, exist_ok=True)
        proof_file = proof_dir / "SLO-TEST-001-proof.receipt"
        receipt_data = {
            "schema": "fss.release_qualification_receipt.v1",
            "receiptId": "local:test:12345678",
            "laneId": "QL-POLICY-001",
            "sourceCommit": "sha256:0123456789abcdef",
            "sourceTree": "sha256:0123456789abcdef",
            "siblingClosureDigest": "sha256:0123456789abcdef",
            "cargoLockDigest": None,
            "toolchain": "nightly-2026-08-31",
            "hostIdentity": "sha256:0123456789abcdef",
            "target": "x86_64-unknown-linux-gnu",
            "features": [],
            "commands": [{"argv": ["test"], "status": "passed", "outputDigest": "sha256:0123456789abcdef"}],
            "artifactManifestDigest": None,
            "startedAt": {"earliestNs": 1000, "latestNs": 2000, "clockBasis": "host-realtime"},
            "finishedAt": {"earliestNs": 2000, "latestNs": 3000, "clockBasis": "host-realtime"},
            "status": "passed",
        }
        proof_file.write_text(json.dumps(receipt_data, indent=2) + "\n", encoding="utf-8")
        try:
            real_proof_root = "qualification-artifacts/SLO-TEST-001-proof.receipt"
            planted = self.real_slos_text + f"\n| `SLO-TEST-001` | latency <= 5 ms | edge-GPU | achieved | {real_proof_root} |\n"
            is_valid, findings = self._validate_with_planted_slos(planted)
            self.assertTrue(is_valid, f"Expected success with valid proof root, got findings: {[f.message for f in findings]}")
        finally:
            if proof_file.exists():
                proof_file.unlink()

    def test_achieved_with_valid_proof_bundle_passes(self) -> None:
        """SLO validation accepts a valid fss.proof_bundle.v1 proof root (resolving fss-gyqyz)."""
        proof_dir = ROOT / "qualification-artifacts"
        proof_dir.mkdir(parents=True, exist_ok=True)
        proof_file = proof_dir / "SLO-TEST-002-proof.bundle.json"
        bundle_data = {
            "schema": "fss.proof_bundle.v1",
            "bundle_id": "BUNDLE-SLO-TEST-002",
            "claim_id": "SLO-TEST-002",
            "claim_class": "slo",
            "supported_level": "achieved",
            "generation": "gen:fss1:operation-cost-v1",
            "status": "passed",
        }
        proof_file.write_text(json.dumps(bundle_data, indent=2) + "\n", encoding="utf-8")
        try:
            real_proof_root = "qualification-artifacts/SLO-TEST-002-proof.bundle.json"
            planted = self.real_slos_text + f"\n| `SLO-TEST-002` | latency <= 5 ms | edge-GPU | achieved | {real_proof_root} |\n"
            is_valid, findings = self._validate_with_planted_slos(planted)
            self.assertTrue(is_valid, f"Expected success with valid proof bundle, got findings: {[f.message for f in findings]}")
        finally:
            if proof_file.exists():
                proof_file.unlink()

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


class CrimsonWillowAdversarialPlantedNegativeTests(unittest.TestCase):
    """6 adversarial planted negative tests from CrimsonWillow's review."""

    def setUp(self) -> None:
        self.real_slos_text = SLOS_PATH.read_text(encoding="utf-8")
        self.real_costs_text = COSTS_PATH.read_text(encoding="utf-8")
        self.temp_dir = tempfile.TemporaryDirectory()
        self.temp_path = Path(self.temp_dir.name)

    def tearDown(self) -> None:
        self.temp_dir.cleanup()

    # 1. Achieved with proof path escaping qualification artifacts or pointing to non-proof repo file/dir
    def test_1_achieved_with_escaped_or_directory_proof_path(self) -> None:
        planted = self.real_slos_text + "\n| `SLO-TEST-001` | latency <= 5ms | edge-GPU | achieved | qualification-artifacts/../Cargo.toml |\n"
        sf = self.temp_path / "SLOS.md"
        sf.write_text(planted, encoding="utf-8")
        is_valid, findings, _ = slo_validate.validate_slos(root=ROOT, slos_path=sf, costs_path=COSTS_PATH)
        self.assertFalse(is_valid, "Defect 1: Achieved SLO with proof escaping to Cargo.toml wrongly passed!")

    # 2. Renumbered SLO ID
    def test_2_renumbered_slo_id(self) -> None:
        planted = self.real_slos_text + "\n| `SLO-TEST-001` (renumbered from `SLO-OLD-001`) | latency <= 5ms | edge-GPU | target | - |\n"
        sf = self.temp_path / "SLOS.md"
        sf.write_text(planted, encoding="utf-8")
        is_valid, findings, _ = slo_validate.validate_slos(root=ROOT, slos_path=sf, costs_path=COSTS_PATH)
        self.assertFalse(is_valid, "Defect 2: Renumbered SLO ID in ID cell wrongly passed!")

    # 3. Target with no unit or ambiguous unit
    def test_3_target_with_ambiguous_or_no_unit(self) -> None:
        planted = self.real_slos_text + "\n| `SLO-TEST-001` | latency <= 5 | edge-GPU | target | - |\n"
        sf = self.temp_path / "SLOS.md"
        sf.write_text(planted, encoding="utf-8")
        is_valid, findings, _ = slo_validate.validate_slos(root=ROOT, slos_path=sf, costs_path=COSTS_PATH)
        self.assertFalse(is_valid, "Defect 3: Target with ambiguous unit (latency <= 5) wrongly passed!")

    # 4. Operation cost referencing missing SLO (via singular slo_id)
    def test_4_operation_cost_referencing_missing_slo_singular(self) -> None:
        planted_costs = self.real_costs_text + """
[[operation]]
id = "COST-UNREGISTERED-001"
name = "operation referencing missing SLO"
unit = "frame"
slo_id = "SLO-NONEXISTENT-001"
"""
        cf = self.temp_path / "operation_cost_registry.toml"
        cf.write_text(planted_costs, encoding="utf-8")
        is_valid, findings, _ = slo_validate.validate_slos(root=ROOT, slos_path=SLOS_PATH, costs_path=cf)
        self.assertFalse(is_valid, "Defect 4: Operation cost referencing missing SLO via singular slo_id wrongly passed!")

    # 5. Tombstone row referenced as active
    def test_5_tombstone_row_referenced_as_active_in_costs(self) -> None:
        planted_costs = self.real_costs_text + """
[[operation]]
id = "COST-ACTIVE-TOMB-001"
name = "operation referencing tombstone directly"
unit = "operation"
slo_ids = ["SLO-PRIVACY-001"]
"""
        cf = self.temp_path / "operation_cost_registry.toml"
        cf.write_text(planted_costs, encoding="utf-8")
        is_valid, findings, _ = slo_validate.validate_slos(root=ROOT, slos_path=SLOS_PATH, costs_path=cf)
        self.assertFalse(is_valid, "Defect 5: Active operation referencing tombstone SLO-PRIVACY-001 directly wrongly passed!")

    # 6. Target promoted to public claim
    def test_6_target_promoted_to_public_claim(self) -> None:
        planted_claims = (ROOT / "registries/CLAIMS.md").read_text(encoding="utf-8") + (
            "\n| `slo` | operational latency target achieved | `SLO-INGEST-001` achieved in lab |\n"
        )
        cf = self.temp_path / "CLAIMS.md"
        cf.write_text(planted_claims, encoding="utf-8")
        is_valid, findings, _ = slo_validate.validate_slos(
            root=ROOT, slos_path=SLOS_PATH, costs_path=COSTS_PATH, claims_path=cf
        )
        self.assertFalse(is_valid, "Defect 6: Target promoted to public claim wrongly passed!")
        codes = [f.code for f in findings]
        self.assertIn("SLO-VAL-012", codes, "Defect 6: SLO-VAL-012 (CODE_TARGET_CLAIM_PROMOTION) is not emitted!")


class RusticGooseAdversarialNegativeTests(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name)
        self.qual = self.root / "qualification-artifacts"
        self.qual.mkdir()
        self.slos = self.root / "SLOS.md"
        self.costs = self.root / "costs.toml"
        self.claims = self.root / "CLAIMS.md"
        self.costs.write_text("""
[[operation]]
id = "COST-TEST-001"
name = "test"
unit = "frame"
slo_ids = ["SLO-TEST-001"]
""", encoding="utf-8")

    def tearDown(self) -> None:
        self.tmp.cleanup()

    # Finding 1: Symlink inside qualification-artifacts accepted
    def test_f1_symlink_inside_qualification_artifacts_accepted(self) -> None:
        real_proof = self.qual / "real.json"
        real_proof.write_text("proof", encoding="utf-8")
        link = self.qual / "link.json"
        link.symlink_to(real_proof)
        self.slos.write_text("""
| ID | Target | Measurement surface | Status | Proof root |
|---|---|---|---|---|
| `SLO-TEST-001` | latency <= 5 ms | edge-GPU | achieved | qualification-artifacts/link.json |
""", encoding="utf-8")
        valid, findings, _ = slo_validate.validate_slos(root=self.root, slos_path=self.slos, costs_path=self.costs)
        self.assertFalse(valid, "Symlink inside qualification-artifacts was accepted as valid proof!")

    # Finding 2: Empty 0-byte proof file accepted
    def test_f2_empty_proof_file_accepted(self) -> None:
        empty_proof = self.qual / "empty.json"
        empty_proof.write_text("", encoding="utf-8")
        self.slos.write_text("""
| ID | Target | Measurement surface | Status | Proof root |
|---|---|---|---|---|
| `SLO-TEST-001` | latency <= 5 ms | edge-GPU | achieved | qualification-artifacts/empty.json |
""", encoding="utf-8")
        valid, findings, _ = slo_validate.validate_slos(root=self.root, slos_path=self.slos, costs_path=self.costs)
        self.assertFalse(valid, "0-byte empty file was accepted as valid qualification proof!")

    # Finding 3: Unicode confusable in CLAIMS.md silently ignored
    def test_f3_unicode_confusable_in_claims_ignored(self) -> None:
        self.slos.write_text("""
| ID | Target | Measurement surface | Status | Proof root |
|---|---|---|---|---|
| `SLO-TEST-001` | latency <= 5 ms | edge-GPU | target | - |
""", encoding="utf-8")
        self.claims.write_text("""
| ID | Claim | Evidence |
|---|---|---|
| CLAIM-001 | test | `SL\u041e-TEST-001` achieved |
""", encoding="utf-8")
        valid, findings, _ = slo_validate.validate_slos(root=self.root, slos_path=self.slos, costs_path=self.costs, claims_path=self.claims)
        self.assertFalse(valid, "Cyrillic confusable in CLAIMS.md was silently ignored!")

    # Finding 4: Impossible physical and percentage values accepted
    def test_f4_impossible_values_accepted(self) -> None:
        self.assertFalse(slo_validate.validate_target_units("latency <= -5 ms", False), "Negative latency accepted!")
        self.assertFalse(slo_validate.validate_target_units("availability >= 150%", False), "150% availability accepted!")

    # Finding 5: Tombstone in claims emits target promotion instead of tombstone code
    def test_f5_tombstone_in_claims_emits_wrong_code(self) -> None:
        self.slos.write_text("""
| ID | Target | Measurement surface | Status | Proof root |
|---|---|---|---|---|
| `SLO-TEST-001` | latency <= 5 ms | edge-GPU | target | - |
| `SLO-TOMB-001` | tombstone: superseded by `SLO-TEST-001` | edge-GPU | tombstone | - |
""", encoding="utf-8")
        self.claims.write_text("""
| ID | Claim | Evidence |
|---|---|---|
| CLAIM-001 | test | `SLO-TOMB-001` |
""", encoding="utf-8")
        valid, findings, _ = slo_validate.validate_slos(root=self.root, slos_path=self.slos, costs_path=self.costs, claims_path=self.claims)
        codes = [f.code for f in findings]
        self.assertIn("SLO-VAL-014", codes, "Tombstone cited in CLAIMS should emit SLO-VAL-014")

    # Finding 6: Duplicate case-colliding cost operations accepted
    def test_f6_duplicate_case_colliding_cost_operations_accepted(self) -> None:
        self.slos.write_text("""
| ID | Target | Measurement surface | Status | Proof root |
|---|---|---|---|---|
| `SLO-TEST-001` | latency <= 5 ms | edge-GPU | target | - |
""", encoding="utf-8")
        self.costs.write_text("""
[[operation]]
id = "COST-TEST-001"
name = "test 1"
unit = "frame"
slo_ids = ["SLO-TEST-001"]

[[operation]]
id = "cost-test-001"
name = "test 2"
unit = "frame"
slo_ids = ["SLO-TEST-001"]
""", encoding="utf-8")
        valid, findings, _ = slo_validate.validate_slos(root=self.root, slos_path=self.slos, costs_path=self.costs)
        self.assertFalse(valid, "Case-colliding operation IDs in costs.toml were accepted!")

    # Finding 7: Empty string in slo_ids misclassified
    def test_f7_empty_string_in_slo_ids_misclassified(self) -> None:
        self.slos.write_text("""
| ID | Target | Measurement surface | Status | Proof root |
|---|---|---|---|---|
| `SLO-TEST-001` | latency <= 5 ms | edge-GPU | target | - |
""", encoding="utf-8")
        self.costs.write_text("""
[[operation]]
id = "COST-TEST-001"
name = "test"
unit = "frame"
slo_ids = [""]
""", encoding="utf-8")
        valid, findings, _ = slo_validate.validate_slos(root=self.root, slos_path=self.slos, costs_path=self.costs)
        codes = [f.code for f in findings]
        self.assertIn("SLO-VAL-009", codes, "slo_ids=[''] should report unlinked/unregistered SLO reference")

    # Finding 8: check-policy.py passes when slo_valid is False with non-error findings
    def test_f8_check_policy_silent_pass_on_non_error_slo_invalid(self) -> None:
        import importlib.util
        spec = importlib.util.spec_from_file_location("check_policy", (ROOT / "scripts/check-policy.py").resolve())
        cp = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(cp)

        orig_validate = slo_validate.validate_slos
        try:
            slo_validate.validate_slos = lambda root=ROOT, slos_path=None, costs_path=None, claims_path=None: (
                False, [slo_validate.SloFinding("warning", "CODE-WARN", "path", "msg")], {}
            )
            cp.errors = []
            cp.check_slo_policy(ROOT)
            self.assertGreater(len(cp.errors), 0, "check-policy must record an error when slo_valid is False")
        finally:
            slo_validate.validate_slos = orig_validate


class HotConsequentialOperationCostTests(unittest.TestCase):
    """FSS-198 / fss-x4a.26.18: Tests for mandatory hot and consequential operation cost rows."""

    MANDATORY_HOT_PATHS = (
        "COST-SPOOL-INGEST-001",
        "COST-SPOOL-VERIFY-001",
        "COST-SPOOL-DISCARD-001",
        "COST-ROOT-PUBLISH-001",
        "COST-LEDGER-APPEND-001",
        "COST-LEDGER-REPLAY-001",
        "COST-MODEL-IMPORT-001",
        "COST-DURABLE-DECODE-001",
        "COST-PRICING-LOOKUP-001",
    )

    REQUIRED_DIMENSIONS = (
        "latency_ms",
        "cpu_millis",
        "bytes",
        "storage_operations",
        "network_bytes",
        "model_calls",
        "tokens",
        "accelerator_millis",
        "energy_millijoules",
        "privacy_exposure",
        "operator_attention_seconds",
    )

    def test_live_repo_has_all_mandatory_hot_paths_registered(self) -> None:
        """Every hot/consequential path must exist in architecture/operation_cost_registry.toml with cost_vector and baseline_reference."""
        costs_data = tomllib.loads(COSTS_PATH.read_text(encoding="utf-8"))
        operations = {op.get("id"): op for op in costs_data.get("operation", [])}

        for path_id in self.MANDATORY_HOT_PATHS:
            self.assertIn(
                path_id,
                operations,
                f"Mandatory hot/consequential path '{path_id}' is missing from architecture/operation_cost_registry.toml",
            )
            op = operations[path_id]

            # Verify full cost vector
            self.assertIn(
                "cost_vector",
                op,
                f"Mandatory hot path '{path_id}' lacks 'cost_vector'",
            )
            cv = op["cost_vector"]
            self.assertIsInstance(cv, dict, f"cost_vector in '{path_id}' must be a dictionary")
            for dim in self.REQUIRED_DIMENSIONS:
                self.assertIn(
                    dim,
                    cv,
                    f"cost_vector in '{path_id}' lacks required dimension '{dim}'",
                )
                val = cv[dim]
                self.assertTrue(
                    isinstance(val, (int, float)) and val >= 0,
                    f"Dimension '{dim}' in '{path_id}' must be non-negative number, got {val}",
                )

            # Verify reproducible baseline reference
            self.assertIn(
                "baseline_reference",
                op,
                f"Mandatory hot path '{path_id}' lacks 'baseline_reference'",
            )
            baseline = op["baseline_reference"]
            self.assertIsInstance(baseline, str, f"baseline_reference in '{path_id}' must be a string")
            self.assertTrue(bool(baseline.strip()), f"baseline_reference in '{path_id}' must not be empty")
            baseline_path = ROOT / baseline
            self.assertTrue(
                baseline_path.is_file(),
                f"baseline_reference '{baseline}' in '{path_id}' must resolve to an existing file on disk",
            )

    def test_planted_missing_hot_path_fails_closed(self) -> None:
        """Removing a mandatory hot path must cause slo_validate to fail closed with SLO-VAL-015."""
        original_text = COSTS_PATH.read_text(encoding="utf-8")
        blocks = original_text.split("[[operation]]")
        header = blocks[0]
        op_blocks = [b for b in blocks[1:] if 'id = "COST-SPOOL-INGEST-001"' not in b]
        planted_text = header + "".join("[[operation]]" + b for b in op_blocks)

        with tempfile.TemporaryDirectory() as td:
            planted_costs = Path(td) / "operation_cost_registry.toml"
            planted_costs.write_text(planted_text, encoding="utf-8")

            is_valid, findings, _ = slo_validate.validate_slos(
                root=ROOT, slos_path=SLOS_PATH, costs_path=planted_costs
            )
            self.assertFalse(is_valid, "Checker must fail closed when a mandatory hot path is missing")
            codes = [f.code for f in findings]
            self.assertIn("SLO-VAL-015", codes, "Missing hot path must emit diagnostic code SLO-VAL-015")


    def test_planted_missing_cost_vector_fails_closed(self) -> None:
        """A hot path missing cost_vector must cause slo_validate to fail closed with SLO-VAL-016."""
        with tempfile.TemporaryDirectory() as td:
            planted_costs = Path(td) / "operation_cost_registry.toml"
            planted_text = """schema = "fss.operation_cost_registry.v2"
as_of = "2026-08-31"

[[operation]]
id = "COST-SPOOL-INGEST-001"
name = "ingest or stage one spool object"
unit = "spool_object"
slo_ids = ["SLO-INGEST-001"]
baseline_reference = "crates/fss-object/tests/staging_spool_contract.rs"
"""
            planted_costs.write_text(planted_text, encoding="utf-8")

            is_valid, findings, _ = slo_validate.validate_slos(
                root=ROOT, slos_path=SLOS_PATH, costs_path=planted_costs
            )
            self.assertFalse(is_valid, "Checker must fail closed when a hot path lacks cost_vector")
            codes = [f.code for f in findings]
            self.assertIn("SLO-VAL-016", codes, "Missing cost_vector must emit diagnostic code SLO-VAL-016")

    def test_planted_nonexistent_baseline_reference_fails_closed(self) -> None:
        """A hot path with nonexistent baseline_reference must cause slo_validate to fail closed with SLO-VAL-016."""
        with tempfile.TemporaryDirectory() as td:
            planted_costs = Path(td) / "operation_cost_registry.toml"
            planted_text = """schema = "fss.operation_cost_registry.v2"
as_of = "2026-08-31"

[[operation]]
id = "COST-SPOOL-INGEST-001"
name = "ingest or stage one spool object"
unit = "spool_object"
slo_ids = ["SLO-INGEST-001"]
baseline_reference = "crates/fss-object/tests/nonexistent_contract_file.rs"
cost_vector = { latency_ms = 5, cpu_millis = 2, bytes = 65536, storage_operations = 2, network_bytes = 0, model_calls = 0, tokens = 0, accelerator_millis = 0, energy_millijoules = 10, privacy_exposure = 0.0, operator_attention_seconds = 0.0 }
"""
            planted_costs.write_text(planted_text, encoding="utf-8")

            is_valid, findings, _ = slo_validate.validate_slos(
                root=ROOT, slos_path=SLOS_PATH, costs_path=planted_costs
            )
            self.assertFalse(is_valid, "Checker must fail closed when baseline_reference file does not exist")
            codes = [f.code for f in findings]
            self.assertIn("SLO-VAL-016", codes, "Nonexistent baseline_reference must emit diagnostic code SLO-VAL-016")

    def test_planted_incomplete_cost_vector_fails_closed(self) -> None:
        """A hot path with incomplete cost_vector dimensions must fail closed with SLO-VAL-016."""
        with tempfile.TemporaryDirectory() as td:
            planted_costs = Path(td) / "operation_cost_registry.toml"
            planted_text = """schema = "fss.operation_cost_registry.v2"
as_of = "2026-08-31"

[[operation]]
id = "COST-SPOOL-INGEST-001"
name = "ingest or stage one spool object"
unit = "spool_object"
slo_ids = ["SLO-INGEST-001"]
baseline_reference = "crates/fss-object/tests/staging_spool_contract.rs"
cost_vector = { latency_ms = 5, cpu_millis = 2 }
"""
            planted_costs.write_text(planted_text, encoding="utf-8")

            is_valid, findings, _ = slo_validate.validate_slos(
                root=ROOT, slos_path=SLOS_PATH, costs_path=planted_costs
            )
            self.assertFalse(is_valid, "Checker must fail closed when cost_vector lacks required dimensions")
            codes = [f.code for f in findings]
            self.assertIn("SLO-VAL-016", codes, "Incomplete cost_vector must emit diagnostic code SLO-VAL-016")

    def test_planted_negative_cost_vector_value_fails_closed(self) -> None:
        """A hot path with negative cost_vector dimension must fail closed with SLO-VAL-016."""
        with tempfile.TemporaryDirectory() as td:
            planted_costs = Path(td) / "operation_cost_registry.toml"
            planted_text = """schema = "fss.operation_cost_registry.v2"
as_of = "2026-08-31"

[[operation]]
id = "COST-SPOOL-INGEST-001"
name = "ingest or stage one spool object"
unit = "spool_object"
slo_ids = ["SLO-INGEST-001"]
baseline_reference = "crates/fss-object/tests/staging_spool_contract.rs"
cost_vector = { latency_ms = -5, cpu_millis = 2, bytes = 65536, storage_operations = 2, network_bytes = 0, model_calls = 0, tokens = 0, accelerator_millis = 0, energy_millijoules = 10, privacy_exposure = 0.0, operator_attention_seconds = 0.0 }
"""
            planted_costs.write_text(planted_text, encoding="utf-8")

            is_valid, findings, _ = slo_validate.validate_slos(
                root=ROOT, slos_path=SLOS_PATH, costs_path=planted_costs
            )
            self.assertFalse(is_valid, "Checker must fail closed when cost_vector has negative dimension")
            codes = [f.code for f in findings]
            self.assertIn("SLO-VAL-016", codes, "Negative cost_vector value must emit diagnostic code SLO-VAL-016")

    def test_planted_case_folding_hot_path_cannot_bypass_validation(self) -> None:
        """A lowercase hot path ID must not bypass cost_vector and baseline validation (F2)."""
        with tempfile.TemporaryDirectory() as td:
            planted_costs = Path(td) / "operation_cost_registry.toml"
            planted_text = """schema = "fss.operation_cost_registry.v2"
as_of = "2026-08-31"

[[operation]]
id = "cost-spool-ingest-001"
name = "ingest or stage one spool object"
unit = "segment"
slo_ids = ["SLO-INGEST-001"]
"""
            planted_costs.write_text(planted_text, encoding="utf-8")

            is_valid, findings, _ = slo_validate.validate_slos(
                root=ROOT, slos_path=SLOS_PATH, costs_path=planted_costs
            )
            self.assertFalse(is_valid, "Lowercase hot path ID must fail closed and not bypass validation")
            val_011_codes = [
                f.code
                for f in findings
                if f.code == "SLO-VAL-011" and f.params.get("cost_id") == "cost-spool-ingest-001"
            ]
            self.assertIn(
                "SLO-VAL-011",
                val_011_codes,
                f"Expected SLO-VAL-011 specifically for lowercase hot path 'cost-spool-ingest-001', got {[f.code for f in findings]}",
            )

    def test_planted_non_code_baseline_reference_fails_closed(self) -> None:
        """Baseline reference pointing to README.md or Cargo.toml must fail closed with SLO-VAL-016 (F3)."""
        with tempfile.TemporaryDirectory() as td:
            planted_costs = Path(td) / "operation_cost_registry.toml"
            planted_text = """schema = "fss.operation_cost_registry.v2"
as_of = "2026-08-31"

[[operation]]
id = "COST-SPOOL-INGEST-001"
name = "stage raw payload into staging spool"
unit = "segment"
slo_ids = ["SLO-INGEST-001"]
baseline_reference = "README.md"
cost_vector = { latency_ms = 5, cpu_millis = 2, bytes = 65536, storage_operations = 2, network_bytes = 0, model_calls = 0, tokens = 0, accelerator_millis = 0, energy_millijoules = 10, privacy_exposure = 0.0, operator_attention_seconds = 0.0 }
"""
            planted_costs.write_text(planted_text, encoding="utf-8")

            is_valid, findings, _ = slo_validate.validate_slos(
                root=ROOT, slos_path=SLOS_PATH, costs_path=planted_costs
            )
            self.assertFalse(is_valid, "Non-code baseline reference (README.md) must fail closed")
            codes = [f.code for f in findings]
            self.assertIn("SLO-VAL-016", codes)

    def test_planted_empty_or_non_test_baseline_reference_fails_closed(self) -> None:
        """Baseline reference pointing to an empty or non-test .rs file must fail closed with SLO-VAL-016 (F3)."""
        with tempfile.TemporaryDirectory() as td:
            empty_rs = ROOT / "crates" / "fss-core" / "tests" / "_temp_empty_test_baseline.rs"
            try:
                empty_rs.write_text("// no tests here\n", encoding="utf-8")
                planted_costs = Path(td) / "operation_cost_registry.toml"
                planted_text = """schema = "fss.operation_cost_registry.v2"
as_of = "2026-08-31"

[[operation]]
id = "COST-SPOOL-INGEST-001"
name = "stage raw payload into staging spool"
unit = "segment"
slo_ids = ["SLO-INGEST-001"]
baseline_reference = "crates/fss-core/tests/_temp_empty_test_baseline.rs"
cost_vector = { latency_ms = 5, cpu_millis = 2, bytes = 65536, storage_operations = 2, network_bytes = 0, model_calls = 0, tokens = 0, accelerator_millis = 0, energy_millijoules = 10, privacy_exposure = 0.0, operator_attention_seconds = 0.0 }
"""
                planted_costs.write_text(planted_text, encoding="utf-8")

                is_valid, findings, _ = slo_validate.validate_slos(
                    root=ROOT, slos_path=SLOS_PATH, costs_path=planted_costs
                )
                self.assertFalse(is_valid, "Empty/non-test baseline reference must fail closed")
                codes = [f.code for f in findings]
                self.assertIn("SLO-VAL-016", codes)
            finally:
                if empty_rs.exists():
                    empty_rs.unlink()

    def test_spool_operations_match_rust_staging_spool_mechanics(self) -> None:
        """Spool operations must reflect pure-Rust StagingSpool file/hold mechanics, not slab allocators (F5)."""
        costs_data = tomllib.loads(COSTS_PATH.read_text(encoding="utf-8"))
        operations = {op.get("id"): op for op in costs_data.get("operation", [])}

        spool_ops = ["COST-SPOOL-INGEST-001", "COST-SPOOL-VERIFY-001", "COST-SPOOL-DISCARD-001"]
        prohibited_terms = {"allocate_slot", "update_free_list", "invalidate_header", "slot_count"}

        for op_id in spool_ops:
            self.assertIn(op_id, operations, f"Spool operation {op_id} must be registered")
            op = operations[op_id]
            steps = set(op.get("semantic_steps", []))
            vars = set(op.get("variable_costs", []))
            all_terms = steps | vars
            found_prohibited = all_terms & prohibited_terms
            self.assertEqual(
                found_prohibited,
                set(),
                f"Spool operation {op_id} contains fabricated slab terms: {found_prohibited}",
            )

    def test_planted_nan_cost_vector_value_fails_closed(self) -> None:
        """A hot path with NaN cost_vector dimension must fail closed with SLO-VAL-016 (F6)."""
        with tempfile.TemporaryDirectory() as td:
            planted_costs = Path(td) / "operation_cost_registry.toml"
            planted_text = """schema = "fss.operation_cost_registry.v2"
as_of = "2026-08-31"

[[operation]]
id = "COST-SPOOL-INGEST-001"
name = "stage raw payload into staging spool"
unit = "segment"
slo_ids = ["SLO-INGEST-001"]
baseline_reference = "crates/fss-object/tests/staging_spool_contract.rs"
cost_vector = { latency_ms = nan, cpu_millis = 2, bytes = 65536, storage_operations = 2, network_bytes = 0, model_calls = 0, tokens = 0, accelerator_millis = 0, energy_millijoules = 10, privacy_exposure = 0.0, operator_attention_seconds = 0.0 }
"""
            planted_costs.write_text(planted_text, encoding="utf-8")

            is_valid, findings, _ = slo_validate.validate_slos(
                root=ROOT, slos_path=SLOS_PATH, costs_path=planted_costs
            )
            self.assertFalse(is_valid, "Checker must fail closed when cost_vector has NaN dimension")
            codes = [f.code for f in findings]
            self.assertIn("SLO-VAL-016", codes, "NaN cost_vector value must emit diagnostic code SLO-VAL-016")

    def test_planted_inf_cost_vector_value_fails_closed(self) -> None:
        """A hot path with inf cost_vector dimension must fail closed with SLO-VAL-016 (F6)."""
        with tempfile.TemporaryDirectory() as td:
            planted_costs = Path(td) / "operation_cost_registry.toml"
            planted_text = """schema = "fss.operation_cost_registry.v2"
as_of = "2026-08-31"

[[operation]]
id = "COST-SPOOL-INGEST-001"
name = "stage raw payload into staging spool"
unit = "segment"
slo_ids = ["SLO-INGEST-001"]
baseline_reference = "crates/fss-object/tests/staging_spool_contract.rs"
cost_vector = { latency_ms = inf, cpu_millis = 2, bytes = 65536, storage_operations = 2, network_bytes = 0, model_calls = 0, tokens = 0, accelerator_millis = 0, energy_millijoules = 10, privacy_exposure = 0.0, operator_attention_seconds = 0.0 }
"""
            planted_costs.write_text(planted_text, encoding="utf-8")

            is_valid, findings, _ = slo_validate.validate_slos(
                root=ROOT, slos_path=SLOS_PATH, costs_path=planted_costs
            )
            self.assertFalse(is_valid, "Checker must fail closed when cost_vector has inf dimension")
            codes = [f.code for f in findings]
            self.assertIn("SLO-VAL-016", codes, "inf cost_vector value must emit diagnostic code SLO-VAL-016")

    def test_planted_non_dict_operation_entry_fails_closed(self) -> None:
        """Non-dict element in operation list must emit SLO-VAL-011 without crashing (F7)."""
        with tempfile.TemporaryDirectory() as td:
            planted_costs = Path(td) / "operation_cost_registry.toml"
            planted_text = """schema = "fss.operation_cost_registry.v2"
as_of = "2026-08-31"
operation = ["invalid_string_entry"]
"""
            planted_costs.write_text(planted_text, encoding="utf-8")

            is_valid, findings, _ = slo_validate.validate_slos(
                root=ROOT, slos_path=SLOS_PATH, costs_path=planted_costs
            )
            self.assertFalse(is_valid, "Non-dict operation item must fail closed")
            codes = [f.code for f in findings]
            self.assertIn("SLO-VAL-011", codes)

    def test_planted_non_utf8_cost_registry_fails_closed(self) -> None:
        """Non-UTF-8 cost registry file must fail closed with SLO-VAL-011 without unhandled crash (F7)."""
        with tempfile.TemporaryDirectory() as td:
            planted_costs = Path(td) / "operation_cost_registry.toml"
            planted_costs.write_bytes(b"\xff\xfe\x00\x01\x80\x81invalid")

            is_valid, findings, _ = slo_validate.validate_slos(
                root=ROOT, slos_path=SLOS_PATH, costs_path=planted_costs
            )
            self.assertFalse(is_valid, "Non-UTF-8 cost registry must fail closed")
            codes = [f.code for f in findings]
            self.assertIn("SLO-VAL-011", codes)

    def test_planted_extraneous_cost_vector_dimension_fails_closed(self) -> None:
        """Cost vector with extraneous/typoed dimensions must fail closed with SLO-VAL-016 (F8)."""
        with tempfile.TemporaryDirectory() as td:
            planted_costs = Path(td) / "operation_cost_registry.toml"
            planted_text = """schema = "fss.operation_cost_registry.v2"
as_of = "2026-08-31"

[[operation]]
id = "COST-SPOOL-INGEST-001"
name = "stage raw payload into staging spool"
unit = "segment"
slo_ids = ["SLO-INGEST-001"]
baseline_reference = "crates/fss-object/tests/staging_spool_contract.rs"
cost_vector = { latency_ms = 5, cpu_millis = 2, bytes = 65536, storage_operations = 2, network_bytes = 0, model_calls = 0, tokens = 0, accelerator_millis = 0, energy_millijoules = 10, privacy_exposure = 0.0, operator_attention_seconds = 0.0, extraneous_typo_key = 99 }
"""
            planted_costs.write_text(planted_text, encoding="utf-8")

            is_valid, findings, _ = slo_validate.validate_slos(
                root=ROOT, slos_path=SLOS_PATH, costs_path=planted_costs
            )
            self.assertFalse(is_valid, "Extraneous cost_vector dimension must fail closed")
            codes = [f.code for f in findings]
            self.assertIn("SLO-VAL-016", codes, "Extraneous dimension must emit SLO-VAL-016")



class OperationCostProofOwnershipTests(unittest.TestCase):
    """fss-x4a.30.103: Tests for machine-readable operation-cost vectors, proof ownership, and drift."""

    def test_planted_missing_proof_owner_fails_closed_val_017(self) -> None:
        """Operation row missing proof_owner must fail closed with SLO-VAL-017."""
        with tempfile.TemporaryDirectory() as td:
            planted_costs = Path(td) / "operation_cost_registry.toml"
            planted_text = """schema = "fss.operation_cost_registry.v2"
as_of = "2026-08-31"

[[operation]]
id = "COST-TEST-001"
name = "test operation"
unit = "operation"
slo_ids = ["SLO-INGEST-001"]
status = "model_required"
cost_vector = { latency_ms = 1.0, cpu_millis = 1.0, bytes = 1024, storage_operations = 0, network_bytes = 0, model_calls = 0, tokens = 0, accelerator_millis = 0.0, energy_millijoules = 1.0, privacy_exposure = 0.0, operator_attention_seconds = 0.0 }
# missing proof_owner
proof_reference = "crates/fss-core/tests/durable_format_contract.rs::canonical_format_round_trip"
"""
            planted_costs.write_text(planted_text, encoding="utf-8")
            is_valid, findings, _ = slo_validate.validate_slos(
                root=ROOT, slos_path=SLOS_PATH, costs_path=planted_costs
            )
            self.assertFalse(is_valid)
            codes = [f.code for f in findings]
            self.assertIn("SLO-VAL-017", codes)

    def test_planted_unknown_proof_owner_fails_closed_val_017(self) -> None:
        """Operation row with unknown/nonexistent crate or module proof_owner must fail closed with SLO-VAL-017."""
        with tempfile.TemporaryDirectory() as td:
            planted_costs = Path(td) / "operation_cost_registry.toml"
            planted_text = """schema = "fss.operation_cost_registry.v2"
as_of = "2026-08-31"

[[operation]]
id = "COST-TEST-001"
name = "test operation"
unit = "operation"
slo_ids = ["SLO-INGEST-001"]
status = "model_required"
proof_owner = "crates/fss-nonexistent-crate"
proof_reference = "crates/fss-core/tests/durable_format_contract.rs::canonical_format_round_trip"
cost_vector = { latency_ms = 1.0, cpu_millis = 1.0, bytes = 1024, storage_operations = 0, network_bytes = 0, model_calls = 0, tokens = 0, accelerator_millis = 0.0, energy_millijoules = 1.0, privacy_exposure = 0.0, operator_attention_seconds = 0.0 }
"""
            planted_costs.write_text(planted_text, encoding="utf-8")
            is_valid, findings, _ = slo_validate.validate_slos(
                root=ROOT, slos_path=SLOS_PATH, costs_path=planted_costs
            )
            self.assertFalse(is_valid)
            codes = [f.code for f in findings]
            self.assertIn("SLO-VAL-017", codes)

    def test_planted_undeclared_drift_proof_owner_fails_closed_val_017(self) -> None:
        """Operation row with drift owner not declared in [[drift]] table must fail closed with SLO-VAL-017."""
        with tempfile.TemporaryDirectory() as td:
            planted_costs = Path(td) / "operation_cost_registry.toml"
            planted_text = """schema = "fss.operation_cost_registry.v2"
as_of = "2026-08-31"

[[operation]]
id = "COST-TEST-001"
name = "test operation"
unit = "operation"
slo_ids = ["SLO-INGEST-001"]
status = "model_required"
proof_owner = "drift:DRIFT-COST-UNDECLARED-001"
proof_reference = "drift:DRIFT-COST-UNDECLARED-001"
cost_vector = { latency_ms = 1.0, cpu_millis = 1.0, bytes = 1024, storage_operations = 0, network_bytes = 0, model_calls = 0, tokens = 0, accelerator_millis = 0.0, energy_millijoules = 1.0, privacy_exposure = 0.0, operator_attention_seconds = 0.0 }
"""
            planted_costs.write_text(planted_text, encoding="utf-8")
            is_valid, findings, _ = slo_validate.validate_slos(
                root=ROOT, slos_path=SLOS_PATH, costs_path=planted_costs
            )
            self.assertFalse(is_valid)
            codes = [f.code for f in findings]
            self.assertIn("SLO-VAL-017", codes)

    def test_planted_nonexistent_proof_reference_file_fails_closed_val_018(self) -> None:
        """Operation row with nonexistent proof_reference file must fail closed with SLO-VAL-018."""
        with tempfile.TemporaryDirectory() as td:
            planted_costs = Path(td) / "operation_cost_registry.toml"
            planted_text = """schema = "fss.operation_cost_registry.v2"
as_of = "2026-08-31"

[[operation]]
id = "COST-TEST-001"
name = "test operation"
unit = "operation"
slo_ids = ["SLO-INGEST-001"]
status = "model_required"
proof_owner = "crates/fss-core"
proof_reference = "crates/fss-core/tests/nonexistent_contract_file.rs::test_fn"
cost_vector = { latency_ms = 1.0, cpu_millis = 1.0, bytes = 1024, storage_operations = 0, network_bytes = 0, model_calls = 0, tokens = 0, accelerator_millis = 0.0, energy_millijoules = 1.0, privacy_exposure = 0.0, operator_attention_seconds = 0.0 }
"""
            planted_costs.write_text(planted_text, encoding="utf-8")
            is_valid, findings, _ = slo_validate.validate_slos(
                root=ROOT, slos_path=SLOS_PATH, costs_path=planted_costs
            )
            self.assertFalse(is_valid)
            codes = [f.code for f in findings]
            self.assertIn("SLO-VAL-018", codes)

    def test_planted_nonexistent_proof_reference_fn_fails_closed_val_018(self) -> None:
        """Operation row with existing file but nonexistent test fn must fail closed with SLO-VAL-018."""
        with tempfile.TemporaryDirectory() as td:
            planted_costs = Path(td) / "operation_cost_registry.toml"
            planted_text = """schema = "fss.operation_cost_registry.v2"
as_of = "2026-08-31"

[[operation]]
id = "COST-TEST-001"
name = "test operation"
unit = "operation"
slo_ids = ["SLO-INGEST-001"]
status = "model_required"
proof_owner = "crates/fss-core"
proof_reference = "crates/fss-core/tests/durable_format_contract.rs::nonexistent_test_function_symbol"
cost_vector = { latency_ms = 1.0, cpu_millis = 1.0, bytes = 1024, storage_operations = 0, network_bytes = 0, model_calls = 0, tokens = 0, accelerator_millis = 0.0, energy_millijoules = 1.0, privacy_exposure = 0.0, operator_attention_seconds = 0.0 }
"""
            planted_costs.write_text(planted_text, encoding="utf-8")
            is_valid, findings, _ = slo_validate.validate_slos(
                root=ROOT, slos_path=SLOS_PATH, costs_path=planted_costs
            )
            self.assertFalse(is_valid)
            codes = [f.code for f in findings]
            self.assertIn("SLO-VAL-018", codes)

    def test_planted_proof_reference_missing_fn_separator_fails_closed_val_018(self) -> None:
        """Operation row with proof_reference missing '::' fn specifier must fail closed with SLO-VAL-018."""
        with tempfile.TemporaryDirectory() as td:
            planted_costs = Path(td) / "operation_cost_registry.toml"
            planted_text = """schema = "fss.operation_cost_registry.v2"
as_of = "2026-08-31"

[[operation]]
id = "COST-TEST-001"
name = "test operation"
unit = "operation"
slo_ids = ["SLO-INGEST-001"]
status = "model_required"
proof_owner = "crates/fss-core"
proof_reference = "crates/fss-core/tests/durable_format_contract.rs"
cost_vector = { latency_ms = 1.0, cpu_millis = 1.0, bytes = 1024, storage_operations = 0, network_bytes = 0, model_calls = 0, tokens = 0, accelerator_millis = 0.0, energy_millijoules = 1.0, privacy_exposure = 0.0, operator_attention_seconds = 0.0 }
"""
            planted_costs.write_text(planted_text, encoding="utf-8")
            is_valid, findings, _ = slo_validate.validate_slos(
                root=ROOT, slos_path=SLOS_PATH, costs_path=planted_costs
            )
            self.assertFalse(is_valid)
            codes = [f.code for f in findings]
            self.assertIn("SLO-VAL-018", codes)

    def test_planted_owner_mirror_disagreement_fails_closed_val_019(self) -> None:
        """Disagreement between TOML proof_owner and Markdown Proof owner must fail closed with SLO-VAL-019."""
        with tempfile.TemporaryDirectory() as td:
            planted_costs = Path(td) / "operation_cost_registry.toml"
            planted_costs_md = Path(td) / "OPERATION_COSTS.md"
            planted_costs.write_text("""schema = "fss.operation_cost_registry.v2"
as_of = "2026-08-31"

[[operation]]
id = "COST-TEST-001"
name = "test operation"
unit = "operation"
slo_ids = ["SLO-INGEST-001"]
status = "model_required"
proof_owner = "crates/fss-core"
proof_reference = "crates/fss-core/tests/durable_format_contract.rs::canonical_format_round_trip"
cost_vector = { latency_ms = 1.0, cpu_millis = 1.0, bytes = 1024, storage_operations = 0, network_bytes = 0, model_calls = 0, tokens = 0, accelerator_millis = 0.0, energy_millijoules = 1.0, privacy_exposure = 0.0, operator_attention_seconds = 0.0 }
""", encoding="utf-8")
            planted_costs_md.write_text("""# Operation cost registry

| Cost ID | Unit | Mandatory semantic work | Key variables | Proof owner | Proof reference |
|---|---|---|---|---|---|
| `COST-TEST-001` | operation | semantic work | variables | `crates/fss-ledger` | `crates/fss-core/tests/durable_format_contract.rs::canonical_format_round_trip` |
""", encoding="utf-8")
            is_valid, findings, _ = slo_validate.validate_slos(
                root=ROOT, slos_path=SLOS_PATH, costs_path=planted_costs, costs_md_path=planted_costs_md
            )
            self.assertFalse(is_valid)
            codes = [f.code for f in findings]
            self.assertIn("SLO-VAL-019", codes)

    def test_planted_reference_mirror_disagreement_fails_closed_val_019(self) -> None:
        """Disagreement between TOML proof_reference and Markdown Proof reference must fail closed with SLO-VAL-019."""
        with tempfile.TemporaryDirectory() as td:
            planted_costs = Path(td) / "operation_cost_registry.toml"
            planted_costs_md = Path(td) / "OPERATION_COSTS.md"
            planted_costs.write_text("""schema = "fss.operation_cost_registry.v2"
as_of = "2026-08-31"

[[operation]]
id = "COST-TEST-001"
name = "test operation"
unit = "operation"
slo_ids = ["SLO-INGEST-001"]
status = "model_required"
proof_owner = "crates/fss-core"
proof_reference = "crates/fss-core/tests/durable_format_contract.rs::canonical_format_round_trip"
cost_vector = { latency_ms = 1.0, cpu_millis = 1.0, bytes = 1024, storage_operations = 0, network_bytes = 0, model_calls = 0, tokens = 0, accelerator_millis = 0.0, energy_millijoules = 1.0, privacy_exposure = 0.0, operator_attention_seconds = 0.0 }
""", encoding="utf-8")
            planted_costs_md.write_text("""# Operation cost registry

| Cost ID | Unit | Mandatory semantic work | Key variables | Proof owner | Proof reference |
|---|---|---|---|---|---|
| `COST-TEST-001` | operation | semantic work | variables | `crates/fss-core` | `crates/fss-core/tests/durable_format_contract.rs::different_test_fn` |
""", encoding="utf-8")
            is_valid, findings, _ = slo_validate.validate_slos(
                root=ROOT, slos_path=SLOS_PATH, costs_path=planted_costs, costs_md_path=planted_costs_md
            )
            self.assertFalse(is_valid)
            codes = [f.code for f in findings]
            self.assertIn("SLO-VAL-019", codes)

    def test_planted_measured_status_without_artifact_fails_closed_val_020(self) -> None:
        """Operation with status 'measured' lacking measurement_artifact must fail closed with SLO-VAL-020."""
        with tempfile.TemporaryDirectory() as td:
            planted_costs = Path(td) / "operation_cost_registry.toml"
            planted_text = """schema = "fss.operation_cost_registry.v2"
as_of = "2026-08-31"

[[operation]]
id = "COST-TEST-001"
name = "test operation"
unit = "operation"
slo_ids = ["SLO-INGEST-001"]
status = "measured"
proof_owner = "crates/fss-core"
proof_reference = "crates/fss-core/tests/durable_format_contract.rs::canonical_format_round_trip"
cost_vector = { latency_ms = 1.0, cpu_millis = 1.0, bytes = 1024, storage_operations = 0, network_bytes = 0, model_calls = 0, tokens = 0, accelerator_millis = 0.0, energy_millijoules = 1.0, privacy_exposure = 0.0, operator_attention_seconds = 0.0 }
"""
            planted_costs.write_text(planted_text, encoding="utf-8")
            is_valid, findings, _ = slo_validate.validate_slos(
                root=ROOT, slos_path=SLOS_PATH, costs_path=planted_costs
            )
            self.assertFalse(is_valid)
            codes = [f.code for f in findings]
            self.assertIn("SLO-VAL-020", codes)

    def test_planted_measured_status_with_nonexistent_artifact_fails_closed_val_020(self) -> None:
        """Operation with status 'measured' and nonexistent measurement_artifact must fail closed with SLO-VAL-020."""
        with tempfile.TemporaryDirectory() as td:
            planted_costs = Path(td) / "operation_cost_registry.toml"
            planted_text = """schema = "fss.operation_cost_registry.v2"
as_of = "2026-08-31"

[[operation]]
id = "COST-TEST-001"
name = "test operation"
unit = "operation"
slo_ids = ["SLO-INGEST-001"]
status = "measured"
measurement_artifact = "qualification-artifacts/nonexistent_measurement.json"
proof_owner = "crates/fss-core"
proof_reference = "crates/fss-core/tests/durable_format_contract.rs::canonical_format_round_trip"
cost_vector = { latency_ms = 1.0, cpu_millis = 1.0, bytes = 1024, storage_operations = 0, network_bytes = 0, model_calls = 0, tokens = 0, accelerator_millis = 0.0, energy_millijoules = 1.0, privacy_exposure = 0.0, operator_attention_seconds = 0.0 }
"""
            planted_costs.write_text(planted_text, encoding="utf-8")
            is_valid, findings, _ = slo_validate.validate_slos(
                root=ROOT, slos_path=SLOS_PATH, costs_path=planted_costs
            )
            self.assertFalse(is_valid)
            codes = [f.code for f in findings]
            self.assertIn("SLO-VAL-020", codes)

    def test_planted_duplicate_cost_id_emits_val_021(self) -> None:
        """Duplicate or case-colliding operation IDs must emit SLO-VAL-021."""
        with tempfile.TemporaryDirectory() as td:
            planted_costs = Path(td) / "operation_cost_registry.toml"
            planted_text = """schema = "fss.operation_cost_registry.v2"
as_of = "2026-08-31"

[[operation]]
id = "COST-TEST-001"
name = "test operation 1"
unit = "operation"
slo_ids = ["SLO-INGEST-001"]
status = "model_required"
proof_owner = "crates/fss-core"
proof_reference = "crates/fss-core/tests/durable_format_contract.rs::canonical_format_round_trip"
cost_vector = { latency_ms = 1.0, cpu_millis = 1.0, bytes = 1024, storage_operations = 0, network_bytes = 0, model_calls = 0, tokens = 0, accelerator_millis = 0.0, energy_millijoules = 1.0, privacy_exposure = 0.0, operator_attention_seconds = 0.0 }

[[operation]]
id = "cost-test-001"
name = "test operation duplicate"
unit = "operation"
slo_ids = ["SLO-INGEST-001"]
status = "model_required"
proof_owner = "crates/fss-core"
proof_reference = "crates/fss-core/tests/durable_format_contract.rs::canonical_format_round_trip"
cost_vector = { latency_ms = 1.0, cpu_millis = 1.0, bytes = 1024, storage_operations = 0, network_bytes = 0, model_calls = 0, tokens = 0, accelerator_millis = 0.0, energy_millijoules = 1.0, privacy_exposure = 0.0, operator_attention_seconds = 0.0 }
"""
            planted_costs.write_text(planted_text, encoding="utf-8")
            is_valid, findings, _ = slo_validate.validate_slos(
                root=ROOT, slos_path=SLOS_PATH, costs_path=planted_costs
            )
            self.assertFalse(is_valid)
            codes = [f.code for f in findings]
            self.assertIn("SLO-VAL-021", codes)

    def test_planted_malformed_or_renumbered_cost_id_emits_val_021(self) -> None:
        """Malformed or non-conforming cost ID must emit SLO-VAL-021."""
        with tempfile.TemporaryDirectory() as td:
            planted_costs = Path(td) / "operation_cost_registry.toml"
            planted_text = """schema = "fss.operation_cost_registry.v2"
as_of = "2026-08-31"

[[operation]]
id = "INVALID_COST_ID_FORMAT"
name = "test operation"
unit = "operation"
slo_ids = ["SLO-INGEST-001"]
status = "model_required"
proof_owner = "crates/fss-core"
proof_reference = "crates/fss-core/tests/durable_format_contract.rs::canonical_format_round_trip"
cost_vector = { latency_ms = 1.0, cpu_millis = 1.0, bytes = 1024, storage_operations = 0, network_bytes = 0, model_calls = 0, tokens = 0, accelerator_millis = 0.0, energy_millijoules = 1.0, privacy_exposure = 0.0, operator_attention_seconds = 0.0 }
"""
            planted_costs.write_text(planted_text, encoding="utf-8")
            is_valid, findings, _ = slo_validate.validate_slos(
                root=ROOT, slos_path=SLOS_PATH, costs_path=planted_costs
            )
            self.assertFalse(is_valid)
            codes = [f.code for f in findings]
            self.assertIn("SLO-VAL-021", codes)

    def test_live_repo_all_operations_have_cost_vector_and_proof_ownership(self) -> None:
        """Every operation in architecture/operation_cost_registry.toml must have complete cost_vector, proof_owner, and proof_reference."""
        import re
        costs_data = tomllib.loads(COSTS_PATH.read_text(encoding="utf-8"))
        operations = costs_data.get("operation", [])
        self.assertGreaterEqual(len(operations), 41)
        drifts = {d["id"]: d for d in costs_data.get("drift", [])}

        for op in operations:
            cid = op.get("id")
            self.assertIn("cost_vector", op, f"{cid} missing cost_vector")
            cv = op["cost_vector"]
            self.assertIsInstance(cv, dict, f"{cid} cost_vector must be dict")
            for dim in HotConsequentialOperationCostTests.REQUIRED_DIMENSIONS:
                self.assertIn(dim, cv, f"{cid} cost_vector missing dimension {dim}")
                val = cv[dim]
                self.assertIsInstance(val, (int, float), f"{cid} dimension {dim} must be number")
                self.assertFalse(isinstance(val, bool), f"{cid} dimension {dim} must not be bool")
                self.assertFalse(math.isnan(val), f"{cid} dimension {dim} must not be NaN")
                self.assertFalse(math.isinf(val), f"{cid} dimension {dim} must not be inf")
                self.assertGreaterEqual(val, 0, f"{cid} dimension {dim} must be non-negative")

            self.assertIn("proof_owner", op, f"{cid} missing proof_owner")
            owner = op["proof_owner"]
            self.assertIsInstance(owner, str, f"{cid} proof_owner must be string")
            self.assertTrue(bool(owner.strip()), f"{cid} proof_owner must not be empty")

            self.assertIn("proof_reference", op, f"{cid} missing proof_reference")
            ref = op["proof_reference"]
            self.assertIsInstance(ref, str, f"{cid} proof_reference must be string")
            self.assertTrue(bool(ref.strip()), f"{cid} proof_reference must not be empty")

            if owner.startswith("drift:"):
                drift_id = owner.split(":", 1)[1].strip()
                self.assertIn(drift_id, drifts, f"{cid} drift owner '{drift_id}' not found in [[drift]]")
            else:
                self.assertTrue((ROOT / owner).exists(), f"{cid} proof_owner path '{owner}' does not exist")
                self.assertIn("::", ref, f"{cid} proof_reference must contain '::'")
                file_part, fn_name = ref.split("::", 1)
                ref_file = ROOT / file_part
                self.assertTrue(ref_file.is_file(), f"{cid} proof_reference file '{file_part}' does not exist")
                content = ref_file.read_text(encoding="utf-8", errors="replace")
                has_fn = bool(re.search(r"\b(?:async\s+)?fn\s+" + re.escape(fn_name) + r"\b", content))
                self.assertTrue(has_fn, f"{cid} test fn '{fn_name}' not found in '{file_part}'")

    def test_planted_conforming_renumbered_cost_id_emits_val_021(self) -> None:
        """A conforming but renumbered operation ID (e.g. COST-ACQUIRE-002) must fail closed with SLO-VAL-021."""
        with tempfile.TemporaryDirectory() as td:
            planted_costs = Path(td) / "operation_cost_registry.toml"
            mutated_costs = COSTS_PATH.read_text(encoding="utf-8").replace('id = "COST-ACQUIRE-001"', 'id = "COST-ACQUIRE-002"')
            planted_costs.write_text(mutated_costs, encoding="utf-8")
            planted_md = Path(td) / "OPERATION_COSTS.md"
            mutated_md = COSTS_MD_PATH.read_text(encoding="utf-8").replace("`COST-ACQUIRE-001`", "`COST-ACQUIRE-002`")
            planted_md.write_text(mutated_md, encoding="utf-8")
            is_valid, findings, _ = slo_validate.validate_slos(
                root=ROOT, slos_path=SLOS_PATH, costs_path=planted_costs, costs_md_path=planted_md
            )
            self.assertFalse(is_valid, "Renumbered operation ID passed validation!")
            codes = [f.code for f in findings]
            self.assertIn("SLO-VAL-021", codes)

    def test_planted_missing_unit_fails_closed(self) -> None:
        """Operation row missing 'unit' must fail closed with SLO-VAL-011."""
        with tempfile.TemporaryDirectory() as td:
            planted_costs = Path(td) / "operation_cost_registry.toml"
            mutated = COSTS_PATH.read_text(encoding="utf-8").replace('unit = "segment"\n', '')
            planted_costs.write_text(mutated, encoding="utf-8")
            is_valid, findings, _ = slo_validate.validate_slos(
                root=ROOT, slos_path=SLOS_PATH, costs_path=planted_costs, costs_md_path=COSTS_MD_PATH
            )
            self.assertFalse(is_valid, "Operation without unit was accepted!")
            codes = [f.code for f in findings]
            self.assertIn("SLO-VAL-011", codes)

    def test_planted_unit_mirror_mismatch_emits_val_019(self) -> None:
        """Disagreement between TOML unit and Markdown Unit must fail closed with SLO-VAL-019."""
        with tempfile.TemporaryDirectory() as td:
            planted_costs = Path(td) / "operation_cost_registry.toml"
            mutated = COSTS_PATH.read_text(encoding="utf-8").replace('unit = "segment"', 'unit = "bogus_unit"')
            planted_costs.write_text(mutated, encoding="utf-8")
            is_valid, findings, _ = slo_validate.validate_slos(
                root=ROOT, slos_path=SLOS_PATH, costs_path=planted_costs, costs_md_path=COSTS_MD_PATH
            )
            self.assertFalse(is_valid, "Mismatched unit passed validation!")
            codes = [f.code for f in findings]
            self.assertIn("SLO-VAL-019", codes)

    def test_planted_semantic_steps_mirror_mismatch_emits_val_019(self) -> None:
        """Disagreement between TOML semantic_steps and Markdown Mandatory semantic work must emit SLO-VAL-019."""
        with tempfile.TemporaryDirectory() as td:
            planted_costs = Path(td) / "operation_cost_registry.toml"
            mutated = COSTS_PATH.read_text(encoding="utf-8").replace('"adapter_receive"', '"altered_step"')
            planted_costs.write_text(mutated, encoding="utf-8")
            is_valid, findings, _ = slo_validate.validate_slos(
                root=ROOT, slos_path=SLOS_PATH, costs_path=planted_costs, costs_md_path=COSTS_MD_PATH
            )
            self.assertFalse(is_valid, "Mismatched semantic_steps passed validation!")
            codes = [f.code for f in findings]
            self.assertIn("SLO-VAL-019", codes)

    def test_planted_variable_costs_mirror_mismatch_emits_val_019(self) -> None:
        """Disagreement between TOML variable_costs and Markdown Key variables must emit SLO-VAL-019."""
        with tempfile.TemporaryDirectory() as td:
            planted_costs = Path(td) / "operation_cost_registry.toml"
            mutated = COSTS_PATH.read_text(encoding="utf-8").replace('"source_bytes"', '"altered_var"')
            planted_costs.write_text(mutated, encoding="utf-8")
            is_valid, findings, _ = slo_validate.validate_slos(
                root=ROOT, slos_path=SLOS_PATH, costs_path=planted_costs, costs_md_path=COSTS_MD_PATH
            )
            self.assertFalse(is_valid, "Mismatched variable_costs passed validation!")
            codes = [f.code for f in findings]
            self.assertIn("SLO-VAL-019", codes)

    def test_planted_measured_status_with_arbitrary_file_fails_val_020(self) -> None:
        """Operation with status 'measured' and measurement_artifact pointing outside qualification-artifacts must fail closed with SLO-VAL-020."""
        with tempfile.TemporaryDirectory() as td:
            planted_costs = Path(td) / "operation_cost_registry.toml"
            mutated = COSTS_PATH.read_text(encoding="utf-8").replace(
                'status = "model_required"',
                'status = "measured"\nmeasurement_artifact = "Cargo.toml"',
                1
            )
            planted_costs.write_text(mutated, encoding="utf-8")
            is_valid, findings, _ = slo_validate.validate_slos(
                root=ROOT, slos_path=SLOS_PATH, costs_path=planted_costs, costs_md_path=COSTS_MD_PATH
            )
            self.assertFalse(is_valid, "Arbitrary non-qualification file accepted as measurement artifact!")
            codes = [f.code for f in findings]
            self.assertIn("SLO-VAL-020", codes)

    def test_planted_measured_status_with_empty_artifact_fails_val_020(self) -> None:
        """Operation with status 'measured' and empty (0-byte) measurement artifact must fail closed with SLO-VAL-020."""
        with tempfile.TemporaryDirectory() as td:
            empty_art = ROOT / "qualification-artifacts" / "test_empty_receipt.json"
            try:
                empty_art.write_text("", encoding="utf-8")
                planted_costs = Path(td) / "operation_cost_registry.toml"
                mutated = COSTS_PATH.read_text(encoding="utf-8").replace(
                    'status = "model_required"',
                    'status = "measured"\nmeasurement_artifact = "qualification-artifacts/test_empty_receipt.json"',
                    1
                )
                planted_costs.write_text(mutated, encoding="utf-8")
                is_valid, findings, _ = slo_validate.validate_slos(
                    root=ROOT, slos_path=SLOS_PATH, costs_path=planted_costs, costs_md_path=COSTS_MD_PATH
                )
                self.assertFalse(is_valid, "0-byte measurement artifact accepted!")
                codes = [f.code for f in findings]
                self.assertIn("SLO-VAL-020", codes)
            finally:
                if empty_art.exists():
                    empty_art.unlink()

    def test_planted_commented_out_test_fn_fails_closed_val_018(self) -> None:
        """Proof reference pointing to a commented-out test fn must fail closed with SLO-VAL-018."""
        with tempfile.TemporaryDirectory() as td:
            dummy_test = ROOT / "crates/fss-core/tests/comment_masked_test.rs"
            try:
                dummy_test.write_text("// fn test_comment_masked_symbol() {}\n/* fn test_comment_masked_symbol() {} */\n", encoding="utf-8")
                planted_costs = Path(td) / "operation_cost_registry.toml"
                mutated = COSTS_PATH.read_text(encoding="utf-8").replace(
                    'proof_reference = "crates/fss-core/tests/acquisition_lifecycle_contract.rs::test_happy_path_lifecycle_and_streaming_invariants"',
                    'proof_reference = "crates/fss-core/tests/comment_masked_test.rs::test_comment_masked_symbol"'
                )
                planted_costs.write_text(mutated, encoding="utf-8")
                is_valid, findings, _ = slo_validate.validate_slos(
                    root=ROOT, slos_path=SLOS_PATH, costs_path=planted_costs, costs_md_path=COSTS_MD_PATH
                )
                self.assertFalse(is_valid, "Commented-out test function accepted as valid proof reference!")
                codes = [f.code for f in findings]
                self.assertIn("SLO-VAL-018", codes)
            finally:
                if dummy_test.exists():
                    dummy_test.unlink()

    def test_planted_non_crate_proof_owner_fails_closed_val_017(self) -> None:
        """Proof owner pointing to non-crate directory must fail closed with SLO-VAL-017."""
        for bad_owner in [".", "scripts"]:
            with tempfile.TemporaryDirectory() as td:
                planted_costs = Path(td) / "operation_cost_registry.toml"
                mutated = COSTS_PATH.read_text(encoding="utf-8").replace(
                    'proof_owner = "crates/fss-core"',
                    f'proof_owner = "{bad_owner}"',
                    1
                )
                planted_costs.write_text(mutated, encoding="utf-8")
                is_valid, findings, _ = slo_validate.validate_slos(
                    root=ROOT, slos_path=SLOS_PATH, costs_path=planted_costs, costs_md_path=COSTS_MD_PATH
                )
                self.assertFalse(is_valid, f"Non-crate proof_owner '{bad_owner}' was accepted!")
                codes = [f.code for f in findings]
                self.assertIn("SLO-VAL-017", codes)

    def test_planted_drift_table_mirror_mismatch_emits_val_019(self) -> None:
        """Disagreement between TOML drift table and Markdown drift table must emit SLO-VAL-019."""
        with tempfile.TemporaryDirectory() as td:
            planted_md = Path(td) / "OPERATION_COSTS.md"
            mutated_md = COSTS_MD_PATH.read_text(encoding="utf-8").replace(
                '`crates/fss-media` |',
                '`crates/fss-cognition` |',
                1
            )
            planted_md.write_text(mutated_md, encoding="utf-8")
            is_valid, findings, _ = slo_validate.validate_slos(
                root=ROOT, slos_path=SLOS_PATH, costs_path=COSTS_PATH, costs_md_path=planted_md
            )
            self.assertFalse(is_valid, "Drift table mirror mismatch passed validation!")
            codes = [f.code for f in findings]
            self.assertIn("SLO-VAL-019", codes)

    def test_custom_costs_path_still_validates_mirror_when_costs_md_not_passed(self) -> None:
        """Supplying custom costs_path without costs_md_path must still validate against registries/OPERATION_COSTS.md."""
        with tempfile.TemporaryDirectory() as td:
            planted_costs = Path(td) / "operation_cost_registry.toml"
            mutated = COSTS_PATH.read_text(encoding="utf-8").replace(
                'proof_owner = "crates/fss-core"',
                'proof_owner = "crates/fss-ledger"',
                1
            )
            planted_costs.write_text(mutated, encoding="utf-8")
            is_valid, findings, _ = slo_validate.validate_slos(
                root=ROOT, slos_path=SLOS_PATH, costs_path=planted_costs
            )
            self.assertFalse(is_valid, "Custom cost path bypassed mirror validation!")
            codes = [f.code for f in findings]
            self.assertIn("SLO-VAL-019", codes)

    def test_planted_cost_registry_digest_mismatch_emits_val_022(self) -> None:
        """Operation cost registry mutation without generation bump or freeze digest update must emit SLO-VAL-022."""
        with tempfile.TemporaryDirectory() as td:
            planted_costs = Path(td) / "operation_cost_registry.toml"
            mutated = COSTS_PATH.read_text(encoding="utf-8").replace('latency_ms = 10.0', 'latency_ms = 99.0', 1)
            planted_costs.write_text(mutated, encoding="utf-8")
            is_valid, findings, _ = slo_validate.validate_slos(
                root=ROOT, slos_path=SLOS_PATH, costs_path=planted_costs, costs_md_path=COSTS_MD_PATH
            )
            self.assertFalse(is_valid, "Mutated registry without digest update passed validation!")
            codes = [f.code for f in findings]
            self.assertIn("SLO-VAL-022", codes)


if __name__ == "__main__":
    unittest.main(verbosity=2)


