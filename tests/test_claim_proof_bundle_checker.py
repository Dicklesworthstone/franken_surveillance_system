#!/usr/bin/env python3
"""Planted-negative and positive test suite for claim/proof-bundle checker (fss-x4a.6.11 / FSS-011).

Enforces fail-closed verification:
1. Proof bundle existence: nonexistent file, path traversal ('..'), directory path,
   absolute path in documentation, or missing artifact fails with ERR-CLAIM-PROOF-BUNDLE-NOT-FOUND-001.
2. Digest integrity: declared content digest mismatch or artifact digest mismatch
   fails with ERR-CLAIM-PROOF-DIGEST-MISMATCH-001.
3. Level support: claim level exceeding bundle supported level, non-passing bundle status,
   promoted claim without proof bundle, or missing required evidence for claim class
   fails with ERR-CLAIM-PROOF-LEVEL-EXCEEDED-001.
4. Stale generation refusal: 'latest' aliases, tombstoned generations, expired bundles,
   or explicitly stale/superseded generations fail with ERR-CLAIM-PROOF-STALE-GENERATION-001.
5. Input validity: unreadable, corrupt, non-object JSON, or empty (0 bytes / empty dict / empty classes)
   inputs fail with ERR-CLAIM-PROOF-UNREADABLE-INPUT-001 or ERR-CLAIM-PROOF-EMPTY-INPUT-001.
6. Unknown claim class fails with ERR-CLAIM-PROOF-INVALID-CLASS-001.
7. Prohibited claim promotion fails with ERR-CLAIM-PROOF-PROHIBITED-PROMOTION-001.
8. Positive controls: live repo passes, valid bundles pass, valid artifacts pass, CLI flags work.
"""

from __future__ import annotations

import json
import subprocess
import sys
import tempfile
import unittest
import os
import shutil
from datetime import datetime, timezone
from pathlib import Path
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))

from claim_proof_bundle_checker import (
    ERR_BUNDLE_DIGEST_MISMATCH,
    ERR_CLAIM_ID_REUSED,
    ERR_CLAIM_LEVEL_EXCEEDED,
    ERR_CLAIM_MISSING_FIELD,
    ERR_CLAIM_REGISTRY_DRIFT,
    ERR_EMPTY_INPUT,
    ERR_INVALID_CLAIM_CLASS,
    ERR_PROHIBITED_CLAIM_PROMOTION,
    ERR_PROOF_BUNDLE_NOT_FOUND,
    ERR_STALE_GENERATION,
    ERR_UNREADABLE_INPUT,
    audit_claim_kind_registry,
    audit_claim_proof_bundles,
    compute_bundle_digest,
    compute_canonical_claims_digest,
    compute_sha256,
    is_latest_generation,
    load_authoritative_claims,
    parse_markdown_tables,
    scan_markdown_claim_tables,
    verify_proof_bundle,
    BASELINE_CLAIMS_FREEZE_DIGEST,
    BASELINE_CLAIMS_GENERATION,
    CANONICAL_CLAIM_CLASSES,
    CANONICAL_PROHIBITED_PROMOTIONS,
    EXPECTED_CLAIMS_FREEZE_DIGESTS,
)
import claim_proof_bundle_checker as cpb


class TestClaimProofBundlePositiveControls(unittest.TestCase):
    """Positive controls asserting valid inputs pass with zero errors."""

    def test_live_repo_passes(self) -> None:
        """The actual repository state passes the claim/proof-bundle audit with zero errors."""
        is_valid, findings, summary = audit_claim_proof_bundles(ROOT)
        self.assertTrue(
            is_valid,
            f"Live repo failed claim/proof-bundle audit with {len(findings)} findings: {[f.message for f in findings]}",
        )
        self.assertEqual(summary["status"], "pass")
        self.assertEqual(summary["error_count"], 0)
        self.assertGreater(summary["authoritative_classes_count"], 0)

    def test_cli_live_repo_passes(self) -> None:
        """CLI invocation on live repository exits with code 0."""
        cmd = [sys.executable, str(ROOT / "scripts/claim_proof_bundle_checker.py")]
        result = subprocess.run(cmd, capture_output=True, text=True, cwd=str(ROOT))
        self.assertEqual(result.returncode, 0, f"CLI failed: {result.stderr}\n{result.stdout}")
        self.assertIn("[PASS]", result.stdout)

    def test_cli_json_mode(self) -> None:
        """CLI --json emits valid JSON matching summary structure."""
        cmd = [sys.executable, str(ROOT / "scripts/claim_proof_bundle_checker.py"), "--json"]
        result = subprocess.run(cmd, capture_output=True, text=True, cwd=str(ROOT))
        self.assertEqual(result.returncode, 0)
        report = json.loads(result.stdout)
        self.assertIn("summary", report)
        self.assertIn("findings", report)
        self.assertEqual(report["summary"]["status"], "pass")
        self.assertEqual(report["summary"]["error_count"], 0)

    def test_cli_quiet_mode(self) -> None:
        """CLI --quiet suppresses non-error stdout on passing repo."""
        cmd = [sys.executable, str(ROOT / "scripts/claim_proof_bundle_checker.py"), "--quiet"]
        result = subprocess.run(cmd, capture_output=True, text=True, cwd=str(ROOT))
        self.assertEqual(result.returncode, 0)
        self.assertEqual(result.stdout.strip(), "")

    def test_positive_valid_bundle(self) -> None:
        """A well-formed proof bundle with matching digest and valid metadata passes."""
        with tempfile.TemporaryDirectory() as tmpdir:
            tmp_root = Path(tmpdir)
            known_classes, prohibited, _ = load_authoritative_claims(ROOT / "architecture/claims.json")

            bundle_data = {
                "schema": "fss.proof_bundle.v1",
                "bundle_id": "BUNDLE-TEST-001",
                "claim_id": "PROOF-TEST-001",
                "claim_class": "proof",
                "supported_level": "achieved",
                "generation": "gen-2026-09-01",
                "status": "passed",
                "retained_evidence": [
                    "formal_artifact",
                    "toolchain_identity",
                    "proof_check_receipt",
                ],
            }
            digest = compute_bundle_digest(bundle_data)
            bundle_data["content_digest"] = digest

            bundle_file = tmp_root / "test.bundle.json"
            bundle_file.write_text(json.dumps(bundle_data, indent=2), encoding="utf-8")

            is_valid, findings, loaded_data = verify_proof_bundle(
                bundle_path=bundle_file,
                root=tmp_root,
                expected_claim_id="PROOF-TEST-001",
                claim_level="achieved",
                known_classes=known_classes,
                prohibited_promotions=prohibited,
            )
            self.assertTrue(is_valid, f"Expected pass, got findings: {[f.message for f in findings]}")
            self.assertEqual(len(findings), 0)
            self.assertIsNotNone(loaded_data)

    def test_positive_bundle_with_verified_artifacts(self) -> None:
        """A proof bundle declaring artifacts with matching sha256 digests passes."""
        with tempfile.TemporaryDirectory() as tmpdir:
            tmp_root = Path(tmpdir)
            known_classes, prohibited, _ = load_authoritative_claims(ROOT / "architecture/claims.json")

            art1_file = tmp_root / "artifact1.bin"
            art1_content = b"artifact 1 content sample data"
            art1_file.write_bytes(art1_content)
            art1_digest = compute_sha256(art1_content)

            bundle_data = {
                "schema": "fss.proof_bundle.v1",
                "bundle_id": "BUNDLE-ART-001",
                "claim_id": "INV-TEST-001",
                "claim_class": "invariant",
                "supported_level": "achieved",
                "generation": "gen-2026-09-01",
                "status": "verified",
                "retained_evidence": [
                    "contract",
                    "mechanical_check",
                    "counterexample_suite",
                ],
                "artifacts": [
                    {
                        "path": "artifact1.bin",
                        "digest": art1_digest,
                    }
                ],
            }
            digest = compute_bundle_digest(bundle_data)
            bundle_data["content_digest"] = digest

            bundle_file = tmp_root / "art.bundle.json"
            bundle_file.write_text(json.dumps(bundle_data), encoding="utf-8")

            is_valid, findings, _ = verify_proof_bundle(
                bundle_path=bundle_file,
                root=tmp_root,
                known_classes=known_classes,
                prohibited_promotions=prohibited,
            )
            self.assertTrue(is_valid, f"Expected pass, got findings: {[f.message for f in findings]}")
            self.assertEqual(len(findings), 0)

    def test_positive_markdown_table_with_valid_bundle(self) -> None:
        """Markdown table citing a valid relative proof bundle passes scanning."""
        with tempfile.TemporaryDirectory() as tmpdir:
            tmp_root = Path(tmpdir)
            known_classes, prohibited, _ = load_authoritative_claims(ROOT / "architecture/claims.json")

            bundle_data = {
                "schema": "fss.proof_bundle.v1",
                "claim_id": "PROOF-001",
                "claim_class": "proof",
                "supported_level": "achieved",
                "generation": "gen-active-01",
                "status": "passed",
                "retained_evidence": [
                    "formal_artifact",
                    "toolchain_identity",
                    "proof_check_receipt",
                ],
            }
            bundle_data["content_digest"] = compute_bundle_digest(bundle_data)
            rel_bundle = "proof_bundles/proof1.bundle.json"
            full_bundle_path = tmp_root / rel_bundle
            full_bundle_path.parent.mkdir(parents=True, exist_ok=True)
            full_bundle_path.write_text(json.dumps(bundle_data), encoding="utf-8")

            md_content = (
                "# Status Table\n\n"
                "| ID | Status | Proof root |\n"
                "|---|---|---|\n"
                f"| `PROOF-001` | achieved | `{rel_bundle}` |\n"
            )
            md_file = tmp_root / "test_table.md"
            md_file.write_text(md_content, encoding="utf-8")

            findings = scan_markdown_claim_tables(
                md_path=md_file,
                root=tmp_root,
                known_classes=known_classes,
                tombstoned_ids=set(),
                prohibited_promotions=prohibited,
            )
            self.assertEqual(len(findings), 0, f"Expected 0 findings, got: {[f.message for f in findings]}")


class TestPlantedNegativeProofBundleNotFound(unittest.TestCase):
    """Planted-negative tests for ERR-CLAIM-PROOF-BUNDLE-NOT-FOUND-001."""

    def test_planted_nonexistent_proof_bundle_in_table_fails(self) -> None:
        """Markdown table citing a nonexistent proof bundle fails with ERR_PROOF_BUNDLE_NOT_FOUND."""
        with tempfile.TemporaryDirectory() as tmpdir:
            tmp_root = Path(tmpdir)
            known_classes, prohibited, _ = load_authoritative_claims(ROOT / "architecture/claims.json")

            md_content = (
                "| ID | Status | Proof root |\n"
                "|---|---|---|\n"
                "| `SLO-MISSING` | achieved | `qualification-artifacts/does_not_exist.bundle.json` |\n"
            )
            md_file = tmp_root / "missing.md"
            md_file.write_text(md_content, encoding="utf-8")

            findings = scan_markdown_claim_tables(
                md_path=md_file,
                root=tmp_root,
                known_classes=known_classes,
                tombstoned_ids=set(),
                prohibited_promotions=prohibited,
            )
            codes = [f.code for f in findings]
            self.assertIn(ERR_PROOF_BUNDLE_NOT_FOUND, codes)

    def test_planted_path_traversal_fails(self) -> None:
        """Proof bundle path with '..' traversal fails with ERR_PROOF_BUNDLE_NOT_FOUND."""
        with tempfile.TemporaryDirectory() as tmpdir:
            tmp_root = Path(tmpdir)
            traversal_path = tmp_root / "subdir/../../etc/passwd"
            is_valid, findings, _ = verify_proof_bundle(
                bundle_path=traversal_path,
                root=tmp_root,
            )
            self.assertFalse(is_valid)
            self.assertIn(ERR_PROOF_BUNDLE_NOT_FOUND, [f.code for f in findings])
            self.assertTrue(any("traversal" in f.message for f in findings))

    def test_planted_directory_as_proof_bundle_fails(self) -> None:
        """Path pointing to a directory instead of a file fails with ERR_PROOF_BUNDLE_NOT_FOUND."""
        with tempfile.TemporaryDirectory() as tmpdir:
            tmp_root = Path(tmpdir)
            dir_path = tmp_root / "my_dir"
            dir_path.mkdir()

            is_valid, findings, _ = verify_proof_bundle(
                bundle_path=dir_path,
                root=tmp_root,
            )
            self.assertFalse(is_valid)
            self.assertIn(ERR_PROOF_BUNDLE_NOT_FOUND, [f.code for f in findings])
            self.assertTrue(any("not a regular file" in f.message for f in findings))

    def test_planted_missing_artifact_in_bundle_fails(self) -> None:
        """Bundle referencing a nonexistent artifact fails with ERR_PROOF_BUNDLE_NOT_FOUND."""
        with tempfile.TemporaryDirectory() as tmpdir:
            tmp_root = Path(tmpdir)
            bundle_data = {
                "schema": "fss.proof_bundle.v1",
                "status": "passed",
                "artifacts": [
                    {
                        "path": "qualification-artifacts/nonexistent_measurement.bin",
                        "digest": "sha256:0000000000000000000000000000000000000000000000000000000000000000",
                    }
                ],
            }
            bundle_file = tmp_root / "bundle.json"
            bundle_file.write_text(json.dumps(bundle_data), encoding="utf-8")

            is_valid, findings, _ = verify_proof_bundle(
                bundle_path=bundle_file,
                root=tmp_root,
            )
            self.assertFalse(is_valid)
            self.assertIn(ERR_PROOF_BUNDLE_NOT_FOUND, [f.code for f in findings])
            self.assertTrue(any("artifact file does not exist" in f.message for f in findings))

    def test_planted_absolute_path_in_table_fails(self) -> None:
        """Markdown table citing an absolute filesystem path fails with ERR_PROOF_BUNDLE_NOT_FOUND."""
        with tempfile.TemporaryDirectory() as tmpdir:
            tmp_root = Path(tmpdir)
            known_classes, prohibited, _ = load_authoritative_claims(ROOT / "architecture/claims.json")

            md_content = (
                "| ID | Status | Proof root |\n"
                "|---|---|---|\n"
                "| `SLO-ABS` | achieved | `/etc/shadow` |\n"
            )
            md_file = tmp_root / "absolute.md"
            md_file.write_text(md_content, encoding="utf-8")

            findings = scan_markdown_claim_tables(
                md_path=md_file,
                root=tmp_root,
                known_classes=known_classes,
                tombstoned_ids=set(),
                prohibited_promotions=prohibited,
            )
            codes = [f.code for f in findings]
            self.assertIn(ERR_PROOF_BUNDLE_NOT_FOUND, codes)
            self.assertTrue(any("repository-relative" in f.message for f in findings))


class TestPlantedNegativeDigestMismatch(unittest.TestCase):
    """Planted-negative tests for ERR-CLAIM-PROOF-DIGEST-MISMATCH-001."""

    def test_planted_bundle_content_digest_mismatch_fails(self) -> None:
        """Proof bundle with tampered content_digest fails with ERR_BUNDLE_DIGEST_MISMATCH."""
        with tempfile.TemporaryDirectory() as tmpdir:
            tmp_root = Path(tmpdir)
            bundle_data = {
                "schema": "fss.proof_bundle.v1",
                "bundle_id": "BUNDLE-TAMPERED-001",
                "content_digest": "sha256:ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
                "status": "passed",
            }
            bundle_file = tmp_root / "tampered.json"
            bundle_file.write_text(json.dumps(bundle_data), encoding="utf-8")

            is_valid, findings, _ = verify_proof_bundle(
                bundle_path=bundle_file,
                root=tmp_root,
            )
            self.assertFalse(is_valid)
            self.assertIn(ERR_BUNDLE_DIGEST_MISMATCH, [f.code for f in findings])
            self.assertTrue(any("does not match computed digest" in f.message for f in findings))

    def test_planted_artifact_digest_mismatch_fails(self) -> None:
        """Proof bundle with an artifact whose actual digest differs from declared digest fails."""
        with tempfile.TemporaryDirectory() as tmpdir:
            tmp_root = Path(tmpdir)
            art_file = tmp_root / "actual_artifact.bin"
            art_file.write_bytes(b"actual content on disk")

            bundle_data = {
                "schema": "fss.proof_bundle.v1",
                "bundle_id": "BUNDLE-ART-MISMATCH",
                "status": "passed",
                "artifacts": [
                    {
                        "path": "actual_artifact.bin",
                        "digest": "sha256:0000000000000000000000000000000000000000000000000000000000000000",
                    }
                ],
            }
            bundle_file = tmp_root / "bundle.json"
            bundle_file.write_text(json.dumps(bundle_data), encoding="utf-8")

            is_valid, findings, _ = verify_proof_bundle(
                bundle_path=bundle_file,
                root=tmp_root,
            )
            self.assertFalse(is_valid)
            self.assertIn(ERR_BUNDLE_DIGEST_MISMATCH, [f.code for f in findings])
            self.assertTrue(any("digest mismatch" in f.message for f in findings))


class TestPlantedNegativeClaimLevelExceeded(unittest.TestCase):
    """Planted-negative tests for ERR-CLAIM-PROOF-LEVEL-EXCEEDED-001 and class/promotion checks."""

    def test_planted_claim_level_higher_than_supported_fails(self) -> None:
        """Claiming 'achieved' when bundle only supports 'target' fails with ERR_CLAIM_LEVEL_EXCEEDED."""
        with tempfile.TemporaryDirectory() as tmpdir:
            tmp_root = Path(tmpdir)
            bundle_data = {
                "schema": "fss.proof_bundle.v1",
                "supported_level": "target",
                "status": "passed",
            }
            bundle_file = tmp_root / "bundle.json"
            bundle_file.write_text(json.dumps(bundle_data), encoding="utf-8")

            is_valid, findings, _ = verify_proof_bundle(
                bundle_path=bundle_file,
                root=tmp_root,
                claim_level="achieved",
            )
            self.assertFalse(is_valid)
            self.assertIn(ERR_CLAIM_LEVEL_EXCEEDED, [f.code for f in findings])
            self.assertTrue(any("exceeds proof bundle supported level" in f.message for f in findings))

    def test_planted_failed_bundle_status_fails(self) -> None:
        """Proof bundle with status 'failed', 'broken', or 'revoked' fails with ERR_CLAIM_LEVEL_EXCEEDED."""
        for failed_st in ("failed", "broken", "revoked", "blocked", "staged", "indeterminate"):
            with tempfile.TemporaryDirectory() as tmpdir:
                tmp_root = Path(tmpdir)
                bundle_data = {
                    "schema": "fss.proof_bundle.v1",
                    "supported_level": "achieved",
                    "status": failed_st,
                }
                bundle_file = tmp_root / "bundle.json"
                bundle_file.write_text(json.dumps(bundle_data), encoding="utf-8")

                is_valid, findings, _ = verify_proof_bundle(
                    bundle_path=bundle_file,
                    root=tmp_root,
                    claim_level="achieved",
                )
                self.assertFalse(is_valid, f"Status '{failed_st}' should have failed")
                self.assertIn(ERR_CLAIM_LEVEL_EXCEEDED, [f.code for f in findings])

    def test_planted_promoted_claim_without_proof_root_fails(self) -> None:
        """Markdown row marked 'achieved' with '-' or empty proof root fails with ERR_CLAIM_LEVEL_EXCEEDED."""
        with tempfile.TemporaryDirectory() as tmpdir:
            tmp_root = Path(tmpdir)
            known_classes, prohibited, _ = load_authoritative_claims(ROOT / "architecture/claims.json")

            md_content = (
                "| ID | Status | Proof root |\n"
                "|---|---|---|\n"
                "| `SLO-UNBACKED` | achieved | - |\n"
            )
            md_file = tmp_root / "unbacked.md"
            md_file.write_text(md_content, encoding="utf-8")

            findings = scan_markdown_claim_tables(
                md_path=md_file,
                root=tmp_root,
                known_classes=known_classes,
                tombstoned_ids=set(),
                prohibited_promotions=prohibited,
            )
            codes = [f.code for f in findings]
            self.assertIn(ERR_CLAIM_LEVEL_EXCEEDED, codes)
            self.assertTrue(any("without referencing a retained proof bundle" in f.message for f in findings))

    def test_planted_missing_required_evidence_for_class_fails(self) -> None:
        """Proof bundle missing mandatory evidence for registered class fails with ERR_CLAIM_LEVEL_EXCEEDED."""
        with tempfile.TemporaryDirectory() as tmpdir:
            tmp_root = Path(tmpdir)
            known_classes = {
                "slo": ["operation_cost_row", "measurement_artifact", "environment_manifest"]
            }
            bundle_data = {
                "schema": "fss.proof_bundle.v1",
                "claim_class": "slo",
                "status": "passed",
                "supported_level": "achieved",
                "retained_evidence": ["operation_cost_row"],  # missing 2 required pieces
            }
            bundle_file = tmp_root / "bundle.json"
            bundle_file.write_text(json.dumps(bundle_data), encoding="utf-8")

            is_valid, findings, _ = verify_proof_bundle(
                bundle_path=bundle_file,
                root=tmp_root,
                known_classes=known_classes,
            )
            self.assertFalse(is_valid)
            self.assertIn(ERR_CLAIM_LEVEL_EXCEEDED, [f.code for f in findings])
            self.assertTrue(any("missing required evidence" in f.message for f in findings))

    def test_planted_unknown_claim_class_fails(self) -> None:
        """Proof bundle with unregistered claim class fails with ERR_INVALID_CLAIM_CLASS."""
        with tempfile.TemporaryDirectory() as tmpdir:
            tmp_root = Path(tmpdir)
            known_classes = {"slo": [], "invariant": []}
            bundle_data = {
                "schema": "fss.proof_bundle.v1",
                "claim_class": "invented_unregistered_class",
                "status": "passed",
            }
            bundle_file = tmp_root / "bundle.json"
            bundle_file.write_text(json.dumps(bundle_data), encoding="utf-8")

            is_valid, findings, _ = verify_proof_bundle(
                bundle_path=bundle_file,
                root=tmp_root,
                known_classes=known_classes,
            )
            self.assertFalse(is_valid)
            self.assertIn(ERR_INVALID_CLAIM_CLASS, [f.code for f in findings])

    def test_planted_prohibited_claim_promotion_fails(self) -> None:
        """Proof bundle using a prohibited claim promotion fails with ERR_PROHIBITED_CLAIM_PROMOTION."""
        with tempfile.TemporaryDirectory() as tmpdir:
            tmp_root = Path(tmpdir)
            prohibited = {"source_presence_as_support", "single_demo_as_readiness"}
            bundle_data = {
                "schema": "fss.proof_bundle.v1",
                "status": "passed",
                "basis": "source_presence_as_support",
            }
            bundle_file = tmp_root / "prohibited.json"
            bundle_file.write_text(json.dumps(bundle_data), encoding="utf-8")

            is_valid, findings, _ = verify_proof_bundle(
                bundle_path=bundle_file,
                root=tmp_root,
                prohibited_promotions=prohibited,
            )
            self.assertFalse(is_valid)
            self.assertIn(ERR_PROHIBITED_CLAIM_PROMOTION, [f.code for f in findings])


class TestPlantedNegativeStaleGeneration(unittest.TestCase):
    """Planted-negative tests for ERR-CLAIM-PROOF-STALE-GENERATION-001."""

    def test_planted_latest_alias_in_generation_string_fails(self) -> None:
        """Bundle referencing 'latest', 'v-latest', or 'v1-latest' fails with ERR_STALE_GENERATION."""
        for alias in ("latest", "LATEST", "v-latest", "latest-v1", "camera-latest"):
            self.assertTrue(is_latest_generation(alias), f"Expected '{alias}' to be detected as latest")
            with tempfile.TemporaryDirectory() as tmpdir:
                tmp_root = Path(tmpdir)
                bundle_data = {
                    "schema": "fss.proof_bundle.v1",
                    "generation": alias,
                    "status": "passed",
                }
                bundle_file = tmp_root / "bundle.json"
                bundle_file.write_text(json.dumps(bundle_data), encoding="utf-8")

                is_valid, findings, _ = verify_proof_bundle(
                    bundle_path=bundle_file,
                    root=tmp_root,
                )
                self.assertFalse(is_valid, f"Alias '{alias}' should have failed")
                self.assertIn(ERR_STALE_GENERATION, [f.code for f in findings])
                self.assertTrue(any("prohibited 'latest' alias" in f.message for f in findings))

    def test_planted_latest_alias_in_generation_dict_or_list_fails(self) -> None:
        """Nested 'latest' alias in generation dict or list fails with ERR_STALE_GENERATION."""
        with tempfile.TemporaryDirectory() as tmpdir:
            tmp_root = Path(tmpdir)
            bundle_data = {
                "schema": "fss.proof_bundle.v1",
                "generation": {"model_weights": "latest"},
                "status": "passed",
            }
            bundle_file = tmp_root / "bundle.json"
            bundle_file.write_text(json.dumps(bundle_data), encoding="utf-8")

            is_valid, findings, _ = verify_proof_bundle(
                bundle_path=bundle_file,
                root=tmp_root,
            )
            self.assertFalse(is_valid)
            self.assertIn(ERR_STALE_GENERATION, [f.code for f in findings])

    def test_planted_tombstoned_generation_fails(self) -> None:
        """Bundle referencing a tombstoned generation ID fails with ERR_STALE_GENERATION."""
        with tempfile.TemporaryDirectory() as tmpdir:
            tmp_root = Path(tmpdir)
            bundle_data = {
                "schema": "fss.proof_bundle.v1",
                "generation": "GEN-TOMBSTONED-OLD",
                "status": "passed",
            }
            bundle_file = tmp_root / "bundle.json"
            bundle_file.write_text(json.dumps(bundle_data), encoding="utf-8")

            is_valid, findings, _ = verify_proof_bundle(
                bundle_path=bundle_file,
                root=tmp_root,
                tombstoned_ids={"GEN-TOMBSTONED-OLD"},
            )
            self.assertFalse(is_valid)
            self.assertIn(ERR_STALE_GENERATION, [f.code for f in findings])
            self.assertTrue(any("tombstoned generation" in f.message for f in findings))

    def test_planted_explicit_stale_or_superseded_generation_fails(self) -> None:
        """Bundle declaring is_stale=True or status='stale' fails with ERR_STALE_GENERATION."""
        with tempfile.TemporaryDirectory() as tmpdir:
            tmp_root = Path(tmpdir)
            bundle_data = {
                "schema": "fss.proof_bundle.v1",
                "generation": {
                    "id": "gen-old",
                    "is_stale": True,
                },
                "status": "passed",
            }
            bundle_file = tmp_root / "bundle.json"
            bundle_file.write_text(json.dumps(bundle_data), encoding="utf-8")

            is_valid, findings, _ = verify_proof_bundle(
                bundle_path=bundle_file,
                root=tmp_root,
            )
            self.assertFalse(is_valid)
            self.assertIn(ERR_STALE_GENERATION, [f.code for f in findings])
            self.assertTrue(any("stale or superseded" in f.message for f in findings))

    def test_planted_expired_bundle_fails(self) -> None:
        """Bundle marked is_expired=True fails with ERR_STALE_GENERATION."""
        with tempfile.TemporaryDirectory() as tmpdir:
            tmp_root = Path(tmpdir)
            bundle_data = {
                "schema": "fss.proof_bundle.v1",
                "is_expired": True,
                "status": "passed",
            }
            bundle_file = tmp_root / "bundle.json"
            bundle_file.write_text(json.dumps(bundle_data), encoding="utf-8")

            is_valid, findings, _ = verify_proof_bundle(
                bundle_path=bundle_file,
                root=tmp_root,
            )
            self.assertFalse(is_valid)
            self.assertIn(ERR_STALE_GENERATION, [f.code for f in findings])
            self.assertTrue(any("expired" in f.message for f in findings))


class TestPlantedNegativeUnreadableAndEmptyInputs(unittest.TestCase):
    """Planted-negative tests for ERR-CLAIM-PROOF-UNREADABLE-INPUT-001 and ERR-CLAIM-PROOF-EMPTY-INPUT-001."""

    def test_planted_empty_bundle_file_fails(self) -> None:
        """Empty 0-byte proof bundle file fails with ERR_EMPTY_INPUT."""
        with tempfile.TemporaryDirectory() as tmpdir:
            tmp_root = Path(tmpdir)
            empty_file = tmp_root / "empty.bundle.json"
            empty_file.write_bytes(b"")

            is_valid, findings, _ = verify_proof_bundle(
                bundle_path=empty_file,
                root=tmp_root,
            )
            self.assertFalse(is_valid)
            self.assertIn(ERR_EMPTY_INPUT, [f.code for f in findings])
            self.assertTrue(any("0 bytes" in f.message for f in findings))

    def test_planted_empty_json_object_bundle_fails(self) -> None:
        """Proof bundle containing an empty JSON object '{}' fails with ERR_EMPTY_INPUT."""
        with tempfile.TemporaryDirectory() as tmpdir:
            tmp_root = Path(tmpdir)
            empty_json = tmp_root / "empty_obj.bundle.json"
            empty_json.write_text("{}", encoding="utf-8")

            is_valid, findings, _ = verify_proof_bundle(
                bundle_path=empty_json,
                root=tmp_root,
            )
            self.assertFalse(is_valid)
            self.assertIn(ERR_EMPTY_INPUT, [f.code for f in findings])
            self.assertTrue(any("empty JSON object" in f.message for f in findings))

    def test_planted_corrupt_json_bundle_fails(self) -> None:
        """Proof bundle containing corrupt JSON syntax fails with ERR_UNREADABLE_INPUT."""
        with tempfile.TemporaryDirectory() as tmpdir:
            tmp_root = Path(tmpdir)
            corrupt_file = tmp_root / "corrupt.bundle.json"
            corrupt_file.write_text("{ unquoted_key: invalid_json, ", encoding="utf-8")

            is_valid, findings, _ = verify_proof_bundle(
                bundle_path=corrupt_file,
                root=tmp_root,
            )
            self.assertFalse(is_valid)
            self.assertIn(ERR_UNREADABLE_INPUT, [f.code for f in findings])
            self.assertTrue(any("invalid JSON" in f.message for f in findings))

    def test_planted_non_object_json_bundle_fails(self) -> None:
        """Proof bundle whose JSON root is an array instead of an object fails with ERR_UNREADABLE_INPUT."""
        with tempfile.TemporaryDirectory() as tmpdir:
            tmp_root = Path(tmpdir)
            array_file = tmp_root / "array.bundle.json"
            array_file.write_text("[\"not_an_object\"]", encoding="utf-8")

            is_valid, findings, _ = verify_proof_bundle(
                bundle_path=array_file,
                root=tmp_root,
            )
            self.assertFalse(is_valid)
            self.assertIn(ERR_UNREADABLE_INPUT, [f.code for f in findings])
            self.assertTrue(any("must be an object" in f.message for f in findings))

    def test_planted_empty_markdown_file_fails(self) -> None:
        """Empty 0-byte markdown file fails with ERR_EMPTY_INPUT."""
        with tempfile.TemporaryDirectory() as tmpdir:
            tmp_root = Path(tmpdir)
            empty_md = tmp_root / "empty.md"
            empty_md.write_bytes(b"")

            findings = scan_markdown_claim_tables(
                md_path=empty_md,
                root=tmp_root,
                known_classes={},
                tombstoned_ids=set(),
            )
            self.assertIn(ERR_EMPTY_INPUT, [f.code for f in findings])

    def test_planted_empty_claims_registry_fails(self) -> None:
        """Empty 0-byte claims.json fails with ERR_EMPTY_INPUT."""
        with tempfile.TemporaryDirectory() as tmpdir:
            tmp_root = Path(tmpdir)
            empty_claims = tmp_root / "empty_claims.json"
            empty_claims.write_bytes(b"")

            _, _, findings = load_authoritative_claims(empty_claims)
            self.assertIn(ERR_EMPTY_INPUT, [f.code for f in findings])

    def test_planted_corrupt_claims_registry_fails(self) -> None:
        """Malformed JSON claims.json fails with ERR_UNREADABLE_INPUT."""
        with tempfile.TemporaryDirectory() as tmpdir:
            tmp_root = Path(tmpdir)
            corrupt_claims = tmp_root / "corrupt_claims.json"
            corrupt_claims.write_text("{ broken", encoding="utf-8")

            _, _, findings = load_authoritative_claims(corrupt_claims)
            self.assertIn(ERR_UNREADABLE_INPUT, [f.code for f in findings])

    def test_planted_claims_registry_empty_classes_fails(self) -> None:
        """claims.json with empty classes array fails with ERR_EMPTY_INPUT."""
        with tempfile.TemporaryDirectory() as tmpdir:
            tmp_root = Path(tmpdir)
            empty_classes_claims = tmp_root / "empty_classes.json"
            empty_classes_claims.write_text("{\"classes\": []}", encoding="utf-8")

            _, _, findings = load_authoritative_claims(empty_classes_claims)
            self.assertIn(ERR_EMPTY_INPUT, [f.code for f in findings])


class TestCliEndToEndFailures(unittest.TestCase):
    """End-to-end CLI integration tests asserting non-zero exit codes on failure."""

    def test_cli_fails_on_nonexistent_bundle_arg(self) -> None:
        """CLI with --bundle pointing to nonexistent file exits 1."""
        cmd = [
            sys.executable,
            str(ROOT / "scripts/claim_proof_bundle_checker.py"),
            "--bundle",
            "nonexistent/file/path.bundle.json",
        ]
        result = subprocess.run(cmd, capture_output=True, text=True, cwd=str(ROOT))
        self.assertEqual(result.returncode, 1)
        self.assertIn("[FAIL]", result.stdout)
        self.assertIn(ERR_PROOF_BUNDLE_NOT_FOUND, result.stdout)

    def test_cli_fails_on_corrupt_bundle_arg(self) -> None:
        """CLI with --bundle pointing to corrupt file exits 1."""
        with tempfile.NamedTemporaryFile(suffix=".bundle.json", mode="w", delete=False) as f:
            f.write("{ corrupt json")
            f_path = f.name
        try:
            cmd = [
                sys.executable,
                str(ROOT / "scripts/claim_proof_bundle_checker.py"),
                "--bundle",
                f_path,
            ]
            result = subprocess.run(cmd, capture_output=True, text=True, cwd=str(ROOT))
            self.assertEqual(result.returncode, 1)
            self.assertIn("[FAIL]", result.stdout)
            self.assertIn(ERR_UNREADABLE_INPUT, result.stdout)
        finally:
            Path(f_path).unlink(missing_ok=True)


# ---------------------------------------------------------------------------
# Rework (review-606 findings F1-F7, orchestrator gate findings, fail-open scan)
# ---------------------------------------------------------------------------

SLO_EVIDENCE = ["operation_cost_row", "measurement_artifact", "environment_manifest"]
ZERO_DIGEST = "sha256:" + "0" * 64
FIXTURE_FILES = (
    "architecture/claims.json",
    "architecture/readiness_dimensions.json",
    "architecture/stable_id_resolution.json",
    "architecture/operation_cost_registry.toml",
    "registries/CLAIMS.md",
    "registries/SLOS.md",
    "registries/QUALIFICATION_LANES.md",
    "README.md",
)
_DROP = object()

DEFAULT_MEASUREMENT_DATA = {
    "schema": "fss.operation_cost_measurement.v1",
    "slo_id": "SLO-DETECT-001",
    "operation_id": "COST-DETECT-001",
    "generation": "gen-2026-09-01",
    "measurement_window": {
        "started_at": "2026-09-01T00:00:00Z",
        "finished_at": "2026-09-01T01:00:00Z",
    },
    "target": 100.0,
    "actual": 85.0,
}
DEFAULT_MEASUREMENT_BYTES = json.dumps(DEFAULT_MEASUREMENT_DATA).encode("utf-8")
DEFAULT_MEASUREMENT_DIGEST = compute_sha256(DEFAULT_MEASUREMENT_BYTES)
DEFAULT_MEASUREMENT_REL = "qualification-artifacts/meas.json"
DEFAULT_MEASUREMENT_ARTIFACT = {"path": DEFAULT_MEASUREMENT_REL, "digest": DEFAULT_MEASUREMENT_DIGEST}


def _known_classes() -> dict[str, list[str]]:
    known, _, findings = load_authoritative_claims(ROOT / "architecture/claims.json")
    assert not findings, findings
    return known


def make_bundle(**overrides: object) -> dict:
    """A fully valid SLO proof bundle; each negative test perturbs exactly one aspect."""
    data: dict = {
        "schema": "fss.proof_bundle.v1",
        "bundle_id": "BUNDLE-TEST-001",
        "claim_id": "SLO-DETECT-001",
        "claim_class": "slo",
        "supported_level": "achieved",
        "generation": "gen-2026-09-01",
        "status": "passed",
        "retained_evidence": list(SLO_EVIDENCE),
        "artifacts": [dict(DEFAULT_MEASUREMENT_ARTIFACT)],
    }
    if "objects" in overrides and "artifacts" not in overrides:
        data.pop("artifacts", None)
    for key, value in overrides.items():
        if value is _DROP:
            data.pop(key, None)
        else:
            data[key] = value
    return data


def seal(data: dict) -> dict:
    """Binds the canonical content digest over everything except the digest field itself."""
    sealed = {k: v for k, v in data.items() if k != "content_digest"}
    sealed["content_digest"] = compute_bundle_digest(sealed)
    return sealed


def write_json(path: Path, data: object) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(data), encoding="utf-8")
    return path


def verify(root: Path, data: dict, name: str = "b.bundle.json", **kwargs: object):
    path = write_json(root / name, data)
    kwargs.setdefault("known_classes", _known_classes())
    default_meas_path = root / DEFAULT_MEASUREMENT_REL
    if not default_meas_path.exists():
        for key in ("artifacts", "objects"):
            entries = data.get(key)
            if isinstance(entries, list):
                for e in entries:
                    if isinstance(e, dict) and e.get("path") == DEFAULT_MEASUREMENT_REL:
                        default_meas_path.parent.mkdir(parents=True, exist_ok=True)
                        default_meas_path.write_bytes(DEFAULT_MEASUREMENT_BYTES)
                        break
    return verify_proof_bundle(bundle_path=path, root=root, **kwargs)


def claim_table(*rows: str) -> str:
    return "| ID | Status | Proof root |\n|---|---|---|\n" + "".join(r + "\n" for r in rows)


def scan(root: Path, text: str, name: str = "table.md") -> list:
    md_file = root / name
    md_file.write_text(text, encoding="utf-8")
    return scan_markdown_claim_tables(md_file, root, _known_classes(), set())


def build_fixture_root(tmp: Path) -> Path:
    """A minimal copy of the real authority surfaces; it passes the audit unmodified."""
    root = tmp / "repo"
    for rel in FIXTURE_FILES:
        (root / rel).parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(ROOT / rel, root / rel)
    return root


def run_cli(*args: str) -> subprocess.CompletedProcess:
    cmd = [sys.executable, str(ROOT / "scripts/claim_proof_bundle_checker.py"), *args]
    return subprocess.run(cmd, capture_output=True, text=True, cwd=str(ROOT))


def make_receipt(status: str = "passed", command_status: str = "passed") -> dict:
    return {
        "schema": "fss.release_qualification_receipt.v1",
        "receiptId": "local:policy:0123456789abcdef",
        "laneId": "QL-POLICY-001",
        "sourceCommit": "git:0123456789abcdef",
        "sourceTree": "git-tree:0123456789abcdef",
        "siblingClosureDigest": "sha256:" + "1" * 64,
        "cargoLockDigest": None,
        "toolchain": "nightly-2026-09-01",
        "hostIdentity": "sha256:" + "2" * 64,
        "target": "Linux-x86_64",
        "features": [],
        "commands": [{"argv": ["python3", "x.py"], "status": command_status, "outputDigest": "sha256:" + "3" * 64}],
        "artifactManifestDigest": None,
        "startedAt": {"earliestNs": 1, "latestNs": 1, "clockBasis": "host-realtime"},
        "finishedAt": {"earliestNs": 2, "latestNs": 2, "clockBasis": "host-realtime"},
        "status": status,
    }


def codes(findings: list) -> list[str]:
    return [f.code for f in findings]


def error_codes(findings: list) -> list[str]:
    return [f.code for f in findings if f.severity == "error"]


class TestReworkHarnessControls(unittest.TestCase):
    """The helpers produce inputs that pass, so every negative below isolates one defect."""

    def test_helper_valid_bundle_passes(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            ok, findings, _ = verify(
                Path(tmpdir), seal(make_bundle()), expected_claim_id="SLO-DETECT-001", claim_level="achieved"
            )
            self.assertTrue(ok, [f.message for f in findings])

    def test_fixture_root_passes_audit_and_cli(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            root = build_fixture_root(Path(tmpdir))
            ok, findings, _ = audit_claim_proof_bundles(root)
            self.assertTrue(ok, [f.message for f in findings])
            result = run_cli("--root", str(root))
            self.assertEqual(result.returncode, 0, result.stdout + result.stderr)


class TestReview606F1BundleDigest(unittest.TestCase):
    """F1 (CRITICAL): the bundle content digest is mandatory and binds every other field."""

    def test_f1_bundle_without_content_digest_fails(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            ok, findings, _ = verify(Path(tmpdir), make_bundle())
            self.assertFalse(ok, "a proof bundle omitting its content digest must fail closed")
            self.assertIn(ERR_BUNDLE_DIGEST_MISMATCH, codes(findings))

    def test_f1_alternative_digest_fields_are_digested_payload(self) -> None:
        for injected in ("digest", "bundle_digest", "bundleDigest"):
            with self.subTest(field=injected), tempfile.TemporaryDirectory() as tmpdir:
                data = seal(make_bundle())
                data[injected] = "sha256:" + "a" * 64  # injected after sealing
                ok, findings, _ = verify(Path(tmpdir), data)
                self.assertFalse(ok, f"untracked '{injected}' field must not escape the content digest")
                self.assertIn(ERR_BUNDLE_DIGEST_MISMATCH, codes(findings))

    def test_f1_ambiguous_multiple_content_digests_fail(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            data = seal(make_bundle())
            data["contentDigest"] = ZERO_DIGEST
            ok, findings, _ = verify(Path(tmpdir), data)
            self.assertFalse(ok, "two competing content digest fields must fail closed")
            self.assertIn(ERR_BUNDLE_DIGEST_MISMATCH, codes(findings))


class TestReview606F2Artifacts(unittest.TestCase):
    """F2 (CRITICAL): every declared artifact is contained, present, a regular file, and digest-bound."""

    def test_f2_artifact_without_digest_fails(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            tmp = Path(tmpdir)
            (tmp / "present.bin").write_bytes(b"x")
            for art, expected in (
                ({"path": "nonexistent_file.bin"}, ERR_PROOF_BUNDLE_NOT_FOUND),
                ({"path": "present.bin"}, ERR_BUNDLE_DIGEST_MISMATCH),
            ):
                with self.subTest(artifact=art):
                    ok, findings, _ = verify(tmp, seal(make_bundle(artifacts=[art])))
                    self.assertFalse(ok, "an artifact without a digest must fail closed")
                    self.assertIn(expected, codes(findings))

    def test_f2_directory_artifact_fails(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            tmp = Path(tmpdir)
            (tmp / "sub_dir").mkdir()
            ok, findings, _ = verify(tmp, seal(make_bundle(artifacts=[{"path": "sub_dir", "digest": ZERO_DIGEST}])))
            self.assertFalse(ok, "a directory artifact must fail closed")
            self.assertIn(ERR_PROOF_BUNDLE_NOT_FOUND, codes(findings))

    def test_f2_absolute_artifact_path_fails(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            tmp = Path(tmpdir)
            art = tmp / "a.bin"
            art.write_bytes(b"payload")
            data = seal(make_bundle(artifacts=[{"path": str(art), "digest": compute_sha256(b"payload")}]))
            ok, findings, _ = verify(tmp, data)
            self.assertFalse(ok, "absolute artifact paths must be refused")
            self.assertIn(ERR_PROOF_BUNDLE_NOT_FOUND, codes(findings))

    def test_f2_traversal_artifact_path_fails(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            tmp = Path(tmpdir)
            root = tmp / "root"
            (root / "sub").mkdir(parents=True)
            (tmp / "outside.bin").write_bytes(b"outside")
            data = seal(make_bundle(artifacts=[{"path": "sub/../../outside.bin", "digest": compute_sha256(b"outside")}]))
            ok, findings, _ = verify(root, data)
            self.assertFalse(ok, "'..' artifact paths must be refused")
            self.assertIn(ERR_PROOF_BUNDLE_NOT_FOUND, codes(findings))

    def test_f2_symlink_escape_artifact_fails(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            tmp = Path(tmpdir)
            root = tmp / "root"
            root.mkdir()
            (tmp / "outside.bin").write_bytes(b"outside")
            (root / "link.bin").symlink_to(tmp / "outside.bin")
            data = seal(make_bundle(artifacts=[{"path": "link.bin", "digest": compute_sha256(b"outside")}]))
            ok, findings, _ = verify(root, data)
            self.assertFalse(ok, "an artifact resolving outside the root must be refused")
            self.assertIn(ERR_PROOF_BUNDLE_NOT_FOUND, codes(findings))

    def test_f2_evidence_bundle_uri_hint_objects_are_checked(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            tmp = Path(tmpdir)
            (tmp / "obj.bin").write_bytes(b"object bytes")
            obj = {"digest": ZERO_DIGEST, "role": "frame", "sizeBytes": 12, "retentionState": "local", "uriHint": "obj.bin"}
            ok, findings, _ = verify(tmp, seal(make_bundle(objects=[obj])))
            self.assertFalse(ok, "canonical evidence-bundle objects (uriHint) must be digest-checked")
            self.assertIn(ERR_BUNDLE_DIGEST_MISMATCH, codes(findings))

    def test_f2_objects_not_hidden_behind_artifacts(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            tmp = Path(tmpdir)
            (tmp / "good.bin").write_bytes(b"good")
            (tmp / "bad.bin").write_bytes(b"bad")
            data = seal(make_bundle(
                artifacts=[{"path": "good.bin", "digest": compute_sha256(b"good")}],
                objects=[{"digest": ZERO_DIGEST, "role": "r", "sizeBytes": 3, "retentionState": "local", "uriHint": "bad.bin"}],
            ))
            ok, findings, _ = verify(tmp, data)
            self.assertFalse(ok, "a non-empty 'artifacts' list must not hide 'objects'")
            self.assertIn(ERR_BUNDLE_DIGEST_MISMATCH, codes(findings))

    def test_f2_unverifiable_or_malformed_artifact_entries_fail(self) -> None:
        cases = {
            "remote_retention": {"digest": ZERO_DIGEST, "role": "r", "sizeBytes": 1, "retentionState": "remote", "uriHint": "s3://bucket/key"},
            "no_locator": {"digest": ZERO_DIGEST, "role": "r", "sizeBytes": 1, "retentionState": "local"},
            "non_object_entry": "some/file.bin",
            "unknown_retention_state": {"digest": ZERO_DIGEST, "role": "r", "sizeBytes": 1, "retentionState": "maybe", "uriHint": "x.bin"},
        }
        for label, entry in cases.items():
            with self.subTest(case=label), tempfile.TemporaryDirectory() as tmpdir:
                ok, findings, _ = verify(Path(tmpdir), seal(make_bundle(objects=[entry])))
                self.assertFalse(ok, f"artifact entry '{label}' cannot be verified and must fail closed")

    def test_f2_intentionally_omitted_object_is_explicit_not_a_failure(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            obj = {"digest": ZERO_DIGEST, "role": "r", "sizeBytes": 0, "retentionState": "intentionally_omitted", "uriHint": None}
            ok, findings, _ = verify(Path(tmpdir), seal(make_bundle(objects=[dict(DEFAULT_MEASUREMENT_ARTIFACT), obj])))
            self.assertTrue(ok, [f.message for f in findings])

    @unittest.skipIf(hasattr(os, "geteuid") and os.geteuid() == 0, "root ignores file permissions")
    def test_f2_unreadable_artifact_is_typed_finding_not_crash(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            tmp = Path(tmpdir)
            art = tmp / "locked.bin"
            art.write_bytes(b"secret-free payload")
            art.chmod(0)
            try:
                ok, findings, _ = verify(tmp, seal(make_bundle(artifacts=[{"path": "locked.bin", "digest": ZERO_DIGEST}])))
            finally:
                art.chmod(0o600)
            self.assertFalse(ok)
            self.assertIn(ERR_UNREADABLE_INPUT, codes(findings))


class TestReview606F3ClaimBinding(unittest.TestCase):
    """F3 (HIGH): a bundle must bind the exact claim that cites it."""

    def test_f3_mismatched_claim_id_fails(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            ok, findings, _ = verify(Path(tmpdir), seal(make_bundle(claim_id="SLO-COST-002")), expected_claim_id="SLO-DETECT-001")
            self.assertFalse(ok, "bundle claim_id differing from expected_claim_id must fail closed")
            self.assertIn(cpb.ERR_CLAIM_BINDING_MISMATCH, codes(findings))

    def test_f3_bundle_without_claim_id_fails(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            ok, findings, _ = verify(Path(tmpdir), seal(make_bundle(claim_id=_DROP)), expected_claim_id="SLO-DETECT-001")
            self.assertFalse(ok, "a bundle binding no claim cannot prove a specific claim")
            self.assertIn(cpb.ERR_CLAIM_BINDING_MISMATCH, codes(findings))

    def test_f3_markdown_row_cross_claim_substitution_fails(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            tmp = Path(tmpdir)
            write_json(tmp / "p/other.bundle.json", seal(make_bundle(claim_id="SLO-COST-002")))
            findings = scan(tmp, claim_table("| `SLO-DETECT-001` | achieved | `p/other.bundle.json` |"))
            self.assertTrue(findings, "a row citing another claim's bundle must fail")
            self.assertIn(cpb.ERR_CLAIM_BINDING_MISMATCH, codes(findings))

    def test_f3_promoted_row_without_id_column_fails(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            tmp = Path(tmpdir)
            write_json(tmp / "p/b.bundle.json", seal(make_bundle()))
            findings = scan(tmp, "| Status | Proof root |\n|---|---|\n| achieved | `p/b.bundle.json` |\n")
            self.assertTrue(findings, "a promoted row with no claim ID cannot be bound to its proof")
            self.assertIn(cpb.ERR_CLAIM_BINDING_MISMATCH, codes(findings))


class TestReview606F4LevelComparisons(unittest.TestCase):
    """F4 (HIGH): unknown levels/statuses fail closed; every promoted level needs proof."""

    def test_f4_unrecognized_bundle_statuses_fail(self) -> None:
        for status in ("rejected", "error", "aborted", "crashed", "", _DROP):
            with self.subTest(status=status), tempfile.TemporaryDirectory() as tmpdir:
                ok, findings, _ = verify(Path(tmpdir), seal(make_bundle(status=status)), claim_level="achieved")
                self.assertFalse(ok, f"bundle status {status!r} must not be accepted as passing")

    def test_f4_unknown_claim_level_fails(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            ok, findings, _ = verify(Path(tmpdir), seal(make_bundle()), claim_level="certified")
            self.assertFalse(ok, "an unrecognized claim level must not default to a low rank")
            self.assertIn(cpb.ERR_UNRECOGNIZED_STATE, codes(findings))

    def test_f4_unknown_or_missing_supported_level_fails(self) -> None:
        for level in ("unsupported", "none", _DROP):
            with self.subTest(level=level), tempfile.TemporaryDirectory() as tmpdir:
                ok, findings, _ = verify(Path(tmpdir), seal(make_bundle(supported_level=level)), claim_level="specified")
                self.assertFalse(ok, f"supported level {level!r} must not default to a low rank")

    def test_f4_supported_level_whitespace_is_normalized(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            ok, findings, _ = verify(Path(tmpdir), seal(make_bundle(supported_level=" Achieved ")), claim_level="achieved")
            self.assertTrue(ok, [f.message for f in findings])

    def test_f4_implemented_levels_without_proof_fail(self) -> None:
        for status in ("implemented", "reference_implemented", "positively_verified", "qualified"):
            with self.subTest(status=status), tempfile.TemporaryDirectory() as tmpdir:
                findings = scan(Path(tmpdir), claim_table(f"| SLO-1 | {status} | - |"))
                self.assertIn(ERR_CLAIM_LEVEL_EXCEEDED, codes(findings), f"'{status}' requires retained proof")

    def test_f4_implemented_row_citing_draft_bundle_fails(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            tmp = Path(tmpdir)
            write_json(tmp / "p/b.bundle.json", seal(make_bundle(claim_id="SLO-1", supported_level="draft")))
            findings = scan(tmp, claim_table("| SLO-1 | implemented | `p/b.bundle.json` |"))
            self.assertIn(ERR_CLAIM_LEVEL_EXCEEDED, codes(findings))

    def test_f4_unrecognized_markdown_status_fails(self) -> None:
        for status in ("certified", "complete", ""):
            with self.subTest(status=status), tempfile.TemporaryDirectory() as tmpdir:
                findings = scan(Path(tmpdir), claim_table(f"| SLO-1 | {status} | - |"))
                self.assertTrue(findings, f"status {status!r} must not be silently accepted")
                self.assertIn(cpb.ERR_UNRECOGNIZED_STATE, codes(findings))


class TestReview606F5MarkdownSurfaces(unittest.TestCase):
    """F5 (HIGH): markdown formatting cannot hide claims; claim surfaces cannot vanish."""

    def test_f5_emphasized_status_is_recognized(self) -> None:
        for cell in ("**achieved**", "*qualified*", "__verified__", "_achieved_", "<b>achieved</b>", "~~achieved~~"):
            with self.subTest(cell=cell), tempfile.TemporaryDirectory() as tmpdir:
                findings = scan(Path(tmpdir), claim_table(f"| SLO-1 | {cell} | - |"))
                self.assertIn(ERR_CLAIM_LEVEL_EXCEEDED, codes(findings), f"{cell} must be recognized as promoted")

    def test_f5_borderless_gfm_table_is_scanned(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            findings = scan(Path(tmpdir), "ID | Status | Proof root\n--- | --- | ---\nSLO-1 | achieved | -\n")
            self.assertIn(ERR_CLAIM_LEVEL_EXCEEDED, codes(findings))
            tables = parse_markdown_tables("ID | Status | Proof root\n--- | --- | ---\nSLO-1 | achieved | -\n")
            self.assertEqual(tables, [(["ID", "Status", "Proof root"], [["SLO-1", "achieved", "-"]])])

    def test_f5_tilde_fence_hides_nothing_and_is_skipped(self) -> None:
        text = "~~~\n| ID | Status | Proof root |\n|---|---|---|\n| SLO-1 | achieved | - |\n~~~\n"
        self.assertEqual(parse_markdown_tables(text), [])

    def test_f5_missing_claim_surface_fails_audit(self) -> None:
        for rel in ("registries/SLOS.md", "registries/QUALIFICATION_LANES.md", "README.md"):
            with self.subTest(surface=rel), tempfile.TemporaryDirectory() as tmpdir:
                root = build_fixture_root(Path(tmpdir))
                (root / rel).unlink()
                ok, findings, _ = audit_claim_proof_bundles(root)
                self.assertFalse(ok, f"missing {rel} must fail the audit")
                self.assertTrue(any(f.file == rel for f in findings), [(f.file, f.message) for f in findings])

    def test_f5_slos_without_claim_table_fails(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            root = build_fixture_root(Path(tmpdir))
            slos = root / "registries/SLOS.md"
            slos.write_text(slos.read_text(encoding="utf-8").replace("| Status | Proof root |", "| State | Evidence |"), encoding="utf-8")
            ok, findings, _ = audit_claim_proof_bundles(root)
            self.assertFalse(ok, "SLOS.md whose claim table cannot be recognized must fail, not audit zero rows")
            self.assertIn(ERR_EMPTY_INPUT, codes(findings))


class TestReview606F6Generations(unittest.TestCase):
    """F6 (MEDIUM): 'latest' tags, case-variant tombstones, nested generations, and expiry."""

    def test_f6_latest_tag_variants(self) -> None:
        for alias in ("model:latest", "latest/v1", "v1:latest", "model@latest", "weights/latest"):
            with self.subTest(alias=alias):
                self.assertTrue(is_latest_generation(alias))
        for benign in ("gen-2026-09-01", "lateststyle-001", "v1"):
            with self.subTest(benign=benign):
                self.assertFalse(is_latest_generation(benign))

    def test_f6_tombstone_match_is_case_and_whitespace_insensitive(self) -> None:
        for value in ("gen-tombstone-01", " GEN-TOMBSTONE-01 "):
            with self.subTest(value=value), tempfile.TemporaryDirectory() as tmpdir:
                ok, findings, _ = verify(Path(tmpdir), seal(make_bundle(generation=value)), tombstoned_ids={"GEN-TOMBSTONE-01"})
                self.assertFalse(ok, "a case/whitespace variant of a tombstoned ID must fail closed")
                self.assertIn(ERR_STALE_GENERATION, codes(findings))

    def test_f6_generation_fields_outside_top_level_list_are_checked(self) -> None:
        cases = {
            "environment": {"environment": {"modelGeneration": "model:latest"}},
            "device_generation": {"device_generation": "latest"},
            "adapter_generation": {"adapter_generation": "latest"},
            "config_generation": {"config_generation": "latest"},
            "nested_matrix": {"platform_matrix": [{"model_generation_id": "latest"}]},
        }
        for label, extra in cases.items():
            with self.subTest(case=label), tempfile.TemporaryDirectory() as tmpdir:
                ok, findings, _ = verify(Path(tmpdir), seal(make_bundle(**extra)))
                self.assertFalse(ok, f"'latest' in {label} must be refused")
                self.assertIn(ERR_STALE_GENERATION, codes(findings))

    def test_f6_expiry_timestamps_are_enforced(self) -> None:
        now = datetime(2026, 9, 12, tzinfo=timezone.utc)
        for key in ("expires_at", "expiresAt", "valid_until", "validUntil"):
            with self.subTest(key=key), tempfile.TemporaryDirectory() as tmpdir:
                ok, findings, _ = verify(Path(tmpdir), seal(make_bundle(**{key: "2026-01-01T00:00:00Z"})), now=now)
                self.assertFalse(ok, f"a bundle past its {key} must fail closed")
                self.assertIn(ERR_STALE_GENERATION, codes(findings))
        with tempfile.TemporaryDirectory() as tmpdir:
            ok, findings, _ = verify(Path(tmpdir), seal(make_bundle(expires_at="2027-01-01T00:00:00Z")), now=now)
            self.assertTrue(ok, [f.message for f in findings])

    def test_f6_malformed_expiry_markers_fail(self) -> None:
        for extra in ({"expires_at": "soon"}, {"expires_at": 12}, {"is_expired": "true"}, {"is_expired": 1}):
            with self.subTest(extra=extra), tempfile.TemporaryDirectory() as tmpdir:
                ok, findings, _ = verify(Path(tmpdir), seal(make_bundle(**extra)))
                self.assertFalse(ok, f"indeterminate expiry {extra} must not be treated as unexpired")


class TestReview606F7ReceiptsAndVacuity(unittest.TestCase):
    """F7 (MEDIUM): receipts are inspected, the live pass is not vacuous, CLI failures are typed."""

    def test_f7_non_passing_receipt_fails_closed_when_verified(self) -> None:
        for status in ("failed", "partial", "interrupted"):
            with self.subTest(status=status), tempfile.TemporaryDirectory() as tmpdir:
                tmp = Path(tmpdir)
                path = write_json(tmp / "qualification-artifacts/local/run1/qualification-receipt.json", make_receipt(status))
                ok, findings, _ = verify_proof_bundle(path, tmp)
                self.assertFalse(ok, f"a '{status}' qualification receipt must fail closed")

    def test_f7_receipt_claiming_pass_with_failed_command_fails(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            tmp = Path(tmpdir)
            path = write_json(tmp / "qualification-receipt.json", make_receipt("passed", command_status="failed"))
            ok, findings, _ = verify_proof_bundle(path, tmp)
            self.assertFalse(ok, "a 'passed' receipt containing a failed command is self-contradictory")

    def test_f7_receipt_cannot_bind_a_claim(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            tmp = Path(tmpdir)
            write_json(tmp / "qualification-artifacts/r/qualification-receipt.json", make_receipt("passed"))
            findings = scan(tmp, claim_table("| SLO-1 | achieved | `qualification-artifacts/r/qualification-receipt.json` |"))
            self.assertIn(cpb.ERR_CLAIM_BINDING_MISMATCH, codes(findings))

    def test_f7_audit_inspects_qualification_receipts(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            root = build_fixture_root(Path(tmpdir))
            rel = "qualification-artifacts/local/run1/qualification-receipt.json"
            write_json(root / rel, make_receipt("failed"))
            ok, findings, summary = audit_claim_proof_bundles(root)
            self.assertEqual(summary["receipts_inspected"], 1)
            self.assertEqual(summary["receipts_nonpassing"], 1)
            warned = [f for f in findings if f.file == rel and f.code == cpb.WARN_NONPASSING_RECEIPT]
            self.assertEqual(len(warned), 1, [(f.code, f.file) for f in findings])
            self.assertEqual(warned[0].severity, "warning")
            self.assertTrue(ok, "an uncited failed local receipt is reported, not a claim violation")

    def test_f7_corrupt_or_malformed_receipt_fails_audit(self) -> None:
        for label, payload in (("corrupt", "{ nope"), ("missing_fields", json.dumps({"schema": "fss.release_qualification_receipt.v1", "status": "passed"}))):
            with self.subTest(case=label), tempfile.TemporaryDirectory() as tmpdir:
                root = build_fixture_root(Path(tmpdir))
                path = root / "qualification-artifacts/local/run1/qualification-receipt.json"
                path.parent.mkdir(parents=True)
                path.write_text(payload, encoding="utf-8")
                ok, findings, _ = audit_claim_proof_bundles(root)
                self.assertFalse(ok, f"{label} receipt under the retention root must fail closed")

    def test_f7_live_repo_pass_is_not_vacuous(self) -> None:
        ok, findings, summary = audit_claim_proof_bundles(ROOT)
        self.assertTrue(ok, [f.message for f in findings])
        self.assertIn("registries/SLOS.md", summary["claim_surfaces_scanned"])
        slo_rows = sum(1 for line in (ROOT / "registries/SLOS.md").read_text(encoding="utf-8").splitlines() if line.startswith("| `SLO-"))
        self.assertGreater(slo_rows, 0)
        self.assertGreaterEqual(summary["claim_rows_evaluated"], slo_rows)
        for key in ("promoted_claim_rows", "bundles_checked", "receipts_inspected", "receipts_nonpassing"):
            self.assertIn(key, summary)

    def test_f7_cli_claims_flag_failures_exit_nonzero(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            bad = Path(tmpdir) / "claims.json"
            for payload, code in (("{ broken", ERR_UNREADABLE_INPUT), ("", ERR_EMPTY_INPUT), ('{"classes": []}', ERR_EMPTY_INPUT)):
                with self.subTest(payload=payload):
                    bad.write_text(payload, encoding="utf-8")
                    result = run_cli("--claims", str(bad))
                    self.assertEqual(result.returncode, 1, result.stdout)
                    self.assertIn(code, result.stdout)

    def test_f7_cli_repo_wide_failure_exits_nonzero(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            root = build_fixture_root(Path(tmpdir))
            slos = root / "registries/SLOS.md"
            text = slos.read_text(encoding="utf-8")
            first = next(line for line in text.splitlines() if line.startswith("| `SLO-"))
            slos.write_text(text.replace(first, first.replace("| target | - |", "| achieved | - |")), encoding="utf-8")
            result = run_cli("--root", str(root), "--json")
            self.assertEqual(result.returncode, 1, result.stdout)
            report = json.loads(result.stdout)
            self.assertIn(ERR_CLAIM_LEVEL_EXCEEDED, [f["code"] for f in report["findings"]])


class TestGateTombstoneIndex(unittest.TestCase):
    """Gate B1: the tombstone index must load or the run fails with a typed code and non-zero exit."""

    def _run_with_index(self, payload: bytes | None) -> subprocess.CompletedProcess:
        with tempfile.TemporaryDirectory() as tmpdir:
            root = build_fixture_root(Path(tmpdir))
            index = root / "architecture/stable_id_resolution.json"
            if payload is None:
                index.unlink()
            else:
                index.write_bytes(payload)
            return run_cli("--root", str(root))

    def test_gate_corrupt_index_fails_run(self) -> None:
        result = self._run_with_index(b"{ not json")
        self.assertNotEqual(result.returncode, 0, result.stdout)
        self.assertIn(getattr(cpb, "ERR_TOMBSTONE_INDEX_UNAVAILABLE", "<missing>"), result.stdout)

    def test_gate_empty_index_fails_run(self) -> None:
        for payload in (b"", b"   \n", b"{}", b'{"schema": "fss.stable_id_resolution.v1", "resolutions": []}'):
            with self.subTest(payload=payload):
                result = self._run_with_index(payload)
                self.assertNotEqual(result.returncode, 0, result.stdout)
                self.assertIn(getattr(cpb, "ERR_TOMBSTONE_INDEX_UNAVAILABLE", "<missing>"), result.stdout)

    def test_gate_missing_or_wrong_schema_index_fails_run(self) -> None:
        for payload in (None, b'{"schema": "fss.other.v1", "resolutions": [{"legacyId": "GOAL-001"}]}', b"[1, 2]", b"\xff\xfe\x00"):
            with self.subTest(payload=payload):
                result = self._run_with_index(payload)
                self.assertNotEqual(result.returncode, 0, result.stdout)
                self.assertIn(getattr(cpb, "ERR_TOMBSTONE_INDEX_UNAVAILABLE", "<missing>"), result.stdout)

    def test_gate_index_failure_also_fails_single_bundle_mode(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            root = build_fixture_root(Path(tmpdir))
            write_json(root / "p/b.bundle.json", seal(make_bundle()))
            (root / "architecture/stable_id_resolution.json").write_text("{ nope", encoding="utf-8")
            result = run_cli("--root", str(root), "--bundle", "p/b.bundle.json")
            self.assertNotEqual(result.returncode, 0, result.stdout)

    def test_gate_tombstones_from_repository_index_are_enforced(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            root = build_fixture_root(Path(tmpdir))
            index_path = root / "architecture/stable_id_resolution.json"
            index = json.loads(index_path.read_text(encoding="utf-8"))
            index["resolutions"].append({
                "legacyId": "SLO-OLD-001", "title": "Retired objective", "canonicalId": "SLO-OLD-001",
                "disposition": "tombstoned", "status": "tombstoned", "titleDigest": ZERO_DIGEST,
            })
            index_path.write_text(json.dumps(index), encoding="utf-8")
            write_json(root / "qualification-artifacts/p/x.bundle.json", seal(make_bundle(generation="slo-old-001")))
            ok, findings, _ = audit_claim_proof_bundles(root)
            self.assertFalse(ok, "a bundle bound to a tombstoned ID from the stable-ID index must fail")
            self.assertIn(ERR_STALE_GENERATION, codes(findings))


class _ExplodingPartsPath(type(Path())):
    """A path whose .parts raises: guards must surface this, never silently skip the check."""

    @property
    def parts(self):  # type: ignore[override]
        raise RuntimeError("parts unavailable")


class TestGateNoSilentGuards(unittest.TestCase):
    """Gate B2/B3: no guard skips its check; only decode errors map to ERR_UNREADABLE_INPUT."""

    def test_gate_traversal_guard_cannot_be_skipped(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            tmp = Path(tmpdir)
            (tmp / "sub").mkdir()
            write_json(tmp / "b.bundle.json", seal(make_bundle()))
            try:
                ok, _, _ = verify_proof_bundle(_ExplodingPartsPath("sub/../b.bundle.json"), tmp, known_classes=_known_classes())
            except RuntimeError:
                return  # surfaced loudly: acceptable
            self.assertFalse(ok, "the '..' guard was skipped and the bundle passed")

    def test_gate_bundle_decode_errors_are_typed(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            tmp = Path(tmpdir)
            for payload in (b"\xff\xfe not utf8", b"{ broken"):
                with self.subTest(payload=payload):
                    path = tmp / "x.bundle.json"
                    path.write_bytes(payload)
                    ok, findings, _ = verify_proof_bundle(path, tmp)
                    self.assertFalse(ok)
                    self.assertIn(ERR_UNREADABLE_INPUT, codes(findings))

    def test_gate_claims_decode_errors_are_typed(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            path = Path(tmpdir) / "claims.json"
            path.write_bytes(b"\xff\xfe not utf8")
            _, _, findings = load_authoritative_claims(path)
            self.assertIn(ERR_UNREADABLE_INPUT, codes(findings))

    def test_gate_internal_faults_are_not_mislabelled_as_input_errors(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            tmp = Path(tmpdir)
            claims = write_json(tmp / "claims.json", {"classes": [{"id": "slo", "requiredEvidence": ["x"]}], "prohibited": []})
            bundle = write_json(tmp / "b.bundle.json", seal(make_bundle()))
            known = _known_classes()
            with mock.patch.object(cpb.json, "loads", side_effect=RuntimeError("internal fault")):
                with self.assertRaises(RuntimeError):
                    load_authoritative_claims(claims)
                with self.assertRaises(RuntimeError):
                    verify_proof_bundle(bundle, tmp, known_classes=known)


class TestFailOpenScan(unittest.TestCase):
    """Other silent defaults found by scanning the whole checker."""

    def test_scan_claim_class_without_valid_required_evidence_fails(self) -> None:
        for entry in ({"id": "slo"}, {"id": "slo", "requiredEvidence": "x"}, {"id": "slo", "requiredEvidence": []}, {"id": "slo", "requiredEvidence": [1]}):
            with self.subTest(entry=entry), tempfile.TemporaryDirectory() as tmpdir:
                path = write_json(Path(tmpdir) / "claims.json", {"classes": [entry], "prohibited": ["p"]})
                _, _, findings = load_authoritative_claims(path)
                self.assertTrue(findings, f"class {entry} would require no evidence")

    def test_scan_duplicate_claim_class_fails(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            path = write_json(Path(tmpdir) / "claims.json", {"classes": [{"id": "slo", "requiredEvidence": ["a"]}, {"id": "slo", "requiredEvidence": ["b"]}], "prohibited": ["p"]})
            _, _, findings = load_authoritative_claims(path)
            self.assertTrue(findings, "a duplicate class silently overwrote its first definition")

    def test_scan_missing_or_malformed_prohibited_list_fails(self) -> None:
        for extra in ({}, {"prohibited": "x"}, {"prohibited": [1]}):
            with self.subTest(extra=extra), tempfile.TemporaryDirectory() as tmpdir:
                path = write_json(Path(tmpdir) / "claims.json", {"classes": [{"id": "slo", "requiredEvidence": ["a"]}], **extra})
                _, _, findings = load_authoritative_claims(path)
                self.assertTrue(findings, "prohibited promotions silently became an empty set")

    def test_scan_bundle_without_claim_class_fails(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            ok, findings, _ = verify(Path(tmpdir), seal(make_bundle(claim_class=_DROP)))
            self.assertFalse(ok, "without a claim class, required evidence is never checked")
            self.assertIn(ERR_INVALID_CLAIM_CLASS, codes(findings))

    def test_scan_missing_class_registry_fails(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            ok, findings, _ = verify(Path(tmpdir), seal(make_bundle()), known_classes=None)
            self.assertFalse(ok, "without a class registry, required evidence is never checked")
            self.assertIn(ERR_INVALID_CLAIM_CLASS, codes(findings))

    def test_scan_malformed_retained_evidence_is_typed_finding(self) -> None:
        for value in ([{"a": 1}], "operation_cost_row", [1, 2]):
            with self.subTest(value=value), tempfile.TemporaryDirectory() as tmpdir:
                ok, findings, _ = verify(Path(tmpdir), seal(make_bundle(retained_evidence=value)))
                self.assertFalse(ok)
                self.assertIn(ERR_CLAIM_LEVEL_EXCEEDED, codes(findings))

    def test_scan_mandatory_authority_file_that_is_a_directory_fails(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            root = build_fixture_root(Path(tmpdir))
            target = root / "architecture/readiness_dimensions.json"
            target.unlink()
            target.mkdir()
            (target / "filler").write_text("x", encoding="utf-8")
            ok, findings, _ = audit_claim_proof_bundles(root)
            self.assertFalse(ok, "a directory is not an authority file")

    def test_scan_corrupt_or_drifted_readiness_registry_fails(self) -> None:
        for payload in ("{ broken", json.dumps({"schema": "fss.readiness_dimensions.v2", "states": []}),
                        json.dumps({"schema": "fss.readiness_dimensions.v2", "states": ["absent", "certified"]})):
            with self.subTest(payload=payload), tempfile.TemporaryDirectory() as tmpdir:
                root = build_fixture_root(Path(tmpdir))
                (root / "architecture/readiness_dimensions.json").write_text(payload, encoding="utf-8")
                ok, findings, _ = audit_claim_proof_bundles(root)
                self.assertFalse(ok, "a corrupt or drifted readiness vocabulary must fail closed")

    def test_scan_markdown_with_invalid_utf8_is_typed_finding(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            md = Path(tmpdir) / "bad.md"
            md.write_bytes(b"| ID | Status |\n|---|---|\n| X \xff | achieved |\n")
            findings = scan_markdown_claim_tables(md, Path(tmpdir), {}, set())
            self.assertIn(ERR_UNREADABLE_INPUT, codes(findings))

    @unittest.skipIf(hasattr(os, "geteuid") and os.geteuid() == 0, "root ignores directory permissions")
    def test_scan_unreadable_retention_directory_fails(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            root = build_fixture_root(Path(tmpdir))
            locked = root / "qualification-artifacts/local/locked"
            locked.mkdir(parents=True)
            write_json(locked / "x.bundle.json", make_bundle())
            locked.chmod(0)
            try:
                ok, findings, _ = audit_claim_proof_bundles(root)
            finally:
                locked.chmod(0o700)
            self.assertFalse(ok, "an unreadable retention directory was silently skipped")
            self.assertIn(ERR_UNREADABLE_INPUT, codes(findings))

    def test_scan_failed_bundles_are_not_counted_as_verified(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            root = build_fixture_root(Path(tmpdir))
            write_json(root / "qualification-artifacts/p/x.bundle.json", make_bundle())  # unsealed
            ok, _, summary = audit_claim_proof_bundles(root)
            self.assertFalse(ok)
            self.assertEqual(summary["verified_bundles_count"], 0)

    def test_scan_symlinked_citation_escaping_root_fails(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            tmp = Path(tmpdir)
            root = tmp / "root"
            root.mkdir()
            write_json(tmp / "outside.bundle.json", seal(make_bundle(claim_id="SLO-1")))
            (root / "link.bundle.json").symlink_to(tmp / "outside.bundle.json")
            findings = scan(root, claim_table("| SLO-1 | achieved | `link.bundle.json` |"))
            self.assertIn(ERR_PROOF_BUNDLE_NOT_FOUND, codes(findings))

    def test_scan_receipt_constants_match_schema(self) -> None:
        schema = json.loads((ROOT / "schemas/release_qualification_receipt.v1.json").read_text(encoding="utf-8"))
        self.assertEqual(cpb.QUALIFICATION_RECEIPT_SCHEMA, schema["properties"]["schema"]["const"])
        self.assertEqual(tuple(cpb.RECEIPT_REQUIRED_FIELDS), tuple(schema["required"]))
        self.assertEqual(frozenset(cpb.RECEIPT_STATUSES), frozenset(schema["properties"]["status"]["enum"]))


class TestAtomicReceiptWritingAndCorruptReceiptNaming(unittest.TestCase):
    """fss-1geb3: atomic receipt write prevents partial reads; corrupt receipt errors name the file."""

    def test_corrupt_receipt_error_names_the_file(self) -> None:
        """The claim checker's corrupt-receipt error messages must name the receipt file."""
        with tempfile.TemporaryDirectory() as tmpdir:
            root = build_fixture_root(Path(tmpdir))
            rel = "qualification-artifacts/local/run1/qualification-receipt.json"
            receipt_file = root / rel
            receipt_file.parent.mkdir(parents=True, exist_ok=True)

            # 1. Truncated/corrupt JSON
            receipt_file.write_text('{"schema": "fss.release_qualification_receipt.v1", "receiptId":', encoding="utf-8")
            findings, status = cpb.inspect_qualification_receipt(receipt_file, root)
            self.assertIsNone(status)
            self.assertTrue(len(findings) > 0)
            self.assertIn(cpb.ERR_UNREADABLE_INPUT, codes(findings))
            self.assertTrue(any(rel in f.message for f in findings), [(f.code, f.message) for f in findings])

            # 2. Corrupt schema
            receipt_file.write_text(json.dumps({"schema": "fss.corrupted_schema.v9", "status": "passed"}), encoding="utf-8")
            findings, status = cpb.inspect_qualification_receipt(receipt_file, root)
            self.assertIsNone(status)
            self.assertIn(cpb.ERR_UNRECOGNIZED_STATE, codes(findings))
            self.assertTrue(any(rel in f.message for f in findings), [(f.code, f.message) for f in findings])

            # 3. Missing required fields (corrupt receipt structure)
            receipt_file.write_text(json.dumps({"schema": "fss.release_qualification_receipt.v1", "status": "passed"}), encoding="utf-8")
            findings, status = cpb.inspect_qualification_receipt(receipt_file, root)
            self.assertTrue(any(rel in f.message for f in findings), [(f.code, f.message) for f in findings])

    def test_planted_negative_truncated_mid_write_proves_reader_isolation(self) -> None:
        """Planted-negative test: truncating a receipt mid-write in-place causes readers to observe
        a corrupt receipt naming the file, whereas atomic writing guarantees readers see either the
        old or the new complete receipt, never a partial/corrupt receipt.
        """
        with tempfile.TemporaryDirectory() as tmpdir:
            root = build_fixture_root(Path(tmpdir))
            rel = "qualification-artifacts/local/run1/qualification-receipt.json"
            receipt_file = root / rel
            receipt_file.parent.mkdir(parents=True, exist_ok=True)

            old_receipt = make_receipt("passed")
            new_receipt = make_receipt("passed")
            new_receipt["receiptId"] = "local:policy:new_receipt_001"

            # Write initial complete receipt
            cpb.write_qualification_receipt(receipt_file, old_receipt)
            findings, status = cpb.inspect_qualification_receipt(receipt_file, root)
            self.assertEqual(status, "passed")
            self.assertEqual(len(findings), 0)

            # Planted negative: non-atomic in-place write truncated mid-write
            # Simulates what qualify.sh previously did: opening output_path directly and writing partial bytes
            new_bytes = (json.dumps(new_receipt, indent=2) + "\n").encode("utf-8")
            truncated_len = len(new_bytes) // 3
            with open(receipt_file, "wb") as f:
                f.write(new_bytes[:truncated_len])
                f.flush()

            # Concurrent reader inspecting the file during/after non-atomic partial write sees corruption
            corrupt_findings, corrupt_status = cpb.inspect_qualification_receipt(receipt_file, root)
            self.assertIsNone(corrupt_status)
            self.assertTrue(any(f.code == cpb.ERR_UNREADABLE_INPUT for f in corrupt_findings))
            self.assertTrue(any(rel in f.message for f in corrupt_findings), "Corrupt receipt error must name file")

            # Restore old receipt and demonstrate atomic write isolation
            cpb.write_qualification_receipt(receipt_file, old_receipt)

    def test_write_qualification_receipt_mid_write_truncation_preserves_old_receipt(self) -> None:
        """write_qualification_receipt must preserve existing receipt and clean up temp files when truncated mid-write."""
        with tempfile.TemporaryDirectory() as tmpdir:
            root = build_fixture_root(Path(tmpdir))
            rel = "qualification-artifacts/local/run1/qualification-receipt.json"
            receipt_file = root / rel
            receipt_file.parent.mkdir(parents=True, exist_ok=True)
            old_receipt = make_receipt("passed")
            new_receipt = make_receipt("passed")
            new_receipt["receiptId"] = "local:policy:new_receipt_001"
            cpb.write_qualification_receipt(receipt_file, old_receipt)

            original_open = os.fdopen
            def crashing_fdopen(*args, **kwargs):
                handle = original_open(*args, **kwargs)
                original_write = handle.write
                def truncated_write(data):
                    original_write(data[:len(data) // 3])
                    handle.flush()
                    raise OSError("Simulated disk full / process crash mid-write")
                handle.write = truncated_write
                return handle

            with mock.patch("os.fdopen", side_effect=crashing_fdopen):
                with self.assertRaises(OSError):
                    cpb.write_qualification_receipt(receipt_file, new_receipt)

            # Reader must see intact old receipt, never a corrupt/partial receipt
            findings, status = cpb.inspect_qualification_receipt(receipt_file, root)
            self.assertEqual(status, "passed")
            self.assertEqual(len(findings), 0)
            data, _ = cpb._read_json_document(receipt_file, rel, "qualification receipt")
            self.assertIsNotNone(data)
            self.assertEqual(data["receiptId"], old_receipt["receiptId"])

            # Aborted temp file must be unlinked
            temp_files = list(receipt_file.parent.glob(".*.tmp.*"))
            self.assertEqual(temp_files, [], "write_qualification_receipt must clean up temp files on write failure")

    def test_test_suite_does_not_use_colliding_static_temp_file(self) -> None:
        """Tests must not hardcode static temp filenames like .tmp.simulated that collide in parallel runs."""
        test_file_lines = (ROOT / "tests/test_claim_proof_bundle_checker.py").read_text(encoding="utf-8").splitlines()
        forbidden = f".tmp.{'simulated'}"
        matching = [line for line in test_file_lines if forbidden in line and "forbidden" not in line and "def test_" not in line and "Tests must not" not in line]
        self.assertEqual(
            matching,
            [],
            f"test_claim_proof_bundle_checker.py hardcodes a static temporary filename which collides across concurrent runs: {matching}",
        )

    def test_release_qualify_writes_build_receipt_atomically(self) -> None:
        """scripts/release_qualify.sh must route build.json and every digest-bound receipt output
        through the shared atomic writer instead of an inline copy or a '>' redirection.
        (build_release needs cargo, so the write behaviour itself is proven through the shared
        `capture`/`write_json_atomic` entry points in TestSharedAtomicWriter.)"""
        script_text = (ROOT / "scripts/release_qualify.sh").read_text(encoding="utf-8")
        self.assertNotIn("Path(sys.argv[1]).write_text(", script_text)
        self.assertNotIn("tempfile.mkstemp", script_text, "release_qualify.sh must not carry its own atomic writer copy")
        self.assertIn("from qualification_receipt import write_json_atomic", script_text)
        self.assertNotRegex(script_text, r'>\s*"\$RECEIPT_DIR/', "receipt outputs must not be written in place with '>'")
        for name in ("cargo-metadata.json", "smoke-help.txt", "capabilities.json", "repository-manifest-audit.txt"):
            self.assertIn(f'capture --output "$RECEIPT_DIR/{name}"', script_text.replace("--merge-stderr ", ""), name)

    def test_qualify_finalize_handles_truncated_commands_record(self) -> None:
        """A partial (truncated) commands.jsonl line must not crash the real qualify.sh finalize
        path: it is recorded as a failed command and the receipt is still written."""
        self.assertIn("handle.flush()", (ROOT / "scripts/qualify.sh").read_text(encoding="utf-8"), "append_record must flush and fsync")
        with tempfile.TemporaryDirectory() as tmpdir:
            run_dir = Path(tmpdir) / "run"
            valid = json.dumps(_record_row("policy")) + "\n"
            result = run_qualify_finalize(run_dir, records=(valid + '{"id":"x","sta').encode("utf-8"))
            receipt = json.loads((run_dir / "qualification-receipt.json").read_text(encoding="utf-8"))
            self.assertEqual(receipt["status"], "failed", result.stderr)
            self.assertEqual([c["argv"] for c in receipt["commands"]], [["python3", "policy.py"], ["corrupt_record"]])
            self.assertNotEqual(result.returncode, 0)

    def test_written_receipt_has_standard_permissions(self) -> None:
        """Qualification receipts written by write_qualification_receipt must have standard permissions (0644)."""
        with tempfile.TemporaryDirectory() as tmpdir:
            receipt_file = Path(tmpdir) / "qualification-receipt.json"
            cpb.write_qualification_receipt(receipt_file, make_receipt("passed"))
            mode = receipt_file.stat().st_mode & 0o777
            self.assertEqual(mode, 0o644, f"Receipt file permissions should be 0644, got {oct(mode)}")

    def test_qualify_script_atomic_receipt_contract(self) -> None:
        """There is exactly one atomic writer: qualify.sh, release_qualify.sh and the checker all
        delegate to scripts/qualification_receipt.py (behaviour is proven in
        TestQualifyFinalizeBehaviour; this pins that no second copy can drift back in)."""
        import qualification_receipt

        self.assertIs(cpb.write_qualification_receipt, qualification_receipt.write_qualification_receipt)
        for rel in ("scripts/qualify.sh", "scripts/release_qualify.sh", "scripts/claim_proof_bundle_checker.py"):
            text = (ROOT / rel).read_text(encoding="utf-8")
            for token in ("mkstemp(", "os.replace(", ".write_text(json.dumps"):
                self.assertNotIn(token, text, f"{rel} carries its own receipt writer ({token})")
        self.assertIn('scripts/qualification_receipt.py" finalize', (ROOT / "scripts/qualify.sh").read_text(encoding="utf-8"))


# --- fss-1geb3: behavioural tests of the shipped receipt write paths --------------------------
#
# The finalize tests extract the real `pinned_toolchain` and `finalize` functions from
# scripts/qualify.sh and run them exactly as its EXIT trap does. FSS_QUALIFY_ROOT_UNDER_TEST points
# them (and the run-directory tests) at another checkout, e.g. an export of an older commit, so a
# regression can be demonstrated against the historical writer.
QUALIFY_ROOT = Path(os.environ.get("FSS_QUALIFY_ROOT_UNDER_TEST", str(ROOT))).resolve()
RECEIPT_TEMP_PREFIX = ".qualification-receipt.json.tmp."
_KILL_ON_RECEIPT_FSYNC = """
import os, signal
_real_fsync = os.fsync
def _fsync(fd):
    try:
        name = os.path.basename(os.readlink(f"/proc/self/fd/{fd}"))
    except OSError:
        name = ""
    if name.startswith(%r):
        os.kill(os.getpid(), signal.SIGKILL)
    return _real_fsync(fd)
os.fsync = _fsync
""" % RECEIPT_TEMP_PREFIX


def _record_row(name: str, status: str = "passed") -> dict:
    return {"id": name, "status": status, "outputDigest": "sha256:" + "4" * 64, "argv": ["python3", f"{name}.py"]}


def _finalize_harness(root: Path) -> str:
    text = (root / "scripts/qualify.sh").read_text(encoding="utf-8")
    pinned_start = text.index("\npinned_toolchain() {\n") + 1
    pinned = text[pinned_start:text.index("\n}\n", pinned_start) + 3]
    finalize_start = text.index("\nfinalize() {\n") + 1
    finalize = text[finalize_start:text.index("\ntrap finalize EXIT", finalize_start) + 1]
    return pinned + finalize


def run_qualify_finalize(
    run_dir: Path,
    *,
    records: bytes | None,
    final_status: str = "passed",
    exit_code: int = 0,
    fsize_limit: int | None = None,
    pythonpath: Path | None = None,
) -> subprocess.CompletedProcess:
    """Runs qualify.sh's finalize trap (the shipped receipt path) against ``run_dir``."""
    import shlex

    run_dir.mkdir(parents=True, exist_ok=True)
    if records is not None:
        (run_dir / "commands.jsonl").write_bytes(records)
    script = "\n".join([
        "set -Eeuo pipefail",
        f"ROOT={shlex.quote(str(QUALIFY_ROOT))}",
        'cd "$ROOT"',
        "LANE=policy",
        f"RECEIPT_DIR={shlex.quote(str(run_dir))}",
        'records="$RECEIPT_DIR/commands.jsonl"',
        "WRITE_RECEIPT=1",
        "started_ns=1",
        f"final_status={final_status}",
        _finalize_harness(QUALIFY_ROOT),
        "trap finalize EXIT",
        f"exit {exit_code}",
    ])
    env = {k: v for k, v in os.environ.items() if not k.startswith("FSS_DSR_")}
    env["PYTHONDONTWRITEBYTECODE"] = "1"
    if pythonpath is not None:
        env["PYTHONPATH"] = str(pythonpath)

    def limit_file_size() -> None:
        import resource

        resource.setrlimit(resource.RLIMIT_FSIZE, (fsize_limit, fsize_limit))

    return subprocess.run(
        [shutil.which("bash") or "/bin/bash", "-c", script],
        capture_output=True, text=True, env=env, timeout=120,
        preexec_fn=limit_file_size if fsize_limit is not None else None,
    )


def _receipt_temps(directory: Path) -> list[Path]:
    return sorted(directory.glob(RECEIPT_TEMP_PREFIX + "*"))


class TestQualifyFinalizeBehaviour(unittest.TestCase):
    """fss-1geb3: the shipped qualify.sh finalize path writes receipts atomically and always."""

    def _previous_receipt(self, run_dir: Path) -> bytes:
        previous = make_receipt("passed")
        previous["receiptId"] = "local:policy:previous_receipt"
        write_json(run_dir / "qualification-receipt.json", previous)
        return (run_dir / "qualification-receipt.json").read_bytes()

    def test_efbig_mid_write_keeps_previous_receipt(self) -> None:
        """A write that fails part-way (RLIMIT_FSIZE -> EFBIG after 2 KiB of a ~7 KiB receipt)
        must leave the previous receipt byte-identical and no partial receipt readable. The
        in-place writer (b5441b5^) truncates the old receipt to 2 KiB of broken JSON."""
        with tempfile.TemporaryDirectory() as tmpdir:
            run_dir = Path(tmpdir) / "run"
            run_dir.mkdir()
            previous = self._previous_receipt(run_dir)
            records = "".join(json.dumps(_record_row(f"step{i:02d}")) + "\n" for i in range(40)).encode("utf-8")

            crashed = run_qualify_finalize(run_dir, records=records, fsize_limit=2048)
            self.assertEqual((run_dir / "qualification-receipt.json").read_bytes(), previous, crashed.stderr)
            self.assertEqual(_receipt_temps(run_dir), [], "an aborted write must not leave a temp receipt behind")
            self.assertNotEqual(crashed.returncode, 0, "a run whose receipt could not be written must not exit 0")
            self.assertNotIn("qualification receipt: ", crashed.stderr, "the receipt path must not be announced when nothing was written")

            # Control: without the limit the same finalize writes the new, complete receipt.
            written = run_qualify_finalize(run_dir, records=None)
            self.assertEqual(written.returncode, 0, written.stderr)
            receipt = json.loads((run_dir / "qualification-receipt.json").read_text(encoding="utf-8"))
            self.assertEqual(len(receipt["commands"]), 40)
            self.assertGreater(len((run_dir / "qualification-receipt.json").read_bytes()), 2048)

    @unittest.skipUnless(Path("/proc/self/fd").is_dir(), "needs /proc to identify the receipt temp fd")
    def test_sigkill_mid_write_keeps_previous_receipt_and_audit_ignores_leftover_temp(self) -> None:
        """SIGKILL while the new receipt is being made durable (a real crash, not an exception)
        leaves the previous receipt intact; the leftover temp file under qualification-artifacts/
        is never read as a receipt by the repository-wide audit."""
        with tempfile.TemporaryDirectory() as tmpdir:
            root = build_fixture_root(Path(tmpdir))
            run_dir = root / "qualification-artifacts/local/run1"
            run_dir.mkdir(parents=True)
            previous = self._previous_receipt(run_dir)
            site = Path(tmpdir) / "site"
            site.mkdir()
            (site / "sitecustomize.py").write_text(_KILL_ON_RECEIPT_FSYNC, encoding="utf-8")

            records = (json.dumps(_record_row("policy")) + "\n").encode("utf-8")
            crashed = run_qualify_finalize(run_dir, records=records, pythonpath=site)
            self.assertEqual((run_dir / "qualification-receipt.json").read_bytes(), previous, crashed.stderr)
            leftovers = _receipt_temps(run_dir)
            self.assertEqual(len(leftovers), 1, f"the killed writer must leave its temp file: {crashed.stderr}")
            self.assertNotEqual(crashed.returncode, 0)
            self.assertNotIn("qualification receipt: ", crashed.stderr)

            ok, findings, summary = audit_claim_proof_bundles(root)
            self.assertTrue(ok, [(f.code, f.file, f.message) for f in findings])
            self.assertEqual(summary["receipts_inspected"], 1)
            self.assertEqual(summary["receipts_passed"], 1)
            self.assertFalse(any(RECEIPT_TEMP_PREFIX in f.file or RECEIPT_TEMP_PREFIX in f.message for f in findings))

    def test_planted_partial_temp_receipt_is_never_audited(self) -> None:
        """A partial `.qualification-receipt.json.tmp.*` file (with or without a real receipt next
        to it) is not a receipt: the audit neither inspects nor fails on it."""
        for with_receipt in (False, True):
            with self.subTest(with_receipt=with_receipt), tempfile.TemporaryDirectory() as tmpdir:
                root = build_fixture_root(Path(tmpdir))
                run_dir = root / "qualification-artifacts/local/run1"
                run_dir.mkdir(parents=True)
                (run_dir / (RECEIPT_TEMP_PREFIX + "k3j9x_")).write_text('{"schema": "fss.release_qualification_receipt.v1", "sta', encoding="utf-8")
                if with_receipt:
                    write_json(run_dir / "qualification-receipt.json", make_receipt("passed"))
                ok, findings, summary = audit_claim_proof_bundles(root)
                self.assertTrue(ok, [(f.code, f.file, f.message) for f in findings])
                self.assertEqual(summary["receipts_inspected"], int(with_receipt))

    def test_non_object_command_record_still_writes_failed_receipt(self) -> None:
        """A commands.jsonl line that is valid JSON but not a command object (`[1,2]` and friends)
        must not crash finalize: a failed receipt is written, its path is printed because it
        exists, and the run exits non-zero."""
        digest = b'"sha256:' + b"4" * 64 + b'"'
        malformed = {
            "list": b"[1,2]\n",
            "string": b'"x"\n',
            "null": b"null\n",
            "argv_not_list": b'{"argv":"python3","status":"passed","outputDigest":' + digest + b"}\n",
            "bad_status": b'{"argv":["a"],"status":"great","outputDigest":' + digest + b"}\n",
            "not_utf8": b"\xff\xfe\n",
        }
        for label, line in malformed.items():
            with self.subTest(record=label), tempfile.TemporaryDirectory() as tmpdir:
                run_dir = Path(tmpdir) / "run"
                result = run_qualify_finalize(run_dir, records=line)
                receipt_path = run_dir / "qualification-receipt.json"
                self.assertTrue(receipt_path.is_file(), f"no receipt written for {label}: {result.stderr}")
                receipt = json.loads(receipt_path.read_text(encoding="utf-8"))
                self.assertEqual(receipt["status"], "failed")
                self.assertEqual(receipt["commands"][0]["argv"], ["corrupt_record"])
                self.assertEqual(receipt["commands"][0]["status"], "failed")
                self.assertIn(f"qualification receipt: {receipt_path}", result.stderr)
                self.assertNotEqual(result.returncode, 0, "a failed receipt must not accompany exit 0")
                findings, status = cpb.inspect_qualification_receipt(receipt_path, run_dir)
                self.assertEqual(status, "failed")
                self.assertEqual(error_codes(findings), [], [f.message for f in findings])


class TestQualifyRunDirectories(unittest.TestCase):
    """fss-1geb3: runs never share or truncate another run's receipt directory."""

    STAMP = "19700101T000001Z"

    def _stamp_dirs(self) -> list[Path]:
        return sorted((QUALIFY_ROOT / "qualification-artifacts/local").glob(f"{self.STAMP}-docs*"))

    def _cleanup_stamp_dirs(self) -> None:
        for leftover in self._stamp_dirs():
            shutil.rmtree(leftover)

    def test_same_second_same_lane_runs_get_distinct_directories(self) -> None:
        """Two concurrent `qualify.sh --lane docs` runs inside the same UTC second each keep their
        own commands.jsonl and receipt (the second-resolution stamp used to make them collide)."""
        self._cleanup_stamp_dirs()
        self.addCleanup(self._cleanup_stamp_dirs)
        with tempfile.TemporaryDirectory() as tmpdir:
            bin_dir = Path(tmpdir) / "bin"
            bin_dir.mkdir()
            fake_date = bin_dir / "date"
            fake_date.write_text(f"#!/bin/sh\nprintf '%s\\n' {self.STAMP}\n", encoding="utf-8")
            fake_date.chmod(0o755)
            env = {k: v for k, v in os.environ.items() if k != "FSS_RECEIPT_DIR"}
            env["PATH"] = f"{bin_dir}{os.pathsep}{env.get('PATH', '')}"
            env["PYTHONDONTWRITEBYTECODE"] = "1"
            procs = [
                subprocess.Popen(
                    [shutil.which("bash") or "/bin/bash", str(QUALIFY_ROOT / "scripts/qualify.sh"), "--lane", "docs"],
                    cwd=str(QUALIFY_ROOT), env=env, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True,
                )
                for _ in range(2)
            ]
            stderrs = [proc.communicate(timeout=300)[1] for proc in procs]
        run_dirs = self._stamp_dirs()
        self.assertEqual(len(run_dirs), 2, f"expected two run directories, got {run_dirs}: {stderrs}")
        for run_dir in run_dirs:
            receipt = json.loads((run_dir / "qualification-receipt.json").read_text(encoding="utf-8"))
            rows = [json.loads(line) for line in (run_dir / "commands.jsonl").read_text(encoding="utf-8").splitlines() if line.strip()]
            self.assertGreater(len(rows), 0)
            self.assertEqual(len({row["id"] for row in rows}), len(rows), f"{run_dir} holds another run's records")
            self.assertEqual(receipt["commands"], [{k: row[k] for k in ("argv", "status", "outputDigest")} for row in rows])
            announcement = f"qualification receipt: {run_dir / 'qualification-receipt.json'}"
            self.assertEqual(sum(announcement in err for err in stderrs), 1, f"{run_dir} must belong to exactly one run")

    def test_explicit_receipt_dir_holding_a_run_is_refused_not_truncated(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            run_dir = Path(tmpdir) / "shared"
            run_dir.mkdir()
            prior = (json.dumps(_record_row("prior")) + "\n").encode("utf-8")
            (run_dir / "commands.jsonl").write_bytes(prior)
            env = {k: v for k, v in os.environ.items() if k != "FSS_RECEIPT_DIR"}
            result = subprocess.run(
                [shutil.which("bash") or "/bin/bash", str(QUALIFY_ROOT / "scripts/qualify.sh"), "--lane", "docs", "--receipt-dir", str(run_dir)],
                cwd=str(QUALIFY_ROOT), env=env, capture_output=True, text=True, timeout=300,
            )
            self.assertEqual((run_dir / "commands.jsonl").read_bytes(), prior, "another run's log was truncated")
            self.assertEqual(result.returncode, 4, result.stderr)
            self.assertFalse((run_dir / "qualification-receipt.json").exists())


class TestSharedAtomicWriter(unittest.TestCase):
    """fss-1geb3: durability details of scripts/qualification_receipt.py (the one writer)."""

    @staticmethod
    def _recording_fsync(log: list):
        real_fsync = os.fsync

        def fsync(fd: int) -> None:
            log.append((os.readlink(f"/proc/self/fd/{fd}"), os.fstat(fd).st_mode & 0o777))
            real_fsync(fd)

        return fsync

    @unittest.skipUnless(Path("/proc/self/fd").is_dir(), "needs /proc to name fsynced descriptors")
    def test_mode_is_set_before_fsync_and_new_parents_are_fsynced(self) -> None:
        import qualification_receipt as qr

        with tempfile.TemporaryDirectory() as tmpdir:
            base = Path(tmpdir).resolve()
            target = base / "a" / "b" / "qualification-receipt.json"
            log: list = []
            with mock.patch("os.fsync", side_effect=self._recording_fsync(log)):
                qr.write_qualification_receipt(target, make_receipt("passed"))
            synced = [path for path, _ in log]
            temp_syncs = [(path, mode) for path, mode in log if os.path.basename(path).startswith(RECEIPT_TEMP_PREFIX)]
            self.assertEqual(len(temp_syncs), 1, log)
            self.assertEqual(temp_syncs[0][1], 0o644, "the file mode must be final before its data is fsynced")
            for parent in (base, base / "a"):
                self.assertIn(str(parent), synced, f"the new directory under {parent} was not fsynced into it")
            self.assertEqual(synced[-1], str(base / "a" / "b"), "the rename must be fsynced last")
            self.assertEqual(target.stat().st_mode & 0o777, 0o644)

    def test_capture_writes_only_successful_output(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            out = Path(tmpdir) / "receipts" / "capabilities.json"
            script = str(ROOT / "scripts/qualification_receipt.py")
            ok = subprocess.run([sys.executable, script, "capture", "--output", str(out), "--", sys.executable, "-c", "print('{\"ok\": 1}')"], capture_output=True)
            self.assertEqual(ok.returncode, 0, ok.stderr)
            self.assertEqual(out.read_bytes(), b'{"ok": 1}\n')
            self.assertEqual(out.stat().st_mode & 0o777, 0o644)

            failing = "import sys; sys.stdout.write('{\"trunc'); sys.stdout.flush(); sys.exit(3)"
            bad = subprocess.run([sys.executable, script, "capture", "--output", str(out), "--", sys.executable, "-c", failing], capture_output=True)
            self.assertEqual(bad.returncode, 3)
            self.assertEqual(out.read_bytes(), b'{"ok": 1}\n', "a failing command must leave the previous output untouched")

            merged = Path(tmpdir) / "smoke-help.txt"
            both = "import sys; print('out'); sys.stdout.flush(); print('err', file=sys.stderr)"
            res = subprocess.run([sys.executable, script, "capture", "--merge-stderr", "--output", str(merged), "--", sys.executable, "-c", both], capture_output=True)
            self.assertEqual(res.returncode, 0, res.stderr)
            self.assertEqual(merged.read_text(encoding="utf-8").split(), ["out", "err"])

            missing = subprocess.run([sys.executable, script, "capture", "--output", str(Path(tmpdir) / "none.txt"), "--", "/nonexistent/fss-binary"], capture_output=True)
            self.assertEqual(missing.returncode, 127)
            self.assertFalse((Path(tmpdir) / "none.txt").exists())
            self.assertEqual(sorted(p.name for p in out.parent.iterdir()), ["capabilities.json"], "no temp files may remain")

    def test_descriptor_is_closed_when_fchmod_fails(self) -> None:
        """fss-xhxwh: a failing fchmod must not leak the temp-file descriptor (or the temp file)."""
        import errno
        import qualification_receipt as qr

        with tempfile.TemporaryDirectory() as tmpdir:
            target = Path(tmpdir) / "qualification-receipt.json"
            target.write_bytes(b"previous\n")
            opened: list[int] = []
            real_mkstemp = tempfile.mkstemp

            def recording_mkstemp(*args, **kwargs):
                descriptor, name = real_mkstemp(*args, **kwargs)
                opened.append(descriptor)
                return descriptor, name

            with mock.patch("tempfile.mkstemp", side_effect=recording_mkstemp), \
                    mock.patch("os.fchmod", side_effect=PermissionError(errno.EPERM, "fchmod refused")):
                with self.assertRaises(PermissionError):
                    qr.atomic_write_bytes(target, b"new\n")
            self.assertEqual(len(opened), 1)
            try:
                os.fstat(opened[0])
            except OSError as exc:
                self.assertEqual(exc.errno, errno.EBADF)
            else:
                os.close(opened[0])
                self.fail("the temp-file descriptor leaked after fchmod failed")
            self.assertEqual(target.read_bytes(), b"previous\n")
            self.assertEqual(sorted(p.name for p in Path(tmpdir).iterdir()), ["qualification-receipt.json"])

    def test_temp_unlink_failure_does_not_mask_the_original_error(self) -> None:
        """fss-xhxwh: when the write fails and removing the temp file also fails, the caller sees
        the original error; the secondary failure is attached to it and logged, not substituted."""
        import contextlib
        import errno
        import io
        import qualification_receipt as qr

        with tempfile.TemporaryDirectory() as tmpdir:
            target = Path(tmpdir) / "qualification-receipt.json"
            target.write_bytes(b"previous\n")
            original = OSError(errno.EIO, "replace failed")
            stderr = io.StringIO()
            with mock.patch("os.replace", side_effect=original), \
                    mock.patch("os.unlink", side_effect=PermissionError(errno.EACCES, "unlink refused")), \
                    contextlib.redirect_stderr(stderr):
                with self.assertRaises(OSError) as raised:
                    qr.atomic_write_bytes(target, b"new\n")
            self.assertIs(raised.exception, original, f"got {raised.exception!r} instead of the original error")
            notes = "\n".join(getattr(raised.exception, "__notes__", []))
            self.assertIn("unlink refused", notes)
            self.assertIn(RECEIPT_TEMP_PREFIX, notes)
            self.assertIn("unlink refused", stderr.getvalue())
            self.assertEqual(target.read_bytes(), b"previous\n")

    def test_prepare_exact_run_dir_that_is_a_regular_file_is_named_precisely(self) -> None:
        """fss-xhxwh: an explicit --exact path that is a regular file (itself or an ancestor) is
        reported as not a directory, not as a directory that already holds a run's log."""
        script = str(ROOT / "scripts/qualification_receipt.py")
        with tempfile.TemporaryDirectory() as tmpdir:
            regular = Path(tmpdir) / "receipt-dir"
            regular.write_bytes(b"not a directory\n")
            for exact in (regular, regular / "nested"):
                with self.subTest(exact=exact.name):
                    result = subprocess.run(
                        [sys.executable, script, "prepare-run-dir", "--exact", str(exact)],
                        capture_output=True, text=True, timeout=60,
                    )
                    self.assertEqual(result.returncode, 4, result.stderr)
                    self.assertNotIn("already holds", result.stderr)
                    self.assertIn("is not a directory", result.stderr)
                    self.assertIn(str(regular), result.stderr)
                    self.assertEqual(result.stdout, "")
                    self.assertEqual(regular.read_bytes(), b"not a directory\n")

    def test_load_command_records_classifies_every_malformed_line(self) -> None:
        import qualification_receipt as qr

        digest = b'"sha256:' + b"4" * 64 + b'"'
        good = json.dumps(_record_row("ok")).encode("utf-8")
        cases = {
            b"[1,2]": True, b'"x"': True, b"7": True, b"null": True, b"{}": True, b'{"argv":[': True,
            b"\xff\xfe": True, b"[" * 100000: True,
            b'{"argv":[],"status":"passed","outputDigest":' + digest + b"}": True,
            b'{"argv":["a"],"status":"passed","outputDigest":7}': True,
            b'{"argv":["a",1],"status":"passed","outputDigest":' + digest + b"}": True,
            good: False,
        }
        with tempfile.TemporaryDirectory() as tmpdir:
            records = Path(tmpdir) / "commands.jsonl"
            for line, is_malformed in cases.items():
                with self.subTest(line=line[:40]):
                    records.write_bytes(line + b"\n")
                    commands, malformed = qr.load_command_records(records)
                    self.assertEqual(malformed, is_malformed)
                    self.assertEqual(len(commands), 1)
                    self.assertEqual(commands[0]["argv"] == ["corrupt_record"], is_malformed)
            self.assertEqual(qr.load_command_records(Path(tmpdir) / "absent.jsonl"), ([], False))



class TestClaimKindRegistryAuditing(unittest.TestCase):
    """Audits the machine-readable claim-kind registry against registries/CLAIMS.md and baseline (fss-x4a.30.87.1)."""

    def setUp(self) -> None:
        self.claims_json_path = ROOT / "architecture/claims.json"
        self.claims_md_path = ROOT / "registries/CLAIMS.md"

    def test_live_claim_kind_registry_passes(self) -> None:
        """The real claims.json and registries/CLAIMS.md must pass with 0 errors and all classes."""
        findings = audit_claim_kind_registry(ROOT, self.claims_json_path, self.claims_md_path)
        errors = [f for f in findings if f.severity == "error"]
        self.assertEqual(errors, [], f"Claim kind registry audit failed on real files: {errors}")

    def test_live_claims_freeze_digest_exact_match(self) -> None:
        """The real claims.json must match BASELINE_CLAIMS_GENERATION and BASELINE_CLAIMS_FREEZE_DIGEST exactly."""
        data = json.loads(self.claims_json_path.read_text(encoding="utf-8"))
        self.assertEqual(data.get("generation"), BASELINE_CLAIMS_GENERATION)
        self.assertEqual(data.get("freezeDigest"), BASELINE_CLAIMS_FREEZE_DIGEST)
        computed = compute_canonical_claims_digest(data)
        self.assertEqual(computed, BASELINE_CLAIMS_FREEZE_DIGEST)
        self.assertEqual(data.get("freezeDigest"), computed)

    def test_claims_freeze_digest_mismatch_fails(self) -> None:
        """Mutating a claim field without recomputing freezeDigest emits ERR-CLAIM-PROOF-DIGEST-MISMATCH-001."""
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            arch = root / "architecture"
            reg = root / "registries"
            arch.mkdir(parents=True)
            reg.mkdir(parents=True)

            (reg / "CLAIMS.md").write_text(self.claims_md_path.read_text(encoding="utf-8"), encoding="utf-8")
            data = json.loads(self.claims_json_path.read_text(encoding="utf-8"))
            data["freezeDigest"] = "sha256:0000000000000000000000000000000000000000000000000000000000000000"
            (arch / "claims.json").write_text(json.dumps(data, indent=2), encoding="utf-8")

            findings = audit_claim_kind_registry(root, arch / "claims.json", reg / "CLAIMS.md")
            codes = [f.code for f in findings]
            self.assertIn(ERR_BUNDLE_DIGEST_MISMATCH, codes)

    def test_claims_generation_unrecognized_fails(self) -> None:
        """Unrecognized generation without authorized freeze digest emits ERR-CLAIM-PROOF-STALE-GENERATION-001."""
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            arch = root / "architecture"
            reg = root / "registries"
            arch.mkdir(parents=True)
            reg.mkdir(parents=True)

            (reg / "CLAIMS.md").write_text(self.claims_md_path.read_text(encoding="utf-8"), encoding="utf-8")
            data = json.loads(self.claims_json_path.read_text(encoding="utf-8"))
            data["generation"] = "gen:unregistered:claims-v999"
            data["freezeDigest"] = compute_canonical_claims_digest(data)
            (arch / "claims.json").write_text(json.dumps(data, indent=2), encoding="utf-8")

            findings = audit_claim_kind_registry(root, arch / "claims.json", reg / "CLAIMS.md")
            codes = [f.code for f in findings]
            self.assertIn(ERR_STALE_GENERATION, codes)

    def test_claims_prohibited_list_tampering_fails(self) -> None:
        """Tampering with or weakening the prohibited list emits ERR-CLAIM-REGISTRY-DRIFT-001."""
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            arch = root / "architecture"
            reg = root / "registries"
            arch.mkdir(parents=True)
            reg.mkdir(parents=True)

            (reg / "CLAIMS.md").write_text(self.claims_md_path.read_text(encoding="utf-8"), encoding="utf-8")
            data = json.loads(self.claims_json_path.read_text(encoding="utf-8"))
            data["prohibited"] = ["allow_everything"]
            (arch / "claims.json").write_text(json.dumps(data, indent=2), encoding="utf-8")

            findings = audit_claim_kind_registry(root, arch / "claims.json", reg / "CLAIMS.md")
            codes = [f.code for f in findings]
            self.assertIn(ERR_CLAIM_REGISTRY_DRIFT, codes)

    def test_claims_missing_top_level_metadata_fails(self) -> None:
        """Deleting required top-level metadata fields emits ERR-CLAIM-MISSING-FIELD-001."""
        for field_name in ("schema", "generation", "freezeDigest", "sourceDocument", "prohibited"):
            with tempfile.TemporaryDirectory() as td:
                root = Path(td)
                arch = root / "architecture"
                reg = root / "registries"
                arch.mkdir(parents=True)
                reg.mkdir(parents=True)

                (reg / "CLAIMS.md").write_text(self.claims_md_path.read_text(encoding="utf-8"), encoding="utf-8")
                data = json.loads(self.claims_json_path.read_text(encoding="utf-8"))
                del data[field_name]
                (arch / "claims.json").write_text(json.dumps(data, indent=2), encoding="utf-8")

                findings = audit_claim_kind_registry(root, arch / "claims.json", reg / "CLAIMS.md")
                codes = [f.code for f in findings]
                self.assertIn(ERR_CLAIM_MISSING_FIELD, codes)

    def test_claims_missing_claim_class_field_fails(self) -> None:
        """Omitting 'claim_class' from a class entry emits ERR-CLAIM-MISSING-FIELD-001."""
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            arch = root / "architecture"
            reg = root / "registries"
            arch.mkdir(parents=True)
            reg.mkdir(parents=True)

            (reg / "CLAIMS.md").write_text(self.claims_md_path.read_text(encoding="utf-8"), encoding="utf-8")
            data = json.loads(self.claims_json_path.read_text(encoding="utf-8"))
            data["classes"][0].pop("claim_class", None)
            (arch / "claims.json").write_text(json.dumps(data, indent=2), encoding="utf-8")

            findings = audit_claim_kind_registry(root, arch / "claims.json", reg / "CLAIMS.md")
            codes = [f.code for f in findings]
            self.assertIn(ERR_CLAIM_MISSING_FIELD, codes)

    def test_claims_required_evidence_weakening_fails(self) -> None:
        """Weakening or mutating requiredEvidence for any class emits ERR-CLAIM-REGISTRY-DRIFT-001."""
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            arch = root / "architecture"
            reg = root / "registries"
            arch.mkdir(parents=True)
            reg.mkdir(parents=True)

            (reg / "CLAIMS.md").write_text(self.claims_md_path.read_text(encoding="utf-8"), encoding="utf-8")
            data = json.loads(self.claims_json_path.read_text(encoding="utf-8"))
            data["classes"][0]["requiredEvidence"] = ["completely_unauthorized_token"]
            (arch / "claims.json").write_text(json.dumps(data, indent=2), encoding="utf-8")

            findings = audit_claim_kind_registry(root, arch / "claims.json", reg / "CLAIMS.md")
            codes = [f.code for f in findings]
            self.assertIn(ERR_CLAIM_REGISTRY_DRIFT, codes)

    def test_claims_case_collision_duplicate_fails(self) -> None:
        """Case-folded collision (e.g. 'INVARIANT' vs 'invariant') emits ERR-CLAIM-ID-REUSED-001."""
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            arch = root / "architecture"
            reg = root / "registries"
            arch.mkdir(parents=True)
            reg.mkdir(parents=True)

            (reg / "CLAIMS.md").write_text(self.claims_md_path.read_text(encoding="utf-8"), encoding="utf-8")
            data = json.loads(self.claims_json_path.read_text(encoding="utf-8"))
            dup = dict(data["classes"][0])
            dup["id"] = "INVARIANT"
            dup["claim_class"] = "INVARIANT"
            data["classes"].append(dup)
            (arch / "claims.json").write_text(json.dumps(data, indent=2), encoding="utf-8")

            findings = audit_claim_kind_registry(root, arch / "claims.json", reg / "CLAIMS.md")
            codes = [f.code for f in findings]
            self.assertIn(ERR_CLAIM_ID_REUSED, codes)

    @mock.patch("claim_proof_bundle_checker.load_tombstone_index")
    def test_claims_tombstone_class_fails(self, mock_tombstones: mock.MagicMock) -> None:
        """Attempting to use a tombstoned identifier as an active claim class emits ERR-CLAIM-ID-REUSED-001."""
        mock_tombstones.return_value = ({"TOMBSTONED-CLASS"}, [])
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            arch = root / "architecture"
            reg = root / "registries"
            arch.mkdir(parents=True)
            reg.mkdir(parents=True)

            (reg / "CLAIMS.md").write_text(self.claims_md_path.read_text(encoding="utf-8"), encoding="utf-8")
            data = json.loads(self.claims_json_path.read_text(encoding="utf-8"))
            data["classes"][0]["id"] = "TOMBSTONED-CLASS"
            data["classes"][0]["claim_class"] = "TOMBSTONED-CLASS"
            (arch / "claims.json").write_text(json.dumps(data, indent=2), encoding="utf-8")

            findings = audit_claim_kind_registry(root, arch / "claims.json", reg / "CLAIMS.md")
            codes = [f.code for f in findings]
            self.assertIn(ERR_CLAIM_ID_REUSED, codes)

    def test_claim_kind_registry_drift_meaning_mismatch(self) -> None:
        """Mismatch in meaning between claims.json and CLAIMS.md emits ERR-CLAIM-REGISTRY-DRIFT-001."""
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            arch = root / "architecture"
            reg = root / "registries"
            arch.mkdir(parents=True)
            reg.mkdir(parents=True)

            md_content = self.claims_md_path.read_text(encoding="utf-8")
            (reg / "CLAIMS.md").write_text(md_content, encoding="utf-8")

            data = json.loads(self.claims_json_path.read_text(encoding="utf-8"))
            if "classes" in data and len(data["classes"]) > 0:
                data["classes"][0]["meaning"] = "altered unauthorized meaning description"
            (arch / "claims.json").write_text(json.dumps(data, indent=2), encoding="utf-8")

            findings = audit_claim_kind_registry(root, arch / "claims.json", reg / "CLAIMS.md")
            codes = [f.code for f in findings]
            self.assertIn(ERR_CLAIM_REGISTRY_DRIFT, codes)

    def test_claim_kind_registry_drift_evidence_mismatch(self) -> None:
        """Mismatch in minimum evidence between claims.json and CLAIMS.md emits ERR-CLAIM-REGISTRY-DRIFT-001."""
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            arch = root / "architecture"
            reg = root / "registries"
            arch.mkdir(parents=True)
            reg.mkdir(parents=True)

            md_content = self.claims_md_path.read_text(encoding="utf-8")
            (reg / "CLAIMS.md").write_text(md_content, encoding="utf-8")

            data = json.loads(self.claims_json_path.read_text(encoding="utf-8"))
            if "classes" in data and len(data["classes"]) > 0:
                data["classes"][0]["minimum_evidence"] = "fabricated evidence requirement"
            (arch / "claims.json").write_text(json.dumps(data, indent=2), encoding="utf-8")

            findings = audit_claim_kind_registry(root, arch / "claims.json", reg / "CLAIMS.md")
            codes = [f.code for f in findings]
            self.assertIn(ERR_CLAIM_REGISTRY_DRIFT, codes)

    def test_claim_kind_registry_drift_order_mismatch(self) -> None:
        """Reordered claim classes between claims.json and CLAIMS.md emit ERR-CLAIM-REGISTRY-DRIFT-001."""
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            arch = root / "architecture"
            reg = root / "registries"
            arch.mkdir(parents=True)
            reg.mkdir(parents=True)

            md_content = self.claims_md_path.read_text(encoding="utf-8")
            (reg / "CLAIMS.md").write_text(md_content, encoding="utf-8")

            data = json.loads(self.claims_json_path.read_text(encoding="utf-8"))
            if "classes" in data and len(data["classes"]) >= 2:
                data["classes"][0], data["classes"][1] = data["classes"][1], data["classes"][0]
            (arch / "claims.json").write_text(json.dumps(data, indent=2), encoding="utf-8")

            findings = audit_claim_kind_registry(root, arch / "claims.json", reg / "CLAIMS.md")
            codes = [f.code for f in findings]
            self.assertIn(ERR_CLAIM_REGISTRY_DRIFT, codes)

    def test_claim_kind_registry_id_reused(self) -> None:
        """Duplicate or reused claim class ID emits ERR-CLAIM-ID-REUSED-001."""
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            arch = root / "architecture"
            reg = root / "registries"
            arch.mkdir(parents=True)
            reg.mkdir(parents=True)

            md_content = self.claims_md_path.read_text(encoding="utf-8")
            (reg / "CLAIMS.md").write_text(md_content, encoding="utf-8")

            data = json.loads(self.claims_json_path.read_text(encoding="utf-8"))
            if "classes" in data and len(data["classes"]) >= 2:
                # duplicate the first class ID onto the second
                data["classes"][1]["id"] = data["classes"][0]["id"]
                data["classes"][1]["claim_class"] = data["classes"][0]["id"]
            (arch / "claims.json").write_text(json.dumps(data, indent=2), encoding="utf-8")

            findings = audit_claim_kind_registry(root, arch / "claims.json", reg / "CLAIMS.md")
            codes = [f.code for f in findings]
            self.assertIn(ERR_CLAIM_ID_REUSED, codes)

    def test_claim_kind_registry_missing_field(self) -> None:
        """Missing required normative field (meaning, minimum_evidence, id) emits ERR-CLAIM-MISSING-FIELD-001."""
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            arch = root / "architecture"
            reg = root / "registries"
            arch.mkdir(parents=True)
            reg.mkdir(parents=True)

            md_content = self.claims_md_path.read_text(encoding="utf-8")
            (reg / "CLAIMS.md").write_text(md_content, encoding="utf-8")

            data = json.loads(self.claims_json_path.read_text(encoding="utf-8"))
            if "classes" in data and len(data["classes"]) > 0:
                data["classes"][0].pop("meaning", None)
            (arch / "claims.json").write_text(json.dumps(data, indent=2), encoding="utf-8")

            findings = audit_claim_kind_registry(root, arch / "claims.json", reg / "CLAIMS.md")
            codes = [f.code for f in findings]
            self.assertIn(ERR_CLAIM_MISSING_FIELD, codes)


class TestSloClaimClassRealization(unittest.TestCase):
    """Verifies the realization of claim class 'slo' (fss-x4a.30.87.5)."""

    def setUp(self) -> None:
        self.claims_json_path = ROOT / "architecture/claims.json"
        self.claims_md_path = ROOT / "registries/CLAIMS.md"
        self.known_classes, self.prohibited, _ = load_authoritative_claims(self.claims_json_path)

    def test_slo_claim_class_exact_normative_fields(self) -> None:
        """The 'slo' claim class has exact normative fields in both JSON and Markdown."""
        self.assertIn("slo", self.known_classes)
        data = json.loads(self.claims_json_path.read_text(encoding="utf-8"))
        slo_entry = next((c for c in data.get("classes", []) if c.get("id") == "slo"), None)
        self.assertIsNotNone(slo_entry, "slo entry not found in claims.json classes")
        self.assertEqual(slo_entry.get("claim_class"), "slo")
        self.assertEqual(slo_entry.get("meaning"), "operational latency/availability/cost target achieved")
        self.assertEqual(
            slo_entry.get("minimum_evidence"),
            "operation-cost row, environment, workload, raw measurements, failures",
        )
        self.assertEqual(
            slo_entry.get("requiredEvidence"),
            ["operation_cost_row", "measurement_artifact", "environment_manifest"],
        )

    def test_slo_proof_bundle_complete_evidence_passes(self) -> None:
        """A well-formed proof bundle for an SLO with complete required evidence passes verification."""
        with tempfile.TemporaryDirectory() as tmpdir:
            tmp_root = Path(tmpdir)
            meas_path = tmp_root / "qualification-artifacts/meas.json"
            meas_path.parent.mkdir(parents=True, exist_ok=True)
            meas_data = {
                "schema": "fss.operation_cost_measurement.v1",
                "slo_id": "SLO-INGEST-001",
                "operation_id": "COST-ACQUIRE-001",
                "generation": "gen-2026-09-01",
                "environment": {"profile": "reference"},
                "status": "passed",
                "started_at": "2026-09-01T00:00:00Z",
                "finished_at": "2026-09-01T00:01:00Z",
                "target_ms": 10.0,
                "actual_ms": 8.0,
            }
            meas_path.write_text(json.dumps(meas_data), encoding="utf-8")
            meas_digest = compute_sha256(meas_path.read_bytes())

            bundle_data = {
                "schema": "fss.proof_bundle.v1",
                "bundle_id": "BUNDLE-SLO-INGEST-001",
                "claim_id": "SLO-INGEST-001",
                "claim_class": "slo",
                "supported_level": "achieved",
                "generation": "gen-2026-09-01",
                "status": "passed",
                "retained_evidence": [
                    "operation_cost_row",
                    "measurement_artifact",
                    "environment_manifest",
                ],
                "artifacts": [
                    {"path": "qualification-artifacts/meas.json", "digest": meas_digest}
                ],
            }
            bundle_data["content_digest"] = compute_bundle_digest(bundle_data)
            bundle_file = tmp_root / "slo_ingest.bundle.json"
            bundle_file.write_text(json.dumps(bundle_data, indent=2), encoding="utf-8")

            is_valid, findings, loaded_data = verify_proof_bundle(
                bundle_path=bundle_file,
                root=tmp_root,
                expected_claim_id="SLO-INGEST-001",
                claim_level="achieved",
                known_classes=self.known_classes,
                prohibited_promotions=self.prohibited,
            )
            self.assertTrue(is_valid, f"Expected pass, got findings: {[f.message for f in findings]}")
            self.assertEqual(len(findings), 0)
            self.assertIsNotNone(loaded_data)

    def test_slo_proof_bundle_missing_evidence_fails(self) -> None:
        """Dropping any required evidence from an 'slo' proof bundle emits ERR-CLAIM-PROOF-LEVEL-EXCEEDED-001."""
        for dropped in ("operation_cost_row", "measurement_artifact", "environment_manifest"):
            with tempfile.TemporaryDirectory() as tmpdir:
                tmp_root = Path(tmpdir)
                evidence = [
                    e for e in ["operation_cost_row", "measurement_artifact", "environment_manifest"]
                    if e != dropped
                ]
                bundle_data = {
                    "schema": "fss.proof_bundle.v1",
                    "bundle_id": "BUNDLE-SLO-INGEST-FAIL",
                    "claim_id": "SLO-INGEST-001",
                    "claim_class": "slo",
                    "supported_level": "achieved",
                    "generation": "gen-2026-09-01",
                    "status": "passed",
                    "retained_evidence": evidence,
                }
                bundle_data["content_digest"] = compute_bundle_digest(bundle_data)
                bundle_file = tmp_root / "slo_fail.bundle.json"
                bundle_file.write_text(json.dumps(bundle_data, indent=2), encoding="utf-8")

                is_valid, findings, _ = verify_proof_bundle(
                    bundle_path=bundle_file,
                    root=tmp_root,
                    expected_claim_id="SLO-INGEST-001",
                    claim_level="achieved",
                    known_classes=self.known_classes,
                    prohibited_promotions=self.prohibited,
                )
                self.assertFalse(is_valid)
                codes = [f.code for f in findings]
                self.assertIn(ERR_CLAIM_LEVEL_EXCEEDED, codes)

    def test_slo_proof_bundle_stale_generation_fails(self) -> None:
        """A proof bundle referencing prohibited 'latest' alias emits ERR-CLAIM-PROOF-STALE-GENERATION-001."""
        with tempfile.TemporaryDirectory() as tmpdir:
            tmp_root = Path(tmpdir)
            bundle_data = {
                "schema": "fss.proof_bundle.v1",
                "bundle_id": "BUNDLE-SLO-INGEST-STALE",
                "claim_id": "SLO-INGEST-001",
                "claim_class": "slo",
                "supported_level": "achieved",
                "generation": "latest",
                "status": "passed",
                "retained_evidence": [
                    "operation_cost_row",
                    "measurement_artifact",
                    "environment_manifest",
                ],
            }
            bundle_data["content_digest"] = compute_bundle_digest(bundle_data)
            bundle_file = tmp_root / "slo_stale.bundle.json"
            bundle_file.write_text(json.dumps(bundle_data, indent=2), encoding="utf-8")

            is_valid, findings, _ = verify_proof_bundle(
                bundle_path=bundle_file,
                root=tmp_root,
                expected_claim_id="SLO-INGEST-001",
                claim_level="achieved",
                known_classes=self.known_classes,
                prohibited_promotions=self.prohibited,
            )
            self.assertFalse(is_valid)
            codes = [f.code for f in findings]
            self.assertIn(ERR_STALE_GENERATION, codes)


class TestSloEvidenceInspectionFailures(unittest.TestCase):
    """Planted negative tests for real SLO evidence inspection per mail #806 / fss-x4a.30.87.5."""

    def setUp(self) -> None:
        self.known_classes, self.prohibited, _ = load_authoritative_claims(ROOT / "architecture/claims.json")

    def test_planted_slo_no_measurement_on_disk_fails(self) -> None:
        """Plant 1: SLO proof bundle without measurement artifact fails with ERR-CLAIM-PROOF-LEVEL-EXCEEDED-001."""
        with tempfile.TemporaryDirectory() as tmpdir:
            tmp_root = Path(tmpdir)
            bundle_data = {
                "schema": "fss.proof_bundle.v1",
                "bundle_id": "BUNDLE-SLO-INGEST-EMPTY-ARTS",
                "claim_id": "SLO-INGEST-001",
                "claim_class": "slo",
                "supported_level": "achieved",
                "generation": "gen-2026-09-01",
                "status": "passed",
                "retained_evidence": [
                    "operation_cost_row",
                    "measurement_artifact",
                    "environment_manifest",
                ],
                "artifacts": [],
            }
            bundle_data["content_digest"] = compute_bundle_digest(bundle_data)
            bundle_file = tmp_root / "slo.bundle.json"
            bundle_file.write_text(json.dumps(bundle_data), encoding="utf-8")

            is_valid, findings, _ = verify_proof_bundle(
                bundle_path=bundle_file,
                root=tmp_root,
                expected_claim_id="SLO-INGEST-001",
                claim_level="achieved",
                known_classes=self.known_classes,
                prohibited_promotions=self.prohibited,
            )
            self.assertFalse(is_valid)
            codes = [f.code for f in findings]
            self.assertIn(ERR_CLAIM_LEVEL_EXCEEDED, codes)

    def test_planted_slo_mismatched_slo_id_fails(self) -> None:
        """Plant 2a: Measurement artifact tied to different SLO ID emits ERR-CLAIM-PROOF-CLAIM-BINDING-MISMATCH-001."""
        with tempfile.TemporaryDirectory() as tmpdir:
            tmp_root = Path(tmpdir)
            meas_path = tmp_root / "qualification-artifacts/meas.json"
            meas_path.parent.mkdir(parents=True, exist_ok=True)
            meas_data = {
                "schema": "fss.operation_cost_measurement.v1",
                "slo_id": "SLO-OTHER-999",
                "operation_id": "COST-ACQUIRE-001",
                "generation": "gen:fss1:operation-cost-v1",
                "environment": {"profile": "reference"},
                "status": "passed",
                "started_at": "2026-09-01T00:00:00Z",
                "finished_at": "2026-09-01T00:01:00Z",
                "target_ms": 10.0,
                "actual_ms": 5.0,
            }
            meas_path.write_text(json.dumps(meas_data), encoding="utf-8")
            meas_digest = compute_sha256(meas_path.read_bytes())

            bundle_data = {
                "schema": "fss.proof_bundle.v1",
                "bundle_id": "BUNDLE-SLO-INGEST-MISMATCH",
                "claim_id": "SLO-INGEST-001",
                "claim_class": "slo",
                "supported_level": "achieved",
                "generation": "gen-2026-09-01",
                "status": "passed",
                "retained_evidence": [
                    "operation_cost_row",
                    "measurement_artifact",
                    "environment_manifest",
                ],
                "artifacts": [
                    {"path": "qualification-artifacts/meas.json", "digest": meas_digest}
                ],
            }
            bundle_data["content_digest"] = compute_bundle_digest(bundle_data)
            bundle_file = tmp_root / "slo.bundle.json"
            bundle_file.write_text(json.dumps(bundle_data), encoding="utf-8")

            from claim_proof_bundle_checker import ERR_CLAIM_BINDING_MISMATCH
            is_valid, findings, _ = verify_proof_bundle(
                bundle_path=bundle_file,
                root=tmp_root,
                expected_claim_id="SLO-INGEST-001",
                claim_level="achieved",
                known_classes=self.known_classes,
                prohibited_promotions=self.prohibited,
            )
            self.assertFalse(is_valid)
            codes = [f.code for f in findings]
            self.assertIn(ERR_CLAIM_BINDING_MISMATCH, codes)

    def test_planted_slo_mismatched_cost_operation_fails(self) -> None:
        """Plant 2b: Measurement artifact with unknown/unassociated operation ID emits ERR-CLAIM-PROOF-CLAIM-BINDING-MISMATCH-001."""
        with tempfile.TemporaryDirectory() as tmpdir:
            tmp_root = Path(tmpdir)
            meas_path = tmp_root / "qualification-artifacts/meas.json"
            meas_path.parent.mkdir(parents=True, exist_ok=True)
            meas_data = {
                "schema": "fss.operation_cost_measurement.v1",
                "slo_id": "SLO-INGEST-001",
                "operation_id": "cost-different-op-001",
                "generation": "gen:fss1:operation-cost-v1",
                "environment": {"profile": "reference"},
                "status": "passed",
                "started_at": "2026-09-01T00:00:00Z",
                "finished_at": "2026-09-01T00:01:00Z",
                "target_ms": 10.0,
                "actual_ms": 5.0,
            }
            meas_path.write_text(json.dumps(meas_data), encoding="utf-8")
            meas_digest = compute_sha256(meas_path.read_bytes())

            bundle_data = {
                "schema": "fss.proof_bundle.v1",
                "bundle_id": "BUNDLE-SLO-INGEST-OP-MISMATCH",
                "claim_id": "SLO-INGEST-001",
                "claim_class": "slo",
                "supported_level": "achieved",
                "generation": "gen-2026-09-01",
                "status": "passed",
                "retained_evidence": [
                    "operation_cost_row",
                    "measurement_artifact",
                    "environment_manifest",
                ],
                "artifacts": [
                    {"path": "qualification-artifacts/meas.json", "digest": meas_digest}
                ],
            }
            bundle_data["content_digest"] = compute_bundle_digest(bundle_data)
            bundle_file = tmp_root / "slo.bundle.json"
            bundle_file.write_text(json.dumps(bundle_data), encoding="utf-8")

            from claim_proof_bundle_checker import ERR_CLAIM_BINDING_MISMATCH
            is_valid, findings, _ = verify_proof_bundle(
                bundle_path=bundle_file,
                root=tmp_root,
                expected_claim_id="SLO-INGEST-001",
                claim_level="achieved",
                known_classes=self.known_classes,
                prohibited_promotions=self.prohibited,
            )
            self.assertFalse(is_valid)
            codes = [f.code for f in findings]
            self.assertIn(ERR_CLAIM_BINDING_MISMATCH, codes)

    def test_planted_slo_stale_measurement_window_fails(self) -> None:
        """Plant 3: Measurement window timestamped in 2024 fails with ERR-CLAIM-PROOF-STALE-GENERATION-001."""
        with tempfile.TemporaryDirectory() as tmpdir:
            tmp_root = Path(tmpdir)
            meas_path = tmp_root / "qualification-artifacts/meas.json"
            meas_path.parent.mkdir(parents=True, exist_ok=True)
            meas_data = {
                "schema": "fss.operation_cost_measurement.v1",
                "slo_id": "SLO-INGEST-001",
                "operation_id": "COST-ACQUIRE-001",
                "generation": "gen:fss1:operation-cost-v1",
                "environment": {"profile": "reference"},
                "status": "passed",
                "started_at": "2024-01-01T00:00:00Z",
                "finished_at": "2024-01-01T00:01:00Z",
                "target_ms": 10.0,
                "actual_ms": 5.0,
            }
            meas_path.write_text(json.dumps(meas_data), encoding="utf-8")
            meas_digest = compute_sha256(meas_path.read_bytes())

            bundle_data = {
                "schema": "fss.proof_bundle.v1",
                "bundle_id": "BUNDLE-SLO-INGEST-STALE-WIN",
                "claim_id": "SLO-INGEST-001",
                "claim_class": "slo",
                "supported_level": "achieved",
                "generation": "gen-2026-09-01",
                "status": "passed",
                "retained_evidence": [
                    "operation_cost_row",
                    "measurement_artifact",
                    "environment_manifest",
                ],
                "artifacts": [
                    {"path": "qualification-artifacts/meas.json", "digest": meas_digest}
                ],
            }
            bundle_data["content_digest"] = compute_bundle_digest(bundle_data)
            bundle_file = tmp_root / "slo.bundle.json"
            bundle_file.write_text(json.dumps(bundle_data), encoding="utf-8")

            is_valid, findings, _ = verify_proof_bundle(
                bundle_path=bundle_file,
                root=tmp_root,
                expected_claim_id="SLO-INGEST-001",
                claim_level="achieved",
                known_classes=self.known_classes,
                prohibited_promotions=self.prohibited,
            )
            self.assertFalse(is_valid)
            codes = [f.code for f in findings]
            self.assertIn(ERR_STALE_GENERATION, codes)

    def test_planted_slo_target_met_only_by_rounding_fails(self) -> None:
        """Plant 4: Target met only by rounding (target 5.0, actual 5.4, rounded 5.0) emits ERR-CLAIM-PROOF-LEVEL-EXCEEDED-001."""
        with tempfile.TemporaryDirectory() as tmpdir:
            tmp_root = Path(tmpdir)
            meas_path = tmp_root / "qualification-artifacts/meas.json"
            meas_path.parent.mkdir(parents=True, exist_ok=True)
            meas_data = {
                "schema": "fss.operation_cost_measurement.v1",
                "slo_id": "SLO-INGEST-001",
                "operation_id": "COST-ACQUIRE-001",
                "generation": "gen:fss1:operation-cost-v1",
                "environment": {"profile": "reference"},
                "status": "passed",
                "started_at": "2026-09-01T00:00:00Z",
                "finished_at": "2026-09-01T00:01:00Z",
                "target_ms": 5.0,
                "actual_ms": 5.4,
                "reported_rounded_ms": 5.0,
            }
            meas_path.write_text(json.dumps(meas_data), encoding="utf-8")
            meas_digest = compute_sha256(meas_path.read_bytes())

            bundle_data = {
                "schema": "fss.proof_bundle.v1",
                "bundle_id": "BUNDLE-SLO-INGEST-ROUNDING",
                "claim_id": "SLO-INGEST-001",
                "claim_class": "slo",
                "supported_level": "achieved",
                "generation": "gen-2026-09-01",
                "status": "passed",
                "retained_evidence": [
                    "operation_cost_row",
                    "measurement_artifact",
                    "environment_manifest",
                ],
                "artifacts": [
                    {"path": "qualification-artifacts/meas.json", "digest": meas_digest}
                ],
            }
            bundle_data["content_digest"] = compute_bundle_digest(bundle_data)
            bundle_file = tmp_root / "slo.bundle.json"
            bundle_file.write_text(json.dumps(bundle_data), encoding="utf-8")

            is_valid, findings, _ = verify_proof_bundle(
                bundle_path=bundle_file,
                root=tmp_root,
                expected_claim_id="SLO-INGEST-001",
                claim_level="achieved",
                known_classes=self.known_classes,
                prohibited_promotions=self.prohibited,
            )
            self.assertFalse(is_valid)
            codes = [f.code for f in findings]
            self.assertIn(ERR_CLAIM_LEVEL_EXCEEDED, codes)

    def test_planted_slo_nan_infinity_values_fail(self) -> None:
        """Plant 5: Measurement declaring NaN or Infinity emits ERR-CLAIM-PROOF-LEVEL-EXCEEDED-001."""
        with tempfile.TemporaryDirectory() as tmpdir:
            tmp_root = Path(tmpdir)
            meas_path = tmp_root / "qualification-artifacts/meas.json"
            meas_path.parent.mkdir(parents=True, exist_ok=True)
            meas_data = {
                "schema": "fss.operation_cost_measurement.v1",
                "slo_id": "SLO-INGEST-001",
                "operation_id": "COST-ACQUIRE-001",
                "generation": "gen:fss1:operation-cost-v1",
                "environment": {"profile": "reference"},
                "status": "passed",
                "started_at": "2026-09-01T00:00:00Z",
                "finished_at": "2026-09-01T00:01:00Z",
                "target_ms": 10.0,
                "actual_ms": "NaN",
                "cpu_millis": "Infinity",
            }
            meas_path.write_text(json.dumps(meas_data), encoding="utf-8")
            meas_digest = compute_sha256(meas_path.read_bytes())

            bundle_data = {
                "schema": "fss.proof_bundle.v1",
                "bundle_id": "BUNDLE-SLO-INGEST-NAN",
                "claim_id": "SLO-INGEST-001",
                "claim_class": "slo",
                "supported_level": "achieved",
                "generation": "gen-2026-09-01",
                "status": "passed",
                "retained_evidence": [
                    "operation_cost_row",
                    "measurement_artifact",
                    "environment_manifest",
                ],
                "artifacts": [
                    {"path": "qualification-artifacts/meas.json", "digest": meas_digest}
                ],
            }
            bundle_data["content_digest"] = compute_bundle_digest(bundle_data)
            bundle_file = tmp_root / "slo.bundle.json"
            bundle_file.write_text(json.dumps(bundle_data), encoding="utf-8")

            is_valid, findings, _ = verify_proof_bundle(
                bundle_path=bundle_file,
                root=tmp_root,
                expected_claim_id="SLO-INGEST-001",
                claim_level="achieved",
                known_classes=self.known_classes,
                prohibited_promotions=self.prohibited,
            )
            self.assertFalse(is_valid)
            codes = [f.code for f in findings]
            self.assertIn(ERR_CLAIM_LEVEL_EXCEEDED, codes)

    def test_planted_slo_stale_generation_fails(self) -> None:
        """Plant 2c: Measurement artifact with stale generation emits ERR-CLAIM-PROOF-STALE-GENERATION-001."""
        with tempfile.TemporaryDirectory() as tmpdir:
            tmp_root = Path(tmpdir)
            meas_path = tmp_root / "qualification-artifacts/meas.json"
            meas_path.parent.mkdir(parents=True, exist_ok=True)
            meas_data = {
                "schema": "fss.operation_cost_measurement.v1",
                "slo_id": "SLO-INGEST-001",
                "operation_id": "COST-ACQUIRE-001",
                "generation": "gen-2020-01-01",
                "environment": {"profile": "reference"},
                "status": "passed",
                "started_at": "2026-09-01T00:00:00Z",
                "finished_at": "2026-09-01T00:01:00Z",
                "target_ms": 10.0,
                "actual_ms": 5.0,
            }
            meas_path.write_text(json.dumps(meas_data), encoding="utf-8")
            meas_digest = compute_sha256(meas_path.read_bytes())

            bundle_data = {
                "schema": "fss.proof_bundle.v1",
                "bundle_id": "BUNDLE-SLO-INGEST-STALE-GEN",
                "claim_id": "SLO-INGEST-001",
                "claim_class": "slo",
                "supported_level": "achieved",
                "generation": "gen-2026-09-01",
                "status": "passed",
                "retained_evidence": [
                    "operation_cost_row",
                    "measurement_artifact",
                    "environment_manifest",
                ],
                "artifacts": [
                    {"path": "qualification-artifacts/meas.json", "digest": meas_digest}
                ],
            }
            bundle_data["content_digest"] = compute_bundle_digest(bundle_data)
            bundle_file = tmp_root / "slo.bundle.json"
            bundle_file.write_text(json.dumps(bundle_data), encoding="utf-8")

            is_valid, findings, _ = verify_proof_bundle(
                bundle_path=bundle_file,
                root=tmp_root,
                expected_claim_id="SLO-INGEST-001",
                claim_level="achieved",
                known_classes=self.known_classes,
                prohibited_promotions=self.prohibited,
            )
            self.assertFalse(is_valid)
            codes = [f.code for f in findings]
            self.assertIn(ERR_STALE_GENERATION, codes)

    def test_planted_slo_upgraded_beyond_evidence_fails(self) -> None:
        """Plant 6: Empty dummy evidence upgraded directly to 'achieved' emits ERR-CLAIM-PROOF-LEVEL-EXCEEDED-001."""
        with tempfile.TemporaryDirectory() as tmpdir:
            tmp_root = Path(tmpdir)
            bundle_data = {
                "schema": "fss.proof_bundle.v1",
                "bundle_id": "BUNDLE-SLO-UPGRADED-DUMMY",
                "claim_id": "SLO-INGEST-001",
                "claim_class": "slo",
                "supported_level": "achieved",
                "generation": "gen-2026-09-01",
                "status": "passed",
                "retained_evidence": ["operation_cost_row", "measurement_artifact", "environment_manifest"],
                "artifacts": [],
            }
            bundle_data["content_digest"] = compute_bundle_digest(bundle_data)
            bundle_file = tmp_root / "dummy.bundle.json"
            bundle_file.write_text(json.dumps(bundle_data), encoding="utf-8")

            is_valid, findings, _ = verify_proof_bundle(
                bundle_path=bundle_file,
                root=tmp_root,
                expected_claim_id="SLO-INGEST-001",
                claim_level="achieved",
                known_classes=self.known_classes,
                prohibited_promotions=self.prohibited,
            )
            self.assertFalse(is_valid)
            codes = [f.code for f in findings]
            self.assertIn(ERR_CLAIM_LEVEL_EXCEEDED, codes)

    def test_planted_slo_valid_measurement_passes(self) -> None:
        """Positive control: Well-formed SLO proof bundle with valid measurement artifact passes with 0 errors."""
        with tempfile.TemporaryDirectory() as tmpdir:
            tmp_root = Path(tmpdir)
            meas_path = tmp_root / "qualification-artifacts/meas.json"
            meas_path.parent.mkdir(parents=True, exist_ok=True)
            meas_data = {
                "schema": "fss.operation_cost_measurement.v1",
                "slo_id": "SLO-INGEST-001",
                "operation_id": "COST-ACQUIRE-001",
                "generation": "gen:fss1:operation-cost-v1",
                "environment": {"profile": "reference"},
                "status": "passed",
                "started_at": "2026-09-01T00:00:00Z",
                "finished_at": "2026-09-01T00:01:00Z",
                "target_ms": 10.0,
                "actual_ms": 8.0,
            }
            meas_path.write_text(json.dumps(meas_data), encoding="utf-8")
            meas_digest = compute_sha256(meas_path.read_bytes())

            bundle_data = {
                "schema": "fss.proof_bundle.v1",
                "bundle_id": "BUNDLE-SLO-INGEST-VALID",
                "claim_id": "SLO-INGEST-001",
                "claim_class": "slo",
                "supported_level": "achieved",
                "generation": "gen:fss1:operation-cost-v1",
                "status": "passed",
                "retained_evidence": [
                    "operation_cost_row",
                    "measurement_artifact",
                    "environment_manifest",
                ],
                "artifacts": [
                    {"path": "qualification-artifacts/meas.json", "digest": meas_digest}
                ],
            }
            bundle_data["content_digest"] = compute_bundle_digest(bundle_data)
            bundle_file = tmp_root / "slo.bundle.json"
            bundle_file.write_text(json.dumps(bundle_data), encoding="utf-8")

            is_valid, findings, _ = verify_proof_bundle(
                bundle_path=bundle_file,
                root=tmp_root,
                expected_claim_id="SLO-INGEST-001",
                claim_level="achieved",
                known_classes=self.known_classes,
                prohibited_promotions=self.prohibited,
            )
            self.assertTrue(is_valid, f"Expected pass, got: {[f.message for f in findings]}")
            self.assertEqual(len(findings), 0)


if __name__ == "__main__":
    unittest.main()


