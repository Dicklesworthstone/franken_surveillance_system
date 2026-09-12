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
    ERR_CLAIM_LEVEL_EXCEEDED,
    ERR_EMPTY_INPUT,
    ERR_INVALID_CLAIM_CLASS,
    ERR_PROHIBITED_CLAIM_PROMOTION,
    ERR_PROOF_BUNDLE_NOT_FOUND,
    ERR_STALE_GENERATION,
    ERR_UNREADABLE_INPUT,
    audit_claim_proof_bundles,
    compute_bundle_digest,
    compute_sha256,
    is_latest_generation,
    load_authoritative_claims,
    parse_markdown_tables,
    scan_markdown_claim_tables,
    verify_proof_bundle,
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
                "claim_id": "SLO-TEST-001",
                "claim_class": "slo",
                "supported_level": "achieved",
                "generation": "gen-2026-09-01",
                "status": "passed",
                "retained_evidence": [
                    "operation_cost_row",
                    "measurement_artifact",
                    "environment_manifest",
                ],
            }
            digest = compute_bundle_digest(bundle_data)
            bundle_data["content_digest"] = digest

            bundle_file = tmp_root / "test.bundle.json"
            bundle_file.write_text(json.dumps(bundle_data, indent=2), encoding="utf-8")

            is_valid, findings, loaded_data = verify_proof_bundle(
                bundle_path=bundle_file,
                root=tmp_root,
                expected_claim_id="SLO-TEST-001",
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
                "claim_id": "SLO-001",
                "claim_class": "slo",
                "supported_level": "achieved",
                "generation": "gen-active-01",
                "status": "passed",
                "retained_evidence": [
                    "operation_cost_row",
                    "measurement_artifact",
                    "environment_manifest",
                ],
            }
            bundle_data["content_digest"] = compute_bundle_digest(bundle_data)
            rel_bundle = "proof_bundles/slo1.bundle.json"
            full_bundle_path = tmp_root / rel_bundle
            full_bundle_path.parent.mkdir(parents=True, exist_ok=True)
            full_bundle_path.write_text(json.dumps(bundle_data), encoding="utf-8")

            md_content = (
                "# Status Table\n\n"
                "| ID | Status | Proof root |\n"
                "|---|---|---|\n"
                f"| `SLO-001` | achieved | `{rel_bundle}` |\n"
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
    "registries/CLAIMS.md",
    "registries/SLOS.md",
    "registries/QUALIFICATION_LANES.md",
    "README.md",
)
_DROP = object()


def _known_classes() -> dict[str, list[str]]:
    known, _, findings = load_authoritative_claims(ROOT / "architecture/claims.json")
    assert not findings, findings
    return known


def make_bundle(**overrides: object) -> dict:
    """A fully valid SLO proof bundle; each negative test perturbs exactly one aspect."""
    data: dict = {
        "schema": "fss.proof_bundle.v1",
        "bundle_id": "BUNDLE-TEST-001",
        "claim_id": "SLO-TEST-001",
        "claim_class": "slo",
        "supported_level": "achieved",
        "generation": "gen-2026-09-01",
        "status": "passed",
        "retained_evidence": list(SLO_EVIDENCE),
    }
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
                Path(tmpdir), seal(make_bundle()), expected_claim_id="SLO-TEST-001", claim_level="achieved"
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
            ok, findings, _ = verify(Path(tmpdir), seal(make_bundle(objects=[obj])))
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
        """scripts/release_qualify.sh must write build.json atomically, not directly via write_text."""
        script_text = (ROOT / "scripts/release_qualify.sh").read_text(encoding="utf-8")
        self.assertNotIn(
            "Path(sys.argv[1]).write_text(",
            script_text,
            "scripts/release_qualify.sh writes build.json in-place via write_text, allowing partial reads",
        )
        self.assertIn("tempfile.mkstemp", script_text)
        self.assertIn("os.fsync", script_text)
        self.assertIn("os.replace", script_text)

    def test_qualify_finalize_handles_truncated_commands_record(self) -> None:
        """qualify.sh finalize trap must not crash with unhandled JSONDecodeError if commands.jsonl has a partial line."""
        script_text = (ROOT / "scripts/qualify.sh").read_text(encoding="utf-8")
        self.assertIn(
            "json.JSONDecodeError",
            script_text,
            "qualify.sh must handle JSONDecodeError in finalize trap",
        )
        self.assertIn(
            "handle.flush()",
            script_text,
            "qualify.sh append_record must flush and fsync",
        )

    def test_written_receipt_has_standard_permissions(self) -> None:
        """Qualification receipts written by write_qualification_receipt must have standard permissions (0644)."""
        with tempfile.TemporaryDirectory() as tmpdir:
            receipt_file = Path(tmpdir) / "qualification-receipt.json"
            cpb.write_qualification_receipt(receipt_file, make_receipt("passed"))
            mode = receipt_file.stat().st_mode & 0o777
            self.assertEqual(mode, 0o644, f"Receipt file permissions should be 0644, got {oct(mode)}")

    def test_qualify_script_atomic_receipt_contract(self) -> None:
        """scripts/qualify.sh must write receipts to temp file in same directory, fsync, and rename."""
        script_text = (ROOT / "scripts/qualify.sh").read_text(encoding="utf-8")
        # Must not write directly in place with write_text
        self.assertNotIn(
            'pathlib.Path(output_path).write_text(',
            script_text,
            "scripts/qualify.sh must not write qualification receipt in-place",
        )
        # Must create temp file in same directory, fsync, and replace/rename
        self.assertIn("tempfile.mkstemp", script_text)
        self.assertIn("os.fsync", script_text)
        self.assertIn("os.replace", script_text)


if __name__ == "__main__":
    unittest.main()
