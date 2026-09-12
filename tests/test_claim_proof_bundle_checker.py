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
from pathlib import Path

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
                        "path": str(art1_file),
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
                        "path": str(art_file),
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


if __name__ == "__main__":
    unittest.main()
