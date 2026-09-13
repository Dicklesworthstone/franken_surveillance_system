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
8. Positive controls: the live repository passes; complete slo and bounded_model bundles verify;
   a complete proof bundle never verifies statically (ERR-CLAIM-PROOF-PROVER-RUN-REQUIRED-001);
   valid artifacts pass; CLI flags work.
"""

from __future__ import annotations

import inspect
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

ERR_CLAIM_BINDING_MISMATCH = cpb.ERR_CLAIM_BINDING_MISMATCH
ERR_BOUND_DERIVATION_UNBOUND = cpb.ERR_BOUND_DERIVATION_UNBOUND
ERR_BOUND_EXPRESSION_UNBOUND = cpb.ERR_BOUND_EXPRESSION_UNBOUND


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
        """A complete 'slo' proof bundle (retained measurement bound to its SLO row, cost
        operation, generation, validity window, and retained environment manifest) passes."""
        with tempfile.TemporaryDirectory() as tmpdir:
            tmp_root = Path(tmpdir)
            known_classes, prohibited, _ = load_authoritative_claims(ROOT / "architecture/claims.json")
            bundle_file = write_slo_bundle(tmp_root, build_slo_fixture(tmp_root))

            is_valid, findings, loaded_data = verify_proof_bundle(
                bundle_path=bundle_file,
                root=tmp_root,
                expected_claim_id=SLO_CLAIM_ID,
                claim_level="achieved",
                known_classes=known_classes,
                prohibited_promotions=prohibited,
                now=SLO_NOW,
            )
            self.assertTrue(is_valid, f"Expected pass, got findings: {[f.message for f in findings]}")
            self.assertEqual(len(findings), 0)
            self.assertIsNotNone(loaded_data)

    def test_positive_bundle_with_verified_artifacts(self) -> None:
        """A proof bundle declaring artifacts with matching sha256 digests passes; uncited, its
        class is resolved from the SLO registry by its claim id, not taken from the bundle."""
        with tempfile.TemporaryDirectory() as tmpdir:
            tmp_root = Path(tmpdir)
            known_classes, prohibited, _ = load_authoritative_claims(ROOT / "architecture/claims.json")

            art1_file = tmp_root / "artifact1.bin"
            art1_content = b"artifact 1 content sample data"
            art1_file.write_bytes(art1_content)
            art1_digest = compute_sha256(art1_content)

            bundle_data = build_slo_fixture(tmp_root)
            bundle_data["artifacts"].append({"path": "artifact1.bin", "digest": art1_digest})
            bundle_file = write_slo_bundle(tmp_root, bundle_data)

            is_valid, findings, _ = verify_proof_bundle(
                bundle_path=bundle_file,
                root=tmp_root,
                known_classes=known_classes,
                prohibited_promotions=prohibited,
                now=SLO_NOW,
            )
            self.assertTrue(is_valid, f"Expected pass, got findings: {[f.message for f in findings]}")
            self.assertEqual(len(findings), 0)

    def test_positive_markdown_table_with_valid_bundle(self) -> None:
        """Markdown table row citing a complete 'slo' proof bundle passes scanning; the row
        status reaches the bundle as its claim level, so the slo evidence is inspected."""
        with tempfile.TemporaryDirectory() as tmpdir:
            tmp_root = Path(tmpdir)
            known_classes, prohibited, _ = load_authoritative_claims(ROOT / "architecture/claims.json")
            write_slo_bundle(tmp_root, build_slo_fixture(tmp_root))

            md_content = (
                "# Status Table\n\n"
                "| ID | Status | Proof root |\n"
                "|---|---|---|\n"
                f"| `{SLO_CLAIM_ID}` | achieved | `{SLO_BUNDLE_REL}` |\n"
            )
            md_file = tmp_root / "test_table.md"
            md_file.write_text(md_content, encoding="utf-8")

            stats: dict[str, int] = {}
            findings = scan_markdown_claim_tables(
                md_path=md_file,
                root=tmp_root,
                known_classes=known_classes,
                tombstoned_ids=set(),
                prohibited_promotions=prohibited,
                stats=stats,
                now=SLO_NOW,
            )
            self.assertEqual(len(findings), 0, f"Expected 0 findings, got: {[f.message for f in findings]}")
            self.assertEqual((stats["promoted"], stats["bundles_checked"], stats["bundles_passed"]), (1, 1, 1))

    def test_positive_slos_md_row_cites_valid_slo_bundle_end_to_end(self) -> None:
        """registries/SLOS.md marks SLO-DETECT-001 achieved and cites a complete slo bundle:
        the repository audit (markdown surface + retention walk) and the CLI both pass."""
        with tempfile.TemporaryDirectory() as tmpdir:
            root = build_fixture_root(Path(tmpdir))
            write_slo_bundle(root, build_slo_fixture(root))
            promote_slos_row(root, SLO_CLAIM_ID, SLO_BUNDLE_REL)
            ok, findings, summary = audit_claim_proof_bundles(root, now=SLO_NOW)
            self.assertTrue(ok, [f"{f.code}: {f.message}" for f in findings])
            self.assertEqual(summary["error_count"], 0)
            self.assertEqual(summary["promoted_claim_rows"], 1)
            self.assertEqual((summary["bundles_checked"], summary["verified_bundles_count"]), (1, 1))
            result = run_cli("--root", str(root), "--as-of", "2026-09-02T00:00:00Z")
            self.assertEqual(result.returncode, 0, result.stdout + result.stderr)

    def test_positive_markdown_row_cites_complete_proof_bundle(self) -> None:
        """A claim row (ID | Class | Status | Proof root) citing a complete 'proof' bundle passes;
        the row status reaches the bundle as its claim level and the row class governs."""
        with tempfile.TemporaryDirectory() as tmpdir:
            root = Path(tmpdir)
            write_json(root / PROOF_BUNDLE_REL, seal(build_proof_fixture(root)))
            findings, stats = scan_with_stats(root, class_table(f"| `{PROOF_CLAIM_ID}` | proof | verified | `{PROOF_BUNDLE_REL}` | {PROOF_GENERATION} |"))
            # Round 3, decision A: a statically clean proof still needs a prover-run receipt.
            self.assertEqual(error_code_set(findings), [_code("ERR_PROOF_PROVER_RUN_REQUIRED")], [f"{f.code}: {f.message}" for f in findings])
            self.assertEqual([f.code for f in findings if f.severity != "error"], [], "a proof refusal must carry no warnings")
            self.assertEqual((stats["promoted"], stats["bundles_checked"], stats["bundles_passed"]), (1, 1, 0))

    def test_positive_markdown_row_cites_complete_bounded_model_bundle(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            root = Path(tmpdir)
            write_json(root / BOUND_BUNDLE_REL, seal(build_bound_fixture(root)))
            findings, stats = scan_with_stats(root, class_table(f"| `{BOUND_CLAIM_ID}` | bounded_model | verified | `{BOUND_BUNDLE_REL}` | {BOUND_GENERATION} |"))
            self.assertEqual(findings, [], [f"{f.code}: {f.message}" for f in findings])
            self.assertEqual((stats["promoted"], stats["bundles_checked"], stats["bundles_passed"]), (1, 1, 1))

    def test_positive_readme_row_cites_complete_proof_bundle_end_to_end(self) -> None:
        """README.md claim row with a Class column citing a complete proof bundle: the audit
        (markdown scan + retention walk, which inherits the citing row's class) and CLI pass."""
        with tempfile.TemporaryDirectory() as tmpdir:
            root = build_fixture_root(Path(tmpdir))
            write_json(root / PROOF_BUNDLE_REL, seal(build_proof_fixture(root)))
            append_readme_table(root, class_table(f"| `{PROOF_CLAIM_ID}` | proof | verified | `{PROOF_BUNDLE_REL}` | {PROOF_GENERATION} |"))
            ok, findings, summary = audit_with(root, CLAIM_ROW_CLASSES)
            # Round 3, decision A: a statically clean proof still needs a prover-run receipt.
            self.assertFalse(ok)
            self.assertEqual(error_code_set(findings), [_code("ERR_PROOF_PROVER_RUN_REQUIRED")], [f"{f.code}: {f.message}" for f in findings])
            self.assertEqual([f.code for f in findings if f.severity != "error"], [], "a proof refusal must carry no warnings")
            self.assertEqual((summary["bundles_checked"], summary["verified_bundles_count"]), (1, 0))
            self.assertEqual(summary.get("unpromoted_bundles_count", 0), 0)
            # No repository registry binds FORMAL-002 (review item A): the registry-only CLI refuses it.
            result = run_cli("--root", str(root), "--as-of", "2026-09-02T00:00:00Z")
            self.assertEqual(result.returncode, 1, result.stdout + result.stderr)
            self.assertIn("ERR-CLAIM-CLASS-UNRESOLVED-001", result.stdout)


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
                expected_claim_id="SLO-DETECT-001",  # a claim id a registry binds (review item A)
                claim_class="slo",  # the citing claim row's class; a bundle never picks its own
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
        # Round 8 (O9): the file lies inside --root; a path outside the root is refused before reading.
        root_dir = tempfile.mkdtemp()
        with tempfile.NamedTemporaryFile(suffix=".bundle.json", mode="w", delete=False, dir=root_dir) as f:
            f.write("{ corrupt json")
            f_path = f.name
        try:
            cmd = [
                sys.executable,
                str(ROOT / "scripts/claim_proof_bundle_checker.py"),
                "--root",
                root_dir,
                "--bundle",
                f_path,
            ]
            result = subprocess.run(cmd, capture_output=True, text=True, cwd=str(ROOT))
            self.assertEqual(result.returncode, 1)
            self.assertIn("[FAIL]", result.stdout)
            self.assertIn(ERR_UNREADABLE_INPUT, result.stdout)
        finally:
            Path(f_path).unlink(missing_ok=True)
            shutil.rmtree(root_dir, ignore_errors=True)  # round 9: the migrated temp root is removed too


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

# Canonical slo measurement shape (fss-x4a.30.87.5): the target and comparator come from the
# SLO-DETECT-001 row of registries/SLOS.md ("p95 ... <= 1.5 s"); the measurement carries exactly
# one canonical 'actual', its unit, a validity window, a passing status, and the digest of a
# retained environment manifest.
FIXED_NOW = datetime(2026, 9, 2, tzinfo=timezone.utc)
DEFAULT_ENVIRONMENT_DATA = {
    "schema": "fss.environment_manifest.v1",
    "host_profile": "edge-gpu-reference",
    "workload": "declared detect profile",
}
DEFAULT_ENVIRONMENT_BYTES = json.dumps(DEFAULT_ENVIRONMENT_DATA).encode("utf-8")
DEFAULT_ENVIRONMENT_DIGEST = compute_sha256(DEFAULT_ENVIRONMENT_BYTES)
DEFAULT_ENVIRONMENT_REL = "qualification-artifacts/env.json"
DEFAULT_ENVIRONMENT_ARTIFACT = {"role": "environment_manifest", "path": DEFAULT_ENVIRONMENT_REL, "digest": DEFAULT_ENVIRONMENT_DIGEST}
DEFAULT_MEASUREMENT_DATA = {
    "schema": "fss.slo_measurement.v1",
    "slo_id": "SLO-DETECT-001",
    "operation_id": "COST-DETECT-001",
    "generation": "gen-2026-09-01",
    "operation_cost_generation": "gen:fss1:operation-cost-v1",
    "status": "passed",
    "measurement_window": {
        "started_at": "2026-09-01T00:00:00Z",
        "finished_at": "2026-09-01T01:00:00Z",
    },
    "unit": "s",
    "statistic": "p95",  # SLO-DETECT-001 is a p95 target (round 4, B16)
    "actual": 1.2,
    "environment_manifest_digest": DEFAULT_ENVIRONMENT_DIGEST,
}
DEFAULT_MEASUREMENT_BYTES = json.dumps(DEFAULT_MEASUREMENT_DATA).encode("utf-8")
DEFAULT_MEASUREMENT_DIGEST = compute_sha256(DEFAULT_MEASUREMENT_BYTES)
DEFAULT_MEASUREMENT_REL = "qualification-artifacts/meas.json"
DEFAULT_MEASUREMENT_ARTIFACT = {"role": "measurement_artifact", "path": DEFAULT_MEASUREMENT_REL, "digest": DEFAULT_MEASUREMENT_DIGEST}
DEFAULT_RETAINED_FILES = {
    DEFAULT_MEASUREMENT_REL: DEFAULT_MEASUREMENT_BYTES,
    DEFAULT_ENVIRONMENT_REL: DEFAULT_ENVIRONMENT_BYTES,
}


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
        "artifacts": [dict(DEFAULT_MEASUREMENT_ARTIFACT), dict(DEFAULT_ENVIRONMENT_ARTIFACT)],
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
    kwargs.setdefault("now", FIXED_NOW)
    referenced: set[str] = set()
    for key in ("artifacts", "objects"):
        entries = data.get(key)
        if isinstance(entries, list):
            referenced.update(e.get("path") for e in entries if isinstance(e, dict) and isinstance(e.get("path"), str))
    for rel, raw in DEFAULT_RETAINED_FILES.items():
        if rel in referenced and not (root / rel).exists():
            (root / rel).parent.mkdir(parents=True, exist_ok=True)
            (root / rel).write_bytes(raw)
    if referenced & set(DEFAULT_RETAINED_FILES):
        ensure_slo_freshness_bound(root)  # the default slo measurement needs its cost row's bound (slo item 6)
    return verify_proof_bundle(bundle_path=path, root=root, **kwargs)


def claim_table(*rows: str) -> str:
    return "| ID | Status | Proof root |\n|---|---|---|\n" + "".join(r + "\n" for r in rows)


def scan(root: Path, text: str, name: str = "table.md") -> list:
    md_file = root / name
    md_file.write_text(text, encoding="utf-8")
    return scan_markdown_claim_tables(md_file, root, _known_classes(), set(), now=FIXED_NOW)


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
            ok, findings, _ = verify(Path(tmpdir), seal(make_bundle(objects=[dict(DEFAULT_MEASUREMENT_ARTIFACT), dict(DEFAULT_ENVIRONMENT_ARTIFACT), obj])))
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
            bundle_file = write_slo_bundle(tmp_root, build_slo_fixture(tmp_root))

            is_valid, findings, loaded_data = verify_proof_bundle(
                bundle_path=bundle_file,
                root=tmp_root,
                expected_claim_id=SLO_CLAIM_ID,
                claim_level="achieved",
                known_classes=self.known_classes,
                prohibited_promotions=self.prohibited,
                now=SLO_NOW,
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
    """Planted negative tests for real SLO evidence inspection per mail #806 / fss-x4a.30.87.5.

    Rebased on build_slo_fixture: every plant perturbs one aspect of a valid slo claim, keeps
    its original assertion, and pins the exact finding-id set."""

    def plant(self, **case: object) -> list:
        with tempfile.TemporaryDirectory() as tmpdir:
            root = Path(tmpdir)
            is_valid, findings, _ = verify_slo_bundle(root, build_slo_fixture(root, **case))
            self.assertFalse(is_valid)
            return findings

    def test_planted_slo_no_measurement_on_disk_fails(self) -> None:
        """Plant 1: SLO proof bundle without measurement artifact fails with ERR-CLAIM-PROOF-LEVEL-EXCEEDED-001."""
        for case in ({"bundle": {"artifacts": []}}, {"omit_roles": ("measurement_artifact",)}):
            with self.subTest(case=case):
                findings = self.plant(**case)
                self.assertIn(ERR_CLAIM_LEVEL_EXCEEDED, codes(findings))
                self.assertEqual(error_code_set(findings), [ERR_CLAIM_LEVEL_EXCEEDED])

    def test_planted_slo_mismatched_slo_id_fails(self) -> None:
        """Plant 2a: Measurement artifact tied to different SLO ID emits ERR-CLAIM-PROOF-CLAIM-BINDING-MISMATCH-001."""
        findings = self.plant(measurement={"slo_id": "SLO-OTHER-999"})
        self.assertIn(ERR_CLAIM_BINDING_MISMATCH, codes(findings))
        self.assertEqual(error_code_set(findings), [ERR_CLAIM_BINDING_MISMATCH])

    def test_planted_slo_mismatched_cost_operation_fails(self) -> None:
        """Plant 2b: Measurement artifact with unknown/unassociated operation ID emits ERR-CLAIM-PROOF-CLAIM-BINDING-MISMATCH-001."""
        for operation_id in ("cost-different-op-001", "COST-PROXY-001"):
            with self.subTest(operation_id=operation_id):
                findings = self.plant(measurement={"operation_id": operation_id})
                self.assertIn(ERR_CLAIM_BINDING_MISMATCH, codes(findings))
                self.assertEqual(error_code_set(findings), [ERR_CLAIM_BINDING_MISMATCH])

    def test_planted_slo_stale_measurement_window_fails(self) -> None:
        """Plant 3: Measurement window timestamped in 2024 fails with ERR-CLAIM-PROOF-STALE-GENERATION-001."""
        findings = self.plant(measurement={"measurement_window": {"started_at": "2024-01-01T00:00:00Z", "finished_at": "2024-01-01T00:01:00Z"}})
        self.assertIn(ERR_STALE_GENERATION, codes(findings))
        self.assertEqual(error_code_set(findings), [ERR_STALE_GENERATION])

    def test_planted_slo_target_met_only_by_rounding_fails(self) -> None:
        """Plant 4: Target met only by rounding (target 1.5 s, actual 1.54, rounded 1.5) emits ERR-CLAIM-PROOF-LEVEL-EXCEEDED-001."""
        findings = self.plant(measurement={"actual": 1.54, "reported_rounded": 1.5})
        self.assertIn(ERR_CLAIM_LEVEL_EXCEEDED, codes(findings))
        self.assertEqual(error_code_set(findings), [ERR_CLAIM_LEVEL_EXCEEDED])

    def test_planted_slo_nan_infinity_values_fail(self) -> None:
        """Plant 5: Measurement declaring NaN or Infinity emits ERR-CLAIM-PROOF-LEVEL-EXCEEDED-001."""
        findings = self.plant(measurement={"actual": "NaN", "cpu_millis": "Infinity"})
        self.assertIn(ERR_CLAIM_LEVEL_EXCEEDED, codes(findings))
        # Round 5: 'cpu_millis' is also outside the measurement's exact field set.
        self.assertEqual(error_code_set(findings), sorted([ERR_CLAIM_LEVEL_EXCEEDED, FIELD_UNKNOWN]))

    def test_planted_slo_stale_generation_fails(self) -> None:
        """Plant 2c: Measurement artifact with stale generation emits ERR-CLAIM-PROOF-STALE-GENERATION-001."""
        findings = self.plant(measurement={"generation": "gen-2020-01-01"})
        self.assertIn(ERR_STALE_GENERATION, codes(findings))
        self.assertEqual(error_code_set(findings), [ERR_STALE_GENERATION])

    def test_planted_slo_upgraded_beyond_evidence_fails(self) -> None:
        """Plant 6: Empty dummy evidence upgraded directly to 'achieved' emits ERR-CLAIM-PROOF-LEVEL-EXCEEDED-001."""
        findings = self.plant(bundle={"artifacts": [], "bundle_id": "BUNDLE-SLO-UPGRADED-DUMMY"})
        self.assertIn(ERR_CLAIM_LEVEL_EXCEEDED, codes(findings))
        self.assertEqual(error_code_set(findings), [ERR_CLAIM_LEVEL_EXCEEDED])

    def test_planted_slo_valid_measurement_passes(self) -> None:
        """Positive control: Well-formed SLO proof bundle with valid measurement artifact passes with 0 errors."""
        with tempfile.TemporaryDirectory() as tmpdir:
            root = Path(tmpdir)
            is_valid, findings, _ = verify_slo_bundle(root, build_slo_fixture(root))
            self.assertTrue(is_valid, f"Expected pass, got: {[f.message for f in findings]}")
            self.assertEqual(len(findings), 0)


# ---------------------------------------------------------------------------
# Claim class 'slo' independent-review rework (fss-x4a.30.87.5)
# ---------------------------------------------------------------------------

SLO_CLAIM_ID = "SLO-DETECT-001"  # registries/SLOS.md: "p95 first event hypothesis <= 1.5 s ..."
SLO_OPERATION_ID = "COST-DETECT-001"  # operation_cost_registry.toml: slo_ids includes SLO-DETECT-001
SLO_GENERATION = "gen-2026-09-01"
SLO_COST_GENERATION = "gen:fss1:operation-cost-v1"
SLO_NOW = FIXED_NOW
SLO_MEASUREMENT_REL = "qualification-artifacts/slo/detect.measurement.json"
SLO_ENVIRONMENT_REL = "qualification-artifacts/slo/reference.environment.json"
SLO_BUNDLE_REL = "qualification-artifacts/slo/detect.bundle.json"
STATISTICAL_EVIDENCE = ["dataset_manifest", "sampling_protocol", "confidence_interval", "held_out_results"]


def _apply_overrides(doc: dict, overrides: dict | None) -> dict:
    for key, value in (overrides or {}).items():
        if value is _DROP:
            doc.pop(key, None)
        else:
            doc[key] = value
    return doc


SLO_COST_ANCHOR = 'id = "COST-DETECT-001"\n'
SLO_FIXTURE_MAX_AGE_DAYS = 30  # a test-only value: the repository registry leaves the bound unset


def ensure_slo_freshness_bound(root: Path, days: int = SLO_FIXTURE_MAX_AGE_DAYS) -> None:
    """Gives every operation row of the test root's cost registry (a copy of the repository's
    when absent) a measurement_max_age_days. A registry a test planted without the
    COST-DETECT-001 row (empty, malformed, row-less) is left exactly as planted."""
    rel = "architecture/operation_cost_registry.toml"
    target = root / rel
    if not target.exists():
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text((ROOT / rel).read_text(encoding="utf-8"), encoding="utf-8")
    current = target.read_text(encoding="utf-8")
    if SLO_COST_ANCHOR in current and "measurement_max_age_days" not in current:
        lines: list[str] = []
        for line in current.splitlines(keepends=True):
            lines.append(line)
            if line.startswith('id = "COST-') and line.rstrip().endswith('"'):
                lines.append(f"measurement_max_age_days = {days}\n")
        target.write_text("".join(lines), encoding="utf-8")


def build_slo_fixture(
    root: Path,
    *,
    measurement: dict | None = None,
    environment: dict | None = None,
    bundle: dict | None = None,
    omit_roles: tuple[str, ...] = (),
) -> dict:
    """Writes a complete, valid 'slo' claim for SLO-DETECT-001 (retained environment manifest,
    retained measurement bound to it) under root and returns the unsealed bundle. Each
    negative test perturbs exactly one aspect through the override dictionaries."""
    ensure_slo_freshness_bound(root)
    env_doc = _apply_overrides(dict(DEFAULT_ENVIRONMENT_DATA), environment)
    env_digest = _write_doc(root, SLO_ENVIRONMENT_REL, env_doc)
    meas_doc = _apply_overrides({
        "schema": "fss.slo_measurement.v1",
        "slo_id": SLO_CLAIM_ID,
        "operation_id": SLO_OPERATION_ID,
        "generation": SLO_GENERATION,
        "operation_cost_generation": SLO_COST_GENERATION,
        "status": "passed",
        "measurement_window": {"started_at": "2026-09-01T00:00:00Z", "finished_at": "2026-09-01T01:00:00Z"},
        "unit": "s",
        "statistic": "p95",  # SLO-DETECT-001 is a p95 target (round 4, B16)
        "actual": 1.2,
        "environment_manifest_digest": env_digest,
    }, measurement)
    meas_digest = _write_doc(root, SLO_MEASUREMENT_REL, meas_doc)
    artifacts = [
        {"role": "measurement_artifact", "path": SLO_MEASUREMENT_REL, "digest": meas_digest},
        {"role": "environment_manifest", "path": SLO_ENVIRONMENT_REL, "digest": env_digest},
    ]
    return _apply_overrides({
        "schema": "fss.proof_bundle.v1",
        "bundle_id": "BUNDLE-SLO-DETECT-001",
        "claim_id": SLO_CLAIM_ID,
        "claim_class": "slo",
        "supported_level": "achieved",
        "generation": SLO_GENERATION,
        "status": "passed",
        "retained_evidence": list(SLO_EVIDENCE),
        "artifacts": [a for a in artifacts if a["role"] not in omit_roles],
    }, bundle)


def write_slo_bundle(root: Path, data: dict, rel: str = SLO_BUNDLE_REL) -> Path:
    return write_json(root / rel, seal(data))


def verify_slo_bundle(
    root: Path,
    data: dict,
    claim_id: str | None = SLO_CLAIM_ID,
    claim_level: str | None = "achieved",
    now: datetime = SLO_NOW,
    **kwargs: object,
):
    return verify_proof_bundle(
        bundle_path=write_slo_bundle(root, data),
        root=root,
        expected_claim_id=claim_id,
        claim_level=claim_level,
        known_classes=_known_classes(),
        tombstoned_ids=set(),
        prohibited_promotions=set(CANONICAL_PROHIBITED_PROMOTIONS),
        now=now,
        **kwargs,
    )


def promote_slos_row(root: Path, slo_id: str, proof_rel: str) -> None:
    """Marks one registries/SLOS.md row achieved and cites proof_rel as its proof root."""
    slos = root / "registries/SLOS.md"
    lines = slos.read_text(encoding="utf-8").splitlines(keepends=True)
    hits = [i for i, line in enumerate(lines) if line.startswith(f"| `{slo_id}` |")]
    assert len(hits) == 1, hits
    row = lines[hits[0]].rstrip("\n")
    assert row.endswith("| target | - |"), row
    lines[hits[0]] = row[: -len("| target | - |")] + f"| achieved | `{proof_rel}` |\n"
    slos.write_text("".join(lines), encoding="utf-8")


class TestSloIndependentReviewBypasses(unittest.TestCase):
    """fss-x4a.30.87.5 independent review: every planted slo bypass fails closed with an exact
    set of registered finding ids. Each case perturbs exactly one aspect of a valid fixture."""

    def run_case(
        self,
        *,
        measurement: dict | None = None,
        environment: dict | None = None,
        bundle: dict | None = None,
        omit_roles: tuple[str, ...] = (),
        claim_id: str = SLO_CLAIM_ID,
        setup=None,
        after=None,
    ) -> tuple[bool, list]:
        with tempfile.TemporaryDirectory() as tmpdir:
            root = Path(tmpdir)
            if setup is not None:
                setup(root)
            data = build_slo_fixture(root, measurement=measurement, environment=environment, bundle=bundle, omit_roles=omit_roles)
            if after is not None:
                after(root)
            ok, findings, _ = verify_slo_bundle(root, data, claim_id=claim_id)
            return ok, findings

    def assert_fails(self, expected: list[str], **case: object) -> None:
        ok, findings = self.run_case(**case)
        self.assertFalse(ok, "planted bypass was accepted")
        self.assertEqual(error_code_set(findings), sorted(set(expected)), [f"{f.code}: {f.message}" for f in findings])

    def test_control_complete_slo_bundle_passes(self) -> None:
        for label, measurement in (("canonical", None), ("matching authoritative target", {"target": 1.5, "comparison": "<="})):
            with self.subTest(case=label):
                ok, findings = self.run_case(measurement=measurement)
                self.assertTrue(ok, [f.message for f in findings])
                self.assertEqual(findings, [])

    def test_item1_missing_or_unrecognised_actual_fails(self) -> None:
        actual = _code("ERR_SLO_ACTUAL_INVALID")
        for label, measurement, expected in (
            ("no target and no actual", {"actual": _DROP}, [actual]),
            # Round 5: the lookalike key is an unknown field (exact field set), beside the missing actual.
            ("actual under unrecognised key p95_ms", {"actual": _DROP, "p95_ms": 1.2}, [actual, FIELD_UNKNOWN]),
        ):
            with self.subTest(case=label):
                self.assert_fails(expected, measurement=measurement)

    def test_item2_generation_required_and_bound(self) -> None:
        unbound = _code("ERR_SLO_GENERATION_UNBOUND")
        for label, case, expected in (
            ("bundle declares no generation", {"bundle": {"generation": _DROP}}, [unbound]),
            ("measurement declares no generation", {"measurement": {"generation": _DROP}}, [unbound]),
            ("measurement unbound to cost-registry generation", {"measurement": {"operation_cost_generation": _DROP}}, [unbound]),
            ("measurement against a stale cost-registry generation", {"measurement": {"operation_cost_generation": "gen:fss1:operation-cost-v0"}}, [ERR_STALE_GENERATION]),
        ):
            with self.subTest(case=label):
                self.assert_fails(expected, **case)

    def test_item3_validity_window_is_real(self) -> None:
        window = _code("ERR_SLO_WINDOW_INVALID")

        def win(started: object, finished: object) -> dict:
            return {"measurement_window": {"started_at": started, "finished_at": finished}}

        for label, measurement, expected in (
            ("unparseable 'yesterday'", win("yesterday", "2026-09-01T01:00:00Z"), [window]),
            ("zone-less instant", win("2026-09-01T00:00:00", "2026-09-01T01:00:00Z"), [window]),
            ("finished before started", win("2026-09-01T01:00:00Z", "2026-09-01T00:00:00Z"), [window]),
            ("window in the future", win("2026-09-03T00:00:00Z", "2026-09-03T01:00:00Z"), [window]),
            ("older than allowed staleness", win("2026-06-01T00:00:00Z", "2026-06-01T01:00:00Z"), [ERR_STALE_GENERATION]),
            ("no window", {"measurement_window": _DROP}, [window]),
        ):
            with self.subTest(case=label):
                self.assert_fails(expected, measurement=measurement)

    def test_item4_measurement_cannot_override_comparator(self) -> None:
        override = _code("ERR_SLO_COMPARATOR_OVERRIDE")
        self.assert_fails([override, ERR_CLAIM_LEVEL_EXCEEDED], measurement={"comparison": ">=", "actual": 2.0})
        self.assert_fails([override], measurement={"comparator": "ge"})

    def test_item5_non_numeric_or_rounded_only_actual_fails(self) -> None:
        actual = _code("ERR_SLO_ACTUAL_INVALID")
        for label, measurement, expected in (
            ("string actual", {"actual": "1.2"}, [actual]),
            ("boolean actual", {"actual": True}, [actual]),
            ("rounded value only", {"actual": _DROP, "reported_rounded": 1.0}, [actual]),
            ("rounded value never compared", {"actual": 1.54, "reported_rounded": 1.5}, [ERR_CLAIM_LEVEL_EXCEEDED]),
            ("negative actual", {"actual": -0.5}, [actual]),
        ):
            with self.subTest(case=label):
                self.assert_fails(expected, measurement=measurement)

    def test_item6_target_comes_from_authoritative_slo_row(self) -> None:
        target = _code("ERR_SLO_TARGET_UNBOUND")
        for label, case, expected in (
            ("measurement relaxes the target", {"measurement": {"target": 5.0, "actual": 3.0}}, [target, ERR_CLAIM_LEVEL_EXCEEDED]),
            ("non-canonical target field", {"measurement": {"target_ms": 5000.0}}, [FIELD_UNKNOWN]),  # round 5: exact field set
            ("unit differs from the SLO unit", {"measurement": {"unit": "ms", "actual": 1200.0}}, [target]),
            ("no unit", {"measurement": {"unit": _DROP}}, [target]),
            (
                "SLO row has no numeric threshold",
                {
                    "claim_id": "SLO-INGEST-001",
                    "bundle": {"claim_id": "SLO-INGEST-001"},
                    "measurement": {"slo_id": "SLO-INGEST-001", "operation_id": "COST-ACQUIRE-001", "target": 10.0, "unit": "ms", "actual": 8.0},
                },
                [target],
            ),
            (
                "SLO id not in the registry",
                {"claim_id": "SLO-NOPE-001", "bundle": {"claim_id": "SLO-NOPE-001"}, "measurement": {"slo_id": "SLO-NOPE-001"}},
                [_code("ERR_CLAIM_CLASS_UNRESOLVED")],  # review P6: only a registries/SLOS.md row binds an SLO id
            ),
        ):
            with self.subTest(case=label):
                self.assert_fails(expected, **case)

    def test_item7_exactly_one_canonical_actual(self) -> None:
        actual = _code("ERR_SLO_ACTUAL_INVALID")
        # Round 5: an actual-like key is an unknown field (exact field set), and the canonical
        # actual is compared regardless: 9.0 s misses the 1.5 s target.
        self.assert_fails([FIELD_UNKNOWN, ERR_CLAIM_LEVEL_EXCEEDED], measurement={"actual": 9.0, "actual_ms": 1.0, "target": 1.5})
        self.assert_fails([FIELD_UNKNOWN], measurement={"actual": 1.2, "achieved": 1.2})
        del actual  # the actual-shadow denylist is gone; ERR-CLAIM-SLO-ACTUAL-INVALID-001 is not expected here

    def test_item8_class_comes_from_claim_row_not_bundle(self) -> None:
        # (i) an SLO-row claim whose bundle relabels itself 'statistical' (never inspected)
        # while its measurement misses the target.
        self.assert_fails(
            [ERR_CLAIM_BINDING_MISMATCH, ERR_CLAIM_LEVEL_EXCEEDED],
            measurement={"actual": 2.0},
            bundle={"claim_class": "statistical", "retained_evidence": list(STATISTICAL_EVIDENCE)},
        )
        # (ii) a complete, valid 'proof' bundle bound to the SLO id.
        with tempfile.TemporaryDirectory() as tmpdir:
            root = Path(tmpdir)
            data = build_proof_fixture(
                root,
                model={"claim_ids": [SLO_CLAIM_ID]},
                receipt={"claim_id": SLO_CLAIM_ID},
                bundle={"claim_id": SLO_CLAIM_ID, "theorem": {"claim_id": SLO_CLAIM_ID, "statement": PROOF_THEOREM}},
            )
            ok, findings, _ = verify_slo_bundle(root, data, claim_level="verified")
            self.assertFalse(ok, "a 'proof'-relabelled bundle for an SLO-row claim skipped the slo checks")
            self.assertEqual(
                error_code_set(findings),
                sorted({ERR_CLAIM_BINDING_MISMATCH, ERR_CLAIM_LEVEL_EXCEEDED, _code("ERR_SLO_ENVIRONMENT_UNRETAINED")}),
                [f"{f.code}: {f.message}" for f in findings],
            )

    def test_item8_relabel_end_to_end_through_slos_md_and_cli(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            root = build_fixture_root(Path(tmpdir))
            data = build_slo_fixture(
                root,
                measurement={"actual": 2.0},
                bundle={"claim_class": "statistical", "retained_evidence": list(STATISTICAL_EVIDENCE)},
            )
            write_slo_bundle(root, data)
            promote_slos_row(root, SLO_CLAIM_ID, SLO_BUNDLE_REL)
            ok, findings, summary = audit_claim_proof_bundles(root, now=SLO_NOW)
            self.assertFalse(ok, "relabelled SLO bundle passed the repository audit")
            self.assertEqual(error_code_set(findings), sorted({ERR_CLAIM_BINDING_MISMATCH, ERR_CLAIM_LEVEL_EXCEEDED}))
            self.assertEqual(summary["verified_bundles_count"], 0)
            result = run_cli("--root", str(root), "--as-of", "2026-09-02T00:00:00Z")
            self.assertEqual(result.returncode, 1, result.stdout + result.stderr)

    def test_item9_failed_measurement_and_unretained_environment_fail(self) -> None:
        not_passed = _code("ERR_SLO_MEASUREMENT_NOT_PASSED")
        env = _code("ERR_SLO_ENVIRONMENT_UNRETAINED")

        def delete_env(root: Path) -> None:
            (root / SLO_ENVIRONMENT_REL).unlink()

        for label, case, expected in (
            ("measurement status failed", {"measurement": {"status": "failed"}}, [not_passed]),
            ("measurement declares no status", {"measurement": {"status": _DROP}}, [not_passed]),
            ("no environment manifest retained", {"omit_roles": ("environment_manifest",)}, [env]),
            ("environment manifest absent on disk", {"after": delete_env}, [env, ERR_PROOF_BUNDLE_NOT_FOUND]),
            ("measurement not bound to the retained manifest", {"measurement": {"environment_manifest_digest": ZERO_DIGEST}}, [env]),
            ("measurement declares no manifest binding", {"measurement": {"environment_manifest_digest": _DROP}}, [env]),
        ):
            with self.subTest(case=label):
                self.assert_fails(expected, **case)

    def test_item10_malformed_or_empty_registries_under_root_fail_closed(self) -> None:
        registry = _code("ERR_SLO_REGISTRY_INVALID")

        def put(rel: str, text: str):
            def setup(root: Path) -> None:
                (root / rel).parent.mkdir(parents=True, exist_ok=True)
                (root / rel).write_text(text, encoding="utf-8")
            return setup

        cost = "architecture/operation_cost_registry.toml"
        for label, setup in (
            ("empty cost registry", put(cost, "")),
            ("malformed cost registry", put(cost, "[[operation]\nid = \n")),
            ("cost registry without operations", put(cost, 'generation = "gen:fss1:operation-cost-v1"\n')),
            ("empty SLO registry", put("registries/SLOS.md", "")),
            ("SLO registry without a table", put("registries/SLOS.md", "# SLO registry\n\nnothing here\n")),
        ):
            with self.subTest(case=label):
                self.assert_fails([registry], setup=setup)


# ---------------------------------------------------------------------------
# Claim class 'proof' realization (fss-x4a.30.87.2)
# ---------------------------------------------------------------------------

PROOF_EVIDENCE = ["formal_artifact", "toolchain_identity", "proof_check_receipt"]
PROOF_CLAIM_ID = "FORMAL-002"
PROOF_GENERATION = "gen:fss1:formal-publication-v1"
PROOF_MODEL_ID = "MODEL-TLA-PUBLICATION-001"
PROOF_THEOREM = "Root manifest is never visible before all referenced objects are durable"
PROOF_THEOREM_NAME = "RootLast"
PROOF_MODEL_REL = "proofs/tla/publication.model.json"
PROOF_MODEL_SOURCE_REL = "proofs/tla/Publication.tla"
PROOF_ARTIFACT_REL = "proofs/tla/PublicationProof.tla"
PROOF_RECEIPT_REL = "qualification-artifacts/proof/publication.check.json"
PROOF_MODEL_SOURCE_BYTES = b"---- MODULE Publication ----\nVARIABLES staged, durable, visible\n====\n"
PROOF_ARTIFACT_BYTES = b"---- MODULE PublicationProof ----\nEXTENDS Publication\nTHEOREM RootLast == Spec => []RootVisibleImpliesDurable\n====\n"


def _code(name: str) -> str:
    """Resolves a registered finding id; an unregistered id can never match a real finding."""
    return getattr(cpb, name, f"<unregistered {name}>")


def _write_bytes(root: Path, rel: str, data: bytes) -> str:
    path = root / rel
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(data)
    return compute_sha256(data)


def _write_doc(root: Path, rel: str, doc: dict) -> str:
    return _write_bytes(root, rel, json.dumps(doc, sort_keys=True).encode("utf-8"))


def build_proof_fixture(
    root: Path,
    *,
    model: dict | None = None,
    receipt: dict | None = None,
    bundle: dict | None = None,
    artifact_rel: str = PROOF_ARTIFACT_REL,
    artifact_bytes: bytes = PROOF_ARTIFACT_BYTES,
    omit_roles: tuple[str, ...] = (),
    extra_artifacts: list[dict] | None = None,
) -> dict:
    """Writes a complete, valid 'proof' claim (model manifest, model source, formal proof
    artifact, check receipt) under root and returns the unsealed bundle. Each negative
    test perturbs exactly one aspect through the override dictionaries."""
    source_digest = _write_bytes(root, PROOF_MODEL_SOURCE_REL, PROOF_MODEL_SOURCE_BYTES)
    model_doc = {
        "schema": "fss.formal_model.v1",
        "model_id": PROOF_MODEL_ID,
        "generation": PROOF_GENERATION,
        "claim_ids": [PROOF_CLAIM_ID],
        "source": {"path": PROOF_MODEL_SOURCE_REL, "digest": source_digest},
    }
    model_doc.update(model or {})
    model_digest = _write_doc(root, PROOF_MODEL_REL, model_doc)
    artifact_digest = _write_bytes(root, artifact_rel, artifact_bytes)
    receipt_doc = {
        "schema": "fss.proof_check_receipt.v1",
        "claim_id": PROOF_CLAIM_ID,
        "status": "passed",
        "checker": "tlaps",
        "checker_version": "1.5.0",
        "model_id": PROOF_MODEL_ID,
        "model_generation": PROOF_GENERATION,
        "formal_artifact_digest": artifact_digest,
        "theorem_statement": PROOF_THEOREM,
        "theorem_name": PROOF_THEOREM_NAME,
        "model_source_digest": source_digest,
    }
    receipt_doc.update(receipt or {})
    receipt_digest = _write_doc(root, PROOF_RECEIPT_REL, receipt_doc)
    artifacts = [
        {"role": "formal_model", "path": PROOF_MODEL_REL, "digest": model_digest},
        {"role": "formal_artifact", "path": artifact_rel, "digest": artifact_digest},
        {"role": "proof_check_receipt", "path": PROOF_RECEIPT_REL, "digest": receipt_digest},
    ]
    artifacts = [a for a in artifacts if a["role"] not in omit_roles] + list(extra_artifacts or [])
    data = {
        "schema": "fss.proof_bundle.v1",
        "bundle_id": "BUNDLE-PROOF-FORMAL-002",
        "claim_id": PROOF_CLAIM_ID,
        "claim_class": "proof",
        "supported_level": "verified",
        "generation": PROOF_GENERATION,
        "status": "passed",
        "retained_evidence": list(PROOF_EVIDENCE),
        "theorem": {"claim_id": PROOF_CLAIM_ID, "name": PROOF_THEOREM_NAME, "statement": PROOF_THEOREM},
        "formal_model": {"model_id": PROOF_MODEL_ID, "generation": PROOF_GENERATION},
        "assumptions": [
            {"id": "ASSUME-PUT-ATOMIC", "statement": "each object-store PUT is atomic per object"},
            {"id": "ASSUME-FAIR-SCHEDULER", "statement": "the publisher is weakly fair"},
        ],
        "toolchain_identity": {"checker": "tlaps", "version": "1.5.0"},
        "artifacts": artifacts,
    }
    for key, value in (bundle or {}).items():
        if value is _DROP:
            data.pop(key, None)
        else:
            data[key] = value
    return data


# The citing claim row's generation reaches verify_proof_bundle only where the checker accepts it,
# so a checker without row-generation binding fails these tests by accepting bypasses rather than
# by a TypeError; test_6_verify_accepts_the_claim_row_generation pins that it is accepted.
_VERIFY_ACCEPTS_CLAIM_GENERATION = "claim_generation" in inspect.signature(verify_proof_bundle).parameters


def verify_class_bundle(
    root: Path,
    data: dict,
    claim_id: str,
    claim_level: str | None = "verified",
    claim_class: str | None = None,
    claim_generation: object = _DROP,
):
    """Verifies data as cited by the claim row claim_id; the row's class is claim_class, else
    the class of that fixture claim (CLAIM_ROW_CLASSES), never the bundle's own declaration.
    The row's generation is claim_generation, else that fixture claim's (CLAIM_ROW_GENERATIONS)."""
    path = write_json(root / "qualification-artifacts/claim.bundle.json", seal(data))
    extra: dict = {}
    if _VERIFY_ACCEPTS_CLAIM_GENERATION:
        extra["claim_generation"] = CLAIM_ROW_GENERATIONS.get(claim_id) if claim_generation is _DROP else claim_generation
    return verify_proof_bundle(
        bundle_path=path,
        root=root,
        expected_claim_id=claim_id,
        claim_level=claim_level,
        claim_class=claim_class if claim_class is not None else CLAIM_ROW_CLASSES.get(claim_id),
        known_classes=_known_classes(),
        tombstoned_ids=set(),
        prohibited_promotions=set(CANONICAL_PROHIBITED_PROMOTIONS),
        **extra,
        **_bindings_kw(verify_proof_bundle, CLAIM_ROW_CLASSES),
    )


def error_code_set(findings: list) -> list[str]:
    return sorted(set(error_codes(findings)))


class TestProofClaimClassRealization(unittest.TestCase):
    """Claim class 'proof' opens and validates the evidence its row demands (fss-x4a.30.87.2)."""

    def _run(self, **kwargs: object):
        with tempfile.TemporaryDirectory() as tmpdir:
            root = Path(tmpdir)
            data = build_proof_fixture(root, **kwargs)
            return verify_class_bundle(root, data, PROOF_CLAIM_ID)

    def assertRefused(self, result, expected: list[str]) -> None:
        is_valid, findings, _ = result
        self.assertFalse(is_valid, "planted bypass was accepted: " + repr([f.message for f in findings]))
        self.assertEqual(error_code_set(findings), sorted(expected), [f.message for f in findings])

    def test_proof_row_exact_normative_fields(self) -> None:
        data = json.loads((ROOT / "architecture/claims.json").read_text(encoding="utf-8"))
        row = next(c for c in data["classes"] if c["id"] == "proof")
        self.assertEqual(row["claim_class"], "proof")
        self.assertEqual(row["meaning"], "theorem under declared formal model")
        self.assertEqual(row["minimum_evidence"], "formal artifact, assumptions, toolchain identity, check receipt")
        self.assertEqual(row["requiredEvidence"], ["formal_artifact", "toolchain_identity", "proof_check_receipt"])
        self.assertEqual(CANONICAL_CLAIM_CLASSES["proof"], row)

    def test_proof_finding_ids_are_registered(self) -> None:
        errors_md = (ROOT / "registries/ERRORS.md").read_text(encoding="utf-8")
        expected = {
            "ERR_PROOF_FORMAL_MODEL_UNBOUND": "ERR-CLAIM-PROOF-FORMAL-MODEL-UNBOUND-001",
            "ERR_PROOF_MODEL_GENERATION_MISMATCH": "ERR-CLAIM-PROOF-MODEL-GENERATION-MISMATCH-001",
            "ERR_PROOF_THEOREM_UNBOUND": "ERR-CLAIM-PROOF-THEOREM-UNBOUND-001",
            "ERR_PROOF_FORMAL_ARTIFACT_MISSING": "ERR-CLAIM-PROOF-FORMAL-ARTIFACT-MISSING-001",
            "ERR_PROOF_TESTS_ONLY": "ERR-CLAIM-PROOF-TESTS-ONLY-001",
            "ERR_PROOF_TOOLCHAIN_UNBOUND": "ERR-CLAIM-PROOF-TOOLCHAIN-UNBOUND-001",
            "ERR_PROOF_CHECK_RECEIPT_INVALID": "ERR-CLAIM-PROOF-CHECK-RECEIPT-INVALID-001",
            "ERR_CLAIM_ASSUMPTIONS_MISSING": "ERR-CLAIM-ASSUMPTIONS-MISSING-001",
        }
        for name, code in expected.items():
            self.assertEqual(_code(name), code)
            self.assertIn(code, cpb.DIAGNOSTIC_REGISTRY)
            self.assertEqual(errors_md.count(f"| `{code}` |"), 1, code)

    def test_proof_complete_static_evidence_still_requires_a_prover_run(self) -> None:
        is_valid, findings, _ = self._run()
        self.assertFalse(is_valid)
        self.assertEqual(error_code_set(findings), [_code("ERR_PROOF_PROVER_RUN_REQUIRED")], [f.message for f in findings])
        self.assertEqual([f.code for f in findings if f.severity != "error"], [], "a proof refusal must carry no warnings")

    def test_planted_proof_without_formal_artifact_fails(self) -> None:
        self.assertRefused(self._run(omit_roles=("formal_artifact",)), [_code("ERR_PROOF_FORMAL_ARTIFACT_MISSING")])

    def test_planted_proof_artifact_missing_on_disk_fails(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            root = Path(tmpdir)
            data = build_proof_fixture(root)
            (root / PROOF_ARTIFACT_REL).unlink()
            result = verify_class_bundle(root, data, PROOF_CLAIM_ID)
        self.assertRefused(result, [ERR_PROOF_BUNDLE_NOT_FOUND, _code("ERR_PROOF_FORMAL_ARTIFACT_MISSING")])

    def test_planted_proof_empty_formal_artifact_fails(self) -> None:
        self.assertRefused(self._run(artifact_bytes=b"  \n"), [_code("ERR_PROOF_FORMAL_ARTIFACT_MISSING")])

    def test_planted_proof_model_generation_mismatch_fails(self) -> None:
        stale = "gen:fss1:formal-publication-v0"
        result = self._run(
            model={"generation": stale},
            receipt={"model_generation": stale},
            bundle={"formal_model": {"model_id": PROOF_MODEL_ID, "generation": stale}},
        )
        self.assertRefused(result, [_code("ERR_PROOF_MODEL_GENERATION_MISMATCH")])

    def test_planted_proof_declared_model_generation_differs_from_manifest_fails(self) -> None:
        result = self._run(bundle={"formal_model": {"model_id": PROOF_MODEL_ID, "generation": "gen:fss1:formal-publication-v2"}})
        self.assertRefused(result, [_code("ERR_PROOF_MODEL_GENERATION_MISMATCH")])

    def test_planted_proof_receipt_checked_other_model_generation_fails(self) -> None:
        result = self._run(receipt={"model_generation": "gen:fss1:formal-publication-v0"})
        self.assertRefused(result, [_code("ERR_PROOF_MODEL_GENERATION_MISMATCH")])

    def test_planted_proof_backed_only_by_tests_fails(self) -> None:
        result = self._run(
            artifact_rel="tests/test_publication.py",
            artifact_bytes=b"def test_root_last():\n    assert True\n",
            receipt={"checker": "pytest", "checker_version": "8.3.2"},
            bundle={"toolchain_identity": {"checker": "pytest", "version": "8.3.2"}},
        )
        self.assertRefused(result, [_code("ERR_PROOF_TESTS_ONLY")])

    def test_planted_proof_with_test_results_instead_of_formal_artifact_fails(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            root = Path(tmpdir)
            digest = _write_bytes(root, "qualification-artifacts/proof/tests.log", b"test_root_last ... ok\n")
            data = build_proof_fixture(
                root,
                omit_roles=("formal_artifact",),
                extra_artifacts=[{"role": "test_results", "path": "qualification-artifacts/proof/tests.log", "digest": digest}],
            )
            result = verify_class_bundle(root, data, PROOF_CLAIM_ID)
        self.assertRefused(result, [_code("ERR_PROOF_FORMAL_ARTIFACT_MISSING"), _code("ERR_PROOF_TESTS_ONLY")])

    def test_planted_proof_formal_artifact_in_wrong_language_fails(self) -> None:
        self.assertRefused(
            self._run(artifact_rel="proofs/tla/PublicationProof.txt"),
            [_code("ERR_PROOF_FORMAL_ARTIFACT_MISSING")],
        )

    def test_planted_proof_without_formal_model_fails(self) -> None:
        self.assertRefused(self._run(omit_roles=("formal_model",)), [_code("ERR_PROOF_FORMAL_MODEL_UNBOUND")])

    def test_planted_proof_model_not_bound_to_claim_fails(self) -> None:
        self.assertRefused(self._run(model={"claim_ids": ["FORMAL-003"]}), [_code("ERR_PROOF_FORMAL_MODEL_UNBOUND")])

    def test_planted_proof_declared_model_id_differs_fails(self) -> None:
        result = self._run(bundle={"formal_model": {"model_id": "MODEL-TLA-OTHER-001", "generation": PROOF_GENERATION}})
        self.assertRefused(result, [_code("ERR_PROOF_FORMAL_MODEL_UNBOUND")])

    def test_planted_proof_model_source_missing_fails(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            root = Path(tmpdir)
            data = build_proof_fixture(root)
            (root / PROOF_MODEL_SOURCE_REL).unlink()
            result = verify_class_bundle(root, data, PROOF_CLAIM_ID)
        self.assertRefused(result, [_code("ERR_PROOF_FORMAL_MODEL_UNBOUND")])

    def test_planted_proof_model_manifest_not_json_fails(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            root = Path(tmpdir)
            data = build_proof_fixture(root)
            data["artifacts"][0]["digest"] = _write_bytes(root, PROOF_MODEL_REL, b"not json")
            result = verify_class_bundle(root, data, PROOF_CLAIM_ID)
        self.assertRefused(result, [_code("ERR_PROOF_FORMAL_MODEL_UNBOUND")])

    def test_planted_proof_without_theorem_fails(self) -> None:
        self.assertRefused(self._run(bundle={"theorem": _DROP}), [_code("ERR_PROOF_THEOREM_UNBOUND")])

    def test_planted_proof_theorem_bound_to_other_claim_fails(self) -> None:
        result = self._run(bundle={"theorem": {"claim_id": "FORMAL-003", "statement": PROOF_THEOREM}})
        self.assertRefused(result, [_code("ERR_PROOF_THEOREM_UNBOUND")])

    def test_planted_proof_receipt_checked_other_theorem_fails(self) -> None:
        result = self._run(receipt={"theorem_statement": "Some weaker theorem"})
        self.assertRefused(result, [_code("ERR_PROOF_THEOREM_UNBOUND")])

    def test_planted_proof_without_check_receipt_fails(self) -> None:
        self.assertRefused(self._run(omit_roles=("proof_check_receipt",)), [_code("ERR_PROOF_CHECK_RECEIPT_INVALID")])

    def test_planted_proof_failed_check_receipt_fails(self) -> None:
        self.assertRefused(self._run(receipt={"status": "failed"}), [_code("ERR_PROOF_CHECK_RECEIPT_INVALID")])

    def test_planted_proof_receipt_for_other_artifact_fails(self) -> None:
        result = self._run(receipt={"formal_artifact_digest": "sha256:" + "a" * 64})
        self.assertRefused(result, [_code("ERR_PROOF_CHECK_RECEIPT_INVALID")])

    def test_planted_proof_receipt_for_other_claim_fails(self) -> None:
        self.assertRefused(self._run(receipt={"claim_id": "FORMAL-003"}), [_code("ERR_PROOF_CHECK_RECEIPT_INVALID")])

    def test_planted_proof_without_toolchain_identity_fails(self) -> None:
        self.assertRefused(self._run(bundle={"toolchain_identity": _DROP}), [_code("ERR_PROOF_TOOLCHAIN_UNBOUND")])

    def test_planted_proof_latest_toolchain_version_fails(self) -> None:
        result = self._run(
            bundle={"toolchain_identity": {"checker": "tlc", "version": "latest"}},
            receipt={"checker_version": "latest"},
        )
        self.assertRefused(result, [_code("ERR_PROOF_TOOLCHAIN_UNBOUND")])

    def test_planted_proof_receipt_toolchain_differs_fails(self) -> None:
        self.assertRefused(self._run(receipt={"checker_version": "2.18"}), [_code("ERR_PROOF_TOOLCHAIN_UNBOUND")])

    def test_planted_proof_unknown_checker_fails(self) -> None:
        result = self._run(
            bundle={"toolchain_identity": {"checker": "handwave", "version": "1"}},
            receipt={"checker": "handwave", "checker_version": "1"},
        )
        self.assertRefused(result, [_code("ERR_PROOF_TOOLCHAIN_UNBOUND")])

    def test_planted_proof_empty_assumptions_fails(self) -> None:
        self.assertRefused(self._run(bundle={"assumptions": []}), [_code("ERR_CLAIM_ASSUMPTIONS_MISSING")])

    def test_planted_proof_missing_assumptions_fails(self) -> None:
        self.assertRefused(self._run(bundle={"assumptions": _DROP}), [_code("ERR_CLAIM_ASSUMPTIONS_MISSING")])

    def test_planted_proof_unnamed_assumption_fails(self) -> None:
        result = self._run(bundle={"assumptions": [{"id": "", "statement": "anonymous"}]})
        self.assertRefused(result, [_code("ERR_CLAIM_ASSUMPTIONS_MISSING")])

    def test_proof_findings_carry_claim_class_param(self) -> None:
        _, findings, _ = self._run(omit_roles=("formal_artifact",))
        realized = [f for f in findings if f.code == _code("ERR_PROOF_FORMAL_ARTIFACT_MISSING")]
        self.assertEqual(len(realized), 1)
        self.assertEqual(realized[0].params.get("claim_class"), "proof")
        self.assertEqual(realized[0].params.get("claim_id"), PROOF_CLAIM_ID)

    def test_live_repo_passes_only_because_no_proof_claims_exist(self) -> None:
        is_valid, findings, _ = audit_claim_proof_bundles(root=ROOT)
        self.assertTrue(is_valid, [f.message for f in findings])
        retention = ROOT / "qualification-artifacts"
        proof_bundles = []
        if retention.is_dir():
            for path in sorted(retention.rglob("*")):
                if path.is_file() and path.name.endswith(cpb.BUNDLE_SUFFIXES):
                    if json.loads(path.read_text(encoding="utf-8")).get("claim_class") == "proof":
                        proof_bundles.append(path)
        self.assertEqual(proof_bundles, [])


# ---------------------------------------------------------------------------
# Claim class 'bounded_model' realization (fss-x4a.30.87.3)
# ---------------------------------------------------------------------------

BOUND_EVIDENCE = ["assumptions", "derivation", "sensitivity_analysis"]
BOUND_CLAIM_ID = "BOUND-INGEST-LATENCY-001"
BOUND_GENERATION = "gen:fss1:bound-ingest-v1"
BOUND_DERIVATION_REL = "proofs/bounds/ingest_latency.derivation.json"
BOUND_EXPRESSION = "L_ingest <= D_decode + Q_max * D_frame"
BOUND_BUNDLE_REL = "qualification-artifacts/bounds/ingest-latency.bundle.json"
PROOF_BUNDLE_REL = "qualification-artifacts/proof/formal-002.bundle.json"
# The class each fixture claim row declares (claim tables carry it in their Class column).
CLAIM_ROW_CLASSES = {PROOF_CLAIM_ID: "proof", BOUND_CLAIM_ID: "bounded_model"}
CLAIM_ROW_GENERATIONS = {PROOF_CLAIM_ID: PROOF_GENERATION, BOUND_CLAIM_ID: BOUND_GENERATION}
BOUND_ASSUMPTIONS = [
    {"id": "ASSUME-QUEUE-BOUND", "statement": "the ingest queue holds at most Q_max = 8 frames"},
    {"id": "ASSUME-DECODE-WCET", "statement": "decode worst-case execution time is at most 40 ms"},
]


def build_bound_fixture(
    root: Path,
    *,
    derivation: dict | None = None,
    bound: dict | None = None,
    bundle: dict | None = None,
    omit_derivation: bool = False,
) -> dict:
    """Writes a complete, valid 'bounded_model' claim (derivation artifact on disk) under root
    and returns the unsealed bundle; negative tests perturb exactly one aspect."""
    derivation_doc = {
        "schema": "fss.bound_derivation.v1",
        "claim_id": BOUND_CLAIM_ID,
        "generation": BOUND_GENERATION,
        "expression": BOUND_EXPRESSION,
        "comparator": "<=",
        "derived_value": 120.0,
        "units": "ms",
        "assumption_ids": [a["id"] for a in BOUND_ASSUMPTIONS],
        "steps": [
            "L_ingest = D_decode + W_queue",
            "W_queue <= Q_max * D_frame under FIFO service of a bounded queue",
            "D_decode <= 40 ms, Q_max = 8, D_frame = 10 ms, so L_ingest <= 120 ms",
        ],
        "sensitivity": [{"parameter": "Q_max", "partial": "+10 ms per additional queued frame"}],
        "invalidators": ["Q_max raised above 8", "decoder WCET exceeds 40 ms"],
        "inputs": {
            "D_decode": {"value": 40.0, "units": "ms"},
            "Q_max": {"value": 8, "units": "frames"},
            "D_frame": {"value": 10.0, "units": "ms"},
        },
        "formula": "D_decode + Q_max * D_frame",
    }
    for key, value in (derivation or {}).items():
        if value is _DROP:
            derivation_doc.pop(key, None)
        else:
            derivation_doc[key] = value
    derivation_digest = _write_doc(root, BOUND_DERIVATION_REL, derivation_doc)
    bound_obj = {"claim_id": BOUND_CLAIM_ID, "expression": BOUND_EXPRESSION, "comparator": "<=", "value": 120.0, "units": "ms"}
    for key, value in (bound or {}).items():
        if value is _DROP:
            bound_obj.pop(key, None)
        else:
            bound_obj[key] = value
    data = {
        "schema": "fss.proof_bundle.v1",
        "bundle_id": "BUNDLE-BOUND-INGEST-001",
        "claim_id": BOUND_CLAIM_ID,
        "claim_class": "bounded_model",
        "supported_level": "verified",
        "generation": BOUND_GENERATION,
        "status": "passed",
        "retained_evidence": list(BOUND_EVIDENCE),
        "assumptions": [dict(a) for a in BOUND_ASSUMPTIONS],
        "bound": bound_obj,
        "artifacts": [] if omit_derivation else [
            {"role": "derivation", "path": BOUND_DERIVATION_REL, "digest": derivation_digest},
        ],
    }
    for key, value in (bundle or {}).items():
        if value is _DROP:
            data.pop(key, None)
        else:
            data[key] = value
    return data


class TestBoundedModelClaimClassRealization(unittest.TestCase):
    """Claim class 'bounded_model' opens and validates the evidence its row demands (fss-x4a.30.87.3)."""

    def _run(self, **kwargs: object):
        with tempfile.TemporaryDirectory() as tmpdir:
            root = Path(tmpdir)
            data = build_bound_fixture(root, **kwargs)
            return verify_class_bundle(root, data, BOUND_CLAIM_ID)

    def assertRefused(self, result, expected: list[str]) -> None:
        is_valid, findings, _ = result
        self.assertFalse(is_valid, "planted bypass was accepted: " + repr([f.message for f in findings]))
        self.assertEqual(error_code_set(findings), sorted(expected), [f.message for f in findings])

    def test_bounded_model_row_exact_normative_fields(self) -> None:
        data = json.loads((ROOT / "architecture/claims.json").read_text(encoding="utf-8"))
        row = next(c for c in data["classes"] if c["id"] == "bounded_model")
        self.assertEqual(row["claim_class"], "bounded_model")
        self.assertEqual(row["meaning"], "analytically derived bound under assumptions")
        self.assertEqual(row["minimum_evidence"], "derivation, units, assumptions, sensitivity and invalidators")
        self.assertEqual(row["requiredEvidence"], ["assumptions", "derivation", "sensitivity_analysis"])
        self.assertEqual(CANONICAL_CLAIM_CLASSES["bounded_model"], row)

    def test_bounded_model_finding_ids_are_registered(self) -> None:
        errors_md = (ROOT / "registries/ERRORS.md").read_text(encoding="utf-8")
        expected = {
            "ERR_BOUND_DERIVATION_UNBOUND": "ERR-CLAIM-BOUND-DERIVATION-UNBOUND-001",
            "ERR_BOUND_EXPRESSION_UNBOUND": "ERR-CLAIM-BOUND-EXPRESSION-UNBOUND-001",
            "ERR_BOUND_UNITS_MISSING": "ERR-CLAIM-BOUND-UNITS-MISSING-001",
            "ERR_BOUND_TIGHTER_THAN_DERIVATION": "ERR-CLAIM-BOUND-TIGHTER-THAN-DERIVATION-001",
            "ERR_BOUND_SENSITIVITY_MISSING": "ERR-CLAIM-BOUND-SENSITIVITY-MISSING-001",
            "ERR_CLAIM_ASSUMPTIONS_MISSING": "ERR-CLAIM-ASSUMPTIONS-MISSING-001",
        }
        for name, code in expected.items():
            self.assertEqual(_code(name), code)
            self.assertIn(code, cpb.DIAGNOSTIC_REGISTRY)
            self.assertEqual(errors_md.count(f"| `{code}` |"), 1, code)

    def test_bounded_model_complete_evidence_passes(self) -> None:
        is_valid, findings, _ = self._run()
        self.assertTrue(is_valid, [f.message for f in findings])
        self.assertEqual(findings, [])

    def test_bounded_model_looser_than_derivation_passes(self) -> None:
        is_valid, findings, _ = self._run(bound={"value": 150.0})
        self.assertTrue(is_valid, [f.message for f in findings])
        self.assertEqual(findings, [])

    def test_planted_bound_empty_assumptions_fails(self) -> None:
        self.assertRefused(self._run(bundle={"assumptions": []}), [_code("ERR_CLAIM_ASSUMPTIONS_MISSING")])

    def test_planted_bound_missing_assumptions_fails(self) -> None:
        self.assertRefused(self._run(bundle={"assumptions": _DROP}), [_code("ERR_CLAIM_ASSUMPTIONS_MISSING")])

    def test_planted_bound_unnamed_assumption_fails(self) -> None:
        result = self._run(bundle={"assumptions": [{"statement": "queue is bounded"}, dict(BOUND_ASSUMPTIONS[1])]})
        self.assertRefused(result, [_code("ERR_CLAIM_ASSUMPTIONS_MISSING")])

    def test_planted_bound_claim_omits_derivation_assumption_fails(self) -> None:
        result = self._run(bundle={"assumptions": [dict(BOUND_ASSUMPTIONS[1])]})
        self.assertRefused(result, [_code("ERR_CLAIM_ASSUMPTIONS_MISSING")])

    def test_planted_bound_without_derivation_artifact_fails(self) -> None:
        self.assertRefused(self._run(omit_derivation=True), [_code("ERR_BOUND_DERIVATION_UNBOUND")])

    def test_planted_bound_derivation_missing_on_disk_fails(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            root = Path(tmpdir)
            data = build_bound_fixture(root)
            (root / BOUND_DERIVATION_REL).unlink()
            result = verify_class_bundle(root, data, BOUND_CLAIM_ID)
        self.assertRefused(result, [ERR_PROOF_BUNDLE_NOT_FOUND, _code("ERR_BOUND_DERIVATION_UNBOUND")])

    def test_planted_bound_derivation_for_other_claim_fails(self) -> None:
        self.assertRefused(self._run(derivation={"claim_id": "BOUND-OTHER-001"}), [_code("ERR_BOUND_DERIVATION_UNBOUND")])

    def test_planted_bound_derivation_other_generation_fails(self) -> None:
        result = self._run(derivation={"generation": "gen:fss1:bound-ingest-v0"})
        self.assertRefused(result, [_code("ERR_BOUND_DERIVATION_UNBOUND")])

    def test_planted_bound_derivation_without_steps_fails(self) -> None:
        self.assertRefused(self._run(derivation={"steps": []}), [_code("ERR_BOUND_DERIVATION_UNBOUND")])

    def test_planted_bound_missing_units_fails(self) -> None:
        self.assertRefused(self._run(bound={"units": _DROP}), [_code("ERR_BOUND_UNITS_MISSING")])

    def test_planted_bound_derivation_missing_units_fails(self) -> None:
        self.assertRefused(self._run(derivation={"units": _DROP}), [_code("ERR_BOUND_UNITS_MISSING")])

    def test_planted_bound_units_differ_from_derivation_fails(self) -> None:
        self.assertRefused(self._run(bound={"units": "s"}), [_code("ERR_BOUND_UNITS_MISSING")])

    def test_planted_bound_tighter_than_derivation_fails(self) -> None:
        self.assertRefused(self._run(bound={"value": 100.0}), [_code("ERR_BOUND_TIGHTER_THAN_DERIVATION")])

    def test_planted_bound_tighter_by_epsilon_fails(self) -> None:
        self.assertRefused(self._run(bound={"value": 119.999}), [_code("ERR_BOUND_TIGHTER_THAN_DERIVATION")])

    def test_planted_lower_bound_tighter_than_derivation_fails(self) -> None:
        expression = "A_archive >= 100 - P_loss"
        result = self._run(
            bound={"expression": expression, "comparator": ">=", "value": 99.95, "units": "%"},
            derivation={
                "expression": expression, "comparator": ">=", "derived_value": 99.9, "units": "%",
                "inputs": {"P_loss": {"value": 0.1, "units": "%"}}, "formula": "100 - P_loss",
                "sensitivity": [{"parameter": "P_loss", "partial": "-1 % availability per 1 % of loss"}],
            },
        )
        self.assertRefused(result, [_code("ERR_BOUND_TIGHTER_THAN_DERIVATION")])

    def test_planted_bound_missing_bound_fails(self) -> None:
        self.assertRefused(self._run(bundle={"bound": _DROP}), [_code("ERR_BOUND_EXPRESSION_UNBOUND")])

    def test_planted_bound_missing_expression_fails(self) -> None:
        self.assertRefused(self._run(bound={"expression": _DROP}), [_code("ERR_BOUND_EXPRESSION_UNBOUND")])

    def test_planted_bound_expression_differs_from_derivation_fails(self) -> None:
        result = self._run(bound={"expression": "L_ingest <= D_decode"})
        self.assertRefused(result, [_code("ERR_BOUND_EXPRESSION_UNBOUND")])

    def test_planted_bound_bound_to_other_claim_fails(self) -> None:
        self.assertRefused(self._run(bound={"claim_id": "BOUND-OTHER-001"}), [_code("ERR_BOUND_EXPRESSION_UNBOUND")])

    def test_planted_bound_comparator_differs_from_derivation_fails(self) -> None:
        self.assertRefused(self._run(bound={"comparator": ">="}), [_code("ERR_BOUND_EXPRESSION_UNBOUND")])

    def test_planted_bound_non_finite_value_fails(self) -> None:
        self.assertRefused(self._run(bound={"value": float("nan")}), [_code("ERR_BOUND_EXPRESSION_UNBOUND")])

    def test_planted_bound_derivation_without_sensitivity_fails(self) -> None:
        self.assertRefused(self._run(derivation={"sensitivity": []}), [_code("ERR_BOUND_SENSITIVITY_MISSING")])

    def test_planted_bound_derivation_without_invalidators_fails(self) -> None:
        self.assertRefused(self._run(derivation={"invalidators": _DROP}), [_code("ERR_BOUND_SENSITIVITY_MISSING")])

    def test_bound_findings_carry_claim_class_param(self) -> None:
        _, findings, _ = self._run(bound={"value": 100.0})
        realized = [f for f in findings if f.code == _code("ERR_BOUND_TIGHTER_THAN_DERIVATION")]
        self.assertEqual(len(realized), 1)
        self.assertEqual(realized[0].params.get("claim_class"), "bounded_model")
        self.assertEqual(realized[0].params.get("claim_id"), BOUND_CLAIM_ID)
        self.assertEqual(realized[0].params.get("claimed_value"), 100.0)
        self.assertEqual(realized[0].params.get("derived_value"), 120.0)

    def test_live_repo_passes_only_because_no_bounded_model_claims_exist(self) -> None:
        is_valid, findings, _ = audit_claim_proof_bundles(root=ROOT)
        self.assertTrue(is_valid, [f.message for f in findings])
        retention = ROOT / "qualification-artifacts"
        bound_bundles = []
        if retention.is_dir():
            for path in sorted(retention.rglob("*")):
                if path.is_file() and path.name.endswith(cpb.BUNDLE_SUFFIXES):
                    if json.loads(path.read_text(encoding="utf-8")).get("claim_class") == "bounded_model":
                        bound_bundles.append(path)
        self.assertEqual(bound_bundles, [])

# ---------------------------------------------------------------------------
# Cross-class fail-opens from the proof/bounded_model review (fss-x4a.30.87.2)
# ---------------------------------------------------------------------------

HUGE_INT = 10 ** 400  # a valid JSON integer literal that float() cannot represent
OVERSIZED_INT_TEXT = "1" + "0" * 5000  # beyond CPython's int-parsing digit limit


def class_table(*rows: str) -> str:
    return "| ID | Class | Status | Proof root | Generation |\n|---|---|---|---|---|\n" + "".join(r + "\n" for r in rows)


def scan_with_stats(root: Path, text: str, name: str = "table.md") -> tuple[list, dict]:
    md_file = root / name
    md_file.write_text(text, encoding="utf-8")
    stats: dict[str, int] = {}
    findings = scan_markdown_claim_tables(
        md_file, root, _known_classes(), set(),
        prohibited_promotions=set(CANONICAL_PROHIBITED_PROMOTIONS), stats=stats, now=FIXED_NOW,
        **_bindings_kw(scan_markdown_claim_tables, CLAIM_ROW_CLASSES),
    )
    return findings, stats


def append_readme_table(root: Path, table: str) -> None:
    readme = root / "README.md"
    readme.write_text(readme.read_text(encoding="utf-8") + "\n\n" + table, encoding="utf-8")


def relabelled_proof(root: Path, relabel: str) -> dict:
    """A complete proof claim whose bundle relabels itself and strips the proof evidence names."""
    return build_proof_fixture(root, bundle={"claim_class": relabel, "retained_evidence": list(_known_classes()[relabel])})


class TestCrossClassReviewFailOpens(unittest.TestCase):
    """fss-x4a.30.87.2 cross-class review: each planted fail-open fails closed with an exact
    finding-id set, or (overflow) yields a registered finding instead of a traceback."""

    UNRESOLVED = _code("ERR_CLAIM_CLASS_UNRESOLVED")

    def assert_codes(self, findings: list, expected: list[str]) -> None:
        self.assertEqual(error_code_set(findings), sorted(set(expected)), [f"{f.code}: {f.message}" for f in findings])

    def test_a_relabelled_proof_bundle_without_claim_row_class_fails(self) -> None:
        for relabel in ("statistical", "invariant", "benchmark"):
            with self.subTest(relabel=relabel), tempfile.TemporaryDirectory() as tmpdir:
                root = Path(tmpdir)
                path = write_json(root / PROOF_BUNDLE_REL, seal(relabelled_proof(root, relabel)))
                ok, findings, _ = verify_proof_bundle(
                    bundle_path=path, root=root, expected_claim_id=PROOF_CLAIM_ID, claim_level="verified",
                    known_classes=_known_classes(), tombstoned_ids=set(),
                    prohibited_promotions=set(CANONICAL_PROHIBITED_PROMOTIONS), now=FIXED_NOW,
                )
                self.assertFalse(ok, f"proof bundle relabelled '{relabel}' was accepted on its own say-so")
                self.assert_codes(findings, [self.UNRESOLVED])

    def test_a_markdown_row_without_class_citing_bare_statistical_bundle_fails(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            root = Path(tmpdir)
            write_json(root / "proof_bundles/stat1.bundle.json", seal({
                "schema": "fss.proof_bundle.v1",
                "claim_id": "STAT-001",
                "claim_class": "statistical",
                "supported_level": "achieved",
                "generation": "gen-active-01",
                "status": "passed",
                "retained_evidence": list(STATISTICAL_EVIDENCE),
            }))
            findings, stats = scan_with_stats(root, claim_table("| `STAT-001` | achieved | `proof_bundles/stat1.bundle.json` |"))
            self.assert_codes(findings, [self.UNRESOLVED])
            self.assertEqual(stats["bundles_passed"], 0)

    def test_a_class_column_governs_relabelled_proof_bundle(self) -> None:
        for relabel in ("statistical", "invariant", "benchmark"):
            with self.subTest(relabel=relabel), tempfile.TemporaryDirectory() as tmpdir:
                root = Path(tmpdir)
                write_json(root / PROOF_BUNDLE_REL, seal(relabelled_proof(root, relabel)))
                findings, stats = scan_with_stats(root, class_table(f"| `{PROOF_CLAIM_ID}` | proof | verified | `{PROOF_BUNDLE_REL}` | {PROOF_GENERATION} |"))
                self.assert_codes(findings, [ERR_CLAIM_BINDING_MISMATCH, ERR_CLAIM_LEVEL_EXCEEDED])
                self.assertEqual(stats["bundles_passed"], 0)

    def test_a_row_class_cannot_override_the_slo_registry(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            root = Path(tmpdir)
            write_slo_bundle(root, build_slo_fixture(root))
            findings, _ = scan_with_stats(root, class_table(f"| `{SLO_CLAIM_ID}` | proof | achieved | `{SLO_BUNDLE_REL}` |"))
            self.assert_codes(findings, [ERR_CLAIM_BINDING_MISMATCH])

    def test_a_relabel_end_to_end_through_readme_and_cli(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            root = build_fixture_root(Path(tmpdir))
            write_json(root / PROOF_BUNDLE_REL, seal(relabelled_proof(root, "statistical")))
            append_readme_table(root, class_table(f"| `{PROOF_CLAIM_ID}` | proof | verified | `{PROOF_BUNDLE_REL}` | {PROOF_GENERATION} |"))
            ok, findings, summary = audit_with(root, CLAIM_ROW_CLASSES)
            self.assertFalse(ok, "relabelled proof bundle passed the repository audit")
            self.assert_codes(findings, [ERR_CLAIM_BINDING_MISMATCH, ERR_CLAIM_LEVEL_EXCEEDED])
            self.assertEqual(summary["verified_bundles_count"], 0)
            result = run_cli("--root", str(root), "--as-of", "2026-09-02T00:00:00Z")
            self.assertEqual(result.returncode, 1, result.stdout + result.stderr)

    def test_b_unpromoted_bundle_is_not_counted_as_verified(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            root = build_fixture_root(Path(tmpdir))
            for rel, raw in DEFAULT_RETAINED_FILES.items():
                (root / rel).parent.mkdir(parents=True, exist_ok=True)
                (root / rel).write_bytes(raw)
            write_json(root / "qualification-artifacts/p/spec.bundle.json", seal(make_bundle(supported_level="specified")))
            ok, findings, summary = audit_claim_proof_bundles(root, now=FIXED_NOW)
            self.assertTrue(ok, [f"{f.code}: {f.message}" for f in findings])
            self.assertEqual(summary["bundles_checked"], 1)
            self.assertEqual(summary["verified_bundles_count"], 0, "an unpromoted bundle was reported as verified")
            self.assertEqual(summary.get("unpromoted_bundles_count"), 1)
            result = run_cli("--root", str(root), "--as-of", "2026-09-02T00:00:00Z")
            self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
            self.assertIn("0/1 claims verified", result.stdout)
            self.assertIn("1 unpromoted", result.stdout)

    def test_b_draft_absent_and_unknown_supported_levels_fail(self) -> None:
        for level, expected in (("draft", ERR_CLAIM_LEVEL_EXCEEDED), ("absent", ERR_CLAIM_LEVEL_EXCEEDED), ("gold", cpb.ERR_UNRECOGNIZED_STATE)):
            with self.subTest(level=level), tempfile.TemporaryDirectory() as tmpdir:
                ok, findings, _ = verify(Path(tmpdir), seal(make_bundle(supported_level=level)))
                self.assertFalse(ok, f"supported level '{level}' was accepted")
                self.assert_codes(findings, [expected])

    def test_c_overflowing_integers_are_findings_not_crashes(self) -> None:
        def bound_value(root: Path):
            return verify_class_bundle(root, build_bound_fixture(root, bound={"value": HUGE_INT}), BOUND_CLAIM_ID)

        def derived_value(root: Path):
            return verify_class_bundle(root, build_bound_fixture(root, derivation={"derived_value": HUGE_INT}), BOUND_CLAIM_ID)

        def slo_actual(root: Path):
            return verify_slo_bundle(root, build_slo_fixture(root, measurement={"actual": HUGE_INT}))

        def slo_target(root: Path):
            return verify_slo_bundle(root, build_slo_fixture(root, measurement={"target": HUGE_INT}))

        def oversized_bundle(root: Path):
            text = json.dumps(seal(make_bundle()))
            path = root / "big.bundle.json"
            path.write_text(text[:-1] + f', "huge": {OVERSIZED_INT_TEXT}}}', encoding="utf-8")
            return verify_proof_bundle(bundle_path=path, root=root, known_classes=_known_classes(), now=FIXED_NOW)

        def oversized_measurement(root: Path):
            data = build_slo_fixture(root)
            meas_path = root / SLO_MEASUREMENT_REL
            raw = meas_path.read_text(encoding="utf-8")
            meas_path.write_text(raw[:-1] + f', "huge": {OVERSIZED_INT_TEXT}}}', encoding="utf-8")
            data["artifacts"][0]["digest"] = compute_sha256(meas_path.read_bytes())
            return verify_slo_bundle(root, data)

        for label, run, expected in (
            ("bounded_model bound value", bound_value, [ERR_BOUND_EXPRESSION_UNBOUND]),
            ("bounded_model derived value", derived_value, [ERR_BOUND_DERIVATION_UNBOUND]),
            ("slo actual", slo_actual, [_code("ERR_SLO_ACTUAL_INVALID")]),
            ("slo restated target", slo_target, [_code("ERR_SLO_TARGET_UNBOUND")]),
            ("bundle with oversized integer", oversized_bundle, [ERR_UNREADABLE_INPUT]),
            ("measurement with oversized integer", oversized_measurement, [ERR_CLAIM_LEVEL_EXCEEDED]),
        ):
            with self.subTest(case=label), tempfile.TemporaryDirectory() as tmpdir:
                ok, findings, _ = run(Path(tmpdir))
                self.assertFalse(ok)
                self.assert_codes(findings, expected)

    def test_c_cli_reports_overflow_instead_of_traceback(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            root = build_fixture_root(Path(tmpdir))
            write_slo_bundle(root, build_slo_fixture(root, measurement={"actual": HUGE_INT}))
            promote_slos_row(root, SLO_CLAIM_ID, SLO_BUNDLE_REL)
            result = run_cli("--root", str(root), "--as-of", "2026-09-02T00:00:00Z")
            self.assertNotIn("Traceback", result.stderr)
            self.assertEqual(result.returncode, 1, result.stdout + result.stderr)
            self.assertIn("ERR-CLAIM-SLO-ACTUAL-INVALID-001", result.stdout)



# ---------------------------------------------------------------------------
# 'proof' independent-review findings 1-6 (fss-x4a.30.87.2)
# ---------------------------------------------------------------------------

NBSP = " "
LEAN_ARTIFACT_REL = "proofs/lean4/Publication.lean"
LEAN_OK_BYTES = b"import Std\n\n-- a comment may mention sorry without proving anything\ntheorem RootLast : True := by\n  trivial\n"
LEAN_TOOLCHAIN = {"checker": "lean4", "version": "v4.9.0"}
LEAN_RECEIPT = {"checker": "lean4", "checker_version": "v4.9.0"}


def lean_fixture(**kwargs: object) -> dict:
    """Overrides that turn the canonical TLA+ proof fixture into a Lean 4 one."""
    bundle = dict(kwargs.pop("bundle", {}) or {})
    bundle.setdefault("toolchain_identity", dict(LEAN_TOOLCHAIN))
    receipt = dict(LEAN_RECEIPT)
    receipt.update(kwargs.pop("receipt", {}) or {})
    out = {"artifact_rel": LEAN_ARTIFACT_REL, "artifact_bytes": LEAN_OK_BYTES, "bundle": bundle, "receipt": receipt}
    out.update(kwargs)
    return out


class TestProofReviewFindings(unittest.TestCase):
    """Each 'proof' bypass from the independent review fails closed with an exact finding-id set."""

    def _run(self, claim_generation: object = _DROP, **kwargs: object):
        with tempfile.TemporaryDirectory() as tmpdir:
            root = Path(tmpdir)
            data = build_proof_fixture(root, **kwargs)
            return verify_class_bundle(root, data, PROOF_CLAIM_ID, claim_generation=claim_generation)

    def assertRefused(self, result, expected: list[str]) -> None:
        is_valid, findings, _ = result
        self.assertFalse(is_valid, "planted bypass was accepted: " + repr([f"{f.code}: {f.message}" for f in findings]))
        self.assertEqual(error_code_set(findings), sorted(set(expected)), [f"{f.code}: {f.message}" for f in findings])

    def assertAccepted(self, result) -> None:
        is_valid, findings, _ = result
        self.assertTrue(is_valid, [f"{f.code}: {f.message}" for f in findings])
        self.assertEqual(findings, [])

    def test_review_finding_ids_are_registered(self) -> None:
        errors_md = (ROOT / "registries/ERRORS.md").read_text(encoding="utf-8")
        for name, code in {
            "ERR_CLAIM_GENERATION_UNBOUND": "ERR-CLAIM-GENERATION-UNBOUND-001",
            "ERR_PROOF_UNPROVEN_PLACEHOLDER": "ERR-CLAIM-PROOF-UNPROVEN-PLACEHOLDER-001",
        }.items():
            self.assertEqual(_code(name), code)
            self.assertIn(code, cpb.DIAGNOSTIC_REGISTRY)
            self.assertEqual(errors_md.count(f"| `{code}` |"), 1, code)

    # Positive controls ------------------------------------------------------

    def test_lean_proof_with_complete_static_evidence_still_requires_a_prover_run(self) -> None:
        self.assertRefused(self._run(**lean_fixture()), [_code("ERR_PROOF_PROVER_RUN_REQUIRED")])

    def test_tla_proof_with_complete_static_evidence_still_requires_a_prover_run(self) -> None:
        self.assertRefused(self._run(), [_code("ERR_PROOF_PROVER_RUN_REQUIRED")])

    # (1) Formal artifact content --------------------------------------------

    def test_1_one_byte_tla_artifact_fails(self) -> None:
        self.assertRefused(self._run(artifact_bytes=b"x"), [ERR_PROOF_FORMAL_ARTIFACT_MISSING_CODE()])

    def test_1_tla_module_without_declared_theorem_fails(self) -> None:
        body = b"---- MODULE PublicationProof ----\nEXTENDS Publication\nRootLast == TRUE\n====\n"
        self.assertRefused(self._run(artifact_bytes=body), [_code("ERR_PROOF_THEOREM_UNBOUND")])

    def test_1_tla_module_declaring_another_theorem_fails(self) -> None:
        body = b"---- MODULE PublicationProof ----\nTHEOREM Other == TRUE\n====\n"
        self.assertRefused(self._run(artifact_bytes=body), [_code("ERR_PROOF_THEOREM_UNBOUND")])

    def test_1_theorem_only_inside_a_tla_comment_fails(self) -> None:
        body = b"---- MODULE PublicationProof ----\n\\* THEOREM RootLast == TRUE\n(* THEOREM RootLast == TRUE *)\n====\n"
        self.assertRefused(self._run(artifact_bytes=body), [_code("ERR_PROOF_THEOREM_UNBOUND")])

    def test_1_lean_sorry_fails(self) -> None:
        result = self._run(**lean_fixture(artifact_bytes=b"theorem RootLast : False := by sorry\n"))
        self.assertRefused(result, [_code("ERR_PROOF_UNPROVEN_PLACEHOLDER")])

    def test_1_lean_admit_fails(self) -> None:
        result = self._run(**lean_fixture(artifact_bytes=b"theorem RootLast : False := by\n  admit\n"))
        self.assertRefused(result, [_code("ERR_PROOF_UNPROVEN_PLACEHOLDER")])

    def test_1_tlaps_omitted_proof_fails(self) -> None:
        body = b"---- MODULE PublicationProof ----\nTHEOREM RootLast == TRUE\nPROOF OMITTED\n====\n"
        result = self._run(
            artifact_bytes=body,
            bundle={"toolchain_identity": {"checker": "tlaps", "version": "1.5.0"}},
            receipt={"checker": "tlaps", "checker_version": "1.5.0"},
        )
        self.assertRefused(result, [_code("ERR_PROOF_UNPROVEN_PLACEHOLDER")])

    def test_1_bundle_theorem_without_formal_name_fails(self) -> None:
        result = self._run(bundle={"theorem": {"claim_id": PROOF_CLAIM_ID, "statement": PROOF_THEOREM}})
        self.assertRefused(result, [_code("ERR_PROOF_THEOREM_UNBOUND")])

    def test_1_receipt_checked_another_theorem_name_fails(self) -> None:
        self.assertRefused(self._run(receipt={"theorem_name": "Other"}), [_code("ERR_PROOF_THEOREM_UNBOUND")])

    # (2) Receipt binds the model source --------------------------------------

    def test_2_garbage_model_source_with_unchanged_receipt_fails(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            root = Path(tmpdir)
            data = build_proof_fixture(root)
            model_doc = json.loads((root / PROOF_MODEL_REL).read_text(encoding="utf-8"))
            model_doc["source"]["digest"] = _write_bytes(root, PROOF_MODEL_SOURCE_REL, b"garbage, not the checked model\n")
            data["artifacts"][0]["digest"] = _write_doc(root, PROOF_MODEL_REL, model_doc)
            result = verify_class_bundle(root, data, PROOF_CLAIM_ID)
        self.assertRefused(result, [_code("ERR_PROOF_CHECK_RECEIPT_INVALID")])

    def test_2_receipt_without_model_source_digest_fails(self) -> None:
        self.assertRefused(self._run(receipt={"model_source_digest": None}), [_code("ERR_PROOF_CHECK_RECEIPT_INVALID")])

    # (3) Tests disguised by extension ----------------------------------------

    def test_3_test_directory_lean_file_fails(self) -> None:
        result = self._run(**lean_fixture(artifact_rel="tests/test_publication.lean"))
        self.assertRefused(result, [_code("ERR_PROOF_TESTS_ONLY")])

    def test_3_double_suffix_py_tla_fails(self) -> None:
        self.assertRefused(self._run(artifact_rel="proofs/tla/PublicationProof.py.tla"), [_code("ERR_PROOF_TESTS_ONLY")])

    def test_3_test_named_tla_module_fails(self) -> None:
        self.assertRefused(self._run(artifact_rel="proofs/tla/PublicationTest.tla"), [_code("ERR_PROOF_TESTS_ONLY")])

    def test_3_lean_text_in_tla_file_fails(self) -> None:
        self.assertRefused(self._run(artifact_bytes=LEAN_OK_BYTES), [ERR_PROOF_FORMAL_ARTIFACT_MISSING_CODE()])

    def test_3_uppercase_lean_suffix_fails(self) -> None:
        result = self._run(**lean_fixture(artifact_rel="proofs/lean4/Publication.LEAN"))
        self.assertRefused(result, [ERR_PROOF_FORMAL_ARTIFACT_MISSING_CODE()])

    # (4) Concrete toolchain version ------------------------------------------

    def test_4_floating_or_unknown_versions_fail(self) -> None:
        for version in ("*", "any", ">=2.0", "unknown", "dev", "2.x", "stable", "nightly", "HEAD", "2"):
            with self.subTest(version=version):
                result = self._run(
                    bundle={"toolchain_identity": {"checker": "tlc", "version": version}},
                    receipt={"checker_version": version},
                )
                self.assertRefused(result, [_code("ERR_PROOF_TOOLCHAIN_UNBOUND")])

    # (5) No stripping of non-breaking or other whitespace ---------------------

    def test_5_non_breaking_space_is_never_stripped(self) -> None:
        cases = (
            ("receipt claim id", {"receipt": {"claim_id": PROOF_CLAIM_ID + NBSP}}, "ERR_PROOF_CHECK_RECEIPT_INVALID"),
            ("toolchain version", {
                "bundle": {"toolchain_identity": {"checker": "tlc", "version": "2.19" + NBSP}},
                "receipt": {"checker_version": "2.19" + NBSP},
            }, "ERR_PROOF_TOOLCHAIN_UNBOUND"),
            ("theorem statement", {
                "bundle": {"theorem": {"claim_id": PROOF_CLAIM_ID, "name": PROOF_THEOREM_NAME, "statement": PROOF_THEOREM + NBSP}},
                "receipt": {"theorem_statement": PROOF_THEOREM + NBSP},
            }, "ERR_PROOF_THEOREM_UNBOUND"),
            ("declared model id", {
                "bundle": {"formal_model": {"model_id": NBSP + PROOF_MODEL_ID, "generation": PROOF_GENERATION}},
            }, "ERR_PROOF_FORMAL_MODEL_UNBOUND"),
            ("receipt model generation", {"receipt": {"model_generation": PROOF_GENERATION + NBSP}}, "ERR_PROOF_MODEL_GENERATION_MISMATCH"),
        )
        for label, overrides, code_name in cases:
            with self.subTest(field=label):
                self.assertRefused(self._run(**overrides), [_code(code_name)])

    # (6) Generation bound to the claim row -----------------------------------

    def test_6_verify_accepts_the_claim_row_generation(self) -> None:
        self.assertIn("claim_generation", inspect.signature(verify_proof_bundle).parameters)

    def test_6_self_consistent_old_generation_fails(self) -> None:
        stale = "gen:fss1:formal-publication-v0"
        result = self._run(
            model={"generation": stale},
            receipt={"model_generation": stale},
            bundle={"generation": stale, "formal_model": {"model_id": PROOF_MODEL_ID, "generation": stale}},
        )
        self.assertRefused(result, [ERR_STALE_GENERATION])

    def test_6_claim_row_without_generation_fails(self) -> None:
        self.assertRefused(self._run(claim_generation=None), [_code("ERR_CLAIM_GENERATION_UNBOUND")])

    def test_6_markdown_row_generation_governs(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            root = Path(tmpdir)
            write_json(root / PROOF_BUNDLE_REL, seal(build_proof_fixture(root)))
            row = f"| `{PROOF_CLAIM_ID}` | proof | verified | `{PROOF_BUNDLE_REL}` | gen:fss1:formal-publication-v0 |"
            findings, stats = scan_with_stats(root, class_table(row))
            self.assertEqual(error_code_set(findings), [ERR_STALE_GENERATION], [f"{f.code}: {f.message}" for f in findings])
            self.assertEqual(stats["bundles_passed"], 0)

    def test_6_markdown_row_without_generation_cell_fails(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            root = Path(tmpdir)
            write_json(root / PROOF_BUNDLE_REL, seal(build_proof_fixture(root)))
            findings, stats = scan_with_stats(root, class_table(f"| `{PROOF_CLAIM_ID}` | proof | verified | `{PROOF_BUNDLE_REL}` |"))
            self.assertEqual(error_code_set(findings), [_code("ERR_CLAIM_GENERATION_UNBOUND")], [f"{f.code}: {f.message}" for f in findings])
            self.assertEqual(stats["bundles_passed"], 0)

    def test_6_audit_refuses_a_stale_row_generation_once(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            root = build_fixture_root(Path(tmpdir))
            write_json(root / PROOF_BUNDLE_REL, seal(build_proof_fixture(root)))
            row = f"| `{PROOF_CLAIM_ID}` | proof | verified | `{PROOF_BUNDLE_REL}` | gen:fss1:formal-publication-v0 |"
            append_readme_table(root, class_table(row))
            ok, findings, summary = audit_with(root, CLAIM_ROW_CLASSES)
            self.assertFalse(ok)
            self.assertEqual(error_code_set(findings), [ERR_STALE_GENERATION], [f"{f.code}: {f.message}" for f in findings])
            stale = [f for f in findings if f.code == ERR_STALE_GENERATION]
            self.assertEqual(len(stale), 1, "the citing row refuses it once; the retention walk never re-verifies a cited bundle")
            self.assertEqual(summary["verified_bundles_count"], 0)


def ERR_PROOF_FORMAL_ARTIFACT_MISSING_CODE() -> str:
    return _code("ERR_PROOF_FORMAL_ARTIFACT_MISSING")


# ---------------------------------------------------------------------------
# Cross-class review of 5a79f2c, items A-D (fss-x4a.30.87.2)
# ---------------------------------------------------------------------------

INV_CLAIM_ID = "INV-001"  # architecture/invariants.json binds it to class 'invariant'
INV_BUNDLE_REL = "qualification-artifacts/inv/inv-001.bundle.json"
STAT_CLAIM_ID = "STAT-001"  # no repository registry binds it


def _bindings_kw(fn, bindings: dict) -> dict:
    """Passes explicit claim-class bindings only to a checker that accepts them, so a checker
    without registry-bound class resolution fails these tests by accepting, never by TypeError."""
    return {"class_bindings": dict(bindings)} if "class_bindings" in inspect.signature(fn).parameters else {}


def audit_with(root: Path, bindings: dict | None = None, now: datetime = FIXED_NOW):
    return audit_claim_proof_bundles(root, now=now, **(_bindings_kw(audit_claim_proof_bundles, bindings) if bindings else {}))


def scan_plain(root: Path, text: str, name: str = "table.md") -> tuple[list, dict]:
    """Scans a claim table with no class bindings beyond what the checker itself knows."""
    md_file = root / name
    md_file.write_text(text, encoding="utf-8")
    stats: dict[str, int] = {}
    findings = scan_markdown_claim_tables(
        md_file, root, _known_classes(), set(),
        prohibited_promotions=set(CANONICAL_PROHIBITED_PROMOTIONS), stats=stats, now=FIXED_NOW,
    )
    return findings, stats


def bare_class_bundle(claim_id: str, claim_class: str, level: str = "verified") -> dict:
    """A bundle carrying only the required-evidence names of an unrealized class."""
    return seal({
        "schema": "fss.proof_bundle.v1",
        "claim_id": claim_id,
        "claim_class": claim_class,
        "supported_level": level,
        "generation": "gen-active-01",
        "status": "passed",
        "retained_evidence": list(_known_classes()[claim_class]),
    })


class TestClassReviewItemsAtoD(unittest.TestCase):
    """Each fail-open found in the review of 5a79f2c fails closed with an exact finding-id set."""

    UNRESOLVED = _code("ERR_CLAIM_CLASS_UNRESOLVED")

    def assert_codes(self, findings: list, expected: list[str]) -> None:
        self.assertEqual(error_code_set(findings), sorted(set(expected)), [f"{f.code}: {f.message}" for f in findings])

    def test_stale_generation_id_is_registered(self) -> None:
        errors_md = (ROOT / "registries/ERRORS.md").read_text(encoding="utf-8")
        self.assertEqual(ERR_STALE_GENERATION, "ERR-CLAIM-PROOF-STALE-GENERATION-001")
        self.assertEqual(errors_md.count(f"| `{ERR_STALE_GENERATION}` |"), 1)

    # A. A class comes from a registry that binds the claim id ------------------

    def test_A_unbound_id_is_unresolved_whatever_the_class_column_says(self) -> None:
        for relabel in ("statistical", "invariant", "benchmark"):
            with self.subTest(row_class=relabel), tempfile.TemporaryDirectory() as tmpdir:
                root = Path(tmpdir)
                write_json(root / PROOF_BUNDLE_REL, bare_class_bundle(PROOF_CLAIM_ID, relabel))
                findings, stats = scan_plain(root, class_table(f"| `{PROOF_CLAIM_ID}` | {relabel} | verified | `{PROOF_BUNDLE_REL}` |"))
                self.assert_codes(findings, [self.UNRESOLVED])
                self.assertEqual(stats["bundles_passed"], 0)

    def test_A_unbound_id_is_unresolved_end_to_end(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            root = build_fixture_root(Path(tmpdir))
            write_json(root / PROOF_BUNDLE_REL, bare_class_bundle(PROOF_CLAIM_ID, "statistical"))
            append_readme_table(root, class_table(f"| `{PROOF_CLAIM_ID}` | statistical | verified | `{PROOF_BUNDLE_REL}` |"))
            ok, findings, summary = audit_with(root)
            self.assertFalse(ok)
            self.assert_codes(findings, [self.UNRESOLVED])
            self.assertEqual(summary["verified_bundles_count"], 0)
            result = run_cli("--root", str(root), "--as-of", "2026-09-02T00:00:00Z")
            self.assertEqual(result.returncode, 1, result.stdout + result.stderr)

    def test_A_invariant_registry_binding_beats_the_row_class(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            root = build_fixture_root(Path(tmpdir))
            write_json(root / INV_BUNDLE_REL, bare_class_bundle(INV_CLAIM_ID, "statistical"))
            append_readme_table(root, class_table(f"| `{INV_CLAIM_ID}` | statistical | verified | `{INV_BUNDLE_REL}` |"))
            ok, findings, summary = audit_with(root)
            self.assertFalse(ok, "a row relabelled an invariant claim as statistical")
            self.assert_codes(findings, [ERR_CLAIM_BINDING_MISMATCH, ERR_CLAIM_LEVEL_EXCEEDED, _code("ERR_CLAIM_CLASS_EVIDENCE_UNINSPECTED")])
            self.assertEqual(summary["verified_bundles_count"], 0)

    def test_A_explicit_binding_cannot_override_the_invariant_registry(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            root = build_fixture_root(Path(tmpdir))
            write_json(root / INV_BUNDLE_REL, bare_class_bundle(INV_CLAIM_ID, "statistical"))
            append_readme_table(root, class_table(f"| `{INV_CLAIM_ID}` | statistical | verified | `{INV_BUNDLE_REL}` |"))
            ok, findings, _ = audit_with(root, {INV_CLAIM_ID: "statistical"})
            self.assertFalse(ok)
            self.assert_codes(findings, [ERR_CLAIM_BINDING_MISMATCH, ERR_CLAIM_LEVEL_EXCEEDED, _code("ERR_CLAIM_CLASS_EVIDENCE_UNINSPECTED")])

    # B. Verified only when the citing row's status is promoted ------------------

    def test_B_specified_row_citing_an_achieved_bundle_is_not_verified(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            root = Path(tmpdir)
            write_json(root / BOUND_BUNDLE_REL, seal(build_bound_fixture(root, bundle={"supported_level": "achieved"})))
            findings, stats = scan_with_stats(root, class_table(f"| `{BOUND_CLAIM_ID}` | bounded_model | specified | `{BOUND_BUNDLE_REL}` | {BOUND_GENERATION} |"))
            self.assertEqual(findings, [], [f"{f.code}: {f.message}" for f in findings])
            self.assertEqual(
                (stats["promoted"], stats["bundles_checked"], stats["bundles_passed"], stats["bundles_unpromoted"]),
                (0, 1, 0, 1),
            )

    def test_B_specified_row_is_not_verified_end_to_end(self) -> None:
        """A registries/SLOS.md row left at 'target' cites an achieved, fully evidenced slo bundle
        (an invariant bundle can no longer pass at all: review item P7)."""
        with tempfile.TemporaryDirectory() as tmpdir:
            root = build_fixture_root(Path(tmpdir))
            write_slo_bundle(root, build_slo_fixture(root))
            cite_slos_row(root, SLO_CLAIM_ID, SLO_BUNDLE_REL, "target")
            ok, findings, summary = audit_with(root, now=SLO_NOW)
            self.assertTrue(ok, [f"{f.code}: {f.message}" for f in findings])
            self.assertEqual(
                (summary["bundles_checked"], summary["verified_bundles_count"], summary["unpromoted_bundles_count"]),
                (1, 0, 1),
            )

    # C + D. One bundle, one count; invariant and statistical positive paths ---

    def test_C_D_P7_registry_bound_invariant_claim_is_never_verified_from_evidence_names(self) -> None:
        """Review item P7 overturns the D positive path: the invariant class has no evidence
        inspection, so a promoted invariant claim is refused (and still counted once, item C)."""
        with tempfile.TemporaryDirectory() as tmpdir:
            root = build_fixture_root(Path(tmpdir))
            write_json(root / INV_BUNDLE_REL, bare_class_bundle(INV_CLAIM_ID, "invariant"))
            append_readme_table(root, class_table(f"| `{INV_CLAIM_ID}` | invariant | verified | `{INV_BUNDLE_REL}` |"))
            ok, findings, summary = audit_with(root)
            self.assertFalse(ok)
            self.assert_codes(findings, [_code("ERR_CLAIM_CLASS_EVIDENCE_UNINSPECTED")])
            self.assertEqual(
                (summary["bundles_checked"], summary["verified_bundles_count"], summary["unpromoted_bundles_count"]),
                (1, 0, 0),
                "a bundle cited by a row and retained under qualification-artifacts is one bundle",
            )
            result = run_cli("--root", str(root), "--as-of", "2026-09-02T00:00:00Z")
            self.assertEqual(result.returncode, 1, result.stdout + result.stderr)
            self.assertIn("0/1 claims verified", result.stdout)

    def test_D_P7_statistical_claim_is_never_verified_from_evidence_names(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            root = Path(tmpdir)
            path = write_json(root / "proof_bundles/stat1.bundle.json", bare_class_bundle(STAT_CLAIM_ID, "statistical", level="achieved"))
            ok, findings, _ = verify_proof_bundle(
                bundle_path=path, root=root, expected_claim_id=STAT_CLAIM_ID, claim_level="achieved",
                claim_class="statistical", known_classes=_known_classes(), tombstoned_ids=set(),
                prohibited_promotions=set(CANONICAL_PROHIBITED_PROMOTIONS), now=FIXED_NOW,
                **_bindings_kw(verify_proof_bundle, {STAT_CLAIM_ID: "statistical"}),
            )
            self.assertFalse(ok)
            self.assertEqual(error_code_set(findings), [_code("ERR_CLAIM_CLASS_EVIDENCE_UNINSPECTED")])


# ---------------------------------------------------------------------------
# 'bounded_model' independent-review findings 1-5 (fss-x4a.30.87.3)
# ---------------------------------------------------------------------------


class TestBoundedModelReviewFindings(unittest.TestCase):
    """Each 'bounded_model' bypass from the independent review fails closed with an exact finding-id set."""

    def _run(self, claim_generation: object = _DROP, **kwargs: object):
        with tempfile.TemporaryDirectory() as tmpdir:
            root = Path(tmpdir)
            data = build_bound_fixture(root, **kwargs)
            return verify_class_bundle(root, data, BOUND_CLAIM_ID, claim_generation=claim_generation)

    def assertRefused(self, result, expected: list[str]) -> None:
        is_valid, findings, _ = result
        self.assertFalse(is_valid, "planted bypass was accepted: " + repr([f"{f.code}: {f.message}" for f in findings]))
        self.assertEqual(error_code_set(findings), sorted(set(expected)), [f"{f.code}: {f.message}" for f in findings])

    def test_review_finding_ids_are_registered(self) -> None:
        errors_md = (ROOT / "registries/ERRORS.md").read_text(encoding="utf-8")
        for name, code in {
            "ERR_BOUND_VALUE_OUT_OF_DOMAIN": "ERR-CLAIM-BOUND-VALUE-OUT-OF-DOMAIN-001",
            "ERR_BOUND_DERIVATION_NOT_RECOMPUTABLE": "ERR-CLAIM-BOUND-DERIVATION-NOT-RECOMPUTABLE-001",
        }.items():
            self.assertEqual(_code(name), code)
            self.assertIn(code, cpb.DIAGNOSTIC_REGISTRY)
            self.assertEqual(errors_md.count(f"| `{code}` |"), 1, code)

    def test_complete_recomputable_derivation_passes(self) -> None:
        is_valid, findings, _ = self._run()
        self.assertTrue(is_valid, [f"{f.code}: {f.message}" for f in findings])
        self.assertEqual(findings, [])

    # (1) Registered units only ---------------------------------------------------

    def test_1_placeholder_or_unregistered_units_fail(self) -> None:
        for units in ("none", "-", "unknown", "n/a", "?", "TBD", "MS", "ratio"):
            with self.subTest(units=units):
                result = self._run(bound={"units": units}, derivation={"units": units})
                self.assertRefused(result, [_code("ERR_BOUND_UNITS_MISSING")])

    def test_1_unregistered_input_units_fail(self) -> None:
        inputs = {"D_decode": {"value": 40.0, "units": "none"}, "Q_max": {"value": 8, "units": "frames"}, "D_frame": {"value": 10.0, "units": "ms"}}
        self.assertRefused(self._run(derivation={"inputs": inputs}), [_code("ERR_BOUND_UNITS_MISSING")])

    # (2) Case-distinct and invisible-character duplicate assumption ids -------

    def test_2_case_distinct_duplicate_assumption_ids_fail(self) -> None:
        assumptions = [dict(a) for a in BOUND_ASSUMPTIONS] + [{"id": "assume-queue-bound", "statement": "the queue is bounded again"}]
        self.assertRefused(self._run(bundle={"assumptions": assumptions}), [_code("ERR_CLAIM_ASSUMPTIONS_MISSING")])

    def test_2_assumption_id_with_non_breaking_space_fails(self) -> None:
        assumptions = [{"id": "ASSUME-QUEUE-BOUND" + NBSP, "statement": BOUND_ASSUMPTIONS[0]["statement"]}, dict(BOUND_ASSUMPTIONS[1])]
        self.assertRefused(self._run(bundle={"assumptions": assumptions}), [_code("ERR_CLAIM_ASSUMPTIONS_MISSING")])

    # (3) Substantive derivation content --------------------------------------

    def test_3_trivial_derivation_content_fails(self) -> None:
        for label, derivation, code_name in (
            ("steps ['.']", {"steps": ["."]}, "ERR_BOUND_DERIVATION_UNBOUND"),
            ("steps ['none']", {"steps": ["none"]}, "ERR_BOUND_DERIVATION_UNBOUND"),
            ("sensitivity ['none']", {"sensitivity": ["none"]}, "ERR_BOUND_SENSITIVITY_MISSING"),
            ("sensitivity [{'x': None}]", {"sensitivity": [{"x": None}]}, ("ERR_BOUND_SENSITIVITY_MISSING", "ERR_EVIDENCE_FIELD_UNKNOWN")),  # round 5: 'x' is also not a sensitivity field
            ("sensitivity on a non-input", {"sensitivity": [{"parameter": "Z_unknown", "partial": "+1 ms per unit"}]}, "ERR_BOUND_SENSITIVITY_MISSING"),
            ("sensitivity without effect", {"sensitivity": [{"parameter": "Q_max", "partial": "?"}]}, "ERR_BOUND_SENSITIVITY_MISSING"),
            ("invalidators ['none']", {"invalidators": ["none"]}, "ERR_BOUND_SENSITIVITY_MISSING"),
            ("invalidators ['TBD', '-']", {"invalidators": ["TBD", "-"]}, "ERR_BOUND_SENSITIVITY_MISSING"),
        ):
            with self.subTest(case=label):
                names = (code_name,) if isinstance(code_name, str) else code_name
                self.assertRefused(self._run(derivation=derivation), [_code(n) for n in names])

    # (4) Values inside their unit's domain -------------------------------------

    def test_4_negative_latency_bound_fails(self) -> None:
        self.assertRefused(self._run(bound={"value": -5.0}), [_code("ERR_BOUND_VALUE_OUT_OF_DOMAIN")])

    def test_4_percent_above_one_hundred_fails(self) -> None:
        percent_inputs = {"D_decode": {"value": 40.0, "units": "%"}, "Q_max": {"value": 8, "units": "frames"}, "D_frame": {"value": 10.0, "units": "%"}}
        result = self._run(bound={"units": "%", "value": 150.0}, derivation={"units": "%", "inputs": percent_inputs})
        self.assertRefused(result, [_code("ERR_BOUND_VALUE_OUT_OF_DOMAIN")])

    def test_4_negative_input_fails(self) -> None:
        inputs = {"D_decode": {"value": -40.0, "units": "ms"}, "Q_max": {"value": 8, "units": "frames"}, "D_frame": {"value": 20.0, "units": "ms"}}
        self.assertRefused(self._run(derivation={"inputs": inputs}), [_code("ERR_BOUND_VALUE_OUT_OF_DOMAIN")])

    # (5) The derived value is recomputed from recorded inputs ------------------

    def test_5_self_asserted_derived_value_fails(self) -> None:
        self.assertRefused(self._run(derivation={"derived_value": 100.0}, bound={"value": 100.0}), [_code("ERR_BOUND_DERIVATION_NOT_RECOMPUTABLE")])

    def test_5_derivation_without_inputs_or_formula_fails(self) -> None:
        for label, derivation in (
            ("no inputs", {"inputs": _DROP}),
            ("empty inputs", {"inputs": {}}),
            ("no formula", {"formula": _DROP}),
            ("formula names an unrecorded input", {"formula": "D_decode + Q_max * D_frame + X"}),
            ("formula is not arithmetic", {"formula": "__import__('os').getpid()"}),
            ("formula divides by zero", {"formula": "D_decode / (Q_max - Q_max)"}),
            ("formula is not the derived expression", {"formula": "D_frame * Q_max + D_decode"}),
        ):
            with self.subTest(case=label):
                self.assertRefused(self._run(derivation=derivation), [_code("ERR_BOUND_DERIVATION_NOT_RECOMPUTABLE")])

    # Generation bound to the claim row (as for 'proof') -----------------------

    def test_self_consistent_old_generation_fails(self) -> None:
        stale = "gen:fss1:bound-ingest-v0"
        result = self._run(bundle={"generation": stale}, derivation={"generation": stale})
        self.assertRefused(result, [ERR_STALE_GENERATION])

    def test_claim_row_without_generation_fails(self) -> None:
        self.assertRefused(self._run(claim_generation=None), [_code("ERR_CLAIM_GENERATION_UNBOUND")])


# ---------------------------------------------------------------------------
# 'slo' review of f00d2a0, items 1-7 (fss-x4a.30.87.5)
# ---------------------------------------------------------------------------

SLOS_REL = "registries/SLOS.md"
COST_REL = "architecture/operation_cost_registry.toml"
DETECT_TARGET = "≤ 1.5 s"


def _repo_detect_row() -> tuple[str, str]:
    text = (ROOT / SLOS_REL).read_text(encoding="utf-8")
    row = next(line for line in text.splitlines() if line.startswith(f"| `{SLO_CLAIM_ID}` |"))
    assert DETECT_TARGET in row, row
    return text, row


def put_slos(transform):
    """A setup hook writing a copy of registries/SLOS.md transformed by transform(text, row)."""
    def setup(root: Path) -> None:
        text, row = _repo_detect_row()
        (root / SLOS_REL).parent.mkdir(parents=True, exist_ok=True)
        (root / SLOS_REL).write_text(transform(text, row), encoding="utf-8")
    return setup


def put_cost_registry(extra_line: str | None):
    """An after hook writing the repository cost registry with extra_line after every operation
    id (None: exactly the repository's own registry, which sets no bound). Every row listing the
    SLO must set the bound, and the strictest applies (review S2)."""
    def after(root: Path) -> None:
        text = (ROOT / COST_REL).read_text(encoding="utf-8")
        if extra_line is not None:
            text = "".join(
                line + (extra_line + "\n" if line.startswith('id = "COST-') else "")
                for line in text.splitlines(keepends=True)
            )
        (root / COST_REL).write_text(text, encoding="utf-8")
    return after


class TestSloReviewItems1to7(unittest.TestCase):
    """Each slo bypass found in the review of f00d2a0 fails closed with an exact finding-id set."""

    UNBOUND = _code("ERR_SLO_TARGET_UNBOUND")

    def run_case(self, *, measurement: dict | None = None, setup=None, after=None, now: datetime = SLO_NOW):
        with tempfile.TemporaryDirectory() as tmpdir:
            root = Path(tmpdir)
            if setup is not None:
                setup(root)
            data = build_slo_fixture(root, measurement=measurement)
            if after is not None:
                after(root)
            ok, findings, _ = verify_slo_bundle(root, data, now=now)
            return ok, findings

    def assert_refused(self, expected: list[str], **case: object) -> None:
        ok, findings = self.run_case(**case)
        self.assertFalse(ok, "planted bypass was accepted: " + repr([f"{f.code}: {f.message}" for f in findings]))
        self.assertEqual(error_code_set(findings), sorted(set(expected)), [f"{f.code}: {f.message}" for f in findings])

    def test_review_finding_id_is_registered(self) -> None:
        code = "ERR-CLAIM-SLO-FRESHNESS-BOUND-UNSET-001"
        self.assertEqual(_code("ERR_SLO_FRESHNESS_UNSET"), code)
        self.assertIn(code, cpb.DIAGNOSTIC_REGISTRY)
        self.assertEqual((ROOT / "registries/ERRORS.md").read_text(encoding="utf-8").count(f"| `{code}` |"), 1)

    def test_positive_control_with_a_registry_freshness_bound_passes(self) -> None:
        ok, findings = self.run_case()
        self.assertTrue(ok, [f"{f.code}: {f.message}" for f in findings])
        self.assertEqual(findings, [])

    # 1. Units compared exactly ----------------------------------------------------

    def test_1_measurement_unit_case_variant_fails(self) -> None:
        for unit in ("S", " s", "s "):
            with self.subTest(unit=unit):
                self.assert_refused([self.UNBOUND], measurement={"unit": unit})

    def test_1_registry_unit_case_variant_fails(self) -> None:
        self.assert_refused([self.UNBOUND], setup=put_slos(lambda text, row: text.replace(row, row.replace(DETECT_TARGET, "≤ 1.5 S"))))

    # 2. Rows hidden in comments or fences are not authoritative -------------------

    def test_2_row_hidden_in_an_html_comment_fails(self) -> None:
        def hide(text: str, row: str) -> str:
            return text.replace(row + "\n", "") + "\n<!--\n" + row.replace(DETECT_TARGET, "≤ 100 s") + "\n-->\n"
        # Review P6: a hidden row binds nothing, so the SLO id itself is unresolved.
        self.assert_refused([_code("ERR_CLAIM_CLASS_UNRESOLVED")], measurement={"actual": 50.0}, setup=put_slos(hide))

    def test_2_row_hidden_in_a_code_fence_fails(self) -> None:
        def fence(text: str, row: str) -> str:
            return text.replace(row + "\n", "") + "\n```\n" + row.replace(DETECT_TARGET, "≤ 100 s") + "\n```\n"
        # Review P6: a fenced row binds nothing, so the SLO id itself is unresolved.
        self.assert_refused([_code("ERR_CLAIM_CLASS_UNRESOLVED")], measurement={"actual": 50.0}, setup=put_slos(fence))

    # 3. The comparator is a standalone, unnegated token ----------------------------

    def test_3_negated_or_glued_comparators_fail(self) -> None:
        for target in ("not > 1.5 s", "-> 1.5 s", "never ≤ 1.5 s", "<≤ 1.5 s"):
            with self.subTest(target=target):
                self.assert_refused([self.UNBOUND], setup=put_slos(lambda text, row, t=target: text.replace(row, row.replace(DETECT_TARGET, t))))

    # 4. A non-finite target is never a threshold ---------------------------------

    def test_4_overflowing_target_fails(self) -> None:
        huge = "≤ 1" + "0" * 400 + " s"
        self.assert_refused([self.UNBOUND], setup=put_slos(lambda text, row: text.replace(row, row.replace(DETECT_TARGET, huge))))

    # 5. Cost-registry integers beyond the parser's limit are a registry finding ----

    def test_5_oversized_integer_in_cost_registry_is_a_finding(self) -> None:
        def setup(root: Path) -> None:
            text = (ROOT / COST_REL).read_text(encoding="utf-8") + "\noversized = 1" + "0" * 5000 + "\n"
            (root / COST_REL).parent.mkdir(parents=True, exist_ok=True)
            (root / COST_REL).write_text(text, encoding="utf-8")
        self.assert_refused([_code("ERR_SLO_REGISTRY_INVALID")], setup=setup)

    # 6. The freshness bound comes only from the registry --------------------------

    def test_6_no_hard_coded_freshness_bound(self) -> None:
        self.assertFalse(hasattr(cpb, "SLO_MEASUREMENT_MAX_AGE"))

    def test_6_unset_freshness_bound_fails_closed(self) -> None:
        self.assert_refused([_code("ERR_SLO_FRESHNESS_UNSET")], after=put_cost_registry(None))

    def test_6_malformed_freshness_bound_is_a_registry_finding(self) -> None:
        for value in ("0", "-1", '"30"', "true", "1.5", "1000000"):
            with self.subTest(value=value):
                self.assert_refused([_code("ERR_SLO_REGISTRY_INVALID")], after=put_cost_registry(f"measurement_max_age_days = {value}"))

    def test_6_registry_bound_governs_staleness(self) -> None:
        ten_days_old = {"measurement_window": {"started_at": "2026-08-23T00:00:00Z", "finished_at": "2026-08-23T01:00:00Z"}}
        self.assert_refused([ERR_STALE_GENERATION], measurement=ten_days_old, after=put_cost_registry("measurement_max_age_days = 7"))
        sixty_days_old = {"measurement_window": {"started_at": "2026-07-04T00:00:00Z", "finished_at": "2026-07-04T01:00:00Z"}}
        ok, findings = self.run_case(measurement=sixty_days_old, after=put_cost_registry("measurement_max_age_days = 90"))
        self.assertTrue(ok, [f"{f.code}: {f.message}" for f in findings])
        self.assertEqual(findings, [])

    # 7. Naive instants and non-finite actuals ---------------------------------------

    def test_7_naive_evaluation_instant_is_a_finding(self) -> None:
        self.assert_refused([ERR_UNRECOGNIZED_STATE_CODE()], now=datetime(2026, 9, 2))

    def test_7_naive_evaluation_instant_fails_the_audit(self) -> None:
        ok, findings, _ = audit_claim_proof_bundles(ROOT, now=datetime(2026, 9, 2))
        self.assertFalse(ok)
        self.assertEqual(error_code_set(findings), [ERR_UNRECOGNIZED_STATE_CODE()])

    def test_7_non_finite_actual_is_actual_invalid(self) -> None:
        for actual in (float("inf"), 1e309):
            with self.subTest(actual=actual):
                self.assert_refused([_code("ERR_SLO_ACTUAL_INVALID")], measurement={"actual": actual})


def ERR_UNRECOGNIZED_STATE_CODE() -> str:
    return _code("ERR_UNRECOGNIZED_STATE")


# ---------------------------------------------------------------------------
# Review of c3a17fd..f0222b0, proof items P1-P4 (fss-x4a.30.87.2); probe p2_formal.py
# ---------------------------------------------------------------------------

TLA_MODULE_HEAD = b"---- MODULE PublicationProof ----\n"


def run_formal(rel: str, raw: bytes, lean: bool = False, checker: str | None = None, version: str = "1.5.0"):
    """Verifies the canonical proof claim with only its formal artifact replaced (probe p2's run)."""
    with tempfile.TemporaryDirectory() as tmpdir:
        root = Path(tmpdir)
        kwargs = lean_fixture(artifact_rel=rel, artifact_bytes=raw) if lean else dict(artifact_rel=rel, artifact_bytes=raw)
        if checker is not None:
            kwargs["bundle"] = {"toolchain_identity": {"checker": checker, "version": version}}
            kwargs["receipt"] = {"checker": checker, "checker_version": version}
        data = build_proof_fixture(root, **kwargs)
        ok, findings, _ = verify_class_bundle(root, data, PROOF_CLAIM_ID)
        return ok, error_code_set(findings)


LEAN_REL = "proofs/lean4/Publication.lean"
TLA_REL = "proofs/tla/PublicationProof.tla"


class TestProofLexerAndEscapes(unittest.TestCase):
    """Probe p2_formal.py cases as planted tests with exact finding-id sets."""

    PROVER = _code("ERR_PROOF_PROVER_RUN_REQUIRED")  # round 3, decision A: a statically clean proof still needs a prover run

    def expect(self, cases: dict, language_lean: bool, rel: str) -> None:
        for label, (raw, expected) in cases.items():
            with self.subTest(case=label):
                ok, codes = run_formal(rel, raw, lean=language_lean)
                self.assertEqual(codes, sorted(expected), label)
                self.assertEqual(ok, not expected, label)

    def test_unsound_escape_id_is_registered(self) -> None:
        code = "ERR-CLAIM-PROOF-UNSOUND-ESCAPE-001"
        self.assertEqual(_code("ERR_PROOF_UNSOUND_ESCAPE"), code)
        self.assertIn(code, cpb.DIAGNOSTIC_REGISTRY)
        self.assertEqual((ROOT / "registries/ERRORS.md").read_text(encoding="utf-8").count(f"| `{code}` |"), 1)

    def test_P1_P2_P3_lean_probe_cases(self) -> None:
        unproven, escape = _code("ERR_PROOF_UNPROVEN_PLACEHOLDER"), _code("ERR_PROOF_UNSOUND_ESCAPE")
        theorem, missing = _code("ERR_PROOF_THEOREM_UNBOUND"), _code("ERR_PROOF_FORMAL_ARTIFACT_MISSING")
        self.expect({
            "L0 control": (b"theorem RootLast : True := by\n  trivial\n", [self.PROVER]),
            "L1 '--' in a string hides sorry": (b'theorem RootLast : 1 = 2 := by\n  have h : "--" = "--" := rfl; sorry\n', [unproven]),
            "L2 _root_.sorryAx": (b"theorem RootLast : 1 = 2 := _root_.sorryAx _ false\n", [unproven]),
            "L3 MVarId.admit via elab": (b'open Lean Elab Tactic in\nelab "cheat" : tactic => liftMetaTactic fun g => do g.admit; pure []\ntheorem RootLast : 1 = 2 := by cheat\n', [unproven, escape]),
            "L4 axiom False": (b"axiom cheat : False\ntheorem RootLast : 1 = 2 := cheat.elim\n", [escape]),
            "L5 nested block comment": (b"/- /- -/\ntheorem RootLast : True := trivial\n-/\n", [theorem]),
            "L6 theorem inside a string": (b'def s := "\ntheorem RootLast : True := trivial\n"\n', [theorem]),
            "L7 theorem after #exit": (b"#exit\ntheorem RootLast : True := trivial\n", [escape, theorem]),
            "L8 Cyrillic sorry lookalike": ("theorem RootLast : 1 = 2 := by\n  ѕorry\n".encode(), [unproven]),
            "L9 admit in a tactic block": (b"theorem RootLast : 1 = 2 := by\n  admit\n", [unproven]),
            "L10 Python saved as .lean": (b"import pytest\ntheorem RootLast = None\ndef test_root_last():\n    assert True\n", [missing]),
            "L11 stop tactic": (b"theorem RootLast : 1 = 2 := by\n  stop\n  rfl\n", [unproven]),
            "L12 '/-' in a string hides sorry": (b'theorem RootLast : "/-" = "/-" := by\n  sorry\ndef t := "-/"\n', [unproven]),
            "L13 @sorryAx": (b"theorem RootLast : 1 = 2 := @sorryAx _ false\n", [unproven]),
            "L14 decreasing_by sorry": (b"theorem RootLast : True := trivial\ndecreasing_by sorry\n", [unproven]),
            "L15 guillemet-quoted sorry": ("theorem RootLast : 1 = 2 := «sorry»\n".encode(), [unproven]),
            "L16 unterminated nested comment": (b"/- /- -/\ntheorem RootLast : True := trivial\n", [missing]),
        }, True, LEAN_REL)

    def test_P1_lean_lexer_does_not_over_refuse(self) -> None:
        self.expect({
            "sorry only in strings, char literals and nested comments": (
                b'def msg := "sorry -- /- admit"\ndef c := \'-\'\n/- outer /- inner sorry -/ still comment admit -/\n'
                b"-- stop\ntheorem RootLast : True := by\n  trivial\n", [self.PROVER]),
            "attributes, namespaces and a Greek binder": (
                "namespace Pub\n@[simp] theorem RootLast (α : Type) : True := by\n  trivial\nend Pub\n".encode(), [self.PROVER]),
        }, True, LEAN_REL)

    def test_P1_P2_tla_probe_cases(self) -> None:
        unproven, escape = _code("ERR_PROOF_UNPROVEN_PLACEHOLDER"), _code("ERR_PROOF_UNSOUND_ESCAPE")
        theorem, missing = _code("ERR_PROOF_THEOREM_UNBOUND"), _code("ERR_PROOF_FORMAL_ARTIFACT_MISSING")
        m = TLA_MODULE_HEAD
        self.expect({
            "T0 control": (m + b"THEOREM RootLast == TRUE\n====\n", [self.PROVER]),
            "T1 theorem in a nested (* comment": (m + b"(* (* *)\nTHEOREM RootLast == TRUE\n*)\n====\n", [theorem]),
            "T2 '(*' in a string hides OMITTED": (m + b'THEOREM RootLast == "(*" = "(*"\nPROOF OMITTED\nLEMMA Z == "*)" = "*)"\n====\n', [unproven]),
            "T3 theorem in a second module after ====": (m + b"====\n---- MODULE Other ----\nTHEOREM RootLast == TRUE\n====\n", [theorem]),
            "T4 theorem in a nested module": (m + b"---- MODULE Inner ----\nTHEOREM RootLast == TRUE\n====\n====\n", [theorem]),
            "T5a THEOREM and name on separate lines": (m + b"THEOREM\n  RootLast == TRUE\n====\n", [theorem]),
            "T5b unicode definition sign": (m + "THEOREM RootLast ≜ TRUE\n====\n".encode(), [theorem]),
            "T5c indented THEOREM": (m + b"   THEOREM RootLast == TRUE\n====\n", [self.PROVER]),
            "T6 ASSUME FALSE with PROOF OBVIOUS": (m + b"ASSUME FALSE\nTHEOREM RootLast == 1 = 2\nPROOF OBVIOUS\n====\n", [escape]),
            "T6b AXIOM": (m + b"AXIOM FALSE\nTHEOREM RootLast == 1 = 2\nBY DEF RootLast\n====\n", [escape]),
            "T7 lowercase omitted": (m + b"THEOREM RootLast == 1 = 2\nPROOF omitted\n====\n", [unproven]),
            "T8 OMITTED": (m + b"THEOREM RootLast == 1 = 2\nPROOF OMITTED\n====\n", [unproven]),
            "T9 text before the header": (b"junk\n" + m + b"THEOREM RootLast == TRUE\n====\n", [missing]),
            "T10 sequent ASSUME inside a theorem": (m + b"THEOREM RootLast ==\n  ASSUME NEW x\n  PROVE x = x\nOBVIOUS\n====\n", [self.PROVER]),
            "T11 unterminated module": (m + b"THEOREM RootLast == TRUE\n", [missing]),
        }, False, TLA_REL)

    def test_P2_model_checkers_cannot_back_a_proof(self) -> None:
        for checker in ("tlc", "apalache"):
            with self.subTest(checker=checker):
                ok, codes = run_formal(TLA_REL, TLA_MODULE_HEAD + b"THEOREM RootLast == TRUE\n====\n", checker=checker, version="2.19")
                self.assertFalse(ok)
                self.assertEqual(codes, [_code("ERR_PROOF_TOOLCHAIN_UNBOUND")])

    def test_P4_disguised_test_paths(self) -> None:
        body = TLA_MODULE_HEAD + b"THEOREM RootLast == TRUE\n====\n"
        for rel in ("proofs/test_suite/Proof.tla", "proofs/__tests__/Proof.tla", "proofs/unit-tests/Proof.tla",
                    "proofs/TestSpec.tla", "proofs/ProofTest.tla", "proofs/pytest_proof.tla", "proofs/spec.py.tla",
                    "proofs/fuzz/Proof.tla", "proofs/spec/Proof.tla", "proofs/proof_tests/Proof.tla", "proofs/TESTS/Proof.tla"):
            with self.subTest(path=rel):
                ok, codes = run_formal(rel, body)
                self.assertFalse(ok)
                self.assertEqual(codes, [_code("ERR_PROOF_TESTS_ONLY")])
        for rel in ("proofs/check/PublicationProof.tla", "proofs/tla/PublicationSpec.tla", "proofs/tla/Attestation.tla"):
            with self.subTest(control=rel):
                self.assertEqual(run_formal(rel, body), (False, [self.PROVER]))
        ok, codes = run_formal("proofs/Proof.TLA", body)
        self.assertEqual((ok, codes), (False, [_code("ERR_PROOF_FORMAL_ARTIFACT_MISSING")]))


# ---------------------------------------------------------------------------
# Review of c3a17fd..f0222b0, items P5-P7 (fss-x4a.30.87.2); probe p3_class.py
# ---------------------------------------------------------------------------

INV_REGISTRY_REL = "architecture/invariants.json"


def cite_slos_row(root: Path, slo_id: str, proof_rel: str, status: str) -> None:
    """Sets one registries/SLOS.md row's status and cites proof_rel as its proof root."""
    slos = root / "registries/SLOS.md"
    lines = slos.read_text(encoding="utf-8").splitlines(keepends=True)
    hits = [i for i, line in enumerate(lines) if line.startswith(f"| `{slo_id}` |")]
    assert len(hits) == 1, hits
    row = lines[hits[0]].rstrip("\n")
    assert row.endswith("| target | - |"), row
    lines[hits[0]] = row[: -len("| target | - |")] + f"| {status} | `{proof_rel}` |\n"
    slos.write_text("".join(lines), encoding="utf-8")


def readme_audit(rows: list[str], files: dict, bindings: dict | None = None, inv_extra: list | None = None):
    """Probe p3's readme_audit: README claim rows citing bundles, optional extra invariant rows."""
    with tempfile.TemporaryDirectory() as tmpdir:
        root = build_fixture_root(Path(tmpdir))
        if inv_extra is not None:
            doc = json.loads((ROOT / INV_REGISTRY_REL).read_text(encoding="utf-8"))
            doc["invariants"].extend(inv_extra)
            write_json(root / INV_REGISTRY_REL, doc)
        for rel, data in files.items():
            write_json(root / rel, data)
        append_readme_table(root, class_table(*rows))
        ok, findings, summary = audit_with(root, bindings)
        return ok, error_code_set(findings), (summary["bundles_checked"], summary["verified_bundles_count"], summary["unpromoted_bundles_count"])


class TestReviewP5toP7(unittest.TestCase):
    """Probe p3_class.py cases as planted tests with exact finding-id sets."""

    def test_new_ids_are_registered(self) -> None:
        errors_md = (ROOT / "registries/ERRORS.md").read_text(encoding="utf-8")
        for name, code in {
            "ERR_CLAIM_CLASS_REGISTRY_INVALID": "ERR-CLAIM-CLASS-REGISTRY-INVALID-001",
            "ERR_CLAIM_CLASS_EVIDENCE_UNINSPECTED": "ERR-CLAIM-CLASS-EVIDENCE-UNINSPECTED-001",
        }.items():
            self.assertEqual(_code(name), code)
            self.assertIn(code, cpb.DIAGNOSTIC_REGISTRY)
            self.assertEqual(errors_md.count(f"| `{code}` |"), 1, code)

    # P5. Top-level identity is byte-exact ----------------------------------------

    def test_P5_top_level_identity_is_byte_exact(self) -> None:
        mismatch, unrecognized = ERR_CLAIM_BINDING_MISMATCH, _code("ERR_UNRECOGNIZED_STATE")
        for label, override, expected in (
            ("claim_id with NBSP", {"claim_id": PROOF_CLAIM_ID + NBSP}, [mismatch]),
            ("claimId with NBSP beside claim_id", {"claimId": PROOF_CLAIM_ID + NBSP}, [mismatch]),
            ("claim_id with a leading space", {"claim_id": " " + PROOF_CLAIM_ID}, [mismatch]),
            ("claim_class with NBSP", {"claim_class": "proof" + NBSP}, [mismatch]),
            ("status PASSED with NBSP", {"status": "PASSED" + NBSP}, [unrecognized]),
            ("status PASSED", {"status": "PASSED"}, [unrecognized]),
            ("status with a trailing space", {"status": "passed "}, [unrecognized]),
        ):
            with self.subTest(case=label), tempfile.TemporaryDirectory() as tmpdir:
                root = Path(tmpdir)
                ok, findings, _ = verify_class_bundle(root, build_proof_fixture(root, bundle=override), PROOF_CLAIM_ID)
                self.assertFalse(ok, label)
                self.assertEqual(error_code_set(findings), expected, [f"{f.code}: {f.message}" for f in findings])

    # P6. Class binding --------------------------------------------------------------

    def test_P6_tombstoned_invariant_cannot_be_rebound_by_an_explicit_binding(self) -> None:
        rows = ["| `INV-900` | invariant | verified | `qualification-artifacts/inv/t.bundle.json` |"]
        files = {"qualification-artifacts/inv/t.bundle.json": bare_class_bundle("INV-900", "invariant")}
        extra = [{"id": "INV-900", "status": "tombstoned"}]
        unresolved = _code("ERR_CLAIM_CLASS_UNRESOLVED")
        self.assertEqual(readme_audit(rows, files, None, extra), (False, [unresolved], (1, 0, 0)))
        self.assertEqual(readme_audit(rows, files, {"INV-900": "invariant"}, extra), (False, [unresolved], (1, 0, 0)))

    def test_P6_duplicate_invariant_ids_are_registry_invalid(self) -> None:
        rows = ["| `INV-901` | invariant | verified | `qualification-artifacts/inv/u.bundle.json` |"]
        files = {"qualification-artifacts/inv/u.bundle.json": bare_class_bundle("INV-901", "invariant")}
        base = [_code("ERR_CLAIM_CLASS_REGISTRY_INVALID"), _code("ERR_CLAIM_CLASS_UNRESOLVED")]
        for label, extra, also in (
            ("tombstoned then normative", [{"id": "INV-901", "status": "tombstoned"}, {"id": "INV-901", "status": "normative"}], []),
            # the repository stable-ID audit refuses case-distinct duplicate ids as well
            ("case-distinct", [{"id": "INV-901", "status": "normative"}, {"id": "inv-901", "status": "normative"}],
             [_code("ERR_TOMBSTONE_INDEX_UNAVAILABLE")]),
        ):
            with self.subTest(case=label):
                self.assertEqual(readme_audit(rows, files, None, extra), (False, sorted(base + also), (1, 0, 0)))

    def test_P6_slo_ids_bind_only_through_slos_md_rows(self) -> None:
        self.assertEqual(cpb._registry_claim_class("SLO-DETECT-001", {}), "slo")
        self.assertIsNone(cpb._registry_claim_class("SLO-NOTREAL-999", {}))
        self.assertIsNone(cpb._registry_claim_class("SLO-NOTREAL-999", {"SLO-NOTREAL-999": "slo"}))
        for bindings in ({}, {"SLO-NOTREAL-999": "slo"}):
            with self.subTest(bindings=bindings), tempfile.TemporaryDirectory() as tmpdir:
                root = Path(tmpdir)
                bundle = seal({**make_bundle(claim_id="SLO-NOTREAL-999"), "artifacts": []})
                path = write_json(root / "proof_bundles/notreal.bundle.json", bundle)
                ok, findings, _ = verify_proof_bundle(
                    bundle_path=path, root=root, expected_claim_id="SLO-NOTREAL-999", claim_level="achieved",
                    known_classes=_known_classes(), tombstoned_ids=set(), now=FIXED_NOW,
                    **_bindings_kw(verify_proof_bundle, bindings),
                )
                self.assertFalse(ok)
                self.assertEqual(error_code_set(findings), [_code("ERR_CLAIM_CLASS_UNRESOLVED")])

    # P7. The verified count cannot be inflated --------------------------------------

    def test_P7_unrealized_class_is_never_verified(self) -> None:
        rows = ["| `INV-001` | invariant | verified | `qualification-artifacts/inv/a.bundle.json` |"]
        files = {"qualification-artifacts/inv/a.bundle.json": bare_class_bundle("INV-001", "invariant")}
        self.assertEqual(readme_audit(rows, files), (False, [_code("ERR_CLAIM_CLASS_EVIDENCE_UNINSPECTED")], (1, 0, 0)))

    def test_P7_two_copies_of_one_bundle_count_once(self) -> None:
        copy_rel = "qualification-artifacts/bounds/ingest-latency-copy.bundle.json"
        with tempfile.TemporaryDirectory() as tmpdir:
            root = build_fixture_root(Path(tmpdir))
            bundle = seal(build_bound_fixture(root))
            write_json(root / BOUND_BUNDLE_REL, bundle)
            write_json(root / copy_rel, bundle)
            table = class_table(
                f"| `{BOUND_CLAIM_ID}` | bounded_model | verified | `{BOUND_BUNDLE_REL}` | {BOUND_GENERATION} |",
                f"| `{BOUND_CLAIM_ID}` | bounded_model | verified | `{copy_rel}` | {BOUND_GENERATION} |",
            )
            findings, stats = scan_with_stats(root, table)
            self.assertEqual(findings, [], [f"{f.code}: {f.message}" for f in findings])
            self.assertEqual((stats["bundles_checked"], stats["bundles_passed"], stats["bundles_unpromoted"]), (1, 1, 0))
            append_readme_table(root, table)
            ok, findings, summary = audit_with(root, CLAIM_ROW_CLASSES)
            self.assertTrue(ok, [f"{f.code}: {f.message}" for f in findings])
            self.assertEqual((summary["bundles_checked"], summary["verified_bundles_count"], summary["unpromoted_bundles_count"]), (1, 1, 0))

    def test_P7_scan_counts_one_resolved_path_once(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            root = Path(tmpdir)
            write_json(root / BOUND_BUNDLE_REL, seal(build_bound_fixture(root)))
            findings, stats = scan_with_stats(root, class_table(
                f"| `{BOUND_CLAIM_ID}` | bounded_model | verified | `{BOUND_BUNDLE_REL}` | {BOUND_GENERATION} |",
                f"| `{BOUND_CLAIM_ID}` | bounded_model | verified | `./{BOUND_BUNDLE_REL}` | {BOUND_GENERATION} |",
            ))
            self.assertEqual(findings, [])
            self.assertEqual((stats["promoted"], stats["bundles_checked"], stats["bundles_passed"]), (2, 1, 1))


# ---------------------------------------------------------------------------
# Review of c3a17fd..f0222b0, bounded_model items B1-B4 (fss-x4a.30.87.3); probes p1, p5
# ---------------------------------------------------------------------------

FIXTURE_INPUTS = {
    "D_decode": {"value": 40.0, "units": "ms"},
    "Q_max": {"value": 8, "units": "frames"},
    "D_frame": {"value": 10.0, "units": "ms"},
}


def bound_case(formula: str, inputs: dict, value: float, derived: float, expression: str | None = None) -> dict:
    """Overrides for build_bound_fixture: a claim whose bound and derivation both use formula."""
    expression = expression if expression is not None else f"L_ingest <= {formula}"
    first = next(iter(inputs))
    return {
        "bound": {"expression": expression, "value": value},
        "derivation": {
            "expression": expression, "formula": formula, "inputs": inputs, "derived_value": derived,
            "sensitivity": [{"parameter": first, "partial": "larger values raise the derived bound"}],
        },
    }


class TestBoundedReviewB1toB4(unittest.TestCase):
    """Probe p1_formula.py / p5_gen_bound.py bound cases as planted tests with exact finding-id sets."""

    def run_bound(self, **kwargs: object):
        with tempfile.TemporaryDirectory() as tmpdir:
            root = Path(tmpdir)
            ok, findings, _ = verify_class_bundle(root, build_bound_fixture(root, **kwargs), BOUND_CLAIM_ID)
            return ok, error_code_set(findings)

    def assert_case(self, expected: list[str], **kwargs: object) -> None:
        ok, codes = self.run_bound(**kwargs)
        self.assertEqual(codes, sorted(expected))
        self.assertEqual(ok, not expected)

    def test_dimension_id_is_registered(self) -> None:
        code = "ERR-CLAIM-BOUND-DIMENSION-MISMATCH-001"
        self.assertEqual(_code("ERR_BOUND_DIMENSION_MISMATCH"), code)
        self.assertIn(code, cpb.DIAGNOSTIC_REGISTRY)
        self.assertEqual((ROOT / "registries/ERRORS.md").read_text(encoding="utf-8").count(f"| `{code}` |"), 1)

    # B1. Every intermediate result is finite and never underflows to zero --------

    def test_B1_intermediate_overflow_and_underflow_fail(self) -> None:
        recompute, dimension = _code("ERR_BOUND_DERIVATION_NOT_RECOMPUTABLE"), _code("ERR_BOUND_DIMENSION_MISMATCH")
        huge, tiny = {"X": {"value": 1e308, "units": "ms"}}, {"X": {"value": 1e-200, "units": "ms"}}
        for label, case, expected in (
            ("overflow hidden by a later division", bound_case("X / (X * X) * X * X", huge, 0.0, 0.0), [recompute]),
            ("underflow to zero", bound_case("X * X / X", tiny, 0.0, 0.0), [recompute]),
            ("probe 1 / (X * X)", bound_case("1 / (X * X)", huge, 0.0, 0.0), [recompute, dimension]),
        ):
            with self.subTest(case=label):
                self.assert_case(expected, **case)
        with self.assertRaises(cpb._FormulaError):
            cpb._evaluate_formula("1/(x*x)", {"x": 1e308})

    # B2. Placeholders survive neither punctuation nor repetition ------------------

    def test_B2_punctuated_or_trivial_content_fails(self) -> None:
        unbound, sensitivity = _code("ERR_BOUND_DERIVATION_UNBOUND"), _code("ERR_BOUND_SENSITIVITY_MISSING")
        for label, derivation, expected in (
            ("probe: TBD. none. (n/a) / TODO! unknown. / tbd;",
             {"steps": ["TBD.", "none.", "(n/a)"], "invalidators": ["TODO!", "unknown."],
              "sensitivity": [{"parameter": "Q_max", "partial": "tbd;"}]}, [unbound, sensitivity]),
            ("probe: aaa / xxx / zzz",
             {"steps": ["aaa"], "invalidators": ["xxx"], "sensitivity": [{"parameter": "Q_max", "partial": "zzz"}]}, [unbound, sensitivity]),
            ("steps N/A N/A", {"steps": ["N/A N/A"]}, [unbound]),
            ("invalidators (none)", {"invalidators": ["(none)"]}, [sensitivity]),
            ("invalidators not applicable", {"invalidators": ["not applicable"]}, [sensitivity]),
            ("partial queue queue", {"sensitivity": [{"parameter": "Q_max", "partial": "queue queue"}]}, [sensitivity]),
        ):
            with self.subTest(case=label):
                self.assert_case(expected, derivation=derivation)

    # B3. Units propagate through the formula -----------------------------------------

    def test_B3_dimensionally_inconsistent_formulas_fail(self) -> None:
        dimension, recompute = _code("ERR_BOUND_DIMENSION_MISMATCH"), _code("ERR_BOUND_DERIVATION_NOT_RECOMPUTABLE")
        for label, case, expected in (
            ("probe: ms + frames", bound_case("D_decode + Q_max", {k: FIXTURE_INPUTS[k] for k in ("D_decode", "Q_max")}, 48.0, 48.0), [dimension]),
            ("result in ms squared", bound_case("D_decode * D_frame", {k: FIXTURE_INPUTS[k] for k in ("D_decode", "D_frame")}, 400.0, 400.0), [dimension]),
            ("a constant names no input", bound_case("120", FIXTURE_INPUTS, 120.0, 120.0), [recompute]),
        ):
            with self.subTest(case=label):
                self.assert_case(expected, **case)

    def test_B3_count_units_are_dimensionless_and_constants_adopt_units(self) -> None:
        self.assert_case([])  # D_decode [ms] + Q_max [frames] * D_frame [ms] is a latency in ms

    # B4. The formula is compared to the expression as a syntax tree -------------------

    def test_B4_formula_spacing_and_parentheses_do_not_matter(self) -> None:
        for label, case in (
            ("probe: no spaces", {"derivation": {"formula": "D_decode+Q_max*D_frame"}}),
            ("redundant parentheses", {"derivation": {"formula": "(D_decode) + (Q_max * D_frame)"}}),
            ("expression without spaces around the comparator", {
                "bound": {"expression": "L_ingest<=D_decode + Q_max * D_frame"},
                "derivation": {"expression": "L_ingest<=D_decode + Q_max * D_frame"},
            }),
        ):
            with self.subTest(case=label):
                self.assert_case([], **case)


# ---------------------------------------------------------------------------
# Review of c3a17fd..f0222b0, slo items S1-S3 (fss-x4a.30.87.5); probe p4_slo.py
# ---------------------------------------------------------------------------

# Every live registries/SLOS.md target with a threshold, as (comparator, value, unit) triples.
LIVE_SLO_THRESHOLDS = {
    "SLO-LIVE-001": [("<=", 750.0, "ms")],
    "SLO-DETECT-001": [("<=", 1.5, "s")],
    "SLO-ALERT-001": [("<=", 3.0, "s")],
    "SLO-QUERY-001": [("<=", 100.0, "ms")],
    "SLO-AGENT-001": [("<=", 800.0, "tokens"), ("<=", 250.0, "ms")],
    "SLO-CONTINUITY-001": [(">=", 99.9, "%")],
    "SLO-AGENT-ORIENT-001": [("<=", 2.0, "semantic calls"), ("<=", 1600.0, "output tokens")],
    "SLO-AGENT-FOLLOW-001": [("<=", 250.0, "ms")],
}


def cost_registry_with_bounds(default: int, overrides: dict[str, int]) -> str:
    """The repository cost registry with measurement_max_age_days on every operation row."""
    lines: list[str] = []
    for line in (ROOT / COST_REL).read_text(encoding="utf-8").splitlines(keepends=True):
        lines.append(line)
        if line.startswith('id = "COST-'):
            op_id = line.split('"')[1]
            lines.append(f"measurement_max_age_days = {overrides.get(op_id, default)}\n")
    return "".join(lines)


class TestSloReviewS1toS3(unittest.TestCase):
    """Probe p4_slo.py cases as planted tests with exact finding-id sets."""

    def run_case(self, *, measurement: dict | None = None, setup=None, after=None):
        with tempfile.TemporaryDirectory() as tmpdir:
            root = Path(tmpdir)
            if setup is not None:
                setup(root)
            data = build_slo_fixture(root, measurement=measurement)
            if after is not None:
                after(root)
            ok, findings, _ = verify_slo_bundle(root, data, now=SLO_NOW)
            return ok, error_code_set(findings)

    # S1. A positive target grammar ---------------------------------------------------

    def test_S1_every_live_slos_md_target_parses(self) -> None:
        parse = getattr(cpb, "_parse_slo_target", None)
        self.assertIsNotNone(parse, "the checker has no positive SLO target grammar")
        rows, registry_findings = cpb.load_slo_registry(ROOT)
        self.assertEqual(registry_findings, [])
        parsed = {}
        for slo_id, row in sorted(rows.items()):
            if row.is_tombstone:
                continue
            thresholds, defect = parse(row.target)
            self.assertIsNone(defect, f"{slo_id} target {row.target!r}: {defect}")
            if thresholds:
                parsed[slo_id] = [(t.comparator, t.value, t.unit) for t in thresholds]
        self.assertEqual(parsed, LIVE_SLO_THRESHOLDS)

    def test_S1_targets_outside_the_grammar_are_unbound(self) -> None:
        unbound = _code("ERR_SLO_TARGET_UNBOUND")
        for target in ("(not ≤ 1.5 s)", "*not* ≤ 1.5 s", "not: ≤ 1.5 s", "isn't ≤ 1.5 s", "¬ ≤ 1.5 s", "!≤ 1.5 s",
                       "never ≤ 1.5 s", "NOT ≤ 1.5 s", "not​ ≤ 1.5 s", "not ≤ 1.5 s", "p95≤ 1.5 s", "≤1.5 s",
                       "≤ 1.5 S", "≤ 1" + "0" * 400 + " s", "≤ 1.5 s (not guaranteed)", "without ≤ 1.5 s",
                       "exceeds ≤ 1.5 s", "“not” ≤ 1.5 s", "not<br>≤ 1.5 s", "_not_ ≤ 1.5 s", "not. ≤ 1.5 s",
                       "~~≤ 1.5 s~~", "≤ 1.5 s or ≤ 900 ms", "<= 1.5 s"):
            with self.subTest(target=target):
                setup = put_slos(lambda text, row, t=target: text.replace(row, row.replace(DETECT_TARGET, t)))
                self.assertEqual(self.run_case(setup=setup), (False, [unbound]))

    def test_S1_targets_slo_validate_refuses_are_registry_findings(self) -> None:
        """slo_validate refuses these rows structurally (a glued unit is ambiguous; registered units
        are never negative), so the whole registry is refused before the grammar is reached."""
        for target in ("≤ 1.5s", "≤ -1.5 s"):
            with self.subTest(target=target):
                setup = put_slos(lambda text, row, t=target: text.replace(row, row.replace(DETECT_TARGET, t)))
                self.assertEqual(self.run_case(setup=setup), (False, [_code("ERR_SLO_REGISTRY_INVALID")]))

    # S2. The strictest bound over every operation row listing the SLO ---------------

    def test_S2_a_measurement_cannot_pick_a_laxer_operation_row(self) -> None:
        old = {"measurement_window": {"started_at": "2016-09-01T00:00:00Z", "finished_at": "2016-09-01T01:00:00Z"}}
        registry = cost_registry_with_bounds(36500, {"COST-DETECT-001": 1})

        def after(root: Path) -> None:
            (root / COST_REL).write_text(registry, encoding="utf-8")

        for operation in ("COST-DETECT-001", "COST-DECODE-001", "COST-EVENT-001"):
            with self.subTest(operation=operation):
                self.assertEqual(self.run_case(measurement={**old, "operation_id": operation}, after=after), (False, [ERR_STALE_GENERATION]))

    def test_S2_every_row_listing_the_slo_must_set_a_bound(self) -> None:
        text = (ROOT / COST_REL).read_text(encoding="utf-8").replace(
            'id = "COST-DETECT-001"\n', 'id = "COST-DETECT-001"\nmeasurement_max_age_days = 30\n', 1)

        def after(root: Path) -> None:
            (root / COST_REL).write_text(text, encoding="utf-8")

        self.assertEqual(self.run_case(after=after), (False, [_code("ERR_SLO_FRESHNESS_UNSET")]))

    # S3. CommonMark fences ------------------------------------------------------------

    def test_S3_visible_markdown_follows_commonmark_fences(self) -> None:
        self.assertEqual(cpb._visible_markdown("a\n````\n```\n| inside a 4-backtick fence |\n````\nb\n"), "a\n\n\n\n\nb\n")
        self.assertEqual(
            cpb._visible_markdown("```\n<!--\n```\n| visible row |\n| x |\n-->\n"),
            "\n\n\n| visible row |\n| x |\n-->\n",
        )
        self.assertEqual(cpb._visible_markdown("x <!-- hidden --> y\n<!--\nhidden\n--> z\n"), "x  y\n\n\n z\n")

    def test_S3_claim_tables_and_slos_md_agree_on_fences(self) -> None:
        text = "````\n```\n| ID | Status | Proof root |\n|---|---|---|\n| `SLO-DETECT-001` | achieved | `x.bundle.json` |\n````\n"
        self.assertEqual(parse_markdown_tables(text), [])

    def test_S3_row_after_a_fence_holding_a_comment_opener_is_live(self) -> None:
        def fence_first(text: str, row: str) -> str:
            header = next(line for line in text.splitlines() if line.startswith("| ID |"))
            return text.replace(header, "```\n<!--\n```\n\n" + header, 1)
        self.assertEqual(self.run_case(setup=put_slos(fence_first)), (True, []))

    def test_S3_row_inside_a_longer_fence_is_hidden(self) -> None:
        def hide(text: str, row: str) -> str:
            return text.replace(row + "\n", "") + "\n````\n```\n" + row.replace(DETECT_TARGET, "≤ 100 s") + "\n````\n"
        self.assertEqual(self.run_case(measurement={"actual": 50.0}, setup=put_slos(hide)), (False, [_code("ERR_CLAIM_CLASS_UNRESOLVED")]))


# ---------------------------------------------------------------------------
# Round-3 re-review, 30.87.2 part A: proofs fail closed, count per claim, deep JSON
# (probes p6_lexers.py, p8_e2e.py cases B and C, p7_dos.py JSON nesting)
# ---------------------------------------------------------------------------

DEEP_JSON = b"[" * 100000 + b"]" * 100000


class TestRound3ProofFailClosedAndCounts(unittest.TestCase):
    """A proof never verifies from static evidence; verified counts are per claim; deep JSON is a finding."""

    PROVER = _code("ERR_PROOF_PROVER_RUN_REQUIRED")

    def test_prover_run_id_is_registered(self) -> None:
        code = "ERR-CLAIM-PROOF-PROVER-RUN-REQUIRED-001"
        self.assertEqual(self.PROVER, code)
        self.assertIn(code, cpb.DIAGNOSTIC_REGISTRY)
        self.assertEqual((ROOT / "registries/ERRORS.md").read_text(encoding="utf-8").count(f"| `{code}` |"), 1)

    def test_A_static_evidence_never_verifies_a_proof(self) -> None:
        for label, kwargs in (("TLA+ checked by tlaps", {}), ("Lean 4", lean_fixture())):
            with self.subTest(case=label), tempfile.TemporaryDirectory() as tmpdir:
                root = Path(tmpdir)
                ok, findings, _ = verify_class_bundle(root, build_proof_fixture(root, **kwargs), PROOF_CLAIM_ID)
                self.assertFalse(ok, "a proof was verified from static evidence alone")
                self.assertEqual(error_code_set(findings), [self.PROVER])

    def test_A_a_proof_claim_row_is_never_counted_verified(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            root = Path(tmpdir)
            write_json(root / PROOF_BUNDLE_REL, seal(build_proof_fixture(root)))
            findings, stats = scan_with_stats(root, class_table(f"| `{PROOF_CLAIM_ID}` | proof | verified | `{PROOF_BUNDLE_REL}` | {PROOF_GENERATION} |"))
            self.assertEqual(error_code_set(findings), [self.PROVER])
            self.assertEqual((stats["promoted"], stats["bundles_checked"], stats["bundles_passed"], stats["bundles_unpromoted"]), (1, 1, 0, 0))

    def test_A_a_statically_defective_proof_reports_its_defect(self) -> None:
        """The prover-run finding marks an otherwise clean bundle; a defective one reports its defect."""
        with tempfile.TemporaryDirectory() as tmpdir:
            root = Path(tmpdir)
            ok, findings, _ = verify_class_bundle(root, build_proof_fixture(root, bundle={"theorem": _DROP}), PROOF_CLAIM_ID)
            self.assertFalse(ok)
            self.assertEqual(error_code_set(findings), [_code("ERR_PROOF_THEOREM_UNBOUND")])

    def test_count_is_per_claim_not_per_bundle(self) -> None:
        second_rel = "qualification-artifacts/bounds/ingest-latency-2.bundle.json"
        with tempfile.TemporaryDirectory() as tmpdir:
            root = build_fixture_root(Path(tmpdir))
            first = seal(build_bound_fixture(root))
            second = seal({**{k: v for k, v in first.items() if k != "content_digest"}, "bundle_id": "BUNDLE-BOUND-INGEST-002"})  # round 5: an allowed field, not an unknown one
            self.assertNotEqual(first["content_digest"], second["content_digest"])
            write_json(root / BOUND_BUNDLE_REL, first)
            write_json(root / second_rel, second)
            table = class_table(
                f"| `{BOUND_CLAIM_ID}` | bounded_model | verified | `{BOUND_BUNDLE_REL}` | {BOUND_GENERATION} |",
                f"| `{BOUND_CLAIM_ID}` | bounded_model | verified | `{second_rel}` | {BOUND_GENERATION} |",
            )
            findings, stats = scan_with_stats(root, table)
            self.assertEqual(findings, [], [f"{f.code}: {f.message}" for f in findings])
            self.assertEqual((stats["bundles_checked"], stats["bundles_passed"], stats["bundles_unpromoted"]), (1, 1, 0))
            append_readme_table(root, table)
            ok, findings, summary = audit_with(root, CLAIM_ROW_CLASSES)
            self.assertTrue(ok, [f"{f.code}: {f.message}" for f in findings])
            self.assertEqual((summary["bundles_checked"], summary["verified_bundles_count"], summary["unpromoted_bundles_count"]), (1, 1, 0))

    def test_deep_json_is_unreadable_input(self) -> None:
        self.assertIsNone(cpb._json_object(b'{"a":' + DEEP_JSON + b"}"))
        with tempfile.TemporaryDirectory() as tmpdir:
            path = Path(tmpdir) / "b.json"
            path.write_bytes(b'{"a":' + DEEP_JSON + b"}")
            data, findings = cpb._read_json_document(path, "b.json", "proof bundle")
            self.assertIsNone(data)
            self.assertEqual(codes(findings), [ERR_UNREADABLE_INPUT])

    def test_deep_json_bundle_fails_the_cli_without_a_traceback(self) -> None:
        rel = "proof_bundles/deep.bundle.json"
        with tempfile.TemporaryDirectory() as tmpdir:
            root = build_fixture_root(Path(tmpdir))
            (root / rel).parent.mkdir(parents=True, exist_ok=True)
            (root / rel).write_bytes(b'{"claim_id":"INV-001","x":' + DEEP_JSON + b"}")
            append_readme_table(root, class_table(f"| `INV-001` | invariant | verified | `{rel}` |"))
            result = run_cli("--root", str(root), "--as-of", "2026-09-02T00:00:00Z")
            self.assertEqual(result.returncode, 1, result.stdout + result.stderr)
            self.assertNotIn("Traceback", result.stderr)
            self.assertIn(ERR_UNREADABLE_INPUT, result.stdout)


# ---------------------------------------------------------------------------
# Round-3 re-review, 30.87.2 part B: the static pre-filter (probes p6_lexers.py, p7_dos.py)
# ---------------------------------------------------------------------------

TIMED_FORMAL_CASES = {
    "1MB of blank lines after a theorem without ':='": ('b"theorem RootLast : True\\n" + b" \\n" * 500000', "lean"),
    "1MB of comments": ('b"theorem RootLast : True := trivial\\n" + b"-- comment line padding padding padding\\n" * 25000', "lean"),
    "1MB of strings": ('b"theorem RootLast : True := trivial\\n" + b\'def s := "aaaaaaaaaaaaaaaaaaaaaaaaaaaaa"\\n\' * 25000', "lean"),
    "1MB of identifiers": ('b"theorem RootLast : True := trivial\\n" + b"def x := y + z + w + v + u + t + s + r + q + p\\n" * 22000', "lean"),
    "500k nested Lean comments": ('b"theorem RootLast : True := trivial\\n/-" + b"/-" * 500000 + b"-/" * 500001 + b"\\n"', "lean"),
    "500k nested TLA+ comments": ('b"---- MODULE M ----\\n" + b"(*" * 500000 + b"*)" * 500000 + b"\\nTHEOREM RootLast == TRUE\\n====\\n"', "tla"),
    "1MB dash line": ('b"---- MODULE M ----\\n" + b"-" * 1000000 + b"\\nTHEOREM RootLast == TRUE\\n====\\n"', "tla"),
    "1MB near-header line": ('b"---- MODULE M ----\\n---- MODULE A " + b"-" * 1000000 + b"x\\nTHEOREM RootLast == TRUE\\n====\\n"', "tla"),
    "1MB of leading spaces": ('b" " * 1000000 + b"theorem RootLast : True := trivial\\n"', "lean"),
    "r and 1M hashes": ('b"theorem RootLast : True := trivial\\n" + b"r" + b"#" * 1000000 + b"\\n"', "lean"),
}


def timed_formal_check(expression: str, language: str, timeout: float = 30.0):
    """Runs _check_formal_content on a generated input in a child process with a hard timeout."""
    import time
    code = (
        f"import sys, json\nsys.path.insert(0, {str(ROOT / 'scripts')!r})\n"
        "import claim_proof_bundle_checker as c\n"
        f"raw = {expression}\nfindings = []\n"
        f"c._check_formal_content(raw, 'p.' + {language!r}, {language!r}, 'RootLast', 'b', {{'claim_id': 'X'}}, findings)\n"
        "print(json.dumps(sorted({f.code for f in findings})))\n"
    )
    start = time.perf_counter()
    result = subprocess.run([sys.executable, "-B", "-c", code], capture_output=True, text=True, timeout=timeout)
    return time.perf_counter() - start, result


class TestRound3StaticPreFilter(unittest.TestCase):
    """Probe p6_lexers.py / p7_dos.py cases as planted tests with exact finding-id sets."""

    PROVER = _code("ERR_PROOF_PROVER_RUN_REQUIRED")

    def expect(self, cases: dict, lean: bool, rel: str) -> None:
        for label, (raw, expected) in cases.items():
            with self.subTest(case=label):
                ok, codes_found = run_formal(rel, raw, lean=lean)
                self.assertFalse(ok, label)
                self.assertEqual(codes_found, sorted(expected), label)

    def test_B_lean_probe_cases(self) -> None:
        unproven, escape = _code("ERR_PROOF_UNPROVEN_PLACEHOLDER"), _code("ERR_PROOF_UNSOUND_ESCAPE")
        theorem, missing, prover = _code("ERR_PROOF_THEOREM_UNBOUND"), _code("ERR_PROOF_FORMAL_ARTIFACT_MISSING"), self.PROVER
        self.expect({
            "LX1 !'\"' lexer desync hides sorry": (b"theorem RootLast : (1:Nat) = 2 := by\n  first | exact (!'\"') | exact sorry -- \"\n", [unproven]),
            "LX2 raw string then sorry": (b'def s := r#"-- "#\ntheorem RootLast : 1 = 2 := by\n  sorry\n', [unproven]),
            "LX3 theorem inside a raw string": (b'def s := r#"\ntheorem RootLast : True := trivial\n"#\n', [theorem]),
            "LX4a char '\\'' then sorry": (b"def c := '\\''\ntheorem RootLast : 1 = 2 := by\n  sorry\n", [unproven]),
            "LX4b char '\"' then sorry": (b"def c := '\"'\ntheorem RootLast : 1 = 2 := by\n  sorry\n", [unproven]),
            "LX5 -- in a block comment": (b"/- -- -/\ntheorem RootLast : 1 = 2 := by\n  sorry\n", [unproven]),
            "LX6 unterminated block comment": (b"theorem RootLast : True := trivial\n/- /- -/\n", [missing]),
            "LX7 unterminated string": (b'theorem RootLast : True := trivial\ndef s := "abc\n', [missing]),
            "LX7b unterminated raw string": (b'theorem RootLast : True := trivial\ndef s := r#"abc"\n', [missing]),
            "LX8a CRLF control": (b"theorem RootLast : True := by\r\n  trivial\r\n", [prover]),
            "LX8b CRLF sorry": (b"theorem RootLast : 1 = 2 := by\r\n  sorry\r\n", [unproven]),
            "LX9 BOM control": ("\ufefftheorem RootLast : True := by\n  trivial\n".encode(), [prover]),
            "LX10 tab-indented sorry": (b"theorem RootLast : 1 = 2 := by\n\tsorry\n", [unproven]),
            "LX11 exact?": (b"theorem RootLast : True := by\n  exact?\n", [prover]),
            "LX12 decide +native": (b"theorem RootLast : 1 = 2 := by\n  decide +native\n", [escape]),
            "LX13 decide (config := { native := true })": (b"theorem RootLast : 1 = 2 := by\n  decide (config := { native := true })\n", [escape]),
            "LX14 bv_decide": (b"theorem RootLast : 1 = 2 := by\n  bv_decide\n", [escape]),
            "LX15 implemented_by and ofReduceBool": (b"unsafe def lieImpl : Bool := true\n@[implemented_by lieImpl] def lie : Bool := false\ntheorem RootLast : lie = true := Lean.ofReduceBool lie true rfl\n", [escape]),
            "LX16 trustCompiler": (b"theorem RootLast : 1 = 2 := by\n  have := Lean.trustCompiler\n  exact absurd rfl (by simp)\n", [escape]),
            "LX17 lcProof": (b"theorem RootLast : 1 = 2 := lcProof\n", [escape]),
            "LX18 set_option debug.skipKernelTC": (b"set_option debug.skipKernelTC true in\ntheorem RootLast : True := trivial\n", [escape]),
            "LX19 #eval elaborating an axiom from a string": (b'open Lean Elab Command in\n#eval show CommandElabM Unit from do\n  match Parser.runParserCategory (\xe2\x86\x90 getEnv) `command "axiom cheat : False" with\n  | .ok stx => elabCommand stx\n  | .error e => throwError e\ntheorem RootLast : 1 = 2 := cheat.elim\n', [escape]),
            "LX20 by_elab mkSorry": (b"theorem RootLast : 1 = 2 := by_elab do\n  Lean.Meta.mkSorry (\xe2\x86\x90 Lean.Meta.mkEq (Lean.toExpr 1) (Lean.toExpr 2)) false\n", [escape]),
            "LX21 sorry inside s! interpolation": (b'def s : String := s!"{(sorry : Nat)}"\ntheorem RootLast : True := trivial\n', [unproven]),
            "LX22 import of a sorried module": (b"import Cheat.Sorried\ntheorem RootLast : 1 = 2 := Cheat.bad\n", [escape]),
            "LX23 opaque, partial, unsafe": (b"opaque o : Nat\npartial def f : Nat \xe2\x86\x92 Nat := fun n => f n\nunsafe def u : Nat := 0\ntheorem RootLast : True := trivial\n", [prover]),
            "LX24 Inhabited False from sorry": (b"instance : Inhabited False := \xe2\x9f\xa8sorry\xe2\x9f\xa9\ntheorem RootLast : True := trivial\n", [unproven]),
            "LX25 Classical.choice": (b"theorem RootLast : Nonempty Nat := \xe2\x9f\xa8Classical.choice \xe2\x9f\xa80\xe2\x9f\xa9\xe2\x9f\xa9\n", [prover]),
            "LX26 decide on a false goal": (b"theorem RootLast : 1 = 2 := by\n  decide\n", [prover]),
            "LX27 all-indented Python": (b"    import pytest\n    theorem RootLast : True := trivial\n    def test_root_last():\n        assert True\n", [missing]),
            "LX28 notation for sorry": (b'notation "cheat" => sorry\ntheorem RootLast : 1 = 2 := cheat\n', [unproven]),
            "LX29 import Cheat": (b"import Cheat\ntheorem RootLast : 1 = 2 := by\n  simp_all [Cheat.bad]\n", [escape]),
            "LX30 #exit in a string then sorry": (b'def s := "#exit"\ntheorem RootLast : 1 = 2 := by\n  sorry\n', [unproven]),
            "LX31 10k nested comments": (b"/-" * 10000 + b"-/" * 10000 + b"\ntheorem RootLast : True := trivial\n", [prover]),
            "LX32 @[extern]": (b'@[extern "c_lie"] def g : Nat \xe2\x86\x92 Nat := id\ntheorem RootLast : True := trivial\n', [escape]),
            "LX33 by_elab inside s! interpolation": (b'def s : String := s!"{(by_elab do return Lean.toExpr 1 : Nat)}"\ntheorem RootLast : True := trivial\n', [escape]),
            "LX34 #check": (b"#check Nat\ntheorem RootLast : True := trivial\n", [escape]),
            "LX35 import after a command": (b"theorem RootLast : True := trivial\nimport Std\n", [missing]),
            "LX36 import Init and Std": (b"import Init.Core\nimport Std\ntheorem RootLast : True := trivial\n", [prover]),
        }, True, LEAN_REL)

    def test_B_tla_probe_cases(self) -> None:
        unproven, escape, prover = _code("ERR_PROOF_UNPROVEN_PLACEHOLDER"), _code("ERR_PROOF_UNSOUND_ESCAPE"), self.PROVER
        m = TLA_MODULE_HEAD
        self.expect({
            "TX1 CONSTANT C ASSUME FALSE on one line": (m + b"CONSTANT C ASSUME FALSE\nTHEOREM RootLast == 1 = 2\nPROOF OBVIOUS\n====\n", [escape]),
            "TX2 VARIABLE x AXIOM FALSE": (m + b"VARIABLE x AXIOM FALSE\nTHEOREM RootLast == 1 = 2\nPROOF OBVIOUS\n====\n", [escape]),
            "TX2b definition then ASSUME on one line": (m + b"C == TRUE ASSUME FALSE\nTHEOREM RootLast == 1 = 2\nPROOF OBVIOUS\n====\n", [escape]),
            "TX3 EXTENDS a non-standard module": (m + b"EXTENDS Cheat\nTHEOREM RootLast == 1 = 2\nPROOF OBVIOUS\n====\n", [escape]),
            "TX4 INSTANCE of a nested module with ASSUME": (m + b"---- MODULE Inner ----\nASSUME FALSE\n====\nI == INSTANCE Inner\nTHEOREM RootLast == 1 = 2\nPROOF OBVIOUS\n====\n", [escape]),
            "TX5 LOCAL INSTANCE of a standard module": (m + b"LOCAL INSTANCE Naturals\nTHEOREM RootLast == TRUE\n====\n", [prover]),
            "TX6 compact header": (b"----MODULE PublicationProof----\nTHEOREM RootLast == TRUE\n====\n", [prover]),
            "TX7 \\* hides a terminator": (m + b"THEOREM RootLast == TRUE\n\\* ====\nPROOF OMITTED\n====\n", [unproven]),
            "TX8 terminator with a trailing comment": (m + b"THEOREM RootLast == TRUE\n==== \\* end\n", [prover]),
            "TX9 CRLF control": ((m + b"THEOREM RootLast == TRUE\n====\n").replace(b"\n", b"\r\n"), [prover]),
            "TX10 PROOF OBVIOUS of FALSE": (m + b"THEOREM RootLast == FALSE\nPROOF OBVIOUS\n====\n", [prover]),
            "TX11 BY DEF": (m + b"F == TRUE\nTHEOREM RootLast == F\nBY DEF F\n====\n", [prover]),
            "TX12 a definition line then ASSUME": (m + b"F ==\nASSUME FALSE\nTHEOREM RootLast == 1 = 2\nPROOF OBVIOUS\n====\n", [escape]),
            "TX13 a comment then ASSUME on one line": (m + b"(* x *) ASSUME FALSE\nTHEOREM RootLast == TRUE\n====\n", [escape]),
            "TX14 10k nested comments": (m + b"(*" * 10000 + b"*)" * 10000 + b"\nTHEOREM RootLast == TRUE\n====\n", [prover]),
            "TX15 BOM": ("\ufeff".encode() + m + b"THEOREM RootLast == TRUE\n====\n", [prover]),
            "TX16 sequent theorem with ASSUME FALSE": (m + b"THEOREM Cheat ==\nASSUME FALSE PROVE 1 = 2\nTHEOREM RootLast == 1 = 2\nBY Cheat\n====\n", [prover]),
            "TX17 EXTENDS the declared model module": (m + b"EXTENDS Publication, Naturals\nTHEOREM RootLast == TRUE\n====\n", [prover]),
            "TX18 EXTENDS continued on the next line": (m + b"EXTENDS Naturals,\n  Cheat\nTHEOREM RootLast == TRUE\n====\n", [escape]),
        }, False, TLA_REL)

    def test_B_one_megabyte_inputs_run_in_bounded_time(self) -> None:
        for label, (expression, language) in TIMED_FORMAL_CASES.items():
            with self.subTest(case=label):
                try:
                    elapsed, result = timed_formal_check(expression, language)
                except subprocess.TimeoutExpired:
                    self.fail(f"{label}: the static pre-filter did not finish within 30 s")
                self.assertEqual(result.returncode, 0, result.stderr[-400:])
                self.assertLess(elapsed, 30.0)
                self.assertIsInstance(json.loads(result.stdout), list)


# ---------------------------------------------------------------------------
# Round-3 re-review, 30.87.3 (probes p5_gen_bound.py, p7_dos.py, p8_e2e.py case A)
# ---------------------------------------------------------------------------

DEEP_FORMULA = "(" + "-" * 490 + "D_decode)+Q_max"


class TestRound3BoundedModel(unittest.TestCase):
    """Round-3 bounded_model findings as planted tests with exact finding-id sets."""

    RECOMPUTE = _code("ERR_BOUND_DERIVATION_NOT_RECOMPUTABLE")

    def run_bound(self, **kwargs: object):
        with tempfile.TemporaryDirectory() as tmpdir:
            root = Path(tmpdir)
            ok, findings, _ = verify_class_bundle(root, build_bound_fixture(root, **kwargs), BOUND_CLAIM_ID)
            return ok, error_code_set(findings)

    def deep_case(self) -> dict:
        expression = "L_ingest <= " + DEEP_FORMULA
        return {"bound": {"expression": expression, "value": 48.0},
                "derivation": {"expression": expression, "derived_value": 48.0, "formula": DEEP_FORMULA}}

    def test_deep_formula_is_a_finding_not_a_recursion_error(self) -> None:
        self.assertEqual(self.run_bound(**self.deep_case()), (False, [self.RECOMPUTE]))
        with self.assertRaises(cpb._FormulaError):
            cpb._check_formula_dimensions(DEEP_FORMULA, {"D_decode": "ms", "Q_max": "frames"}, "ms")
        with self.assertRaises(cpb._FormulaError):
            cpb._check_formula_dimensions("-" * 505 + "a", {"a": "ms"}, "frames")
        with self.assertRaises(cpb._FormulaError):
            cpb._evaluate_formula("-" * 505 + "a", {"a": 1.0})

    def test_deep_formula_through_the_audit_is_a_finding(self) -> None:
        rel = "proof_bundles/deep_bound.bundle.json"
        with tempfile.TemporaryDirectory() as tmpdir:
            root = build_fixture_root(Path(tmpdir))
            write_json(root / rel, seal(build_bound_fixture(root, **self.deep_case())))
            append_readme_table(root, class_table(f"| `{BOUND_CLAIM_ID}` | bounded_model | verified | `{rel}` | {BOUND_GENERATION} |"))
            ok, findings, summary = audit_with(root, CLAIM_ROW_CLASSES)
            self.assertFalse(ok)
            self.assertEqual(error_code_set(findings), [self.RECOMPUTE])
            self.assertEqual(summary["verified_bundles_count"], 0)

    def test_distinct_count_units_are_distinct_dimensions(self) -> None:
        def counts(formula: str, inputs: dict) -> dict:
            case = bound_case(formula, inputs, 10.0, 10.0)
            case["bound"]["units"] = "frames"
            case["derivation"]["units"] = "frames"
            return case
        frames_and_tasks = {"Q_max": {"value": 8, "units": "frames"}, "N_tasks": {"value": 2, "units": "tasks"}}
        self.assertEqual(self.run_bound(**counts("Q_max + N_tasks", frames_and_tasks)), (False, [_code("ERR_BOUND_DIMENSION_MISMATCH")]))
        frames_only = {"Q_max": {"value": 8, "units": "frames"}, "Q_extra": {"value": 2, "units": "frames"}}
        self.assertEqual(self.run_bound(**counts("Q_max + Q_extra", frames_only)), (True, []))

    def test_generation_cell_is_compared_byte_for_byte(self) -> None:
        unbound = _code("ERR_CLAIM_GENERATION_UNBOUND")
        for cell, expected, passed in (
            (BOUND_GENERATION, [], 1),
            (f"`{BOUND_GENERATION}`", [unbound], 0),
            (f"**{BOUND_GENERATION}**", [unbound], 0),
            (BOUND_GENERATION + NBSP, [unbound], 0),
            ("gen:fss1:bound​-ingest-v1", [unbound], 0),
        ):
            with self.subTest(cell=cell), tempfile.TemporaryDirectory() as tmpdir:
                root = Path(tmpdir)
                write_json(root / BOUND_BUNDLE_REL, seal(build_bound_fixture(root)))
                findings, stats = scan_with_stats(root, class_table(f"| `{BOUND_CLAIM_ID}` | bounded_model | verified | `{BOUND_BUNDLE_REL}` | {cell} |"))
                self.assertEqual(error_code_set(findings), expected, [f"{f.code}: {f.message}" for f in findings])
                self.assertEqual(stats["bundles_passed"], passed)

    def test_unused_derivation_input_is_refused(self) -> None:
        inputs = {**FIXTURE_INPUTS, "Junk": {"value": 1.0, "units": "ms"}}
        self.assertEqual(self.run_bound(derivation={"inputs": inputs}), (False, [self.RECOMPUTE]))


# ---------------------------------------------------------------------------
# Round-3 re-review, 30.87.5 (probe p9_slo.py; TOML nesting from the cross-cutting item)
# ---------------------------------------------------------------------------

AGENT_SLO_ID = "SLO-AGENT-001"  # registries/SLOS.md: "initial agent answer ≤ 800 tokens and ≤ 250 ms, ..."
AGENT_OPERATION_ID = "COST-QUERY-001"  # operation_cost_registry.toml: slo_ids ["SLO-AGENT-001"]


def build_conjunct_fixture(root: Path, measurements: list[dict]) -> dict:
    """An slo claim for SLO-AGENT-001 retaining one measurement per entry of measurements."""
    # SLO-AGENT-001 names no statistic, so its measurements declare none (round 4, B15).
    first = {"slo_id": AGENT_SLO_ID, "operation_id": AGENT_OPERATION_ID, "statistic": _DROP, **measurements[0]}
    data = build_slo_fixture(root, measurement=first, bundle={"claim_id": AGENT_SLO_ID, "bundle_id": "BUNDLE-SLO-AGENT-001"})
    base = json.loads((root / SLO_MEASUREMENT_REL).read_text(encoding="utf-8"))
    for index, extra in enumerate(measurements[1:], start=2):
        rel = f"qualification-artifacts/slo/measurement-{index}.json"
        digest = _write_doc(root, rel, {**base, **extra})
        data["artifacts"].append({"role": "measurement_artifact", "path": rel, "digest": digest})
    return data


class TestRound3Slo(unittest.TestCase):
    """Round-3 slo findings as planted tests with exact finding-id sets."""

    UNBOUND = _code("ERR_SLO_TARGET_UNBOUND")

    def run_conjuncts(self, measurements: list[dict]):
        with tempfile.TemporaryDirectory() as tmpdir:
            root = Path(tmpdir)
            ok, findings, _ = verify_slo_bundle(root, build_conjunct_fixture(root, measurements), claim_id=AGENT_SLO_ID)
            return ok, error_code_set(findings)

    # Conjunctive targets need evidence for every conjunct ---------------------------

    def test_conjunctive_target_with_one_measurement_per_conjunct_passes(self) -> None:
        self.assertEqual(self.run_conjuncts([{"unit": "tokens", "actual": 700.0}, {"unit": "ms", "actual": 200.0}]), (True, []))

    def test_conjunctive_target_missing_a_conjunct_fails(self) -> None:
        for label, measurements in (
            ("only the tokens conjunct", [{"unit": "tokens", "actual": 700.0}]),
            ("only the ms conjunct", [{"unit": "ms", "actual": 200.0}]),
        ):
            with self.subTest(case=label):
                self.assertEqual(self.run_conjuncts(measurements), (False, [self.UNBOUND]))

    def test_every_conjunct_must_meet_its_threshold(self) -> None:
        self.assertEqual(
            self.run_conjuncts([{"unit": "tokens", "actual": 700.0}, {"unit": "ms", "actual": 300.0}]),
            (False, [ERR_CLAIM_LEVEL_EXCEEDED]),
        )

    def test_a_conjunct_measured_twice_is_unbound(self) -> None:
        self.assertEqual(
            self.run_conjuncts([{"unit": "tokens", "actual": 700.0}, {"unit": "tokens", "actual": 650.0}, {"unit": "ms", "actual": 200.0}]),
            (False, [self.UNBOUND]),
        )

    # Context and subject words sit at the grammar's fixed positions --------------------

    def test_scrambled_or_repeated_context_words_are_outside_the_grammar(self) -> None:
        for target in ("p95 latency ≤ 750 ms on on on LAN LAN", "latency ≤ 750 ms without", "a a a a ≤ 0 ms",
                       "≤ 750 ms , , ,", "p95 ≤ 750 ms after without first for", "to in a ≤ 5 s without evidence",
                       "p95 latency < 750 ms", "p95 ≤ 01,000.5 ms", "≤ 750 ms\u200b", "≤ 750\u00a0ms",
                       "p95 first event hypothesis ≤ 1.5 s evidence threat observable first after"):
            with self.subTest(target=target):
                thresholds, defect = cpb._parse_slo_target(target)
                self.assertEqual(thresholds, [])
                self.assertIsNotNone(defect)
        for target, expected in (
            ("≤ 750 ms", [("<=", 750.0, "ms")]),
            ("≤ 750 ms and ≤ 1 s", [("<=", 750.0, "ms"), ("<=", 1.0, "s")]),
            ("p95 first event hypothesis ≤ 1.5 s after first observable threat evidence", [("<=", 1.5, "s")]),
        ):
            with self.subTest(target=target):
                thresholds, defect = cpb._parse_slo_target(target)
                self.assertIsNone(defect)
                self.assertEqual([(t.comparator, t.value, t.unit) for t in thresholds], expected)

    def test_scrambled_context_in_slos_md_leaves_the_claim_unbound(self) -> None:
        def scramble(text: str, row: str) -> str:
            return text.replace(row, row.replace("after first observable threat evidence", "evidence threat observable first after"))
        with tempfile.TemporaryDirectory() as tmpdir:
            root = Path(tmpdir)
            put_slos(scramble)(root)
            ok, findings, _ = verify_slo_bundle(root, build_slo_fixture(root))
            self.assertEqual((ok, error_code_set(findings)), (False, [self.UNBOUND]))

    # Deep TOML is a registry finding --------------------------------------------------

    def test_deeply_nested_cost_registry_is_a_registry_finding(self) -> None:
        def setup(root: Path) -> None:
            text = (ROOT / COST_REL).read_text(encoding="utf-8") + "\ndeep = " + "[" * 100000 + "]" * 100000 + "\n"
            (root / COST_REL).parent.mkdir(parents=True, exist_ok=True)
            (root / COST_REL).write_text(text, encoding="utf-8")
        with tempfile.TemporaryDirectory() as tmpdir:
            root = Path(tmpdir)
            setup(root)
            ok, findings, _ = verify_slo_bundle(root, build_slo_fixture(root))
            self.assertEqual((ok, error_code_set(findings)), (False, [_code("ERR_SLO_REGISTRY_INVALID")]))

# ---------------------------------------------------------------------------
# Round-4 review, 30.87.2: crash freedom, honest counting, coverage (probes p10 C, p11, p12)
# ---------------------------------------------------------------------------


def nested_dict(depth: int) -> object:
    value: object = 1
    for _ in range(depth):
        value = {"g": value}
    return value


def deep_bundle_bytes(key: str, depth: int, as_list: bool = False) -> bytes:
    inner = (b"[" * depth + b"]" * depth) if as_list else (b'{"g":' * depth + b"1" + b"}" * depth)
    return b'{"claim_id":"INV-001","' + key.encode() + b'":' + inner + b"}"


def cli_on(root: Path) -> subprocess.CompletedProcess:
    return run_cli("--root", str(root), "--as-of", "2026-09-02T00:00:00Z")


class TestRound4CrashFreedomAndHonesty(unittest.TestCase):
    """Round-4 30.87.2 findings as planted tests: typed findings, never tracebacks."""

    def assert_cli_finding(self, root: Path, code: str) -> None:
        result = cli_on(root)
        self.assertEqual(result.returncode, 1, result.stdout[-400:] + result.stderr[-400:])
        self.assertNotIn("Traceback", result.stderr)
        self.assertIn(code, result.stdout)

    # Deep JSON --------------------------------------------------------------------

    def test_deep_bundle_is_unreadable_not_a_recursion_error(self) -> None:
        for key, depth, as_list in (("generation", 1000, False), ("note", 1000, False), ("note", 5000, True), ("environment", 5000, False)):
            with self.subTest(key=key, depth=depth, as_list=as_list), tempfile.TemporaryDirectory() as tmpdir:
                root = Path(tmpdir)
                path = root / "proof_bundles/x.bundle.json"
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_bytes(deep_bundle_bytes(key, depth, as_list))
                ok, findings, _ = verify_proof_bundle(bundle_path=path, root=root, known_classes=_known_classes(), now=FIXED_NOW)
                self.assertFalse(ok)
                self.assertEqual(error_code_set(findings), [ERR_UNREADABLE_INPUT])

    def test_deep_bundle_fails_the_cli_without_a_traceback(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            root = build_fixture_root(Path(tmpdir))
            rel = "proof_bundles/x.bundle.json"
            (root / rel).parent.mkdir(parents=True, exist_ok=True)
            (root / rel).write_bytes(deep_bundle_bytes("generation", 1000))
            append_readme_table(root, class_table(f"| `INV-001` | invariant | verified | `{rel}` | g1 |"))
            self.assert_cli_finding(root, ERR_UNREADABLE_INPUT)

    def test_deep_evidence_documents_are_findings(self) -> None:
        deep = nested_dict(1000)
        with tempfile.TemporaryDirectory() as tmpdir:
            root = Path(tmpdir)
            ok, findings, _ = verify_slo_bundle(root, build_slo_fixture(root, measurement={"notes": deep}))
            self.assertEqual((ok, error_code_set(findings)), (False, [ERR_CLAIM_LEVEL_EXCEEDED]))
        with tempfile.TemporaryDirectory() as tmpdir:
            root = Path(tmpdir)
            ok, findings, _ = verify_class_bundle(root, build_bound_fixture(root, derivation={"notes": deep}), BOUND_CLAIM_ID)
            self.assertEqual((ok, error_code_set(findings)), (False, [_code("ERR_BOUND_DERIVATION_UNBOUND")]))
        with tempfile.TemporaryDirectory() as tmpdir:
            root = Path(tmpdir)
            ok, findings, _ = verify_class_bundle(root, build_proof_fixture(root, receipt={"notes": deep}), PROOF_CLAIM_ID)
            self.assertEqual((ok, error_code_set(findings)), (False, [_code("ERR_PROOF_CHECK_RECEIPT_INVALID")]))

    def test_nan_scan_is_iterative(self) -> None:
        findings: list = []
        self.assertTrue(cpb._scan_nan_inf_negative({"x": {"y": [nested_dict(3000), float("nan")]}}, "b", "", findings))
        self.assertEqual(codes(findings), [ERR_CLAIM_LEVEL_EXCEEDED])
        findings = []
        cpb._check_generations({"generation": nested_dict(3000)}, "b", set(), findings)
        self.assertEqual(findings, [])

    # NUL characters and undecodable registry text -------------------------------------

    def test_nul_in_a_cited_proof_path_is_a_finding(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            root = build_fixture_root(Path(tmpdir))
            append_readme_table(root, class_table("| `INV-001` | invariant | verified | proof_bundles/a\x00b.bundle.json | g1 |"))
            self.assert_cli_finding(root, ERR_PROOF_BUNDLE_NOT_FOUND)
        with tempfile.TemporaryDirectory() as tmpdir:
            root = Path(tmpdir)
            ok, findings, _ = verify_proof_bundle(bundle_path=Path("a\x00b.bundle.json"), root=root, known_classes=_known_classes())
            self.assertEqual((ok, error_code_set(findings)), (False, [ERR_PROOF_BUNDLE_NOT_FOUND]))

    def test_nul_in_an_artifact_path_is_a_finding(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            root = build_fixture_root(Path(tmpdir))
            rel = "proof_bundles/x.bundle.json"
            (root / rel).parent.mkdir(parents=True, exist_ok=True)
            (root / rel).write_bytes(json.dumps({"claim_id": "INV-001", "artifacts": [{"path": "a\x00b", "digest": "sha256:" + "0" * 64}]}).encode())
            append_readme_table(root, class_table(f"| `INV-001` | invariant | verified | `{rel}` | g1 |"))
            self.assert_cli_finding(root, ERR_PROOF_BUNDLE_NOT_FOUND)

    def test_invalid_utf8_in_claims_md_is_a_finding(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            root = build_fixture_root(Path(tmpdir))
            claims_md = root / "registries/CLAIMS.md"
            claims_md.write_bytes(claims_md.read_bytes() + b"\n\xff\xfe bad\n")
            self.assert_cli_finding(root, ERR_UNREADABLE_INPUT)
            findings = audit_claim_kind_registry(root=root, claims_json_path=root / "architecture/claims.json", claims_md_path=claims_md)
            # The tombstone index is read from the same file, so it is unavailable too (fail closed).
            self.assertEqual(codes(findings), ["ERR-CLAIM-PROOF-TOMBSTONE-INDEX-UNAVAILABLE-001", ERR_UNREADABLE_INPUT])

    # Honest counting and docs -----------------------------------------------------------

    def test_cli_counts_claims_not_proof_bundles(self) -> None:
        result = run_cli()
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertIn("0/0 claims verified (counted per claim, all classes; 0 unpromoted", result.stdout)
        self.assertNotIn("proof bundles verified", result.stdout)

    def test_docs_say_proofs_never_verify_statically_and_count_per_claim(self) -> None:
        self.assertIn("ERR-CLAIM-PROOF-PROVER-RUN-REQUIRED-001", cpb.__doc__)
        self.assertIn("counted per claim, not per bundle", cpb.__doc__)
        self.assertNotIn("a passing fss.proof_check_receipt", cpb._verify_proof_claim_evidence.__doc__)
        self.assertIn("Nothing here shows that a prover ran", cpb._verify_proof_claim_evidence.__doc__)
        module_doc = sys.modules[__name__].__doc__ or ""
        self.assertNotIn("valid bundles pass", module_doc)

    # Coverage pins ------------------------------------------------------------------------

    def test_digest_dedup_counts_uncited_copies_once(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            root = build_fixture_root(Path(tmpdir))
            bundle = seal(build_bound_fixture(root))
            write_json(root / "qualification-artifacts/bounds/a.bundle.json", bundle)
            write_json(root / "qualification-artifacts/bounds/b.bundle.json", bundle)
            _, _, summary = audit_with(root, CLAIM_ROW_CLASSES)
            self.assertEqual((summary["bundles_checked"], summary["verified_bundles_count"]), (1, 0))

    def test_distinct_claim_ids_citing_one_bundle_are_separate_claims(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            root = Path(tmpdir)
            write_json(root / BOUND_BUNDLE_REL, seal(build_bound_fixture(root)))
            findings, stats = scan_with_stats(root, class_table(
                f"| `{BOUND_CLAIM_ID}` | bounded_model | verified | `{BOUND_BUNDLE_REL}` | {BOUND_GENERATION} |",
                f"| `BOUND-OTHER-001` | bounded_model | verified | `{BOUND_BUNDLE_REL}` | {BOUND_GENERATION} |",
            ))
            self.assertEqual(error_code_set(findings), sorted([cpb.ERR_CLAIM_BINDING_MISMATCH, _code("ERR_CLAIM_CLASS_UNRESOLVED")]))
            self.assertEqual((stats["bundles_checked"], stats["bundles_passed"]), (2, 1))

    def test_import_mathlib_is_refused(self) -> None:
        body = b"import Mathlib.Order.Basic\ntheorem RootLast : True := trivial\n"
        self.assertEqual(run_formal(LEAN_REL, body, lean=True), (False, [_code("ERR_PROOF_UNSOUND_ESCAPE")]))


# ---------------------------------------------------------------------------
# Round-4 review, 30.87.5: coherent conjuncts (B5, B14) and exact statistic (B15, B16), probe p10 B
# ---------------------------------------------------------------------------


def slo_window(started: str, finished: str) -> dict:
    return {"measurement_window": {"started_at": started, "finished_at": finished}}


class TestRound4SloCoherence(unittest.TestCase):
    """Round-4 slo findings as planted tests with exact finding-id sets."""

    INCOHERENT = "ERR-CLAIM-SLO-CONJUNCT-INCOHERENT-001"
    STATISTIC = "ERR-CLAIM-SLO-STATISTIC-MISMATCH-001"
    TOK = {"unit": "tokens", "actual": 700.0}
    MS = {"unit": "ms", "actual": 200.0}

    def run_conjuncts(self, measurements: list[dict]):
        with tempfile.TemporaryDirectory() as tmpdir:
            root = Path(tmpdir)
            ok, findings, _ = verify_slo_bundle(root, build_conjunct_fixture(root, measurements), claim_id=AGENT_SLO_ID)
            return ok, error_code_set(findings)

    def run_detect(self, measurement: dict):
        with tempfile.TemporaryDirectory() as tmpdir:
            root = Path(tmpdir)
            ok, findings, _ = verify_slo_bundle(root, build_slo_fixture(root, measurement=measurement))
            return ok, error_code_set(findings)

    # B5: one operation -----------------------------------------------------------------

    def test_b5_conjuncts_measured_on_different_operations_are_incoherent(self) -> None:
        # COST-GRAPH-001 and COST-QUERY-001 both list SLO-AGENT-001: each measurement alone is bound.
        self.assertEqual(self.run_conjuncts([self.TOK, {**self.MS, "operation_id": "COST-GRAPH-001"}]), (False, [self.INCOHERENT]))
        self.assertEqual(self.run_conjuncts([{**self.TOK, "operation_id": "COST-GRAPH-001"}, {**self.MS, "operation_id": "COST-GRAPH-001"}]), (True, []))

    # B14: overlapping windows --------------------------------------------------------------
    # The window is planted on the second measurement: build_conjunct_fixture copies the first
    # measurement into every later one, so a window planted on the first is shared by both.

    def test_b14_conjunct_windows_must_share_an_instant(self) -> None:
        for label, window in (
            ("29 days apart", slo_window("2026-08-04T00:00:00+00:00", "2026-08-04T01:00:00+00:00")),
            ("touching after", slo_window("2026-09-01T01:00:00Z", "2026-09-01T02:00:00Z")),
            ("touching before", slo_window("2026-08-31T23:00:00Z", "2026-09-01T00:00:00Z")),
            ("same instants, other offset", slo_window("2026-09-01T02:00:00+01:00", "2026-09-01T03:00:00+01:00")),
        ):
            with self.subTest(case=label):
                self.assertEqual(self.run_conjuncts([self.TOK, {**self.MS, **window}]), (False, [self.INCOHERENT]))

    def test_b14_overlapping_or_nested_windows_pass(self) -> None:
        for label, window in (
            ("nested", slo_window("2026-09-01T00:15:00Z", "2026-09-01T00:45:00Z")),
            ("overlapping", slo_window("2026-08-31T23:30:00Z", "2026-09-01T00:30:00Z")),
            ("same interval, other offset", slo_window("2026-09-01T01:00:00+01:00", "2026-09-01T02:00:00+01:00")),
        ):
            with self.subTest(case=label):
                self.assertEqual(self.run_conjuncts([self.TOK, {**self.MS, **window}]), (True, []))

    # B15/B16: the exact statistic -----------------------------------------------------------

    def test_b15_statistic_declared_for_a_target_that_names_none(self) -> None:
        for statistic in ("p50", "p95"):
            with self.subTest(statistic=statistic):
                self.assertEqual(self.run_conjuncts([self.TOK, {**self.MS, "statistic": statistic}]), (False, [self.STATISTIC]))

    def test_b16_statistic_must_be_exactly_the_targets(self) -> None:
        # Round 5: a statistic-like key is an unknown field (the measurement's exact field set); the
        # statistic itself is still compared exactly against the target's.
        both = sorted([self.STATISTIC, FIELD_UNKNOWN])
        for label, override, expected in (
            ("probe p10 B16", {"statistic": "p50", "percentile": 50}, both),
            ("p50", {"statistic": "p50"}, [self.STATISTIC]),
            ("missing", {"statistic": _DROP}, [self.STATISTIC]),
            ("case", {"statistic": "P95"}, [self.STATISTIC]),
            ("padded", {"statistic": " p95"}, [self.STATISTIC]),
            ("number", {"statistic": 95}, [self.STATISTIC]),
            ("p99.9", {"statistic": "p99.9"}, [self.STATISTIC]),
            ("alias beside", {"statistic": "p95", "percentile": 95}, [FIELD_UNKNOWN]),
            ("alias instead", {"statistic": _DROP, "quantile": "p95"}, both),
            ("case-variant key", {"statistic": "p95", "Statistic": "p50"}, [FIELD_UNKNOWN]),
        ):
            with self.subTest(case=label):
                self.assertEqual(self.run_detect(override), (False, expected))

    def test_declared_target_statistic_passes(self) -> None:
        self.assertEqual(self.run_detect({"statistic": "p95"}), (True, []))

    def test_statistic_is_read_from_the_target(self) -> None:
        self.assertEqual(cpb._slo_target_statistic("p95 first event hypothesis ≤ 1.5 s after first observable threat evidence"), "p95")
        self.assertEqual(cpb._slo_target_statistic("p99.9 ≤ 750 ms"), "p99.9")
        self.assertIsNone(cpb._slo_target_statistic("≤ 750 ms and ≤ 1 s"))

    def test_round4_slo_ids_are_registered(self) -> None:
        errors_md = (ROOT / "registries/ERRORS.md").read_text(encoding="utf-8")
        for name, code in (("ERR_SLO_CONJUNCT_INCOHERENT", self.INCOHERENT), ("ERR_SLO_STATISTIC_MISMATCH", self.STATISTIC)):
            with self.subTest(code=code):
                self.assertEqual(_code(name), code)
                self.assertIn(code, cpb.DIAGNOSTIC_REGISTRY)
                self.assertEqual(errors_md.count(f"| `{code}` |"), 1)


# ---------------------------------------------------------------------------
# Round-5 review, 30.87.2: exact field sets, exact schema, encoding-safe CLI (probes p13-p15)
# ---------------------------------------------------------------------------

FIELD_UNKNOWN = "ERR-CLAIM-EVIDENCE-FIELD-UNKNOWN-001"
SCHEMA_INVALID = "ERR-CLAIM-PROOF-BUNDLE-SCHEMA-INVALID-001"


def run_bytes_cli(args: list[bytes], env: dict | None = None) -> subprocess.CompletedProcess:
    """Runs the CLI with raw argv bytes and captures raw output bytes (no decoding in the harness)."""
    cmd = [sys.executable.encode(), b"-B", str(ROOT / "scripts/claim_proof_bundle_checker.py").encode(), *args]
    return subprocess.run(cmd, capture_output=True, cwd=str(ROOT), env=env, timeout=600)


def promoted_slo_root(tmp: Path, measurement: dict | None = None, bundle: dict | None = None) -> Path:
    """A fixture root whose SLOS.md row promotes SLO-DETECT-001 citing a (perturbed) slo bundle."""
    root = build_fixture_root(tmp)
    write_slo_bundle(root, build_slo_fixture(root, measurement=measurement, bundle=bundle))
    promote_slos_row(root, SLO_CLAIM_ID, SLO_BUNDLE_REL)
    return root


class TestRound5AllowlistsAndOutput(unittest.TestCase):
    """Round-5 30.87.2 findings (root-cause directive, F1) as planted tests with exact id sets."""

    PROVER = "ERR-CLAIM-PROOF-PROVER-RUN-REQUIRED-001"
    RECEIPT = "ERR-CLAIM-PROOF-CHECK-RECEIPT-INVALID-001"

    def run_bound(self, bundle: dict | None = None, mutate=None):
        with tempfile.TemporaryDirectory() as tmpdir:
            root = Path(tmpdir)
            data = build_bound_fixture(root, bundle=bundle)
            if mutate is not None:
                mutate(data)
            ok, findings, _ = verify_class_bundle(root, data, BOUND_CLAIM_ID)
            return ok, error_code_set(findings)

    def run_proof(self, **kwargs: object):
        with tempfile.TemporaryDirectory() as tmpdir:
            root = Path(tmpdir)
            ok, findings, _ = verify_class_bundle(root, build_proof_fixture(root, **kwargs), PROOF_CLAIM_ID)
            return ok, error_code_set(findings)

    def run_slo(self, bundle: dict | None = None, mutate=None):
        with tempfile.TemporaryDirectory() as tmpdir:
            root = Path(tmpdir)
            data = build_slo_fixture(root, bundle=bundle)
            if mutate is not None:
                mutate(data)
            ok, findings, _ = verify_slo_bundle(root, data)
            return ok, error_code_set(findings)

    # Controls ----------------------------------------------------------------------------

    def test_complete_fixtures_carry_only_known_fields(self) -> None:
        self.assertEqual(self.run_bound(), (True, []))
        self.assertEqual(self.run_slo(), (True, []))
        self.assertEqual(self.run_proof(), (False, [self.PROVER]))

    # Exact schema and bundle_id ---------------------------------------------------------------

    def test_bundle_schema_must_be_exactly_fss_proof_bundle_v1(self) -> None:
        for schema in (0, "latest", None, [], "fss.proof_bundle.v2", "FSS.PROOF_BUNDLE.V1", "fss.proof_bundle.v1 ",
                       " fss.proof_bundle.v1", "fss.proof_bundle.v1​", "\ud800", _DROP):
            with self.subTest(schema=schema):
                self.assertEqual(self.run_bound(bundle={"schema": schema}), (False, [SCHEMA_INVALID]))
        for schema in (0, "latest"):
            with self.subTest(slo_schema=schema):
                self.assertEqual(self.run_slo(bundle={"schema": schema}), (False, [SCHEMA_INVALID]))

    def test_bundle_id_when_present_is_an_exact_token(self) -> None:
        for bundle_id in ([], 1.5, None, "", "a b", "\ud800", "​", "BUNDLE X"):
            with self.subTest(bundle_id=bundle_id):
                self.assertEqual(self.run_bound(bundle={"bundle_id": bundle_id}), (False, [SCHEMA_INVALID]))
        self.assertEqual(self.run_bound(bundle={"bundle_id": _DROP}), (True, []))

    # Bundle top level, artifact entries, assumptions ------------------------------------------

    def test_unknown_bundle_fields_are_findings(self) -> None:
        for key in ("notes", "Bound", "bound ", " bound", "claim_id​", "\ud800", "CLAIM_ID", "claimid", "Schema",
                    "bundleId", "statistic", "percentile_rank", "summary"):
            with self.subTest(key=key):
                self.assertEqual(self.run_bound(bundle={key: 1}), (False, [FIELD_UNKNOWN]))

    def test_bundle_fields_are_those_of_its_class(self) -> None:
        self.assertEqual(self.run_slo(bundle={"bound": {"value": 1}}), (False, [FIELD_UNKNOWN]))
        self.assertEqual(self.run_slo(bundle={"theorem": {}}), (False, [FIELD_UNKNOWN]))
        self.assertEqual(self.run_slo(bundle={"assumptions": []}), (False, [FIELD_UNKNOWN]))
        self.assertEqual(self.run_bound(bundle={"theorem": {}}), (False, [FIELD_UNKNOWN]))
        self.assertEqual(self.run_proof(bundle={"bound": {}}), (False, [FIELD_UNKNOWN]))

    def test_unknown_artifact_entry_fields_are_findings(self) -> None:
        for key in ("Path", "sha256", "digest ", "role​", "size", "media_type", "\ud800"):
            with self.subTest(key=key):
                def plant(data: dict, key: str = key) -> None:
                    data["artifacts"][0][key] = "x"
                self.assertEqual(self.run_bound(mutate=plant), (False, [FIELD_UNKNOWN]))
        def plant_slo(data: dict) -> None:
            data["artifacts"][0]["note"] = "x"
        self.assertEqual(self.run_slo(mutate=plant_slo), (False, [FIELD_UNKNOWN]))

    def test_unknown_assumption_fields_are_findings(self) -> None:
        assumptions = [dict(a) for a in BOUND_ASSUMPTIONS]
        assumptions[0]["note"] = "x"
        self.assertEqual(self.run_bound(bundle={"assumptions": assumptions}), (False, [FIELD_UNKNOWN]))
        proof_assumptions = [
            {"id": "ASSUME-PUT-ATOMIC", "statement": "each object-store PUT is atomic per object", "Statement": "none"},
            {"id": "ASSUME-FAIR-SCHEDULER", "statement": "the publisher is weakly fair"},
        ]
        self.assertEqual(self.run_proof(bundle={"assumptions": proof_assumptions}), (False, [FIELD_UNKNOWN]))

    # Proof evidence documents ----------------------------------------------------------------

    def test_unknown_proof_document_fields_are_findings(self) -> None:
        theorem = {"claim_id": PROOF_CLAIM_ID, "name": PROOF_THEOREM_NAME, "statement": PROOF_THEOREM}
        source = {"path": PROOF_MODEL_SOURCE_REL, "digest": compute_sha256(PROOF_MODEL_SOURCE_BYTES)}
        for label, kwargs in (
            ("theorem", {"bundle": {"theorem": {**theorem, "proof": "trivial"}}}),
            ("theorem case-variant key", {"bundle": {"theorem": {**theorem, "Name": "Other"}}}),
            ("toolchain", {"bundle": {"toolchain_identity": {"checker": "tlaps", "version": "1.5.0", "flags": "--skip"}}}),
            ("formal model reference", {"bundle": {"formal_model": {"model_id": PROOF_MODEL_ID, "generation": PROOF_GENERATION, "source": "x"}}}),
            ("receipt", {"receipt": {"status_detail": "x"}}),
            ("receipt case-variant key", {"receipt": {"Status": "failed"}}),
            ("receipt nested lookalike", {"receipt": {"summary": {"status": "failed"}}}),
            ("model manifest", {"model": {"notes": "x"}}),
            ("model source", {"model": {"source": {**source, "size": 1}}}),
        ):
            with self.subTest(case=label):
                self.assertEqual(self.run_proof(**kwargs), (False, [FIELD_UNKNOWN]))

    def test_receipt_status_of_any_json_type_is_a_finding_not_a_crash(self) -> None:
        for status in ([], {}, ["passed"], {"passed": True}, 1, None, "Passed"):
            with self.subTest(status=status):
                self.assertEqual(self.run_proof(receipt={"status": status}), (False, [self.RECEIPT]))

    # F1: encoding-safe text output ----------------------------------------------------------------

    def assert_clean_failure(self, result: subprocess.CompletedProcess, expected: bytes | None = None) -> None:
        self.assertEqual(result.returncode, 1, (result.stdout[-300:], result.stderr[-600:]))
        self.assertNotIn(b"Traceback", result.stderr)
        self.assertIn(b"[FAIL]", result.stdout)
        if expected is not None:
            self.assertIn(expected, result.stdout)

    def test_text_cli_escapes_lone_surrogates_from_evidence(self) -> None:
        for label, kwargs, escaped in (
            ("measurement operation_id", {"measurement": {"operation_id": "\ud800"}}, b"\\ud800"),
            ("measurement slo_id", {"measurement": {"slo_id": "\udfff"}}, b"\\udfff"),
            ("bundle generation", {"bundle": {"generation": "\ud800"}}, b"\\ud800"),
            ("artifact path", {"bundle": {"artifacts": [{"role": "measurement_artifact", "path": "\ud800", "digest": "sha256:" + "0" * 64}]}}, b"\\ud800"),
        ):
            with self.subTest(case=label), tempfile.TemporaryDirectory() as tmpdir:
                root = promoted_slo_root(Path(tmpdir), **kwargs)
                result = run_bytes_cli([b"--root", str(root).encode(), b"--as-of", b"2026-09-02T00:00:00Z"])
                self.assert_clean_failure(result, escaped)

    def test_text_cli_escapes_undecodable_argv_bytes(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            root = promoted_slo_root(Path(tmpdir))
            for label, args in (
                ("--bundle", [b"--root", str(root).encode(), b"--bundle", b"x\xff.json"]),
                ("--claims", [b"--root", str(root).encode(), b"--claims", b"x\xff.json"]),
                ("--root", [b"--root", b"/nonexistent\xff"]),
            ):
                with self.subTest(arg=label):
                    self.assert_clean_failure(run_bytes_cli(args + [b"--as-of", b"2026-09-02T00:00:00Z"]), b"\\udcff")

    def test_text_cli_under_an_ascii_output_encoding(self) -> None:
        env = dict(os.environ, PYTHONIOENCODING="ascii")
        for label, measurement in (
            ("finding text with a non-ASCII comparator", {"statistic": "p50"}),
            ("surrogate and non-ASCII evidence", {"statistic": "\ud800", "operation_id": "é\ud800"}),
        ):
            with self.subTest(case=label), tempfile.TemporaryDirectory() as tmpdir:
                root = promoted_slo_root(Path(tmpdir), measurement=measurement)
                result = run_bytes_cli([b"--root", str(root).encode(), b"--as-of", b"2026-09-02T00:00:00Z"], env=env)
                self.assert_clean_failure(result)
                result.stdout.decode("ascii")  # the whole report is ASCII: nothing unencodable leaked
        with tempfile.TemporaryDirectory() as tmpdir:
            root = promoted_slo_root(Path(tmpdir), measurement={"statistic": "p50"})
            result = run_bytes_cli([b"--root", str(root).encode(), b"--as-of", b"2026-09-02T00:00:00Z"], env=env)
            self.assertIn(b"\\u2264", result.stdout)  # the SLO target's comparator, escaped

    def test_round5_proof_ids_are_registered(self) -> None:
        errors_md = (ROOT / "registries/ERRORS.md").read_text(encoding="utf-8")
        for name, code in (("ERR_EVIDENCE_FIELD_UNKNOWN", FIELD_UNKNOWN), ("ERR_BUNDLE_SCHEMA_INVALID", SCHEMA_INVALID)):
            with self.subTest(code=code):
                self.assertEqual(_code(name), code)
                self.assertIn(code, cpb.DIAGNOSTIC_REGISTRY)
                self.assertEqual(errors_md.count(f"| `{code}` |"), 1)


class TestRound5ObjectSize(unittest.TestCase):
    """sizeBytes belongs to the registered object shape (schemas/evidence_bundle.v1.json), so an
    artifact entry may declare it; it is then checked, never ignored."""

    def run_size(self, size: object = None, exact: bool = False):
        with tempfile.TemporaryDirectory() as tmpdir:
            root = Path(tmpdir)
            data = build_bound_fixture(root)
            entry = data["artifacts"][0]
            entry["sizeBytes"] = len((root / entry["path"]).read_bytes()) if exact else size
            ok, findings, _ = verify_class_bundle(root, data, BOUND_CLAIM_ID)
            return ok, error_code_set(findings)

    def test_the_exact_size_of_the_retained_bytes_passes(self) -> None:
        self.assertEqual(self.run_size(exact=True), (True, []))

    def test_a_declared_size_other_than_the_retained_bytes_fails(self) -> None:
        for size in (0, 1, 10**30):
            with self.subTest(size=size):
                self.assertEqual(self.run_size(size), (False, [ERR_BUNDLE_DIGEST_MISMATCH]))

    def test_a_declared_size_must_be_a_non_negative_integer(self) -> None:
        for size in (-1, 1.5, 2.0, True, "3", None, []):
            with self.subTest(size=size):
                self.assertEqual(self.run_size(size), (False, [ERR_UNREADABLE_INPUT]))


# ---------------------------------------------------------------------------
# Round-5 review, 30.87.3: F2 comparator types, bounded_model field allowlists (probes p15, p17)
# ---------------------------------------------------------------------------


class TestRound5BoundedModel(unittest.TestCase):
    """Round-5 bounded_model findings as planted tests with exact finding-id sets."""

    EXPRESSION = "ERR-CLAIM-BOUND-EXPRESSION-UNBOUND-001"
    DERIVATION = "ERR-CLAIM-BOUND-DERIVATION-UNBOUND-001"

    def run_bound(self, **kwargs: object):
        with tempfile.TemporaryDirectory() as tmpdir:
            root = Path(tmpdir)
            ok, findings, _ = verify_class_bundle(root, build_bound_fixture(root, **kwargs), BOUND_CLAIM_ID)
            return ok, error_code_set(findings)

    # F2: a comparator of any JSON type is a finding, never a TypeError ---------------------------

    def test_f2_bound_comparator_of_any_type(self) -> None:
        for comparator in ([], ["<="], {}, {"op": "<="}, None, 1, "=<", "≤", "<= "):
            with self.subTest(comparator=comparator):
                self.assertEqual(self.run_bound(bound={"comparator": comparator}), (False, [self.EXPRESSION]))

    def test_f2_derivation_comparator_of_any_type(self) -> None:
        for comparator in ([], ["<="], {}, {"op": "<="}, None, 1, "≤"):
            with self.subTest(comparator=comparator):
                self.assertEqual(self.run_bound(derivation={"comparator": comparator}), (False, [self.DERIVATION]))

    def test_f2_audit_with_class_bindings_reports_instead_of_raising(self) -> None:
        for where in ("bound", "derivation"):
            with self.subTest(where=where), tempfile.TemporaryDirectory() as tmpdir:
                root = build_fixture_root(Path(tmpdir))
                data = build_bound_fixture(root, **{where: {"comparator": []}})
                write_json(root / BOUND_BUNDLE_REL, seal(data))
                append_readme_table(root, class_table(f"| `{BOUND_CLAIM_ID}` | bounded_model | verified | `{BOUND_BUNDLE_REL}` | {BOUND_GENERATION} |"))
                ok, findings, _ = audit_with(root, CLAIM_ROW_CLASSES)
                self.assertFalse(ok)
                self.assertEqual(error_code_set(findings), [self.EXPRESSION if where == "bound" else self.DERIVATION])

    # Exact field sets ------------------------------------------------------------------------------

    def test_unknown_bound_fields_are_findings(self) -> None:
        for key in ("Comparator", "comparator ", "value_ms", "tolerance", "units​", "\ud800"):
            with self.subTest(key=key):
                self.assertEqual(self.run_bound(bound={key: "x"}), (False, [FIELD_UNKNOWN]))

    def test_unknown_derivation_fields_are_findings(self) -> None:
        for key in ("notes", "derivedValue", "Formula", "derived_value ", "margin", "\ud800"):
            with self.subTest(key=key):
                self.assertEqual(self.run_bound(derivation={key: "x"}), (False, [FIELD_UNKNOWN]))

    def test_unknown_derivation_input_fields_are_findings(self) -> None:
        inputs = {
            "D_decode": {"value": 40.0, "units": "ms"},
            "Q_max": {"value": 8, "units": "frames"},
            "D_frame": {"value": 10.0, "units": "ms"},
        }
        for key in ("Units", "note", "value "):
            with self.subTest(key=key):
                planted = {name: dict(entry) for name, entry in inputs.items()}
                planted["Q_max"][key] = "x"
                self.assertEqual(self.run_bound(derivation={"inputs": planted}), (False, [FIELD_UNKNOWN]))

    def test_unknown_sensitivity_fields_are_findings(self) -> None:
        for key in ("partial_ms", "Parameter", "note"):
            with self.subTest(key=key):
                entry = {"parameter": "Q_max", "partial": "+10 ms per additional queued frame", key: "x"}
                self.assertEqual(self.run_bound(derivation={"sensitivity": [entry]}), (False, [FIELD_UNKNOWN]))


# ---------------------------------------------------------------------------
# Round-5 review, 30.87.5: measurement field sets (F3, F6), bounded windows (F4), exact ids (F5)
# ---------------------------------------------------------------------------


# The environment manifest digest build_slo_fixture retains (written with sort_keys, via _write_doc).
SLO_FIXTURE_ENVIRONMENT_DIGEST = compute_sha256(json.dumps(DEFAULT_ENVIRONMENT_DATA, sort_keys=True).encode("utf-8"))


class TestRound5Slo(unittest.TestCase):
    """Round-5 slo findings (probes p13, p14, p16) as planted tests with exact finding-id sets."""

    TOK = {"unit": "tokens", "actual": 700.0}
    MS = {"unit": "ms", "actual": 200.0}
    BINDING = "ERR-CLAIM-PROOF-CLAIM-BINDING-MISMATCH-001"
    GEN_UNBOUND = "ERR-CLAIM-SLO-GENERATION-UNBOUND-001"
    ENV = "ERR-CLAIM-SLO-ENVIRONMENT-UNRETAINED-001"
    STATISTIC = "ERR-CLAIM-SLO-STATISTIC-MISMATCH-001"

    def run_conjuncts(self, measurements: list[dict]):
        with tempfile.TemporaryDirectory() as tmpdir:
            root = Path(tmpdir)
            ok, findings, _ = verify_slo_bundle(root, build_conjunct_fixture(root, measurements), claim_id=AGENT_SLO_ID)
            return ok, error_code_set(findings)

    def run_detect(self, measurement: dict | None = None, bundle: dict | None = None):
        with tempfile.TemporaryDirectory() as tmpdir:
            root = Path(tmpdir)
            ok, findings, _ = verify_slo_bundle(root, build_slo_fixture(root, measurement=measurement, bundle=bundle))
            return ok, error_code_set(findings)

    def test_controls(self) -> None:
        self.assertEqual(self.run_detect(), (True, []))
        self.assertEqual(self.run_conjuncts([self.TOK, self.MS]), (True, []))
        self.assertEqual(self.run_detect({"environment_manifest_digest": SLO_FIXTURE_ENVIRONMENT_DIGEST}), (True, []))

    # F3: the statistic has one exact field; every lookalike is an unknown field ---------------------

    def test_f3_statistic_lookalikes_beside_the_canonical_statistic(self) -> None:
        for key, value in (
            ("summary", {"statistic": "p50"}), ("percentile_rank", 50), ("Percentile ", 50), (" percentile", 50),
            ("percentile​", 50), ("\ud800", 1), ("stats", "p50"), ("reported_statistic", "p50"), ("pct", 50),
            ("q", 0.5), ("aggregate_fn", "median"), ("median", True), ("kind", "median"), ("STATISTIC", "p50"),
            ("metric", "p50_latency"), ("perc", 50), ("p50", 1.2),
        ):
            with self.subTest(key=key):
                self.assertEqual(self.run_detect({"statistic": "p95", key: value}), (False, [FIELD_UNKNOWN]))

    def test_f3_statistic_lookalikes_instead_of_the_canonical_statistic(self) -> None:
        for key, value in (("percentile_rank", 95), ("pct", 95), ("summary", {"statistic": "p95"}), ("reported_statistic", "p95")):
            with self.subTest(key=key):
                self.assertEqual(self.run_detect({"statistic": _DROP, key: value}), (False, sorted([FIELD_UNKNOWN, self.STATISTIC])))

    def test_f3_statistic_lookalikes_on_a_target_naming_none(self) -> None:
        for key, value in (("percentile_rank", 50), ("summary", {"statistic": "p50"})):
            with self.subTest(key=key):
                self.assertEqual(self.run_conjuncts([self.TOK, {**self.MS, key: value}]), (False, [FIELD_UNKNOWN]))

    # F6: lookalike keys beside canonical fields ----------------------------------------------------

    def test_f6_lookalike_keys_beside_canonical_fields(self) -> None:
        stale_window = {"started_at": "2020-01-01T00:00:00Z", "finished_at": "2020-01-01T01:00:00Z"}
        for key, value in (
            ("operationId", "COST-GRAPH-001"), ("operation", "COST-GRAPH-001"), ("window", stale_window),
            ("measurement_window ", stale_window), ("Actual", 1.0), ("actual_ms", 1.0), ("achieved", 1.0),
            ("target_ms", 5000.0), ("unit ", "s"), ("slo_id​", "SLO-OTHER-001"), ("Operation_id", "COST-GRAPH-001"),
        ):
            with self.subTest(key=key):
                self.assertEqual(self.run_conjuncts([self.TOK, {**self.MS, key: value}]), (False, [FIELD_UNKNOWN]))

    def test_f6_extra_keys_inside_the_measurement_window(self) -> None:
        for key in ("start", "Started_at", "finished_at ", "duration", "\ud800"):
            with self.subTest(key=key):
                window = {"started_at": "2026-09-01T00:10:00Z", "finished_at": "2026-09-01T00:20:00Z", key: "2020-01-01T00:00:00Z"}
                self.assertEqual(self.run_conjuncts([self.TOK, {**self.MS, "measurement_window": window}]), (False, [FIELD_UNKNOWN]))

    # F4: a window lies wholly within the registry freshness bound ---------------------------------

    def test_f4_a_window_must_start_within_the_freshness_bound(self) -> None:
        # The fixture registry bound is SLO_FIXTURE_MAX_AGE_DAYS = 30 days before SLO_NOW (2026-09-02).
        for label, started in (("year 0001", "0001-01-01T00:00:00+00:00"), ("year 2000", "2000-01-01T00:00:00Z"),
                               ("31 days before now", "2026-08-02T00:00:00Z")):
            with self.subTest(case=label):
                window = slo_window(started, "2026-09-01T00:30:00Z")
                self.assertEqual(self.run_conjuncts([self.TOK, {**self.MS, **window}]), (False, [ERR_STALE_GENERATION]))
                self.assertEqual(self.run_detect(window), (False, [ERR_STALE_GENERATION]))

    def test_f4_a_window_starting_exactly_at_the_bound_passes(self) -> None:
        self.assertEqual(self.run_detect(slo_window("2026-08-03T00:00:00Z", "2026-09-01T00:30:00Z")), (True, []))

    # F5: identities are compared byte for byte -----------------------------------------------------

    def test_f5_operation_ids_are_compared_byte_for_byte(self) -> None:
        for op in (" COST-QUERY-001", "COST-QUERY-001 ", "COST-QUERY-001\xa0", "COST-QUERY-001​", "\tCOST-QUERY-001"):
            with self.subTest(operation_id=op):
                self.assertEqual(self.run_conjuncts([self.TOK, {**self.MS, "operation_id": op}]), (False, [self.BINDING]))
        both_padded = [{**self.TOK, "operation_id": " COST-QUERY-001"}, {**self.MS, "operation_id": "COST-QUERY-001 "}]
        self.assertEqual(self.run_conjuncts(both_padded), (False, [self.BINDING]))

    def test_f5_other_measurement_identities_are_byte_exact(self) -> None:
        self.assertEqual(self.run_detect({"slo_id": " SLO-DETECT-001"}), (False, [self.BINDING]))
        self.assertEqual(self.run_detect({"generation": SLO_GENERATION + " "}), (False, [self.GEN_UNBOUND]))
        self.assertEqual(self.run_detect({"operation_cost_generation": " " + SLO_COST_GENERATION}), (False, [self.GEN_UNBOUND]))
        for digest in (SLO_FIXTURE_ENVIRONMENT_DIGEST.upper(), " " + SLO_FIXTURE_ENVIRONMENT_DIGEST, SLO_FIXTURE_ENVIRONMENT_DIGEST + "\xa0"):
            with self.subTest(environment_manifest_digest=digest):
                self.assertEqual(self.run_detect({"environment_manifest_digest": digest}), (False, [self.ENV]))
        padded = SLO_GENERATION + " "
        self.assertEqual(self.run_detect({"generation": padded}, bundle={"generation": padded}), (False, [self.GEN_UNBOUND]))


class TestRound5ExactTextSurrogates(unittest.TestCase):
    """A lone surrogate is not text (probe p15 fuzz: a bounded_model assumption statement "\\ud800"
    verified). Exact text refuses it wherever the bounded_model evidence requires text."""

    ASSUMPTIONS = "ERR-CLAIM-ASSUMPTIONS-MISSING-001"
    EXPRESSION = "ERR-CLAIM-BOUND-EXPRESSION-UNBOUND-001"

    def run_bound(self, **kwargs: object):
        with tempfile.TemporaryDirectory() as tmpdir:
            root = Path(tmpdir)
            ok, findings, _ = verify_class_bundle(root, build_bound_fixture(root, **kwargs), BOUND_CLAIM_ID)
            return ok, error_code_set(findings)

    def test_exact_text_refuses_lone_surrogates(self) -> None:
        for text in ("\ud800", "\udfff", "each PUT is atomic \udcff", "\ud83d"):
            with self.subTest(text=text):
                self.assertIsNone(cpb._exact_text(text))
        self.assertEqual(cpb._exact_text("each PUT is atomic é ≤ 1"), "each PUT is atomic é ≤ 1")

    def test_assumption_statement_that_is_not_text_fails(self) -> None:
        for statement in ("\ud800", "each object-store PUT is atomic \udfff"):
            with self.subTest(statement=statement):
                assumptions = [dict(a) for a in BOUND_ASSUMPTIONS]
                assumptions[0]["statement"] = statement
                self.assertEqual(self.run_bound(bundle={"assumptions": assumptions}), (False, [self.ASSUMPTIONS]))

    def test_bound_expression_that_is_not_text_fails(self) -> None:
        self.assertEqual(self.run_bound(bound={"expression": BOUND_EXPRESSION + " \ud800"}), (False, [self.EXPRESSION]))


# ---------------------------------------------------------------------------
# Round-6 review, 30.87.2: duplicate JSON keys (N1), byte-exact digests (N3), regular files (N4),
# EPIPE (N5), qualification receipt lookalikes, ERRORS.md rows (N2) (probes p18-p21)
# ---------------------------------------------------------------------------

DUPLICATE_KEY = "ERR-CLAIM-EVIDENCE-DUPLICATE-KEY-001"
_DUPLICATE_MARK = "__round6_duplicate_key__"


def json_with_duplicate(doc: object, doc_path: tuple, key: str, first_value: object) -> bytes:
    """JSON text of doc in which the object at doc_path declares key twice: first_value, then its
    real value (so a plain parser, keeping the last value, reads the document unchanged)."""
    doc = json.loads(json.dumps(doc))
    target = doc
    for step in doc_path:
        target = target[step]
    rebuilt = {_DUPLICATE_MARK: first_value, **target}
    target.clear()
    target.update(rebuilt)
    text = json.dumps(doc)
    assert text.count(json.dumps(_DUPLICATE_MARK)) == 1
    return text.replace(json.dumps(_DUPLICATE_MARK), json.dumps(key)).encode("utf-8")


def verify_with_duplicate_bundle(runner, doc_path: tuple, key: str, first_value: object):
    """Runs runner() with every bundle it writes carrying key twice in the object at doc_path."""
    module = sys.modules[__name__]

    def write_duplicated(path: Path, data: object) -> Path:
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(json_with_duplicate(data, doc_path, key, first_value))
        return path

    with mock.patch.object(module, "write_json", write_duplicated):
        return runner()


def plant_duplicate_in_document(root: Path, data: dict, rel: str, role: str, doc_path: tuple, key: str, first_value: object) -> None:
    """Rewrites a retained evidence document with key declared twice and rebinds its digest."""
    doc = json.loads((root / rel).read_text(encoding="utf-8"))
    raw = json_with_duplicate(doc, doc_path, key, first_value)
    (root / rel).write_bytes(raw)
    for entry in data["artifacts"]:
        if entry["role"] == role:
            entry["digest"] = compute_sha256(raw)


SLO_VERIFY = lambda root, data: verify_slo_bundle(root, data)  # noqa: E731
BOUND_VERIFY = lambda root, data: verify_class_bundle(root, data, BOUND_CLAIM_ID)  # noqa: E731
PROOF_VERIFY = lambda root, data: verify_class_bundle(root, data, PROOF_CLAIM_ID)  # noqa: E731


class TestRound6DuplicateKeys(unittest.TestCase):
    """N1: a key declared twice in any object of any JSON document the checker reads is refused."""

    ENV = "ERR-CLAIM-SLO-ENVIRONMENT-UNRETAINED-001"
    DERIVATION = "ERR-CLAIM-BOUND-DERIVATION-UNBOUND-001"
    RECEIPT = "ERR-CLAIM-PROOF-CHECK-RECEIPT-INVALID-001"
    MODEL = "ERR-CLAIM-PROOF-FORMAL-MODEL-UNBOUND-001"

    def bundle_case(self, builder, verifier, doc_path: tuple, key: str, first_value: object):
        with tempfile.TemporaryDirectory() as tmpdir:
            root = Path(tmpdir)
            data = builder(root)
            ok, findings, _ = verify_with_duplicate_bundle(lambda: verifier(root, data), doc_path, key, first_value)
            return ok, error_code_set(findings)

    def document_case(self, builder, verifier, rel: str, role: str, doc_path: tuple, key: str, first_value: object):
        with tempfile.TemporaryDirectory() as tmpdir:
            root = Path(tmpdir)
            data = builder(root)
            plant_duplicate_in_document(root, data, rel, role, doc_path, key, first_value)
            ok, findings, _ = verifier(root, data)
            return ok, error_code_set(findings)

    def test_duplicate_keys_in_the_bundle_at_any_level(self) -> None:
        for label, builder, verifier, doc_path, key, first in (
            ("slo bundle root generation", build_slo_fixture, SLO_VERIFY, (), "generation", "gen-2020-01-01"),
            ("slo artifact entry role", build_slo_fixture, SLO_VERIFY, ("artifacts", 0), "role", "environment_manifest"),
            ("bound bundle root claim_id", build_bound_fixture, BOUND_VERIFY, (), "claim_id", "BOUND-OTHER-001"),
            ("bound value", build_bound_fixture, BOUND_VERIFY, ("bound",), "value", 1e9),
            ("bound assumption id", build_bound_fixture, BOUND_VERIFY, ("assumptions", 0), "id", "ASSUME-OTHER"),
            ("proof theorem statement", build_proof_fixture, PROOF_VERIFY, ("theorem",), "statement", "False"),
            ("proof toolchain version", build_proof_fixture, PROOF_VERIFY, ("toolchain_identity",), "version", "0.0.1"),
            ("proof formal_model generation", build_proof_fixture, PROOF_VERIFY, ("formal_model",), "generation", "gen:old"),
        ):
            with self.subTest(case=label):
                self.assertEqual(self.bundle_case(builder, verifier, doc_path, key, first), (False, [DUPLICATE_KEY]))

    def test_duplicate_keys_in_every_retained_evidence_document(self) -> None:
        for label, builder, verifier, rel, role, doc_path, key, first, refusal in (
            ("slo measurement actual", build_slo_fixture, SLO_VERIFY, SLO_MEASUREMENT_REL, "measurement_artifact", (), "actual", 99.0, ERR_CLAIM_LEVEL_EXCEEDED),
            ("slo measurement status", build_slo_fixture, SLO_VERIFY, SLO_MEASUREMENT_REL, "measurement_artifact", (), "status", "failed", ERR_CLAIM_LEVEL_EXCEEDED),
            ("slo measurement_window start", build_slo_fixture, SLO_VERIFY, SLO_MEASUREMENT_REL, "measurement_artifact", ("measurement_window",), "started_at", "2000-01-01T00:00:00Z", ERR_CLAIM_LEVEL_EXCEEDED),
            ("slo environment manifest", build_slo_fixture, SLO_VERIFY, SLO_ENVIRONMENT_REL, "environment_manifest", (), "host_profile", "other-host", self.ENV),
            ("bound derivation derived_value", build_bound_fixture, BOUND_VERIFY, BOUND_DERIVATION_REL, "derivation", (), "derived_value", 1.0, self.DERIVATION),
            ("bound derivation input", build_bound_fixture, BOUND_VERIFY, BOUND_DERIVATION_REL, "derivation", ("inputs", "D_decode"), "value", 4000.0, self.DERIVATION),
            ("bound sensitivity entry", build_bound_fixture, BOUND_VERIFY, BOUND_DERIVATION_REL, "derivation", ("sensitivity", 0), "partial", "?", self.DERIVATION),
            ("proof check receipt status", build_proof_fixture, PROOF_VERIFY, PROOF_RECEIPT_REL, "proof_check_receipt", (), "status", "failed", self.RECEIPT),
            ("proof model manifest claim_ids", build_proof_fixture, PROOF_VERIFY, PROOF_MODEL_REL, "formal_model", (), "claim_ids", ["OTHER-001"], self.MODEL),
            ("proof model source digest", build_proof_fixture, PROOF_VERIFY, PROOF_MODEL_REL, "formal_model", ("source",), "digest", "sha256:" + "0" * 64, self.MODEL),
        ):
            with self.subTest(case=label):
                self.assertEqual(self.document_case(builder, verifier, rel, role, doc_path, key, first), (False, sorted([DUPLICATE_KEY, refusal])))

    def test_duplicate_keys_in_registries(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            root = build_fixture_root(Path(tmpdir))
            claims = root / "architecture/claims.json"
            doc = json.loads(claims.read_text(encoding="utf-8"))
            first = next(iter(doc))
            claims.write_bytes(json_with_duplicate(doc, (), first, doc[first]))
            _, _, findings = load_authoritative_claims(claims)
            self.assertEqual(codes(findings), [DUPLICATE_KEY])
            self.assertEqual(codes(audit_claim_kind_registry(root=root, claims_json_path=claims, claims_md_path=root / "registries/CLAIMS.md")), [DUPLICATE_KEY])
        for rel, load, expected in (
            ("architecture/invariants.json", lambda root: cpb.load_claim_class_bindings(root)[1], [DUPLICATE_KEY]),
            ("architecture/stable_id_resolution.json", lambda root: cpb.load_tombstone_index(root)[1], sorted([DUPLICATE_KEY, "ERR-CLAIM-PROOF-TOMBSTONE-INDEX-UNAVAILABLE-001"])),
            ("architecture/readiness_dimensions.json", lambda root: cpb.load_readiness_states(root / "architecture/readiness_dimensions.json", "r")[1], [DUPLICATE_KEY]),
        ):
            with self.subTest(registry=rel), tempfile.TemporaryDirectory() as tmpdir:
                root = build_fixture_root(Path(tmpdir))
                doc = json.loads((ROOT / rel).read_text(encoding="utf-8"))
                first = next(iter(doc))
                (root / rel).parent.mkdir(parents=True, exist_ok=True)
                (root / rel).write_bytes(json_with_duplicate(doc, (), first, doc[first]))
                self.assertEqual(sorted(codes(load(root))), expected)

    def test_duplicate_keys_in_qualification_receipts(self) -> None:
        for label, doc_path, key, first in (
            ("status first=failed", (), "status", "failed"),
            ("status first=passed", (), "status", "passed"),
            ("command status first=failed", ("commands", 0), "status", "failed"),
        ):
            with self.subTest(case=label), tempfile.TemporaryDirectory() as tmpdir:
                root = Path(tmpdir)
                path = root / RETENTION_REL_FOR_TESTS
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_bytes(json_with_duplicate(make_receipt(), doc_path, key, first))
                findings, status = inspect_qualification_receipt_for_tests(path, root)
                self.assertEqual((error_code_set(findings), status), ([DUPLICATE_KEY], None))

    def test_cli_duplicate_actual_no_longer_verifies(self) -> None:
        """Probe p21: measurement bytes {"actual": 99.0, "actual": 1.2, ...} verified end to end."""
        with tempfile.TemporaryDirectory() as tmpdir:
            root = build_fixture_root(Path(tmpdir))
            data = build_slo_fixture(root, measurement={"actual": 1.2})
            path = root / SLO_MEASUREMENT_REL
            raw = path.read_bytes().replace(b'{"actual"', b'{"actual": 99.0, "actual"', 1)
            self.assertEqual(raw.count(b'"actual"'), 2)
            path.write_bytes(raw)
            for entry in data["artifacts"]:
                if entry["role"] == "measurement_artifact":
                    entry["digest"] = compute_sha256(raw)
            write_slo_bundle(root, data)
            promote_slos_row(root, SLO_CLAIM_ID, SLO_BUNDLE_REL)
            rc, errors, summary = run_json_cli(root)  # round 8: exact finding set, not assertIn
            self.assertEqual((rc, errors), (1, sorted([DUPLICATE_KEY, ERR_CLAIM_LEVEL_EXCEEDED])))
            self.assertEqual((summary["verified_bundles_count"], summary["bundles_checked"]), (0, 1))


RETENTION_REL_FOR_TESTS = "qualification-artifacts/lane/qualification-receipt.json"


def inspect_qualification_receipt_for_tests(path: Path, root: Path):
    return cpb.inspect_qualification_receipt(path, root)


class TestRound6ReceiptLookalikes(unittest.TestCase):
    """A lookalike of a field the checker relies on can no longer shadow it in a qualification
    receipt (probe p20 R2): refused as an unknown field."""

    def inspect(self, doc: dict):
        with tempfile.TemporaryDirectory() as tmpdir:
            root = Path(tmpdir)
            path = root / RETENTION_REL_FOR_TESTS
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(json.dumps(doc), encoding="utf-8")
            findings, status = inspect_qualification_receipt_for_tests(path, root)
            return error_code_set(findings), status

    def test_controls(self) -> None:
        self.assertEqual(self.inspect(make_receipt()), ([], "passed"))
        self.assertEqual(self.inspect(make_receipt(status="failed")), ([], "failed"))

    def test_lookalikes_of_relied_on_fields_are_refused(self) -> None:
        for key in ("Status", "STATUS", " status", "status ", "status​", "ｓｔａｔｕｓ", "Commands", "Schema", "receiptid"):
            with self.subTest(key=key):
                self.assertEqual(self.inspect({**make_receipt(), key: "failed"})[0], [FIELD_UNKNOWN])

    def test_lookalike_command_status_is_refused(self) -> None:
        receipt = make_receipt()
        receipt["commands"][0]["Status"] = "failed"
        self.assertEqual(self.inspect(receipt)[0], [FIELD_UNKNOWN])


class TestRound6Digests(unittest.TestCase):
    """N3: artifact digests are compared byte for byte against the schema pattern; a null
    retentionState is refused (the schema enum has no null)."""

    DIGEST = "ERR-CLAIM-PROOF-DIGEST-MISMATCH-001"

    def run_slo(self, mutate):
        with tempfile.TemporaryDirectory() as tmpdir:
            root = Path(tmpdir)
            data = build_slo_fixture(root)
            mutate(data["artifacts"][0])
            ok, findings, _ = verify_slo_bundle(root, data)
            return ok, error_code_set(findings)

    def test_non_exact_digests_are_refused(self) -> None:
        for label, transform in (
            ("uppercase", lambda d: d.upper()),
            ("SHA256 prefix only", lambda d: "SHA256" + d[6:]),
            ("padded", lambda d: " " + d + "\n"),
            ("trailing newline", lambda d: d + "\n"),
            ("uppercase hex", lambda d: d[:7] + d[7:].upper()),
        ):
            with self.subTest(case=label):
                def mutate(entry: dict, transform=transform) -> None:
                    entry["digest"] = transform(entry["digest"])
                self.assertEqual(self.run_slo(mutate), (False, sorted([self.DIGEST, ERR_CLAIM_LEVEL_EXCEEDED])))

    def test_open_retained_file_takes_only_an_exact_digest(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            root = Path(tmpdir)
            digest = compute_sha256(b"x")
            (root / "a.bin").write_bytes(b"x")
            self.assertEqual(cpb._open_retained_file(root, "a.bin", digest), (b"x", ""))
            for declared in (digest.upper(), " " + digest, digest + "\n"):
                with self.subTest(declared=declared):
                    self.assertIsNone(cpb._open_retained_file(root, "a.bin", declared)[0])

    def test_null_retention_state_is_refused(self) -> None:
        def mutate(entry: dict) -> None:
            entry["retentionState"] = None
        self.assertEqual(self.run_slo(mutate), (False, [_code("ERR_UNRECOGNIZED_STATE")]))


class TestRound6Streams(unittest.TestCase):
    """N4: only regular files are read (a FIFO never hangs the checker); N5: a closed stdout ends
    without a traceback and the verdict is still the exit code."""

    def run_cli_with_timeout(self, root: Path, *extra: str) -> subprocess.CompletedProcess:
        cmd = [sys.executable, "-B", str(ROOT / "scripts/claim_proof_bundle_checker.py"), "--root", str(root), "--as-of", "2026-09-02T00:00:00Z", *extra]
        try:
            return subprocess.run(cmd, capture_output=True, timeout=90)
        except subprocess.TimeoutExpired:
            self.fail(f"the checker hung (killed after 90 s): {extra}")

    def test_fifo_in_place_of_a_file_is_refused_not_read(self) -> None:
        index_and_read = sorted([TOMBSTONE_UNAVAILABLE, ERR_UNREADABLE_INPUT])
        for rel, expected in (
            ("registries/CLAIMS.md", index_and_read), ("architecture/claims.json", index_and_read),
            ("registries/SLOS.md", index_and_read), ("architecture/invariants.json", index_and_read),
            ("qualification-artifacts/lane/qualification-receipt.json", [ERR_UNREADABLE_INPUT]), ("README.md", [ERR_UNREADABLE_INPUT]),
        ):
            with self.subTest(file=rel), tempfile.TemporaryDirectory() as tmpdir:
                root = build_fixture_root(Path(tmpdir))
                path = root / rel
                path.parent.mkdir(parents=True, exist_ok=True)
                if path.exists():
                    path.unlink()
                os.mkfifo(path)
                result = self.run_cli_with_timeout(root, "--json")
                self.assertEqual(result.returncode, 1, (result.stdout[-300:], result.stderr[-300:]))
                self.assertNotIn(b"Traceback", result.stderr)
                report = json.loads(result.stdout)  # round 8: exact finding set, not assertIn(b"ERR-")
                self.assertEqual(sorted({f["code"] for f in report["findings"] if f["severity"] == "error"}), expected)

    def test_read_regular_file_refuses_a_fifo_without_blocking(self) -> None:
        code = ("import sys; sys.path.insert(0, sys.argv[1]); import claim_proof_bundle_checker as c, os\n"
                "os.mkfifo(sys.argv[2])\n"
                "try:\n    c._read_regular_file(__import__('pathlib').Path(sys.argv[2]))\n"
                "except OSError as exc:\n    print('refused', type(exc).__name__)\n")
        with tempfile.TemporaryDirectory() as tmpdir:
            result = subprocess.run([sys.executable, "-B", "-c", code, str(ROOT / "scripts"), str(Path(tmpdir) / "f")], capture_output=True, text=True, timeout=60)
            self.assertEqual(result.stdout.strip(), "refused _NotRegularFile", result.stderr[-300:])

    def test_closed_stdout_pipe_ends_without_a_traceback(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            root = promoted_slo_root(Path(tmpdir), measurement={"actual": 99.0})
            cmd = [sys.executable, "-B", str(ROOT / "scripts/claim_proof_bundle_checker.py"), "--root", str(root), "--as-of", "2026-09-02T00:00:00Z"]
            proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            proc.stdout.close()
            err = proc.stderr.read()
            proc.stderr.close()
            proc.wait(timeout=120)
            self.assertNotIn(b"Traceback", err)
            self.assertEqual(proc.returncode, 1, err[-300:])  # the audit's verdict, not an error code

    def test_closed_stdout_descriptor_ends_without_a_traceback(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            root = promoted_slo_root(Path(tmpdir), measurement={"actual": 99.0})
            cmd = [sys.executable, "-B", str(ROOT / "scripts/claim_proof_bundle_checker.py"), "--root", str(root), "--as-of", "2026-09-02T00:00:00Z"]
            result = subprocess.run(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.PIPE, timeout=120, close_fds=True,
                                    preexec_fn=lambda: os.close(1))
            self.assertNotIn(b"Traceback", result.stderr)
            self.assertEqual(result.returncode, 1, result.stderr[-300:])


class TestRound6ErrorsRows(unittest.TestCase):
    """N2 (authorized rewording) and the new DUPLICATE-KEY row."""

    def row(self, code: str) -> str:
        rows = [line for line in (ROOT / "registries/ERRORS.md").read_text(encoding="utf-8").splitlines() if line.startswith(f"| `{code}` |")]
        self.assertEqual(len(rows), 1, code)
        return rows[0]

    def test_field_unknown_row_names_every_document(self) -> None:
        row = self.row(FIELD_UNKNOWN)
        for document in ("measurement_window", "derivation input", "sensitivity entry", "model source", "qualification receipt"):
            with self.subTest(document=document):
                self.assertIn(document, row)

    def test_duplicate_key_id_is_registered(self) -> None:
        self.assertEqual(_code("ERR_EVIDENCE_DUPLICATE_KEY"), DUPLICATE_KEY)
        self.assertIn(DUPLICATE_KEY, cpb.DIAGNOSTIC_REGISTRY)
        self.assertIn("same key twice", self.row(DUPLICATE_KEY))


class TestRound6SloErrorsRows(unittest.TestCase):
    """N2 (rewording authorized by the round-6 review): the slo rows of registries/ERRORS.md no
    longer describe the removed denylists; a lookalike key is an unknown field."""

    def test_slo_rows_describe_current_behaviour(self) -> None:
        text = (ROOT / "registries/ERRORS.md").read_text(encoding="utf-8")
        for code, gone in (
            ("ERR-CLAIM-SLO-TARGET-UNBOUND-001", "non-canonical to"),
            ("ERR-CLAIM-SLO-ACTUAL-INVALID-001", "shadowed by"),
            ("ERR-CLAIM-SLO-STATISTIC-MISMATCH-001", "shadowed by"),
        ):
            with self.subTest(code=code):
                rows = [line for line in text.splitlines() if line.startswith(f"| `{code}` |")]
                self.assertEqual(len(rows), 1)
                self.assertNotIn(gone, rows[0])
                self.assertIn(FIELD_UNKNOWN, rows[0])
                self.assertNotIn("shadowed", cpb.DIAGNOSTIC_REGISTRY[code]["trigger"])


# ---------------------------------------------------------------------------
# Round-8 review, 30.87.2: F1 index duplicate keys, O9 containment, F5 summary honesty and receipts,
# F2 output streams, F3 per-file byte cap (exact finding sets on --json output)
# ---------------------------------------------------------------------------

TOMBSTONE_UNAVAILABLE = "ERR-CLAIM-PROOF-TOMBSTONE-INDEX-UNAVAILABLE-001"
BUNDLE_NOT_FOUND = "ERR-CLAIM-PROOF-BUNDLE-NOT-FOUND-001"
CHECKER_SCRIPT = ROOT / "scripts/claim_proof_bundle_checker.py"


def run_json_cli(root: Path, *extra: str, timeout: int = 120):
    """(exit code, sorted error finding ids, summary) of a --json CLI run."""
    cmd = [sys.executable, "-B", str(CHECKER_SCRIPT), "--root", str(root), "--as-of", "2026-09-02T00:00:00Z", "--json", *extra]
    result = subprocess.run(cmd, capture_output=True, timeout=timeout)
    report = json.loads(result.stdout)
    return result.returncode, sorted({f["code"] for f in report["findings"] if f["severity"] == "error"}), report["summary"]


def plant_receipt(root: Path, doc: object, rel: str = RETENTION_REL_FOR_TESTS) -> Path:
    path = root / rel
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(doc), encoding="utf-8")
    return path


class TestRound8IndexDuplicateKeys(unittest.TestCase):
    """F1 (executed exploit): stable_id_audit parses architecture/*.json with plain json.loads, so a
    duplicate 'status' un-tombstoned an identifier; the checker now parses those files first."""

    def run_exploit(self, extra_json: bytes):
        with tempfile.TemporaryDirectory() as tmpdir:
            root = promoted_slo_root(Path(tmpdir), measurement={"generation": "FSS-990"}, bundle={"generation": "FSS-990"})
            (root / "architecture/extra.json").write_bytes(extra_json)
            return run_json_cli(root)

    def test_f1_duplicate_status_in_an_index_json_is_refused(self) -> None:
        rc, errors, summary = self.run_exploit(b'{"items":[{"id":"FSS-990","status":"tombstoned","status":"active"}]}')
        self.assertEqual((rc, errors), (1, sorted([DUPLICATE_KEY, TOMBSTONE_UNAVAILABLE])))
        self.assertEqual(summary["verified_bundles_count"], 0)

    def test_f1_control_a_single_tombstoned_status_is_stale(self) -> None:
        rc, errors, _ = self.run_exploit(b'{"items":[{"id":"FSS-990","status":"tombstoned"}]}')
        self.assertEqual((rc, errors), (1, [ERR_STALE_GENERATION]))

    def test_f1_api_names_the_file(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            root = build_fixture_root(Path(tmpdir))
            (root / "architecture/extra.json").write_bytes(b'{"a": 1, "a": 2}')
            _, findings = cpb.load_tombstone_index(root)
            self.assertEqual(sorted(codes(findings)), sorted([DUPLICATE_KEY, TOMBSTONE_UNAVAILABLE]))
            self.assertIn("architecture/extra.json", [f.file for f in findings if f.code == DUPLICATE_KEY][0])


class TestRound8Containment(unittest.TestCase):
    """O9: absolute paths, in-root symlinks pointing outside, and receipts are held to the root."""

    def test_o9_passing_receipt_outside_the_root(self) -> None:
        with tempfile.TemporaryDirectory() as outside, tempfile.TemporaryDirectory() as tmpdir:
            root = build_fixture_root(Path(tmpdir))
            receipt = plant_receipt(Path(outside), make_receipt(), "qualification-receipt.json")
            self.assertEqual(run_json_cli(root, "--bundle", str(receipt))[:2], (1, [BUNDLE_NOT_FOUND]))
            ok, findings, _ = verify_proof_bundle(bundle_path=receipt, root=root, known_classes=_known_classes(), now=FIXED_NOW)
            self.assertEqual((ok, error_code_set(findings)), (False, [BUNDLE_NOT_FOUND]))

    def test_o9_absolute_in_root_symlink_pointing_outside(self) -> None:
        with tempfile.TemporaryDirectory() as outside, tempfile.TemporaryDirectory() as tmpdir:
            root = build_fixture_root(Path(tmpdir))
            target = plant_receipt(Path(outside), make_receipt(), "qualification-receipt.json")
            link = root / "qualification-artifacts/link.bundle.json"
            link.parent.mkdir(parents=True, exist_ok=True)
            os.symlink(target, link)
            self.assertEqual(run_json_cli(root, "--bundle", str(link))[:2], (1, [BUNDLE_NOT_FOUND]))

    def test_o9_retained_receipt_symlinked_outside(self) -> None:
        with tempfile.TemporaryDirectory() as outside, tempfile.TemporaryDirectory() as tmpdir:
            root = build_fixture_root(Path(tmpdir))
            target = plant_receipt(Path(outside), make_receipt(), "qualification-receipt.json")
            link = root / RETENTION_REL_FOR_TESTS
            link.parent.mkdir(parents=True, exist_ok=True)
            os.symlink(target, link)
            rc, errors, summary = run_json_cli(root)
            self.assertEqual((rc, errors, summary["receipts_passed"]), (1, [BUNDLE_NOT_FOUND], 0))

    def test_o9_absolute_path_inside_the_root_still_verifies(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            root = promoted_slo_root(Path(tmpdir))
            rc, errors, summary = run_json_cli(root, "--bundle", str(root / SLO_BUNDLE_REL))
            self.assertEqual((rc, errors), (0, []))


class TestRound8SummaryAndReceipts(unittest.TestCase):
    """F5: the summary never reports a claim verified in a run that fails closed, and a malformed
    uncited receipt is counted as invalid, never as passed."""

    def test_f5_failed_run_reports_no_claim_verified(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            root = promoted_slo_root(Path(tmpdir))
            self.assertEqual(run_json_cli(root)[2]["verified_bundles_count"], 1)  # control: the claim verifies
            (root / "architecture/stable_id_resolution.json").write_text('{"schema": "other"}', encoding="utf-8")
            rc, errors, summary = run_json_cli(root)
            self.assertEqual((rc, errors, summary["verified_bundles_count"]), (1, [TOMBSTONE_UNAVAILABLE], 0))
            self.assertIn("failed closed", summary["verification_withheld"])
            text = run_bytes_cli([b"--root", str(root).encode(), b"--as-of", b"2026-09-02T00:00:00Z"])
            self.assertIn(b"0/1 claims verified (withheld: the run failed closed", text.stdout)
            self.assertNotIn(b"1/1 claims verified", text.stdout)

    def test_f5_malformed_receipts_are_invalid_not_passed(self) -> None:
        good = make_receipt()
        for label, doc in (
            ("receiptId 5", {**good, "receiptId": 5}),
            ("startedAt 'yesterday'", {**good, "startedAt": "yesterday"}),
            ("toolchain null", {**good, "toolchain": None}),
            ("command without argv and outputDigest", {**good, "commands": [{"status": "passed"}]}),
            ("every command skipped", make_receipt(command_status="skipped")),
            ("finishedAt before startedAt", {**good, "startedAt": {"earliestNs": 5, "latestNs": 5, "clockBasis": "host-realtime"},
                                             "finishedAt": {"earliestNs": 1, "latestNs": 1, "clockBasis": "host-realtime"}}),
            ("laneId pattern", {**good, "laneId": "lane one"}),
        ):
            with self.subTest(case=label), tempfile.TemporaryDirectory() as tmpdir:
                root = build_fixture_root(Path(tmpdir))
                plant_receipt(root, doc)
                rc, errors, summary = run_json_cli(root)
                self.assertEqual((rc, errors), (1, [ERR_UNREADABLE_INPUT]))
                self.assertEqual((summary["receipts_passed"], summary["receipts_invalid"]), (0, 1))

    def test_f5_unknown_receipt_fields_are_unknown_fields(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            root = build_fixture_root(Path(tmpdir))
            plant_receipt(root, {**make_receipt(), "zz": 1})
            rc, errors, summary = run_json_cli(root)
            self.assertEqual((rc, errors, summary["receipts_invalid"]), (1, [FIELD_UNKNOWN], 1))

    def test_f5_valid_receipts_are_counted(self) -> None:
        for status, counts in (("passed", (1, 0, 0)), ("failed", (0, 1, 0))):
            with self.subTest(status=status), tempfile.TemporaryDirectory() as tmpdir:
                root = build_fixture_root(Path(tmpdir))
                plant_receipt(root, make_receipt(status=status, command_status=status))
                rc, errors, summary = run_json_cli(root)
                self.assertEqual((rc, errors), (0, []))
                self.assertEqual((summary["receipts_passed"], summary["receipts_nonpassing"], summary["receipts_invalid"]), counts)


class TestRound8OutputStreams(unittest.TestCase):
    """F2: help, usage errors, and reports that cannot be written fail closed with exit 1 and no traceback."""

    def test_f2_help_into_a_closed_pipe(self) -> None:
        proc = subprocess.Popen([sys.executable, "-B", str(CHECKER_SCRIPT), "--help"], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        proc.stdout.close()
        err = proc.stderr.read()
        proc.stderr.close()
        proc.wait(timeout=60)
        self.assertNotIn(b"Traceback", err)
        self.assertEqual(proc.returncode, 1, err[-300:])

    def test_f2_usage_error_with_stderr_closed(self) -> None:
        proc = subprocess.Popen([sys.executable, "-B", str(CHECKER_SCRIPT), "--frobnicate"], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        proc.stderr.close()
        out = proc.stdout.read()
        proc.stdout.close()
        proc.wait(timeout=60)
        self.assertNotIn(b"Traceback", out)
        self.assertEqual(proc.returncode, 1)

    @unittest.skipUnless(os.path.exists("/dev/full"), "needs /dev/full")
    def test_f2_stdout_on_a_full_device(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir, open("/dev/full", "wb") as full:
            root = promoted_slo_root(Path(tmpdir))
            result = subprocess.run([sys.executable, "-B", str(CHECKER_SCRIPT), "--root", str(root), "--as-of", "2026-09-02T00:00:00Z"],
                                    stdout=full, stderr=subprocess.PIPE, timeout=120)
            self.assertNotIn(b"Traceback", result.stderr)
            self.assertEqual(result.returncode, 1, result.stderr[-300:])  # the audit passes; the report was not delivered


class TestRound8ByteCap(unittest.TestCase):
    """F3: a per-file byte cap; at most cap + 1 bytes are read (sparse files: nothing is allocated on disk)."""

    def test_f3_file_over_the_cap_is_refused(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir, mock.patch.object(cpb, "MAX_INPUT_BYTES", 1024):
            big = Path(tmpdir) / "big.bundle.json"
            with open(big, "wb") as handle:
                handle.truncate(1 << 30)  # a sparse 1 GiB file
            with self.assertRaises(cpb._InputTooLarge):
                cpb._read_regular_file(big)
            data, findings = cpb._read_json_document(big, "big.bundle.json", "proof bundle")
            self.assertEqual((data, codes(findings)), (None, [ERR_UNREADABLE_INPUT]))
            self.assertIn("per-file cap of 1024 bytes", findings[0].message)
            exact = Path(tmpdir) / "exact.bin"
            with open(exact, "wb") as handle:
                handle.truncate(1024)
            self.assertEqual(len(cpb._read_regular_file(exact)), 1024)

    def test_f3_cli_refuses_a_bundle_over_the_real_cap(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            root = promoted_slo_root(Path(tmpdir))
            with open(root / SLO_BUNDLE_REL, "r+b") as handle:
                handle.truncate(cpb.MAX_INPUT_BYTES + 1)  # sparse: the tail is zeros
            self.assertEqual(run_json_cli(root)[:2], (1, [ERR_UNREADABLE_INPUT]))


# ---------------------------------------------------------------------------
# Round-9 review, 30.87.2: N1 fail-closed receipt schema interpretation, N2 no stdout, N3 index
# re-hash, N4 containment on the open descriptor
# ---------------------------------------------------------------------------

RECEIPT_SCHEMA_SOURCE = ROOT / "schemas/release_qualification_receipt.v1.json"


def inspect_with_schema(mutate_schema, receipt: dict) -> list[str]:
    """Error ids of inspecting receipt against a modified copy of the registered receipt schema."""
    schema = json.loads(RECEIPT_SCHEMA_SOURCE.read_text(encoding="utf-8"))
    mutate_schema(schema)
    with tempfile.TemporaryDirectory() as tmpdir:
        root = Path(tmpdir)
        schema_path = root / "schema.json"
        schema_path.write_text(json.dumps(schema), encoding="utf-8")
        receipt_path = plant_receipt(root, receipt)
        with mock.patch.object(cpb, "RECEIPT_SCHEMA_PATH", schema_path):
            findings, _ = cpb.inspect_qualification_receipt(receipt_path, root)
        return error_code_set(findings)


def schema_edit(*steps: tuple[tuple, object]):
    """A schema mutation setting each (path, value): path is a tuple of keys into the schema."""
    def mutate(schema: dict) -> None:
        for path, value in steps:
            target = schema
            for key in path[:-1]:
                target = target[key]
            target[path[-1]] = value
    return mutate


TOOLCHAIN = ("properties", "toolchain")
COMMAND_STATUS = ("properties", "commands", "items", "properties", "status")


class TestRound9ReceiptSchemaInterpretation(unittest.TestCase):
    """N1: every schema form the validator does not fully implement is a fail-closed violation that
    no filter discards; the forms it does implement are applied with JSON Schema semantics."""

    def test_control_unmodified_schema(self) -> None:
        self.assertEqual(inspect_with_schema(lambda s: None, make_receipt()), [])

    def test_a_unknown_keywords_are_never_filtered(self) -> None:
        for label, mutate in (
            ("format under properties.status", schema_edit((("properties", "status", "format"), "x"))),
            ("x-new under commands", schema_edit((("properties", "commands", "x-new"), 1))),
            ("format under the command status", schema_edit((COMMAND_STATUS + ("format",), "x"))),
            ("unknown keyword at the root", schema_edit((("if",), {"type": "object"}))),
        ):
            with self.subTest(case=label):
                self.assertEqual(inspect_with_schema(mutate, make_receipt()), [ERR_UNREADABLE_INPUT])

    def test_b_type_lists_are_implemented_and_malformed_types_refused(self) -> None:
        string_or_null = schema_edit((TOOLCHAIN + ("type",), ["string", "null"]))
        self.assertEqual(inspect_with_schema(string_or_null, make_receipt()), [])
        self.assertEqual(inspect_with_schema(string_or_null, {**make_receipt(), "toolchain": None}), [])
        self.assertEqual(inspect_with_schema(string_or_null, {**make_receipt(), "toolchain": 5}), [ERR_UNREADABLE_INPUT])
        for bad in (["string", "bogus"], 7, [], ["string", "string"], "String"):
            with self.subTest(type=bad):
                self.assertEqual(inspect_with_schema(schema_edit((TOOLCHAIN + ("type",), bad)), make_receipt()), [ERR_UNREADABLE_INPUT])

    def test_c_patterns_have_json_schema_semantics_or_are_refused(self) -> None:
        def with_pattern(pattern: str, toolchain: str) -> list[str]:
            mutate = schema_edit((TOOLCHAIN + ("pattern",), pattern))
            return inspect_with_schema(mutate, {**make_receipt(), "toolchain": toolchain})
        self.assertEqual(with_pattern("^nightly\\$", "nightly$"), [])  # an escaped $ is a literal $
        self.assertEqual(with_pattern("^nightly\\$", "nightly-2026-09-01"), [ERR_UNREADABLE_INPUT])
        self.assertEqual(with_pattern("night", "a nightly build"), [])  # search, not full match
        self.assertEqual(with_pattern("^night$", "night\n"), [ERR_UNREADABLE_INPUT])  # ECMA-262 $
        self.assertEqual(with_pattern("^[a-z]{3,}$", "nightly"), [])
        for pattern in ("(?i)^x", "\\d+", "[", "^a.b$", "[^a]+", "a{,3}", "a$b", "x^", "\\bx", "(?=x)"):
            with self.subTest(pattern=pattern):
                self.assertEqual(with_pattern(pattern, "nightly"), [ERR_UNREADABLE_INPUT])

    def test_d_additional_properties_schemas_anyof_siblings_and_tuple_items(self) -> None:
        additional = schema_edit((("properties", "startedAt", "additionalProperties"), {"type": "string"}))
        started = {"earliestNs": 1, "latestNs": 1, "clockBasis": "host-realtime"}
        self.assertEqual(inspect_with_schema(additional, {**make_receipt(), "startedAt": {**started, "note": "x"}}), [])
        self.assertEqual(inspect_with_schema(additional, {**make_receipt(), "startedAt": {**started, "note": 5}}), [ERR_UNREADABLE_INPUT])
        siblings = schema_edit((TOOLCHAIN, {"anyOf": [{"type": "string"}, {"type": "null"}], "minLength": 50}))
        self.assertEqual(inspect_with_schema(siblings, make_receipt()), [ERR_UNREADABLE_INPUT])
        self.assertEqual(inspect_with_schema(siblings, {**make_receipt(), "toolchain": "t" * 50}), [])
        for label, items in (("tuple form", [{"type": "object"}]), ("boolean", True)):
            with self.subTest(items=label):
                self.assertEqual(inspect_with_schema(schema_edit((("properties", "commands", "items"), items)), make_receipt()), [ERR_UNREADABLE_INPUT])

    def test_integral_floats_are_integers(self) -> None:
        started = {"earliestNs": 1.0, "latestNs": 1, "clockBasis": "host-realtime"}
        self.assertEqual(inspect_with_schema(lambda s: None, {**make_receipt(), "startedAt": started}), [])


class TestRound9ClosedStdout(unittest.TestCase):
    """N2: with fd 1 closed before start, no report can be written: exit 1, even for a passing audit."""

    def run_with_stdout_closed(self, *args: str) -> subprocess.CompletedProcess:
        return subprocess.run([sys.executable, "-B", str(CHECKER_SCRIPT), *args], stdout=subprocess.DEVNULL,
                              stderr=subprocess.PIPE, timeout=120, preexec_fn=lambda: os.close(1))

    def test_passing_audit_with_stdout_closed_fails_closed(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            root = build_fixture_root(Path(tmpdir))
            control = subprocess.run([sys.executable, "-B", str(CHECKER_SCRIPT), "--root", str(root), "--as-of", "2026-09-02T00:00:00Z"],
                                     stdout=subprocess.DEVNULL, stderr=subprocess.PIPE, timeout=120)
            self.assertEqual(control.returncode, 0, control.stderr[-300:])
            result = self.run_with_stdout_closed("--root", str(root), "--as-of", "2026-09-02T00:00:00Z")
            self.assertNotIn(b"Traceback", result.stderr)
            self.assertEqual(result.returncode, 1)

    def test_help_with_stdout_closed_fails_closed(self) -> None:
        result = self.run_with_stdout_closed("--help")
        self.assertNotIn(b"Traceback", result.stderr)
        self.assertEqual(result.returncode, 1)


class TestRound9IndexRehash(unittest.TestCase):
    """N3: the stable-ID index must read the bytes the checker pre-parsed; a change, addition, or
    removal while it is built, or a file deleted before it is read, leaves it unavailable."""

    def load_with(self, during_build=None, before_read=None):
        with tempfile.TemporaryDirectory() as tmpdir:
            root = build_fixture_root(Path(tmpdir))
            extra = root / "architecture/extra.json"
            extra.write_bytes(b'{"items":[{"id":"FSS-990","status":"tombstoned"}]}')
            real_index = cpb.stable_id_audit._load_repository_index
            real_read = cpb._read_regular_file

            def index(root_arg: Path):
                if during_build is not None:
                    during_build(root)
                return real_index(root_arg)

            def read(path: Path) -> bytes:
                if before_read is not None and path == extra:
                    before_read(extra)
                return real_read(path)

            with mock.patch.object(cpb.stable_id_audit, "_load_repository_index", index), mock.patch.object(cpb, "_read_regular_file", read):
                tombstones, findings = cpb.load_tombstone_index(root)
            return tombstones, sorted(codes(findings)), [f.message for f in findings]

    def test_control_tombstone_is_indexed(self) -> None:
        tombstones, found, _ = self.load_with()
        self.assertEqual(found, [])
        self.assertIn(cpb.normalize_id("FSS-990"), tombstones)

    def test_a_file_changed_while_the_index_is_built(self) -> None:
        def flip(root: Path) -> None:  # the round-8 exploit, swapped in after the pre-parse
            (root / "architecture/extra.json").write_bytes(b'{"items":[{"id":"FSS-990","status":"tombstoned","status":"active"}]}')
        tombstones, found, messages = self.load_with(during_build=flip)
        self.assertEqual((tombstones, found), (set(), [TOMBSTONE_UNAVAILABLE]))
        self.assertIn("changed while the stable-ID index was built", messages[0])

    def test_a_file_added_while_the_index_is_built(self) -> None:
        def add(root: Path) -> None:
            (root / "architecture/late.json").write_bytes(b'{"items":[]}')
        tombstones, found, _ = self.load_with(during_build=add)
        self.assertEqual((tombstones, found), (set(), [TOMBSTONE_UNAVAILABLE]))

    def test_a_file_deleted_between_the_glob_and_its_read(self) -> None:
        tombstones, found, _ = self.load_with(before_read=lambda path: path.unlink())
        self.assertEqual((tombstones, found), (set(), [TOMBSTONE_UNAVAILABLE]))


class TestRound9DescriptorContainment(unittest.TestCase):
    """N4: a path checked for containment and then swapped for a symlink to an outside file before it
    is opened is refused: containment is checked on the open descriptor, which is then read."""

    def swap_after_path_check(self, target_in_root: Path, outside_file: Path):
        real_contained = cpb._is_contained
        state = {"swapped": False}

        def contained(path: Path, root: Path) -> bool:
            verdict = real_contained(path, root)
            if not state["swapped"] and Path(path) == target_in_root:
                state["swapped"] = True
                target_in_root.unlink()
                os.symlink(outside_file, target_in_root)
            return verdict
        return mock.patch.object(cpb, "_is_contained", contained)

    def test_bundle_swapped_for_an_outside_symlink_is_refused(self) -> None:
        with tempfile.TemporaryDirectory() as outside, tempfile.TemporaryDirectory() as tmpdir:
            root = Path(tmpdir)
            outside_receipt = plant_receipt(Path(outside), make_receipt(), "qualification-receipt.json")
            bundle = plant_receipt(root, make_receipt(), "qualification-artifacts/x.bundle.json")
            with self.swap_after_path_check(bundle, outside_receipt):
                ok, findings, _ = verify_proof_bundle(bundle_path=bundle, root=root, known_classes=_known_classes(), now=FIXED_NOW)
            self.assertEqual((ok, error_code_set(findings)), (False, [BUNDLE_NOT_FOUND]))

    def test_retained_receipt_swapped_for_an_outside_symlink_is_refused(self) -> None:
        with tempfile.TemporaryDirectory() as outside, tempfile.TemporaryDirectory() as tmpdir:
            root = Path(tmpdir)
            outside_receipt = plant_receipt(Path(outside), make_receipt(), "qualification-receipt.json")
            receipt = plant_receipt(root, make_receipt())
            with self.swap_after_path_check(receipt, outside_receipt):
                findings, status = cpb.inspect_qualification_receipt(receipt, root)
            self.assertEqual((error_code_set(findings), status), ([BUNDLE_NOT_FOUND], None))

    def test_read_contained_file_checks_the_descriptor(self) -> None:
        with tempfile.TemporaryDirectory() as outside, tempfile.TemporaryDirectory() as tmpdir:
            root = Path(tmpdir)
            (Path(outside) / "x").write_bytes(b"outside")
            (root / "inside").write_bytes(b"inside")
            os.symlink(root / "inside", root / "link-in")
            os.symlink(Path(outside) / "x", root / "link-out")
            self.assertEqual(cpb._read_contained_file(root / "inside", root), b"inside")
            self.assertEqual(cpb._read_contained_file(root / "link-in", root), b"inside")  # an in-root symlink stays valid
            with self.assertRaises(cpb._OutsideRoot):
                cpb._read_contained_file(root / "link-out", root)


# ---------------------------------------------------------------------------
# Round-10 review, 30.87.2: W1 load-bearing test gaps, W2 schema depth, W4 possessive quantifiers,
# W3 the stable-ID index built from a private snapshot of the parsed bytes
# ---------------------------------------------------------------------------


def inspect_with_schema_text(schema_text: str, receipt: dict) -> list[str]:
    """Error ids of inspecting receipt against a schema given as raw JSON text."""
    with tempfile.TemporaryDirectory() as tmpdir:
        root = Path(tmpdir)
        schema_path = root / "schema.json"
        schema_path.write_text(schema_text, encoding="utf-8")
        receipt_path = plant_receipt(root, receipt)
        with mock.patch.object(cpb, "RECEIPT_SCHEMA_PATH", schema_path):
            findings, _ = cpb.inspect_qualification_receipt(receipt_path, root)
        return error_code_set(findings)


class TestRound10(unittest.TestCase):
    """Round-10 findings as planted tests with exact finding sets."""

    def with_toolchain_schema(self, sub_schema: object, toolchain: object) -> list[str]:
        return inspect_with_schema(schema_edit((TOOLCHAIN, sub_schema)), {**make_receipt(), "toolchain": toolchain})

    # W1a: JSON Schema equality never equates a boolean with a number ----------------------------

    def test_w1a_booleans_never_equal_numbers_in_const_or_enum(self) -> None:
        refused = [ERR_UNREADABLE_INPUT]
        for label, sub_schema, value, expected in (
            ("const true, value 1", {"const": True}, 1, refused),
            ("const 1, value true", {"const": 1}, True, refused),
            ("const false, value 0", {"const": False}, 0, refused),
            ("const 0, value false", {"const": 0}, False, refused),
            ("enum [true], value 1", {"enum": [True]}, 1, refused),
            ("enum [0], value false", {"enum": [0]}, False, refused),
            ("nested array const", {"const": [True]}, [1], refused),
            ("nested object const", {"const": {"a": False}}, {"a": 0}, refused),
            ("nested enum", {"enum": [[0, {"b": True}]]}, [False, {"b": 1}], refused),
            ("control: true is true", {"const": True}, True, []),
            ("control: 1 equals 1.0", {"const": 1}, 1.0, []),
            ("control: nested numbers by value", {"const": [1, {"a": 2}]}, [1.0, {"a": 2.0}], []),
        ):
            with self.subTest(case=label):
                self.assertEqual(self.with_toolchain_schema(sub_schema, value), expected)

    # W1b: the fallback path is confirmed by device and inode -------------------------------------

    def test_w1b_fallback_path_refuses_an_outside_descriptor(self) -> None:
        """No /proc: the realpath of the path is the candidate. The path was a symlink to an outside
        file when opened and is an in-root file by the time its realpath is taken: without the
        device/inode confirmation the descriptor's outside bytes would be read as contained."""
        real_readlink = os.readlink
        with tempfile.TemporaryDirectory() as outside, tempfile.TemporaryDirectory() as tmpdir:
            root = Path(tmpdir)
            (Path(outside) / "x").write_bytes(b"outside")
            link = root / "x.json"
            os.symlink(Path(outside) / "x", link)

            def readlink_without_proc(path, *args, **kwargs):
                if str(path).startswith("/proc/self/fd/"):
                    link.unlink()
                    link.write_bytes(b"inside")  # swapped after the open, before the fallback realpath
                    raise OSError("no /proc on this platform")
                return real_readlink(path, *args, **kwargs)

            with mock.patch.object(cpb.os, "readlink", readlink_without_proc):
                with self.assertRaises(cpb._OutsideRoot):
                    cpb._read_contained_file(link, root)

    def test_w1b_fallback_path_reads_an_unswapped_file(self) -> None:
        real_readlink = os.readlink
        with tempfile.TemporaryDirectory() as tmpdir:
            root = Path(tmpdir)
            (root / "x.json").write_bytes(b"inside")

            def readlink_without_proc(path, *args, **kwargs):
                if str(path).startswith("/proc/self/fd/"):
                    raise OSError("no /proc on this platform")
                return real_readlink(path, *args, **kwargs)

            with mock.patch.object(cpb.os, "readlink", readlink_without_proc):
                self.assertEqual(cpb._read_contained_file(root / "x.json", root), b"inside")

    # W2: a schema deeper than MAX_JSON_DEPTH is refused, never a RecursionError ---------------------

    def test_w2_deeply_nested_schema_is_refused(self) -> None:
        schema = json.loads(RECEIPT_SCHEMA_SOURCE.read_text(encoding="utf-8"))
        schema["properties"]["toolchain"] = "__DEEP__"
        deep = '{"anyOf": [' * 3000 + '{"type": "string"}' + "]}" * 3000
        text = json.dumps(schema).replace('"__DEEP__"', deep)
        self.assertEqual(inspect_with_schema_text(text, make_receipt()), [ERR_UNREADABLE_INPUT])

    def test_w2_depth_is_checked_before_the_walk(self) -> None:
        node: object = {"type": "string"}
        for _ in range(3000):
            node = {"anyOf": [node]}
        problems = cpb._schema_interpretation_problems(node)
        self.assertEqual(len(problems), 1)
        self.assertIn("nests deeper than", problems[0])

    # W4: possessive quantifiers are refused ---------------------------------------------------

    def test_w4_possessive_quantifiers_are_refused(self) -> None:
        for pattern in ("^a*+$", "^a{2}+$", "^a++$", "^a?+$", "^a+?+$", "^a{2,}+$"):
            with self.subTest(pattern=pattern):
                self.assertEqual(self.with_toolchain_schema({"pattern": pattern}, "aa"), [ERR_UNREADABLE_INPUT])
                self.assertIsNone(cpb._translate_pattern(pattern))
        for pattern, value in (("^a+$", "aaa"), ("^a*?$", "aaa"), ("^a{2}$", "aa"), ("^[+]+$", "++"), ("^a\\++$", "a++")):
            with self.subTest(control=pattern):
                self.assertEqual(self.with_toolchain_schema({"pattern": pattern}, value), [])

    # W3: the index is built from exactly the bytes that were parsed ------------------------------

    def test_w3_index_is_built_from_the_parsed_bytes(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            root = build_fixture_root(Path(tmpdir))
            extra = root / "architecture/extra.json"
            original = b'{"items":[{"id":"FSS-990","status":"tombstoned"}]}'
            extra.write_bytes(original)
            real_index = cpb.stable_id_audit._load_repository_index
            seen_roots: list[Path] = []

            def index(root_arg: Path):
                seen_roots.append(Path(root_arg))
                extra.write_bytes(b'{"items":[{"id":"FSS-990","status":"tombstoned","status":"active"}]}')  # swapped in on disk...
                try:
                    return real_index(root_arg)
                finally:
                    extra.write_bytes(original)  # ...and back before any re-check could see it

            with mock.patch.object(cpb.stable_id_audit, "_load_repository_index", index):
                tombstones, findings = cpb.load_tombstone_index(root)
            self.assertEqual(findings, [])
            self.assertIn(cpb.normalize_id("FSS-990"), tombstones)
            self.assertNotEqual(seen_roots[0].resolve(), root.resolve())


if __name__ == "__main__":
    unittest.main()


