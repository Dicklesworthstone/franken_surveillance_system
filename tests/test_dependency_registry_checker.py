#!/usr/bin/env python3
"""Deterministic verification suite for the dependency-class registry checker (fss-x4a.30.88.1).

Tests the fail-closed verification of architecture/dependencies.json against
registries/DEPENDENCIES.md and canonical baseline constants according to the SWARM RULE:
- Pinned freeze digest covering all fields, metadata, and generation
- Exact digest assertion against BASELINE_DEPENDENCIES_FREEZE_DIGEST
- Mandatory generation bump enforcement
- Planted bypasses:
  * Mutated row without generation bump
  * Self-referential / tampered digest
  * Unpinned / stale generation
  * Missing top-level metadata fields
  * Missing mandatory row fields
  * Duplicate or case-colliding stable IDs
  * Tombstoned ID resurrection
  * Markdown mirror drift (class, rule, scope, missing/extra rows)
  * Corrupt or empty JSON / Markdown files
  * Tests that reject prefix-only digest checks
"""
from __future__ import annotations

import copy
import hashlib
import json
import shutil
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))

import dependency_registry_checker
from dependency_registry_checker import (
    BASELINE_DEPENDENCIES_FREEZE_DIGEST,
    BASELINE_DEPENDENCIES_GENERATION,
    CANONICAL_DEPENDENCY_CLASSES,
    EXPECTED_FREEZE_DIGESTS,
    MANDATORY_ROW_FIELDS,
    MANDATORY_TOP_LEVEL_FIELDS,
    ERR_DEP_CORRUPT_FILE,
    ERR_DEP_DIGEST_MISMATCH,
    ERR_DEP_FREEZE_DIVERGENCE,
    ERR_DEP_GENERATION_MISMATCH,
    ERR_DEP_MISSING_FIELD,
    ERR_DEP_REGISTRY_DRIFT,
    ERR_DEP_STABLE_ID_REUSED,
    compute_canonical_dependencies_digest,
    validate_dependency_registry,
)


class TestDependencyRegistryChecker(unittest.TestCase):
    """Verifies dependency registry checker against live repository and planted faults."""

    def setUp(self) -> None:
        self.tmp_dir = tempfile.TemporaryDirectory()
        self.tmp_root = Path(self.tmp_dir.name)
        # Mirror architecture and registries directories
        (self.tmp_root / "architecture").mkdir(parents=True, exist_ok=True)
        (self.tmp_root / "registries").mkdir(parents=True, exist_ok=True)

        shutil.copy2(ROOT / "architecture/dependencies.json", self.tmp_root / "architecture/dependencies.json")
        shutil.copy2(ROOT / "registries/DEPENDENCIES.md", self.tmp_root / "registries/DEPENDENCIES.md")
        if (ROOT / "architecture/stable_id_resolution.json").is_file():
            shutil.copy2(ROOT / "architecture/stable_id_resolution.json", self.tmp_root / "architecture/stable_id_resolution.json")

    def tearDown(self) -> None:
        self.tmp_dir.cleanup()

    def test_live_registry_passes(self) -> None:
        """Live repository dependencies.json passes validation with 0 errors."""
        result = validate_dependency_registry(ROOT)
        self.assertTrue(result.passed, f"Live registry validation failed: {[e.message for e in result.errors]}")
        self.assertEqual(len(result.errors), 0)
        self.assertEqual(result.dependency_count, 5)
        self.assertEqual(result.freeze_digest, BASELINE_DEPENDENCIES_FREEZE_DIGEST)

    def test_exact_freeze_digest_assertion(self) -> None:
        """Freeze digest matches exact constant byte-for-byte; no prefix-only matching."""
        result = validate_dependency_registry(self.tmp_root)
        self.assertTrue(result.passed)
        self.assertEqual(result.freeze_digest, BASELINE_DEPENDENCIES_FREEZE_DIGEST)
        # Ensure length is full sha256: prefix + 64 hex chars
        self.assertTrue(result.freeze_digest.startswith("sha256:"))
        self.assertEqual(len(result.freeze_digest), 7 + 64)

    def test_canonical_digest_deterministic(self) -> None:
        """Canonical digest is deterministic and invariant to row permutation."""
        json_path = self.tmp_root / "architecture/dependencies.json"
        data = json.loads(json_path.read_text(encoding="utf-8"))

        digest1 = compute_canonical_dependencies_digest(data)
        # Reverse rows
        data_rev = copy.deepcopy(data)
        data_rev["dependencies"] = list(reversed(data_rev["dependencies"]))
        digest2 = compute_canonical_dependencies_digest(data_rev)
        self.assertEqual(digest1, digest2)
        self.assertEqual(digest1, BASELINE_DEPENDENCIES_FREEZE_DIGEST)

    def test_tampered_digest_rejected(self) -> None:
        """Self-referential digest mutation: tampered freezeDigest is rejected."""
        json_path = self.tmp_root / "architecture/dependencies.json"
        data = json.loads(json_path.read_text(encoding="utf-8"))
        data["freezeDigest"] = "sha256:0000000000000000000000000000000000000000000000000000000000000000"
        json_path.write_text(json.dumps(data, indent=2), encoding="utf-8")

        result = validate_dependency_registry(self.tmp_root)
        self.assertFalse(result.passed)
        error_codes = [e.code for e in result.errors]
        self.assertIn(ERR_DEP_DIGEST_MISMATCH, error_codes)

    def test_row_mutation_without_generation_bump_rejected(self) -> None:
        """Row mutated and re-digested without generation bump fails freeze divergence."""
        json_path = self.tmp_root / "architecture/dependencies.json"
        data = json.loads(json_path.read_text(encoding="utf-8"))
        # Mutate rule of DEP-OWNED-001
        for dep in data["dependencies"]:
            if dep["id"] == "DEP-OWNED-001":
                dep["rule"] = "tampered rule without approval"
        # Recompute digest to simulate attacker updating freezeDigest
        data["freezeDigest"] = compute_canonical_dependencies_digest(data)
        json_path.write_text(json.dumps(data, indent=2), encoding="utf-8")

        result = validate_dependency_registry(self.tmp_root)
        self.assertFalse(result.passed)
        error_codes = [e.code for e in result.errors]
        self.assertIn(ERR_DEP_FREEZE_DIVERGENCE, error_codes)
        self.assertIn(ERR_DEP_REGISTRY_DRIFT, error_codes)

    def test_unpinned_generation_rejected(self) -> None:
        """Unrecognized generation identifier is rejected with ERR-DEP-GENERATION-MISMATCH-001."""
        json_path = self.tmp_root / "architecture/dependencies.json"
        data = json.loads(json_path.read_text(encoding="utf-8"))
        data["generation"] = "gen:fss1:dependencies-unauthorized-v99"
        data["freezeDigest"] = compute_canonical_dependencies_digest(data)
        json_path.write_text(json.dumps(data, indent=2), encoding="utf-8")

        result = validate_dependency_registry(self.tmp_root)
        self.assertFalse(result.passed)
        error_codes = [e.code for e in result.errors]
        self.assertIn(ERR_DEP_GENERATION_MISMATCH, error_codes)

    def test_missing_top_level_field_rejected(self) -> None:
        """Missing any mandatory top-level field is rejected with ERR-DEP-MISSING-FIELD-001."""
        json_path = self.tmp_root / "architecture/dependencies.json"
        original_data = json.loads(json_path.read_text(encoding="utf-8"))

        for field_name in MANDATORY_TOP_LEVEL_FIELDS:
            data = copy.deepcopy(original_data)
            del data[field_name]
            json_path.write_text(json.dumps(data, indent=2), encoding="utf-8")

            result = validate_dependency_registry(self.tmp_root)
            self.assertFalse(result.passed, f"Expected failure when missing top-level field '{field_name}'")
            error_codes = [e.code for e in result.errors]
            self.assertIn(ERR_DEP_MISSING_FIELD, error_codes, f"Missing field '{field_name}' did not emit {ERR_DEP_MISSING_FIELD}")

    def test_missing_row_field_rejected(self) -> None:
        """Missing any mandatory row field is rejected with ERR-DEP-MISSING-FIELD-001."""
        json_path = self.tmp_root / "architecture/dependencies.json"
        original_data = json.loads(json_path.read_text(encoding="utf-8"))

        for row_field in MANDATORY_ROW_FIELDS:
            data = copy.deepcopy(original_data)
            del data["dependencies"][0][row_field]
            data["freezeDigest"] = compute_canonical_dependencies_digest(data)
            json_path.write_text(json.dumps(data, indent=2), encoding="utf-8")

            result = validate_dependency_registry(self.tmp_root)
            self.assertFalse(result.passed, f"Expected failure when missing row field '{row_field}'")
            error_codes = [e.code for e in result.errors]
            self.assertIn(ERR_DEP_MISSING_FIELD, error_codes, f"Missing row field '{row_field}' did not emit {ERR_DEP_MISSING_FIELD}")

    def test_duplicate_id_rejected(self) -> None:
        """Duplicate dependency class ID is rejected with ERR-DEP-STABLE-ID-REUSED-001."""
        json_path = self.tmp_root / "architecture/dependencies.json"
        data = json.loads(json_path.read_text(encoding="utf-8"))
        data["dependencies"].append(copy.deepcopy(data["dependencies"][0]))
        data["freezeDigest"] = compute_canonical_dependencies_digest(data)
        json_path.write_text(json.dumps(data, indent=2), encoding="utf-8")

        result = validate_dependency_registry(self.tmp_root)
        self.assertFalse(result.passed)
        error_codes = [e.code for e in result.errors]
        self.assertIn(ERR_DEP_STABLE_ID_REUSED, error_codes)

    def test_case_colliding_id_rejected(self) -> None:
        """Case-colliding dependency class ID is rejected with ERR-DEP-STABLE-ID-REUSED-001."""
        json_path = self.tmp_root / "architecture/dependencies.json"
        data = json.loads(json_path.read_text(encoding="utf-8"))
        dupe = copy.deepcopy(data["dependencies"][0])
        dupe["id"] = dupe["id"].lower()
        data["dependencies"].append(dupe)
        data["freezeDigest"] = compute_canonical_dependencies_digest(data)
        json_path.write_text(json.dumps(data, indent=2), encoding="utf-8")

        result = validate_dependency_registry(self.tmp_root)
        self.assertFalse(result.passed)
        error_codes = [e.code for e in result.errors]
        self.assertIn(ERR_DEP_STABLE_ID_REUSED, error_codes)

    def test_tombstoned_id_rejected(self) -> None:
        """Resurrecting a tombstoned identifier fails with ERR-DEP-STABLE-ID-REUSED-001."""
        tombstone_file = self.tmp_root / "architecture/stable_id_resolution.json"
        tombstone_data = {
            "schema": "fss.stable_id_resolution.v1",
            "asOf": "2026-09-01",
            "resolutions": [
                {
                    "legacyId": "DEP-OWNED-001",
                    "status": "tombstoned",
                    "canonicalId": "DEP-OWNED-999",
                }
            ],
        }
        tombstone_file.write_text(json.dumps(tombstone_data, indent=2), encoding="utf-8")

        result = validate_dependency_registry(self.tmp_root)
        self.assertFalse(result.passed)
        error_codes = [e.code for e in result.errors]
        self.assertIn(ERR_DEP_STABLE_ID_REUSED, error_codes)

    def test_markdown_mirror_drift_rejected(self) -> None:
        """Markdown mirror disagreement in class, rule, scope, or row count is rejected."""
        md_path = self.tmp_root / "registries/DEPENDENCIES.md"
        original_md = md_path.read_text(encoding="utf-8")

        # 1. Mutate class
        tampered_md = original_md.replace("Owned runtime and Franken-suite families", "Drifted Class Name")
        md_path.write_text(tampered_md, encoding="utf-8")
        result = validate_dependency_registry(self.tmp_root)
        self.assertFalse(result.passed)
        self.assertIn(ERR_DEP_REGISTRY_DRIFT, [e.code for e in result.errors])

        # 2. Mutate scope
        tampered_md = original_md.replace("`Production`", "`Experimental`")
        md_path.write_text(tampered_md, encoding="utf-8")
        result = validate_dependency_registry(self.tmp_root)
        self.assertFalse(result.passed)
        self.assertIn(ERR_DEP_REGISTRY_DRIFT, [e.code for e in result.errors])

        # 3. Drop a row in markdown
        lines = original_md.splitlines()
        filtered_lines = [l for l in lines if "DEP-EXCEPTION-001" not in l]
        md_path.write_text("\n".join(filtered_lines) + "\n", encoding="utf-8")
        result = validate_dependency_registry(self.tmp_root)
        self.assertFalse(result.passed)
        self.assertIn(ERR_DEP_REGISTRY_DRIFT, [e.code for e in result.errors])

    def test_corrupt_or_empty_files_rejected(self) -> None:
        """Corrupt or 0-byte JSON and Markdown files fail closed with ERR-DEP-CORRUPT-FILE-001."""
        json_path = self.tmp_root / "architecture/dependencies.json"
        md_path = self.tmp_root / "registries/DEPENDENCIES.md"

        # 0-byte JSON
        json_path.write_text("", encoding="utf-8")
        result = validate_dependency_registry(self.tmp_root)
        self.assertFalse(result.passed)
        self.assertIn(ERR_DEP_CORRUPT_FILE, [e.code for e in result.errors])

        # Invalid JSON syntax
        json_path.write_text("{ unquoted_key: ]", encoding="utf-8")
        result = validate_dependency_registry(self.tmp_root)
        self.assertFalse(result.passed)
        self.assertIn(ERR_DEP_CORRUPT_FILE, [e.code for e in result.errors])

        # Restore JSON, empty markdown
        shutil.copy2(ROOT / "architecture/dependencies.json", json_path)
        md_path.write_text("# Empty dependencies\n", encoding="utf-8")
        result = validate_dependency_registry(self.tmp_root)
        self.assertFalse(result.passed)
        self.assertIn(ERR_DEP_CORRUPT_FILE, [e.code for e in result.errors])

    def test_prefix_only_digest_bypass_prevented(self) -> None:
        """Verify that digest checking fails if only prefix matches."""
        json_path = self.tmp_root / "architecture/dependencies.json"
        data = json.loads(json_path.read_text(encoding="utf-8"))
        # Keep prefix, change last 8 chars
        prefix = BASELINE_DEPENDENCIES_FREEZE_DIGEST[:-8]
        data["freezeDigest"] = prefix + "deadbeef"
        json_path.write_text(json.dumps(data, indent=2), encoding="utf-8")

        result = validate_dependency_registry(self.tmp_root)
        self.assertFalse(result.passed)
        error_codes = [e.code for e in result.errors]
        self.assertIn(ERR_DEP_DIGEST_MISMATCH, error_codes)


class TestDependencyClassification(unittest.TestCase):
    """Verifies that dependency_audit classifies packages into DEP classes and reports consumers."""

    def test_classify_owned_crates(self) -> None:
        """Owned workspace members and allowed in-house families map to DEP-OWNED-001."""
        import dependency_audit
        policy = {
            "in_house": {"allowed_families": ["asupersync", "frankensqlite", "fsqlite-*", "fss-*"]},
            "fundamental": {"allowed_subject_to_audit": ["serde"]},
            "laboratory_oracles": {"excluded_from_production_release_closure": ["opencv"]},
            "exception_candidates": {"not_admitted_without_dep_record_adr_and_release_evidence": ["blake3"]},
            "forbidden": {"crates": ["tokio"]},
        }
        members = {"fss-core", "fss-cli", "fss-ledger"}

        for crate_name in ("fss-core", "fss-cli", "fss-ledger", "asupersync", "frankensqlite", "fsqlite-wal"):
            dep_id, code, reason = dependency_audit.classify_dependency_package(crate_name, policy, members, is_production=True)
            self.assertEqual(dep_id, "DEP-OWNED-001", f"Expected {crate_name} to be DEP-OWNED-001")
            self.assertIsNone(code)
            self.assertIsNone(reason)

    def test_unclassified_crate_rejected(self) -> None:
        """Unrecognized external crate fails with DEP-AUD-042."""
        import dependency_audit
        policy = {
            "in_house": {"allowed_families": ["fss-*"]},
            "fundamental": {"allowed_subject_to_audit": []},
            "laboratory_oracles": {"excluded_from_production_release_closure": []},
            "exception_candidates": {"not_admitted_without_dep_record_adr_and_release_evidence": []},
            "forbidden": {"crates": []},
        }
        members = {"fss-core"}

        findings: list[dependency_audit.Finding] = []
        resolved = [{"name": "totally-unrecognized-crate", "version": "1.0.0"}]
        res = dependency_audit.audit_dependency_classes(findings, ROOT, policy, members, resolved)
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0].code, "DEP-AUD-042")
        self.assertIn("totally-unrecognized-crate", findings[0].message)

    def test_census_counts_owned_consumers(self) -> None:
        """Live repository audit classifies all workspace crates into DEP-OWNED-001 and reports consumer count."""
        import dependency_audit
        findings: list[dependency_audit.Finding] = []
        members = {"fss-cli", "fss-core", "fss-ledger", "fss-model-ir", "fss-object", "fss-packet", "fss-publication", "fss-reference", "fss-tensor"}
        resolved = [{"name": m, "version": "0.0.1"} for m in members]
        res = dependency_audit.audit_dependency_classes(findings, ROOT, {"in_house": {"allowed_families": ["fss-*"]}}, members, resolved)
        self.assertEqual(len(findings), 0)
        census = res["census"]
        self.assertEqual(census["DEP-OWNED-001"]["consumerCount"], 9)
        self.assertTrue(census["DEP-OWNED-001"]["hasRealConsumer"])
        self.assertIsNone(census["DEP-OWNED-001"]["drift"])

    def test_unconsumed_rows_drift_reported(self) -> None:
        """Unconsumed rows return explicit non-empty drift explanations."""
        import dependency_audit
        findings: list[dependency_audit.Finding] = []
        members = {"fss-core"}
        resolved = [{"name": "fss-core", "version": "0.0.1"}]
        res = dependency_audit.audit_dependency_classes(findings, ROOT, {"in_house": {"allowed_families": ["fss-*"]}}, members, resolved)
        census = res["census"]
        for dep_id in ("DEP-FUND-001", "DEP-LAB-001", "DEP-ORACLE-001", "DEP-EXCEPTION-001"):
            self.assertEqual(census[dep_id]["consumerCount"], 0)
            self.assertFalse(census[dep_id]["hasRealConsumer"])
            self.assertIsNotNone(census[dep_id]["drift"])
            self.assertIn("no real consumer", census[dep_id]["drift"])

    def test_warn_unconsumed_emits_warning(self) -> None:
        """When warn_unconsumed=True, DEP-AUD-044 warnings are emitted for unconsumed classes."""
        import dependency_audit
        findings: list[dependency_audit.Finding] = []
        members = {"fss-core"}
        resolved = [{"name": "fss-core", "version": "0.0.1"}]
        res = dependency_audit.audit_dependency_classes(findings, ROOT, {"in_house": {"allowed_families": ["fss-*"]}}, members, resolved, warn_unconsumed=True)
        dep_044_findings = [f for f in findings if f.code == "DEP-AUD-044"]
        self.assertEqual(len(dep_044_findings), 4)
        for f in dep_044_findings:
            self.assertEqual(f.severity, "warning")


if __name__ == "__main__":
    unittest.main()
