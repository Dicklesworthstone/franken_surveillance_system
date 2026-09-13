#!/usr/bin/env python3
"""Deterministic verification suite for dependency constitution and DEP-CLASS-F0 (fss-x4a.30.88.16).

Tests fail-closed enforcement of architecture/dependency_constitution.json against
docs/DEPENDENCY_CONSTITUTION.md and real Cargo metadata under the six-point SWARM RULE:
- Pinned freeze digest constant covering all fields, metadata, and generation
- Exact digest assertion against BASELINE_DEPENDENCY_CONSTITUTION_FREEZE_DIGEST
- Mandatory generation bump enforcement
- Baseline-checked dependency classes (DEP-CLASS-F0 through DEP-CLASS-F4)
- Semantic invariants for DEP-CLASS-F0 (constitutional admission, pure-Rust production)
- Real Cargo metadata inspection (parses package objects, checks edition 2024, forbids native links)
- Planted bypasses:
  * Mutated row without generation bump
  * Self-referential / tampered digest
  * Unpinned / stale generation
  * Missing top-level metadata fields
  * Missing class or production fields
  * Duplicate or case-colliding stable IDs
  * Tombstoned ID resurrection
  * Markdown mirror drift (missing/drifted class sections)
  * Corrupt or empty JSON / Markdown files
  * Tests that reject prefix-only digest checks
  * Cargo metadata edition, native links, and production language violations
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

import dependency_constitution_checker
from dependency_constitution_checker import (
    BASELINE_DEPENDENCY_CONSTITUTION_FREEZE_DIGEST,
    BASELINE_DEPENDENCY_CONSTITUTION_GENERATION,
    CANONICAL_DEPENDENCY_CLASSES,
    EXPECTED_FREEZE_DIGESTS,
    MANDATORY_CLASS_FIELDS,
    MANDATORY_PRODUCTION_FIELDS,
    MANDATORY_TOP_LEVEL_FIELDS,
    REQUIRED_PRODUCTION_VALUES,
    ERR_DEP_CONST_INVARIANT,
    ERR_DEP_CONST_METADATA_VIOLATION,
    ERR_DEP_CORRUPT_FILE,
    ERR_DEP_DIGEST_MISMATCH,
    ERR_DEP_FREEZE_DIVERGENCE,
    ERR_DEP_GENERATION_MISMATCH,
    ERR_DEP_MISSING_FIELD,
    ERR_DEP_REGISTRY_DRIFT,
    ERR_DEP_STABLE_ID_REUSED,
    compute_canonical_constitution_digest,
    validate_cargo_metadata_for_f0,
    validate_dependency_constitution,
)


class TestDependencyConstitutionChecker(unittest.TestCase):
    """Verifies dependency constitution checker against live repository and planted faults."""

    def setUp(self) -> None:
        self.tmp_dir = tempfile.TemporaryDirectory()
        self.tmp_root = Path(self.tmp_dir.name)
        (self.tmp_root / "architecture").mkdir(parents=True, exist_ok=True)
        (self.tmp_root / "docs").mkdir(parents=True, exist_ok=True)

        shutil.copy2(
            ROOT / "architecture/dependency_constitution.json",
            self.tmp_root / "architecture/dependency_constitution.json",
        )
        shutil.copy2(
            ROOT / "docs/DEPENDENCY_CONSTITUTION.md",
            self.tmp_root / "docs/DEPENDENCY_CONSTITUTION.md",
        )
        if (ROOT / "architecture/stable_id_resolution.json").is_file():
            shutil.copy2(
                ROOT / "architecture/stable_id_resolution.json",
                self.tmp_root / "architecture/stable_id_resolution.json",
            )

    def tearDown(self) -> None:
        self.tmp_dir.cleanup()

    def test_live_constitution_passes(self) -> None:
        """Live repository dependency_constitution.json passes validation with 0 errors."""
        result = validate_dependency_constitution(ROOT)
        self.assertTrue(
            result.passed,
            f"Live constitution validation failed: {[e.message for e in result.errors]}",
        )
        self.assertEqual(len(result.errors), 0)
        self.assertEqual(result.class_count, 5)
        self.assertEqual(result.freeze_digest, BASELINE_DEPENDENCY_CONSTITUTION_FREEZE_DIGEST)

    def test_exact_freeze_digest_assertion(self) -> None:
        """Freeze digest matches exact constant byte-for-byte; no prefix-only matching."""
        result = validate_dependency_constitution(self.tmp_root, skip_cargo_metadata=True)
        self.assertTrue(result.passed)
        self.assertEqual(result.freeze_digest, BASELINE_DEPENDENCY_CONSTITUTION_FREEZE_DIGEST)
        self.assertTrue(result.freeze_digest.startswith("sha256:"))
        self.assertEqual(len(result.freeze_digest), 7 + 64)

    def test_canonical_digest_deterministic(self) -> None:
        """Canonical digest is deterministic and invariant to class row permutation."""
        json_path = self.tmp_root / "architecture/dependency_constitution.json"
        data = json.loads(json_path.read_text(encoding="utf-8"))

        digest1 = compute_canonical_constitution_digest(data)
        data_rev = copy.deepcopy(data)
        data_rev["classes"] = list(reversed(data_rev["classes"]))
        digest2 = compute_canonical_constitution_digest(data_rev)
        self.assertEqual(digest1, digest2)
        self.assertEqual(digest1, BASELINE_DEPENDENCY_CONSTITUTION_FREEZE_DIGEST)

    def test_tampered_digest_rejected(self) -> None:
        """Self-referential digest mutation: tampered freezeDigest is rejected."""
        json_path = self.tmp_root / "architecture/dependency_constitution.json"
        data = json.loads(json_path.read_text(encoding="utf-8"))
        data["freezeDigest"] = "sha256:0000000000000000000000000000000000000000000000000000000000000000"
        json_path.write_text(json.dumps(data, indent=2), encoding="utf-8")

        result = validate_dependency_constitution(self.tmp_root, skip_cargo_metadata=True)
        self.assertFalse(result.passed)
        error_codes = [e.code for e in result.errors]
        self.assertIn(ERR_DEP_DIGEST_MISMATCH, error_codes)

    def test_row_mutation_without_generation_bump_rejected(self) -> None:
        """Class row mutated and re-digested without generation bump fails freeze divergence."""
        json_path = self.tmp_root / "architecture/dependency_constitution.json"
        data = json.loads(json_path.read_text(encoding="utf-8"))
        # Mutate admission of DEP-CLASS-F0
        for c in data["classes"]:
            if c["id"] == "DEP-CLASS-F0":
                c["admission"] = "tampered-admission"
        data["freezeDigest"] = compute_canonical_constitution_digest(data)
        json_path.write_text(json.dumps(data, indent=2), encoding="utf-8")

        result = validate_dependency_constitution(self.tmp_root, skip_cargo_metadata=True)
        self.assertFalse(result.passed)
        error_codes = [e.code for e in result.errors]
        self.assertIn(ERR_DEP_FREEZE_DIVERGENCE, error_codes)
        self.assertIn(ERR_DEP_CONST_INVARIANT, error_codes)

    def test_unpinned_generation_rejected(self) -> None:
        """Unrecognized generation identifier is rejected with ERR-DEP-GENERATION-MISMATCH-001."""
        json_path = self.tmp_root / "architecture/dependency_constitution.json"
        data = json.loads(json_path.read_text(encoding="utf-8"))
        data["generation"] = "gen:fss1:dep-constitution-v99"
        data["freezeDigest"] = compute_canonical_constitution_digest(data)
        json_path.write_text(json.dumps(data, indent=2), encoding="utf-8")

        result = validate_dependency_constitution(self.tmp_root, skip_cargo_metadata=True)
        self.assertFalse(result.passed)
        error_codes = [e.code for e in result.errors]
        self.assertIn(ERR_DEP_GENERATION_MISMATCH, error_codes)

    def test_missing_top_level_field_rejected(self) -> None:
        """Missing any mandatory top-level field is rejected with ERR-DEP-MISSING-FIELD-001."""
        json_path = self.tmp_root / "architecture/dependency_constitution.json"
        original_data = json.loads(json_path.read_text(encoding="utf-8"))

        for field_name in MANDATORY_TOP_LEVEL_FIELDS:
            data = copy.deepcopy(original_data)
            del data[field_name]
            json_path.write_text(json.dumps(data, indent=2), encoding="utf-8")

            result = validate_dependency_constitution(self.tmp_root, skip_cargo_metadata=True)
            self.assertFalse(result.passed, f"Expected failure when missing top-level field '{field_name}'")
            error_codes = [e.code for e in result.errors]
            self.assertIn(ERR_DEP_MISSING_FIELD, error_codes)

    def test_missing_class_field_rejected(self) -> None:
        """Missing any mandatory class field is rejected with ERR-DEP-MISSING-FIELD-001."""
        json_path = self.tmp_root / "architecture/dependency_constitution.json"
        original_data = json.loads(json_path.read_text(encoding="utf-8"))

        for c_field in MANDATORY_CLASS_FIELDS:
            data = copy.deepcopy(original_data)
            del data["classes"][0][c_field]
            data["freezeDigest"] = compute_canonical_constitution_digest(data)
            json_path.write_text(json.dumps(data, indent=2), encoding="utf-8")

            result = validate_dependency_constitution(self.tmp_root, skip_cargo_metadata=True)
            self.assertFalse(result.passed, f"Expected failure when missing class field '{c_field}'")
            error_codes = [e.code for e in result.errors]
            self.assertIn(ERR_DEP_MISSING_FIELD, error_codes)

    def test_missing_production_field_rejected(self) -> None:
        """Missing any mandatory production field is rejected with ERR-DEP-MISSING-FIELD-001."""
        json_path = self.tmp_root / "architecture/dependency_constitution.json"
        original_data = json.loads(json_path.read_text(encoding="utf-8"))

        for p_field in MANDATORY_PRODUCTION_FIELDS:
            data = copy.deepcopy(original_data)
            del data["production"][p_field]
            data["freezeDigest"] = compute_canonical_constitution_digest(data)
            json_path.write_text(json.dumps(data, indent=2), encoding="utf-8")

            result = validate_dependency_constitution(self.tmp_root, skip_cargo_metadata=True)
            self.assertFalse(result.passed, f"Expected failure when missing production field '{p_field}'")
            error_codes = [e.code for e in result.errors]
            self.assertIn(ERR_DEP_MISSING_FIELD, error_codes)

    def test_duplicate_class_id_rejected(self) -> None:
        """Duplicate class ID is rejected with ERR-DEP-STABLE-ID-REUSED-001."""
        json_path = self.tmp_root / "architecture/dependency_constitution.json"
        data = json.loads(json_path.read_text(encoding="utf-8"))
        data["classes"].append(copy.deepcopy(data["classes"][0]))
        data["freezeDigest"] = compute_canonical_constitution_digest(data)
        json_path.write_text(json.dumps(data, indent=2), encoding="utf-8")

        result = validate_dependency_constitution(self.tmp_root, skip_cargo_metadata=True)
        self.assertFalse(result.passed)
        error_codes = [e.code for e in result.errors]
        self.assertIn(ERR_DEP_STABLE_ID_REUSED, error_codes)

    def test_case_colliding_class_id_rejected(self) -> None:
        """Case-colliding class ID is rejected with ERR-DEP-STABLE-ID-REUSED-001."""
        json_path = self.tmp_root / "architecture/dependency_constitution.json"
        data = json.loads(json_path.read_text(encoding="utf-8"))
        dupe = copy.deepcopy(data["classes"][0])
        dupe["id"] = dupe["id"].lower()
        data["classes"].append(dupe)
        data["freezeDigest"] = compute_canonical_constitution_digest(data)
        json_path.write_text(json.dumps(data, indent=2), encoding="utf-8")

        result = validate_dependency_constitution(self.tmp_root, skip_cargo_metadata=True)
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
                    "legacyId": "DEP-CLASS-F0",
                    "status": "tombstoned",
                    "canonicalId": "DEP-CLASS-F99",
                }
            ],
        }
        tombstone_file.write_text(json.dumps(tombstone_data, indent=2), encoding="utf-8")

        result = validate_dependency_constitution(self.tmp_root, skip_cargo_metadata=True)
        self.assertFalse(result.passed)
        error_codes = [e.code for e in result.errors]
        self.assertIn(ERR_DEP_STABLE_ID_REUSED, error_codes)

    def test_markdown_mirror_drift_rejected(self) -> None:
        """Markdown documentation missing class section fails with ERR-DEP-REGISTRY-DRIFT-001."""
        md_path = self.tmp_root / "docs/DEPENDENCY_CONSTITUTION.md"
        original_md = md_path.read_text(encoding="utf-8")
        # Remove Class F0 section
        tampered_md = original_md.replace("### 2.1 Class F0 — Rust language and standard library", "### 2.1 Dropped Section")
        md_path.write_text(tampered_md, encoding="utf-8")

        result = validate_dependency_constitution(self.tmp_root, skip_cargo_metadata=True)
        self.assertFalse(result.passed)
        self.assertIn(ERR_DEP_REGISTRY_DRIFT, [e.code for e in result.errors])

    def test_corrupt_or_empty_files_rejected(self) -> None:
        """Corrupt or 0-byte files fail closed with ERR-DEP-CORRUPT-FILE-001."""
        json_path = self.tmp_root / "architecture/dependency_constitution.json"
        json_path.write_text("", encoding="utf-8")
        result = validate_dependency_constitution(self.tmp_root, skip_cargo_metadata=True)
        self.assertFalse(result.passed)
        self.assertIn(ERR_DEP_CORRUPT_FILE, [e.code for e in result.errors])

        json_path.write_text("{ syntax_error: [", encoding="utf-8")
        result = validate_dependency_constitution(self.tmp_root, skip_cargo_metadata=True)
        self.assertFalse(result.passed)
        self.assertIn(ERR_DEP_CORRUPT_FILE, [e.code for e in result.errors])

    def test_prefix_only_digest_bypass_prevented(self) -> None:
        """Digest check fails if only prefix matches."""
        json_path = self.tmp_root / "architecture/dependency_constitution.json"
        data = json.loads(json_path.read_text(encoding="utf-8"))
        prefix = BASELINE_DEPENDENCY_CONSTITUTION_FREEZE_DIGEST[:-8]
        data["freezeDigest"] = prefix + "deadbeef"
        json_path.write_text(json.dumps(data, indent=2), encoding="utf-8")

        result = validate_dependency_constitution(self.tmp_root, skip_cargo_metadata=True)
        self.assertFalse(result.passed)
        self.assertIn(ERR_DEP_DIGEST_MISMATCH, [e.code for e in result.errors])

    def test_dep_class_f0_admission_invariant(self) -> None:
        """Non-constitutional admission for DEP-CLASS-F0 is rejected with ERR-DEP-CONST-INVARIANT-001."""
        json_path = self.tmp_root / "architecture/dependency_constitution.json"
        data = json.loads(json_path.read_text(encoding="utf-8"))
        for c in data["classes"]:
            if c["id"] == "DEP-CLASS-F0":
                c["admission"] = "permissive"
        data["freezeDigest"] = compute_canonical_constitution_digest(data)
        json_path.write_text(json.dumps(data, indent=2), encoding="utf-8")

        result = validate_dependency_constitution(self.tmp_root, skip_cargo_metadata=True)
        self.assertFalse(result.passed)
        self.assertIn(ERR_DEP_CONST_INVARIANT, [e.code for e in result.errors])

    def test_dep_class_f0_production_invariants(self) -> None:
        """Tampered production language or unsafe policy fails closed with ERR-DEP-CONST-INVARIANT-001."""
        json_path = self.tmp_root / "architecture/dependency_constitution.json"
        data = json.loads(json_path.read_text(encoding="utf-8"))
        data["production"]["language"] = "c++"
        data["freezeDigest"] = compute_canonical_constitution_digest(data)
        json_path.write_text(json.dumps(data, indent=2), encoding="utf-8")

        result = validate_dependency_constitution(self.tmp_root, skip_cargo_metadata=True)
        self.assertFalse(result.passed)
        self.assertIn(ERR_DEP_CONST_INVARIANT, [e.code for e in result.errors])

    def test_cargo_metadata_inspection_live_passes(self) -> None:
        """Real Cargo metadata from live repository passes DEP-CLASS-F0 inspection."""
        result = validate_dependency_constitution(ROOT, skip_cargo_metadata=False)
        self.assertTrue(result.passed, f"Cargo metadata inspection failed: {[e.message for e in result.errors]}")

    def test_cargo_metadata_edition_violation_rejected(self) -> None:
        """Planted package in Cargo metadata declaring edition '2021' fails closed."""
        res = dependency_constitution_checker.ValidationResult()
        mock_metadata = {
            "packages": [
                {
                    "name": "fss-core",
                    "id": "fss-core 0.0.1",
                    "edition": "2021",
                    "manifest_path": "/path/to/fss-core/Cargo.toml",
                    "links": None,
                }
            ],
            "workspace_members": ["fss-core 0.0.1"],
            "metadata": {"fss": {"production_language": "rust"}},
        }
        validate_cargo_metadata_for_f0(res, mock_metadata, ROOT)
        self.assertFalse(res.passed)
        self.assertIn(ERR_DEP_CONST_METADATA_VIOLATION, [e.code for e in res.errors])
        self.assertTrue(any("must declare edition '2024'" in e.message for e in res.errors))

    def test_cargo_metadata_native_links_rejected(self) -> None:
        """Planted package in Cargo metadata declaring native C/C++ links fails closed."""
        res = dependency_constitution_checker.ValidationResult()
        mock_metadata = {
            "packages": [
                {
                    "name": "fss-core",
                    "id": "fss-core 0.0.1",
                    "edition": "2024",
                    "manifest_path": "/path/to/fss-core/Cargo.toml",
                    "links": "system_c_runtime",
                }
            ],
            "workspace_members": ["fss-core 0.0.1"],
            "metadata": {"fss": {"production_language": "rust"}},
        }
        validate_cargo_metadata_for_f0(res, mock_metadata, ROOT)
        self.assertFalse(res.passed)
        self.assertIn(ERR_DEP_CONST_METADATA_VIOLATION, [e.code for e in res.errors])
        self.assertTrue(any("declares native links" in e.message for e in res.errors))

    def test_cargo_metadata_production_language_violation(self) -> None:
        """Planted workspace metadata declaring non-rust language fails closed."""
        res = dependency_constitution_checker.ValidationResult()
        mock_metadata = {
            "packages": [
                {
                    "name": "fss-core",
                    "id": "fss-core 0.0.1",
                    "edition": "2024",
                    "manifest_path": "/path/to/fss-core/Cargo.toml",
                    "links": None,
                }
            ],
            "workspace_members": ["fss-core 0.0.1"],
            "metadata": {"fss": {"production_language": "python"}},
        }
        validate_cargo_metadata_for_f0(res, mock_metadata, ROOT)
        self.assertFalse(res.passed)
        self.assertIn(ERR_DEP_CONST_METADATA_VIOLATION, [e.code for e in res.errors])
        self.assertTrue(any("production_language must be 'rust'" in e.message for e in res.errors))


if __name__ == "__main__":
    unittest.main()
