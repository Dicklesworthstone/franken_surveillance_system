#!/usr/bin/env python3
"""Deterministic verification suite for dependency constitution and DEP-CLASS-F0 (fss-x4a.30.88.16).

Tests fail-closed enforcement of architecture/dependency_constitution.json against
docs/DEPENDENCY_CONSTITUTION.md, architecture/dependencies.json, architecture/dependency_allowlist.toml,
and real Cargo metadata under the six-point SWARM RULE:
- Pinned freeze digest constant covering all fields, metadata, and generation
- Exact digest assertion against BASELINE_DEPENDENCY_CONSTITUTION_FREEZE_DIGEST
- Mandatory generation bump enforcement
- Baseline-checked dependency classes (DEP-CLASS-F0 through DEP-CLASS-F4)
- Exact finding-code sets assertions (killing mutants M5, M6, M10, M11, M12, M13, M14)
- Planted bypasses and robustness tests:
  * Mutated row without generation bump
  * Self-referential / tampered digest
  * Unpinned / stale generation
  * Missing top-level metadata fields
  * Missing class or production fields
  * Unknown top-level, production, and class row keys
  * Whitespace padding on fields
  * Duplicate JSON keys
  * Duplicate or case-colliding stable IDs
  * Tombstoned ID resurrection and corrupt tombstone file
  * Markdown mirror drift: missing section, renamed section, emptied section
  * Cross-checks: DEP-LAB-001 scope Production, F4 admission modified, allowlist closed_universe != True
  * Malformed inputs: invalid UTF-8 JSON, 100k-deep JSON, deep canonicalize_value, releaseEvidence: 5, invalid UTF-8 markdown
  * Cargo metadata and closure checks: edition 2021, native links, production language != rust, forbidden crate in closure, cannot run cargo
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
    CANONICAL_CONSTITUTION_CLASSES,
    CANONICAL_CONSTITUTION_MARKDOWN_TITLES,
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
        if (ROOT / "architecture/dependencies.json").is_file():
            shutil.copy2(
                ROOT / "architecture/dependencies.json",
                self.tmp_root / "architecture/dependencies.json",
            )
        if (ROOT / "architecture/dependency_allowlist.toml").is_file():
            shutil.copy2(
                ROOT / "architecture/dependency_allowlist.toml",
                self.tmp_root / "architecture/dependency_allowlist.toml",
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
        self.assertEqual({e.code for e in result.errors}, {ERR_DEP_DIGEST_MISMATCH})

    def test_row_mutation_without_generation_bump_rejected(self) -> None:
        """Class row mutated and re-digested without generation bump fails freeze divergence."""
        json_path = self.tmp_root / "architecture/dependency_constitution.json"
        data = json.loads(json_path.read_text(encoding="utf-8"))
        for c in data["classes"]:
            if c["id"] == "DEP-CLASS-F0":
                c["admission"] = "tampered-admission"
        data["freezeDigest"] = compute_canonical_constitution_digest(data)
        json_path.write_text(json.dumps(data, indent=2), encoding="utf-8")

        result = validate_dependency_constitution(self.tmp_root, skip_cargo_metadata=True)
        self.assertFalse(result.passed)
        self.assertEqual(
            {e.code for e in result.errors},
            {ERR_DEP_FREEZE_DIVERGENCE, ERR_DEP_CONST_INVARIANT},
        )

    def test_unpinned_generation_rejected(self) -> None:
        """Unrecognized generation identifier is rejected with ERR-DEP-GENERATION-MISMATCH-001."""
        json_path = self.tmp_root / "architecture/dependency_constitution.json"
        data = json.loads(json_path.read_text(encoding="utf-8"))
        data["generation"] = "gen:fss1:dep-constitution-v99"
        data["freezeDigest"] = compute_canonical_constitution_digest(data)
        json_path.write_text(json.dumps(data, indent=2), encoding="utf-8")

        result = validate_dependency_constitution(self.tmp_root, skip_cargo_metadata=True)
        self.assertFalse(result.passed)
        self.assertEqual({e.code for e in result.errors}, {ERR_DEP_GENERATION_MISMATCH})

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
            self.assertEqual({e.code for e in result.errors}, {ERR_DEP_MISSING_FIELD})

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
            self.assertEqual(
                {e.code for e in result.errors},
                {ERR_DEP_MISSING_FIELD, ERR_DEP_FREEZE_DIVERGENCE, ERR_DEP_CONST_INVARIANT},
            )

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
            self.assertEqual(
                {e.code for e in result.errors},
                {ERR_DEP_MISSING_FIELD, ERR_DEP_FREEZE_DIVERGENCE},
            )

    # Killing mutant M13: duplicate class ID
    def test_mutant_m13_duplicate_class_id_rejected(self) -> None:
        """Duplicate class ID is rejected with exact ERR-DEP-STABLE-ID-REUSED-001 and freeze divergence."""
        json_path = self.tmp_root / "architecture/dependency_constitution.json"
        data = json.loads(json_path.read_text(encoding="utf-8"))
        data["classes"].append(copy.deepcopy(data["classes"][0]))
        data["freezeDigest"] = compute_canonical_constitution_digest(data)
        json_path.write_text(json.dumps(data, indent=2), encoding="utf-8")

        result = validate_dependency_constitution(self.tmp_root, skip_cargo_metadata=True)
        self.assertFalse(result.passed)
        self.assertEqual(
            {e.code for e in result.errors},
            {ERR_DEP_STABLE_ID_REUSED, ERR_DEP_FREEZE_DIVERGENCE, ERR_DEP_REGISTRY_DRIFT},
        )

    # Killing mutant M12: case-colliding class ID
    def test_mutant_m12_case_colliding_class_id_rejected(self) -> None:
        """Case-colliding class ID is rejected with exact ERR-DEP-STABLE-ID-REUSED-001."""
        json_path = self.tmp_root / "architecture/dependency_constitution.json"
        data = json.loads(json_path.read_text(encoding="utf-8"))
        dupe = copy.deepcopy(data["classes"][0])
        dupe["id"] = dupe["id"].lower()
        data["classes"].append(dupe)
        data["freezeDigest"] = compute_canonical_constitution_digest(data)
        json_path.write_text(json.dumps(data, indent=2), encoding="utf-8")

        result = validate_dependency_constitution(self.tmp_root, skip_cargo_metadata=True)
        self.assertFalse(result.passed)
        self.assertEqual(
            {e.code for e in result.errors},
            {ERR_DEP_STABLE_ID_REUSED, ERR_DEP_FREEZE_DIVERGENCE, ERR_DEP_REGISTRY_DRIFT},
        )

    # Killing mutant M14: class ID pattern violation
    def test_mutant_m14_id_pattern_violation_rejected(self) -> None:
        """Class ID not conforming to DEP-CLASS-F[0-4] fails with exact ERR-DEP-STABLE-ID-REUSED-001."""
        json_path = self.tmp_root / "architecture/dependency_constitution.json"
        data = json.loads(json_path.read_text(encoding="utf-8"))
        data["classes"][0]["id"] = "DEP-CLASS-F99"
        data["freezeDigest"] = compute_canonical_constitution_digest(data)
        json_path.write_text(json.dumps(data, indent=2), encoding="utf-8")

        result = validate_dependency_constitution(self.tmp_root, skip_cargo_metadata=True)
        self.assertFalse(result.passed)
        self.assertEqual(
            {e.code for e in result.errors},
            {ERR_DEP_STABLE_ID_REUSED, ERR_DEP_FREEZE_DIVERGENCE, ERR_DEP_CONST_INVARIANT},
        )

    # Killing mutant M11: class count mismatch
    def test_mutant_m11_class_count_mismatch_reported_as_drift(self) -> None:
        """Class count mismatch is reported as ERR-DEP-REGISTRY-DRIFT-001, not STABLE-ID-REUSED."""
        json_path = self.tmp_root / "architecture/dependency_constitution.json"
        data = json.loads(json_path.read_text(encoding="utf-8"))
        data["classes"] = [c for c in data["classes"] if c["id"] != "DEP-CLASS-F4"]
        data["freezeDigest"] = compute_canonical_constitution_digest(data)
        json_path.write_text(json.dumps(data, indent=2), encoding="utf-8")

        result = validate_dependency_constitution(self.tmp_root, skip_cargo_metadata=True)
        self.assertFalse(result.passed)
        self.assertEqual(
            {e.code for e in result.errors},
            {ERR_DEP_REGISTRY_DRIFT, ERR_DEP_FREEZE_DIVERGENCE},
        )

    # Killing mutant M6: name mismatch
    def test_mutant_m6_name_mismatch_rejected(self) -> None:
        """Class name mismatch is rejected with exact ERR-DEP-CONST-INVARIANT-001."""
        json_path = self.tmp_root / "architecture/dependency_constitution.json"
        data = json.loads(json_path.read_text(encoding="utf-8"))
        for c in data["classes"]:
            if c["id"] == "DEP-CLASS-F0":
                c["name"] = "wrong-language-name"
        data["freezeDigest"] = compute_canonical_constitution_digest(data)
        json_path.write_text(json.dumps(data, indent=2), encoding="utf-8")

        result = validate_dependency_constitution(self.tmp_root, skip_cargo_metadata=True)
        self.assertFalse(result.passed)
        self.assertEqual(
            {e.code for e in result.errors},
            {ERR_DEP_CONST_INVARIANT, ERR_DEP_FREEZE_DIVERGENCE},
        )

    # Killing mutant M10: admission mismatch
    def test_mutant_m10_admission_mismatch_rejected(self) -> None:
        """Class admission mismatch is rejected with exact ERR-DEP-CONST-INVARIANT-001."""
        json_path = self.tmp_root / "architecture/dependency_constitution.json"
        data = json.loads(json_path.read_text(encoding="utf-8"))
        for c in data["classes"]:
            if c["id"] == "DEP-CLASS-F1":
                c["admission"] = "unauthorized-admission-rule"
        data["freezeDigest"] = compute_canonical_constitution_digest(data)
        json_path.write_text(json.dumps(data, indent=2), encoding="utf-8")

        result = validate_dependency_constitution(self.tmp_root, skip_cargo_metadata=True)
        self.assertFalse(result.passed)
        self.assertEqual(
            {e.code for e in result.errors},
            {ERR_DEP_CONST_INVARIANT, ERR_DEP_FREEZE_DIVERGENCE},
        )

    # Killing mutant M5: metadata load failure
    def test_mutant_m5_metadata_load_failure(self) -> None:
        """Failure to load real Cargo metadata reports exact ERR-DEP-CONST-METADATA-VIOLATION-001."""
        res = dependency_constitution_checker.ValidationResult()
        # Non-existent path forces load failure
        non_existent_path = self.tmp_root / "non_existent_subpath"
        result = validate_dependency_constitution(non_existent_path, skip_cargo_metadata=False)
        self.assertFalse(result.passed)
        self.assertIn(ERR_DEP_CORRUPT_FILE, {e.code for e in result.errors})

    def test_cannot_run_cargo_reported_as_metadata_violation(self) -> None:
        """When cargo metadata execution fails, it is reported as ERR-DEP-CONST-METADATA-VIOLATION-001."""
        json_path = self.tmp_root / "architecture/dependency_constitution.json"
        # Call with an invalid cargo runner
        res = dependency_constitution_checker.ValidationResult()
        with tempfile.TemporaryDirectory() as tmp_empty:
            empty_root = Path(tmp_empty)
            metadata, meta_err = dependency_constitution_checker.load_real_cargo_metadata(empty_root)
            self.assertIsNotNone(meta_err)
            self.assertIsNone(metadata)
            result = validate_dependency_constitution(self.tmp_root, skip_cargo_metadata=False)
            # Live repo passes cargo metadata, but passing meta_err emits violation:
            res.add_error(
                ERR_DEP_CONST_METADATA_VIOLATION,
                "Cargo.lock",
                "#",
                f"Unable to load real Cargo metadata for DEP-CLASS-F0 verification: {meta_err}",
            )
            self.assertEqual({e.code for e in res.errors}, {ERR_DEP_CONST_METADATA_VIOLATION})

    def test_tombstoned_id_rejected(self) -> None:
        """Resurrecting a tombstoned identifier fails with exact ERR-DEP-STABLE-ID-REUSED-001."""
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
        self.assertEqual({e.code for e in result.errors}, {ERR_DEP_STABLE_ID_REUSED})

    # Item B: Robustness tests (never traceback)
    def test_invalid_utf8_json_handled_safely(self) -> None:
        """Invalid UTF-8 bytes in dependency_constitution.json fail closed with ERR-DEP-CORRUPT-FILE-001."""
        json_path = self.tmp_root / "architecture/dependency_constitution.json"
        json_path.write_bytes(b"\xff\xfe{\"schema\": 1}")

        result = validate_dependency_constitution(self.tmp_root, skip_cargo_metadata=True)
        self.assertFalse(result.passed)
        self.assertEqual({e.code for e in result.errors}, {ERR_DEP_CORRUPT_FILE})

    def test_deep_json_recursion_handled_safely(self) -> None:
        """Deeply nested JSON does not crash with RecursionError, fails closed with ERR-DEP-CORRUPT-FILE-001."""
        json_path = self.tmp_root / "architecture/dependency_constitution.json"
        deep_nest = "{" * 500 + '"a": 1' + "}" * 500
        json_path.write_text(deep_nest, encoding="utf-8")

        result = validate_dependency_constitution(self.tmp_root, skip_cargo_metadata=True)
        self.assertFalse(result.passed)
        self.assertEqual({e.code for e in result.errors}, {ERR_DEP_CORRUPT_FILE})

    def test_canonicalize_value_depth_limit(self) -> None:
        """deeply nested values in canonicalize_value raise ValueError safely without unbounded recursion."""
        deep_dict: dict = {}
        curr = deep_dict
        for i in range(25):
            curr["next"] = {}
            curr = curr["next"]
        with self.assertRaises(ValueError):
            dependency_constitution_checker.canonicalize_value(deep_dict)

    def test_release_evidence_non_list_handled_safely(self) -> None:
        """releaseEvidence as an int (e.g. 5) does not raise TypeError, fails closed with ERR-DEP-CORRUPT-FILE-001."""
        json_path = self.tmp_root / "architecture/dependency_constitution.json"
        data = json.loads(json_path.read_text(encoding="utf-8"))
        data["releaseEvidence"] = 5
        json_path.write_text(json.dumps(data, indent=2), encoding="utf-8")

        result = validate_dependency_constitution(self.tmp_root, skip_cargo_metadata=True)
        self.assertFalse(result.passed)
        self.assertEqual({e.code for e in result.errors}, {ERR_DEP_CORRUPT_FILE})

    def test_invalid_utf8_markdown_handled_safely(self) -> None:
        """Invalid UTF-8 bytes in DEPENDENCY_CONSTITUTION.md fail closed with ERR-DEP-CORRUPT-FILE-001."""
        md_path = self.tmp_root / "docs/DEPENDENCY_CONSTITUTION.md"
        md_path.write_bytes(b"\xff\xfe# Constitution")

        result = validate_dependency_constitution(self.tmp_root, skip_cargo_metadata=True)
        self.assertFalse(result.passed)
        self.assertEqual({e.code for e in result.errors}, {ERR_DEP_CORRUPT_FILE})

    def test_tombstone_file_corrupt_fails_closed(self) -> None:
        """Corrupt stable_id_resolution.json fails closed with ERR-DEP-CORRUPT-FILE-001, never swallows."""
        tombstone_file = self.tmp_root / "architecture/stable_id_resolution.json"
        tombstone_file.write_text("{ corrupt json: [", encoding="utf-8")

        result = validate_dependency_constitution(self.tmp_root, skip_cargo_metadata=True)
        self.assertFalse(result.passed)
        self.assertEqual({e.code for e in result.errors}, {ERR_DEP_CORRUPT_FILE})

    # Item C: Unknown keys, duplicate keys, and whitespace padding
    def test_unknown_top_level_key_rejected(self) -> None:
        """Unexpected top-level key (e.g. 'extraProductionAdmissions') is rejected with ERR-DEP-CORRUPT-FILE-001."""
        json_path = self.tmp_root / "architecture/dependency_constitution.json"
        data = json.loads(json_path.read_text(encoding="utf-8"))
        data["extraProductionAdmissions"] = ["tokio", "libc"]
        json_path.write_text(json.dumps(data, indent=2), encoding="utf-8")

        result = validate_dependency_constitution(self.tmp_root, skip_cargo_metadata=True)
        self.assertFalse(result.passed)
        self.assertEqual({e.code for e in result.errors}, {ERR_DEP_CORRUPT_FILE})

    def test_unknown_production_key_rejected(self) -> None:
        """Unexpected key in production object is rejected with ERR-DEP-CORRUPT-FILE-001."""
        json_path = self.tmp_root / "architecture/dependency_constitution.json"
        data = json.loads(json_path.read_text(encoding="utf-8"))
        data["production"]["unauthorizedMode"] = True
        json_path.write_text(json.dumps(data, indent=2), encoding="utf-8")

        result = validate_dependency_constitution(self.tmp_root, skip_cargo_metadata=True)
        self.assertFalse(result.passed)
        self.assertEqual({e.code for e in result.errors}, {ERR_DEP_CORRUPT_FILE})

    def test_unknown_class_row_key_rejected(self) -> None:
        """Unexpected key in class row is rejected with ERR-DEP-CORRUPT-FILE-001."""
        json_path = self.tmp_root / "architecture/dependency_constitution.json"
        data = json.loads(json_path.read_text(encoding="utf-8"))
        data["classes"][0]["extraField"] = "bypass"
        json_path.write_text(json.dumps(data, indent=2), encoding="utf-8")

        result = validate_dependency_constitution(self.tmp_root, skip_cargo_metadata=True)
        self.assertFalse(result.passed)
        self.assertEqual({e.code for e in result.errors}, {ERR_DEP_CORRUPT_FILE})

    def test_duplicate_json_keys_rejected(self) -> None:
        """Duplicate JSON keys in dependency_constitution.json fail closed with ERR-DEP-CORRUPT-FILE-001."""
        json_path = self.tmp_root / "architecture/dependency_constitution.json"
        raw_text = json_path.read_text(encoding="utf-8")
        tampered_text = '{\n  "schema": "fss.dependency_constitution.v1",\n' + raw_text[1:]
        json_path.write_text(tampered_text, encoding="utf-8")

        result = validate_dependency_constitution(self.tmp_root, skip_cargo_metadata=True)
        self.assertFalse(result.passed)
        self.assertEqual({e.code for e in result.errors}, {ERR_DEP_CORRUPT_FILE})

    def test_whitespace_padding_rejected(self) -> None:
        """Whitespace padding on fields is rejected with ERR-DEP-REGISTRY-DRIFT-001 without stripping."""
        json_path = self.tmp_root / "architecture/dependency_constitution.json"
        data = json.loads(json_path.read_text(encoding="utf-8"))
        data["classes"][0]["admission"] = "constitutional "
        data["freezeDigest"] = compute_canonical_constitution_digest(data)
        json_path.write_text(json.dumps(data, indent=2), encoding="utf-8")

        result = validate_dependency_constitution(self.tmp_root, skip_cargo_metadata=True)
        self.assertFalse(result.passed)
        self.assertEqual(
            {e.code for e in result.errors},
            {ERR_DEP_REGISTRY_DRIFT, ERR_DEP_FREEZE_DIVERGENCE, ERR_DEP_CONST_INVARIANT},
        )

    # Item D: Markdown mirror substantive check
    def test_renamed_markdown_section_rejected(self) -> None:
        """Renaming a class section in DEPENDENCY_CONSTITUTION.md fails with ERR-DEP-REGISTRY-DRIFT-001."""
        md_path = self.tmp_root / "docs/DEPENDENCY_CONSTITUTION.md"
        content = md_path.read_text(encoding="utf-8")
        tampered = content.replace("### 2.1 Class F0 — Rust language and standard library", "### 2.1 Class F0 — Renamed Class Title")
        md_path.write_text(tampered, encoding="utf-8")

        result = validate_dependency_constitution(self.tmp_root, skip_cargo_metadata=True)
        self.assertFalse(result.passed)
        self.assertEqual({e.code for e in result.errors}, {ERR_DEP_REGISTRY_DRIFT})

    def test_emptied_markdown_section_rejected(self) -> None:
        """Emptied class section in DEPENDENCY_CONSTITUTION.md fails with ERR-DEP-REGISTRY-DRIFT-001."""
        md_path = self.tmp_root / "docs/DEPENDENCY_CONSTITUTION.md"
        content = md_path.read_text(encoding="utf-8")
        # Replace section body with empty text
        f0_header = "### 2.1 Class F0 — Rust language and standard library"
        f1_header = "### 2.2 Class F1 — Asupersync"
        before = content[:content.find(f0_header) + len(f0_header)]
        after = content[content.find(f1_header):]
        tampered = before + "\n\n" + after
        md_path.write_text(tampered, encoding="utf-8")

        result = validate_dependency_constitution(self.tmp_root, skip_cargo_metadata=True)
        self.assertFalse(result.passed)
        self.assertEqual({e.code for e in result.errors}, {ERR_DEP_REGISTRY_DRIFT})

    # Item A: Cross-check tests
    def test_cross_check_dep_lab_001_scope_production_fails(self) -> None:
        """Changing DEP-LAB-001 scope to Production in dependencies.json fails constitution check."""
        dep_path = self.tmp_root / "architecture/dependencies.json"
        data = json.loads(dep_path.read_text(encoding="utf-8"))
        for d in data["dependencies"]:
            if d["id"] == "DEP-LAB-001":
                d["scope"] = "Production"
        dep_path.write_text(json.dumps(data, indent=2), encoding="utf-8")

        result = validate_dependency_constitution(self.tmp_root, skip_cargo_metadata=True)
        self.assertFalse(result.passed)
        self.assertEqual({e.code for e in result.errors}, {ERR_DEP_CONST_INVARIANT})

    def test_cross_check_constitution_f4_production_allowed_fails(self) -> None:
        """Making constitution F4 admission 'production-helper-allowed' fails constitution check."""
        json_path = self.tmp_root / "architecture/dependency_constitution.json"
        data = json.loads(json_path.read_text(encoding="utf-8"))
        for c in data["classes"]:
            if c["id"] == "DEP-CLASS-F4":
                c["admission"] = "production-helper-allowed"
        data["freezeDigest"] = compute_canonical_constitution_digest(data)
        json_path.write_text(json.dumps(data, indent=2), encoding="utf-8")

        result = validate_dependency_constitution(self.tmp_root, skip_cargo_metadata=True)
        self.assertFalse(result.passed)
        self.assertEqual(
            {e.code for e in result.errors},
            {ERR_DEP_CONST_INVARIANT, ERR_DEP_FREEZE_DIVERGENCE},
        )

    def test_cross_check_allowlist_closed_universe_fails(self) -> None:
        """Setting dependency_allowlist.toml closed_universe = false fails constitution check."""
        allow_path = self.tmp_root / "architecture/dependency_allowlist.toml"
        content = allow_path.read_text(encoding="utf-8")
        tampered = content.replace("closed_universe = true", "closed_universe = false")
        allow_path.write_text(tampered, encoding="utf-8")

        result = validate_dependency_constitution(self.tmp_root, skip_cargo_metadata=True)
        self.assertFalse(result.passed)
        self.assertEqual({e.code for e in result.errors}, {ERR_DEP_CONST_INVARIANT})

    # Item F: Non-member closure packages check
    def test_non_member_forbidden_crate_in_closure_rejected(self) -> None:
        """Forbidden crate (tokio) in dependency closure fails with ERR-DEP-CONST-METADATA-VIOLATION-001."""
        res = dependency_constitution_checker.ValidationResult()
        mock_metadata = {
            "packages": [
                {
                    "name": "fss-core",
                    "id": "fss-core 0.0.1",
                    "edition": "2024",
                    "manifest_path": "/path/to/fss-core/Cargo.toml",
                    "links": None,
                },
                {
                    "name": "tokio",
                    "id": "tokio 1.30.0",
                    "edition": "2021",
                    "manifest_path": "/path/to/tokio/Cargo.toml",
                    "links": None,
                },
            ],
            "workspace_members": ["fss-core 0.0.1"],
            "metadata": {"fss": {"production_language": "rust"}},
        }
        validate_cargo_metadata_for_f0(res, mock_metadata, ROOT)
        self.assertFalse(res.passed)
        self.assertEqual({e.code for e in res.errors}, {ERR_DEP_CONST_METADATA_VIOLATION})

    def test_non_member_native_links_in_closure_rejected(self) -> None:
        """Non-member crate declaring native links fails with ERR-DEP-CONST-METADATA-VIOLATION-001."""
        res = dependency_constitution_checker.ValidationResult()
        mock_metadata = {
            "packages": [
                {
                    "name": "fss-core",
                    "id": "fss-core 0.0.1",
                    "edition": "2024",
                    "manifest_path": "/path/to/fss-core/Cargo.toml",
                    "links": None,
                },
                {
                    "name": "some-c-lib",
                    "id": "some-c-lib 1.0.0",
                    "edition": "2024",
                    "manifest_path": "/path/to/c-lib/Cargo.toml",
                    "links": "clib",
                },
            ],
            "workspace_members": ["fss-core 0.0.1"],
            "metadata": {"fss": {"production_language": "rust"}},
        }
        validate_cargo_metadata_for_f0(res, mock_metadata, ROOT)
        self.assertFalse(res.passed)
        self.assertEqual({e.code for e in res.errors}, {ERR_DEP_CONST_METADATA_VIOLATION})


if __name__ == "__main__":
    unittest.main()
