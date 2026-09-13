#!/usr/bin/env python3
"""Deterministic verification suite for the dependency-class registry checker (fss-x4a.30.88.1).

Tests the fail-closed verification of architecture/dependencies.json against
registries/DEPENDENCIES.md and canonical baseline constants according to the SWARM RULE:
- Pinned freeze digest covering all fields, metadata, and generation
- Exact digest assertion against BASELINE_DEPENDENCIES_FREEZE_DIGEST
- Mandatory generation bump enforcement
- Exact finding-code sets assertions (killing mutants M4, M4b, M4c, M10, M11, M12, M13)
- Planted bypasses:
  * Mutated row without generation bump
  * Self-referential / tampered digest
  * Unpinned / stale generation
  * Missing top-level metadata fields
  * Missing mandatory row fields
  * Unknown top-level keys and row keys
  * Whitespace padding on fields
  * Duplicate JSON keys
  * Duplicate or case-colliding stable IDs
  * Tombstoned ID resurrection
  * Markdown mirror drift (class, rule, scope, missing/extra rows, duplicate rows, non-backticked rows)
  * Scope vs constitution cross-check (DEP-LAB-001 scope Production)
  * Malformed data types (generation as list, dependencies as dict/str/list-of-ints, invalid UTF-8)
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
    BASELINE_CONSTITUTION_FREEZE_DIGEST,
    BASELINE_ALLOWLIST_FREEZE_DIGEST,
    MAX_REGISTRY_FILE_SIZE_BYTES,
    CANONICAL_DEPENDENCY_REGISTRY_ROWS,
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
    ERR_DEP_CONST_INVARIANT,
    compute_canonical_dependencies_digest,
    compute_allowlist_freeze_digest,
    compute_constitution_freeze_digest,
    resolve_dependency_row_metadata,
    validate_dependency_registry,
)


class TestDependencyRegistryChecker(unittest.TestCase):
    """Verifies dependency registry checker against live repository and planted faults."""

    def setUp(self) -> None:
        self.tmp_dir = tempfile.TemporaryDirectory()
        self.tmp_root = Path(self.tmp_dir.name)
        (self.tmp_root / "architecture").mkdir(parents=True, exist_ok=True)
        (self.tmp_root / "registries").mkdir(parents=True, exist_ok=True)

        shutil.copy2(ROOT / "architecture/dependencies.json", self.tmp_root / "architecture/dependencies.json")
        shutil.copy2(ROOT / "registries/DEPENDENCIES.md", self.tmp_root / "registries/DEPENDENCIES.md")
        if (ROOT / "architecture/dependency_constitution.json").is_file():
            shutil.copy2(ROOT / "architecture/dependency_constitution.json", self.tmp_root / "architecture/dependency_constitution.json")
        if (ROOT / "architecture/dependency_allowlist.toml").is_file():
            shutil.copy2(ROOT / "architecture/dependency_allowlist.toml", self.tmp_root / "architecture/dependency_allowlist.toml")
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
        self.assertTrue(result.freeze_digest.startswith("sha256:"))
        self.assertEqual(len(result.freeze_digest), 7 + 64)

    def test_canonical_digest_deterministic(self) -> None:
        """Canonical digest is deterministic and invariant to row permutation."""
        json_path = self.tmp_root / "architecture/dependencies.json"
        data = json.loads(json_path.read_text(encoding="utf-8"))

        digest1 = compute_canonical_dependencies_digest(data)
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
        self.assertEqual({e.code for e in result.errors}, {ERR_DEP_DIGEST_MISMATCH})

    def test_row_mutation_without_generation_bump_rejected(self) -> None:
        """Row mutated and re-digested without generation bump fails freeze divergence."""
        json_path = self.tmp_root / "architecture/dependencies.json"
        data = json.loads(json_path.read_text(encoding="utf-8"))
        for dep in data["dependencies"]:
            if dep["id"] == "DEP-OWNED-001":
                dep["rule"] = "tampered rule without approval"
        data["freezeDigest"] = compute_canonical_dependencies_digest(data)
        json_path.write_text(json.dumps(data, indent=2), encoding="utf-8")

        result = validate_dependency_registry(self.tmp_root)
        self.assertFalse(result.passed)
        self.assertEqual({e.code for e in result.errors}, {ERR_DEP_FREEZE_DIVERGENCE, ERR_DEP_REGISTRY_DRIFT})

    def test_unpinned_generation_rejected(self) -> None:
        """Unrecognized generation identifier is rejected with exact ERR-DEP-GENERATION-MISMATCH-001."""
        json_path = self.tmp_root / "architecture/dependencies.json"
        data = json.loads(json_path.read_text(encoding="utf-8"))
        data["generation"] = "gen:fss1:dependencies-unauthorized-v99"
        data["freezeDigest"] = compute_canonical_dependencies_digest(data)
        json_path.write_text(json.dumps(data, indent=2), encoding="utf-8")

        result = validate_dependency_registry(self.tmp_root)
        self.assertFalse(result.passed)
        self.assertEqual({e.code for e in result.errors}, {ERR_DEP_GENERATION_MISMATCH})

    def test_missing_top_level_field_rejected(self) -> None:
        """Missing any mandatory top-level field is rejected with exact ERR-DEP-MISSING-FIELD-001."""
        json_path = self.tmp_root / "architecture/dependencies.json"
        original_data = json.loads(json_path.read_text(encoding="utf-8"))

        for field_name in MANDATORY_TOP_LEVEL_FIELDS:
            data = copy.deepcopy(original_data)
            del data[field_name]
            json_path.write_text(json.dumps(data, indent=2), encoding="utf-8")

            result = validate_dependency_registry(self.tmp_root)
            self.assertFalse(result.passed, f"Expected failure when missing top-level field '{field_name}'")
            self.assertEqual({e.code for e in result.errors}, {ERR_DEP_MISSING_FIELD})

    def test_missing_row_field_rejected(self) -> None:
        """Missing any mandatory row field is rejected with exact ERR-DEP-MISSING-FIELD-001."""
        json_path = self.tmp_root / "architecture/dependencies.json"
        original_data = json.loads(json_path.read_text(encoding="utf-8"))

        for row_field in MANDATORY_ROW_FIELDS:
            data = copy.deepcopy(original_data)
            del data["dependencies"][0][row_field]
            data["freezeDigest"] = compute_canonical_dependencies_digest(data)
            json_path.write_text(json.dumps(data, indent=2), encoding="utf-8")

            result = validate_dependency_registry(self.tmp_root)
            self.assertFalse(result.passed, f"Expected failure when missing row field '{row_field}'")
            self.assertEqual({e.code for e in result.errors}, {ERR_DEP_MISSING_FIELD})

    def test_duplicate_id_rejected(self) -> None:
        """Duplicate dependency class ID is rejected with ERR-DEP-STABLE-ID-REUSED-001."""
        json_path = self.tmp_root / "architecture/dependencies.json"
        data = json.loads(json_path.read_text(encoding="utf-8"))
        data["dependencies"].append(copy.deepcopy(data["dependencies"][0]))
        data["freezeDigest"] = compute_canonical_dependencies_digest(data)
        json_path.write_text(json.dumps(data, indent=2), encoding="utf-8")

        result = validate_dependency_registry(self.tmp_root)
        self.assertFalse(result.passed)
        self.assertEqual({e.code for e in result.errors}, {ERR_DEP_STABLE_ID_REUSED, ERR_DEP_FREEZE_DIVERGENCE})

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
        self.assertEqual({e.code for e in result.errors}, {ERR_DEP_STABLE_ID_REUSED, ERR_DEP_FREEZE_DIVERGENCE, ERR_DEP_REGISTRY_DRIFT})

    def test_tombstoned_id_rejected(self) -> None:
        """Resurrecting a tombstoned identifier fails with exact ERR-DEP-STABLE-ID-REUSED-001."""
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
        self.assertEqual({e.code for e in result.errors}, {ERR_DEP_STABLE_ID_REUSED})

    # Killing mutant M4: baseline ID compare
    def test_mutant_m4_baseline_id_compare(self) -> None:
        """Planted unrecognized dependency ID is rejected against baseline with exact ERR-DEP-REGISTRY-DRIFT-001."""
        json_path = self.tmp_root / "architecture/dependencies.json"
        data = json.loads(json_path.read_text(encoding="utf-8"))
        data["dependencies"][0]["id"] = "DEP-ROGUE-001"
        data["freezeDigest"] = compute_canonical_dependencies_digest(data)
        json_path.write_text(json.dumps(data, indent=2), encoding="utf-8")

        result = validate_dependency_registry(self.tmp_root)
        self.assertFalse(result.passed)
        self.assertEqual({e.code for e in result.errors}, {ERR_DEP_FREEZE_DIVERGENCE, ERR_DEP_REGISTRY_DRIFT})

    # Killing mutants M4b & M4c: missing canonical row
    def test_mutant_m4b_missing_canonical_row(self) -> None:
        """Missing canonical baseline row DEP-OWNED-001 is rejected with exact ERR-DEP-REGISTRY-DRIFT-001 and freeze divergence."""
        json_path = self.tmp_root / "architecture/dependencies.json"
        data = json.loads(json_path.read_text(encoding="utf-8"))
        data["dependencies"] = [d for d in data["dependencies"] if d["id"] != "DEP-OWNED-001"]
        data["freezeDigest"] = compute_canonical_dependencies_digest(data)
        json_path.write_text(json.dumps(data, indent=2), encoding="utf-8")

        result = validate_dependency_registry(self.tmp_root)
        self.assertFalse(result.passed)
        self.assertEqual({e.code for e in result.errors}, {ERR_DEP_FREEZE_DIVERGENCE, ERR_DEP_REGISTRY_DRIFT})

    def test_mutant_m4c_missing_canonical_row(self) -> None:
        """Missing canonical baseline row DEP-EXCEPTION-001 is rejected with exact ERR-DEP-REGISTRY-DRIFT-001 and freeze divergence."""
        json_path = self.tmp_root / "architecture/dependencies.json"
        data = json.loads(json_path.read_text(encoding="utf-8"))
        data["dependencies"] = [d for d in data["dependencies"] if d["id"] != "DEP-EXCEPTION-001"]
        data["freezeDigest"] = compute_canonical_dependencies_digest(data)
        json_path.write_text(json.dumps(data, indent=2), encoding="utf-8")

        result = validate_dependency_registry(self.tmp_root)
        self.assertFalse(result.passed)
        self.assertEqual({e.code for e in result.errors}, {ERR_DEP_FREEZE_DIVERGENCE, ERR_DEP_REGISTRY_DRIFT})

    # Item C: Unknown top-level key rejection
    def test_unknown_top_level_key_rejected(self) -> None:
        """Unexpected top-level key (e.g. 'overrides') is rejected with exact ERR-DEP-CORRUPT-FILE-001."""
        json_path = self.tmp_root / "architecture/dependencies.json"
        data = json.loads(json_path.read_text(encoding="utf-8"))
        data["overrides"] = {"DEP-FUND-001": "allowed"}
        json_path.write_text(json.dumps(data, indent=2), encoding="utf-8")

        result = validate_dependency_registry(self.tmp_root)
        self.assertFalse(result.passed)
        self.assertEqual({e.code for e in result.errors}, {ERR_DEP_CORRUPT_FILE})

    # Item C: Unknown row key rejection
    def test_unknown_row_key_rejected(self) -> None:
        """Unexpected key in dependency row is rejected with exact ERR-DEP-CORRUPT-FILE-001."""
        json_path = self.tmp_root / "architecture/dependencies.json"
        data = json.loads(json_path.read_text(encoding="utf-8"))
        data["dependencies"][0]["extraAdmission"] = "bypass"
        json_path.write_text(json.dumps(data, indent=2), encoding="utf-8")

        result = validate_dependency_registry(self.tmp_root)
        self.assertFalse(result.passed)
        self.assertEqual({e.code for e in result.errors}, {ERR_DEP_CORRUPT_FILE})

    # Item C: Duplicate JSON keys rejection
    def test_duplicate_json_keys_rejected(self) -> None:
        """Duplicate JSON keys in dependencies.json fail closed with ERR-DEP-CORRUPT-FILE-001."""
        json_path = self.tmp_root / "architecture/dependencies.json"
        raw_text = json_path.read_text(encoding="utf-8")
        tampered_text = '{\n  "schema": "fss.dependencies.v1",\n' + raw_text[1:]
        json_path.write_text(tampered_text, encoding="utf-8")

        result = validate_dependency_registry(self.tmp_root)
        self.assertFalse(result.passed)
        self.assertEqual({e.code for e in result.errors}, {ERR_DEP_CORRUPT_FILE})

    # Item C: Whitespace padding rejection
    def test_whitespace_padding_rejected(self) -> None:
        """Whitespace padding like 'Production ' is rejected without stripping."""
        json_path = self.tmp_root / "architecture/dependencies.json"
        data = json.loads(json_path.read_text(encoding="utf-8"))
        data["dependencies"][0]["scope"] = "Production "
        data["freezeDigest"] = compute_canonical_dependencies_digest(data)
        json_path.write_text(json.dumps(data, indent=2), encoding="utf-8")

        result = validate_dependency_registry(self.tmp_root)
        self.assertFalse(result.passed)
        self.assertEqual({e.code for e in result.errors}, {ERR_DEP_FREEZE_DIVERGENCE, ERR_DEP_REGISTRY_DRIFT})

    # Item D: Non-backticked markdown rows and duplicate markdown rows
    def test_non_backticked_markdown_row_parsed(self) -> None:
        """Non-backticked markdown rows like | DEP-ROGUE-001 | are not silently ignored."""
        md_path = self.tmp_root / "registries/DEPENDENCIES.md"
        extra_row = "| DEP-ROGUE-001 | DEP-CLASS-F4 | Rogue package | test | Development only |\n"
        md_path.write_text(md_path.read_text(encoding="utf-8") + extra_row, encoding="utf-8")

        result = validate_dependency_registry(self.tmp_root)
        self.assertFalse(result.passed)
        self.assertEqual({e.code for e in result.errors}, {ERR_DEP_REGISTRY_DRIFT})

    def test_duplicate_markdown_row_rejected(self) -> None:
        """Duplicate rows in markdown table fail closed with ERR-DEP-STABLE-ID-REUSED-001."""
        md_path = self.tmp_root / "registries/DEPENDENCIES.md"
        content = md_path.read_text(encoding="utf-8")
        dup_row = "| `DEP-OWNED-001` | `DEP-CLASS-F2` | Owned runtime and Franken-suite families | admitted after per-mechanism integration gate | `Production` |\n"
        md_path.write_text(content + dup_row, encoding="utf-8")

        result = validate_dependency_registry(self.tmp_root)
        self.assertFalse(result.passed)
        self.assertEqual({e.code for e in result.errors}, {ERR_DEP_STABLE_ID_REUSED})

    # Item A: Scope vs constitution cross-check
    def test_scope_constitution_cross_check_failure(self) -> None:
        """Changing DEP-LAB-001 scope to Production fails cross-check with ERR-DEP-CONST-INVARIANT-001."""
        json_path = self.tmp_root / "architecture/dependencies.json"
        data = json.loads(json_path.read_text(encoding="utf-8"))
        for dep in data["dependencies"]:
            if dep["id"] == "DEP-LAB-001":
                dep["scope"] = "Production"
        data["freezeDigest"] = compute_canonical_dependencies_digest(data)
        json_path.write_text(json.dumps(data, indent=2), encoding="utf-8")

        result = validate_dependency_registry(self.tmp_root)
        self.assertFalse(result.passed)
        self.assertEqual({e.code for e in result.errors}, {ERR_DEP_CONST_INVARIANT, ERR_DEP_FREEZE_DIVERGENCE, ERR_DEP_REGISTRY_DRIFT})

    # Item B: Malformed input robustness (never raise exception)
    def test_malformed_generation_list_handled_safely(self) -> None:
        """generation as a list does not raise TypeError, fails closed with ERR-DEP-MISSING-FIELD-001."""
        json_path = self.tmp_root / "architecture/dependencies.json"
        data = json.loads(json_path.read_text(encoding="utf-8"))
        data["generation"] = ["invalid-list"]
        json_path.write_text(json.dumps(data, indent=2), encoding="utf-8")

        result = validate_dependency_registry(self.tmp_root)
        self.assertFalse(result.passed)
        self.assertEqual({e.code for e in result.errors}, {ERR_DEP_MISSING_FIELD})

    def test_malformed_dependencies_types_handled_safely(self) -> None:
        """dependencies as dict, string, list of ints, or list with null do not crash."""
        json_path = self.tmp_root / "architecture/dependencies.json"
        for bad_deps in ({"a": 1}, "abc", [1], [None]):
            with self.subTest(bad_deps=bad_deps):
                data = json.loads(json_path.read_text(encoding="utf-8"))
                data["dependencies"] = bad_deps
                json_path.write_text(json.dumps(data, indent=2), encoding="utf-8")

                result = validate_dependency_registry(self.tmp_root)
                self.assertFalse(result.passed)
                self.assertEqual({e.code for e in result.errors}, {ERR_DEP_CORRUPT_FILE})

    def test_invalid_utf8_json_handled_safely(self) -> None:
        """Invalid UTF-8 bytes in dependencies.json fail closed with exact ERR-DEP-CORRUPT-FILE-001."""
        json_path = self.tmp_root / "architecture/dependencies.json"
        json_path.write_bytes(b"\xff\xfe{\"schema\": 1}")

        result = validate_dependency_registry(self.tmp_root)
        self.assertFalse(result.passed)
        self.assertEqual({e.code for e in result.errors}, {ERR_DEP_CORRUPT_FILE})

    # Restored test 1: markdown mirror drift
    def test_markdown_mirror_drift_rejected(self) -> None:
        """Markdown mirror disagreement in class, rule, scope, or row count is rejected."""
        md_path = self.tmp_root / "registries/DEPENDENCIES.md"
        original_md = md_path.read_text(encoding="utf-8")

        # 1. Mutate class
        tampered_md = original_md.replace("Owned runtime and Franken-suite families", "Drifted Class Name")
        md_path.write_text(tampered_md, encoding="utf-8")
        result = validate_dependency_registry(self.tmp_root)
        self.assertFalse(result.passed)
        self.assertEqual({e.code for e in result.errors}, {ERR_DEP_REGISTRY_DRIFT})

        # 2. Mutate scope
        tampered_md = original_md.replace("`Production`", "`Experimental`")
        md_path.write_text(tampered_md, encoding="utf-8")
        result = validate_dependency_registry(self.tmp_root)
        self.assertFalse(result.passed)
        self.assertEqual({e.code for e in result.errors}, {ERR_DEP_REGISTRY_DRIFT})

        # 3. Drop a row in markdown
        lines = original_md.splitlines()
        filtered_lines = [l for l in lines if "DEP-EXCEPTION-001" not in l]
        md_path.write_text("\n".join(filtered_lines) + "\n", encoding="utf-8")
        result = validate_dependency_registry(self.tmp_root)
        self.assertFalse(result.passed)
        self.assertEqual({e.code for e in result.errors}, {ERR_DEP_REGISTRY_DRIFT})

    # Restored test 2: corrupt or empty files
    def test_corrupt_or_empty_files_rejected(self) -> None:
        """Corrupt or 0-byte JSON and Markdown files fail closed with ERR-DEP-CORRUPT-FILE-001."""
        json_path = self.tmp_root / "architecture/dependencies.json"
        md_path = self.tmp_root / "registries/DEPENDENCIES.md"

        # 0-byte JSON
        json_path.write_text("", encoding="utf-8")
        result = validate_dependency_registry(self.tmp_root)
        self.assertFalse(result.passed)
        self.assertEqual({e.code for e in result.errors}, {ERR_DEP_CORRUPT_FILE})

        # Invalid JSON syntax
        json_path.write_text("{ unquoted_key: ]", encoding="utf-8")
        result = validate_dependency_registry(self.tmp_root)
        self.assertFalse(result.passed)
        self.assertEqual({e.code for e in result.errors}, {ERR_DEP_CORRUPT_FILE})

        # Restore JSON, empty markdown
        shutil.copy2(ROOT / "architecture/dependencies.json", json_path)
        md_path.write_text("# Empty dependencies\n", encoding="utf-8")
        result = validate_dependency_registry(self.tmp_root)
        self.assertFalse(result.passed)
        self.assertEqual({e.code for e in result.errors}, {ERR_DEP_CORRUPT_FILE})

    # Restored test 3: prefix-only digest bypass prevented (M-prefix)
    def test_prefix_only_digest_bypass_prevented(self) -> None:
        """Verify that digest checking fails if only prefix matches."""
        json_path = self.tmp_root / "architecture/dependencies.json"
        data = json.loads(json_path.read_text(encoding="utf-8"))
        prefix = BASELINE_DEPENDENCIES_FREEZE_DIGEST[:-8]
        data["freezeDigest"] = prefix + "deadbeef"
        json_path.write_text(json.dumps(data, indent=2), encoding="utf-8")

        result = validate_dependency_registry(self.tmp_root)
        self.assertFalse(result.passed)
        self.assertEqual({e.code for e in result.errors}, {ERR_DEP_DIGEST_MISMATCH})

    # Mutant M4b: constitutionClass mismatch
    def test_mutant_m4b_constitution_class_mismatch(self) -> None:
        """Mutating constitutionClass in JSON row fails with exact ERR-DEP-CONST-INVARIANT-001."""
        json_path = self.tmp_root / "architecture/dependencies.json"
        data = json.loads(json_path.read_text(encoding="utf-8"))
        data["dependencies"][0]["constitutionClass"] = "DEP-CLASS-F99"
        data["freezeDigest"] = compute_canonical_dependencies_digest(data)
        json_path.write_text(json.dumps(data, indent=2), encoding="utf-8")

        result = validate_dependency_registry(self.tmp_root)
        self.assertFalse(result.passed)
        self.assertEqual({e.code for e in result.errors}, {ERR_DEP_CONST_INVARIANT, ERR_DEP_FREEZE_DIVERGENCE, ERR_DEP_REGISTRY_DRIFT})

    # Mutant M4c: rule mismatch
    def test_mutant_m4c_rule_mismatch(self) -> None:
        """Mutating rule in JSON emits ERR-DEP-REGISTRY-DRIFT-001."""
        json_path = self.tmp_root / "architecture/dependencies.json"
        data = json.loads(json_path.read_text(encoding="utf-8"))
        data["dependencies"][0]["rule"] = "tampered rule divergence"
        data["freezeDigest"] = compute_canonical_dependencies_digest(data)
        json_path.write_text(json.dumps(data, indent=2), encoding="utf-8")

        result = validate_dependency_registry(self.tmp_root)
        self.assertFalse(result.passed)
        self.assertEqual({e.code for e in result.errors}, {ERR_DEP_FREEZE_DIVERGENCE, ERR_DEP_REGISTRY_DRIFT})

    # Mutant M4d: scope mismatch
    def test_mutant_m4d_scope_mismatch(self) -> None:
        """Mutating scope in JSON emits ERR-DEP-REGISTRY-DRIFT-001."""
        json_path = self.tmp_root / "architecture/dependencies.json"
        data = json.loads(json_path.read_text(encoding="utf-8"))
        data["dependencies"][0]["scope"] = "Development only"
        data["freezeDigest"] = compute_canonical_dependencies_digest(data)
        json_path.write_text(json.dumps(data, indent=2), encoding="utf-8")

        result = validate_dependency_registry(self.tmp_root)
        self.assertFalse(result.passed)
        self.assertEqual({e.code for e in result.errors}, {ERR_DEP_FREEZE_DIVERGENCE, ERR_DEP_REGISTRY_DRIFT})

    # Mutant M-F4adm: F4 admission mutated in constitution
    def test_mutant_m_f4adm_admission_mutated(self) -> None:
        """DEP-CLASS-F4 admission mutated in constitution fails with exact ERR-DEP-CONST-INVARIANT-001."""
        const_path = self.tmp_root / "architecture/dependency_constitution.json"
        data = json.loads(const_path.read_text(encoding="utf-8"))
        for c in data.get("classes", []):
            if c.get("id") == "DEP-CLASS-F4":
                c["admission"] = "production-allowed"
        const_path.write_text(json.dumps(data, indent=2), encoding="utf-8")

        result = validate_dependency_registry(self.tmp_root)
        self.assertFalse(result.passed)
        self.assertEqual({e.code for e in result.errors}, {ERR_DEP_CONST_INVARIANT})

    # Mutant M-closed: allowlist closed_universe != True
    def test_mutant_m_closed_allowlist_closed_universe(self) -> None:
        """dependency_allowlist.toml closed_universe=false fails with exact ERR-DEP-CONST-INVARIANT-001."""
        allow_path = self.tmp_root / "architecture/dependency_allowlist.toml"
        text = allow_path.read_text(encoding="utf-8").replace("closed_universe = true", "closed_universe = false")
        allow_path.write_text(text, encoding="utf-8")

        result = validate_dependency_registry(self.tmp_root)
        self.assertFalse(result.passed)
        self.assertEqual({e.code for e in result.errors}, {ERR_DEP_CONST_INVARIANT})

    # Mutant M10b: missing mandatory row field without digest update
    def test_mutant_m10b_missing_mandatory_row_field(self) -> None:
        """Row missing mandatory field without digest recompute fails with exact ERR-DEP-MISSING-FIELD-001."""
        json_path = self.tmp_root / "architecture/dependencies.json"
        data = json.loads(json_path.read_text(encoding="utf-8"))
        del data["dependencies"][0]["rule"]
        json_path.write_text(json.dumps(data, indent=2), encoding="utf-8")

        result = validate_dependency_registry(self.tmp_root)
        self.assertFalse(result.passed)
        self.assertEqual({e.code for e in result.errors}, {ERR_DEP_MISSING_FIELD})

    # Mutant M12c: case-colliding ID
    def test_mutant_m12c_case_colliding_id(self) -> None:
        """Case-colliding dependency ID fails with ERR-DEP-STABLE-ID-REUSED-001."""
        json_path = self.tmp_root / "architecture/dependencies.json"
        data = json.loads(json_path.read_text(encoding="utf-8"))
        dupe = copy.deepcopy(data["dependencies"][0])
        dupe["id"] = dupe["id"].lower()
        data["dependencies"].append(dupe)
        data["freezeDigest"] = compute_canonical_dependencies_digest(data)
        json_path.write_text(json.dumps(data, indent=2), encoding="utf-8")

        result = validate_dependency_registry(self.tmp_root)
        self.assertFalse(result.passed)
        self.assertEqual({e.code for e in result.errors}, {ERR_DEP_STABLE_ID_REUSED, ERR_DEP_FREEZE_DIVERGENCE, ERR_DEP_REGISTRY_DRIFT})

    # Mutant M13b: duplicate ID in JSON
    def test_mutant_m13b_duplicate_id_in_json(self) -> None:
        """Duplicate ID in JSON dependencies array fails with ERR-DEP-STABLE-ID-REUSED-001."""
        json_path = self.tmp_root / "architecture/dependencies.json"
        data = json.loads(json_path.read_text(encoding="utf-8"))
        data["dependencies"].append(copy.deepcopy(data["dependencies"][0]))
        data["freezeDigest"] = compute_canonical_dependencies_digest(data)
        json_path.write_text(json.dumps(data, indent=2), encoding="utf-8")

        result = validate_dependency_registry(self.tmp_root)
        self.assertFalse(result.passed)
        self.assertEqual({e.code for e in result.errors}, {ERR_DEP_STABLE_ID_REUSED, ERR_DEP_FREEZE_DIVERGENCE})

    # Mutant M13c: duplicate ID in markdown
    def test_mutant_m13c_duplicate_id_in_markdown(self) -> None:
        """Duplicate ID in markdown mirror fails with exact ERR-DEP-STABLE-ID-REUSED-001."""
        md_path = self.tmp_root / "registries/DEPENDENCIES.md"
        content = md_path.read_text(encoding="utf-8")
        dup_row = "| `DEP-OWNED-001` | `DEP-CLASS-F2` | Owned runtime and Franken-suite families | admitted after per-mechanism integration gate | `Production` |\n"
        md_path.write_text(content + dup_row, encoding="utf-8")

        result = validate_dependency_registry(self.tmp_root)
        self.assertFalse(result.passed)
        self.assertEqual({e.code for e in result.errors}, {ERR_DEP_STABLE_ID_REUSED})

    # Scenarios S3, S4, S5 crosswalk and allowlist moves
    def test_scenarios_s3_s4_s5_crosswalk(self) -> None:
        """Crosswalk scenarios S3, S4, S5 and allowlist invariants fail closed."""
        const_path = self.tmp_root / "architecture/dependency_constitution.json"
        allow_path = self.tmp_root / "architecture/dependency_allowlist.toml"

        # S3: mutate DEP-CLASS-F2 admission
        data = json.loads(const_path.read_text(encoding="utf-8"))
        for c in data.get("classes", []):
            if c.get("id") == "DEP-CLASS-F2":
                c["admission"] = "unadmitted"
        const_path.write_text(json.dumps(data, indent=2), encoding="utf-8")
        result = validate_dependency_registry(self.tmp_root)
        self.assertFalse(result.passed)
        self.assertEqual({e.code for e in result.errors}, {ERR_DEP_CONST_INVARIANT})
        shutil.copy2(ROOT / "architecture/dependency_constitution.json", const_path)

        # S4: mutate DEP-CLASS-F3 admission
        data = json.loads(const_path.read_text(encoding="utf-8"))
        for c in data.get("classes", []):
            if c.get("id") == "DEP-CLASS-F3":
                c["admission"] = "unadmitted"
        const_path.write_text(json.dumps(data, indent=2), encoding="utf-8")
        result = validate_dependency_registry(self.tmp_root)
        self.assertFalse(result.passed)
        self.assertEqual({e.code for e in result.errors}, {ERR_DEP_CONST_INVARIANT})
        shutil.copy2(ROOT / "architecture/dependency_constitution.json", const_path)

        # S5: mutate DEP-CLASS-F4 name
        data = json.loads(const_path.read_text(encoding="utf-8"))
        for c in data.get("classes", []):
            if c.get("id") == "DEP-CLASS-F4":
                c["name"] = "wrong-name"
        const_path.write_text(json.dumps(data, indent=2), encoding="utf-8")
        result = validate_dependency_registry(self.tmp_root)
        self.assertFalse(result.passed)
        self.assertEqual({e.code for e in result.errors}, {ERR_DEP_CONST_INVARIANT})
        shutil.copy2(ROOT / "architecture/dependency_constitution.json", const_path)

        # Allowlist: serde in forbidden.crates
        orig_allow = allow_path.read_text(encoding="utf-8")
        allow_with_serde = orig_allow.replace('crates = [', 'crates = ["serde", ')
        allow_path.write_text(allow_with_serde, encoding="utf-8")
        result = validate_dependency_registry(self.tmp_root)
        self.assertFalse(result.passed)
        self.assertEqual({e.code for e in result.errors}, {ERR_DEP_CONST_INVARIANT})
        allow_path.write_text(orig_allow, encoding="utf-8")

        # Allowlist: missing [laboratory_oracles]
        allow_no_lab = orig_allow.replace("[laboratory_oracles]", "[disabled_laboratory_oracles]")
        allow_path.write_text(allow_no_lab, encoding="utf-8")
        result = validate_dependency_registry(self.tmp_root)
        self.assertFalse(result.passed)
        self.assertEqual({e.code for e in result.errors}, {ERR_DEP_CONST_INVARIANT})
        allow_path.write_text(orig_allow, encoding="utf-8")

        # Duplicate keys in constitution
        tampered = '{\n  "schema": "fss.dependency_constitution.v1",\n' + const_path.read_text(encoding="utf-8")[1:]
        const_path.write_text(tampered, encoding="utf-8")
        result = validate_dependency_registry(self.tmp_root)
        self.assertFalse(result.passed)
        self.assertEqual({e.code for e in result.errors}, {ERR_DEP_CORRUPT_FILE})
        shutil.copy2(ROOT / "architecture/dependency_constitution.json", const_path)

        # Missing constitution file
        const_path.unlink()
        result = validate_dependency_registry(self.tmp_root)
        self.assertFalse(result.passed)
        self.assertEqual({e.code for e in result.errors}, {ERR_DEP_CORRUPT_FILE})
        shutil.copy2(ROOT / "architecture/dependency_constitution.json", const_path)

        # Missing allowlist file
        allow_path.unlink()
        result = validate_dependency_registry(self.tmp_root)
        self.assertFalse(result.passed)
        self.assertEqual({e.code for e in result.errors}, {ERR_DEP_CORRUPT_FILE})
        shutil.copy2(ROOT / "architecture/dependency_allowlist.toml", allow_path)

    # File size bound test
    def test_file_size_bound(self) -> None:
        """Files exceeding MAX_REGISTRY_FILE_SIZE_BYTES fail with exact ERR-DEP-CORRUPT-FILE-001."""
        orig_stat = Path.stat
        def fake_stat(self: Path, *args: Any, **kwargs: Any) -> Any:
            st = orig_stat(self, *args, **kwargs)
            if str(self).endswith("dependencies.json"):
                class FakeStat:
                    st_size = 11 * 1024 * 1024
                return FakeStat()
            return st

        Path.stat = fake_stat  # type: ignore[method-assign]
        try:
            result = validate_dependency_registry(self.tmp_root)
            self.assertFalse(result.passed)
            self.assertEqual({e.code for e in result.errors}, {ERR_DEP_CORRUPT_FILE})
        finally:
            Path.stat = orig_stat

    # Markdown rogue rows detection
    def test_markdown_rogue_rows_detected(self) -> None:
        """Rogue markdown rows (bad casing, bold, missing pipes, bad columns) emit ERR-DEP-REGISTRY-DRIFT-001."""
        md_path = self.tmp_root / "registries/DEPENDENCIES.md"
        base_md = md_path.read_text(encoding="utf-8")

        cases = [
            base_md + "| `dep-rogue-001` | `DEP-CLASS-F2` | Rogue | none | `Production` |\n",
            base_md + "| **`DEP-ROGUE-001`** | `DEP-CLASS-F2` | Rogue | none | `Production` |\n",
            base_md + "DEP-ROGUE-001 | `DEP-CLASS-F2` | Rogue | none | `Production`\n",
            base_md + "| `DEP-CLASS-F2` | `DEP-ROGUE-001` | Rogue | none | `Production` |\n",
            base_md + "| DEP-ROGUE-001 | `DEP-CLASS-F2` | Rogue | none | `Production` |\n",
            base_md + "| `DEP-ROGUE-001` | `DEP-CLASS-F2` | `Rogue` | none | `Production` |\n",
            base_md + "| `DEP-ROGUE-001` | `DEP-CLASS-F2` | Rogue | `Production` |\n",
        ]
        for idx, rogue_content in enumerate(cases):
            with self.subTest(case_idx=idx):
                md_path.write_text(rogue_content, encoding="utf-8")
                result = validate_dependency_registry(self.tmp_root)
                self.assertFalse(result.passed)
                self.assertIn(ERR_DEP_REGISTRY_DRIFT, [e.code for e in result.errors])

    # Scope metadata resolution
    def test_scope_metadata_resolution(self) -> None:
        """resolve_dependency_row_metadata returns owner, producers, consumers, contractBasis, and tombstone status."""
        meta = resolve_dependency_row_metadata("DEP-OWNED-001", repo_root=ROOT)
        self.assertEqual(meta["id"], "DEP-OWNED-001")
        self.assertEqual(meta["owner"], "fss-runtime")
        self.assertFalse(meta["isTombstoned"])
        self.assertFalse(meta["tombstone"])
        self.assertEqual(meta["contractBasis"], "fss.agent_contract_basis.v1")
        self.assertIn("fss-core", meta["producers"])
        self.assertIn("fss-cli", meta["consumers"])

        meta_fund = resolve_dependency_row_metadata("DEP-FUND-001", repo_root=ROOT)
        self.assertEqual(meta_fund["id"], "DEP-FUND-001")
        self.assertEqual(meta_fund["owner"], "fss-data-shape")
        self.assertFalse(meta_fund["isTombstoned"])


class TestDependencyClassification(unittest.TestCase):
    """Verifies that dependency_audit classifies packages into DEP classes and reports consumers."""

    # Restored test 4: owned classification
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
        admitted = {"asupersync", "frankensqlite"}

        for crate_name in ("fss-core", "fss-cli", "fss-ledger", "asupersync", "frankensqlite", "fsqlite-wal"):
            dep_id, code, reason = dependency_audit.classify_dependency_package(crate_name, policy, members, is_production=True, admitted_in_house=admitted)
            self.assertEqual(dep_id, "DEP-OWNED-001", f"Expected {crate_name} to be DEP-OWNED-001")
            self.assertIsNone(code)
            self.assertIsNone(reason)

    # Restored test 5: unclassified crate rejected (M-042)
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

    # Restored test 6: census counts owned consumers (M-census)
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

    # Restored test 7: unconsumed rows drift reported
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

    # Restored test 8: warn unconsumed emits warning (M-044)
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

    # Killing mutant M12: serde is neutral pending fss-ndxis
    def test_mutant_m12_serde_pending_fss_ndxis(self) -> None:
        """serde/serde_json are quarantined with DEP-AUD-045 (pending owner decision fss-ndxis), never admitted."""
        import dependency_audit
        policy = {
            "in_house": {"allowed_families": ["fss-*"]},
            "fundamental": {"allowed_subject_to_audit": ["serde", "serde_json"]},
            "forbidden": {"crates": []},
        }
        members = {"fss-core"}

        for serde_pkg in ("serde", "serde_json"):
            dep_id, code, reason = dependency_audit.classify_dependency_package(serde_pkg, policy, members, is_production=True)
            self.assertEqual(dep_id, "DEP-FUND-001")
            self.assertEqual(code, "DEP-AUD-045")
            self.assertIn("pending owner decision fss-ndxis", reason)

    # Killing mutant M13: lab/oracle quarantine
    def test_mutant_m13_lab_oracle_quarantine(self) -> None:
        """Lab and oracle packages in production scope emit DEP-AUD-043; in dev-only scope they pass."""
        import dependency_audit
        policy = {
            "in_house": {"allowed_families": ["fss-*"]},
            "fundamental": {"allowed_subject_to_audit": []},
            "laboratory_oracles": {"excluded_from_production_release_closure": ["opencv", "ffmpeg"]},
            "forbidden": {"crates": []},
        }
        members = {"fss-core"}

        # Production scope: must fail with DEP-AUD-043
        dep_id, code, reason = dependency_audit.classify_dependency_package("opencv", policy, members, is_production=True)
        self.assertEqual(dep_id, "DEP-LAB-001")
        self.assertEqual(code, "DEP-AUD-043")
        self.assertIn("reachable from production", reason)

        # Dev-only scope: permitted in development
        dep_id, code, reason = dependency_audit.classify_dependency_package("opencv", policy, members, is_production=False)
        self.assertEqual(dep_id, "DEP-LAB-001")
        self.assertIsNone(code)
        self.assertIsNone(reason)

    # Killing mutant M10: DEP-AUD-043 production reachability
    def test_mutant_m10_production_reachability(self) -> None:
        """DEP-AUD-043 is only emitted when an unadmitted crate is reachable from production."""
        import dependency_audit
        policy = {
            "in_house": {"allowed_families": ["fss-*"]},
            "fundamental": {"allowed_subject_to_audit": []},
            "laboratory_oracles": {"excluded_from_production_release_closure": ["ffmpeg"]},
            "forbidden": {"crates": []},
        }
        members = {"fss-core"}
        findings: list[dependency_audit.Finding] = []
        resolved = [{"name": "ffmpeg", "version": "4.4.0"}]
        # dev-only direct dependency
        direct = [{"manifest": "crates/fss-core/Cargo.toml", "section": "dev-dependencies", "name": "ffmpeg"}]
        with tempfile.TemporaryDirectory() as tmp_d:
            tmp_root = Path(tmp_d)
            (tmp_root / "Cargo.lock").write_text(
                '[[package]]\nname = "ffmpeg"\nversion = "4.4.0"\n',
                encoding="utf-8",
            )
            (tmp_root / "architecture").mkdir()
            shutil.copy2(ROOT / "architecture/franken_imports.json", tmp_root / "architecture/franken_imports.json")
            res = dependency_audit.audit_dependency_classes(findings, tmp_root, policy, members, resolved, direct=direct)
        # Should NOT emit DEP-AUD-043 because ffmpeg is dev-only!
        self.assertEqual([f.code for f in findings], [])

    # Killing mutant M11: class audit wired into audit_workspace
    def test_mutant_m11_class_audit_wired_into_audit_workspace(self) -> None:
        """audit_workspace must include census and unconsumed dependency class reports."""
        import dependency_audit
        report, rc = dependency_audit.audit_workspace(ROOT, policy_path=ROOT / "architecture/dependency_allowlist.toml")
        self.assertIn("schema", report)
        self.assertEqual(report["schema"], "fss.dependency_audit.v4")
        self.assertIn("dependencyClassCensus", report)
        self.assertIn("unconsumedDependencyClasses", report)
        self.assertIn("DEP-OWNED-001", report["dependencyClassCensus"])
        self.assertIn("DEP-FUND-001", report["dependencyClassCensus"])

    def test_forbidden_crates_never_exception_candidates(self) -> None:
        """tokio is forbidden and cannot be classified as DEP-EXCEPTION-001."""
        import dependency_audit
        policy = {
            "in_house": {"allowed_families": ["fss-*"]},
            "fundamental": {"allowed_subject_to_audit": []},
            "forbidden": {"crates": ["tokio"]},
            "exception_candidates": {"not_admitted_without_dep_record_adr_and_release_evidence": ["tokio"]},
        }
        dep_id, code, reason = dependency_audit.classify_dependency_package("tokio", policy, {"fss-core"}, is_production=True)
        self.assertNotEqual(dep_id, "DEP-EXCEPTION-001")
        self.assertEqual(code, "DEP-AUD-030")

    # Killing mutant M-gate: in-house import gate enforcement
    def test_mutant_m_gate_in_house_import_gate(self) -> None:
        """In-house gate fails closed when unmapped, unadmitted, or admitted_in_house=None."""
        import dependency_audit
        policy = {
            "in_house": {"allowed_families": ["ft-*", "fsqlite-*", "asupersync*"]},
            "fundamental": {"allowed_subject_to_audit": []},
            "forbidden": {"crates": []},
        }
        members = {"fss-core"}

        # admitted_in_house is None -> fail closed
        dep_id, code, reason = dependency_audit.classify_dependency_package("ft-kernel", policy, members, is_production=True, admitted_in_house=None)
        self.assertEqual(code, "DEP-AUD-043")

        # frankentorch not in admitted_in_house -> fail closed
        dep_id, code, reason = dependency_audit.classify_dependency_package("ft-kernel", policy, members, is_production=True, admitted_in_house={"frankensqlite"})
        self.assertEqual(code, "DEP-AUD-043")

        # frankentorch admitted -> succeeds
        dep_id, code, reason = dependency_audit.classify_dependency_package("ft-kernel", policy, members, is_production=True, admitted_in_house={"frankentorch"})
        self.assertEqual(dep_id, "DEP-OWNED-001")
        self.assertIsNone(code)

    # Killing mutant M-census: member inflation prevention
    def test_mutant_m_census_consumer_count_without_member_inflation(self) -> None:
        """Sibling workspace member dependencies do NOT inflate consumer count of DEP-OWNED-001."""
        import dependency_audit
        policy = {
            "in_house": {"allowed_families": ["fss-*"]},
            "fundamental": {"allowed_subject_to_audit": []},
            "forbidden": {"crates": []},
        }
        members = {"fss-cli", "fss-core"}
        findings: list[dependency_audit.Finding] = []
        resolved = [{"name": "fss-cli", "version": "0.0.1"}, {"name": "fss-core", "version": "0.0.1"}]
        # Sibling edge: fss-cli depends on fss-core
        direct = [{"manifest": "crates/fss-cli/Cargo.toml", "section": "dependencies", "name": "fss-core"}]
        res = dependency_audit.audit_dependency_classes(findings, ROOT, policy, members, resolved, direct=direct)
        census = res["census"]
        # Consumer count must be 0 because sibling member dependencies do not count as external consumers
        self.assertEqual(census["DEP-OWNED-001"]["consumerCount"], 0)

    # Killing mutant M-lock: Cargo.lock and franken_imports.json validation
    def test_mutant_m_lock_validation(self) -> None:
        """Cargo.lock and franken_imports.json validation fails closed with DEP-AUD-010."""
        import dependency_audit
        policy = {"in_house": {"allowed_families": ["fss-*"]}}
        members = {"fss-core"}

        with tempfile.TemporaryDirectory() as tmp_d:
            tmp_root = Path(tmp_d)
            # 1. Missing Cargo.lock
            findings: list[dependency_audit.Finding] = []
            res = dependency_audit.audit_dependency_classes(findings, tmp_root, policy, members, [])
            self.assertEqual([f.code for f in findings], ["DEP-AUD-010"])

            # 2. 0-byte Cargo.lock
            (tmp_root / "Cargo.lock").write_text("", encoding="utf-8")
            findings = []
            res = dependency_audit.audit_dependency_classes(findings, tmp_root, policy, members, [])
            self.assertEqual([f.code for f in findings], ["DEP-AUD-010"])

            # 3. Malformed Cargo.lock (package not a list)
            (tmp_root / "Cargo.lock").write_text('package = "invalid"\n', encoding="utf-8")
            findings = []
            res = dependency_audit.audit_dependency_classes(findings, tmp_root, policy, members, [])
            self.assertEqual([f.code for f in findings], ["DEP-AUD-010"])

            # 4. Malformed Cargo.lock (package = [1, 2] elements not tables)
            (tmp_root / "Cargo.lock").write_text('package = [1, 2]\n', encoding="utf-8")
            findings = []
            res = dependency_audit.audit_dependency_classes(findings, tmp_root, policy, members, [])
            self.assertEqual([f.code for f in findings], ["DEP-AUD-010"])

            # 5. Corrupt franken_imports.json
            (tmp_root / "Cargo.lock").write_text('version = 3\n', encoding="utf-8")
            (tmp_root / "architecture").mkdir(exist_ok=True)
            (tmp_root / "architecture/franken_imports.json").write_text('{"invalid": json}', encoding="utf-8")
            findings = []
            res = dependency_audit.audit_dependency_classes(findings, tmp_root, policy, members, [])
            self.assertEqual([f.code for f in findings], ["DEP-AUD-010"])


if __name__ == "__main__":
    unittest.main()
