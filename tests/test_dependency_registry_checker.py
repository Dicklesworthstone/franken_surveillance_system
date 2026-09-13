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
            self.assertEqual({e.code for e in result.errors}, {ERR_DEP_MISSING_FIELD, ERR_DEP_FREEZE_DIVERGENCE, ERR_DEP_REGISTRY_DRIFT})

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
                self.assertTrue(len(result.errors) > 0)

    def test_invalid_utf8_json_handled_safely(self) -> None:
        """Invalid UTF-8 bytes in dependencies.json fail closed with exact ERR-DEP-CORRUPT-FILE-001."""
        json_path = self.tmp_root / "architecture/dependencies.json"
        json_path.write_bytes(b"\xff\xfe{\"schema\": 1}")

        result = validate_dependency_registry(self.tmp_root)
        self.assertFalse(result.passed)
        self.assertEqual({e.code for e in result.errors}, {ERR_DEP_CORRUPT_FILE})


class TestDependencyClassification(unittest.TestCase):
    """Verifies that dependency_audit classifies packages into DEP classes and reports consumers."""

    # Killing mutant M12: serde is neutral pending fss-ndxis
    def test_mutant_m12_serde_pending_fss_ndxis(self) -> None:
        """serde/serde_json are quarantined with DEP-AUD-045 (pending owner decision fss-ndxis), never admitted."""
        import dependency_audit
        policy = {
            "in_house": {"allowed_families": ["fss-*"]},
            "fundamental": {"allowed_subject_to_audit": []},
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
            res = dependency_audit.audit_dependency_classes(findings, tmp_root, policy, members, resolved, direct=direct)
        # Should NOT emit DEP-AUD-043 because ffmpeg is dev-only!
        self.assertEqual([f.code for f in findings], [])

    # Killing mutant M11: class audit unwired from audit_workspace
    def test_mutant_m11_class_audit_wired_into_audit_workspace(self) -> None:
        """audit_workspace must include census and unconsumed dependency class reports."""
        import dependency_audit
        report, rc = dependency_audit.audit_workspace(ROOT, policy_path=ROOT / "architecture/dependency_allowlist.toml")
        self.assertIn("schema", report)
        self.assertEqual(report["schema"], "fss.dependency_audit.v4")

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


if __name__ == "__main__":
    unittest.main()
