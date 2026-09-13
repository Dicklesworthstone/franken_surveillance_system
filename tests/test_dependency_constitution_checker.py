#!/usr/bin/env python3
"""Deterministic verification suite for dependency constitution and DEP-CLASS-F0 (fss-x4a.30.88.16).

Tests fail-closed enforcement of architecture/dependency_constitution.json against
docs/DEPENDENCY_CONSTITUTION.md, architecture/dependencies.json, architecture/dependency_allowlist.toml,
rust-toolchain.toml, and real Cargo metadata under the six-point SWARM RULE:
- Pinned freeze digest constant covering all fields, metadata, and generation.
- Exact digest assertion against BASELINE_DEPENDENCY_CONSTITUTION_FREEZE_DIGEST.
- Mandatory generation bump enforcement (ERR-DEP-GENERATION-MISMATCH-001, ERR-DEP-FREEZE-DIVERGENCE-001).
- Baseline-checked dependency classes (DEP-CLASS-F0 through DEP-CLASS-F4).
- Exact finding-code sets assertions killing all mutants (M5, M6, M12, X1-X4, X5b, X7, X11, X15).
- Allowlist 16-policy crosswalk and table consistency.
- Substantive markdown mirror verification (semantics, duplicates, 0-byte).
- Toolchain identity fail-closed verification.
- Safe handling of malformed cargo metadata (null packages, list root, string metadata).
"""
from __future__ import annotations

import copy
import hashlib
import json
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import MagicMock, patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))

import dependency_constitution_checker
from dependency_constitution_checker import (
    BASELINE_DEPENDENCY_CONSTITUTION_FREEZE_DIGEST,
    BASELINE_DEPENDENCY_CONSTITUTION_GENERATION,
    CANONICAL_CONSTITUTION_CLASSES,
    CANONICAL_CONSTITUTION_MARKDOWN_TITLES,
    CARGO_METADATA_TIMEOUT_SECONDS,
    EXPECTED_FREEZE_DIGESTS,
    MANDATORY_CLASS_FIELDS,
    MANDATORY_PRODUCTION_FIELDS,
    MANDATORY_TOP_LEVEL_FIELDS,
    REQUIRED_ALLOWLIST_POLICY,
    REQUIRED_PRODUCTION_VALUES,
    REQUIRED_RUST_CHANNEL,
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
    extract_markdown_class_sections,
    load_real_cargo_metadata,
    load_tombstoned_ids,
    validate_cargo_metadata_for_f0,
    validate_dependency_constitution,
    validate_toolchain_identity,
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
        if (ROOT / "rust-toolchain.toml").is_file():
            shutil.copy2(
                ROOT / "rust-toolchain.toml",
                self.tmp_root / "rust-toolchain.toml",
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

    # Mutant M13: duplicate class ID
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

    # Mutant M12: case-colliding class ID
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
            {ERR_DEP_STABLE_ID_REUSED, ERR_DEP_FREEZE_DIVERGENCE, ERR_DEP_REGISTRY_DRIFT, ERR_DEP_CONST_INVARIANT},
        )
        self.assertTrue(any("Case-colliding" in e.message for e in result.errors))

    # Pattern violation (was STABLE-ID-REUSED, now CONST-INVARIANT per review item 8)
    def test_id_pattern_violation_rejected_as_invariant(self) -> None:
        """Class ID not conforming to DEP-CLASS-F[0-4] fails with exact ERR-DEP-CONST-INVARIANT-001."""
        json_path = self.tmp_root / "architecture/dependency_constitution.json"
        data = json.loads(json_path.read_text(encoding="utf-8"))
        data["classes"][0]["id"] = "DEP-CLASS-F99"
        data["freezeDigest"] = compute_canonical_constitution_digest(data)
        json_path.write_text(json.dumps(data, indent=2), encoding="utf-8")

        result = validate_dependency_constitution(self.tmp_root, skip_cargo_metadata=True)
        self.assertFalse(result.passed)
        self.assertEqual(
            {e.code for e in result.errors},
            {ERR_DEP_CONST_INVARIANT, ERR_DEP_FREEZE_DIVERGENCE},
        )

    # Mutant M11: class count mismatch
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

    # Mutant M6: name mismatch on classes (testing both F0 and non-F0 classes to kill surviving mutants)
    def test_mutant_m6_name_mismatch_rejected(self) -> None:
        """Class name mismatch on F0 and F1 is rejected with exact ERR-DEP-CONST-INVARIANT-001."""
        json_path = self.tmp_root / "architecture/dependency_constitution.json"
        data = json.loads(json_path.read_text(encoding="utf-8"))
        for c in data["classes"]:
            if c["id"] == "DEP-CLASS-F1":
                c["name"] = "wrong-asupersync-name"
        data["freezeDigest"] = compute_canonical_constitution_digest(data)
        json_path.write_text(json.dumps(data, indent=2), encoding="utf-8")

        result = validate_dependency_constitution(self.tmp_root, skip_cargo_metadata=True)
        self.assertFalse(result.passed)
        self.assertEqual(
            {e.code for e in result.errors},
            {ERR_DEP_CONST_INVARIANT, ERR_DEP_FREEZE_DIVERGENCE},
        )
        self.assertTrue(any("Class 'DEP-CLASS-F1' name mismatch" in e.message for e in result.errors))

    # Mutant M10: admission mismatch
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

    # Mutant M5 & X5b: metadata load failure, non-JSON output, timeout reported as ERR_DEP_CORRUPT_FILE
    def test_mutant_m5_metadata_load_failure(self) -> None:
        """Failure to load real Cargo metadata reports exact ERR-DEP-CORRUPT-FILE-001."""
        with patch("dependency_constitution_checker.load_real_cargo_metadata", return_value=(None, "cargo metadata failed")):
            result = validate_dependency_constitution(self.tmp_root, skip_cargo_metadata=False)
            self.assertFalse(result.passed)
            self.assertEqual({e.code for e in result.errors}, {ERR_DEP_CORRUPT_FILE})

    def test_cannot_run_cargo_reported_as_corrupt_file(self) -> None:
        """When cargo metadata execution fails, it reports exact ERR-DEP-CORRUPT-FILE-001."""
        def mock_run(cmd, *args, **kwargs):
            if "cargo" in cmd:
                raise FileNotFoundError("cargo not found")
            proc = MagicMock()
            proc.returncode = 0
            proc.stdout = "rustc 1.100.0-nightly (908501772 2026-08-30)\nhost: x86_64-unknown-linux-gnu\nrelease: 1.100.0-nightly\n"
            return proc

        with patch("subprocess.run", side_effect=mock_run):
            meta, meta_err = load_real_cargo_metadata(self.tmp_root)
            self.assertIsNone(meta)
            self.assertIn("cargo metadata execution error", meta_err or "")

            result = validate_dependency_constitution(self.tmp_root, skip_cargo_metadata=False)
            self.assertFalse(result.passed)
            self.assertEqual({e.code for e in result.errors}, {ERR_DEP_CORRUPT_FILE})

    def test_cargo_metadata_non_json_output_rejected(self) -> None:
        """Non-JSON output from cargo metadata reports exact ERR-DEP-CORRUPT-FILE-001."""
        def mock_run(cmd, *args, **kwargs):
            proc = MagicMock()
            proc.returncode = 0
            if "cargo" in cmd:
                proc.stdout = "not json at all"
            else:
                proc.stdout = "rustc 1.100.0-nightly (908501772 2026-08-30)\nhost: x86_64-unknown-linux-gnu\nrelease: 1.100.0-nightly\n"
            return proc

        with patch("subprocess.run", side_effect=mock_run):
            meta, meta_err = load_real_cargo_metadata(self.tmp_root)
            self.assertIsNone(meta)
            self.assertIn("not valid JSON", meta_err or "")

            result = validate_dependency_constitution(self.tmp_root, skip_cargo_metadata=False)
            self.assertFalse(result.passed)
            self.assertEqual({e.code for e in result.errors}, {ERR_DEP_CORRUPT_FILE})

    # Mutant X11: timeout bound operational constant and timeout rejection
    def test_mutant_x11_cargo_metadata_timeout(self) -> None:
        """Operational timeout constant is 30s and TimeoutExpired reports exact ERR-DEP-CORRUPT-FILE-001."""
        self.assertEqual(CARGO_METADATA_TIMEOUT_SECONDS, 30)
        def mock_run(cmd, *args, **kwargs):
            if "cargo" in cmd:
                raise subprocess.TimeoutExpired(cmd=cmd, timeout=30)
            proc = MagicMock()
            proc.returncode = 0
            proc.stdout = "rustc 1.100.0-nightly (908501772 2026-08-30)\nhost: x86_64-unknown-linux-gnu\nrelease: 1.100.0-nightly\n"
            return proc

        with patch("subprocess.run", side_effect=mock_run):
            meta, meta_err = load_real_cargo_metadata(self.tmp_root)
            self.assertIsNone(meta)
            self.assertIn("timed out after 30s", meta_err or "")

            result = validate_dependency_constitution(self.tmp_root, skip_cargo_metadata=False)
            self.assertFalse(result.passed)
            self.assertEqual({e.code for e in result.errors}, {ERR_DEP_CORRUPT_FILE})

    # Mutant X15: typed digest comparison (schema: 5 vs "5")
    def test_mutant_x15_typed_digest_comparison(self) -> None:
        """schema: 5 and '5' produce distinct digests and non-string schema is rejected fail-closed."""
        json_path = self.tmp_root / "architecture/dependency_constitution.json"
        data = json.loads(json_path.read_text(encoding="utf-8"))

        d_int = dict(data, schema=5)
        d_str = dict(data, schema="5")
        dig_int = compute_canonical_constitution_digest(d_int)
        dig_str = compute_canonical_constitution_digest(d_str)
        self.assertNotEqual(dig_int, dig_str)

        # schema as integer fails closed with ERR_DEP_CORRUPT_FILE
        json_path.write_text(json.dumps(d_int, indent=2), encoding="utf-8")
        result = validate_dependency_constitution(self.tmp_root, skip_cargo_metadata=True)
        self.assertFalse(result.passed)
        self.assertEqual({e.code for e in result.errors}, {ERR_DEP_CORRUPT_FILE})

    # Restored test X1: test_dep_class_f0_production_invariants
    def test_dep_class_f0_production_invariants(self) -> None:
        """Tampered production language or unsafe policy fails closed with ERR-DEP-CONST-INVARIANT-001."""
        json_path = self.tmp_root / "architecture/dependency_constitution.json"
        data = json.loads(json_path.read_text(encoding="utf-8"))
        data["production"]["language"] = "c++"
        data["freezeDigest"] = compute_canonical_constitution_digest(data)
        json_path.write_text(json.dumps(data, indent=2), encoding="utf-8")

        result = validate_dependency_constitution(self.tmp_root, skip_cargo_metadata=True)
        self.assertFalse(result.passed)
        self.assertEqual(
            {e.code for e in result.errors},
            {ERR_DEP_CONST_INVARIANT, ERR_DEP_FREEZE_DIVERGENCE},
        )

    # Restored test X2: test_cargo_metadata_edition_violation_rejected
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
        self.assertEqual({e.code for e in res.errors}, {ERR_DEP_CONST_METADATA_VIOLATION})
        self.assertTrue(any("must declare edition '2024'" in e.message for e in res.errors))

    # Restored test X3: member case of test_cargo_metadata_native_links_rejected
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
        self.assertEqual({e.code for e in res.errors}, {ERR_DEP_CONST_METADATA_VIOLATION})
        self.assertTrue(any("declares native links" in e.message for e in res.errors))

    # Restored test X4: test_cargo_metadata_production_language_violation
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
        self.assertEqual({e.code for e in res.errors}, {ERR_DEP_CONST_METADATA_VIOLATION})
        self.assertTrue(any("production_language must be 'rust'" in e.message for e in res.errors))

    # Restored test: 0-byte and syntax-error cases of test_corrupt_or_empty_files_rejected
    def test_corrupt_or_empty_files_rejected(self) -> None:
        """Corrupt or 0-byte files fail closed with exact ERR-DEP-CORRUPT-FILE-001."""
        json_path = self.tmp_root / "architecture/dependency_constitution.json"
        json_path.write_text("", encoding="utf-8")
        result = validate_dependency_constitution(self.tmp_root, skip_cargo_metadata=True)
        self.assertFalse(result.passed)
        self.assertEqual({e.code for e in result.errors}, {ERR_DEP_CORRUPT_FILE})

        json_path.write_text("{ syntax_error: [", encoding="utf-8")
        result = validate_dependency_constitution(self.tmp_root, skip_cargo_metadata=True)
        self.assertFalse(result.passed)
        self.assertEqual({e.code for e in result.errors}, {ERR_DEP_CORRUPT_FILE})

    # Restored test: missing-section branch of test_markdown_mirror_drift_rejected
    def test_markdown_mirror_drift_rejected(self) -> None:
        """Markdown documentation missing class section fails with exact ERR-DEP-REGISTRY-DRIFT-001."""
        md_path = self.tmp_root / "docs/DEPENDENCY_CONSTITUTION.md"
        original_md = md_path.read_text(encoding="utf-8")
        tampered_md = original_md.replace("### 2.1 Class F0 — Rust language and standard library", "### 2.1 Dropped Section")
        md_path.write_text(tampered_md, encoding="utf-8")

        result = validate_dependency_constitution(self.tmp_root, skip_cargo_metadata=True)
        self.assertFalse(result.passed)
        self.assertEqual({e.code for e in result.errors}, {ERR_DEP_REGISTRY_DRIFT})

    # Mutant X7: markdown mirror checks (0-byte, duplicate F0 section, lorem body)
    def test_mutant_x7_markdown_0_byte_rejected(self) -> None:
        """0-byte DEPENDENCY_CONSTITUTION.md fails closed with exact ERR-DEP-CORRUPT-FILE-001."""
        md_path = self.tmp_root / "docs/DEPENDENCY_CONSTITUTION.md"
        md_path.write_bytes(b"")

        result = validate_dependency_constitution(self.tmp_root, skip_cargo_metadata=True)
        self.assertFalse(result.passed)
        self.assertEqual({e.code for e in result.errors}, {ERR_DEP_CORRUPT_FILE})

    def test_mutant_x7_markdown_duplicate_section_rejected(self) -> None:
        """Duplicated Class F0 section in markdown fails with exact ERR-DEP-REGISTRY-DRIFT-001."""
        md_path = self.tmp_root / "docs/DEPENDENCY_CONSTITUTION.md"
        content = md_path.read_text(encoding="utf-8")
        dupe_header = "\n\n### 2.1 Class F0 — Rust language and standard library\nDuplicate body.\n"
        md_path.write_text(content + dupe_header, encoding="utf-8")

        result = validate_dependency_constitution(self.tmp_root, skip_cargo_metadata=True)
        self.assertFalse(result.passed)
        self.assertEqual({e.code for e in result.errors}, {ERR_DEP_REGISTRY_DRIFT})
        self.assertTrue(any("Duplicate class section header" in e.message for e in result.errors))

    def test_mutant_x7_markdown_lorem_body_rejected(self) -> None:
        """Class section body with lorem ipsum fails with exact ERR-DEP-REGISTRY-DRIFT-001."""
        md_path = self.tmp_root / "docs/DEPENDENCY_CONSTITUTION.md"
        content = md_path.read_text(encoding="utf-8")
        f0_header = "### 2.1 Class F0 — Rust language and standard library"
        f1_header = "### 2.2 Class F1 — Asupersync"
        before = content[:content.find(f0_header) + len(f0_header)]
        after = content[content.find(f1_header):]
        tampered = before + "\n\nLorem ipsum dolor sit amet, consectetur adipiscing elit.\n\n" + after
        md_path.write_text(tampered, encoding="utf-8")

        result = validate_dependency_constitution(self.tmp_root, skip_cargo_metadata=True)
        self.assertFalse(result.passed)
        self.assertEqual({e.code for e in result.errors}, {ERR_DEP_REGISTRY_DRIFT})
        self.assertTrue(any("contains hollow or placeholder text" in e.message for e in result.errors))

    def test_renamed_markdown_section_rejected(self) -> None:
        """Renaming a class section in DEPENDENCY_CONSTITUTION.md fails with ERR-DEP-REGISTRY-DRIFT-001."""
        md_path = self.tmp_root / "docs/DEPENDENCY_CONSTITUTION.md"
        content = md_path.read_text(encoding="utf-8")
        tampered = content.replace("### 2.1 Class F0 — Rust language and standard library", "### 2.1 Class F0 — Renamed Class Title")
        md_path.write_text(tampered, encoding="utf-8")

        result = validate_dependency_constitution(self.tmp_root, skip_cargo_metadata=True)
        self.assertFalse(result.passed)
        self.assertEqual({e.code for e in result.errors}, {ERR_DEP_REGISTRY_DRIFT})

    # Review Item 5: Traceback robustness in validate_cargo_metadata_for_f0
    def test_cargo_metadata_list_root_handled_safely(self) -> None:
        """Cargo metadata returning a JSON list fails closed without AttributeError."""
        res = dependency_constitution_checker.ValidationResult()
        validate_cargo_metadata_for_f0(res, [{"package": 1}], ROOT)
        self.assertFalse(res.passed)
        self.assertEqual({e.code for e in res.errors}, {ERR_DEP_CONST_METADATA_VIOLATION})
        self.assertTrue(any("must be a JSON object" in e.message for e in res.errors))

    def test_cargo_metadata_null_members_and_packages_handled_safely(self) -> None:
        """Cargo metadata with null workspace_members and packages handled without TypeError."""
        res = dependency_constitution_checker.ValidationResult()
        mock_meta = {
            "packages": None,
            "workspace_members": None,
            "metadata": {"fss": {"production_language": "rust"}},
        }
        validate_cargo_metadata_for_f0(res, mock_meta, ROOT)
        self.assertTrue(res.passed)

    def test_cargo_metadata_string_fss_metadata_handled_safely(self) -> None:
        """Cargo metadata with [workspace.metadata] fss = 'x' handled without AttributeError."""
        res = dependency_constitution_checker.ValidationResult()
        mock_meta = {
            "packages": [],
            "workspace_members": [],
            "metadata": {"fss": "corrupted-string"},
        }
        validate_cargo_metadata_for_f0(res, mock_meta, ROOT)
        self.assertFalse(res.passed)
        self.assertEqual({e.code for e in res.errors}, {ERR_DEP_CONST_METADATA_VIOLATION})
        self.assertTrue(any("production_language must be 'rust'" in e.message for e in res.errors))

    # Review Item 6: Tombstone loader fail-closed on missing file and string resolutions
    def test_tombstone_file_missing_fails_closed(self) -> None:
        """Missing stable_id_resolution.json fails closed with exact ERR-DEP-CORRUPT-FILE-001."""
        res_file = self.tmp_root / "architecture/stable_id_resolution.json"
        if res_file.is_file():
            res_file.unlink()
        ids, errs = load_tombstoned_ids(self.tmp_root)
        self.assertEqual(len(ids), 0)
        self.assertEqual({e.code for e in errs}, {ERR_DEP_CORRUPT_FILE})

    def test_tombstone_resolutions_not_list_fails_closed(self) -> None:
        """Field 'resolutions' as a string/dict fails closed with exact ERR-DEP-CORRUPT-FILE-001."""
        res_file = self.tmp_root / "architecture/stable_id_resolution.json"
        res_file.write_text(json.dumps({"schema": "v1", "resolutions": "not a list"}), encoding="utf-8")
        ids, errs = load_tombstoned_ids(self.tmp_root)
        self.assertEqual(len(ids), 0)
        self.assertEqual({e.code for e in errs}, {ERR_DEP_CORRUPT_FILE})

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

    # Review Item 4: Toolchain identity fail-closed
    def test_toolchain_channel_stable_rejected(self) -> None:
        """rust-toolchain.toml declaring channel = 'stable' is rejected with ERR-DEP-CONST-INVARIANT-001."""
        tc_file = self.tmp_root / "rust-toolchain.toml"
        tc_file.write_text('[toolchain]\nchannel = "stable"\nprofile = "minimal"\n', encoding="utf-8")

        res = dependency_constitution_checker.ValidationResult()
        channel = validate_toolchain_identity(self.tmp_root, res)
        self.assertIsNone(channel)
        self.assertFalse(res.passed)
        self.assertEqual({e.code for e in res.errors}, {ERR_DEP_CONST_INVARIANT})

    def test_toolchain_file_missing_fails_closed(self) -> None:
        """Missing rust-toolchain.toml fails closed with ERR-DEP-CORRUPT-FILE-001."""
        tc_file = self.tmp_root / "rust-toolchain.toml"
        if tc_file.is_file():
            tc_file.unlink()

        res = dependency_constitution_checker.ValidationResult()
        channel = validate_toolchain_identity(self.tmp_root, res)
        self.assertIsNone(channel)
        self.assertFalse(res.passed)
        self.assertEqual({e.code for e in res.errors}, {ERR_DEP_CORRUPT_FILE})

    def test_toolchain_file_unparseable_fails_closed(self) -> None:
        """Unparseable rust-toolchain.toml fails closed with ERR-DEP-CORRUPT-FILE-001."""
        tc_file = self.tmp_root / "rust-toolchain.toml"
        tc_file.write_text("invalid toml [ [ [", encoding="utf-8")

        res = dependency_constitution_checker.ValidationResult()
        channel = validate_toolchain_identity(self.tmp_root, res)
        self.assertIsNone(channel)
        self.assertFalse(res.passed)
        self.assertEqual({e.code for e in res.errors}, {ERR_DEP_CORRUPT_FILE})

    # Review Item 2: Allowlist crosswalk divergences
    def test_allowlist_dropping_ffmpeg_from_oracles_rejected(self) -> None:
        """Dropping ffmpeg from laboratory_oracles.excluded_from_production_release_closure is rejected."""
        allow_path = self.tmp_root / "architecture/dependency_allowlist.toml"
        content = allow_path.read_text(encoding="utf-8")
        tampered = content.replace('"ffmpeg", ', '')
        allow_path.write_text(tampered, encoding="utf-8")

        result = validate_dependency_constitution(self.tmp_root, skip_cargo_metadata=True)
        self.assertFalse(result.passed)
        self.assertEqual({e.code for e in result.errors}, {ERR_DEP_CONST_INVARIANT})

    def test_allowlist_adding_ffmpeg_to_in_house_rejected(self) -> None:
        """Adding ffmpeg to in_house.allowed_families is rejected."""
        allow_path = self.tmp_root / "architecture/dependency_allowlist.toml"
        content = allow_path.read_text(encoding="utf-8")
        tampered = content.replace('"asupersync",', '"asupersync", "ffmpeg",')
        allow_path.write_text(tampered, encoding="utf-8")

        result = validate_dependency_constitution(self.tmp_root, skip_cargo_metadata=True)
        self.assertFalse(result.passed)
        self.assertEqual({e.code for e in result.errors}, {ERR_DEP_CONST_INVARIANT})

    def test_allowlist_policy_flag_divergences_rejected(self) -> None:
        """Testing all 16 policy flags fail closed when mutated."""
        allow_path = self.tmp_root / "architecture/dependency_allowlist.toml"
        original_content = allow_path.read_text(encoding="utf-8")

        test_mutations = [
            ("c_or_cpp_ffi_allowed = false", "c_or_cpp_ffi_allowed = true"),
            ("serde_may_not_define_durable_bytes = true", "serde_may_not_define_durable_bytes = false"),
            ("fss_crates_must_forbid_unsafe = true", "fss_crates_must_forbid_unsafe = false"),
            ("runtime_acquisition_allowed = false", "runtime_acquisition_allowed = true"),
        ]
        for orig, mut in test_mutations:
            allow_path.write_text(original_content.replace(orig, mut), encoding="utf-8")
            result = validate_dependency_constitution(self.tmp_root, skip_cargo_metadata=True)
            self.assertFalse(result.passed, f"Expected rejection for {mut}")
            self.assertEqual({e.code for e in result.errors}, {ERR_DEP_CONST_INVARIANT})

    def test_allowlist_empty_forbidden_or_fundamental_rejected(self) -> None:
        """Emptying forbidden.crates or fundamental.allowed_subject_to_audit is rejected."""
        allow_path = self.tmp_root / "architecture/dependency_allowlist.toml"
        content = allow_path.read_text(encoding="utf-8")

        # Empty forbidden crates
        tampered = content.replace('crates = [\n  "tokio", "async-std", "smol", "glommio", "monoio", "rayon",\n  "reqwest", "hyper", "rusqlite", "sqlx", "diesel", "rocksdb",\n  "pyo3", "opencv", "ffmpeg-next", "gstreamer", "ort", "tch"\n]', 'crates = []')
        allow_path.write_text(tampered, encoding="utf-8")
        result = validate_dependency_constitution(self.tmp_root, skip_cargo_metadata=True)
        self.assertFalse(result.passed)
        self.assertEqual({e.code for e in result.errors}, {ERR_DEP_CONST_INVARIANT})

    # Review Item 2: Dependencies crosswalk (scope production, Production helper, relabel F3+Production, removed constitutionClass)
    def test_dependencies_scope_lowercase_production_rejected(self) -> None:
        """Scope 'production' (lowercase) in dependencies.json is rejected."""
        dep_path = self.tmp_root / "architecture/dependencies.json"
        data = json.loads(dep_path.read_text(encoding="utf-8"))
        data["dependencies"][0]["scope"] = "production"
        dep_path.write_text(json.dumps(data, indent=2), encoding="utf-8")

        result = validate_dependency_constitution(self.tmp_root, skip_cargo_metadata=True)
        self.assertFalse(result.passed)
        self.assertEqual({e.code for e in result.errors}, {ERR_DEP_CONST_INVARIANT})

    def test_dependencies_scope_production_helper_rejected(self) -> None:
        """Scope 'Production helper' in dependencies.json is rejected."""
        dep_path = self.tmp_root / "architecture/dependencies.json"
        data = json.loads(dep_path.read_text(encoding="utf-8"))
        data["dependencies"][0]["scope"] = "Production helper"
        dep_path.write_text(json.dumps(data, indent=2), encoding="utf-8")

        result = validate_dependency_constitution(self.tmp_root, skip_cargo_metadata=True)
        self.assertFalse(result.passed)
        self.assertEqual({e.code for e in result.errors}, {ERR_DEP_CONST_INVARIANT})

    def test_dependencies_relabel_f3_production_rejected(self) -> None:
        """Relabeling DEP-CLASS-F3 to unreserved Production scope is rejected."""
        dep_path = self.tmp_root / "architecture/dependencies.json"
        data = json.loads(dep_path.read_text(encoding="utf-8"))
        for d in data["dependencies"]:
            if d.get("id") == "DEP-FUND-001":
                d["scope"] = "Production"
        dep_path.write_text(json.dumps(data, indent=2), encoding="utf-8")

        result = validate_dependency_constitution(self.tmp_root, skip_cargo_metadata=True)
        self.assertFalse(result.passed)
        self.assertEqual({e.code for e in result.errors}, {ERR_DEP_CONST_INVARIANT})

    def test_dependencies_removed_constitution_class_rejected(self) -> None:
        """Removing constitutionClass from a row in dependencies.json is rejected."""
        dep_path = self.tmp_root / "architecture/dependencies.json"
        data = json.loads(dep_path.read_text(encoding="utf-8"))
        del data["dependencies"][0]["constitutionClass"]
        dep_path.write_text(json.dumps(data, indent=2), encoding="utf-8")

        result = validate_dependency_constitution(self.tmp_root, skip_cargo_metadata=True)
        self.assertFalse(result.passed)
        self.assertEqual({e.code for e in result.errors}, {ERR_DEP_CONST_INVARIANT})

    # Review Item 3: F0 closure (unadmitted crate, custom-build, proc-macro, exception candidate)
    def test_f0_closure_unadmitted_crate_rejected(self) -> None:
        """Unadmitted crate (libc, libloading, any unlisted) in closure fails closed."""
        res = dependency_constitution_checker.ValidationResult()
        mock_meta = {
            "packages": [
                {
                    "name": "fss-core",
                    "id": "fss-core 0.0.1",
                    "edition": "2024",
                    "manifest_path": "/path/to/fss-core/Cargo.toml",
                    "links": None,
                },
                {
                    "name": "libc",
                    "id": "libc 0.2.140",
                    "edition": "2021",
                    "manifest_path": "/path/to/libc/Cargo.toml",
                    "links": None,
                },
            ],
            "workspace_members": ["fss-core 0.0.1"],
            "metadata": {"fss": {"production_language": "rust"}},
        }
        validate_cargo_metadata_for_f0(res, mock_meta, ROOT)
        self.assertFalse(res.passed)
        self.assertEqual({e.code for e in res.errors}, {ERR_DEP_CONST_METADATA_VIOLATION})
        self.assertTrue(any("Unadmitted external crate 'libc'" in e.message for e in res.errors))

    def test_f0_closure_exception_candidate_blake3_rejected(self) -> None:
        """Exception candidate 'blake3' not admitted without DEP record fails closed."""
        res = dependency_constitution_checker.ValidationResult()
        allow_data = {
            "exception_candidates": {
                "not_admitted_without_dep_record_adr_and_release_evidence": ["blake3"]
            }
        }
        mock_meta = {
            "packages": [
                {
                    "name": "fss-core",
                    "id": "fss-core 0.0.1",
                    "edition": "2024",
                    "manifest_path": "/path/to/fss-core/Cargo.toml",
                    "links": None,
                },
                {
                    "name": "blake3",
                    "id": "blake3 1.5.0",
                    "edition": "2021",
                    "manifest_path": "/path/to/blake3/Cargo.toml",
                    "links": None,
                },
            ],
            "workspace_members": ["fss-core 0.0.1"],
            "metadata": {"fss": {"production_language": "rust"}},
        }
        validate_cargo_metadata_for_f0(res, mock_meta, ROOT, allow_data=allow_data)
        self.assertFalse(res.passed)
        self.assertEqual({e.code for e in res.errors}, {ERR_DEP_CONST_METADATA_VIOLATION})
        self.assertTrue(any("Exception candidate 'blake3'" in e.message for e in res.errors))

    def test_f0_closure_custom_build_target_rejected(self) -> None:
        """Package declaring custom-build (build.rs) target fails closed."""
        res = dependency_constitution_checker.ValidationResult()
        mock_meta = {
            "packages": [
                {
                    "name": "fss-core",
                    "id": "fss-core 0.0.1",
                    "edition": "2024",
                    "manifest_path": "/path/to/fss-core/Cargo.toml",
                    "links": None,
                    "targets": [{"kind": ["custom-build"], "name": "build-script-build"}],
                }
            ],
            "workspace_members": ["fss-core 0.0.1"],
            "metadata": {"fss": {"production_language": "rust"}},
        }
        validate_cargo_metadata_for_f0(res, mock_meta, ROOT)
        self.assertFalse(res.passed)
        self.assertEqual({e.code for e in res.errors}, {ERR_DEP_CONST_METADATA_VIOLATION})
        self.assertTrue(any("declares custom-build" in e.message for e in res.errors))

    def test_f0_closure_proc_macro_target_rejected(self) -> None:
        """Package declaring proc-macro target fails closed."""
        res = dependency_constitution_checker.ValidationResult()
        mock_meta = {
            "packages": [
                {
                    "name": "fss-core",
                    "id": "fss-core 0.0.1",
                    "edition": "2024",
                    "manifest_path": "/path/to/fss-core/Cargo.toml",
                    "links": None,
                    "targets": [{"kind": ["proc-macro"], "name": "fss-macros"}],
                }
            ],
            "workspace_members": ["fss-core 0.0.1"],
            "metadata": {"fss": {"production_language": "rust"}},
        }
        validate_cargo_metadata_for_f0(res, mock_meta, ROOT)
        self.assertFalse(res.passed)
        self.assertEqual({e.code for e in res.errors}, {ERR_DEP_CONST_METADATA_VIOLATION})
        self.assertTrue(any("declares proc-macro" in e.message for e in res.errors))

    # Review Item 8: Whitespace emitted as ERR_DEP_CORRUPT_FILE
    def test_whitespace_padding_rejected_as_corrupt_file(self) -> None:
        """Whitespace padding on fields is rejected with exact ERR-DEP-CORRUPT-FILE-001."""
        json_path = self.tmp_root / "architecture/dependency_constitution.json"
        data = json.loads(json_path.read_text(encoding="utf-8"))
        data["classes"][0]["admission"] = "constitutional "
        data["freezeDigest"] = compute_canonical_constitution_digest(data)
        json_path.write_text(json.dumps(data, indent=2), encoding="utf-8")

        result = validate_dependency_constitution(self.tmp_root, skip_cargo_metadata=True)
        self.assertFalse(result.passed)
        self.assertEqual(
            {e.code for e in result.errors},
            {ERR_DEP_CORRUPT_FILE, ERR_DEP_FREEZE_DIVERGENCE, ERR_DEP_CONST_INVARIANT},
        )

    # Malformed inputs
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

    def test_unknown_top_level_key_rejected(self) -> None:
        """Unexpected top-level key is rejected with ERR-DEP-CORRUPT-FILE-001."""
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


if __name__ == "__main__":
    unittest.main()
