#!/usr/bin/env python3
"""Planted-negative test suite for architecture/registry consistency checker (fss-x4a.6.9 / FSS-009).

Enforces that:
1. Missing identifiers (in either direction) fail deterministically with ERR-CONSISTENCY-MISSING-IDENTIFIER-001.
2. Contradicted metadata between architecture JSON and registry Markdown fails with ERR-CONSISTENCY-CONTRADICTED-METADATA-001.
3. Count/cardinality mismatches fail with ERR-CONSISTENCY-COUNT-MISMATCH-001.
4. Dangling references to nonexistent gates, views, capabilities fail with ERR-CONSISTENCY-DANGLING-REFERENCE-001.
5. Active components referencing tombstoned IDs fail with ERR-CONSISTENCY-TOMBSTONE-IN-USE-001.
6. Unregistered schemas/domains implemented or present on disk fail with ERR-CONSISTENCY-UNREGISTERED-RUST-001.
7. Missing mandatory files fail closed with ERR-CONSISTENCY-MISSING-FILE-001.
8. Malformed/corrupt files fail closed with ERR-CONSISTENCY-CORRUPT-FILE-001.
9. Live repository passes with 0 errors and complete consistency across all 116 invariants, 27 algorithms,
   13 publication primitives, 47 imports, 14 operations, 8 views, 15 lanes, 41 costs, and 72 schemas.
10. CLI exits with code 0 and emits compliant text, JSON, and report formats.
11. Adversarial review remediation tests (review-529):
    - CRITICAL fail-closed on unreadable or empty stable-ID index (stops immediately, zero dangling errors)
    - Tombstone validation for Section 3.10 operationRefs, viewRefs, knowledgeStateRefs, provenanceClassRefs
    - Vacuous consistency prevention (rejects empty collections and missing root collection keys)
    - Duplicate identifier detection in Markdown tables and JSON array mappings
    - Comprehensive cross-checks for model runtime, dependencies, crate topology, and sub-registries
    - Spaced delimiter row parsing in markdown tables
"""
from __future__ import annotations

import json
import subprocess
import sys
import tempfile
import unittest
import unittest.mock
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))

import stable_id_audit

from architecture_registry_consistency import (
    ERR_CORRUPT_FILE,
    ERR_COUNT_MISMATCH,
    ERR_CONTRADICTED_METADATA,
    ERR_DANGLING_REFERENCE,
    ERR_GRAPH_MISSING_COMPLEXITY_WITNESS,
    ERR_GRAPH_MISSING_OUTPUT_WITNESS,
    ERR_GRAPH_MISSING_TIE_BREAK,
    ERR_GRAPH_PROJECTION_MISMATCH,
    ERR_GRAPH_STABLE_ID_DRIFT,
    ERR_GRAPH_UNREGISTERED_PROJECTION,
    ERR_MISSING_FILE,
    ERR_MISSING_IDENTIFIER,
    ERR_TOMBSTONE_IN_USE,
    ERR_UNREGISTERED_RUST_IDENTIFIER,
    parse_markdown_table_rows,
    validate_consistency,
)


def create_mock_repo(tmp_path: Path) -> Path:
    """Creates a fast, isolated repository replica using symlinks for mutation tests."""
    for dir_name in ("architecture", "registries", "schemas", "crates", "scripts"):
        src_dir = ROOT / dir_name
        dst_dir = tmp_path / dir_name
        dst_dir.mkdir(parents=True, exist_ok=True)
        if dir_name == "crates":
            for sub in src_dir.iterdir():
                (dst_dir / sub.name).symlink_to(sub)
        else:
            for item in src_dir.iterdir():
                if item.is_file():
                    (dst_dir / item.name).symlink_to(item)
                elif item.is_dir():
                    (dst_dir / item.name).symlink_to(item)

    plan_file = ROOT / "COMPREHENSIVE_PLAN_FOR_FRANKEN_SURVEILLANCE_SYSTEM.md"
    if plan_file.is_file():
        (tmp_path / plan_file.name).symlink_to(plan_file)

    return tmp_path


class TestLiveRepoConsistency(unittest.TestCase):
    """Verifies that the actual repository passes all architecture/registry consistency checks."""

    def test_live_repo_passes(self) -> None:
        is_valid, findings, summary = validate_consistency(ROOT)
        self.assertTrue(
            is_valid,
            f"Live repo failed consistency check with {len(findings)} findings: {[f.message for f in findings]}",
        )
        self.assertEqual(len(findings), 0)
        self.assertEqual(summary["status"], "pass")
        self.assertEqual(summary["error_count"], 0)
        self.assertEqual(summary["invariants_count"], 116)
        self.assertEqual(summary["algorithms_count"], 27)
        self.assertEqual(summary["publication_primitives_count"], 13)
        self.assertEqual(summary["franken_imports_count"], 47)
        self.assertEqual(summary["agent_operations_count"], 14)
        self.assertEqual(summary["agent_views_count"], 8)
        self.assertEqual(summary["qualification_lanes_count"], 15)
        self.assertEqual(summary["costs_count"], 41)
        # 72 = 71 + SCHEMA-NEGATIVE-EVIDENCE-REPORT-001 (fss-x4a.6.12 negative-evidence report).
        self.assertEqual(summary["schemas_count"], 72)
        self.assertGreater(summary["known_active_ids"], 800)
        self.assertGreaterEqual(summary["tombstone_ids"], 14)


class TestFailClosedOnMissingAndCorruptFiles(unittest.TestCase):
    """Verifies fail-closed behavior on missing or corrupt files."""

    def test_planted_missing_architecture_file_fails_closed(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            repo = create_mock_repo(Path(td))
            target = repo / "architecture/invariants.json"
            target.unlink()

            is_valid, findings, _ = validate_consistency(repo)
            self.assertFalse(is_valid)
            missing_findings = [f for f in findings if f.code == ERR_MISSING_FILE]
            self.assertGreaterEqual(len(missing_findings), 1)
            self.assertTrue(any("architecture/invariants.json" in f.file for f in missing_findings))

    def test_planted_missing_registry_file_fails_closed(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            repo = create_mock_repo(Path(td))
            target = repo / "registries/INVARIANTS.md"
            target.unlink()

            is_valid, findings, _ = validate_consistency(repo)
            self.assertFalse(is_valid)
            missing_findings = [f for f in findings if f.code == ERR_MISSING_FILE]
            self.assertGreaterEqual(len(missing_findings), 1)
            self.assertTrue(any("registries/INVARIANTS.md" in f.file for f in missing_findings))

    def test_planted_corrupt_json_file_fails_closed(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            repo = create_mock_repo(Path(td))
            target = repo / "architecture/agent_operations.json"
            target.unlink()
            target.write_text("{\n  \"schema\": \"fss.agent_operations.v1\",\n  BROKEN_JSON", encoding="utf-8")

            is_valid, findings, _ = validate_consistency(repo)
            self.assertFalse(is_valid)
            corrupt_findings = [f for f in findings if f.code == ERR_CORRUPT_FILE]
            self.assertGreaterEqual(len(corrupt_findings), 1)
            self.assertTrue(any("architecture/agent_operations.json" in f.file for f in corrupt_findings))

    def test_planted_corrupt_toml_file_fails_closed(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            repo = create_mock_repo(Path(td))
            target = repo / "architecture/operation_cost_registry.toml"
            target.unlink()
            target.write_text("schema = [unclosed bracket", encoding="utf-8")

            is_valid, findings, _ = validate_consistency(repo)
            self.assertFalse(is_valid)
            corrupt_findings = [f for f in findings if f.code == ERR_CORRUPT_FILE]
            self.assertGreaterEqual(len(corrupt_findings), 1)
            self.assertTrue(any("architecture/operation_cost_registry.toml" in f.file for f in corrupt_findings))

    def test_planted_corrupt_stable_id_index_fails_closed(self) -> None:
        """Verifies that an exception loading the stable-ID repository index fails closed."""
        with tempfile.TemporaryDirectory() as td:
            repo = create_mock_repo(Path(td))
            with unittest.mock.patch(
                "stable_id_audit._load_repository_index",
                side_effect=stable_id_audit.AuditError(
                    "ERR-STABLE-ID-INDEX-CORRUPT", "simulated corrupt stable-ID index"
                ),
            ):
                is_valid, findings, _ = validate_consistency(repo)
                self.assertFalse(is_valid)
                corrupt_findings = [f for f in findings if f.code == ERR_CORRUPT_FILE]
                self.assertGreaterEqual(len(corrupt_findings), 1)
                self.assertTrue(
                    any("failed to load stable-ID repository index" in f.message for f in corrupt_findings)
                )

    def test_planted_removed_stable_id_index_fails_closed(self) -> None:
        """Verifies that an empty/removed stable-ID index fails closed rather than passing silently."""
        with tempfile.TemporaryDirectory() as td:
            repo = create_mock_repo(Path(td))
            with unittest.mock.patch(
                "stable_id_audit._load_repository_index",
                return_value=stable_id_audit.RepositoryIndex(),
            ):
                is_valid, findings, _ = validate_consistency(repo)
                self.assertFalse(is_valid)
                corrupt_findings = [f for f in findings if f.code == ERR_CORRUPT_FILE]
                self.assertGreaterEqual(len(corrupt_findings), 1)
                self.assertTrue(
                    any("stable-ID repository index is empty" in f.message for f in corrupt_findings)
                )


class TestIdentifierPresenceAndCount(unittest.TestCase):
    """Verifies detection of missing identifiers and count mismatches."""

    def test_planted_missing_identifier_in_architecture_fails(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            repo = create_mock_repo(Path(td))
            target = repo / "architecture/invariants.json"
            raw_data = json.loads((ROOT / "architecture/invariants.json").read_text(encoding="utf-8"))
            raw_data["invariants"] = [inv for inv in raw_data["invariants"] if inv.get("id") != "INV-001"]
            target.unlink()
            target.write_text(json.dumps(raw_data), encoding="utf-8")

            is_valid, findings, _ = validate_consistency(repo)
            self.assertFalse(is_valid)
            missing_findings = [f for f in findings if f.code == ERR_MISSING_IDENTIFIER]
            count_findings = [f for f in findings if f.code == ERR_COUNT_MISMATCH]
            self.assertTrue(any("INV-001" in f.message for f in missing_findings))
            self.assertGreaterEqual(len(count_findings), 1)

    def test_planted_missing_identifier_in_registry_fails(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            repo = create_mock_repo(Path(td))
            target = repo / "registries/INVARIANTS.md"
            lines = (ROOT / "registries/INVARIANTS.md").read_text(encoding="utf-8").splitlines()
            filtered_lines = [line for line in lines if "`INV-001`" not in line]
            target.unlink()
            target.write_text("\n".join(filtered_lines), encoding="utf-8")

            is_valid, findings, _ = validate_consistency(repo)
            self.assertFalse(is_valid)
            missing_findings = [f for f in findings if f.code == ERR_MISSING_IDENTIFIER]
            count_findings = [f for f in findings if f.code == ERR_COUNT_MISMATCH]
            self.assertTrue(any("INV-001" in f.message for f in missing_findings))
            self.assertGreaterEqual(len(count_findings), 1)

    def test_planted_extra_unregistered_identifier_in_registry_fails(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            repo = create_mock_repo(Path(td))
            target = repo / "registries/PUBLICATION_PRIMITIVES.md"
            content = (ROOT / "registries/PUBLICATION_PRIMITIVES.md").read_text(encoding="utf-8")
            extra_row = "| `PUB-PRIM-099` | dummy_primitive | local | verified | None | Dummy description |"
            content += f"\n{extra_row}\n"
            target.unlink()
            target.write_text(content, encoding="utf-8")

            is_valid, findings, _ = validate_consistency(repo)
            self.assertFalse(is_valid)
            missing_findings = [f for f in findings if f.code == ERR_MISSING_IDENTIFIER]
            count_findings = [f for f in findings if f.code == ERR_COUNT_MISMATCH]
            self.assertTrue(any("PUB-PRIM-099" in f.message for f in missing_findings))
            self.assertGreaterEqual(len(count_findings), 1)


class TestContradictedMetadata(unittest.TestCase):
    """Verifies detection of contradictory metadata between architecture and registry."""

    def test_planted_contradicted_qualification_lane_fails(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            repo = create_mock_repo(Path(td))
            target = repo / "architecture/release_qualification.json"
            raw_data = json.loads((ROOT / "architecture/release_qualification.json").read_text(encoding="utf-8"))
            raw_data["lanes"][0]["scope"] = "planted_contradicted_scope"
            target.unlink()
            target.write_text(json.dumps(raw_data), encoding="utf-8")

            is_valid, findings, _ = validate_consistency(repo)
            self.assertFalse(is_valid)
            contra_findings = [f for f in findings if f.code == ERR_CONTRADICTED_METADATA]
            self.assertTrue(any("scope mismatch" in f.message for f in contra_findings))

    def test_planted_contradicted_agent_operation_mode_fails(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            repo = create_mock_repo(Path(td))
            target = repo / "architecture/agent_operations.json"
            raw_data = json.loads((ROOT / "architecture/agent_operations.json").read_text(encoding="utf-8"))
            raw_data["operations"][0]["mode"] = "planted_wrong_mode"
            target.unlink()
            target.write_text(json.dumps(raw_data), encoding="utf-8")

            is_valid, findings, _ = validate_consistency(repo)
            self.assertFalse(is_valid)
            contra_findings = [f for f in findings if f.code == ERR_CONTRADICTED_METADATA]
            self.assertTrue(any("mode mismatch" in f.message for f in contra_findings))

    def test_planted_contradicted_view_tokens_fails(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            repo = create_mock_repo(Path(td))
            target = repo / "architecture/agent_views.json"
            raw_data = json.loads((ROOT / "architecture/agent_views.json").read_text(encoding="utf-8"))
            raw_data["views"][0]["targetTokens"] = 999999
            target.unlink()
            target.write_text(json.dumps(raw_data), encoding="utf-8")

            is_valid, findings, _ = validate_consistency(repo)
            self.assertFalse(is_valid)
            contra_findings = [f for f in findings if f.code == ERR_CONTRADICTED_METADATA]
            self.assertTrue(any("targetTokens mismatch" in f.message for f in contra_findings))

    def test_planted_contradicted_algorithm_exactness_fails(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            repo = create_mock_repo(Path(td))
            target = repo / "architecture/graph_algorithms.json"
            raw_data = json.loads((ROOT / "architecture/graph_algorithms.json").read_text(encoding="utf-8"))
            raw_data["algorithms"][0]["exactness"] = "heuristic"
            target.unlink()
            target.write_text(json.dumps(raw_data), encoding="utf-8")

            is_valid, findings, _ = validate_consistency(repo)
            self.assertFalse(is_valid)
            contra_findings = [f for f in findings if f.code == ERR_CONTRADICTED_METADATA]
            self.assertTrue(any("exactness mismatch" in f.message for f in contra_findings))


class TestDanglingReferences(unittest.TestCase):
    """Verifies detection of dangling cross-entity references."""

    def test_planted_dangling_capability_reference_fails(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            repo = create_mock_repo(Path(td))
            target = repo / "architecture/agent_operations.json"
            raw_data = json.loads((ROOT / "architecture/agent_operations.json").read_text(encoding="utf-8"))
            raw_data["operations"][0]["requiredCapabilities"] = ["CAP-NONEXISTENT-999"]
            target.unlink()
            target.write_text(json.dumps(raw_data), encoding="utf-8")

            is_valid, findings, _ = validate_consistency(repo)
            self.assertFalse(is_valid)
            dangling_findings = [f for f in findings if f.code == ERR_DANGLING_REFERENCE]
            self.assertTrue(any("CAP-NONEXISTENT-999" in f.message for f in dangling_findings))

    def test_planted_dangling_view_reference_fails(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            repo = create_mock_repo(Path(td))
            target = repo / "architecture/agent_operations.json"
            raw_data = json.loads((ROOT / "architecture/agent_operations.json").read_text(encoding="utf-8"))
            raw_data["operations"][0]["defaultView"] = "AVIEW-NONEXISTENT-999"
            target.unlink()
            target.write_text(json.dumps(raw_data), encoding="utf-8")

            is_valid, findings, _ = validate_consistency(repo)
            self.assertFalse(is_valid)
            dangling_findings = [f for f in findings if f.code == ERR_DANGLING_REFERENCE]
            self.assertTrue(any("AVIEW-NONEXISTENT-999" in f.message for f in dangling_findings))

    def test_planted_dangling_gate_reference_fails(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            repo = create_mock_repo(Path(td))
            target = repo / "architecture/agent_views.json"
            raw_data = json.loads((ROOT / "architecture/agent_views.json").read_text(encoding="utf-8"))
            raw_data["views"][0]["gate"] = "QL-NONEXISTENT-999"
            target.unlink()
            target.write_text(json.dumps(raw_data), encoding="utf-8")

            is_valid, findings, _ = validate_consistency(repo)
            self.assertFalse(is_valid)
            dangling_findings = [f for f in findings if f.code == ERR_DANGLING_REFERENCE]
            self.assertTrue(any("QL-NONEXISTENT-999" in f.message for f in dangling_findings))


class TestTombstoneUsage(unittest.TestCase):
    """Verifies detection of active components referencing tombstoned identifiers."""

    def test_planted_tombstoned_gate_reference_fails(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            repo = create_mock_repo(Path(td))
            target = repo / "architecture/agent_operations.json"
            raw_data = json.loads((ROOT / "architecture/agent_operations.json").read_text(encoding="utf-8"))
            raw_data["operations"][0]["gate"] = "SCHEMA-DOMAIN-TOMBSTONE-001"
            target.unlink()
            target.write_text(json.dumps(raw_data), encoding="utf-8")

            is_valid, findings, _ = validate_consistency(repo)
            self.assertFalse(is_valid)
            tombstone_findings = [f for f in findings if f.code == ERR_TOMBSTONE_IN_USE]
            self.assertTrue(any("SCHEMA-DOMAIN-TOMBSTONE-001" in f.message for f in tombstone_findings))

    def test_planted_tombstoned_capability_reference_fails(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            repo = create_mock_repo(Path(td))
            target = repo / "architecture/agent_operations.json"
            raw_data = json.loads((ROOT / "architecture/agent_operations.json").read_text(encoding="utf-8"))
            raw_data["operations"][0]["requiredCapabilities"] = ["ERR-OP-PRECONDITION-FAILED-001"]
            target.unlink()
            target.write_text(json.dumps(raw_data), encoding="utf-8")

            is_valid, findings, _ = validate_consistency(repo)
            self.assertFalse(is_valid)
            tombstone_findings = [f for f in findings if f.code == ERR_TOMBSTONE_IN_USE]
            self.assertTrue(any("ERR-OP-PRECONDITION-FAILED-001" in f.message for f in tombstone_findings))


class TestUnregisteredRustArtifacts(unittest.TestCase):
    """Verifies detection of unregistered schemas or digest domains via schema_validate reuse."""

    def test_planted_unregistered_schema_file_fails(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            repo = create_mock_repo(Path(td))
            unregistered_file = repo / "schemas/fss.planted_unregistered_schema.v1.json"
            schema_payload = {
                "$schema": "https://json-schema.org/draft/2020-12/schema",
                "$id": "https://schemas.fss.org/fss.planted_unregistered_schema.v1.json",
                "title": "PlantedUnregisteredSchema",
                "type": "object",
            }
            unregistered_file.write_text(json.dumps(schema_payload), encoding="utf-8")

            is_valid, findings, _ = validate_consistency(repo)
            self.assertFalse(is_valid)
            unregistered_findings = [
                f for f in findings if f.code in (ERR_UNREGISTERED_RUST_IDENTIFIER, ERR_MISSING_IDENTIFIER)
            ]
            self.assertTrue(any("fss.planted_unregistered_schema.v1.json" in f.message for f in unregistered_findings))


class TestAdversarialConsistencyDefects(unittest.TestCase):
    """Failing-first planted negative tests verifying fixes for all review-529 defect findings."""

    def test_broad_except_continues_with_partial_data_emitting_spurious_dangling_errors(self) -> None:
        """Finding 1 (CRITICAL fail-open): Proves that a failure in stable_id_audit._load_repository_index
        fails closed immediately and does not emit spurious downstream dangling reference errors."""
        with tempfile.TemporaryDirectory() as td:
            repo = create_mock_repo(Path(td))
            with unittest.mock.patch(
                "stable_id_audit._load_repository_index",
                side_effect=RuntimeError("simulated unreadable index"),
            ):
                is_valid, findings, _ = validate_consistency(repo)
                self.assertFalse(is_valid)

                corrupt_findings = [f for f in findings if f.code == ERR_CORRUPT_FILE]
                self.assertGreaterEqual(len(corrupt_findings), 1)

                dangling_findings = [f for f in findings if f.code == ERR_DANGLING_REFERENCE]
                self.assertEqual(
                    len(dangling_findings),
                    0,
                    f"Checker continued on partial state and emitted {len(dangling_findings)} spurious dangling errors",
                )

    def test_tombstoned_operation_accepted_in_agent_operating_model(self) -> None:
        """Finding 2 (HIGH): Proves that Section 3.10 enforces tombstoned_ids checks on operationRefs."""
        with tempfile.TemporaryDirectory() as td:
            repo = create_mock_repo(Path(td))

            target_json = repo / "architecture/agent_operations.json"
            data = json.loads(target_json.read_text(encoding="utf-8"))
            op_id = data["operations"][0]["id"]
            data["operations"][0]["status"] = "tombstone"
            target_json.unlink()
            target_json.write_text(json.dumps(data), encoding="utf-8")

            target_md = repo / "registries/AGENT_OPERATIONS.md"
            lines = target_md.read_text(encoding="utf-8").splitlines()
            new_lines = []
            for line in lines:
                if op_id in line:
                    parts = line.split("|")
                    parts[-2] = " tombstone "
                    new_lines.append("|".join(parts))
                else:
                    new_lines.append(line)
            target_md.unlink()
            target_md.write_text("\n".join(new_lines), encoding="utf-8")

            is_valid, findings, _ = validate_consistency(repo)
            self.assertFalse(is_valid)

            tomb_findings = [
                f for f in findings
                if f.code == ERR_TOMBSTONE_IN_USE
                and f.file == "architecture/agent_operating_model.json"
                and op_id in f.message
            ]
            self.assertGreaterEqual(
                len(tomb_findings),
                1,
                f"Tombstoned operation '{op_id}' in agent_operating_model.json was accepted without ERR_TOMBSTONE_IN_USE",
            )

    def test_vacuous_pass_on_empty_registry_rejected(self) -> None:
        """Finding 3 (HIGH): Proves that an empty architecture array and empty markdown table fail closed."""
        with tempfile.TemporaryDirectory() as td:
            repo = create_mock_repo(Path(td))

            target_json = repo / "architecture/franken_imports.json"
            target_json.unlink()
            target_json.write_text(json.dumps({"schema": "fss.franken_imports.v1", "imports": []}), encoding="utf-8")

            target_md = repo / "registries/IMPORTS.md"
            target_md.unlink()
            target_md.write_text("# Franken imports registry\n\n| ID | Import | Source |\n|---|---|---|\n", encoding="utf-8")

            is_valid, findings, summary = validate_consistency(repo)
            self.assertFalse(is_valid)
            imp_findings = [f for f in findings if "IMPORTS" in f.file or "imports" in f.file]
            self.assertGreaterEqual(
                len(imp_findings),
                1,
                "Completely empty imports registry was accepted vacuously with 0 findings",
            )

    def test_missing_root_key_in_architecture_file_rejected(self) -> None:
        """Finding 3 (HIGH): Proves that a missing mandatory root collection key fails closed."""
        with tempfile.TemporaryDirectory() as td:
            repo = create_mock_repo(Path(td))

            target_json = repo / "architecture/invariants.json"
            target_json.unlink()
            target_json.write_text(json.dumps({"schema": "fss.invariants.v1"}), encoding="utf-8")

            is_valid, findings, _ = validate_consistency(repo)
            self.assertFalse(is_valid)
            inv_findings = [f for f in findings if f.file == "architecture/invariants.json"]
            self.assertGreaterEqual(
                len(inv_findings),
                1,
                "Missing 'invariants' root key was accepted without error",
            )

    def test_duplicate_markdown_identifier_fails(self) -> None:
        """Finding 4 (HIGH): Proves that duplicate IDs in markdown tables are detected."""
        with tempfile.TemporaryDirectory() as td:
            repo = create_mock_repo(Path(td))

            target_md = repo / "registries/INVARIANTS.md"
            content = target_md.read_text(encoding="utf-8")
            dup_row = "| `INV-001` | Duplicate exact invariant | normative |"
            target_md.unlink()
            target_md.write_text(content + "\n" + dup_row + "\n", encoding="utf-8")

            is_valid, findings, _ = validate_consistency(repo)
            self.assertFalse(is_valid)
            inv_findings = [f for f in findings if "invariants" in f.file or "INVARIANTS" in f.file]
            self.assertGreaterEqual(
                len(inv_findings),
                1,
                "Duplicate INV-001 in registries/INVARIANTS.md was silently swallowed without detection",
            )

    def test_duplicate_architecture_identifier_fails(self) -> None:
        """Finding 4 (HIGH): Proves that duplicate IDs in architecture JSON arrays are detected."""
        with tempfile.TemporaryDirectory() as td:
            repo = create_mock_repo(Path(td))

            target_json = repo / "architecture/agent_operations.json"
            data = json.loads(target_json.read_text(encoding="utf-8"))
            data["operations"].append(data["operations"][0].copy())
            target_json.unlink()
            target_json.write_text(json.dumps(data), encoding="utf-8")

            is_valid, findings, _ = validate_consistency(repo)
            self.assertFalse(is_valid)
            dup_findings = [
                f for f in findings
                if f.code == ERR_COUNT_MISMATCH and "duplicate identifier" in f.message
            ]
            self.assertGreaterEqual(
                len(dup_findings),
                1,
                "Duplicate operation in architecture/agent_operations.json was not detected",
            )

    def test_parse_markdown_table_rows_skips_spaced_delimiter_rows(self) -> None:
        """Finding 6 (MEDIUM): Proves that spaced delimiter rows are not parsed into data rows."""
        sample_table = (
            "# Sample table\n\n"
            "| ID | Name | Status |\n"
            "| --- | :---: | ---: |\n"
            "| `INV-001` | Test invariant | normative |\n"
        )
        rows = parse_markdown_table_rows(sample_table)
        self.assertEqual(len(rows), 2)
        self.assertEqual(rows[0], ["ID", "Name", "Status"])
        self.assertEqual(rows[1], ["INV-001", "Test invariant", "normative"])

    def test_contradicted_semantic_objects_fails(self) -> None:
        """Finding 5 (HIGH): Proves that sub-registries in agent_contracts.json are cross-checked."""
        with tempfile.TemporaryDirectory() as td:
            repo = create_mock_repo(Path(td))

            target_json = repo / "architecture/agent_contracts.json"
            data = json.loads(target_json.read_text(encoding="utf-8"))
            data["semanticObjects"]["MissionContract"] = "fss.planted_wrong_schema.v1"
            target_json.unlink()
            target_json.write_text(json.dumps(data), encoding="utf-8")

            is_valid, findings, _ = validate_consistency(repo)
            self.assertFalse(is_valid)
            schema_findings = [
                f for f in findings
                if f.code == ERR_CONTRADICTED_METADATA and "MissionContract" in f.message
            ]
            self.assertGreaterEqual(
                len(schema_findings),
                1,
                "Contradicted semanticObject schema in agent_contracts.json was not detected",
            )

    def test_unregistered_crate_in_topology_fails(self) -> None:
        """Finding 5 (HIGH): Proves that crate_topology.json is cross-checked against crates/ on disk."""
        with tempfile.TemporaryDirectory() as td:
            repo = create_mock_repo(Path(td))

            unreg_crate = repo / "crates/fss-planted-unregistered"
            unreg_crate.mkdir(parents=True)
            (unreg_crate / "Cargo.toml").write_text(
                '[package]\nname = "fss-planted-unregistered"\nversion = "0.0.1"\nedition = "2024"\n',
                encoding="utf-8",
            )

            is_valid, findings, _ = validate_consistency(repo)
            self.assertFalse(is_valid)
            crate_findings = [
                f for f in findings
                if f.code == ERR_MISSING_IDENTIFIER and "fss-planted-unregistered" in f.message
            ]
            self.assertGreaterEqual(
                len(crate_findings),
                1,
                "Unregistered crate on disk was not detected by crate_topology cross-check",
            )

    def test_tombstoned_gate_in_publication_primitives_fails(self) -> None:
        """Finding 5 (HIGH): Proves that gate references in publication_primitives are validated."""
        with tempfile.TemporaryDirectory() as td:
            repo = create_mock_repo(Path(td))

            target_json = repo / "architecture/publication_primitives.json"
            data = json.loads(target_json.read_text(encoding="utf-8"))
            data["primitives"][0]["gate"] = "SCHEMA-DOMAIN-TOMBSTONE-001"
            target_json.unlink()
            target_json.write_text(json.dumps(data), encoding="utf-8")

            is_valid, findings, _ = validate_consistency(repo)
            self.assertFalse(is_valid)
            tomb_findings = [
                f for f in findings
                if f.code == ERR_TOMBSTONE_IN_USE and "SCHEMA-DOMAIN-TOMBSTONE-001" in f.message
            ]
            self.assertGreaterEqual(
                len(tomb_findings),
                1,
                "Tombstoned gate in publication_primitives.json was not detected",
            )


class TestCliInvocation(unittest.TestCase):
    """Verifies the CLI interface: exit codes, text output, JSON output, and report saving."""

    def test_cli_text_output_passes_on_live_repo(self) -> None:
        proc = subprocess.run(
            [sys.executable, str(ROOT / "scripts/architecture_registry_consistency.py")],
            cwd=str(ROOT),
            capture_output=True,
            text=True,
        )
        self.assertEqual(proc.returncode, 0, f"CLI failed: {proc.stderr}")
        self.assertIn("[PASS] Architecture/registry consistency audit passed", proc.stdout)

    def test_cli_json_flag_passes_on_live_repo(self) -> None:
        proc = subprocess.run(
            [sys.executable, str(ROOT / "scripts/architecture_registry_consistency.py"), "--json"],
            cwd=str(ROOT),
            capture_output=True,
            text=True,
        )
        self.assertEqual(proc.returncode, 0, f"CLI failed: {proc.stderr}")
        data = json.loads(proc.stdout)
        self.assertEqual(data["status"], "passed")
        self.assertEqual(data["summary"]["status"], "pass")
        self.assertEqual(len(data["findings"]), 0)

    def test_cli_format_json_passes_on_live_repo(self) -> None:
        proc = subprocess.run(
            [sys.executable, str(ROOT / "scripts/architecture_registry_consistency.py"), "--format", "json"],
            cwd=str(ROOT),
            capture_output=True,
            text=True,
        )
        self.assertEqual(proc.returncode, 0, f"CLI failed: {proc.stderr}")
        data = json.loads(proc.stdout)
        self.assertEqual(data["status"], "passed")

    def test_cli_report_output(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            report_path = Path(td) / "report.json"
            proc = subprocess.run(
                [
                    sys.executable,
                    str(ROOT / "scripts/architecture_registry_consistency.py"),
                    "--report",
                    str(report_path),
                ],
                cwd=str(ROOT),
                capture_output=True,
                text=True,
            )
            self.assertEqual(proc.returncode, 0, f"CLI failed: {proc.stderr}")
            self.assertTrue(report_path.is_file())
            data = json.loads(report_path.read_text(encoding="utf-8"))
            self.assertEqual(data["status"], "passed")
            self.assertEqual(len(data["findings"]), 0)


class TestGraphAlgorithmRegistryConsistency(unittest.TestCase):
    """Verifies row-by-row consistency for graph algorithm projections and witnesses (fss-x4a.30.92)."""

    def test_planted_unregistered_graph_projection_in_json_fails_closed(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            repo = create_mock_repo(Path(td))
            target = repo / "architecture/graph_algorithms.json"
            raw_data = json.loads((ROOT / "architecture/graph_algorithms.json").read_text(encoding="utf-8"))
            raw_data["algorithms"][0]["projection"] = ["UnregisteredProjectionGraph"]
            target.unlink()
            target.write_text(json.dumps(raw_data), encoding="utf-8")

            is_valid, findings, _ = validate_consistency(repo)
            self.assertFalse(is_valid)
            proj_findings = [f for f in findings if f.code == ERR_GRAPH_UNREGISTERED_PROJECTION]
            self.assertGreaterEqual(len(proj_findings), 1)
            self.assertTrue(any("UnregisteredProjectionGraph" in f.message for f in proj_findings))

    def test_planted_unregistered_graph_projection_in_markdown_fails_closed(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            repo = create_mock_repo(Path(td))
            target = repo / "registries/GRAPH_ALGORITHMS.md"
            text = (ROOT / "registries/GRAPH_ALGORITHMS.md").read_text(encoding="utf-8")
            text = text.replace("`SensorCoverageGraph`", "`NonexistentProjectionGraph`", 1)
            target.unlink()
            target.write_text(text, encoding="utf-8")

            is_valid, findings, _ = validate_consistency(repo)
            self.assertFalse(is_valid)
            proj_findings = [f for f in findings if f.code == ERR_GRAPH_UNREGISTERED_PROJECTION]
            self.assertGreaterEqual(len(proj_findings), 1)
            self.assertTrue(any("NonexistentProjectionGraph" in f.message for f in proj_findings))

    def test_planted_missing_graph_tie_break_fails_closed(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            repo = create_mock_repo(Path(td))
            target = repo / "architecture/graph_algorithms.json"
            raw_data = json.loads((ROOT / "architecture/graph_algorithms.json").read_text(encoding="utf-8"))
            raw_data["algorithms"][0]["tieBreak"] = ""
            target.unlink()
            target.write_text(json.dumps(raw_data), encoding="utf-8")

            is_valid, findings, _ = validate_consistency(repo)
            self.assertFalse(is_valid)
            tb_findings = [f for f in findings if f.code == ERR_GRAPH_MISSING_TIE_BREAK]
            self.assertGreaterEqual(len(tb_findings), 1)
            self.assertTrue(any(raw_data["algorithms"][0]["id"] in f.location for f in tb_findings))

    def test_planted_non_deterministic_graph_tie_break_fails_closed(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            repo = create_mock_repo(Path(td))
            target = repo / "architecture/graph_algorithms.json"
            raw_data = json.loads((ROOT / "architecture/graph_algorithms.json").read_text(encoding="utf-8"))
            raw_data["algorithms"][0]["tieBreak"] = "arbitrary random pick"
            target.unlink()
            target.write_text(json.dumps(raw_data), encoding="utf-8")

            is_valid, findings, _ = validate_consistency(repo)
            self.assertFalse(is_valid)
            tb_findings = [f for f in findings if f.code == ERR_GRAPH_MISSING_TIE_BREAK]
            self.assertGreaterEqual(len(tb_findings), 1)

    def test_planted_missing_complexity_witness_fails_closed(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            repo = create_mock_repo(Path(td))
            target = repo / "architecture/graph_algorithms.json"
            raw_data = json.loads((ROOT / "architecture/graph_algorithms.json").read_text(encoding="utf-8"))
            raw_data["algorithms"][0]["complexityWitness"] = ""
            target.unlink()
            target.write_text(json.dumps(raw_data), encoding="utf-8")

            is_valid, findings, _ = validate_consistency(repo)
            self.assertFalse(is_valid)
            cw_findings = [f for f in findings if f.code == ERR_GRAPH_MISSING_COMPLEXITY_WITNESS]
            self.assertGreaterEqual(len(cw_findings), 1)

    def test_planted_missing_output_size_witness_fails_closed(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            repo = create_mock_repo(Path(td))
            target = repo / "architecture/graph_algorithms.json"
            raw_data = json.loads((ROOT / "architecture/graph_algorithms.json").read_text(encoding="utf-8"))
            raw_data["algorithms"][0].pop("outputSizeWitness", None)
            target.unlink()
            target.write_text(json.dumps(raw_data), encoding="utf-8")

            is_valid, findings, _ = validate_consistency(repo)
            self.assertFalse(is_valid)
            ow_findings = [f for f in findings if f.code == ERR_GRAPH_MISSING_OUTPUT_WITNESS]
            self.assertGreaterEqual(len(ow_findings), 1)

    def test_planted_graph_projection_mirror_mismatch_fails_closed(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            repo = create_mock_repo(Path(td))
            target = repo / "registries/GRAPH_ALGORITHMS.md"
            text = (ROOT / "registries/GRAPH_ALGORITHMS.md").read_text(encoding="utf-8")
            text = text.replace(
                "`SensorCoverageGraph`, `DeviceFailureGraph`, `EvidenceClaimGraph`",
                "`SensorCoverageGraph`",
                1,
            )
            target.unlink()
            target.write_text(text, encoding="utf-8")

            is_valid, findings, _ = validate_consistency(repo)
            self.assertFalse(is_valid)
            mismatch_findings = [f for f in findings if f.code == ERR_GRAPH_PROJECTION_MISMATCH]
            self.assertGreaterEqual(len(mismatch_findings), 1)
            self.assertTrue(any("ALG-BRIDGE-001" in f.location for f in mismatch_findings))

    def test_planted_graph_algorithm_stable_id_renumbered_fails_closed(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            repo = create_mock_repo(Path(td))
            target = repo / "architecture/graph_algorithms.json"
            raw_data = json.loads((ROOT / "architecture/graph_algorithms.json").read_text(encoding="utf-8"))
            raw_data["algorithms"][0]["id"] = "ALG-DYNCONN-002"
            target.unlink()
            target.write_text(json.dumps(raw_data), encoding="utf-8")

            is_valid, findings, _ = validate_consistency(repo)
            self.assertFalse(is_valid)
            drift_findings = [f for f in findings if f.code == ERR_GRAPH_STABLE_ID_DRIFT]
            self.assertGreaterEqual(len(drift_findings), 1)


if __name__ == "__main__":
    unittest.main()
