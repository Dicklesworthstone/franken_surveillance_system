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
   13 publication primitives, 47 imports, 14 operations, 8 views, 15 lanes, 33 costs, and 66 schemas.
10. CLI exits with code 0 and emits compliant text, JSON, and report formats.
"""
from __future__ import annotations

import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))

from architecture_registry_consistency import (
    ERR_CORRUPT_FILE,
    ERR_COUNT_MISMATCH,
    ERR_CONTRADICTED_METADATA,
    ERR_DANGLING_REFERENCE,
    ERR_MISSING_FILE,
    ERR_MISSING_IDENTIFIER,
    ERR_TOMBSTONE_IN_USE,
    ERR_UNREGISTERED_RUST_IDENTIFIER,
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
        self.assertEqual(summary["costs_count"], 33)
        self.assertEqual(summary["schemas_count"], 66)
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


if __name__ == "__main__":
    unittest.main()
