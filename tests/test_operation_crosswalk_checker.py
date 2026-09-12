#!/usr/bin/env python3
"""Planted-negative test suite for operation registry crosswalk checker (fss-x4a.25.1 / FSS-176).

Verifies that the crosswalk checker fails closed on:
1. Missing operation in crosswalk (present in agent_operations.json but missing in crosswalk)
2. Missing operation in agent_operations.json (present in crosswalk but missing in agent_operations)
3. Missing surface mapping (cli_command, library_entry_point, or mcp_tool_name missing/empty)
4. Name collision on CLI command
5. Name collision on MCP tool name
6. Name collision on library entry point
7. Unregistered error code (error ID not in registries/ERRORS.md)
8. Stale entry / status mismatch (active crosswalk mapping for tombstoned/deprecated operation)
9. Tombstoned error in active mapping
10. Markdown table and JSON crosswalk divergence
11. Empty crosswalk collection or missing mandatory file
12. Live repository passes with 0 errors across all 14 registered operations
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

try:
    import operation_crosswalk_checker
    from operation_crosswalk_checker import (
        ERR_CROSSWALK_CORRUPT_FILE,
        ERR_CROSSWALK_DIVERGENCE,
        ERR_CROSSWALK_NAME_COLLISION,
        ERR_CROSSWALK_STALE_ENTRY,
        ERR_CROSSWALK_SURFACE_MISSING,
        ERR_CROSSWALK_UNREGISTERED_ERROR,
        validate_crosswalk,
    )
except ImportError:
    # Allows initial failing test before module creation
    operation_crosswalk_checker = None  # type: ignore[assignment]
    ERR_CROSSWALK_CORRUPT_FILE = "ERR-CROSSWALK-CORRUPT-FILE-001"
    ERR_CROSSWALK_DIVERGENCE = "ERR-CROSSWALK-DIVERGENCE-001"
    ERR_CROSSWALK_NAME_COLLISION = "ERR-CROSSWALK-NAME-COLLISION-001"
    ERR_CROSSWALK_STALE_ENTRY = "ERR-CROSSWALK-STALE-ENTRY-001"
    ERR_CROSSWALK_SURFACE_MISSING = "ERR-CROSSWALK-SURFACE-MISSING-001"
    ERR_CROSSWALK_UNREGISTERED_ERROR = "ERR-CROSSWALK-UNREGISTERED-ERROR-001"
    validate_crosswalk = None  # type: ignore[assignment]


def create_mock_repo(tmp_path: Path) -> Path:
    """Creates an isolated repository replica with symlinks for mutation tests."""
    for dir_name in ("architecture", "registries", "schemas", "crates", "scripts"):
        src_dir = ROOT / dir_name
        dst_dir = tmp_path / dir_name
        dst_dir.mkdir(parents=True, exist_ok=True)
        if dir_name in ("architecture", "registries", "schemas"):
            for f in src_dir.iterdir():
                if f.is_file():
                    (dst_dir / f.name).symlink_to(f)
    return tmp_path


class TestOperationCrosswalkChecker(unittest.TestCase):
    """Test suite and planted negatives for operation crosswalk checker."""

    def setUp(self) -> None:
        if operation_crosswalk_checker is None or validate_crosswalk is None:
            self.fail("operation_crosswalk_checker module not yet implemented")

    def test_live_repository_passes_with_zero_errors(self) -> None:
        """The live repository must satisfy the crosswalk with 0 errors across all 14 operations."""
        result = validate_crosswalk(ROOT)
        self.assertTrue(result.passed, f"Live repository failed validation: {result.errors}")
        self.assertEqual(len(result.errors), 0)
        self.assertEqual(result.operation_count, 14)

    def test_missing_operation_in_crosswalk_fails_closed(self) -> None:
        """An operation present in agent_operations.json but omitted from crosswalk fails closed."""
        with tempfile.TemporaryDirectory() as tmp_dir:
            repo = create_mock_repo(Path(tmp_dir))
            crosswalk_file = repo / "architecture" / "operation_crosswalk.json"
            crosswalk_file.unlink()

            data = json.loads((ROOT / "architecture" / "operation_crosswalk.json").read_text(encoding="utf-8"))
            # Remove AOP-001
            data["crosswalk"] = [entry for entry in data["crosswalk"] if entry["operation_id"] != "AOP-001"]
            crosswalk_file.write_text(json.dumps(data, indent=2), encoding="utf-8")

            result = validate_crosswalk(repo)
            self.assertFalse(result.passed)
            self.assertTrue(
                any(err.code == ERR_CROSSWALK_SURFACE_MISSING and "AOP-001" in err.message for err in result.errors),
                f"Expected missing operation error for AOP-001, got {result.errors}",
            )

    def test_missing_surface_mapping_fails_closed(self) -> None:
        """An operation missing one of its surface mappings (e.g. mcp_tool_name) fails closed."""
        for surface_field in ("cli_command", "library_entry_point", "mcp_tool_name"):
            with tempfile.TemporaryDirectory() as tmp_dir:
                repo = create_mock_repo(Path(tmp_dir))
                crosswalk_file = repo / "architecture" / "operation_crosswalk.json"
                crosswalk_file.unlink()

                data = json.loads((ROOT / "architecture" / "operation_crosswalk.json").read_text(encoding="utf-8"))
                for entry in data["crosswalk"]:
                    if entry["operation_id"] == "AOP-003":
                        entry[surface_field] = ""
                crosswalk_file.write_text(json.dumps(data, indent=2), encoding="utf-8")

                result = validate_crosswalk(repo)
                self.assertFalse(result.passed, f"Should fail when {surface_field} is empty")
                self.assertTrue(
                    any(err.code == ERR_CROSSWALK_SURFACE_MISSING and surface_field in err.message for err in result.errors),
                    f"Expected surface missing error for {surface_field}, got {result.errors}",
                )

    def test_extra_operation_in_crosswalk_fails_closed(self) -> None:
        """An operation present in crosswalk but missing from agent_operations.json fails closed."""
        with tempfile.TemporaryDirectory() as tmp_dir:
            repo = create_mock_repo(Path(tmp_dir))
            crosswalk_file = repo / "architecture" / "operation_crosswalk.json"
            crosswalk_file.unlink()

            data = json.loads((ROOT / "architecture" / "operation_crosswalk.json").read_text(encoding="utf-8"))
            data["crosswalk"].append({
                "operation_id": "AOP-999",
                "operation_name": "invented.verb",
                "cli_command": "fss invented verb",
                "library_entry_point": "fss_fake::invented_verb",
                "mcp_tool_name": "fss_invented_verb",
                "primary_error_id": "ERR-AUTH-DENIED-001",
                "error_identities": ["ERR-AUTH-DENIED-001"],
                "exit_identities": ["EXIT-OK-000", "EXIT-CLI-RUNTIME-FAILURE-001"],
                "status": "specified",
            })
            crosswalk_file.write_text(json.dumps(data, indent=2), encoding="utf-8")

            result = validate_crosswalk(repo)
            self.assertFalse(result.passed)
            self.assertTrue(
                any(err.code == ERR_CROSSWALK_SURFACE_MISSING and "AOP-999" in err.message for err in result.errors),
                f"Expected error for extra unmapped operation AOP-999, got {result.errors}",
            )

    def test_cli_command_collision_fails_closed(self) -> None:
        """Two operations colliding on the same CLI command fail closed."""
        with tempfile.TemporaryDirectory() as tmp_dir:
            repo = create_mock_repo(Path(tmp_dir))
            crosswalk_file = repo / "architecture" / "operation_crosswalk.json"
            crosswalk_file.unlink()

            data = json.loads((ROOT / "architecture" / "operation_crosswalk.json").read_text(encoding="utf-8"))
            data["crosswalk"][1]["cli_command"] = data["crosswalk"][0]["cli_command"]
            crosswalk_file.write_text(json.dumps(data, indent=2), encoding="utf-8")

            result = validate_crosswalk(repo)
            self.assertFalse(result.passed)
            self.assertTrue(
                any(err.code == ERR_CROSSWALK_NAME_COLLISION and "cli_command" in err.target for err in result.errors),
                f"Expected CLI collision error, got {result.errors}",
            )

    def test_mcp_tool_collision_fails_closed(self) -> None:
        """Two operations colliding on the same MCP tool name fail closed."""
        with tempfile.TemporaryDirectory() as tmp_dir:
            repo = create_mock_repo(Path(tmp_dir))
            crosswalk_file = repo / "architecture" / "operation_crosswalk.json"
            crosswalk_file.unlink()

            data = json.loads((ROOT / "architecture" / "operation_crosswalk.json").read_text(encoding="utf-8"))
            data["crosswalk"][1]["mcp_tool_name"] = data["crosswalk"][0]["mcp_tool_name"]
            crosswalk_file.write_text(json.dumps(data, indent=2), encoding="utf-8")

            result = validate_crosswalk(repo)
            self.assertFalse(result.passed)
            self.assertTrue(
                any(err.code == ERR_CROSSWALK_NAME_COLLISION and "mcp_tool_name" in err.target for err in result.errors),
                f"Expected MCP collision error, got {result.errors}",
            )

    def test_library_entry_point_collision_fails_closed(self) -> None:
        """Two operations colliding on the same library entry point fail closed."""
        with tempfile.TemporaryDirectory() as tmp_dir:
            repo = create_mock_repo(Path(tmp_dir))
            crosswalk_file = repo / "architecture" / "operation_crosswalk.json"
            crosswalk_file.unlink()

            data = json.loads((ROOT / "architecture" / "operation_crosswalk.json").read_text(encoding="utf-8"))
            data["crosswalk"][1]["library_entry_point"] = data["crosswalk"][0]["library_entry_point"]
            crosswalk_file.write_text(json.dumps(data, indent=2), encoding="utf-8")

            result = validate_crosswalk(repo)
            self.assertFalse(result.passed)
            self.assertTrue(
                any(err.code == ERR_CROSSWALK_NAME_COLLISION and "library_entry_point" in err.target for err in result.errors),
                f"Expected library collision error, got {result.errors}",
            )

    def test_unregistered_error_code_fails_closed(self) -> None:
        """An operation mapping an unregistered error code fails closed."""
        with tempfile.TemporaryDirectory() as tmp_dir:
            repo = create_mock_repo(Path(tmp_dir))
            crosswalk_file = repo / "architecture" / "operation_crosswalk.json"
            crosswalk_file.unlink()

            data = json.loads((ROOT / "architecture" / "operation_crosswalk.json").read_text(encoding="utf-8"))
            data["crosswalk"][0]["error_identities"].append("ERR-UNREGISTERED-FICTIONAL-001")
            crosswalk_file.write_text(json.dumps(data, indent=2), encoding="utf-8")

            result = validate_crosswalk(repo)
            self.assertFalse(result.passed)
            self.assertTrue(
                any(err.code == ERR_CROSSWALK_UNREGISTERED_ERROR and "ERR-UNREGISTERED-FICTIONAL-001" in err.message for err in result.errors),
                f"Expected unregistered error code error, got {result.errors}",
            )

    def test_tombstoned_error_in_active_mapping_fails_closed(self) -> None:
        """Referencing a tombstoned error in an active mapping fails closed."""
        with tempfile.TemporaryDirectory() as tmp_dir:
            repo = create_mock_repo(Path(tmp_dir))
            crosswalk_file = repo / "architecture" / "operation_crosswalk.json"
            crosswalk_file.unlink()

            data = json.loads((ROOT / "architecture" / "operation_crosswalk.json").read_text(encoding="utf-8"))
            # ERR-OP-PRECONDITION-FAILED-001 is explicitly a tombstone in ERRORS.md
            data["crosswalk"][0]["primary_error_id"] = "ERR-OP-PRECONDITION-FAILED-001"
            crosswalk_file.write_text(json.dumps(data, indent=2), encoding="utf-8")

            result = validate_crosswalk(repo)
            self.assertFalse(result.passed)
            self.assertTrue(
                any(err.code == ERR_CROSSWALK_STALE_ENTRY and "tombstone" in err.message.lower() for err in result.errors),
                f"Expected tombstone/stale error, got {result.errors}",
            )

    def test_stale_status_mismatch_fails_closed(self) -> None:
        """Status mismatch between crosswalk and agent_operations.json fails closed."""
        with tempfile.TemporaryDirectory() as tmp_dir:
            repo = create_mock_repo(Path(tmp_dir))
            crosswalk_file = repo / "architecture" / "operation_crosswalk.json"
            crosswalk_file.unlink()

            data = json.loads((ROOT / "architecture" / "operation_crosswalk.json").read_text(encoding="utf-8"))
            data["crosswalk"][0]["status"] = "retired"
            crosswalk_file.write_text(json.dumps(data, indent=2), encoding="utf-8")

            result = validate_crosswalk(repo)
            self.assertFalse(result.passed)
            self.assertTrue(
                any(err.code == ERR_CROSSWALK_STALE_ENTRY and "status" in err.message.lower() for err in result.errors),
                f"Expected status mismatch error, got {result.errors}",
            )

    def test_markdown_json_divergence_fails_closed(self) -> None:
        """Divergence between Markdown table and JSON crosswalk fails closed."""
        with tempfile.TemporaryDirectory() as tmp_dir:
            repo = create_mock_repo(Path(tmp_dir))
            md_file = repo / "registries" / "OPERATION_CROSSWALK.md"
            md_file.unlink()

            content = (ROOT / "registries" / "OPERATION_CROSSWALK.md").read_text(encoding="utf-8")
            # Corrupt one CLI command in markdown table
            corrupted = content.replace("fss session open", "fss session altered_open")
            md_file.write_text(corrupted, encoding="utf-8")

            result = validate_crosswalk(repo)
            self.assertFalse(result.passed)
            self.assertTrue(
                any(err.code == ERR_CROSSWALK_DIVERGENCE for err in result.errors),
                f"Expected markdown divergence error, got {result.errors}",
            )

    def test_empty_crosswalk_fails_closed(self) -> None:
        """An empty crosswalk list fails closed."""
        with tempfile.TemporaryDirectory() as tmp_dir:
            repo = create_mock_repo(Path(tmp_dir))
            crosswalk_file = repo / "architecture" / "operation_crosswalk.json"
            crosswalk_file.unlink()

            data = {"schema": "fss.operation_crosswalk.v1", "crosswalk": []}
            crosswalk_file.write_text(json.dumps(data, indent=2), encoding="utf-8")

            result = validate_crosswalk(repo)
            self.assertFalse(result.passed)
            self.assertTrue(
                any(err.code == ERR_CROSSWALK_CORRUPT_FILE for err in result.errors),
                f"Expected corrupt/empty file error, got {result.errors}",
            )

    def test_cli_execution(self) -> None:
        """CLI invocation of the checker passes on live repo and outputs JSON report."""
        checker_path = ROOT / "scripts" / "operation_crosswalk_checker.py"
        proc = subprocess.run(
            [sys.executable, str(checker_path), "--json"],
            capture_output=True,
            text=True,
            cwd=str(ROOT),
            check=False,
        )
        self.assertEqual(proc.returncode, 0, f"Checker failed: {proc.stderr}")
        data = json.loads(proc.stdout)
        self.assertEqual(data["status"], "passed")
        self.assertEqual(data["operationCount"], 14)


if __name__ == "__main__":
    unittest.main()
