#!/usr/bin/env python3
"""Planted-negative test suite for dependency DAG checker (fss-x4a.6.10 / FSS-010).

Enforces that:
1. Directed cycles fail closed with ERR-DAG-CYCLE-001.
2. Self-dependencies (length-1 cycles) fail closed with ERR-DAG-SELF-DEPENDENCY-001.
3. Dangling references to undefined IDs fail closed with ERR-DAG-DANGLING-REFERENCE-001.
4. Duplicate node definitions fail closed with ERR-DAG-DUPLICATE-ID-001.
5. Missing input files fail closed with ERR-DAG-MISSING-FILE-001.
6. Malformed/corrupt files fail closed with ERR-DAG-CORRUPT-FILE-001.
7. Vacuous/empty input graphs fail closed with ERR-DAG-EMPTY-INPUT-001.
8. Upward layer inversions in crate topology fail closed with ERR-DAG-LAYER-INVERSION-001.
9. Active nodes referencing tombstoned dependencies fail closed with ERR-DAG-TOMBSTONE-REFERENCE-001.
10. Live repository beads DAG and crate topology pass with zero errors.
11. CLI returns deterministic exit codes (0 on success, 1 on validation error, 2 on usage error)
    and valid structured JSON report.
"""
from __future__ import annotations

import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))

from dependency_dag_checker import (
    ERR_DAG_CORRUPT_FILE,
    ERR_DAG_CYCLE,
    ERR_DAG_DANGLING_REFERENCE,
    ERR_DAG_DUPLICATE_ID,
    ERR_DAG_EMPTY_INPUT,
    ERR_DAG_LAYER_INVERSION,
    ERR_DAG_MISSING_FILE,
    ERR_DAG_SELF_DEPENDENCY,
    ERR_DAG_TOMBSTONE_REFERENCE,
    REPORT_SCHEMA,
    validate_all,
    validate_beads_dag,
    validate_crate_topology_dag,
    validate_dag_file,
    validate_generic_graph,
)


class TestPlantedNegativeDagChecker(unittest.TestCase):
    """Verifies that dependency_dag_checker fails closed on planted defects with typed error codes."""

    def test_planted_cycle_fails_with_err_dag_cycle(self) -> None:
        """A directed cycle (A -> B -> C -> A) must be detected and reported with ERR-DAG-CYCLE-001."""
        nodes = {
            "node-A": ["node-B"],
            "node-B": ["node-C"],
            "node-C": ["node-A"],
        }
        is_valid, findings, summary = validate_generic_graph(nodes, source="planted_cycle_test")
        self.assertFalse(is_valid)
        self.assertGreater(summary["error_count"], 0)
        cycle_findings = [f for f in findings if f.code == ERR_DAG_CYCLE]
        self.assertGreaterEqual(len(cycle_findings), 1)
        self.assertTrue(any("node-A" in f.message for f in cycle_findings))

    def test_planted_self_dependency_fails_with_err_dag_self_dependency(self) -> None:
        """A node depending directly on itself (A -> A) must trigger ERR-DAG-SELF-DEPENDENCY-001."""
        nodes = {
            "node-A": ["node-A"],
            "node-B": ["node-A"],
        }
        is_valid, findings, summary = validate_generic_graph(nodes, source="planted_self_dep_test")
        self.assertFalse(is_valid)
        self.assertGreater(summary["error_count"], 0)
        self_findings = [f for f in findings if f.code == ERR_DAG_SELF_DEPENDENCY]
        self.assertGreaterEqual(len(self_findings), 1)
        self.assertEqual(self_findings[0].node_id, "node-A")

    def test_planted_dangling_reference_fails_with_err_dag_dangling_reference(self) -> None:
        """A dependency reference to an undefined node must fail closed with ERR-DAG-DANGLING-REFERENCE-001."""
        nodes = {
            "node-A": ["node-B", "node-NONEXISTENT"],
            "node-B": [],
        }
        is_valid, findings, summary = validate_generic_graph(nodes, source="planted_dangling_test")
        self.assertFalse(is_valid)
        dangling_findings = [f for f in findings if f.code == ERR_DAG_DANGLING_REFERENCE]
        self.assertGreaterEqual(len(dangling_findings), 1)
        self.assertEqual(dangling_findings[0].node_id, "node-A")
        self.assertEqual(dangling_findings[0].target_id, "node-NONEXISTENT")

    def test_planted_duplicate_id_fails_with_err_dag_duplicate_id(self) -> None:
        """Duplicate node definitions in a file must trigger ERR-DAG-DUPLICATE-ID-001."""
        with tempfile.NamedTemporaryFile("w", suffix=".jsonl", delete=False) as f:
            f.write(json.dumps({"id": "node-1", "dependencies": []}) + "\n")
            f.write(json.dumps({"id": "node-2", "dependencies": ["node-1"]}) + "\n")
            f.write(json.dumps({"id": "node-1", "dependencies": []}) + "\n")
            f_path = Path(f.name)

        try:
            is_valid, findings, summary = validate_dag_file(f_path)
            self.assertFalse(is_valid)
            dup_findings = [f for f in findings if f.code == ERR_DAG_DUPLICATE_ID]
            self.assertGreaterEqual(len(dup_findings), 1)
            self.assertEqual(dup_findings[0].node_id, "node-1")
        finally:
            f_path.unlink(missing_ok=True)

    def test_planted_missing_file_fails_with_err_dag_missing_file(self) -> None:
        """A nonexistent file path must fail closed with ERR-DAG-MISSING-FILE-001."""
        nonexistent = ROOT / "nonexistent_dag_file_12345.jsonl"
        is_valid, findings, summary = validate_dag_file(nonexistent)
        self.assertFalse(is_valid)
        missing_findings = [f for f in findings if f.code == ERR_DAG_MISSING_FILE]
        self.assertGreaterEqual(len(missing_findings), 1)

    def test_planted_corrupt_file_fails_with_err_dag_corrupt_file(self) -> None:
        """Corrupt or invalid JSON/JSONL syntax must fail closed with ERR-DAG-CORRUPT-FILE-001."""
        with tempfile.NamedTemporaryFile("w", suffix=".jsonl", delete=False) as f:
            f.write('{"id": "node-1", "dependencies": []}\n')
            f.write('INVALID JSON LINE NOT PARSEABLE <<>>\n')
            f_path = Path(f.name)

        try:
            is_valid, findings, summary = validate_dag_file(f_path)
            self.assertFalse(is_valid)
            corrupt_findings = [f for f in findings if f.code == ERR_DAG_CORRUPT_FILE]
            self.assertGreaterEqual(len(corrupt_findings), 1)
        finally:
            f_path.unlink(missing_ok=True)

    def test_planted_empty_input_fails_with_err_dag_empty_input(self) -> None:
        """Empty input with 0 nodes must fail closed with ERR-DAG-EMPTY-INPUT-001 (no vacuous success)."""
        is_valid, findings, summary = validate_generic_graph({}, source="empty_test")
        self.assertFalse(is_valid)
        empty_findings = [f for f in findings if f.code == ERR_DAG_EMPTY_INPUT]
        self.assertGreaterEqual(len(empty_findings), 1)

    def test_planted_layer_inversion_fails_with_err_dag_layer_inversion(self) -> None:
        """An upward dependency between crate layers (e.g. L0 -> L2) must trigger ERR-DAG-LAYER-INVERSION-001."""
        layers = [
            {"id": "L0", "crates": [{"name": "crate-base", "status": "implemented"}]},
            {"id": "L1", "crates": [{"name": "crate-mid", "status": "implemented"}]},
            {"id": "L2", "crates": [{"name": "crate-high", "status": "implemented"}]},
        ]
        crate_deps = {
            "crate-base": ["crate-high"],
            "crate-mid": ["crate-base"],
            "crate-high": ["crate-mid"],
        }
        from dependency_dag_checker import check_crate_layer_inversions
        inversions = check_crate_layer_inversions(layers, crate_deps)
        self.assertGreaterEqual(len(inversions), 1)
        self.assertEqual(inversions[0].code, ERR_DAG_LAYER_INVERSION)
        self.assertEqual(inversions[0].node_id, "crate-base")
        self.assertEqual(inversions[0].target_id, "crate-high")

    def test_planted_tombstone_reference_fails_with_err_dag_tombstone_reference(self) -> None:
        """An active node referencing a tombstoned dependency must fail with ERR-DAG-TOMBSTONE-REFERENCE-001."""
        nodes = {
            "issue-active": ["issue-tombstoned"],
            "issue-tombstoned": [],
        }
        node_metadata = {
            "issue-active": {"status": "open"},
            "issue-tombstoned": {"status": "tombstoned"},
        }
        is_valid, findings, summary = validate_generic_graph(
            nodes, node_metadata=node_metadata, source="tombstone_test"
        )
        self.assertFalse(is_valid)
        tomb_findings = [f for f in findings if f.code == ERR_DAG_TOMBSTONE_REFERENCE]
        self.assertGreaterEqual(len(tomb_findings), 1)
        self.assertEqual(tomb_findings[0].node_id, "issue-active")
        self.assertEqual(tomb_findings[0].target_id, "issue-tombstoned")


class TestLiveRepositoryDag(unittest.TestCase):
    """Verifies that the live repository dependency graphs are valid DAGs with 0 errors."""

    def test_live_repository_beads_dag_is_clean(self) -> None:
        """The real .beads/issues.jsonl must be a valid DAG with 0 cycles, 0 dangling refs, 0 duplicate IDs."""
        is_valid, findings, summary = validate_beads_dag(ROOT)
        self.assertTrue(
            is_valid,
            f"Beads DAG validation failed with {len(findings)} findings: {[f.message for f in findings]}",
        )
        self.assertEqual(len(findings), 0)
        self.assertEqual(summary["status"], "pass")
        self.assertGreater(summary["node_count"], 50)
        self.assertGreater(summary["edge_count"], 20)

    def test_live_repository_crate_topology_is_clean(self) -> None:
        """The real architecture/crate_topology.json and crates/*/Cargo.toml must have 0 cycles and 0 layer inversions."""
        is_valid, findings, summary = validate_crate_topology_dag(ROOT)
        self.assertTrue(
            is_valid,
            f"Crate topology validation failed with {len(findings)} findings: {[f.message for f in findings]}",
        )
        self.assertEqual(len(findings), 0)
        self.assertEqual(summary["status"], "pass")
        self.assertGreater(summary["crate_count"], 4)

    def test_validate_all_live_repository(self) -> None:
        """validate_all over the live repository must pass with status 'pass'."""
        is_valid, findings, summary = validate_all(ROOT)
        self.assertTrue(
            is_valid,
            f"validate_all failed with {len(findings)} findings: {[f.message for f in findings]}",
        )
        self.assertEqual(len(findings), 0)
        self.assertEqual(summary["status"], "pass")


class TestCliInvocation(unittest.TestCase):
    """Verifies CLI execution, exit codes, and JSON reporting format."""

    def test_cli_live_repo_passes(self) -> None:
        """Running scripts/dependency_dag_checker.py against the repo passes with exit code 0."""
        cmd = [sys.executable, str(ROOT / "scripts/dependency_dag_checker.py"), "--repo-root", str(ROOT)]
        res = subprocess.run(cmd, capture_output=True, text=True)
        self.assertEqual(res.returncode, 0, f"CLI stderr: {res.stderr}\nstdout: {res.stdout}")
        self.assertIn("[PASS]", res.stdout)

    def test_cli_json_report_conforms_to_schema(self) -> None:
        """Running with --json produces valid JSON report conforming to REPORT_SCHEMA."""
        cmd = [sys.executable, str(ROOT / "scripts/dependency_dag_checker.py"), "--json"]
        res = subprocess.run(cmd, capture_output=True, text=True)
        self.assertEqual(res.returncode, 0, f"CLI stderr: {res.stderr}\nstdout: {res.stdout}")
        data = json.loads(res.stdout)
        self.assertEqual(data["schema"], REPORT_SCHEMA)
        self.assertEqual(data["status"], "pass")
        self.assertEqual(data["error_count"], 0)
        self.assertIn("findings", data)
        self.assertIn("summary", data)

    def test_cli_file_flag_on_planted_cycle_fails_with_exit_code_1(self) -> None:
        """Running CLI on a file with a planted cycle returns exit code 1."""
        with tempfile.NamedTemporaryFile("w", suffix=".jsonl", delete=False) as f:
            f.write(json.dumps({"id": "task-1", "dependencies": ["task-2"]}) + "\n")
            f.write(json.dumps({"id": "task-2", "dependencies": ["task-1"]}) + "\n")
            f_path = Path(f.name)

        try:
            cmd = [sys.executable, str(ROOT / "scripts/dependency_dag_checker.py"), "--file", str(f_path)]
            res = subprocess.run(cmd, capture_output=True, text=True)
            self.assertEqual(res.returncode, 1)
            self.assertIn(ERR_DAG_CYCLE, res.stdout + res.stderr)
        finally:
            f_path.unlink(missing_ok=True)


if __name__ == "__main__":
    unittest.main()
