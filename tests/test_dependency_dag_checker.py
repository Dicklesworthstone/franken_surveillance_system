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
12. (review-591) Cycle enumeration is exact and deterministic: every elementary cycle, including
    self-loops, 2-cycles, long cycles, and cycles mixing beads edge kinds (blocks, conditional-blocks,
    waits-for, and parent-child oriented parent -> child as br's blocking graph does).
13. (review-591) validate_beads_dag and validate_crate_topology_dag reject dangling, undeclared,
    duplicate, unknown-kind, unreadable, empty, partial, and schema-violating input with typed codes;
    layer inversions can only be waived in the registry and stay visible as warnings.
"""
from __future__ import annotations

import ast
import itertools
import json
import os
import random
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
import dependency_dag_checker as ddc


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
        # The only permitted finding is the registry-declared fss-cli -> fss-reference
        # waiver, which must stay visible as a warning (review-591 finding 10).
        self.assertEqual(
            [(f.code, f.severity, f.node_id, f.target_id) for f in findings],
            [(ddc.WARN_DAG_LAYER_INVERSION_WAIVED, "warning", "fss-cli", "fss-reference")],
        )
        self.assertEqual(summary["status"], "pass")
        self.assertEqual(summary["error_count"], 0)
        self.assertTrue(summary["complete"])
        self.assertGreater(summary["crate_count"], 4)

    def test_validate_all_live_repository(self) -> None:
        """validate_all over the live repository must pass with status 'pass'."""
        is_valid, findings, summary = validate_all(ROOT)
        self.assertTrue(
            is_valid,
            f"validate_all failed with {len(findings)} findings: {[f.message for f in findings]}",
        )
        self.assertEqual([f for f in findings if f.severity == "error"], [])
        self.assertEqual([f.code for f in findings], [ddc.WARN_DAG_LAYER_INVERSION_WAIVED])
        self.assertEqual(summary["status"], "pass")
        self.assertTrue(summary["complete"])


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


# ---------------------------------------------------------------------------
# review-591 regression suite.  Every test below was written before the fix and
# observed failing against d09644e; names map 1:1 onto review-591 findings.
# ---------------------------------------------------------------------------

CHECKER = ROOT / "scripts/dependency_dag_checker.py"


def _codes(findings) -> list[str]:
    return [f.code for f in findings]


def _issue(issue_id: str, deps=(), status: str = "open") -> dict:
    return {
        "id": issue_id,
        "status": status,
        "dependencies": [
            {"issue_id": issue_id, "depends_on_id": target, "type": kind} for target, kind in deps
        ],
    }


def _write_beads(repo: Path, rows, trailing_newline: bool = True) -> Path:
    (repo / ".beads").mkdir(exist_ok=True)
    path = repo / ".beads/issues.jsonl"
    text = "\n".join(json.dumps(r) if not isinstance(r, str) else r for r in rows)
    if rows and trailing_newline:
        text += "\n"
    path.write_text(text, encoding="utf-8")
    return path


def _crate_repo(repo: Path, layers, manifests: dict[str, str], extra_topology: dict | None = None) -> None:
    """Build a synthetic repo: architecture/crate_topology.json + crates/<dir>/Cargo.toml."""
    (repo / "architecture").mkdir(exist_ok=True)
    doc = {"layers": layers}
    if extra_topology:
        doc.update(extra_topology)
    (repo / "architecture/crate_topology.json").write_text(json.dumps(doc), encoding="utf-8")
    (repo / "crates").mkdir(exist_ok=True)
    for dirname, text in manifests.items():
        (repo / "crates" / dirname).mkdir(exist_ok=True)
        (repo / "crates" / dirname / "Cargo.toml").write_text(text, encoding="utf-8")


def _manifest(name: str, deps: dict[str, str] | None = None, table: str = "dependencies") -> str:
    lines = [f'[package]\nname = "{name}"\n']
    if deps:
        lines.append(f"[{table}]\n")
        for key, spec in deps.items():
            lines.append(f"{key} = {spec}\n")
    return "".join(lines)


def _layers(*layer_crates: list[str]) -> list[dict]:
    return [
        {"id": f"L{i}", "crates": [{"name": c, "status": "implemented", "unsafe": "forbid"} for c in crates]}
        for i, crates in enumerate(layer_crates)
    ]


def _count_elementary_cycles_complete_digraph(n: int) -> int:
    # sum_{k=2..n} C(n,k) * (k-1)!  (self-loops excluded)
    from math import comb, factorial

    return sum(comb(n, k) * factorial(k - 1) for k in range(2, n + 1))


class TestReview591Finding1ExactCycleEnumeration(unittest.TestCase):
    def test_f1_find_cycles_detects_all_intersecting_elementary_cycles(self) -> None:
        graph = {"B": ["C", "E"], "C": ["D"], "D": ["B"], "E": ["D"]}
        self.assertEqual(ddc.find_cycles(graph), [["B", "C", "D", "B"], ["B", "E", "D", "B"]])

    def test_f1_find_cycles_exact_count_on_complete_digraph(self) -> None:
        for n in (3, 4, 5):
            nodes = [f"n{i}" for i in range(n)]
            graph = {u: [v for v in nodes if v != u] for u in nodes}
            cycles = ddc.find_cycles(graph)
            self.assertEqual(len(cycles), _count_elementary_cycles_complete_digraph(n))
            self.assertEqual(len({tuple(c) for c in cycles}), len(cycles), "duplicate cycles reported")
            for c in cycles:
                self.assertEqual(c[0], c[-1])
                self.assertEqual(c[0], min(c[:-1]), "cycle not rotated to canonical start")
                self.assertEqual(len(set(c[:-1])), len(c) - 1, "non-elementary cycle reported")

    def test_f1_find_cycles_two_cycle_and_long_cycle(self) -> None:
        self.assertEqual(ddc.find_cycles({"a": ["b"], "b": ["a"]}), [["a", "b", "a"]])
        n = 5000  # deep enough to break any recursive DFS
        nodes = [f"x{i:05d}" for i in range(n)]
        graph = {nodes[i]: [nodes[(i + 1) % n]] for i in range(n)}
        cycles = ddc.find_cycles(graph)
        self.assertEqual(len(cycles), 1)
        self.assertEqual(cycles[0], nodes + [nodes[0]])

    def test_f1_find_cycles_is_deterministic_under_input_permutation(self) -> None:
        base = {
            "a": ["b", "d"], "b": ["c", "a"], "c": ["a", "e"], "d": ["c"], "e": ["e", "b"], "f": ["a"],
        }
        expected = ddc.find_cycles(base)
        rng = random.Random(591)
        for _ in range(25):
            keys = list(base)
            rng.shuffle(keys)
            shuffled = {k: rng.sample(base[k], len(base[k])) for k in keys}
            self.assertEqual(ddc.find_cycles(shuffled), expected)
        self.assertEqual(expected, sorted(expected, key=lambda c: (len(c), c)))

    def test_f1_validate_generic_graph_reports_every_elementary_cycle(self) -> None:
        graph = {"B": ["C", "E"], "C": ["D"], "D": ["B"], "E": ["D"]}
        ok, findings, summary = validate_generic_graph(graph, source="t")
        self.assertFalse(ok)
        paths = [f.cycle_path for f in findings if f.code == ERR_DAG_CYCLE]
        self.assertEqual(paths, [["B", "C", "D", "B"], ["B", "E", "D", "B"]])
        self.assertEqual(summary["cycle_count"], 2)
        self.assertTrue(summary["cycle_enumeration_complete"])

    def test_f1_bounded_enumeration_reports_incompleteness_not_success(self) -> None:
        nodes = [f"n{i}" for i in range(7)]
        graph = {u: [v for v in nodes if v != u] for u in nodes}
        ok, findings, summary = validate_generic_graph(graph, source="t", cycle_limit=50)
        self.assertFalse(ok)
        self.assertFalse(summary["cycle_enumeration_complete"])
        incomplete = [f for f in findings if f.code == ddc.ERR_DAG_CYCLE_ENUMERATION_INCOMPLETE]
        self.assertEqual(len(incomplete), 1)
        self.assertEqual(incomplete[0].cycle_path, sorted(nodes))
        self.assertEqual(len([f for f in findings if f.code == ERR_DAG_CYCLE]), 50)


class TestReview591Finding3SelfLoops(unittest.TestCase):
    def test_f3_find_cycles_includes_self_loop(self) -> None:
        self.assertEqual(ddc.find_cycles({"A": ["A"]}), [["A", "A"]])

    def test_f3_self_loop_summary_is_consistent(self) -> None:
        ok, findings, summary = validate_generic_graph({"A": ["A"]}, source="t")
        self.assertFalse(ok)
        self.assertEqual(_codes(findings), [ERR_DAG_SELF_DEPENDENCY])
        self.assertEqual(summary["cycle_count"], 1)
        self.assertEqual(summary["self_dependency_count"], 1)


class TestReview591Finding2BeadsEdgeKinds(unittest.TestCase):
    def _run(self, rows, **kw):
        with tempfile.TemporaryDirectory() as tmp:
            repo = Path(tmp)
            _write_beads(repo, rows, **kw)
            return validate_beads_dag(repo)

    def test_f2_parent_child_cycle_rejected(self) -> None:
        ok, findings, _ = self._run([
            _issue("task-A", [("task-B", "parent-child")]),
            _issue("task-B", [("task-A", "parent-child")]),
        ])
        self.assertFalse(ok)
        self.assertIn(ERR_DAG_CYCLE, _codes(findings))

    def test_f2_parent_child_self_loop_rejected(self) -> None:
        ok, findings, _ = self._run([_issue("task-A", [("task-A", "parent-child")])])
        self.assertFalse(ok)
        self.assertIn(ERR_DAG_SELF_DEPENDENCY, _codes(findings))

    def test_f2_parent_child_dangling_rejected(self) -> None:
        ok, findings, _ = self._run([_issue("task-C", [("GHOST-PARENT", "parent-child")])])
        self.assertFalse(ok)
        dangling = [f for f in findings if f.code == ERR_DAG_DANGLING_REFERENCE]
        self.assertEqual([(f.node_id, f.target_id) for f in dangling], [("task-C", "GHOST-PARENT")])

    def test_f2_mixed_blocks_and_parent_child_cycle_rejected(self) -> None:
        # child waits on parent via `blocks`, parent waits on child via hierarchy -> deadlock.
        ok, findings, _ = self._run([
            _issue("epic"),
            _issue("child", [("epic", "parent-child"), ("epic", "blocks")]),
        ])
        self.assertFalse(ok)
        cyc = [f for f in findings if f.code == ERR_DAG_CYCLE]
        self.assertEqual([f.cycle_path for f in cyc], [["child", "epic", "child"]])
        self.assertIn("blocks", cyc[0].message)
        self.assertIn("parent-child", cyc[0].message)

    def test_f2_epic_blocked_by_its_children_is_not_a_false_cycle(self) -> None:
        # br orients parent-child as parent -> child in the blocking graph, so an
        # epic that `blocks`-depends on its own children is consistent.
        ok, findings, summary = self._run([
            _issue("epic", [("c1", "blocks"), ("c2", "blocks")]),
            _issue("c1", [("epic", "parent-child")]),
            _issue("c2", [("epic", "parent-child"), ("c1", "blocks")]),
        ])
        self.assertTrue(ok, [f.message for f in findings])
        self.assertEqual(summary["edge_count"], 5)

    def test_f2_conditional_blocks_and_waits_for_cycles_rejected(self) -> None:
        ok, findings, _ = self._run([
            _issue("a", [("b", "conditional-blocks")]),
            _issue("b", [("c", "waits-for")]),
            _issue("c", [("a", "blocks")]),
        ])
        self.assertFalse(ok)
        self.assertEqual([f.cycle_path for f in findings if f.code == ERR_DAG_CYCLE], [["a", "b", "c", "a"]])

    def test_f2_non_blocking_edges_checked_for_dangling_and_self_but_not_cycles(self) -> None:
        ok, findings, summary = self._run([
            _issue("a", [("b", "related")]),
            _issue("b", [("a", "related"), ("a", "discovered-from")]),
        ])
        self.assertTrue(ok, [f.message for f in findings])
        self.assertEqual(summary["edge_count"], 3)
        ok, findings, _ = self._run([_issue("a", [("ghost", "related")])])
        self.assertFalse(ok)
        self.assertIn(ERR_DAG_DANGLING_REFERENCE, _codes(findings))
        ok, findings, _ = self._run([_issue("a", [("a", "related")])])
        self.assertFalse(ok)
        self.assertIn(ERR_DAG_SELF_DEPENDENCY, _codes(findings))

    def test_f2_unknown_edge_kind_fails_closed(self) -> None:
        ok, findings, _ = self._run([_issue("a"), _issue("b", [("a", "maybe-blocks")])])
        self.assertFalse(ok)
        self.assertIn(ddc.ERR_DAG_UNKNOWN_EDGE_KIND, _codes(findings))

    def test_f2_edge_counts_cover_every_kind(self) -> None:
        ok, findings, summary = self._run([
            _issue("p"),
            _issue("a", [("p", "parent-child"), ("b", "related")]),
            _issue("b", [("p", "parent-child"), ("a", "blocks")]),
        ])
        self.assertTrue(ok, [f.message for f in findings])
        self.assertEqual(summary["edge_count"], 4)
        self.assertEqual(summary["edge_kind_counts"], {"blocks": 1, "parent-child": 2, "related": 1})


class TestReview591BeadsInputIntegrity(unittest.TestCase):
    """Other fail-open paths in validate_beads_dag found while fixing review-591."""

    def _run_text(self, text: str | bytes):
        with tempfile.TemporaryDirectory() as tmp:
            repo = Path(tmp)
            (repo / ".beads").mkdir()
            path = repo / ".beads/issues.jsonl"
            if isinstance(text, bytes):
                path.write_bytes(text)
            else:
                path.write_text(text, encoding="utf-8")
            return validate_beads_dag(repo)

    def test_beads_duplicate_id_rejected_and_both_definitions_checked(self) -> None:
        rows = [
            _issue("a", [("b", "blocks")]),
            _issue("b"),
            _issue("a"),  # later duplicate must not erase the first definition's edges
            _issue("c", [("a", "blocks")]),
        ]
        rows[1] = _issue("b", [("a", "blocks")])
        ok, findings, _ = self._run_text("\n".join(json.dumps(r) for r in rows) + "\n")
        self.assertFalse(ok)
        self.assertIn(ERR_DAG_DUPLICATE_ID, _codes(findings))
        self.assertIn(ERR_DAG_CYCLE, _codes(findings))

    def test_beads_empty_file_rejected(self) -> None:
        ok, findings, _ = self._run_text("")
        self.assertFalse(ok)
        self.assertEqual(_codes(findings), [ERR_DAG_EMPTY_INPUT])

    def test_beads_truncated_final_record_rejected(self) -> None:
        ok, findings, _ = self._run_text(json.dumps(_issue("a")) + "\n" + json.dumps(_issue("b")))
        self.assertFalse(ok)
        self.assertEqual(_codes(findings), [ERR_DAG_CORRUPT_FILE])

    def test_beads_invalid_utf8_is_typed_corrupt_not_a_crash(self) -> None:
        ok, findings, _ = self._run_text(b'{"id": "a\xff\xfe"}\n')
        self.assertFalse(ok)
        self.assertEqual(_codes(findings), [ERR_DAG_CORRUPT_FILE])

    def test_beads_malformed_dependency_entries_rejected(self) -> None:
        bad_rows = [
            {"id": "a", "dependencies": "b"},  # non-list
            {"id": "a", "dependencies": [{"issue_id": "a", "type": "blocks"}]},  # no depends_on_id
            {"id": "a", "dependencies": [{"issue_id": "a", "depends_on_id": "b"}]},  # no type
            {"id": "a", "dependencies": [{"issue_id": "zzz", "depends_on_id": "b", "type": "blocks"}]},  # owner mismatch
            {"id": "a", "dependencies": ["b"]},  # non-object entry
            {"id": "", "dependencies": []},  # empty id
            {"id": 7, "dependencies": []},  # non-string id
        ]
        for row in bad_rows:
            with self.subTest(row=row):
                text = json.dumps(row) + "\n" + json.dumps(_issue("b")) + "\n"
                ok, findings, _ = self._run_text(text)
                self.assertFalse(ok)
                self.assertIn(ERR_DAG_CORRUPT_FILE, _codes(findings))

    def test_beads_duplicate_json_key_rejected(self) -> None:
        ok, findings, _ = self._run_text('{"id": "a", "id": "b"}\n')
        self.assertFalse(ok)
        self.assertIn(ERR_DAG_DUPLICATE_ID, _codes(findings))

    def test_beads_unreadable_file_typed(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            repo = Path(tmp)
            path = _write_beads(repo, [_issue("a")])
            os.chmod(path, 0)
            try:
                if os.access(path, os.R_OK):
                    self.skipTest("running with privileges that bypass file modes")
                ok, findings, _ = validate_beads_dag(repo)
            finally:
                os.chmod(path, 0o644)
        self.assertFalse(ok)
        self.assertEqual(_codes(findings), [ddc.ERR_DAG_UNREADABLE_FILE])


class TestReview591CrateTopology(unittest.TestCase):
    def _run(self, layers, manifests, extra=None):
        with tempfile.TemporaryDirectory() as tmp:
            repo = Path(tmp)
            _crate_repo(repo, layers, manifests, extra)
            return validate_crate_topology_dag(repo)

    def test_f4_undeclared_crate_dependency_rejected(self) -> None:
        ok, findings, _ = self._run(
            [{"id": "L0", "crates": [{"name": "fss-core"}]}],
            {"fss-core": _manifest("fss-core", {"fss-phantom": '{ path = "../fss-phantom" }'})},
        )
        self.assertFalse(ok)
        dangling = [f for f in findings if f.code == ERR_DAG_DANGLING_REFERENCE]
        self.assertEqual([(f.node_id, f.target_id) for f in dangling], [("fss-core", "fss-phantom")])

    def test_f4_declared_but_absent_crate_dependency_rejected(self) -> None:
        ok, findings, _ = self._run(
            _layers(["fss-core", "fss-types"]),
            {"fss-core": _manifest("fss-core", {"fss-types": '{ path = "../fss-types" }'})},
        )
        self.assertFalse(ok)
        self.assertIn(ERR_DAG_DANGLING_REFERENCE, _codes(findings))

    def test_f4_renamed_dependency_resolved_by_package_name(self) -> None:
        ok, findings, _ = self._run(
            _layers(["fss-core"], ["fss-cli"]),
            {
                "fss-core": _manifest("fss-core", {"cli": '{ package = "fss-cli", path = "../fss-cli" }'}),
                "fss-cli": _manifest("fss-cli", {"fss-core": '{ path = "../fss-core" }'}),
            },
        )
        self.assertFalse(ok)
        self.assertIn(ERR_DAG_CYCLE, _codes(findings))
        self.assertIn(ERR_DAG_LAYER_INVERSION, _codes(findings))

    def test_f4_every_dependency_table_is_an_edge(self) -> None:
        for table in ("build-dependencies", "dev-dependencies", "target.'cfg(unix)'.dependencies"):
            with self.subTest(table=table):
                ok, findings, _ = self._run(
                    _layers(["fss-core"], ["fss-cli"]),
                    {
                        "fss-core": _manifest("fss-core", {"fss-cli": '{ path = "../fss-cli" }'}, table=table),
                        "fss-cli": _manifest("fss-cli"),
                    },
                )
                self.assertFalse(ok)
                self.assertIn(ERR_DAG_LAYER_INVERSION, _codes(findings))

    def test_f4_crate_on_disk_not_declared_in_topology_rejected(self) -> None:
        ok, findings, _ = self._run(
            _layers(["fss-core"]),
            {"fss-core": _manifest("fss-core"), "fss-rogue": _manifest("fss-rogue", {"fss-core": '{ path = "../fss-core" }'})},
        )
        self.assertFalse(ok)
        self.assertIn(ddc.ERR_DAG_UNDECLARED_NODE, _codes(findings))

    def test_f4_external_registry_dependency_is_not_dangling(self) -> None:
        ok, findings, _ = self._run(
            _layers(["fss-core"]),
            {"fss-core": _manifest("fss-core", {"serde": '"1"'})},
        )
        self.assertTrue(ok, [f.message for f in findings])

    def test_f5_empty_layers_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            repo = Path(tmp)
            (repo / "architecture").mkdir()
            (repo / "architecture/crate_topology.json").write_text(json.dumps({"layers": []}))
            # A real crate on disk: the vacuous hierarchy must not silently pass it.
            (repo / "crates/fss-core").mkdir(parents=True)
            (repo / "crates/fss-core/Cargo.toml").write_text(_manifest("fss-core"))
            ok, findings, _ = validate_crate_topology_dag(repo)
        self.assertFalse(ok)
        self.assertIn(ERR_DAG_EMPTY_INPUT, _codes(findings))

    def test_f8_corrupt_cargo_manifest_fails_and_marks_check_incomplete(self) -> None:
        ok, findings, summary = self._run(
            _layers(["fss-core"], ["fss-cli"]),
            {"fss-core": _manifest("fss-core"), "fss-cli": "[package\nname = broken"},
        )
        self.assertFalse(ok)
        self.assertIn(ERR_DAG_CORRUPT_FILE, _codes(findings))
        self.assertFalse(summary["complete"])

    def test_f8_invalid_layer_id_is_corrupt_not_layer_999(self) -> None:
        layers = [
            {"id": "L0", "crates": [{"name": "fss-core"}]},
            {"id": "top", "crates": [{"name": "fss-cli"}]},
        ]
        ok, findings, _ = self._run(
            layers,
            {"fss-core": _manifest("fss-core"), "fss-cli": _manifest("fss-cli")},
        )
        self.assertFalse(ok)
        self.assertIn(ERR_DAG_CORRUPT_FILE, _codes(findings))

    def test_f8_malformed_topology_entries_are_typed_not_crashes(self) -> None:
        bad_layer_sets = [
            [{"id": "L0", "crates": ["fss-core"]}],  # non-object crate
            [{"id": "L0", "crates": [{"status": "implemented"}]}],  # nameless crate
            ["L0"],  # non-object layer
            [{"id": "L0", "crates": [{"name": "fss-core"}]}, {"id": "L0", "crates": [{"name": "fss-cli"}]}],  # dup layer
            [{"id": "L0", "crates": "fss-core"}],  # non-list crates
        ]
        for layers in bad_layer_sets:
            with self.subTest(layers=layers):
                ok, findings, _ = self._run(layers, {"fss-core": _manifest("fss-core")})
                self.assertFalse(ok)
                self.assertTrue(
                    {ERR_DAG_CORRUPT_FILE, ERR_DAG_DUPLICATE_ID} & set(_codes(findings)), _codes(findings)
                )

    def test_f9_full_topology_cycle_detected_through_validate_crate_topology_dag(self) -> None:
        ok, findings, _ = self._run(
            _layers(["crate-base"], ["crate-mid"], ["crate-high"]),
            {
                "crate-base": _manifest("crate-base", {"crate-high": '{ path = "../crate-high" }'}),
                "crate-mid": _manifest("crate-mid", {"crate-base": '{ path = "../crate-base" }'}),
                "crate-high": _manifest("crate-high", {"crate-mid": '{ path = "../crate-mid" }'}),
            },
        )
        self.assertFalse(ok)
        cycles = [f.cycle_path for f in findings if f.code == ERR_DAG_CYCLE]
        self.assertEqual(cycles, [["crate-base", "crate-high", "crate-mid", "crate-base"]])
        self.assertIn(ERR_DAG_LAYER_INVERSION, _codes(findings))

    def test_f10_no_hardcoded_waiver_upward_edge_fails_without_registry_waiver(self) -> None:
        source = CHECKER.read_text(encoding="utf-8")
        self.assertNotIn("ALLOWED_REHEARSAL_EDGES", source)
        self.assertNotIn('("fss-cli", "fss-reference")', source)
        ok, findings, _ = self._run(
            _layers(["fss-core"], ["fss-cli"], ["fss-reference"]),
            {
                "fss-core": _manifest("fss-core"),
                "fss-cli": _manifest("fss-cli", {"fss-reference": '{ path = "../fss-reference" }'}),
                "fss-reference": _manifest("fss-reference", {"fss-core": '{ path = "../fss-core" }'}),
            },
        )
        self.assertFalse(ok)
        inv = [f for f in findings if f.code == ERR_DAG_LAYER_INVERSION]
        self.assertEqual([(f.node_id, f.target_id) for f in inv], [("fss-cli", "fss-reference")])

    def test_f10_registry_waiver_is_reported_as_warning_not_hidden(self) -> None:
        layers = _layers(["fss-core"], ["fss-cli"], ["fss-reference"])
        manifests = {
            "fss-core": _manifest("fss-core"),
            "fss-cli": _manifest("fss-cli", {"fss-reference": '{ path = "../fss-reference" }'}),
            "fss-reference": _manifest("fss-reference"),
        }
        waiver = {"layerWaivers": [{"from": "fss-cli", "to": "fss-reference", "reason": "rehearsal harness"}]}
        ok, findings, summary = self._run(layers, manifests, waiver)
        self.assertTrue(ok, [f.message for f in findings])
        self.assertEqual(_codes(findings), [ddc.WARN_DAG_LAYER_INVERSION_WAIVED])
        self.assertEqual(summary["warning_count"], 1)
        self.assertEqual(summary["waived_inversions"], [["fss-cli", "fss-reference"]])

    def test_f10_stale_or_malformed_waivers_rejected(self) -> None:
        layers = _layers(["fss-core"], ["fss-cli"])
        manifests = {"fss-core": _manifest("fss-core"), "fss-cli": _manifest("fss-cli", {"fss-core": '{ path = "../fss-core" }'})}
        cases = [
            ({"layerWaivers": [{"from": "fss-core", "to": "fss-cli", "reason": "no such edge"}]}, ddc.ERR_DAG_STALE_WAIVER),
            ({"layerWaivers": [{"from": "fss-cli", "to": "fss-core", "reason": "edge is downward"}]}, ddc.ERR_DAG_STALE_WAIVER),
            ({"layerWaivers": [{"from": "fss-cli", "to": "fss-core"}]}, ERR_DAG_CORRUPT_FILE),
            ({"layerWaivers": {"from": "fss-cli"}}, ERR_DAG_CORRUPT_FILE),
        ]
        for extra, code in cases:
            with self.subTest(extra=extra):
                ok, findings, _ = self._run(layers, manifests, extra)
                self.assertFalse(ok)
                self.assertIn(code, _codes(findings))


class TestReview591GenericFiles(unittest.TestCase):
    def _json_file(self, content: str, suffix: str = ".json"):
        tmp = tempfile.NamedTemporaryFile("w", suffix=suffix, delete=False, encoding="utf-8")
        tmp.write(content)
        tmp.close()
        self.addCleanup(lambda: Path(tmp.name).unlink(missing_ok=True))
        return Path(tmp.name)

    def test_f6_arbitrary_json_object_fails_closed(self) -> None:
        path = self._json_file(json.dumps({"service": "franken-surveillance", "version": "1.0"}))
        ok, findings, _ = validate_dag_file(path)
        self.assertFalse(ok)
        self.assertEqual(_codes(findings), [ERR_DAG_CORRUPT_FILE])

    def test_f6_non_list_or_non_string_dependencies_fail_closed(self) -> None:
        bad = [
            {"nodes": {"a": "b"}},
            {"nodes": {"a": [1]}},
            {"nodes": [{"id": "a", "dependencies": "b"}]},
            {"nodes": [{"id": 5, "dependencies": []}]},
            {"nodes": [{"id": "a", "dependencies": [{"weird": "x"}]}]},
            [{"id": "a", "dependencies": {"b": 1}}],
        ]
        for doc in bad:
            with self.subTest(doc=doc):
                ok, findings, _ = validate_dag_file(self._json_file(json.dumps(doc)))
                self.assertFalse(ok)
                self.assertIn(ERR_DAG_CORRUPT_FILE, _codes(findings))

    def test_f6_duplicate_json_keys_rejected(self) -> None:
        path = self._json_file('{"nodes": {"a": [], "a": ["b"]}}')
        ok, findings, _ = validate_dag_file(path)
        self.assertFalse(ok)
        self.assertIn(ERR_DAG_DUPLICATE_ID, _codes(findings))

    def test_f6_list_form_dependency_objects_are_resolved(self) -> None:
        path = self._json_file(json.dumps([
            {"id": "a", "dependencies": [{"depends_on_id": "b"}]},
            {"id": "b", "dependencies": [{"id": "a"}]},
        ]))
        ok, findings, _ = validate_dag_file(path)
        self.assertFalse(ok)
        self.assertEqual([f.cycle_path for f in findings if f.code == ERR_DAG_CYCLE], [["a", "b", "a"]])

    def test_f7_unreadable_json_and_jsonl_are_typed_unreadable(self) -> None:
        for suffix, content in ((".json", '{"nodes": []}'), (".jsonl", '{"id": "a"}\n')):
            with self.subTest(suffix=suffix):
                path = self._json_file(content, suffix)
                os.chmod(path, 0)
                try:
                    if os.access(path, os.R_OK):
                        self.skipTest("running with privileges that bypass file modes")
                    ok, findings, _ = validate_dag_file(path)
                finally:
                    os.chmod(path, 0o644)
                self.assertFalse(ok)
                self.assertEqual(_codes(findings), [ddc.ERR_DAG_UNREADABLE_FILE])

    def test_empty_json_and_jsonl_files_are_typed_empty(self) -> None:
        for suffix, content in ((".json", ""), (".json", "  \n"), (".jsonl", ""), (".json", '{"nodes": []}')):
            with self.subTest(suffix=suffix, content=content):
                ok, findings, _ = validate_dag_file(self._json_file(content, suffix))
                self.assertFalse(ok)
                self.assertEqual(_codes(findings), [ERR_DAG_EMPTY_INPUT])

    def test_invalid_utf8_json_is_typed_corrupt(self) -> None:
        path = self._json_file("", ".json")
        path.write_bytes(b'{"nodes": [{"id": "\xff"}]}')
        ok, findings, _ = validate_dag_file(path)
        self.assertFalse(ok)
        self.assertEqual(_codes(findings), [ERR_DAG_CORRUPT_FILE])


class TestReview591ExceptionHygiene(unittest.TestCase):
    def test_f8_no_broad_exception_handlers_in_checker(self) -> None:
        tree = ast.parse(CHECKER.read_text(encoding="utf-8"))
        broad = []
        for node in ast.walk(tree):
            if isinstance(node, ast.ExceptHandler):
                names = []
                if node.type is None:
                    names = ["<bare>"]
                elif isinstance(node.type, ast.Name):
                    names = [node.type.id]
                elif isinstance(node.type, ast.Tuple):
                    names = [e.id for e in node.type.elts if isinstance(e, ast.Name)]
                if {"<bare>", "Exception", "BaseException"} & set(names):
                    broad.append(node.lineno)
        self.assertEqual(broad, [], f"broad exception handlers at lines {broad}")


class TestReview591CliExitCodes(unittest.TestCase):
    def _cli(self, *args: str):
        return subprocess.run([sys.executable, str(CHECKER), *args], capture_output=True, text=True)

    def test_f9_usage_errors_exit_2(self) -> None:
        self.assertEqual(self._cli("--no-such-flag").returncode, 2)
        with tempfile.TemporaryDirectory() as tmp:
            res = self._cli("--file", str(Path(tmp) / "x.jsonl"), "--repo-root", tmp)
        self.assertEqual(res.returncode, 2, res.stderr)

    def test_every_planted_input_defect_exits_nonzero_with_typed_code(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            d = Path(tmp)
            cases = {
                "missing.jsonl": (None, ERR_DAG_MISSING_FILE),
                "empty.jsonl": ("", ERR_DAG_EMPTY_INPUT),
                "corrupt.json": ("{not json", ERR_DAG_CORRUPT_FILE),
                "bogus.json": (json.dumps({"port": 8080}), ERR_DAG_CORRUPT_FILE),
                "dangling.jsonl": (json.dumps({"id": "a", "dependencies": ["ghost"]}) + "\n", ERR_DAG_DANGLING_REFERENCE),
                "dup.jsonl": ((json.dumps({"id": "a"}) + "\n") * 2, ERR_DAG_DUPLICATE_ID),
                "self.jsonl": (json.dumps({"id": "a", "dependencies": ["a"]}) + "\n", ERR_DAG_SELF_DEPENDENCY),
            }
            for name, (content, code) in cases.items():
                path = d / name
                if content is not None:
                    path.write_text(content, encoding="utf-8")
                with self.subTest(name=name):
                    res = self._cli("--file", str(path), "--json")
                    self.assertEqual(res.returncode, 1, res.stdout + res.stderr)
                    report = json.loads(res.stdout)
                    self.assertEqual(report["status"], "fail")
                    self.assertIn(code, [f["code"] for f in report["findings"]])

    def test_strict_mode_fails_on_waived_inversion_warning(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            repo = Path(tmp)
            _write_beads(repo, [_issue("a"), _issue("b", [("a", "blocks")])])
            _crate_repo(
                repo,
                _layers(["fss-core"], ["fss-cli"], ["fss-reference"]),
                {
                    "fss-core": _manifest("fss-core"),
                    "fss-cli": _manifest("fss-cli", {"fss-reference": '{ path = "../fss-reference" }'}),
                    "fss-reference": _manifest("fss-reference"),
                },
                {"layerWaivers": [{"from": "fss-cli", "to": "fss-reference", "reason": "rehearsal"}]},
            )
            relaxed = self._cli("--repo-root", tmp, "--json")
            strict = self._cli("--repo-root", tmp, "--json", "--strict")
        self.assertEqual(relaxed.returncode, 0, relaxed.stdout + relaxed.stderr)
        self.assertEqual(json.loads(relaxed.stdout)["warning_count"], 1)
        self.assertEqual(strict.returncode, 1, strict.stdout)


class TestReview591LiveRepositoryPlausibility(unittest.TestCase):
    def test_f10_live_beads_edge_count_covers_every_dependency_row(self) -> None:
        expected: dict[str, int] = {}
        with open(ROOT / ".beads/issues.jsonl", encoding="utf-8") as fh:
            for line in fh:
                if line.strip():
                    for dep in json.loads(line).get("dependencies") or []:
                        expected[dep["type"]] = expected.get(dep["type"], 0) + 1
        ok, findings, summary = validate_beads_dag(ROOT)
        self.assertTrue(ok, [f.message for f in findings])
        self.assertEqual(summary["edge_kind_counts"], dict(sorted(expected.items())))
        self.assertEqual(summary["edge_count"], sum(expected.values()))


if __name__ == "__main__":
    unittest.main()
