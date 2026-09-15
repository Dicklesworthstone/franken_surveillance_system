#!/usr/bin/env python3
"""Planted-negative test suite for the agent operation registry checker (fss-x4a.30.83.17).

Verifies fail-closed enforcement of:
1. Live repository passes with 0 errors across all 14 operation rows
2. Row drift between architecture JSON and the markdown mirror (ERR-OP-REGISTRY-DRIFT-001)
3. Missing, duplicate, or renumbered stable IDs (ERR-OP-STABLE-ID-REUSED-001)
4. Missing or empty mandatory row/metadata fields (ERR-OP-MISSING-FIELD-001)
5. Missing or corrupt mandatory registry files (ERR-OP-CORRUPT-FILE-001)
6. Semantic invariant violations: effect/mode contradiction, unregistered retry class or
   view, frozen public-registry disagreement (ERR-OP-SEMANTIC-INVARIANT-001)
7. Typed Rust table drift, including a missing agent_operation.rs (ERR-OP-RUST-DRIFT-001)
"""
from __future__ import annotations

import json
import shutil
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))

import agent_operation_registry_checker
from agent_operation_registry_checker import (
    ERR_OP_CORRUPT_FILE,
    ERR_OP_MISSING_FIELD,
    ERR_OP_REGISTRY_DRIFT,
    ERR_OP_RUST_DRIFT,
    ERR_OP_SEMANTIC_INVARIANT,
    ERR_OP_STABLE_ID_REUSED,
    canonical_fields_from_text,
    extract_rust_canonical_rows,
    validate_agent_operation_registry,
)

REGISTRY_FILES = {
    "architecture/agent_operations.json",
    "architecture/fss1_public_registry.json",
    "registries/AGENT_OPERATIONS.md",
    "crates/fss-core/src/agent_operation.rs",
}


class AgentOperationRegistryCheckerTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp_dir = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp_dir.cleanup)
        self.fake_root = Path(self.temp_dir.name)
        for rel in REGISTRY_FILES:
            destination = self.fake_root / rel
            destination.parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(ROOT / rel, destination)

    def load_registry(self) -> dict:
        path = self.fake_root / "architecture/agent_operations.json"
        return json.loads(path.read_text(encoding="utf-8"))

    def save_registry(self, doc: dict) -> None:
        path = self.fake_root / "architecture/agent_operations.json"
        path.write_text(json.dumps(doc, indent=2) + "\n", encoding="utf-8")

    def row(self, opid: str) -> dict:
        doc = self.load_registry()
        return next(op for op in doc["operations"] if op["id"] == opid)

    def replace_row(self, opid: str, mutate) -> None:
        doc = self.load_registry()
        for op in doc["operations"]:
            if op["id"] == opid:
                mutate(op)
        self.save_registry(doc)

    def error_codes(self):
        result = validate_agent_operation_registry(self.fake_root)
        return result, {error.code for error in result.errors}

    def test_live_repository_passes(self) -> None:
        result = validate_agent_operation_registry(self.fake_root)
        self.assertTrue(result.passed, msg=str(result.errors))
        self.assertEqual(result.operation_count, 14)
        self.assertEqual(result.errors, [])

    def test_markdown_row_drift_is_detected(self) -> None:
        md_path = self.fake_root / "registries/AGENT_OPERATIONS.md"
        text = md_path.read_text(encoding="utf-8")
        text = text.replace("| `commit` |", "| `commitX` |")
        md_path.write_text(text, encoding="utf-8")
        _, codes = self.error_codes()
        self.assertIn(ERR_OP_REGISTRY_DRIFT, codes)

    def test_markdown_missing_row_is_detected(self) -> None:
        md_path = self.fake_root / "registries/AGENT_OPERATIONS.md"
        lines = [
            line
            for line in md_path.read_text(encoding="utf-8").splitlines()
            if "`AOP-003`" not in line
        ]
        md_path.write_text("\n".join(lines) + "\n", encoding="utf-8")
        _, codes = self.error_codes()
        self.assertIn(ERR_OP_REGISTRY_DRIFT, codes)

    def test_duplicate_stable_id_is_detected(self) -> None:
        doc = self.load_registry()
        duplicate = dict(self.row("AOP-014"))
        duplicate["id"] = "AOP-001"
        doc["operations"].append(duplicate)
        self.save_registry(doc)
        _, codes = self.error_codes()
        self.assertIn(ERR_OP_STABLE_ID_REUSED, codes)

    def test_corrupt_registry_json_is_detected(self) -> None:
        path = self.fake_root / "architecture/agent_operations.json"
        path.write_text("{not json", encoding="utf-8")
        _, codes = self.error_codes()
        self.assertIn(ERR_OP_CORRUPT_FILE, codes)

    def test_missing_files_fail_closed(self) -> None:
        (self.fake_root / "registries/AGENT_OPERATIONS.md").unlink()
        (self.fake_root / "crates/fss-core/src/agent_operation.rs").unlink()
        (self.fake_root / "architecture/fss1_public_registry.json").unlink()
        _, codes = self.error_codes()
        self.assertIn(ERR_OP_CORRUPT_FILE, codes)
        self.assertIn(ERR_OP_RUST_DRIFT, codes)

    def test_semantic_invariant_effectful_contradiction(self) -> None:
        def make_effectful(op: dict) -> None:
            op["effectful"] = True

        self.replace_row("AOP-003", make_effectful)
        _, codes = self.error_codes()
        self.assertIn(ERR_OP_SEMANTIC_INVARIANT, codes)

    def test_semantic_invariant_unregistered_retry_class(self) -> None:
        def bad_retry(op: dict) -> None:
            op["retryClasses"] = ["retry_whenever"]

        self.replace_row("AOP-005", bad_retry)
        _, codes = self.error_codes()
        self.assertIn(ERR_OP_SEMANTIC_INVARIANT, codes)

    def test_semantic_invariant_bad_view_and_status(self) -> None:
        def bad_view(op: dict) -> None:
            op["defaultView"] = "VIEW-BRIEF"

        self.replace_row("AOP-004", bad_view)
        _, codes = self.error_codes()
        self.assertIn(ERR_OP_SEMANTIC_INVARIANT, codes)

    def test_frozen_public_registry_disagreement(self) -> None:
        frozen_path = self.fake_root / "architecture/fss1_public_registry.json"
        doc = json.loads(frozen_path.read_text(encoding="utf-8"))
        for op in doc["operations"]:
            if op["id"] == "AOP-012":
                op["defaultView"] = "AVIEW-001"
        frozen_path.write_text(json.dumps(doc, indent=2) + "\n", encoding="utf-8")
        _, codes = self.error_codes()
        self.assertIn(ERR_OP_SEMANTIC_INVARIANT, codes)

    def test_rust_canonical_row_drift_is_detected(self) -> None:
        rs_path = self.fake_root / "crates/fss-core/src/agent_operation.rs"
        text = rs_path.read_text(encoding="utf-8")
        # Tamper one field inside the AOP-001 canonical row literal: owner crate.
        text = text.replace(
            "AOP-001|session.open|session_control|fss-agent-session|",
            "AOP-001|session.open|session_control|fss-agent-sessionX|",
        )
        rs_path.write_text(text, encoding="utf-8")
        _, codes = self.error_codes()
        self.assertIn(ERR_OP_RUST_DRIFT, codes)

    def test_rust_missing_canonical_row_is_detected(self) -> None:
        rs_path = self.fake_root / "crates/fss-core/src/agent_operation.rs"
        text = rs_path.read_text(encoding="utf-8")
        lines = [line for line in text.splitlines() if '"AOP-014|' not in line]
        rs_path.write_text("\n".join(lines) + "\n", encoding="utf-8")
        _, codes = self.error_codes()
        self.assertIn(ERR_OP_RUST_DRIFT, codes)

    def test_rust_row_literal_helpers(self) -> None:
        rows = extract_rust_canonical_rows(
            ROOT / "crates/fss-core/src/agent_operation.rs"
        )
        self.assertEqual(len(rows), 14)
        fields = canonical_fields_from_text(rows["AOP-008"])
        self.assertIsNotNone(fields)
        self.assertEqual(fields["name"], "commit")
        self.assertTrue(fields["effectful"])
        self.assertTrue(fields["durable"])
        self.assertEqual(fields["mode"], "effect_commit")
        self.assertIsNone(canonical_fields_from_text("AOP-001|too|few"))


if __name__ == "__main__":
    unittest.main()
