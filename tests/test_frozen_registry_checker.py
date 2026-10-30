#!/usr/bin/env python3
"""Planted-negative test suite for fss/1 frozen public operation and resource registry checker (fss-x4a.24.1 / FSS-201).

Verifies that the frozen registry checker fails closed on:
1. Operation added, removed, renamed, or renumbered without a new registry generation (ERR-FROZEN-REGISTRY-DRIFT-001)
2. Resource added, removed, renamed, or renumbered without a new registry generation (ERR-FROZEN-REGISTRY-DRIFT-001)
3. Stable ID reused (ERR-FROZEN-STABLE-ID-REUSED-001)
4. Tombstoned entry resurrected (ERR-FROZEN-TOMBSTONE-RESURRECTED-001)
5. Canonical freeze digest mismatch (ERR-FROZEN-DIGEST-MISMATCH-001)
6. Crosswalk or presentation surfaces reference unregistered operation (ERR-FROZEN-UNREGISTERED-OP-001)
7. Missing or corrupted registry files (ERR-FROZEN-CORRUPT-FILE-001)
8. Live repository passes with 0 errors across all public operations and resources
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
    import frozen_registry_checker
    from frozen_registry_checker import (
        BASELINE_GENERATION,
        CURRENT_GENERATION,
        FROZEN_REGISTRY_V1_PATH,
        BASELINE_OPERATIONS,
        BASELINE_RESOURCES,
        ERR_FROZEN_CORRUPT_FILE,
        ERR_FROZEN_DIGEST_MISMATCH,
        ERR_FROZEN_REGISTRY_DRIFT,
        ERR_FROZEN_STABLE_ID_REUSED,
        ERR_FROZEN_TOMBSTONE_RESURRECTED,
        ERR_FROZEN_UNREGISTERED_OP,
        EXPECTED_FREEZE_DIGESTS,
        compute_canonical_freeze_digest,
        frozen_rows_for_generation,
        load_legacy_registry,
        validate_frozen_registry,
    )
except ImportError:
    frozen_registry_checker = None  # type: ignore[assignment]
    BASELINE_GENERATION = "gen:fss1:public-v1"
    CURRENT_GENERATION = "gen:fss1:public-v2"
    FROZEN_REGISTRY_V1_PATH = "architecture/fss1_public_registry.v1.json"
    BASELINE_OPERATIONS = {}
    BASELINE_RESOURCES = {}
    EXPECTED_FREEZE_DIGESTS = {}
    ERR_FROZEN_REGISTRY_DRIFT = "ERR-FROZEN-REGISTRY-DRIFT-001"
    ERR_FROZEN_STABLE_ID_REUSED = "ERR-FROZEN-STABLE-ID-REUSED-001"
    ERR_FROZEN_TOMBSTONE_RESURRECTED = "ERR-FROZEN-TOMBSTONE-RESURRECTED-001"
    ERR_FROZEN_DIGEST_MISMATCH = "ERR-FROZEN-DIGEST-MISMATCH-001"
    ERR_FROZEN_UNREGISTERED_OP = "ERR-FROZEN-UNREGISTERED-OP-001"
    ERR_FROZEN_CORRUPT_FILE = "ERR-FROZEN-CORRUPT-FILE-001"
    compute_canonical_freeze_digest = None  # type: ignore[assignment]
    validate_frozen_registry = None  # type: ignore[assignment]


def create_mock_repo(tmp_path: Path) -> Path:
    """Creates an isolated repository replica with symlinks for mutation tests."""
    for dir_name in ("architecture", "registries", "schemas", "crates", "scripts"):
        src_dir = ROOT / dir_name
        dst_dir = tmp_path / dir_name
        dst_dir.mkdir(parents=True, exist_ok=True)
        if dir_name in ("architecture", "registries", "schemas", "scripts"):
            for f in src_dir.iterdir():
                if f.is_file():
                    (dst_dir / f.name).symlink_to(f)
        elif dir_name == "crates":
            cli_src_dst = dst_dir / "fss-cli" / "src"
            cli_src_dst.mkdir(parents=True, exist_ok=True)
            cli_src = src_dir / "fss-cli" / "src"
            if cli_src.is_dir():
                for f in cli_src.iterdir():
                    if f.is_file():
                        (cli_src_dst / f.name).symlink_to(f)
    return tmp_path


class TestFrozenRegistryChecker(unittest.TestCase):
    """Test suite and planted negatives for frozen public registry checker."""

    def setUp(self) -> None:
        if frozen_registry_checker is None or validate_frozen_registry is None:
            self.fail("frozen_registry_checker module not yet implemented")

    def test_live_repository_passes_with_zero_errors(self) -> None:
        """The live repository must satisfy the frozen registry contract with 0 errors."""
        result = validate_frozen_registry(ROOT)
        self.assertTrue(result.passed, f"Live repository failed validation: {result.errors}")
        self.assertEqual(len(result.errors), 0)
        self.assertEqual(result.operation_count, 14)
        self.assertEqual(result.resource_count, 15)
        self.assertEqual(result.freeze_digest, EXPECTED_FREEZE_DIGESTS[CURRENT_GENERATION])

    def test_planted_negative_op_added_without_generation_bump(self) -> None:
        """Adding an operation without bumping registry generation must fail closed."""
        with tempfile.TemporaryDirectory() as tmp_dir:
            repo = create_mock_repo(Path(tmp_dir))
            reg_file = repo / "architecture" / "fss1_public_registry.json"
            reg_file.unlink()

            data = json.loads((ROOT / "architecture" / "fss1_public_registry.json").read_text(encoding="utf-8"))
            new_op = {
                "id": "AOP-015",
                "kind": "operation",
                "name": "session.inspect",
                "generation": data["registryGeneration"],
                "owner": "fss-agent-session",
                "requestEnvelope": "fss.agent_request_envelope.v1",
                "responseEnvelope": "fss.agent_response_envelope.v1",
                "compatibilityClass": "backward_compatible",
                "status": "specified",
            }
            data["operations"].append(new_op)
            data["freezeDigest"] = compute_canonical_freeze_digest(data)
            reg_file.write_text(json.dumps(data, indent=2), encoding="utf-8")

            result = validate_frozen_registry(repo)
            self.assertFalse(result.passed)
            self.assertTrue(
                any(err.code == ERR_FROZEN_REGISTRY_DRIFT for err in result.errors),
                f"Expected ERR_FROZEN_REGISTRY_DRIFT, got {result.errors}",
            )

    def test_planted_negative_op_removed_without_generation_bump(self) -> None:
        """Removing an operation without bumping registry generation must fail closed."""
        with tempfile.TemporaryDirectory() as tmp_dir:
            repo = create_mock_repo(Path(tmp_dir))
            reg_file = repo / "architecture" / "fss1_public_registry.json"
            reg_file.unlink()

            data = json.loads((ROOT / "architecture" / "fss1_public_registry.json").read_text(encoding="utf-8"))
            data["operations"] = [op for op in data["operations"] if op["id"] != "AOP-001"]
            data["freezeDigest"] = compute_canonical_freeze_digest(data)
            reg_file.write_text(json.dumps(data, indent=2), encoding="utf-8")

            result = validate_frozen_registry(repo)
            self.assertFalse(result.passed)
            self.assertTrue(
                any(err.code == ERR_FROZEN_REGISTRY_DRIFT for err in result.errors),
                f"Expected ERR_FROZEN_REGISTRY_DRIFT, got {result.errors}",
            )

    def test_planted_negative_op_renamed_without_generation_bump(self) -> None:
        """Renaming an operation without bumping registry generation must fail closed."""
        with tempfile.TemporaryDirectory() as tmp_dir:
            repo = create_mock_repo(Path(tmp_dir))
            reg_file = repo / "architecture" / "fss1_public_registry.json"
            reg_file.unlink()

            data = json.loads((ROOT / "architecture" / "fss1_public_registry.json").read_text(encoding="utf-8"))
            for op in data["operations"]:
                if op["id"] == "AOP-001":
                    op["name"] = "session.start"
            data["freezeDigest"] = compute_canonical_freeze_digest(data)
            reg_file.write_text(json.dumps(data, indent=2), encoding="utf-8")

            result = validate_frozen_registry(repo)
            self.assertFalse(result.passed)
            self.assertTrue(
                any(err.code == ERR_FROZEN_REGISTRY_DRIFT for err in result.errors),
                f"Expected ERR_FROZEN_REGISTRY_DRIFT, got {result.errors}",
            )

    def test_planted_negative_op_renumbered_without_generation_bump(self) -> None:
        """Renumbering an operation without bumping registry generation must fail closed."""
        with tempfile.TemporaryDirectory() as tmp_dir:
            repo = create_mock_repo(Path(tmp_dir))
            reg_file = repo / "architecture" / "fss1_public_registry.json"
            reg_file.unlink()

            data = json.loads((ROOT / "architecture" / "fss1_public_registry.json").read_text(encoding="utf-8"))
            for op in data["operations"]:
                if op["id"] == "AOP-001":
                    op["id"] = "AOP-099"
            data["freezeDigest"] = compute_canonical_freeze_digest(data)
            reg_file.write_text(json.dumps(data, indent=2), encoding="utf-8")

            result = validate_frozen_registry(repo)
            self.assertFalse(result.passed)
            self.assertTrue(
                any(err.code == ERR_FROZEN_REGISTRY_DRIFT for err in result.errors),
                f"Expected ERR_FROZEN_REGISTRY_DRIFT, got {result.errors}",
            )

    def test_planted_negative_resource_added_without_generation_bump(self) -> None:
        """Adding a resource without bumping registry generation must fail closed."""
        with tempfile.TemporaryDirectory() as tmp_dir:
            repo = create_mock_repo(Path(tmp_dir))
            reg_file = repo / "architecture" / "fss1_public_registry.json"
            reg_file.unlink()

            data = json.loads((ROOT / "architecture" / "fss1_public_registry.json").read_text(encoding="utf-8"))
            new_res = {
                "id": "ARES-016",
                "kind": "resource",
                "name": "custom.resource",
                "generation": data["registryGeneration"],
                "owner": "fss-custom",
                "uriTemplate": "fss://custom/{resource}",
                "requestEnvelope": "fss.agent_request_envelope.v1",
                "responseEnvelope": "fss.agent_response_envelope.v1",
                "payloadSchema": "fss.custom.v1",
                "compatibilityClass": "backward_compatible",
                "status": "specified",
            }
            data["resources"].append(new_res)
            data["freezeDigest"] = compute_canonical_freeze_digest(data)
            reg_file.write_text(json.dumps(data, indent=2), encoding="utf-8")

            result = validate_frozen_registry(repo)
            self.assertFalse(result.passed)
            self.assertTrue(
                any(err.code == ERR_FROZEN_REGISTRY_DRIFT for err in result.errors),
                f"Expected ERR_FROZEN_REGISTRY_DRIFT, got {result.errors}",
            )

    def test_planted_negative_resource_removed_without_generation_bump(self) -> None:
        """Removing a resource without bumping registry generation must fail closed."""
        with tempfile.TemporaryDirectory() as tmp_dir:
            repo = create_mock_repo(Path(tmp_dir))
            reg_file = repo / "architecture" / "fss1_public_registry.json"
            reg_file.unlink()

            data = json.loads((ROOT / "architecture" / "fss1_public_registry.json").read_text(encoding="utf-8"))
            data["resources"] = [r for r in data["resources"] if r["id"] != "ARES-001"]
            data["freezeDigest"] = compute_canonical_freeze_digest(data)
            reg_file.write_text(json.dumps(data, indent=2), encoding="utf-8")

            result = validate_frozen_registry(repo)
            self.assertFalse(result.passed)
            self.assertTrue(
                any(err.code == ERR_FROZEN_REGISTRY_DRIFT for err in result.errors),
                f"Expected ERR_FROZEN_REGISTRY_DRIFT, got {result.errors}",
            )

    def test_planted_negative_resource_renamed_without_generation_bump(self) -> None:
        """Renaming a resource without bumping registry generation must fail closed."""
        with tempfile.TemporaryDirectory() as tmp_dir:
            repo = create_mock_repo(Path(tmp_dir))
            reg_file = repo / "architecture" / "fss1_public_registry.json"
            reg_file.unlink()

            data = json.loads((ROOT / "architecture" / "fss1_public_registry.json").read_text(encoding="utf-8"))
            for r in data["resources"]:
                if r["id"] == "ARES-001":
                    r["name"] = "deployment.renamed_anchor"
            data["freezeDigest"] = compute_canonical_freeze_digest(data)
            reg_file.write_text(json.dumps(data, indent=2), encoding="utf-8")

            result = validate_frozen_registry(repo)
            self.assertFalse(result.passed)
            self.assertTrue(
                any(err.code == ERR_FROZEN_REGISTRY_DRIFT for err in result.errors),
                f"Expected ERR_FROZEN_REGISTRY_DRIFT, got {result.errors}",
            )

    def test_planted_negative_stable_id_reused(self) -> None:
        """Reusing a stable ID across or within operations and resources must fail closed."""
        with tempfile.TemporaryDirectory() as tmp_dir:
            repo = create_mock_repo(Path(tmp_dir))
            reg_file = repo / "architecture" / "fss1_public_registry.json"
            reg_file.unlink()

            data = json.loads((ROOT / "architecture" / "fss1_public_registry.json").read_text(encoding="utf-8"))
            # Make ARES-001 reuse AOP-001
            for r in data["resources"]:
                if r["id"] == "ARES-001":
                    r["id"] = "AOP-001"
            reg_file.write_text(json.dumps(data, indent=2), encoding="utf-8")

            result = validate_frozen_registry(repo)
            self.assertFalse(result.passed)
            self.assertTrue(
                any(err.code == ERR_FROZEN_STABLE_ID_REUSED for err in result.errors),
                f"Expected ERR_FROZEN_STABLE_ID_REUSED, got {result.errors}",
            )

    def test_planted_negative_tombstone_resurrected(self) -> None:
        """Resurrecting a tombstoned operation or resource into active status must fail closed."""
        with tempfile.TemporaryDirectory() as tmp_dir:
            repo = create_mock_repo(Path(tmp_dir))
            reg_file = repo / "architecture" / "fss1_public_registry.json"
            reg_file.unlink()

            data = json.loads((ROOT / "architecture" / "fss1_public_registry.json").read_text(encoding="utf-8"))
            data["tombstones"] = [
                {
                    "id": "AOP-001",
                    "kind": "operation",
                    "reason": "superseded by new protocol",
                    "tombstonedAt": "2026-09-01",
                }
            ]
            reg_file.write_text(json.dumps(data, indent=2), encoding="utf-8")

            result = validate_frozen_registry(repo)
            self.assertFalse(result.passed)
            self.assertTrue(
                any(err.code == ERR_FROZEN_TOMBSTONE_RESURRECTED for err in result.errors),
                f"Expected ERR_FROZEN_TOMBSTONE_RESURRECTED, got {result.errors}",
            )

    def test_planted_negative_digest_mismatch(self) -> None:
        """A corrupted or mismatched freeze digest must fail closed."""
        with tempfile.TemporaryDirectory() as tmp_dir:
            repo = create_mock_repo(Path(tmp_dir))
            reg_file = repo / "architecture" / "fss1_public_registry.json"
            reg_file.unlink()

            data = json.loads((ROOT / "architecture" / "fss1_public_registry.json").read_text(encoding="utf-8"))
            data["freezeDigest"] = "sha256:0000000000000000000000000000000000000000000000000000000000000000"
            reg_file.write_text(json.dumps(data, indent=2), encoding="utf-8")

            result = validate_frozen_registry(repo)
            self.assertFalse(result.passed)
            self.assertTrue(
                any(err.code == ERR_FROZEN_DIGEST_MISMATCH for err in result.errors),
                f"Expected ERR_FROZEN_DIGEST_MISMATCH, got {result.errors}",
            )

    def test_planted_negative_crosswalk_references_unregistered_op(self) -> None:
        """A crosswalk entry referencing an operation not in the frozen registry must fail closed."""
        with tempfile.TemporaryDirectory() as tmp_dir:
            repo = create_mock_repo(Path(tmp_dir))
            cw_file = repo / "architecture" / "operation_crosswalk.json"
            cw_file.unlink()

            data = json.loads((ROOT / "architecture" / "operation_crosswalk.json").read_text(encoding="utf-8"))
            data["crosswalk"].append(
                {
                    "operation_id": "AOP-999",
                    "operation_name": "unregistered.fake",
                    "owner": "fss-fake",
                    "cli_command": "fss fake",
                    "library_entry_point": "fss_fake::fake",
                    "mcp_tool_name": "fake",
                    "primary_error_id": "ERR-AUTH-DENIED-001",
                    "error_identities": ["ERR-AUTH-DENIED-001"],
                    "exit_identities": ["EXIT-OK-000"],
                    "status": "specified",
                }
            )
            cw_file.write_text(json.dumps(data, indent=2), encoding="utf-8")

            result = validate_frozen_registry(repo)
            self.assertFalse(result.passed)
            self.assertTrue(
                any(err.code == ERR_FROZEN_UNREGISTERED_OP and "AOP-999" in err.message for err in result.errors),
                f"Expected ERR_FROZEN_UNREGISTERED_OP for AOP-999, got {result.errors}",
            )

    def test_planted_negative_unvalidated_field_drift_with_matching_digest_fails(self) -> None:
        """Mutating an operation field (e.g. cliCommand) and recomputing freezeDigest must fail closed."""
        with tempfile.TemporaryDirectory() as tmp_dir:
            repo = create_mock_repo(Path(tmp_dir))
            reg_file = repo / "architecture" / "fss1_public_registry.json"
            reg_file.unlink()

            data = json.loads((ROOT / "architecture" / "fss1_public_registry.json").read_text(encoding="utf-8"))
            data["operations"][0]["cliCommand"] = "fss session hacked"
            data["freezeDigest"] = compute_canonical_freeze_digest(data)
            reg_file.write_text(json.dumps(data, indent=2), encoding="utf-8")

            result = validate_frozen_registry(repo)
            self.assertFalse(result.passed)
            self.assertTrue(
                any(err.code == ERR_FROZEN_REGISTRY_DRIFT for err in result.errors),
                f"Expected ERR_FROZEN_REGISTRY_DRIFT, got {result.errors}",
            )
            self.assertTrue(
                any(err.code == ERR_FROZEN_DIGEST_MISMATCH for err in result.errors),
                f"Expected ERR_FROZEN_DIGEST_MISMATCH against pinned digest, got {result.errors}",
            )

    def test_planted_negative_generation_bump_changes_freeze_digest(self) -> None:
        """Top-level registryGeneration must be bound to the canonical freeze digest."""
        data = json.loads((ROOT / "architecture" / "fss1_public_registry.json").read_text(encoding="utf-8"))
        d1 = compute_canonical_freeze_digest(data)
        data["registryGeneration"] = "gen:fss1:public-v3"
        d2 = compute_canonical_freeze_digest(data)
        self.assertNotEqual(d1, d2, "Changing registryGeneration must alter canonical freeze digest")

    def test_planted_negative_top_level_schema_or_protocol_change_fails(self) -> None:
        """Altering semanticProtocol or schema must alter the digest and fail validation."""
        with tempfile.TemporaryDirectory() as tmp_dir:
            repo = create_mock_repo(Path(tmp_dir))
            reg_file = repo / "architecture" / "fss1_public_registry.json"
            reg_file.unlink()

            data = json.loads((ROOT / "architecture" / "fss1_public_registry.json").read_text(encoding="utf-8"))
            data["semanticProtocol"] = "fss/2"
            data["freezeDigest"] = compute_canonical_freeze_digest(data)
            reg_file.write_text(json.dumps(data, indent=2), encoding="utf-8")

            result = validate_frozen_registry(repo)
            self.assertFalse(result.passed)
            self.assertTrue(
                any(err.code == ERR_FROZEN_CORRUPT_FILE and "semanticProtocol" in err.target for err in result.errors),
                f"Expected ERR_FROZEN_CORRUPT_FILE for semanticProtocol, got {result.errors}",
            )

    def test_planted_negative_rust_crosswalk_unregistered_non_aop_op_fails(self) -> None:
        """Rust CLI crosswalk referencing an unregistered operation with non-AOP scheme must fail closed."""
        with tempfile.TemporaryDirectory() as tmp_dir:
            repo = create_mock_repo(Path(tmp_dir))
            crosswalk_rs = repo / "crates" / "fss-cli" / "src" / "crosswalk.rs"
            crosswalk_rs.unlink()
            crosswalk_rs.write_text(
                'pub static FAKE_ENTRY: &str = "test";\n'
                'const FAKE_OP: &str = r#"operation_id: "OP-001""#;\n',
                encoding="utf-8",
            )

            result = validate_frozen_registry(repo)
            self.assertFalse(result.passed)
            self.assertTrue(
                any(err.code == ERR_FROZEN_UNREGISTERED_OP and "OP-001" in err.message for err in result.errors),
                f"Expected ERR_FROZEN_UNREGISTERED_OP for OP-001, got {result.errors}",
            )

    def test_planted_negative_duplicate_or_empty_ids_fail_digest_calculation(self) -> None:
        """compute_canonical_freeze_digest must fail closed with ValueError on empty or duplicate IDs."""
        data = json.loads((ROOT / "architecture" / "fss1_public_registry.json").read_text(encoding="utf-8"))
        data_empty = json.loads(json.dumps(data))
        data_empty["operations"][0]["id"] = ""
        with self.assertRaises(ValueError):
            compute_canonical_freeze_digest(data_empty)

        data_dup = json.loads(json.dumps(data))
        data_dup["operations"][1]["id"] = "AOP-001"
        with self.assertRaises(ValueError):
            compute_canonical_freeze_digest(data_dup)

    def test_canonical_list_order_invariance(self) -> None:
        """Permuting list-valued fields must produce the exact same canonical freeze digest."""
        data = json.loads((ROOT / "architecture" / "fss1_public_registry.json").read_text(encoding="utf-8"))
        d1 = compute_canonical_freeze_digest(data)
        for op in data["operations"]:
            if op["id"] == "AOP-004":
                op["responsePayloadSchemas"] = list(reversed(op["responsePayloadSchemas"]))
        d2 = compute_canonical_freeze_digest(data)
        self.assertEqual(d1, d2, "Permuted list fields must produce identical canonical freeze digest")
        self.assertEqual(d1, EXPECTED_FREEZE_DIGESTS[CURRENT_GENERATION])

    def test_two_pinned_generations_preserve_exact_v1_and_only_add_probe_payload(self) -> None:
        legacy = load_legacy_registry(ROOT)
        self.assertEqual(legacy["registryGeneration"], BASELINE_GENERATION)
        self.assertEqual(legacy["freezeDigest"], EXPECTED_FREEZE_DIGESTS[BASELINE_GENERATION])
        old_ops = {row["id"]: row for row in legacy["operations"]}
        old_resources = {row["id"]: row for row in legacy["resources"]}
        self.assertEqual(old_ops, BASELINE_OPERATIONS)
        self.assertEqual(old_resources, BASELINE_RESOURCES)
        new_ops, new_resources = frozen_rows_for_generation(CURRENT_GENERATION)
        for opid, row in new_ops.items():
            row["generation"] = BASELINE_GENERATION
            if opid == "AOP-006":
                self.assertEqual(row["responsePayloadSchemas"].pop(), "fss.agent_cognitive_envelope.v2")
            self.assertEqual(row, old_ops[opid])
        for resid, row in new_resources.items():
            row["generation"] = BASELINE_GENERATION
            self.assertEqual(row, old_resources[resid])
        self.assertEqual(frozen_rows_for_generation(BASELINE_GENERATION), (old_ops, old_resources))

    def test_archived_v1_remains_a_valid_complete_generation(self) -> None:
        with tempfile.TemporaryDirectory() as tmp_dir:
            repo = create_mock_repo(Path(tmp_dir))
            path = repo / "architecture/fss1_public_registry.json"
            path.unlink()
            path.write_bytes((ROOT / FROZEN_REGISTRY_V1_PATH).read_bytes())
            result = validate_frozen_registry(repo)
            self.assertTrue(result.passed, result.errors)
            self.assertEqual(result.freeze_digest, EXPECTED_FREEZE_DIGESTS[BASELINE_GENERATION])

    def test_unregistered_generation_cannot_bypass_a_matching_self_digest(self) -> None:
        with tempfile.TemporaryDirectory() as tmp_dir:
            repo = create_mock_repo(Path(tmp_dir))
            path = repo / "architecture/fss1_public_registry.json"
            data = json.loads(path.read_text())
            path.unlink()
            data["registryGeneration"] = "gen:fss1:public-unregistered"
            for row in data["operations"] + data["resources"]:
                row["generation"] = data["registryGeneration"]
            data["operations"][0]["owner"] = "fss-unregistered-owner"
            data["freezeDigest"] = compute_canonical_freeze_digest(data)
            path.write_text(json.dumps(data))
            result = validate_frozen_registry(repo)
            self.assertFalse(result.passed)
            self.assertIn(ERR_FROZEN_REGISTRY_DRIFT, {err.code for err in result.errors})

    def test_v1_cannot_gain_v2_payload_by_recomputing_its_digest(self) -> None:
        with tempfile.TemporaryDirectory() as tmp_dir:
            repo = create_mock_repo(Path(tmp_dir))
            path = repo / "architecture/fss1_public_registry.json"
            path.unlink()
            data = load_legacy_registry(ROOT)
            row = next(row for row in data["operations"] if row["id"] == "AOP-006")
            row["responsePayloadSchemas"].append("fss.agent_cognitive_envelope.v2")
            data["freezeDigest"] = compute_canonical_freeze_digest(data)
            path.write_text(json.dumps(data))
            result = validate_frozen_registry(repo)
            codes = {err.code for err in result.errors}
            self.assertFalse(result.passed)
            self.assertIn(ERR_FROZEN_REGISTRY_DRIFT, codes)
            self.assertIn(ERR_FROZEN_DIGEST_MISMATCH, codes)

    def test_v1_archive_is_mandatory_and_byte_preserved(self) -> None:
        for mode in ("missing", "rewritten", "widened"):
            with self.subTest(mode=mode), tempfile.TemporaryDirectory() as tmp_dir:
                repo = create_mock_repo(Path(tmp_dir))
                path = repo / FROZEN_REGISTRY_V1_PATH
                path.unlink()
                if mode != "missing":
                    data = load_legacy_registry(ROOT)
                    if mode == "widened":
                        data["operations"][5]["responsePayloadSchemas"].append("fss.agent_cognitive_envelope.v2")
                        data["freezeDigest"] = compute_canonical_freeze_digest(data)
                    path.write_text(json.dumps(data))
                result = validate_frozen_registry(repo)
                expected = ERR_FROZEN_CORRUPT_FILE if mode == "missing" else ERR_FROZEN_DIGEST_MISMATCH
                self.assertFalse(result.passed)
                self.assertIn(expected, {err.code for err in result.errors})

    def test_cli_invocation_json(self) -> None:
        """CLI invocation with --json must return valid JSON payload."""
        checker_path = ROOT / "scripts" / "frozen_registry_checker.py"
        res = subprocess.run(
            [sys.executable, "-B", str(checker_path), "--json"],
            capture_output=True,
            text=True,
            check=False,
        )
        self.assertEqual(res.returncode, 0, f"CLI returned non-zero: {res.stderr}")
        data = json.loads(res.stdout)
        self.assertEqual(data["status"], "passed")
        self.assertEqual(data["operationCount"], 14)
        self.assertEqual(data["resourceCount"], 15)
        self.assertEqual(data["errorCount"], 0)


if __name__ == "__main__":
    unittest.main()
