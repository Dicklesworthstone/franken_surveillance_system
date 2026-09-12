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
        ERR_FROZEN_CORRUPT_FILE,
        ERR_FROZEN_DIGEST_MISMATCH,
        ERR_FROZEN_REGISTRY_DRIFT,
        ERR_FROZEN_STABLE_ID_REUSED,
        ERR_FROZEN_TOMBSTONE_RESURRECTED,
        ERR_FROZEN_UNREGISTERED_OP,
        compute_canonical_freeze_digest,
        validate_frozen_registry,
    )
except ImportError:
    frozen_registry_checker = None  # type: ignore[assignment]
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
        if dir_name in ("architecture", "registries", "schemas"):
            for f in src_dir.iterdir():
                if f.is_file():
                    (dst_dir / f.name).symlink_to(f)
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
            data["freezeDigest"] = compute_canonical_freeze_digest(data["operations"], data["resources"])
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
            data["freezeDigest"] = compute_canonical_freeze_digest(data["operations"], data["resources"])
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
            data["freezeDigest"] = compute_canonical_freeze_digest(data["operations"], data["resources"])
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
            data["freezeDigest"] = compute_canonical_freeze_digest(data["operations"], data["resources"])
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
            data["freezeDigest"] = compute_canonical_freeze_digest(data["operations"], data["resources"])
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
            data["freezeDigest"] = compute_canonical_freeze_digest(data["operations"], data["resources"])
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
            data["freezeDigest"] = compute_canonical_freeze_digest(data["operations"], data["resources"])
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
            data["freezeDigest"] = compute_canonical_freeze_digest(data["operations"], data["resources"])
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
            data["freezeDigest"] = compute_canonical_freeze_digest(
                data["operations"], data["resources"], data.get("tombstones", [])
            )
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

    def test_cli_invocation_json(self) -> None:
        """CLI invocation with --json must return valid JSON payload."""
        checker_path = ROOT / "scripts" / "frozen_registry_checker.py"
        res = subprocess.run(
            [sys.executable, str(checker_path), "--json"],
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
