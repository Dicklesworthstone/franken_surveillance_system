#!/usr/bin/env python3
"""Tests for SLO reference consistency between operation costs and SLO registry.

Validates that:
- Every `slo_ids` entry in architecture/operation_cost_registry.toml resolves to a registered SLO in registries/SLOS.md
- The four reconciled SLOs (SLO-PRIVACY-001, SLO-MODEL-001, SLO-RECOVERY-001, SLO-RELEASE-001) resolve correctly
- Planted dangling references fail deterministically with actionable diagnostics
- Malformed, duplicate, and cyclic tombstone references are detected and rejected
- Emits structured, secret-free JSON-serializable audit reports
"""

from __future__ import annotations

import hashlib
import json
import re
import sys
import tomllib
import unittest
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
COSTS_PATH = ROOT / "architecture/operation_cost_registry.toml"
SLOS_PATH = ROOT / "registries/SLOS.md"

SLO_ID_REGEX = re.compile(r"^SLO-[A-Z0-9]+(?:-[A-Z0-9]+)*-[0-9]{3}$")
SLO_TABLE_ROW_REGEX = re.compile(r"^\|\s*`((?:SLO)-[A-Z0-9-]+)`\s*\|\s*([^|]+)\s*\|\s*([^|]+)\s*\|$", re.MULTILINE)
TOMBSTONE_REGEX = re.compile(r"^tombstone:\s*superseded\s*by\s*`((?:SLO)-[A-Z0-9-]+)`", re.IGNORECASE)


class SloResolutionError(Exception):
    """Base error for SLO resolution failures."""


class DanglingSloReferenceError(SloResolutionError):
    """Raised when an operation-cost row references an unregistered SLO."""


class MalformedSloError(SloResolutionError):
    """Raised when an SLO ID or table row is malformed."""


class DuplicateSloError(SloResolutionError):
    """Raised when an SLO ID is defined multiple times."""


class InvalidTombstoneError(SloResolutionError):
    """Raised when a tombstone crosswalk is invalid or cyclic."""


def parse_slos_markdown(markdown_text: str) -> dict[str, dict[str, Any]]:
    """Parse SLO rows from markdown text.
    
    Returns a dict mapping SLO ID to its row metadata:
    {
        "id": "SLO-...",
        "target": "...",
        "scope": "...",
        "is_tombstone": bool,
        "superseded_by": Optional[str],
    }
    """
    slos: dict[str, dict[str, Any]] = {}
    for match in SLO_TABLE_ROW_REGEX.finditer(markdown_text):
        slo_id, target, scope = match.group(1).strip(), match.group(2).strip(), match.group(3).strip()
        if not SLO_ID_REGEX.match(slo_id):
            raise MalformedSloError(f"Malformed SLO ID: '{slo_id}'")
        if slo_id in slos:
            raise DuplicateSloError(f"Duplicate SLO ID: '{slo_id}'")
        
        tombstone_match = TOMBSTONE_REGEX.search(target)
        is_tombstone = tombstone_match is not None
        superseded_by = tombstone_match.group(1) if tombstone_match else None
        
        slos[slo_id] = {
            "id": slo_id,
            "target": target,
            "scope": scope,
            "is_tombstone": is_tombstone,
            "superseded_by": superseded_by,
        }
    return slos


def parse_costs_toml(toml_text: str) -> list[dict[str, Any]]:
    """Parse operations from operation_cost_registry.toml content."""
    data = tomllib.loads(toml_text)
    operations = data.get("operation", [])
    if not isinstance(operations, list):
        raise ValueError("operation_cost_registry.toml missing [[operation]] list")
    return operations


def audit_slo_references(
    costs_toml_text: str,
    slos_markdown_text: str,
) -> dict[str, Any]:
    """Audit that every slo_ids entry in costs resolves to a registered SLO row.
    
    Validates tombstone chains and detects cycles or dangling successors.
    Returns a structured audit report.
    """
    slos = parse_slos_markdown(slos_markdown_text)
    operations = parse_costs_toml(costs_toml_text)
    
    # Validate tombstone integrity
    for slo_id, slo_data in slos.items():
        if slo_data["is_tombstone"]:
            successor = slo_data["superseded_by"]
            if not successor:
                raise InvalidTombstoneError(f"Tombstone {slo_id} missing successor")
            visited = {slo_id}
            curr = successor
            while curr in slos and slos[curr]["is_tombstone"]:
                if curr in visited:
                    raise InvalidTombstoneError(f"Cyclic tombstone chain detected at {curr}")
                visited.add(curr)
                curr = slos[curr]["superseded_by"]
            if curr not in slos:
                raise InvalidTombstoneError(f"Tombstone {slo_id} points to unregistered successor {curr}")
    
    resolutions: list[dict[str, Any]] = []
    dangling_references: list[dict[str, Any]] = []
    
    for op in operations:
        cost_id = op.get("id", "UNKNOWN_COST_ID")
        referenced_slos = op.get("slo_ids", [])
        for ref_slo_id in referenced_slos:
            if not SLO_ID_REGEX.match(ref_slo_id):
                raise MalformedSloError(f"Operation {cost_id} references malformed SLO ID '{ref_slo_id}'")
            if ref_slo_id not in slos:
                dangling_references.append({
                    "cost_id": cost_id,
                    "slo_id": ref_slo_id,
                    "reason": "unregistered_slo",
                })
            else:
                slo_info = slos[ref_slo_id]
                canonical_target = slo_info["id"]
                if slo_info["is_tombstone"]:
                    # Trace to terminal successor
                    curr = slo_info["superseded_by"]
                    while curr in slos and slos[curr]["is_tombstone"]:
                        curr = slos[curr]["superseded_by"]
                    canonical_target = curr
                resolutions.append({
                    "cost_id": cost_id,
                    "referenced_slo_id": ref_slo_id,
                    "resolved_canonical_id": canonical_target,
                    "is_tombstone": slo_info["is_tombstone"],
                })
    
    report = {
        "status": "pass" if not dangling_references else "fail",
        "total_operations": len(operations),
        "total_slos_registered": len(slos),
        "total_references_checked": len(resolutions) + len(dangling_references),
        "dangling_references": dangling_references,
        "resolutions": resolutions,
        "costs_digest": hashlib.sha256(costs_toml_text.encode("utf-8")).hexdigest(),
        "slos_digest": hashlib.sha256(slos_markdown_text.encode("utf-8")).hexdigest(),
    }
    
    if dangling_references:
        dangling_list = ", ".join(f"{d['cost_id']} -> {d['slo_id']}" for d in dangling_references)
        raise DanglingSloReferenceError(
            f"Dangling SLO references found ({len(dangling_references)}): {dangling_list}"
        )
    
    return report


class SloOperationCostConsistencyTests(unittest.TestCase):
    """Test suite for SLO reference consistency and planted faults."""

    def setUp(self) -> None:
        self.real_costs_text = COSTS_PATH.read_text(encoding="utf-8")
        self.real_slos_text = SLOS_PATH.read_text(encoding="utf-8")

    def test_real_repository_consistency(self) -> None:
        """Verify that live repo operation costs and SLO registry are 100% consistent."""
        report = audit_slo_references(self.real_costs_text, self.real_slos_text)
        self.assertEqual(report["status"], "pass")
        self.assertEqual(len(report["dangling_references"]), 0)
        self.assertGreater(report["total_references_checked"], 0)
        
        # Verify the four target SLO IDs are present and resolve
        resolved_slos = {r["referenced_slo_id"] for r in report["resolutions"]}
        canonical_slos = {r["resolved_canonical_id"] for r in report["resolutions"]}
        
        # COST-DELETE-001 resolves to SLO-DELETE-001
        self.assertIn("SLO-DELETE-001", canonical_slos)
        # COST-MODEL-IMPORT-001 resolves to SLO-MODEL-001
        self.assertIn("SLO-MODEL-001", resolved_slos)
        # COST-CHECKPOINT-001 resolves to SLO-RECOVERY-001
        self.assertIn("SLO-RECOVERY-001", resolved_slos)
        # COST-RELEASE-001 resolves to SLO-RELEASE-001
        self.assertIn("SLO-RELEASE-001", resolved_slos)
        
        # Verify SLO-PRIVACY-001 is registered as tombstone superseded by SLO-DELETE-001
        slos = parse_slos_markdown(self.real_slos_text)
        self.assertIn("SLO-PRIVACY-001", slos)
        self.assertTrue(slos["SLO-PRIVACY-001"]["is_tombstone"])
        self.assertEqual(slos["SLO-PRIVACY-001"]["superseded_by"], "SLO-DELETE-001")

    def test_planted_dangling_reference_fails(self) -> None:
        """Planted dangling reference in operation-cost registry must fail."""
        planted_costs = self.real_costs_text.replace(
            'slo_ids = ["SLO-DELETE-001"]',
            'slo_ids = ["SLO-NONEXISTENT-999"]',
        )
        with self.assertRaises(DanglingSloReferenceError) as ctx:
            audit_slo_references(planted_costs, self.real_slos_text)
        self.assertIn("SLO-NONEXISTENT-999", str(ctx.exception))
        self.assertIn("COST-DELETE-001", str(ctx.exception))

    def test_planted_original_four_dangling_references_fail_on_unreconciled_slos(self) -> None:
        """Simulate the original unreconciled SLOS.md state and confirm all 4 fail."""
        # Strip out the 4 reconciled SLO rows to reproduce the pre-fix state
        unreconciled_slos = "\n".join(
            line for line in self.real_slos_text.splitlines()
            if not any(k in line for k in ["SLO-MODEL-001", "SLO-RECOVERY-001", "SLO-RELEASE-001", "SLO-PRIVACY-001"])
        )
        # Point COST-DELETE-001 back to SLO-PRIVACY-001 as in original state
        original_costs = self.real_costs_text.replace(
            'slo_ids = ["SLO-DELETE-001"]',
            'slo_ids = ["SLO-PRIVACY-001"]',
        )
        with self.assertRaises(DanglingSloReferenceError) as ctx:
            audit_slo_references(original_costs, unreconciled_slos)
        err_msg = str(ctx.exception)
        self.assertIn("SLO-PRIVACY-001", err_msg)
        self.assertIn("SLO-MODEL-001", err_msg)
        self.assertIn("SLO-RECOVERY-001", err_msg)
        self.assertIn("SLO-RELEASE-001", err_msg)

    def test_tombstone_resolution_through_crosswalk(self) -> None:
        """If an operation references a tombstoned SLO, it resolves to canonical successor."""
        costs_with_tombstone = self.real_costs_text.replace(
            'slo_ids = ["SLO-DELETE-001"]',
            'slo_ids = ["SLO-PRIVACY-001"]',
        )
        report = audit_slo_references(costs_with_tombstone, self.real_slos_text)
        self.assertEqual(report["status"], "pass")
        # Find resolution for COST-DELETE-001
        delete_resolutions = [r for r in report["resolutions"] if r["cost_id"] == "COST-DELETE-001"]
        self.assertEqual(len(delete_resolutions), 1)
        self.assertEqual(delete_resolutions[0]["referenced_slo_id"], "SLO-PRIVACY-001")
        self.assertEqual(delete_resolutions[0]["resolved_canonical_id"], "SLO-DELETE-001")
        self.assertTrue(delete_resolutions[0]["is_tombstone"])

    def test_planted_malformed_slo_id_fails(self) -> None:
        """Planted malformed SLO ID fails validation."""
        planted_costs = self.real_costs_text.replace(
            'slo_ids = ["SLO-DELETE-001"]',
            'slo_ids = ["not_a_valid_slo_id"]',
        )
        with self.assertRaises(MalformedSloError):
            audit_slo_references(planted_costs, self.real_slos_text)

    def test_planted_duplicate_slo_id_fails(self) -> None:
        """Planted duplicate SLO ID in registry fails validation."""
        planted_slos = self.real_slos_text + "\n| `SLO-DELETE-001` | duplicate target | duplicate scope |\n"
        with self.assertRaises(DuplicateSloError):
            audit_slo_references(self.real_costs_text, planted_slos)

    def test_planted_cyclic_tombstone_fails(self) -> None:
        """Planted cyclic tombstone chain fails validation."""
        planted_slos = self.real_slos_text + (
            "\n| `SLO-LOOP-A-001` | tombstone: superseded by `SLO-LOOP-B-001` | loop A |\n"
            "| `SLO-LOOP-B-001` | tombstone: superseded by `SLO-LOOP-A-001` | loop B |\n"
        )
        with self.assertRaises(InvalidTombstoneError):
            audit_slo_references(self.real_costs_text, planted_slos)

    def test_planted_tombstone_dangling_successor_fails(self) -> None:
        """Planted tombstone pointing to a nonexistent successor fails validation."""
        planted_slos = self.real_slos_text + (
            "\n| `SLO-ORPHAN-001` | tombstone: superseded by `SLO-DOESNOTEXIST-001` | orphan |\n"
        )
        with self.assertRaises(InvalidTombstoneError):
            audit_slo_references(self.real_costs_text, planted_slos)


if __name__ == "__main__":
    unittest.main(verbosity=2)
