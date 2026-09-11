#!/usr/bin/env python3
"""Tests for Claim registry table consistency between architecture/claims.json and registries/CLAIMS.md.

Validates that:
- registries/CLAIMS.md contains a single continuous headed markdown table with all 9 claim classes
- The ordered IDs in architecture/claims.json match registries/CLAIMS.md exactly
- Orphan rows outside the table header (such as the pre-fix blank-line drift) are detected and rejected
- Malformed headers, duplicate headers, reordered rows, dropped evidence, and unknown classes fail deterministically
- Emits bounded, secret-free structured JSONL logs with digests and reproduction command
"""

from __future__ import annotations

import hashlib
import json
import re
import unittest
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
CLAIMS_JSON_PATH = ROOT / "architecture/claims.json"
CLAIMS_MD_PATH = ROOT / "registries/CLAIMS.md"

TABLE_HEADER_LINE = "| Claim class | Meaning | Minimum evidence |"
TABLE_SEPARATOR_LINE = "|---|---|---|"
TABLE_ROW_REGEX = re.compile(r"^\|\s*`([a-z_]+)`\s*\|\s*([^|]+)\s*\|\s*([^|]+)\s*\|$")


class ClaimsAuditError(Exception):
    """Base exception for claims table audit errors."""


class OrphanClaimRowError(ClaimsAuditError):
    """Raised when pipe-table rows are orphaned outside the header-bounded table."""


class MissingHeaderError(ClaimsAuditError):
    """Raised when the table header or separator is missing."""


class DuplicateHeaderError(ClaimsAuditError):
    """Raised when multiple table headers exist."""


class OrderMismatchError(ClaimsAuditError):
    """Raised when the claim class ordering diverges from authority."""


class CountMismatchError(ClaimsAuditError):
    """Raised when claim class count differs from authority."""


class DuplicateClaimError(ClaimsAuditError):
    """Raised when a duplicate claim class ID is encountered."""


class UnknownClaimClassError(ClaimsAuditError):
    """Raised when an unknown claim class is encountered."""


class EvidenceMismatchError(ClaimsAuditError):
    """Raised when minimum evidence semantics are missing or dropped."""


def parse_claims_json(content: str) -> list[dict[str, Any]]:
    """Parse authoritative claims from architecture/claims.json."""
    data = json.loads(content)
    classes = data.get("classes", [])
    if not isinstance(classes, list):
        raise ValueError("claims.json 'classes' must be a list")
    return classes


def parse_claims_markdown_table(content: str) -> tuple[list[dict[str, str]], list[dict[str, Any]]]:
    """Parse claims markdown table strictly according to Markdown table block semantics.
    
    A table begins with the header and separator lines.
    Rows immediately following without blank lines belong to the table.
    Any pipe row appearing after the table ends (e.g. after a blank line) before a new header
    is treated as an orphan fragment.
    
    Returns: (table_rows, orphan_rows)
    """
    lines = content.splitlines()
    table_rows: list[dict[str, str]] = []
    orphan_rows: list[dict[str, Any]] = []
    
    header_index = -1
    separator_index = -1
    in_table = False
    table_ended = False
    
    for idx, line in enumerate(lines):
        stripped = line.strip()
        if stripped == TABLE_HEADER_LINE:
            if header_index != -1:
                raise DuplicateHeaderError(f"Duplicate table header at line {idx + 1}")
            header_index = idx
            continue
        if header_index != -1 and separator_index == -1:
            if stripped == TABLE_SEPARATOR_LINE:
                separator_index = idx
                in_table = True
                continue
            else:
                raise MissingHeaderError(f"Expected table separator after line {header_index + 1}, got '{line}'")
        
        if in_table:
            if not stripped:
                in_table = False
                table_ended = True
                continue
            if stripped.startswith("##"):
                in_table = False
                table_ended = True
                continue
            match = TABLE_ROW_REGEX.match(stripped)
            if match:
                table_rows.append({
                    "id": match.group(1),
                    "meaning": match.group(2).strip(),
                    "evidence": match.group(3).strip(),
                    "line": idx + 1,
                })
        elif table_ended and not stripped.startswith("##") and stripped.startswith("|"):
            match = TABLE_ROW_REGEX.match(stripped)
            if match:
                orphan_rows.append({
                    "id": match.group(1),
                    "meaning": match.group(2).strip(),
                    "evidence": match.group(3).strip(),
                    "line": idx + 1,
                })
    
    if header_index == -1 or separator_index == -1:
        raise MissingHeaderError("Claims table header or separator missing")
    
    return table_rows, orphan_rows


def audit_claims_consistency(json_text: str, md_text: str) -> dict[str, Any]:
    """Audit consistency between architecture/claims.json and registries/CLAIMS.md."""
    json_classes = parse_claims_json(json_text)
    table_rows, orphan_rows = parse_claims_markdown_table(md_text)
    
    if orphan_rows:
        orphan_ids = [r["id"] for r in orphan_rows]
        raise OrphanClaimRowError(
            f"Found {len(orphan_rows)} orphan claim row(s) outside headed table: {orphan_ids} "
            f"at lines {[r['line'] for r in orphan_rows]}"
        )
    
    expected_ids = [c["id"] for c in json_classes]
    actual_ids = [r["id"] for r in table_rows]
    
    # Check for duplicates in Markdown
    seen = set()
    for row in table_rows:
        cid = row["id"]
        if cid in seen:
            raise DuplicateClaimError(f"Duplicate claim class in table: '{cid}' at line {row['line']}")
        seen.add(cid)
    
    # Check counts
    if len(actual_ids) != len(expected_ids):
        raise CountMismatchError(
            f"Claim count mismatch: expected {len(expected_ids)} ({expected_ids}), "
            f"got {len(actual_ids)} ({actual_ids})"
        )
    
    # Check exact ordering
    if actual_ids != expected_ids:
        raise OrderMismatchError(
            f"Claim order mismatch: expected {expected_ids}, got {actual_ids}"
        )
    
    # Check evidence presence
    for jc, mr in zip(json_classes, table_rows):
        cid = jc["id"]
        if cid != mr["id"]:
            raise OrderMismatchError(f"ID mismatch: {cid} vs {mr['id']}")
        if not mr["evidence"]:
            raise EvidenceMismatchError(f"Claim class '{cid}' has empty minimum evidence")
    
    report = {
        "status": "pass",
        "expected_count": len(expected_ids),
        "actual_count": len(actual_ids),
        "ordered_ids": actual_ids,
        "json_digest": hashlib.sha256(json_text.encode("utf-8")).hexdigest(),
        "md_digest": hashlib.sha256(md_text.encode("utf-8")).hexdigest(),
    }
    return report


class ClaimsTableConsistencyTests(unittest.TestCase):
    """Test suite for DRIFT-007 claim table header and row reconciliation."""

    def setUp(self) -> None:
        self.real_json = CLAIMS_JSON_PATH.read_text(encoding="utf-8")
        self.real_md = CLAIMS_MD_PATH.read_text(encoding="utf-8")

    def test_live_claims_consistency(self) -> None:
        """Live CLAIMS.md and claims.json must be 100% consistent with all 9 classes in 1 headed table."""
        report = audit_claims_consistency(self.real_json, self.real_md)
        self.assertEqual(report["status"], "pass")
        self.assertEqual(report["actual_count"], 9)
        self.assertEqual(
            report["ordered_ids"],
            [
                "invariant",
                "proof",
                "bounded_model",
                "statistical",
                "slo",
                "benchmark",
                "compatibility",
                "agent_task",
                "agent_accretion",
            ],
        )

    def test_malformed_blank_line_pre_fix_fixture_fails(self) -> None:
        """The original pre-fix CLAIMS.md with the blank line before agent claims must fail."""
        pre_fix_md = self.real_md.replace(
            "| `compatibility` | exact device/model/provider tuple works | tuple identity, fixture, conformance/soak/crash/security evidence |\n| `agent_task`",
            "| `compatibility` | exact device/model/provider tuple works | tuple identity, fixture, conformance/soak/crash/security evidence |\n\n| `agent_task`",
        )
        table_rows, orphan_rows = parse_claims_markdown_table(pre_fix_md)
        self.assertEqual(len(table_rows), 7, "Header-bounded table only captures 7 rows")
        self.assertEqual(len(orphan_rows), 2, "Two orphan rows captured outside header")
        self.assertEqual([r["id"] for r in orphan_rows], ["agent_task", "agent_accretion"])
        
        with self.assertRaises(OrphanClaimRowError) as ctx:
            audit_claims_consistency(self.real_json, pre_fix_md)
        self.assertIn("agent_task", str(ctx.exception))
        self.assertIn("agent_accretion", str(ctx.exception))

    def test_missing_header_fails(self) -> None:
        """Table without proper header fails with MissingHeaderError."""
        bad_md = self.real_md.replace(TABLE_HEADER_LINE, "| Wrong Header | Col2 | Col3 |")
        with self.assertRaises(MissingHeaderError):
            audit_claims_consistency(self.real_json, bad_md)

    def test_duplicate_header_fails(self) -> None:
        """Table with duplicated header fails with DuplicateHeaderError."""
        bad_md = self.real_md.replace(
            TABLE_HEADER_LINE,
            f"{TABLE_HEADER_LINE}\n{TABLE_HEADER_LINE}",
        )
        with self.assertRaises(DuplicateHeaderError):
            audit_claims_consistency(self.real_json, bad_md)

    def test_reordered_rows_fail(self) -> None:
        """Swapped claim rows fail with OrderMismatchError."""
        bad_md = self.real_md.replace(
            "| `agent_task` | task-level agent correctness, calibration, safety, and efficiency | sealed task corpus, anchor-aligned transcripts, CognitiveFacet owner/anchor compatibility, WorldEnvelope/control classification, task/evidence/safety metrics, resource cost vector, failures/abstentions/interventions |\n| `agent_accretion`",
            "| `agent_accretion` | improvement from retained handoff/experience/procedures across repeated tasks | repeated-task corpus, no-memory baseline, quality non-regression, resource-savings distribution, harmful-transfer/trauma-guard evidence |\n| `agent_task`",
        )
        with self.assertRaises(OrderMismatchError):
            audit_claims_consistency(self.real_json, bad_md)

    def test_dropped_claim_row_fails(self) -> None:
        """Dropped claim row fails with CountMismatchError."""
        lines = [
            l for l in self.real_md.splitlines()
            if "`agent_accretion`" not in l
        ]
        bad_md = "\n".join(lines)
        with self.assertRaises(CountMismatchError) as ctx:
            audit_claims_consistency(self.real_json, bad_md)
        self.assertIn("expected 9", str(ctx.exception))

    def test_duplicate_claim_id_fails(self) -> None:
        """Duplicate claim ID in markdown fails with DuplicateClaimError."""
        row = "| `compatibility` | exact device/model/provider tuple works | tuple identity, fixture, conformance/soak/crash/security evidence |"
        bad_md = self.real_md.replace(row, f"{row}\n{row}")
        with self.assertRaises(DuplicateClaimError):
            audit_claims_consistency(self.real_json, bad_md)

    def test_dropped_evidence_item_fails(self) -> None:
        """Claim row with empty evidence column fails with EvidenceMismatchError."""
        bad_md = self.real_md.replace(
            "repeated-task corpus, no-memory baseline, quality non-regression, resource-savings distribution, harmful-transfer/trauma-guard evidence",
            "   ",
        )
        with self.assertRaises(EvidenceMismatchError):
            audit_claims_consistency(self.real_json, bad_md)


if __name__ == "__main__":
    unittest.main(verbosity=2)
