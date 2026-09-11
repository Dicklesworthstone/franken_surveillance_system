#!/usr/bin/env python3
"""Tests for hosted GitHub Actions workflow immutable commit pinning.

Validates that:
- Every action reference in .github/workflows/*.yml is pinned to a full 40-char commit SHA
- Every pinned action includes an audited release/tag version comment (e.g. # v4.2.2)
- Mutable tags (@v4), branch references (@main), short SHAs, and expressions fail deterministically
- Only reviewed allowlisted actions (actions/checkout) are permitted
- Emits structured, secret-free audit reports with diagnostics
"""

from __future__ import annotations

import hashlib
import json
import re
import unittest
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
WORKFLOWS_DIR = ROOT / ".github/workflows"

FULL_HEX_SHA_REGEX = re.compile(r"^[0-9a-f]{40}$")
# Allowlisted actions mapped to their allowed commit SHAs and human versions
ALLOWED_ACTIONS: dict[str, dict[str, str]] = {
    "actions/checkout": {
        "11bd71901bbe5b1630ceea73d27597364c9af683": "v4.2.2",
    },
}

ACTION_USES_LINE_REGEX = re.compile(
    r"^\s*-\s*uses:\s*['\"]?([^@\s'\"]+)@([^#\s'\"]+)['\"]?(?:\s*#\s*(.+))?$"
)


class ActionPinPolicyError(Exception):
    """Base error for workflow action pin policy violations."""


class UnpinnedActionError(ActionPinPolicyError):
    """Raised when an action reference is not a full 40-character hex SHA."""


class UnregisteredActionError(ActionPinPolicyError):
    """Raised when an action is not in the approved allowlist."""


class MissingVersionCommentError(ActionPinPolicyError):
    """Raised when a pinned action lacks an audited version comment."""


def parse_workflow_action_uses(content: str, filename: str = "<unknown>") -> list[dict[str, Any]]:
    """Extract action uses from workflow YAML content line-by-line."""
    findings: list[dict[str, Any]] = []
    for line_number, line in enumerate(content.splitlines(), 1):
        stripped = line.strip()
        if not stripped.startswith("- uses:"):
            continue
        match = ACTION_USES_LINE_REGEX.match(line)
        if match:
            action_name = match.group(1).strip()
            action_ref = match.group(2).strip()
            comment = match.group(3).strip() if match.group(3) else None
            findings.append({
                "file": filename,
                "line_number": line_number,
                "raw_line": stripped,
                "action": action_name,
                "ref": action_ref,
                "comment": comment,
            })
        else:
            # Fallback for unexpected format with - uses:
            parts = stripped[len("- uses:"):].strip().split("@")
            action_name = parts[0].strip() if parts else "unknown"
            action_ref = parts[1].strip() if len(parts) > 1 else ""
            findings.append({
                "file": filename,
                "line_number": line_number,
                "raw_line": stripped,
                "action": action_name,
                "ref": action_ref,
                "comment": None,
            })
    return findings


def validate_action_uses(uses_record: dict[str, Any]) -> dict[str, Any]:
    """Validate a single action uses record against immutable provenance policy."""
    action = uses_record["action"]
    ref = uses_record["ref"]
    comment = uses_record["comment"]
    file = uses_record["file"]
    line_num = uses_record["line_number"]

    # 1. Action must be in allowlist
    if action not in ALLOWED_ACTIONS:
        raise UnregisteredActionError(
            f"Unregistered action '{action}' at {file}:{line_num}. "
            f"Allowed actions: {sorted(ALLOWED_ACTIONS.keys())}"
        )

    # 2. Ref must be a full 40-char lowercase hex commit SHA
    if not FULL_HEX_SHA_REGEX.match(ref):
        if len(ref) < 40 and all(c in "0123456789abcdefABCDEF" for c in ref):
            reason = f"short SHA '{ref}' (must be full 40-char SHA)"
        elif ref.startswith("v") or ref in ("main", "master", "develop"):
            reason = f"mutable symbolic ref '{ref}'"
        elif "${{" in ref:
            reason = f"dynamic expression ref '{ref}'"
        else:
            reason = f"unsupported ref '{ref}'"
        raise UnpinnedActionError(
            f"Unpinned action '{action}@{ref}' at {file}:{line_num}: {reason}"
        )

    # 3. Ref must be an approved SHA for this action
    approved_shas = ALLOWED_ACTIONS[action]
    if ref not in approved_shas:
        raise UnregisteredActionError(
            f"Action '{action}@{ref}' at {file}:{line_num} uses unreviewed SHA. "
            f"Approved SHAs: {sorted(approved_shas.keys())}"
        )

    # 4. Must include a version comment
    if not comment:
        raise MissingVersionCommentError(
            f"Pinned action '{action}@{ref}' at {file}:{line_num} lacks required version comment (e.g. # v4.2.2)"
        )

    expected_version = approved_shas[ref]
    if expected_version not in comment:
        raise MissingVersionCommentError(
            f"Action '{action}@{ref}' comment '{comment}' at {file}:{line_num} does not contain expected version '{expected_version}'"
        )

    return {
        "status": "valid",
        "action": action,
        "commit": ref,
        "version": expected_version,
        "file": file,
        "line": line_num,
    }


def audit_workflow_files(workflow_paths: list[Path]) -> dict[str, Any]:
    """Audit all action uses across given workflow files."""
    all_findings: list[dict[str, Any]] = []
    validated_records: list[dict[str, Any]] = []
    errors: list[str] = []

    for path in workflow_paths:
        content = path.read_text(encoding="utf-8")
        uses_list = parse_workflow_action_uses(content, filename=str(path.name))
        all_findings.extend(uses_list)
        for record in uses_list:
            try:
                valid_info = validate_action_uses(record)
                validated_records.append(valid_info)
            except ActionPinPolicyError as exc:
                errors.append(str(exc))

    return {
        "status": "pass" if not errors else "fail",
        "files_checked": [p.name for p in workflow_paths],
        "total_actions": len(all_findings),
        "validated_count": len(validated_records),
        "errors": errors,
        "records": validated_records,
    }


class WorkflowActionPinsTests(unittest.TestCase):
    """Test suite for workflow action immutable pinning policy."""

    def setUp(self) -> None:
        self.workflow_paths = sorted(WORKFLOWS_DIR.glob("*.y*ml"))
        self.assertTrue(len(self.workflow_paths) > 0, "Workflow files must exist in .github/workflows")

    def test_live_workflows_are_pinned(self) -> None:
        """All live repo workflows must have only approved, pinned action references."""
        report = audit_workflow_files(self.workflow_paths)
        self.assertEqual(report["errors"], [], f"Live workflow policy errors: {report['errors']}")
        self.assertEqual(report["status"], "pass")
        self.assertEqual(report["total_actions"], 7, "Expected exactly 7 actions across ci.yml and release.yml")
        for rec in report["records"]:
            self.assertEqual(rec["action"], "actions/checkout")
            self.assertEqual(rec["commit"], "11bd71901bbe5b1630ceea73d27597364c9af683")
            self.assertEqual(rec["version"], "v4.2.2")

    def test_planted_tag_only_action_fails(self) -> None:
        """Planted mutable tag reference (@v4) must fail with UnpinnedActionError."""
        bad_workflow = """
name: test
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
"""
        records = parse_workflow_action_uses(bad_workflow, "test.yml")
        self.assertEqual(len(records), 1)
        with self.assertRaises(UnpinnedActionError) as ctx:
            validate_action_uses(records[0])
        self.assertIn("mutable symbolic ref 'v4'", str(ctx.exception))

    def test_planted_short_sha_fails(self) -> None:
        """Planted short commit SHA must fail with UnpinnedActionError."""
        bad_workflow = """
name: test
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@11bd719 # v4.2.2
"""
        records = parse_workflow_action_uses(bad_workflow, "test.yml")
        with self.assertRaises(UnpinnedActionError) as ctx:
            validate_action_uses(records[0])
        self.assertIn("short SHA", str(ctx.exception))

    def test_planted_branch_ref_fails(self) -> None:
        """Planted branch reference (@main) must fail with UnpinnedActionError."""
        bad_workflow = """
name: test
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@main # main
"""
        records = parse_workflow_action_uses(bad_workflow, "test.yml")
        with self.assertRaises(UnpinnedActionError) as ctx:
            validate_action_uses(records[0])
        self.assertIn("mutable symbolic ref 'main'", str(ctx.exception))

    def test_planted_missing_version_comment_fails(self) -> None:
        """Planted pinned SHA without version comment must fail with MissingVersionCommentError."""
        bad_workflow = """
name: test
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@11bd71901bbe5b1630ceea73d27597364c9af683
"""
        records = parse_workflow_action_uses(bad_workflow, "test.yml")
        with self.assertRaises(MissingVersionCommentError) as ctx:
            validate_action_uses(records[0])
        self.assertIn("lacks required version comment", str(ctx.exception))

    def test_planted_unregistered_action_fails(self) -> None:
        """Planted unapproved action repository must fail with UnregisteredActionError."""
        bad_workflow = """
name: test
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - uses: thirdparty/untrusted-action@11bd71901bbe5b1630ceea73d27597364c9af683 # v1.0
"""
        records = parse_workflow_action_uses(bad_workflow, "test.yml")
        with self.assertRaises(UnregisteredActionError) as ctx:
            validate_action_uses(records[0])
        self.assertIn("Unregistered action", str(ctx.exception))

    def test_planted_unreviewed_sha_fails(self) -> None:
        """Planted unknown commit SHA for approved action fails."""
        bad_workflow = """
name: test
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@0000000000000000000000000000000000000000 # v4.2.2
"""
        records = parse_workflow_action_uses(bad_workflow, "test.yml")
        with self.assertRaises(UnregisteredActionError) as ctx:
            validate_action_uses(records[0])
        self.assertIn("unreviewed SHA", str(ctx.exception))

    def test_pre_fix_unpinned_state_reproduced_and_rejected(self) -> None:
        """Verify that the pre-fix state with floating tags fails with exactly 7 errors."""
        ci_unpinned = (WORKFLOWS_DIR / "ci.yml").read_text(encoding="utf-8").replace(
            "actions/checkout@11bd71901bbe5b1630ceea73d27597364c9af683 # v4.2.2",
            "actions/checkout@v4",
        )
        release_unpinned = (WORKFLOWS_DIR / "release.yml").read_text(encoding="utf-8").replace(
            "actions/checkout@11bd71901bbe5b1630ceea73d27597364c9af683 # v4.2.2",
            "actions/checkout@v4",
        )
        ci_findings = parse_workflow_action_uses(ci_unpinned, "ci.yml")
        release_findings = parse_workflow_action_uses(release_unpinned, "release.yml")
        self.assertEqual(len(ci_findings), 2)
        self.assertEqual(len(release_findings), 5)
        
        errors = []
        for r in ci_findings + release_findings:
            try:
                validate_action_uses(r)
            except ActionPinPolicyError as exc:
                errors.append(str(exc))
        self.assertEqual(len(errors), 7)
        for err in errors:
            self.assertIn("mutable symbolic ref 'v4'", err)


if __name__ == "__main__":
    unittest.main(verbosity=2)
