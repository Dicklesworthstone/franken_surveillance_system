#!/usr/bin/env python3
"""Tests for Beads tracker ignore policy and versionability contract (TRACKER-001 / fss-x4a.1.7).

Validates that:
- Canonical tracker artifacts (.beads/issues.jsonl, .beads/config.yaml, .beads/.gitignore,
  .beads/metadata.json) are tracked in Git and NOT ignored by any gitignore rules.
- Ephemeral database state, WAL files, locks, history, and recovery directories
  (.beads/beads.db, .beads/beads.db-wal, .beads/*.lock, .beads/.br_history/, .beads/.br_recovery/)
  are strictly ignored by .beads/.gitignore.
- Root .gitignore does NOT contain broad ignore rules (like `/.beads/`) that blind Git
  to .beads/.gitignore or prevent issues.jsonl from being tracked.
- Deterministic planted fault tests verify fail-closed behavior for broad root ignores,
  ignored JSONL files, or leaked database/lock/recovery artifacts.
- Emits bounded, secret-free structured JSONL logs.
"""

from __future__ import annotations

import fnmatch
import hashlib
import json
import os
import re
import subprocess
import time
import unittest
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
ROOT_GITIGNORE_PATH = ROOT / ".gitignore"
BEADS_GITIGNORE_PATH = ROOT / ".beads/.gitignore"
BEADS_CONFIG_PATH = ROOT / ".beads/config.yaml"
BEADS_ISSUES_PATH = ROOT / ".beads/issues.jsonl"
BEADS_METADATA_PATH = ROOT / ".beads/metadata.json"

CANONICAL_TRACKER_FILES = [
    ".beads/issues.jsonl",
    ".beads/config.yaml",
    ".beads/.gitignore",
    ".beads/metadata.json",
]

EPHEMERAL_TEST_PATHS = [
    ".beads/beads.db",
    ".beads/beads.db-wal",
    ".beads/beads.db-shm",
    ".beads/beads.db-wal-cert",
    ".beads/beads.db-wal-cert-head",
    ".beads/beads.db-fsqlite-ns-gate",
    ".beads/beads.db-fsqlite-ns-use",
    ".beads/beads.db.fsqlite-migration-state",
    ".beads/.write.lock",
    ".beads/daemon.lock",
    ".beads/.sync.lock",
    ".beads/.bv.lock",
    ".beads/.br-db-openers-test.lock",
    ".beads/.br_history/snapshot.jsonl",
    ".beads/.br_recovery/quarantine.bak",
    ".beads/last-touched",
    ".beads/daemon.log",
    ".beads/daemon.pid",
    ".beads/bd.sock",
    ".beads/sync-state.json",
    ".beads/sync_base.jsonl",
    ".beads/beads.base.jsonl",
    ".beads/beads.left.jsonl",
    ".beads/beads.right.jsonl",
]


class TrackerIgnorePolicyError(Exception):
    """Base exception for tracker ignore policy audit errors."""


class BroadBeadsIgnoreError(TrackerIgnorePolicyError):
    """Raised when root .gitignore contains an unqualified rule ignoring all of .beads/."""


class CanonicalTrackerIgnoredError(TrackerIgnorePolicyError):
    """Raised when canonical tracker artifacts (e.g. issues.jsonl) are ignored."""


class EphemeralArtifactNotIgnoredError(TrackerIgnorePolicyError):
    """Raised when ephemeral tracker artifacts (e.g. beads.db, locks, recovery) are not ignored."""


class TrackerFileUntrackedError(TrackerIgnorePolicyError):
    """Raised when canonical tracker artifacts are not tracked in Git index."""


def audit_root_gitignore(content: str) -> None:
    """Ensure root .gitignore does not broadly ignore the .beads directory."""
    lines = [line.strip() for line in content.splitlines()]
    forbidden_patterns = ["/.beads/", "/.beads", ".beads/", ".beads"]
    for idx, line in enumerate(lines, 1):
        if line.startswith("#"):
            continue
        if line in forbidden_patterns:
            raise BroadBeadsIgnoreError(
                f"Root .gitignore contains broad ignore rule '{line}' at line {idx} "
                f"which disables .beads/.gitignore and blinds Git to canonical issues.jsonl"
            )


def audit_beads_gitignore(content: str) -> None:
    """Ensure .beads/.gitignore contains all mandatory ignore patterns and does not ignore canonical files."""
    lines = [line.strip() for line in content.splitlines() if line.strip() and not line.strip().startswith("#")]

    required_patterns = [
        "*.db",
        "*.db-wal*",
        "*.db-shm",
        "*.lock",
        ".br_history/",
        ".br_recovery/",
    ]
    for pattern in required_patterns:
        if pattern not in lines:
            raise EphemeralArtifactNotIgnoredError(
                f".beads/.gitignore is missing required ignore pattern '{pattern}'"
            )

    disallowed_exact_patterns = [
        "issues.jsonl",
        "*.jsonl",
        "config.yaml",
        "*.yaml",
        ".gitignore",
        "metadata.json",
    ]
    for pattern in disallowed_exact_patterns:
        if pattern in lines:
            raise CanonicalTrackerIgnoredError(
                f".beads/.gitignore contains disallowed pattern '{pattern}' that would ignore canonical state"
            )


def match_gitignore_pattern(pattern: str, relative_path: str, is_dir: bool = False) -> bool:
    """Pure-python gitignore pattern matcher for path relative to .beads/."""
    pattern = pattern.strip()
    if not pattern or pattern.startswith("#"):
        return False

    pattern_is_dir = pattern.endswith("/")
    if pattern_is_dir:
        pattern = pattern.rstrip("/")
        if not is_dir and "/" not in relative_path:
            return False

    if pattern.startswith("/"):
        pattern = pattern.lstrip("/")
        return fnmatch.fnmatch(relative_path, pattern)

    if "/" in pattern:
        return fnmatch.fnmatch(relative_path, pattern)

    parts = relative_path.split("/")
    filename = parts[-1]
    if fnmatch.fnmatch(filename, pattern):
        return True
    for p in parts[:-1]:
        if fnmatch.fnmatch(p, pattern):
            return True
    return False


def is_path_ignored_by_beads_gitignore(inner_gitignore_content: str, path_in_beads: str, is_dir: bool = False) -> bool:
    """Test if a path relative to .beads/ is ignored by inner .beads/.gitignore rules."""
    ignored = False
    for line in inner_gitignore_content.splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        if line.startswith("!"):
            neg_pattern = line[1:]
            if match_gitignore_pattern(neg_pattern, path_in_beads, is_dir=is_dir):
                ignored = False
        else:
            if match_gitignore_pattern(line, path_in_beads, is_dir=is_dir):
                ignored = True
    return ignored


def audit_tracker_ignore_matrix(
    root_gitignore: str,
    inner_gitignore: str,
    canonical_files: list[str] | None = None,
    ephemeral_files: list[str] | None = None,
) -> dict[str, Any]:
    """Audit tracker ignore rules across root and inner gitignore."""
    audit_root_gitignore(root_gitignore)
    audit_beads_gitignore(inner_gitignore)

    canonical = canonical_files or CANONICAL_TRACKER_FILES
    ephemeral = ephemeral_files or EPHEMERAL_TEST_PATHS

    # Verify canonical files are NOT ignored by inner gitignore
    for full_path in canonical:
        rel = full_path.replace(".beads/", "")
        if is_path_ignored_by_beads_gitignore(inner_gitignore, rel):
            raise CanonicalTrackerIgnoredError(
                f"Canonical tracker file '{full_path}' is ignored by inner .beads/.gitignore"
            )

    # Verify ephemeral files ARE ignored by inner gitignore
    for full_path in ephemeral:
        rel = full_path.replace(".beads/", "")
        is_directory = full_path.endswith("/") or ".br_history/" in full_path or ".br_recovery/" in full_path
        if not is_path_ignored_by_beads_gitignore(inner_gitignore, rel, is_dir=is_directory):
            raise EphemeralArtifactNotIgnoredError(
                f"Ephemeral tracker artifact '{full_path}' is NOT ignored by inner .beads/.gitignore"
            )

    return {
        "status": "pass",
        "canonical_count": len(canonical),
        "ephemeral_count": len(ephemeral),
        "root_digest": hashlib.sha256(root_gitignore.encode("utf-8")).hexdigest(),
        "inner_digest": hashlib.sha256(inner_gitignore.encode("utf-8")).hexdigest(),
    }


class TrackerIgnorePolicyTests(unittest.TestCase):
    """Test suite for TRACKER-001 ignore policy and versioning contract."""

    def setUp(self) -> None:
        self.root_gitignore_text = ROOT_GITIGNORE_PATH.read_text(encoding="utf-8")
        self.beads_gitignore_text = BEADS_GITIGNORE_PATH.read_text(encoding="utf-8")
        self.start_time = time.monotonic()

    def tearDown(self) -> None:
        elapsed = time.monotonic() - self.start_time
        log_entry = {
            "schema_version": "franken_surveillance.test_log.v1",
            "run_id": f"run-{int(time.time())}",
            "test_name": self._testMethodName,
            "elapsed_seconds": round(elapsed, 4),
            "status": "ok",
        }
        print(f"TRACKER_POLICY_LOG: {json.dumps(log_entry)}")

    def test_live_root_gitignore_does_not_broadly_ignore_beads(self) -> None:
        """Root .gitignore must not contain broad /.beads/ or .beads/ pattern."""
        audit_root_gitignore(self.root_gitignore_text)
        self.assertNotIn("/.beads/", self.root_gitignore_text)
        self.assertNotIn("/.beads\n", self.root_gitignore_text)

    def test_live_inner_beads_gitignore_has_all_required_rules(self) -> None:
        """Inner .beads/.gitignore must contain all required ignore patterns."""
        audit_beads_gitignore(self.beads_gitignore_text)

    def test_live_tracker_policy_matrix(self) -> None:
        """Live root and inner gitignore must pass the combined ignore matrix audit."""
        result = audit_tracker_ignore_matrix(self.root_gitignore_text, self.beads_gitignore_text)
        self.assertEqual(result["status"], "pass")
        self.assertEqual(result["canonical_count"], len(CANONICAL_TRACKER_FILES))
        self.assertGreaterEqual(result["ephemeral_count"], len(EPHEMERAL_TEST_PATHS))

    def test_live_git_tracked_status(self) -> None:
        """Git index must actively track issues.jsonl, config.yaml, .gitignore, metadata.json."""
        proc = subprocess.run(
            ["git", "ls-files", ".beads/issues.jsonl", ".beads/config.yaml", ".beads/.gitignore", ".beads/metadata.json"],
            cwd=ROOT,
            capture_output=True,
            text=True,
            check=True,
        )
        tracked_files = [line.strip() for line in proc.stdout.splitlines() if line.strip()]
        for expected in CANONICAL_TRACKER_FILES:
            self.assertIn(expected, tracked_files, f"Expected {expected} to be tracked in Git index")

    def test_live_git_check_ignore_negative_for_canonical_files(self) -> None:
        """git check-ignore --no-index must return exit code 1 for canonical tracker files."""
        for path in CANONICAL_TRACKER_FILES:
            proc = subprocess.run(
                ["git", "check-ignore", "--no-index", "-v", path],
                cwd=ROOT,
                capture_output=True,
                text=True,
            )
            self.assertEqual(
                proc.returncode,
                1,
                f"Expected canonical file {path} to NOT be ignored, but git check-ignore returned: {proc.stdout}",
            )

    def test_live_git_check_ignore_positive_for_ephemeral_files(self) -> None:
        """git check-ignore --no-index must return exit code 0 for ephemeral database, lock, and recovery files."""
        for path in EPHEMERAL_TEST_PATHS:
            proc = subprocess.run(
                ["git", "check-ignore", "--no-index", "-v", path],
                cwd=ROOT,
                capture_output=True,
                text=True,
            )
            self.assertEqual(
                proc.returncode,
                0,
                f"Expected ephemeral path {path} to be ignored by git, but git check-ignore returned exit {proc.returncode}: {proc.stderr}",
            )
            self.assertIn(".beads/.gitignore", proc.stdout, f"Path {path} must be ignored by .beads/.gitignore")

    def test_fault_planted_broad_root_ignore_fails(self) -> None:
        """Planted /.beads/ in root .gitignore must fail with BroadBeadsIgnoreError."""
        bad_root = self.root_gitignore_text + "\n/.beads/\n"
        with self.assertRaises(BroadBeadsIgnoreError) as ctx:
            audit_root_gitignore(bad_root)
        self.assertIn("/.beads/", str(ctx.exception))

    def test_fault_planted_ignored_issues_jsonl_fails(self) -> None:
        """Planted issues.jsonl pattern in .beads/.gitignore must fail with CanonicalTrackerIgnoredError."""
        bad_inner = self.beads_gitignore_text + "\nissues.jsonl\n"
        with self.assertRaises(CanonicalTrackerIgnoredError) as ctx:
            audit_beads_gitignore(bad_inner)
        self.assertIn("issues.jsonl", str(ctx.exception))

    def test_fault_planted_wildcard_jsonl_ignore_fails(self) -> None:
        """Planted *.jsonl in .beads/.gitignore must fail with CanonicalTrackerIgnoredError."""
        bad_inner = self.beads_gitignore_text + "\n*.jsonl\n"
        with self.assertRaises(CanonicalTrackerIgnoredError) as ctx:
            audit_beads_gitignore(bad_inner)
        self.assertIn("*.jsonl", str(ctx.exception))

    def test_fault_planted_missing_db_pattern_fails(self) -> None:
        """Removing *.db pattern from .beads/.gitignore must fail with EphemeralArtifactNotIgnoredError."""
        bad_inner = self.beads_gitignore_text.replace("*.db\n", "")
        with self.assertRaises(EphemeralArtifactNotIgnoredError) as ctx:
            audit_beads_gitignore(bad_inner)
        self.assertIn("*.db", str(ctx.exception))

    def test_fault_planted_missing_recovery_pattern_fails(self) -> None:
        """Removing .br_recovery/ from .beads/.gitignore must fail with EphemeralArtifactNotIgnoredError."""
        bad_inner = self.beads_gitignore_text.replace(".br_recovery/\n", "")
        with self.assertRaises(EphemeralArtifactNotIgnoredError) as ctx:
            audit_beads_gitignore(bad_inner)
        self.assertIn(".br_recovery/", str(ctx.exception))

    def test_fault_planted_missing_lock_pattern_fails(self) -> None:
        """Removing *.lock from .beads/.gitignore must fail with EphemeralArtifactNotIgnoredError."""
        bad_inner = self.beads_gitignore_text.replace("*.lock\n", "")
        with self.assertRaises(EphemeralArtifactNotIgnoredError) as ctx:
            audit_beads_gitignore(bad_inner)
        self.assertIn("*.lock", str(ctx.exception))


if __name__ == "__main__":
    unittest.main(verbosity=2)
