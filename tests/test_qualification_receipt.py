#!/usr/bin/env python3
"""tests/test_qualification_receipt.py — contract suite for the local qualification
lane receipt schema and aggregator (FSS-187, bead fss-x4a.26.7).

The receipt writer is the one durable writer for qualification receipts; these
tests pin its honesty semantics: malformed, empty, or failed command records can
never produce a passing receipt; writes are atomic (no partial files); digests
are deterministic over the same inputs; and corrupt input is recorded, never
silently dropped.
"""

import json
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO / "scripts"))

import qualification_receipt as qr  # noqa: E402


def _receipt_kwargs(tmp: Path, commands, malformed=False, status="passed"):
    lock = tmp / "Cargo.lock"
    lock.write_text("# lock\n", encoding="utf-8")
    return dict(
        commands=commands,
        malformed=malformed,
        lane="policy",
        source_commit="git:" + "a" * 40,
        source_tree="clean",
        sibling_digest="sha256:" + "1" * 64,
        host_digest="sha256:" + "2" * 64,
        toolchain="nightly-2026-08-31",
        target="darwin-arm64",
        started_ns=1_000,
        finished_ns=2_000,
        status=status,
        manifest_root="sha256:" + "3" * 64,
        cargo_lock=lock,
    )


GOOD_COMMAND = {
    "argv": ["python3", "scripts/check-policy.py"],
    "status": "passed",
    "outputDigest": "sha256:" + "0" * 64,
}


class TestReceiptSchema(unittest.TestCase):
    """The built receipt carries the registered schema and every provenance field."""

    def test_happy_path_receipt_fields(self):
        with tempfile.TemporaryDirectory() as td:
            receipt = qr.build_receipt(**_receipt_kwargs(Path(td), [GOOD_COMMAND]))
        self.assertEqual(receipt["schema"], qr.RECEIPT_SCHEMA)
        self.assertEqual(receipt["laneId"], qr.LANE_IDS["policy"])
        self.assertEqual(receipt["sourceCommit"], "git:" + "a" * 40)
        self.assertEqual(receipt["status"], "passed")
        self.assertEqual(receipt["commands"], [GOOD_COMMAND])
        self.assertTrue(receipt["cargoLockDigest"].startswith("sha256:"))
        self.assertTrue(receipt["artifactManifestDigest"].startswith("sha256:"))
        self.assertEqual(receipt["startedAt"]["clockBasis"], "host-realtime")
        self.assertEqual(receipt["finishedAt"]["earliestNs"], 2_000)

    def test_deterministic_over_same_inputs(self):
        with tempfile.TemporaryDirectory() as td:
            kwargs = _receipt_kwargs(Path(td), [GOOD_COMMAND])
            r1 = qr.build_receipt(**kwargs)
            r2 = qr.build_receipt(**kwargs)
        self.assertEqual(
            json.dumps(r1, sort_keys=True), json.dumps(r2, sort_keys=True),
            "same inputs must produce byte-identical receipts",
        )


class TestHonestyDowngrades(unittest.TestCase):
    """A receipt may never upgrade beyond the truth of its command records."""

    def test_failed_command_forces_failed_receipt(self):
        bad = {**GOOD_COMMAND, "status": "failed"}
        with tempfile.TemporaryDirectory() as td:
            receipt = qr.build_receipt(**_receipt_kwargs(Path(td), [GOOD_COMMAND, bad]))
        self.assertEqual(receipt["status"], "failed", "a failed command must fail the receipt")

    def test_empty_command_record_set_fails(self):
        with tempfile.TemporaryDirectory() as td:
            receipt = qr.build_receipt(**_receipt_kwargs(Path(td), []))
        self.assertEqual(receipt["status"], "failed")
        self.assertEqual(receipt["commands"][0]["status"], "failed")

    def test_malformed_flag_fails(self):
        with tempfile.TemporaryDirectory() as td:
            receipt = qr.build_receipt(**_receipt_kwargs(Path(td), [GOOD_COMMAND], malformed=True))
        self.assertEqual(receipt["status"], "failed")


class TestRecordLoading(unittest.TestCase):
    """commands.jsonl loading: valid rows pass; anything else becomes a failed corrupt record."""

    def _write(self, td: Path, lines: list[str]) -> Path:
        p = Path(td) / "commands.jsonl"
        p.write_text("\n".join(lines) + "\n", encoding="utf-8")
        return p

    def test_valid_rows_load(self):
        with tempfile.TemporaryDirectory() as td:
            path = self._write(Path(td), [json.dumps(GOOD_COMMAND), json.dumps({**GOOD_COMMAND, "status": "failed"})])
            commands, malformed = qr.load_command_records(path)
        self.assertFalse(malformed)
        self.assertEqual(len(commands), 2)

    def test_garbage_line_becomes_corrupt_record(self):
        with tempfile.TemporaryDirectory() as td:
            path = self._write(Path(td), [json.dumps(GOOD_COMMAND), "not json at all {{{"])
            commands, malformed = qr.load_command_records(path)
        self.assertTrue(malformed)
        self.assertEqual(commands[1]["argv"], ["corrupt_record"])
        self.assertEqual(commands[1]["status"], "failed")
        self.assertTrue(commands[1]["outputDigest"].startswith("sha256:"))

    def test_structurally_invalid_row_is_corrupt(self):
        bad = {"argv": [], "status": "passed", "outputDigest": "sha256:" + "0" * 64}
        with tempfile.TemporaryDirectory() as td:
            path = self._write(Path(td), [json.dumps(bad)])
            commands, malformed = qr.load_command_records(path)
        self.assertTrue(malformed)
        self.assertEqual(commands[0]["argv"], ["corrupt_record"])

    def test_overlong_argv_item_is_corrupt(self):
        bad = {**GOOD_COMMAND, "argv": ["x" * (qr.ARGV_ITEM_MAX + 1)]}
        with tempfile.TemporaryDirectory() as td:
            path = self._write(Path(td), [json.dumps(bad)])
            commands, malformed = qr.load_command_records(path)
        self.assertTrue(malformed)
        self.assertEqual(commands[0]["argv"], ["corrupt_record"])

    def test_missing_records_file_is_empty_not_corrupt(self):
        with tempfile.TemporaryDirectory() as td:
            commands, malformed = qr.load_command_records(Path(td) / "commands.jsonl")
        self.assertEqual(commands, [])
        self.assertFalse(malformed)

    def test_duplicate_records_are_kept_honestly(self):
        with tempfile.TemporaryDirectory() as td:
            path = self._write(Path(td), [json.dumps(GOOD_COMMAND), json.dumps(GOOD_COMMAND)])
            commands, malformed = qr.load_command_records(path)
        self.assertEqual(len(commands), 2, "duplicates must not be silently coalesced")


class TestDurability(unittest.TestCase):
    """Receipt writes are atomic: no partial or torn file is ever visible."""

    def test_atomic_write_leaves_no_temp_files(self):
        with tempfile.TemporaryDirectory() as td:
            target = Path(td) / "receipt.json"
            qr.write_json_atomic(target, {"status": "passed"})
            self.assertTrue(target.is_file())
            leftovers = [p.name for p in Path(td).iterdir() if p.name != "receipt.json"]
            self.assertEqual(leftovers, [], f"stray temp files: {leftovers}")

    def test_written_receipt_round_trips(self):
        with tempfile.TemporaryDirectory() as td:
            receipt = qr.build_receipt(**_receipt_kwargs(Path(td), [GOOD_COMMAND]))
            target = Path(td) / "receipt.json"
            qr.write_qualification_receipt(target, receipt)
            loaded = json.loads(target.read_text(encoding="utf-8"))
        self.assertEqual(loaded["status"], "passed")
        self.assertEqual(loaded["schema"], qr.RECEIPT_SCHEMA)

    def test_finalize_end_to_end_via_cli(self):
        with tempfile.TemporaryDirectory() as td:
            run_dir = Path(td) / "run"
            prep = subprocess.run(
                [sys.executable, str(REPO / "scripts" / "qualification_receipt.py"),
                 "prepare-run-dir", "--exact", str(run_dir)],
                capture_output=True, text=True,
            )
            self.assertEqual(prep.returncode, 0, prep.stderr[-200:])
            records = run_dir / "commands.jsonl"
            records.write_text(json.dumps(GOOD_COMMAND) + "\n", encoding="utf-8")
            lock = Path(td) / "Cargo.lock"
            lock.write_text("# lock\n", encoding="utf-8")
            fin = subprocess.run(
                [sys.executable, str(REPO / "scripts" / "qualification_receipt.py"), "finalize",
                 "--output", str(run_dir / "qualification-receipt.json"),
                 "--records", str(records), "--lane", "policy",
                 "--source-commit", "git:" + "a" * 40, "--source-tree", "clean",
                 "--sibling-digest", "sha256:" + "1" * 64, "--host-digest", "sha256:" + "2" * 64,
                 "--toolchain", "nightly-2026-08-31", "--target", "darwin-arm64",
                 "--started-ns", "1000", "--finished-ns", "2000", "--status", "passed",
                 "--manifest-root", "sha256:" + "3" * 64, "--cargo-lock", str(lock)],
                capture_output=True, text=True,
            )
            self.assertEqual(fin.returncode, 0, fin.stderr[-300:])
            receipt = json.loads((run_dir / "qualification-receipt.json").read_text(encoding="utf-8"))
            self.assertEqual(receipt["status"], "passed")
            self.assertEqual(receipt["laneId"], qr.LANE_IDS["policy"])


class TestSiblingClosure(unittest.TestCase):
    """FSS-185: the sibling-closure digest is deterministic, tamper-sensitive,
    and fails closed on unreadable inputs."""

    def _write_inputs(self, root: Path, lock_text: str = "# lock\n"):
        (root / "architecture").mkdir(parents=True, exist_ok=True)
        (root / "architecture" / "franken_imports.json").write_text("{}", encoding="utf-8")
        (root / "architecture" / "dependency_allowlist.toml").write_text("[x]\n", encoding="utf-8")
        (root / "rust-toolchain.toml").write_text(lock_text, encoding="utf-8")

    def test_deterministic_over_same_inputs(self):
        import sibling_closure as sc
        with tempfile.TemporaryDirectory() as td:
            self._write_inputs(Path(td))
            self.assertEqual(sc.compute_sibling_digest(Path(td)), sc.compute_sibling_digest(Path(td)))

    def test_tamper_changes_digest(self):
        import sibling_closure as sc
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            self._write_inputs(root)
            before = sc.compute_sibling_digest(root)
            self._write_inputs(root, lock_text="# lock v2\n")
            after = sc.compute_sibling_digest(root)
        self.assertNotEqual(before, after, "a changed sibling input must change the closure digest")

    def test_missing_input_fails_closed(self):
        import sibling_closure as sc
        with tempfile.TemporaryDirectory() as td:
            with self.assertRaises((FileNotFoundError, OSError)):
                sc.compute_sibling_digest(Path(td))

    def test_cli_matches_library(self):
        import sibling_closure as sc
        with tempfile.TemporaryDirectory() as td:
            self._write_inputs(Path(td))
            proc = subprocess.run(
                [sys.executable, str(REPO / "scripts" / "sibling_closure.py"), td],
                capture_output=True, text=True,
            )
            self.assertEqual(proc.returncode, 0)
            self.assertEqual(proc.stdout.strip(), sc.compute_sibling_digest(Path(td)))


if __name__ == "__main__":
    unittest.main()
