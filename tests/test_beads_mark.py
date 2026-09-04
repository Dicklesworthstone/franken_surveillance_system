#!/usr/bin/env python3

from __future__ import annotations

import importlib.util
import json
import pathlib
import tempfile
import unittest

ROOT = pathlib.Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location("beads_mark", ROOT / "scripts" / "beads_mark.py")
assert SPEC is not None and SPEC.loader is not None
MODULE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(MODULE)


class BeadsMarkTests(unittest.TestCase):
    def write_fixture(self, directory: pathlib.Path, records: list[dict[str, object]]) -> pathlib.Path:
        path = directory / "issues.jsonl"
        path.write_text(
            "".join(json.dumps(record, separators=(",", ":")) + "\n" for record in records),
            encoding="utf-8",
        )
        return path

    def test_updates_exact_external_ref_and_appends_monotone_comment(self) -> None:
        with tempfile.TemporaryDirectory() as raw_directory:
            directory = pathlib.Path(raw_directory)
            path = self.write_fixture(
                directory,
                [
                    {
                        "id": "bead:one",
                        "external_ref": "FSS-209",
                        "status": "open",
                        "comments": [],
                    },
                    {
                        "id": "bead:two",
                        "external_ref": "FSS-210",
                        "status": "open",
                        "comments": [
                            {
                                "id": 7,
                                "issue_id": "bead:two",
                                "author": "prior",
                                "text": "prior comment",
                                "created_at": "2026-09-01T00:00:00Z",
                            }
                        ],
                    },
                ],
            )
            lines, issue_id = MODULE.transform(
                path,
                external_ref="FSS-210",
                status="in_progress",
                author="agent",
                comment="implementation started",
                timestamp="2026-09-03T20:00:00Z",
            )
            MODULE.atomic_write(path, lines)
            records = [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines()]
            self.assertEqual(issue_id, "bead:two")
            self.assertEqual(records[0]["status"], "open")
            self.assertEqual(records[1]["status"], "in_progress")
            self.assertEqual(records[1]["updated_at"], "2026-09-03T20:00:00Z")
            self.assertEqual(records[1]["comments"][-1]["id"], 8)
            self.assertEqual(records[1]["comments"][-1]["text"], "implementation started")

    def test_duplicate_external_ref_fails_without_mutating_source(self) -> None:
        with tempfile.TemporaryDirectory() as raw_directory:
            directory = pathlib.Path(raw_directory)
            path = self.write_fixture(
                directory,
                [
                    {"id": "bead:one", "external_ref": "FSS-210", "status": "open"},
                    {"id": "bead:two", "external_ref": "FSS-210", "status": "open"},
                ],
            )
            before = path.read_bytes()
            with self.assertRaisesRegex(ValueError, "found 2"):
                MODULE.transform(
                    path,
                    external_ref="FSS-210",
                    status="in_progress",
                    author="agent",
                    comment=None,
                    timestamp="2026-09-03T20:00:00Z",
                )
            self.assertEqual(path.read_bytes(), before)

    def test_missing_external_ref_fails(self) -> None:
        with tempfile.TemporaryDirectory() as raw_directory:
            directory = pathlib.Path(raw_directory)
            path = self.write_fixture(
                directory,
                [{"id": "bead:one", "external_ref": "FSS-209", "status": "open"}],
            )
            with self.assertRaisesRegex(ValueError, "found 0"):
                MODULE.transform(
                    path,
                    external_ref="FSS-210",
                    status="in_progress",
                    author="agent",
                    comment=None,
                    timestamp="2026-09-03T20:00:00Z",
                )

    def test_malformed_json_reports_line_number(self) -> None:
        with tempfile.TemporaryDirectory() as raw_directory:
            path = pathlib.Path(raw_directory) / "issues.jsonl"
            path.write_text('{"id":"ok"}\nnot-json\n', encoding="utf-8")
            with self.assertRaisesRegex(ValueError, "line 2"):
                MODULE.transform(
                    path,
                    external_ref="FSS-210",
                    status="in_progress",
                    author="agent",
                    comment=None,
                    timestamp="2026-09-03T20:00:00Z",
                )


if __name__ == "__main__":
    unittest.main()
