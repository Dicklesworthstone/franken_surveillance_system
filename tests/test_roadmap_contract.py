#!/usr/bin/env python3
"""tests/test_roadmap_contract.py — DOC-063 (bead fss-x4a.5.63): the roadmap
stays gate-scoped intent — checked boxes mean reference capability exists,
never production qualification; the bead graph/registries remain authoritative;
no schedule claims; and the honesty invariants are pinned so prose cannot
upgrade machine status.
"""

import re
import unittest
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
ROADMAP = (REPO / "ROADMAP.md").read_text(encoding="utf-8")


class TestRoadmapContract(unittest.TestCase):
    def test_header_scopes_boxes_to_reference_capability(self):
        self.assertIn("implementation-order guide", ROADMAP)
        self.assertIn("does not imply production qualification", ROADMAP)
        self.assertIn("remain authoritative", ROADMAP)

    def test_no_schedule_claims(self):
        # No dates/quarters attached to work items (phase headers excluded).
        for line in ROADMAP.splitlines():
            if line.startswith(("#", "The", "Its", "detailed", "links")) or not line.strip():
                continue
            self.assertIsNone(
                re.search(r"\b(Q[1-4] 20\d\d|by 20\d\d|20\d\d-Q[1-4])\b", line),
                f"schedule claim in roadmap line: {line[:60]}",
            )

    def test_no_production_readiness_language(self):
        for forbidden in ("production ready", "production-ready", "qualified for production", "shipped"):
            self.assertNotIn(forbidden.lower(), ROADMAP.lower())

    def test_both_checked_and_unchecked_exist(self):
        checked = re.findall(r"- \[x\] ", ROADMAP)
        unchecked = re.findall(r"- \[ \] ", ROADMAP)
        self.assertGreater(len(checked), 10)
        self.assertGreater(len(unchecked), 10, "an all-checked roadmap would be a readiness claim")

    def test_companion_plan_flagged_as_unchanged_status(self):
        self.assertIn("without changing their status", ROADMAP)


if __name__ == "__main__":
    unittest.main()
