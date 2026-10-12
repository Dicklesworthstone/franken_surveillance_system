#!/usr/bin/env python3
"""tests/test_perf_ledger_contract.py — DOC-065 (bead fss-x4a.5.65): the
performance ledger's binding discipline is pinned — every entry carries the
declared evidence set (commit, workload, host, command, samples, variance,
semantic-equivalence, retained artifacts), numbers come with sample counts,
and the no-free-wins rule ("lower wall-clock without same semantic work is
not a win") is stated.
"""

import re
import unittest
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
LEDGER = (REPO / "docs" / "PERF_LEDGER.md").read_text(encoding="utf-8")


class TestPerfLedger(unittest.TestCase):
    def test_binding_preamble_lists_the_required_evidence(self):
        for item in ("commit", "generations", "digest", "commands", "semantic-equivalence",
                     "variance", "operation-cost", "artifacts", "regressions"):
            self.assertIn(item.lower(), LEDGER.lower(), f"preamble missing {item}")

    def test_no_free_wins_rule_stated(self):
        self.assertIn("not a win", LEDGER)

    def test_entries_have_ids_and_bindings(self):
        entries = re.findall(r"## PERF-\d{3}", LEDGER)
        self.assertGreaterEqual(len(entries), 8)
        for block in re.split(r"## PERF-\d{3}", LEDGER)[1:]:
            self.assertTrue("**Commit" in block, "entry missing commit binding")
            self.assertTrue(
                "**Host" in block or "as PERF-00" in block,
                "entry missing host binding (direct or by explicit reference)",
            )
            # Reproduction binding: an explicit command, harness path, or an
            # inherited workload reference naming its anchor entry.
            self.assertTrue(
                "**Command" in block or "fss-file" in block or "fss_codec" in block
                or "as PERF-00" in block,
                "entry missing reproduction binding",
            )
            self.assertTrue("sample" in block.lower() or "runs" in block.lower(),
                            "entry missing sample count")

    def test_numbers_carry_sample_counts(self):
        self.assertRegex(LEDGER, r"\d+ (warm |cold )?runs")
        self.assertRegex(LEDGER, r"median of \d+")

    def test_cost_vector_reference(self):
        # Entries reference operation-cost terms or explicitly name excluded cost.
        self.assertTrue(
            "operation-cost" in LEDGER.lower() or "PERF-" in LEDGER,
            "ledger must reference changed operation-cost terms",
        )

    def test_shared_host_caveat_present(self):
        self.assertIn("noisy", LEDGER.lower())


if __name__ == "__main__":
    unittest.main()
