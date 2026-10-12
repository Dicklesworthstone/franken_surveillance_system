#!/usr/bin/env python3
"""tests/test_pricing_reference_contract.py — DOC-066 (bead fss-x4a.5.66):
the pricing reference stays a dated research input — never executable
configuration, never a timeless cost claim. The as-of date is in the
filename and body; the re-check mandate is stated; vendors' prices are
attributed to consulted pages; and the machine pricing manifest
(fss-core pricing module) derives cost from explicit inputs, never from
this document.
"""

import re
import unittest
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
PRICING = (REPO / "docs" / "PRICING_REFERENCE_2026-08-30.md").read_text(encoding="utf-8")


class TestPricingReference(unittest.TestCase):
    def test_dated_research_input_disclaimer(self):
        self.assertIn("dated research input", PRICING)
        self.assertIn("not executable configuration", PRICING)

    def test_recheck_mandate(self):
        self.assertIn("Re-check provider documentation", PRICING)

    def test_asof_date_in_filename_and_body(self):
        self.assertIn("2026-08-30", PRICING)
        self.assertIn("2026-08-30", (REPO / "docs" / "PRICING_REFERENCE_2026-08-30.md").name)

    def test_prices_attributed_to_consulted_sources(self):
        self.assertIn("official pricing", PRICING)
        self.assertIn("consulted", PRICING)

    def test_subject_to_change_caveat(self):
        self.assertTrue(
            "subject to" in PRICING.lower() or "current" in PRICING.lower(),
            "prices must carry a provider-definitions caveat",
        )

    def test_machine_pricing_is_input_derived_not_doc_derived(self):
        # The typed pricing manifest computes from explicit usage inputs.
        pricing_src = (REPO / "crates" / "fss-core" / "src" / "pricing.rs").read_text(encoding="utf-8")
        self.assertIn("ArchiveMonthlyUsage", pricing_src)
        self.assertIn("ArchiveMonthlyCost", pricing_src)
        self.assertNotIn(
            "PRICING_REFERENCE", pricing_src,
            "the machine pricing module must not read the dated research doc",
        )


if __name__ == "__main__":
    unittest.main()
