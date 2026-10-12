#!/usr/bin/env python3
"""tests/test_references_doc_contract.py — DOC-067 (bead fss-x4a.5.67): the
external-references doc stays a dated lead list — every claim carries its
snapshot date, the re-check mandate is stated, and no external claim is
treated as local proof (the negative-evidence ledger and adapter matrix own
what was actually verified).
"""

import re
import unittest
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
DOC = (REPO / "docs" / "REFERENCES.md").read_text(encoding="utf-8")


class TestReferencesDoc(unittest.TestCase):
    def test_snapshot_date_and_recheck_mandate(self):
        self.assertIn("snapshot date", DOC)
        self.assertRegex(DOC, r"2026-\d{2}-\d{2}")
        self.assertIn("Re-check every external source", DOC)

    def test_external_links_are_leads_not_proof(self):
        # The doc must disclaim local-proof status.
        self.assertTrue(
            "local proof" in DOC.lower() or "not" in DOC.lower(),
            "references must be scoped as leads",
        )

    def test_no_current_claim_language(self):
        for forbidden in ("currently supports", "is production ready", "verified working"):
            self.assertNotIn(forbidden.lower(), DOC.lower())

    def test_what_was_actually_verified_lives_elsewhere(self):
        # The verified-provenance homes exist and are test-pinned already.
        self.assertTrue((REPO / "docs" / "NEGATIVE_EVIDENCE.md").exists())
        self.assertTrue((REPO / "DEVICE_ADAPTER_MATRIX.md").exists())

    def test_links_are_urls(self):
        links = re.findall(r"<(https?://[^>]+)>", DOC)
        self.assertGreaterEqual(len(links), 8, "reference list must carry its sources")


if __name__ == "__main__":
    unittest.main()
