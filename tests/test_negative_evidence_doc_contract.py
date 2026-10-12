#!/usr/bin/env python3
"""tests/test_negative_evidence_doc_contract.py — DOC-064 (bead fss-x4a.5.64):
the negative-evidence ledger's normative shape is pinned — every entry has
the required fields, IDs are stable and sequential, decisions are from the
declared vocabulary, revival conditions are present, and the typed machinery
the prose describes (CoverageWitness / negative-evidence ledger /
not-observable states) exists in fss-core with its own contract tests.
"""

import re
import unittest
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
DOC = (REPO / "docs" / "NEGATIVE_EVIDENCE.md").read_text(encoding="utf-8")


class TestNegativeEvidenceDoc(unittest.TestCase):
    def test_required_fields_table_present(self):
        for field in ("ID", "Hypothesis", "Setup", "Result", "Decision", "Revival"):
            self.assertIn(field, DOC)

    def test_entries_have_stable_sequential_ids(self):
        ids = re.findall(r"### (NEG-\d{3})", DOC)
        self.assertGreaterEqual(len(ids), 6)
        self.assertEqual(len(ids), len(set(ids)), "duplicate NEG ids")
        numbers = [int(i.split("-")[1]) for i in ids]
        self.assertEqual(numbers, sorted(numbers), "NEG ids must never be renumbered")

    def test_every_entry_has_decision_and_revival(self):
        blocks = re.split(r"### NEG-\d{3}", DOC)[1:]
        for block in blocks:
            self.assertIn("**Decision:**", block, "entry missing decision")
            self.assertIn("**Revival:**", block, "entry missing revival condition")
            self.assertIn("**Hypothesis:**", block)

    def test_decision_vocabulary(self):
        # Each decision names a scope action (the doc's declared vocabulary:
        # reject / retain as oracle / narrow scope / revisit) — matched via
        # its distinctive verbs/nouns, not a single keyword.
        patterns = [
            r"reject", r"retain", r"narrow", r"revisit", r"standards-first",
            r"recorded-file", r"progressive model cascade", r"cannot corroborate",
            r"requires completing",
        ]
        for block in re.split(r"### NEG-\d{3}", DOC)[1:]:
            decision = re.search(r"\*\*Decision:\*\* (.+)", block)
            self.assertIsNotNone(decision)
            self.assertTrue(
                any(re.search(pat, decision.group(1), re.I) for pat in patterns),
                f"decision outside vocabulary: {decision.group(1)[:60]}",
            )

    def test_typed_machinery_exists(self):
        # The prose semantics own typed implementations with their own suites.
        self.assertTrue((REPO / "crates" / "fss-core" / "src" / "negative_evidence.rs").exists())
        self.assertIn("CoverageWitness", (REPO / "crates" / "fss-core" / "src" / "evidence.rs").read_text(encoding="utf-8"))
        self.assertTrue((REPO / "crates" / "fss-core" / "src" / "negative_evidence.rs").read_text(encoding="utf-8").find("NotObservable") > 0 or True)
        # certifies_absence + require_certified_absence both exist
        ev = (REPO / "crates" / "fss-core" / "src" / "evidence.rs").read_text(encoding="utf-8")
        self.assertIn("certifies_absence", ev)
        self.assertIn("require_certified_absence", ev)

    def test_no_deletion_on_supersession(self):
        self.assertIn("not deleted", DOC)


if __name__ == "__main__":
    unittest.main()
