#!/usr/bin/env python3
"""tests/test_pr_template_contract.py — DOC-068 (bead fss-x4a.5.68): the PR
template guides scope/evidence/claim-boundary honestly and stays a guide,
not a second machine authority — its checklist references the real
qualification entrypoint and its claim-boundary section is mandatory prose.
"""

import unittest
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
TPL = (REPO / ".github" / "PULL_REQUEST_TEMPLATE.md").read_text(encoding="utf-8")


class TestPRTemplate(unittest.TestCase):
    def test_scope_section_names_stable_ids(self):
        self.assertIn("Requirement/work-package IDs", TPL)
        self.assertIn("Gate/readiness dimensions", TPL)

    def test_evidence_section_covers_the_proof_kinds(self):
        for item in ("Deterministic/reference tests", "Fault/cancellation/crash tests",
                     "Negative evidence", "Performance/cost"):
            self.assertIn(item, TPL)

    def test_claim_boundary_is_mandatory_prose(self):
        self.assertIn("State exactly what this PR proves and what it does **not** qualify", TPL)

    def test_checklist_references_the_real_entrypoint(self):
        self.assertIn("bash scripts/qualify.sh", TPL)
        self.assertIn("MANIFEST.sha256", TPL)

    def test_security_privacy_items_present(self):
        self.assertIn("No credentials", TPL)
        self.assertIn("private captures", TPL)

    def test_negative_results_retained(self):
        self.assertIn("retained rather than omitted", TPL)

    def test_guide_not_authority(self):
        # The template must not invent its own machine status vocabulary.
        for forbidden in ("production ready", "approved by", "release authority"):
            self.assertNotIn(forbidden.lower(), TPL.lower())


if __name__ == "__main__":
    unittest.main()
