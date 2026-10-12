#!/usr/bin/env python3
"""tests/test_contributing_contract.py — DOC-062 (bead fss-x4a.5.62): the
contributor workflow's enforceable statements are reconciled to owning
machinery. Each "hard rule" must map to a mechanical enforcer that exists in
the repo; the qualification entrypoint named by the prose must be the one the
machine contract declares; and the prose may not upgrade machine status.
"""

import re
import unittest
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
CONTRIBUTING = (REPO / "CONTRIBUTING.md").read_text(encoding="utf-8")
LOCAL_QUAL = (REPO / "architecture" / "local_qualification.toml").read_text(encoding="utf-8")

# rule → (marker in CONTRIBUTING, enforcing artifact that must exist)
RULES = {
    "no-unsafe": ("No `unsafe` anywhere", "scripts/unsafe_prohibition_checker.py"),
    "no-tokio": ("No Tokio ecosystem", "scripts/dependency_closure_scanner.py"),
    "no-detached-subprocess": ("No detached task", "scripts/dependency_audit.py"),
    "no-network-in-build": ("No hidden network downloads", "scripts/netseal_selftest.py"),
    "no-unversioned-durable": ("No mutable durable format", "crates/fss-core/src/contract_basis.rs"),
    "no-credential-commit": ("No committed credentials", "scripts/check-policy.py"),
    "no-unqualified-claims": ("No model or device support claim", "scripts/standards_first_adapter_checker.py"),
    "no-rewritten-evidence": ("No rewrite of canonical evidence", "crates/fss-core/src/evidence.rs"),
    "no-benchmark-without-samples": ("No benchmark result without raw samples", "docs/PERF_LEDGER.md"),
}


class TestContributorContract(unittest.TestCase):
    def test_every_hard_rule_maps_to_an_enforcer(self):
        for rule, (marker, enforcer) in RULES.items():
            self.assertIn(marker, CONTRIBUTING, f"rule {rule} missing from CONTRIBUTING")
            self.assertTrue(
                (REPO / enforcer).exists(),
                f"rule {rule}: enforcing artifact {enforcer} does not exist",
            )

    def test_qualification_entrypoint_is_the_machine_entrypoint(self):
        self.assertIn("bash scripts/qualify.sh", CONTRIBUTING)
        self.assertIn('repository_entrypoint = "scripts/qualify.sh"', LOCAL_QUAL)

    def test_hosted_ci_disclaimer_present(self):
        self.assertIn("Hosted CI is not", CONTRIBUTING)
        self.assertIn("portable_executable_specification_only", LOCAL_QUAL)

    def test_prose_makes_no_production_claim(self):
        for forbidden in ("production ready", "production-ready", "qualified for production"):
            self.assertNotIn(forbidden.lower(), CONTRIBUTING.lower())

    def test_registry_before_prose_rule_present(self):
        self.assertIn("Add or update the relevant registry before relying on prose", CONTRIBUTING)


if __name__ == "__main__":
    unittest.main()
