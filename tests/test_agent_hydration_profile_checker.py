#!/usr/bin/env python3
"""Mutation checks for the separately selected event-hydration contract generation."""
from __future__ import annotations

import json
import shutil
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))
import agent_hydration_profile_checker as checker


class HydrationProfileTests(unittest.TestCase):
    def setUp(self) -> None:
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        paths = {
            checker.PROFILE_PATH, checker.SCHEMA_PATH, checker.CORE_PATH,
            checker.FIXTURE_PATH, *checker.PRESERVED,
            "crates/fss-core/src/agent_operation.rs",
        }
        for relative in paths:
            destination = self.root / relative
            destination.parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(ROOT / relative, destination)

    def errors(self) -> list[str]:
        return checker.validate_hydration_profile(self.root)

    def change_profile(self, update) -> None:
        path = self.root / checker.PROFILE_PATH
        profile = json.loads(path.read_text())
        update(profile)
        path.write_text(json.dumps(profile, indent=2) + "\n")

    def test_exact_live_profile_and_reference_fixture_pass(self) -> None:
        self.assertEqual(self.errors(), [])

    def test_write_semantics_cannot_be_relabelled_as_a_safe_read(self) -> None:
        self.change_profile(lambda value: value["operation"].update(mode="read_compile", durable=False))
        self.assertTrue(any("operation semantics" in error for error in self.errors()))

    def test_missing_hydration_grant_and_new_selector_are_rejected(self) -> None:
        self.change_profile(lambda value: value["operation"].update(requiredCapabilities=["CAP-AGENT-QUERY-001"]))
        self.assertTrue(self.errors())
        (self.root / checker.PROFILE_PATH).write_text(json.dumps(checker.expected_profile()))
        self.change_profile(lambda value: value["selector"].update(target="events"))
        self.assertTrue(self.errors())

    def test_schema_byte_drift_cannot_reuse_published_basis(self) -> None:
        path = self.root / checker.SCHEMA_PATH
        path.write_bytes(path.read_bytes() + b"\n")
        errors = self.errors()
        self.assertTrue(any("HYDRATION_RESPONSE_SCHEMA_DIGEST" in error for error in errors))
        self.assertTrue(any("binary fixture" in error for error in errors))

    def test_native_profile_pin_drift_is_rejected(self) -> None:
        path = self.root / checker.CORE_PATH
        path.write_text(path.read_text().replace(checker.PINS["HYDRATION_SCHEMA_CATALOG_DIGEST"], "sha256:" + "1" * 64))
        self.assertTrue(any("native hydration profile constant" in error for error in self.errors()))

    def test_mixed_or_corrupt_binary_basis_is_rejected(self) -> None:
        destination = self.root / checker.FIXTURE_PATH
        destination.write_bytes((self.root / "tests/fixtures/contract_basis_v4.bin").read_bytes())
        self.assertTrue(any("binary fixture" in error for error in self.errors()))

    def test_original_baseline_cannot_be_changed_to_hide_profile(self) -> None:
        path = self.root / "crates/fss-core/src/agent_operation.rs"
        path.write_text(path.read_text().replace(checker.LEGACY_QUERY_ROW, checker.ROW))
        self.assertTrue(any("default AOP-005" in error for error in self.errors()))

    def test_duplicate_and_unknown_profile_fields_fail_closed(self) -> None:
        path = self.root / checker.PROFILE_PATH
        path.write_text(path.read_text().replace("{", '{"schema":"duplicate",', 1))
        self.assertTrue(any("duplicate JSON" in error for error in self.errors()))
        path.write_text(json.dumps({**checker.expected_profile(), "grantsFromClient": True}))
        self.assertTrue(self.errors())

    def test_missing_profile_or_legacy_fixture_cannot_pass(self) -> None:
        (self.root / checker.FIXTURE_PATH).unlink()
        self.assertTrue(self.errors())

    def test_initial_profile_manifest_schema_and_binary_cannot_be_rewritten(self) -> None:
        for relative in (
            "architecture/agent_hydration_profile.v1.json",
            "tests/fixtures/agent_evidence_hydration_profile_v1.schema.json",
            "tests/fixtures/contract_basis_event_hydration_v1.bin",
        ):
            with self.subTest(path=relative):
                path = self.root / relative
                original = path.read_bytes()
                path.write_bytes(original + b"\n")
                self.assertTrue(any(relative in error for error in self.errors()))
                path.write_bytes(original)

    def test_initial_wrapper_cannot_reuse_the_corrected_profile_basis(self) -> None:
        original = self.root / "tests/fixtures/agent_evidence_hydration_profile_v1.schema.json"
        (self.root / checker.SCHEMA_PATH).write_bytes(original.read_bytes())
        self.assertTrue(any("HYDRATION_RESPONSE_SCHEMA_DIGEST" in error for error in self.errors()))


if __name__ == "__main__":
    unittest.main()
