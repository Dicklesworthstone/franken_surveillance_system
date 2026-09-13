#!/usr/bin/env python3
"""Validates `fss negative-evidence --json` reports against schemas/negative_evidence_report.v1.json.

The Rust contract test `test_cli_json_reports_match_schema_goldens`
(crates/fss-cli/tests/negative_evidence_cli_contract.rs) asserts that the CLI emits exactly the
golden documents in tests/fixtures/negative_evidence_report/, so validating the goldens here
validates the CLI output. The schema itself is audited with scripts/schema_validate.py like every
repository schema; instances are validated with the jsonschema Draft 2020-12 validator, the same
oracle tests/test_schema_validate.py uses.
"""
from __future__ import annotations

import copy
import json
import sys
import unittest
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))
import schema_validate  # noqa: E402

SCHEMA_PATH = ROOT / "schemas" / "negative_evidence_report.v1.json"
GOLDEN_DIR = ROOT / "tests" / "fixtures" / "negative_evidence_report"
EXPECTED_GOLDENS = {
    "append_witnessed.json",
    "list_builtin.json",
    "verify_builtin.json",
    "verify_legacy_v1_refused.json",
}


def load(path: Path) -> Any:
    return json.loads(path.read_text(encoding="utf-8"))


def validator() -> Any:
    from jsonschema import Draft202012Validator  # type: ignore

    schema = load(SCHEMA_PATH)
    Draft202012Validator.check_schema(schema)
    return Draft202012Validator(schema)


def errors_of(instance: Any) -> list[str]:
    return sorted(error.message for error in validator().iter_errors(instance))


class NegativeEvidenceReportSchemaTests(unittest.TestCase):
    def setUp(self) -> None:
        try:
            import jsonschema  # type: ignore  # noqa: F401
        except ImportError:  # pragma: no cover - same policy as tests/test_schema_validate.py
            self.skipTest("jsonschema Draft 2020-12 oracle unavailable")

    def test_schema_passes_repository_audit(self) -> None:
        # Only this schema's findings are asserted: the catalog-wide status can fail for
        # unrelated schemas owned by other work.
        report = schema_validate.audit(schemas_dir=ROOT / "schemas")
        own = [f for f in report["findings"] if "negative_evidence_report" in json.dumps(f)]
        self.assertEqual(own, [])
        self.assertGreaterEqual(report["schemaCount"], 1)

    def test_expected_goldens_are_present(self) -> None:
        self.assertEqual({p.name for p in GOLDEN_DIR.glob("*.json")}, EXPECTED_GOLDENS)

    def test_goldens_validate_against_schema(self) -> None:
        for path in sorted(GOLDEN_DIR.glob("*.json")):
            with self.subTest(golden=path.name):
                self.assertEqual(errors_of(load(path)), [])

    def test_envelope_claims_are_rejected(self) -> None:
        report = load(GOLDEN_DIR / "list_builtin.json")
        relabelled = copy.deepcopy(report)
        relabelled["schema"] = "fss.agent_response_envelope.v1"
        self.assertNotEqual(errors_of(relabelled), [])
        with_operation = copy.deepcopy(report)
        with_operation["operationId"] = "AOP-005"
        self.assertNotEqual(errors_of(with_operation), [])

    def test_invalid_values_are_rejected(self) -> None:
        report = load(GOLDEN_DIR / "list_builtin.json")
        cases = {
            "unknown knowledge state": ("epistemicState", "certain"),
            "alias identifier": ("appendedId", "NEG-01"),
            "old format version": ("formatVersion", 1),
        }
        for name, (key, value) in cases.items():
            with self.subTest(case=name):
                broken = copy.deepcopy(report)
                broken[key] = value
                self.assertNotEqual(errors_of(broken), [])
        missing_field = copy.deepcopy(report)
        del missing_field["entries"][0]["decisionProvenance"]
        self.assertNotEqual(errors_of(missing_field), [])

    def test_epistemic_state_is_derived_from_entries(self) -> None:
        for name in ("list_builtin.json",):
            report = load(GOLDEN_DIR / name)
            counts: dict[str, int] = {}
            for entry in report["entries"]:
                counts[entry["knowledgeState"]] = counts.get(entry["knowledgeState"], 0) + 1
            self.assertEqual(report["knowledgeStateCounts"], counts)
            expected = next(iter(counts)) if len(counts) == 1 else None
            self.assertEqual(report["epistemicState"], expected)
            self.assertEqual(report["entryCount"], len(report["entries"]))

    def test_epistemic_state_is_consistent_with_counts_in_every_golden(self) -> None:
        for path in sorted(GOLDEN_DIR.glob("*.json")):
            report = load(path)
            counts = report["knowledgeStateCounts"]
            with self.subTest(golden=path.name):
                self.assertEqual(sum(counts.values()), report["entryCount"] or 0)
                if report["epistemicState"] is None:
                    # Never upgraded: null means no entries or more than one state.
                    self.assertNotEqual(len(counts), 1)
                else:
                    # A state such as "known" is reported only when every entry has it.
                    self.assertEqual(counts, {report["epistemicState"]: report["entryCount"]})

    def test_append_report_does_not_upgrade_mixed_states(self) -> None:
        report = load(GOLDEN_DIR / "append_witnessed.json")
        self.assertEqual(report["knowledgeStateCounts"], {"known": 1, "unknown": 3})
        self.assertIsNone(report["epistemicState"])
        self.assertTrue(any(note.startswith("mixed_knowledge_states") for note in report["degradation"]))

    def test_refusal_report_carries_error_identity(self) -> None:
        report = load(GOLDEN_DIR / "verify_legacy_v1_refused.json")
        self.assertEqual(report["outcome"], "error")
        self.assertEqual(report["errorId"], "ERR-NEG-UNKNOWN-VERSION-001")
        self.assertIs(report["verified"], False)
        self.assertIsNone(report["entryCount"])


if __name__ == "__main__":
    unittest.main()
