#!/usr/bin/env python3
"""Unit tests for json_instance_validate.py."""

import hashlib
import json
import os
import sys
import tempfile
import unittest
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO_ROOT / "scripts"))

from json_instance_validate import (
    InstanceValidator,
    JsonInstanceValidationError,
    SchemaSyntaxError,
    parse_strict_json,
    validate_instance_file,
)


class TestJsonInstanceValidate(unittest.TestCase):
    def setUp(self):
        self.validator = InstanceValidator(REPO_ROOT / "schemas")

    def test_strict_json_rejection(self):
        # NaN rejected
        with self.assertRaises(JsonInstanceValidationError):
            parse_strict_json('{"val": NaN}')
        # Infinity rejected
        with self.assertRaises(JsonInstanceValidationError):
            parse_strict_json('{"val": Infinity}')
        # Duplicate keys rejected
        with self.assertRaises(JsonInstanceValidationError):
            parse_strict_json('{"key": 1, "key": 2}')

    def test_type_strictness(self):
        schema = {"type": "integer"}
        # Valid integer
        self.validator.validate(schema, 42)
        # Boolean is NOT an integer
        with self.assertRaises(JsonInstanceValidationError):
            self.validator.validate(schema, True)
        # Float is NOT an integer
        with self.assertRaises(JsonInstanceValidationError):
            self.validator.validate(schema, 42.0)

        schema_num = {"type": "number"}
        self.validator.validate(schema_num, 42)
        self.validator.validate(schema_num, 42.5)
        # Boolean is NOT a number
        with self.assertRaises(JsonInstanceValidationError):
            self.validator.validate(schema_num, False)

    def test_const_strictness(self):
        schema = {"const": 1}
        self.validator.validate(schema, 1)
        # 1 vs True
        with self.assertRaises(JsonInstanceValidationError):
            self.validator.validate(schema, True)
        # 1 vs 1.0
        with self.assertRaises(JsonInstanceValidationError):
            self.validator.validate(schema, 1.0)

    def test_enum_strictness(self):
        schema = {"enum": ["ok", "error", 10]}
        self.validator.validate(schema, "ok")
        self.validator.validate(schema, 10)
        with self.assertRaises(JsonInstanceValidationError):
            self.validator.validate(schema, "missing")
        with self.assertRaises(JsonInstanceValidationError):
            self.validator.validate(schema, 10.0)

    def test_pattern_end_anchoring(self):
        schema = {"type": "string", "pattern": r"^[a-z]+$"}
        self.validator.validate(schema, "abc")
        # Trailing newline must NOT be accepted
        with self.assertRaises(JsonInstanceValidationError):
            self.validator.validate(schema, "abc\n")
        # Trailing char
        with self.assertRaises(JsonInstanceValidationError):
            self.validator.validate(schema, "abc1")

    def test_unsupported_keyword_rejection(self):
        schema = {
            "type": "object",
            "properties": {
                "field": {
                    "type": "string",
                    "dependentRequired": {"a": ["b"]},  # unsupported in reachable subschema
                }
            },
        }
        with self.assertRaises(SchemaSyntaxError):
            self.validator.validate(schema, {"field": "hello"})

    def test_maximum_and_max_properties(self):
        self.validator.validate({"type": "number", "maximum": 1}, 1)
        with self.assertRaises(JsonInstanceValidationError):
            self.validator.validate({"type": "number", "maximum": 1}, 1.5)
        schema = {"type": "object", "maxProperties": 1}
        self.validator.validate(schema, {"a": 1})
        with self.assertRaises(JsonInstanceValidationError):
            self.validator.validate(schema, {"a": 1, "b": 2})

    def test_unique_items_is_type_strict(self):
        schema = {"type": "array", "uniqueItems": True}
        self.validator.validate(schema, [1, 1.0, True, "1", [1], {"a": 1}])
        with self.assertRaises(JsonInstanceValidationError):
            self.validator.validate(schema, ["x", "y", "x"])
        with self.assertRaises(JsonInstanceValidationError):
            self.validator.validate(schema, [{"a": [1]}, {"a": [1]}])
        # uniqueItems: false imposes nothing.
        self.validator.validate({"type": "array", "uniqueItems": False}, [1, 1])

    def test_all_of_not_and_conditionals(self):
        schema = {
            "type": "object",
            "properties": {"state": {"enum": ["a", "b", "c"]}, "basis": {"type": "string"}},
            "allOf": [
                {
                    "if": {"properties": {"state": {"const": "a"}}, "required": ["state"]},
                    "then": {"required": ["basis"]},
                },
                {
                    "if": {"properties": {"state": {"const": "b"}}, "required": ["state"]},
                    "then": {"not": {"required": ["basis"]}},
                    "else": {"properties": {"basis": {"minLength": 2}}},
                },
            ],
        }
        self.validator.validate(schema, {"state": "a", "basis": "xy"})
        self.validator.validate(schema, {"state": "b"})
        self.validator.validate(schema, {"state": "c"})
        # then: `a` requires basis
        with self.assertRaises(JsonInstanceValidationError):
            self.validator.validate(schema, {"state": "a"})
        # then/not: `b` forbids basis
        with self.assertRaises(JsonInstanceValidationError):
            self.validator.validate(schema, {"state": "b", "basis": "xy"})
        # else: non-`b` basis must be at least two characters
        with self.assertRaises(JsonInstanceValidationError):
            self.validator.validate(schema, {"state": "c", "basis": "x"})

    def test_unsupported_keyword_inside_conditional_is_refused(self):
        schema = {"if": {"type": "string"}, "then": {"dependentSchemas": {}}}
        with self.assertRaises(SchemaSyntaxError):
            self.validator.validate(schema, "x")

    def test_agent_contract_schemas_are_statically_supported(self):
        # Every keyword reachable from the orient/explain answer schemas is in the subset, so a
        # conforming instance can be validated end to end (fss-iqg1k).
        for name in (
            "agent_response_envelope.v1.json",
            "situation_capsule.v1.json",
            "agent_cognitive_envelope.v1.json",
        ):
            path = REPO_ROOT / "schemas" / name
            schema = parse_strict_json(path.read_text(encoding="utf-8"))
            self.validator.check_reachable_schema_keywords(schema, schema, name, name)
        with self.assertRaises(JsonInstanceValidationError):
            self.validator.validate(
                parse_strict_json(
                    (REPO_ROOT / "schemas" / "situation_capsule.v1.json").read_text(encoding="utf-8")
                ),
                {},
            )

    def test_cross_file_ref(self):
        schema = {
            "type": "object",
            "properties": {
                "digest": {"$ref": "sensor_capsule.v1.json#/$defs/digest"}
            },
            "required": ["digest"],
        }
        # Valid sha256
        self.validator.validate(
            schema,
            {"digest": "sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"},
        )
        # Valid sentinel format: fss-na:<64 hex>
        self.validator.validate(
            schema,
            {"digest": "fss-na:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"},
        )
        # Invalid format
        with self.assertRaises(JsonInstanceValidationError):
            self.validator.validate(schema, {"digest": "invalid:123"})
        # Invalid uppercase
        with self.assertRaises(JsonInstanceValidationError):
            self.validator.validate(
                schema,
                {"digest": "sha256:0123456789ABCDEF0123456789abcdef0123456789abcdef0123456789abcdef"},
            )

    def test_validate_model_execution_receipt_instance(self):
        schema_path = REPO_ROOT / "schemas" / "model_execution_receipt.v1.json"
        valid_receipt = {
            "schema": "fss.model_execution_receipt.v1",
            "jobId": "exec:test-1234",
            "inputRoots": [
                "sha256:0000000000000000000000000000000000000000000000000000000000000001"
            ],
            "modelPackageRoot": "fss-na:0000000000000000000000000000000000000000000000000000000000000002",
            "activationGeneration": "fss-na:0000000000000000000000000000000000000000000000000000000000000003",
            "preprocessProgram": "sha256:0000000000000000000000000000000000000000000000000000000000000004",
            "postprocessProgram": "sha256:0000000000000000000000000000000000000000000000000000000000000005",
            "operatorRegistryGeneration": "sha256:0000000000000000000000000000000000000000000000000000000000000006",
            "executionPlanDigest": "sha256:0000000000000000000000000000000000000000000000000000000000000007",
            "backend": {
                "id": "scalar-reference",
                "implementation": "fss-reference scalar_executor@1",
                "hardware": "host-independent-scalar",
                "featureSet": [
                    "f32",
                    "fixed-order",
                    "no-fma",
                    "sentinel:activationGeneration=unactivated_reference_run",
                ],
            },
            "numericPolicyDigest": "sha256:0000000000000000000000000000000000000000000000000000000000000008",
            "budget": {
                "inputBytes": 1024,
                "outputBytes": 512,
                "peakBytes": 2048,
                "workUnits": 10000,
                "wallNs": 0,
            },
            "usage": {
                "inputBytes": 1024,
                "outputBytes": 512,
                "peakBytes": 1536,
                "workUnits": 4500,
                "wallNs": 0,
            },
            "outcome": "ok",
            "cancelReason": None,
            "errorId": None,
            "outputRoot": "sha256:0000000000000000000000000000000000000000000000000000000000000009",
            "operatorTraceDigest": "sha256:000000000000000000000000000000000000000000000000000000000000000a",
            "decisionPathDigest": "sha256:000000000000000000000000000000000000000000000000000000000000000b",
            "shadowComparison": None,
        }

        schema_doc = json.loads(schema_path.read_text(encoding="utf-8"))
        self.validator.validate(schema_doc, valid_receipt, schema_path.name)

        # Missing required field
        invalid_missing = dict(valid_receipt)
        del invalid_missing["executionPlanDigest"]
        with self.assertRaises(JsonInstanceValidationError):
            self.validator.validate(schema_doc, invalid_missing, schema_path.name)

        # Invalid outcome enum
        invalid_outcome = dict(valid_receipt)
        invalid_outcome["outcome"] = "some_unknown_outcome"
        with self.assertRaises(JsonInstanceValidationError):
            self.validator.validate(schema_doc, invalid_outcome, schema_path.name)

        # Disallowed additional property
        invalid_extra = dict(valid_receipt)
        invalid_extra["extraField"] = "disallowed"
        with self.assertRaises(JsonInstanceValidationError):
            self.validator.validate(schema_doc, invalid_extra, schema_path.name)

        # Planted invalid: negative workUnits in budget
        invalid_budget = dict(valid_receipt)
        invalid_budget["budget"] = dict(valid_receipt["budget"])
        invalid_budget["budget"]["workUnits"] = -1
        with self.assertRaises(JsonInstanceValidationError):
            self.validator.validate(schema_doc, invalid_budget, schema_path.name)

        # Error outcome with errorId
        error_receipt = dict(valid_receipt)
        error_receipt["outcome"] = "error"
        error_receipt["errorId"] = "ERR-EXEC-UNSUPPORTED-OPERATOR-001"
        error_receipt["outputRoot"] = None
        error_receipt["operatorTraceDigest"] = None
        self.validator.validate(schema_doc, error_receipt, schema_path.name)

        # Cancelled outcome with cancelReason
        cancel_receipt = dict(valid_receipt)
        cancel_receipt["outcome"] = "cancelled"
        cancel_receipt["cancelReason"] = "pre-execution"
        cancel_receipt["outputRoot"] = None
        cancel_receipt["operatorTraceDigest"] = None
        self.validator.validate(schema_doc, cancel_receipt, schema_path.name)

        # Budget exhausted outcome
        budget_ex_receipt = dict(valid_receipt)
        budget_ex_receipt["outcome"] = "budget_exhausted"
        budget_ex_receipt["outputRoot"] = None
        budget_ex_receipt["operatorTraceDigest"] = None
        self.validator.validate(schema_doc, budget_ex_receipt, schema_path.name)

        # Shadow comparison with valid metrics
        shadow_receipt = dict(valid_receipt)
        shadow_receipt["shadowComparison"] = {
            "oracleIdentity": "test-oracle@v1",
            "oracleOutputDigest": "sha256:000000000000000000000000000000000000000000000000000000000000000c",
            "divergenceClass": "none",
            "metrics": {
                "maxAbsoluteDifference": 0.0001,
                "cosineSimilarity": 0.99999,
            },
        }
        self.validator.validate(schema_doc, shadow_receipt, schema_path.name)

        # Shadow comparison with invalid metric value (string instead of number)
        shadow_invalid = dict(shadow_receipt)
        shadow_invalid["shadowComparison"] = dict(shadow_receipt["shadowComparison"])
        shadow_invalid["shadowComparison"]["metrics"] = {"cosineSimilarity": "invalid_str"}
        with self.assertRaises(JsonInstanceValidationError):
            self.validator.validate(schema_doc, shadow_invalid, schema_path.name)

    def test_refusal_scope_unreachable(self):
        # Schema with unsupported keyword in an unreachable $defs entry is NOT refused
        schema_with_unreachable_kw = {
            "type": "object",
            "properties": {
                "foo": {"type": "string"}
            },
            "$defs": {
                "unreachableDefinition": {
                    "unsupportedKeywordXYZ": "ignored_because_unreachable"
                }
            }
        }
        self.validator.validate(schema_with_unreachable_kw, {"foo": "hello"})

        # Schema with unsupported keyword in an optional property MUST be refused
        # even when the instance does not supply that optional property
        schema_with_reachable_kw = {
            "type": "object",
            "properties": {
                "foo": {"type": "string"},
                "optionalBar": {
                    "type": "string",
                    "unsupportedKeywordABC": 123
                }
            }
        }
        with self.assertRaises(SchemaSyntaxError):
            self.validator.validate(schema_with_reachable_kw, {"foo": "hello"})

    def test_sentinel_recomputation(self):
        import hashlib
        field = "activationGeneration"
        reason = "unactivated_reference_run"
        seed = f"fss.model_execution_receipt.v1/sentinel/{field}/{reason}"
        expected_hex = hashlib.sha256(seed.encode("utf-8")).hexdigest()
        sentinel = f"fss-na:{expected_hex}"

        # Must match regex pattern of sensor_capsule.v1.json#/$defs/digest
        schema = {"$ref": "sensor_capsule.v1.json#/$defs/digest"}
        self.validator.validate(schema, sentinel)

        # Must start with fss-na: (distinct scheme, never sha256:)
        self.assertTrue(sentinel.startswith("fss-na:"))
        self.assertEqual(len(sentinel), 7 + 64)


class TestEmittedModelReceipts(unittest.TestCase):
    """Receipts emitted by Rust (crates/fss-reference/tests/model_receipt_contract.rs pins these
    exact bytes) validated against the schema (fss-2h5zq.48)."""

    FIXTURE_DIR = REPO_ROOT / "tests" / "fixtures" / "model_receipts"
    SCHEMA_PATH = REPO_ROOT / "schemas" / "model_execution_receipt.v1.json"
    CASES = ("ok", "error", "budget_exhausted", "cancelled", "activity_package")
    DIGEST_FIELDS = (
        "modelPackageRoot",
        "activationGeneration",
        "preprocessProgram",
        "postprocessProgram",
        "operatorRegistryGeneration",
        "executionPlanDigest",
        "numericPolicyDigest",
        "decisionPathDigest",
    )

    def setUp(self):
        self.validator = InstanceValidator(REPO_ROOT / "schemas")
        self.schema = parse_strict_json(self.SCHEMA_PATH.read_text(encoding="utf-8"))

    def load(self, case):
        text = (self.FIXTURE_DIR / f"{case}.json").read_text(encoding="utf-8")
        return parse_strict_json(text)

    def test_every_emitted_receipt_validates(self):
        outcomes = set()
        for case in self.CASES:
            with self.subTest(case=case):
                receipt = self.load(case)
                validate_instance_file(self.SCHEMA_PATH, self.FIXTURE_DIR / f"{case}.json")
                outcomes.add(receipt["outcome"])
                print(
                    json.dumps(
                        {
                            "bead": "fss-2h5zq.48",
                            "step": "receipt_schema",
                            "case": case,
                            "outcome": receipt["outcome"],
                            "verdict": "valid",
                        }
                    )
                )
        self.assertEqual(outcomes, {"ok", "error", "budget_exhausted", "cancelled"})

    def test_outcome_fields_are_consistent(self):
        for case in self.CASES:
            with self.subTest(case=case):
                receipt = self.load(case)
                ok = receipt["outcome"] == "ok"
                self.assertEqual(receipt["outputRoot"] is not None, ok)
                self.assertEqual(receipt["operatorTraceDigest"] is not None, ok)
                self.assertEqual(receipt["errorId"] is not None, receipt["outcome"] == "error")
                self.assertEqual(
                    receipt["cancelReason"] is not None, receipt["outcome"] == "cancelled"
                )

    def test_sentinels_recompute_and_are_declared(self):
        for case in self.CASES:
            with self.subTest(case=case):
                receipt = self.load(case)
                features = receipt["backend"]["featureSet"]
                declared = {
                    f[len("sentinel:"):] for f in features if f.startswith("sentinel:")
                }
                seen = set()
                for field in self.DIGEST_FIELDS:
                    value = receipt[field]
                    if value.startswith("fss-na:"):
                        matches = [d for d in declared if d.startswith(field + "=")]
                        self.assertEqual(len(matches), 1, field)
                        reason = matches[0].split("=", 1)[1]
                        text = f"fss.model_execution_receipt.v1/sentinel/{field}/{reason}"
                        expected = "fss-na:" + hashlib.sha256(text.encode()).hexdigest()
                        self.assertEqual(value, expected, field)
                        seen.add(matches[0])
                    else:
                        self.assertRegex(value, r"\Asha256:[0-9a-f]{64}\Z", field)
                self.assertEqual(seen, declared)
                self.assertIn("activationGeneration=unactivated_reference_run", declared)

    def test_package_receipt_links_sources_and_names_its_package(self):
        receipt = self.load("activity_package")
        self.assertRegex(receipt["modelPackageRoot"], r"\Asha256:[0-9a-f]{64}\Z")
        features = receipt["backend"]["featureSet"]
        self.assertIn("input_roots:tensors=3,sources=2", features)
        self.assertEqual(len(receipt["inputRoots"]), 5)
        for case in ("ok", "error", "budget_exhausted", "cancelled"):
            self.assertTrue(self.load(case)["modelPackageRoot"].startswith("fss-na:"))

    def test_planted_mutations_of_emitted_receipts_are_refused(self):
        base = self.load("activity_package")

        def refused(mutate):
            receipt = json.loads(json.dumps(base))
            mutate(receipt)
            with self.assertRaises(JsonInstanceValidationError):
                self.validator.validate(self.schema, receipt, self.SCHEMA_PATH.name)

        refused(lambda r: r.__setitem__("modelPackageRoot", "not_applicable"))
        refused(lambda r: r.__setitem__("modelPackageRoot", r["modelPackageRoot"] + "\n"))
        refused(lambda r: r.pop("decisionPathDigest"))
        refused(lambda r: r.__setitem__("extra", 1))
        refused(lambda r: r.__setitem__("outcome", "succeeded"))
        refused(lambda r: r["usage"].__setitem__("workUnits", -1))
        refused(lambda r: r["usage"].__setitem__("wallNs", True))
        refused(lambda r: r.__setitem__("inputRoots", []))
        refused(lambda r: r.__setitem__("activationGeneration", None))


if __name__ == "__main__":
    unittest.main()

