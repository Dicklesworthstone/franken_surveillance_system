#!/usr/bin/env python3
"""Unit tests for json_instance_validate.py."""

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


if __name__ == "__main__":
    unittest.main()

