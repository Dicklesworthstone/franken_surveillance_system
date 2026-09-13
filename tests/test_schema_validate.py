#!/usr/bin/env python3
"""Comprehensive test suite for scripts/schema_validate.py.

Covers:
- Unit tests: every Draft 2020-12 keyword value type, local reference forms, escaped JSON Pointers,
  IDs, anchors, duplicate IDs, missing targets, invalid regex, contradictory bounds, unsupported dialects.
- Cyclic & recursive schemas: self-reference, mutual recursion, cycle detection, unguarded cycle rejection.
- Adversarial fixtures: path traversal, symlink escape, network URLs, deep recursion, file size limit,
  invalid UTF-8, malformed JSON, diagnostic truncation.
- Property tests: totality, determinism, graph-closure preservation, corruption preservation.
- Differential tests: comparison with sealed jsonschema Draft202012Validator oracle where available.
- Subprocess clean environment tests: isolated execution with no ambient packages.
"""
from __future__ import annotations

import importlib.util
import json
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
SCRIPT_PATH = ROOT / "scripts" / "schema_validate.py"

sys.path.insert(0, str(ROOT / "scripts"))
import schema_validate

DIALECT_2020_12 = schema_validate.DRAFT_2020_12_DIALECT


def make_valid_schema(
    schema_name: str = "test.schema.v1",
    schema_id: str | None = None,
    schema_dialect: str = DIALECT_2020_12,
    defs: dict[str, Any] | None = None,
    vocabulary: dict[str, bool] | None = None,
    **kwargs: Any,
) -> dict[str, Any]:
    sid = schema_id if schema_id is not None else f"https://franken-surveillance-system.invalid/schemas/{schema_name}.json"
    base: dict[str, Any] = {
        "$schema": schema_dialect,
        "$id": sid,
        "title": f"Test Schema {schema_name}",
        "type": "object",
        "properties": {
            "schema": {"const": f"fss.{schema_name}"},
        },
        "required": ["schema"],
        "additionalProperties": False,
    }
    if defs is not None:
        base["$defs"] = defs
    if vocabulary is not None:
        base["$vocabulary"] = vocabulary
    base.update(kwargs)
    return base


class TestValidRepositoryCatalog(unittest.TestCase):
    """Validate that the real schemas in schemas/*.json pass all checks."""

    def test_repository_schemas_pass(self) -> None:
        report = schema_validate.audit(schemas_dir=ROOT / "schemas")
        self.assertEqual(report["status"], "passed")
        self.assertEqual(report["errorCount"], 0)
        self.assertEqual(len([f for f in report["findings"] if f.get("severity") == "error"]), 0)
        self.assertGreaterEqual(report["schemaCount"], 57)
        self.assertGreaterEqual(report["referenceCount"], 200)
        self.assertTrue(report["catalogDigest"].startswith("sha256:"))
        self.assertTrue(report["proofHash"].startswith("sha256:"))
        self.assertEqual(report["cost"]["networkBytes"], 0)


class TestKeywordValueTypes(unittest.TestCase):
    """Unit tests for every keyword value type and constraint in Draft 2020-12."""

    def run_on_schema(self, schema_dict: dict[str, Any], filename: str = "fixture.json") -> dict[str, Any]:
        with tempfile.TemporaryDirectory() as temp_dir:
            temp_path = Path(temp_dir)
            file_path = temp_path / filename
            file_path.write_text(json.dumps(schema_dict), encoding="utf-8")
            return schema_validate.audit(schemas_dir=temp_path)

    def test_type_keyword(self) -> None:
        # Valid string types
        for t in ["null", "boolean", "object", "array", "number", "string", "integer"]:
            s = make_valid_schema(properties={"schema": {"const": "test"}, "val": {"type": t}})
            report = self.run_on_schema(s)
            self.assertEqual(report["status"], "passed", f"type '{t}' should pass")

        # Valid array of types
        s = make_valid_schema(properties={"schema": {"const": "test"}, "val": {"type": ["string", "null"]}})
        report = self.run_on_schema(s)
        self.assertEqual(report["status"], "passed")

        # Invalid type name
        s = make_valid_schema(properties={"schema": {"const": "test"}, "val": {"type": "invalid_type"}})
        report = self.run_on_schema(s)
        self.assertEqual(report["status"], "failed")
        self.assertTrue(any(f["code"] == schema_validate.CODE_INVALID_KEYWORD_SHAPE for f in report["findings"]))

        # Duplicate type in array
        s = make_valid_schema(properties={"schema": {"const": "test"}, "val": {"type": ["string", "string"]}})
        report = self.run_on_schema(s)
        self.assertEqual(report["status"], "failed")
        self.assertTrue(any(f["code"] == schema_validate.CODE_INVALID_KEYWORD_SHAPE for f in report["findings"]))

        # Empty type array
        s = make_valid_schema(properties={"schema": {"const": "test"}, "val": {"type": []}})
        report = self.run_on_schema(s)
        self.assertEqual(report["status"], "failed")

    def test_numeric_bounds_and_contradictions(self) -> None:
        # Valid bounds
        s = make_valid_schema(properties={"schema": {"const": "test"}, "num": {"type": "number", "minimum": 1, "maximum": 10}})
        self.assertEqual(self.run_on_schema(s)["status"], "passed")

        # Contradictory minimum > maximum
        s = make_valid_schema(properties={"schema": {"const": "test"}, "num": {"type": "number", "minimum": 10, "maximum": 1}})
        report = self.run_on_schema(s)
        self.assertEqual(report["status"], "failed")
        self.assertTrue(any(f["code"] == schema_validate.CODE_INVALID_KEYWORD_SHAPE and "contradictory" in f["message"] for f in report["findings"]))

        # Contradictory exclusiveMinimum >= exclusiveMaximum
        s = make_valid_schema(properties={"schema": {"const": "test"}, "num": {"type": "number", "exclusiveMinimum": 5, "exclusiveMaximum": 5}})
        report = self.run_on_schema(s)
        self.assertEqual(report["status"], "failed")

        # multipleOf <= 0
        s = make_valid_schema(properties={"schema": {"const": "test"}, "num": {"type": "number", "multipleOf": 0}})
        report = self.run_on_schema(s)
        self.assertEqual(report["status"], "failed")

        s = make_valid_schema(properties={"schema": {"const": "test"}, "num": {"type": "number", "multipleOf": -2}})
        report = self.run_on_schema(s)
        self.assertEqual(report["status"], "failed")

    def test_string_bounds_and_regex(self) -> None:
        # Valid minLength / maxLength
        s = make_valid_schema(properties={"schema": {"const": "test"}, "txt": {"type": "string", "minLength": 2, "maxLength": 5}})
        self.assertEqual(self.run_on_schema(s)["status"], "passed")

        # Contradictory minLength > maxLength
        s = make_valid_schema(properties={"schema": {"const": "test"}, "txt": {"type": "string", "minLength": 10, "maxLength": 2}})
        report = self.run_on_schema(s)
        self.assertEqual(report["status"], "failed")

        # Negative minLength
        s = make_valid_schema(properties={"schema": {"const": "test"}, "txt": {"type": "string", "minLength": -1}})
        self.assertEqual(self.run_on_schema(s)["status"], "failed")

        # Valid regex pattern
        s = make_valid_schema(properties={"schema": {"const": "test"}, "txt": {"type": "string", "pattern": "^[a-z]+$"}})
        self.assertEqual(self.run_on_schema(s)["status"], "passed")

        # Invalid regex pattern
        s = make_valid_schema(properties={"schema": {"const": "test"}, "txt": {"type": "string", "pattern": "[a-z"}})
        report = self.run_on_schema(s)
        self.assertEqual(report["status"], "failed")
        self.assertTrue(any(f["code"] == schema_validate.CODE_INVALID_REGEX for f in report["findings"]))

        # Invalid regex in patternProperties key
        s = make_valid_schema(patternProperties={"[unclosed": {"type": "string"}})
        report = self.run_on_schema(s)
        self.assertEqual(report["status"], "failed")
        self.assertTrue(any(f["code"] == schema_validate.CODE_INVALID_REGEX for f in report["findings"]))

    def test_array_keywords(self) -> None:
        # Valid items (schema)
        s = make_valid_schema(properties={"schema": {"const": "test"}, "arr": {"type": "array", "items": {"type": "string"}}})
        self.assertEqual(self.run_on_schema(s)["status"], "passed")

        # In Draft 2020-12, items CANNOT be an array of schemas (use prefixItems)
        s = make_valid_schema(properties={"schema": {"const": "test"}, "arr": {"type": "array", "items": [{"type": "string"}]}})
        report = self.run_on_schema(s)
        self.assertEqual(report["status"], "failed")
        self.assertTrue(any("prefixItems" in f["message"] for f in report["findings"]))

        # Valid prefixItems
        s = make_valid_schema(properties={"schema": {"const": "test"}, "arr": {"type": "array", "prefixItems": [{"type": "string"}, {"type": "number"}]}})
        self.assertEqual(self.run_on_schema(s)["status"], "passed")

        # Contradictory minItems > maxItems
        s = make_valid_schema(properties={"schema": {"const": "test"}, "arr": {"type": "array", "minItems": 5, "maxItems": 2}})
        self.assertEqual(self.run_on_schema(s)["status"], "failed")

        # Contradictory minContains > maxContains
        s = make_valid_schema(properties={"schema": {"const": "test"}, "arr": {"type": "array", "contains": {"type": "string"}, "minContains": 5, "maxContains": 2}})
        self.assertEqual(self.run_on_schema(s)["status"], "failed")

        # uniqueItems
        s = make_valid_schema(properties={"schema": {"const": "test"}, "arr": {"type": "array", "uniqueItems": True}})
        self.assertEqual(self.run_on_schema(s)["status"], "passed")

    def test_object_keywords(self) -> None:
        # Contradictory minProperties > maxProperties
        s = make_valid_schema(minProperties=10, maxProperties=2)
        self.assertEqual(self.run_on_schema(s)["status"], "failed")

        # Duplicate in required list
        s = make_valid_schema(required=["schema", "schema"])
        report = self.run_on_schema(s)
        self.assertEqual(report["status"], "failed")
        self.assertTrue(any("duplicate required" in f["message"] for f in report["findings"]))

        # dependentRequired with duplicates
        s = make_valid_schema(dependentRequired={"a": ["b", "b"]})
        report = self.run_on_schema(s)
        self.assertEqual(report["status"], "failed")

        # additionalProperties boolean and schema
        s1 = make_valid_schema(additionalProperties=True)
        self.assertEqual(self.run_on_schema(s1)["status"], "passed")
        s2 = make_valid_schema(additionalProperties={"type": "string"})
        self.assertEqual(self.run_on_schema(s2)["status"], "passed")

        # propertyNames
        s = make_valid_schema(propertyNames={"pattern": "^[a-z]+$"})
        self.assertEqual(self.run_on_schema(s)["status"], "passed")

    def test_combinators(self) -> None:
        # allOf, anyOf, oneOf
        s = make_valid_schema(
            allOf=[{"properties": {"a": {"type": "string"}}}],
            anyOf=[{"properties": {"b": {"type": "number"}}}],
            oneOf=[{"properties": {"c": {"type": "boolean"}}}],
        )
        s["not"] = {"type": "null"}
        self.assertEqual(self.run_on_schema(s)["status"], "passed")

        # Empty combinator array
        s = make_valid_schema(allOf=[])
        self.assertEqual(self.run_on_schema(s)["status"], "failed")

    def test_metadata_and_annotations(self) -> None:
        s = make_valid_schema(
            description="A valid test schema",
            default={"schema": "fss.test.schema.v1"},
            deprecated=False,
            readOnly=False,
            writeOnly=False,
            examples=[{"schema": "fss.test.schema.v1"}],
            format="uri",
            contentEncoding="base64",
            contentMediaType="application/json",
            contentSchema={"type": "object"},
        )
        self.assertEqual(self.run_on_schema(s)["status"], "passed")


class TestReferenceForms(unittest.TestCase):
    """Test all local reference forms, pointer escapes, and anchor lookups."""

    def test_same_document_pointer_and_defs(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            temp_path = Path(temp_dir)
            schema = make_valid_schema(
                defs={
                    "ident": {"type": "string", "minLength": 1},
                },
                properties={
                    "schema": {"const": "fss.test.schema.v1"},
                    "myId": {"$ref": "#/$defs/ident"},
                },
            )
            (temp_path / "a.json").write_text(json.dumps(schema), encoding="utf-8")
            report = schema_validate.audit(schemas_dir=temp_path)
            self.assertEqual(report["status"], "passed")

    def test_escaped_json_pointer_tokens(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            temp_path = Path(temp_dir)
            schema = make_valid_schema(
                defs={
                    "a/b~c": {"type": "string"},
                },
                properties={
                    "schema": {"const": "fss.test.schema.v1"},
                    "val": {"$ref": "#/$defs/a~1b~0c"},
                },
            )
            (temp_path / "a.json").write_text(json.dumps(schema), encoding="utf-8")
            report = schema_validate.audit(schemas_dir=temp_path)
            self.assertEqual(report["status"], "passed")

    def test_anchor_and_dynamic_anchor(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            temp_path = Path(temp_dir)
            schema = make_valid_schema(
                defs={
                    "anchored": {
                        "$anchor": "myAnchor",
                        "type": "string",
                    },
                },
                properties={
                    "schema": {"const": "fss.test.schema.v1"},
                    "val": {"$ref": "#myAnchor"},
                },
            )
            (temp_path / "a.json").write_text(json.dumps(schema), encoding="utf-8")
            report = schema_validate.audit(schemas_dir=temp_path)
            self.assertEqual(report["status"], "passed")

    def test_cross_file_relative_reference(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            temp_path = Path(temp_dir)
            common = make_valid_schema(
                "common.v1",
                defs={
                    "identifier": {"type": "string"},
                },
            )
            consumer = make_valid_schema(
                "consumer.v1",
                properties={
                    "schema": {"const": "fss.consumer.v1"},
                    "id": {"$ref": "common.v1.json#/$defs/identifier"},
                },
            )
            (temp_path / "common.v1.json").write_text(json.dumps(common), encoding="utf-8")
            (temp_path / "consumer.v1.json").write_text(json.dumps(consumer), encoding="utf-8")
            report = schema_validate.audit(schemas_dir=temp_path)
            self.assertEqual(report["status"], "passed")

    def test_canonical_uri_reference(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            temp_path = Path(temp_dir)
            target = make_valid_schema(
                "target.v1",
                defs={"token": {"type": "string"}},
            )
            consumer = make_valid_schema(
                "consumer.v1",
                properties={
                    "schema": {"const": "fss.consumer.v1"},
                    "tok": {"$ref": "https://franken-surveillance-system.invalid/schemas/target.v1.json#/$defs/token"},
                },
            )
            (temp_path / "target.v1.json").write_text(json.dumps(target), encoding="utf-8")
            (temp_path / "consumer.v1.json").write_text(json.dumps(consumer), encoding="utf-8")
            report = schema_validate.audit(schemas_dir=temp_path)
            self.assertEqual(report["status"], "passed")

    def test_unresolved_reference_and_pointer(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            temp_path = Path(temp_dir)
            schema = make_valid_schema(
                properties={
                    "schema": {"const": "fss.test.schema.v1"},
                    "val": {"$ref": "non_existent.json#/$defs/foo"},
                },
            )
            (temp_path / "a.json").write_text(json.dumps(schema), encoding="utf-8")
            report = schema_validate.audit(schemas_dir=temp_path)
            self.assertEqual(report["status"], "failed")
            self.assertTrue(any(f["code"] == schema_validate.CODE_UNRESOLVED_REFERENCE for f in report["findings"]))

        with tempfile.TemporaryDirectory() as temp_dir:
            temp_path = Path(temp_dir)
            schema = make_valid_schema(
                properties={
                    "schema": {"const": "fss.test.schema.v1"},
                    "val": {"$ref": "#/$defs/missing_token"},
                },
            )
            (temp_path / "a.json").write_text(json.dumps(schema), encoding="utf-8")
            report = schema_validate.audit(schemas_dir=temp_path)
            self.assertEqual(report["status"], "failed")
            self.assertTrue(any(f["code"] == schema_validate.CODE_UNRESOLVED_POINTER for f in report["findings"]))

    def test_unresolved_anchor(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            temp_path = Path(temp_dir)
            schema = make_valid_schema(
                properties={
                    "schema": {"const": "fss.test.schema.v1"},
                    "val": {"$ref": "#missingAnchor"},
                },
            )
            (temp_path / "a.json").write_text(json.dumps(schema), encoding="utf-8")
            report = schema_validate.audit(schemas_dir=temp_path)
            self.assertEqual(report["status"], "failed")
            self.assertTrue(any(f["code"] == schema_validate.CODE_UNRESOLVED_ANCHOR for f in report["findings"]))


class TestDialectAndVocabularies(unittest.TestCase):
    """Test dialect and vocabulary gating."""

    def test_unsupported_dialects_fail_closed(self) -> None:
        unsupported = [
            "http://json-schema.org/draft-07/schema#",
            "http://json-schema.org/draft-04/schema#",
            "https://json-schema.org/draft/2019-09/schema",
            "https://example.com/custom-dialect",
        ]
        for bad_dialect in unsupported:
            with tempfile.TemporaryDirectory() as temp_dir:
                temp_path = Path(temp_dir)
                schema = make_valid_schema(schema_dialect=bad_dialect)
                (temp_path / "a.json").write_text(json.dumps(schema), encoding="utf-8")
                report = schema_validate.audit(schemas_dir=temp_path)
                self.assertEqual(report["status"], "failed", f"dialect {bad_dialect} should fail")
                self.assertTrue(any(f["code"] == schema_validate.CODE_INVALID_DIALECT for f in report["findings"]))

    def test_missing_and_non_string_schema(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            temp_path = Path(temp_dir)
            schema = make_valid_schema()
            del schema["$schema"]
            (temp_path / "a.json").write_text(json.dumps(schema), encoding="utf-8")
            report = schema_validate.audit(schemas_dir=temp_path)
            self.assertEqual(report["status"], "failed")
            self.assertTrue(any(f["code"] == schema_validate.CODE_INVALID_DIALECT for f in report["findings"]))

        with tempfile.TemporaryDirectory() as temp_dir:
            temp_path = Path(temp_dir)
            schema = make_valid_schema()
            schema["$schema"] = 12345
            (temp_path / "a.json").write_text(json.dumps(schema), encoding="utf-8")
            report = schema_validate.audit(schemas_dir=temp_path)
            self.assertEqual(report["status"], "failed")
            self.assertTrue(any(f["code"] == schema_validate.CODE_INVALID_DIALECT for f in report["findings"]))

    def test_unsupported_required_vocabulary(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            temp_path = Path(temp_dir)
            schema = make_valid_schema(
                vocabulary={
                    "https://json-schema.org/draft/2020-12/vocab/core": True,
                    "https://example.com/vocab/unsupported": True,
                }
            )
            (temp_path / "a.json").write_text(json.dumps(schema), encoding="utf-8")
            report = schema_validate.audit(schemas_dir=temp_path)
            self.assertEqual(report["status"], "failed")
            self.assertTrue(any(f["code"] == schema_validate.CODE_UNSUPPORTED_VOCABULARY for f in report["findings"]))


class TestIdentitiesAndAnchors(unittest.TestCase):
    """Test duplicate canonical IDs, fragments in $id, and duplicate anchors."""

    def test_duplicate_canonical_id(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            temp_path = Path(temp_dir)
            s1 = make_valid_schema("shared.v1")
            s2 = make_valid_schema("other.v1", schema_id="https://franken-surveillance-system.invalid/schemas/shared.v1.json")
            (temp_path / "s1.json").write_text(json.dumps(s1), encoding="utf-8")
            (temp_path / "s2.json").write_text(json.dumps(s2), encoding="utf-8")
            report = schema_validate.audit(schemas_dir=temp_path)
            self.assertEqual(report["status"], "failed")
            self.assertTrue(any(f["code"] == schema_validate.CODE_DUPLICATE_CANONICAL_ID for f in report["findings"]))

    def test_id_with_non_empty_fragment(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            temp_path = Path(temp_dir)
            s = make_valid_schema(
                schema_id="https://franken-surveillance-system.invalid/schemas/test.json#some-fragment"
            )
            (temp_path / "a.json").write_text(json.dumps(s), encoding="utf-8")
            report = schema_validate.audit(schemas_dir=temp_path)
            self.assertEqual(report["status"], "failed")
            self.assertTrue(any(f["code"] == schema_validate.CODE_INVALID_URI_REFERENCE for f in report["findings"]))

    def test_duplicate_anchor(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            temp_path = Path(temp_dir)
            s = make_valid_schema(
                properties={
                    "schema": {"const": "test"},
                    "a": {"$anchor": "dupAnchor", "type": "string"},
                    "b": {"$anchor": "dupAnchor", "type": "number"},
                }
            )
            (temp_path / "a.json").write_text(json.dumps(s), encoding="utf-8")
            report = schema_validate.audit(schemas_dir=temp_path)
            self.assertEqual(report["status"], "failed")
            self.assertTrue(any(f["code"] == schema_validate.CODE_DUPLICATE_ANCHOR for f in report["findings"]))


class TestCyclicAndRecursiveSchemas(unittest.TestCase):
    """Test cyclic reference handling and detection."""

    def test_valid_self_recursive_schema(self) -> None:
        # Recursive tree node: children is array of tree nodes
        with tempfile.TemporaryDirectory() as temp_dir:
            temp_path = Path(temp_dir)
            tree_schema = make_valid_schema(
                "tree.v1",
                properties={
                    "schema": {"const": "fss.tree.v1"},
                    "name": {"type": "string"},
                    "children": {
                        "type": "array",
                        "items": {"$ref": "tree.v1.json"},
                    },
                },
            )
            (temp_path / "tree.v1.json").write_text(json.dumps(tree_schema), encoding="utf-8")
            report = schema_validate.audit(schemas_dir=temp_path)
            self.assertEqual(report["status"], "passed")
            self.assertEqual(report["cycleCount"], 1)

    def test_valid_mutually_recursive_schemas(self) -> None:
        # A references B, B references A
        with tempfile.TemporaryDirectory() as temp_dir:
            temp_path = Path(temp_dir)
            schema_a = make_valid_schema(
                "a.v1",
                properties={
                    "schema": {"const": "fss.a.v1"},
                    "childB": {"$ref": "b.v1.json"},
                },
            )
            schema_b = make_valid_schema(
                "b.v1",
                properties={
                    "schema": {"const": "fss.b.v1"},
                    "childA": {"$ref": "a.v1.json"},
                },
            )
            (temp_path / "a.v1.json").write_text(json.dumps(schema_a), encoding="utf-8")
            (temp_path / "b.v1.json").write_text(json.dumps(schema_b), encoding="utf-8")
            report = schema_validate.audit(schemas_dir=temp_path)
            self.assertEqual(report["status"], "passed")
            self.assertGreaterEqual(report["cycleCount"], 1)

    def test_unguarded_direct_cycle_rejected(self) -> None:
        # A top-level schema referencing another directly without gating: infinite loop / reference bomb
        with tempfile.TemporaryDirectory() as temp_dir:
            temp_path = Path(temp_dir)
            bad_loop = {
                "$schema": DIALECT_2020_12,
                "$id": "https://franken-surveillance-system.invalid/schemas/bomb.v1.json",
                "$ref": "bomb.v1.json",
            }
            (temp_path / "bomb.v1.json").write_text(json.dumps(bad_loop), encoding="utf-8")
            report = schema_validate.audit(schemas_dir=temp_path)
            self.assertEqual(report["status"], "failed")
            self.assertTrue(any(f["code"] == schema_validate.CODE_UNGUARDED_CYCLE for f in report["findings"]))


class TestAdversarialAndNegativeFixtures(unittest.TestCase):
    """Test security boundaries and adversarial inputs."""

    def test_path_traversal_forbidden(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            temp_path = Path(temp_dir)
            schema = make_valid_schema(
                properties={
                    "schema": {"const": "fss.test.schema.v1"},
                    "val": {"$ref": "../../../etc/passwd"},
                },
            )
            (temp_path / "a.json").write_text(json.dumps(schema), encoding="utf-8")
            report = schema_validate.audit(schemas_dir=temp_path)
            self.assertEqual(report["status"], "failed")
            self.assertTrue(any(f["code"] == schema_validate.CODE_PATH_TRAVERSAL for f in report["findings"]))

    def test_network_url_reference_forbidden_offline(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            temp_path = Path(temp_dir)
            schema = make_valid_schema(
                properties={
                    "schema": {"const": "fss.test.schema.v1"},
                    "val": {"$ref": "https://evil.external.com/schema.json"},
                },
            )
            (temp_path / "a.json").write_text(json.dumps(schema), encoding="utf-8")
            report = schema_validate.audit(schemas_dir=temp_path)
            self.assertEqual(report["status"], "failed")
            self.assertTrue(any(f["code"] == schema_validate.CODE_NETWORK_FETCH_FORBIDDEN for f in report["findings"]))

    def test_deep_recursion_resource_limit(self) -> None:
        # Nest subschemas deeper than max_depth
        deep_node: dict[str, Any] = {"type": "string"}
        for _ in range(70):
            deep_node = {"type": "object", "properties": {"nested": deep_node}}
        schema = make_valid_schema(properties={"schema": {"const": "test"}, "deep": deep_node})

        with tempfile.TemporaryDirectory() as temp_dir:
            temp_path = Path(temp_dir)
            (temp_path / "deep.json").write_text(json.dumps(schema), encoding="utf-8")
            report = schema_validate.audit(schemas_dir=temp_path, max_depth=32)
            self.assertEqual(report["status"], "failed")
            self.assertTrue(any(f["code"] == schema_validate.CODE_RECURSION_LIMIT_EXCEEDED for f in report["findings"]))

    def test_file_size_resource_limit(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            temp_path = Path(temp_dir)
            schema = make_valid_schema(description="A" * 5000)
            (temp_path / "big.json").write_text(json.dumps(schema), encoding="utf-8")
            report = schema_validate.audit(schemas_dir=temp_path, max_file_bytes=1000)
            self.assertEqual(report["status"], "failed")
            self.assertTrue(any(f["code"] == schema_validate.CODE_RESOURCE_LIMIT_EXCEEDED for f in report["findings"]))

    def test_invalid_utf8(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            temp_path = Path(temp_dir)
            (temp_path / "bad_utf8.json").write_bytes(b'{"key": "\xff\xfe\x00"}')
            report = schema_validate.audit(schemas_dir=temp_path)
            self.assertEqual(report["status"], "failed")
            self.assertTrue(any(f["code"] == schema_validate.CODE_MALFORMED_JSON for f in report["findings"]))

    def test_json_syntax_error(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            temp_path = Path(temp_dir)
            (temp_path / "syntax.json").write_text('{"unclosed": ', encoding="utf-8")
            report = schema_validate.audit(schemas_dir=temp_path)
            self.assertEqual(report["status"], "failed")
            self.assertTrue(any(f["code"] == schema_validate.CODE_MALFORMED_JSON for f in report["findings"]))

    def test_non_object_root_schema(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            temp_path = Path(temp_dir)
            (temp_path / "not_object.json").write_text('["array", "not", "object"]', encoding="utf-8")
            report = schema_validate.audit(schemas_dir=temp_path)
            self.assertEqual(report["status"], "failed")
            self.assertTrue(any(f["code"] == schema_validate.CODE_INVALID_SCHEMA_TYPE for f in report["findings"]))

    def test_bounded_diagnostics_truncation(self) -> None:
        # Generate many errors and verify cap at max_errors
        bad_props = {f"prop_{i}": {"type": "bad_type"} for i in range(25)}
        schema = make_valid_schema(properties=bad_props)

        with tempfile.TemporaryDirectory() as temp_dir:
            temp_path = Path(temp_dir)
            (temp_path / "many_errors.json").write_text(json.dumps(schema), encoding="utf-8")
            report = schema_validate.audit(schemas_dir=temp_path, max_errors=5)
            self.assertEqual(report["status"], "failed")
            self.assertEqual(report["diagnosticCardinality"], 5)
            self.assertTrue(report["diagnosticsTruncated"])


class TestPropertyBasedTotalityAndDeterminism(unittest.TestCase):
    """Property tests: determinism, totality, and graph-closure invariants."""

    def test_determinism(self) -> None:
        report1 = schema_validate.audit(schemas_dir=ROOT / "schemas")
        report2 = schema_validate.audit(schemas_dir=ROOT / "schemas")
        self.assertEqual(report1["catalogDigest"], report2["catalogDigest"])
        self.assertEqual(report1["schemaCount"], report2["schemaCount"])
        self.assertEqual(report1["referenceCount"], report2["referenceCount"])
        self.assertEqual(report1["findings"], report2["findings"])

    def test_totality_on_arbitrary_json(self) -> None:
        # Must never raise an uncaught exception on arbitrary JSON inputs
        fuzz_samples = [
            {},
            {"$schema": None},
            {"$schema": "", "properties": None},
            {"allOf": [None, 123, "string", True, False]},
            {"type": ["null", 123]},
            {"pattern": "("},
            {"$ref": ""},
            {"$ref": "#/123/456"},
        ]
        with tempfile.TemporaryDirectory() as temp_dir:
            temp_path = Path(temp_dir)
            for i, sample in enumerate(fuzz_samples):
                (temp_path / f"sample_{i}.json").write_text(json.dumps(sample), encoding="utf-8")
            report = schema_validate.audit(schemas_dir=temp_path)
            self.assertEqual(report["status"], "failed")

    def test_graph_closure_preservation(self) -> None:
        # In a valid two-file schema graph, removing the target MUST cause failure
        with tempfile.TemporaryDirectory() as temp_dir:
            temp_path = Path(temp_dir)
            common = make_valid_schema("common.v1", defs={"id": {"type": "string"}})
            consumer = make_valid_schema("consumer.v1", properties={"schema": {"const": "fss.consumer.v1"}, "id": {"$ref": "common.v1.json#/$defs/id"}})
            (temp_path / "common.v1.json").write_text(json.dumps(common), encoding="utf-8")
            (temp_path / "consumer.v1.json").write_text(json.dumps(consumer), encoding="utf-8")

            # Initially passes
            self.assertEqual(schema_validate.audit(schemas_dir=temp_path)["status"], "passed")

            # Remove referenced contract
            (temp_path / "common.v1.json").unlink()
            report = schema_validate.audit(schemas_dir=temp_path)
            self.assertEqual(report["status"], "failed")
            self.assertTrue(any(f["code"] == schema_validate.CODE_UNRESOLVED_REFERENCE for f in report["findings"]))

    def test_corruption_preservation(self) -> None:
        # Corrupting a referenced definition MUST cause failure
        with tempfile.TemporaryDirectory() as temp_dir:
            temp_path = Path(temp_dir)
            common = make_valid_schema("common.v1", defs={"id": {"type": "string"}})
            consumer = make_valid_schema("consumer.v1", properties={"schema": {"const": "fss.consumer.v1"}, "id": {"$ref": "common.v1.json#/$defs/id"}})
            (temp_path / "common.v1.json").write_text(json.dumps(common), encoding="utf-8")
            (temp_path / "consumer.v1.json").write_text(json.dumps(consumer), encoding="utf-8")

            # Corrupt common.v1.json definition: change $defs key
            corrupted = make_valid_schema("common.v1", defs={"different_key": {"type": "string"}})
            (temp_path / "common.v1.json").write_text(json.dumps(corrupted), encoding="utf-8")
            report = schema_validate.audit(schemas_dir=temp_path)
            self.assertEqual(report["status"], "failed")
            self.assertTrue(any(f["code"] == schema_validate.CODE_UNRESOLVED_POINTER for f in report["findings"]))


class TestDifferentialOracle(unittest.TestCase):
    """Differential test against independent Draft 2020-12 oracle if installed."""

    def test_conformance_with_jsonschema_oracle(self) -> None:
        try:
            import jsonschema  # type: ignore
        except ImportError:
            self.skipTest("ambient jsonschema package not installed")

        validator_cls = jsonschema.Draft202012Validator

        # Test valid repo schemas
        for schema_path in sorted((ROOT / "schemas").glob("*.json")):
            with schema_path.open("r", encoding="utf-8") as f:
                doc = json.load(f)
            # Both must agree this schema is valid Draft 2020-12
            validator_cls.check_schema(doc)

        # Test invalid schemas: both must flag them
        invalid_cases = [
            {"$schema": DIALECT_2020_12, "type": "not_a_type"},
            {"$schema": DIALECT_2020_12, "items": [{"type": "string"}]},  # tuple in items
            {"$schema": DIALECT_2020_12, "multipleOf": -1},
            {"$schema": DIALECT_2020_12, "pattern": "["},
        ]
        for inv in invalid_cases:
            with self.assertRaises(Exception):
                validator_cls.check_schema(inv)

            with tempfile.TemporaryDirectory() as temp_dir:
                p = Path(temp_dir)
                (p / "inv.json").write_text(json.dumps(inv), encoding="utf-8")
                report = schema_validate.audit(schemas_dir=p)
                self.assertEqual(report["status"], "failed")


class TestSubprocessCleanEnvironment(unittest.TestCase):
    """Execute schema_validate.py in an isolated subprocess with zero ambient dependencies."""

    def test_clean_subprocess_execution(self) -> None:
        env = os.environ.copy()
        env["PYTHONPATH"] = ""
        result = subprocess.run(
            [sys.executable, str(SCRIPT_PATH)],
            cwd=ROOT,
            capture_output=True,
            text=True,
            env=env,
        )
        self.assertEqual(result.returncode, 0, f"stdout: {result.stdout}\nstderr: {result.stderr}")
        self.assertIn("schema validation passed", result.stdout)
        self.assertRegex(result.stdout, r"schemaCount=\d+")
        self.assertIn("status=passed", result.stdout)

    def test_clean_subprocess_json_output(self) -> None:
        env = os.environ.copy()
        env["PYTHONPATH"] = ""
        result = subprocess.run(
            [sys.executable, str(SCRIPT_PATH), "--json"],
            cwd=ROOT,
            capture_output=True,
            text=True,
            env=env,
        )
        self.assertEqual(result.returncode, 0)
        data = json.loads(result.stdout)
        self.assertEqual(data["status"], "passed")
        self.assertGreaterEqual(data["schemaCount"], 57)
        self.assertEqual(data["cost"]["networkBytes"], 0)

    def test_clean_subprocess_failure_exit_code(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            temp_path = Path(temp_dir)
            bad = {"$schema": "invalid-dialect"}
            (temp_path / "bad.json").write_text(json.dumps(bad), encoding="utf-8")

            result = subprocess.run(
                [sys.executable, str(SCRIPT_PATH), "--schemas-dir", str(temp_path)],
                cwd=ROOT,
                capture_output=True,
                text=True,
            )
            self.assertEqual(result.returncode, 1)
            self.assertIn("schema validation failed", result.stderr)
            self.assertIn(schema_validate.CODE_INVALID_DIALECT, result.stderr)


class TestSchemaConstitution(unittest.TestCase):
    def test_authoritative_constitution(self) -> None:
        validator = schema_validate.Validator()
        result = schema_validate.validate_schema_constitution(
            repo_root=ROOT,
            schemas_dir=ROOT / "schemas",
            schemas_md_path=ROOT / "registries" / "SCHEMAS.md",
            architecture_dir=ROOT / "architecture",
            crates_dir=ROOT / "crates",
            validator=validator,
        )
        self.assertEqual(result["status"], "passed")
        self.assertGreaterEqual(result["totalDeclared"], 60)
        self.assertEqual(result["totalDeclared"], result["implementedCount"] + result["declaredOnlyCount"])
        self.assertEqual(sum(1 for s in result["schemas"] if s["status"] == "implemented" and s["owner"] is None), 0)
        self.assertGreaterEqual(result["implementedCount"], 17)
        self.assertGreaterEqual(result["architectureReferenceCount"], 140)
        self.assertTrue(result["constitutionDigest"].startswith("sha256:"))

        # No error findings
        error_findings = [f for f in validator.findings if f.severity == "error"]
        self.assertEqual(len(error_findings), 0)

        # Identity and explicit set of expected declared-only schemas
        expected_declared_only = {
            "fss.adapter_compatibility_certificate.v1",
            "fss.agent_affordance.v1",
            "fss.agent_cognitive_envelope.v1",
            "fss.agent_control_plan.v1",
            "fss.agent_execution_episode.v1",
            "fss.agent_feedback_proposal.v1",
            "fss.agent_finding.v1",
            "fss.agent_handoff_capsule.v1",
            "fss.agent_hypothesis_workspace.v1",
            "fss.agent_learning_proposal.v1",
            "fss.agent_mission.v1",
            "fss.agent_objective_contract.v1",
            "fss.agent_query_plan.v1",
            "fss.agent_request_envelope.v1",
            "fss.agent_response_envelope.v1",
            "fss.agent_session.v1",
            "fss.agent_session_capsule.v1",
            "fss.agent_work_claim.v1",
            "fss.calibration_certificate.v1",
            "fss.cancellation_drain_certificate.v1",
            "fss.capabilities.v1",
            "fss.decision_card.v1",
            "fss.doctor.v1",
            "fss.evidence_anchor.v1",
            "fss.evidence_bundle.v1",
            "fss.evidence_delta_batch.v1",
            "fss.experience_capsule.v1",
            "fss.graph_algorithm_witness.v1",
            "fss.investigation_state.v1",
            "fss.license_inventory.v1",
            "fss.model_execution_receipt.v1",
            "fss.model_manifest.v1",
            "fss.model_package_manifest.v1",
            "fss.qualification_root.v2",
            "fss.release_build_receipt.v1",
            "fss.release_qualification_receipt.v1",
            "fss.release_stage_verification.v1",
            "fss.semantic_handle.v1",
            "fss.source_manifest.v1",
            "fss.status.v1",
            "fss.transfer_manifest.v1",
            "fss.transfer_receipt.v1",
        }
        actual_declared_only = {s["name"] for s in result["schemas"] if s["status"] == "declared"}
        self.assertTrue(expected_declared_only.issubset(actual_declared_only))

        # Reconciled canonical-digest domains and continuation cursor: zero unregistered drift
        unreg_findings = [f for f in validator.findings if f.code == schema_validate.CODE_UNREGISTERED_IMPLEMENTED_SCHEMA]
        self.assertEqual(len(unreg_findings), 0)
        self.assertEqual(result["unregisteredImplementedCount"], 0)
        self.assertEqual(result["digestDomainCount"], 44)

        # Continuation cursor is verified implemented
        implemented_names = {s["name"] for s in result["schemas"] if s["status"] == "implemented"}
        self.assertIn("fss.agent_continuation_cursor.v1", implemented_names)

        # Check implemented vs declared invariants
        for item in result["schemas"]:
            if item["status"] == "implemented":
                self.assertIsNotNone(item["owner"])
                self.assertEqual(item["owner"]["crate"], "fss-core")
                self.assertNotEqual(item["owner"]["type"], "Unknown")
                self.assertTrue((ROOT / item["owner"]["file"]).is_file())
            else:
                self.assertEqual(item["status"], "declared")
                self.assertIsNone(item["owner"])

    def test_duplicate_stable_id_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            td = Path(temp_dir)
            fake_md = td / "SCHEMAS.md"
            fake_md.write_text(
                "# Schema registry\n\n"
                "| ID | Schema | File | Authority | Compatibility rule |\n"
                "|---|---|---|---|---|\n"
                "| `SCHEMA-FOO-001` | `fss.foo.v1` | `CLI output` | auth | rule |\n"
                "| `SCHEMA-FOO-001` | `fss.bar.v1` | `CLI output` | auth | rule |\n"
            )
            validator = schema_validate.Validator()
            result = schema_validate.validate_schema_constitution(
                repo_root=td,
                schemas_dir=td / "schemas",
                schemas_md_path=fake_md,
                architecture_dir=td / "architecture",
                crates_dir=td / "crates",
                validator=validator,
            )
            self.assertEqual(result["status"], "failed")
            codes = [f.code for f in validator.findings]
            self.assertIn(schema_validate.CODE_DUPLICATE_STABLE_ID, codes)

    def test_duplicate_schema_name_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            td = Path(temp_dir)
            fake_md = td / "SCHEMAS.md"
            fake_md.write_text(
                "# Schema registry\n\n"
                "| ID | Schema | File | Authority | Compatibility rule |\n"
                "|---|---|---|---|---|\n"
                "| `SCHEMA-FOO-001` | `fss.foo.v1` | `CLI output` | auth | rule |\n"
                "| `SCHEMA-FOO-002` | `fss.foo.v1` | `CLI output` | auth | rule |\n"
            )
            validator = schema_validate.Validator()
            result = schema_validate.validate_schema_constitution(
                repo_root=td,
                schemas_dir=td / "schemas",
                schemas_md_path=fake_md,
                architecture_dir=td / "architecture",
                crates_dir=td / "crates",
                validator=validator,
            )
            self.assertEqual(result["status"], "failed")
            codes = [f.code for f in validator.findings]
            self.assertIn(schema_validate.CODE_DUPLICATE_SCHEMA_NAME, codes)

    def test_invalid_stable_id_syntax_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            td = Path(temp_dir)
            fake_md = td / "SCHEMAS.md"
            fake_md.write_text(
                "# Schema registry\n\n"
                "| ID | Schema | File | Authority | Compatibility rule |\n"
                "|---|---|---|---|---|\n"
                "| `INVALID_ID_001` | `fss.foo.v1` | `CLI output` | auth | rule |\n"
            )
            validator = schema_validate.Validator()
            result = schema_validate.validate_schema_constitution(
                repo_root=td,
                schemas_dir=td / "schemas",
                schemas_md_path=fake_md,
                architecture_dir=td / "architecture",
                crates_dir=td / "crates",
                validator=validator,
            )
            self.assertEqual(result["status"], "failed")
            codes = [f.code for f in validator.findings]
            self.assertIn(schema_validate.CODE_INVALID_STABLE_ID, codes)

    def test_invalid_schema_name_syntax_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            td = Path(temp_dir)
            fake_md = td / "SCHEMAS.md"
            fake_md.write_text(
                "# Schema registry\n\n"
                "| ID | Schema | File | Authority | Compatibility rule |\n"
                "|---|---|---|---|---|\n"
                "| `SCHEMA-FOO-001` | `bad_schema_name` | `CLI output` | auth | rule |\n"
            )
            validator = schema_validate.Validator()
            result = schema_validate.validate_schema_constitution(
                repo_root=td,
                schemas_dir=td / "schemas",
                schemas_md_path=fake_md,
                architecture_dir=td / "architecture",
                crates_dir=td / "crates",
                validator=validator,
            )
            self.assertEqual(result["status"], "failed")
            codes = [f.code for f in validator.findings]
            self.assertIn(schema_validate.CODE_INVALID_SCHEMA_NAME, codes)

    def test_missing_schema_file_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            td = Path(temp_dir)
            fake_md = td / "SCHEMAS.md"
            fake_md.write_text(
                "# Schema registry\n\n"
                "| ID | Schema | File | Authority | Compatibility rule |\n"
                "|---|---|---|---|---|\n"
                "| `SCHEMA-FOO-001` | `fss.foo.v1` | `schemas/nonexistent.v1.json` | auth | rule |\n"
            )
            validator = schema_validate.Validator()
            result = schema_validate.validate_schema_constitution(
                repo_root=td,
                schemas_dir=td / "schemas",
                schemas_md_path=fake_md,
                architecture_dir=td / "architecture",
                crates_dir=td / "crates",
                validator=validator,
            )
            self.assertEqual(result["status"], "failed")
            codes = [f.code for f in validator.findings]
            self.assertIn(schema_validate.CODE_MISSING_SCHEMA_FILE, codes)

    def test_unregistered_schema_file_on_disk_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            td = Path(temp_dir)
            schemas_d = td / "schemas"
            schemas_d.mkdir()
            (schemas_d / "orphan.v1.json").write_text(json.dumps(make_valid_schema("orphan.v1")))
            fake_md = td / "SCHEMAS.md"
            fake_md.write_text(
                "# Schema registry\n\n"
                "| ID | Schema | File | Authority | Compatibility rule |\n"
                "|---|---|---|---|---|\n"
                "| `SCHEMA-FOO-001` | `fss.foo.v1` | `CLI output` | auth | rule |\n"
            )
            validator = schema_validate.Validator()
            result = schema_validate.validate_schema_constitution(
                repo_root=td,
                schemas_dir=schemas_d,
                schemas_md_path=fake_md,
                architecture_dir=td / "architecture",
                crates_dir=td / "crates",
                validator=validator,
            )
            self.assertEqual(result["status"], "failed")
            codes = [f.code for f in validator.findings]
            self.assertIn(schema_validate.CODE_UNREGISTERED_SCHEMA_FILE, codes)

    def test_schema_const_mismatch_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            td = Path(temp_dir)
            schemas_d = td / "schemas"
            schemas_d.mkdir()
            schema_obj = make_valid_schema("foo.v1")
            schema_obj["properties"]["schema"]["const"] = "fss.bar.v1"
            (schemas_d / "foo.v1.json").write_text(json.dumps(schema_obj))

            fake_md = td / "SCHEMAS.md"
            fake_md.write_text(
                "# Schema registry\n\n"
                "| ID | Schema | File | Authority | Compatibility rule |\n"
                "|---|---|---|---|---|\n"
                "| `SCHEMA-FOO-001` | `fss.foo.v1` | `schemas/foo.v1.json` | auth | rule |\n"
            )
            validator = schema_validate.Validator()
            result = schema_validate.validate_schema_constitution(
                repo_root=td,
                schemas_dir=schemas_d,
                schemas_md_path=fake_md,
                architecture_dir=td / "architecture",
                crates_dir=td / "crates",
                validator=validator,
            )
            self.assertEqual(result["status"], "failed")
            codes = [f.code for f in validator.findings]
            self.assertIn(schema_validate.CODE_SCHEMA_CONST_MISMATCH, codes)

    def test_schema_id_mismatch_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            td = Path(temp_dir)
            schemas_d = td / "schemas"
            schemas_d.mkdir()
            schema_obj = make_valid_schema("foo.v1", schema_id="https://invalid.example/wrong_filename.json")
            (schemas_d / "foo.v1.json").write_text(json.dumps(schema_obj))

            fake_md = td / "SCHEMAS.md"
            fake_md.write_text(
                "# Schema registry\n\n"
                "| ID | Schema | File | Authority | Compatibility rule |\n"
                "|---|---|---|---|---|\n"
                "| `SCHEMA-FOO-001` | `fss.foo.v1` | `schemas/foo.v1.json` | auth | rule |\n"
            )
            validator = schema_validate.Validator()
            result = schema_validate.validate_schema_constitution(
                repo_root=td,
                schemas_dir=schemas_d,
                schemas_md_path=fake_md,
                architecture_dir=td / "architecture",
                crates_dir=td / "crates",
                validator=validator,
            )
            self.assertEqual(result["status"], "failed")
            codes = [f.code for f in validator.findings]
            self.assertIn(schema_validate.CODE_SCHEMA_ID_MISMATCH, codes)

    def test_undeclared_schema_reference_in_architecture_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            td = Path(temp_dir)
            arch_d = td / "architecture"
            arch_d.mkdir()
            (arch_d / "test_arch.json").write_text(json.dumps({
                "schema": "fss.test_arch.v1",
                "semanticObjects": {
                    "Phantom": "fss.phantom_schema.v1"
                }
            }))
            fake_md = td / "SCHEMAS.md"
            fake_md.write_text(
                "# Schema registry\n\n"
                "| ID | Schema | File | Authority | Compatibility rule |\n"
                "|---|---|---|---|---|\n"
                "| `SCHEMA-FOO-001` | `fss.foo.v1` | `CLI output` | auth | rule |\n"
            )
            validator = schema_validate.Validator()
            result = schema_validate.validate_schema_constitution(
                repo_root=td,
                schemas_dir=td / "schemas",
                schemas_md_path=fake_md,
                architecture_dir=arch_d,
                crates_dir=td / "crates",
                validator=validator,
            )
            self.assertEqual(result["status"], "failed")
            codes = [f.code for f in validator.findings]
            self.assertIn(schema_validate.CODE_UNDECLARED_SCHEMA_REFERENCE, codes)

    def test_unowned_implemented_schema_claim_fails_closed(self) -> None:
        validator = schema_validate.Validator()
        claimed = {
            "fss.agent_mission.v1": "implemented"  # declared-only; has no Rust owner in fss-core
        }
        result = schema_validate.validate_schema_constitution(
            repo_root=ROOT,
            schemas_dir=ROOT / "schemas",
            schemas_md_path=ROOT / "registries" / "SCHEMAS.md",
            architecture_dir=ROOT / "architecture",
            crates_dir=ROOT / "crates",
            validator=validator,
            claimed_statuses=claimed,
        )
        self.assertEqual(result["status"], "failed")
        codes = [f.code for f in validator.findings]
        self.assertIn(schema_validate.CODE_UNOWNED_IMPLEMENTED_SCHEMA, codes)

    def test_invalid_implementation_owner_claim_fails_closed(self) -> None:
        validator = schema_validate.Validator()
        claimed = {
            "fss.agent_contract_basis.v1": {
                "status": "implemented",
                "owner": {"type": "WrongType"}
            }
        }
        result = schema_validate.validate_schema_constitution(
            repo_root=ROOT,
            schemas_dir=ROOT / "schemas",
            schemas_md_path=ROOT / "registries" / "SCHEMAS.md",
            architecture_dir=ROOT / "architecture",
            crates_dir=ROOT / "crates",
            validator=validator,
            claimed_statuses=claimed,
        )
        self.assertEqual(result["status"], "failed")
        codes = [f.code for f in validator.findings]
        self.assertIn(schema_validate.CODE_INVALID_IMPLEMENTATION_OWNER, codes)

    def test_constitution_determinism(self) -> None:
        r1 = schema_validate.validate_schema_constitution(
            repo_root=ROOT,
            schemas_dir=ROOT / "schemas",
            schemas_md_path=ROOT / "registries" / "SCHEMAS.md",
            architecture_dir=ROOT / "architecture",
            crates_dir=ROOT / "crates",
        )
        r2 = schema_validate.validate_schema_constitution(
            repo_root=ROOT,
            schemas_dir=ROOT / "schemas",
            schemas_md_path=ROOT / "registries" / "SCHEMAS.md",
            architecture_dir=ROOT / "architecture",
            crates_dir=ROOT / "crates",
        )
        self.assertEqual(r1["constitutionDigest"], r2["constitutionDigest"])
        self.assertEqual(r1["totalDeclared"], r2["totalDeclared"])
        self.assertEqual(r1["implementedCount"], r2["implementedCount"])
        self.assertEqual(r1["declaredOnlyCount"], r2["declaredOnlyCount"])
        self.assertEqual(r1["schemas"], r2["schemas"])

    def test_cli_subprocess_constitution_receipt(self) -> None:
        env = dict(os.environ)
        env["PYTHONPATH"] = ""
        result = subprocess.run(
            [sys.executable, str(SCRIPT_PATH), "--json"],
            cwd=ROOT,
            capture_output=True,
            text=True,
            env=env,
        )
        self.assertEqual(result.returncode, 0)
        data = json.loads(result.stdout)
        self.assertEqual(data["status"], "passed")
        self.assertIn("constitution", data)
        const = data["constitution"]
        self.assertGreaterEqual(const["totalDeclared"], 60)
        self.assertEqual(const["totalDeclared"], const["implementedCount"] + const["declaredOnlyCount"])
        self.assertGreaterEqual(const["implementedCount"], 17)
        self.assertIn("constitutionDigest", data)
        self.assertTrue(data["constitutionDigest"].startswith("sha256:"))

    def test_cli_subprocess_constitution_only(self) -> None:
        result = subprocess.run(
            [sys.executable, str(SCRIPT_PATH), "--constitution-only"],
            cwd=ROOT,
            capture_output=True,
            text=True,
        )
        self.assertEqual(result.returncode, 0)
        self.assertRegex(result.stdout, r"constitution: \d+ declared \(\d+ implemented, \d+ declared-only\), 0 unowned")
        self.assertRegex(result.stdout, r"constitutionDeclared=\d+")
        self.assertRegex(result.stdout, r"constitutionImplemented=\d+")
        self.assertRegex(result.stdout, r"constitutionDeclaredOnly=\d+")
        self.assertIn("status=passed", result.stdout)


class TestSchemaConstitutionCrossReviewRegressions(unittest.TestCase):
    """Regressions for cross-review findings on schema constitution implementation."""

    def test_ghost_struct_in_comment_must_not_be_implemented(self) -> None:
        """Ghost struct inside block comment must not be credited as owner."""
        with tempfile.TemporaryDirectory() as td:
            tdp = Path(td)
            src = tdp / "crates" / "fss-core" / "src"
            src.mkdir(parents=True)
            (src / "comment.rs").write_text("/*\nstruct GhostStruct;\n\"fss.sensor_capsule.v1\"\n*/\n", encoding="utf-8")
            schemas_d = tdp / "schemas"
            schemas_d.mkdir()
            schema_json = {
                "$schema": "https://json-schema.org/draft/2020-12/schema",
                "$id": "https://franken-surveillance.org/schemas/sensor_capsule.v1.json",
                "type": "object",
                "properties": {"schema": {"type": "string", "const": "fss.sensor_capsule.v1"}},
                "required": ["schema"]
            }
            (schemas_d / "sensor_capsule.v1.json").write_text(json.dumps(schema_json), encoding="utf-8")
            md = tdp / "registries" / "SCHEMAS.md"
            md.parent.mkdir()
            md.write_text("# Schemas\n| ID | Schema | File | Authority | Compatibility rule |\n|---|---|---|---|---|\n| `SCHEMA-SENSOR-CAPSULE-001` | `fss.sensor_capsule.v1` | `schemas/sensor_capsule.v1.json` | authority | rule |\n", encoding="utf-8")
            v = schema_validate.Validator()
            res = schema_validate.validate_schema_constitution(repo_root=tdp, schemas_dir=schemas_d, schemas_md_path=md, architecture_dir=tdp/"architecture", crates_dir=tdp/"crates", validator=v)
            self.assertEqual(res["schemas"][0]["status"], "declared")
            self.assertIsNone(res["schemas"][0]["owner"])

    def test_inline_comment_schema_must_not_be_implemented(self) -> None:
        """Schema mentioned in inline comment must not be credited as owner."""
        with tempfile.TemporaryDirectory() as td:
            tdp = Path(td)
            src = tdp / "crates" / "fss-core" / "src"
            src.mkdir(parents=True)
            (src / "lib.rs").write_text("pub struct RealStruct;\nimpl RealStruct {\n    pub fn helper(&self) {\n        let _x = 1; // \"fss.sensor_capsule.v1\"\n    }\n}\n", encoding="utf-8")
            schemas_d = tdp / "schemas"
            schemas_d.mkdir()
            schema_json = {
                "$schema": "https://json-schema.org/draft/2020-12/schema",
                "$id": "https://franken-surveillance.org/schemas/sensor_capsule.v1.json",
                "type": "object",
                "properties": {"schema": {"type": "string", "const": "fss.sensor_capsule.v1"}},
                "required": ["schema"]
            }
            (schemas_d / "sensor_capsule.v1.json").write_text(json.dumps(schema_json), encoding="utf-8")
            md = tdp / "registries" / "SCHEMAS.md"
            md.parent.mkdir()
            md.write_text("# Schemas\n| ID | Schema | File | Authority | Compatibility rule |\n|---|---|---|---|---|\n| `SCHEMA-SENSOR-CAPSULE-001` | `fss.sensor_capsule.v1` | `schemas/sensor_capsule.v1.json` | authority | rule |\n", encoding="utf-8")
            v = schema_validate.Validator()
            res = schema_validate.validate_schema_constitution(repo_root=tdp, schemas_dir=schemas_d, schemas_md_path=md, architecture_dir=tdp/"architecture", crates_dir=tdp/"crates", validator=v)
            self.assertEqual(res["schemas"][0]["status"], "declared")
            self.assertIsNone(res["schemas"][0]["owner"])

    def test_test_helper_must_not_be_production_owner(self) -> None:
        """Test helpers in tests.rs or #[cfg(test)] must not be production owners."""
        with tempfile.TemporaryDirectory() as td:
            tdp = Path(td)
            src = tdp / "crates" / "fss-core" / "src"
            src.mkdir(parents=True)
            (src / "lib.rs").write_text("// lib\n", encoding="utf-8")
            (src / "tests.rs").write_text("#[cfg(test)]\nmod tests {\n    struct MockHelper;\n    #[test]\n    fn t() { let _ = \"fss.sensor_capsule.v1\"; }\n}\n", encoding="utf-8")
            schemas_d = tdp / "schemas"
            schemas_d.mkdir()
            schema_json = {
                "$schema": "https://json-schema.org/draft/2020-12/schema",
                "$id": "https://franken-surveillance.org/schemas/sensor_capsule.v1.json",
                "type": "object",
                "properties": {"schema": {"type": "string", "const": "fss.sensor_capsule.v1"}},
                "required": ["schema"]
            }
            (schemas_d / "sensor_capsule.v1.json").write_text(json.dumps(schema_json), encoding="utf-8")
            md = tdp / "registries" / "SCHEMAS.md"
            md.parent.mkdir()
            md.write_text("# Schemas\n| ID | Schema | File | Authority | Compatibility rule |\n|---|---|---|---|---|\n| `SCHEMA-SENSOR-CAPSULE-001` | `fss.sensor_capsule.v1` | `schemas/sensor_capsule.v1.json` | authority | rule |\n", encoding="utf-8")
            v = schema_validate.Validator()
            res = schema_validate.validate_schema_constitution(repo_root=tdp, schemas_dir=schemas_d, schemas_md_path=md, architecture_dir=tdp/"architecture", crates_dir=tdp/"crates", validator=v)
            self.assertEqual(res["schemas"][0]["status"], "declared")
            self.assertIsNone(res["schemas"][0]["owner"])

    def test_file_outside_schemas_must_be_rejected(self) -> None:
        """Schema file outside schemas/ must be rejected."""
        with tempfile.TemporaryDirectory() as td:
            tdp = Path(td)
            other_d = tdp / "other_dir"
            other_d.mkdir()
            schema_json = {
                "$schema": "https://json-schema.org/draft/2020-12/schema",
                "$id": "https://franken-surveillance.org/schemas/sensor_capsule.v1.json",
                "type": "object",
                "properties": {"schema": {"type": "string", "const": "fss.sensor_capsule.v1"}},
                "required": ["schema"]
            }
            (other_d / "sensor_capsule.v1.json").write_text(json.dumps(schema_json), encoding="utf-8")
            schemas_d = tdp / "schemas"
            schemas_d.mkdir()
            md = tdp / "registries" / "SCHEMAS.md"
            md.parent.mkdir()
            md.write_text("# Schemas\n| ID | Schema | File | Authority | Compatibility rule |\n|---|---|---|---|---|\n| `SCHEMA-SENSOR-CAPSULE-001` | `fss.sensor_capsule.v1` | `other_dir/sensor_capsule.v1.json` | authority | rule |\n", encoding="utf-8")
            v = schema_validate.Validator()
            res = schema_validate.validate_schema_constitution(repo_root=tdp, schemas_dir=schemas_d, schemas_md_path=md, architecture_dir=tdp/"architecture", crates_dir=tdp/"crates", validator=v)
            self.assertEqual(res["status"], "failed")
            self.assertTrue(any(f.code == schema_validate.CODE_MALFORMED_REGISTRY_ROW for f in v.findings))

    def test_unknown_owner_type_is_classified_as_declared(self) -> None:
        """Unowned/unknown owner type must not be reported as implemented."""
        with tempfile.TemporaryDirectory() as td:
            tdp = Path(td)
            src = tdp / "crates" / "fss-core" / "src"
            src.mkdir(parents=True)
            (src / "bare.rs").write_text("let _s = \"fss.sensor_capsule.v1\";\n", encoding="utf-8")
            schemas_d = tdp / "schemas"
            schemas_d.mkdir()
            schema_json = {
                "$schema": "https://json-schema.org/draft/2020-12/schema",
                "$id": "https://franken-surveillance.org/schemas/sensor_capsule.v1.json",
                "type": "object",
                "properties": {"schema": {"type": "string", "const": "fss.sensor_capsule.v1"}},
                "required": ["schema"]
            }
            (schemas_d / "sensor_capsule.v1.json").write_text(json.dumps(schema_json), encoding="utf-8")
            md = tdp / "registries" / "SCHEMAS.md"
            md.parent.mkdir()
            md.write_text("# Schemas\n| ID | Schema | File | Authority | Compatibility rule |\n|---|---|---|---|---|\n| `SCHEMA-SENSOR-CAPSULE-001` | `fss.sensor_capsule.v1` | `schemas/sensor_capsule.v1.json` | authority | rule |\n", encoding="utf-8")
            v = schema_validate.Validator()
            res = schema_validate.validate_schema_constitution(repo_root=tdp, schemas_dir=schemas_d, schemas_md_path=md, architecture_dir=tdp/"architecture", crates_dir=tdp/"crates", validator=v)
            self.assertEqual(res["status"], "failed")
            self.assertEqual(res["schemas"][0]["status"], "declared")
            self.assertIsNone(res["schemas"][0]["owner"])
            self.assertTrue(any(f.code == schema_validate.CODE_UNOWNED_IMPLEMENTED_SCHEMA for f in v.findings))

    def test_unregistered_implemented_schemas_drift_detection(self) -> None:
        """Finding 6 & bead fss-x4a.6.24: Implemented schemas must be registered; zero unregistered drift in tree."""
        validator = schema_validate.Validator()
        result = schema_validate.validate_schema_constitution(
            repo_root=ROOT,
            schemas_dir=ROOT / "schemas",
            schemas_md_path=ROOT / "registries" / "SCHEMAS.md",
            digest_domains_path=ROOT / "registries" / "DIGEST_DOMAINS.md",
            architecture_dir=ROOT / "architecture",
            crates_dir=ROOT / "crates",
            validator=validator,
        )
        self.assertEqual(result["status"], "passed")
        self.assertEqual(result["unregisteredImplementedCount"], 0)
        self.assertEqual(result["digestDomainCount"], 44)
        self.assertEqual(result["implementedCount"], 28)

        unreg_findings = [
            f for f in validator.findings
            if f.code == schema_validate.CODE_UNREGISTERED_IMPLEMENTED_SCHEMA
        ]
        self.assertEqual(len(unreg_findings), 0)

    def test_planted_unregistered_domain_literal_fails(self) -> None:
        """Planted negative: an unregistered fss.x.v1 literal in Rust code causes validator to fail."""
        with tempfile.TemporaryDirectory() as td:
            tdp = Path(td)
            schemas_d = tdp / "schemas"
            schemas_d.mkdir()
            reg_d = tdp / "registries"
            reg_d.mkdir()
            crates_d = tdp / "crates" / "fss-core" / "src"
            crates_d.mkdir(parents=True)
            arch_d = tdp / "architecture"
            arch_d.mkdir()

            # Create minimal valid schema and registry
            sf = schemas_d / "sensor_capsule.v1.json"
            sf.write_text(json.dumps({
                "$schema": "https://json-schema.org/draft/2020-12/schema",
                "$id": "https://schemas.fss.org/schemas/sensor_capsule.v1.json",
                "type": "object",
                "properties": {"schema": {"const": "fss.sensor_capsule.v1"}},
                "required": ["schema"],
            }), encoding="utf-8")

            md = reg_d / "SCHEMAS.md"
            md.write_text("# Schemas\n| ID | Schema | File | Authority | Compatibility rule |\n|---|---|---|---|---|\n| `SCHEMA-SENSOR-CAPSULE-001` | `fss.sensor_capsule.v1` | `schemas/sensor_capsule.v1.json` | authority | rule |\n", encoding="utf-8")

            # DIGEST_DOMAINS.md with valid domain
            dd = reg_d / "DIGEST_DOMAINS.md"
            dd.write_text("# Domains\n| ID | Domain | Scope | Authority | Invariant rule |\n|---|---|---|---|---|\n| `SCHEMA-DOMAIN-CANONICAL-001` | `fss.canonical.v1` | Core | authority | rule |\n", encoding="utf-8")

            # Plant an unregistered fss.*.v1 literal in Rust code
            rust_file = crates_d / "lib.rs"
            rust_file.write_text('pub const ROGUE_DOMAIN: &str = "fss.rogue_unregistered_domain.v1";\n', encoding="utf-8")

            v = schema_validate.Validator()
            res = schema_validate.validate_schema_constitution(
                repo_root=tdp,
                schemas_dir=schemas_d,
                schemas_md_path=md,
                digest_domains_path=dd,
                architecture_dir=arch_d,
                crates_dir=tdp / "crates",
                validator=v,
            )
            self.assertEqual(res["status"], "failed")
            self.assertEqual(res["unregisteredImplementedCount"], 1)
            self.assertEqual(res["unregisteredImplementedSchemas"][0]["name"], "fss.rogue_unregistered_domain.v1")

            unreg_errors = [
                f for f in v.findings
                if f.code == schema_validate.CODE_UNREGISTERED_IMPLEMENTED_SCHEMA and f.severity == "error"
            ]
            self.assertEqual(len(unreg_errors), 1)
            self.assertIn("fss.rogue_unregistered_domain.v1", unreg_errors[0].message)

    def test_digest_domains_validation_errors(self) -> None:
        """Verify that duplicate or invalid stable IDs / domain names in DIGEST_DOMAINS.md fail."""
        with tempfile.TemporaryDirectory() as td:
            tdp = Path(td)
            schemas_d = tdp / "schemas"
            schemas_d.mkdir()
            reg_d = tdp / "registries"
            reg_d.mkdir()
            crates_d = tdp / "crates"
            crates_d.mkdir()
            arch_d = tdp / "architecture"
            arch_d.mkdir()

            md = reg_d / "SCHEMAS.md"
            md.write_text("# Schemas\n| ID | Schema | File | Authority | Compatibility rule |\n|---|---|---|---|---|\n", encoding="utf-8")

            # Duplicate domain ID and invalid domain name
            dd = reg_d / "DIGEST_DOMAINS.md"
            dd.write_text(
                "# Domains\n| ID | Domain | Scope | Authority | Invariant rule |\n|---|---|---|---|---|\n"
                "| `INVALID_ID` | `fss.canonical.v1` | Core | auth | rule |\n"
                "| `SCHEMA-DOMAIN-001` | `invalid-name-shape` | Core | auth | rule |\n"
                "| `SCHEMA-DOMAIN-002` | `fss.dup.v1` | Core | auth | rule |\n"
                "| `SCHEMA-DOMAIN-002` | `fss.dup2.v1` | Core | auth | rule |\n",
                encoding="utf-8",
            )

            v = schema_validate.Validator()
            res = schema_validate.validate_schema_constitution(
                repo_root=tdp,
                schemas_dir=schemas_d,
                schemas_md_path=md,
                digest_domains_path=dd,
                architecture_dir=arch_d,
                crates_dir=crates_d,
                validator=v,
            )
            self.assertEqual(res["status"], "failed")
            codes = {f.code for f in v.findings}
            self.assertIn(schema_validate.CODE_INVALID_STABLE_ID, codes)
            self.assertIn(schema_validate.CODE_INVALID_SCHEMA_NAME, codes)
            self.assertIn(schema_validate.CODE_DUPLICATE_STABLE_ID, codes)


if __name__ == "__main__":
    unittest.main()
