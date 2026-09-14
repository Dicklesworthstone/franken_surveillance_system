#!/usr/bin/env python3
r"""Strict JSON Schema Draft 2020-12 instance validator (stdlib only).

Validates JSON instances against repository JSON schemas adhering to the
CAP- EXEC model execution receipt specification (fss-2h5zq.47):
- Supported validation keywords: type (including type arrays), const, enum,
  required, properties, additionalProperties (bool or schema), pattern,
  minLength, maxLength, minimum, minItems, maxItems, items, anyOf, $ref.
- Supported container/annotation keywords: $schema, $id, title, description,
  $comment, $defs.
- Refuses any unknown keyword in statically reachable subschemas.
- Strict type semantics: bool is not integer or number; const/enum compare type-strictly.
- ECMA-style end anchoring (\Z) for pattern keywords.
- Strict JSON parsing: rejects NaN, Infinity, -Infinity, and duplicate keys.
- Resolves $ref across schemas/ using SchemaCatalog from schema_validate.
"""
from __future__ import annotations

import argparse
import json
import math
import os
import re
import sys
from pathlib import Path
from typing import Any

# Ensure scripts/ is on sys.path to import SchemaCatalog from schema_validate
_SCRIPTS_DIR = Path(__file__).resolve().parent
if str(_SCRIPTS_DIR) not in sys.path:
    sys.path.insert(0, str(_SCRIPTS_DIR))

try:
    from schema_validate import SchemaCatalog, Validator as CatalogValidator
except ImportError:
    SchemaCatalog = None  # type: ignore
    CatalogValidator = None  # type: ignore

SUPPORTED_ANNOTATION_KEYWORDS = frozenset({
    "$schema",
    "$id",
    "title",
    "description",
    "$comment",
    "$defs",
})

SUPPORTED_VALIDATION_KEYWORDS = frozenset({
    "type",
    "const",
    "enum",
    "required",
    "properties",
    "additionalProperties",
    "pattern",
    "minLength",
    "maxLength",
    "minimum",
    "minItems",
    "maxItems",
    "items",
    "anyOf",
    "$ref",
})

ALL_SUPPORTED_KEYWORDS = SUPPORTED_ANNOTATION_KEYWORDS | SUPPORTED_VALIDATION_KEYWORDS


class JsonInstanceValidationError(Exception):
    """Raised when instance validation fails."""

    def __init__(self, path: str, message: str, keyword: str = ""):
        super().__init__(f"at '{path}': {message}")
        self.path = path
        self.message = message
        self.keyword = keyword


class SchemaSyntaxError(Exception):
    """Raised when an unsupported or unknown keyword is found in a reachable schema."""

    def __init__(self, schema_path: str, keyword: str, message: str):
        super().__init__(f"at '{schema_path}': unsupported keyword '{keyword}': {message}")
        self.schema_path = schema_path
        self.keyword = keyword
        self.message = message


def parse_strict_json(text: str) -> Any:
    """Parses JSON text rejecting NaN/Infinity and duplicate keys."""

    def reject_constant(val: str) -> None:
        raise JsonInstanceValidationError(
            "#", f"disallowed JSON constant: {val}"
        )

    def reject_duplicates(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
        obj: dict[str, Any] = {}
        for k, v in pairs:
            if k in obj:
                raise JsonInstanceValidationError(
                    "#", f"duplicate JSON key '{k}'"
                )
            obj[k] = v
        return obj

    try:
        return json.loads(
            text,
            parse_constant=reject_constant,
            object_pairs_hook=reject_duplicates,
        )
    except json.JSONDecodeError as exc:
        raise JsonInstanceValidationError("#", f"malformed JSON: {exc}")


def check_type_strict(val: Any, expected: str) -> bool:
    """Type-strict check where bool is neither integer nor number."""
    if expected == "null":
        return val is None
    if expected == "boolean":
        return isinstance(val, bool)
    if expected == "integer":
        return isinstance(val, int) and not isinstance(val, bool)
    if expected == "number":
        return isinstance(val, (int, float)) and not isinstance(val, bool) and math.isfinite(val)
    if expected == "string":
        return isinstance(val, str)
    if expected == "array":
        return isinstance(val, list)
    if expected == "object":
        return isinstance(val, dict)
    raise SchemaSyntaxError("#", "type", f"unrecognized schema type '{expected}'")


class InstanceValidator:
    """Validates JSON instances against Draft 2020-12 subschemas."""

    def __init__(self, schemas_dir: Path | None = None):
        if schemas_dir is None:
            schemas_dir = _SCRIPTS_DIR.parent / "schemas"
        self.schemas_dir = schemas_dir.resolve()
        self.catalog = None
        if CatalogValidator is not None and self.schemas_dir.is_dir():
            cat_val = CatalogValidator()
            self.catalog = cat_val.load_catalog(self.schemas_dir)
        self._compiled_patterns: dict[str, re.Pattern[str]] = {}
        self._verified_subschemas: set[int] = set()

    def _resolve_ref(
        self, ref: str, current_doc: dict[str, Any], origin_rel: str
    ) -> tuple[dict[str, Any], str]:
        """Resolves a $ref pointer to a target schema dictionary."""
        file_part, sep, fragment = ref.partition("#")
        target_doc = current_doc
        target_rel = origin_rel

        if file_part:
            if file_part.startswith(("http://", "https://")):
                if self.catalog and file_part in self.catalog.schemas_by_id:
                    target_rel = self.catalog.schemas_by_id[file_part]
                    target_doc = self.catalog.schemas_by_relative[target_rel]
                else:
                    raise SchemaSyntaxError(
                        origin_rel, "$ref", f"cannot resolve remote URI: {file_part}"
                    )
            else:
                target_path = (self.schemas_dir / file_part).resolve()
                if not target_path.is_relative_to(self.schemas_dir):
                    raise SchemaSyntaxError(
                        origin_rel, "$ref", f"path traversal outside schemas/: {file_part}"
                    )
                target_rel = file_part
                if self.catalog and file_part in self.catalog.schemas_by_relative:
                    target_doc = self.catalog.schemas_by_relative[file_part]
                elif target_path.is_file():
                    target_doc = parse_strict_json(target_path.read_text(encoding="utf-8"))
                else:
                    raise SchemaSyntaxError(
                        origin_rel, "$ref", f"referenced file not found: {file_part}"
                    )

        if not sep or not fragment:
            return target_doc, target_rel

        # Resolve fragment pointer e.g. /$defs/digest
        tokens = fragment.lstrip("/").split("/")
        current = target_doc
        for token in tokens:
            unescaped = token.replace("~1", "/").replace("~0", "~")
            if not isinstance(current, dict) or unescaped not in current:
                raise SchemaSyntaxError(
                    target_rel,
                    "$ref",
                    f"fragment '{fragment}' could not be resolved in schema '{target_rel}'",
                )
            current = current[unescaped]

        if not isinstance(current, dict):
            raise SchemaSyntaxError(
                target_rel, "$ref", f"resolved pointer '{ref}' did not yield a schema object"
            )

        return current, target_rel

    def _check_reachable_keywords(self, schema: dict[str, Any], schema_loc: str) -> None:
        """Verifies that only supported keywords exist in reachable subschema."""
        sid = id(schema)
        if sid in self._verified_subschemas:
            return
        self._verified_subschemas.add(sid)

        for kw in schema:
            if kw not in ALL_SUPPORTED_KEYWORDS:
                raise SchemaSyntaxError(
                    schema_loc,
                    kw,
                    f"keyword '{kw}' is not in the supported Draft 2020-12 subset",
                )

    def check_reachable_schema_keywords(
        self,
        schema: Any,
        current_doc: dict[str, Any],
        origin_rel: str,
        schema_loc: str,
        visited: set[int] | None = None,
    ) -> None:
        """Statically traverses reachable subschemas from root to refuse unsupported keywords."""
        if not isinstance(schema, dict):
            return
        if visited is None:
            visited = set()
        sid = id(schema)
        if sid in visited:
            return
        visited.add(sid)

        self._check_reachable_keywords(schema, schema_loc)

        if "$ref" in schema:
            ref = schema["$ref"]
            resolved, new_origin = self._resolve_ref(ref, current_doc, origin_rel)
            self.check_reachable_schema_keywords(
                resolved, resolved, new_origin, f"{new_origin}#{ref}", visited
            )

        if "properties" in schema and isinstance(schema["properties"], dict):
            for k, prop_schema in schema["properties"].items():
                self.check_reachable_schema_keywords(
                    prop_schema, current_doc, origin_rel, f"{schema_loc}/properties/{k}", visited
                )

        if "additionalProperties" in schema and isinstance(schema["additionalProperties"], dict):
            self.check_reachable_schema_keywords(
                schema["additionalProperties"],
                current_doc,
                origin_rel,
                f"{schema_loc}/additionalProperties",
                visited,
            )

        if "items" in schema and isinstance(schema["items"], dict):
            self.check_reachable_schema_keywords(
                schema["items"], current_doc, origin_rel, f"{schema_loc}/items", visited
            )

        if "anyOf" in schema and isinstance(schema["anyOf"], list):
            for idx, alt in enumerate(schema["anyOf"]):
                self.check_reachable_schema_keywords(
                    alt, current_doc, origin_rel, f"{schema_loc}/anyOf/{idx}", visited
                )

    def validate_node(
        self,
        schema: dict[str, Any],
        instance: Any,
        data_path: str,
        current_doc: dict[str, Any],
        origin_rel: str,
        schema_loc: str,
    ) -> None:
        """Validates instance node against schema node."""
        if not isinstance(schema, dict):
            return

        self._check_reachable_keywords(schema, schema_loc)

        # 1. Resolve $ref if present
        if "$ref" in schema:
            ref = schema["$ref"]
            resolved_schema, new_origin = self._resolve_ref(ref, current_doc, origin_rel)
            self.validate_node(
                resolved_schema,
                instance,
                data_path,
                resolved_schema,
                new_origin,
                f"{new_origin}#{ref}",
            )
            # Draft 2020-12 allows adjacent keywords next to $ref; continue validating schema

        # 2. type
        if "type" in schema:
            expected_type = schema["type"]
            if isinstance(expected_type, list):
                if not any(check_type_strict(instance, t) for t in expected_type):
                    raise JsonInstanceValidationError(
                        data_path,
                        f"expected type one of {expected_type}, got {type(instance).__name__}",
                        "type",
                    )
            elif isinstance(expected_type, str):
                if not check_type_strict(instance, expected_type):
                    raise JsonInstanceValidationError(
                        data_path,
                        f"expected type '{expected_type}', got {type(instance).__name__}",
                        "type",
                    )

        # 3. const (type-strict)
        if "const" in schema:
            expected_const = schema["const"]
            if type(instance) is not type(expected_const) or instance != expected_const:
                raise JsonInstanceValidationError(
                    data_path,
                    f"const mismatch: expected {expected_const!r}, got {instance!r}",
                    "const",
                )

        # 4. enum (type-strict)
        if "enum" in schema:
            allowed_enum = schema["enum"]
            if not any(type(instance) is type(e) and instance == e for e in allowed_enum):
                raise JsonInstanceValidationError(
                    data_path,
                    f"value {instance!r} not in enum {allowed_enum!r}",
                    "enum",
                )

        # 5. String-specific keywords: pattern, minLength, maxLength
        if isinstance(instance, str):
            if "minLength" in schema:
                ml = schema["minLength"]
                if len(instance) < ml:
                    raise JsonInstanceValidationError(
                        data_path,
                        f"string length {len(instance)} is less than minLength {ml}",
                        "minLength",
                    )
            if "maxLength" in schema:
                ml = schema["maxLength"]
                if len(instance) > ml:
                    raise JsonInstanceValidationError(
                        data_path,
                        f"string length {len(instance)} is greater than maxLength {ml}",
                        "maxLength",
                    )
            if "pattern" in schema:
                pat_str = schema["pattern"]
                if pat_str not in self._compiled_patterns:
                    # End-anchor with \Z if it ends with $ to prevent trailing newline acceptance
                    effective_pat = pat_str
                    if effective_pat.endswith("$") and not effective_pat.endswith(r"\$"):
                        effective_pat = effective_pat[:-1] + r"\Z"
                    try:
                        self._compiled_patterns[pat_str] = re.compile(effective_pat)
                    except re.error as exc:
                        raise SchemaSyntaxError(
                            schema_loc, "pattern", f"invalid regex '{pat_str}': {exc}"
                        )
                regex = self._compiled_patterns[pat_str]
                if not regex.search(instance):
                    raise JsonInstanceValidationError(
                        data_path,
                        f"string '{instance}' does not match pattern '{pat_str}'",
                        "pattern",
                    )

        # 6. Number/Integer-specific keywords: minimum
        if isinstance(instance, (int, float)) and not isinstance(instance, bool):
            if "minimum" in schema:
                min_val = schema["minimum"]
                if instance < min_val:
                    raise JsonInstanceValidationError(
                        data_path,
                        f"numeric value {instance} is less than minimum {min_val}",
                        "minimum",
                    )

        # 7. Array-specific keywords: minItems, maxItems, items
        if isinstance(instance, list):
            if "minItems" in schema:
                mi = schema["minItems"]
                if len(instance) < mi:
                    raise JsonInstanceValidationError(
                        data_path,
                        f"array length {len(instance)} is less than minItems {mi}",
                        "minItems",
                    )
            if "maxItems" in schema:
                mi = schema["maxItems"]
                if len(instance) > mi:
                    raise JsonInstanceValidationError(
                        data_path,
                        f"array length {len(instance)} is greater than maxItems {mi}",
                        "maxItems",
                    )
            if "items" in schema:
                item_schema = schema["items"]
                for i, item in enumerate(instance):
                    item_path = f"{data_path}[{i}]"
                    self.validate_node(
                        item_schema,
                        item,
                        item_path,
                        current_doc,
                        origin_rel,
                        f"{schema_loc}/items",
                    )

        # 8. Object-specific keywords: required, properties, additionalProperties
        if isinstance(instance, dict):
            if "required" in schema:
                req_props = schema["required"]
                for prop_name in req_props:
                    if prop_name not in instance:
                        raise JsonInstanceValidationError(
                            data_path,
                            f"missing required property '{prop_name}'",
                            "required",
                        )

            properties_schema = schema.get("properties", {})
            additional_props = schema.get("additionalProperties", True)

            for key, val in instance.items():
                prop_path = f"{data_path}.{key}" if data_path != "#" else f"#/{key}"
                if key in properties_schema:
                    prop_subschema = properties_schema[key]
                    self.validate_node(
                        prop_subschema,
                        val,
                        prop_path,
                        current_doc,
                        origin_rel,
                        f"{schema_loc}/properties/{key}",
                    )
                else:
                    if additional_props is False:
                        raise JsonInstanceValidationError(
                            data_path,
                            f"additional property '{key}' not permitted by schema",
                            "additionalProperties",
                        )
                    if isinstance(additional_props, dict):
                        self.validate_node(
                            additional_props,
                            val,
                            prop_path,
                            current_doc,
                            origin_rel,
                            f"{schema_loc}/additionalProperties",
                        )

        # 9. anyOf
        if "anyOf" in schema:
            alternatives = schema["anyOf"]
            passed = False
            last_err = None
            for idx, alt in enumerate(alternatives):
                try:
                    self.validate_node(
                        alt,
                        instance,
                        data_path,
                        current_doc,
                        origin_rel,
                        f"{schema_loc}/anyOf/{idx}",
                    )
                    passed = True
                    break
                except JsonInstanceValidationError as exc:
                    last_err = exc
            if not passed:
                raise JsonInstanceValidationError(
                    data_path,
                    f"value failed all anyOf branches (last branch error: {last_err})",
                    "anyOf",
                )

    def validate(self, schema_doc: dict[str, Any], instance: Any, schema_name: str = "root") -> None:
        """Validates instance against root schema document."""
        self.check_reachable_schema_keywords(schema_doc, schema_doc, schema_name, schema_name)
        self.validate_node(
            schema=schema_doc,
            instance=instance,
            data_path="#",
            current_doc=schema_doc,
            origin_rel=schema_name,
            schema_loc=schema_name,
        )


def validate_instance_file(schema_path: Path, instance_path: Path) -> None:
    """Validates instance file against schema file on disk."""
    schema_text = schema_path.read_text(encoding="utf-8")
    instance_text = instance_path.read_text(encoding="utf-8")
    schema_doc = parse_strict_json(schema_text)
    instance = parse_strict_json(instance_text)

    validator = InstanceValidator(schema_path.parent)
    validator.validate(schema_doc, instance, schema_path.name)


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Strict JSON Schema Draft 2020-12 instance validator (stdlib only)"
    )
    parser.add_argument("schema", type=Path, help="Path to JSON schema file")
    parser.add_argument("instance", type=Path, help="Path to JSON instance file")
    args = parser.parse_args()

    if not args.schema.is_file():
        print(f"Error: schema file not found: {args.schema}", file=sys.stderr)
        return 2
    if not args.instance.is_file():
        print(f"Error: instance file not found: {args.instance}", file=sys.stderr)
        return 2

    try:
        validate_instance_file(args.schema, args.instance)
        print(f"OK: instance '{args.instance}' validates against schema '{args.schema}'")
        return 0
    except (JsonInstanceValidationError, SchemaSyntaxError) as exc:
        print(f"VALIDATION_FAILURE: {exc}", file=sys.stderr)
        return 1
    except Exception as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 3


if __name__ == "__main__":
    sys.exit(main())
