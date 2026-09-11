#!/usr/bin/env python3
"""Offline Draft 2020-12 JSON Schema meta-schema and local reference validator.

Part of FSS architecture qualification (fss-x4a.6.19).
Zero external/third-party dependencies: strictly Python standard library.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import platform
import re
import resource
import sys
import time
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
DEFAULT_SCHEMAS_DIR = ROOT / "schemas"

DRAFT_2020_12_DIALECT = "https://json-schema.org/draft/2020-12/schema"
DRAFT_2020_12_CORE_VOCAB = "https://json-schema.org/draft/2020-12/vocab/core"
DRAFT_2020_12_APPLICATOR_VOCAB = "https://json-schema.org/draft/2020-12/vocab/applicator"
DRAFT_2020_12_UNEVALUATED_VOCAB = "https://json-schema.org/draft/2020-12/vocab/unevaluated"
DRAFT_2020_12_VALIDATION_VOCAB = "https://json-schema.org/draft/2020-12/vocab/validation"
DRAFT_2020_12_METADATA_VOCAB = "https://json-schema.org/draft/2020-12/vocab/meta-data"
DRAFT_2020_12_FORMAT_VOCAB = "https://json-schema.org/draft/2020-12/vocab/format-annotation"
DRAFT_2020_12_CONTENT_VOCAB = "https://json-schema.org/draft/2020-12/vocab/content"

SUPPORTED_VOCABULARIES = {
    DRAFT_2020_12_CORE_VOCAB: True,
    DRAFT_2020_12_APPLICATOR_VOCAB: True,
    DRAFT_2020_12_UNEVALUATED_VOCAB: True,
    DRAFT_2020_12_VALIDATION_VOCAB: True,
    DRAFT_2020_12_METADATA_VOCAB: True,
    DRAFT_2020_12_FORMAT_VOCAB: True,
    DRAFT_2020_12_CONTENT_VOCAB: True,
}

ANCHOR_PATTERN = re.compile(r"^[A-Za-z_][-A-Za-z0-9._]*$")
VALID_SIMPLE_TYPES = frozenset({"null", "boolean", "object", "array", "number", "string", "integer"})

DEFAULT_MAX_DEPTH = 64
DEFAULT_MAX_ERRORS = 100
DEFAULT_MAX_FILE_BYTES = 10 * 1024 * 1024  # 10 MB
DEFAULT_BUDGET_WALL_NS = 30_000_000_000     # 30 seconds
DEFAULT_BUDGET_PEAK_BYTES = 256 * 1024 * 1024  # 256 MB
DEFAULT_BUDGET_WORK_UNITS = 1000

# Diagnostic Codes
CODE_INVALID_DIALECT = "invalid_dialect"
CODE_UNSUPPORTED_VOCABULARY = "unsupported_vocabulary"
CODE_INVALID_KEYWORD_SHAPE = "invalid_keyword_shape"
CODE_INVALID_SCHEMA_TYPE = "invalid_schema_type"
CODE_INVALID_REGEX = "invalid_regex"
CODE_INVALID_URI_REFERENCE = "invalid_uri_reference"
CODE_PATH_TRAVERSAL = "path_traversal"
CODE_SYMLINK_ESCAPE = "symlink_escape"
CODE_NETWORK_FETCH_FORBIDDEN = "network_fetch_forbidden"
CODE_UNRESOLVED_REFERENCE = "unresolved_reference"
CODE_UNRESOLVED_POINTER = "unresolved_pointer"
CODE_UNRESOLVED_ANCHOR = "unresolved_anchor"
CODE_DUPLICATE_CANONICAL_ID = "duplicate_canonical_id"
CODE_DUPLICATE_ANCHOR = "duplicate_anchor"
CODE_RECURSION_LIMIT_EXCEEDED = "recursion_limit_exceeded"
CODE_RESOURCE_LIMIT_EXCEEDED = "resource_limit_exceeded"
CODE_INCOMPLETE_CATALOG = "incomplete_catalog"
CODE_VALIDATOR_UNAVAILABLE = "validator_unavailable"
CODE_MALFORMED_JSON = "malformed_json"
CODE_UNGUARDED_CYCLE = "unguarded_cycle"
CODE_CASE_FOLD_COLLISION = "case_fold_collision"


class SchemaValidationError(Exception):
    """Base exception for schema validation errors."""
    pass


class ValidatorUnavailableError(SchemaValidationError):
    pass


@dataclass(frozen=True)
class Finding:
    code: str
    schema_path: str
    json_path: str
    message: str
    severity: str = "error"

    def to_dict(self) -> dict[str, str]:
        return asdict(self)


class SchemaCatalog:
    def __init__(self, root_dir: Path):
        self.root_dir = root_dir.resolve()
        self.schemas_by_relative: dict[str, Any] = {}
        self.schemas_by_id: dict[str, str] = {}  # canonical $id -> relative path
        self.anchors_by_relative: dict[str, dict[str, Any]] = {}  # relative -> {anchor: subschema}
        self.file_digests: dict[str, str] = {}
        self.raw_bytes_by_relative: dict[str, bytes] = {}


def canonical_json_bytes(obj: Any) -> bytes:
    return json.dumps(obj, sort_keys=True, separators=(",", ":")).encode("utf-8")


def compute_meta_schema_digest() -> str:
    """Deterministic hash of Draft 2020-12 normative meta-schema definition."""
    descriptor = {
        "$id": DRAFT_2020_12_DIALECT,
        "$vocabulary": SUPPORTED_VOCABULARIES,
        "valid_types": sorted(VALID_SIMPLE_TYPES),
        "anchor_pattern": ANCHOR_PATTERN.pattern,
    }
    return "sha256:" + hashlib.sha256(canonical_json_bytes(descriptor)).hexdigest()


def compute_environment_identity() -> str:
    parts = [
        platform.node(),
        platform.platform(),
        platform.machine(),
        sys.version.split()[0],
        os.environ.get("FSS_DSR_HOST_ID", ""),
    ]
    return "sha256:" + hashlib.sha256("|".join(parts).encode("utf-8")).hexdigest()


class Validator:
    def __init__(
        self,
        max_depth: int = DEFAULT_MAX_DEPTH,
        max_errors: int = DEFAULT_MAX_ERRORS,
        max_file_bytes: int = DEFAULT_MAX_FILE_BYTES,
        require_object_root: bool = True,
    ):
        self.max_depth = max_depth
        self.max_errors = max_errors
        self.max_file_bytes = max_file_bytes
        self.require_object_root = require_object_root
        self.findings: list[Finding] = []
        self.truncated = False
        self.reference_count = 0
        self.bytes_read = 0

    def emit(self, code: str, schema_path: str, json_path: str, message: str, severity: str = "error") -> None:
        if len(self.findings) >= self.max_errors:
            self.truncated = True
            return
        self.findings.append(Finding(code, schema_path, json_path, message, severity))

    def load_catalog(self, schemas_dir: Path, target_file: Path | None = None) -> SchemaCatalog:
        catalog = SchemaCatalog(schemas_dir)
        if not schemas_dir.is_dir():
            self.emit(
                CODE_INCOMPLETE_CATALOG,
                schemas_dir.as_posix(),
                "#",
                f"schemas directory does not exist: {schemas_dir}",
            )
            return catalog

        if target_file is not None:
            schema_files = [target_file]
        else:
            schema_files = sorted(schemas_dir.glob("*.json"))

        case_fold_map: dict[str, str] = {}

        for file_path in schema_files:
            relative = file_path.relative_to(schemas_dir).as_posix()
            lowered = relative.lower()
            if lowered in case_fold_map:
                self.emit(
                    CODE_CASE_FOLD_COLLISION,
                    relative,
                    "#",
                    f"case-fold collision between '{relative}' and '{case_fold_map[lowered]}'",
                )
            else:
                case_fold_map[lowered] = relative

            # Check file size
            try:
                st = file_path.stat()
            except OSError as exc:
                self.emit(CODE_INCOMPLETE_CATALOG, relative, "#", f"cannot stat schema file: {exc}")
                continue

            if st.st_size > self.max_file_bytes:
                self.emit(
                    CODE_RESOURCE_LIMIT_EXCEEDED,
                    relative,
                    "#",
                    f"schema file exceeds size limit ({st.st_size} > {self.max_file_bytes} bytes)",
                )
                continue

            try:
                raw_bytes = file_path.read_bytes()
            except OSError as exc:
                self.emit(CODE_INCOMPLETE_CATALOG, relative, "#", f"cannot read schema file: {exc}")
                continue

            self.bytes_read += len(raw_bytes)
            digest = hashlib.sha256(raw_bytes).hexdigest()
            catalog.file_digests[relative] = f"sha256:{digest}"
            catalog.raw_bytes_by_relative[relative] = raw_bytes

            try:
                text = raw_bytes.decode("utf-8")
            except UnicodeDecodeError as exc:
                self.emit(CODE_MALFORMED_JSON, relative, "#", f"invalid UTF-8 encoding: {exc}")
                continue

            try:
                doc = json.loads(text)
            except json.JSONDecodeError as exc:
                self.emit(CODE_MALFORMED_JSON, relative, f"#{exc.pos}", f"JSON syntax error: {exc.msg} at line {exc.lineno} col {exc.colno}")
                continue

            catalog.schemas_by_relative[relative] = doc
            catalog.anchors_by_relative[relative] = {}

        return catalog

    def validate_catalog(self, catalog: SchemaCatalog) -> None:
        # Phase 1: Meta-Schema validation of individual schema documents
        for relative in sorted(catalog.schemas_by_relative.keys()):
            doc = catalog.schemas_by_relative[relative]
            self._validate_document_meta_schema(relative, doc, catalog)

        # Phase 2: Reference extraction & resolution
        self._validate_all_references(catalog)

        # Phase 3: Dependency graph and cycle analysis
        self._analyze_graph_and_cycles(catalog)

    def _validate_document_meta_schema(self, relative: str, doc: Any, catalog: SchemaCatalog) -> None:
        if self.require_object_root:
            if not isinstance(doc, dict):
                self.emit(
                    CODE_INVALID_SCHEMA_TYPE,
                    relative,
                    "#",
                    f"root schema must be a JSON object, got {type(doc).__name__}",
                )
                return
        elif not isinstance(doc, (dict, bool)):
            self.emit(
                CODE_INVALID_SCHEMA_TYPE,
                relative,
                "#",
                f"schema must be a JSON object or boolean, got {type(doc).__name__}",
            )
            return

        if isinstance(doc, bool):
            return

        # Check top-level $schema
        if "$schema" not in doc:
            self.emit(CODE_INVALID_DIALECT, relative, "#/$schema", "missing required $schema declaration")
        else:
            dialect = doc["$schema"]
            if not isinstance(dialect, str):
                self.emit(CODE_INVALID_DIALECT, relative, "#/$schema", f"$schema must be a string, got {type(dialect).__name__}")
            elif dialect != DRAFT_2020_12_DIALECT:
                self.emit(
                    CODE_INVALID_DIALECT,
                    relative,
                    "#/$schema",
                    f"unsupported schema dialect '{dialect}', expected '{DRAFT_2020_12_DIALECT}'",
                )

        # Check top-level $id
        if "$id" in doc:
            schema_id = doc["$id"]
            if not isinstance(schema_id, str):
                self.emit(CODE_INVALID_URI_REFERENCE, relative, "#/$id", f"$id must be a string, got {type(schema_id).__name__}")
            else:
                if "#" in schema_id:
                    part_after = schema_id.partition("#")[2]
                    if part_after:
                        self.emit(
                            CODE_INVALID_URI_REFERENCE,
                            relative,
                            "#/$id",
                            f"$id must not contain a non-empty fragment: '{schema_id}'",
                        )
                if schema_id in catalog.schemas_by_id:
                    prior = catalog.schemas_by_id[schema_id]
                    self.emit(
                        CODE_DUPLICATE_CANONICAL_ID,
                        relative,
                        "#/$id",
                        f"duplicate canonical $id '{schema_id}' already declared in {prior}",
                    )
                else:
                    catalog.schemas_by_id[schema_id] = relative

        # Recursive keyword and node validation
        self._validate_schema_node(relative, doc, "#", catalog, depth=0)

    def _validate_schema_node(
        self, relative: str, node: Any, path: str, catalog: SchemaCatalog, depth: int
    ) -> None:
        if depth > self.max_depth:
            self.emit(
                CODE_RECURSION_LIMIT_EXCEEDED,
                relative,
                path,
                f"schema nesting exceeds maximum recursion depth ({self.max_depth})",
            )
            return

        if isinstance(node, bool):
            return

        if not isinstance(node, dict):
            self.emit(
                CODE_INVALID_SCHEMA_TYPE,
                relative,
                path,
                f"subschema must be an object or boolean, got {type(node).__name__}",
            )
            return

        # Anchors
        for anchor_kw in ("$anchor", "$dynamicAnchor"):
            if anchor_kw in node:
                val = node[anchor_kw]
                if not isinstance(val, str):
                    self.emit(CODE_INVALID_KEYWORD_SHAPE, relative, f"{path}/{anchor_kw}", f"{anchor_kw} must be a string")
                elif not ANCHOR_PATTERN.fullmatch(val):
                    self.emit(
                        CODE_INVALID_KEYWORD_SHAPE,
                        relative,
                        f"{path}/{anchor_kw}",
                        f"{anchor_kw} '{val}' does not match pattern {ANCHOR_PATTERN.pattern}",
                    )
                else:
                    anchors = catalog.anchors_by_relative.setdefault(relative, {})
                    if val in anchors:
                        self.emit(
                            CODE_DUPLICATE_ANCHOR,
                            relative,
                            f"{path}/{anchor_kw}",
                            f"duplicate {anchor_kw} '{val}' within schema {relative}",
                        )
                    else:
                        anchors[val] = node

        # Subschema dialect declaration if present
        if "$schema" in node and path != "#":
            sub_dialect = node["$schema"]
            if sub_dialect != DRAFT_2020_12_DIALECT:
                self.emit(
                    CODE_INVALID_DIALECT,
                    relative,
                    f"{path}/$schema",
                    f"subschema specifies unsupported dialect '{sub_dialect}'",
                )

        # $vocabulary
        if "$vocabulary" in node:
            vocab = node["$vocabulary"]
            if not isinstance(vocab, dict):
                self.emit(CODE_INVALID_KEYWORD_SHAPE, relative, f"{path}/$vocabulary", "$vocabulary must be an object")
            else:
                for uri, required in vocab.items():
                    if not isinstance(uri, str) or not isinstance(required, bool):
                        self.emit(CODE_INVALID_KEYWORD_SHAPE, relative, f"{path}/$vocabulary", "vocabulary entries must map URI string to boolean")
                    elif uri not in SUPPORTED_VOCABULARIES and required:
                        self.emit(
                            CODE_UNSUPPORTED_VOCABULARY,
                            relative,
                            f"{path}/$vocabulary",
                            f"unsupported required vocabulary: {uri}",
                        )

        # $comment
        if "$comment" in node and not isinstance(node["$comment"], str):
            self.emit(CODE_INVALID_KEYWORD_SHAPE, relative, f"{path}/$comment", "$comment must be a string")

        # type
        if "type" in node:
            t = node["type"]
            if isinstance(t, str):
                if t not in VALID_SIMPLE_TYPES:
                    self.emit(CODE_INVALID_KEYWORD_SHAPE, relative, f"{path}/type", f"invalid type '{t}'")
            elif isinstance(t, list):
                if not t:
                    self.emit(CODE_INVALID_KEYWORD_SHAPE, relative, f"{path}/type", "type array must be non-empty")
                else:
                    seen_types = set()
                    for idx, item in enumerate(t):
                        if not isinstance(item, str) or item not in VALID_SIMPLE_TYPES:
                            self.emit(CODE_INVALID_KEYWORD_SHAPE, relative, f"{path}/type/{idx}", f"invalid type '{item}'")
                        if item in seen_types:
                            self.emit(CODE_INVALID_KEYWORD_SHAPE, relative, f"{path}/type", f"duplicate type '{item}' in type array")
                        seen_types.add(item)
            else:
                self.emit(CODE_INVALID_KEYWORD_SHAPE, relative, f"{path}/type", f"type must be a string or array of strings, got {type(t).__name__}")

        # enum
        if "enum" in node:
            enum_val = node["enum"]
            if not isinstance(enum_val, list):
                self.emit(CODE_INVALID_KEYWORD_SHAPE, relative, f"{path}/enum", "enum must be an array")

        # multipleOf
        if "multipleOf" in node:
            mo = node["multipleOf"]
            if isinstance(mo, bool) or not isinstance(mo, (int, float)) or mo <= 0:
                self.emit(CODE_INVALID_KEYWORD_SHAPE, relative, f"{path}/multipleOf", "multipleOf must be a number strictly greater than 0")

        # minimum, maximum, exclusiveMinimum, exclusiveMaximum
        min_val = None
        max_val = None
        ex_min = None
        ex_max = None

        if "minimum" in node:
            v = node["minimum"]
            if isinstance(v, bool) or not isinstance(v, (int, float)):
                self.emit(CODE_INVALID_KEYWORD_SHAPE, relative, f"{path}/minimum", "minimum must be a number")
            else:
                min_val = v
        if "maximum" in node:
            v = node["maximum"]
            if isinstance(v, bool) or not isinstance(v, (int, float)):
                self.emit(CODE_INVALID_KEYWORD_SHAPE, relative, f"{path}/maximum", "maximum must be a number")
            else:
                max_val = v
        if "exclusiveMinimum" in node:
            v = node["exclusiveMinimum"]
            if isinstance(v, bool) or not isinstance(v, (int, float)):
                self.emit(CODE_INVALID_KEYWORD_SHAPE, relative, f"{path}/exclusiveMinimum", "exclusiveMinimum must be a number")
            else:
                ex_min = v
        if "exclusiveMaximum" in node:
            v = node["exclusiveMaximum"]
            if isinstance(v, bool) or not isinstance(v, (int, float)):
                self.emit(CODE_INVALID_KEYWORD_SHAPE, relative, f"{path}/exclusiveMaximum", "exclusiveMaximum must be a number")
            else:
                ex_max = v

        if min_val is not None and max_val is not None and min_val > max_val:
            self.emit(CODE_INVALID_KEYWORD_SHAPE, relative, path, f"contradictory bounds: minimum ({min_val}) > maximum ({max_val})")
        if ex_min is not None and ex_max is not None and ex_min >= ex_max:
            self.emit(CODE_INVALID_KEYWORD_SHAPE, relative, path, f"contradictory bounds: exclusiveMinimum ({ex_min}) >= exclusiveMaximum ({ex_max})")
        if min_val is not None and ex_max is not None and min_val >= ex_max:
            self.emit(CODE_INVALID_KEYWORD_SHAPE, relative, path, f"contradictory bounds: minimum ({min_val}) >= exclusiveMaximum ({ex_max})")
        if ex_min is not None and max_val is not None and ex_min >= max_val:
            self.emit(CODE_INVALID_KEYWORD_SHAPE, relative, path, f"contradictory bounds: exclusiveMinimum ({ex_min}) >= maximum ({max_val})")

        # minLength, maxLength
        min_len = None
        max_len = None
        if "minLength" in node:
            v = node["minLength"]
            if isinstance(v, bool) or not isinstance(v, int) or v < 0:
                self.emit(CODE_INVALID_KEYWORD_SHAPE, relative, f"{path}/minLength", "minLength must be a non-negative integer")
            else:
                min_len = v
        if "maxLength" in node:
            v = node["maxLength"]
            if isinstance(v, bool) or not isinstance(v, int) or v < 0:
                self.emit(CODE_INVALID_KEYWORD_SHAPE, relative, f"{path}/maxLength", "maxLength must be a non-negative integer")
            else:
                max_len = v
        if min_len is not None and max_len is not None and min_len > max_len:
            self.emit(CODE_INVALID_KEYWORD_SHAPE, relative, path, f"contradictory bounds: minLength ({min_len}) > maxLength ({max_len})")

        # pattern
        if "pattern" in node:
            pat = node["pattern"]
            if not isinstance(pat, str):
                self.emit(CODE_INVALID_KEYWORD_SHAPE, relative, f"{path}/pattern", "pattern must be a string")
            else:
                try:
                    re.compile(pat)
                except re.error as exc:
                    self.emit(CODE_INVALID_REGEX, relative, f"{path}/pattern", f"invalid regular expression '{pat}': {exc}")

        # minItems, maxItems
        min_items = None
        max_items = None
        if "minItems" in node:
            v = node["minItems"]
            if isinstance(v, bool) or not isinstance(v, int) or v < 0:
                self.emit(CODE_INVALID_KEYWORD_SHAPE, relative, f"{path}/minItems", "minItems must be a non-negative integer")
            else:
                min_items = v
        if "maxItems" in node:
            v = node["maxItems"]
            if isinstance(v, bool) or not isinstance(v, int) or v < 0:
                self.emit(CODE_INVALID_KEYWORD_SHAPE, relative, f"{path}/maxItems", "maxItems must be a non-negative integer")
            else:
                max_items = v
        if min_items is not None and max_items is not None and min_items > max_items:
            self.emit(CODE_INVALID_KEYWORD_SHAPE, relative, path, f"contradictory bounds: minItems ({min_items}) > maxItems ({max_items})")

        # uniqueItems
        if "uniqueItems" in node and not isinstance(node["uniqueItems"], bool):
            self.emit(CODE_INVALID_KEYWORD_SHAPE, relative, f"{path}/uniqueItems", "uniqueItems must be a boolean")

        # minContains, maxContains
        min_contains = None
        max_contains = None
        if "minContains" in node:
            v = node["minContains"]
            if isinstance(v, bool) or not isinstance(v, int) or v < 0:
                self.emit(CODE_INVALID_KEYWORD_SHAPE, relative, f"{path}/minContains", "minContains must be a non-negative integer")
            else:
                min_contains = v
        if "maxContains" in node:
            v = node["maxContains"]
            if isinstance(v, bool) or not isinstance(v, int) or v < 0:
                self.emit(CODE_INVALID_KEYWORD_SHAPE, relative, f"{path}/maxContains", "maxContains must be a non-negative integer")
            else:
                max_contains = v
        if min_contains is not None and max_contains is not None and min_contains > max_contains:
            self.emit(CODE_INVALID_KEYWORD_SHAPE, relative, path, f"contradictory bounds: minContains ({min_contains}) > maxContains ({max_contains})")

        # minProperties, maxProperties
        min_props = None
        max_props = None
        if "minProperties" in node:
            v = node["minProperties"]
            if isinstance(v, bool) or not isinstance(v, int) or v < 0:
                self.emit(CODE_INVALID_KEYWORD_SHAPE, relative, f"{path}/minProperties", "minProperties must be a non-negative integer")
            else:
                min_props = v
        if "maxProperties" in node:
            v = node["maxProperties"]
            if isinstance(v, bool) or not isinstance(v, int) or v < 0:
                self.emit(CODE_INVALID_KEYWORD_SHAPE, relative, f"{path}/maxProperties", "maxProperties must be a non-negative integer")
            else:
                max_props = v
        if min_props is not None and max_props is not None and min_props > max_props:
            self.emit(CODE_INVALID_KEYWORD_SHAPE, relative, path, f"contradictory bounds: minProperties ({min_props}) > maxProperties ({max_props})")

        # required
        if "required" in node:
            req = node["required"]
            if not isinstance(req, list):
                self.emit(CODE_INVALID_KEYWORD_SHAPE, relative, f"{path}/required", "required must be an array of strings")
            else:
                seen_req = set()
                for idx, r in enumerate(req):
                    if not isinstance(r, str):
                        self.emit(CODE_INVALID_KEYWORD_SHAPE, relative, f"{path}/required/{idx}", "required item must be a string")
                    elif r in seen_req:
                        self.emit(CODE_INVALID_KEYWORD_SHAPE, relative, f"{path}/required", f"duplicate required property '{r}'")
                    seen_req.add(r)

        # dependentRequired
        if "dependentRequired" in node:
            dr = node["dependentRequired"]
            if not isinstance(dr, dict):
                self.emit(CODE_INVALID_KEYWORD_SHAPE, relative, f"{path}/dependentRequired", "dependentRequired must be an object")
            else:
                for k, v in dr.items():
                    if not isinstance(v, list) or not all(isinstance(x, str) for x in v):
                        self.emit(CODE_INVALID_KEYWORD_SHAPE, relative, f"{path}/dependentRequired/{k}", "dependentRequired entries must be arrays of strings")
                    elif len(v) != len(set(v)):
                        self.emit(CODE_INVALID_KEYWORD_SHAPE, relative, f"{path}/dependentRequired/{k}", "dependentRequired entries must contain unique strings")

        # properties
        if "properties" in node:
            props = node["properties"]
            if not isinstance(props, dict):
                self.emit(CODE_INVALID_KEYWORD_SHAPE, relative, f"{path}/properties", "properties must be an object")
            else:
                for prop_name, prop_sub in props.items():
                    self._validate_schema_node(relative, prop_sub, f"{path}/properties/{prop_name}", catalog, depth + 1)

        # patternProperties
        if "patternProperties" in node:
            pat_props = node["patternProperties"]
            if not isinstance(pat_props, dict):
                self.emit(CODE_INVALID_KEYWORD_SHAPE, relative, f"{path}/patternProperties", "patternProperties must be an object")
            else:
                for regex_key, prop_sub in pat_props.items():
                    try:
                        re.compile(regex_key)
                    except re.error as exc:
                        self.emit(CODE_INVALID_REGEX, relative, f"{path}/patternProperties/{regex_key}", f"invalid regex in patternProperties key '{regex_key}': {exc}")
                    self._validate_schema_node(relative, prop_sub, f"{path}/patternProperties/{regex_key}", catalog, depth + 1)

        # additionalProperties
        if "additionalProperties" in node:
            ap = node["additionalProperties"]
            if not isinstance(ap, (dict, bool)):
                self.emit(CODE_INVALID_KEYWORD_SHAPE, relative, f"{path}/additionalProperties", "additionalProperties must be a schema or boolean")
            else:
                self._validate_schema_node(relative, ap, f"{path}/additionalProperties", catalog, depth + 1)

        # propertyNames
        if "propertyNames" in node:
            pn = node["propertyNames"]
            if not isinstance(pn, (dict, bool)):
                self.emit(CODE_INVALID_KEYWORD_SHAPE, relative, f"{path}/propertyNames", "propertyNames must be a schema or boolean")
            else:
                self._validate_schema_node(relative, pn, f"{path}/propertyNames", catalog, depth + 1)

        # items (in Draft 2020-12, items must be a single schema, not a list)
        if "items" in node:
            it = node["items"]
            if isinstance(it, list):
                self.emit(
                    CODE_INVALID_KEYWORD_SHAPE,
                    relative,
                    f"{path}/items",
                    "in Draft 2020-12, items must be a schema; use prefixItems for array tuple schemas",
                )
            elif not isinstance(it, (dict, bool)):
                self.emit(CODE_INVALID_KEYWORD_SHAPE, relative, f"{path}/items", "items must be a schema or boolean")
            else:
                self._validate_schema_node(relative, it, f"{path}/items", catalog, depth + 1)

        # prefixItems
        if "prefixItems" in node:
            pi = node["prefixItems"]
            if not isinstance(pi, list):
                self.emit(CODE_INVALID_KEYWORD_SHAPE, relative, f"{path}/prefixItems", "prefixItems must be an array of schemas")
            else:
                for idx, sub in enumerate(pi):
                    self._validate_schema_node(relative, sub, f"{path}/prefixItems/{idx}", catalog, depth + 1)

        # contains
        if "contains" in node:
            cnt = node["contains"]
            if not isinstance(cnt, (dict, bool)):
                self.emit(CODE_INVALID_KEYWORD_SHAPE, relative, f"{path}/contains", "contains must be a schema or boolean")
            else:
                self._validate_schema_node(relative, cnt, f"{path}/contains", catalog, depth + 1)

        # combinators: allOf, anyOf, oneOf
        for comb in ("allOf", "anyOf", "oneOf"):
            if comb in node:
                c_val = node[comb]
                if not isinstance(c_val, list):
                    self.emit(CODE_INVALID_KEYWORD_SHAPE, relative, f"{path}/{comb}", f"{comb} must be an array of schemas")
                elif not c_val:
                    self.emit(CODE_INVALID_KEYWORD_SHAPE, relative, f"{path}/{comb}", f"{comb} array must be non-empty")
                else:
                    for idx, sub in enumerate(c_val):
                        self._validate_schema_node(relative, sub, f"{path}/{comb}/{idx}", catalog, depth + 1)

        # not, if, then, else
        for single in ("not", "if", "then", "else"):
            if single in node:
                s_val = node[single]
                if not isinstance(s_val, (dict, bool)):
                    self.emit(CODE_INVALID_KEYWORD_SHAPE, relative, f"{path}/{single}", f"{single} must be a schema or boolean")
                else:
                    self._validate_schema_node(relative, s_val, f"{path}/{single}", catalog, depth + 1)

        # dependentSchemas
        if "dependentSchemas" in node:
            ds = node["dependentSchemas"]
            if not isinstance(ds, dict):
                self.emit(CODE_INVALID_KEYWORD_SHAPE, relative, f"{path}/dependentSchemas", "dependentSchemas must be an object")
            else:
                for k, sub in ds.items():
                    self._validate_schema_node(relative, sub, f"{path}/dependentSchemas/{k}", catalog, depth + 1)

        # unevaluatedItems, unevaluatedProperties
        for un in ("unevaluatedItems", "unevaluatedProperties"):
            if un in node:
                u_val = node[un]
                if not isinstance(u_val, (dict, bool)):
                    self.emit(CODE_INVALID_KEYWORD_SHAPE, relative, f"{path}/{un}", f"{un} must be a schema or boolean")
                else:
                    self._validate_schema_node(relative, u_val, f"{path}/{un}", catalog, depth + 1)

        # $defs
        if "$defs" in node:
            defs = node["$defs"]
            if not isinstance(defs, dict):
                self.emit(CODE_INVALID_KEYWORD_SHAPE, relative, f"{path}/$defs", "$defs must be an object")
            else:
                for def_name, def_sub in defs.items():
                    self._validate_schema_node(relative, def_sub, f"{path}/$defs/{def_name}", catalog, depth + 1)

        # format, contentEncoding, contentMediaType
        for str_kw in ("format", "contentEncoding", "contentMediaType", "title", "description"):
            if str_kw in node and not isinstance(node[str_kw], str):
                self.emit(CODE_INVALID_KEYWORD_SHAPE, relative, f"{path}/{str_kw}", f"{str_kw} must be a string")

        # contentSchema
        if "contentSchema" in node:
            cs = node["contentSchema"]
            if not isinstance(cs, (dict, bool)):
                self.emit(CODE_INVALID_KEYWORD_SHAPE, relative, f"{path}/contentSchema", "contentSchema must be a schema or boolean")
            else:
                self._validate_schema_node(relative, cs, f"{path}/contentSchema", catalog, depth + 1)

        # boolean flags: deprecated, readOnly, writeOnly
        for bool_kw in ("deprecated", "readOnly", "writeOnly"):
            if bool_kw in node and not isinstance(node[bool_kw], bool):
                self.emit(CODE_INVALID_KEYWORD_SHAPE, relative, f"{path}/{bool_kw}", f"{bool_kw} must be a boolean")

        # examples
        if "examples" in node and not isinstance(node["examples"], list):
            self.emit(CODE_INVALID_KEYWORD_SHAPE, relative, f"{path}/examples", "examples must be an array")

    def _validate_all_references(self, catalog: SchemaCatalog) -> None:
        """Find every $ref and $dynamicRef and verify it resolves strictly within catalog."""
        def extract_refs(val: Any, rel_path: str, cur_path: str) -> None:
            if isinstance(val, dict):
                for ref_kw in ("$ref", "$dynamicRef"):
                    if ref_kw in val:
                        self.reference_count += 1
                        ref_str = val[ref_kw]
                        if not isinstance(ref_str, str):
                            self.emit(CODE_INVALID_KEYWORD_SHAPE, rel_path, f"{cur_path}/{ref_kw}", f"{ref_kw} must be a string")
                        else:
                            self._resolve_reference(rel_path, f"{cur_path}/{ref_kw}", ref_str, catalog)
                for k, child in val.items():
                    extract_refs(child, rel_path, f"{cur_path}/{k}")
            elif isinstance(val, list):
                for idx, item in enumerate(val):
                    extract_refs(item, rel_path, f"{cur_path}/{idx}")

        for relative, schema_doc in sorted(catalog.schemas_by_relative.items()):
            extract_refs(schema_doc, relative, "#")

    def _resolve_reference(
        self, origin_relative: str, json_path: str, ref: str, catalog: SchemaCatalog
    ) -> None:
        if not ref.strip():
            self.emit(CODE_INVALID_URI_REFERENCE, origin_relative, json_path, "empty reference string")
            return

        # Check for remote network URI
        if ref.startswith(("http://", "https://")):
            # Only allowed if it exactly matches a known $id in the offline catalog
            base_uri, _, fragment = ref.partition("#")
            target_relative = catalog.schemas_by_id.get(base_uri)
            if target_relative is None:
                self.emit(
                    CODE_NETWORK_FETCH_FORBIDDEN,
                    origin_relative,
                    json_path,
                    f"network fetch forbidden for offline reference: '{ref}'",
                )
                return
            target_doc = catalog.schemas_by_relative.get(target_relative)
            if target_doc is None:
                self.emit(CODE_UNRESOLVED_REFERENCE, origin_relative, json_path, f"unresolved target schema: '{target_relative}'")
                return
            if fragment:
                self._resolve_fragment(target_relative, target_doc, fragment, origin_relative, json_path, ref, catalog)
            return

        # Local file / pointer reference
        file_part, separator, fragment = ref.partition("#")

        if not file_part:
            # Same document reference
            target_relative = origin_relative
            target_doc = catalog.schemas_by_relative.get(origin_relative)
            if target_doc is None:
                self.emit(CODE_UNRESOLVED_REFERENCE, origin_relative, json_path, f"schema document missing: {origin_relative}")
                return
        else:
            # Path security checks
            origin_path = catalog.root_dir / origin_relative
            target_path = (origin_path.parent / file_part).resolve()

            # Path traversal check
            if not target_path.is_relative_to(catalog.root_dir):
                self.emit(
                    CODE_PATH_TRAVERSAL,
                    origin_relative,
                    json_path,
                    f"path traversal: reference '{ref}' escapes schemas root directory",
                )
                return

            # Symlink escape check
            if target_path.is_symlink():
                real_target = target_path.resolve()
                if not real_target.is_relative_to(catalog.root_dir):
                    self.emit(
                        CODE_SYMLINK_ESCAPE,
                        origin_relative,
                        json_path,
                        f"symlink escape: reference target '{file_part}' resolves outside schemas root",
                    )
                    return

            target_relative = target_path.relative_to(catalog.root_dir).as_posix()
            target_doc = catalog.schemas_by_relative.get(target_relative)
            if target_doc is None:
                self.emit(
                    CODE_UNRESOLVED_REFERENCE,
                    origin_relative,
                    json_path,
                    f"unresolved local schema file reference: '{ref}' (target '{target_relative}' not in catalog)",
                )
                return

        if separator:
            self._resolve_fragment(target_relative, target_doc, fragment, origin_relative, json_path, ref, catalog)

    def _resolve_fragment(
        self,
        target_relative: str,
        target_doc: Any,
        fragment: str,
        origin_relative: str,
        json_path: str,
        ref: str,
        catalog: SchemaCatalog,
    ) -> None:
        if not fragment:
            return

        if fragment.startswith("/"):
            # JSON Pointer fragment
            current = target_doc
            for raw_token in fragment[1:].split("/"):
                token = raw_token.replace("~1", "/").replace("~0", "~")
                if isinstance(current, dict) and token in current:
                    current = current[token]
                elif isinstance(current, list) and token.isdigit() and int(token) < len(current):
                    current = current[int(token)]
                else:
                    self.emit(
                        CODE_UNRESOLVED_POINTER,
                        origin_relative,
                        json_path,
                        f"unresolved JSON pointer '{fragment}' in reference '{ref}' (token '{token}' not found)",
                    )
                    return
        else:
            # Anchor fragment
            anchors = catalog.anchors_by_relative.get(target_relative, {})
            if fragment not in anchors:
                self.emit(
                    CODE_UNRESOLVED_ANCHOR,
                    origin_relative,
                    json_path,
                    f"unresolved anchor '#{fragment}' in reference '{ref}'",
                )

    def _analyze_graph_and_cycles(self, catalog: SchemaCatalog) -> None:
        """Analyze reference graph, compute cycles and verify recursive structures."""
        adj: dict[str, set[str]] = {rel: set() for rel in catalog.schemas_by_relative}

        for relative, doc in catalog.schemas_by_relative.items():
            self._collect_direct_schema_dependencies(doc, relative, adj[relative], catalog)

        # Find cycles using DFS
        color: dict[str, int] = {}  # 0=unvisited, 1=visiting, 2=visited
        self.cycles: list[list[str]] = []

        def dfs(node: str, stack: list[str]) -> None:
            color[node] = 1
            stack.append(node)
            for nxt in sorted(adj.get(node, set())):
                if color.get(nxt, 0) == 1:
                    # Found cycle
                    idx = stack.index(nxt)
                    cycle = stack[idx:] + [nxt]
                    self.cycles.append(cycle)
                elif color.get(nxt, 0) == 0:
                    dfs(nxt, stack)
            stack.pop()
            color[node] = 2

        for node in sorted(adj.keys()):
            if color.get(node, 0) == 0:
                dfs(node, [])

        # Verify whether cycles are guarded
        for cycle in self.cycles:
            self._verify_cycle_guarded(cycle, catalog)

    def _collect_direct_schema_dependencies(
        self, val: Any, origin: str, deps: set[str], catalog: SchemaCatalog
    ) -> None:
        if isinstance(val, dict):
            for ref_kw in ("$ref", "$dynamicRef"):
                if ref_kw in val and isinstance(val[ref_kw], str):
                    ref = val[ref_kw]
                    if ref.startswith(("http://", "https://")):
                        base = ref.partition("#")[0]
                        tgt = catalog.schemas_by_id.get(base)
                        if tgt:
                            deps.add(tgt)
                    else:
                        file_part = ref.partition("#")[0]
                        if file_part:
                            origin_path = catalog.root_dir / origin
                            try:
                                tgt_path = (origin_path.parent / file_part).resolve()
                                if tgt_path.is_relative_to(catalog.root_dir):
                                    deps.add(tgt_path.relative_to(catalog.root_dir).as_posix())
                            except Exception:
                                pass
                        else:
                            # Self-reference
                            deps.add(origin)
            for child in val.values():
                self._collect_direct_schema_dependencies(child, origin, deps, catalog)
        elif isinstance(val, list):
            for child in val:
                self._collect_direct_schema_dependencies(child, origin, deps, catalog)

    def _verify_cycle_guarded(self, cycle: list[str], catalog: SchemaCatalog) -> None:
        """Verify that a cycle is guarded (e.g. within properties/items) and not an immediate loop."""
        # Check if any schema in the cycle has a top-level un-guarded reference to another
        for i in range(len(cycle) - 1):
            src = cycle[i]
            dst = cycle[i + 1]
            doc = catalog.schemas_by_relative.get(src)
            if isinstance(doc, dict):
                ref = doc.get("$ref") or doc.get("$dynamicRef")
                if isinstance(ref, str):
                    # Top-level direct ref
                    if src == dst or ref.startswith(f"{dst}#") or ref == dst:
                        self.emit(
                            CODE_UNGUARDED_CYCLE,
                            src,
                            "#/$ref",
                            f"unguarded direct reference cycle: {' -> '.join(cycle)}",
                        )


def audit(
    schemas_dir: Path = DEFAULT_SCHEMAS_DIR,
    target_file: Path | None = None,
    max_depth: int = DEFAULT_MAX_DEPTH,
    max_errors: int = DEFAULT_MAX_ERRORS,
    max_file_bytes: int = DEFAULT_MAX_FILE_BYTES,
    budget_wall_ns: int = DEFAULT_BUDGET_WALL_NS,
    budget_peak_bytes: int = DEFAULT_BUDGET_PEAK_BYTES,
    budget_work_units: int = DEFAULT_BUDGET_WORK_UNITS,
) -> dict[str, Any]:
    """Execute complete deterministic Draft 2020-12 meta-schema and reference validation."""
    start_wall_ns = time.perf_counter_ns()
    times_start = os.times()

    validator = Validator(
        max_depth=max_depth,
        max_errors=max_errors,
        max_file_bytes=max_file_bytes,
        require_object_root=True,
    )

    catalog = validator.load_catalog(schemas_dir, target_file)

    if not catalog.schemas_by_relative and target_file is None:
        validator.emit(
            CODE_INCOMPLETE_CATALOG,
            schemas_dir.as_posix(),
            "#",
            f"no JSON schema files found in {schemas_dir}",
        )
    else:
        validator.validate_catalog(catalog)

    end_wall_ns = time.perf_counter_ns()
    times_end = os.times()
    wall_ns = max(0, end_wall_ns - start_wall_ns)
    cpu_user_ns = max(0, int((times_end.user - times_start.user) * 1_000_000_000))
    cpu_sys_ns = max(0, int((times_end.system - times_start.system) * 1_000_000_000))

    try:
        peak_bytes = resource.getrusage(resource.RUSAGE_SELF).ru_maxrss * 1024
    except Exception:
        peak_bytes = 0

    findings_sorted = sorted(
        validator.findings,
        key=lambda f: (f.schema_path, f.code, f.json_path, f.message),
    )

    status = "passed" if not findings_sorted else "failed"

    # Catalog digest: canonical ordered hashes of relative paths and contents
    hasher = hashlib.sha256()
    for rel in sorted(catalog.file_digests.keys()):
        hasher.update(rel.encode("utf-8"))
        hasher.update(b"\0")
        hasher.update(catalog.file_digests[rel].encode("utf-8"))
        hasher.update(b"\n")
    catalog_digest = "sha256:" + hasher.hexdigest()

    validator_script = Path(__file__).resolve()
    validator_digest = "sha256:" + hashlib.sha256(validator_script.read_bytes()).hexdigest()
    meta_schema_digest = compute_meta_schema_digest()

    schema_count = len(catalog.schemas_by_relative)
    used_work_units = schema_count + validator.reference_count

    report = {
        "schema": "fss.schema_validation_receipt.v1",
        "status": status,
        "schemaCount": schema_count,
        "referenceCount": validator.reference_count,
        "cycleCount": len(getattr(validator, "cycles", [])),
        "cycles": sorted(getattr(validator, "cycles", [])),
        "diagnosticCardinality": len(findings_sorted),
        "diagnosticsTruncated": validator.truncated,
        "findings": [f.to_dict() for f in findings_sorted],
        "cost": {
            "cpuUserNs": cpu_user_ns,
            "cpuSystemNs": cpu_sys_ns,
            "wallNs": wall_ns,
            "peakMemoryBytes": peak_bytes,
            "bytesRead": validator.bytes_read,
            "bytesWritten": 0,
            "networkBytes": 0,
            "retries": 0,
            "operatorBurden": 0,
            "measurementMethod": "getrusage+perf_counter_ns",
        },
        "budget": {
            "starting": {
                "maxWallNs": budget_wall_ns,
                "maxPeakBytes": budget_peak_bytes,
                "maxWorkUnits": budget_work_units,
            },
            "used": {
                "wallNs": wall_ns,
                "peakBytes": peak_bytes,
                "workUnits": used_work_units,
            },
            "remaining": {
                "wallNs": max(0, budget_wall_ns - wall_ns),
                "peakBytes": max(0, budget_peak_bytes - peak_bytes),
                "workUnits": max(0, budget_work_units - used_work_units),
            },
        },
        "catalogDigest": catalog_digest,
        "validatorDigest": validator_digest,
        "metaSchemaDigest": meta_schema_digest,
        "toolchain": f"python3-{sys.version.split()[0]}",
        "environmentIdentity": compute_environment_identity(),
        "excludedDimensions": [],
        "reproductionCommand": f"python3 scripts/schema_validate.py{' --schemas-dir ' + str(schemas_dir) if schemas_dir != DEFAULT_SCHEMAS_DIR else ''}",
    }

    report["proofHash"] = "sha256:" + hashlib.sha256(canonical_json_bytes(report)).hexdigest()
    return report


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Deterministic offline Draft 2020-12 meta-schema and local reference validator"
    )
    parser.add_argument("--schemas-dir", type=Path, default=DEFAULT_SCHEMAS_DIR, help="Path to schemas directory")
    parser.add_argument("--schema", type=Path, default=None, help="Validate specific schema file")
    parser.add_argument("--json", action="store_true", help="Output full structured JSON report")
    parser.add_argument("--report", type=Path, default=None, help="Save structured JSON report to file")
    parser.add_argument("--max-depth", type=int, default=DEFAULT_MAX_DEPTH, help="Maximum recursion depth")
    parser.add_argument("--max-errors", type=int, default=DEFAULT_MAX_ERRORS, help="Maximum error diagnostics")
    parser.add_argument("--max-file-bytes", type=int, default=DEFAULT_MAX_FILE_BYTES, help="Maximum schema file size")
    args = parser.parse_args()

    try:
        report = audit(
            schemas_dir=args.schemas_dir,
            target_file=args.schema,
            max_depth=args.max_depth,
            max_errors=args.max_errors,
            max_file_bytes=args.max_file_bytes,
        )
    except Exception as exc:
        err_report = {
            "schema": "fss.schema_validation_receipt.v1",
            "status": "failed",
            "error": str(exc),
            "code": CODE_VALIDATOR_UNAVAILABLE,
        }
        if args.json:
            print(json.dumps(err_report, indent=2))
        else:
            print(f"schema validation aborted: {exc}", file=sys.stderr)
        return 2

    if args.report:
        args.report.write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")

    if args.json:
        print(json.dumps(report, indent=2))
    else:
        status = report["status"]
        schema_count = report["schemaCount"]
        findings = report["findings"]
        ref_count = report["referenceCount"]
        cycle_count = report["cycleCount"]
        proof_hash = report["proofHash"]
        cat_digest = report["catalogDigest"]

        if status == "passed":
            print(f"schema validation passed: {schema_count} schemas evaluated, 0 errors, {ref_count} refs resolved")
            print(f"schemaCount={schema_count}")
            print(f"referenceCount={ref_count}")
            print(f"cycleCount={cycle_count}")
            print(f"catalogDigest={cat_digest}")
            print(f"proofHash={proof_hash}")
            print("status=passed")
        else:
            print(f"schema validation failed: {len(findings)} error(s)", file=sys.stderr)
            for f in findings:
                print(f"[{f['code']}] {f['schema_path']}:{f['json_path']}: {f['message']}", file=sys.stderr)
            if report.get("diagnosticsTruncated"):
                print("note: diagnostic findings truncated at threshold", file=sys.stderr)
            print("status=failed")

    return 0 if report["status"] == "passed" else 1


if __name__ == "__main__":
    sys.exit(main())
