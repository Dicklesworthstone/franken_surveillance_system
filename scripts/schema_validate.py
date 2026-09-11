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
DEFAULT_REGISTRIES_DIR = ROOT / "registries"
DEFAULT_SCHEMAS_MD = DEFAULT_REGISTRIES_DIR / "SCHEMAS.md"
DEFAULT_DIGEST_DOMAINS_MD = DEFAULT_REGISTRIES_DIR / "DIGEST_DOMAINS.md"
DEFAULT_ARCHITECTURE_DIR = ROOT / "architecture"
DEFAULT_CRATES_DIR = ROOT / "crates"

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
STABLE_ID_PATTERN = re.compile(r"^SCHEMA-[A-Z0-9]+(?:-[A-Z0-9]+)*$")
SCHEMA_NAME_PATTERN = re.compile(r"^fss\.[a-z0-9_.]+\.v\d+$")
VALID_SIMPLE_TYPES = frozenset({"null", "boolean", "object", "array", "number", "string", "integer"})

DEFAULT_MAX_DEPTH = 64
DEFAULT_MAX_ERRORS = 100
DEFAULT_MAX_FILE_BYTES = 10 * 1024 * 1024  # 10 MB
DEFAULT_BUDGET_WALL_NS = 30_000_000_000     # 30 seconds
DEFAULT_BUDGET_PEAK_BYTES = 256 * 1024 * 1024  # 256 MB
DEFAULT_BUDGET_WORK_UNITS = 1000

# Diagnostic Codes - Meta-Schema and References
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

# Diagnostic Codes - Schema Constitution & Implementation
CODE_DUPLICATE_STABLE_ID = "duplicate_stable_id"
CODE_DUPLICATE_SCHEMA_NAME = "duplicate_schema_name"
CODE_INVALID_STABLE_ID = "invalid_stable_id"
CODE_INVALID_SCHEMA_NAME = "invalid_schema_name"
CODE_MISSING_SCHEMA_FILE = "missing_schema_file"
CODE_UNREGISTERED_SCHEMA_FILE = "unregistered_schema_file"
CODE_SCHEMA_CONST_MISMATCH = "schema_const_mismatch"
CODE_SCHEMA_ID_MISMATCH = "schema_id_mismatch"
CODE_UNDECLARED_SCHEMA_REFERENCE = "undeclared_schema_reference"
CODE_UNOWNED_IMPLEMENTED_SCHEMA = "unowned_implemented_schema"
CODE_INVALID_IMPLEMENTATION_OWNER = "invalid_implementation_owner"
CODE_MALFORMED_REGISTRY_ROW = "malformed_registry_row"
CODE_UNREGISTERED_IMPLEMENTED_SCHEMA = "unregistered_implemented_schema"

CONSTITUTION_CODES = frozenset({
    CODE_DUPLICATE_STABLE_ID,
    CODE_DUPLICATE_SCHEMA_NAME,
    CODE_INVALID_STABLE_ID,
    CODE_INVALID_SCHEMA_NAME,
    CODE_MISSING_SCHEMA_FILE,
    CODE_UNREGISTERED_SCHEMA_FILE,
    CODE_SCHEMA_CONST_MISMATCH,
    CODE_SCHEMA_ID_MISMATCH,
    CODE_UNDECLARED_SCHEMA_REFERENCE,
    CODE_UNOWNED_IMPLEMENTED_SCHEMA,
    CODE_INVALID_IMPLEMENTATION_OWNER,
    CODE_MALFORMED_REGISTRY_ROW,
    CODE_UNREGISTERED_IMPLEMENTED_SCHEMA,
})


class SchemaValidationError(Exception):
    """Base exception for schema validation errors."""
    pass


class ValidatorUnavailableError(SchemaValidationError):
    pass


@dataclass(frozen=True)
class RustOwner:
    crate: str
    file: str
    type_name: str
    line: int

    def to_dict(self) -> dict[str, Any]:
        return {
            "crate": self.crate,
            "file": self.file,
            "type": self.type_name,
            "line": self.line,
        }


@dataclass(frozen=True)
class SchemaDeclaration:
    stable_id: str
    schema_name: str
    file_path: str
    authority: str
    compatibility_rule: str
    status: str  # "implemented" | "declared"
    owner: RustOwner | None = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "stableId": self.stable_id,
            "name": self.schema_name,
            "file": self.file_path,
            "authority": self.authority,
            "compatibilityRule": self.compatibility_rule,
            "status": self.status,
            "owner": self.owner.to_dict() if self.owner else None,
        }


@dataclass(frozen=True)
class DigestDomainDeclaration:
    stable_id: str
    domain_name: str
    scope: str
    authority: str
    invariant_rule: str

    def to_dict(self) -> dict[str, str]:
        return {
            "stableId": self.stable_id,
            "domain": self.domain_name,
            "scope": self.scope,
            "authority": self.authority,
            "invariantRule": self.invariant_rule,
        }


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
            resolved_tf = target_file.resolve()
            resolved_sd = schemas_dir.resolve()
            if not resolved_tf.is_relative_to(resolved_sd):
                if (resolved_sd / target_file.name).is_file():
                    resolved_tf = (resolved_sd / target_file.name).resolve()
            schema_files = [resolved_tf]
        else:
            schema_files = sorted(schemas_dir.glob("*.json"))

        case_fold_map: dict[str, str] = {}

        for file_path in schema_files:
            try:
                relative = file_path.resolve().relative_to(schemas_dir.resolve()).as_posix()
            except ValueError:
                relative = file_path.name
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


def strip_rust_comments(source: str) -> str:
    """Deterministic Rust comment stripper preserving newlines and line numbers."""
    result: list[str] = []
    i = 0
    n = len(source)
    while i < n:
        if source[i] == 'r' and (i + 1 < n and (source[i+1] == '"' or source[i+1] == '#')):
            m = re.match(r'r(#*)"', source[i:])
            if m:
                hashes = m.group(1)
                end_pat = f'"{hashes}'
                end_idx = source.find(end_pat, i + len(m.group(0)))
                if end_idx != -1:
                    result.append(source[i : end_idx + len(end_pat)])
                    i = end_idx + len(end_pat)
                    continue
        if source[i] == '"':
            start = i
            i += 1
            while i < n:
                if source[i] == '\\':
                    i += 2
                elif source[i] == '"':
                    i += 1
                    break
                else:
                    i += 1
            result.append(source[start:i])
            continue
        if source[i] == "'":
            next_nl = source.find('\n', i)
            limit = min(n, i + 12) if next_nl == -1 else min(n, i + 12, next_nl)
            is_char = False
            for j in range(i + 1, limit):
                if source[j] == '\\':
                    continue
                if source[j] == "'":
                    is_char = True
                    result.append(source[i : j + 1])
                    i = j + 1
                    break
            if is_char:
                continue
            result.append(source[i])
            i += 1
            continue
        if source[i:i+2] == '//':
            nl_idx = source.find('\n', i)
            if nl_idx == -1:
                break
            result.append('\n')
            i = nl_idx + 1
            continue
        if source[i:i+2] == '/*':
            depth = 1
            i += 2
            while i < n and depth > 0:
                if source[i:i+2] == '/*':
                    depth += 1
                    i += 2
                elif source[i:i+2] == '*/':
                    depth -= 1
                    i += 2
                elif source[i] == '\n':
                    result.append('\n')
                    i += 1
                else:
                    i += 1
            continue
        result.append(source[i])
        i += 1
    return "".join(result)


def scan_rust_schema_owners(crates_dir: Path) -> dict[str, RustOwner]:
    """Scan crates/fss-core/src (or crates directory) to discover Rust types encoding schemas."""
    owners: dict[str, RustOwner] = {}
    fss_core_src = crates_dir / "fss-core" / "src"
    if not fss_core_src.is_dir():
        if (crates_dir / "src").is_dir():
            fss_core_src = crates_dir / "src"
        else:
            return owners

    for rs_path in sorted(fss_core_src.rglob("*.rs")):
        rs_name = rs_path.name
        if rs_name == "tests.rs" or rs_name.endswith("_test.rs") or rs_name.endswith("_tests.rs"):
            continue
        if any(p in ("tests", "benches", "examples") for p in rs_path.parts):
            continue

        try:
            raw_text = rs_path.read_text(encoding="utf-8")
        except OSError:
            continue
        text = strip_rust_comments(raw_text)
        lines = text.splitlines()
        rel_path = rs_path.as_posix()
        if "crates/" in rel_path:
            rel_path = rel_path[rel_path.index("crates/"):]

        current_type = None
        brace_depth = 0
        in_test_cfg = False
        waiting_for_test_brace = False
        test_cfg_depth = 0

        for line_no, line in enumerate(lines, 1):
            stripped = line.strip()
            if not stripped:
                continue

            if "#[cfg(test)]" in stripped:
                waiting_for_test_brace = True
                test_cfg_depth = brace_depth

            if waiting_for_test_brace:
                open_b = line.count("{")
                close_b = line.count("}")
                brace_depth += open_b - close_b
                if "{" in line:
                    waiting_for_test_brace = False
                    in_test_cfg = True
                    if brace_depth <= test_cfg_depth:
                        in_test_cfg = False
                elif ";" in line:
                    waiting_for_test_brace = False
                continue

            if in_test_cfg:
                open_b = line.count("{")
                close_b = line.count("}")
                brace_depth += open_b - close_b
                if brace_depth <= test_cfg_depth:
                    in_test_cfg = False
                continue

            if brace_depth == 0:
                m_impl_trait = re.match(r'^\s*impl(?:<[^>]+>)?\s+[A-Za-z0-9_:]+(?:<[^>]+>)?\s+for\s+([A-Za-z0-9_]+)\b', line)
                m_impl = re.match(r'^\s*impl(?:<[^>]+>)?\s+([A-Za-z0-9_]+)(?:<[^>]+>)?\s*(?:where\b|\{)', line)
                m_struct = re.match(r'^\s*(?:pub(?:\([^)]+\))?\s+)?(?:struct|enum)\s+([A-Za-z0-9_]+)\b', line)

                if m_impl_trait:
                    current_type = m_impl_trait.group(1)
                elif m_impl:
                    current_type = m_impl.group(1)
                elif m_struct:
                    current_type = m_struct.group(1)

            for match in re.finditer(r'"(fss\.[a-z0-9_.]+\.v\d+)"', line):
                schema_name = match.group(1)
                resolved_type = current_type
                if not resolved_type:
                    for b_idx in range(line_no - 1, max(0, line_no - 80), -1):
                        b_line = lines[b_idx]
                        m1 = re.match(r'^\s*impl(?:<[^>]+>)?\s+[A-Za-z0-9_:]+(?:<[^>]+>)?\s+for\s+([A-Za-z0-9_]+)\b', b_line)
                        m2 = re.match(r'^\s*impl(?:<[^>]+>)?\s+([A-Za-z0-9_]+)(?:<[^>]+>)?\s*(?:where\b|\{)', b_line)
                        m3 = re.match(r'^\s*(?:pub(?:\([^)]+\))?\s+)?(?:struct|enum)\s+([A-Za-z0-9_]+)\b', b_line)
                        m = m1 or m2 or m3
                        if m:
                            resolved_type = m.group(1)
                            break

                if schema_name not in owners:
                    owners[schema_name] = RustOwner(
                        crate="fss-core",
                        file=rel_path,
                        type_name=resolved_type or "Unknown",
                        line=line_no,
                    )

            open_b = line.count("{")
            close_b = line.count("}")
            brace_depth += open_b - close_b
            if brace_depth <= 0:
                brace_depth = 0
                current_type = None

    return owners


def parse_schemas_md(schemas_md_path: Path) -> list[dict[str, str]]:
    """Parse table rows from registries/SCHEMAS.md."""
    if not schemas_md_path.is_file():
        raise SchemaValidationError(f"schemas registry not found: {schemas_md_path}")

    text = schemas_md_path.read_text(encoding="utf-8")
    rows: list[dict[str, str]] = []
    for line_no, line in enumerate(text.splitlines(), 1):
        stripped = line.strip()
        if not stripped.startswith("|") or stripped.startswith("|---"):
            continue
        parts = [p.strip().strip("`") for p in stripped.split("|")[1:-1]]
        if len(parts) >= 5 and parts[0] != "ID":
            rows.append({
                "id": parts[0],
                "schema": parts[1],
                "file": parts[2],
                "authority": parts[3],
                "rule": parts[4],
                "line": str(line_no),
            })
    return rows


def parse_digest_domains_md(digest_domains_path: Path) -> list[DigestDomainDeclaration]:
    """Parse table rows from registries/DIGEST_DOMAINS.md."""
    if not digest_domains_path.is_file():
        return []

    text = digest_domains_path.read_text(encoding="utf-8")
    domains: list[DigestDomainDeclaration] = []
    seen_ids: set[str] = set()
    seen_domains: set[str] = set()

    for line_no, line in enumerate(text.splitlines(), 1):
        stripped = line.strip()
        if not stripped.startswith("|") or stripped.startswith("|---"):
            continue
        parts = [p.strip().strip("`") for p in stripped.split("|")[1:-1]]
        if len(parts) >= 5 and parts[0] != "ID":
            sid, dname, scope, auth, rule = parts[0], parts[1], parts[2], parts[3], parts[4]
            if sid in seen_ids or dname in seen_domains:
                continue
            seen_ids.add(sid)
            seen_domains.add(dname)
            domains.append(
                DigestDomainDeclaration(
                    stable_id=sid,
                    domain_name=dname,
                    scope=scope,
                    authority=auth,
                    invariant_rule=rule,
                )
            )
    return domains


def extract_architecture_schema_references(architecture_dir: Path) -> list[tuple[str, str, str]]:
    """Extract schema references from architecture/*.json documents.
    
    Returns list of tuples: (arch_relative_path, json_pointer_path, schema_name).
    """
    references: list[tuple[str, str, str]] = []
    if not architecture_dir.is_dir():
        return references

    for arch_path in sorted(architecture_dir.glob("*.json")):
        try:
            data = json.loads(arch_path.read_text(encoding="utf-8"))
        except Exception:
            continue
        rel = f"architecture/{arch_path.name}"

        def walk(val: Any, ptr: str) -> None:
            if isinstance(val, dict):
                for k, v in val.items():
                    walk(v, f"{ptr}/{k}")
            elif isinstance(val, list):
                for idx, item in enumerate(val):
                    walk(item, f"{ptr}/{idx}")
            elif isinstance(val, str):
                if ptr != "#/schema" and SCHEMA_NAME_PATTERN.match(val):
                    references.append((rel, ptr, val))

        walk(data, "#")
    return references


def validate_schema_constitution(
    repo_root: Path = ROOT,
    schemas_dir: Path = DEFAULT_SCHEMAS_DIR,
    schemas_md_path: Path = DEFAULT_SCHEMAS_MD,
    architecture_dir: Path = DEFAULT_ARCHITECTURE_DIR,
    crates_dir: Path = DEFAULT_CRATES_DIR,
    validator: Validator | None = None,
    digest_domains_path: Path | None = None,
    claimed_statuses: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """Validate complete schema constitution, uniqueness, references, and declaration vs implementation.
    
    Enforces that:
    1. Every schema declared in registries/SCHEMAS.md has a valid, unique stable ID and schema name.
    2. Every registered schema file exists on disk, declares matching schema const and valid $id.
    3. Every schema file in schemas/*.json is registered in SCHEMAS.md (no unregistered schema files).
    4. Every schema referenced in architecture/*.json is declared in SCHEMAS.md (no dangling references).
    5. 'declared' vs 'implemented' is machine-checked from fss-core Rust types; no schema may be
       reported as implemented without a verified named Rust owner.
    """
    if validator is None:
        validator = Validator()

    if not schemas_md_path.is_file():
        validator.emit(
            CODE_INCOMPLETE_CATALOG,
            schemas_md_path.as_posix(),
            "#",
            f"schemas registry markdown file not found: {schemas_md_path}",
        )
        return {
            "status": "failed",
            "totalDeclared": 0,
            "implementedCount": 0,
            "declaredOnlyCount": 0,
            "architectureReferenceCount": 0,
            "constitutionDigest": "",
            "schemas": [],
        }

    try:
        raw_rows = parse_schemas_md(schemas_md_path)
    except Exception as exc:
        validator.emit(CODE_MALFORMED_REGISTRY_ROW, schemas_md_path.as_posix(), "#", str(exc))
        return {
            "status": "failed",
            "totalDeclared": 0,
            "implementedCount": 0,
            "declaredOnlyCount": 0,
            "architectureReferenceCount": 0,
            "constitutionDigest": "",
            "schemas": [],
        }

    seen_ids: dict[str, str] = {}
    seen_names: dict[str, str] = {}
    seen_files: set[str] = set()

    # Step 1: Parse rows & check syntax, uniqueness, file existence, and property constraints
    for row in raw_rows:
        sid = row["id"]
        sname = row["schema"]
        fpath = row["file"]
        lno = row["line"]

        if not STABLE_ID_PATTERN.match(sid):
            validator.emit(
                CODE_INVALID_STABLE_ID,
                schemas_md_path.as_posix(),
                f"#{lno}/ID",
                f"invalid stable ID syntax: '{sid}' (must match {STABLE_ID_PATTERN.pattern})",
            )
        if not SCHEMA_NAME_PATTERN.match(sname):
            validator.emit(
                CODE_INVALID_SCHEMA_NAME,
                schemas_md_path.as_posix(),
                f"#{lno}/Schema",
                f"invalid schema name syntax: '{sname}' (must match {SCHEMA_NAME_PATTERN.pattern})",
            )

        if sid in seen_ids:
            validator.emit(
                CODE_DUPLICATE_STABLE_ID,
                schemas_md_path.as_posix(),
                f"#{lno}/ID",
                f"duplicate stable ID '{sid}' (previously defined at line {seen_ids[sid]})",
            )
        else:
            seen_ids[sid] = lno

        if sname in seen_names:
            validator.emit(
                CODE_DUPLICATE_SCHEMA_NAME,
                schemas_md_path.as_posix(),
                f"#{lno}/Schema",
                f"duplicate schema name '{sname}' (previously defined at line {seen_names[sname]})",
            )
        else:
            seen_names[sname] = lno

        if fpath != "CLI output":
            if not (fpath.startswith("schemas/") or fpath.startswith("architecture/")):
                validator.emit(
                    CODE_MALFORMED_REGISTRY_ROW,
                    schemas_md_path.as_posix(),
                    f"#{lno}/File",
                    f"schema file path '{fpath}' must reside in schemas/ directory",
                )
            if fpath in seen_files:
                validator.emit(
                    CODE_MALFORMED_REGISTRY_ROW,
                    schemas_md_path.as_posix(),
                    f"#{lno}/File",
                    f"duplicate schema file path in registry: '{fpath}'",
                )
            seen_files.add(fpath)

            disk_path = repo_root / fpath
            if not disk_path.is_file():
                validator.emit(
                    CODE_MISSING_SCHEMA_FILE,
                    schemas_md_path.as_posix(),
                    f"#{lno}/File",
                    f"registered schema file does not exist: '{fpath}'",
                )
            else:
                try:
                    doc = json.loads(disk_path.read_text(encoding="utf-8"))
                    if isinstance(doc, dict):
                        const_val = doc.get("properties", {}).get("schema", {}).get("const")
                        if const_val != sname:
                            validator.emit(
                                CODE_SCHEMA_CONST_MISMATCH,
                                fpath,
                                "#/properties/schema/const",
                                f"schema const mismatch: expected '{sname}', found '{const_val}'",
                            )
                        doc_id = str(doc.get("$id", ""))
                        if not doc_id.endswith("/" + disk_path.name):
                            validator.emit(
                                CODE_SCHEMA_ID_MISMATCH,
                                fpath,
                                "#/$id",
                                f"schema $id '{doc_id}' does not match filename '/{disk_path.name}'",
                            )
                except Exception as exc:
                    validator.emit(CODE_MALFORMED_JSON, fpath, "#", f"cannot parse schema json: {exc}")

    # Step 1.5: Parse & validate canonical digest domains from DIGEST_DOMAINS.md
    d_path = digest_domains_path or (schemas_md_path.parent / "DIGEST_DOMAINS.md")
    registered_domains: list[DigestDomainDeclaration] = []
    seen_domain_ids: dict[str, str] = {}
    seen_domain_names: dict[str, str] = {}

    if d_path.is_file():
        text = d_path.read_text(encoding="utf-8")
        for line_no, line in enumerate(text.splitlines(), 1):
            stripped = line.strip()
            if not stripped.startswith("|") or stripped.startswith("|---"):
                continue
            parts = [p.strip().strip("`") for p in stripped.split("|")[1:-1]]
            if len(parts) >= 5 and parts[0] != "ID":
                sid, dname, scope, auth, rule = parts[0], parts[1], parts[2], parts[3], parts[4]
                if not STABLE_ID_PATTERN.match(sid):
                    validator.emit(
                        CODE_INVALID_STABLE_ID,
                        d_path.as_posix(),
                        f"#{line_no}/ID",
                        f"invalid stable ID syntax: '{sid}' (must match {STABLE_ID_PATTERN.pattern})",
                    )
                if not SCHEMA_NAME_PATTERN.match(dname):
                    validator.emit(
                        CODE_INVALID_SCHEMA_NAME,
                        d_path.as_posix(),
                        f"#{line_no}/Domain",
                        f"invalid domain name syntax: '{dname}' (must match {SCHEMA_NAME_PATTERN.pattern})",
                    )
                if sid in seen_ids or sid in seen_domain_ids:
                    validator.emit(
                        CODE_DUPLICATE_STABLE_ID,
                        d_path.as_posix(),
                        f"#{line_no}/ID",
                        f"duplicate stable ID '{sid}' in {d_path.name}",
                    )
                else:
                    seen_domain_ids[sid] = str(line_no)

                if dname in seen_names or dname in seen_domain_names:
                    validator.emit(
                        CODE_DUPLICATE_SCHEMA_NAME,
                        d_path.as_posix(),
                        f"#{line_no}/Domain",
                        f"duplicate domain name '{dname}' in {d_path.name}",
                    )
                else:
                    seen_domain_names[dname] = str(line_no)

                registered_domains.append(
                    DigestDomainDeclaration(
                        stable_id=sid,
                        domain_name=dname,
                        scope=scope,
                        authority=auth,
                        invariant_rule=rule,
                    )
                )

    all_registered_names = set(seen_names) | set(seen_domain_names)

    # Step 2: Check for unregistered schema files on disk
    if schemas_dir.is_dir():
        for sf in sorted(schemas_dir.glob("*.json")):
            try:
                rel_sf = sf.resolve().relative_to(repo_root.resolve()).as_posix()
            except ValueError:
                rel_sf = f"schemas/{sf.name}"
            if rel_sf not in seen_files:
                validator.emit(
                    CODE_UNREGISTERED_SCHEMA_FILE,
                    rel_sf,
                    "#",
                    f"schema file '{rel_sf}' exists on disk but is not declared in registry {schemas_md_path.name}",
                )

    # Step 3: Check architecture schema references
    arch_refs = extract_architecture_schema_references(architecture_dir)
    for arch_file, ptr, ref_sname in arch_refs:
        if ref_sname not in all_registered_names:
            validator.emit(
                CODE_UNDECLARED_SCHEMA_REFERENCE,
                arch_file,
                ptr,
                f"referenced schema '{ref_sname}' is not declared in registry {schemas_md_path.name}",
            )

    # Step 4: Scan Rust owners in crates/fss-core and classify declared vs implemented
    rust_owners = scan_rust_schema_owners(crates_dir)

    declarations: list[SchemaDeclaration] = []
    seen_decl_ids: set[str] = set()
    for row in raw_rows:
        sid = row["id"]
        if sid in seen_decl_ids:
            continue
        seen_decl_ids.add(sid)

        sname = row["schema"]
        fpath = row["file"]
        auth = row["authority"]
        rule = row["rule"]

        owner = rust_owners.get(sname)
        if owner is not None:
            owner_file = repo_root / owner.file
            if not owner_file.is_file():
                validator.emit(
                    CODE_INVALID_IMPLEMENTATION_OWNER,
                    schemas_md_path.as_posix(),
                    f"#{sname}",
                    f"Rust owner file does not exist: {owner.file}",
                )
                status = "declared"
                owner = None
            elif owner.type_name == "Unknown":
                validator.emit(
                    CODE_UNOWNED_IMPLEMENTED_SCHEMA,
                    schemas_md_path.as_posix(),
                    f"#{sname}",
                    f"schema '{sname}' has unknown Rust owner type in {owner.file}",
                )
                status = "declared"
                owner = None
            else:
                status = "implemented"
        else:
            status = "declared"

        decl = SchemaDeclaration(
            stable_id=sid,
            schema_name=sname,
            file_path=fpath,
            authority=auth,
            compatibility_rule=rule,
            status=status,
            owner=owner if status == "implemented" else None,
        )

        # Invariant: no schema may be reported as implemented without a named Rust owner
        if decl.status == "implemented" and decl.owner is None:
            validator.emit(
                CODE_UNOWNED_IMPLEMENTED_SCHEMA,
                schemas_md_path.as_posix(),
                f"#{sname}",
                f"schema '{sname}' reported as implemented without a named Rust owner",
            )

        declarations.append(decl)

    # Step 5: Validate external / claimed statuses if provided
    if claimed_statuses is not None:
        for claim_sname, claim_val in claimed_statuses.items():
            if isinstance(claim_val, dict):
                claim_status = claim_val.get("status")
                claim_owner = claim_val.get("owner")
            else:
                claim_status = str(claim_val)
                claim_owner = None

            actual_owner = rust_owners.get(claim_sname)
            if claim_status == "implemented":
                if actual_owner is None:
                    validator.emit(
                        CODE_UNOWNED_IMPLEMENTED_SCHEMA,
                        schemas_md_path.as_posix(),
                        f"#{claim_sname}",
                        f"schema '{claim_sname}' claimed as implemented but has no named Rust owner in fss-core",
                    )
                elif claim_owner is not None:
                    if isinstance(claim_owner, dict):
                        claimed_type = claim_owner.get("type")
                        if claimed_type and claimed_type != actual_owner.type_name:
                            validator.emit(
                                CODE_INVALID_IMPLEMENTATION_OWNER,
                                schemas_md_path.as_posix(),
                                f"#{claim_sname}",
                                f"schema '{claim_sname}' claimed owner type '{claimed_type}' does not match actual Rust owner '{actual_owner.type_name}'",
                            )

    # Step 5.5: Detect drift - schemas or digest domains implemented in Rust but not registered
    unregistered_decls: list[dict[str, Any]] = []
    for unreg_sname, unreg_owner in sorted(rust_owners.items()):
        if unreg_sname not in all_registered_names:
            validator.emit(
                CODE_UNREGISTERED_IMPLEMENTED_SCHEMA,
                unreg_owner.file,
                f"#{unreg_sname}",
                f"identifier '{unreg_sname}' is implemented in Rust ({unreg_owner.file}:{unreg_owner.line}) but not declared in registries (neither {schemas_md_path.name} nor {d_path.name})",
                severity="error",
            )
            unregistered_decls.append({
                "name": unreg_sname,
                "owner": unreg_owner.to_dict(),
            })

    # Step 6: Compute deterministic constitution digest
    sorted_decls = sorted(declarations, key=lambda d: d.stable_id)
    schemas_md_raw = schemas_md_path.read_bytes() if schemas_md_path.is_file() else b""
    schemas_md_digest = "sha256:" + hashlib.sha256(schemas_md_raw).hexdigest()

    sorted_domains = sorted(registered_domains, key=lambda d: d.stable_id)
    digest_domains_raw = d_path.read_bytes() if d_path.is_file() else b""
    digest_domains_digest = "sha256:" + hashlib.sha256(digest_domains_raw).hexdigest()

    const_payload = {
        "schemasMdDigest": schemas_md_digest,
        "digestDomainsMdDigest": digest_domains_digest,
        "declarations": [d.to_dict() for d in sorted_decls],
        "digestDomains": [d.to_dict() for d in sorted_domains],
    }
    constitution_digest = "sha256:" + hashlib.sha256(canonical_json_bytes(const_payload)).hexdigest()

    has_const_error = any(f.code in CONSTITUTION_CODES and f.severity == "error" for f in validator.findings)
    const_status = "failed" if has_const_error else "passed"

    return {
        "status": const_status,
        "totalDeclared": len(declarations),
        "implementedCount": sum(1 for d in declarations if d.status == "implemented"),
        "declaredOnlyCount": sum(1 for d in declarations if d.status == "declared"),
        "architectureReferenceCount": len(arch_refs),
        "digestDomainCount": len(registered_domains),
        "digestDomains": [d.to_dict() for d in sorted_domains],
        "unregisteredImplementedCount": len(unregistered_decls),
        "unregisteredImplementedSchemas": unregistered_decls,
        "constitutionDigest": constitution_digest,
        "schemas": [d.to_dict() for d in sorted_decls],
    }


def audit(
    schemas_dir: Path = DEFAULT_SCHEMAS_DIR,
    target_file: Path | None = None,
    registries_dir: Path = DEFAULT_REGISTRIES_DIR,
    schemas_md_path: Path | None = None,
    digest_domains_path: Path | None = None,
    architecture_dir: Path = DEFAULT_ARCHITECTURE_DIR,
    crates_dir: Path = DEFAULT_CRATES_DIR,
    check_constitution: bool = True,
    constitution_only: bool = False,
    claimed_statuses: dict[str, Any] | None = None,
    max_depth: int = DEFAULT_MAX_DEPTH,
    max_errors: int = DEFAULT_MAX_ERRORS,
    max_file_bytes: int = DEFAULT_MAX_FILE_BYTES,
    budget_wall_ns: int = DEFAULT_BUDGET_WALL_NS,
    budget_peak_bytes: int = DEFAULT_BUDGET_PEAK_BYTES,
    budget_work_units: int = DEFAULT_BUDGET_WORK_UNITS,
) -> dict[str, Any]:
    """Execute complete deterministic Draft 2020-12 meta-schema, reference, and constitution validation."""
    start_wall_ns = time.perf_counter_ns()
    times_start = os.times()

    validator = Validator(
        max_depth=max_depth,
        max_errors=max_errors,
        max_file_bytes=max_file_bytes,
        require_object_root=True,
    )

    catalog = SchemaCatalog(schemas_dir)
    if not constitution_only:
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

    # Validate schema constitution when not scoped to a single target file
    effective_check_constitution = (
        check_constitution
        and (target_file is None or constitution_only)
        and (schemas_dir.resolve() == DEFAULT_SCHEMAS_DIR.resolve() or schemas_md_path is not None or constitution_only)
    )
    constitution_report: dict[str, Any] | None = None
    if effective_check_constitution:
        s_md = schemas_md_path or (registries_dir / "SCHEMAS.md")
        d_md = digest_domains_path or (registries_dir / "DIGEST_DOMAINS.md")
        constitution_report = validate_schema_constitution(
            repo_root=ROOT,
            schemas_dir=schemas_dir,
            schemas_md_path=s_md,
            digest_domains_path=d_md,
            architecture_dir=architecture_dir,
            crates_dir=crates_dir,
            validator=validator,
            claimed_statuses=claimed_statuses,
        )

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

    error_findings = [f for f in findings_sorted if f.severity == "error"]
    status = "passed" if not error_findings else "failed"

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
    if constitution_report is not None:
        used_work_units += constitution_report.get("totalDeclared", 0) + constitution_report.get("digestDomainCount", 0)

    report: dict[str, Any] = {
        "schema": "fss.schema_validation_receipt.v1",
        "status": status,
        "schemaCount": schema_count,
        "referenceCount": validator.reference_count,
        "cycleCount": len(getattr(validator, "cycles", [])),
        "cycles": sorted(getattr(validator, "cycles", [])),
        "diagnosticCardinality": len(findings_sorted),
        "errorCount": len(error_findings),
        "warningCount": sum(1 for f in findings_sorted if f.severity == "warning"),
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

    if constitution_report is not None:
        report["constitution"] = constitution_report
        report["constitutionDigest"] = constitution_report.get("constitutionDigest", "")

    report["proofHash"] = "sha256:" + hashlib.sha256(canonical_json_bytes(report)).hexdigest()
    return report


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Deterministic offline Draft 2020-12 meta-schema, reference, and schema constitution validator"
    )
    parser.add_argument("--schemas-dir", type=Path, default=DEFAULT_SCHEMAS_DIR, help="Path to schemas directory")
    parser.add_argument("--registries-dir", type=Path, default=DEFAULT_REGISTRIES_DIR, help="Path to registries directory")
    parser.add_argument("--schemas-md", type=Path, default=None, help="Path to SCHEMAS.md registry file")
    parser.add_argument("--digest-domains-md", type=Path, default=None, help="Path to DIGEST_DOMAINS.md registry file")
    parser.add_argument("--architecture-dir", type=Path, default=DEFAULT_ARCHITECTURE_DIR, help="Path to architecture directory")
    parser.add_argument("--crates-dir", type=Path, default=DEFAULT_CRATES_DIR, help="Path to crates directory")
    parser.add_argument("--schema", type=Path, default=None, help="Validate specific schema file")
    parser.add_argument("--skip-constitution", action="store_true", help="Skip schema constitution validation")
    parser.add_argument("--constitution-only", action="store_true", help="Only validate schema constitution and declaration vs implementation")
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
            registries_dir=args.registries_dir,
            schemas_md_path=args.schemas_md,
            digest_domains_path=args.digest_domains_md,
            architecture_dir=args.architecture_dir,
            crates_dir=args.crates_dir,
            check_constitution=not args.skip_constitution,
            constitution_only=args.constitution_only,
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
            if "constitution" in report:
                const = report["constitution"]
                c_dec = const.get("totalDeclared", 0)
                c_imp = const.get("implementedCount", 0)
                c_only = const.get("declaredOnlyCount", 0)
                c_dom = const.get("digestDomainCount", 0)
                c_unreg = const.get("unregisteredImplementedCount", 0)
                print(f"constitution: {c_dec} declared ({c_imp} implemented, {c_only} declared-only), 0 unowned, {c_dom} digest domains, {c_unreg} unregistered")
                print(f"constitutionDeclared={c_dec}")
                print(f"constitutionImplemented={c_imp}")
                print(f"constitutionDeclaredOnly={c_only}")
                print(f"constitutionDigestDomains={c_dom}")
                print(f"constitutionUnregistered={c_unreg}")
                if "constitutionDigest" in report:
                    print(f"constitutionDigest={report['constitutionDigest']}")
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
