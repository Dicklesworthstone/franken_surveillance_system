#!/usr/bin/env python3
"""Fail-closed agent operation registry checker (fss-x4a.30.83.17).

Enforces the registered `fss/1` operation contract (AOP-001..AOP-014):
1. Operation registry row drift between architecture JSON and markdown mirror (ERR-OP-REGISTRY-DRIFT-001)
2. Stable ID reused, duplicated, renumbered, or diverging from the canonical row set (ERR-OP-STABLE-ID-REUSED-001)
3. Missing or empty mandatory field in an operation row or top-level metadata (ERR-OP-MISSING-FIELD-001)
4. Corrupt or missing mandatory registry files (ERR-OP-CORRUPT-FILE-001)
5. Operation semantic invariant violation: effect/mode contradiction, durability
   contradiction, unregistered view/payload/capability/gate/retry spelling, frozen
   public-registry disagreement (ERR-OP-SEMANTIC-INVARIANT-001)
6. Typed Rust operation table drift versus the machine registry; a missing
   crates/fss-core/src/agent_operation.rs is a failure, never a skip (ERR-OP-RUST-DRIFT-001)
"""
from __future__ import annotations

import argparse
import json
import re
import sys
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]

# Registered stable diagnostic finding IDs (registries/ERRORS.md)
ERR_OP_REGISTRY_DRIFT = "ERR-OP-REGISTRY-DRIFT-001"
ERR_OP_STABLE_ID_REUSED = "ERR-OP-STABLE-ID-REUSED-001"
ERR_OP_MISSING_FIELD = "ERR-OP-MISSING-FIELD-001"
ERR_OP_CORRUPT_FILE = "ERR-OP-CORRUPT-FILE-001"
ERR_OP_SEMANTIC_INVARIANT = "ERR-OP-SEMANTIC-INVARIANT-001"
ERR_OP_RUST_DRIFT = "ERR-OP-RUST-DRIFT-001"

AGENT_OPERATIONS_JSON_PATH = "architecture/agent_operations.json"
AGENT_OPERATIONS_MD_PATH = "registries/AGENT_OPERATIONS.md"
FROZEN_PUBLIC_REGISTRY_PATH = "architecture/fss1_public_registry.json"
AGENT_OPERATION_RS_PATH = "crates/fss-core/src/agent_operation.rs"
AGENT_VIEWS_JSON_PATH = "architecture/agent_views.json"
AGENT_VIEWS_MD_PATH = "registries/AGENT_VIEWS.md"
AGENT_VIEW_RS_PATH = "crates/fss-core/src/agent_view.rs"

# Views: registered stable diagnostic finding IDs (registries/ERRORS.md)
ERR_VW_REGISTRY_DRIFT = "ERR-VW-REGISTRY-DRIFT-001"
ERR_VW_STABLE_ID_REUSED = "ERR-VW-STABLE-ID-REUSED-001"
ERR_VW_MISSING_FIELD = "ERR-VW-MISSING-FIELD-001"
ERR_VW_CORRUPT_FILE = "ERR-VW-CORRUPT-FILE-001"
ERR_VW_SEMANTIC_INVARIANT = "ERR-VW-SEMANTIC-INVARIANT-001"
ERR_VW_RUST_DRIFT = "ERR-VW-RUST-DRIFT-001"

EXPECTED_VIEW_IDS = [f"AVIEW-{i:03d}" for i in range(1, 9)]
VIEW_ROW_KEYS = [
    "id", "name", "owner", "purpose", "requiredSections",
    "targetTokens", "maximumTokens", "gate", "status",
]
CANONICAL_VIEW_ROW_RE = re.compile(r'"(AVIEW-\d{3}\|[^"\n]+)"')

EXPECTED_IDS = [f"AOP-{i:03d}" for i in range(1, 15)]

REGISTERED_MODES = {
    "session_control",
    "read",
    "read_wait",
    "read_compile",
    "read_compute",
    "cognition_write",
    "plan_prepare",
    "effect_commit",
    "lifecycle_effect",
    "continuity_publish",
    "advisory_write",
    "diagnostic_prepare",
}
EFFECT_MODES = {"effect_commit", "lifecycle_effect"}
EPHEMERAL_MODES = {"read", "read_compile", "read_compute"}
REGISTERED_RETRY_CLASSES = {
    "never_unchanged",
    "backoff",
    "operator_action_required",
    "resume_from_continuation",
    "safe_read_retry",
    "refresh_and_retry",
    "rebase_required",
    "reconciliation_required",
}
REGISTERED_GATE = "QL-AGENT-001"
REQUEST_ENVELOPE_SCHEMA = "fss.agent_request_envelope.v1"
RESPONSE_ENVELOPE_SCHEMA = "fss.agent_response_envelope.v1"
REGISTERED_STATUS = "specified"

ROW_KEYS = [
    "id",
    "name",
    "purpose",
    "mode",
    "owner",
    "defaultView",
    "effectful",
    "durable",
    "requiredCapabilities",
    "inputSchema",
    "outputSchema",
    "retryClasses",
    "gate",
    "status",
    "requestPayloadSchema",
    "responsePayloadSchemas",
]

DELIMITER_ROW_RE = re.compile(r"^\s*\|(?:\s*:?-+:?\s*\|)+\s*$")
CANONICAL_ROW_RE = re.compile(r'"(AOP-\d{3}\|[^"\n]+)"')


@dataclass(frozen=True)
class DiagnosticError:
    code: str
    file_path: str
    target: str
    message: str


@dataclass
class ValidationResult:
    passed: bool = True
    operation_count: int = 0
    view_count: int = 0
    errors: list[DiagnosticError] = field(default_factory=list)

    def add_error(self, code: str, file_path: str, target: str, message: str) -> None:
        self.passed = False
        self.errors.append(
            DiagnosticError(code=code, file_path=file_path, target=target, message=message)
        )


def parse_markdown_table(file_path: Path) -> list[dict[str, str]]:
    """Parses a GitHub-flavored Markdown table into row dictionaries keyed by header."""
    if not file_path.is_file():
        return []
    try:
        lines = file_path.read_text(encoding="utf-8").splitlines()
    except OSError:
        return []

    header: list[str] = []
    rows: list[dict[str, str]] = []
    for line in lines:
        stripped = line.strip()
        if not stripped.startswith("|") or not stripped.endswith("|"):
            continue
        cells = [cell.strip().strip("`") for cell in stripped[1:-1].split("|")]
        if DELIMITER_ROW_RE.match(stripped):
            continue
        if not header:
            header = cells
            continue
        row = dict(zip(header, cells))
        if row.get("ID"):
            rows.append(row)
    return rows


def canonical_fields_from_text(text: str) -> dict[str, Any] | None:
    """Parses one canonical Rust row literal into the machine field set."""
    fields = text.split("|")
    if len(fields) != 14:
        return None
    return {
        "id": fields[0],
        "name": fields[1],
        "mode": fields[2],
        "owner": fields[3],
        "defaultView": fields[4],
        "requestPayloadSchema": fields[5],
        "responsePayloadSchemas": fields[6].split(";") if fields[6] else [],
        "inputSchema": fields[7],
        "outputSchema": fields[8],
        "effectful": fields[9] == "1",
        "durable": fields[10] == "1",
        "gate": fields[11],
        "requiredCapabilities": fields[12].split(";") if fields[12] else [],
        "retryClasses": fields[13].split(";") if fields[13] else [],
    }


def extract_rust_canonical_rows(rs_path: Path) -> dict[str, str]:
    """Extracts canonical row literals from `canonical_row_encoding` match arms."""
    content = rs_path.read_text(encoding="utf-8")
    fn_start = content.index("pub const fn canonical_row_encoding(self)")
    fn_body = content[fn_start:]
    return {
        text.split("|", 1)[0]: text for text in CANONICAL_ROW_RE.findall(fn_body)
    }


def canonical_fields_from_json(row: dict[str, Any]) -> dict[str, Any]:
    return {
        "id": row["id"],
        "name": row["name"],
        "mode": row["mode"],
        "owner": row["owner"],
        "defaultView": row["defaultView"],
        "requestPayloadSchema": row["requestPayloadSchema"],
        "responsePayloadSchemas": list(row["responsePayloadSchemas"]),
        "inputSchema": row["inputSchema"],
        "outputSchema": row["outputSchema"],
        "effectful": bool(row["effectful"]),
        "durable": bool(row["durable"]),
        "gate": row["gate"],
        "requiredCapabilities": list(row["requiredCapabilities"]),
        "retryClasses": list(row["retryClasses"]),
    }


def validate_row_semantics(
    row: dict[str, Any], result: ValidationResult, file_path: str
) -> None:
    opid = row.get("id", "?")
    target = f"#/operations/{opid}"
    mode = row["mode"]
    if mode not in REGISTERED_MODES:
        result.add_error(
            ERR_OP_SEMANTIC_INVARIANT, file_path, f"{target}/mode",
            f"operation '{opid}' has unregistered mode '{mode}'",
        )
        return
    if row["effectful"] != (mode in EFFECT_MODES):
        result.add_error(
            ERR_OP_SEMANTIC_INVARIANT, file_path, f"{target}/effectful",
            f"operation '{opid}' effectful={row['effectful']} contradicts mode '{mode}'",
        )
    if row["durable"] != (mode not in EPHEMERAL_MODES):
        result.add_error(
            ERR_OP_SEMANTIC_INVARIANT, file_path, f"{target}/durable",
            f"operation '{opid}' durable={row['durable']} contradicts mode '{mode}'",
        )
    if row["effectful"] and not row["durable"]:
        result.add_error(
            ERR_OP_SEMANTIC_INVARIANT, file_path, f"{target}/durable",
            f"effectful operation '{opid}' must be durable",
        )
    if not re.fullmatch(r"AVIEW-\d{3}", row["defaultView"]):
        result.add_error(
            ERR_OP_SEMANTIC_INVARIANT, file_path, f"{target}/defaultView",
            f"operation '{opid}' default view '{row['defaultView']}' is not an AVIEW identity",
        )
    for schema_field in ("requestPayloadSchema", "inputSchema", "outputSchema"):
        value = row[schema_field]
        if not value.startswith("fss."):
            result.add_error(
                ERR_OP_SEMANTIC_INVARIANT, file_path, f"{target}/{schema_field}",
                f"operation '{opid}' schema '{value}' is not an fss. schema identity",
            )
    if not row["responsePayloadSchemas"]:
        result.add_error(
            ERR_OP_SEMANTIC_INVARIANT, file_path, f"{target}/responsePayloadSchemas",
            f"operation '{opid}' must declare at least one response payload schema",
        )
    for schema in row["responsePayloadSchemas"]:
        if not schema.startswith("fss."):
            result.add_error(
                ERR_OP_SEMANTIC_INVARIANT, file_path, f"{target}/responsePayloadSchemas",
                f"operation '{opid}' response schema '{schema}' is not an fss. identity",
            )
    if not row["requiredCapabilities"]:
        result.add_error(
            ERR_OP_SEMANTIC_INVARIANT, file_path, f"{target}/requiredCapabilities",
            f"operation '{opid}' must require at least one capability",
        )
    for capability in row["requiredCapabilities"]:
        if not capability.startswith("CAP-"):
            result.add_error(
                ERR_OP_SEMANTIC_INVARIANT, file_path, f"{target}/requiredCapabilities",
                f"operation '{opid}' capability '{capability}' is not a CAP identity",
            )
    if row["gate"] != REGISTERED_GATE:
        result.add_error(
            ERR_OP_SEMANTIC_INVARIANT, file_path, f"{target}/gate",
            f"operation '{opid}' gate '{row['gate']}' diverges from '{REGISTERED_GATE}'",
        )
    for retry in row["retryClasses"]:
        if retry not in REGISTERED_RETRY_CLASSES:
            result.add_error(
                ERR_OP_SEMANTIC_INVARIANT, file_path, f"{target}/retryClasses",
                f"operation '{opid}' has unregistered retry class '{retry}'",
            )
    if row["status"] != REGISTERED_STATUS:
        result.add_error(
            ERR_OP_SEMANTIC_INVARIANT, file_path, f"{target}/status",
            f"operation '{opid}' status '{row['status']}' diverges from baseline "
            f"'{REGISTERED_STATUS}'; a transition requires a registry generation bump",
        )


def validate_agent_operation_registry(repo_root: Path) -> ValidationResult:
    result = ValidationResult()

    json_path = repo_root / AGENT_OPERATIONS_JSON_PATH
    md_path = repo_root / AGENT_OPERATIONS_MD_PATH
    frozen_path = repo_root / FROZEN_PUBLIC_REGISTRY_PATH
    rs_path = repo_root / AGENT_OPERATION_RS_PATH

    # 4. Corrupt or missing mandatory files.
    operations: list[dict[str, Any]] = []
    if not json_path.is_file():
        result.add_error(
            ERR_OP_CORRUPT_FILE, AGENT_OPERATIONS_JSON_PATH, "#", "missing mandatory registry file"
        )
    else:
        try:
            doc = json.loads(json_path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError) as exc:
            result.add_error(
                ERR_OP_CORRUPT_FILE, AGENT_OPERATIONS_JSON_PATH, "#", f"corrupt registry file: {exc}"
            )
            doc = None
        if isinstance(doc, dict):
            if doc.get("schema") != "fss.agent_operations.v1":
                result.add_error(
                    ERR_OP_MISSING_FIELD, AGENT_OPERATIONS_JSON_PATH, "#/schema",
                    "registry schema must be fss.agent_operations.v1",
                )
            for metadata_field in ("asOf", "semanticProtocol", "worldEnvelopeRule"):
                value = doc.get(metadata_field)
                if not isinstance(value, str) or not value.strip():
                    result.add_error(
                        ERR_OP_MISSING_FIELD, AGENT_OPERATIONS_JSON_PATH, f"#/{metadata_field}",
                        "missing or empty top-level metadata",
                    )
            if doc.get("semanticProtocol") != "fss/1":
                result.add_error(
                    ERR_OP_SEMANTIC_INVARIANT, AGENT_OPERATIONS_JSON_PATH, "#/semanticProtocol",
                    "operation registry must pin semantic protocol fss/1",
                )
            raw_operations = doc.get("operations")
            if not isinstance(raw_operations, list):
                result.add_error(
                    ERR_OP_CORRUPT_FILE, AGENT_OPERATIONS_JSON_PATH, "#/operations",
                    "missing mandatory 'operations' collection",
                )
            else:
                operations = [op for op in raw_operations if isinstance(op, dict)]

    if not md_path.is_file():
        result.add_error(
            ERR_OP_CORRUPT_FILE, AGENT_OPERATIONS_MD_PATH, "#", "missing mandatory registry mirror"
        )
    if not frozen_path.is_file():
        result.add_error(
            ERR_OP_CORRUPT_FILE, FROZEN_PUBLIC_REGISTRY_PATH, "#", "missing frozen public registry"
        )
    if not rs_path.is_file():
        result.add_error(
            ERR_OP_RUST_DRIFT, AGENT_OPERATION_RS_PATH, "#",
            "missing typed operation table crates/fss-core/src/agent_operation.rs",
        )
    if result.errors:
        return result

    # 2. Stable IDs: exact canonical set, no duplicates, no renumbering.
    json_map: dict[str, dict[str, Any]] = {}
    for row in operations:
        opid = row.get("id")
        if not isinstance(opid, str) or not opid:
            result.add_error(
                ERR_OP_MISSING_FIELD, AGENT_OPERATIONS_JSON_PATH, "#/operations",
                "operation row without a stable ID",
            )
            continue
        if opid in json_map:
            result.add_error(
                ERR_OP_STABLE_ID_REUSED, AGENT_OPERATIONS_JSON_PATH, f"#/operations/{opid}",
                f"stable ID '{opid}' duplicated",
            )
            continue
        json_map[opid] = row
    if sorted(json_map) != EXPECTED_IDS:
        result.add_error(
            ERR_OP_STABLE_ID_REUSED, AGENT_OPERATIONS_JSON_PATH, "#/operations",
            f"stable ID set diverged from AOP-001..AOP-014: found {sorted(json_map)}",
        )

    # 3. Mandatory fields. Rows missing mandatory fields are excluded from the
    # deeper semantic/Rust passes: the missing-field error already fails the run,
    # and those passes assume a structurally complete row.
    incomplete: set[str] = set()
    for opid, row in json_map.items():
        row_has_missing = False
        for key in ROW_KEYS:
            value = row.get(key)
            if value is None or (isinstance(value, str) and not value.strip()):
                result.add_error(
                    ERR_OP_MISSING_FIELD, AGENT_OPERATIONS_JSON_PATH, f"#/operations/{opid}/{key}",
                    "missing or empty mandatory operation field",
                )
                row_has_missing = True
            elif isinstance(value, list) and not value:
                result.add_error(
                    ERR_OP_MISSING_FIELD, AGENT_OPERATIONS_JSON_PATH, f"#/operations/{opid}/{key}",
                    "empty mandatory operation list field",
                )
                row_has_missing = True
        if row_has_missing:
            incomplete.add(opid)
    result.operation_count = len(json_map)

    # 1. Row drift between machine registry and markdown mirror.
    md_rows = parse_markdown_table(md_path)
    md_map = {row["ID"]: row for row in md_rows if row.get("ID", "").startswith("AOP-")}
    if len(md_map) != len(md_rows):
        result.add_error(
            ERR_OP_CORRUPT_FILE, AGENT_OPERATIONS_MD_PATH, "#",
            "markdown table contains rows without a stable AOP ID",
        )
    if set(md_map) != set(json_map):
        for opid in set(json_map) - set(md_map):
            result.add_error(
                ERR_OP_REGISTRY_DRIFT, AGENT_OPERATIONS_MD_PATH, f"#{opid}",
                f"operation '{opid}' in architecture is missing from the markdown mirror",
            )
        for opid in set(md_map) - set(json_map):
            result.add_error(
                ERR_OP_REGISTRY_DRIFT, AGENT_OPERATIONS_JSON_PATH, f"#/operations/{opid}",
                f"operation '{opid}' in markdown is missing from the machine registry",
            )

    def yes_no(value: str) -> bool:
        return value.strip().lower() == "yes"

    for opid in sorted(set(json_map) & set(md_map)):
        row, md = json_map[opid], md_map[opid]
        drift_checks = [
            ("name", "Name", row.get("name"), md.get("Name")),
            ("owner", "Owner", row.get("owner"), md.get("Owner")),
            ("mode", "Mode", row.get("mode"), md.get("Mode")),
            ("defaultView", "Default view", row.get("defaultView"), md.get("Default view")),
            (
                "requestPayloadSchema",
                "Typed request payload",
                row.get("requestPayloadSchema"),
                md.get("Typed request payload"),
            ),
            ("effectful", "Effectful", row.get("effectful"), yes_no(md.get("Effectful", ""))),
            ("durable", "Durable", row.get("durable"), yes_no(md.get("Durable", ""))),
            ("gate", "Gate", row.get("gate"), md.get("Gate")),
            ("status", "Status", row.get("status"), md.get("Status")),
        ]
        for json_key, md_key, json_value, md_value in drift_checks:
            if json_value != md_value:
                result.add_error(
                    ERR_OP_REGISTRY_DRIFT, AGENT_OPERATIONS_JSON_PATH,
                    f"#/operations/{opid}/{json_key}",
                    f"field '{json_key}' drifted between machine registry ({json_value!r}) "
                    f"and markdown mirror ({md_value!r})",
                )

    # 5. Semantic invariants per machine row.
    for opid in sorted(json_map):
        if opid not in incomplete:
            validate_row_semantics(json_map[opid], result, AGENT_OPERATIONS_JSON_PATH)

    # 5b. Frozen public-registry agreement.
    try:
        frozen_doc = json.loads(frozen_path.read_text(encoding="utf-8"))
        frozen_map = {
            op.get("id"): op
            for op in frozen_doc.get("operations", [])
            if isinstance(op, dict) and op.get("id")
        }
    except (OSError, json.JSONDecodeError) as exc:
        result.add_error(
            ERR_OP_CORRUPT_FILE, FROZEN_PUBLIC_REGISTRY_PATH, "#", f"corrupt frozen registry: {exc}"
        )
        frozen_map = {}
    for opid in sorted(set(json_map) & set(frozen_map)):
        row, frozen = json_map[opid], frozen_map[opid]
        for key in ("name", "requestPayloadSchema", "responsePayloadSchemas", "defaultView", "status"):
            if row.get(key) != frozen.get(key):
                result.add_error(
                    ERR_OP_SEMANTIC_INVARIANT, FROZEN_PUBLIC_REGISTRY_PATH,
                    f"#/operations/{opid}/{key}",
                    f"frozen public registry field '{key}' ({frozen.get(key)!r}) diverges from "
                    f"machine registry ({row.get(key)!r})",
                )

    # 6. Typed Rust table drift.
    if rs_path.is_file():
        try:
            rust_rows = extract_rust_canonical_rows(rs_path)
        except (OSError, ValueError) as exc:
            result.add_error(
                ERR_OP_RUST_DRIFT, AGENT_OPERATION_RS_PATH, "#/canonical_row_encoding",
                f"failed to parse canonical rows from agent_operation.rs: {exc}",
            )
            rust_rows = {}
        for opid in EXPECTED_IDS:
            if opid not in rust_rows:
                result.add_error(
                    ERR_OP_RUST_DRIFT, AGENT_OPERATION_RS_PATH,
                    f"#/canonical_row_encoding/{opid}",
                    f"typed operation table is missing canonical row '{opid}'",
                )
        for opid in sorted(rust_rows):
            if opid not in EXPECTED_IDS:
                result.add_error(
                    ERR_OP_RUST_DRIFT, AGENT_OPERATION_RS_PATH,
                    f"#/canonical_row_encoding/{opid}",
                    f"typed operation table carries unregistered row '{opid}'",
                )
                continue
            rust_fields = canonical_fields_from_text(rust_rows[opid])
            if rust_fields is None:
                result.add_error(
                    ERR_OP_RUST_DRIFT, AGENT_OPERATION_RS_PATH,
                    f"#/canonical_row_encoding/{opid}",
                    f"canonical row '{opid}' does not have exactly 14 fields",
                )
                continue
            if opid in incomplete:
                continue
            json_fields = canonical_fields_from_json(json_map[opid])
            for key in json_fields:
                if rust_fields[key] != json_fields[key]:
                    result.add_error(
                        ERR_OP_RUST_DRIFT, AGENT_OPERATION_RS_PATH,
                        f"#/canonical_row_encoding/{opid}/{key}",
                        f"Rust row field '{key}' ({rust_fields[key]!r}) drifted from machine "
                        f"registry ({json_fields[key]!r})",
                    )

    return result


def canonical_view_fields_from_text(text: str) -> dict[str, Any] | None:
    fields = text.split("|")
    if len(fields) != 7:
        return None
    sections = fields[6].split(";") if fields[6] else []
    return {
        "id": fields[0],
        "name": fields[1],
        "owner": fields[2],
        "targetTokens": int(fields[3]),
        "maximumTokens": int(fields[4]),
        "gate": fields[5],
        "requiredSections": sections,
    }


def extract_rust_view_rows(rs_path: Path) -> dict[str, str]:
    content = rs_path.read_text(encoding="utf-8")
    fn_start = content.index("pub const fn canonical_row_encoding(self)")
    fn_body = content[fn_start:]
    return {text.split("|", 1)[0]: text for text in CANONICAL_VIEW_ROW_RE.findall(fn_body)}


def validate_agent_view_registry(
    repo_root: Path, result: ValidationResult
) -> ValidationResult:
    json_path = repo_root / AGENT_VIEWS_JSON_PATH
    md_path = repo_root / AGENT_VIEWS_MD_PATH
    rs_path = repo_root / AGENT_VIEW_RS_PATH

    views: list[dict[str, Any]] = []
    if not json_path.is_file():
        result.add_error(ERR_VW_CORRUPT_FILE, AGENT_VIEWS_JSON_PATH, "#", "missing mandatory view registry")
    else:
        try:
            doc = json.loads(json_path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError) as exc:
            result.add_error(ERR_VW_CORRUPT_FILE, AGENT_VIEWS_JSON_PATH, "#", f"corrupt view registry: {exc}")
            doc = None
        if isinstance(doc, dict):
            if doc.get("schema") != "fss.agent_views.v1":
                result.add_error(ERR_VW_MISSING_FIELD, AGENT_VIEWS_JSON_PATH, "#/schema", "registry schema must be fss.agent_views.v1")
            if not isinstance(doc.get("asOf"), str) or not doc.get("asOf", "").strip():
                result.add_error(ERR_VW_MISSING_FIELD, AGENT_VIEWS_JSON_PATH, "#/asOf", "missing or empty asOf metadata")
            raw = doc.get("views")
            if not isinstance(raw, list):
                result.add_error(ERR_VW_CORRUPT_FILE, AGENT_VIEWS_JSON_PATH, "#/views", "missing mandatory 'views' collection")
            else:
                views = [v for v in raw if isinstance(v, dict)]
    if not md_path.is_file():
        result.add_error(ERR_VW_CORRUPT_FILE, AGENT_VIEWS_MD_PATH, "#", "missing mandatory view mirror")
    if not rs_path.is_file():
        result.add_error(ERR_VW_RUST_DRIFT, AGENT_VIEW_RS_PATH, "#", "missing typed view table crates/fss-core/src/agent_view.rs")

    view_map: dict[str, dict[str, Any]] = {}
    for row in views:
        vid = row.get("id")
        if not isinstance(vid, str) or not vid:
            result.add_error(ERR_VW_MISSING_FIELD, AGENT_VIEWS_JSON_PATH, "#/views", "view row without a stable ID")
            continue
        if vid in view_map:
            result.add_error(ERR_VW_STABLE_ID_REUSED, AGENT_VIEWS_JSON_PATH, f"#/views/{vid}", f"stable ID '{vid}' duplicated")
            continue
        view_map[vid] = row
    if sorted(view_map) != EXPECTED_VIEW_IDS:
        result.add_error(ERR_VW_STABLE_ID_REUSED, AGENT_VIEWS_JSON_PATH, "#/views", f"stable ID set diverged from AVIEW-001..008: found {sorted(view_map)}")

    incomplete: set[str] = set()
    for vid, row in view_map.items():
        for key in VIEW_ROW_KEYS:
            value = row.get(key)
            if value is None or (isinstance(value, str) and not value.strip()):
                result.add_error(ERR_VW_MISSING_FIELD, AGENT_VIEWS_JSON_PATH, f"#/views/{vid}/{key}", "missing or empty mandatory view field")
                incomplete.add(vid)
            elif isinstance(value, list) and not value:
                result.add_error(ERR_VW_MISSING_FIELD, AGENT_VIEWS_JSON_PATH, f"#/views/{vid}/{key}", "empty mandatory view list field")
                incomplete.add(vid)
    result.view_count = len(view_map)

    md_rows = parse_markdown_table(md_path)
    md_map = {row["ID"]: row for row in md_rows if row.get("ID", "").startswith("AVIEW-")}
    if set(md_map) != set(view_map):
        for vid in set(view_map) - set(md_map):
            result.add_error(ERR_VW_REGISTRY_DRIFT, AGENT_VIEWS_MD_PATH, f"#{vid}", f"view '{vid}' in architecture is missing from the markdown mirror")
        for vid in set(md_map) - set(view_map):
            result.add_error(ERR_VW_REGISTRY_DRIFT, AGENT_VIEWS_JSON_PATH, f"#/views/{vid}", f"view '{vid}' in markdown is missing from the machine registry")
    for vid in sorted(set(view_map) & set(md_map)):
        row, md = view_map[vid], md_map[vid]
        for json_key, md_key, in (("name", "Name"), ("owner", "Owner"), ("gate", "Gate"), ("status", "Status")):
            if row.get(json_key) != md.get(md_key):
                result.add_error(ERR_VW_REGISTRY_DRIFT, AGENT_VIEWS_JSON_PATH, f"#/views/{vid}/{json_key}", f"field '{json_key}' drifted between machine registry ({row.get(json_key)!r}) and markdown mirror ({md.get(md_key)!r})")
        try:
            md_target = int(str(md.get("Target tokens", "")).strip())
        except ValueError:
            md_target = md.get("Target tokens")
        if row.get("targetTokens") != md_target:
            result.add_error(ERR_VW_REGISTRY_DRIFT, AGENT_VIEWS_JSON_PATH, f"#/views/{vid}/targetTokens", f"targetTokens drifted: JSON {row.get('targetTokens')!r} vs markdown {md.get('Target tokens')!r}")
        try:
            md_maximum = int(str(md.get("Maximum tokens", "")).strip())
        except ValueError:
            md_maximum = md.get("Maximum tokens")
        if row.get("maximumTokens") != md_maximum:
            result.add_error(ERR_VW_REGISTRY_DRIFT, AGENT_VIEWS_JSON_PATH, f"#/views/{vid}/maximumTokens", f"maximumTokens drifted: JSON {row.get('maximumTokens')!r} vs markdown {md.get('Maximum tokens')!r}")

    for vid in sorted(view_map):
        if vid in incomplete:
            continue
        row = view_map[vid]
        target, maximum = row.get("targetTokens"), row.get("maximumTokens")
        if not isinstance(target, int) or not isinstance(maximum, int) or target < 1 or maximum < target:
            result.add_error(ERR_VW_SEMANTIC_INVARIANT, AGENT_VIEWS_JSON_PATH, f"#/views/{vid}/targetTokens", f"view '{vid}' token bounds violate 1 <= target <= maximum")
        if row.get("gate") != REGISTERED_GATE:
            result.add_error(ERR_VW_SEMANTIC_INVARIANT, AGENT_VIEWS_JSON_PATH, f"#/views/{vid}/gate", f"view '{vid}' gate diverges from '{REGISTERED_GATE}'")
        if row.get("status") != REGISTERED_STATUS:
            result.add_error(ERR_VW_SEMANTIC_INVARIANT, AGENT_VIEWS_JSON_PATH, f"#/views/{vid}/status", f"view '{vid}' status diverges from baseline; a transition requires a registry generation bump")
        if not str(row.get("owner", "")).startswith("fss-"):
            result.add_error(ERR_VW_SEMANTIC_INVARIANT, AGENT_VIEWS_JSON_PATH, f"#/views/{vid}/owner", f"view '{vid}' owner is not an fss- crate identity")

    # Foreign key: every operation default view must be a registered view.
    operations_path = repo_root / AGENT_OPERATIONS_JSON_PATH
    try:
        operations_doc = json.loads(operations_path.read_text(encoding="utf-8"))
        for op in operations_doc.get("operations", []):
            default_view = op.get("defaultView")
            if default_view not in view_map:
                result.add_error(ERR_VW_SEMANTIC_INVARIANT, AGENT_OPERATIONS_JSON_PATH, f"#/operations/{op.get('id')}/defaultView", f"default view '{default_view}' is not a registered view")
    except (OSError, json.JSONDecodeError):
        pass

    # Typed Rust table agreement.
    if rs_path.is_file():
        try:
            rust_rows = extract_rust_view_rows(rs_path)
        except (OSError, ValueError) as exc:
            result.add_error(ERR_VW_RUST_DRIFT, AGENT_VIEW_RS_PATH, "#/canonical_row_encoding", f"failed to parse canonical view rows: {exc}")
            rust_rows = {}
        for vid in EXPECTED_VIEW_IDS:
            if vid not in rust_rows:
                result.add_error(ERR_VW_RUST_DRIFT, AGENT_VIEW_RS_PATH, f"#/canonical_row_encoding/{vid}", f"typed view table is missing canonical row '{vid}'")
        for vid in sorted(rust_rows):
            if vid not in EXPECTED_VIEW_IDS:
                result.add_error(ERR_VW_RUST_DRIFT, AGENT_VIEW_RS_PATH, f"#/canonical_row_encoding/{vid}", f"typed view table carries unregistered row '{vid}'")
                continue
            fields = canonical_view_fields_from_text(rust_rows[vid])
            row = view_map.get(vid, {})
            if fields is None:
                result.add_error(ERR_VW_RUST_DRIFT, AGENT_VIEW_RS_PATH, f"#/canonical_row_encoding/{vid}", f"canonical view row '{vid}' does not have exactly 7 fields")
                continue
            if vid in incomplete:
                continue
            expected = {
                "id": vid,
                "name": row.get("name"),
                "owner": row.get("owner"),
                "targetTokens": row.get("targetTokens"),
                "maximumTokens": row.get("maximumTokens"),
                "gate": row.get("gate"),
                "requiredSections": list(row.get("requiredSections", [])),
            }
            for key, value in expected.items():
                if fields.get(key) != value:
                    result.add_error(ERR_VW_RUST_DRIFT, AGENT_VIEW_RS_PATH, f"#/canonical_row_encoding/{vid}/{key}", f"Rust view row field '{key}' ({fields.get(key)!r}) drifted from machine registry ({value!r})")
    return result


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Validate agent operation registry against markdown, frozen registry, and typed Rust table"
    )
    parser.add_argument("--repo-root", type=Path, default=ROOT, help="Path to repository root")
    parser.add_argument("--json", action="store_true", help="Emit machine-readable JSON")
    args = parser.parse_args()

    result = validate_agent_operation_registry(args.repo_root)
    result = validate_agent_view_registry(args.repo_root, result)
    if args.json:
        payload = {
            "schema": "fss.agent_operation_registry_validation.v1",
            "passed": result.passed,
            "operationCount": result.operation_count,
            "viewCount": result.view_count,
            "errorCount": len(result.errors),
            "errors": [asdict(e) for e in result.errors],
        }
        print(json.dumps(payload, indent=2))
    else:
        if result.passed:
            print(
                f"[PASS] Agent operation and view registries verified: {result.operation_count} operations, "
                f"{result.view_count} views with typed Rust agreement."
            )
        else:
            print(
                f"[FAIL] Agent operation registry failed with {len(result.errors)} errors:",
                file=sys.stderr,
            )
            for err in result.errors:
                print(
                    f"  [{err.code}] {err.file_path} ({err.target}): {err.message}",
                    file=sys.stderr,
                )

    return 0 if result.passed else 1


if __name__ == "__main__":
    sys.exit(main())
