#!/usr/bin/env python3
"""Deterministic SLO constitution and operation-cost reference validator (fss-x4a.30.107).

Validates that:
- Every SLO row in registries/SLOS.md has a stable ID matching ^SLO-[A-Z0-9]+(?:-[A-Z0-9]+)*-[0-9]{3}$
- Every SLO has a measurable target, a declared measurement surface, a valid status ('target', 'tombstone', or 'achieved')
- Status 'achieved' requires a non-empty, resolvable retained proof root; an SLO marked achieved without a proof root fails
- Tombstones must resolve through valid non-cyclic crosswalks to canonical registered SLOs
- Operation-cost rows in architecture/operation_cost_registry.toml referencing slo_ids must resolve to registered SLOs
- Public claims cannot be generated from targets alone
"""
from __future__ import annotations

import argparse
import hashlib
import json
import math
import os
import re
import sys
import time
import tomllib
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
DEFAULT_SLOS_MD = ROOT / "registries/SLOS.md"
DEFAULT_COSTS_TOML = ROOT / "architecture/operation_cost_registry.toml"
DEFAULT_CLAIMS_MD = ROOT / "registries/CLAIMS.md"

SLO_ID_REGEX = re.compile(r"^SLO-[A-Z0-9]+(?:-[A-Z0-9]+)*-[0-9]{3}$")
COST_ID_REGEX = re.compile(r"^COST-[A-Z0-9]+(?:-[A-Z0-9]+)*-[0-9]{3}$")
TOMBSTONE_REGEX = re.compile(r"tombstone:\s*superseded\s*by\s*`((?:SLO)-[A-Z0-9-]+)`", re.IGNORECASE)

VALID_STATUSES = frozenset({"target", "tombstone", "achieved"})
NON_PROOF_ROOTS = frozenset({"-", "none", "null", "n/a", "na", ""})

# Registered physical, statistical, and discrete measurement units
REGISTERED_UNITS = frozenset({
    "ns", "us", "ms", "s", "sec", "seconds", "min", "minutes", "hours",
    "fps", "frames/s", "events/s", "mb/s", "kib/s", "access_units", "frames", "stream_second",
    "%", "percent", "percentage", "auprc",
    "tokens", "output tokens", "semantic calls", "calls", "operations",
    "alerts/property-day", "camera-month", "object operation",
    "tasks", "processes", "descriptors", "bytes",
})

# Recognized structured zero, invariance, and closure contract patterns
APPROVED_TARGET_PATTERNS = [
    re.compile(r"^tombstone:\s*superseded\s*by\b", re.IGNORECASE),
    re.compile(r"\bzero\s+(?:owned|task-critical|protected|hidden)\b", re.IGNORECASE),
    re.compile(r"^no\s+acknowledged\s+source\s+segment\s+lost\b", re.IGNORECASE),
    re.compile(r"^every\s+(?:published|agent-started)\b", re.IGNORECASE),
    re.compile(r"meets?\s+registered\s+.*(?:residual\s+)?bounds", re.IGNORECASE),
    re.compile(r"within\s+bounded\s+.*and\s+recovery\s+time", re.IGNORECASE),
    re.compile(r"^complete\s+release\s+matrix\s+qualified", re.IGNORECASE),
    re.compile(r"^release-specific\s+(?:lower|upper)\b", re.IGNORECASE),
    re.compile(r"^maximize\s+event\s+auprc\b", re.IGNORECASE),
    re.compile(r"cognition\s+cost/camera-month\b", re.IGNORECASE),
    re.compile(r"archive\s+cost/object\s+operation\b", re.IGNORECASE),
    re.compile(r"^promoted\s+memory/procedure\s+improves\b", re.IGNORECASE),
    re.compile(r"^agent\s+task\s+success/calibration\s+is\s+non-inferior\b", re.IGNORECASE),
    re.compile(r"^resumed\s+agent\s+reconstructs\b", re.IGNORECASE),
    re.compile(r"^deletion\s+closure\s+reaches\s+terminal\s+proof\b", re.IGNORECASE),
]

# Known allowed keys in [[operation]] tables
KNOWN_OPERATION_KEYS = frozenset({
    "id", "name", "unit", "semantic_steps", "variable_costs", "slo_ids", "status", "notes",
    "cost_vector", "baseline_reference", "proof_owner", "owner", "proof_reference", "measurement_artifact",
})

# Diagnostic codes
CODE_INVALID_SLO_ID = "SLO-VAL-001"
CODE_DUPLICATE_SLO_ID = "SLO-VAL-002"
CODE_INVALID_SLO_STATUS = "SLO-VAL-003"
CODE_ACHIEVED_WITHOUT_PROOF_ROOT = "SLO-VAL-004"
CODE_PROOF_ROOT_NOT_FOUND = "SLO-VAL-005"
CODE_MISSING_TARGET = "SLO-VAL-006"
CODE_MISSING_MEASUREMENT_SURFACE = "SLO-VAL-007"
CODE_INVALID_TOMBSTONE = "SLO-VAL-008"
CODE_UNREGISTERED_SLO_REFERENCE = "SLO-VAL-009"
CODE_MALFORMED_COST_SLO_REFERENCE = "SLO-VAL-010"
CODE_MALFORMED_TABLE = "SLO-VAL-011"
CODE_TARGET_CLAIM_PROMOTION = "SLO-VAL-012"
CODE_AMBIGUOUS_TARGET_UNIT = "SLO-VAL-013"
CODE_TOMBSTONE_REFERENCED_AS_ACTIVE = "SLO-VAL-014"
CODE_HOT_PATH_MISSING_COST_ROW = "SLO-VAL-015"
CODE_MISSING_COST_VECTOR_OR_BASELINE = "SLO-VAL-016"
CODE_MISSING_OR_UNKNOWN_OWNER = "SLO-VAL-017"
CODE_PROOF_REFERENCE_NOT_FOUND = "SLO-VAL-018"
CODE_OWNER_MIRROR_DISAGREEMENT = "SLO-VAL-019"
CODE_MEASURED_WITHOUT_ARTIFACT = "SLO-VAL-020"
CODE_DUPLICATE_OR_RENUMBERED_COST_ID = "SLO-VAL-021"
CODE_FREEZE_DIGEST_MISMATCH = "SLO-VAL-022"

BASELINE_OPERATION_COST_GENERATION = "gen:fss1:operation-cost-v1"
EXPECTED_OPERATION_COST_FREEZE_DIGESTS: dict[str, str] = {
    "gen:fss1:operation-cost-v1": "sha256:c885c834fe3d492076090e551c5988d6ed363bcf3a2432c41e67fe527ccf83b9",
}

CANONICAL_COST_OPERATIONS: frozenset[str] = frozenset({
    "COST-ACQUIRE-001", "COST-RTSP-001", "COST-PARSE-001", "COST-DECODE-001",
    "COST-PROXY-001", "COST-QUALITY-001", "COST-DETECT-001", "COST-TRACK-001",
    "COST-ASSOC-001", "COST-ANALYZE-001", "COST-GRAPH-001", "COST-SEARCH-001",
    "COST-EVENT-001", "COST-ALERT-001", "COST-ARCHIVE-001", "COST-ATP-001",
    "COST-RETRIEVE-001", "COST-DELETE-001", "COST-CALIBRATE-001", "COST-TWIN-001",
    "COST-MODEL-IMPORT-001", "COST-QUERY-001", "COST-CHECKPOINT-001", "COST-RELEASE-001",
    "COST-ORIENT-001", "COST-FOLLOW-001", "COST-CONTEXT-001", "COST-INVESTIGATE-001",
    "COST-AFFORDANCE-001", "COST-AGENT-PLAN-001", "COST-EXPLAIN-001", "COST-HANDOFF-001",
    "COST-ACCRETE-001", "COST-SPOOL-INGEST-001", "COST-SPOOL-VERIFY-001",
    "COST-SPOOL-DISCARD-001", "COST-ROOT-PUBLISH-001", "COST-LEDGER-APPEND-001",
    "COST-LEDGER-REPLAY-001", "COST-DURABLE-DECODE-001", "COST-PRICING-LOOKUP-001",
})

CANONICAL_DRIFT_IDS: frozenset[str] = frozenset({
    f"DRIFT-{i:03d}" for i in range(1, 20)
})

MANDATORY_HOT_PATHS: dict[str, dict[str, str]] = {
    "COST-SPOOL-INGEST-001": {
        "name": "spool ingest",
        "baseline": "crates/fss-object/tests/staging_spool_contract.rs",
    },
    "COST-SPOOL-VERIFY-001": {
        "name": "spool verify",
        "baseline": "crates/fss-object/tests/staging_spool_contract.rs",
    },
    "COST-SPOOL-DISCARD-001": {
        "name": "spool discard",
        "baseline": "crates/fss-object/tests/staging_spool_contract.rs",
    },
    "COST-ROOT-PUBLISH-001": {
        "name": "root publication",
        "baseline": "crates/fss-publication/tests/root_publication_review568.rs",
    },
    "COST-LEDGER-APPEND-001": {
        "name": "ledger append",
        "baseline": "crates/fss-ledger/tests/ledger_oracle_contract.rs",
    },
    "COST-LEDGER-REPLAY-001": {
        "name": "ledger replay",
        "baseline": "crates/fss-ledger/tests/ledger_oracle_contract.rs",
    },
    "COST-MODEL-IMPORT-001": {
        "name": "model package import",
        "baseline": "crates/fss-object/tests/model_package_contract.rs",
    },
    "COST-DURABLE-DECODE-001": {
        "name": "durable-format decode",
        "baseline": "crates/fss-core/tests/durable_format_contract.rs",
    },
    "COST-PRICING-LOOKUP-001": {
        "name": "provider pricing lookup",
        "baseline": "crates/fss-core/tests/pricing_manifest_contract.rs",
    },
}

MANDATORY_HOT_PATHS_LOWER: dict[str, tuple[str, dict[str, str]]] = {
    k.lower(): (k, v) for k, v in MANDATORY_HOT_PATHS.items()
}

REQUIRED_COST_VECTOR_DIMENSIONS: tuple[str, ...] = (
    "latency_ms",
    "cpu_millis",
    "bytes",
    "storage_operations",
    "network_bytes",
    "model_calls",
    "tokens",
    "accelerator_millis",
    "energy_millijoules",
    "privacy_exposure",
    "operator_attention_seconds",
)

DIAGNOSTIC_REGISTRY: dict[str, dict[str, str]] = {
    CODE_INVALID_SLO_ID: {
        "trigger": "SLO ID does not match canonical naming convention ^SLO-[A-Z0-9]+(?:-[A-Z0-9]+)*-[0-9]{3}$",
        "remediation": "Correct the SLO ID spelling and numeric suffix; preserve stable IDs without renumbering",
    },
    CODE_DUPLICATE_SLO_ID: {
        "trigger": "SLO ID is declared more than once or collides under case folding",
        "remediation": "Deduplicate or allocate a unique stable ID; do not reuse existing IDs",
    },
    CODE_INVALID_SLO_STATUS: {
        "trigger": "SLO status is not one of 'target', 'tombstone', or 'achieved'",
        "remediation": "Set status to 'target' (or 'tombstone' for superseded IDs); use 'achieved' only with proof",
    },
    CODE_ACHIEVED_WITHOUT_PROOF_ROOT: {
        "trigger": "SLO is marked 'achieved' without referencing a retained proof root",
        "remediation": "Attach an immutable retained proof root reference or revert status to 'target'",
    },
    CODE_PROOF_ROOT_NOT_FOUND: {
        "trigger": "Referenced proof root path does not exist on disk as a file under qualification-artifacts/",
        "remediation": "Provide the exact path to a retained qualification artifact file strictly under qualification-artifacts/",
    },
    CODE_MISSING_TARGET: {
        "trigger": "SLO row lacks a measurable target specification",
        "remediation": "Define an explicit, measurable target threshold or bound before qualification",
    },
    CODE_MISSING_MEASUREMENT_SURFACE: {
        "trigger": "SLO row lacks a declared measurement surface / workload profile",
        "remediation": "Specify the exact measurement surface, hardware profile, or sealed corpus",
    },
    CODE_INVALID_TOMBSTONE: {
        "trigger": "Tombstone successor is missing, unregistered, or forms a cyclic reference",
        "remediation": "Point the tombstone to an active canonical successor SLO without cycles",
    },
    CODE_UNREGISTERED_SLO_REFERENCE: {
        "trigger": "Operation cost references an unregistered SLO ID or lacks SLO linkage",
        "remediation": "Register the SLO in registries/SLOS.md or correct the cost slo_ids reference",
    },
    CODE_MALFORMED_COST_SLO_REFERENCE: {
        "trigger": "Operation cost references a malformed SLO ID format",
        "remediation": "Format the referenced SLO ID as ^SLO-[A-Z0-9]+(?:-[A-Z0-9]+)*-[0-9]{3}$",
    },
    CODE_MALFORMED_TABLE: {
        "trigger": "SLO markdown table header, row structure, or operation table is malformed",
        "remediation": "Ensure standard format: | ID | Target | Measurement surface | Status | Proof root |",
    },
    CODE_TARGET_CLAIM_PROMOTION: {
        "trigger": "An SLO target was promoted to a public claim without an achieved qualification proof",
        "remediation": "Treat targets as goals to qualify, not achieved claims, until verified at release gates",
    },
    CODE_AMBIGUOUS_TARGET_UNIT: {
        "trigger": "SLO target lacks a registered physical, statistical, or structured contract unit bound",
        "remediation": "Specify an explicit bound with a registered unit (e.g. ms, s, %, fps, tokens, alerts/property-day) or approved zero/closure contract",
    },
    CODE_TOMBSTONE_REFERENCED_AS_ACTIVE: {
        "trigger": "Active operation links directly to a tombstoned SLO rather than its canonical successor",
        "remediation": "Update operation slo_ids to reference the canonical successor SLO directly",
    },
    CODE_HOT_PATH_MISSING_COST_ROW: {
        "trigger": "A mandatory hot or consequential path exists in code but lacks an operation-cost row in architecture/operation_cost_registry.toml",
        "remediation": "Add [[operation]] table for the missing hot path with a full cost_vector and reproducible baseline_reference",
    },
    CODE_MISSING_COST_VECTOR_OR_BASELINE: {
        "trigger": "An operation cost row lacks a complete cost vector or valid baseline reference",
        "remediation": "Provide an explicit cost_vector table with all 11 dimensions and a valid baseline_reference resolving to an existing test file",
    },
    CODE_MISSING_OR_UNKNOWN_OWNER: {
        "trigger": "Operation cost row lacks a named proof owner (crate/module) or references an undeclared drift row",
        "remediation": "Provide an existing crate or module proof_owner, or record as an explicit drift row (drift:DRIFT-...) in [[drift]]",
    },
    CODE_PROOF_REFERENCE_NOT_FOUND: {
        "trigger": "Operation cost proof reference file or test function does not exist on disk",
        "remediation": "Provide the exact path and test function (path/to/test.rs::test_fn) that retains the verification evidence",
    },
    CODE_OWNER_MIRROR_DISAGREEMENT: {
        "trigger": "Operation cost proof owner or proof reference differs between architecture/operation_cost_registry.toml and registries/OPERATION_COSTS.md",
        "remediation": "Synchronize Proof owner and Proof reference columns in registries/OPERATION_COSTS.md with architecture/operation_cost_registry.toml",
    },
    CODE_MEASURED_WITHOUT_ARTIFACT: {
        "trigger": "Operation cost row has status 'measured' without a retained measurement artifact on disk",
        "remediation": "Attach an existing measurement_artifact path under qualification-artifacts/ or revert status to 'model_required'",
    },
    CODE_DUPLICATE_OR_RENUMBERED_COST_ID: {
        "trigger": "Operation cost ID is duplicated, case-colliding, malformed, or renumbered",
        "remediation": "Ensure all operation IDs are unique, match canonical COST-*-NNN naming, and preserve stable IDs without renumbering",
    },
    CODE_FREEZE_DIGEST_MISMATCH: {
        "trigger": "Operation cost registry generation or freeze digest diverged from pinned canonical baseline",
        "remediation": "Update registry generation and pinned freeze digest according to registered migration procedures",
    },
}


def canonicalize_value(val: Any) -> Any:
    """Recursively canonicalizes dicts and lists for deterministic JSON serialization."""
    if isinstance(val, dict):
        return {k: canonicalize_value(v) for k, v in sorted(val.items())}
    if isinstance(val, list):
        return [canonicalize_value(item) for item in val]
    return val


def compute_canonical_cost_registry_digest(data: dict[str, Any]) -> str:
    """Computes SHA-256 digest of canonically serialized operation cost registry data.
    Binds schema, as_of, generation, sorted operations, and sorted drift tables,
    strictly excluding the registry_digest field itself to prevent self-referential digests."""
    raw_ops = data.get("operation", [])
    raw_drifts = data.get("drift", [])

    canonical_payload = {
        "as_of": str(data.get("as_of", "")).strip(),
        "drift": [canonicalize_value(r) for r in sorted(raw_drifts, key=lambda r: str(r.get("id", "")))],
        "generation": str(data.get("generation", "")).strip(),
        "operation": [canonicalize_value(r) for r in sorted(raw_ops, key=lambda r: str(r.get("id", "")))],
        "schema": str(data.get("schema", "")).strip(),
    }
    canonical_bytes = json.dumps(canonical_payload, sort_keys=True, separators=(",", ":")).encode("utf-8")
    return f"sha256:{hashlib.sha256(canonical_bytes).hexdigest()}"


def load_tombstone_set(root: Path) -> set[str]:
    """Loads tombstoned stable IDs from architecture/stable_id_resolution.json."""
    tombstones: set[str] = set()
    res_path = root / "architecture/stable_id_resolution.json"
    if res_path.is_file():
        try:
            data = json.loads(res_path.read_text(encoding="utf-8"))
            for res in data.get("resolutions", []):
                if res.get("status") in ("tombstone", "tombstoned", "superseded"):
                    if "legacyId" in res:
                        tombstones.add(str(res["legacyId"]).strip())
                    if "canonicalId" in res:
                        tombstones.add(str(res["canonicalId"]).strip())
        except Exception:
            pass
    return tombstones


def strip_rust_comments_and_strings(source: str) -> str:
    """Strips Rust line comments (//), block comments (/* ... */ with nesting),
    and string literals (including raw strings) to prevent commented-out or
    string-embedded function declarations from matching symbol resolution."""
    chars: list[str] = []
    i = 0
    n = len(source)
    while i < n:
        if source[i:i+2] == "//":
            i += 2
            while i < n and source[i] != "\n":
                i += 1
            continue
        if source[i:i+2] == "/*":
            depth = 1
            i += 2
            while i < n and depth > 0:
                if source[i:i+2] == "/*":
                    depth += 1
                    i += 2
                elif source[i:i+2] == "*/":
                    depth -= 1
                    i += 2
                else:
                    if source[i] == "\n":
                        chars.append("\n")
                    i += 1
            continue
        if source[i] == "r" and (i + 1 < n) and (source[i+1] == '"' or source[i+1] == "#"):
            j = i + 1
            hashes = 0
            while j < n and source[j] == "#":
                hashes += 1
                j += 1
            if j < n and source[j] == '"':
                closing = '"' + ("#" * hashes)
                k = source.find(closing, j + 1)
                if k != -1:
                    i = k + len(closing)
                    chars.append('""')
                    continue
        if source[i] == '"':
            i += 1
            while i < n:
                if source[i] == "\\":
                    i += 2
                elif source[i] == '"':
                    i += 1
                    break
                else:
                    i += 1
            chars.append('""')
            continue
        chars.append(source[i])
        i += 1
    return "".join(chars)


@dataclass(frozen=True)
class SloFinding:
    severity: str
    code: str
    path: str
    message: str
    remediation: str = ""
    params: dict[str, Any] = field(default_factory=dict)


@dataclass(frozen=True)
class SloRow:
    id: str
    target: str
    measurement_surface: str
    status: str
    proof_root: str
    is_tombstone: bool
    superseded_by: str | None


def sanitize_path(p: Path | str, root: Path = ROOT) -> str:
    s = str(p)
    try:
        p_obj = Path(p) if isinstance(p, str) else p
        rel = p_obj.resolve().relative_to(root.resolve()).as_posix()
        return rel
    except (ValueError, OSError):
        return s


def parse_markdown_table(
    markdown_text: str,
    path_str: str,
    findings: list[SloFinding],
) -> list[dict[str, str]]:
    """Parse markdown table rows into dictionaries based on header columns."""
    lines = markdown_text.splitlines()
    header_cols: list[str] | None = None
    rows: list[dict[str, str]] = []
    
    for line_idx, line in enumerate(lines, start=1):
        stripped = line.strip()
        if not stripped.startswith("|") or not stripped.endswith("|"):
            continue
        
        # Split by unescaped pipes
        cells = [c.strip() for c in stripped[1:-1].split("|")]
        
        if header_cols is None:
            # Header line
            header_cols = [re.sub(r"\s+", " ", c.lower()) for c in cells]
            continue
        
        # Separator line: |---|---|...
        if all(re.match(r"^:?-+:?$", c) for c in cells):
            continue
        
        if len(cells) != len(header_cols):
            findings.append(SloFinding(
                severity="error",
                code=CODE_MALFORMED_TABLE,
                path=path_str,
                message=f"Row {line_idx} column count mismatch: expected {len(header_cols)}, found {len(cells)}",
                remediation=DIAGNOSTIC_REGISTRY[CODE_MALFORMED_TABLE]["remediation"],
                params={"line": line_idx, "expected_cols": len(header_cols), "found_cols": len(cells)},
            ))
            continue
        
        row_dict = {header_cols[i]: cells[i] for i in range(len(cells))}
        rows.append(row_dict)
    
    return rows


def validate_target_units(target: str, is_tombstone: bool) -> bool:
    """Validate that target matches a structured threshold grammar with registered units and valid ranges."""
    if is_tombstone:
        return True

    t_lower = target.lower()

    # Check approved qualitative/closure contract patterns first
    if any(pat.search(t_lower) for pat in APPROVED_TARGET_PATTERNS):
        return True

    # F4: Physical, rate, count, and size units cannot be negative.
    if re.search(r"(?:<=|>=|<|>|==|≤|≥)\s*-\s*\d", target) or re.search(r"-\s*\d+(?:\.\d+)?\s*(?:%|percent|[a-z/_-]+)", t_lower):
        return False

    # Check percentage ranges: [0, 100]
    percent_matches = re.findall(r"([+-]?\d+(?:\.\d+)?)\s*(?:%|percent)", target)
    if percent_matches:
        for p_str in percent_matches:
            try:
                p_val = float(p_str)
                if p_val < 0.0 or p_val > 100.0:
                    return False
            except ValueError:
                return False
        return True

    has_operator = bool(re.search(r"(?:<=|>=|<|>|==|≤|≥)", target))
    has_number = bool(re.search(r"\b\d+(?:\.\d+)?", target))

    if has_operator or has_number:
        # Check that numeric values associated with units are non-negative
        for unit in sorted(REGISTERED_UNITS, key=len, reverse=True):
            if unit == "%":
                continue
            if re.search(r"\b" + re.escape(unit) + r"\b", t_lower):
                num_matches = re.findall(r"([+-]?\d+(?:\.\d+)?)\s*" + re.escape(unit) + r"\b", t_lower)
                for n_str in num_matches:
                    try:
                        if float(n_str) < 0.0:
                            return False
                    except ValueError:
                        return False
                return True
        return False

    return False


def parse_slos(
    markdown_text: str,
    path: Path,
    root: Path,
    findings: list[SloFinding],
) -> dict[str, SloRow]:
    """Parse and validate all SLO rows from registries/SLOS.md."""
    path_str = sanitize_path(path, root)
    raw_rows = parse_markdown_table(markdown_text, path_str, findings)

    slos: dict[str, SloRow] = {}
    zero_width_chars = frozenset({"\u200b", "\u200c", "\u200d", "\ufeff"})

    for row_idx, row in enumerate(raw_rows, start=1):
        # Extract ID (strictly anchored to whole cell; rejects trailing annotations or aliases)
        id_cell = row.get("id", "").strip()

        # F3: IDs must be validated as pure ASCII first; any non-ASCII or zero-width character is an error
        if not id_cell.isascii() or any(c in id_cell for c in zero_width_chars):
            findings.append(SloFinding(
                severity="error",
                code=CODE_INVALID_SLO_ID,
                path=path_str,
                message=f"Row {row_idx} SLO ID cell contains non-ASCII or zero-width characters: '{id_cell}'",
                remediation="SLO IDs must be pure ASCII with no non-ASCII or zero-width characters",
                params={"row": row_idx, "raw_id": id_cell},
            ))
            continue

        m_id = re.match(r"^`?((?:SLO)-[A-Z0-9]+(?:-[A-Z0-9]+)*-[0-9]{3})`?$", id_cell)
        if not m_id:
            findings.append(SloFinding(
                severity="error",
                code=CODE_INVALID_SLO_ID,
                path=path_str,
                message=f"Row {row_idx} has invalid, malformed, or unanchored SLO ID cell: '{id_cell}' (must contain only the canonical SLO ID, no trailing text or aliases)",
                remediation=DIAGNOSTIC_REGISTRY[CODE_INVALID_SLO_ID]["remediation"],
                params={"row": row_idx, "raw_id": id_cell},
            ))
            continue

        slo_id = m_id.group(1).strip()

        # F6: Check duplicate SLO ID (exact match; case-collision code removed since SLO_ID_REGEX enforces uppercase)
        if slo_id in slos:
            existing = slos[slo_id]
            findings.append(SloFinding(
                severity="error",
                code=CODE_DUPLICATE_SLO_ID,
                path=path_str,
                message=f"Duplicate SLO ID detected: '{slo_id}'",
                remediation=DIAGNOSTIC_REGISTRY[CODE_DUPLICATE_SLO_ID]["remediation"],
                params={"slo_id": slo_id, "collides_with": existing.id},
            ))
            continue

        target = row.get("target", "").strip()
        measurement_surface = (
            row.get("measurement surface")
            or row.get("measurement_surface")
            or row.get("scope/condition")
            or row.get("scope")
            or ""
        ).strip()
        status_raw = (row.get("status") or "target").strip().lower()
        proof_root = (row.get("proof root") or row.get("proof_root") or "-").strip()

        # Tombstone detection
        tombstone_match = TOMBSTONE_REGEX.search(target) or TOMBSTONE_REGEX.search(measurement_surface)
        is_tombstone = tombstone_match is not None or status_raw == "tombstone"
        superseded_by = tombstone_match.group(1) if tombstone_match else None

        # Status validation
        if status_raw not in VALID_STATUSES:
            findings.append(SloFinding(
                severity="error",
                code=CODE_INVALID_SLO_STATUS,
                path=path_str,
                message=f"SLO {slo_id} has invalid status '{status_raw}'; must be one of {sorted(VALID_STATUSES)}",
                remediation=DIAGNOSTIC_REGISTRY[CODE_INVALID_SLO_STATUS]["remediation"],
                params={"slo_id": slo_id, "status": status_raw},
            ))

        # Target presence and structured unit grammar check
        if not target or target.lower() in {"-", "none", "null", "n/a", "na"}:
            findings.append(SloFinding(
                severity="error",
                code=CODE_MISSING_TARGET,
                path=path_str,
                message=f"SLO {slo_id} lacks a measurable target description",
                remediation=DIAGNOSTIC_REGISTRY[CODE_MISSING_TARGET]["remediation"],
                params={"slo_id": slo_id},
            ))
        elif not validate_target_units(target, is_tombstone):
            findings.append(SloFinding(
                severity="error",
                code=CODE_AMBIGUOUS_TARGET_UNIT,
                path=path_str,
                message=f"SLO {slo_id} target '{target}' does not match structured threshold grammar with registered units",
                remediation=DIAGNOSTIC_REGISTRY[CODE_AMBIGUOUS_TARGET_UNIT]["remediation"],
                params={"slo_id": slo_id, "target": target},
            ))

        # Public claim promotion check on target column
        if status_raw == "target" and re.search(r"\bachieved\b", target, re.IGNORECASE):
            findings.append(SloFinding(
                severity="error",
                code=CODE_TARGET_CLAIM_PROMOTION,
                path=path_str,
                message=f"SLO {slo_id} target text claims 'achieved' while row status is 'target'; targets cannot claim achievement without status='achieved' and retained proof",
                remediation=DIAGNOSTIC_REGISTRY[CODE_TARGET_CLAIM_PROMOTION]["remediation"],
                params={"slo_id": slo_id},
            ))

        # Measurement surface presence check
        if not measurement_surface or measurement_surface.lower() in {"-", "none", "null", "n/a", "na"}:
            findings.append(SloFinding(
                severity="error",
                code=CODE_MISSING_MEASUREMENT_SURFACE,
                path=path_str,
                message=f"SLO {slo_id} lacks a declared measurement surface / workload profile",
                remediation=DIAGNOSTIC_REGISTRY[CODE_MISSING_MEASUREMENT_SURFACE]["remediation"],
                params={"slo_id": slo_id},
            ))

        # Achieved status requires valid proof root strictly under qualification-artifacts/
        if status_raw == "achieved":
            if proof_root.lower() in NON_PROOF_ROOTS or proof_root in {".", "./", "/", "\\"}:
                findings.append(SloFinding(
                    severity="error",
                    code=CODE_ACHIEVED_WITHOUT_PROOF_ROOT,
                    path=path_str,
                    message=f"SLO {slo_id} is marked 'achieved' without referencing a retained proof root (found '{proof_root}')",
                    remediation=DIAGNOSTIC_REGISTRY[CODE_ACHIEVED_WITHOUT_PROOF_ROOT]["remediation"],
                    params={"slo_id": slo_id, "proof_root": proof_root},
                ))
            else:
                proof_path = Path(proof_root)
                if proof_path.is_absolute():
                    findings.append(SloFinding(
                        severity="error",
                        code=CODE_PROOF_ROOT_NOT_FOUND,
                        path=path_str,
                        message=f"SLO {slo_id} referenced proof root cannot be an absolute path: '{proof_root}'",
                        remediation="Proof root must be a relative path strictly within qualification-artifacts/",
                        params={"slo_id": slo_id, "proof_root": proof_root},
                    ))
                elif ".." in proof_path.parts:
                    findings.append(SloFinding(
                        severity="error",
                        code=CODE_PROOF_ROOT_NOT_FOUND,
                        path=path_str,
                        message=f"SLO {slo_id} referenced proof root '{proof_root}' contains forbidden traversal components ('..')",
                        remediation="Proof root must not contain '..' components",
                        params={"slo_id": slo_id, "proof_root": proof_root},
                    ))
                else:
                    qual_dir = root / "qualification-artifacts"
                    parts = proof_path.parts
                    if parts and parts[0] == "qualification-artifacts":
                        parts = parts[1:]

                    if not parts:
                        findings.append(SloFinding(
                            severity="error",
                            code=CODE_PROOF_ROOT_NOT_FOUND,
                            path=path_str,
                            message=f"SLO {slo_id} referenced proof root '{proof_root}' points to qualification-artifacts root directory, not a file",
                            remediation="Proof root must point to a specific qualification receipt file",
                            params={"slo_id": slo_id, "proof_root": proof_root},
                        ))
                    else:
                        # F1: reject symlinks anywhere in the proof path (lstat each component; no .resolve() escape)
                        has_symlink = False
                        curr = qual_dir
                        try:
                            if os.path.islink(curr):
                                has_symlink = True
                        except OSError:
                            pass

                        for part in parts:
                            curr = curr / part
                            try:
                                if os.path.islink(curr):
                                    has_symlink = True
                                    break
                            except OSError:
                                pass

                        if has_symlink:
                            findings.append(SloFinding(
                                severity="error",
                                code=CODE_PROOF_ROOT_NOT_FOUND,
                                path=path_str,
                                message=f"SLO {slo_id} referenced proof root '{proof_root}' contains a symlink at '{curr}'; symlinks in proof paths are strictly forbidden",
                                remediation="Use real, regular files without symlinks for qualification proof roots",
                                params={"slo_id": slo_id, "proof_root": proof_root, "symlink": str(curr)},
                            ))
                        elif not curr.is_file():
                            findings.append(SloFinding(
                                severity="error",
                                code=CODE_PROOF_ROOT_NOT_FOUND,
                                path=path_str,
                                message=f"SLO {slo_id} referenced proof root does not exist as a regular file on disk: '{proof_root}'",
                                remediation=DIAGNOSTIC_REGISTRY[CODE_PROOF_ROOT_NOT_FOUND]["remediation"],
                                params={"slo_id": slo_id, "proof_root": proof_root},
                            ))
                        elif curr.name.startswith(".") or ".tmp." in curr.name or curr.name.endswith(".tmp"):
                            findings.append(SloFinding(
                                severity="error",
                                code=CODE_ACHIEVED_WITHOUT_PROOF_ROOT,
                                path=path_str,
                                message=f"SLO {slo_id} referenced proof root '{proof_root}' is a temporary or hidden receipt file; transient artifacts cannot serve as proof",
                                remediation="Qualification proof root must reference an official published receipt, not a temporary or hidden file",
                                params={"slo_id": slo_id, "proof_root": proof_root},
                            ))
                        else:
                            # F2: an achieved proof root must be a non-empty JSON file that parses as a qualification receipt with schema fss.release_qualification_receipt.v1
                            file_size = curr.stat().st_size
                            if file_size == 0:
                                findings.append(SloFinding(
                                    severity="error",
                                    code=CODE_ACHIEVED_WITHOUT_PROOF_ROOT,
                                    path=path_str,
                                    message=f"SLO {slo_id} referenced proof root '{proof_root}' is empty (0 bytes); existence is not proof",
                                    remediation="Qualification proof root must be a valid, non-empty receipt",
                                    params={"slo_id": slo_id, "proof_root": proof_root},
                                ))
                            else:
                                receipt_json: Any = None
                                try:
                                    content = curr.read_text(encoding="utf-8")
                                    receipt_json = json.loads(content)
                                except (json.JSONDecodeError, OSError, UnicodeDecodeError) as exc:
                                    findings.append(SloFinding(
                                        severity="error",
                                        code=CODE_ACHIEVED_WITHOUT_PROOF_ROOT,
                                        path=path_str,
                                        message=f"SLO {slo_id} referenced proof root '{proof_root}' is not valid JSON: {exc}",
                                        remediation="Ensure proof root contains valid JSON",
                                        params={"slo_id": slo_id, "proof_root": proof_root, "error": str(exc)},
                                    ))

                                if isinstance(receipt_json, dict):
                                    receipt_schema = receipt_json.get("schema")
                                    if receipt_schema not in ("fss.release_qualification_receipt.v1", "fss.proof_bundle.v1"):
                                        findings.append(SloFinding(
                                            severity="error",
                                            code=CODE_ACHIEVED_WITHOUT_PROOF_ROOT,
                                            path=path_str,
                                            message=f"SLO {slo_id} referenced proof root '{proof_root}' schema is '{receipt_schema}'; expected 'fss.release_qualification_receipt.v1' or 'fss.proof_bundle.v1'",
                                            remediation="Proof root must specify schema 'fss.release_qualification_receipt.v1' or 'fss.proof_bundle.v1'",
                                            params={"slo_id": slo_id, "proof_root": proof_root, "schema": str(receipt_schema)},
                                        ))
                                    elif receipt_schema == "fss.proof_bundle.v1":
                                        bundle_req = ["schema", "status"]
                                        missing_keys = [k for k in bundle_req if k not in receipt_json]
                                        bound_claim = receipt_json.get("claim_id") or receipt_json.get("claimId")
                                        if missing_keys:
                                            findings.append(SloFinding(
                                                severity="error",
                                                code=CODE_ACHIEVED_WITHOUT_PROOF_ROOT,
                                                path=path_str,
                                                message=f"SLO {slo_id} proof bundle '{proof_root}' missing required fields: {missing_keys}",
                                                remediation="Proof bundle must satisfy fss.proof_bundle.v1 schema",
                                                params={"slo_id": slo_id, "missing": missing_keys},
                                            ))
                                        elif bound_claim != slo_id:
                                            findings.append(SloFinding(
                                                severity="error",
                                                code=CODE_ACHIEVED_WITHOUT_PROOF_ROOT,
                                                path=path_str,
                                                message=f"SLO {slo_id} proof bundle '{proof_root}' claim_id is '{bound_claim}'; expected '{slo_id}'",
                                                remediation="Proof bundle must bind the citing SLO ID",
                                                params={"slo_id": slo_id, "claim_id": str(bound_claim)},
                                            ))
                                        elif receipt_json.get("status") != "passed":
                                            findings.append(SloFinding(
                                                severity="error",
                                                code=CODE_ACHIEVED_WITHOUT_PROOF_ROOT,
                                                path=path_str,
                                                message=f"SLO {slo_id} proof bundle '{proof_root}' status is '{receipt_json.get('status')}'; must be 'passed'",
                                                remediation="Achieved SLO must reference a passed proof bundle",
                                                params={"slo_id": slo_id, "status": str(receipt_json.get("status"))},
                                            ))
                                    else:
                                        receipt_req = [
                                            "receiptId", "laneId", "sourceCommit", "sourceTree",
                                            "siblingClosureDigest", "toolchain", "hostIdentity",
                                            "target", "features", "commands", "status"
                                        ]
                                        missing_keys = [k for k in receipt_req if k not in receipt_json]
                                        if missing_keys:
                                            findings.append(SloFinding(
                                                severity="error",
                                                code=CODE_ACHIEVED_WITHOUT_PROOF_ROOT,
                                                path=path_str,
                                                message=f"SLO {slo_id} qualification receipt '{proof_root}' missing required fields: {missing_keys}",
                                                remediation="Receipt must satisfy fss.release_qualification_receipt.v1 schema",
                                                params={"slo_id": slo_id, "missing": missing_keys},
                                            ))
                                        elif receipt_json.get("status") != "passed":
                                            findings.append(SloFinding(
                                                severity="error",
                                                code=CODE_ACHIEVED_WITHOUT_PROOF_ROOT,
                                                path=path_str,
                                                message=f"SLO {slo_id} qualification receipt '{proof_root}' status is '{receipt_json.get('status')}'; must be 'passed'",
                                                remediation="Achieved SLO must reference a passed qualification receipt",
                                                params={"slo_id": slo_id, "status": str(receipt_json.get("status"))},
                                            ))

        # Tombstone validation
        if is_tombstone:
            if status_raw != "tombstone":
                findings.append(SloFinding(
                    severity="error",
                    code=CODE_INVALID_SLO_STATUS,
                    path=path_str,
                    message=f"SLO {slo_id} specifies a tombstone in target/scope but has status '{status_raw}'; tombstone rows must have status 'tombstone' (never 'target' or 'achieved')",
                    remediation="Set status to 'tombstone' for superseded rows; tombstones cannot be target or achieved",
                    params={"slo_id": slo_id, "status": status_raw},
                ))
            if not superseded_by:
                findings.append(SloFinding(
                    severity="error",
                    code=CODE_INVALID_TOMBSTONE,
                    path=path_str,
                    message=f"Tombstone SLO {slo_id} must specify canonical successor using `tombstone: superseded by `SLO-...``",
                    remediation=DIAGNOSTIC_REGISTRY[CODE_INVALID_TOMBSTONE]["remediation"],
                    params={"slo_id": slo_id},
                ))
        elif status_raw == "tombstone":
            if not superseded_by:
                findings.append(SloFinding(
                    severity="error",
                    code=CODE_INVALID_TOMBSTONE,
                    path=path_str,
                    message=f"Tombstone SLO {slo_id} with status 'tombstone' must specify canonical successor using `tombstone: superseded by `SLO-...``",
                    remediation=DIAGNOSTIC_REGISTRY[CODE_INVALID_TOMBSTONE]["remediation"],
                    params={"slo_id": slo_id},
                ))
        
        slo_obj = SloRow(
            id=slo_id,
            target=target,
            measurement_surface=measurement_surface,
            status=status_raw,
            proof_root=proof_root,
            is_tombstone=is_tombstone,
            superseded_by=superseded_by,
        )
        slos[slo_id] = slo_obj
    
    # Second pass: validate tombstone chains (cycles and dangling references)
    for slo_id, slo_obj in slos.items():
        if slo_obj.is_tombstone and slo_obj.superseded_by:
            visited = {slo_id}
            curr = slo_obj.superseded_by
            while curr in slos and slos[curr].is_tombstone:
                if curr in visited:
                    findings.append(SloFinding(
                        severity="error",
                        code=CODE_INVALID_TOMBSTONE,
                        path=path_str,
                        message=f"Cyclic tombstone chain detected involving {slo_id} and {curr}",
                        remediation=DIAGNOSTIC_REGISTRY[CODE_INVALID_TOMBSTONE]["remediation"],
                        params={"slo_id": slo_id, "cycle_at": curr},
                    ))
                    break
                visited.add(curr)
                curr = slos[curr].superseded_by or ""
            
            if curr not in slos:
                findings.append(SloFinding(
                    severity="error",
                    code=CODE_INVALID_TOMBSTONE,
                    path=path_str,
                    message=f"Tombstone SLO {slo_id} points to unregistered successor '{curr}'",
                    remediation=DIAGNOSTIC_REGISTRY[CODE_INVALID_TOMBSTONE]["remediation"],
                    params={"slo_id": slo_id, "successor": curr},
                ))
    
    return slos


def validate_cost_references(
    costs_path: Path,
    slos: dict[str, SloRow],
    root: Path,
    findings: list[SloFinding],
    target_costs_md_path: Path | None = None,
) -> list[dict[str, Any]]:
    """Validate that every slo_ids entry in operation_cost_registry.toml resolves to a registered SLO,
    and enforce complete cost vectors, proof ownership, and drift tracking."""
    path_str = sanitize_path(costs_path, root)
    if not costs_path.is_file():
        findings.append(SloFinding(
            severity="error",
            code=CODE_MALFORMED_TABLE,
            path=path_str,
            message=f"Operation cost registry file missing: {path_str}",
            remediation="Restore architecture/operation_cost_registry.toml from reviewed custody",
            params={"path": path_str},
        ))
        return []

    try:
        cost_text = costs_path.read_text(encoding="utf-8")
        cost_data = tomllib.loads(cost_text)
    except (tomllib.TOMLDecodeError, OSError, UnicodeDecodeError) as exc:
        findings.append(SloFinding(
            severity="error",
            code=CODE_MALFORMED_TABLE,
            path=path_str,
            message=f"Failed to parse operation_cost_registry.toml: {exc}",
            remediation="Correct TOML syntax and UTF-8 encoding in architecture/operation_cost_registry.toml",
            params={"error": str(exc)},
        ))
        return []

    # Generation and Freeze Digest validation (SLO-VAL-022)
    declared_gen = str(cost_data.get("generation", "")).strip()
    declared_digest = str(cost_data.get("registry_digest", "")).strip()
    is_default_registry = (costs_path.resolve() == (root / "architecture/operation_cost_registry.toml").resolve())

    if not declared_gen:
        findings.append(SloFinding(
            severity="error",
            code=CODE_FREEZE_DIGEST_MISMATCH,
            path=path_str,
            message="Operation cost registry missing or empty 'generation'",
            remediation=DIAGNOSTIC_REGISTRY[CODE_FREEZE_DIGEST_MISMATCH]["remediation"],
        ))
    elif is_default_registry and declared_gen != BASELINE_OPERATION_COST_GENERATION:
        findings.append(SloFinding(
            severity="error",
            code=CODE_FREEZE_DIGEST_MISMATCH,
            path=path_str,
            message=f"Operation cost registry generation mismatch: declared '{declared_gen}', expected '{BASELINE_OPERATION_COST_GENERATION}'",
            remediation=DIAGNOSTIC_REGISTRY[CODE_FREEZE_DIGEST_MISMATCH]["remediation"],
            params={"declared_generation": declared_gen, "expected_generation": BASELINE_OPERATION_COST_GENERATION},
        ))

    if not declared_digest:
        findings.append(SloFinding(
            severity="error",
            code=CODE_FREEZE_DIGEST_MISMATCH,
            path=path_str,
            message="Operation cost registry missing or empty 'registry_digest'",
            remediation=DIAGNOSTIC_REGISTRY[CODE_FREEZE_DIGEST_MISMATCH]["remediation"],
        ))
    else:
        computed_digest = compute_canonical_cost_registry_digest(cost_data)
        if declared_digest != computed_digest:
            findings.append(SloFinding(
                severity="error",
                code=CODE_FREEZE_DIGEST_MISMATCH,
                path=path_str,
                message=f"Operation cost registry digest mismatch: declared '{declared_digest}', computed '{computed_digest}'",
                remediation=DIAGNOSTIC_REGISTRY[CODE_FREEZE_DIGEST_MISMATCH]["remediation"],
                params={"declared_digest": declared_digest, "computed_digest": computed_digest},
            ))

        expected_pinned = EXPECTED_OPERATION_COST_FREEZE_DIGESTS.get(declared_gen)
        if expected_pinned is None:
            findings.append(SloFinding(
                severity="error",
                code=CODE_FREEZE_DIGEST_MISMATCH,
                path=path_str,
                message=f"No pinned freeze digest for generation '{declared_gen}'",
                remediation=DIAGNOSTIC_REGISTRY[CODE_FREEZE_DIGEST_MISMATCH]["remediation"],
                params={"generation": declared_gen},
            ))
        elif declared_digest != expected_pinned:
            findings.append(SloFinding(
                severity="error",
                code=CODE_FREEZE_DIGEST_MISMATCH,
                path=path_str,
                message=f"Operation cost registry freeze digest diverged from pinned baseline: declared '{declared_digest}', pinned '{expected_pinned}'",
                remediation=DIAGNOSTIC_REGISTRY[CODE_FREEZE_DIGEST_MISMATCH]["remediation"],
                params={"declared_digest": declared_digest, "pinned_digest": expected_pinned},
            ))

    resolutions: list[dict[str, Any]] = []
    operations = cost_data.get("operation", [])
    if not isinstance(operations, list):
        findings.append(SloFinding(
            severity="error",
            code=CODE_MALFORMED_TABLE,
            path=path_str,
            message="operation_cost_registry.toml missing [[operation]] list",
            remediation="Ensure operation_cost_registry.toml defines [[operation]] tables",
        ))
        return []

    drifts = cost_data.get("drift", [])
    declared_drifts: dict[str, dict[str, Any]] = {}
    if isinstance(drifts, list):
        for d in drifts:
            if isinstance(d, dict) and "id" in d and isinstance(d["id"], str):
                declared_drifts[d["id"].strip()] = d

    seen_op_ids: dict[str, str] = {}
    tombstones = load_tombstone_set(root)

    for op in operations:
        if not isinstance(op, dict):
            findings.append(SloFinding(
                severity="error",
                code=CODE_MALFORMED_TABLE,
                path=path_str,
                message=f"Operation table entry is not a table/dict: {op!r}",
                remediation="Ensure every [[operation]] table is a valid dictionary/table",
                params={"operation": str(op)},
            ))
            continue

        cost_id = op.get("id", "UNKNOWN_COST")

        if not isinstance(cost_id, str) or not cost_id.strip():
            findings.append(SloFinding(
                severity="error",
                code=CODE_MALFORMED_TABLE,
                path=path_str,
                message=f"Operation table entry missing valid 'id': {op}",
                remediation="Ensure every [[operation]] table has a non-empty string 'id'",
                params={"operation": str(op)},
            ))
            continue

        cost_id = cost_id.strip()
        lower_cost_id = cost_id.lower()

        if not COST_ID_REGEX.match(cost_id):
            findings.append(SloFinding(
                severity="error",
                code=CODE_MALFORMED_TABLE,
                path=path_str,
                message=f"Operation ID '{cost_id}' does not match canonical format COST-*-NNN",
                remediation="Ensure operation ID matches uppercase format COST-*-NNN",
                params={"cost_id": cost_id},
            ))
            findings.append(SloFinding(
                severity="error",
                code=CODE_DUPLICATE_OR_RENUMBERED_COST_ID,
                path=path_str,
                message=f"Operation ID '{cost_id}' does not match canonical format COST-*-NNN or has been renumbered",
                remediation=DIAGNOSTIC_REGISTRY[CODE_DUPLICATE_OR_RENUMBERED_COST_ID]["remediation"],
                params={"cost_id": cost_id},
            ))
        elif cost_id not in CANONICAL_COST_OPERATIONS:
            if cost_id in tombstones:
                findings.append(SloFinding(
                    severity="error",
                    code=CODE_DUPLICATE_OR_RENUMBERED_COST_ID,
                    path=path_str,
                    message=f"Tombstoned operation ID '{cost_id}' cannot be resurrected or used as active",
                    remediation=DIAGNOSTIC_REGISTRY[CODE_DUPLICATE_OR_RENUMBERED_COST_ID]["remediation"],
                    params={"cost_id": cost_id},
                ))
            else:
                findings.append(SloFinding(
                    severity="error",
                    code=CODE_DUPLICATE_OR_RENUMBERED_COST_ID,
                    path=path_str,
                    message=f"Unknown, unregistered, or renumbered operation ID detected: '{cost_id}'. Stable IDs must never be renumbered or altered without formal registration.",
                    remediation=DIAGNOSTIC_REGISTRY[CODE_DUPLICATE_OR_RENUMBERED_COST_ID]["remediation"],
                    params={"cost_id": cost_id},
                ))

        if lower_cost_id in seen_op_ids:
            findings.append(SloFinding(
                severity="error",
                code=CODE_DUPLICATE_OR_RENUMBERED_COST_ID,
                path=path_str,
                message=f"Duplicate or case-colliding operation ID detected: '{cost_id}' (collides with '{seen_op_ids[lower_cost_id]}')",
                remediation=DIAGNOSTIC_REGISTRY[CODE_DUPLICATE_OR_RENUMBERED_COST_ID]["remediation"],
                params={"cost_id": cost_id, "collides_with": seen_op_ids[lower_cost_id]},
            ))
            continue
        seen_op_ids[lower_cost_id] = cost_id

        # Reject unknown keys in operation row
        unknown_keys = set(op.keys()) - KNOWN_OPERATION_KEYS
        if unknown_keys:
            if "slo_id" in unknown_keys:
                findings.append(SloFinding(
                    severity="error",
                    code=CODE_MALFORMED_TABLE,
                    path=path_str,
                    message=f"Operation {cost_id} uses invalid singular key 'slo_id'; operation costs must use 'slo_ids' list",
                    remediation="Change 'slo_id' to 'slo_ids' with a list of registered SLO IDs",
                    params={"cost_id": cost_id, "unknown_keys": sorted(unknown_keys)},
                ))
            else:
                findings.append(SloFinding(
                    severity="error",
                    code=CODE_MALFORMED_TABLE,
                    path=path_str,
                    message=f"Operation {cost_id} contains unknown key(s): {sorted(unknown_keys)}. Allowed keys: {sorted(KNOWN_OPERATION_KEYS)}",
                    remediation="Remove unknown keys from operation table",
                    params={"cost_id": cost_id, "unknown_keys": sorted(unknown_keys)},
                ))

        # Unit validation: every operation must specify a non-empty unit
        unit_val = op.get("unit")
        if not isinstance(unit_val, str) or not unit_val.strip():
            findings.append(SloFinding(
                severity="error",
                code=CODE_MALFORMED_TABLE,
                path=path_str,
                message=f"Operation '{cost_id}' missing or empty 'unit'; every operation cost row must specify its measurement unit",
                remediation="Provide a non-empty string 'unit' for the operation",
                params={"cost_id": cost_id},
            ))

        if "slo_ids" not in op:
            findings.append(SloFinding(
                severity="error",
                code=CODE_UNREGISTERED_SLO_REFERENCE,
                path=path_str,
                message=f"Operation {cost_id} lacks 'slo_ids'; every operation must link to at least one valid SLO",
                remediation="Add 'slo_ids' list with registered SLO IDs",
                params={"cost_id": cost_id},
            ))
            continue

        referenced_slos = op.get("slo_ids", [])
        if not isinstance(referenced_slos, list) or len(referenced_slos) == 0:
            findings.append(SloFinding(
                severity="error",
                code=CODE_UNREGISTERED_SLO_REFERENCE,
                path=path_str,
                message=f"Operation {cost_id} has empty or non-list 'slo_ids'; every operation must link to at least one valid SLO",
                remediation="Ensure 'slo_ids' is a non-empty list of registered SLO IDs",
                params={"cost_id": cost_id},
            ))
            continue

        for ref_slo_id in referenced_slos:
            if not isinstance(ref_slo_id, str) or not ref_slo_id.strip():
                findings.append(SloFinding(
                    severity="error",
                    code=CODE_UNREGISTERED_SLO_REFERENCE,
                    path=path_str,
                    message=f"Operation {cost_id} has empty string in 'slo_ids'; every operation must link to at least one valid SLO",
                    remediation="Ensure 'slo_ids' contains non-empty, registered SLO IDs",
                    params={"cost_id": cost_id, "slo_id": str(ref_slo_id)},
                ))
                continue

            if not SLO_ID_REGEX.match(ref_slo_id):
                findings.append(SloFinding(
                    severity="error",
                    code=CODE_MALFORMED_COST_SLO_REFERENCE,
                    path=path_str,
                    message=f"Operation {cost_id} references malformed SLO ID '{ref_slo_id}'",
                    remediation=DIAGNOSTIC_REGISTRY[CODE_MALFORMED_COST_SLO_REFERENCE]["remediation"],
                    params={"cost_id": cost_id, "slo_id": str(ref_slo_id)},
                ))
                continue

            if ref_slo_id not in slos:
                findings.append(SloFinding(
                    severity="error",
                    code=CODE_UNREGISTERED_SLO_REFERENCE,
                    path=path_str,
                    message=f"Operation cost {cost_id} references unregistered SLO: {ref_slo_id}",
                    remediation=DIAGNOSTIC_REGISTRY[CODE_UNREGISTERED_SLO_REFERENCE]["remediation"],
                    params={"cost_id": cost_id, "slo_id": ref_slo_id},
                ))
            else:
                slo_info = slos[ref_slo_id]
                if slo_info.is_tombstone:
                    canonical_target = slo_info.superseded_by or slo_info.id
                    findings.append(SloFinding(
                        severity="error",
                        code=CODE_TOMBSTONE_REFERENCED_AS_ACTIVE,
                        path=path_str,
                        message=f"Active operation {cost_id} directly references tombstoned SLO '{ref_slo_id}'; must cite canonical successor '{canonical_target}'",
                        remediation=DIAGNOSTIC_REGISTRY[CODE_TOMBSTONE_REFERENCED_AS_ACTIVE]["remediation"],
                        params={"cost_id": cost_id, "referenced_slo_id": ref_slo_id, "successor": canonical_target},
                    ))
                    continue

                resolutions.append({
                    "cost_id": cost_id,
                    "referenced_slo_id": ref_slo_id,
                    "resolved_canonical_id": slo_info.id,
                    "is_tombstone": False,
                    "status": slo_info.status,
                })

        # Cost vector validation: every operation must carry a complete machine-readable cost vector
        is_mandatory_hot_path = (
            cost_id in MANDATORY_HOT_PATHS or lower_cost_id in MANDATORY_HOT_PATHS_LOWER
        )
        has_cost_vector = "cost_vector" in op
        has_baseline = "baseline_reference" in op

        # If it is any operation in the registry, cost_vector is required
        if not has_cost_vector:
            findings.append(SloFinding(
                severity="error",
                code=CODE_MISSING_COST_VECTOR_OR_BASELINE,
                path=path_str,
                message=f"Operation '{cost_id}' lacks 'cost_vector' table",
                remediation=DIAGNOSTIC_REGISTRY[CODE_MISSING_COST_VECTOR_OR_BASELINE]["remediation"],
                params={"cost_id": cost_id},
            ))
        elif not isinstance(op["cost_vector"], dict):
            findings.append(SloFinding(
                severity="error",
                code=CODE_MISSING_COST_VECTOR_OR_BASELINE,
                path=path_str,
                message=f"Operation '{cost_id}' 'cost_vector' must be a table/dictionary",
                remediation=DIAGNOSTIC_REGISTRY[CODE_MISSING_COST_VECTOR_OR_BASELINE]["remediation"],
                params={"cost_id": cost_id},
            ))
        else:
            cv = op["cost_vector"]
            extra_dims = sorted(set(cv.keys()) - set(REQUIRED_COST_VECTOR_DIMENSIONS))
            if extra_dims:
                findings.append(SloFinding(
                    severity="error",
                    code=CODE_MISSING_COST_VECTOR_OR_BASELINE,
                    path=path_str,
                    message=f"Operation '{cost_id}' 'cost_vector' contains extraneous dimension(s): {extra_dims}",
                    remediation=DIAGNOSTIC_REGISTRY[CODE_MISSING_COST_VECTOR_OR_BASELINE]["remediation"],
                    params={"cost_id": cost_id, "extraneous_dimensions": extra_dims},
                ))
            missing_dims = sorted(set(REQUIRED_COST_VECTOR_DIMENSIONS) - set(cv.keys()))
            if missing_dims:
                findings.append(SloFinding(
                    severity="error",
                    code=CODE_MISSING_COST_VECTOR_OR_BASELINE,
                    path=path_str,
                    message=f"Operation '{cost_id}' 'cost_vector' lacks required dimension(s): {missing_dims}",
                    remediation=DIAGNOSTIC_REGISTRY[CODE_MISSING_COST_VECTOR_OR_BASELINE]["remediation"],
                    params={"cost_id": cost_id, "missing_dimensions": missing_dims},
                ))
            for dim in REQUIRED_COST_VECTOR_DIMENSIONS:
                if dim in cv:
                    val = cv[dim]
                    if (
                        not isinstance(val, (int, float))
                        or isinstance(val, bool)
                        or math.isnan(val)
                        or math.isinf(val)
                        or val < 0
                    ):
                        findings.append(SloFinding(
                            severity="error",
                            code=CODE_MISSING_COST_VECTOR_OR_BASELINE,
                            path=path_str,
                            message=f"Operation '{cost_id}' dimension '{dim}' must be non-negative finite numeric value, got {val}",
                            remediation=DIAGNOSTIC_REGISTRY[CODE_MISSING_COST_VECTOR_OR_BASELINE]["remediation"],
                            params={"cost_id": cost_id, "dimension": dim, "value": val},
                        ))

        # Baseline reference validation (for hot paths or where declared)
        if is_mandatory_hot_path and not has_baseline:
            findings.append(SloFinding(
                severity="error",
                code=CODE_MISSING_COST_VECTOR_OR_BASELINE,
                path=path_str,
                message=f"Mandatory hot/consequential path '{cost_id}' lacks 'baseline_reference'",
                remediation=DIAGNOSTIC_REGISTRY[CODE_MISSING_COST_VECTOR_OR_BASELINE]["remediation"],
                params={"cost_id": cost_id},
            ))
        elif has_baseline:
            base_ref = op["baseline_reference"]
            if not isinstance(base_ref, str) or not base_ref.strip():
                findings.append(SloFinding(
                    severity="error",
                    code=CODE_MISSING_COST_VECTOR_OR_BASELINE,
                    path=path_str,
                    message=f"Operation '{cost_id}' 'baseline_reference' must be a non-empty string",
                    remediation=DIAGNOSTIC_REGISTRY[CODE_MISSING_COST_VECTOR_OR_BASELINE]["remediation"],
                    params={"cost_id": cost_id},
                ))
            else:
                file_part = base_ref.split(":")[0].strip()
                ref_file = root / file_part
                if not (
                    file_part.endswith(".rs")
                    and (
                        file_part.startswith("tests/")
                        or file_part.startswith("benches/")
                        or file_part.startswith("crates/")
                    )
                ):
                    findings.append(SloFinding(
                        severity="error",
                        code=CODE_MISSING_COST_VECTOR_OR_BASELINE,
                        path=path_str,
                        message=f"Operation '{cost_id}' baseline reference '{base_ref}' must be a Rust test/benchmark file (.rs) under tests/, benches/, or crates/",
                        remediation=DIAGNOSTIC_REGISTRY[CODE_MISSING_COST_VECTOR_OR_BASELINE]["remediation"],
                        params={"cost_id": cost_id, "baseline_reference": base_ref, "file": file_part},
                    ))
                elif not ref_file.is_file():
                    findings.append(SloFinding(
                        severity="error",
                        code=CODE_MISSING_COST_VECTOR_OR_BASELINE,
                        path=path_str,
                        message=f"Operation '{cost_id}' baseline reference '{base_ref}' does not exist on disk as a file",
                        remediation=DIAGNOSTIC_REGISTRY[CODE_MISSING_COST_VECTOR_OR_BASELINE]["remediation"],
                        params={"cost_id": cost_id, "baseline_reference": base_ref, "file": file_part},
                    ))
                else:
                    content = ref_file.read_text(encoding="utf-8", errors="replace")
                    has_test_markers = any(
                        marker in content
                        for marker in (
                            "#[test]",
                            "#[tokio::test]",
                            "#[asupersync::test]",
                            "fn test_",
                            "assert!",
                            "assert_eq!",
                        )
                    )
                    if not has_test_markers:
                        findings.append(SloFinding(
                            severity="error",
                            code=CODE_MISSING_COST_VECTOR_OR_BASELINE,
                            path=path_str,
                            message=f"Operation '{cost_id}' baseline reference '{base_ref}' contains no test routines or assertions",
                            remediation=DIAGNOSTIC_REGISTRY[CODE_MISSING_COST_VECTOR_OR_BASELINE]["remediation"],
                            params={"cost_id": cost_id, "baseline_reference": base_ref, "file": file_part},
                        ))

        # Proof owner validation (SLO-VAL-017)
        raw_owner = op.get("proof_owner") or op.get("owner")
        is_drift = False
        if not isinstance(raw_owner, str) or not raw_owner.strip():
            findings.append(SloFinding(
                severity="error",
                code=CODE_MISSING_OR_UNKNOWN_OWNER,
                path=path_str,
                message=f"Operation '{cost_id}' lacks a named 'proof_owner'",
                remediation=DIAGNOSTIC_REGISTRY[CODE_MISSING_OR_UNKNOWN_OWNER]["remediation"],
                params={"cost_id": cost_id},
            ))
        else:
            owner_str = raw_owner.strip()
            if owner_str.startswith("drift:"):
                is_drift = True
                drift_id = owner_str.split(":", 1)[1].strip()
                if not drift_id or drift_id not in declared_drifts:
                    findings.append(SloFinding(
                        severity="error",
                        code=CODE_MISSING_OR_UNKNOWN_OWNER,
                        path=path_str,
                        message=f"Operation '{cost_id}' references undeclared drift owner '{owner_str}' (not in [[drift]])",
                        remediation=DIAGNOSTIC_REGISTRY[CODE_MISSING_OR_UNKNOWN_OWNER]["remediation"],
                        params={"cost_id": cost_id, "drift_id": drift_id},
                    ))
            elif owner_str == "unknown":
                findings.append(SloFinding(
                    severity="error",
                    code=CODE_MISSING_OR_UNKNOWN_OWNER,
                    path=path_str,
                    message=f"Operation '{cost_id}' has unknown proof_owner; genuinely unknown proof owners must be recorded as explicit drift rows (drift:DRIFT-...)",
                    remediation=DIAGNOSTIC_REGISTRY[CODE_MISSING_OR_UNKNOWN_OWNER]["remediation"],
                    params={"cost_id": cost_id},
                ))
            elif not owner_str.startswith("crates/"):
                findings.append(SloFinding(
                    severity="error",
                    code=CODE_MISSING_OR_UNKNOWN_OWNER,
                    path=path_str,
                    message=f"Operation '{cost_id}' proof_owner '{owner_str}' must resolve to a crate directory under 'crates/' or a Rust module within 'crates/'",
                    remediation="Set proof_owner to a crate under crates/ (e.g. 'crates/fss-core') or an explicit drift entry",
                    params={"cost_id": cost_id, "proof_owner": owner_str},
                ))
            else:
                owner_path = root / owner_str
                is_crate = owner_path.is_dir() and (owner_path / "Cargo.toml").is_file()
                is_mod = (owner_path.is_file() and owner_str.endswith(".rs")) or (root / f"{owner_str}.rs").is_file()
                if not (is_crate or is_mod):
                    findings.append(SloFinding(
                        severity="error",
                        code=CODE_MISSING_OR_UNKNOWN_OWNER,
                        path=path_str,
                        message=f"Operation '{cost_id}' proof_owner '{owner_str}' does not resolve to an existing crate or Rust module on disk under 'crates/'",
                        remediation=DIAGNOSTIC_REGISTRY[CODE_MISSING_OR_UNKNOWN_OWNER]["remediation"],
                        params={"cost_id": cost_id, "proof_owner": owner_str},
                    ))

        # Proof reference validation (SLO-VAL-018)
        if is_drift:
            proof_ref = op.get("proof_reference")
            if not isinstance(proof_ref, str) or not proof_ref.strip():
                findings.append(SloFinding(
                    severity="error",
                    code=CODE_PROOF_REFERENCE_NOT_FOUND,
                    path=path_str,
                    message=f"Operation '{cost_id}' lacks 'proof_reference'",
                    remediation=DIAGNOSTIC_REGISTRY[CODE_PROOF_REFERENCE_NOT_FOUND]["remediation"],
                    params={"cost_id": cost_id},
                ))
            elif not proof_ref.strip().startswith("drift:"):
                findings.append(SloFinding(
                    severity="error",
                    code=CODE_PROOF_REFERENCE_NOT_FOUND,
                    path=path_str,
                    message=f"Operation '{cost_id}' is drift but proof_reference '{proof_ref}' does not start with 'drift:'",
                    remediation=DIAGNOSTIC_REGISTRY[CODE_PROOF_REFERENCE_NOT_FOUND]["remediation"],
                    params={"cost_id": cost_id, "proof_reference": proof_ref},
                ))
        else:
            proof_ref = op.get("proof_reference")
            if not isinstance(proof_ref, str) or not proof_ref.strip():
                findings.append(SloFinding(
                    severity="error",
                    code=CODE_PROOF_REFERENCE_NOT_FOUND,
                    path=path_str,
                    message=f"Operation '{cost_id}' lacks 'proof_reference'",
                    remediation=DIAGNOSTIC_REGISTRY[CODE_PROOF_REFERENCE_NOT_FOUND]["remediation"],
                    params={"cost_id": cost_id},
                ))
            else:
                proof_ref = proof_ref.strip()
                if "::" not in proof_ref:
                    findings.append(SloFinding(
                        severity="error",
                        code=CODE_PROOF_REFERENCE_NOT_FOUND,
                        path=path_str,
                        message=f"Operation '{cost_id}' proof_reference '{proof_ref}' must specify file and test fn separated by '::'",
                        remediation=DIAGNOSTIC_REGISTRY[CODE_PROOF_REFERENCE_NOT_FOUND]["remediation"],
                        params={"cost_id": cost_id, "proof_reference": proof_ref},
                    ))
                else:
                    ref_file_str, test_fn = proof_ref.split("::", 1)
                    ref_file_str = ref_file_str.strip()
                    test_fn = test_fn.strip()
                    ref_file = root / ref_file_str
                    if not (ref_file_str.endswith(".rs") and ref_file.is_file()):
                        findings.append(SloFinding(
                            severity="error",
                            code=CODE_PROOF_REFERENCE_NOT_FOUND,
                            path=path_str,
                            message=f"Operation '{cost_id}' proof_reference file '{ref_file_str}' does not exist on disk as a Rust source file",
                            remediation=DIAGNOSTIC_REGISTRY[CODE_PROOF_REFERENCE_NOT_FOUND]["remediation"],
                            params={"cost_id": cost_id, "file": ref_file_str},
                        ))
                    elif not test_fn:
                        findings.append(SloFinding(
                            severity="error",
                            code=CODE_PROOF_REFERENCE_NOT_FOUND,
                            path=path_str,
                            message=f"Operation '{cost_id}' proof_reference '{proof_ref}' specifies an empty test function name",
                            remediation=DIAGNOSTIC_REGISTRY[CODE_PROOF_REFERENCE_NOT_FOUND]["remediation"],
                            params={"cost_id": cost_id, "proof_reference": proof_ref},
                        ))
                    else:
                        file_content = ref_file.read_text(encoding="utf-8", errors="replace")
                        cleaned_content = strip_rust_comments_and_strings(file_content)
                        fn_pattern = re.compile(r"\b(?:async\s+)?fn\s+" + re.escape(test_fn) + r"\b")
                        if not fn_pattern.search(cleaned_content):
                            findings.append(SloFinding(
                                severity="error",
                                code=CODE_PROOF_REFERENCE_NOT_FOUND,
                                path=path_str,
                                message=f"Operation '{cost_id}' proof_reference test fn '{test_fn}' not found in '{ref_file_str}' (excluding comments/docstrings)",
                                remediation=DIAGNOSTIC_REGISTRY[CODE_PROOF_REFERENCE_NOT_FOUND]["remediation"],
                                params={"cost_id": cost_id, "file": ref_file_str, "test_fn": test_fn},
                            ))

        # Measured status validation (SLO-VAL-020)
        status_val = op.get("status", "model_required")
        if status_val == "measured":
            meas_artifact = op.get("measurement_artifact")
            if not isinstance(meas_artifact, str) or not meas_artifact.strip():
                findings.append(SloFinding(
                    severity="error",
                    code=CODE_MEASURED_WITHOUT_ARTIFACT,
                    path=path_str,
                    message=f"Operation '{cost_id}' has status 'measured' but lacks 'measurement_artifact'",
                    remediation=DIAGNOSTIC_REGISTRY[CODE_MEASURED_WITHOUT_ARTIFACT]["remediation"],
                    params={"cost_id": cost_id},
                ))
            else:
                raw_art = meas_artifact.strip()
                meas_path = Path(raw_art)
                if meas_path.is_absolute():
                    findings.append(SloFinding(
                        severity="error",
                        code=CODE_MEASURED_WITHOUT_ARTIFACT,
                        path=path_str,
                        message=f"Operation '{cost_id}' measurement artifact cannot be an absolute path: '{raw_art}'",
                        remediation="Measurement artifact must be a relative path strictly within qualification-artifacts/",
                        params={"cost_id": cost_id, "measurement_artifact": raw_art},
                    ))
                elif ".." in meas_path.parts:
                    findings.append(SloFinding(
                        severity="error",
                        code=CODE_MEASURED_WITHOUT_ARTIFACT,
                        path=path_str,
                        message=f"Operation '{cost_id}' measurement artifact '{raw_art}' contains forbidden traversal components ('..')",
                        remediation="Measurement artifact must not contain '..' components",
                        params={"cost_id": cost_id, "measurement_artifact": raw_art},
                    ))
                elif not (meas_path.parts and meas_path.parts[0] == "qualification-artifacts" and len(meas_path.parts) >= 2):
                    findings.append(SloFinding(
                        severity="error",
                        code=CODE_MEASURED_WITHOUT_ARTIFACT,
                        path=path_str,
                        message=f"Operation '{cost_id}' measurement artifact '{raw_art}' must be located strictly under qualification-artifacts/",
                        remediation="Measurement artifact must point to a file under qualification-artifacts/",
                        params={"cost_id": cost_id, "measurement_artifact": raw_art},
                    ))
                else:
                    curr = root / "qualification-artifacts"
                    has_symlink = False
                    for part in meas_path.parts[1:]:
                        curr = curr / part
                        try:
                            if os.path.islink(curr):
                                has_symlink = True
                                break
                        except OSError:
                            pass

                    if has_symlink:
                        findings.append(SloFinding(
                            severity="error",
                            code=CODE_MEASURED_WITHOUT_ARTIFACT,
                            path=path_str,
                            message=f"Operation '{cost_id}' measurement artifact '{raw_art}' contains a symlink at '{curr}'; symlinks are strictly forbidden",
                            remediation="Use regular files without symlinks for measurement artifacts",
                            params={"cost_id": cost_id, "measurement_artifact": raw_art, "symlink": str(curr)},
                        ))
                    elif not curr.is_file():
                        findings.append(SloFinding(
                            severity="error",
                            code=CODE_MEASURED_WITHOUT_ARTIFACT,
                            path=path_str,
                            message=f"Operation '{cost_id}' measurement artifact '{raw_art}' does not exist as a regular file on disk",
                            remediation=DIAGNOSTIC_REGISTRY[CODE_MEASURED_WITHOUT_ARTIFACT]["remediation"],
                            params={"cost_id": cost_id, "measurement_artifact": raw_art},
                        ))
                    elif curr.name.startswith(".") or ".tmp." in curr.name or curr.name.endswith(".tmp"):
                        findings.append(SloFinding(
                            severity="error",
                            code=CODE_MEASURED_WITHOUT_ARTIFACT,
                            path=path_str,
                            message=f"Operation '{cost_id}' measurement artifact '{raw_art}' is a temporary or hidden file; transient artifacts cannot serve as proof",
                            remediation="Measurement artifact must reference an official published receipt or measurement",
                            params={"cost_id": cost_id, "measurement_artifact": raw_art},
                        ))
                    elif curr.stat().st_size == 0:
                        findings.append(SloFinding(
                            severity="error",
                            code=CODE_MEASURED_WITHOUT_ARTIFACT,
                            path=path_str,
                            message=f"Operation '{cost_id}' measurement artifact '{raw_art}' is empty (0 bytes); existence is not proof",
                            remediation="Measurement artifact must be a valid, non-empty JSON file",
                            params={"cost_id": cost_id, "measurement_artifact": raw_art},
                        ))
                    else:
                        art_json: Any = None
                        try:
                            art_json = json.loads(curr.read_text(encoding="utf-8"))
                        except Exception as exc:
                            findings.append(SloFinding(
                                severity="error",
                                code=CODE_MEASURED_WITHOUT_ARTIFACT,
                                path=path_str,
                                message=f"Operation '{cost_id}' measurement artifact '{raw_art}' is not valid JSON: {exc}",
                                remediation="Ensure measurement artifact contains valid JSON",
                                params={"cost_id": cost_id, "measurement_artifact": raw_art, "error": str(exc)},
                            ))

                        if isinstance(art_json, dict):
                            art_schema = art_json.get("schema")
                            if art_schema == "fss.release_qualification_receipt.v1":
                                req_keys = ["receiptId", "laneId", "sourceCommit", "toolchain", "hostIdentity", "target", "status"]
                                missing = [k for k in req_keys if k not in art_json]
                                if missing:
                                    findings.append(SloFinding(
                                        severity="error",
                                        code=CODE_MEASURED_WITHOUT_ARTIFACT,
                                        path=path_str,
                                        message=f"Operation '{cost_id}' measurement receipt '{raw_art}' missing required fields: {missing}",
                                        remediation="Receipt must satisfy fss.release_qualification_receipt.v1 schema",
                                        params={"cost_id": cost_id, "missing": missing},
                                    ))
                                elif art_json.get("status") != "passed":
                                    findings.append(SloFinding(
                                        severity="error",
                                        code=CODE_MEASURED_WITHOUT_ARTIFACT,
                                        path=path_str,
                                        message=f"Operation '{cost_id}' measurement receipt '{raw_art}' status is '{art_json.get('status')}'; must be 'passed'",
                                        remediation="Measured status requires a passed qualification receipt",
                                        params={"cost_id": cost_id, "status": str(art_json.get("status"))},
                                    ))
                            elif art_schema == "fss.operation_cost_measurement.v1":
                                req_keys = ["operation_id", "generation", "environment", "status"]
                                missing = [k for k in req_keys if k not in art_json]
                                if missing:
                                    findings.append(SloFinding(
                                        severity="error",
                                        code=CODE_MEASURED_WITHOUT_ARTIFACT,
                                        path=path_str,
                                        message=f"Operation '{cost_id}' measurement artifact '{raw_art}' missing required fields: {missing}",
                                        remediation="Measurement artifact must satisfy fss.operation_cost_measurement.v1 schema",
                                        params={"cost_id": cost_id, "missing": missing},
                                    ))
                                elif art_json.get("operation_id") != cost_id:
                                    findings.append(SloFinding(
                                        severity="error",
                                        code=CODE_MEASURED_WITHOUT_ARTIFACT,
                                        path=path_str,
                                        message=f"Operation '{cost_id}' measurement artifact '{raw_art}' operation_id is '{art_json.get('operation_id')}'; expected '{cost_id}'",
                                        remediation="Measurement artifact must anchor the exact operation ID",
                                        params={"cost_id": cost_id, "artifact_operation_id": str(art_json.get("operation_id"))},
                                    ))
                                elif art_json.get("status") not in ("passed", "measured"):
                                    findings.append(SloFinding(
                                        severity="error",
                                        code=CODE_MEASURED_WITHOUT_ARTIFACT,
                                        path=path_str,
                                        message=f"Operation '{cost_id}' measurement artifact '{raw_art}' status is '{art_json.get('status')}'; must be 'passed' or 'measured'",
                                        remediation="Measurement artifact must indicate passed or measured status",
                                        params={"cost_id": cost_id, "status": str(art_json.get("status"))},
                                    ))
                            else:
                                findings.append(SloFinding(
                                    severity="error",
                                    code=CODE_MEASURED_WITHOUT_ARTIFACT,
                                    path=path_str,
                                    message=f"Operation '{cost_id}' measurement artifact '{raw_art}' has invalid or missing schema '{art_schema}'; expected 'fss.release_qualification_receipt.v1' or 'fss.operation_cost_measurement.v1'",
                                    remediation="Measurement artifact must declare valid receipt schema",
                                    params={"cost_id": cost_id, "schema": str(art_schema)},
                                ))

    # Check that every mandatory canonical and hot/consequential path is present
    seen_exact_ids = set(seen_op_ids.values())
    missing_canonical = sorted(CANONICAL_COST_OPERATIONS - seen_exact_ids)
    if missing_canonical:
        findings.append(SloFinding(
            severity="error",
            code=CODE_DUPLICATE_OR_RENUMBERED_COST_ID,
            path=path_str,
            message=f"Canonical operation ID(s) missing from registry (possible renumbering or deletion): {missing_canonical}",
            remediation=DIAGNOSTIC_REGISTRY[CODE_DUPLICATE_OR_RENUMBERED_COST_ID]["remediation"],
            params={"missing_canonical": missing_canonical},
        ))

    for hot_id, hot_info in MANDATORY_HOT_PATHS.items():
        if hot_id not in seen_exact_ids:
            findings.append(SloFinding(
                severity="error",
                code=CODE_HOT_PATH_MISSING_COST_ROW,
                path=path_str,
                message=f"Mandatory hot/consequential path '{hot_id}' ({hot_info['name']}) lacks an operation-cost row in {path_str}",
                remediation=DIAGNOSTIC_REGISTRY[CODE_HOT_PATH_MISSING_COST_ROW]["remediation"],
                params={"cost_id": hot_id, "name": hot_info["name"]},
            ))

    # Validate [[drift]] rows in TOML
    seen_drift_ids: set[str] = set()
    for d in drifts:
        if not isinstance(d, dict):
            findings.append(SloFinding(
                severity="error",
                code=CODE_MALFORMED_TABLE,
                path=path_str,
                message=f"Drift entry is not a table: {d!r}",
                remediation="Ensure [[drift]] entries are tables",
            ))
            continue
        did = str(d.get("id", "")).strip()
        if not did or not re.match(r"^DRIFT-[0-9]{3}$", did):
            findings.append(SloFinding(
                severity="error",
                code=CODE_MALFORMED_TABLE,
                path=path_str,
                message=f"Drift ID '{did}' does not match format DRIFT-NNN",
                remediation="Ensure drift ID matches DRIFT-NNN",
                params={"drift_id": did},
            ))
            continue
        if did in seen_drift_ids:
            findings.append(SloFinding(
                severity="error",
                code=CODE_DUPLICATE_OR_RENUMBERED_COST_ID,
                path=path_str,
                message=f"Duplicate drift ID '{did}' in {path_str}",
                remediation="Ensure drift IDs are unique",
                params={"drift_id": did},
            ))
            continue
        seen_drift_ids.add(did)

        d_op = str(d.get("operation_id", "")).strip()
        if not d_op or d_op not in CANONICAL_COST_OPERATIONS:
            findings.append(SloFinding(
                severity="error",
                code=CODE_MALFORMED_TABLE,
                path=path_str,
                message=f"Drift '{did}' references unregistered operation_id '{d_op}'",
                remediation="Ensure drift references a canonical operation ID",
                params={"drift_id": did, "operation_id": d_op},
            ))

        d_lane = str(d.get("target_lane", "")).strip()
        if not d_lane or not d_lane.startswith("crates/"):
            findings.append(SloFinding(
                severity="error",
                code=CODE_MISSING_OR_UNKNOWN_OWNER,
                path=path_str,
                message=f"Drift '{did}' target_lane '{d_lane}' must start with 'crates/'",
                remediation="Specify a valid crate path under crates/ for target_lane",
                params={"drift_id": did, "target_lane": d_lane},
            ))

    missing_drifts = sorted(CANONICAL_DRIFT_IDS - seen_drift_ids)
    if missing_drifts:
        findings.append(SloFinding(
            severity="error",
            code=CODE_DUPLICATE_OR_RENUMBERED_COST_ID,
            path=path_str,
            message=f"Canonical drift ID(s) missing from registry: {missing_drifts}",
            remediation="Ensure all canonical drift IDs are tracked in [[drift]]",
            params={"missing_drifts": missing_drifts},
        ))

    # Owner and mirror disagreement validation (SLO-VAL-019)
    if target_costs_md_path and target_costs_md_path.is_file():
        md_text = target_costs_md_path.read_text(encoding="utf-8")
        md_ops: dict[str, dict[str, Any]] = {}
        md_drifts: dict[str, dict[str, str]] = {}
        in_drift_section = False

        for line in md_text.splitlines():
            s = line.strip()
            if "## Operation cost drift registry" in s:
                in_drift_section = True
                continue
            if not (s.startswith("|") and s.endswith("|")):
                continue
            cells = [c.strip().strip("`") for c in s[1:-1].split("|")]
            if not cells:
                continue
            first = cells[0]
            if in_drift_section:
                if first.startswith("DRIFT-"):
                    if len(cells) >= 5:
                        if first in md_drifts:
                            findings.append(SloFinding(
                                severity="error",
                                code=CODE_DUPLICATE_OR_RENUMBERED_COST_ID,
                                path=sanitize_path(target_costs_md_path, root),
                                message=f"Duplicate drift ID '{first}' in registries/OPERATION_COSTS.md",
                                remediation=DIAGNOSTIC_REGISTRY[CODE_DUPLICATE_OR_RENUMBERED_COST_ID]["remediation"],
                                params={"drift_id": first},
                            ))
                        md_drifts[first] = {
                            "operation_id": cells[1],
                            "status": cells[2],
                            "description": cells[3],
                            "target_lane": cells[4],
                        }
            else:
                if first.startswith("COST-"):
                    if len(cells) >= 6:
                        if first in md_ops:
                            findings.append(SloFinding(
                                severity="error",
                                code=CODE_DUPLICATE_OR_RENUMBERED_COST_ID,
                                path=sanitize_path(target_costs_md_path, root),
                                message=f"Duplicate operation ID '{first}' in registries/OPERATION_COSTS.md",
                                remediation=DIAGNOSTIC_REGISTRY[CODE_DUPLICATE_OR_RENUMBERED_COST_ID]["remediation"],
                                params={"cost_id": first},
                            ))
                        md_ops[first] = {
                            "unit": cells[1],
                            "semantic_steps": [w.strip() for w in cells[2].split(",") if w.strip()],
                            "variable_costs": [w.strip() for w in cells[3].split(",") if w.strip()],
                            "proof_owner": cells[4],
                            "proof_reference": cells[5],
                        }

        # Compare TOML operations against Markdown
        for op in operations:
            if not isinstance(op, dict):
                continue
            cid = op.get("id")
            if not cid or not isinstance(cid, str):
                continue
            cid = cid.strip()
            if cid not in md_ops:
                findings.append(SloFinding(
                    severity="error",
                    code=CODE_OWNER_MIRROR_DISAGREEMENT,
                    path=sanitize_path(target_costs_md_path, root),
                    message=f"Operation '{cid}' in TOML is missing from registries/OPERATION_COSTS.md table",
                    remediation=DIAGNOSTIC_REGISTRY[CODE_OWNER_MIRROR_DISAGREEMENT]["remediation"],
                    params={"cost_id": cid},
                ))
            else:
                md_entry = md_ops[cid]
                # Check unit
                toml_unit = str(op.get("unit") or "").strip()
                md_unit = md_entry["unit"].strip()
                if toml_unit != md_unit:
                    findings.append(SloFinding(
                        severity="error",
                        code=CODE_OWNER_MIRROR_DISAGREEMENT,
                        path=sanitize_path(target_costs_md_path, root),
                        message=f"Operation '{cid}' unit mismatch: TOML has '{toml_unit}', Markdown has '{md_unit}'",
                        remediation=DIAGNOSTIC_REGISTRY[CODE_OWNER_MIRROR_DISAGREEMENT]["remediation"],
                        params={"cost_id": cid, "toml_unit": toml_unit, "md_unit": md_unit},
                    ))

                # Check semantic_steps
                toml_steps = [s.replace("_", " ").strip() for s in op.get("semantic_steps", []) if isinstance(s, str)]
                if toml_steps != md_entry["semantic_steps"]:
                    findings.append(SloFinding(
                        severity="error",
                        code=CODE_OWNER_MIRROR_DISAGREEMENT,
                        path=sanitize_path(target_costs_md_path, root),
                        message=f"Operation '{cid}' semantic_steps mismatch: TOML has {toml_steps}, Markdown has {md_entry['semantic_steps']}",
                        remediation=DIAGNOSTIC_REGISTRY[CODE_OWNER_MIRROR_DISAGREEMENT]["remediation"],
                        params={"cost_id": cid, "toml_steps": toml_steps, "md_steps": md_entry["semantic_steps"]},
                    ))

                # Check variable_costs
                toml_vars = [s.replace("_", " ").strip() for s in op.get("variable_costs", []) if isinstance(s, str)]
                if toml_vars != md_entry["variable_costs"]:
                    findings.append(SloFinding(
                        severity="error",
                        code=CODE_OWNER_MIRROR_DISAGREEMENT,
                        path=sanitize_path(target_costs_md_path, root),
                        message=f"Operation '{cid}' variable_costs mismatch: TOML has {toml_vars}, Markdown has {md_entry['variable_costs']}",
                        remediation=DIAGNOSTIC_REGISTRY[CODE_OWNER_MIRROR_DISAGREEMENT]["remediation"],
                        params={"cost_id": cid, "toml_vars": toml_vars, "md_vars": md_entry["variable_costs"]},
                    ))

                # Check proof_owner
                toml_owner = str(op.get("proof_owner") or op.get("owner") or "").strip()
                md_owner = md_entry["proof_owner"].strip()
                if toml_owner != md_owner:
                    findings.append(SloFinding(
                        severity="error",
                        code=CODE_OWNER_MIRROR_DISAGREEMENT,
                        path=sanitize_path(target_costs_md_path, root),
                        message=f"Operation '{cid}' proof owner mismatch: TOML has '{toml_owner}', Markdown has '{md_owner}'",
                        remediation=DIAGNOSTIC_REGISTRY[CODE_OWNER_MIRROR_DISAGREEMENT]["remediation"],
                        params={"cost_id": cid, "toml_owner": toml_owner, "md_owner": md_owner},
                    ))

                # Check proof_reference
                toml_ref = str(op.get("proof_reference") or "").strip()
                md_ref = md_entry["proof_reference"].strip()
                if toml_ref != md_ref:
                    findings.append(SloFinding(
                        severity="error",
                        code=CODE_OWNER_MIRROR_DISAGREEMENT,
                        path=sanitize_path(target_costs_md_path, root),
                        message=f"Operation '{cid}' proof reference mismatch: TOML has '{toml_ref}', Markdown has '{md_ref}'",
                        remediation=DIAGNOSTIC_REGISTRY[CODE_OWNER_MIRROR_DISAGREEMENT]["remediation"],
                        params={"cost_id": cid, "toml_ref": toml_ref, "md_ref": md_ref},
                    ))

        # Check for operations in Markdown that are missing from TOML
        toml_op_ids = {op.get("id") for op in operations if isinstance(op, dict) and "id" in op}
        for md_cid in md_ops:
            if md_cid not in toml_op_ids:
                findings.append(SloFinding(
                    severity="error",
                    code=CODE_OWNER_MIRROR_DISAGREEMENT,
                    path=sanitize_path(target_costs_md_path, root),
                    message=f"Operation '{md_cid}' in registries/OPERATION_COSTS.md is missing from TOML",
                    remediation=DIAGNOSTIC_REGISTRY[CODE_OWNER_MIRROR_DISAGREEMENT]["remediation"],
                    params={"cost_id": md_cid},
                ))

        # Compare TOML drift table against Markdown drift table
        for d in drifts:
            if not isinstance(d, dict):
                continue
            did = d.get("id")
            if not did or not isinstance(did, str):
                continue
            did = did.strip()
            if did not in md_drifts:
                findings.append(SloFinding(
                    severity="error",
                    code=CODE_OWNER_MIRROR_DISAGREEMENT,
                    path=sanitize_path(target_costs_md_path, root),
                    message=f"Drift '{did}' in TOML is missing from registries/OPERATION_COSTS.md drift table",
                    remediation=DIAGNOSTIC_REGISTRY[CODE_OWNER_MIRROR_DISAGREEMENT]["remediation"],
                    params={"drift_id": did},
                ))
            else:
                mdd = md_drifts[did]
                d_op = str(d.get("operation_id", "")).strip()
                if d_op != mdd["operation_id"]:
                    findings.append(SloFinding(
                        severity="error",
                        code=CODE_OWNER_MIRROR_DISAGREEMENT,
                        path=sanitize_path(target_costs_md_path, root),
                        message=f"Drift '{did}' operation_id mismatch: TOML has '{d_op}', Markdown has '{mdd['operation_id']}'",
                        remediation=DIAGNOSTIC_REGISTRY[CODE_OWNER_MIRROR_DISAGREEMENT]["remediation"],
                        params={"drift_id": did, "toml_op": d_op, "md_op": mdd["operation_id"]},
                    ))
                d_status = str(d.get("status", "")).strip()
                if d_status != mdd["status"]:
                    findings.append(SloFinding(
                        severity="error",
                        code=CODE_OWNER_MIRROR_DISAGREEMENT,
                        path=sanitize_path(target_costs_md_path, root),
                        message=f"Drift '{did}' status mismatch: TOML has '{d_status}', Markdown has '{mdd['status']}'",
                        remediation=DIAGNOSTIC_REGISTRY[CODE_OWNER_MIRROR_DISAGREEMENT]["remediation"],
                        params={"drift_id": did, "toml_status": d_status, "md_status": mdd["status"]},
                    ))
                d_desc = str(d.get("description", "")).strip()
                if d_desc != mdd["description"]:
                    findings.append(SloFinding(
                        severity="error",
                        code=CODE_OWNER_MIRROR_DISAGREEMENT,
                        path=sanitize_path(target_costs_md_path, root),
                        message=f"Drift '{did}' description mismatch: TOML has '{d_desc}', Markdown has '{mdd['description']}'",
                        remediation=DIAGNOSTIC_REGISTRY[CODE_OWNER_MIRROR_DISAGREEMENT]["remediation"],
                        params={"drift_id": did, "toml_desc": d_desc, "md_desc": mdd["description"]},
                    ))
                d_lane = str(d.get("target_lane", "")).strip()
                if d_lane != mdd["target_lane"]:
                    findings.append(SloFinding(
                        severity="error",
                        code=CODE_OWNER_MIRROR_DISAGREEMENT,
                        path=sanitize_path(target_costs_md_path, root),
                        message=f"Drift '{did}' target_lane mismatch: TOML has '{d_lane}', Markdown has '{mdd['target_lane']}'",
                        remediation=DIAGNOSTIC_REGISTRY[CODE_OWNER_MIRROR_DISAGREEMENT]["remediation"],
                        params={"drift_id": did, "toml_lane": d_lane, "md_lane": mdd["target_lane"]},
                    ))

        toml_drift_ids = {d.get("id") for d in drifts if isinstance(d, dict) and "id" in d}
        for md_did in md_drifts:
            if md_did not in toml_drift_ids:
                findings.append(SloFinding(
                    severity="error",
                    code=CODE_OWNER_MIRROR_DISAGREEMENT,
                    path=sanitize_path(target_costs_md_path, root),
                    message=f"Drift '{md_did}' in registries/OPERATION_COSTS.md is missing from TOML",
                    remediation=DIAGNOSTIC_REGISTRY[CODE_OWNER_MIRROR_DISAGREEMENT]["remediation"],
                    params={"drift_id": md_did},
                ))

    return resolutions


def validate_claim_promotions(
    claims_path: Path,
    slos: dict[str, SloRow],
    root: Path,
    findings: list[SloFinding],
) -> None:
    """Validate that no public claim in CLAIMS.md cites an unachieved/target SLO as evidence."""
    path_str = sanitize_path(claims_path, root)
    if not claims_path.is_file():
        return

    claims_text = claims_path.read_text(encoding="utf-8")
    zero_width_chars = frozenset({"\u200b", "\u200c", "\u200d", "\ufeff"})

    # Extract all candidate SLO citations (backticked spans and SLO-like tokens)
    citations: set[str] = set()

    slo_prefix_pattern = re.compile(r"^(?:SL[O\u041e]|[\u0421\u0441][\u041b\u044c][\u041e\u043e])[-_]", re.IGNORECASE)

    # 1. Backticked tokens
    for m in re.finditer(r"`([^`]+)`", claims_text):
        token = m.group(1).strip()
        if slo_prefix_pattern.search(token):
            citations.add(token)

    # 2. Unbackticked tokens
    for m in re.finditer(r"\b(?:SL[O\u041e]|[\u0421\u0441][\u041b\u044c][\u041e\u043e])-[^\s|`]+\b", claims_text, re.IGNORECASE):
        citations.add(m.group(0).strip())

    for citation in sorted(citations):
        # F3: IDs and claim citations must be validated as pure ASCII first
        if not citation.isascii() or any(c in citation for c in zero_width_chars):
            findings.append(SloFinding(
                severity="error",
                code=CODE_INVALID_SLO_ID,
                path=path_str,
                message=f"Public claim citation contains non-ASCII or zero-width characters: '{citation}'",
                remediation="Claim citations must be pure ASCII with no non-ASCII or zero-width characters",
                params={"citation": citation},
            ))
            continue

        # F5: A claim citing an alias/non-conforming ID is an error
        if not SLO_ID_REGEX.match(citation):
            findings.append(SloFinding(
                severity="error",
                code=CODE_INVALID_SLO_ID,
                path=path_str,
                message=f"Public claim cites non-conforming or alias SLO ID: '{citation}'",
                remediation=DIAGNOSTIC_REGISTRY[CODE_INVALID_SLO_ID]["remediation"],
                params={"citation": citation},
            ))
            continue

        if citation not in slos:
            findings.append(SloFinding(
                severity="error",
                code=CODE_UNREGISTERED_SLO_REFERENCE,
                path=path_str,
                message=f"Public claim in {path_str} cites unregistered SLO '{citation}'",
                remediation=DIAGNOSTIC_REGISTRY[CODE_UNREGISTERED_SLO_REFERENCE]["remediation"],
                params={"slo_id": citation},
            ))
            continue

        slo_info = slos[citation]
        # F5: A claim citing a tombstone emits SLO-VAL-014
        if slo_info.is_tombstone:
            findings.append(SloFinding(
                severity="error",
                code=CODE_TOMBSTONE_REFERENCED_AS_ACTIVE,
                path=path_str,
                message=f"Public claim in {path_str} cites tombstoned SLO '{citation}'; must cite canonical successor '{slo_info.superseded_by}'",
                remediation=DIAGNOSTIC_REGISTRY[CODE_TOMBSTONE_REFERENCED_AS_ACTIVE]["remediation"],
                params={"slo_id": citation, "superseded_by": slo_info.superseded_by},
            ))
        elif slo_info.status != "achieved":
            findings.append(SloFinding(
                severity="error",
                code=CODE_TARGET_CLAIM_PROMOTION,
                path=path_str,
                message=f"Public claim in {path_str} cites SLO '{citation}' with status '{slo_info.status}' as evidence; targets cannot be promoted to public claims without retained qualification proof",
                remediation=DIAGNOSTIC_REGISTRY[CODE_TARGET_CLAIM_PROMOTION]["remediation"],
                params={"slo_id": citation, "status": slo_info.status},
            ))


def validate_slos(
    root: Path = ROOT,
    slos_path: Path | None = None,
    costs_path: Path | None = None,
    claims_path: Path | None = None,
    costs_md_path: Path | None = None,
) -> tuple[bool, list[SloFinding], dict[str, Any]]:
    """Primary audit entrypoint: validates registries/SLOS.md, cost references, and claim promotions."""
    start_ns = time.time_ns()
    target_slos_path = slos_path or (root / "registries/SLOS.md")
    target_costs_path = costs_path or (root / "architecture/operation_cost_registry.toml")
    target_claims_path = claims_path or (root / "registries/CLAIMS.md")
    target_costs_md_path = costs_md_path or (root / "registries/OPERATION_COSTS.md")
    should_check_mirror = target_costs_md_path.is_file()

    findings: list[SloFinding] = []

    if not target_slos_path.is_file():
        findings.append(SloFinding(
            severity="error",
            code=CODE_MALFORMED_TABLE,
            path=sanitize_path(target_slos_path, root),
            message=f"SLO registry file missing: {target_slos_path}",
            remediation="Restore registries/SLOS.md from source custody",
        ))
        summary = {
            "status": "fail",
            "total_slos": 0,
            "error_count": 1,
            "warning_count": 0,
        }
        return False, findings, summary

    slos_text = target_slos_path.read_text(encoding="utf-8")
    slos = parse_slos(slos_text, target_slos_path, root, findings)

    resolutions = validate_cost_references(
        target_costs_path,
        slos,
        root,
        findings,
        target_costs_md_path=target_costs_md_path if should_check_mirror else None,
    )
    validate_claim_promotions(target_claims_path, slos, root, findings)

    error_count = sum(1 for f in findings if f.severity == "error")
    warning_count = sum(1 for f in findings if f.severity == "warning")
    is_valid = error_count == 0

    elapsed_ms = (time.time_ns() - start_ns) / 1_000_000.0

    summary = {
        "schema": "fss.slo_audit.v1",
        "status": "pass" if is_valid else "fail",
        "timestamp_utc": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "slos_path": sanitize_path(target_slos_path, root),
        "costs_path": sanitize_path(target_costs_path, root),
        "claims_path": sanitize_path(target_claims_path, root),
        "costs_md_path": sanitize_path(target_costs_md_path, root),
        "total_slos": len(slos),
        "target_count": sum(1 for s in slos.values() if s.status == "target"),
        "tombstone_count": sum(1 for s in slos.values() if s.is_tombstone),
        "achieved_count": sum(1 for s in slos.values() if s.status == "achieved"),
        "total_cost_references": len(resolutions),
        "error_count": error_count,
        "warning_count": warning_count,
        "elapsed_ms": round(elapsed_ms, 3),
        "slos_digest": hashlib.sha256(slos_text.encode("utf-8")).hexdigest(),
    }

    return is_valid, findings, summary


def main() -> int:
    parser = argparse.ArgumentParser(description="Validate SLO registry and operation cost consistency.")
    parser.add_argument("--root", type=Path, default=ROOT, help="Repository root path")
    parser.add_argument("--slos", type=Path, default=None, help="Path to registries/SLOS.md")
    parser.add_argument("--costs", type=Path, default=None, help="Path to architecture/operation_cost_registry.toml")
    parser.add_argument("--costs-md", type=Path, default=None, help="Path to registries/OPERATION_COSTS.md")
    parser.add_argument("--claims", type=Path, default=None, help="Path to registries/CLAIMS.md")
    parser.add_argument("--json", action="store_true", help="Output machine-readable JSON report")
    parser.add_argument("--quiet", action="store_true", help="Suppress non-error output")
    args = parser.parse_args()

    is_valid, findings, summary = validate_slos(
        root=args.root,
        slos_path=args.slos,
        costs_path=args.costs,
        claims_path=args.claims,
        costs_md_path=args.costs_md,
    )

    if args.json:
        report = {
            "summary": summary,
            "findings": [asdict(f) for f in findings],
        }
        print(json.dumps(report, indent=2, sort_keys=True))
    else:
        if not args.quiet or not is_valid:
            status_tag = "PASS" if is_valid else "FAIL"
            print(f"[{status_tag}] SLO constitution audit: {summary['total_slos']} SLOs ({summary['target_count']} target, {summary['tombstone_count']} tombstone, {summary['achieved_count']} achieved), {summary['total_cost_references']} cost references")
            for f in findings:
                print(f"  {f.severity.upper()} [{f.code}] {f.path}: {f.message}")
                if f.remediation:
                    print(f"    Remediation: {f.remediation}")

    return 0 if is_valid else 1


if __name__ == "__main__":
    sys.exit(main())
