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
    "id", "name", "unit", "semantic_steps", "variable_costs", "slo_ids", "status", "notes"
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
}


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
    except Exception:
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
    """Validate that target matches a structured threshold grammar with registered units."""
    if is_tombstone:
        return True

    t_lower = target.lower()

    # Check approved qualitative/closure contract patterns first
    if any(pat.search(t_lower) for pat in APPROVED_TARGET_PATTERNS):
        return True

    has_operator = bool(re.search(r"(?:<=|>=|<|>|==|≤|≥)", target))
    has_number = bool(re.search(r"\b\d+(?:\.\d+)?", target))

    if has_operator or has_number:
        for unit in sorted(REGISTERED_UNITS, key=len, reverse=True):
            if unit == "%":
                if "%" in target:
                    return True
            else:
                if re.search(r"\b" + re.escape(unit) + r"\b", t_lower):
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
    case_folded: dict[str, str] = {}

    for row_idx, row in enumerate(raw_rows, start=1):
        # Extract ID (strictly anchored to whole cell; rejects trailing annotations or aliases)
        id_cell = row.get("id", "").strip()
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

        # Check duplicate and case-fold collision
        lower_id = slo_id.lower()
        if slo_id in slos or lower_id in case_folded:
            existing = slos.get(slo_id) or slos.get(case_folded.get(lower_id, ""))
            findings.append(SloFinding(
                severity="error",
                code=CODE_DUPLICATE_SLO_ID,
                path=path_str,
                message=f"Duplicate or case-colliding SLO ID detected: '{slo_id}' (collides with '{existing.id if existing else lower_id}')",
                remediation=DIAGNOSTIC_REGISTRY[CODE_DUPLICATE_SLO_ID]["remediation"],
                params={"slo_id": slo_id, "collides_with": existing.id if existing else lower_id},
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
                else:
                    qual_dir = (root / "qualification-artifacts").resolve()
                    resolved_cand = (root / proof_path).resolve()
                    if not resolved_cand.is_relative_to(qual_dir):
                        resolved_cand = (qual_dir / proof_path).resolve()

                    if not resolved_cand.is_relative_to(qual_dir) or resolved_cand == qual_dir:
                        findings.append(SloFinding(
                            severity="error",
                            code=CODE_PROOF_ROOT_NOT_FOUND,
                            path=path_str,
                            message=f"SLO {slo_id} referenced proof root '{proof_root}' does not resolve to a file strictly within qualification-artifacts/",
                            remediation="Proof root must resolve to a file strictly within qualification-artifacts/",
                            params={"slo_id": slo_id, "proof_root": proof_root},
                        ))
                    elif not resolved_cand.is_file():
                        findings.append(SloFinding(
                            severity="error",
                            code=CODE_PROOF_ROOT_NOT_FOUND,
                            path=path_str,
                            message=f"SLO {slo_id} referenced proof root does not exist as a regular file on disk: '{proof_root}'",
                            remediation=DIAGNOSTIC_REGISTRY[CODE_PROOF_ROOT_NOT_FOUND]["remediation"],
                            params={"slo_id": slo_id, "proof_root": proof_root},
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
        case_folded[lower_id] = slo_id
    
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
) -> list[dict[str, Any]]:
    """Validate that every slo_ids entry in operation_cost_registry.toml resolves to a registered SLO."""
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
        cost_data = tomllib.loads(costs_path.read_text(encoding="utf-8"))
    except Exception as exc:
        findings.append(SloFinding(
            severity="error",
            code=CODE_MALFORMED_TABLE,
            path=path_str,
            message=f"Failed to parse operation_cost_registry.toml: {exc}",
            remediation="Correct TOML syntax in architecture/operation_cost_registry.toml",
            params={"error": str(exc)},
        ))
        return []
    
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
    
    for op in operations:
        cost_id = op.get("id", "UNKNOWN_COST")

        # F4: Reject unknown keys in operation row (including singular 'slo_id')
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
            if not isinstance(ref_slo_id, str) or not SLO_ID_REGEX.match(ref_slo_id):
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
                # F5: An active operation referencing a tombstone directly is an error
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

    # Extract all SLO IDs mentioned in claims text
    referenced_slo_matches = re.findall(r"`?((?:SLO)-[A-Z0-9]+(?:-[A-Z0-9]+)*-[0-9]{3})`?", claims_text)
    for ref_slo_id in set(referenced_slo_matches):
        if ref_slo_id in slos:
            slo_info = slos[ref_slo_id]
            if slo_info.status != "achieved":
                findings.append(SloFinding(
                    severity="error",
                    code=CODE_TARGET_CLAIM_PROMOTION,
                    path=path_str,
                    message=f"Public claim in {path_str} cites SLO '{ref_slo_id}' with status '{slo_info.status}' as evidence; targets cannot be promoted to public claims without retained qualification proof",
                    remediation=DIAGNOSTIC_REGISTRY[CODE_TARGET_CLAIM_PROMOTION]["remediation"],
                    params={"slo_id": ref_slo_id, "status": slo_info.status},
                ))
        else:
            findings.append(SloFinding(
                severity="error",
                code=CODE_TARGET_CLAIM_PROMOTION,
                path=path_str,
                message=f"Public claim in {path_str} cites unregistered SLO '{ref_slo_id}'",
                remediation=DIAGNOSTIC_REGISTRY[CODE_TARGET_CLAIM_PROMOTION]["remediation"],
                params={"slo_id": ref_slo_id},
            ))


def validate_slos(
    root: Path = ROOT,
    slos_path: Path | None = None,
    costs_path: Path | None = None,
    claims_path: Path | None = None,
) -> tuple[bool, list[SloFinding], dict[str, Any]]:
    """Primary audit entrypoint: validates registries/SLOS.md, cost references, and claim promotions."""
    start_ns = time.time_ns()
    target_slos_path = slos_path or (root / "registries/SLOS.md")
    target_costs_path = costs_path or (root / "architecture/operation_cost_registry.toml")
    target_claims_path = claims_path or (root / "registries/CLAIMS.md")

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

    resolutions = validate_cost_references(target_costs_path, slos, root, findings)
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
    parser.add_argument("--claims", type=Path, default=None, help="Path to registries/CLAIMS.md")
    parser.add_argument("--json", action="store_true", help="Output machine-readable JSON report")
    parser.add_argument("--quiet", action="store_true", help="Suppress non-error output")
    args = parser.parse_args()

    is_valid, findings, summary = validate_slos(
        root=args.root,
        slos_path=args.slos,
        costs_path=args.costs,
        claims_path=args.claims,
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
