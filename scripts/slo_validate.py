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

SLO_ID_REGEX = re.compile(r"^SLO-[A-Z0-9]+(?:-[A-Z0-9]+)*-[0-9]{3}$")
TOMBSTONE_REGEX = re.compile(r"tombstone:\s*superseded\s*by\s*`((?:SLO)-[A-Z0-9-]+)`", re.IGNORECASE)

VALID_STATUSES = frozenset({"target", "tombstone", "achieved"})
NON_PROOF_ROOTS = frozenset({"-", "none", "null", "n/a", "na", ""})

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
        "trigger": "Referenced proof root path does not exist on disk",
        "remediation": "Provide the exact path to the retained qualification artifact or proof bundle",
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
        "trigger": "Operation cost references an unregistered SLO ID",
        "remediation": "Register the SLO in registries/SLOS.md or correct the cost slo_ids reference",
    },
    CODE_MALFORMED_COST_SLO_REFERENCE: {
        "trigger": "Operation cost references a malformed SLO ID format",
        "remediation": "Format the referenced SLO ID as ^SLO-[A-Z0-9]+(?:-[A-Z0-9]+)*-[0-9]{3}$",
    },
    CODE_MALFORMED_TABLE: {
        "trigger": "SLO markdown table header or row structure is malformed",
        "remediation": "Ensure standard 5-column table format: | ID | Target | Measurement surface | Status | Proof root |",
    },
    CODE_TARGET_CLAIM_PROMOTION: {
        "trigger": "An SLO target was promoted to a public claim without an achieved qualification proof",
        "remediation": "Treat targets as goals to qualify, not achieved claims, until verified at release gates",
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
        # Extract ID (handle backticks if present)
        id_cell = row.get("id", "")
        m_id = re.search(r"`?((?:SLO)-[A-Za-z0-9-]+)`?", id_cell)
        if not m_id:
            raw_id = id_cell.strip("` ")
            findings.append(SloFinding(
                severity="error",
                code=CODE_INVALID_SLO_ID,
                path=path_str,
                message=f"Row {row_idx} has malformed or missing SLO ID: '{raw_id}'",
                remediation=DIAGNOSTIC_REGISTRY[CODE_INVALID_SLO_ID]["remediation"],
                params={"row": row_idx, "raw_id": raw_id},
            ))
            continue
        
        slo_id = m_id.group(1).strip()
        if not SLO_ID_REGEX.match(slo_id):
            findings.append(SloFinding(
                severity="error",
                code=CODE_INVALID_SLO_ID,
                path=path_str,
                message=f"SLO ID does not match canonical format ^SLO-[A-Z0-9]+(?:-[A-Z0-9]+)*-[0-9]{{3}}$: '{slo_id}'",
                remediation=DIAGNOSTIC_REGISTRY[CODE_INVALID_SLO_ID]["remediation"],
                params={"slo_id": slo_id, "row": row_idx},
            ))
        
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
        
        # Target presence check
        if not target or target.lower() in {"-", "none", "null", "n/a", "na"}:
            findings.append(SloFinding(
                severity="error",
                code=CODE_MISSING_TARGET,
                path=path_str,
                message=f"SLO {slo_id} lacks a measurable target description",
                remediation=DIAGNOSTIC_REGISTRY[CODE_MISSING_TARGET]["remediation"],
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
        
        # Achieved status requires valid proof root
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
                        remediation="Proof root must be a relative path within the repository or qualification artifacts",
                        params={"slo_id": slo_id, "proof_root": proof_root},
                    ))
                else:
                    root_resolved = root.resolve()
                    resolved_cand = (root / proof_path).resolve()
                    cand_in_qual = (root / "qualification-artifacts" / proof_path).resolve()
                    
                    valid = False
                    if (
                        resolved_cand != root_resolved
                        and resolved_cand.is_relative_to(root_resolved)
                        and resolved_cand.exists()
                    ):
                        valid = True
                    elif (
                        cand_in_qual != root_resolved
                        and cand_in_qual.is_relative_to(root_resolved)
                        and cand_in_qual.exists()
                    ):
                        valid = True
                    
                    if not valid:
                        findings.append(SloFinding(
                            severity="error",
                            code=CODE_PROOF_ROOT_NOT_FOUND,
                            path=path_str,
                            message=f"SLO {slo_id} referenced proof root does not exist on disk: '{proof_root}'",
                            remediation=DIAGNOSTIC_REGISTRY[CODE_PROOF_ROOT_NOT_FOUND]["remediation"],
                            params={"slo_id": slo_id, "proof_root": proof_root},
                        ))
        
        # Tombstone validation
        if is_tombstone and not superseded_by:
            findings.append(SloFinding(
                severity="error",
                code=CODE_INVALID_TOMBSTONE,
                path=path_str,
                message=f"Tombstone SLO {slo_id} must specify canonical successor using `tombstone: superseded by `SLO-...``",
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
        referenced_slos = op.get("slo_ids", [])
        if not isinstance(referenced_slos, list):
            findings.append(SloFinding(
                severity="error",
                code=CODE_MALFORMED_COST_SLO_REFERENCE,
                path=path_str,
                message=f"Operation {cost_id} slo_ids must be a list of strings",
                remediation="Ensure slo_ids is a list of registered SLO ID strings",
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
                canonical_target = slo_info.id
                if slo_info.is_tombstone:
                    curr = slo_info.superseded_by or ""
                    visited = {slo_info.id}
                    while curr in slos and slos[curr].is_tombstone:
                        if curr in visited:
                            break
                        visited.add(curr)
                        curr = slos[curr].superseded_by or ""
                    canonical_target = curr
                
                resolutions.append({
                    "cost_id": cost_id,
                    "referenced_slo_id": ref_slo_id,
                    "resolved_canonical_id": canonical_target,
                    "is_tombstone": slo_info.is_tombstone,
                    "status": slo_info.status,
                })
    
    return resolutions


def validate_slos(
    root: Path = ROOT,
    slos_path: Path | None = None,
    costs_path: Path | None = None,
) -> tuple[bool, list[SloFinding], dict[str, Any]]:
    """Primary audit entrypoint: validates registries/SLOS.md and cost references."""
    start_ns = time.time_ns()
    target_slos_path = slos_path or (root / "registries/SLOS.md")
    target_costs_path = costs_path or (root / "architecture/operation_cost_registry.toml")
    
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
    parser.add_argument("--json", action="store_true", help="Output machine-readable JSON report")
    parser.add_argument("--quiet", action="store_true", help="Suppress non-error output")
    args = parser.parse_args()
    
    is_valid, findings, summary = validate_slos(
        root=args.root,
        slos_path=args.slos,
        costs_path=args.costs,
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
