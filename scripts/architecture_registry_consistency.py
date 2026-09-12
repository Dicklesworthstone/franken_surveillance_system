#!/usr/bin/env python3
"""Deterministic architecture/registry consistency checker (fss-x4a.6.9 / FSS-009).

Cross-validates architecture/*.json against registries/*.md, schemas/, and Rust implementations.

Detects:
1. Missing identifiers: an identifier declared in an architecture JSON but missing from its
   corresponding registry Markdown, or vice-versa.
2. Contradicted metadata: conflicting status, name/title, token budget, mode, or gate
   between architecture JSON and registry Markdown.
3. Count mismatches: cardinality differences between paired architecture/registry sources
   or between registries/SCHEMAS.md and schemas/*.json.
4. Dangling references: cross-registry references (gates, views, capabilities, invariants,
   SLOs, activation primitives) pointing to nonexistent identifiers.
5. Tombstoned IDs in use: retired or superseded identifiers referenced by active entities.
6. Unregistered Rust schemas and digest domains: schemas or digest domains implemented
   in Rust that are not registered in SCHEMAS.md or DIGEST_DOMAINS.md (via schema_validate).
7. Missing or corrupt files: fail-closed enforcement ensuring all required architecture
   and registry files exist and parse cleanly.
"""
from __future__ import annotations

import argparse
import json
import re
import sys
import tomllib
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))

import schema_validate
import stable_id_audit

# Stable diagnostic error codes
ERR_MISSING_IDENTIFIER = "ERR-CONSISTENCY-MISSING-IDENTIFIER-001"
ERR_CONTRADICTED_METADATA = "ERR-CONSISTENCY-CONTRADICTED-METADATA-001"
ERR_COUNT_MISMATCH = "ERR-CONSISTENCY-COUNT-MISMATCH-001"
ERR_DANGLING_REFERENCE = "ERR-CONSISTENCY-DANGLING-REFERENCE-001"
ERR_TOMBSTONE_IN_USE = "ERR-CONSISTENCY-TOMBSTONE-IN-USE-001"
ERR_UNREGISTERED_RUST_IDENTIFIER = "ERR-CONSISTENCY-UNREGISTERED-RUST-001"
ERR_MISSING_FILE = "ERR-CONSISTENCY-MISSING-FILE-001"
ERR_CORRUPT_FILE = "ERR-CONSISTENCY-CORRUPT-FILE-001"

TOMBSTONE_STATES = stable_id_audit.TOMBSTONE_STATES

MANDATORY_ARCHITECTURE_FILES = (
    "architecture/invariants.json",
    "architecture/graph_algorithms.json",
    "architecture/publication_primitives.json",
    "architecture/franken_imports.json",
    "architecture/agent_operations.json",
    "architecture/agent_views.json",
    "architecture/release_qualification.json",
    "architecture/agent_abstraction_stack.json",
    "architecture/agent_contracts.json",
    "architecture/agent_operating_model.json",
    "architecture/claims.json",
    "architecture/model_runtime_registry.json",
    "architecture/semantic_hydration.json",
    "architecture/decision_cards.json",
    "architecture/crate_topology.json",
    "architecture/dependency_constitution.json",
    "architecture/operation_cost_registry.toml",
)

MANDATORY_REGISTRY_FILES = (
    "registries/INVARIANTS.md",
    "registries/GRAPH_ALGORITHMS.md",
    "registries/PUBLICATION_PRIMITIVES.md",
    "registries/IMPORTS.md",
    "registries/AGENT_OPERATIONS.md",
    "registries/AGENT_VIEWS.md",
    "registries/QUALIFICATION_LANES.md",
    "registries/AGENT_ABSTRACTIONS.md",
    "registries/AGENT_CONTRACTS.md",
    "registries/CLAIMS.md",
    "registries/MODELS.md",
    "registries/SEMANTIC_HYDRATION.md",
    "registries/CAPABILITIES.md",
    "registries/ERRORS.md",
    "registries/SLOS.md",
    "registries/TESTS.md",
    "registries/RISKS.md",
    "registries/SCHEMAS.md",
    "registries/DIGEST_DOMAINS.md",
    "registries/DEPENDENCIES.md",
    "registries/OPERATION_COSTS.md",
)


@dataclass(frozen=True)
class Finding:
    code: str
    file: str
    location: str
    message: str


def parse_markdown_table_rows(text: str) -> list[list[str]]:
    """Extracts table rows from markdown text, stripping backticks and whitespace."""
    clean_text = stable_id_audit._strip_html_comments(text)
    rows: list[list[str]] = []
    in_fence = False
    for line in clean_text.splitlines():
        stripped = line.strip()
        if stripped.startswith("```"):
            in_fence = not in_fence
            continue
        if in_fence:
            continue
        if stripped.startswith("|") and not stripped.startswith("|---"):
            cells = [c.strip().strip("`") for c in stripped.split("|")[1:-1]]
            if cells:
                rows.append(cells)
    return rows


def validate_consistency(repo_root: Path = ROOT) -> tuple[bool, list[Finding], dict[str, Any]]:
    """Cross-validates architecture/*.json against registries/*.md, schemas/, and Rust code.

    Returns:
        tuple of (is_valid: bool, findings: list[Finding], summary: dict[str, Any])
    """
    findings: list[Finding] = []

    def emit(code: str, file_path: str, location: str, message: str) -> None:
        findings.append(Finding(code=code, file=file_path, location=location, message=message))

    # 1. Preflight check: fail closed on missing or corrupt files
    parsed_json: dict[str, Any] = {}
    parsed_toml: dict[str, Any] = {}
    parsed_md: dict[str, str] = {}

    for rel in MANDATORY_ARCHITECTURE_FILES:
        path = repo_root / rel
        if not path.is_file():
            emit(ERR_MISSING_FILE, rel, "#", f"required architecture file missing: {rel}")
            continue
        try:
            content = path.read_text(encoding="utf-8-sig")
        except Exception as exc:
            emit(ERR_CORRUPT_FILE, rel, "#", f"cannot read {rel}: {exc}")
            continue

        if rel.endswith(".json"):
            try:
                parsed_json[rel] = json.loads(content)
            except Exception as exc:
                emit(ERR_CORRUPT_FILE, rel, "#", f"invalid JSON in {rel}: {exc}")
        elif rel.endswith(".toml"):
            try:
                parsed_toml[rel] = tomllib.loads(content)
            except Exception as exc:
                emit(ERR_CORRUPT_FILE, rel, "#", f"invalid TOML in {rel}: {exc}")

    for rel in MANDATORY_REGISTRY_FILES:
        path = repo_root / rel
        if not path.is_file():
            emit(ERR_MISSING_FILE, rel, "#", f"required registry file missing: {rel}")
            continue
        try:
            parsed_md[rel] = path.read_text(encoding="utf-8-sig")
        except Exception as exc:
            emit(ERR_CORRUPT_FILE, rel, "#", f"cannot read {rel}: {exc}")

    # If any mandatory file was missing or corrupt, stop immediately (fail closed)
    if findings:
        return False, findings, {
            "status": "fail",
            "error_count": len(findings),
            "checked_pairs": 0,
            "checked_references": 0,
        }

    # Helper to extract IDs and rows from markdown tables
    def extract_md_rows_by_id(rel: str, id_prefix: str | None = None) -> dict[str, list[str]]:
        text = parsed_md.get(rel, "")
        rows = parse_markdown_table_rows(text)
        result: dict[str, list[str]] = {}
        for r in rows:
            if not r:
                continue
            first = r[0]
            if first in ("ID", "Claim class", "Level", "Cost ID"):
                continue
            if id_prefix is None or first.startswith(id_prefix):
                result[first] = r
        return result

    # 2. Paired Registry Verifications
    # 2.1 Invariants
    inv_arch = parsed_json["architecture/invariants.json"].get("invariants", [])
    inv_arch_map = {item["id"]: item for item in inv_arch if isinstance(item, dict) and "id" in item}
    inv_md_map = extract_md_rows_by_id("registries/INVARIANTS.md", "INV-")

    if len(inv_arch_map) != len(inv_md_map):
        emit(
            ERR_COUNT_MISMATCH,
            "architecture/invariants.json",
            "#/invariants",
            f"invariants count mismatch: architecture has {len(inv_arch_map)}, registries/INVARIANTS.md has {len(inv_md_map)}",
        )

    for iid, item in inv_arch_map.items():
        if iid not in inv_md_map:
            emit(
                ERR_MISSING_IDENTIFIER,
                "registries/INVARIANTS.md",
                f"#{iid}",
                f"invariant '{iid}' in architecture/invariants.json is missing from registries/INVARIANTS.md",
            )
        else:
            md_row = inv_md_map[iid]
            md_status = md_row[2] if len(md_row) >= 3 else ""
            json_status = str(item.get("status", ""))
            if json_status != md_status:
                emit(
                    ERR_CONTRADICTED_METADATA,
                    "architecture/invariants.json",
                    f"#/invariants/{iid}/status",
                    f"invariant '{iid}' status mismatch: architecture has '{json_status}', registries has '{md_status}'",
                )

    for iid in inv_md_map:
        if iid not in inv_arch_map:
            emit(
                ERR_MISSING_IDENTIFIER,
                "architecture/invariants.json",
                f"#/invariants/{iid}",
                f"invariant '{iid}' in registries/INVARIANTS.md is missing from architecture/invariants.json",
            )

    # 2.2 Graph Algorithms
    alg_arch = parsed_json["architecture/graph_algorithms.json"].get("algorithms", [])
    alg_arch_map = {item["id"]: item for item in alg_arch if isinstance(item, dict) and "id" in item}
    alg_md_map = extract_md_rows_by_id("registries/GRAPH_ALGORITHMS.md", "ALG-")

    if len(alg_arch_map) != len(alg_md_map):
        emit(
            ERR_COUNT_MISMATCH,
            "architecture/graph_algorithms.json",
            "#/algorithms",
            f"graph algorithms count mismatch: architecture has {len(alg_arch_map)}, registries has {len(alg_md_map)}",
        )

    for aid, item in alg_arch_map.items():
        if aid not in alg_md_map:
            emit(
                ERR_MISSING_IDENTIFIER,
                "registries/GRAPH_ALGORITHMS.md",
                f"#{aid}",
                f"algorithm '{aid}' in architecture/graph_algorithms.json is missing from registries/GRAPH_ALGORITHMS.md",
            )
        else:
            md_row = alg_md_map[aid]
            # row: [ID, Algorithm, Projections, Exactness class, Admission gate]
            md_name = md_row[1] if len(md_row) >= 2 else ""
            md_exactness = md_row[3] if len(md_row) >= 4 else ""
            md_gate = md_row[4] if len(md_row) >= 5 else ""

            if item.get("name") != md_name:
                emit(
                    ERR_CONTRADICTED_METADATA,
                    "architecture/graph_algorithms.json",
                    f"#/algorithms/{aid}/name",
                    f"algorithm '{aid}' name mismatch: architecture has '{item.get('name')}', registries has '{md_name}'",
                )
            if item.get("exactness") != md_exactness:
                emit(
                    ERR_CONTRADICTED_METADATA,
                    "architecture/graph_algorithms.json",
                    f"#/algorithms/{aid}/exactness",
                    f"algorithm '{aid}' exactness mismatch: architecture has '{item.get('exactness')}', registries has '{md_exactness}'",
                )
            if item.get("gate") != md_gate:
                emit(
                    ERR_CONTRADICTED_METADATA,
                    "architecture/graph_algorithms.json",
                    f"#/algorithms/{aid}/gate",
                    f"algorithm '{aid}' gate mismatch: architecture has '{item.get('gate')}', registries has '{md_gate}'",
                )

    for aid in alg_md_map:
        if aid not in alg_arch_map:
            emit(
                ERR_MISSING_IDENTIFIER,
                "architecture/graph_algorithms.json",
                f"#/algorithms/{aid}",
                f"algorithm '{aid}' in registries/GRAPH_ALGORITHMS.md is missing from architecture/graph_algorithms.json",
            )

    # 2.3 Publication Primitives
    pub_arch = parsed_json["architecture/publication_primitives.json"].get("primitives", [])
    pub_arch_map = {item["id"]: item for item in pub_arch if isinstance(item, dict) and "id" in item}
    pub_md_map = extract_md_rows_by_id("registries/PUBLICATION_PRIMITIVES.md", "PUB-")

    if len(pub_arch_map) != len(pub_md_map):
        emit(
            ERR_COUNT_MISMATCH,
            "architecture/publication_primitives.json",
            "#/primitives",
            f"publication primitives count mismatch: architecture has {len(pub_arch_map)}, registries has {len(pub_md_map)}",
        )

    for pid, item in pub_arch_map.items():
        if pid not in pub_md_map:
            emit(
                ERR_MISSING_IDENTIFIER,
                "registries/PUBLICATION_PRIMITIVES.md",
                f"#{pid}",
                f"publication primitive '{pid}' in architecture is missing from registries/PUBLICATION_PRIMITIVES.md",
            )
        else:
            md_row = pub_md_map[pid]
            # row: [ID, Primitive, Owner, Root invariant, State]
            md_name = md_row[1] if len(md_row) >= 2 else ""
            md_owner = md_row[2] if len(md_row) >= 3 else ""
            md_status = md_row[4] if len(md_row) >= 5 else ""

            if item.get("name") != md_name:
                emit(
                    ERR_CONTRADICTED_METADATA,
                    "architecture/publication_primitives.json",
                    f"#/primitives/{pid}/name",
                    f"primitive '{pid}' name mismatch: architecture has '{item.get('name')}', registries has '{md_name}'",
                )
            if item.get("owner") != md_owner:
                emit(
                    ERR_CONTRADICTED_METADATA,
                    "architecture/publication_primitives.json",
                    f"#/primitives/{pid}/owner",
                    f"primitive '{pid}' owner mismatch: architecture has '{item.get('owner')}', registries has '{md_owner}'",
                )
            if item.get("status") != md_status:
                emit(
                    ERR_CONTRADICTED_METADATA,
                    "architecture/publication_primitives.json",
                    f"#/primitives/{pid}/status",
                    f"primitive '{pid}' status mismatch: architecture has '{item.get('status')}', registries has '{md_status}'",
                )

    for pid in pub_md_map:
        if pid not in pub_arch_map:
            emit(
                ERR_MISSING_IDENTIFIER,
                "architecture/publication_primitives.json",
                f"#/primitives/{pid}",
                f"publication primitive '{pid}' in registries is missing from architecture/publication_primitives.json",
            )

    # 2.4 Franken Imports
    imp_arch = parsed_json["architecture/franken_imports.json"].get("imports", [])
    imp_arch_map = {item["id"]: item for item in imp_arch if isinstance(item, dict) and "id" in item}
    imp_md_map = extract_md_rows_by_id("registries/IMPORTS.md", "IMP-")

    if len(imp_arch_map) != len(imp_md_map):
        emit(
            ERR_COUNT_MISMATCH,
            "architecture/franken_imports.json",
            "#/imports",
            f"franken imports count mismatch: architecture has {len(imp_arch_map)}, registries has {len(imp_md_map)}",
        )

    for imid in imp_arch_map:
        if imid not in imp_md_map:
            emit(
                ERR_MISSING_IDENTIFIER,
                "registries/IMPORTS.md",
                f"#{imid}",
                f"import '{imid}' in architecture/franken_imports.json is missing from registries/IMPORTS.md",
            )
    for imid in imp_md_map:
        if imid not in imp_arch_map:
            emit(
                ERR_MISSING_IDENTIFIER,
                "architecture/franken_imports.json",
                f"#/imports/{imid}",
                f"import '{imid}' in registries/IMPORTS.md is missing from architecture/franken_imports.json",
            )

    # 2.5 Agent Operations
    aop_arch = parsed_json["architecture/agent_operations.json"].get("operations", [])
    aop_arch_map = {item["id"]: item for item in aop_arch if isinstance(item, dict) and "id" in item}
    aop_md_map = extract_md_rows_by_id("registries/AGENT_OPERATIONS.md", "AOP-")

    if len(aop_arch_map) != len(aop_md_map):
        emit(
            ERR_COUNT_MISMATCH,
            "architecture/agent_operations.json",
            "#/operations",
            f"agent operations count mismatch: architecture has {len(aop_arch_map)}, registries has {len(aop_md_map)}",
        )

    for opid, item in aop_arch_map.items():
        if opid not in aop_md_map:
            emit(
                ERR_MISSING_IDENTIFIER,
                "registries/AGENT_OPERATIONS.md",
                f"#{opid}",
                f"operation '{opid}' in architecture is missing from registries/AGENT_OPERATIONS.md",
            )
        else:
            md_row = aop_md_map[opid]
            # row: [ID, Operation, Owner, Mode, Default view, Typed request payload, Effectful, Durable, Gate, Status]
            md_name = md_row[1] if len(md_row) >= 2 else ""
            md_mode = md_row[3] if len(md_row) >= 4 else ""
            md_view = md_row[4] if len(md_row) >= 5 else ""
            md_gate = md_row[8] if len(md_row) >= 9 else ""
            md_status = md_row[9] if len(md_row) >= 10 else ""

            if item.get("name") != md_name:
                emit(
                    ERR_CONTRADICTED_METADATA,
                    "architecture/agent_operations.json",
                    f"#/operations/{opid}/name",
                    f"operation '{opid}' name mismatch: architecture has '{item.get('name')}', registries has '{md_name}'",
                )
            if item.get("mode") != md_mode:
                emit(
                    ERR_CONTRADICTED_METADATA,
                    "architecture/agent_operations.json",
                    f"#/operations/{opid}/mode",
                    f"operation '{opid}' mode mismatch: architecture has '{item.get('mode')}', registries has '{md_mode}'",
                )
            if item.get("defaultView") != md_view:
                emit(
                    ERR_CONTRADICTED_METADATA,
                    "architecture/agent_operations.json",
                    f"#/operations/{opid}/defaultView",
                    f"operation '{opid}' defaultView mismatch: architecture has '{item.get('defaultView')}', registries has '{md_view}'",
                )
            if item.get("gate") != md_gate:
                emit(
                    ERR_CONTRADICTED_METADATA,
                    "architecture/agent_operations.json",
                    f"#/operations/{opid}/gate",
                    f"operation '{opid}' gate mismatch: architecture has '{item.get('gate')}', registries has '{md_gate}'",
                )
            if item.get("status") != md_status:
                emit(
                    ERR_CONTRADICTED_METADATA,
                    "architecture/agent_operations.json",
                    f"#/operations/{opid}/status",
                    f"operation '{opid}' status mismatch: architecture has '{item.get('status')}', registries has '{md_status}'",
                )

    for opid in aop_md_map:
        if opid not in aop_arch_map:
            emit(
                ERR_MISSING_IDENTIFIER,
                "architecture/agent_operations.json",
                f"#/operations/{opid}",
                f"operation '{opid}' in registries is missing from architecture/agent_operations.json",
            )

    # 2.6 Agent Views
    view_arch = parsed_json["architecture/agent_views.json"].get("views", [])
    view_arch_map = {item["id"]: item for item in view_arch if isinstance(item, dict) and "id" in item}
    view_md_map = extract_md_rows_by_id("registries/AGENT_VIEWS.md", "AVIEW-")

    if len(view_arch_map) != len(view_md_map):
        emit(
            ERR_COUNT_MISMATCH,
            "architecture/agent_views.json",
            "#/views",
            f"agent views count mismatch: architecture has {len(view_arch_map)}, registries has {len(view_md_map)}",
        )

    for vid, item in view_arch_map.items():
        if vid not in view_md_map:
            emit(
                ERR_MISSING_IDENTIFIER,
                "registries/AGENT_VIEWS.md",
                f"#{vid}",
                f"view '{vid}' in architecture is missing from registries/AGENT_VIEWS.md",
            )
        else:
            md_row = view_md_map[vid]
            # row: [ID, Name, Owner, Purpose, Target tokens, Maximum tokens, Gate, Status]
            md_name = md_row[1] if len(md_row) >= 2 else ""
            md_owner = md_row[2] if len(md_row) >= 3 else ""
            md_target = int(md_row[4]) if len(md_row) >= 5 and md_row[4].isdigit() else md_row[4]
            md_max = int(md_row[5]) if len(md_row) >= 6 and md_row[5].isdigit() else md_row[5]
            md_gate = md_row[6] if len(md_row) >= 7 else ""
            md_status = md_row[7] if len(md_row) >= 8 else ""

            if item.get("name") != md_name:
                emit(
                    ERR_CONTRADICTED_METADATA,
                    "architecture/agent_views.json",
                    f"#/views/{vid}/name",
                    f"view '{vid}' name mismatch: architecture has '{item.get('name')}', registries has '{md_name}'",
                )
            if item.get("owner") != md_owner:
                emit(
                    ERR_CONTRADICTED_METADATA,
                    "architecture/agent_views.json",
                    f"#/views/{vid}/owner",
                    f"view '{vid}' owner mismatch: architecture has '{item.get('owner')}', registries has '{md_owner}'",
                )
            if item.get("targetTokens") != md_target:
                emit(
                    ERR_CONTRADICTED_METADATA,
                    "architecture/agent_views.json",
                    f"#/views/{vid}/targetTokens",
                    f"view '{vid}' targetTokens mismatch: architecture has '{item.get('targetTokens')}', registries has '{md_target}'",
                )
            if item.get("maximumTokens") != md_max:
                emit(
                    ERR_CONTRADICTED_METADATA,
                    "architecture/agent_views.json",
                    f"#/views/{vid}/maximumTokens",
                    f"view '{vid}' maximumTokens mismatch: architecture has '{item.get('maximumTokens')}', registries has '{md_max}'",
                )
            if item.get("gate") != md_gate:
                emit(
                    ERR_CONTRADICTED_METADATA,
                    "architecture/agent_views.json",
                    f"#/views/{vid}/gate",
                    f"view '{vid}' gate mismatch: architecture has '{item.get('gate')}', registries has '{md_gate}'",
                )
            if item.get("status") != md_status:
                emit(
                    ERR_CONTRADICTED_METADATA,
                    "architecture/agent_views.json",
                    f"#/views/{vid}/status",
                    f"view '{vid}' status mismatch: architecture has '{item.get('status')}', registries has '{md_status}'",
                )

    for vid in view_md_map:
        if vid not in view_arch_map:
            emit(
                ERR_MISSING_IDENTIFIER,
                "architecture/agent_views.json",
                f"#/views/{vid}",
                f"view '{vid}' in registries is missing from architecture/agent_views.json",
            )

    # 2.7 Qualification Lanes
    ql_arch = parsed_json["architecture/release_qualification.json"].get("lanes", [])
    ql_arch_map = {item["id"]: item for item in ql_arch if isinstance(item, dict) and "id" in item}
    ql_md_map = extract_md_rows_by_id("registries/QUALIFICATION_LANES.md", "QL-")

    if len(ql_arch_map) != len(ql_md_map):
        emit(
            ERR_COUNT_MISMATCH,
            "architecture/release_qualification.json",
            "#/lanes",
            f"qualification lanes count mismatch: architecture has {len(ql_arch_map)}, registries has {len(ql_md_map)}",
        )

    for qid, item in ql_arch_map.items():
        if qid not in ql_md_map:
            emit(
                ERR_MISSING_IDENTIFIER,
                "registries/QUALIFICATION_LANES.md",
                f"#{qid}",
                f"qualification lane '{qid}' in architecture is missing from registries/QUALIFICATION_LANES.md",
            )
        else:
            md_row = ql_md_map[qid]
            # row: [ID, Lane, Scope, Required evidence, Authority]
            md_name = md_row[1] if len(md_row) >= 2 else ""
            md_scope = md_row[2] if len(md_row) >= 3 else ""
            md_auth = md_row[4] if len(md_row) >= 5 else ""

            arch_lane_name = item.get("kind") or item.get("lane") or item.get("name")
            if arch_lane_name != md_name:
                emit(
                    ERR_CONTRADICTED_METADATA,
                    "architecture/release_qualification.json",
                    f"#/lanes/{qid}/lane",
                    f"qualification lane '{qid}' name/kind mismatch: architecture has '{arch_lane_name}', registries has '{md_name}'",
                )
            if item.get("scope") != md_scope:
                emit(
                    ERR_CONTRADICTED_METADATA,
                    "architecture/release_qualification.json",
                    f"#/lanes/{qid}/scope",
                    f"qualification lane '{qid}' scope mismatch: architecture has '{item.get('scope')}', registries has '{md_scope}'",
                )
            if item.get("authority") != md_auth:
                emit(
                    ERR_CONTRADICTED_METADATA,
                    "architecture/release_qualification.json",
                    f"#/lanes/{qid}/authority",
                    f"qualification lane '{qid}' authority mismatch: architecture has '{item.get('authority')}', registries has '{md_auth}'",
                )

    for qid in ql_md_map:
        if qid not in ql_arch_map:
            emit(
                ERR_MISSING_IDENTIFIER,
                "architecture/release_qualification.json",
                f"#/lanes/{qid}",
                f"qualification lane '{qid}' in registries is missing from architecture/release_qualification.json",
            )

    # 2.8 Agent Abstraction Stack Layers
    layer_arch = parsed_json["architecture/agent_abstraction_stack.json"].get("layers", [])
    layer_arch_map = {item["id"]: item for item in layer_arch if isinstance(item, dict) and "id" in item}
    layer_md_map = extract_md_rows_by_id("registries/AGENT_ABSTRACTIONS.md", "AGT-")

    if len(layer_arch_map) != len(layer_md_map):
        emit(
            ERR_COUNT_MISMATCH,
            "architecture/agent_abstraction_stack.json",
            "#/layers",
            f"agent layers count mismatch: architecture has {len(layer_arch_map)}, registries has {len(layer_md_map)}",
        )

    for lid, item in layer_arch_map.items():
        if lid not in layer_md_map:
            emit(
                ERR_MISSING_IDENTIFIER,
                "registries/AGENT_ABSTRACTIONS.md",
                f"#{lid}",
                f"layer '{lid}' in architecture is missing from registries/AGENT_ABSTRACTIONS.md",
            )
        else:
            md_row = layer_md_map[lid]
            md_name = md_row[1] if len(md_row) >= 2 else ""
            md_status = md_row[5] if len(md_row) >= 6 else ""
            if item.get("name") != md_name:
                emit(
                    ERR_CONTRADICTED_METADATA,
                    "architecture/agent_abstraction_stack.json",
                    f"#/layers/{lid}/name",
                    f"layer '{lid}' name mismatch: architecture has '{item.get('name')}', registries has '{md_name}'",
                )
            if item.get("status") != md_status:
                emit(
                    ERR_CONTRADICTED_METADATA,
                    "architecture/agent_abstraction_stack.json",
                    f"#/layers/{lid}/status",
                    f"layer '{lid}' status mismatch: architecture has '{item.get('status')}', registries has '{md_status}'",
                )

    for lid in layer_md_map:
        if lid not in layer_arch_map:
            emit(
                ERR_MISSING_IDENTIFIER,
                "architecture/agent_abstraction_stack.json",
                f"#/layers/{lid}",
                f"layer '{lid}' in registries is missing from architecture/agent_abstraction_stack.json",
            )

    # 2.9 Agent Contracts
    ac_doc = parsed_json["architecture/agent_contracts.json"]
    kstate_arch_map = {x["id"]: x for x in ac_doc.get("knowledgeStates", []) if isinstance(x, dict)}
    kstate_md_map = extract_md_rows_by_id("registries/AGENT_CONTRACTS.md", "KSTATE-")
    if len(kstate_arch_map) != len(kstate_md_map):
        emit(
            ERR_COUNT_MISMATCH,
            "architecture/agent_contracts.json",
            "#/knowledgeStates",
            f"knowledge states count mismatch: architecture has {len(kstate_arch_map)}, registries has {len(kstate_md_map)}",
        )
    for kid in kstate_arch_map:
        if kid not in kstate_md_map:
            emit(ERR_MISSING_IDENTIFIER, "registries/AGENT_CONTRACTS.md", f"#{kid}", f"knowledge state '{kid}' missing from registries")
    for kid in kstate_md_map:
        if kid not in kstate_arch_map:
            emit(ERR_MISSING_IDENTIFIER, "architecture/agent_contracts.json", f"#/knowledgeStates/{kid}", f"knowledge state '{kid}' missing from architecture")

    prov_arch_map = {x["id"]: x for x in ac_doc.get("provenanceClasses", []) if isinstance(x, dict)}
    prov_md_map = extract_md_rows_by_id("registries/AGENT_CONTRACTS.md", "PROV-")
    if len(prov_arch_map) != len(prov_md_map):
        emit(
            ERR_COUNT_MISMATCH,
            "architecture/agent_contracts.json",
            "#/provenanceClasses",
            f"provenance classes count mismatch: architecture has {len(prov_arch_map)}, registries has {len(prov_md_map)}",
        )
    for pid in prov_arch_map:
        if pid not in prov_md_map:
            emit(ERR_MISSING_IDENTIFIER, "registries/AGENT_CONTRACTS.md", f"#{pid}", f"provenance class '{pid}' missing from registries")
    for pid in prov_md_map:
        if pid not in prov_arch_map:
            emit(ERR_MISSING_IDENTIFIER, "architecture/agent_contracts.json", f"#/provenanceClasses/{pid}", f"provenance class '{pid}' missing from architecture")

    # 2.10 Semantic Hydration Levels
    hyd_levels = parsed_json["architecture/semantic_hydration.json"].get("levels", [])
    hyd_levels_map = {x["id"]: x for x in hyd_levels if isinstance(x, dict) and "id" in x}
    hyd_md_rows = extract_md_rows_by_id("registries/SEMANTIC_HYDRATION.md", "H")
    if len(hyd_levels_map) != len(hyd_md_rows):
        emit(
            ERR_COUNT_MISMATCH,
            "architecture/semantic_hydration.json",
            "#/levels",
            f"semantic hydration levels count mismatch: architecture has {len(hyd_levels_map)}, registries has {len(hyd_md_rows)}",
        )
    for hid in hyd_levels_map:
        if hid not in hyd_md_rows:
            emit(ERR_MISSING_IDENTIFIER, "registries/SEMANTIC_HYDRATION.md", f"#{hid}", f"hydration level '{hid}' missing from registries")
    for hid in hyd_md_rows:
        if hid not in hyd_levels_map:
            emit(ERR_MISSING_IDENTIFIER, "architecture/semantic_hydration.json", f"#/levels/{hid}", f"hydration level '{hid}' missing from architecture")

    # 2.11 Claims
    claims_arch = parsed_json["architecture/claims.json"].get("classes", [])
    claims_arch_ids = {x["id"] for x in claims_arch if isinstance(x, dict) and "id" in x}
    claims_md_rows = parse_markdown_table_rows(parsed_md["registries/CLAIMS.md"])
    claims_md_ids = {r[0] for r in claims_md_rows if r and r[0] != "Claim class"}
    if len(claims_arch_ids) != len(claims_md_ids):
        emit(
            ERR_COUNT_MISMATCH,
            "architecture/claims.json",
            "#/classes",
            f"claims classes count mismatch: architecture has {len(claims_arch_ids)}, registries has {len(claims_md_ids)}",
        )
    for cid in claims_arch_ids:
        if cid not in claims_md_ids:
            emit(ERR_MISSING_IDENTIFIER, "registries/CLAIMS.md", f"#{cid}", f"claim class '{cid}' missing from registries")
    for cid in claims_md_ids:
        if cid not in claims_arch_ids:
            emit(ERR_MISSING_IDENTIFIER, "architecture/claims.json", f"#/classes/{cid}", f"claim class '{cid}' missing from architecture")

    # 2.12 Operation Costs
    costs_toml = parsed_toml["architecture/operation_cost_registry.toml"].get("operation", [])
    costs_toml_map = {x["id"]: x for x in costs_toml if isinstance(x, dict) and "id" in x}
    costs_md_map = extract_md_rows_by_id("registries/OPERATION_COSTS.md", "COST-")
    if len(costs_toml_map) != len(costs_md_map):
        emit(
            ERR_COUNT_MISMATCH,
            "architecture/operation_cost_registry.toml",
            "#[operation]",
            f"operation costs count mismatch: architecture has {len(costs_toml_map)}, registries has {len(costs_md_map)}",
        )
    for cid in costs_toml_map:
        if cid not in costs_md_map:
            emit(ERR_MISSING_IDENTIFIER, "registries/OPERATION_COSTS.md", f"#{cid}", f"cost ID '{cid}' missing from registries")
    for cid in costs_md_map:
        if cid not in costs_toml_map:
            emit(ERR_MISSING_IDENTIFIER, "architecture/operation_cost_registry.toml", f"#[operation.{cid}]", f"cost ID '{cid}' missing from architecture")

    # 2.13 Schemas vs schema files
    schemas_rows = extract_md_rows_by_id("registries/SCHEMAS.md", "SCHEMA-")
    schemas_dir = repo_root / "schemas"
    disk_schemas = sorted(schemas_dir.glob("*.json")) if schemas_dir.is_dir() else []
    disk_schema_rel_paths = {f"schemas/{p.name}" for p in disk_schemas}

    declared_schema_files = {r[2] for r in schemas_rows.values() if len(r) >= 3 and r[2].startswith("schemas/")}
    if declared_schema_files != disk_schema_rel_paths:
        missing_files = declared_schema_files - disk_schema_rel_paths
        unreg_files = disk_schema_rel_paths - declared_schema_files
        for mf in missing_files:
            emit(ERR_MISSING_FILE, mf, "#", f"schema file '{mf}' declared in registries/SCHEMAS.md does not exist on disk")
        for uf in unreg_files:
            emit(ERR_MISSING_IDENTIFIER, uf, "#", f"schema file '{uf}' exists on disk but is not registered in registries/SCHEMAS.md")

    # 3. Cross-Registry Dangling Reference & Tombstone Checks
    # Build complete active and tombstoned ID sets
    known_active_ids: set[str] = set()
    tombstoned_ids: set[str] = set()

    # Collect from all markdown registries
    for rel, text in parsed_md.items():
        rows = parse_markdown_table_rows(text)
        for r in rows:
            if not r:
                continue
            first = r[0]
            if first in ("ID", "Claim class", "Level", "Cost ID"):
                continue
            known_active_ids.add(first)
            row_str = " ".join(r).lower()
            if any(t in row_str for t in ("tombstone", "superseded")):
                tombstoned_ids.add(first)

    # Collect from architecture JSON
    for rel, data in parsed_json.items():
        def walk_arch(obj: Any) -> None:
            if isinstance(obj, dict):
                status = str(obj.get("status", "")).lower()
                disp = str(obj.get("disposition", "")).lower()
                is_tomb = status in ("tombstone", "superseded") or disp in ("tombstone", "superseded")
                for k in ("id", "canonicalId", "legacyId"):
                    v = obj.get(k)
                    if isinstance(v, str) and ("-" in v or "_" in v):
                        known_active_ids.add(v)
                        if is_tomb:
                            tombstoned_ids.add(v)
                for v in obj.values():
                    walk_arch(v)
            elif isinstance(obj, list):
                for item in obj:
                    walk_arch(item)
        walk_arch(data)

    # Collect from stable_id_audit repository index
    try:
        repo_index = stable_id_audit._load_repository_index(repo_root)
        known_active_ids.update(repo_index.known)
        tombstoned_ids.update(repo_index.tombstoned)
    except Exception:
        pass

    # Validate foreign keys
    cap_md_map = extract_md_rows_by_id("registries/CAPABILITIES.md", "CAP-")

    # 3.1 Operations gates, defaultView, capabilities
    for op in aop_arch:
        opid = op.get("id", "unknown")
        gate = op.get("gate")
        if gate:
            if gate in tombstoned_ids:
                emit(ERR_TOMBSTONE_IN_USE, "architecture/agent_operations.json", f"#/operations/{opid}/gate", f"operation '{opid}' references tombstoned gate '{gate}'")
            elif gate not in ql_arch_map:
                emit(ERR_DANGLING_REFERENCE, "architecture/agent_operations.json", f"#/operations/{opid}/gate", f"operation '{opid}' references nonexistent gate '{gate}'")

        view = op.get("defaultView")
        if view:
            if view in tombstoned_ids:
                emit(ERR_TOMBSTONE_IN_USE, "architecture/agent_operations.json", f"#/operations/{opid}/defaultView", f"operation '{opid}' references tombstoned defaultView '{view}'")
            elif view not in view_arch_map:
                emit(ERR_DANGLING_REFERENCE, "architecture/agent_operations.json", f"#/operations/{opid}/defaultView", f"operation '{opid}' references nonexistent view '{view}'")

        for cap in op.get("requiredCapabilities", []):
            if cap in tombstoned_ids:
                emit(ERR_TOMBSTONE_IN_USE, "architecture/agent_operations.json", f"#/operations/{opid}/requiredCapabilities", f"operation '{opid}' references tombstoned capability '{cap}'")
            elif cap not in cap_md_map:
                emit(ERR_DANGLING_REFERENCE, "architecture/agent_operations.json", f"#/operations/{opid}/requiredCapabilities", f"operation '{opid}' references nonexistent capability '{cap}'")

    # 3.2 Views gates
    for v in view_arch:
        vid = v.get("id", "unknown")
        gate = v.get("gate")
        if gate:
            if gate in tombstoned_ids:
                emit(ERR_TOMBSTONE_IN_USE, "architecture/agent_views.json", f"#/views/{vid}/gate", f"view '{vid}' references tombstoned gate '{gate}'")
            elif gate not in ql_arch_map:
                emit(ERR_DANGLING_REFERENCE, "architecture/agent_views.json", f"#/views/{vid}/gate", f"view '{vid}' references nonexistent gate '{gate}'")

    # 3.3 Algorithms gates
    for alg in alg_arch:
        aid = alg.get("id", "unknown")
        gate = alg.get("gate")
        if gate:
            if gate in tombstoned_ids:
                emit(ERR_TOMBSTONE_IN_USE, "architecture/graph_algorithms.json", f"#/algorithms/{aid}/gate", f"algorithm '{aid}' references tombstoned gate '{gate}'")
            elif gate not in known_active_ids:
                emit(ERR_DANGLING_REFERENCE, "architecture/graph_algorithms.json", f"#/algorithms/{aid}/gate", f"algorithm '{aid}' references nonexistent gate '{gate}'")

    # 3.4 Model runtime activationPrimitive & gate
    mr_doc = parsed_json["architecture/model_runtime_registry.json"]
    ap = mr_doc.get("runtime", {}).get("activationPrimitive")
    if ap:
        if ap in tombstoned_ids:
            emit(ERR_TOMBSTONE_IN_USE, "architecture/model_runtime_registry.json", "#/runtime/activationPrimitive", f"model runtime references tombstoned activation primitive '{ap}'")
        elif ap not in pub_arch_map:
            emit(ERR_DANGLING_REFERENCE, "architecture/model_runtime_registry.json", "#/runtime/activationPrimitive", f"model runtime references nonexistent activation primitive '{ap}'")

    for mc in mr_doc.get("contracts", []):
        mc_id = mc.get("id", "unknown")
        gate = mc.get("gate")
        if gate:
            if gate in tombstoned_ids:
                emit(ERR_TOMBSTONE_IN_USE, "architecture/model_runtime_registry.json", f"#/contracts/{mc_id}/gate", f"model contract '{mc_id}' references tombstoned gate '{gate}'")
            elif gate not in known_active_ids:
                emit(ERR_DANGLING_REFERENCE, "architecture/model_runtime_registry.json", f"#/contracts/{mc_id}/gate", f"model contract '{mc_id}' references nonexistent gate '{gate}'")

    # 3.5 Operation costs slo_ids
    slos_md_map = extract_md_rows_by_id("registries/SLOS.md", "SLO-")
    for c in costs_toml:
        cid = c.get("id", "unknown")
        for slo in c.get("slo_ids", []):
            if slo in tombstoned_ids:
                emit(ERR_TOMBSTONE_IN_USE, "architecture/operation_cost_registry.toml", f"#[operation.{cid}].slo_ids", f"cost '{cid}' references tombstoned SLO '{slo}'")
            elif slo not in slos_md_map:
                emit(ERR_DANGLING_REFERENCE, "architecture/operation_cost_registry.toml", f"#[operation.{cid}].slo_ids", f"cost '{cid}' references nonexistent SLO '{slo}'")

    # 3.6 Invariant references in registries & abstraction stack
    inv_ref_re = re.compile(r"\b(INV-\d{3})\b")
    for rel_doc in ("registries/DIGEST_DOMAINS.md", "registries/SCHEMAS.md"):
        doc_text = parsed_md.get(rel_doc, "")
        for line_no, line in enumerate(doc_text.splitlines(), 1):
            for match in inv_ref_re.finditer(line):
                inv_ref = match.group(1)
                if inv_ref in tombstoned_ids:
                    emit(ERR_TOMBSTONE_IN_USE, rel_doc, f"#{line_no}", f"reference to tombstoned invariant '{inv_ref}' in {rel_doc}:{line_no}")
                elif inv_ref not in inv_arch_map:
                    emit(ERR_DANGLING_REFERENCE, rel_doc, f"#{line_no}", f"reference to nonexistent invariant '{inv_ref}' in {rel_doc}:{line_no}")

    for lyr in layer_arch:
        lid = lyr.get("id", "unknown")
        inv_ref = lyr.get("invariant")
        if inv_ref:
            if inv_ref in tombstoned_ids:
                emit(ERR_TOMBSTONE_IN_USE, "architecture/agent_abstraction_stack.json", f"#/layers/{lid}/invariant", f"layer '{lid}' references tombstoned invariant '{inv_ref}'")
            elif inv_ref not in inv_arch_map:
                emit(ERR_DANGLING_REFERENCE, "architecture/agent_abstraction_stack.json", f"#/layers/{lid}/invariant", f"layer '{lid}' references nonexistent invariant '{inv_ref}'")

    # 3.7 Agent operating model and abstraction stack refs
    for rel_doc, doc in (
        ("architecture/agent_abstraction_stack.json", parsed_json["architecture/agent_abstraction_stack.json"]),
        ("architecture/agent_operating_model.json", parsed_json["architecture/agent_operating_model.json"]),
    ):
        for oref in doc.get("operationRefs", []):
            if oref not in aop_arch_map:
                emit(ERR_DANGLING_REFERENCE, rel_doc, f"#/operationRefs/{oref}", f"{rel_doc} references nonexistent operation '{oref}'")
        for vref in doc.get("viewRefs", []):
            if vref not in view_arch_map:
                emit(ERR_DANGLING_REFERENCE, rel_doc, f"#/viewRefs/{vref}", f"{rel_doc} references nonexistent view '{vref}'")
        for kref in doc.get("knowledgeStateRefs", []):
            if kref not in kstate_arch_map:
                emit(ERR_DANGLING_REFERENCE, rel_doc, f"#/knowledgeStateRefs/{kref}", f"{rel_doc} references nonexistent knowledge state '{kref}'")
        for pref in doc.get("provenanceClassRefs", []):
            if pref not in prov_arch_map:
                emit(ERR_DANGLING_REFERENCE, rel_doc, f"#/provenanceClassRefs/{pref}", f"{rel_doc} references nonexistent provenance class '{pref}'")

    # 4. Schema constitution & unregistered Rust schemas/domains (reusing schema_validate)
    validator = schema_validate.Validator()
    try:
        constitution_res = schema_validate.validate_schema_constitution(
            repo_root=repo_root,
            schemas_dir=repo_root / "schemas",
            schemas_md_path=repo_root / "registries/SCHEMAS.md",
            architecture_dir=repo_root / "architecture",
            crates_dir=repo_root / "crates",
            validator=validator,
            digest_domains_path=repo_root / "registries/DIGEST_DOMAINS.md",
        )
        if constitution_res.get("status") != "passed":
            for vf in validator.findings:
                vf_file = getattr(vf, "schema_path", getattr(vf, "file", "registries/SCHEMAS.md"))
                vf_path = getattr(vf, "json_path", getattr(vf, "path", "#"))
                emit(
                    ERR_UNREGISTERED_RUST_IDENTIFIER,
                    str(vf_file),
                    str(vf_path),
                    f"schema constitution error ({vf.code}): {vf.message}",
                )
    except Exception as exc:
        emit(ERR_CORRUPT_FILE, "registries/SCHEMAS.md", "#", f"failed to validate schema constitution: {exc}")

    is_valid = len(findings) == 0
    summary = {
        "status": "pass" if is_valid else "fail",
        "error_count": len(findings),
        "invariants_count": len(inv_arch_map),
        "algorithms_count": len(alg_arch_map),
        "publication_primitives_count": len(pub_arch_map),
        "franken_imports_count": len(imp_arch_map),
        "agent_operations_count": len(aop_arch_map),
        "agent_views_count": len(view_arch_map),
        "qualification_lanes_count": len(ql_arch_map),
        "costs_count": len(costs_toml_map),
        "schemas_count": len(schemas_rows),
        "known_active_ids": len(known_active_ids),
        "tombstone_ids": len(tombstoned_ids),
    }
    return is_valid, findings, summary


def main() -> int:
    parser = argparse.ArgumentParser(description="Architecture and registry consistency checker.")
    parser.add_argument("--root", type=Path, default=ROOT, help="Repository root directory")
    parser.add_argument("--format", choices=["text", "json"], default="text", help="Output format (text, json)")
    parser.add_argument("--report", type=Path, default=None, help="Save structured JSON report to file")
    parser.add_argument("--json", action="store_true", help="Emit JSON output")
    parser.add_argument("--verbose", "-v", action="store_true", help="Verbose output")
    args = parser.parse_args()

    repo_root = args.root.resolve()
    is_valid, findings, summary = validate_consistency(repo_root)

    report_data = {
        "status": "passed" if is_valid else "failed",
        "summary": summary,
        "findings": [asdict(f) for f in findings],
    }

    if args.report:
        args.report.parent.mkdir(parents=True, exist_ok=True)
        with open(args.report, "w", encoding="utf-8") as f:
            json.dump(report_data, f, indent=2)

    if args.json or args.format == "json":
        print(json.dumps(report_data, indent=2))
    else:
        if is_valid:
            print(
                f"[PASS] Architecture/registry consistency audit passed: "
                f"{summary['invariants_count']} invariants, {summary['algorithms_count']} algorithms, "
                f"{summary['publication_primitives_count']} publication primitives, {summary['franken_imports_count']} imports, "
                f"{summary['agent_operations_count']} operations, {summary['agent_views_count']} views, "
                f"{summary['qualification_lanes_count']} lanes, {summary['costs_count']} costs, "
                f"{summary['schemas_count']} schemas, 0 dangling references, 0 tombstone violations."
            )
        else:
            print(f"[FAIL] Architecture/registry consistency audit failed with {len(findings)} error(s):", file=sys.stderr)
            for f in findings:
                print(f"  [{f.code}] {f.file}:{f.location}: {f.message}", file=sys.stderr)

    return 0 if is_valid else 1


if __name__ == "__main__":
    sys.exit(main())
