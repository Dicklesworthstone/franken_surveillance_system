#!/usr/bin/env python3
"""Deterministic architecture/registry consistency checker (fss-x4a.6.9 / FSS-009).

Cross-validates architecture/*.json against registries/*.md, schemas/, and Rust implementations.

Defect hunting / adversarial review remediation (review-529):
1. CRITICAL fail-open: if _load_repository_index fails or returns an empty index, fail closed
   immediately and return without running downstream foreign-key checks on degraded partial state.
2. HIGH tombstone check in Section 3.7: check operationRefs, viewRefs, knowledgeStateRefs, and
   provenanceClassRefs against tombstoned_ids and emit ERR_TOMBSTONE_IN_USE when referenced.
3. HIGH vacuous consistency: verify root collection key existence and enforce non-empty minimum
   cardinality for all mandatory collections in architecture JSON/TOML and registry Markdown.
4. HIGH duplicate detection: detect and report duplicate identifiers in both Markdown tables
   and architecture JSON arrays with ERR_COUNT_MISMATCH.
5. HIGH complete coverage of all 17 architecture files and 21 registry files:
   Architecture files (17):
     - architecture/invariants.json (2.1: paired with registries/INVARIANTS.md)
     - architecture/graph_algorithms.json (2.2: paired with registries/GRAPH_ALGORITHMS.md)
     - architecture/publication_primitives.json (2.3: paired with registries/PUBLICATION_PRIMITIVES.md, 3.4: gate check)
     - architecture/franken_imports.json (2.4: paired with registries/IMPORTS.md, 3.5: gate check)
     - architecture/agent_operations.json (2.5: paired with registries/AGENT_OPERATIONS.md, 3.1: foreign keys)
     - architecture/agent_views.json (2.6: paired with registries/AGENT_VIEWS.md, 3.2: gate check)
     - architecture/release_qualification.json (2.7: paired with registries/QUALIFICATION_LANES.md)
     - architecture/agent_abstraction_stack.json (2.8: paired with registries/AGENT_ABSTRACTIONS.md, 3.9: invariant ref, 3.10: cross-refs)
     - architecture/agent_contracts.json (2.9: paired with registries/AGENT_CONTRACTS.md, 3.7: gate/lane check)
     - architecture/semantic_hydration.json (2.10: paired with registries/SEMANTIC_HYDRATION.md)
     - architecture/claims.json (2.11: paired with registries/CLAIMS.md)
     - architecture/operation_cost_registry.toml (2.12: paired with registries/OPERATION_COSTS.md, 3.8: slo_ids check)
     - architecture/model_runtime_registry.json (2.14: paired with registries/MODELS.md, 3.6: activationPrimitive & gate checks)
     - architecture/dependency_constitution.json (2.15: paired with registries/DEPENDENCIES.md & allowlist path check)
     - architecture/crate_topology.json (2.16: checked against crates/ directory on disk)
     - architecture/decision_cards.json (2.17: verified for decisionFamily contract & schema)
     - architecture/agent_operating_model.json (3.10: verified operationRefs, viewRefs, knowledgeStateRefs, provenanceClassRefs)
   Registry files (21):
     - registries/INVARIANTS.md (2.1)
     - registries/GRAPH_ALGORITHMS.md (2.2)
     - registries/PUBLICATION_PRIMITIVES.md (2.3)
     - registries/IMPORTS.md (2.4)
     - registries/AGENT_OPERATIONS.md (2.5)
     - registries/AGENT_VIEWS.md (2.6)
     - registries/QUALIFICATION_LANES.md (2.7)
     - registries/AGENT_ABSTRACTIONS.md (2.8)
     - registries/AGENT_CONTRACTS.md (2.9: kstates, prov, disps, semanticObjects, templates, priorities)
     - registries/SEMANTIC_HYDRATION.md (2.10)
     - registries/CLAIMS.md (2.11)
     - registries/OPERATION_COSTS.md (2.12)
     - registries/SCHEMAS.md (2.13: paired with schemas/*.json, 4: schema_validate constitution)
     - registries/MODELS.md (2.14: paired with model_runtime_registry.json)
     - registries/DEPENDENCIES.md (2.15: paired with dependency_constitution.json)
     - registries/CAPABILITIES.md (2.18: non-empty & duplicate checks, 3.1: foreign key validation)
     - registries/ERRORS.md (2.18: non-empty & duplicate checks, 3: foreign key validation)
     - registries/SLOS.md (2.18: non-empty & duplicate checks, 3.8: foreign key validation)
     - registries/TESTS.md (2.18: non-empty & duplicate checks, 3.11: gate foreign key validation)
     - registries/RISKS.md (2.18: non-empty & duplicate checks)
     - registries/DIGEST_DOMAINS.md (2.18: non-empty & duplicate checks, 3.9: invariant refs, 4: schema_validate)
6. MEDIUM spaced delimiter parsing: regex DELIMITER_ROW_RE correctly identifies and skips
   table delimiter rows regardless of alignment colons or whitespace.
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
import seed_requirement_checker

# Stable diagnostic error codes
ERR_MISSING_IDENTIFIER = "ERR-CONSISTENCY-MISSING-IDENTIFIER-001"
ERR_CONTRADICTED_METADATA = "ERR-CONSISTENCY-CONTRADICTED-METADATA-001"
ERR_COUNT_MISMATCH = "ERR-CONSISTENCY-COUNT-MISMATCH-001"
ERR_DANGLING_REFERENCE = "ERR-CONSISTENCY-DANGLING-REFERENCE-001"
ERR_RISK_CROSSWALK = "ERR-CONSISTENCY-RISK-CROSSWALK-001"
ERR_TOMBSTONE_IN_USE = "ERR-CONSISTENCY-TOMBSTONE-IN-USE-001"
ERR_UNREGISTERED_RUST_IDENTIFIER = "ERR-CONSISTENCY-UNREGISTERED-RUST-001"
ERR_MISSING_FILE = "ERR-CONSISTENCY-MISSING-FILE-001"
ERR_CORRUPT_FILE = "ERR-CONSISTENCY-CORRUPT-FILE-001"
ERR_GRAPH_UNREGISTERED_PROJECTION = "ERR-GRAPH-UNREGISTERED-PROJECTION-001"
ERR_GRAPH_MISSING_TIE_BREAK = "ERR-GRAPH-MISSING-TIE-BREAK-001"
ERR_GRAPH_MISSING_COMPLEXITY_WITNESS = "ERR-GRAPH-MISSING-COMPLEXITY-WITNESS-001"
ERR_GRAPH_MISSING_OUTPUT_WITNESS = "ERR-GRAPH-MISSING-OUTPUT-WITNESS-001"
ERR_GRAPH_PROJECTION_MISMATCH = "ERR-GRAPH-PROJECTION-MISMATCH-001"
ERR_GRAPH_STABLE_ID_DRIFT = "ERR-GRAPH-STABLE-ID-DRIFT-001"

# Required fields and admitted statuses for architecture/agent_contracts.json drift records.
AGENT_CONTRACT_DRIFT_FIELDS = ("target", "field", "originalValue", "reconciledValue", "reason", "status")
# `resolved` closes an entry: the owning contract was repaired and the entry must carry a non-empty
# `resolution` naming the repair (fss-x4a.30.84).
AGENT_CONTRACT_DRIFT_STATUSES = frozenset({"open", "reconciled", "reconciled_pending_owner_decision", "resolved"})

REGISTERED_GRAPH_PROJECTIONS = frozenset({
    "SensorCoverageGraph",
    "SpatioTemporalTrackGraph",
    "EvidenceClaimGraph",
    "IncidentCausalGraph",
    "DeviceFailureGraph",
    "ArchiveObjectGraph",
    "AuthorityGraph",
    "PlanObligationGraph",
    "OperationalMemoryGraph",
    "DigitalTwinGraph",
})

CANONICAL_GRAPH_ALGORITHM_IDS = frozenset({
    "ALG-DYNCONN-001",
    "ALG-BRIDGE-001",
    "ALG-SCC-001",
    "ALG-TOPO-001",
    "ALG-DOM-001",
    "ALG-SP-001",
    "ALG-KSP-001",
    "ALG-TREACH-001",
    "ALG-MSD-001",
    "ALG-FLOW-001",
    "ALG-GH-001",
    "ALG-MCF-001",
    "ALG-MATCH-001",
    "ALG-MULTIMATCH-001",
    "ALG-SETCOVER-001",
    "ALG-SUBMOD-001",
    "ALG-MST-001",
    "ALG-STEINER-001",
    "ALG-PPR-001",
    "ALG-HITS-001",
    "ALG-CENTRAL-001",
    "ALG-COMM-001",
    "ALG-SPECTRAL-001",
    "ALG-INTERDICT-001",
    "ALG-RELIABILITY-001",
    "ALG-FACTOR-001",
    "ALG-ZSET-001",
})

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
    "architecture/dependencies.json",
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

DELIMITER_ROW_RE = re.compile(r"^\|(?:\s*:?-+:?\s*\|)+$")


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
        if stripped.startswith("|") and stripped.endswith("|"):
            if DELIMITER_ROW_RE.match(stripped):
                continue
            cells = [c.strip().strip("`") for c in stripped.split("|")[1:-1]]
            if cells and not all(re.match(r"^:?-+:?$", c) for c in cells):
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

    # Helper to extract IDs and rows from markdown tables with duplicate detection
    def extract_md_rows_by_id(rel: str, id_prefix: str | None = None) -> dict[str, list[str]]:
        text = parsed_md.get(rel, "")
        rows = parse_markdown_table_rows(text)
        result: dict[str, list[str]] = {}
        for r in rows:
            if not r:
                continue
            first = r[0]
            if first in ("ID", "Claim class", "Level", "Cost ID", "Object", "Candidate", "Class", "Error code", "Lane"):
                continue
            if id_prefix is None or first.startswith(id_prefix):
                if first in result:
                    emit(
                        ERR_COUNT_MISMATCH,
                        rel,
                        f"#{first}",
                        f"duplicate identifier '{first}' in {rel}",
                    )
                else:
                    result[first] = r
        return result

    # Helper to build architecture ID map with duplicate detection
    def build_arch_map(rel: str, items: list[Any], key: str = "id") -> dict[str, dict[str, Any]]:
        result: dict[str, dict[str, Any]] = {}
        for idx, item in enumerate(items):
            if isinstance(item, dict) and key in item:
                item_id = str(item[key])
                if item_id in result:
                    emit(
                        ERR_COUNT_MISMATCH,
                        rel,
                        f"#/{idx}/{item_id}",
                        f"duplicate identifier '{item_id}' in {rel}",
                    )
                else:
                    result[item_id] = item
        return result

    # 2. Paired Registry Verifications

    # 2.1 Invariants
    inv_doc = parsed_json["architecture/invariants.json"]
    if "invariants" not in inv_doc:
        emit(ERR_CORRUPT_FILE, "architecture/invariants.json", "#", "missing mandatory 'invariants' root key")
        inv_arch = []
    else:
        inv_arch = inv_doc["invariants"]
    inv_arch_map = build_arch_map("architecture/invariants.json", inv_arch)
    inv_md_map = extract_md_rows_by_id("registries/INVARIANTS.md", "INV-")

    if len(inv_arch_map) == 0:
        emit(ERR_COUNT_MISMATCH, "architecture/invariants.json", "#/invariants", "invariants collection must not be empty")
    if len(inv_md_map) == 0:
        emit(ERR_COUNT_MISMATCH, "registries/INVARIANTS.md", "#", "invariants registry must not be empty")

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
    alg_doc = parsed_json["architecture/graph_algorithms.json"]
    if "algorithms" not in alg_doc:
        emit(ERR_CORRUPT_FILE, "architecture/graph_algorithms.json", "#", "missing mandatory 'algorithms' root key")
        alg_arch = []
    else:
        alg_arch = alg_doc["algorithms"]
    alg_arch_map = build_arch_map("architecture/graph_algorithms.json", alg_arch)
    alg_md_map = extract_md_rows_by_id("registries/GRAPH_ALGORITHMS.md", "ALG-")

    if len(alg_arch_map) == 0:
        emit(ERR_COUNT_MISMATCH, "architecture/graph_algorithms.json", "#/algorithms", "algorithms collection must not be empty")
    if len(alg_md_map) == 0:
        emit(ERR_COUNT_MISMATCH, "registries/GRAPH_ALGORITHMS.md", "#", "algorithms registry must not be empty")

    if len(alg_arch_map) != len(alg_md_map):
        emit(
            ERR_COUNT_MISMATCH,
            "architecture/graph_algorithms.json",
            "#/algorithms",
            f"graph algorithms count mismatch: architecture has {len(alg_arch_map)}, registries has {len(alg_md_map)}",
        )

    # Stable ID audit: algorithms must not be renumbered and must match canonical set
    for aid in alg_arch_map:
        if aid not in CANONICAL_GRAPH_ALGORITHM_IDS:
            emit(
                ERR_GRAPH_STABLE_ID_DRIFT,
                "architecture/graph_algorithms.json",
                f"#/algorithms/{aid}",
                f"unknown or renumbered graph algorithm ID '{aid}'; canonical IDs are strictly versioned",
            )
        else:
            status = alg_arch_map[aid].get("status")
            if status in TOMBSTONE_STATES:
                pass
    for cid in sorted(CANONICAL_GRAPH_ALGORITHM_IDS):
        if cid not in alg_arch_map:
            emit(
                ERR_GRAPH_STABLE_ID_DRIFT,
                "architecture/graph_algorithms.json",
                f"#/algorithms/{cid}",
                f"canonical graph algorithm ID '{cid}' missing from architecture/graph_algorithms.json",
            )

    DETERMINISTIC_TIE_BREAK_KEYWORDS = (
        "stable",
        "canonical",
        "insertion order",
        "lexicographic",
        "commit sequence",
        "identity",
        "order",
        "key",
    )
    OUTPUT_BOUND_KEYWORDS = (
        "<=",
        "<",
        "bound",
        "bounded",
        "o(",
        "|v|",
        "|e|",
        "nodes",
        "edges",
        "tuples",
        "entries",
        "components",
        "sets",
        "pairs",
        "elements",
        "records",
        "evaluations",
        "k *",
    )

    for aid, item in alg_arch_map.items():
        # Registered projection validation on JSON row
        raw_projections = item.get("projection")
        if not isinstance(raw_projections, list) or len(raw_projections) == 0:
            emit(
                ERR_GRAPH_UNREGISTERED_PROJECTION,
                "architecture/graph_algorithms.json",
                f"#/algorithms/{aid}/projection",
                f"algorithm '{aid}' must specify a non-empty list of registered projections",
            )
            arch_projs = []
        else:
            arch_projs = [str(p) for p in raw_projections]
            for p_idx, proj in enumerate(arch_projs):
                if proj not in REGISTERED_GRAPH_PROJECTIONS:
                    emit(
                        ERR_GRAPH_UNREGISTERED_PROJECTION,
                        "architecture/graph_algorithms.json",
                        f"#/algorithms/{aid}/projection/{p_idx}",
                        f"algorithm '{aid}' specifies unregistered graph projection '{proj}'",
                    )

        # Deterministic CGSE tie-break rule validation
        tie_break = item.get("tieBreak")
        if not isinstance(tie_break, str) or not tie_break.strip():
            emit(
                ERR_GRAPH_MISSING_TIE_BREAK,
                "architecture/graph_algorithms.json",
                f"#/algorithms/{aid}/tieBreak",
                f"algorithm '{aid}' lacks a deterministic CGSE tie-break rule",
            )
        else:
            tb_lower = tie_break.lower()
            if not any(kw in tb_lower for kw in DETERMINISTIC_TIE_BREAK_KEYWORDS):
                emit(
                    ERR_GRAPH_MISSING_TIE_BREAK,
                    "architecture/graph_algorithms.json",
                    f"#/algorithms/{aid}/tieBreak",
                    f"algorithm '{aid}' tie-break rule '{tie_break}' lacks deterministic ordering criteria",
                )

        # Complexity witness validation
        comp_witness = item.get("complexityWitness")
        if not isinstance(comp_witness, str) or not comp_witness.strip():
            emit(
                ERR_GRAPH_MISSING_COMPLEXITY_WITNESS,
                "architecture/graph_algorithms.json",
                f"#/algorithms/{aid}/complexityWitness",
                f"algorithm '{aid}' lacks declared complexity witness operations",
            )

        # Output-size witness validation with bounds
        out_witness = item.get("outputSizeWitness")
        if not isinstance(out_witness, str) or not out_witness.strip():
            emit(
                ERR_GRAPH_MISSING_OUTPUT_WITNESS,
                "architecture/graph_algorithms.json",
                f"#/algorithms/{aid}/outputSizeWitness",
                f"algorithm '{aid}' lacks declared output-size witness with bounds",
            )
        else:
            ow_lower = out_witness.lower()
            if not any(kw in ow_lower for kw in OUTPUT_BOUND_KEYWORDS):
                emit(
                    ERR_GRAPH_MISSING_OUTPUT_WITNESS,
                    "architecture/graph_algorithms.json",
                    f"#/algorithms/{aid}/outputSizeWitness",
                    f"algorithm '{aid}' output-size witness '{out_witness}' lacks explicit mathematical bounds",
                )

        # Mirror equality and cross-check against Markdown registry
        if aid not in alg_md_map:
            emit(
                ERR_MISSING_IDENTIFIER,
                "registries/GRAPH_ALGORITHMS.md",
                f"#{aid}",
                f"algorithm '{aid}' in architecture/graph_algorithms.json is missing from registries/GRAPH_ALGORITHMS.md",
            )
        else:
            md_row = alg_md_map[aid]
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

            md_proj_raw = md_row[2] if len(md_row) >= 3 else ""
            md_projs = [p.strip("` ") for p in md_proj_raw.split(",") if p.strip("` ")]
            for p in md_projs:
                if p not in REGISTERED_GRAPH_PROJECTIONS:
                    emit(
                        ERR_GRAPH_UNREGISTERED_PROJECTION,
                        "registries/GRAPH_ALGORITHMS.md",
                        f"#{aid}",
                        f"algorithm '{aid}' in registries/GRAPH_ALGORITHMS.md specifies unregistered projection '{p}'",
                    )
            if arch_projs != md_projs:
                emit(
                    ERR_GRAPH_PROJECTION_MISMATCH,
                    "architecture/graph_algorithms.json",
                    f"#/algorithms/{aid}/projection",
                    f"algorithm '{aid}' projections mismatch: architecture has {arch_projs}, registries/GRAPH_ALGORITHMS.md has {md_projs}",
                )

    for aid in alg_md_map:
        if aid not in alg_arch_map:
            emit(
                ERR_MISSING_IDENTIFIER,
                "architecture/graph_algorithms.json",
                f"#/algorithms/{aid}",
                f"algorithm '{aid}' in registries/GRAPH_ALGORITHMS.md is missing from architecture/graph_algorithms.json",
            )

    # Validate optional drifts block if present in architecture JSON
    if "drifts" in alg_doc:
        drifts = alg_doc["drifts"]
        if not isinstance(drifts, list):
            emit(ERR_CORRUPT_FILE, "architecture/graph_algorithms.json", "#/drifts", "'drifts' must be an array")
        else:
            for d_idx, drift in enumerate(drifts):
                if not isinstance(drift, dict):
                    emit(ERR_CORRUPT_FILE, "architecture/graph_algorithms.json", f"#/drifts/{d_idx}", "drift entry must be an object")
                    continue
                d_aid = drift.get("algorithmId")
                if d_aid not in CANONICAL_GRAPH_ALGORITHM_IDS:
                    emit(
                        ERR_GRAPH_STABLE_ID_DRIFT,
                        "architecture/graph_algorithms.json",
                        f"#/drifts/{d_idx}/algorithmId",
                        f"drift entry references unknown algorithm ID '{d_aid}'",
                    )
                for req_field in ("field", "originalValue", "reconciledValue", "reason", "status"):
                    if req_field not in drift:
                        emit(
                            ERR_CORRUPT_FILE,
                            "architecture/graph_algorithms.json",
                            f"#/drifts/{d_idx}/{req_field}",
                            f"drift entry missing required field '{req_field}'",
                        )

    # 2.3 Publication Primitives
    pub_doc = parsed_json["architecture/publication_primitives.json"]
    if "primitives" not in pub_doc:
        emit(ERR_CORRUPT_FILE, "architecture/publication_primitives.json", "#", "missing mandatory 'primitives' root key")
        pub_arch = []
    else:
        pub_arch = pub_doc["primitives"]
    pub_arch_map = build_arch_map("architecture/publication_primitives.json", pub_arch)
    pub_md_map = extract_md_rows_by_id("registries/PUBLICATION_PRIMITIVES.md", "PUB-")

    if len(pub_arch_map) == 0:
        emit(ERR_COUNT_MISMATCH, "architecture/publication_primitives.json", "#/primitives", "publication primitives collection must not be empty")
    if len(pub_md_map) == 0:
        emit(ERR_COUNT_MISMATCH, "registries/PUBLICATION_PRIMITIVES.md", "#", "publication primitives registry must not be empty")

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
    imp_doc = parsed_json["architecture/franken_imports.json"]
    if "imports" not in imp_doc:
        emit(ERR_CORRUPT_FILE, "architecture/franken_imports.json", "#", "missing mandatory 'imports' root key")
        imp_arch = []
    else:
        imp_arch = imp_doc["imports"]
    imp_arch_map = build_arch_map("architecture/franken_imports.json", imp_arch)
    imp_md_map = extract_md_rows_by_id("registries/IMPORTS.md", "IMP-")

    if len(imp_arch_map) == 0:
        emit(ERR_COUNT_MISMATCH, "architecture/franken_imports.json", "#/imports", "franken imports collection must not be empty")
    if len(imp_md_map) == 0:
        emit(ERR_COUNT_MISMATCH, "registries/IMPORTS.md", "#", "franken imports registry must not be empty")

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
    aop_doc = parsed_json["architecture/agent_operations.json"]
    if "operations" not in aop_doc:
        emit(ERR_CORRUPT_FILE, "architecture/agent_operations.json", "#", "missing mandatory 'operations' root key")
        aop_arch = []
    else:
        aop_arch = aop_doc["operations"]
    aop_arch_map = build_arch_map("architecture/agent_operations.json", aop_arch)
    aop_md_map = extract_md_rows_by_id("registries/AGENT_OPERATIONS.md", "AOP-")

    if len(aop_arch_map) == 0:
        emit(ERR_COUNT_MISMATCH, "architecture/agent_operations.json", "#/operations", "agent operations collection must not be empty")
    if len(aop_md_map) == 0:
        emit(ERR_COUNT_MISMATCH, "registries/AGENT_OPERATIONS.md", "#", "agent operations registry must not be empty")

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
    view_doc = parsed_json["architecture/agent_views.json"]
    if "views" not in view_doc:
        emit(ERR_CORRUPT_FILE, "architecture/agent_views.json", "#", "missing mandatory 'views' root key")
        view_arch = []
    else:
        view_arch = view_doc["views"]
    view_arch_map = build_arch_map("architecture/agent_views.json", view_arch)
    view_md_map = extract_md_rows_by_id("registries/AGENT_VIEWS.md", "AVIEW-")

    if len(view_arch_map) == 0:
        emit(ERR_COUNT_MISMATCH, "architecture/agent_views.json", "#/views", "agent views collection must not be empty")
    if len(view_md_map) == 0:
        emit(ERR_COUNT_MISMATCH, "registries/AGENT_VIEWS.md", "#", "agent views registry must not be empty")

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
    ql_doc = parsed_json["architecture/release_qualification.json"]
    if "lanes" not in ql_doc:
        emit(ERR_CORRUPT_FILE, "architecture/release_qualification.json", "#", "missing mandatory 'lanes' root key")
        ql_arch = []
    else:
        ql_arch = ql_doc["lanes"]
    ql_arch_map = build_arch_map("architecture/release_qualification.json", ql_arch)
    ql_md_map = extract_md_rows_by_id("registries/QUALIFICATION_LANES.md", "QL-")

    if len(ql_arch_map) == 0:
        emit(ERR_COUNT_MISMATCH, "architecture/release_qualification.json", "#/lanes", "qualification lanes collection must not be empty")
    if len(ql_md_map) == 0:
        emit(ERR_COUNT_MISMATCH, "registries/QUALIFICATION_LANES.md", "#", "qualification lanes registry must not be empty")

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
    layer_doc = parsed_json["architecture/agent_abstraction_stack.json"]
    if "layers" not in layer_doc:
        emit(ERR_CORRUPT_FILE, "architecture/agent_abstraction_stack.json", "#", "missing mandatory 'layers' root key")
        layer_arch = []
    else:
        layer_arch = layer_doc["layers"]
    layer_arch_map = build_arch_map("architecture/agent_abstraction_stack.json", layer_arch)
    layer_md_map = extract_md_rows_by_id("registries/AGENT_ABSTRACTIONS.md", "AGT-")

    if len(layer_arch_map) == 0:
        emit(ERR_COUNT_MISMATCH, "architecture/agent_abstraction_stack.json", "#/layers", "agent layers collection must not be empty")
    if len(layer_md_map) == 0:
        emit(ERR_COUNT_MISMATCH, "registries/AGENT_ABSTRACTIONS.md", "#", "agent abstractions registry must not be empty")

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

    # 2.9 Agent Contracts & Sub-Registries
    ac_doc = parsed_json["architecture/agent_contracts.json"]
    for req_key in ("knowledgeStates", "provenanceClasses", "hypothesisDispositions", "semanticObjects", "resourceTemplates", "responsePriority"):
        if req_key not in ac_doc:
            emit(ERR_CORRUPT_FILE, "architecture/agent_contracts.json", "#", f"missing mandatory '{req_key}' root key")

    # 2.9a Agent contract drift records (optional). Each entry records a vocabulary that code uses
    # but no machine registry backs, so the vocabulary can never be read as registered. Same
    # shape as the graph_algorithms.json drifts, with a free-form `target` instead of an
    # algorithm ID.
    if "drifts" in ac_doc:
        ac_drifts = ac_doc["drifts"]
        if not isinstance(ac_drifts, list):
            emit(ERR_CORRUPT_FILE, "architecture/agent_contracts.json", "#/drifts", "'drifts' must be an array")
        else:
            seen_targets: set[tuple[str, str]] = set()
            for d_idx, drift in enumerate(ac_drifts):
                if not isinstance(drift, dict):
                    emit(ERR_CORRUPT_FILE, "architecture/agent_contracts.json", f"#/drifts/{d_idx}", "drift entry must be an object")
                    continue
                for req_field in AGENT_CONTRACT_DRIFT_FIELDS:
                    if req_field not in drift:
                        emit(
                            ERR_CORRUPT_FILE,
                            "architecture/agent_contracts.json",
                            f"#/drifts/{d_idx}/{req_field}",
                            f"drift entry missing required field '{req_field}'",
                        )
                for text_field in ("target", "field", "reason", "status"):
                    value = drift.get(text_field)
                    if text_field in drift and (not isinstance(value, str) or not value.strip()):
                        emit(
                            ERR_CORRUPT_FILE,
                            "architecture/agent_contracts.json",
                            f"#/drifts/{d_idx}/{text_field}",
                            f"drift entry field '{text_field}' must be a non-empty string",
                        )
                status = drift.get("status")
                if isinstance(status, str) and status.strip() and status not in AGENT_CONTRACT_DRIFT_STATUSES:
                    emit(
                        ERR_CONTRADICTED_METADATA,
                        "architecture/agent_contracts.json",
                        f"#/drifts/{d_idx}/status",
                        f"drift entry status '{status}' is not one of {sorted(AGENT_CONTRACT_DRIFT_STATUSES)}",
                    )
                if status == "resolved":
                    resolution = drift.get("resolution")
                    if not isinstance(resolution, str) or not resolution.strip():
                        emit(
                            ERR_CORRUPT_FILE,
                            "architecture/agent_contracts.json",
                            f"#/drifts/{d_idx}/resolution",
                            "a resolved drift entry must carry a non-empty 'resolution'",
                        )
                key = (str(drift.get("target")), str(drift.get("field")))
                if key in seen_targets:
                    emit(
                        ERR_CONTRADICTED_METADATA,
                        "architecture/agent_contracts.json",
                        f"#/drifts/{d_idx}",
                        f"duplicate drift entry for target '{key[0]}' field '{key[1]}'",
                    )
                seen_targets.add(key)

    # 2.9b Registered comparison rules, projections, scales, and carriers (fss-x4a.30.84). Each
    # block is cross-checked against the schema or registry it projects onto and against the
    # Rust source that implements it, so the registration can never drift from either.
    ac_file = "architecture/agent_contracts.json"

    def read_repo_text(relative: str) -> str | None:
        try:
            return (repo_root / relative).read_text(encoding="utf-8")
        except OSError:
            emit(ERR_MISSING_FILE, relative, "#", f"file required by {ac_file} cross-checks is missing")
            return None

    def load_schema(relative: str) -> dict[str, Any] | None:
        text = read_repo_text(relative)
        if text is None:
            return None
        try:
            value = json.loads(text)
        except json.JSONDecodeError as exc:
            emit(ERR_CORRUPT_FILE, relative, "#", f"invalid JSON: {exc}")
            return None
        return value if isinstance(value, dict) else None

    comparison = ac_doc.get("meaningfulDeltaComparison")
    if comparison is not None:
        rules = comparison.get("rules") if isinstance(comparison, dict) else None
        if not isinstance(rules, list) or not rules:
            emit(ERR_CORRUPT_FILE, ac_file, "#/meaningfulDeltaComparison/rules", "rules must be a non-empty array")
        else:
            delta_rs = read_repo_text("crates/fss-reference/src/meaningful_delta.rs") or ""
            orient_rs = read_repo_text("crates/fss-reference/src/agent_orient.rs") or ""
            seen_rules: set[str] = set()
            for r_idx, rule in enumerate(rules):
                loc = f"#/meaningfulDeltaComparison/rules/{r_idx}"
                if not isinstance(rule, dict):
                    emit(ERR_CORRUPT_FILE, ac_file, loc, "rule must be an object")
                    continue
                rule_id = rule.get("id")
                if not isinstance(rule_id, str) or not re.fullmatch(r"[a-z][a-z_]*", rule_id) or rule_id in seen_rules:
                    emit(ERR_CONTRADICTED_METADATA, ac_file, f"{loc}/id", f"rule id '{rule_id}' must be a unique snake_case rule identity")
                    continue
                seen_rules.add(rule_id)
                for list_field in ("comparedFields", "excludedFields"):
                    values = rule.get(list_field)
                    if not isinstance(values, list) or not values or not all(isinstance(v, str) and v for v in values):
                        emit(ERR_CORRUPT_FILE, ac_file, f"{loc}/{list_field}", f"{list_field} must be a non-empty string array")
                if isinstance(rule.get("comparedFields"), list) and isinstance(rule.get("excludedFields"), list):
                    overlap = set(rule["comparedFields"]) & set(rule["excludedFields"])
                    if overlap:
                        emit(ERR_CONTRADICTED_METADATA, ac_file, loc, f"fields both compared and excluded: {sorted(overlap)}")
                if rule_id == "anchor_position_restatement":
                    claims = rule.get("claims")
                    if not isinstance(claims, list) or not claims:
                        emit(ERR_CORRUPT_FILE, ac_file, f"{loc}/claims", "anchor_position_restatement must name its anchor-position claims")
                    else:
                        if "pub const ANCHOR_POSITION_CLAIMS" not in delta_rs:
                            emit(ERR_CONTRADICTED_METADATA, ac_file, loc, "meaningful_delta.rs defines no ANCHOR_POSITION_CLAIMS")
                        for claim in claims:
                            if f'"{claim}"' not in orient_rs:
                                emit(ERR_CONTRADICTED_METADATA, ac_file, f"{loc}/claims", f"anchor-position claim '{claim}' is not a claim the orient compiler emits")
                if rule_id == "affordance_cost_repricing" and "fss.reference_affordance_frontier.v2" not in delta_rs:
                    emit(ERR_CONTRADICTED_METADATA, ac_file, loc, "meaningful_delta.rs does not implement the v2 affordance frontier comparison")

    projection = ac_doc.get("evidenceAnchorProjection")
    if projection is not None:
        anchor_schema = load_schema("schemas/evidence_anchor.v1.json")
        fields = projection.get("fields") if isinstance(projection, dict) else None
        if not isinstance(fields, list):
            emit(ERR_CORRUPT_FILE, ac_file, "#/evidenceAnchorProjection/fields", "fields must be an array")
        elif anchor_schema is not None:
            required = set(anchor_schema.get("required", [])) - {"schema"}
            named = [f.get("schemaField") for f in fields if isinstance(f, dict)]
            if sorted(named) != sorted(required) or len(set(named)) != len(named):
                emit(ERR_CONTRADICTED_METADATA, ac_file, "#/evidenceAnchorProjection/fields", f"projection names {sorted(named)}, schema requires {sorted(required)}")
            renderer = read_repo_text("crates/fss-cli/src/agent_json.rs") or ""
            start = renderer.find("pub fn evidence_anchor(")
            body = renderer[start : renderer.find("\n}\n", start)] if start >= 0 else ""
            for f_idx, field in enumerate(fields):
                if not isinstance(field, dict):
                    continue
                schema_field, source = field.get("schemaField"), field.get("source")
                if f'"{schema_field}"' not in body:
                    emit(ERR_CONTRADICTED_METADATA, ac_file, f"#/evidenceAnchorProjection/fields/{f_idx}", f"renderer does not emit '{schema_field}'")
                elif source == "not_applicable_sentinel":
                    if "not_applicable_sentinel(" not in body:
                        emit(ERR_CONTRADICTED_METADATA, ac_file, f"#/evidenceAnchorProjection/fields/{f_idx}", f"renderer emits no sentinel for '{schema_field}'")
                elif source == "null":
                    if f'("{schema_field}", "null"' not in body:
                        emit(ERR_CONTRADICTED_METADATA, ac_file, f"#/evidenceAnchorProjection/fields/{f_idx}", f"renderer does not emit null for '{schema_field}'")
                elif not isinstance(source, str) or f"value.{source}" not in body:
                    emit(ERR_CONTRADICTED_METADATA, ac_file, f"#/evidenceAnchorProjection/fields/{f_idx}", f"renderer does not project '{schema_field}' from LedgerAnchor.{source}")

    scale = ac_doc.get("consequenceSeverityScale")
    if scale is not None:
        world_schema = load_schema("schemas/agent_world_envelope.v1.json")
        levels = scale.get("levels") if isinstance(scale, dict) else None
        if not isinstance(levels, list) or not levels:
            emit(ERR_CORRUPT_FILE, ac_file, "#/consequenceSeverityScale/levels", "levels must be a non-empty array")
        elif world_schema is not None:
            props = world_schema.get("properties", {})
            consequence_enum = set(props.get("materialAlternativeWorlds", {}).get("items", {}).get("properties", {}).get("consequenceClass", {}).get("enum", []))
            loss_enum = set(props.get("adversarialResiduals", {}).get("items", {}).get("properties", {}).get("protectedLossClass", {}).get("enum", []))
            renderer = read_repo_text("crates/fss-cli/src/agent_json.rs") or ""

            def match_arms(function: str) -> dict[str, str]:
                start = renderer.find(f"pub const fn {function}(")
                body = renderer[start : renderer.find("\n}\n", start)] if start >= 0 else ""
                arms: dict[str, str] = {}
                for pattern, label in re.findall(r'^\s*([0-9_| ]+?)\s*=>\s*"([a-z_]+)"', body, re.M):
                    for value in pattern.split("|"):
                        arms[value.strip()] = label
                return arms

            consequence_arms = match_arms("consequence_class")
            loss_arms = match_arms("protected_loss_class")
            for l_idx, level in enumerate(levels):
                loc = f"#/consequenceSeverityScale/levels/{l_idx}"
                if not isinstance(level, dict):
                    emit(ERR_CORRUPT_FILE, ac_file, loc, "level must be an object")
                    continue
                severity = str(level.get("severity"))
                key = "_" if severity.startswith(">=") else severity
                if level.get("consequenceClass") not in consequence_enum:
                    emit(ERR_CONTRADICTED_METADATA, ac_file, f"{loc}/consequenceClass", f"'{level.get('consequenceClass')}' is not a schema consequenceClass")
                if level.get("protectedLossClass") not in loss_enum:
                    emit(ERR_CONTRADICTED_METADATA, ac_file, f"{loc}/protectedLossClass", f"'{level.get('protectedLossClass')}' is not a schema protectedLossClass")
                if consequence_arms.get(key) != level.get("consequenceClass") or loss_arms.get(key) != level.get("protectedLossClass"):
                    emit(ERR_CONTRADICTED_METADATA, ac_file, loc, f"severity {severity} renders {consequence_arms.get(key)}/{loss_arms.get(key)}, registry says {level.get('consequenceClass')}/{level.get('protectedLossClass')}")

    carriers = ac_doc.get("viewSectionCarriers")
    if carriers is not None:
        views_doc = load_schema("architecture/agent_views.json")
        view_rows = {v.get("id"): v for v in (views_doc or {}).get("views", []) if isinstance(v, dict)}
        for view_id, sections in (carriers.items() if isinstance(carriers, dict) else []):
            if view_id == "rule":
                continue
            row = view_rows.get(view_id)
            if row is None or not isinstance(sections, dict):
                emit(ERR_CONTRADICTED_METADATA, ac_file, f"#/viewSectionCarriers/{view_id}", f"'{view_id}' is not a registered view with a section map")
                continue
            required_sections = row.get("requiredSections", [])
            if sorted(sections) != sorted(required_sections):
                emit(ERR_CONTRADICTED_METADATA, ac_file, f"#/viewSectionCarriers/{view_id}", f"carriers {sorted(sections)} != required sections {sorted(required_sections)}")
            for section, carrier in sections.items():
                if not isinstance(carrier, str) or not carrier.strip():
                    emit(ERR_CORRUPT_FILE, ac_file, f"#/viewSectionCarriers/{view_id}/{section}", "carrier must be a non-empty string")

    kstate_arch = ac_doc.get("knowledgeStates", [])
    kstate_arch_map = build_arch_map("architecture/agent_contracts.json", kstate_arch)
    kstate_md_map = extract_md_rows_by_id("registries/AGENT_CONTRACTS.md", "KSTATE-")

    if len(kstate_arch_map) == 0:
        emit(ERR_COUNT_MISMATCH, "architecture/agent_contracts.json", "#/knowledgeStates", "knowledge states collection must not be empty")
    if len(kstate_md_map) == 0:
        emit(ERR_COUNT_MISMATCH, "registries/AGENT_CONTRACTS.md", "#", "knowledge states registry must not be empty")

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

    prov_arch = ac_doc.get("provenanceClasses", [])
    prov_arch_map = build_arch_map("architecture/agent_contracts.json", prov_arch)
    prov_md_map = extract_md_rows_by_id("registries/AGENT_CONTRACTS.md", "PROV-")

    if len(prov_arch_map) == 0:
        emit(ERR_COUNT_MISMATCH, "architecture/agent_contracts.json", "#/provenanceClasses", "provenance classes collection must not be empty")
    if len(prov_md_map) == 0:
        emit(ERR_COUNT_MISMATCH, "registries/AGENT_CONTRACTS.md", "#", "provenance classes registry must not be empty")

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

    # Cross-check hypothesis dispositions
    hyp_disps_json = ac_doc.get("hypothesisDispositions", [])
    if not isinstance(hyp_disps_json, list) or len(hyp_disps_json) == 0:
        emit(ERR_COUNT_MISMATCH, "architecture/agent_contracts.json", "#/hypothesisDispositions", "hypothesisDispositions must be a non-empty list")
    else:
        md_text = parsed_md.get("registries/AGENT_CONTRACTS.md", "")
        match_disp = re.search(r"## Hypothesis dispositions\s*\n\s*([^\n]+)", md_text)
        if not match_disp:
            emit(ERR_MISSING_IDENTIFIER, "registries/AGENT_CONTRACTS.md", "#hypothesis-dispositions", "missing 'Hypothesis dispositions' section in registries/AGENT_CONTRACTS.md")
        else:
            disp_line = match_disp.group(1)
            md_disps = [x.replace("`", "").strip() for x in disp_line.split("·")]
            md_disps = [x for x in md_disps if x]
            if set(hyp_disps_json) != set(md_disps):
                emit(
                    ERR_CONTRADICTED_METADATA,
                    "architecture/agent_contracts.json",
                    "#/hypothesisDispositions",
                    f"hypothesis dispositions mismatch: JSON has {hyp_disps_json}, registries has {md_disps}",
                )

    # Cross-check semantic objects catalog
    sem_objs_json = ac_doc.get("semanticObjects", {})
    if not isinstance(sem_objs_json, dict) or len(sem_objs_json) == 0:
        emit(ERR_COUNT_MISMATCH, "architecture/agent_contracts.json", "#/semanticObjects", "semanticObjects must be a non-empty object mapping")
    else:
        sem_md_rows = parse_markdown_table_rows(parsed_md.get("registries/AGENT_CONTRACTS.md", ""))
        sem_catalog_md = {
            r[0]: r[1]
            for r in sem_md_rows
            if len(r) == 2 and r[0] not in ("Object", "ID", "Claim class", "Level")
        }
        if len(sem_catalog_md) == 0:
            emit(ERR_COUNT_MISMATCH, "registries/AGENT_CONTRACTS.md", "#semantic-object-catalog", "semantic object catalog table must not be empty")
        if len(sem_objs_json) != len(sem_catalog_md):
            emit(
                ERR_COUNT_MISMATCH,
                "architecture/agent_contracts.json",
                "#/semanticObjects",
                f"semantic objects count mismatch: JSON has {len(sem_objs_json)}, registries has {len(sem_catalog_md)}",
            )
        for obj_name, schema_id in sem_objs_json.items():
            if obj_name not in sem_catalog_md:
                emit(ERR_MISSING_IDENTIFIER, "registries/AGENT_CONTRACTS.md", f"#{obj_name}", f"semantic object '{obj_name}' missing from registries catalog")
            elif sem_catalog_md[obj_name] != schema_id:
                emit(
                    ERR_CONTRADICTED_METADATA,
                    "architecture/agent_contracts.json",
                    f"#/semanticObjects/{obj_name}",
                    f"semantic object '{obj_name}' schema mismatch: JSON has '{schema_id}', registries has '{sem_catalog_md[obj_name]}'",
                )
        for obj_name in sem_catalog_md:
            if obj_name not in sem_objs_json:
                emit(ERR_MISSING_IDENTIFIER, "architecture/agent_contracts.json", f"#/semanticObjects/{obj_name}", f"semantic object '{obj_name}' in registries catalog missing from architecture")

    # Resource templates and response priorities non-empty checks
    res_templates = ac_doc.get("resourceTemplates", [])
    if not isinstance(res_templates, list) or len(res_templates) == 0:
        emit(ERR_COUNT_MISMATCH, "architecture/agent_contracts.json", "#/resourceTemplates", "resourceTemplates must be a non-empty list")
    resp_priority = ac_doc.get("responsePriority", [])
    if not isinstance(resp_priority, list) or len(resp_priority) == 0:
        emit(ERR_COUNT_MISMATCH, "architecture/agent_contracts.json", "#/responsePriority", "responsePriority must be a non-empty list")

    # 2.10 Semantic Hydration Levels
    hyd_doc = parsed_json["architecture/semantic_hydration.json"]
    if "levels" not in hyd_doc:
        emit(ERR_CORRUPT_FILE, "architecture/semantic_hydration.json", "#", "missing mandatory 'levels' root key")
        hyd_levels = []
    else:
        hyd_levels = hyd_doc["levels"]
    hyd_levels_map = build_arch_map("architecture/semantic_hydration.json", hyd_levels)
    hyd_md_rows = extract_md_rows_by_id("registries/SEMANTIC_HYDRATION.md", "H")

    if len(hyd_levels_map) == 0:
        emit(ERR_COUNT_MISMATCH, "architecture/semantic_hydration.json", "#/levels", "hydration levels collection must not be empty")
    if len(hyd_md_rows) == 0:
        emit(ERR_COUNT_MISMATCH, "registries/SEMANTIC_HYDRATION.md", "#", "hydration levels registry must not be empty")

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
    claims_doc = parsed_json["architecture/claims.json"]
    if "classes" not in claims_doc:
        emit(ERR_CORRUPT_FILE, "architecture/claims.json", "#", "missing mandatory 'classes' root key")
        claims_arch = []
    else:
        claims_arch = claims_doc["classes"]
    claims_arch_ids = set()
    for item in claims_arch:
        if isinstance(item, dict) and "id" in item:
            cid = str(item["id"])
            if cid in claims_arch_ids:
                emit(ERR_COUNT_MISMATCH, "architecture/claims.json", f"#/classes/{cid}", f"duplicate claim class '{cid}' in architecture/claims.json")
            else:
                claims_arch_ids.add(cid)

    claims_md_rows = parse_markdown_table_rows(parsed_md["registries/CLAIMS.md"])
    claims_md_ids = set()
    for r in claims_md_rows:
        if r and r[0] != "Claim class":
            cid = r[0]
            if cid in claims_md_ids:
                emit(ERR_COUNT_MISMATCH, "registries/CLAIMS.md", f"#{cid}", f"duplicate claim class '{cid}' in registries/CLAIMS.md")
            else:
                claims_md_ids.add(cid)

    if len(claims_arch_ids) == 0:
        emit(ERR_COUNT_MISMATCH, "architecture/claims.json", "#/classes", "claims classes collection must not be empty")
    if len(claims_md_ids) == 0:
        emit(ERR_COUNT_MISMATCH, "registries/CLAIMS.md", "#", "claims classes registry must not be empty")

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
    costs_doc = parsed_toml["architecture/operation_cost_registry.toml"]
    if "operation" not in costs_doc:
        emit(ERR_CORRUPT_FILE, "architecture/operation_cost_registry.toml", "#", "missing mandatory 'operation' root table")
        costs_toml = []
    else:
        costs_toml = costs_doc["operation"]
    costs_toml_map = build_arch_map("architecture/operation_cost_registry.toml", costs_toml)
    costs_md_map = extract_md_rows_by_id("registries/OPERATION_COSTS.md", "COST-")

    if len(costs_toml_map) == 0:
        emit(ERR_COUNT_MISMATCH, "architecture/operation_cost_registry.toml", "#[operation]", "operation costs collection must not be empty")
    if len(costs_md_map) == 0:
        emit(ERR_COUNT_MISMATCH, "registries/OPERATION_COSTS.md", "#", "operation costs registry must not be empty")

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

    # 2.13 Schemas vs Schema Files on Disk
    schemas_rows = extract_md_rows_by_id("registries/SCHEMAS.md", "SCHEMA-")
    if len(schemas_rows) == 0:
        emit(ERR_COUNT_MISMATCH, "registries/SCHEMAS.md", "#", "schemas registry must not be empty")

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

    # 2.14 Models Runtime Registry vs MODELS.md
    mr_doc = parsed_json["architecture/model_runtime_registry.json"]
    if "contracts" not in mr_doc:
        emit(ERR_CORRUPT_FILE, "architecture/model_runtime_registry.json", "#", "missing mandatory 'contracts' root key")
        mr_contracts = []
    else:
        mr_contracts = mr_doc["contracts"]
    mr_contracts_map = build_arch_map("architecture/model_runtime_registry.json", mr_contracts)
    if len(mr_contracts_map) == 0:
        emit(ERR_COUNT_MISMATCH, "architecture/model_runtime_registry.json", "#/contracts", "model runtime contracts must not be empty")

    models_md_map = extract_md_rows_by_id("registries/MODELS.md", "MOD-")
    if len(models_md_map) == 0:
        emit(ERR_COUNT_MISMATCH, "registries/MODELS.md", "#", "models registry must not be empty")

    # 2.15 Dependency Constitution & Dependencies Registry vs DEPENDENCIES.md
    dep_doc = parsed_json.get("architecture/dependency_constitution.json", {})
    if "classes" not in dep_doc:
        emit(ERR_CORRUPT_FILE, "architecture/dependency_constitution.json", "#", "missing mandatory 'classes' root key")
        dep_classes = []
    else:
        dep_classes = dep_doc["classes"]
    dep_classes_map = build_arch_map("architecture/dependency_constitution.json", dep_classes)
    if len(dep_classes_map) == 0:
        emit(ERR_COUNT_MISMATCH, "architecture/dependency_constitution.json", "#/classes", "dependency classes must not be empty")

    normative_policy_path = dep_doc.get("normativePolicy")
    if not normative_policy_path or not (repo_root / normative_policy_path).is_file():
        emit(ERR_MISSING_FILE, str(normative_policy_path or "normativePolicy"), "#", "normativePolicy file declared in dependency constitution does not exist")

    dep_registry_doc = parsed_json.get("architecture/dependencies.json", {})
    dep_registry_rows = dep_registry_doc.get("dependencies", []) if isinstance(dep_registry_doc, dict) else []
    dep_registry_map = build_arch_map("architecture/dependencies.json", dep_registry_rows)
    if len(dep_registry_map) == 0:
        emit(ERR_COUNT_MISMATCH, "architecture/dependencies.json", "#/dependencies", "dependencies registry must not be empty")

    # Cross-check: every dependency row must have constitutionClass referencing a valid constitution class
    for dep_id, dep_row in dep_registry_map.items():
        c_class = dep_row.get("constitutionClass")
        if not c_class:
            emit(ERR_CORRUPT_FILE, "architecture/dependencies.json", f"#{dep_id}/constitutionClass", f"dependency '{dep_id}' missing mandatory constitutionClass reference")
        elif c_class not in dep_classes_map:
            emit(ERR_TARGET_NOT_FOUND, "architecture/dependencies.json", f"#{dep_id}/constitutionClass", f"dependency '{dep_id}' references unknown constitution class '{c_class}'")

    dep_md_map = extract_md_rows_by_id("registries/DEPENDENCIES.md", "DEP-")
    if len(dep_md_map) == 0:
        emit(ERR_COUNT_MISMATCH, "registries/DEPENDENCIES.md", "#", "dependencies registry must not be empty")

    if len(dep_md_map) != len(dep_registry_map):
        emit(ERR_COUNT_MISMATCH, "registries/DEPENDENCIES.md", "#", f"markdown mirror row count ({len(dep_md_map)}) differs from dependencies.json ({len(dep_registry_map)})")
    for dep_id in dep_registry_map:
        if dep_id not in dep_md_map:
            emit(ERR_TARGET_NOT_FOUND, "registries/DEPENDENCIES.md", f"#{dep_id}", f"dependency '{dep_id}' present in dependencies.json is missing from registries/DEPENDENCIES.md")

    # 2.16 Crate Topology vs Crates on Disk
    topo_doc = parsed_json["architecture/crate_topology.json"]
    if "layers" not in topo_doc:
        emit(ERR_CORRUPT_FILE, "architecture/crate_topology.json", "#", "missing mandatory 'layers' root key")
        topo_layers = []
    else:
        topo_layers = topo_doc["layers"]

    declared_crates: dict[str, str] = {}
    for layer in topo_layers:
        for c in layer.get("crates", []):
            cname = c.get("name")
            if cname:
                declared_crates[cname] = c.get("status", "unknown")

    crates_dir = repo_root / "crates"
    disk_crates = {p.name for p in crates_dir.iterdir() if p.is_dir() and (p / "Cargo.toml").is_file()} if crates_dir.is_dir() else set()
    for dc in disk_crates:
        if dc not in declared_crates:
            emit(ERR_MISSING_IDENTIFIER, "architecture/crate_topology.json", f"#/layers/{dc}", f"crate '{dc}' on disk is not declared in crate_topology.json")
    for cc, status in declared_crates.items():
        if status in ("implemented", "skeleton"):
            if cc not in disk_crates:
                emit(ERR_MISSING_FILE, f"crates/{cc}", "#", f"crate '{cc}' declared with status '{status}' does not exist on disk")

    # 2.17 Decision Cards
    dec_doc = parsed_json["architecture/decision_cards.json"]
    if "decisionFamily" not in dec_doc:
        emit(ERR_CORRUPT_FILE, "architecture/decision_cards.json", "#", "missing mandatory 'decisionFamily' root key")
        dec_families = []
    else:
        dec_families = dec_doc["decisionFamily"]
    dec_family_map = build_arch_map("architecture/decision_cards.json", dec_families)
    if len(dec_family_map) == 0:
        emit(ERR_COUNT_MISMATCH, "architecture/decision_cards.json", "#/decisionFamily", "decisionFamily collection must not be empty")

    # 2.18 Individual Registry Non-Empty & Duplicate Checks
    cap_md_map = extract_md_rows_by_id("registries/CAPABILITIES.md", "CAP-")
    if len(cap_md_map) == 0:
        emit(ERR_COUNT_MISMATCH, "registries/CAPABILITIES.md", "#", "capabilities registry must not be empty")

    err_md_map = extract_md_rows_by_id("registries/ERRORS.md", "ERR-")
    if len(err_md_map) == 0:
        emit(ERR_COUNT_MISMATCH, "registries/ERRORS.md", "#", "errors registry must not be empty")

    slos_md_map = extract_md_rows_by_id("registries/SLOS.md", "SLO-")
    if len(slos_md_map) == 0:
        emit(ERR_COUNT_MISMATCH, "registries/SLOS.md", "#", "SLOs registry must not be empty")

    tests_md_map = extract_md_rows_by_id("registries/TESTS.md", "TEST-")
    if len(tests_md_map) == 0:
        emit(ERR_COUNT_MISMATCH, "registries/TESTS.md", "#", "tests registry must not be empty")

    risks_md_map = extract_md_rows_by_id("registries/RISKS.md", "RISK-")
    if len(risks_md_map) == 0:
        emit(ERR_COUNT_MISMATCH, "registries/RISKS.md", "#", "risks registry must not be empty")

    domains_md_map = extract_md_rows_by_id("registries/DIGEST_DOMAINS.md", "SCHEMA-DOMAIN-")
    if len(domains_md_map) == 0:
        emit(ERR_COUNT_MISMATCH, "registries/DIGEST_DOMAINS.md", "#", "digest domains registry must not be empty")

    # 3. Cross-Registry Dangling Reference & Tombstone Checks
    known_active_ids: set[str] = set()
    tombstoned_ids: set[str] = set()

    # Collect from all markdown registries
    for rel, text in parsed_md.items():
        rows = parse_markdown_table_rows(text)
        for r in rows:
            if not r:
                continue
            first = r[0]
            if first in ("ID", "Claim class", "Level", "Cost ID", "Object", "Candidate", "Class", "Error code", "Lane"):
                continue
            known_active_ids.add(first)
            row_str = " ".join(r).lower()
            if any(t in row_str for t in ("tombstone", "superseded")):
                tombstoned_ids.add(first)

    # Collect milestone gates from normative comprehensive plan
    plan_path = repo_root / "COMPREHENSIVE_PLAN_FOR_FRANKEN_SURVEILLANCE_SYSTEM.md"
    if plan_path.is_file():
        plan_rows = parse_markdown_table_rows(plan_path.read_text(encoding="utf-8-sig"))
        for r in plan_rows:
            if r and re.match(r"^GATE-\d{3}$", r[0]):
                known_active_ids.add(r[0])

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

    # Collect from stable_id_audit repository index with immediate fail-closed
    index_loaded = False
    try:
        repo_index = stable_id_audit._load_repository_index(repo_root)
        if not repo_index.known:
            emit(
                ERR_CORRUPT_FILE,
                "architecture",
                "#",
                "stable-ID repository index is empty (no active or known stable IDs found)",
            )
        else:
            known_active_ids.update(repo_index.known)
            tombstoned_ids.update(repo_index.tombstoned)
            index_loaded = True
    except Exception as exc:
        target_file = "architecture"
        if hasattr(exc, "details") and isinstance(exc.details, dict):
            target_file = str(exc.details.get("file") or exc.details.get("source") or target_file)
        emit(
            ERR_CORRUPT_FILE,
            target_file,
            "#",
            f"failed to load stable-ID repository index: {exc}",
        )

    # CRITICAL fail-closed: if the stable-ID repository index is unreadable or empty,
    # stop immediately. Downstream foreign-key checks cannot safely run on partial state.
    if not index_loaded:
        return False, findings, {
            "status": "fail",
            "error_count": len(findings),
            "checked_pairs": 0,
            "checked_references": 0,
        }

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

    # 3.4 Publication Primitives gates
    for prim in pub_arch:
        pid = prim.get("id", "unknown")
        gate = prim.get("gate")
        if gate:
            if gate in tombstoned_ids:
                emit(ERR_TOMBSTONE_IN_USE, "architecture/publication_primitives.json", f"#/primitives/{pid}/gate", f"primitive '{pid}' references tombstoned gate '{gate}'")
            elif gate not in known_active_ids:
                emit(ERR_DANGLING_REFERENCE, "architecture/publication_primitives.json", f"#/primitives/{pid}/gate", f"primitive '{pid}' references nonexistent gate '{gate}'")

    # 3.5 Franken Imports gates
    for imp in imp_arch:
        imid = imp.get("id", "unknown")
        gate = imp.get("gate")
        if gate:
            if gate in tombstoned_ids:
                emit(ERR_TOMBSTONE_IN_USE, "architecture/franken_imports.json", f"#/imports/{imid}/gate", f"import '{imid}' references tombstoned gate '{gate}'")
            elif gate not in known_active_ids:
                emit(ERR_DANGLING_REFERENCE, "architecture/franken_imports.json", f"#/imports/{imid}/gate", f"import '{imid}' references nonexistent gate '{gate}'")

    # 3.6 Model runtime activationPrimitive & gate
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

    # 3.7 Agent Contracts gate & qualification lane
    ac_gate = ac_doc.get("gate")
    if ac_gate:
        if ac_gate in tombstoned_ids:
            emit(ERR_TOMBSTONE_IN_USE, "architecture/agent_contracts.json", "#/gate", f"agent contracts references tombstoned gate '{ac_gate}'")
        elif ac_gate not in known_active_ids:
            emit(ERR_DANGLING_REFERENCE, "architecture/agent_contracts.json", "#/gate", f"agent contracts references nonexistent gate '{ac_gate}'")

    ac_ql = ac_doc.get("qualificationLane")
    if ac_ql:
        if ac_ql in tombstoned_ids:
            emit(ERR_TOMBSTONE_IN_USE, "architecture/agent_contracts.json", "#/qualificationLane", f"agent contracts references tombstoned lane '{ac_ql}'")
        elif ac_ql not in ql_arch_map:
            emit(ERR_DANGLING_REFERENCE, "architecture/agent_contracts.json", "#/qualificationLane", f"agent contracts references nonexistent lane '{ac_ql}'")

    # 3.8 Operation costs slo_ids
    for c in costs_toml:
        cid = c.get("id", "unknown")
        for slo in c.get("slo_ids", []):
            if slo in tombstoned_ids:
                emit(ERR_TOMBSTONE_IN_USE, "architecture/operation_cost_registry.toml", f"#[operation.{cid}].slo_ids", f"cost '{cid}' references tombstoned SLO '{slo}'")
            elif slo not in slos_md_map:
                emit(ERR_DANGLING_REFERENCE, "architecture/operation_cost_registry.toml", f"#[operation.{cid}].slo_ids", f"cost '{cid}' references nonexistent SLO '{slo}'")

    # 3.9 Invariant references in registries & abstraction stack
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

    # 3.10 Agent operating model and abstraction stack cross-references (with tombstone enforcement)
    for rel_doc, doc in (
        ("architecture/agent_abstraction_stack.json", parsed_json["architecture/agent_abstraction_stack.json"]),
        ("architecture/agent_operating_model.json", parsed_json["architecture/agent_operating_model.json"]),
    ):
        for oref in doc.get("operationRefs", []):
            if oref in tombstoned_ids:
                emit(ERR_TOMBSTONE_IN_USE, rel_doc, f"#/operationRefs/{oref}", f"{rel_doc} references tombstoned operation '{oref}'")
            elif oref not in aop_arch_map:
                emit(ERR_DANGLING_REFERENCE, rel_doc, f"#/operationRefs/{oref}", f"{rel_doc} references nonexistent operation '{oref}'")
        for vref in doc.get("viewRefs", []):
            if vref in tombstoned_ids:
                emit(ERR_TOMBSTONE_IN_USE, rel_doc, f"#/viewRefs/{vref}", f"{rel_doc} references tombstoned view '{vref}'")
            elif vref not in view_arch_map:
                emit(ERR_DANGLING_REFERENCE, rel_doc, f"#/viewRefs/{vref}", f"{rel_doc} references nonexistent view '{vref}'")
        for kref in doc.get("knowledgeStateRefs", []):
            if kref in tombstoned_ids:
                emit(ERR_TOMBSTONE_IN_USE, rel_doc, f"#/knowledgeStateRefs/{kref}", f"{rel_doc} references tombstoned knowledge state '{kref}'")
            elif kref not in kstate_arch_map:
                emit(ERR_DANGLING_REFERENCE, rel_doc, f"#/knowledgeStateRefs/{kref}", f"{rel_doc} references nonexistent knowledge state '{kref}'")
        for pref in doc.get("provenanceClassRefs", []):
            if pref in tombstoned_ids:
                emit(ERR_TOMBSTONE_IN_USE, rel_doc, f"#/provenanceClassRefs/{pref}", f"{rel_doc} references tombstoned provenance class '{pref}'")
            elif pref not in prov_arch_map:
                emit(ERR_DANGLING_REFERENCE, rel_doc, f"#/provenanceClassRefs/{pref}", f"{rel_doc} references nonexistent provenance class '{pref}'")

    # 3.11 TESTS.md gate references
    for tid, trow in tests_md_map.items():
        if len(trow) >= 3:
            t_gate = trow[2].strip()
            if t_gate and t_gate != "-":
                if t_gate in tombstoned_ids:
                    emit(ERR_TOMBSTONE_IN_USE, "registries/TESTS.md", f"#{tid}/gate", f"test '{tid}' references tombstoned gate '{t_gate}'")
                elif t_gate not in known_active_ids:
                    emit(ERR_DANGLING_REFERENCE, "registries/TESTS.md", f"#{tid}/gate", f"test '{tid}' references nonexistent gate '{t_gate}'")

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

    # DRIFT-003 has one canonical catalog and one guard, shared with direct E2E.
    seed_report = seed_requirement_checker.check(repo_root)
    for error in seed_report["findings"]:
        emit(error["code"], error["file"], error["location"], error["message"])

    # DRIFT-005: the typed risk crosswalk must map every prose plan risk (RISK-001..030) exactly
    # once onto declared machine risk rows (registries/RISKS.md), with honest coverage states.
    risk_crosswalk_summary: dict[str, int] = {"entries": 0, "uncovered": 0}
    crosswalk_path = repo_root / "architecture/risk_crosswalk.json"
    risks_rows = parse_markdown_table_rows((repo_root / "registries/RISKS.md").read_text(encoding="utf-8"))
    machine_risk_ids = {row[0] for row in risks_rows if row and row[0].startswith("RISK-")}
    if crosswalk_path.is_file():
        try:
            crosswalk = json.loads(crosswalk_path.read_text(encoding="utf-8"))
        except json.JSONDecodeError as exc:
            emit(ERR_RISK_CROSSWALK, "architecture/risk_crosswalk.json", "#", f"risk crosswalk is not valid JSON: {exc}")
            crosswalk = {}
        if crosswalk:
            if crosswalk.get("schema") != "fss.risk_crosswalk.v1":
                emit(ERR_RISK_CROSSWALK, "architecture/risk_crosswalk.json", "schema", "risk crosswalk schema must be fss.risk_crosswalk.v1")
            entries = crosswalk.get("crosswalk")
            if not isinstance(entries, list):
                emit(ERR_RISK_CROSSWALK, "architecture/risk_crosswalk.json", "crosswalk", "risk crosswalk must declare a crosswalk array")
                entries = []
            prose_ids = [e.get("prose_id") for e in entries if isinstance(e, dict)]
            expected_prose = [f"RISK-{i:03d}" for i in range(1, 31)]
            if sorted(filter(None, prose_ids)) != expected_prose:
                emit(ERR_RISK_CROSSWALK, "architecture/risk_crosswalk.json", "crosswalk", f"risk crosswalk must map exactly {expected_prose[0]}..{expected_prose[-1]} once each")
            for entry in entries:
                if not isinstance(entry, dict):
                    continue
                pid = entry.get("prose_id", "?")
                for machine_id in entry.get("machine_risk_ids", []):
                    if machine_id not in machine_risk_ids:
                        emit(ERR_RISK_CROSSWALK, "architecture/risk_crosswalk.json", pid, f"machine risk id '{machine_id}' is not declared in registries/RISKS.md")
                if entry.get("coverage") not in {"covered", "partial", "uncovered"}:
                    emit(ERR_RISK_CROSSWALK, "architecture/risk_crosswalk.json", pid, f"invalid coverage state: {entry.get('coverage')}")
                if entry.get("coverage") == "uncovered" and not entry.get("note"):
                    emit(ERR_RISK_CROSSWALK, "architecture/risk_crosswalk.json", pid, "uncovered crosswalk entries must name the exposure in their note")
            stated = crosswalk.get("coverage_summary", {})
            actual = {
                "covered": sum(1 for e in entries if isinstance(e, dict) and e.get("coverage") == "covered"),
                "partial": sum(1 for e in entries if isinstance(e, dict) and e.get("coverage") == "partial"),
                "uncovered": sum(1 for e in entries if isinstance(e, dict) and e.get("coverage") == "uncovered"),
            }
            if stated.get("covered") != actual["covered"] or stated.get("partial") != actual["partial"] or stated.get("uncovered") != actual["uncovered"]:
                emit(ERR_RISK_CROSSWALK, "architecture/risk_crosswalk.json", "coverage_summary", f"coverage summary {stated} does not match the crosswalk entries {actual}")
            risk_crosswalk_summary = {"entries": len(entries), "uncovered": actual["uncovered"]}

    is_valid = len(findings) == 0
    summary = {
        "status": "pass" if is_valid else "fail",
        "error_count": len(findings),
        "risk_crosswalk_entries": risk_crosswalk_summary.get("entries", 0),
        "risk_crosswalk_uncovered": risk_crosswalk_summary.get("uncovered", 0),
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
        "seed_requirements_count": seed_report["actualCount"],
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
