#!/usr/bin/env python3
"""Fail-closed provenance-class registry checker (fss-x4a.30.83.10).

Enforces the provenance registry contract:
1. Provenance registry row drift between architecture JSON and markdown mirror (ERR-PROV-REGISTRY-DRIFT-001)
2. Stable ID reused, duplicated, renumbered, or diverging from canonical baseline (ERR-PROV-STABLE-ID-REUSED-001)
3. Missing or empty mandatory field in a provenance row or top-level metadata (ERR-PROV-MISSING-FIELD-001)
4. Corrupt or missing mandatory registry files (ERR-PROV-CORRUPT-FILE-001)
5. Registry digest mismatch between declared and canonical computed digest (ERR-PROV-DIGEST-MISMATCH-001)
6. Registry digest diverged from pinned baseline freeze digest (ERR-PROV-FREEZE-DIVERGENCE-001)
7. Registry generation diverged from baseline generation (ERR-PROV-GENERATION-MISMATCH-001)
8. Provenance semantic invariant violation (ERR-PROV-SEMANTIC-INVARIANT-001)
9. Evidence-laundering refusal has no non-test production caller (ERR-PROV-LAUUNDERING-UNWIRED-001, fss-2nwxm)
"""
from __future__ import annotations

import argparse
import hashlib
import json
import re
import sys
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]

# Registered stable diagnostic finding IDs (registries/ERRORS.md)
ERR_PROV_REGISTRY_DRIFT = "ERR-PROV-REGISTRY-DRIFT-001"
ERR_PROV_STABLE_ID_REUSED = "ERR-PROV-STABLE-ID-REUSED-001"
ERR_PROV_MISSING_FIELD = "ERR-PROV-MISSING-FIELD-001"
ERR_PROV_CORRUPT_FILE = "ERR-PROV-CORRUPT-FILE-001"
ERR_PROV_DIGEST_MISMATCH = "ERR-PROV-DIGEST-MISMATCH-001"
ERR_PROV_FREEZE_DIVERGENCE = "ERR-PROV-FREEZE-DIVERGENCE-001"
ERR_PROV_GENERATION_MISMATCH = "ERR-PROV-GENERATION-MISMATCH-001"
ERR_PROV_SEMANTIC_INVARIANT = "ERR-PROV-SEMANTIC-INVARIANT-001"
ERR_PROV_LAUUNDERING_UNWIRED = "ERR-PROV-LAUUNDERING-UNWIRED-001"

AGENT_CONTRACTS_JSON_PATH = "architecture/agent_contracts.json"
PROVENANCE_CLASSES_JSON_PATH = "architecture/provenance_classes.json"
AGENT_CONTRACTS_MD_PATH = "registries/AGENT_CONTRACTS.md"

BASELINE_GENERATION = "gen:fss1:provenance-v1"
BASELINE_FREEZE_DIGEST = "sha256:2db44231489f586cddfab7b538101fbeac487ada3c0167e2f341f28a00aaafde"

EXPECTED_FREEZE_DIGESTS: dict[str, str] = {
    BASELINE_GENERATION: BASELINE_FREEZE_DIGEST,
}

# Full baseline provenance-class rows for generation gen:fss1:provenance-v1
BASELINE_PROVENANCE_CLASSES: dict[str, dict[str, str]] = {
    "PROV-001": {
        "id": "PROV-001",
        "class": "observed",
        "meaning": "Directly supported by canonical sensor, device, operator, or effect evidence.",
    },
    "PROV-002": {
        "id": "PROV-002",
        "class": "derived",
        "meaning": "Deterministically computed from named canonical inputs under a registered algorithm and generation.",
    },
    "PROV-003": {
        "id": "PROV-003",
        "class": "predicted",
        "meaning": "Counterfactual or forward prediction under an explicit branch/model and assumptions.",
    },
    "PROV-004": {
        "id": "PROV-004",
        "class": "remembered",
        "meaning": "Advisory operational memory or prior episode material that must be revalidated against live evidence.",
    },
    "PROV-005": {
        "id": "PROV-005",
        "class": "operator_asserted",
        "meaning": "A human/operator assertion with identity, time, scope, and later corroboration status.",
    },
    "PROV-006": {
        "id": "PROV-006",
        "class": "vendor_claimed",
        "meaning": "Metadata or state asserted by a device/vendor boundary and not treated as independent physical truth.",
    },
    "PROV-007": {
        "id": "PROV-007",
        "class": "policy",
        "meaning": "A rule, threshold, capability, or privacy decision from an exact policy generation.",
    },
}

# Provenance classes forbidden from authorizing irreversible effects
NON_AUTHORIZING_CLASSES: frozenset[str] = frozenset({"predicted", "remembered", "vendor_claimed"})

# Provenance classes permitted to authorize irreversible effects (when knowledge state is known, subject to capability and policy)
AUTHORIZING_CLASSES: frozenset[str] = frozenset({"observed", "derived", "operator_asserted", "policy"})

ALL_PROVENANCE_CLASSES: frozenset[str] = NON_AUTHORIZING_CLASSES | AUTHORIZING_CLASSES

# States requiring evidence for observed / derived provenance
STATES_REQUIRING_EVIDENCE: frozenset[str] = frozenset({
    "known",
    "estimated",
    "conflicted",
    "stale",
})

# States where empty evidence is legitimate and expected (honest absence or non-positive assertion)
STATES_PERMITTING_EMPTY_EVIDENCE: frozenset[str] = frozenset({
    "unknown",
    "not_observable",
    "not_applicable",
    "redacted",
    "indeterminate",
})

MANDATORY_TOP_LEVEL_FIELDS: tuple[str, ...] = (
    "schema",
    "asOf",
    "generation",
    "semanticProtocol",
    "constitutionalDocument",
    "humanContracts",
    "registryDigest",
    "provenanceClasses",
)
ALLOWED_TOP_LEVEL_KEYS: frozenset[str] = frozenset(MANDATORY_TOP_LEVEL_FIELDS)

MANDATORY_ROW_FIELDS: tuple[str, ...] = (
    "id",
    "class",
    "meaning",
)
ALLOWED_ROW_KEYS: frozenset[str] = frozenset(MANDATORY_ROW_FIELDS)

AGENT_CONTRACTS_MANDATORY_ROW_FIELDS: tuple[str, ...] = (
    "id",
    "name",
    "meaning",
)
AGENT_CONTRACTS_ALLOWED_ROW_KEYS: frozenset[str] = frozenset(AGENT_CONTRACTS_MANDATORY_ROW_FIELDS)

PROV_ID_PATTERN = re.compile(r"^PROV-\d{3}$")


@dataclass(frozen=True)
class DiagnosticError:
    code: str
    file_path: str
    target: str
    message: str


@dataclass
class ValidationResult:
    passed: bool = True
    provenance_class_count: int = 0
    registry_digest: str = ""
    errors: list[DiagnosticError] = field(default_factory=list)

    def add_error(self, code: str, file_path: str, target: str, message: str) -> None:
        self.passed = False
        self.errors.append(DiagnosticError(code=code, file_path=file_path, target=target, message=message))


def canonicalize_value(root_val: Any, max_depth: int = 32) -> Any:
    """Iteratively canonicalizes nested dicts and lists with sorted keys without recursion.

    Raises ValueError if nesting depth exceeds max_depth or if unsupported types/cycles are found.
    """
    if not isinstance(root_val, (dict, list)):
        return root_val

    if isinstance(root_val, dict):
        result_root: Any = {}
        stack: list[tuple[Any, Any, list, int]] = [
            (root_val, result_root, sorted(root_val.keys(), reverse=True), 1)
        ]
    else:
        result_root = [None] * len(root_val)
        stack = [
            (root_val, result_root, list(reversed(range(len(root_val)))), 1)
        ]

    while stack:
        src, dst, pending, depth = stack[-1]
        if depth > max_depth:
            raise ValueError(f"Maximum nesting depth of {max_depth} exceeded")
        if not pending:
            stack.pop()
            continue

        key = pending.pop()
        val = src[key]

        if isinstance(val, dict):
            new_dict: dict[str, Any] = {}
            dst[key] = new_dict
            stack.append((val, new_dict, sorted(val.keys(), reverse=True), depth + 1))
        elif isinstance(val, list):
            new_list: list[Any] = [None] * len(val)
            dst[key] = new_list
            stack.append((val, new_list, list(reversed(range(len(val)))), depth + 1))
        else:
            dst[key] = val

    return result_root


def compute_canonical_provenance_digest(
    data_or_classes: dict[str, Any] | list[dict[str, Any]],
    schema: str = "fss.provenance_classes.v1",
    as_of: str = "2026-08-31",
    generation: str = BASELINE_GENERATION,
    semantic_protocol: str = "fss/1",
    constitutional_document: str = "AGENT_COGNITION_AND_CONTROL.md",
    human_contracts: str = "registries/AGENT_CONTRACTS.md",
) -> str:
    """Computes SHA-256 digest of canonically serialized provenance-class registry data.

    Binds top-level metadata (schema, asOf, generation, semanticProtocol,
    constitutionalDocument, humanContracts) and deterministically sorted
    provenanceClasses rows byte-exact.
    """
    if isinstance(data_or_classes, dict):
        data = data_or_classes
        # Reject unknown top-level keys
        unknown_keys = set(data.keys()) - ALLOWED_TOP_LEVEL_KEYS
        if unknown_keys:
            raise ValueError(f"Unknown top-level key(s) in provenance registry: {sorted(unknown_keys)}")

        schema_val = data.get("schema")
        as_of_val = data.get("asOf")
        generation_val = data.get("generation")
        proto_val = data.get("semanticProtocol")
        doc_val = data.get("constitutionalDocument")
        contracts_val = data.get("humanContracts")

        for fname, fval in [
            ("schema", schema_val),
            ("asOf", as_of_val),
            ("generation", generation_val),
            ("semanticProtocol", proto_val),
            ("constitutionalDocument", doc_val),
            ("humanContracts", contracts_val),
        ]:
            if not isinstance(fval, str) or len(fval) == 0:
                raise TypeError(f"Top-level field '{fname}' must be a non-empty string, got {type(fval).__name__}")

        raw_classes = data.get("provenanceClasses")
    elif isinstance(data_or_classes, list):
        schema_val = schema
        as_of_val = as_of
        generation_val = generation
        proto_val = semantic_protocol
        doc_val = constitutional_document
        contracts_val = human_contracts
        raw_classes = data_or_classes
    else:
        raise TypeError(f"Input must be a dict or list, got {type(data_or_classes).__name__}")

    # Type-check provenanceClasses before sorting
    if not isinstance(raw_classes, list):
        raise TypeError(f"provenanceClasses must be a list, got {type(raw_classes).__name__}")

    for idx, r in enumerate(raw_classes):
        if not isinstance(r, dict):
            raise TypeError(f"provenanceClasses row at index {idx} must be a dict, got {type(r).__name__}")
        pid = r.get("id")
        if not isinstance(pid, str) or len(pid) == 0:
            raise TypeError(f"provenanceClasses row at index {idx} missing non-empty string 'id'")

    sorted_classes = sorted(raw_classes, key=lambda r: str(r["id"]))
    canonical_payload = {
        "asOf": as_of_val,
        "constitutionalDocument": doc_val,
        "generation": generation_val,
        "humanContracts": contracts_val,
        "provenanceClasses": [canonicalize_value(r) for r in sorted_classes],
        "schema": schema_val,
        "semanticProtocol": proto_val,
    }
    canonical_bytes = json.dumps(canonical_payload, sort_keys=True, separators=(",", ":")).encode("utf-8")
    return f"sha256:{hashlib.sha256(canonical_bytes).hexdigest()}"


def extract_markdown_provenance_classes(md_path: Path) -> tuple[dict[str, tuple[str, str]], list[str]]:
    """Extracts provenance classes from markdown table.

    Returns:
        (rows_dict, duplicate_ids_list)
        where rows_dict is {id: (class_name, meaning)} with first-row-retained semantics,
        and duplicate_ids_list records any IDs that appeared more than once.
    """
    rows: dict[str, tuple[str, str]] = {}
    seen_ids: set[str] = set()
    duplicates: list[str] = []
    lines = md_path.read_text(encoding="utf-8").splitlines()
    for line in lines:
        stripped = line.strip()
        if stripped.startswith("| `PROV-"):
            parts = [p.strip() for p in stripped.strip("|").split("|")]
            if len(parts) >= 3:
                pid = parts[0].replace("`", "").strip()
                cls = parts[1].replace("`", "").strip()
                meaning = parts[2].strip()
                if pid in seen_ids:
                    duplicates.append(pid)
                else:
                    seen_ids.add(pid)
                    rows[pid] = (cls, meaning)
    return rows, duplicates


def validate_provenance_authorization(
    provenance_class: str,
    knowledge_state: str,
    is_irreversible: bool = False,
) -> tuple[bool, str | None]:
    """Validates whether a provenance class may authorize an effect.

    Non-authorizing classes (predicted, remembered, vendor_claimed) can NEVER
    authorize irreversible effects, regardless of knowledge state or confidence score.
    Irreversible effects additionally require knowledge state 'known'.
    """
    if is_irreversible:
        if provenance_class in NON_AUTHORIZING_CLASSES:
            return (
                False,
                f"Provenance class '{provenance_class}' is non-authorizing and cannot authorize irreversible effects (ERR-PROV-SEMANTIC-INVARIANT-001)",
            )
        if knowledge_state != "known":
            return (
                False,
                f"Irreversible effects require knowledge state 'known', got '{knowledge_state}'",
            )
    return True, None


def validate_state_aware_evidence(
    provenance_class: str,
    knowledge_state: str,
    evidence_count: int,
) -> tuple[bool, str | None]:
    """Enforces the state-aware evidence invariant for provenance classes.

    Observed and Derived provenance require evidence/derivation inputs only when
    the proposition is positively/negatively asserted (known, estimated, conflicted, stale).
    Honest Unknown, NotObservable, NotApplicable, Redacted, or Indeterminate cells
    legitimately have Observed provenance with zero evidence.
    """
    if provenance_class == "observed":
        if knowledge_state in STATES_REQUIRING_EVIDENCE and evidence_count == 0:
            return (
                False,
                f"Observed provenance requires non-empty evidence when knowledge state is '{knowledge_state}' (ERR-PROV-SEMANTIC-INVARIANT-001)",
            )
    elif provenance_class == "derived":
        if knowledge_state in STATES_REQUIRING_EVIDENCE and evidence_count == 0:
            return (
                False,
                f"Derived provenance requires derivation inputs/witness when knowledge state is '{knowledge_state}' (ERR-PROV-SEMANTIC-INVARIANT-001)",
            )
    return True, None


def validate_cell_provenance_invariants(
    provenance_class: str,
    knowledge_state: str,
    evidence_count: int = 0,
    authorizes_irreversible_effect: bool = False,
    file_path: str = PROVENANCE_CLASSES_JSON_PATH,
    target: str = "#",
) -> list[DiagnosticError]:
    """Validates cell-level semantic invariants across knowledge state, provenance class, and evidence."""
    errors: list[DiagnosticError] = []

    if provenance_class not in ALL_PROVENANCE_CLASSES:
        errors.append(
            DiagnosticError(
                code=ERR_PROV_SEMANTIC_INVARIANT,
                file_path=file_path,
                target=f"{target}/provenance_class",
                message=f"Unknown provenance class '{provenance_class}'",
            )
        )

    # Invariant 1: Irreversible effect authorization
    auth_ok, auth_msg = validate_provenance_authorization(
        provenance_class, knowledge_state, is_irreversible=authorizes_irreversible_effect
    )
    if not auth_ok:
        errors.append(
            DiagnosticError(
                code=ERR_PROV_SEMANTIC_INVARIANT,
                file_path=file_path,
                target=f"{target}/authorization",
                message=auth_msg or "Illegal effect authorization",
            )
        )

    # Invariant 2: State-aware evidence requirement
    ev_ok, ev_msg = validate_state_aware_evidence(
        provenance_class, knowledge_state, evidence_count
    )
    if not ev_ok:
        errors.append(
            DiagnosticError(
                code=ERR_PROV_SEMANTIC_INVARIANT,
                file_path=file_path,
                target=f"{target}/evidence",
                message=ev_msg or "Missing required evidence",
            )
        )

    return errors


def extract_rust_may_launder_matrix(contract_rs_path: Path) -> dict[str, list[str]]:
    """Parses `pub const fn may_launder_evidence_into` from `crates/fss-core/src/contract.rs`.

    Evaluates the Rust match expression against all 7 canonical provenance classes to produce
    a mapping of `{source_provenance: [target_provenances]}`.
    """
    content = contract_rs_path.read_text(encoding="utf-8")
    m = re.search(
        r"pub const fn may_launder_evidence_into\s*\(\s*self\s*,\s*target\s*:\s*Self\s*\)\s*->\s*bool\s*\{(.*?)\n    \}",
        content,
        re.DOTALL,
    )
    if not m:
        raise ValueError("Cannot locate pub const fn may_launder_evidence_into in contract.rs")
    lines = m.group(1).splitlines()
    arms: list[tuple[str, str]] = []
    curr_pat: str | None = None
    curr_expr: list[str] = []
    depth = 0
    for line in lines:
        stripped = line.strip()
        if not stripped or stripped == "match self {" or stripped == "}":
            continue
        if curr_pat is None and "=>" in stripped:
            pat_part, expr_part = stripped.split("=>", 1)
            curr_pat = pat_part.strip()
            curr_expr = [expr_part.strip()]
            depth = expr_part.count("(") - expr_part.count(")")
            if depth == 0 and expr_part.strip().endswith(","):
                arms.append((curr_pat, " ".join(curr_expr).rstrip(",")))
                curr_pat = None
                curr_expr = []
        elif curr_pat is not None:
            curr_expr.append(stripped)
            depth += stripped.count("(") - stripped.count(")")
            if depth == 0 and stripped.endswith(","):
                arms.append((curr_pat, " ".join(curr_expr).rstrip(",")))
                curr_pat = None
                curr_expr = []

    variants = [
        "Observed",
        "Derived",
        "Predicted",
        "Remembered",
        "OperatorAsserted",
        "VendorClaimed",
        "Policy",
    ]
    name_map = {
        "Observed": "observed",
        "Derived": "derived",
        "Predicted": "predicted",
        "Remembered": "remembered",
        "OperatorAsserted": "operator_asserted",
        "VendorClaimed": "vendor_claimed",
        "Policy": "policy",
    }
    matrix: dict[str, list[str]] = {}
    for v_self in variants:
        self_name = name_map[v_self]
        expr = None
        for arm_pat, arm_expr in arms:
            pats = [p.strip().replace("Self::", "").strip() for p in arm_pat.split("|")]
            if v_self in pats:
                expr = arm_expr
                break
        if expr is None:
            raise ValueError(f"No match arm found in contract.rs for variant Self::{v_self}")
        targets: list[str] = []
        for v_target in variants:
            if expr == "false":
                matches = False
            elif "!matches!" in expr:
                m_not = re.search(r"!matches!\s*\(\s*target\s*,\s*Self::(\w+)\s*\)", expr)
                if not m_not:
                    raise ValueError(f"Cannot parse !matches expr: {expr}")
                negated_var = m_not.group(1)
                matches = v_target != negated_var
            elif "matches!" in expr:
                m_match = re.search(r"matches!\s*\(\s*target\s*,\s*(.*?)\)", expr)
                if not m_match:
                    raise ValueError(f"Cannot parse matches expr: {expr}")
                allowed = [p.strip().replace("Self::", "").strip() for p in m_match.group(1).split("|")]
                matches = v_target in allowed
            else:
                raise ValueError(f"Unknown match arm expression: {expr}")
            if matches:
                targets.append(name_map[v_target])
        matrix[self_name] = targets
    return matrix


def validate_provenance_registry(repo_root: Path = ROOT) -> ValidationResult:
    result = ValidationResult()
    json_path = repo_root / PROVENANCE_CLASSES_JSON_PATH
    md_path = repo_root / AGENT_CONTRACTS_MD_PATH
    ac_json_path = repo_root / AGENT_CONTRACTS_JSON_PATH

    # Check existence of required files
    if not json_path.is_file():
        result.add_error(
            ERR_PROV_CORRUPT_FILE,
            PROVENANCE_CLASSES_JSON_PATH,
            "#",
            f"Provenance-class registry JSON file does not exist: {json_path}",
        )
        return result

    if not md_path.is_file():
        result.add_error(
            ERR_PROV_CORRUPT_FILE,
            AGENT_CONTRACTS_MD_PATH,
            "#",
            f"Agent contracts markdown file does not exist: {md_path}",
        )

    if not ac_json_path.is_file():
        result.add_error(
            ERR_PROV_CORRUPT_FILE,
            AGENT_CONTRACTS_JSON_PATH,
            "#",
            f"Agent contracts umbrella JSON file does not exist: {ac_json_path}",
        )

    # Parse JSON
    try:
        data = json.loads(json_path.read_text(encoding="utf-8"))
    except Exception as exc:
        result.add_error(
            ERR_PROV_CORRUPT_FILE,
            PROVENANCE_CLASSES_JSON_PATH,
            "#",
            f"Failed to parse provenance-class JSON: {exc}",
        )
        return result

    if not isinstance(data, dict):
        result.add_error(
            ERR_PROV_CORRUPT_FILE,
            PROVENANCE_CLASSES_JSON_PATH,
            "#",
            "Top-level provenance-class registry must be a JSON object",
        )
        return result

    # Reject unknown top-level keys
    for k in sorted(data.keys()):
        if k not in ALLOWED_TOP_LEVEL_KEYS:
            if "authoriz" in k.lower() or "effect" in k.lower() or "irreversible" in k.lower():
                result.add_error(
                    ERR_PROV_SEMANTIC_INVARIANT,
                    PROVENANCE_CLASSES_JSON_PATH,
                    f"#/{k}",
                    f"Semantic invariant violation: unauthorized effect authorization configuration in key '{k}'",
                )
            result.add_error(
                ERR_PROV_CORRUPT_FILE,
                PROVENANCE_CLASSES_JSON_PATH,
                f"#/{k}",
                f"Unknown top-level key: '{k}'",
            )

    # Validate top-level mandatory fields
    for field_name in MANDATORY_TOP_LEVEL_FIELDS:
        val = data.get(field_name)
        if val is None:
            result.add_error(
                ERR_PROV_MISSING_FIELD,
                PROVENANCE_CLASSES_JSON_PATH,
                f"#/{field_name}",
                f"Provenance-class registry missing mandatory top-level field '{field_name}'",
            )
        elif field_name != "provenanceClasses" and (not isinstance(val, str) or len(val) == 0):
            result.add_error(
                ERR_PROV_MISSING_FIELD,
                PROVENANCE_CLASSES_JSON_PATH,
                f"#/{field_name}",
                f"Provenance-class registry top-level field '{field_name}' must be a non-empty string",
            )

    generation = data.get("generation")
    if not generation or not isinstance(generation, str):
        result.add_error(
            ERR_PROV_GENERATION_MISMATCH,
            PROVENANCE_CLASSES_JSON_PATH,
            "#/generation",
            "Provenance-class registry missing or empty 'generation'",
        )
    elif generation != BASELINE_GENERATION:
        result.add_error(
            ERR_PROV_GENERATION_MISMATCH,
            PROVENANCE_CLASSES_JSON_PATH,
            "#/generation",
            f"Provenance-class registry generation mismatch: declared '{generation}', expected '{BASELINE_GENERATION}'",
        )

    declared_digest = data.get("registryDigest")
    if isinstance(declared_digest, str):
        result.registry_digest = declared_digest
    else:
        declared_digest = ""
        result.registry_digest = ""

    # Pinned freeze digest check against EXPECTED_FREEZE_DIGESTS
    expected_pinned_digest = EXPECTED_FREEZE_DIGESTS.get(str(generation))
    if expected_pinned_digest is not None:
        if declared_digest != expected_pinned_digest:
            result.add_error(
                ERR_PROV_FREEZE_DIVERGENCE,
                PROVENANCE_CLASSES_JSON_PATH,
                "#/registryDigest",
                f"Provenance-class registry digest diverged from pinned baseline freeze digest: declared '{declared_digest}', pinned '{expected_pinned_digest}'",
            )
    else:
        result.add_error(
            ERR_PROV_FREEZE_DIVERGENCE,
            PROVENANCE_CLASSES_JSON_PATH,
            "#/registryDigest",
            f"Provenance-class registry digest has no pinned freeze digest for generation '{generation}'",
        )

    classes_list = data.get("provenanceClasses")
    if not isinstance(classes_list, list):
        result.add_error(
            ERR_PROV_CORRUPT_FILE,
            PROVENANCE_CLASSES_JSON_PATH,
            "#/provenanceClasses",
            "Missing or non-array 'provenanceClasses' property in registry",
        )
        return result

    result.provenance_class_count = len(classes_list)

    # Check each row for valid structure, unknown keys, mandatory fields, and semantic invariants
    seen_ids: set[str] = set()
    json_classes: dict[str, dict[str, Any]] = {}
    has_row_corruption = False

    for idx, row in enumerate(classes_list):
        if not isinstance(row, dict):
            result.add_error(
                ERR_PROV_CORRUPT_FILE,
                PROVENANCE_CLASSES_JSON_PATH,
                f"#/provenanceClasses/{idx}",
                f"Provenance-class entry at index {idx} is not an object",
            )
            has_row_corruption = True
            continue

        # Iterative depth bounding check
        try:
            canonicalize_value(row, max_depth=32)
        except ValueError as exc:
            result.add_error(
                ERR_PROV_CORRUPT_FILE,
                PROVENANCE_CLASSES_JSON_PATH,
                f"#/provenanceClasses/{idx}",
                f"Excessive nesting or corrupt row structure: {exc}",
            )
            has_row_corruption = True
            continue

        # Refuse unknown row keys
        for rk in sorted(row.keys()):
            if rk not in ALLOWED_ROW_KEYS:
                result.add_error(
                    ERR_PROV_CORRUPT_FILE,
                    PROVENANCE_CLASSES_JSON_PATH,
                    f"#/provenanceClasses/{idx}/{rk}",
                    f"Unknown row field '{rk}' in provenance class entry {idx}",
                )

        pid = row.get("id")
        if not pid or not isinstance(pid, str) or len(pid) == 0:
            result.add_error(
                ERR_PROV_MISSING_FIELD,
                PROVENANCE_CLASSES_JSON_PATH,
                f"#/provenanceClasses/{idx}/id",
                f"Provenance-class entry at index {idx} missing mandatory 'id'",
            )
            continue

        if not PROV_ID_PATTERN.match(pid):
            result.add_error(
                ERR_PROV_STABLE_ID_REUSED,
                PROVENANCE_CLASSES_JSON_PATH,
                f"#/provenanceClasses/{idx}/id",
                f"Provenance-class ID '{pid}' violates stable ID pattern PROV-NNN",
            )

        if pid in seen_ids:
            result.add_error(
                ERR_PROV_STABLE_ID_REUSED,
                PROVENANCE_CLASSES_JSON_PATH,
                f"#/provenanceClasses/{idx}/id",
                f"Duplicate or reused provenance-class stable ID: {pid}",
            )
        seen_ids.add(pid)
        json_classes[pid] = row

        # Check row mandatory fields
        for field_name in MANDATORY_ROW_FIELDS:
            val = row.get(field_name)
            if val is None or not isinstance(val, str) or len(val) == 0:
                result.add_error(
                    ERR_PROV_MISSING_FIELD,
                    PROVENANCE_CLASSES_JSON_PATH,
                    f"#/provenanceClasses/{pid}/{field_name}",
                    f"Provenance-class '{pid}' missing or empty mandatory field '{field_name}'",
                )

        # Semantic Invariants on row
        cls_name = row.get("class")
        if cls_name and isinstance(cls_name, str):
            if cls_name not in ALL_PROVENANCE_CLASSES:
                result.add_error(
                    ERR_PROV_SEMANTIC_INVARIANT,
                    PROVENANCE_CLASSES_JSON_PATH,
                    f"#/provenanceClasses/{pid}/class",
                    f"Provenance class '{cls_name}' ({pid}) is not a registered canonical provenance class",
                )
            if cls_name in NON_AUTHORIZING_CLASSES:
                if row.get("may_authorize_irreversible_effect") in (True, "yes", "true", "yes, subject to capability and policy"):
                    result.add_error(
                        ERR_PROV_SEMANTIC_INVARIANT,
                        PROVENANCE_CLASSES_JSON_PATH,
                        f"#/provenanceClasses/{pid}/may_authorize_irreversible_effect",
                        f"Non-authorizing provenance class '{cls_name}' ({pid}) illegally authorizes irreversible effects",
                    )

    # Check baseline presence and immutability when at BASELINE_GENERATION
    expected_baseline_ids = set(BASELINE_PROVENANCE_CLASSES.keys())
    missing_baseline_ids = expected_baseline_ids - seen_ids
    for mid in sorted(missing_baseline_ids):
        result.add_error(
            ERR_PROV_STABLE_ID_REUSED,
            PROVENANCE_CLASSES_JSON_PATH,
            f"#/provenanceClasses/{mid}",
            f"Mandatory baseline provenance-class ID '{mid}' is missing from registry",
        )

    extra_ids = seen_ids - expected_baseline_ids
    for xid in sorted(extra_ids):
        result.add_error(
            ERR_PROV_STABLE_ID_REUSED,
            PROVENANCE_CLASSES_JSON_PATH,
            f"#/provenanceClasses/{xid}",
            f"Unregistered or renumbered provenance-class ID '{xid}' present without generation bump",
        )

    if generation == BASELINE_GENERATION:
        for pid, expected_row in BASELINE_PROVENANCE_CLASSES.items():
            if pid in json_classes:
                actual_row = json_classes[pid]
                for k, exp_val in expected_row.items():
                    act_val = actual_row.get(k)
                    if act_val != exp_val:
                        result.add_error(
                            ERR_PROV_REGISTRY_DRIFT,
                            PROVENANCE_CLASSES_JSON_PATH,
                            f"#/provenanceClasses/{pid}/{k}",
                            f"Provenance-class '{pid}' field '{k}' diverged from baseline without generation bump: declared '{act_val}', expected '{exp_val}'",
                        )

    # Computed canonical digest check (byte-exact, safe from tracebacks)
    if not has_row_corruption:
        try:
            computed_digest = compute_canonical_provenance_digest(data)
            if declared_digest != computed_digest:
                result.add_error(
                    ERR_PROV_DIGEST_MISMATCH,
                    PROVENANCE_CLASSES_JSON_PATH,
                    "#/registryDigest",
                    f"Registry digest mismatch: declared '{declared_digest}', computed '{computed_digest}'",
                )
        except Exception as exc:
            result.add_error(
                ERR_PROV_CORRUPT_FILE,
                PROVENANCE_CLASSES_JSON_PATH,
                "#/provenanceClasses",
                f"Failed to compute canonical digest: {exc}",
            )

    # Parse and cross-check against Markdown mirror
    if md_path.is_file():
        try:
            md_classes, md_duplicates = extract_markdown_provenance_classes(md_path)
        except Exception as exc:
            result.add_error(
                ERR_PROV_CORRUPT_FILE,
                AGENT_CONTRACTS_MD_PATH,
                "#",
                f"Failed to extract provenance-class rows from markdown: {exc}",
            )
            md_classes, md_duplicates = {}, []

        # Refuse duplicate IDs in markdown mirror
        for dup_id in md_duplicates:
            result.add_error(
                ERR_PROV_STABLE_ID_REUSED,
                AGENT_CONTRACTS_MD_PATH,
                f"#{dup_id}",
                f"Duplicate provenance-class ID '{dup_id}' in markdown mirror",
            )

        # Check count parity between JSON and Markdown
        if len(json_classes) != len(md_classes):
            result.add_error(
                ERR_PROV_REGISTRY_DRIFT,
                PROVENANCE_CLASSES_JSON_PATH,
                "#/provenanceClasses",
                f"Provenance-class count mismatch: JSON has {len(json_classes)}, Markdown has {len(md_classes)}",
            )

        # Check all MD rows are present in JSON and mirror-equal
        for pid, (md_cls, md_meaning) in md_classes.items():
            if pid not in json_classes:
                result.add_error(
                    ERR_PROV_REGISTRY_DRIFT,
                    PROVENANCE_CLASSES_JSON_PATH,
                    f"#/provenanceClasses/{pid}",
                    f"Provenance-class '{pid}' present in Markdown but missing in JSON",
                )
                continue

            j_row = json_classes[pid]
            if j_row.get("class") != md_cls:
                result.add_error(
                    ERR_PROV_REGISTRY_DRIFT,
                    PROVENANCE_CLASSES_JSON_PATH,
                    f"#/provenanceClasses/{pid}/class",
                    f"Provenance-class '{pid}' class mismatch: JSON '{j_row.get('class')}', MD '{md_cls}'",
                )
            if j_row.get("meaning") != md_meaning:
                result.add_error(
                    ERR_PROV_REGISTRY_DRIFT,
                    PROVENANCE_CLASSES_JSON_PATH,
                    f"#/provenanceClasses/{pid}/meaning",
                    f"Provenance-class '{pid}' meaning mismatch: JSON '{j_row.get('meaning')}', MD '{md_meaning}'",
                )

        # Check all JSON rows are in MD
        for pid in json_classes:
            if pid not in md_classes:
                result.add_error(
                    ERR_PROV_REGISTRY_DRIFT,
                    AGENT_CONTRACTS_MD_PATH,
                    f"#{pid}",
                    f"Provenance-class '{pid}' present in JSON but missing in Markdown",
                )

    # Parse and cross-check against umbrella architecture/agent_contracts.json
    if ac_json_path.is_file():
        try:
            ac_data = json.loads(ac_json_path.read_text(encoding="utf-8"))
        except Exception as exc:
            result.add_error(
                ERR_PROV_CORRUPT_FILE,
                AGENT_CONTRACTS_JSON_PATH,
                "#",
                f"Failed to parse agent contracts JSON: {exc}",
            )
            ac_data = None

        if ac_data is not None:
            if not isinstance(ac_data, dict):
                result.add_error(
                    ERR_PROV_CORRUPT_FILE,
                    AGENT_CONTRACTS_JSON_PATH,
                    "#",
                    "Agent contracts umbrella registry root must be a JSON object",
                )
            else:
                ac_classes_list = ac_data.get("provenanceClasses")
                if not isinstance(ac_classes_list, list):
                    result.add_error(
                        ERR_PROV_CORRUPT_FILE,
                        AGENT_CONTRACTS_JSON_PATH,
                        "#/provenanceClasses",
                        "Missing or non-array 'provenanceClasses' in agent contracts umbrella",
                    )
                else:
                    ac_classes: dict[str, dict[str, Any]] = {}
                    ac_seen_ids: set[str] = set()
                    for ac_idx, ac_row in enumerate(ac_classes_list):
                        if not isinstance(ac_row, dict):
                            result.add_error(
                                ERR_PROV_CORRUPT_FILE,
                                AGENT_CONTRACTS_JSON_PATH,
                                f"#/provenanceClasses/{ac_idx}",
                                f"Agent contracts provenance-class entry at index {ac_idx} is not an object",
                            )
                            continue
                        ac_pid = ac_row.get("id")
                        if not ac_pid or not isinstance(ac_pid, str) or len(ac_pid) == 0:
                            result.add_error(
                                ERR_PROV_MISSING_FIELD,
                                AGENT_CONTRACTS_JSON_PATH,
                                f"#/provenanceClasses/{ac_idx}/id",
                                f"Agent contracts provenance entry at index {ac_idx} missing 'id'",
                            )
                            continue
                        if ac_pid in ac_seen_ids:
                            result.add_error(
                                ERR_PROV_STABLE_ID_REUSED,
                                AGENT_CONTRACTS_JSON_PATH,
                                f"#/provenanceClasses/{ac_idx}/id",
                                f"Duplicate provenance-class ID in agent contracts: {ac_pid}",
                            )
                        ac_seen_ids.add(ac_pid)
                        ac_classes[ac_pid] = ac_row

                        for rk in sorted(ac_row.keys()):
                            if rk not in AGENT_CONTRACTS_ALLOWED_ROW_KEYS:
                                result.add_error(
                                    ERR_PROV_CORRUPT_FILE,
                                    AGENT_CONTRACTS_JSON_PATH,
                                    f"#/provenanceClasses/{ac_pid}/{rk}",
                                    f"Unknown row field '{rk}' in agent contracts provenance row '{ac_pid}'",
                                )
                        for req_f in AGENT_CONTRACTS_MANDATORY_ROW_FIELDS:
                            f_val = ac_row.get(req_f)
                            if not isinstance(f_val, str) or len(f_val) == 0:
                                result.add_error(
                                    ERR_PROV_MISSING_FIELD,
                                    AGENT_CONTRACTS_JSON_PATH,
                                    f"#/provenanceClasses/{ac_pid}/{req_f}",
                                    f"Agent contracts provenance '{ac_pid}' missing mandatory field '{req_f}'",
                                )

                    # Cross-check 1:1 between provenance_classes.json and agent_contracts.json
                    if len(json_classes) != len(ac_classes):
                        result.add_error(
                            ERR_PROV_REGISTRY_DRIFT,
                            PROVENANCE_CLASSES_JSON_PATH,
                            "#/provenanceClasses",
                            f"Provenance class count mismatch between provenance_classes.json ({len(json_classes)}) and agent_contracts.json ({len(ac_classes)})",
                        )

                    for pid, j_row in json_classes.items():
                        if pid not in ac_classes:
                            result.add_error(
                                ERR_PROV_REGISTRY_DRIFT,
                                AGENT_CONTRACTS_JSON_PATH,
                                f"#/provenanceClasses/{pid}",
                                f"Provenance class '{pid}' present in provenance_classes.json but missing in agent_contracts.json",
                            )
                            continue
                        ac_row = ac_classes[pid]
                        # In provenance_classes.json it is 'class', in agent_contracts.json it is 'name'
                        j_cls = j_row.get("class")
                        ac_name = ac_row.get("name")
                        if j_cls != ac_name:
                            result.add_error(
                                ERR_PROV_REGISTRY_DRIFT,
                                AGENT_CONTRACTS_JSON_PATH,
                                f"#/provenanceClasses/{pid}/name",
                                f"Provenance class '{pid}' name mismatch: provenance_classes.json class '{j_cls}', agent_contracts.json name '{ac_name}'",
                            )
                        j_meaning = j_row.get("meaning")
                        ac_meaning = ac_row.get("meaning")
                        if j_meaning != ac_meaning:
                            result.add_error(
                                ERR_PROV_REGISTRY_DRIFT,
                                AGENT_CONTRACTS_JSON_PATH,
                                f"#/provenanceClasses/{pid}/meaning",
                                f"Provenance class '{pid}' meaning mismatch between provenance_classes.json and agent_contracts.json",
                            )

                    for ac_pid in ac_classes:
                        if ac_pid not in json_classes:
                            result.add_error(
                                ERR_PROV_REGISTRY_DRIFT,
                                PROVENANCE_CLASSES_JSON_PATH,
                                f"#/provenanceClasses/{ac_pid}",
                                f"Provenance class '{ac_pid}' present in agent_contracts.json but missing in provenance_classes.json",
                            )

                    # Check mayLaunderEvidenceInto table in agent_contracts.json against contract.rs
                    contract_rs_path = repo_root / "crates/fss-core/src/contract.rs"
                    ac_launder_table = ac_data.get("mayLaunderEvidenceInto")
                    if not isinstance(ac_launder_table, dict):
                        result.add_error(
                            ERR_PROV_MISSING_FIELD,
                            AGENT_CONTRACTS_JSON_PATH,
                            "#/mayLaunderEvidenceInto",
                            "Missing or non-object 'mayLaunderEvidenceInto' in agent contracts umbrella",
                        )
                    elif not contract_rs_path.is_file():
                        result.add_error(
                            ERR_PROV_CORRUPT_FILE,
                            "crates/fss-core/src/contract.rs",
                            "#",
                            "Missing crates/fss-core/src/contract.rs for may_launder_evidence_into verification",
                        )
                    else:
                        try:
                            rust_launder_matrix = extract_rust_may_launder_matrix(contract_rs_path)
                            for cls_name, expected_targets in rust_launder_matrix.items():
                                if cls_name not in ac_launder_table:
                                    result.add_error(
                                        ERR_PROV_REGISTRY_DRIFT,
                                        AGENT_CONTRACTS_JSON_PATH,
                                        f"#/mayLaunderEvidenceInto/{cls_name}",
                                        f"Provenance class '{cls_name}' missing from mayLaunderEvidenceInto in agent contracts",
                                    )
                                    continue
                                actual_targets = ac_launder_table[cls_name]
                                if not isinstance(actual_targets, list) or sorted(actual_targets) != sorted(expected_targets):
                                    result.add_error(
                                        ERR_PROV_REGISTRY_DRIFT,
                                        AGENT_CONTRACTS_JSON_PATH,
                                        f"#/mayLaunderEvidenceInto/{cls_name}",
                                        f"mayLaunderEvidenceInto table for '{cls_name}' drifted between JSON ({actual_targets}) and contract.rs ({expected_targets})",
                                    )
                            for extra_cls in ac_launder_table:
                                if extra_cls not in rust_launder_matrix:
                                    result.add_error(
                                        ERR_PROV_REGISTRY_DRIFT,
                                        AGENT_CONTRACTS_JSON_PATH,
                                        f"#/mayLaunderEvidenceInto/{extra_cls}",
                                        f"Extraneous provenance class '{extra_cls}' in mayLaunderEvidenceInto table",
                                    )
                        except Exception as exc:
                            result.add_error(
                                ERR_PROV_CORRUPT_FILE,
                                "crates/fss-core/src/contract.rs",
                                "#/may_launder_evidence_into",
                                f"Failed to parse may_launder_evidence_into from contract.rs: {exc}",
                            )

    return result


def production_source(text: str) -> str:
    """Blank out inline ``#[cfg(test)]`` item blocks, preserving line structure.

    After a ``#[cfg(test)]`` attribute the scanner suppresses lines until a brace-balanced
    block opens and closes; a ``;`` that appears before any ``{`` ends a body-less item.
    Attribute mentions inside ``//`` comments do not trigger suppression, so a comment that
    merely documents the gate cannot hide or expose callers.
    """
    out: list[str] = []
    suppress = False
    depth = 0
    for line in text.splitlines():
        marker = "#[cfg(test)]"
        if suppress:
            depth += line.count("{") - line.count("}")
            if "{" in line or depth > 0:
                if depth <= 0:
                    suppress = False
            elif ";" in line:
                suppress = False
            out.append("")
            continue
        idx = line.find(marker)
        if idx != -1 and not line[:idx].lstrip().startswith("//"):
            before = line[:idx]
            after = line[idx + len(marker):]
            out.append(before)
            depth = after.count("{") - after.count("}")
            if "{" in after:
                suppress = depth > 0
            elif ";" not in after:
                suppress = True
            continue
        out.append(line)
    return "\n".join(out)


LAUNDERING_METHOD = "verify_no_evidence_laundering"


def production_laundering_call_sites(repo_root: Path) -> list[str]:
    """Returns ``file:line`` for non-test call sites of the laundering refusal.

    Unit-test modules live in ``*_tests.rs`` files or inline ``#[cfg(test)]`` blocks;
    integration tests live under ``crates/<crate>/tests/``. Everything else under
    ``crates/*/src`` is production code.
    """
    call_sites: list[str] = []
    crates_src = repo_root / "crates"
    if not crates_src.is_dir():
        return call_sites
    for path in sorted(crates_src.rglob("*.rs")):
        rel = path.relative_to(repo_root).as_posix()
        parts = rel.split("/")
        if len(parts) >= 3 and parts[2] == "tests":
            continue
        if path.name.endswith("_tests.rs"):
            continue
        try:
            text = path.read_text(encoding="utf-8")
        except OSError:
            continue
        for line_no, line in enumerate(production_source(text).splitlines(), start=1):
            needle = f".{LAUNDERING_METHOD}("
            at = line.find(needle)
            if at == -1:
                continue
            # A match positioned behind a line comment is commented-out code, not a call.
            comment = line.find("//")
            if comment != -1 and comment < at:
                continue
            call_sites.append(f"{rel}:{line_no}")
    return call_sites


def validate_laundering_wiring(repo_root: Path = ROOT) -> ValidationResult:
    """Fails when ``KnowledgeCell::verify_no_evidence_laundering`` has no production caller.

    The PROV laundering refusal only protects evidence when a non-test code path actually
    calls it: unit tests alone pass even if every production call is removed (fss-2nwxm).
    A repo where the check is defined but never wired fails closed here.
    """
    result = ValidationResult()
    if not production_laundering_call_sites(repo_root):
        result.add_error(
            ERR_PROV_LAUUNDERING_UNWIRED,
            "crates/",
            f"KnowledgeCell::{LAUNDERING_METHOD}",
            "no non-test caller of KnowledgeCell::verify_no_evidence_laundering remains; "
            "the PROV evidence-laundering refusal is unenforced on production paths (fss-2nwxm)",
        )
    return result


def main() -> int:
    parser = argparse.ArgumentParser(description="Validate provenance-class registry against markdown mirror and invariants")
    parser.add_argument("--repo-root", type=Path, default=ROOT, help="Path to repository root")
    parser.add_argument("--json", action="store_true", help="Emit machine-readable JSON")
    args = parser.parse_args()

    result = validate_provenance_registry(args.repo_root)
    wiring = validate_laundering_wiring(args.repo_root)
    result.passed = result.passed and wiring.passed
    result.errors.extend(wiring.errors)
    if args.json:
        payload = {
            "schema": "fss.provenance_class_validation.v1",
            "passed": result.passed,
            "provenanceClassCount": result.provenance_class_count,
            "registryDigest": result.registry_digest,
            "errorCount": len(result.errors),
            "errors": [asdict(e) for e in result.errors],
        }
        print(json.dumps(payload, indent=2))
    else:
        if result.passed:
            print(f"[PASS] Provenance-class registry verified: {result.provenance_class_count} provenance classes, digest {result.registry_digest}.")
        else:
            print(f"[FAIL] Provenance-class registry failed with {len(result.errors)} errors:", file=sys.stderr)
            for err in result.errors:
                print(f"  [{err.code}] {err.file_path} ({err.target}): {err.message}", file=sys.stderr)

    return 0 if result.passed else 1


if __name__ == "__main__":
    sys.exit(main())
