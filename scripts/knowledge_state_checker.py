#!/usr/bin/env python3
"""Fail-closed knowledge-state registry checker (fss-x4a.30.83.1).

Enforces the knowledge-state registry contract:
1. Knowledge-state registry row drift between architecture JSON and markdown mirror (ERR-KSTATE-REGISTRY-DRIFT-001)
2. Stable ID reused, duplicated, renumbered, or diverging from canonical baseline (ERR-KSTATE-STABLE-ID-REUSED-001)
3. Missing or empty mandatory field in a knowledge-state row or top-level metadata (ERR-KSTATE-MISSING-FIELD-001)
4. Corrupt or missing mandatory registry files (ERR-KSTATE-CORRUPT-FILE-001)
5. Registry digest mismatch between declared and canonical computed digest (ERR-KSTATE-DIGEST-MISMATCH-001)
6. Registry digest diverged from pinned baseline freeze digest (ERR-KSTATE-FREEZE-DIVERGENCE-001)
7. Registry generation diverged from baseline generation (ERR-KSTATE-GENERATION-MISMATCH-001)
8. Non-known knowledge state illegally authorizes irreversible effect (ERR-KSTATE-ILLEGAL-IRREVERSIBLE-AUTH-001)
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
ERR_KSTATE_REGISTRY_DRIFT = "ERR-KSTATE-REGISTRY-DRIFT-001"
ERR_KSTATE_STABLE_ID_REUSED = "ERR-KSTATE-STABLE-ID-REUSED-001"
ERR_KSTATE_MISSING_FIELD = "ERR-KSTATE-MISSING-FIELD-001"
ERR_KSTATE_CORRUPT_FILE = "ERR-KSTATE-CORRUPT-FILE-001"
ERR_KSTATE_DIGEST_MISMATCH = "ERR-KSTATE-DIGEST-MISMATCH-001"
ERR_KSTATE_FREEZE_DIVERGENCE = "ERR-KSTATE-FREEZE-DIVERGENCE-001"
ERR_KSTATE_GENERATION_MISMATCH = "ERR-KSTATE-GENERATION-MISMATCH-001"
ERR_KSTATE_ILLEGAL_IRREVERSIBLE_AUTH = "ERR-KSTATE-ILLEGAL-IRREVERSIBLE-AUTH-001"

KNOWLEDGE_STATES_JSON_PATH = "architecture/knowledge_states.json"
AGENT_CONTRACTS_MD_PATH = "registries/AGENT_CONTRACTS.md"

BASELINE_GENERATION = "gen:fss1:kstate-v1"
BASELINE_FREEZE_DIGEST = "sha256:bfff3fbe7e9639ba630d70f940fbd01d40ee560a32d64ee2e70be67fb26f4cd8"

EXPECTED_FREEZE_DIGESTS: dict[str, str] = {
    BASELINE_GENERATION: BASELINE_FREEZE_DIGEST,
}

# Full baseline knowledge-state rows for generation gen:fss1:kstate-v1
BASELINE_KNOWLEDGE_STATES: dict[str, dict[str, str]] = {
    "KSTATE-001": {
        "id": "KSTATE-001",
        "state": "known",
        "meaning": "The proposition is established for the named anchor and validity scope by admissible evidence or a proved terminal postcondition.",
        "may_support_planning": "yes",
        "may_authorize_irreversible_effect": "yes, subject to capability and policy",
        "explicit_assumptions_required": "no",
    },
    "KSTATE-002": {
        "id": "KSTATE-002",
        "state": "estimated",
        "meaning": "The proposition is supported by a declared derivation or model with explicit uncertainty and operating-envelope limits.",
        "may_support_planning": "yes",
        "may_authorize_irreversible_effect": "no",
        "explicit_assumptions_required": "yes",
    },
    "KSTATE-003": {
        "id": "KSTATE-003",
        "state": "unknown",
        "meaning": "The authorized evidence acquired so far does not establish the proposition.",
        "may_support_planning": "yes, as an explicit branch or open variable",
        "may_authorize_irreversible_effect": "no",
        "explicit_assumptions_required": "yes",
    },
    "KSTATE-004": {
        "id": "KSTATE-004",
        "state": "conflicted",
        "meaning": "Material admissible evidence supports incompatible propositions or generations.",
        "may_support_planning": "yes, only as competing branches",
        "may_authorize_irreversible_effect": "no",
        "explicit_assumptions_required": "yes",
    },
    "KSTATE-005": {
        "id": "KSTATE-005",
        "state": "stale",
        "meaning": "The proposition was valid only at an older anchor or generation and has not been revalidated.",
        "may_support_planning": "yes, only as a revalidation candidate",
        "may_authorize_irreversible_effect": "no",
        "explicit_assumptions_required": "yes",
    },
    "KSTATE-006": {
        "id": "KSTATE-006",
        "state": "not_observable",
        "meaning": "The declared sensor/authorization/model domain could not have established the proposition for the requested interval.",
        "may_support_planning": "yes, as a protected residual possibility",
        "may_authorize_irreversible_effect": "no",
        "explicit_assumptions_required": "yes",
    },
    "KSTATE-007": {
        "id": "KSTATE-007",
        "state": "redacted",
        "meaning": "The proposition or its evidence exists but is intentionally withheld by the current privacy/capability projection.",
        "may_support_planning": "yes, only through non-leaking abstract constraints",
        "may_authorize_irreversible_effect": "no",
        "explicit_assumptions_required": "yes",
    },
    "KSTATE-008": {
        "id": "KSTATE-008",
        "state": "indeterminate",
        "meaning": "A consequential external outcome may have occurred but is not yet proved or safely negated.",
        "may_support_planning": "yes, only in reconciliation branches",
        "may_authorize_irreversible_effect": "no",
        "explicit_assumptions_required": "yes",
    },
    "KSTATE-009": {
        "id": "KSTATE-009",
        "state": "not_applicable",
        "meaning": "The proposition has no meaning for the named object, scope, or lifecycle state.",
        "may_support_planning": "no",
        "may_authorize_irreversible_effect": "no",
        "explicit_assumptions_required": "no",
    },
}

MANDATORY_TOP_LEVEL_FIELDS: tuple[str, ...] = (
    "schema",
    "asOf",
    "generation",
    "semanticProtocol",
    "constitutionalDocument",
    "humanContracts",
    "registryDigest",
    "knowledgeStates",
)

MANDATORY_ROW_FIELDS: tuple[str, ...] = (
    "id",
    "state",
    "meaning",
    "may_support_planning",
    "may_authorize_irreversible_effect",
    "explicit_assumptions_required",
)

KSTATE_ID_PATTERN = re.compile(r"^KSTATE-\d{3}$")


@dataclass(frozen=True)
class DiagnosticError:
    code: str
    file_path: str
    target: str
    message: str


@dataclass
class ValidationResult:
    passed: bool = True
    knowledge_state_count: int = 0
    registry_digest: str = ""
    errors: list[DiagnosticError] = field(default_factory=list)

    def add_error(self, code: str, file_path: str, target: str, message: str) -> None:
        self.passed = False
        self.errors.append(DiagnosticError(code=code, file_path=file_path, target=target, message=message))


def canonicalize_value(val: Any) -> Any:
    if isinstance(val, dict):
        return {k: canonicalize_value(v) for k, v in sorted(val.items())}
    if isinstance(val, list):
        return [canonicalize_value(item) for item in val]
    return val


def compute_canonical_knowledge_state_digest(
    data_or_kstates: dict[str, Any] | list[dict[str, Any]],
    schema: str = "fss.knowledge_states.v1",
    as_of: str = "2026-08-31",
    generation: str = BASELINE_GENERATION,
    semantic_protocol: str = "fss/1",
    constitutional_document: str = "AGENT_COGNITION_AND_CONTROL.md",
    human_contracts: str = "registries/AGENT_CONTRACTS.md",
) -> str:
    """Computes SHA-256 digest of canonically serialized knowledge-state registry data.

    Binds top-level metadata (schema, asOf, generation, semanticProtocol,
    constitutionalDocument, humanContracts) and deterministically sorted
    knowledgeStates rows.
    """
    if isinstance(data_or_kstates, dict):
        data = data_or_kstates
        schema_val = str(data.get("schema", "")).strip()
        as_of_val = str(data.get("asOf", "")).strip()
        generation_val = str(data.get("generation", "")).strip()
        proto_val = str(data.get("semanticProtocol", "")).strip()
        doc_val = str(data.get("constitutionalDocument", "")).strip()
        contracts_val = str(data.get("humanContracts", "")).strip()
        raw_kstates = data.get("knowledgeStates", [])
    else:
        schema_val = schema
        as_of_val = as_of
        generation_val = generation
        proto_val = semantic_protocol
        doc_val = constitutional_document
        contracts_val = human_contracts
        raw_kstates = data_or_kstates

    sorted_kstates = sorted(raw_kstates, key=lambda r: str(r.get("id", "")))
    canonical_payload = {
        "asOf": as_of_val,
        "constitutionalDocument": doc_val,
        "generation": generation_val,
        "humanContracts": contracts_val,
        "knowledgeStates": [canonicalize_value(r) for r in sorted_kstates],
        "schema": schema_val,
        "semanticProtocol": proto_val,
    }
    canonical_bytes = json.dumps(canonical_payload, sort_keys=True, separators=(",", ":")).encode("utf-8")
    return f"sha256:{hashlib.sha256(canonical_bytes).hexdigest()}"


def extract_markdown_knowledge_states(md_path: Path) -> dict[str, tuple[str, str, str, str, str]]:
    """Extracts knowledge states from markdown table: {id: (state, meaning, may_plan, may_effect, explicit_assump)}."""
    rows: dict[str, tuple[str, str, str, str, str]] = {}
    lines = md_path.read_text(encoding="utf-8").splitlines()
    for line in lines:
        stripped = line.strip()
        if stripped.startswith("| `KSTATE-"):
            parts = [p.strip() for p in stripped.strip("|").split("|")]
            if len(parts) >= 6:
                kid = parts[0].replace("`", "").strip()
                state = parts[1].replace("`", "").strip()
                meaning = parts[2].strip()
                may_plan = parts[3].strip()
                may_effect = parts[4].strip()
                explicit_assump = parts[5].strip()
                rows[kid] = (state, meaning, may_plan, may_effect, explicit_assump)
    return rows


def validate_knowledge_state_registry(repo_root: Path = ROOT) -> ValidationResult:
    result = ValidationResult()
    json_path = repo_root / KNOWLEDGE_STATES_JSON_PATH
    md_path = repo_root / AGENT_CONTRACTS_MD_PATH

    # Check existence
    if not json_path.is_file():
        result.add_error(
            ERR_KSTATE_CORRUPT_FILE,
            KNOWLEDGE_STATES_JSON_PATH,
            "#",
            f"Knowledge-state registry JSON file does not exist: {json_path}",
        )
        return result

    if not md_path.is_file():
        result.add_error(
            ERR_KSTATE_CORRUPT_FILE,
            AGENT_CONTRACTS_MD_PATH,
            "#",
            f"Agent contracts markdown file does not exist: {md_path}",
        )
        return result

    # Parse JSON
    try:
        data = json.loads(json_path.read_text(encoding="utf-8"))
    except Exception as exc:
        result.add_error(
            ERR_KSTATE_CORRUPT_FILE,
            KNOWLEDGE_STATES_JSON_PATH,
            "#",
            f"Failed to parse knowledge-state JSON: {exc}",
        )
        return result

    if not isinstance(data, dict):
        result.add_error(
            ERR_KSTATE_CORRUPT_FILE,
            KNOWLEDGE_STATES_JSON_PATH,
            "#",
            "Top-level knowledge-state registry must be a JSON object",
        )
        return result

    # Validate top-level mandatory fields
    for field_name in MANDATORY_TOP_LEVEL_FIELDS:
        val = data.get(field_name)
        if val is None:
            result.add_error(
                ERR_KSTATE_MISSING_FIELD,
                KNOWLEDGE_STATES_JSON_PATH,
                f"#/{field_name}",
                f"Knowledge-state registry missing mandatory top-level field '{field_name}'",
            )
        elif field_name != "knowledgeStates" and (not isinstance(val, str) or not val.strip()):
            result.add_error(
                ERR_KSTATE_MISSING_FIELD,
                KNOWLEDGE_STATES_JSON_PATH,
                f"#/{field_name}",
                f"Knowledge-state registry top-level field '{field_name}' must be a non-empty string",
            )

    generation = str(data.get("generation", "")).strip()
    if not generation:
        result.add_error(
            ERR_KSTATE_GENERATION_MISMATCH,
            KNOWLEDGE_STATES_JSON_PATH,
            "#/generation",
            "Knowledge-state registry missing or empty 'generation'",
        )
    elif generation != BASELINE_GENERATION:
        result.add_error(
            ERR_KSTATE_GENERATION_MISMATCH,
            KNOWLEDGE_STATES_JSON_PATH,
            "#/generation",
            f"Knowledge-state registry generation mismatch: declared '{generation}', expected '{BASELINE_GENERATION}'",
        )

    declared_digest = str(data.get("registryDigest", "")).strip()
    result.registry_digest = declared_digest

    # Pinned freeze digest check against EXPECTED_FREEZE_DIGESTS
    expected_pinned_digest = EXPECTED_FREEZE_DIGESTS.get(generation)
    if expected_pinned_digest is not None:
        if declared_digest != expected_pinned_digest:
            result.add_error(
                ERR_KSTATE_FREEZE_DIVERGENCE,
                KNOWLEDGE_STATES_JSON_PATH,
                "#/registryDigest",
                f"Knowledge-state registry digest diverged from pinned baseline freeze digest: declared '{declared_digest}', pinned '{expected_pinned_digest}'",
            )
    else:
        result.add_error(
            ERR_KSTATE_FREEZE_DIVERGENCE,
            KNOWLEDGE_STATES_JSON_PATH,
            "#/registryDigest",
            f"Knowledge-state registry digest has no pinned freeze digest for generation '{generation}'",
        )

    # Computed canonical digest check
    computed_digest = compute_canonical_knowledge_state_digest(data)
    if declared_digest != computed_digest:
        result.add_error(
            ERR_KSTATE_DIGEST_MISMATCH,
            KNOWLEDGE_STATES_JSON_PATH,
            "#/registryDigest",
            f"Registry digest mismatch: declared '{declared_digest}', computed '{computed_digest}'",
        )

    kstates_list = data.get("knowledgeStates")
    if not isinstance(kstates_list, list):
        result.add_error(
            ERR_KSTATE_CORRUPT_FILE,
            KNOWLEDGE_STATES_JSON_PATH,
            "#/knowledgeStates",
            "Missing or non-array 'knowledgeStates' property in registry",
        )
        return result

    result.knowledge_state_count = len(kstates_list)

    # Check each row for mandatory fields, valid IDs, and irreversible effect permissions
    seen_ids: set[str] = set()
    json_kstates: dict[str, dict[str, Any]] = {}
    for idx, row in enumerate(kstates_list):
        if not isinstance(row, dict):
            result.add_error(
                ERR_KSTATE_CORRUPT_FILE,
                KNOWLEDGE_STATES_JSON_PATH,
                f"#/knowledgeStates/{idx}",
                f"Knowledge-state entry at index {idx} is not an object",
            )
            continue

        kid = row.get("id")
        if not kid or not isinstance(kid, str) or not kid.strip():
            result.add_error(
                ERR_KSTATE_MISSING_FIELD,
                KNOWLEDGE_STATES_JSON_PATH,
                f"#/knowledgeStates/{idx}/id",
                f"Knowledge-state entry at index {idx} missing mandatory 'id'",
            )
            continue

        kid = kid.strip()
        if not KSTATE_ID_PATTERN.match(kid):
            result.add_error(
                ERR_KSTATE_STABLE_ID_REUSED,
                KNOWLEDGE_STATES_JSON_PATH,
                f"#/knowledgeStates/{idx}/id",
                f"Knowledge-state ID '{kid}' violates stable ID pattern KSTATE-NNN",
            )

        if kid in seen_ids:
            result.add_error(
                ERR_KSTATE_STABLE_ID_REUSED,
                KNOWLEDGE_STATES_JSON_PATH,
                f"#/knowledgeStates/{idx}/id",
                f"Duplicate or reused knowledge-state stable ID: {kid}",
            )
        seen_ids.add(kid)
        json_kstates[kid] = row

        # Check row mandatory fields
        for field_name in MANDATORY_ROW_FIELDS:
            val = row.get(field_name)
            if val is None or not isinstance(val, str) or not val.strip():
                result.add_error(
                    ERR_KSTATE_MISSING_FIELD,
                    KNOWLEDGE_STATES_JSON_PATH,
                    f"#/knowledgeStates/{kid}/{field_name}",
                    f"Knowledge-state '{kid}' missing or empty mandatory field '{field_name}'",
                )

        # Hard constitutional gate on irreversible effects
        state_name = row.get("state")
        may_effect = row.get("may_authorize_irreversible_effect")
        if state_name == "known":
            if may_effect != "yes, subject to capability and policy":
                result.add_error(
                    ERR_KSTATE_ILLEGAL_IRREVERSIBLE_AUTH,
                    KNOWLEDGE_STATES_JSON_PATH,
                    f"#/knowledgeStates/{kid}/may_authorize_irreversible_effect",
                    f"Knowledge-state 'known' ({kid}) must specify 'yes, subject to capability and policy' for may_authorize_irreversible_effect, got '{may_effect}'",
                )
        elif state_name is not None:
            if may_effect != "no":
                result.add_error(
                    ERR_KSTATE_ILLEGAL_IRREVERSIBLE_AUTH,
                    KNOWLEDGE_STATES_JSON_PATH,
                    f"#/knowledgeStates/{kid}/may_authorize_irreversible_effect",
                    f"Non-known knowledge-state '{state_name}' ({kid}) illegally authorizes irreversible effect: '{may_effect}' (must be 'no')",
                )

    # Check baseline presence and immutability when at BASELINE_GENERATION
    expected_baseline_ids = set(BASELINE_KNOWLEDGE_STATES.keys())
    missing_baseline_ids = expected_baseline_ids - seen_ids
    for mid in sorted(missing_baseline_ids):
        result.add_error(
            ERR_KSTATE_STABLE_ID_REUSED,
            KNOWLEDGE_STATES_JSON_PATH,
            f"#/knowledgeStates/{mid}",
            f"Mandatory baseline knowledge-state ID '{mid}' is missing from registry",
        )

    extra_ids = seen_ids - expected_baseline_ids
    for xid in sorted(extra_ids):
        result.add_error(
            ERR_KSTATE_STABLE_ID_REUSED,
            KNOWLEDGE_STATES_JSON_PATH,
            f"#/knowledgeStates/{xid}",
            f"Unregistered or renumbered knowledge-state ID '{xid}' present without generation bump",
        )

    if generation == BASELINE_GENERATION:
        for kid, expected_row in BASELINE_KNOWLEDGE_STATES.items():
            if kid in json_kstates:
                actual_row = json_kstates[kid]
                for k, exp_val in expected_row.items():
                    act_val = actual_row.get(k)
                    if act_val != exp_val:
                        result.add_error(
                            ERR_KSTATE_REGISTRY_DRIFT,
                            KNOWLEDGE_STATES_JSON_PATH,
                            f"#/knowledgeStates/{kid}/{k}",
                            f"Knowledge-state '{kid}' field '{k}' diverged from baseline without generation bump: declared '{act_val}', expected '{exp_val}'",
                        )

    # Parse and cross-check against Markdown mirror
    try:
        md_kstates = extract_markdown_knowledge_states(md_path)
    except Exception as exc:
        result.add_error(
            ERR_KSTATE_CORRUPT_FILE,
            AGENT_CONTRACTS_MD_PATH,
            "#",
            f"Failed to extract knowledge-state rows from markdown: {exc}",
        )
        return result

    # Check count parity
    if len(json_kstates) != len(md_kstates):
        result.add_error(
            ERR_KSTATE_REGISTRY_DRIFT,
            KNOWLEDGE_STATES_JSON_PATH,
            "#/knowledgeStates",
            f"Knowledge-state count mismatch: JSON has {len(json_kstates)}, Markdown has {len(md_kstates)}",
        )

    # Check all MD rows are present in JSON and mirror-equal
    for kid, (md_state, md_meaning, md_plan, md_effect, md_assump) in md_kstates.items():
        # Enforce irreversible effect gate on markdown mirror
        if md_state == "known":
            if md_effect != "yes, subject to capability and policy":
                result.add_error(
                    ERR_KSTATE_ILLEGAL_IRREVERSIBLE_AUTH,
                    AGENT_CONTRACTS_MD_PATH,
                    f"#{kid}/may_authorize_irreversible_effect",
                    f"Markdown knowledge-state 'known' ({kid}) must specify 'yes, subject to capability and policy' for may_authorize_irreversible_effect, got '{md_effect}'",
                )
        else:
            if md_effect != "no":
                result.add_error(
                    ERR_KSTATE_ILLEGAL_IRREVERSIBLE_AUTH,
                    AGENT_CONTRACTS_MD_PATH,
                    f"#{kid}/may_authorize_irreversible_effect",
                    f"Markdown non-known knowledge-state '{md_state}' ({kid}) illegally authorizes irreversible effect: '{md_effect}' (must be 'no')",
                )

        if kid not in json_kstates:
            result.add_error(
                ERR_KSTATE_REGISTRY_DRIFT,
                KNOWLEDGE_STATES_JSON_PATH,
                f"#/knowledgeStates/{kid}",
                f"Knowledge-state '{kid}' present in Markdown but missing in JSON",
            )
            continue

        j_row = json_kstates[kid]
        if j_row.get("state") != md_state:
            result.add_error(
                ERR_KSTATE_REGISTRY_DRIFT,
                KNOWLEDGE_STATES_JSON_PATH,
                f"#/knowledgeStates/{kid}/state",
                f"Knowledge-state '{kid}' state mismatch: JSON '{j_row.get('state')}', MD '{md_state}'",
            )
        if j_row.get("meaning") != md_meaning:
            result.add_error(
                ERR_KSTATE_REGISTRY_DRIFT,
                KNOWLEDGE_STATES_JSON_PATH,
                f"#/knowledgeStates/{kid}/meaning",
                f"Knowledge-state '{kid}' meaning mismatch: JSON '{j_row.get('meaning')}', MD '{md_meaning}'",
            )
        if j_row.get("may_support_planning") != md_plan:
            result.add_error(
                ERR_KSTATE_REGISTRY_DRIFT,
                KNOWLEDGE_STATES_JSON_PATH,
                f"#/knowledgeStates/{kid}/may_support_planning",
                f"Knowledge-state '{kid}' may_support_planning mismatch: JSON '{j_row.get('may_support_planning')}', MD '{md_plan}'",
            )
        if j_row.get("may_authorize_irreversible_effect") != md_effect:
            result.add_error(
                ERR_KSTATE_REGISTRY_DRIFT,
                KNOWLEDGE_STATES_JSON_PATH,
                f"#/knowledgeStates/{kid}/may_authorize_irreversible_effect",
                f"Knowledge-state '{kid}' may_authorize_irreversible_effect mismatch: JSON '{j_row.get('may_authorize_irreversible_effect')}', MD '{md_effect}'",
            )
        if j_row.get("explicit_assumptions_required") != md_assump:
            result.add_error(
                ERR_KSTATE_REGISTRY_DRIFT,
                KNOWLEDGE_STATES_JSON_PATH,
                f"#/knowledgeStates/{kid}/explicit_assumptions_required",
                f"Knowledge-state '{kid}' explicit_assumptions_required mismatch: JSON '{j_row.get('explicit_assumptions_required')}', MD '{md_assump}'",
            )

    # Check all JSON rows are in MD
    for kid in json_kstates:
        if kid not in md_kstates:
            result.add_error(
                ERR_KSTATE_REGISTRY_DRIFT,
                AGENT_CONTRACTS_MD_PATH,
                f"#{kid}",
                f"Knowledge-state '{kid}' present in JSON but missing in Markdown",
            )

    return result


def main() -> int:
    parser = argparse.ArgumentParser(description="Validate knowledge-state registry against markdown mirror and invariants")
    parser.add_argument("--repo-root", type=Path, default=ROOT, help="Path to repository root")
    parser.add_argument("--json", action="store_true", help="Emit machine-readable JSON")
    args = parser.parse_args()

    result = validate_knowledge_state_registry(args.repo_root)
    if args.json:
        payload = {
            "schema": "fss.knowledge_state_validation.v1",
            "passed": result.passed,
            "knowledgeStateCount": result.knowledge_state_count,
            "registryDigest": result.registry_digest,
            "errorCount": len(result.errors),
            "errors": [asdict(e) for e in result.errors],
        }
        print(json.dumps(payload, indent=2))
    else:
        if result.passed:
            print(f"[PASS] Knowledge-state registry verified: {result.knowledge_state_count} knowledge states, digest {result.registry_digest}.")
        else:
            print(f"[FAIL] Knowledge-state registry failed with {len(result.errors)} errors:", file=sys.stderr)
            for err in result.errors:
                print(f"  [{err.code}] {err.file_path} ({err.target}): {err.message}", file=sys.stderr)

    return 0 if result.passed else 1


if __name__ == "__main__":
    sys.exit(main())
