#!/usr/bin/env python3
"""Fail-closed knowledge-state registry checker (fss-x4a.30.83.1).

Enforces the knowledge-state registry contract:
1. Knowledge-state registry row drift between architecture JSON and markdown mirror (ERR-KSTATE-REGISTRY-DRIFT-001)
2. Stable ID reused, duplicated, renumbered, or diverging from canonical baseline (ERR-KSTATE-STABLE-ID-REUSED-001)
3. Missing or empty mandatory field in a knowledge-state row (ERR-KSTATE-MISSING-FIELD-001)
4. Corrupt or missing mandatory registry files (ERR-KSTATE-CORRUPT-FILE-001)
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

KNOWLEDGE_STATES_JSON_PATH = "architecture/knowledge_states.json"
AGENT_CONTRACTS_MD_PATH = "registries/AGENT_CONTRACTS.md"

# Canonical stable ID to state name baseline (immutable 9-state universe)
CANONICAL_BASELINE: dict[str, str] = {
    "KSTATE-001": "known",
    "KSTATE-002": "estimated",
    "KSTATE-003": "unknown",
    "KSTATE-004": "conflicted",
    "KSTATE-005": "stale",
    "KSTATE-006": "not_observable",
    "KSTATE-007": "redacted",
    "KSTATE-008": "indeterminate",
    "KSTATE-009": "not_applicable",
}

MANDATORY_FIELDS: tuple[str, ...] = (
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


def compute_canonical_knowledge_state_digest(knowledge_states: list[dict[str, Any]]) -> str:
    """Computes SHA-256 digest of canonically serialized sorted knowledge-state rows."""
    sorted_rows = sorted(knowledge_states, key=lambda r: str(r.get("id", "")))
    canonical_bytes = json.dumps(sorted_rows, sort_keys=True, separators=(",", ":")).encode("utf-8")
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
    declared_digest = data.get("registryDigest", "")
    result.registry_digest = declared_digest

    # Validate canonical digest
    computed_digest = compute_canonical_knowledge_state_digest(kstates_list)
    if declared_digest != computed_digest:
        result.add_error(
            ERR_KSTATE_REGISTRY_DRIFT,
            KNOWLEDGE_STATES_JSON_PATH,
            "#/registryDigest",
            f"Registry digest mismatch: declared {declared_digest}, computed {computed_digest}",
        )

    # Check each row for mandatory fields, valid IDs, and canonical baseline
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
        if not kid or not isinstance(kid, str):
            result.add_error(
                ERR_KSTATE_MISSING_FIELD,
                KNOWLEDGE_STATES_JSON_PATH,
                f"#/knowledgeStates/{idx}/id",
                f"Knowledge-state entry at index {idx} missing mandatory 'id'",
            )
            continue

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

        # Check mandatory fields
        for field_name in MANDATORY_FIELDS:
            val = row.get(field_name)
            if val is None or not isinstance(val, str) or not val.strip():
                result.add_error(
                    ERR_KSTATE_MISSING_FIELD,
                    KNOWLEDGE_STATES_JSON_PATH,
                    f"#/knowledgeStates/{kid}/{field_name}",
                    f"Knowledge-state '{kid}' missing or empty mandatory field '{field_name}'",
                )

        # Check canonical baseline state name (no renumbering)
        state_name = row.get("state")
        expected_state = CANONICAL_BASELINE.get(kid)
        if expected_state is not None and state_name != expected_state:
            result.add_error(
                ERR_KSTATE_STABLE_ID_REUSED,
                KNOWLEDGE_STATES_JSON_PATH,
                f"#/knowledgeStates/{kid}/state",
                f"Knowledge-state ID '{kid}' renumbered or bound to unexpected state '{state_name}' (expected '{expected_state}')",
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
