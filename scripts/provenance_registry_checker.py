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
NON_AUTHORIZING_CLASSES = {"predicted", "remembered", "vendor_claimed"}

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

MANDATORY_ROW_FIELDS: tuple[str, ...] = (
    "id",
    "class",
    "meaning",
)

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


def canonicalize_value(val: Any) -> Any:
    if isinstance(val, dict):
        return {k: canonicalize_value(v) for k, v in sorted(val.items())}
    if isinstance(val, list):
        return [canonicalize_value(item) for item in val]
    return val


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
    provenanceClasses rows.
    """
    if isinstance(data_or_classes, dict):
        data = data_or_classes
        schema_val = str(data.get("schema", "")).strip()
        as_of_val = str(data.get("asOf", "")).strip()
        generation_val = str(data.get("generation", "")).strip()
        proto_val = str(data.get("semanticProtocol", "")).strip()
        doc_val = str(data.get("constitutionalDocument", "")).strip()
        contracts_val = str(data.get("humanContracts", "")).strip()
        raw_classes = data.get("provenanceClasses", [])
    else:
        schema_val = schema
        as_of_val = as_of
        generation_val = generation
        proto_val = semantic_protocol
        doc_val = constitutional_document
        contracts_val = human_contracts
        raw_classes = data_or_classes

    sorted_classes = sorted(raw_classes, key=lambda r: str(r.get("id", "")))
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


def extract_markdown_provenance_classes(md_path: Path) -> dict[str, tuple[str, str]]:
    """Extracts provenance classes from markdown table: {id: (class_name, meaning)}."""
    rows: dict[str, tuple[str, str]] = {}
    lines = md_path.read_text(encoding="utf-8").splitlines()
    for line in lines:
        stripped = line.strip()
        if stripped.startswith("| `PROV-"):
            parts = [p.strip() for p in stripped.strip("|").split("|")]
            if len(parts) >= 3:
                pid = parts[0].replace("`", "").strip()
                cls = parts[1].replace("`", "").strip()
                meaning = parts[2].strip()
                rows[pid] = (cls, meaning)
    return rows


def validate_provenance_registry(repo_root: Path = ROOT) -> ValidationResult:
    result = ValidationResult()
    json_path = repo_root / PROVENANCE_CLASSES_JSON_PATH
    md_path = repo_root / AGENT_CONTRACTS_MD_PATH

    # Check existence
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
        return result

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
        elif field_name != "provenanceClasses" and (not isinstance(val, str) or not val.strip()):
            result.add_error(
                ERR_PROV_MISSING_FIELD,
                PROVENANCE_CLASSES_JSON_PATH,
                f"#/{field_name}",
                f"Provenance-class registry top-level field '{field_name}' must be a non-empty string",
            )

    generation = str(data.get("generation", "")).strip()
    if not generation:
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

    declared_digest = str(data.get("registryDigest", "")).strip()
    result.registry_digest = declared_digest

    # Pinned freeze digest check against EXPECTED_FREEZE_DIGESTS
    expected_pinned_digest = EXPECTED_FREEZE_DIGESTS.get(generation)
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

    # Computed canonical digest check
    computed_digest = compute_canonical_provenance_digest(data)
    if declared_digest != computed_digest:
        result.add_error(
            ERR_PROV_DIGEST_MISMATCH,
            PROVENANCE_CLASSES_JSON_PATH,
            "#/registryDigest",
            f"Registry digest mismatch: declared '{declared_digest}', computed '{computed_digest}'",
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

    # Check each row for mandatory fields and valid IDs
    seen_ids: set[str] = set()
    json_classes: dict[str, dict[str, Any]] = {}
    for idx, row in enumerate(classes_list):
        if not isinstance(row, dict):
            result.add_error(
                ERR_PROV_CORRUPT_FILE,
                PROVENANCE_CLASSES_JSON_PATH,
                f"#/provenanceClasses/{idx}",
                f"Provenance-class entry at index {idx} is not an object",
            )
            continue

        pid = row.get("id")
        if not pid or not isinstance(pid, str) or not pid.strip():
            result.add_error(
                ERR_PROV_MISSING_FIELD,
                PROVENANCE_CLASSES_JSON_PATH,
                f"#/provenanceClasses/{idx}/id",
                f"Provenance-class entry at index {idx} missing mandatory 'id'",
            )
            continue

        pid = pid.strip()
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
            if val is None or not isinstance(val, str) or not val.strip():
                result.add_error(
                    ERR_PROV_MISSING_FIELD,
                    PROVENANCE_CLASSES_JSON_PATH,
                    f"#/provenanceClasses/{pid}/{field_name}",
                    f"Provenance-class '{pid}' missing or empty mandatory field '{field_name}'",
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

    # Parse and cross-check against Markdown mirror
    try:
        md_classes = extract_markdown_provenance_classes(md_path)
    except Exception as exc:
        result.add_error(
            ERR_PROV_CORRUPT_FILE,
            AGENT_CONTRACTS_MD_PATH,
            "#",
            f"Failed to extract provenance-class rows from markdown: {exc}",
        )
        return result

    # Check count parity
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

    return result


def main() -> int:
    parser = argparse.ArgumentParser(description="Validate provenance-class registry against markdown mirror and invariants")
    parser.add_argument("--repo-root", type=Path, default=ROOT, help="Path to repository root")
    parser.add_argument("--json", action="store_true", help="Emit machine-readable JSON")
    args = parser.parse_args()

    result = validate_provenance_registry(args.repo_root)
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
