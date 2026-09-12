#!/usr/bin/env python3
"""Machine-checked frozen fss/1 public operation and resource registry checker (fss-x4a.24.1 / FSS-201).

Enforces the frozen public contract for fss/1 operations and resources:
1. Public operation or resource added, removed, renamed, or renumbered without a new registry generation (ERR-FROZEN-REGISTRY-DRIFT-001)
2. Stable ID reused across or within operations and resources (ERR-FROZEN-STABLE-ID-REUSED-001)
3. Tombstoned entry resurrected into active registry (ERR-FROZEN-TOMBSTONE-RESURRECTED-001)
4. Canonical freeze digest mismatch over sorted rows (ERR-FROZEN-DIGEST-MISMATCH-001)
5. Crosswalk or presentation surfaces reference unregistered operation (ERR-FROZEN-UNREGISTERED-OP-001)
6. Corrupt or missing mandatory files (ERR-FROZEN-CORRUPT-FILE-001)
"""
from __future__ import annotations

import argparse
import hashlib
import json
import re
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]

# Registered stable diagnostic finding IDs (registries/ERRORS.md)
ERR_FROZEN_REGISTRY_DRIFT = "ERR-FROZEN-REGISTRY-DRIFT-001"
ERR_FROZEN_STABLE_ID_REUSED = "ERR-FROZEN-STABLE-ID-REUSED-001"
ERR_FROZEN_TOMBSTONE_RESURRECTED = "ERR-FROZEN-TOMBSTONE-RESURRECTED-001"
ERR_FROZEN_DIGEST_MISMATCH = "ERR-FROZEN-DIGEST-MISMATCH-001"
ERR_FROZEN_UNREGISTERED_OP = "ERR-FROZEN-UNREGISTERED-OP-001"
ERR_FROZEN_CORRUPT_FILE = "ERR-FROZEN-CORRUPT-FILE-001"

FROZEN_REGISTRY_PATH = "architecture/fss1_public_registry.json"
AGENT_OPERATIONS_PATH = "architecture/agent_operations.json"
AGENT_CONTRACTS_PATH = "architecture/agent_contracts.json"
OPERATION_CROSSWALK_PATH = "architecture/operation_crosswalk.json"
CLI_CROSSWALK_RS_PATH = "crates/fss-cli/src/crosswalk.rs"
ERRORS_MD_PATH = "registries/ERRORS.md"

# Canonical baseline for generation gen:fss1:public-v1
BASELINE_GENERATION = "gen:fss1:public-v1"
BASELINE_OPERATIONS = {
    "AOP-001": ("session.open", "fss-agent-session"),
    "AOP-002": ("session.resume", "fss-agent-session"),
    "AOP-003": ("session.orient", "fss-situation"),
    "AOP-004": ("session.follow", "fss-context-pack"),
    "AOP-005": ("query", "fss-query-plan"),
    "AOP-006": ("investigate", "fss-investigation"),
    "AOP-007": ("plan", "fss-agent-plan"),
    "AOP-008": ("commit", "fss-effect"),
    "AOP-009": ("wait", "fss-obligation"),
    "AOP-010": ("cancel", "fss-obligation"),
    "AOP-011": ("explain", "fss-explain"),
    "AOP-012": ("handoff", "fss-handoff"),
    "AOP-013": ("feedback", "fss-learning"),
    "AOP-014": ("doctor", "fss-doctor"),
}

BASELINE_RESOURCES = {
    "ARES-001": ("deployment.anchor", "fss://deployment/{deployment}/anchor/{anchor}", "fss-anchor"),
    "ARES-002": ("deployment.situation", "fss://deployment/{deployment}/situation/{capsule}", "fss-situation"),
    "ARES-003": ("deployment.sensor", "fss://deployment/{deployment}/sensor/{sensor}", "fss-sensor"),
    "ARES-004": ("deployment.zone", "fss://deployment/{deployment}/zone/{zone}", "fss-zone"),
    "ARES-005": ("deployment.event_revision", "fss://deployment/{deployment}/event/{event}/revision/{revision}", "fss-event"),
    "ARES-006": ("deployment.case_revision", "fss://deployment/{deployment}/case/{case}/revision/{revision}", "fss-investigation"),
    "ARES-007": ("deployment.hypothesis", "fss://deployment/{deployment}/hypothesis/{hypothesis}", "fss-investigation"),
    "ARES-008": ("deployment.evidence", "fss://deployment/{deployment}/evidence/{digest}", "fss-evidence"),
    "ARES-009": ("deployment.plan", "fss://deployment/{deployment}/plan/{plan}", "fss-agent-plan"),
    "ARES-010": ("deployment.obligation", "fss://deployment/{deployment}/obligation/{obligation}", "fss-obligation"),
    "ARES-011": ("mission.revision", "fss://mission/{mission}/revision/{revision}", "fss-mission"),
    "ARES-012": ("session.workspace", "fss://session/{session}/workspace/{workspace}", "fss-agent-session"),
    "ARES-013": ("session.handoff", "fss://session/{session}/handoff/{root}", "fss-handoff"),
    "ARES-014": ("experience", "fss://experience/{capsule}", "fss-learning"),
    "ARES-015": ("doctor", "fss://doctor/{bundle}", "fss-doctor"),
}


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
    resource_count: int = 0
    tombstone_count: int = 0
    freeze_digest: str = ""
    errors: list[DiagnosticError] = field(default_factory=list)

    def add_error(self, code: str, file_path: str, target: str, message: str) -> None:
        self.passed = False
        self.errors.append(DiagnosticError(code=code, file_path=file_path, target=target, message=message))


def compute_canonical_freeze_digest(
    operations: list[dict[str, Any]],
    resources: list[dict[str, Any]],
    tombstones: list[dict[str, Any]] | None = None,
) -> str:
    """Computes SHA-256 digest of canonically serialized sorted rows."""
    all_rows: list[dict[str, Any]] = []
    for op in operations:
        all_rows.append(op)
    for res in resources:
        all_rows.append(res)
    if tombstones:
        for tomb in tombstones:
            all_rows.append(tomb)

    # Sort deterministically by stable identifier
    sorted_rows = sorted(all_rows, key=lambda r: str(r.get("id", "")))
    canonical_bytes = json.dumps(sorted_rows, sort_keys=True, separators=(",", ":")).encode("utf-8")
    return f"sha256:{hashlib.sha256(canonical_bytes).hexdigest()}"


def validate_frozen_registry(repo_root: Path = ROOT) -> ValidationResult:
    """Performs full fail-closed validation of the frozen fss/1 registry."""
    result = ValidationResult()

    frozen_reg_path = repo_root / FROZEN_REGISTRY_PATH
    agent_ops_path = repo_root / AGENT_OPERATIONS_PATH
    agent_contracts_path = repo_root / AGENT_CONTRACTS_PATH
    crosswalk_path = repo_root / OPERATION_CROSSWALK_PATH
    cli_crosswalk_path = repo_root / CLI_CROSSWALK_RS_PATH
    errors_md_path = repo_root / ERRORS_MD_PATH

    for p in (frozen_reg_path, agent_ops_path, agent_contracts_path, crosswalk_path):
        if not p.is_file():
            result.add_error(
                ERR_FROZEN_CORRUPT_FILE,
                str(p.relative_to(repo_root) if repo_root in p.parents else p),
                "#",
                f"Mandatory file missing: {p.name}",
            )
            return result

    # 1. Parse frozen registry JSON
    try:
        frozen_data = json.loads(frozen_reg_path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        result.add_error(
            ERR_FROZEN_CORRUPT_FILE,
            FROZEN_REGISTRY_PATH,
            "#",
            f"Failed to parse frozen registry JSON: {exc}",
        )
        return result

    if not isinstance(frozen_data, dict):
        result.add_error(
            ERR_FROZEN_CORRUPT_FILE,
            FROZEN_REGISTRY_PATH,
            "#",
            "Root of frozen registry must be a JSON object",
        )
        return result

    schema = frozen_data.get("schema")
    if schema != "fss.public_registry.v1":
        result.add_error(
            ERR_FROZEN_CORRUPT_FILE,
            FROZEN_REGISTRY_PATH,
            "#/schema",
            f"Invalid schema: expected 'fss.public_registry.v1', got '{schema}'",
        )

    protocol = frozen_data.get("semanticProtocol")
    if protocol != "fss/1":
        result.add_error(
            ERR_FROZEN_CORRUPT_FILE,
            FROZEN_REGISTRY_PATH,
            "#/semanticProtocol",
            f"Invalid semanticProtocol: expected 'fss/1', got '{protocol}'",
        )

    generation = frozen_data.get("registryGeneration")
    if not isinstance(generation, str) or not generation.strip():
        result.add_error(
            ERR_FROZEN_CORRUPT_FILE,
            FROZEN_REGISTRY_PATH,
            "#/registryGeneration",
            "Missing or invalid registryGeneration",
        )
        return result

    declared_digest = frozen_data.get("freezeDigest")
    if not isinstance(declared_digest, str) or not declared_digest.startswith("sha256:"):
        result.add_error(
            ERR_FROZEN_CORRUPT_FILE,
            FROZEN_REGISTRY_PATH,
            "#/freezeDigest",
            "Missing or malformed freezeDigest",
        )
        return result

    operations = frozen_data.get("operations")
    if not isinstance(operations, list) or len(operations) == 0:
        result.add_error(
            ERR_FROZEN_CORRUPT_FILE,
            FROZEN_REGISTRY_PATH,
            "#/operations",
            "Operations collection is missing, not a list, or empty",
        )
        return result

    resources = frozen_data.get("resources")
    if not isinstance(resources, list) or len(resources) == 0:
        result.add_error(
            ERR_FROZEN_CORRUPT_FILE,
            FROZEN_REGISTRY_PATH,
            "#/resources",
            "Resources collection is missing, not a list, or empty",
        )
        return result

    tombstones = frozen_data.get("tombstones", [])
    if not isinstance(tombstones, list):
        result.add_error(
            ERR_FROZEN_CORRUPT_FILE,
            FROZEN_REGISTRY_PATH,
            "#/tombstones",
            "Tombstones collection must be a list if present",
        )
        return result

    # 2. Check canonical freeze digest
    expected_digest = compute_canonical_freeze_digest(operations, resources, tombstones)
    if declared_digest != expected_digest:
        result.add_error(
            ERR_FROZEN_DIGEST_MISMATCH,
            FROZEN_REGISTRY_PATH,
            "#/freezeDigest",
            f"Freeze digest mismatch: declared '{declared_digest}' != computed '{expected_digest}'",
        )

    result.freeze_digest = declared_digest
    result.operation_count = len(operations)
    result.resource_count = len(resources)
    result.tombstone_count = len(tombstones)

    # 3. Check for stable ID reuse and tombstone resurrection
    seen_ids: dict[str, str] = {}  # id -> kind/location
    tombstoned_ids: set[str] = set()

    for idx, tomb in enumerate(tombstones):
        if not isinstance(tomb, dict):
            continue
        tid = str(tomb.get("id", "")).strip()
        if tid:
            if tid in seen_ids:
                result.add_error(
                    ERR_FROZEN_STABLE_ID_REUSED,
                    FROZEN_REGISTRY_PATH,
                    f"#/tombstones[{idx}]/id",
                    f"Duplicate tombstone identifier: '{tid}'",
                )
            seen_ids[tid] = f"tombstone[{idx}]"
            tombstoned_ids.add(tid)

    op_map: dict[str, dict[str, Any]] = {}
    for idx, op in enumerate(operations):
        if not isinstance(op, dict):
            result.add_error(
                ERR_FROZEN_CORRUPT_FILE,
                FROZEN_REGISTRY_PATH,
                f"#/operations[{idx}]",
                "Operation row must be a JSON object",
            )
            continue
        op_id = str(op.get("id", "")).strip()
        if not op_id:
            result.add_error(
                ERR_FROZEN_CORRUPT_FILE,
                FROZEN_REGISTRY_PATH,
                f"#/operations[{idx}]/id",
                "Operation missing stable identifier",
            )
            continue
        if op_id in seen_ids:
            result.add_error(
                ERR_FROZEN_STABLE_ID_REUSED,
                FROZEN_REGISTRY_PATH,
                f"#/operations[{idx}]/id",
                f"Stable ID '{op_id}' reused (already seen in {seen_ids[op_id]})",
            )
        else:
            seen_ids[op_id] = f"operations[{idx}]"

        if op_id in tombstoned_ids:
            result.add_error(
                ERR_FROZEN_TOMBSTONE_RESURRECTED,
                FROZEN_REGISTRY_PATH,
                f"#/operations[{idx}]/id",
                f"Tombstoned operation '{op_id}' resurrected in active operations",
            )

        status = str(op.get("status", "")).strip().lower()
        if status in ("tombstone", "tombstoned", "superseded"):
            result.add_error(
                ERR_FROZEN_TOMBSTONE_RESURRECTED,
                FROZEN_REGISTRY_PATH,
                f"#/operations[{idx}]/status",
                f"Operation '{op_id}' has tombstone status in active operations list",
            )

        op_map[op_id] = op

    res_map: dict[str, dict[str, Any]] = {}
    for idx, res in enumerate(resources):
        if not isinstance(res, dict):
            result.add_error(
                ERR_FROZEN_CORRUPT_FILE,
                FROZEN_REGISTRY_PATH,
                f"#/resources[{idx}]",
                "Resource row must be a JSON object",
            )
            continue
        res_id = str(res.get("id", "")).strip()
        if not res_id:
            result.add_error(
                ERR_FROZEN_CORRUPT_FILE,
                FROZEN_REGISTRY_PATH,
                f"#/resources[{idx}]/id",
                "Resource missing stable identifier",
            )
            continue
        if res_id in seen_ids:
            result.add_error(
                ERR_FROZEN_STABLE_ID_REUSED,
                FROZEN_REGISTRY_PATH,
                f"#/resources[{idx}]/id",
                f"Stable ID '{res_id}' reused (already seen in {seen_ids[res_id]})",
            )
        else:
            seen_ids[res_id] = f"resources[{idx}]"

        if res_id in tombstoned_ids:
            result.add_error(
                ERR_FROZEN_TOMBSTONE_RESURRECTED,
                FROZEN_REGISTRY_PATH,
                f"#/resources[{idx}]/id",
                f"Tombstoned resource '{res_id}' resurrected in active resources",
            )

        status = str(res.get("status", "")).strip().lower()
        if status in ("tombstone", "tombstoned", "superseded"):
            result.add_error(
                ERR_FROZEN_TOMBSTONE_RESURRECTED,
                FROZEN_REGISTRY_PATH,
                f"#/resources[{idx}]/status",
                f"Resource '{res_id}' has tombstone status in active resources list",
            )

        res_map[res_id] = res

    # 4. Check drift without generation bump
    if generation == BASELINE_GENERATION:
        # Verify operations match baseline exactly
        actual_op_ids = sorted(op_map.keys())
        expected_op_ids = sorted(BASELINE_OPERATIONS.keys())
        if actual_op_ids != expected_op_ids:
            result.add_error(
                ERR_FROZEN_REGISTRY_DRIFT,
                FROZEN_REGISTRY_PATH,
                "#/operations",
                f"Operations altered without generation bump: {actual_op_ids} != {expected_op_ids}",
            )
        else:
            for opid, (expected_name, expected_owner) in BASELINE_OPERATIONS.items():
                op = op_map[opid]
                actual_name = op.get("name")
                actual_owner = op.get("owner")
                if actual_name != expected_name:
                    result.add_error(
                        ERR_FROZEN_REGISTRY_DRIFT,
                        FROZEN_REGISTRY_PATH,
                        f"#/operations/{opid}/name",
                        f"Operation '{opid}' renamed from '{expected_name}' to '{actual_name}' without generation bump",
                    )
                if actual_owner != expected_owner:
                    result.add_error(
                        ERR_FROZEN_REGISTRY_DRIFT,
                        FROZEN_REGISTRY_PATH,
                        f"#/operations/{opid}/owner",
                        f"Operation '{opid}' owner changed without generation bump",
                    )

        # Verify resources match baseline exactly
        actual_res_ids = sorted(res_map.keys())
        expected_res_ids = sorted(BASELINE_RESOURCES.keys())
        if actual_res_ids != expected_res_ids:
            result.add_error(
                ERR_FROZEN_REGISTRY_DRIFT,
                FROZEN_REGISTRY_PATH,
                "#/resources",
                f"Resources altered without generation bump: {actual_res_ids} != {expected_res_ids}",
            )
        else:
            for resid, (expected_name, expected_uri, expected_owner) in BASELINE_RESOURCES.items():
                res = res_map[resid]
                actual_name = res.get("name")
                actual_uri = res.get("uriTemplate")
                actual_owner = res.get("owner")
                if actual_name != expected_name:
                    result.add_error(
                        ERR_FROZEN_REGISTRY_DRIFT,
                        FROZEN_REGISTRY_PATH,
                        f"#/resources/{resid}/name",
                        f"Resource '{resid}' renamed from '{expected_name}' to '{actual_name}' without generation bump",
                    )
                if actual_uri != expected_uri:
                    result.add_error(
                        ERR_FROZEN_REGISTRY_DRIFT,
                        FROZEN_REGISTRY_PATH,
                        f"#/resources/{resid}/uriTemplate",
                        f"Resource '{resid}' URI template changed without generation bump",
                    )
                if actual_owner != expected_owner:
                    result.add_error(
                        ERR_FROZEN_REGISTRY_DRIFT,
                        FROZEN_REGISTRY_PATH,
                        f"#/resources/{resid}/owner",
                        f"Resource '{resid}' owner changed without generation bump",
                    )

    # 5. Cross-check against architecture/agent_operations.json
    try:
        agent_ops_data = json.loads(agent_ops_path.read_text(encoding="utf-8"))
        live_ops = {
            op["id"]: op
            for op in agent_ops_data.get("operations", [])
            if isinstance(op, dict) and "id" in op
        }
        for opid, op in live_ops.items():
            if opid not in op_map:
                result.add_error(
                    ERR_FROZEN_REGISTRY_DRIFT,
                    AGENT_OPERATIONS_PATH,
                    f"#/operations/{opid}",
                    f"Operation '{opid}' in agent_operations.json missing from frozen registry",
                )
            else:
                frozen_op = op_map[opid]
                if op.get("name") != frozen_op.get("name"):
                    result.add_error(
                        ERR_FROZEN_REGISTRY_DRIFT,
                        AGENT_OPERATIONS_PATH,
                        f"#/operations/{opid}/name",
                        f"Operation '{opid}' name mismatch: '{op.get('name')}' != '{frozen_op.get('name')}'",
                    )
                if op.get("owner") != frozen_op.get("owner"):
                    result.add_error(
                        ERR_FROZEN_REGISTRY_DRIFT,
                        AGENT_OPERATIONS_PATH,
                        f"#/operations/{opid}/owner",
                        f"Operation '{opid}' owner mismatch: '{op.get('owner')}' != '{frozen_op.get('owner')}'",
                    )
        for opid in op_map:
            if opid not in live_ops:
                result.add_error(
                    ERR_FROZEN_REGISTRY_DRIFT,
                    FROZEN_REGISTRY_PATH,
                    f"#/operations/{opid}",
                    f"Operation '{opid}' in frozen registry missing from agent_operations.json",
                )
    except (OSError, json.JSONDecodeError) as exc:
        result.add_error(
            ERR_FROZEN_CORRUPT_FILE,
            AGENT_OPERATIONS_PATH,
            "#",
            f"Failed to read agent_operations.json: {exc}",
        )

    # 6. Cross-check against architecture/agent_contracts.json (resourceTemplates)
    try:
        agent_contracts_data = json.loads(agent_contracts_path.read_text(encoding="utf-8"))
        live_templates = set(agent_contracts_data.get("resourceTemplates", []))
        frozen_templates = {res.get("uriTemplate") for res in res_map.values() if res.get("uriTemplate")}
        if live_templates != frozen_templates:
            diff = (live_templates - frozen_templates) | (frozen_templates - live_templates)
            result.add_error(
                ERR_FROZEN_REGISTRY_DRIFT,
                AGENT_CONTRACTS_PATH,
                "#/resourceTemplates",
                f"Resource template divergence between contracts and frozen registry: {diff}",
            )
    except (OSError, json.JSONDecodeError) as exc:
        result.add_error(
            ERR_FROZEN_CORRUPT_FILE,
            AGENT_CONTRACTS_PATH,
            "#",
            f"Failed to read agent_contracts.json: {exc}",
        )

    # 7. Cross-check against operation_crosswalk.json (unregistered op)
    try:
        cw_data = json.loads(crosswalk_path.read_text(encoding="utf-8"))
        for idx, entry in enumerate(cw_data.get("crosswalk", [])):
            if isinstance(entry, dict):
                cw_op_id = str(entry.get("operation_id", "")).strip()
                if cw_op_id and cw_op_id not in op_map:
                    result.add_error(
                        ERR_FROZEN_UNREGISTERED_OP,
                        OPERATION_CROSSWALK_PATH,
                        f"#/crosswalk[{idx}]/operation_id",
                        f"Operation crosswalk references unregistered operation '{cw_op_id}'",
                    )
    except (OSError, json.JSONDecodeError) as exc:
        result.add_error(
            ERR_FROZEN_CORRUPT_FILE,
            OPERATION_CROSSWALK_PATH,
            "#",
            f"Failed to read operation_crosswalk.json: {exc}",
        )

    # 8. Cross-check against crates/fss-cli/src/crosswalk.rs (unregistered op)
    if cli_crosswalk_path.is_file():
        try:
            rs_text = cli_crosswalk_path.read_text(encoding="utf-8")
            rs_op_ids = re.findall(r'operation_id:\s*"(AOP-[0-9]{3})"', rs_text)
            for rs_op_id in rs_op_ids:
                if rs_op_id not in op_map:
                    result.add_error(
                        ERR_FROZEN_UNREGISTERED_OP,
                        CLI_CROSSWALK_RS_PATH,
                        f"#{rs_op_id}",
                        f"Rust crosswalk references unregistered operation '{rs_op_id}'",
                    )
        except OSError as exc:
            result.add_error(
                ERR_FROZEN_CORRUPT_FILE,
                CLI_CROSSWALK_RS_PATH,
                "#",
                f"Failed to read crosswalk.rs: {exc}",
            )

    return result


def main() -> int:
    parser = argparse.ArgumentParser(description="Frozen fss/1 public operation and resource registry checker.")
    parser.add_argument("--json", action="store_true", help="Output machine-readable JSON result.")
    parser.add_argument("--repo-root", type=Path, default=ROOT, help="Repository root directory.")
    args = parser.parse_args()

    result = validate_frozen_registry(args.repo_root)

    if args.json:
        payload = {
            "status": "passed" if result.passed else "failed",
            "operationCount": result.operation_count,
            "resourceCount": result.resource_count,
            "tombstoneCount": result.tombstone_count,
            "freezeDigest": result.freeze_digest,
            "errorCount": len(result.errors),
            "errors": [asdict(e) for e in result.errors],
        }
        print(json.dumps(payload, indent=2))
    else:
        if result.passed:
            print(
                f"[PASS] Frozen fss/1 registry verified: {result.operation_count} operations, "
                f"{result.resource_count} resources, freeze digest {result.freeze_digest}."
            )
        else:
            print(f"[FAIL] Frozen registry verification failed with {len(result.errors)} errors:")
            for err in result.errors:
                print(f"  - [{err.code}] {err.file_path} ({err.target}): {err.message}")

    return 0 if result.passed else 1


if __name__ == "__main__":
    import sys
    sys.exit(main())
