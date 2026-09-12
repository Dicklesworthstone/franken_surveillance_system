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
EXPECTED_FREEZE_DIGESTS: dict[str, str] = {
    "gen:fss1:public-v1": "sha256:9bbec4e6845ea702f676cd22472e5fb0d35ca3b3d97f66cbfccb452182413da8",
}

BASELINE_OPERATIONS: dict[str, dict[str, Any]] = {
    "AOP-001": {"id": "AOP-001", "kind": "operation", "name": "session.open", "generation": "gen:fss1:public-v1", "owner": "fss-agent-session", "requestEnvelope": "fss.agent_request_envelope.v1", "responseEnvelope": "fss.agent_response_envelope.v1", "requestPayloadSchema": "fss.agent_mission.v1", "responsePayloadSchemas": ["fss.situation_capsule.v1"], "defaultView": "AVIEW-002", "cliCommand": "fss session open", "mcpToolName": "session_open", "compatibilityClass": "backward_compatible", "status": "specified"},
    "AOP-002": {"id": "AOP-002", "kind": "operation", "name": "session.resume", "generation": "gen:fss1:public-v1", "owner": "fss-agent-session", "requestEnvelope": "fss.agent_request_envelope.v1", "responseEnvelope": "fss.agent_response_envelope.v1", "requestPayloadSchema": "fss.agent_handoff_capsule.v1", "responsePayloadSchemas": ["fss.situation_capsule.v1"], "defaultView": "AVIEW-006", "cliCommand": "fss session resume", "mcpToolName": "session_resume", "compatibilityClass": "backward_compatible", "status": "specified"},
    "AOP-003": {"id": "AOP-003", "kind": "operation", "name": "session.orient", "generation": "gen:fss1:public-v1", "owner": "fss-situation", "requestEnvelope": "fss.agent_request_envelope.v1", "responseEnvelope": "fss.agent_response_envelope.v1", "requestPayloadSchema": "fss.agent_query_plan.v1", "responsePayloadSchemas": ["fss.situation_capsule.v1"], "defaultView": "AVIEW-002", "cliCommand": "fss session orient", "mcpToolName": "session_orient", "compatibilityClass": "backward_compatible", "status": "specified"},
    "AOP-004": {"id": "AOP-004", "kind": "operation", "name": "session.follow", "generation": "gen:fss1:public-v1", "owner": "fss-context-pack", "requestEnvelope": "fss.agent_request_envelope.v1", "responseEnvelope": "fss.agent_response_envelope.v1", "requestPayloadSchema": "fss.agent_query_plan.v1", "responsePayloadSchemas": ["fss.agent_meaningful_delta.v1", "fss.situation_capsule.v1"], "defaultView": "AVIEW-001", "cliCommand": "fss session follow", "mcpToolName": "session_follow", "compatibilityClass": "backward_compatible", "status": "specified"},
    "AOP-005": {"id": "AOP-005", "kind": "operation", "name": "query", "generation": "gen:fss1:public-v1", "owner": "fss-query-plan", "requestEnvelope": "fss.agent_request_envelope.v1", "responseEnvelope": "fss.agent_response_envelope.v1", "requestPayloadSchema": "fss.agent_query_plan.v1", "responsePayloadSchemas": ["fss.agent_cognitive_envelope.v1"], "defaultView": "AVIEW-003", "cliCommand": "fss query", "mcpToolName": "query", "compatibilityClass": "backward_compatible", "status": "specified"},
    "AOP-006": {"id": "AOP-006", "kind": "operation", "name": "investigate", "generation": "gen:fss1:public-v1", "owner": "fss-investigation", "requestEnvelope": "fss.agent_request_envelope.v1", "responseEnvelope": "fss.agent_response_envelope.v1", "requestPayloadSchema": "fss.investigation_state.v1", "responsePayloadSchemas": ["fss.investigation_state.v1", "fss.agent_cognitive_envelope.v1"], "defaultView": "AVIEW-003", "cliCommand": "fss investigate", "mcpToolName": "investigate", "compatibilityClass": "backward_compatible", "status": "specified"},
    "AOP-007": {"id": "AOP-007", "kind": "operation", "name": "plan", "generation": "gen:fss1:public-v1", "owner": "fss-agent-plan", "requestEnvelope": "fss.agent_request_envelope.v1", "responseEnvelope": "fss.agent_response_envelope.v1", "requestPayloadSchema": "fss.agent_objective_contract.v1", "responsePayloadSchemas": ["fss.agent_control_plan.v1"], "defaultView": "AVIEW-007", "cliCommand": "fss plan", "mcpToolName": "plan", "compatibilityClass": "backward_compatible", "status": "specified"},
    "AOP-008": {"id": "AOP-008", "kind": "operation", "name": "commit", "generation": "gen:fss1:public-v1", "owner": "fss-effect", "requestEnvelope": "fss.agent_request_envelope.v1", "responseEnvelope": "fss.agent_response_envelope.v1", "requestPayloadSchema": "fss.agent_control_plan.v1", "responsePayloadSchemas": ["fss.operation_receipt.v1", "fss.agent_cognitive_envelope.v1"], "defaultView": "AVIEW-005", "cliCommand": "fss commit", "mcpToolName": "commit", "compatibilityClass": "backward_compatible", "status": "specified"},
    "AOP-009": {"id": "AOP-009", "kind": "operation", "name": "wait", "generation": "gen:fss1:public-v1", "owner": "fss-obligation", "requestEnvelope": "fss.agent_request_envelope.v1", "responseEnvelope": "fss.agent_response_envelope.v1", "requestPayloadSchema": "fss.agent_query_plan.v1", "responsePayloadSchemas": ["fss.agent_cognitive_envelope.v1", "fss.operation_receipt.v1"], "defaultView": "AVIEW-005", "cliCommand": "fss wait", "mcpToolName": "wait", "compatibilityClass": "backward_compatible", "status": "specified"},
    "AOP-010": {"id": "AOP-010", "kind": "operation", "name": "cancel", "generation": "gen:fss1:public-v1", "owner": "fss-obligation", "requestEnvelope": "fss.agent_request_envelope.v1", "responseEnvelope": "fss.agent_response_envelope.v1", "requestPayloadSchema": "fss.agent_query_plan.v1", "responsePayloadSchemas": ["fss.operation_receipt.v1", "fss.agent_cognitive_envelope.v1"], "defaultView": "AVIEW-005", "cliCommand": "fss cancel", "mcpToolName": "cancel", "compatibilityClass": "backward_compatible", "status": "specified"},
    "AOP-011": {"id": "AOP-011", "kind": "operation", "name": "explain", "generation": "gen:fss1:public-v1", "owner": "fss-explain", "requestEnvelope": "fss.agent_request_envelope.v1", "responseEnvelope": "fss.agent_response_envelope.v1", "requestPayloadSchema": "fss.agent_query_plan.v1", "responsePayloadSchemas": ["fss.agent_cognitive_envelope.v1"], "defaultView": "AVIEW-007", "cliCommand": "fss explain", "mcpToolName": "explain", "compatibilityClass": "backward_compatible", "status": "specified"},
    "AOP-012": {"id": "AOP-012", "kind": "operation", "name": "handoff", "generation": "gen:fss1:public-v1", "owner": "fss-handoff", "requestEnvelope": "fss.agent_request_envelope.v1", "responseEnvelope": "fss.agent_response_envelope.v1", "requestPayloadSchema": "fss.agent_session_capsule.v1", "responsePayloadSchemas": ["fss.agent_handoff_capsule.v1"], "defaultView": "AVIEW-006", "cliCommand": "fss handoff", "mcpToolName": "handoff", "compatibilityClass": "backward_compatible", "status": "specified"},
    "AOP-013": {"id": "AOP-013", "kind": "operation", "name": "feedback", "generation": "gen:fss1:public-v1", "owner": "fss-learning", "requestEnvelope": "fss.agent_request_envelope.v1", "responseEnvelope": "fss.agent_response_envelope.v1", "requestPayloadSchema": "fss.agent_feedback_proposal.v1", "responsePayloadSchemas": ["fss.agent_feedback_proposal.v1", "fss.experience_capsule.v1"], "defaultView": "AVIEW-007", "cliCommand": "fss feedback", "mcpToolName": "feedback", "compatibilityClass": "backward_compatible", "status": "specified"},
    "AOP-014": {"id": "AOP-014", "kind": "operation", "name": "doctor", "generation": "gen:fss1:public-v1", "owner": "fss-doctor", "requestEnvelope": "fss.agent_request_envelope.v1", "responseEnvelope": "fss.agent_response_envelope.v1", "requestPayloadSchema": "fss.agent_query_plan.v1", "responsePayloadSchemas": ["fss.agent_cognitive_envelope.v1", "fss.evidence_bundle.v1"], "defaultView": "AVIEW-004", "cliCommand": "fss doctor", "mcpToolName": "doctor", "compatibilityClass": "backward_compatible", "status": "specified"},
}

BASELINE_RESOURCES: dict[str, dict[str, Any]] = {
    "ARES-001": {
        "id": "ARES-001",
        "kind": "resource",
        "name": "deployment.anchor",
        "generation": "gen:fss1:public-v1",
        "owner": "fss-anchor",
        "uriTemplate": "fss://deployment/{deployment}/anchor/{anchor}",
        "requestEnvelope": "fss.agent_request_envelope.v1",
        "responseEnvelope": "fss.agent_response_envelope.v1",
        "payloadSchema": "fss.evidence_anchor.v1",
        "compatibilityClass": "backward_compatible",
        "status": "specified",
    },
    "ARES-002": {
        "id": "ARES-002",
        "kind": "resource",
        "name": "deployment.situation",
        "generation": "gen:fss1:public-v1",
        "owner": "fss-situation",
        "uriTemplate": "fss://deployment/{deployment}/situation/{capsule}",
        "requestEnvelope": "fss.agent_request_envelope.v1",
        "responseEnvelope": "fss.agent_response_envelope.v1",
        "payloadSchema": "fss.situation_capsule.v1",
        "compatibilityClass": "backward_compatible",
        "status": "specified",
    },
    "ARES-003": {
        "id": "ARES-003",
        "kind": "resource",
        "name": "deployment.sensor",
        "generation": "gen:fss1:public-v1",
        "owner": "fss-sensor",
        "uriTemplate": "fss://deployment/{deployment}/sensor/{sensor}",
        "requestEnvelope": "fss.agent_request_envelope.v1",
        "responseEnvelope": "fss.agent_response_envelope.v1",
        "payloadSchema": "fss.sensor_capsule.v1",
        "compatibilityClass": "backward_compatible",
        "status": "specified",
    },
    "ARES-004": {
        "id": "ARES-004",
        "kind": "resource",
        "name": "deployment.zone",
        "generation": "gen:fss1:public-v1",
        "owner": "fss-zone",
        "uriTemplate": "fss://deployment/{deployment}/zone/{zone}",
        "requestEnvelope": "fss.agent_request_envelope.v1",
        "responseEnvelope": "fss.agent_response_envelope.v1",
        "payloadSchema": "fss.agent_situation_frame.v1",
        "compatibilityClass": "backward_compatible",
        "status": "specified",
    },
    "ARES-005": {
        "id": "ARES-005",
        "kind": "resource",
        "name": "deployment.event_revision",
        "generation": "gen:fss1:public-v1",
        "owner": "fss-event",
        "uriTemplate": "fss://deployment/{deployment}/event/{event}/revision/{revision}",
        "requestEnvelope": "fss.agent_request_envelope.v1",
        "responseEnvelope": "fss.agent_response_envelope.v1",
        "payloadSchema": "fss.event_hypothesis.v1",
        "compatibilityClass": "backward_compatible",
        "status": "specified",
    },
    "ARES-006": {
        "id": "ARES-006",
        "kind": "resource",
        "name": "deployment.case_revision",
        "generation": "gen:fss1:public-v1",
        "owner": "fss-investigation",
        "uriTemplate": "fss://deployment/{deployment}/case/{case}/revision/{revision}",
        "requestEnvelope": "fss.agent_request_envelope.v1",
        "responseEnvelope": "fss.agent_response_envelope.v1",
        "payloadSchema": "fss.investigation_state.v1",
        "compatibilityClass": "backward_compatible",
        "status": "specified",
    },
    "ARES-007": {
        "id": "ARES-007",
        "kind": "resource",
        "name": "deployment.hypothesis",
        "generation": "gen:fss1:public-v1",
        "owner": "fss-investigation",
        "uriTemplate": "fss://deployment/{deployment}/hypothesis/{hypothesis}",
        "requestEnvelope": "fss.agent_request_envelope.v1",
        "responseEnvelope": "fss.agent_response_envelope.v1",
        "payloadSchema": "fss.agent_hypothesis_workspace.v1",
        "compatibilityClass": "backward_compatible",
        "status": "specified",
    },
    "ARES-008": {
        "id": "ARES-008",
        "kind": "resource",
        "name": "deployment.evidence",
        "generation": "gen:fss1:public-v1",
        "owner": "fss-evidence",
        "uriTemplate": "fss://deployment/{deployment}/evidence/{digest}",
        "requestEnvelope": "fss.agent_request_envelope.v1",
        "responseEnvelope": "fss.agent_response_envelope.v1",
        "payloadSchema": "fss.evidence_bundle.v1",
        "compatibilityClass": "backward_compatible",
        "status": "specified",
    },
    "ARES-009": {
        "id": "ARES-009",
        "kind": "resource",
        "name": "deployment.plan",
        "generation": "gen:fss1:public-v1",
        "owner": "fss-agent-plan",
        "uriTemplate": "fss://deployment/{deployment}/plan/{plan}",
        "requestEnvelope": "fss.agent_request_envelope.v1",
        "responseEnvelope": "fss.agent_response_envelope.v1",
        "payloadSchema": "fss.agent_control_plan.v1",
        "compatibilityClass": "backward_compatible",
        "status": "specified",
    },
    "ARES-010": {
        "id": "ARES-010",
        "kind": "resource",
        "name": "deployment.obligation",
        "generation": "gen:fss1:public-v1",
        "owner": "fss-obligation",
        "uriTemplate": "fss://deployment/{deployment}/obligation/{obligation}",
        "requestEnvelope": "fss.agent_request_envelope.v1",
        "responseEnvelope": "fss.agent_response_envelope.v1",
        "payloadSchema": "fss.prepared_effect.v1",
        "compatibilityClass": "backward_compatible",
        "status": "specified",
    },
    "ARES-011": {
        "id": "ARES-011",
        "kind": "resource",
        "name": "mission.revision",
        "generation": "gen:fss1:public-v1",
        "owner": "fss-mission",
        "uriTemplate": "fss://mission/{mission}/revision/{revision}",
        "requestEnvelope": "fss.agent_request_envelope.v1",
        "responseEnvelope": "fss.agent_response_envelope.v1",
        "payloadSchema": "fss.agent_mission.v1",
        "compatibilityClass": "backward_compatible",
        "status": "specified",
    },
    "ARES-012": {
        "id": "ARES-012",
        "kind": "resource",
        "name": "session.workspace",
        "generation": "gen:fss1:public-v1",
        "owner": "fss-agent-session",
        "uriTemplate": "fss://session/{session}/workspace/{workspace}",
        "requestEnvelope": "fss.agent_request_envelope.v1",
        "responseEnvelope": "fss.agent_response_envelope.v1",
        "payloadSchema": "fss.agent_session_capsule.v1",
        "compatibilityClass": "backward_compatible",
        "status": "specified",
    },
    "ARES-013": {
        "id": "ARES-013",
        "kind": "resource",
        "name": "session.handoff",
        "generation": "gen:fss1:public-v1",
        "owner": "fss-handoff",
        "uriTemplate": "fss://session/{session}/handoff/{root}",
        "requestEnvelope": "fss.agent_request_envelope.v1",
        "responseEnvelope": "fss.agent_response_envelope.v1",
        "payloadSchema": "fss.agent_handoff_capsule.v1",
        "compatibilityClass": "backward_compatible",
        "status": "specified",
    },
    "ARES-014": {
        "id": "ARES-014",
        "kind": "resource",
        "name": "experience",
        "generation": "gen:fss1:public-v1",
        "owner": "fss-learning",
        "uriTemplate": "fss://experience/{capsule}",
        "requestEnvelope": "fss.agent_request_envelope.v1",
        "responseEnvelope": "fss.agent_response_envelope.v1",
        "payloadSchema": "fss.experience_capsule.v1",
        "compatibilityClass": "backward_compatible",
        "status": "specified",
    },
    "ARES-015": {
        "id": "ARES-015",
        "kind": "resource",
        "name": "doctor",
        "generation": "gen:fss1:public-v1",
        "owner": "fss-doctor",
        "uriTemplate": "fss://doctor/{bundle}",
        "requestEnvelope": "fss.agent_request_envelope.v1",
        "responseEnvelope": "fss.agent_response_envelope.v1",
        "payloadSchema": "fss.doctor.v1",
        "compatibilityClass": "backward_compatible",
        "status": "specified",
    },
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


def canonicalize_value(val: Any) -> Any:
    """Deterministically orders dictionaries and primitive lists for canonical hashing."""
    if isinstance(val, dict):
        return {k: canonicalize_value(v) for k, v in sorted(val.items())}
    if isinstance(val, list):
        canon_items = [canonicalize_value(item) for item in val]
        if all(isinstance(x, (str, int, float, bool)) for x in canon_items):
            return sorted(canon_items)
        return canon_items
    return val


def compute_canonical_freeze_digest(
    data_or_ops: dict[str, Any] | list[dict[str, Any]],
    resources: list[dict[str, Any]] | None = None,
    tombstones: list[dict[str, Any]] | None = None,
    schema: str = "fss.public_registry.v1",
    protocol: str = "fss/1",
    generation: str = BASELINE_GENERATION,
) -> str:
    """Computes SHA-256 digest of canonically serialized registry data.

    Binds top-level metadata (schema, semanticProtocol, registryGeneration)
    and deterministically sorted and canonicalized rows (operations, resources, tombstones).
    Fails closed on duplicate or empty IDs.
    """
    if isinstance(data_or_ops, dict):
        data = data_or_ops
        schema_val = str(data.get("schema", "")).strip()
        proto_val = str(data.get("semanticProtocol", "")).strip()
        gen_val = str(data.get("registryGeneration", "")).strip()
        raw_ops = data.get("operations", [])
        raw_res = data.get("resources", [])
        raw_tombs = data.get("tombstones", [])
    else:
        schema_val = schema
        proto_val = protocol
        gen_val = generation
        raw_ops = data_or_ops
        raw_res = resources or []
        raw_tombs = tombstones or []

    if not schema_val:
        raise ValueError("Missing schema")
    if not proto_val:
        raise ValueError("Missing semanticProtocol")
    if not gen_val:
        raise ValueError("Missing registryGeneration")

    seen_ids: set[str] = set()
    for cat, rows in [("operations", raw_ops), ("resources", raw_res), ("tombstones", raw_tombs)]:
        for idx, row in enumerate(rows):
            if not isinstance(row, dict):
                raise ValueError(f"Non-dict entry in {cat}[{idx}]")
            row_id = str(row.get("id", "")).strip()
            if not row_id:
                raise ValueError(f"Empty id in {cat}[{idx}]")
            if row_id in seen_ids:
                raise ValueError(f"Duplicate id '{row_id}' in {cat}[{idx}]")
            seen_ids.add(row_id)

    sorted_ops = sorted(raw_ops, key=lambda r: str(r["id"]))
    sorted_res = sorted(raw_res, key=lambda r: str(r["id"]))
    sorted_tombs = sorted(raw_tombs, key=lambda r: str(r["id"]))

    canonical_payload = {
        "schema": schema_val,
        "semanticProtocol": proto_val,
        "registryGeneration": gen_val,
        "operations": [canonicalize_value(r) for r in sorted_ops],
        "resources": [canonicalize_value(r) for r in sorted_res],
        "tombstones": [canonicalize_value(r) for r in sorted_tombs],
    }

    canonical_bytes = json.dumps(canonical_payload, sort_keys=True, separators=(",", ":")).encode("utf-8")
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

    result.freeze_digest = declared_digest
    result.operation_count = len(operations)
    result.resource_count = len(resources)
    result.tombstone_count = len(tombstones)

    # 2. Check for stable ID reuse and tombstone resurrection
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

    # 3. Check canonical freeze digest
    try:
        expected_digest = compute_canonical_freeze_digest(frozen_data)
        if declared_digest != expected_digest:
            result.add_error(
                ERR_FROZEN_DIGEST_MISMATCH,
                FROZEN_REGISTRY_PATH,
                "#/freezeDigest",
                f"Freeze digest mismatch: declared '{declared_digest}' != computed '{expected_digest}'",
            )

        # Pin expected canonical freeze digest per generation
        expected_pinned_digest = EXPECTED_FREEZE_DIGESTS.get(generation)
        if expected_pinned_digest is not None:
            if declared_digest != expected_pinned_digest:
                result.add_error(
                    ERR_FROZEN_DIGEST_MISMATCH,
                    FROZEN_REGISTRY_PATH,
                    "#/freezeDigest",
                    f"Freeze digest mismatch for generation '{generation}': declared '{declared_digest}' != pinned '{expected_pinned_digest}'",
                )
    except ValueError as exc:
        result.add_error(
            ERR_FROZEN_DIGEST_MISMATCH,
            FROZEN_REGISTRY_PATH,
            "#/freezeDigest",
            f"Failed to compute canonical freeze digest: {exc}",
        )

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
            for opid, expected_op in BASELINE_OPERATIONS.items():
                actual_op = op_map[opid]
                for key, expected_val in expected_op.items():
                    actual_val = actual_op.get(key)
                    if actual_val != expected_val:
                        result.add_error(
                            ERR_FROZEN_REGISTRY_DRIFT,
                            FROZEN_REGISTRY_PATH,
                            f"#/operations/{opid}/{key}",
                            f"Operation '{opid}' field '{key}' changed from '{expected_val}' to '{actual_val}' without generation bump",
                        )
                for key in actual_op:
                    if key not in expected_op:
                        result.add_error(
                            ERR_FROZEN_REGISTRY_DRIFT,
                            FROZEN_REGISTRY_PATH,
                            f"#/operations/{opid}/{key}",
                            f"Operation '{opid}' has unexpected field '{key}' without generation bump",
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
            for resid, expected_res in BASELINE_RESOURCES.items():
                actual_res = res_map[resid]
                for key, expected_val in expected_res.items():
                    actual_val = actual_res.get(key)
                    if actual_val != expected_val:
                        result.add_error(
                            ERR_FROZEN_REGISTRY_DRIFT,
                            FROZEN_REGISTRY_PATH,
                            f"#/resources/{resid}/{key}",
                            f"Resource '{resid}' field '{key}' changed from '{expected_val}' to '{actual_val}' without generation bump",
                        )
                for key in actual_res:
                    if key not in expected_res:
                        result.add_error(
                            ERR_FROZEN_REGISTRY_DRIFT,
                            FROZEN_REGISTRY_PATH,
                            f"#/resources/{resid}/{key}",
                            f"Resource '{resid}' has unexpected field '{key}' without generation bump",
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

    # 8. Cross-check against crates/fss-cli/src/*.rs (unregistered op / resource and non-AOP scheme)
    cli_src_dir = repo_root / "crates/fss-cli/src"
    if cli_src_dir.is_dir():
        for rs_file in sorted(cli_src_dir.glob("*.rs")):
            try:
                rs_text = rs_file.read_text(encoding="utf-8")
                rel_path = str(rs_file.relative_to(repo_root) if repo_root in rs_file.parents else rs_file)
                # Match any string literal assigned to operation_id
                rs_op_ids = re.findall(r'operation_id:\s*"([^"]+)"', rs_text)
                for rs_op_id in rs_op_ids:
                    if rs_op_id not in op_map:
                        result.add_error(
                            ERR_FROZEN_UNREGISTERED_OP,
                            rel_path,
                            f"#{rs_op_id}",
                            f"CLI source '{rel_path}' references unregistered operation '{rs_op_id}'",
                        )
                # Match any string literal assigned to resource_id
                rs_res_ids = re.findall(r'resource_id:\s*"([^"]+)"', rs_text)
                for rs_res_id in rs_res_ids:
                    if rs_res_id not in res_map:
                        result.add_error(
                            ERR_FROZEN_UNREGISTERED_OP,
                            rel_path,
                            f"#{rs_res_id}",
                            f"CLI source '{rel_path}' references unregistered resource '{rs_res_id}'",
                        )
            except OSError as exc:
                result.add_error(
                    ERR_FROZEN_CORRUPT_FILE,
                    str(rs_file.relative_to(repo_root) if repo_root in rs_file.parents else rs_file),
                    "#",
                    f"Failed to read {rs_file.name}: {exc}",
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
