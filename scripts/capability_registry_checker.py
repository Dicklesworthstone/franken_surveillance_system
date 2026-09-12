#!/usr/bin/env python3
"""Fail-closed capability registry checker (fss-x4a.30.86.1).

Enforces the capability registry contract:
1. Capability registry row drift between architecture JSON, baseline, and markdown (ERR-CAPABILITY-REGISTRY-DRIFT-001)
2. Unknown or unregistered semantic plane (ERR-CAPABILITY-UNKNOWN-PLANE-001)
3. Missing default role or required security fields (ERR-CAPABILITY-MISSING-DEFAULT-001)
4. Stable ID reused, renumbered, or resurrected (ERR-CAPABILITY-STABLE-ID-REUSED-001)
5. Canonical freeze digest mismatch against pinned constant (ERR-CAPABILITY-DIGEST-MISMATCH-001)
6. Corrupt or missing mandatory files or top-level metadata (ERR-CAPABILITY-CORRUPT-FILE-001)
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
ERR_CAPABILITY_REGISTRY_DRIFT = "ERR-CAPABILITY-REGISTRY-DRIFT-001"
ERR_CAPABILITY_UNKNOWN_PLANE = "ERR-CAPABILITY-UNKNOWN-PLANE-001"
ERR_CAPABILITY_MISSING_DEFAULT = "ERR-CAPABILITY-MISSING-DEFAULT-001"
ERR_CAPABILITY_STABLE_ID_REUSED = "ERR-CAPABILITY-STABLE-ID-REUSED-001"
ERR_CAPABILITY_DIGEST_MISMATCH = "ERR-CAPABILITY-DIGEST-MISMATCH-001"
ERR_CAPABILITY_CORRUPT_FILE = "ERR-CAPABILITY-CORRUPT-FILE-001"

CAPABILITIES_JSON_PATH = "architecture/capabilities.json"
CAPABILITIES_MD_PATH = "registries/CAPABILITIES.md"

# Expected canonical freeze digests pinned per registry generation
EXPECTED_FREEZE_DIGESTS: dict[str, str] = {
    "gen:fss1:capabilities-v1": "sha256:5056fe20103a6c9a157fdb0e29bf5371384b976e874bf2964ff817fb202f045a",
}
CURRENT_GENERATION = "gen:fss1:capabilities-v1"

# Recognized semantic plane designations in FSS architecture
RECOGNIZED_PLANES = {
    "authority read",
    "authority write",
    "boundary",
    "cognition",
    "cognition read",
    "cognition write",
    "cognition/prepare",
    "effect",
    "effect orchestration",
    "lifecycle effect",
    "agent continuity write",
    "agent continuity read",
    "advisory write",
    "coordination write",
    "authority/cognition read",
    "agent control",
    "agent cognition",
    "coordination",
}

REQUIRED_ROW_FIELDS = (
    "id",
    "capability",
    "scope",
    "plane",
    "defaultRole",
    "denialReason",
    "safeAlternative",
    "generation",
)

BASELINE_CAPABILITIES: dict[str, dict[str, str]] = {
    "CAP-ADAPTER-AUTH-001": {
        "capability": "resolve one adapter secret handle",
        "defaultRole": "adapter host only",
        "denialReason": "ERR-AUTH-DENIED-001: principal lacks CAP-ADAPTER-AUTH-001 authority on device/account",
        "generation": "gen:fss1:capabilities-v1",
        "id": "CAP-ADAPTER-AUTH-001",
        "plane": "boundary",
        "safeAlternative": "delegate secret resolution to sealed adapter host process",
        "scope": "device/account",
    },
    "CAP-ADAPTER-NET-001": {
        "capability": "contact registered device/vendor endpoints",
        "defaultRole": "adapter host only",
        "denialReason": "ERR-AUTH-DENIED-001: principal lacks CAP-ADAPTER-NET-001 authority on destination allowlist",
        "generation": "gen:fss1:capabilities-v1",
        "id": "CAP-ADAPTER-NET-001",
        "plane": "boundary",
        "safeAlternative": "route network requests through authorized adapter host or offline fixtures",
        "scope": "destination allowlist",
    },
    "CAP-AGENT-CANCEL-001": {
        "capability": "request cancellation/drain/reconciliation of owned work",
        "defaultRole": "owner or delegated supervisor",
        "denialReason": "ERR-AUTH-DENIED-001: principal lacks CAP-AGENT-CANCEL-001 authority on session/task/plan/obligation",
        "generation": "gen:fss1:capabilities-v1",
        "id": "CAP-AGENT-CANCEL-001",
        "plane": "lifecycle effect",
        "safeAlternative": "request task owner or supervisor to initiate drain/cancel transition",
        "scope": "session/task/plan/obligation",
    },
    "CAP-AGENT-CASE-WRITE-001": {
        "capability": "create/revise investigations, hypotheses, probes, and findings",
        "defaultRole": "explicit mission role",
        "denialReason": "ERR-AUTH-DENIED-001: principal lacks CAP-AGENT-CASE-WRITE-001 authority on mission/case scope",
        "generation": "gen:fss1:capabilities-v1",
        "id": "CAP-AGENT-CASE-WRITE-001",
        "plane": "agent cognition",
        "safeAlternative": "request mission investigation role or record local hypotheses",
        "scope": "mission/case scope",
    },
    "CAP-AGENT-EVIDENCE-HYDRATE-001": {
        "capability": "hydrate a stable evidence handle to an allowed level",
        "defaultRole": "separately scoped by privacy class",
        "denialReason": "ERR-AUTH-DENIED-001: principal lacks CAP-AGENT-EVIDENCE-HYDRATE-001 authority on object + hydration level",
        "generation": "gen:fss1:capabilities-v1",
        "id": "CAP-AGENT-EVIDENCE-HYDRATE-001",
        "plane": "authority/cognition read",
        "safeAlternative": "request higher privacy-class grant or inspect lower-tier hydration descriptor",
        "scope": "object + hydration level",
    },
    "CAP-AGENT-EXPLAIN-001": {
        "capability": "read minimal evidence/decision subgraphs and counterfactuals",
        "defaultRole": "agent read role",
        "denialReason": "ERR-AUTH-DENIED-001: principal lacks CAP-AGENT-EXPLAIN-001 authority on authorized decision/evidence domain",
        "generation": "gen:fss1:capabilities-v1",
        "id": "CAP-AGENT-EXPLAIN-001",
        "plane": "cognition read",
        "safeAlternative": "request explanation access role or query top-level outcome summary",
        "scope": "authorized decision/evidence domain",
    },
    "CAP-AGENT-FEEDBACK-001": {
        "capability": "append correction, adjudication, outcome, or learning proposal",
        "defaultRole": "scoped agent/operator role",
        "denialReason": "ERR-AUTH-DENIED-001: principal lacks CAP-AGENT-FEEDBACK-001 authority on episode/event/case",
        "generation": "gen:fss1:capabilities-v1",
        "id": "CAP-AGENT-FEEDBACK-001",
        "plane": "advisory write",
        "safeAlternative": "request feedback role or submit offline evaluation report",
        "scope": "episode/event/case",
    },
    "CAP-AGENT-FINDING-WRITE-001": {
        "capability": "publish immutable evidence-linked finding",
        "defaultRole": "explicit mission role",
        "denialReason": "ERR-AUTH-DENIED-001: principal lacks CAP-AGENT-FINDING-WRITE-001 authority on mission/case + evidence scope",
        "generation": "gen:fss1:capabilities-v1",
        "id": "CAP-AGENT-FINDING-WRITE-001",
        "plane": "coordination",
        "safeAlternative": "request mission finding publication role or attach findings to local session capsule",
        "scope": "mission/case + evidence scope",
    },
    "CAP-AGENT-HANDOFF-READ-001": {
        "capability": "accept and rebase an authorized handoff capsule",
        "defaultRole": "named recipient/delegate",
        "denialReason": "ERR-AUTH-DENIED-001: principal lacks CAP-AGENT-HANDOFF-READ-001 authority on exact handoff root + recipient",
        "generation": "gen:fss1:capabilities-v1",
        "id": "CAP-AGENT-HANDOFF-READ-001",
        "plane": "agent continuity read",
        "safeAlternative": "request inclusion as authorized recipient or start fresh session from origin anchor",
        "scope": "exact handoff root + recipient",
    },
    "CAP-AGENT-HANDOFF-WRITE-001": {
        "capability": "publish a redacted root-last handoff capsule",
        "defaultRole": "explicit delegation",
        "denialReason": "ERR-AUTH-DENIED-001: principal lacks CAP-AGENT-HANDOFF-WRITE-001 authority on mission/workspace + recipient scope",
        "generation": "gen:fss1:capabilities-v1",
        "id": "CAP-AGENT-HANDOFF-WRITE-001",
        "plane": "agent continuity write",
        "safeAlternative": "request handoff delegation authorization or retain session locally",
        "scope": "mission/workspace + recipient scope",
    },
    "CAP-AGENT-INVESTIGATE-001": {
        "capability": "create/advance immutable investigation and hypothesis revisions",
        "defaultRole": "explicit investigation role",
        "denialReason": "ERR-AUTH-DENIED-001: principal lacks CAP-AGENT-INVESTIGATE-001 authority on case + evidence domain",
        "generation": "gen:fss1:capabilities-v1",
        "id": "CAP-AGENT-INVESTIGATE-001",
        "plane": "cognition write",
        "safeAlternative": "request investigation role or inspect closed investigation cases",
        "scope": "case + evidence domain",
    },
    "CAP-AGENT-PLAN-COMMIT-001": {
        "capability": "submit an exact prepared plan to domain effect authorities",
        "defaultRole": "denied unless explicit; never substitutes for domain effect capabilities",
        "denialReason": "ERR-AUTH-DENIED-001: principal lacks CAP-AGENT-PLAN-COMMIT-001 authority on plan digest + fences",
        "generation": "gen:fss1:capabilities-v1",
        "id": "CAP-AGENT-PLAN-COMMIT-001",
        "plane": "effect orchestration",
        "safeAlternative": "submit prepared plan to human supervisor for manual approval and domain dispatch",
        "scope": "plan digest + fences",
    },
    "CAP-AGENT-PLAN-PREPARE-001": {
        "capability": "compile and seal a witnessed contingent plan",
        "defaultRole": "explicit planner role",
        "denialReason": "ERR-AUTH-DENIED-001: principal lacks CAP-AGENT-PLAN-PREPARE-001 authority on mission + objective + target domain",
        "generation": "gen:fss1:capabilities-v1",
        "id": "CAP-AGENT-PLAN-PREPARE-001",
        "plane": "cognition/prepare",
        "safeAlternative": "request planner role or inspect established affordance frontier",
        "scope": "mission + objective + target domain",
    },
    "CAP-AGENT-QUERY-001": {
        "capability": "compile and execute bounded semantic queries",
        "defaultRole": "agent read role",
        "denialReason": "ERR-AUTH-DENIED-001: principal lacks CAP-AGENT-QUERY-001 authority on authorized resources + anchor",
        "generation": "gen:fss1:capabilities-v1",
        "id": "CAP-AGENT-QUERY-001",
        "plane": "cognition read",
        "safeAlternative": "request agent query role or query standard pre-aggregated views",
        "scope": "authorized resources + anchor",
    },
    "CAP-AGENT-SESSION-OPEN-001": {
        "capability": "open a mission-scoped agent session",
        "defaultRole": "denied unless negotiated",
        "denialReason": "ERR-AUTH-DENIED-001: principal lacks CAP-AGENT-SESSION-OPEN-001 authority on deployment + mission + principal",
        "generation": "gen:fss1:capabilities-v1",
        "id": "CAP-AGENT-SESSION-OPEN-001",
        "plane": "agent control",
        "safeAlternative": "authenticate principal credentials and negotiate session contract basis",
        "scope": "deployment + mission + principal",
    },
    "CAP-AGENT-SESSION-READ-001": {
        "capability": "read/resume exact workspace or handoff revisions",
        "defaultRole": "session principal",
        "denialReason": "ERR-AUTH-DENIED-001: principal lacks CAP-AGENT-SESSION-READ-001 authority on mission/session/workspace root",
        "generation": "gen:fss1:capabilities-v1",
        "id": "CAP-AGENT-SESSION-READ-001",
        "plane": "agent control",
        "safeAlternative": "authenticate as session principal or request delegated continuation",
        "scope": "mission/session/workspace root",
    },
    "CAP-AGENT-SESSION-WRITE-001": {
        "capability": "create/supersede mission, session, and workspace revisions",
        "defaultRole": "explicit agent-session role",
        "denialReason": "ERR-AUTH-DENIED-001: principal lacks CAP-AGENT-SESSION-WRITE-001 authority on mission + session",
        "generation": "gen:fss1:capabilities-v1",
        "id": "CAP-AGENT-SESSION-WRITE-001",
        "plane": "agent continuity write",
        "safeAlternative": "request agent session authorization or operate in read-only session mode",
        "scope": "mission + session",
    },
    "CAP-AGENT-SITUATION-READ-001": {
        "capability": "read capability-projected SituationFrames, deltas, and obligations",
        "defaultRole": "agent read role",
        "denialReason": "ERR-AUTH-DENIED-001: principal lacks CAP-AGENT-SITUATION-READ-001 authority on deployment/mission/zone/time",
        "generation": "gen:fss1:capabilities-v1",
        "id": "CAP-AGENT-SITUATION-READ-001",
        "plane": "cognition read",
        "safeAlternative": "request agent read role or query minimal public SituationCapsule",
        "scope": "deployment/mission/zone/time",
    },
    "CAP-AGENT-WORK-CLAIM-001": {
        "capability": "reserve a bounded multi-agent work scope under a lease",
        "defaultRole": "agent collaborator role",
        "denialReason": "ERR-AUTH-DENIED-001: principal lacks CAP-AGENT-WORK-CLAIM-001 authority on mission/case/subgraph",
        "generation": "gen:fss1:capabilities-v1",
        "id": "CAP-AGENT-WORK-CLAIM-001",
        "plane": "coordination write",
        "safeAlternative": "request multi-agent collaborator role or wait for lease expiration",
        "scope": "mission/case/subgraph",
    },
    "CAP-ALERT-COMMIT-001": {
        "capability": "commit exact prepared alert",
        "defaultRole": "explicit grant",
        "denialReason": "ERR-AUTH-DENIED-001: principal lacks CAP-ALERT-COMMIT-001 authority on plan digest",
        "generation": "gen:fss1:capabilities-v1",
        "id": "CAP-ALERT-COMMIT-001",
        "plane": "effect",
        "safeAlternative": "request explicit operator grant or queue alert intent for review",
        "scope": "plan digest",
    },
    "CAP-ALERT-PREPARE-001": {
        "capability": "prepare alert intent",
        "defaultRole": "policy/operator",
        "denialReason": "ERR-AUTH-DENIED-001: principal lacks CAP-ALERT-PREPARE-001 authority on event + channel",
        "generation": "gen:fss1:capabilities-v1",
        "id": "CAP-ALERT-PREPARE-001",
        "plane": "effect",
        "safeAlternative": "request alert preparation role or record advisory finding",
        "scope": "event + channel",
    },
    "CAP-CALIBRATE-001": {
        "capability": "run calibration computation",
        "defaultRole": "operator",
        "denialReason": "ERR-AUTH-DENIED-001: principal lacks CAP-CALIBRATE-001 authority on session root + sensors",
        "generation": "gen:fss1:capabilities-v1",
        "id": "CAP-CALIBRATE-001",
        "plane": "cognition",
        "safeAlternative": "request operator calibration role or use existing active calibration generation",
        "scope": "session root + sensors",
    },
    "CAP-DELETE-COMMIT-001": {
        "capability": "execute sealed deletion plan",
        "defaultRole": "strong approval",
        "denialReason": "ERR-AUTH-DENIED-001: principal lacks CAP-DELETE-COMMIT-001 authority on plan digest",
        "generation": "gen:fss1:capabilities-v1",
        "id": "CAP-DELETE-COMMIT-001",
        "plane": "effect",
        "safeAlternative": "obtain dual-custody data governance approval for sealed deletion execution",
        "scope": "plan digest",
    },
    "CAP-DELETE-PREPARE-001": {
        "capability": "compute deletion closure plan",
        "defaultRole": "admin/data subject path",
        "denialReason": "ERR-AUTH-DENIED-001: principal lacks CAP-DELETE-PREPARE-001 authority on subject/object/event",
        "generation": "gen:fss1:capabilities-v1",
        "id": "CAP-DELETE-PREPARE-001",
        "plane": "effect",
        "safeAlternative": "request data governance authorization or initiate subject privacy request workflow",
        "scope": "subject/object/event",
    },
    "CAP-DRONE-CAPTURE-001": {
        "capability": "ingest manually piloted drone capture",
        "defaultRole": "operator",
        "denialReason": "ERR-AUTH-DENIED-001: principal lacks CAP-DRONE-CAPTURE-001 authority on session/device",
        "generation": "gen:fss1:capabilities-v1",
        "id": "CAP-DRONE-CAPTURE-001",
        "plane": "authority read",
        "safeAlternative": "request operator flight ingestion role or ingest stationary sensor capture",
        "scope": "session/device",
    },
    "CAP-DRONE-FLIGHT-001": {
        "capability": "command drone motion",
        "defaultRole": "disabled in v1",
        "denialReason": "ERR-AUTH-DENIED-001: CAP-DRONE-FLIGHT-001 is permanently disabled in v1 under NEG-001/NEG-002",
        "generation": "gen:fss1:capabilities-v1",
        "id": "CAP-DRONE-FLIGHT-001",
        "plane": "effect",
        "safeAlternative": "use authorized stationary sensors or manually piloted tethered capture",
        "scope": "mission/airspace",
    },
    "CAP-EXPORT-COMMIT-001": {
        "capability": "publish exact export",
        "defaultRole": "strong approval",
        "denialReason": "ERR-AUTH-DENIED-001: principal lacks CAP-EXPORT-COMMIT-001 authority on plan digest",
        "generation": "gen:fss1:capabilities-v1",
        "id": "CAP-EXPORT-COMMIT-001",
        "plane": "effect",
        "safeAlternative": "obtain designated custodian approval for export publication",
        "scope": "plan digest",
    },
    "CAP-EXPORT-PREPARE-001": {
        "capability": "build redacted evidence-export plan",
        "defaultRole": "denied",
        "denialReason": "ERR-AUTH-DENIED-001: principal lacks CAP-EXPORT-PREPARE-001 authority on event + recipient + fields",
        "generation": "gen:fss1:capabilities-v1",
        "id": "CAP-EXPORT-PREPARE-001",
        "plane": "effect",
        "safeAlternative": "request evidence export preparation privilege or view in-situ summaries",
        "scope": "event + recipient + fields",
    },
    "CAP-LEDGER-APPEND-001": {
        "capability": "append canonical revision/receipt",
        "defaultRole": "owning service only",
        "denialReason": "ERR-AUTH-DENIED-001: principal lacks CAP-LEDGER-APPEND-001 authority on table family",
        "generation": "gen:fss1:capabilities-v1",
        "id": "CAP-LEDGER-APPEND-001",
        "plane": "authority write",
        "safeAlternative": "submit staged batch to owning ledger service for validation and append",
        "scope": "table family",
    },
    "CAP-MEDIA-DECODE-001": {
        "capability": "decode designated source object",
        "defaultRole": "codec host only",
        "denialReason": "ERR-AUTH-DENIED-001: principal lacks CAP-MEDIA-DECODE-001 authority on object + transform plan",
        "generation": "gen:fss1:capabilities-v1",
        "id": "CAP-MEDIA-DECODE-001",
        "plane": "cognition",
        "safeAlternative": "delegate decoding to codec host or inspect retained keyframes",
        "scope": "object + transform plan",
    },
    "CAP-MODEL-INFER-001": {
        "capability": "invoke exact model generation",
        "defaultRole": "model router",
        "denialReason": "ERR-AUTH-DENIED-001: principal lacks CAP-MODEL-INFER-001 authority on model + inputs + budget",
        "generation": "gen:fss1:capabilities-v1",
        "id": "CAP-MODEL-INFER-001",
        "plane": "cognition",
        "safeAlternative": "submit inference request to model router or use cached belief outputs",
        "scope": "model + inputs + budget",
    },
    "CAP-OBJECT-PUBLISH-001": {
        "capability": "publish root after child proof",
        "defaultRole": "publisher",
        "denialReason": "ERR-AUTH-DENIED-001: principal lacks CAP-OBJECT-PUBLISH-001 authority on reserved root",
        "generation": "gen:fss1:capabilities-v1",
        "id": "CAP-OBJECT-PUBLISH-001",
        "plane": "authority write",
        "safeAlternative": "stage child objects and request publication through designated publisher",
        "scope": "reserved root",
    },
    "CAP-OBJECT-STAGE-001": {
        "capability": "stage encrypted/content objects",
        "defaultRole": "publisher",
        "denialReason": "ERR-AUTH-DENIED-001: principal lacks CAP-OBJECT-STAGE-001 authority on namespace + quota",
        "generation": "gen:fss1:capabilities-v1",
        "id": "CAP-OBJECT-STAGE-001",
        "plane": "authority write",
        "safeAlternative": "request staging allocation or purge unreferenced staging spool data",
        "scope": "namespace + quota",
    },
    "CAP-OBSERVE-EVENT-001": {
        "capability": "query event revisions and bounded evidence",
        "defaultRole": "operator/agent read role",
        "denialReason": "ERR-AUTH-DENIED-001: principal lacks CAP-OBSERVE-EVENT-001 authority on event/zone/time",
        "generation": "gen:fss1:capabilities-v1",
        "id": "CAP-OBSERVE-EVENT-001",
        "plane": "authority read",
        "safeAlternative": "request event observation role or query unprivileged event count",
        "scope": "event/zone/time",
    },
    "CAP-OBSERVE-STATUS-001": {
        "capability": "read system/sensor health",
        "defaultRole": "operator/agent read role",
        "denialReason": "ERR-AUTH-DENIED-001: principal lacks CAP-OBSERVE-STATUS-001 authority on property or sensor set",
        "generation": "gen:fss1:capabilities-v1",
        "id": "CAP-OBSERVE-STATUS-001",
        "plane": "authority read",
        "safeAlternative": "request sensor observation role or query public status summary",
        "scope": "property or sensor set",
    },
    "CAP-PTZ-COMMIT-001": {
        "capability": "commit exact PTZ plan",
        "defaultRole": "explicit grant",
        "denialReason": "ERR-AUTH-DENIED-001: principal lacks CAP-PTZ-COMMIT-001 authority on plan digest + lease",
        "generation": "gen:fss1:capabilities-v1",
        "id": "CAP-PTZ-COMMIT-001",
        "plane": "effect",
        "safeAlternative": "request operator lease grant or wait for scheduled patrol pass",
        "scope": "plan digest + lease",
    },
    "CAP-PTZ-PREPARE-001": {
        "capability": "prepare reversible PTZ plan",
        "defaultRole": "denied",
        "denialReason": "ERR-AUTH-DENIED-001: principal lacks CAP-PTZ-PREPARE-001 authority on camera + pose bounds",
        "generation": "gen:fss1:capabilities-v1",
        "id": "CAP-PTZ-PREPARE-001",
        "plane": "effect",
        "safeAlternative": "request PTZ planner grant or use static camera field of view",
        "scope": "camera + pose bounds",
    },
    "CAP-READ-GEOMETRY-001": {
        "capability": "read detailed property twin",
        "defaultRole": "denied to generic agent",
        "denialReason": "ERR-AUTH-DENIED-001: principal lacks CAP-READ-GEOMETRY-001 authority on property/zone",
        "generation": "gen:fss1:capabilities-v1",
        "id": "CAP-READ-GEOMETRY-001",
        "plane": "authority read",
        "safeAlternative": "request property twin access grant or use coarse bounding-box geometry",
        "scope": "property/zone",
    },
    "CAP-READ-MEDIA-001": {
        "capability": "read private source/proxy media",
        "defaultRole": "denied",
        "denialReason": "ERR-AUTH-DENIED-001: principal lacks CAP-READ-MEDIA-001 authority on object/event/time",
        "generation": "gen:fss1:capabilities-v1",
        "id": "CAP-READ-MEDIA-001",
        "plane": "authority read",
        "safeAlternative": "request explicit media access grant or inspect redacted metadata summary",
        "scope": "object/event/time",
    },
    "CAP-REPAIR-COMMIT-001": {
        "capability": "apply exact repair plan",
        "defaultRole": "strong approval",
        "denialReason": "ERR-AUTH-DENIED-001: principal lacks CAP-REPAIR-COMMIT-001 authority on plan digest",
        "generation": "gen:fss1:capabilities-v1",
        "id": "CAP-REPAIR-COMMIT-001",
        "plane": "effect",
        "safeAlternative": "obtain administrator approval for repair commit or maintain current quarantine",
        "scope": "plan digest",
    },
    "CAP-REPAIR-PREPARE-001": {
        "capability": "generate sealed repair plan",
        "defaultRole": "operator",
        "denialReason": "ERR-AUTH-DENIED-001: principal lacks CAP-REPAIR-PREPARE-001 authority on subsystem/object scope",
        "generation": "gen:fss1:capabilities-v1",
        "id": "CAP-REPAIR-PREPARE-001",
        "plane": "authority read",
        "safeAlternative": "request operator repair inspection role or run read-only diagnostics",
        "scope": "subsystem/object scope",
    },
    "CAP-RETENTION-COMMIT-001": {
        "capability": "commit exact retention mutation",
        "defaultRole": "strong approval",
        "denialReason": "ERR-AUTH-DENIED-001: principal lacks CAP-RETENTION-COMMIT-001 authority on plan digest",
        "generation": "gen:fss1:capabilities-v1",
        "id": "CAP-RETENTION-COMMIT-001",
        "plane": "effect",
        "safeAlternative": "obtain dual-custody administrator approval for retention modification",
        "scope": "plan digest",
    },
    "CAP-RETENTION-PREPARE-001": {
        "capability": "preview retention mutation",
        "defaultRole": "admin",
        "denialReason": "ERR-AUTH-DENIED-001: principal lacks CAP-RETENTION-PREPARE-001 authority on policy/object scope",
        "generation": "gen:fss1:capabilities-v1",
        "id": "CAP-RETENTION-PREPARE-001",
        "plane": "effect",
        "safeAlternative": "request admin role or inspect existing retention schedule",
        "scope": "policy/object scope",
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
    capability_count: int = 0
    registry_digest: str = ""
    errors: list[DiagnosticError] = field(default_factory=list)

    def add_error(self, code: str, file_path: str, target: str, message: str) -> None:
        self.passed = False
        self.errors.append(DiagnosticError(code=code, file_path=file_path, target=target, message=message))


def canonicalize_value(val: Any) -> Any:
    if isinstance(val, dict):
        return {k: canonicalize_value(v) for k, v in sorted(val.items())}
    elif isinstance(val, list):
        if all(isinstance(x, str) for x in val):
            return sorted(val)
        return [canonicalize_value(x) for x in val]
    return val


def compute_canonical_capability_digest(data: dict[str, Any]) -> str:
    """Computes SHA-256 digest of canonically serialized capability registry payload.

    Binds top-level schema, generation, semanticProtocol, asOf, sorted rows,
    and tombstones. Lists are canonically sorted. Fails closed with ValueError on
    empty or duplicate IDs.
    """
    schema = data.get("schema")
    generation = data.get("generation")
    semantic_protocol = data.get("semanticProtocol")
    as_of = data.get("asOf")
    if not all(isinstance(f, str) and f.strip() for f in (schema, generation, semantic_protocol, as_of)):
        raise ValueError("Top-level metadata (schema, generation, semanticProtocol, asOf) must be non-empty strings")

    capabilities = data.get("capabilities", [])
    if not isinstance(capabilities, list):
        raise ValueError("Capabilities must be a list")

    seen_ids: set[str] = set()
    for cap in capabilities:
        if not isinstance(cap, dict):
            raise ValueError("Capability entry must be an object")
        cid = cap.get("id")
        if not cid or not isinstance(cid, str) or not cid.strip():
            raise ValueError("Capability entry must have a non-empty string 'id'")
        if cid in seen_ids:
            raise ValueError(f"Duplicate capability ID: {cid}")
        seen_ids.add(cid)

    tombstones = data.get("tombstones", [])
    if not isinstance(tombstones, list):
        raise ValueError("Tombstones must be a list")

    seen_tombstones: set[str] = set()
    for tomb in tombstones:
        if not isinstance(tomb, dict):
            raise ValueError("Tombstone entry must be an object")
        tid = tomb.get("id")
        if not tid or not isinstance(tid, str) or not tid.strip():
            raise ValueError("Tombstone entry must have a non-empty string 'id'")
        if tid in seen_tombstones:
            raise ValueError(f"Duplicate tombstone ID: {tid}")
        if tid in seen_ids:
            raise ValueError(f"Tombstone ID overlaps with active capability ID: {tid}")
        seen_tombstones.add(tid)

    sorted_caps = sorted([canonicalize_value(r) for r in capabilities], key=lambda r: str(r.get("id", "")))
    sorted_tombstones = sorted([canonicalize_value(r) for r in tombstones], key=lambda r: str(r.get("id", "")))

    canonical_payload = {
        "asOf": as_of,
        "capabilities": sorted_caps,
        "generation": generation,
        "schema": schema,
        "semanticProtocol": semantic_protocol,
        "tombstones": sorted_tombstones,
    }
    canonical_bytes = json.dumps(canonical_payload, sort_keys=True, separators=(",", ":")).encode("utf-8")
    return f"sha256:{hashlib.sha256(canonical_bytes).hexdigest()}"


def extract_markdown_capabilities(md_path: Path) -> dict[str, tuple[str, str, str, str]]:
    """Extracts capabilities from markdown table: {id: (capability, scope, plane, default)}."""
    rows: dict[str, tuple[str, str, str, str]] = {}
    lines = md_path.read_text(encoding="utf-8").splitlines()
    for line in lines:
        if line.startswith("| `CAP-"):
            parts = [p.strip() for p in line.strip().strip("|").split("|")]
            if len(parts) >= 5:
                cap_id = parts[0].replace("`", "")
                rows[cap_id] = (parts[1], parts[2], parts[3], parts[4])
    return rows


def validate_capability_registry(repo_root: Path = ROOT) -> ValidationResult:
    result = ValidationResult()
    json_path = repo_root / CAPABILITIES_JSON_PATH
    md_path = repo_root / CAPABILITIES_MD_PATH

    # Check existence
    if not json_path.is_file():
        result.add_error(
            ERR_CAPABILITY_CORRUPT_FILE,
            CAPABILITIES_JSON_PATH,
            "#",
            f"Capability registry JSON file does not exist: {json_path}",
        )
        return result

    if not md_path.is_file():
        result.add_error(
            ERR_CAPABILITY_CORRUPT_FILE,
            CAPABILITIES_MD_PATH,
            "#",
            f"Capability registry markdown file does not exist: {md_path}",
        )
        return result

    # Parse JSON
    try:
        data = json.loads(json_path.read_text(encoding="utf-8"))
    except Exception as exc:
        result.add_error(
            ERR_CAPABILITY_CORRUPT_FILE,
            CAPABILITIES_JSON_PATH,
            "#",
            f"Failed to parse capability JSON: {exc}",
        )
        return result

    if not isinstance(data, dict):
        result.add_error(
            ERR_CAPABILITY_CORRUPT_FILE,
            CAPABILITIES_JSON_PATH,
            "#",
            "Top-level capability registry must be a JSON object",
        )
        return result

    # Validate top-level schema fields
    schema = data.get("schema")
    if schema != "fss.capability_registry.v1":
        result.add_error(
            ERR_CAPABILITY_CORRUPT_FILE,
            CAPABILITIES_JSON_PATH,
            "#/schema",
            f"Expected schema 'fss.capability_registry.v1', got '{schema}'",
        )

    protocol = data.get("semanticProtocol")
    if protocol != "fss/1":
        result.add_error(
            ERR_CAPABILITY_CORRUPT_FILE,
            CAPABILITIES_JSON_PATH,
            "#/semanticProtocol",
            f"Expected semanticProtocol 'fss/1', got '{protocol}'",
        )

    as_of = data.get("asOf")
    if not as_of or not isinstance(as_of, str):
        result.add_error(
            ERR_CAPABILITY_CORRUPT_FILE,
            CAPABILITIES_JSON_PATH,
            "#/asOf",
            "Missing or invalid 'asOf' date string in registry",
        )

    gen = data.get("generation")
    if not gen or not isinstance(gen, str):
        result.add_error(
            ERR_CAPABILITY_CORRUPT_FILE,
            CAPABILITIES_JSON_PATH,
            "#/generation",
            "Missing or invalid 'generation' string in registry",
        )
        return result

    if gen not in EXPECTED_FREEZE_DIGESTS:
        result.add_error(
            ERR_CAPABILITY_CORRUPT_FILE,
            CAPABILITIES_JSON_PATH,
            "#/generation",
            f"Unrecognized or unpinned capability registry generation: '{gen}'",
        )
        return result

    expected_digest = EXPECTED_FREEZE_DIGESTS[gen]

    capabilities_list = data.get("capabilities")
    if not isinstance(capabilities_list, list):
        result.add_error(
            ERR_CAPABILITY_CORRUPT_FILE,
            CAPABILITIES_JSON_PATH,
            "#/capabilities",
            "Missing or non-array 'capabilities' property in registry",
        )
        return result

    result.capability_count = len(capabilities_list)
    declared_digest = data.get("registryDigest", "")
    result.registry_digest = declared_digest

    # Check tombstones if present
    tombstones_list = data.get("tombstones", [])
    seen_tombstones: set[str] = set()
    if isinstance(tombstones_list, list):
        for idx, tomb in enumerate(tombstones_list):
            if isinstance(tomb, dict):
                tid = tomb.get("id")
                if isinstance(tid, str) and tid:
                    seen_tombstones.add(tid)

    # Check for duplicate stable IDs, missing fields, unknown planes in JSON
    seen_ids: set[str] = set()
    json_caps: dict[str, dict[str, Any]] = {}
    for idx, cap in enumerate(capabilities_list):
        if not isinstance(cap, dict):
            result.add_error(
                ERR_CAPABILITY_CORRUPT_FILE,
                CAPABILITIES_JSON_PATH,
                f"#/capabilities/{idx}",
                "Capability entry must be a JSON object",
            )
            continue

        cid = cap.get("id")
        if not cid or not isinstance(cid, str) or not cid.strip():
            result.add_error(
                ERR_CAPABILITY_CORRUPT_FILE,
                CAPABILITIES_JSON_PATH,
                f"#/capabilities/{idx}/id",
                "Capability entry missing or empty 'id'",
            )
            continue

        if cid in seen_ids:
            result.add_error(
                ERR_CAPABILITY_STABLE_ID_REUSED,
                CAPABILITIES_JSON_PATH,
                f"#/capabilities/{idx}/id",
                f"Duplicate or reused capability stable ID: '{cid}'",
            )
        seen_ids.add(cid)

        if cid in seen_tombstones:
            result.add_error(
                ERR_CAPABILITY_STABLE_ID_REUSED,
                CAPABILITIES_JSON_PATH,
                f"#/capabilities/{idx}/id",
                f"Tombstoned capability ID resurrected as active: '{cid}'",
            )

        json_caps[cid] = cap

        # Validate presence of all required fields
        for field_name in REQUIRED_ROW_FIELDS:
            fval = cap.get(field_name)
            if fval is None or not isinstance(fval, str) or not fval.strip():
                if field_name == "defaultRole":
                    result.add_error(
                        ERR_CAPABILITY_MISSING_DEFAULT,
                        CAPABILITIES_JSON_PATH,
                        f"#/capabilities/{cid}/defaultRole",
                        f"Capability '{cid}' missing required defaultRole",
                    )
                else:
                    result.add_error(
                        ERR_CAPABILITY_CORRUPT_FILE,
                        CAPABILITIES_JSON_PATH,
                        f"#/capabilities/{cid}/{field_name}",
                        f"Capability '{cid}' missing or empty required field '{field_name}'",
                    )

        plane = cap.get("plane", "")
        if plane and plane not in RECOGNIZED_PLANES:
            result.add_error(
                ERR_CAPABILITY_UNKNOWN_PLANE,
                CAPABILITIES_JSON_PATH,
                f"#/capabilities/{cid}/plane",
                f"Capability '{cid}' has unknown or unregistered plane: '{plane}'",
            )

        cap_gen = cap.get("generation", "")
        if cap_gen and cap_gen != gen:
            result.add_error(
                ERR_CAPABILITY_CORRUPT_FILE,
                CAPABILITIES_JSON_PATH,
                f"#/capabilities/{cid}/generation",
                f"Capability '{cid}' generation '{cap_gen}' does not match registry generation '{gen}'",
            )

        # Baseline drift check
        if cid not in BASELINE_CAPABILITIES:
            result.add_error(
                ERR_CAPABILITY_REGISTRY_DRIFT,
                CAPABILITIES_JSON_PATH,
                f"#/capabilities/{cid}",
                f"New capability '{cid}' not in pinned baseline without generation bump",
            )
        else:
            base_entry = BASELINE_CAPABILITIES[cid]
            for k in REQUIRED_ROW_FIELDS:
                if cap.get(k) != base_entry.get(k):
                    result.add_error(
                        ERR_CAPABILITY_REGISTRY_DRIFT,
                        CAPABILITIES_JSON_PATH,
                        f"#/capabilities/{cid}/{k}",
                        f"Capability '{cid}' field '{k}' drifted from baseline: '{cap.get(k)}' != '{base_entry.get(k)}'",
                    )

    # Check for removed baseline IDs
    for base_id in BASELINE_CAPABILITIES:
        if base_id not in seen_ids and base_id not in seen_tombstones:
            result.add_error(
                ERR_CAPABILITY_REGISTRY_DRIFT,
                CAPABILITIES_JSON_PATH,
                f"#/capabilities/{base_id}",
                f"Baseline capability '{base_id}' removed without tombstone or generation bump",
            )

    # Validate canonical digest against pinned constant
    try:
        computed_digest = compute_canonical_capability_digest(data)
    except Exception as exc:
        result.add_error(
            ERR_CAPABILITY_CORRUPT_FILE,
            CAPABILITIES_JSON_PATH,
            "#/registryDigest",
            f"Failed to compute canonical capability digest: {exc}",
        )
        return result

    if declared_digest != expected_digest:
        result.add_error(
            ERR_CAPABILITY_DIGEST_MISMATCH,
            CAPABILITIES_JSON_PATH,
            "#/registryDigest",
            f"Declared digest mismatch for {gen}: declared '{declared_digest}', expected pinned '{expected_digest}'",
        )

    if computed_digest != expected_digest:
        result.add_error(
            ERR_CAPABILITY_DIGEST_MISMATCH,
            CAPABILITIES_JSON_PATH,
            "#/registryDigest",
            f"Computed digest mismatch for {gen}: computed '{computed_digest}', expected pinned '{expected_digest}'",
        )

    # Parse and cross-check against Markdown
    try:
        md_caps = extract_markdown_capabilities(md_path)
    except Exception as exc:
        result.add_error(
            ERR_CAPABILITY_CORRUPT_FILE,
            CAPABILITIES_MD_PATH,
            "#",
            f"Failed to extract capability rows from markdown: {exc}",
        )
        return result

    # Check count parity
    if len(json_caps) != len(md_caps):
        result.add_error(
            ERR_CAPABILITY_REGISTRY_DRIFT,
            CAPABILITIES_JSON_PATH,
            "#/capabilities",
            f"Capability count mismatch: JSON has {len(json_caps)}, Markdown has {len(md_caps)}",
        )

    # Check all MD rows in JSON and match
    for cid, (md_cap, md_scope, md_plane, md_default) in md_caps.items():
        if cid not in json_caps:
            result.add_error(
                ERR_CAPABILITY_REGISTRY_DRIFT,
                CAPABILITIES_JSON_PATH,
                f"#/capabilities/{cid}",
                f"Capability '{cid}' present in Markdown but missing in JSON",
            )
            continue

        j_cap = json_caps[cid]
        if j_cap.get("capability") != md_cap:
            result.add_error(
                ERR_CAPABILITY_REGISTRY_DRIFT,
                CAPABILITIES_JSON_PATH,
                f"#/capabilities/{cid}/capability",
                f"Capability '{cid}' text mismatch: JSON '{j_cap.get('capability')}', MD '{md_cap}'",
            )
        if j_cap.get("scope") != md_scope:
            result.add_error(
                ERR_CAPABILITY_REGISTRY_DRIFT,
                CAPABILITIES_JSON_PATH,
                f"#/capabilities/{cid}/scope",
                f"Capability '{cid}' scope mismatch: JSON '{j_cap.get('scope')}', MD '{md_scope}'",
            )
        if j_cap.get("plane") != md_plane:
            result.add_error(
                ERR_CAPABILITY_REGISTRY_DRIFT,
                CAPABILITIES_JSON_PATH,
                f"#/capabilities/{cid}/plane",
                f"Capability '{cid}' plane mismatch: JSON '{j_cap.get('plane')}', MD '{md_plane}'",
            )
        if j_cap.get("defaultRole") != md_default:
            result.add_error(
                ERR_CAPABILITY_REGISTRY_DRIFT,
                CAPABILITIES_JSON_PATH,
                f"#/capabilities/{cid}/defaultRole",
                f"Capability '{cid}' default mismatch: JSON '{j_cap.get('defaultRole')}', MD '{md_default}'",
            )

    # Check all JSON rows in MD
    for cid in json_caps:
        if cid not in md_caps:
            result.add_error(
                ERR_CAPABILITY_REGISTRY_DRIFT,
                CAPABILITIES_MD_PATH,
                f"#{cid}",
                f"Capability '{cid}' present in JSON but missing in Markdown",
            )

    return result


def main() -> int:
    parser = argparse.ArgumentParser(description="Validate capability registry against markdown mirror and invariants")
    parser.add_argument("--repo-root", type=Path, default=ROOT, help="Path to repository root")
    parser.add_argument("--json", action="store_true", help="Emit machine-readable JSON")
    args = parser.parse_args()

    result = validate_capability_registry(args.repo_root)
    if args.json:
        payload = {
            "schema": "fss.capability_validation.v1",
            "passed": result.passed,
            "capabilityCount": result.capability_count,
            "registryDigest": result.registry_digest,
            "errorCount": len(result.errors),
            "errors": [asdict(e) for e in result.errors],
        }
        print(json.dumps(payload, indent=2))
    else:
        if result.passed:
            print(f"[PASS] Capability registry verified: {result.capability_count} capabilities, digest {result.registry_digest}.")
        else:
            print(f"[FAIL] Capability registry failed with {len(result.errors)} errors:", file=sys.stderr)
            for err in result.errors:
                print(f"  [{err.code}] {err.file_path} ({err.target}): {err.message}", file=sys.stderr)

    return 0 if result.passed else 1


if __name__ == "__main__":
    sys.exit(main())
