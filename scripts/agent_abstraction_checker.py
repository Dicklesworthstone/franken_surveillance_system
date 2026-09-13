#!/usr/bin/env python3
"""Fail-closed agent abstraction stack registry checker (fss-x4a.30.82.3).

Enforces the agent abstraction stack registry contract:
1. Agent abstraction registry row drift between architecture JSON and markdown mirror (ERR-AGT-REGISTRY-DRIFT-001)
2. Stable ID reused, duplicated, renumbered, or diverging from canonical baseline (ERR-AGT-STABLE-ID-REUSED-001)
3. Missing or empty mandatory field in an agent abstraction layer row or top-level metadata (ERR-AGT-MISSING-FIELD-001)
4. Corrupt or missing mandatory registry files (ERR-AGT-CORRUPT-FILE-001)
5. Registry digest mismatch between declared and canonical computed digest (ERR-AGT-DIGEST-MISMATCH-001)
6. Registry digest diverged from pinned baseline freeze digest (ERR-AGT-FREEZE-DIVERGENCE-001)
7. Registry generation diverged from baseline generation (ERR-AGT-GENERATION-MISMATCH-001)
8. Abstraction layer invariant or prohibition violated (ERR-AGT-INVARIANT-VIOLATION-001)
9. Derived beliefs or non-authority layer illegally claims authority or authorizes effects (ERR-AGT-ILLEGAL-AUTHORITY-001)
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
ERR_AGT_REGISTRY_DRIFT = "ERR-AGT-REGISTRY-DRIFT-001"
ERR_AGT_STABLE_ID_REUSED = "ERR-AGT-STABLE-ID-REUSED-001"
ERR_AGT_MISSING_FIELD = "ERR-AGT-MISSING-FIELD-001"
ERR_AGT_CORRUPT_FILE = "ERR-AGT-CORRUPT-FILE-001"
ERR_AGT_DIGEST_MISMATCH = "ERR-AGT-DIGEST-MISMATCH-001"
ERR_AGT_FREEZE_DIVERGENCE = "ERR-AGT-FREEZE-DIVERGENCE-001"
ERR_AGT_GENERATION_MISMATCH = "ERR-AGT-GENERATION-MISMATCH-001"
ERR_AGT_INVARIANT_VIOLATION = "ERR-AGT-INVARIANT-VIOLATION-001"
ERR_AGT_ILLEGAL_AUTHORITY = "ERR-AGT-ILLEGAL-AUTHORITY-001"

AGENT_ABSTRACTION_STACK_JSON_PATH = "architecture/agent_abstraction_stack.json"
AGENT_ABSTRACTIONS_MD_PATH = "registries/AGENT_ABSTRACTIONS.md"

BASELINE_GENERATION = "gen:fss1:abstraction-v1"
BASELINE_FREEZE_DIGEST = "sha256:98dfe512d870a36079fe49435d1f53d669c63a0034d03a771248fbab0abf34a9"

EXPECTED_FREEZE_DIGESTS: dict[str, str] = {
    BASELINE_GENERATION: BASELINE_FREEZE_DIGEST,
}

# Full baseline agent abstraction layers for generation gen:fss1:abstraction-v1
BASELINE_LAYERS: dict[str, dict[str, str]] = {
    "AGT-LAYER-001": {
        "id": "AGT-LAYER-001",
        "invariant": "INV-006",
        "name": "runtime_authority_and_custody",
        "output": "Context, grants, regions, obligations, object roots, and receipts.",
        "owner": "asupersync/authority/object owners",
        "prohibition": "Cannot infer mission meaning or physical truth.",
        "question": "What work, authority, budget, identity, time, and object custody exist?",
        "status": "normative",
    },
    "AGT-LAYER-002": {
        "id": "AGT-LAYER-002",
        "invariant": "INV-003",
        "name": "source_evidence",
        "output": "Immutable sensor capsules, source objects, continuity and time evidence.",
        "owner": "fss-capture/fss-media/fss-chronicle",
        "prohibition": "Cannot promote decode or model output into source evidence.",
        "question": "What exact packets, files, measurements, continuity, and capture-time intervals exist?",
        "status": "normative",
    },
    "AGT-LAYER-003": {
        "id": "AGT-LAYER-003",
        "invariant": "INV-063",
        "name": "world_facts_and_coverage",
        "output": "Device, geometry, calibration, coverage, policy, archive, and effect facts.",
        "owner": "fss-chronicle/fss-coverage",
        "prohibition": "Cannot include unqualified cognition as fact.",
        "question": "What did the system authoritatively observe or do at one anchor?",
        "status": "normative",
    },
    "AGT-LAYER-004": {
        "id": "AGT-LAYER-004",
        "invariant": "INV-069",
        "name": "derived_beliefs",
        "output": "Generation-pinned derived beliefs and graph/search projections with receipts.",
        "owner": "fss-perception/fss-association/fss-graph",
        "prohibition": "Cannot authorize effects or certify absence beyond coverage.",
        "question": "What entities, tracks, events, relations, and uncertainties are supported?",
        "status": "normative",
    },
    "AGT-LAYER-005": {
        "id": "AGT-LAYER-005",
        "invariant": "INV-116",
        "name": "situation_capsule",
        "output": "SituationCapsule containing SituationFrame with WorldEnvelope, MeaningfulDelta, obligations, resource state, categorized control envelope, ContextPack, compression proof, and affordance frontier.",
        "owner": "fss-situation/fss-context-pack/fss-affordance",
        "prohibition": "Cannot hide decision-changing omissions or rebase evidence identities.",
        "question": "What is the smallest sufficient mission-relative driver view now, what changed, and what can safely be done next?",
        "status": "normative",
    },
    "AGT-LAYER-006": {
        "id": "AGT-LAYER-006",
        "invariant": "INV-104",
        "name": "investigation_and_hypotheses",
        "output": "Case revision, hypotheses, support, contradictions, predicted observations, falsifiers, and stop rule.",
        "owner": "fss-investigation",
        "prohibition": "Cannot collapse uncertainty into truth without adjudication.",
        "question": "Which competing explanations remain viable and how can they be discriminated?",
        "status": "normative",
    },
    "AGT-LAYER-007": {
        "id": "AGT-LAYER-007",
        "invariant": "INV-106",
        "name": "affordance_frontier",
        "output": "Pareto frontier of read/control affordances with VOI, cost, risk, reversibility, invalidators, and proof.",
        "owner": "fss-attention/fss-affordance",
        "prohibition": "Cannot grant authority or use one opaque score.",
        "question": "What can be done next, under current capability and budget, and why is it worth doing?",
        "status": "normative",
    },
    "AGT-LAYER-008": {
        "id": "AGT-LAYER-008",
        "invariant": "INV-088",
        "name": "plan_and_effect",
        "output": "Prepared plan, commit ticket, effect receipts, obligation states, and reconciliation path.",
        "owner": "fss-agent-plan/fss-effect",
        "prohibition": "Cannot execute prose or count dispatch as success.",
        "question": "Which witnessed contingent DAG should run and did each effect happen?",
        "status": "normative",
    },
    "AGT-LAYER-009": {
        "id": "AGT-LAYER-009",
        "invariant": "INV-098",
        "name": "outcome_and_episode",
        "output": "Immutable execution episode with attribution hypotheses and resource ledger.",
        "owner": "fss-episode",
        "prohibition": "Cannot rewrite original predictions after outcome.",
        "question": "What was predicted, executed, observed, consumed, and left uncertain?",
        "status": "normative",
    },
    "AGT-LAYER-010": {
        "id": "AGT-LAYER-010",
        "invariant": "INV-094",
        "name": "learning_and_memory",
        "output": "Evidence-linked scoped proposal with counterexamples, harmful outcomes, validation, and expiry.",
        "owner": "fss-learning",
        "prohibition": "Cannot self-promote into active policy or truth.",
        "question": "What reusable rule, anti-pattern, fixture, or runbook improvement should be proposed?",
        "status": "normative",
    },
    "AGT-LAYER-011": {
        "id": "AGT-LAYER-011",
        "invariant": "INV-096",
        "name": "workspace_and_handoff",
        "output": "Versioned workspace revision and root-last HandoffCapsule.",
        "owner": "fss-agent-session/fss-handoff",
        "prohibition": "Cannot preserve hidden conversational state or confer effect authority through custody.",
        "question": "How can this mission resume or transfer without rediscovery or hidden staleness?",
        "status": "normative",
    },
}

CANONICAL_TOWER_ORDER: list[str] = [
    "AGT-LAYER-001",
    "AGT-LAYER-002",
    "AGT-LAYER-003",
    "AGT-LAYER-004",
    "AGT-LAYER-005",
    "AGT-LAYER-006",
    "AGT-LAYER-007",
    "AGT-LAYER-008",
    "AGT-LAYER-009",
    "AGT-LAYER-010",
    "AGT-LAYER-011",
]

MANDATORY_TOP_LEVEL_FIELDS: tuple[str, ...] = (
    "schema",
    "asOf",
    "generation",
    "semanticProtocol",
    "constitutionalRole",
    "truthOwnership",
    "humanRegistry",
    "gate",
    "primaryReadSurface",
    "qualificationLane",
    "rules",
    "knowledgeStateRefs",
    "provenanceClassRefs",
    "hydrationLevels",
    "layers",
    "operationRefs",
    "viewRefs",
    "semanticObjectSchemas",
    "responseComposition",
    "requestComposition",
    "registryDigest",
)

MANDATORY_LAYER_FIELDS: tuple[str, ...] = (
    "id",
    "name",
    "owner",
    "question",
    "output",
    "prohibition",
    "invariant",
    "status",
)

AGT_LAYER_ID_PATTERN = re.compile(r"^AGT-LAYER-\d{3}$")

# Full baseline hydration levels for generation gen:fss1:abstraction-v1
BASELINE_HYDRATION_LEVELS: dict[str, dict[str, str]] = {
    "H0": {
        "id": "H0",
        "name": "identity",
        "content": "digest, type, time/spatial bounds, source, availability, cost, and authority",
    },
    "H1": {
        "id": "H1",
        "name": "semantic_synopsis",
        "content": "typed facts, knowledge states, provenance, contradictions, quality, and omissions",
    },
    "H2": {
        "id": "H2",
        "name": "decision_artifact",
        "content": "authorized redacted keyframes, crops, trajectories, graph neighborhoods, or audio features",
    },
    "H3": {
        "id": "H3",
        "name": "source_evidence",
        "content": "authorized original encoded packets, object bytes, exact metadata, or full-resolution media",
    },
    "H4": {
        "id": "H4",
        "name": "laboratory_expansion",
        "content": "replay bundle, intermediates, alternate decoders/models, and oracle comparisons",
    },
}

CANONICAL_HYDRATION_ORDER: list[str] = [
    "H0",
    "H1",
    "H2",
    "H3",
    "H4",
]

MANDATORY_HYDRATION_FIELDS: tuple[str, ...] = (
    "id",
    "name",
    "content",
)

HYDRATION_ID_PATTERN = re.compile(r"^H[0-4]$")


KNOWN_TOP_LEVEL_KEYS: set[str] = {
    "asOf",
    "constitutionalRole",
    "gate",
    "generation",
    "humanRegistry",
    "hydrationLevels",
    "knowledgeStateRefs",
    "layers",
    "operationRefs",
    "primaryReadSurface",
    "provenanceClassRefs",
    "qualificationLane",
    "requestComposition",
    "responseComposition",
    "rules",
    "schema",
    "semanticObjectSchemas",
    "semanticProtocol",
    "truthOwnership",
    "viewRefs",
}

KNOWN_LAYER_KEYS: set[str] = {
    "id",
    "name",
    "owner",
    "question",
    "output",
    "prohibition",
    "invariant",
    "status",
}

KNOWN_HYDRATION_KEYS: set[str] = {
    "id",
    "name",
    "content",
}


def pairs_hook_reject_duplicates(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    d: dict[str, Any] = {}
    for k, v in pairs:
        if k in d:
            raise ValueError(f"Duplicate JSON key '{k}'")
        d[k] = v
    return d


@dataclass(frozen=True)
class DiagnosticError:
    code: str
    file_path: str
    target: str
    message: str


@dataclass
class ValidationResult:
    passed: bool = True
    layer_count: int = 0
    hydration_level_count: int = 0
    registry_digest: str = ""
    errors: list[DiagnosticError] = field(default_factory=list)

    def add_error(self, code: str, file_path: str, target: str, message: str) -> None:
        self.passed = False
        self.errors.append(DiagnosticError(code=code, file_path=file_path, target=target, message=message))


def canonicalize_value(val: Any) -> Any:
    """Deterministically orders dictionaries for canonical hashing.

    Lists preserve their exact sequence order (order is significant).
    Strings and primitives are preserved byte-exact without stripping.
    """
    if isinstance(val, dict):
        return {k: canonicalize_value(v) for k, v in sorted(val.items())}
    if isinstance(val, list):
        return [canonicalize_value(item) for item in val]
    return val


def compute_canonical_agent_abstraction_digest(data: dict[str, Any]) -> str:
    """Computes SHA-256 digest of canonically serialized agent abstraction stack data.

    Binds top-level metadata and deterministically sorted layers and hydration levels.
    """
    raw_layers = data.get("layers", [])
    raw_hydration = data.get("hydrationLevels", [])

    if not isinstance(raw_layers, list) or not isinstance(raw_hydration, list):
        raise ValueError("layers and hydrationLevels must be lists")

    sorted_layers = sorted(raw_layers, key=lambda r: str(r.get("id", "") if isinstance(r, dict) else ""))
    sorted_hydration = sorted(raw_hydration, key=lambda r: str(r.get("id", "") if isinstance(r, dict) else ""))

    canonical_payload = {
        "asOf": str(data.get("asOf", "")),
        "constitutionalRole": str(data.get("constitutionalRole", "")),
        "gate": str(data.get("gate", "")),
        "generation": str(data.get("generation", "")),
        "humanRegistry": str(data.get("humanRegistry", "")),
        "hydrationLevels": [
            {k: canonicalize_value(v) for k, v in sorted(r.items()) if k in KNOWN_HYDRATION_KEYS}
            if isinstance(r, dict)
            else canonicalize_value(r)
            for r in sorted_hydration
        ],
        "knowledgeStateRefs": canonicalize_value(data.get("knowledgeStateRefs", [])),
        "layers": [
            {k: canonicalize_value(v) for k, v in sorted(r.items()) if k in KNOWN_LAYER_KEYS}
            if isinstance(r, dict)
            else canonicalize_value(r)
            for r in sorted_layers
        ],
        "operationRefs": canonicalize_value(data.get("operationRefs", [])),
        "primaryReadSurface": str(data.get("primaryReadSurface", "")),
        "provenanceClassRefs": canonicalize_value(data.get("provenanceClassRefs", [])),
        "qualificationLane": str(data.get("qualificationLane", "")),
        "requestComposition": canonicalize_value(data.get("requestComposition", {})),
        "responseComposition": canonicalize_value(data.get("responseComposition", {})),
        "rules": canonicalize_value(data.get("rules", [])),
        "schema": str(data.get("schema", "")),
        "semanticObjectSchemas": canonicalize_value(data.get("semanticObjectSchemas", [])),
        "semanticProtocol": str(data.get("semanticProtocol", "")),
        "truthOwnership": str(data.get("truthOwnership", "")),
        "viewRefs": canonicalize_value(data.get("viewRefs", [])),
    }
    canonical_bytes = json.dumps(canonical_payload, sort_keys=True, separators=(",", ":")).encode("utf-8")
    return f"sha256:{hashlib.sha256(canonical_bytes).hexdigest()}"


def extract_markdown_metadata_and_abstractions(
    md_path: Path,
) -> tuple[str, str, dict[str, tuple[str, str, str, str, str]], dict[str, tuple[str, str]], list[str], list[str], list[str]]:
    """Extracts (generation, digest, layer_rows, hydration_rows, duplicate_layer_ids, duplicate_hydration_ids, misplaced_hydration_ids)."""
    rows: dict[str, tuple[str, str, str, str, str]] = {}
    hydration_rows: dict[str, tuple[str, str]] = {}
    duplicate_layer_ids: list[str] = []
    duplicate_hydration_ids: list[str] = []
    misplaced_hydration_ids: list[str] = []
    lines = md_path.read_text(encoding="utf-8").splitlines()
    md_gen = ""
    md_digest = ""
    in_hydration_ladder = False
    for line in lines:
        stripped = line.strip()
        if stripped.startswith("## Hydration ladder"):
            in_hydration_ladder = True
            continue
        elif stripped.startswith("## ") and in_hydration_ladder:
            in_hydration_ladder = False

        if stripped.startswith("Generation:"):
            m = re.search(r"`([^`]+)`", stripped)
            if m:
                md_gen = m.group(1).strip()
        elif stripped.startswith("Registry digest:"):
            m = re.search(r"`([^`]+)`", stripped)
            if m:
                md_digest = m.group(1).strip()
        elif re.match(r"^\|\s*`AGT-LAYER-", stripped):
            parts = [p.strip() for p in stripped.strip("|").split("|")]
            if len(parts) >= 6:
                lid = parts[0].replace("`", "").strip()
                name = parts[1].replace("`", "").strip()
                owner = parts[2].replace("`", "").strip()
                question = parts[3].strip()
                invariant = parts[4].replace("`", "").strip()
                status = parts[5].replace("`", "").strip()
                if lid in rows:
                    duplicate_layer_ids.append(lid)
                rows[lid] = (name, owner, question, invariant, status)
        elif in_hydration_ladder and re.match(r"^\|\s*`H", stripped):
            parts = [p.strip() for p in stripped.strip("|").split("|")]
            if len(parts) >= 3:
                hid = parts[0].replace("`", "").strip()
                name = parts[1].replace("`", "").strip()
                content = parts[2].replace("`", "").strip()
                if hid in hydration_rows:
                    duplicate_hydration_ids.append(hid)
                hydration_rows[hid] = (name, content)
        elif not in_hydration_ladder and re.match(r"^\|\s*`H", stripped):
            parts = [p.strip() for p in stripped.strip("|").split("|")]
            if len(parts) >= 3 and HYDRATION_ID_PATTERN.match(parts[0].replace("`", "").strip()):
                misplaced_hydration_ids.append(parts[0].replace("`", "").strip())
    return md_gen, md_digest, rows, hydration_rows, duplicate_layer_ids, duplicate_hydration_ids, misplaced_hydration_ids


def extract_markdown_agent_abstractions(md_path: Path) -> dict[str, tuple[str, str, str, str, str]]:
    """Extracts abstraction layers from markdown table: {id: (name, owner, question, invariant, status)}."""
    _, _, rows, _, _, _, _ = extract_markdown_metadata_and_abstractions(md_path)
    return rows


def validate_agent_abstraction_registry(repo_root: Path = ROOT) -> ValidationResult:
    result = ValidationResult()
    json_path = repo_root / AGENT_ABSTRACTION_STACK_JSON_PATH
    md_path = repo_root / AGENT_ABSTRACTIONS_MD_PATH

    # Check existence
    if not json_path.is_file():
        result.add_error(
            ERR_AGT_CORRUPT_FILE,
            AGENT_ABSTRACTION_STACK_JSON_PATH,
            "#",
            f"Mandatory agent abstraction JSON file missing: {AGENT_ABSTRACTION_STACK_JSON_PATH}",
        )
        return result

    if not md_path.is_file():
        result.add_error(
            ERR_AGT_CORRUPT_FILE,
            AGENT_ABSTRACTIONS_MD_PATH,
            "#",
            f"Mandatory agent abstractions Markdown mirror missing: {AGENT_ABSTRACTIONS_MD_PATH}",
        )
        return result

    # Parse JSON
    try:
        raw_text = json_path.read_text(encoding="utf-8")
        data = json.loads(raw_text, object_pairs_hook=pairs_hook_reject_duplicates)
    except Exception as exc:
        result.add_error(
            ERR_AGT_CORRUPT_FILE,
            AGENT_ABSTRACTION_STACK_JSON_PATH,
            "#",
            f"Failed to parse agent abstraction JSON: {exc}",
        )
        return result

    if not isinstance(data, dict):
        result.add_error(
            ERR_AGT_CORRUPT_FILE,
            AGENT_ABSTRACTION_STACK_JSON_PATH,
            "#",
            "Root of agent abstraction stack JSON must be an object",
        )
        return result

    # Check unknown top-level keys
    unknown_top_keys = set(data.keys()) - KNOWN_TOP_LEVEL_KEYS - {"registryDigest"}
    for ukey in sorted(unknown_top_keys):
        result.add_error(
            ERR_AGT_INVARIANT_VIOLATION,
            AGENT_ABSTRACTION_STACK_JSON_PATH,
            f"#/{ukey}",
            f"Unknown top-level key '{ukey}' in agent abstraction registry",
        )

    # Check rules type
    if "rules" in data and not isinstance(data["rules"], list):
        result.add_error(
            ERR_AGT_CORRUPT_FILE,
            AGENT_ABSTRACTION_STACK_JSON_PATH,
            "#/rules",
            "'rules' must be a list",
        )

    # Top-level mandatory fields
    for field_name in MANDATORY_TOP_LEVEL_FIELDS:
        if field_name not in data:
            result.add_error(
                ERR_AGT_MISSING_FIELD,
                AGENT_ABSTRACTION_STACK_JSON_PATH,
                f"#/{field_name}",
                f"Missing mandatory top-level field: {field_name}",
            )
        else:
            val = data[field_name]
            if isinstance(val, str) and not val.strip():
                result.add_error(
                    ERR_AGT_MISSING_FIELD,
                    AGENT_ABSTRACTION_STACK_JSON_PATH,
                    f"#/{field_name}",
                    f"Top-level field must not be empty: {field_name}",
                )
            elif isinstance(val, (list, dict)) and len(val) == 0:
                result.add_error(
                    ERR_AGT_MISSING_FIELD,
                    AGENT_ABSTRACTION_STACK_JSON_PATH,
                    f"#/{field_name}",
                    f"Top-level collection must not be empty: {field_name}",
                )

    # Generation check
    gen = str(data.get("generation", "")).strip()
    if not gen:
        result.add_error(
            ERR_AGT_GENERATION_MISMATCH,
            AGENT_ABSTRACTION_STACK_JSON_PATH,
            "#/generation",
            "Missing generation identifier in agent abstraction registry",
        )
    elif gen != BASELINE_GENERATION:
        result.add_error(
            ERR_AGT_GENERATION_MISMATCH,
            AGENT_ABSTRACTION_STACK_JSON_PATH,
            "#/generation",
            f"Registry generation diverged: expected {BASELINE_GENERATION}, got {gen}",
        )

    # Digest verification
    declared_digest = str(data.get("registryDigest", "")).strip()
    try:
        computed_digest = compute_canonical_agent_abstraction_digest(data)
    except Exception as exc:
        result.add_error(
            ERR_AGT_INVARIANT_VIOLATION,
            AGENT_ABSTRACTION_STACK_JSON_PATH,
            "#",
            f"Failed to compute canonical digest: {exc}",
        )
        computed_digest = ""
    result.registry_digest = declared_digest

    if computed_digest and declared_digest != computed_digest:
        result.add_error(
            ERR_AGT_DIGEST_MISMATCH,
            AGENT_ABSTRACTION_STACK_JSON_PATH,
            "#/registryDigest",
            f"Registry digest mismatch: declared {declared_digest}, computed {computed_digest}",
        )

    expected_freeze = EXPECTED_FREEZE_DIGESTS.get(gen)
    if expected_freeze and declared_digest != expected_freeze:
        result.add_error(
            ERR_AGT_FREEZE_DIVERGENCE,
            AGENT_ABSTRACTION_STACK_JSON_PATH,
            "#/registryDigest",
            f"Registry freeze divergence: declared {declared_digest} != expected pinned baseline {expected_freeze}",
        )

    # Validate layers
    raw_layers = data.get("layers", [])
    if not isinstance(raw_layers, list):
        result.add_error(
            ERR_AGT_CORRUPT_FILE,
            AGENT_ABSTRACTION_STACK_JSON_PATH,
            "#/layers",
            "'layers' must be a list",
        )
        return result

    result.layer_count = len(raw_layers)
    seen_ids: set[str] = set()
    observed_layers: dict[str, dict[str, Any]] = {}
    observed_id_order: list[str] = []

    for idx, layer in enumerate(raw_layers):
        if not isinstance(layer, dict):
            result.add_error(
                ERR_AGT_CORRUPT_FILE,
                AGENT_ABSTRACTION_STACK_JSON_PATH,
                f"#/layers/{idx}",
                "Layer item must be a JSON object",
            )
            continue

        lid = str(layer.get("id", "")).strip()
        if not lid:
            result.add_error(
                ERR_AGT_MISSING_FIELD,
                AGENT_ABSTRACTION_STACK_JSON_PATH,
                f"#/layers/{idx}/id",
                "Layer missing mandatory 'id' field",
            )
            continue

        # Check unknown layer keys
        unknown_layer_keys = set(layer.keys()) - KNOWN_LAYER_KEYS
        for ukey in sorted(unknown_layer_keys):
            result.add_error(
                ERR_AGT_INVARIANT_VIOLATION,
                AGENT_ABSTRACTION_STACK_JSON_PATH,
                f"#/layers/{lid}/{ukey}",
                f"Unknown layer key '{ukey}' in layer '{lid}'",
            )

        if not AGT_LAYER_ID_PATTERN.match(lid):
            result.add_error(
                ERR_AGT_STABLE_ID_REUSED,
                AGENT_ABSTRACTION_STACK_JSON_PATH,
                f"#/layers/{idx}/id",
                f"Layer id '{lid}' does not conform to stable ID pattern AGT-LAYER-NNN",
            )

        if lid in seen_ids:
            result.add_error(
                ERR_AGT_STABLE_ID_REUSED,
                AGENT_ABSTRACTION_STACK_JSON_PATH,
                f"#/layers/{idx}/id",
                f"Duplicate layer ID '{lid}' detected",
            )
        seen_ids.add(lid)
        observed_layers[lid] = layer
        observed_id_order.append(lid)

        # Check mandatory layer fields
        for field_name in MANDATORY_LAYER_FIELDS:
            if field_name not in layer:
                result.add_error(
                    ERR_AGT_MISSING_FIELD,
                    AGENT_ABSTRACTION_STACK_JSON_PATH,
                    f"#/layers/{lid}/{field_name}",
                    f"Layer '{lid}' lacks mandatory field '{field_name}'",
                )
            else:
                val = layer[field_name]
                if not str(val).strip():
                    result.add_error(
                        ERR_AGT_MISSING_FIELD,
                        AGENT_ABSTRACTION_STACK_JSON_PATH,
                        f"#/layers/{lid}/{field_name}",
                        f"Layer '{lid}' field '{field_name}' must not be empty",
                    )

    # Check canonical tower ordering
    if observed_id_order != CANONICAL_TOWER_ORDER:
        result.add_error(
            ERR_AGT_REGISTRY_DRIFT,
            AGENT_ABSTRACTION_STACK_JSON_PATH,
            "#/layers",
            f"Layers do not follow canonical abstraction tower ordering: observed {observed_id_order}",
        )

    # Check against baseline layers
    for base_id, base_row in BASELINE_LAYERS.items():
        if base_id not in observed_layers:
            result.add_error(
                ERR_AGT_STABLE_ID_REUSED,
                AGENT_ABSTRACTION_STACK_JSON_PATH,
                f"#/layers/{base_id}",
                f"Baseline layer '{base_id}' missing from layers",
            )
            continue
        obs_row = observed_layers[base_id]
        for field_name in MANDATORY_LAYER_FIELDS:
            expected_val = base_row.get(field_name, "")
            actual_val = str(obs_row.get(field_name, "")).strip()
            if actual_val != expected_val:
                result.add_error(
                    ERR_AGT_REGISTRY_DRIFT,
                    AGENT_ABSTRACTION_STACK_JSON_PATH,
                    f"#/layers/{base_id}/{field_name}",
                    f"Layer '{base_id}' field '{field_name}' diverged from baseline: expected {expected_val!r}, got {actual_val!r}",
                )

    for obs_id in observed_layers:
        if obs_id not in BASELINE_LAYERS:
            result.add_error(
                ERR_AGT_STABLE_ID_REUSED,
                AGENT_ABSTRACTION_STACK_JSON_PATH,
                f"#/layers/{obs_id}",
                f"Un-baselined layer ID '{obs_id}' introduced without generation bump",
            )

    # Validate hydrationLevels
    raw_hydration = data.get("hydrationLevels", [])
    if not isinstance(raw_hydration, list):
        result.add_error(
            ERR_AGT_CORRUPT_FILE,
            AGENT_ABSTRACTION_STACK_JSON_PATH,
            "#/hydrationLevels",
            "'hydrationLevels' must be a list",
        )
        return result

    result.hydration_level_count = len(raw_hydration)
    seen_hid_ids: set[str] = set()
    observed_hydration: dict[str, dict[str, Any]] = {}
    observed_hid_order: list[str] = []

    for idx, hlevel in enumerate(raw_hydration):
        if not isinstance(hlevel, dict):
            result.add_error(
                ERR_AGT_CORRUPT_FILE,
                AGENT_ABSTRACTION_STACK_JSON_PATH,
                f"#/hydrationLevels/{idx}",
                "Hydration level item must be a JSON object",
            )
            continue

        hid = str(hlevel.get("id", "")).strip()
        if not hid:
            result.add_error(
                ERR_AGT_MISSING_FIELD,
                AGENT_ABSTRACTION_STACK_JSON_PATH,
                f"#/hydrationLevels/{idx}/id",
                "Hydration level missing mandatory 'id' field",
            )
            continue

        # Check unknown hydration keys
        unknown_hyd_keys = set(hlevel.keys()) - KNOWN_HYDRATION_KEYS
        for ukey in sorted(unknown_hyd_keys):
            result.add_error(
                ERR_AGT_INVARIANT_VIOLATION,
                AGENT_ABSTRACTION_STACK_JSON_PATH,
                f"#/hydrationLevels/{hid}/{ukey}",
                f"Unknown hydration level key '{ukey}' in hydration level '{hid}'",
            )

        if not HYDRATION_ID_PATTERN.match(hid):
            result.add_error(
                ERR_AGT_STABLE_ID_REUSED,
                AGENT_ABSTRACTION_STACK_JSON_PATH,
                f"#/hydrationLevels/{idx}/id",
                f"Hydration level id '{hid}' does not conform to stable ID pattern H0-H4",
            )

        if hid in seen_hid_ids:
            result.add_error(
                ERR_AGT_STABLE_ID_REUSED,
                AGENT_ABSTRACTION_STACK_JSON_PATH,
                f"#/hydrationLevels/{idx}/id",
                f"Duplicate hydration level ID '{hid}' detected",
            )
        seen_hid_ids.add(hid)
        observed_hydration[hid] = hlevel
        observed_hid_order.append(hid)

        # Check mandatory hydration fields
        for field_name in MANDATORY_HYDRATION_FIELDS:
            if field_name not in hlevel:
                result.add_error(
                    ERR_AGT_MISSING_FIELD,
                    AGENT_ABSTRACTION_STACK_JSON_PATH,
                    f"#/hydrationLevels/{hid}/{field_name}",
                    f"Hydration level '{hid}' lacks mandatory field '{field_name}'",
                )
            else:
                val = hlevel[field_name]
                if not str(val).strip():
                    result.add_error(
                        ERR_AGT_MISSING_FIELD,
                        AGENT_ABSTRACTION_STACK_JSON_PATH,
                        f"#/hydrationLevels/{hid}/{field_name}",
                        f"Hydration level '{hid}' field '{field_name}' must not be empty",
                    )

    # Check canonical hydration ordering
    if observed_hid_order != CANONICAL_HYDRATION_ORDER:
        result.add_error(
            ERR_AGT_REGISTRY_DRIFT,
            AGENT_ABSTRACTION_STACK_JSON_PATH,
            "#/hydrationLevels",
            f"Hydration levels do not follow canonical ladder ordering: observed {observed_hid_order}",
        )

    # Check against baseline hydration levels
    for base_hid, base_hrow in BASELINE_HYDRATION_LEVELS.items():
        if base_hid not in observed_hydration:
            result.add_error(
                ERR_AGT_STABLE_ID_REUSED,
                AGENT_ABSTRACTION_STACK_JSON_PATH,
                f"#/hydrationLevels/{base_hid}",
                f"Baseline hydration level '{base_hid}' missing from hydrationLevels",
            )
            continue
        obs_hrow = observed_hydration[base_hid]
        for field_name in MANDATORY_HYDRATION_FIELDS:
            expected_val = base_hrow.get(field_name, "")
            actual_val = str(obs_hrow.get(field_name, "")).strip()
            if actual_val != expected_val:
                result.add_error(
                    ERR_AGT_REGISTRY_DRIFT,
                    AGENT_ABSTRACTION_STACK_JSON_PATH,
                    f"#/hydrationLevels/{base_hid}/{field_name}",
                    f"Hydration level '{base_hid}' field '{field_name}' diverged from baseline: expected {expected_val!r}, got {actual_val!r}",
                )

    for obs_hid in observed_hydration:
        if obs_hid not in BASELINE_HYDRATION_LEVELS:
            result.add_error(
                ERR_AGT_STABLE_ID_REUSED,
                AGENT_ABSTRACTION_STACK_JSON_PATH,
                f"#/hydrationLevels/{obs_hid}",
                f"Un-baselined hydration level ID '{obs_hid}' introduced without generation bump",
            )

    # Validate against Markdown mirror
    try:
        md_gen, md_digest, md_rows, md_hydration_rows, md_dup_layers, md_dup_hydration, md_misplaced_hydration = (
            extract_markdown_metadata_and_abstractions(md_path)
        )
    except Exception as exc:
        result.add_error(
            ERR_AGT_CORRUPT_FILE,
            AGENT_ABSTRACTIONS_MD_PATH,
            "#",
            f"Failed to parse Markdown agent abstractions: {exc}",
        )
        return result

    for mis_hid in md_misplaced_hydration:
        result.add_error(
            ERR_AGT_REGISTRY_DRIFT,
            AGENT_ABSTRACTIONS_MD_PATH,
            f"#{mis_hid}",
            f"Hydration level '{mis_hid}' found outside '## Hydration ladder' section in markdown mirror",
        )

    for dup_lid in md_dup_layers:
        result.add_error(
            ERR_AGT_STABLE_ID_REUSED,
            AGENT_ABSTRACTIONS_MD_PATH,
            f"#{dup_lid}",
            f"Duplicate layer ID '{dup_lid}' detected in markdown mirror",
        )

    for dup_hid in md_dup_hydration:
        result.add_error(
            ERR_AGT_STABLE_ID_REUSED,
            AGENT_ABSTRACTIONS_MD_PATH,
            f"#{dup_hid}",
            f"Duplicate hydration level ID '{dup_hid}' detected in markdown mirror",
        )

    if not md_gen:
        result.add_error(
            ERR_AGT_MISSING_FIELD,
            AGENT_ABSTRACTIONS_MD_PATH,
            "#generation",
            "Missing or empty 'Generation:' line in markdown mirror",
        )
    elif md_gen != gen:
        result.add_error(
            ERR_AGT_GENERATION_MISMATCH,
            AGENT_ABSTRACTIONS_MD_PATH,
            "#generation",
            f"Markdown mirror generation '{md_gen}' diverged from JSON generation '{gen}'",
        )

    if not md_digest:
        result.add_error(
            ERR_AGT_MISSING_FIELD,
            AGENT_ABSTRACTIONS_MD_PATH,
            "#registryDigest",
            "Missing or empty 'Registry digest:' line in markdown mirror",
        )
    elif md_digest != declared_digest:
        result.add_error(
            ERR_AGT_DIGEST_MISMATCH,
            AGENT_ABSTRACTIONS_MD_PATH,
            "#registryDigest",
            f"Markdown mirror digest '{md_digest}' diverged from JSON digest '{declared_digest}'",
        )

    # Validate hydration levels against Markdown mirror
    for hid, obs_hrow in observed_hydration.items():
        if hid not in md_hydration_rows:
            result.add_error(
                ERR_AGT_REGISTRY_DRIFT,
                AGENT_ABSTRACTIONS_MD_PATH,
                f"#{hid}",
                f"Hydration level '{hid}' in architecture JSON missing from Markdown mirror",
            )
            continue
        md_hname, md_hcontent = md_hydration_rows[hid]
        obs_hname = str(obs_hrow.get("name", "")).strip()
        obs_hcontent = str(obs_hrow.get("content", "")).strip()

        if obs_hname != md_hname:
            result.add_error(
                ERR_AGT_REGISTRY_DRIFT,
                AGENT_ABSTRACTION_STACK_JSON_PATH,
                f"#/hydrationLevels/{hid}/name",
                f"Hydration level '{hid}' name mismatch: JSON has '{obs_hname}', Markdown has '{md_hname}'",
            )
        if obs_hcontent != md_hcontent:
            result.add_error(
                ERR_AGT_REGISTRY_DRIFT,
                AGENT_ABSTRACTION_STACK_JSON_PATH,
                f"#/hydrationLevels/{hid}/content",
                f"Hydration level '{hid}' content mismatch: JSON has '{obs_hcontent}', Markdown has '{md_hcontent}'",
            )

    for md_hid in md_hydration_rows:
        if md_hid not in observed_hydration:
            result.add_error(
                ERR_AGT_REGISTRY_DRIFT,
                AGENT_ABSTRACTION_STACK_JSON_PATH,
                f"#/hydrationLevels/{md_hid}",
                f"Hydration level '{md_hid}' in Markdown mirror missing from architecture JSON",
            )

    for lid, obs_row in observed_layers.items():
        if lid not in md_rows:
            result.add_error(
                ERR_AGT_REGISTRY_DRIFT,
                AGENT_ABSTRACTIONS_MD_PATH,
                f"#{lid}",
                f"Layer '{lid}' in architecture JSON missing from Markdown mirror",
            )
            continue
        md_name, md_owner, md_question, md_inv, md_status = md_rows[lid]
        obs_name = str(obs_row.get("name", "")).strip()
        obs_owner = str(obs_row.get("owner", "")).strip()
        obs_question = str(obs_row.get("question", "")).strip()
        obs_inv = str(obs_row.get("invariant", "")).strip()
        obs_status = str(obs_row.get("status", "")).strip()

        if obs_name != md_name:
            result.add_error(
                ERR_AGT_REGISTRY_DRIFT,
                AGENT_ABSTRACTION_STACK_JSON_PATH,
                f"#/layers/{lid}/name",
                f"Layer '{lid}' name mismatch: JSON has '{obs_name}', Markdown has '{md_name}'",
            )
        if obs_owner != md_owner:
            result.add_error(
                ERR_AGT_REGISTRY_DRIFT,
                AGENT_ABSTRACTION_STACK_JSON_PATH,
                f"#/layers/{lid}/owner",
                f"Layer '{lid}' owner mismatch: JSON has '{obs_owner}', Markdown has '{md_owner}'",
            )
        if obs_question != md_question:
            result.add_error(
                ERR_AGT_REGISTRY_DRIFT,
                AGENT_ABSTRACTION_STACK_JSON_PATH,
                f"#/layers/{lid}/question",
                f"Layer '{lid}' question mismatch: JSON has '{obs_question}', Markdown has '{md_question}'",
            )
        if obs_inv != md_inv:
            result.add_error(
                ERR_AGT_REGISTRY_DRIFT,
                AGENT_ABSTRACTION_STACK_JSON_PATH,
                f"#/layers/{lid}/invariant",
                f"Layer '{lid}' invariant mismatch: JSON has '{obs_inv}', Markdown has '{md_inv}'",
            )
        if obs_status != md_status:
            result.add_error(
                ERR_AGT_REGISTRY_DRIFT,
                AGENT_ABSTRACTION_STACK_JSON_PATH,
                f"#/layers/{lid}/status",
                f"Layer '{lid}' status mismatch: JSON has '{obs_status}', Markdown has '{md_status}'",
            )

    for md_id in md_rows:
        if md_id not in observed_layers:
            result.add_error(
                ERR_AGT_REGISTRY_DRIFT,
                AGENT_ABSTRACTION_STACK_JSON_PATH,
                f"#/layers/{md_id}",
                f"Layer '{md_id}' in Markdown mirror missing from architecture JSON",
            )

    # Semantic Invariant Enforcement for AGT-LAYER-001 (fss-x4a.30.82.1)
    # 1. Runtime authority and custody (AGT-LAYER-001) must have invariant INV-006.
    # 2. Prohibition MUST state: "Cannot infer mission meaning or physical truth."
    # 3. Status MUST be "normative".
    # 4. Owner MUST reference asupersync and authority.
    # 5. Question MUST be: "What work, authority, budget, identity, time, and object custody exist?"
    # 6. Output MUST be: "Context, grants, regions, obligations, object roots, and receipts."
    layer_001 = observed_layers.get("AGT-LAYER-001")
    if layer_001:
        inv = str(layer_001.get("invariant", "")).strip()
        if inv != "INV-006":
            result.add_error(
                ERR_AGT_INVARIANT_VIOLATION,
                AGENT_ABSTRACTION_STACK_JSON_PATH,
                "#/layers/AGT-LAYER-001/invariant",
                f"AGT-LAYER-001 invariant must be INV-006, got '{inv}'",
            )
        prohibition = str(layer_001.get("prohibition", "")).strip()
        if prohibition != "Cannot infer mission meaning or physical truth.":
            result.add_error(
                ERR_AGT_INVARIANT_VIOLATION,
                AGENT_ABSTRACTION_STACK_JSON_PATH,
                "#/layers/AGT-LAYER-001/prohibition",
                f"AGT-LAYER-001 prohibition must be 'Cannot infer mission meaning or physical truth.', got '{prohibition}'",
            )
        status = str(layer_001.get("status", "")).strip()
        if status != "normative":
            result.add_error(
                ERR_AGT_INVARIANT_VIOLATION,
                AGENT_ABSTRACTION_STACK_JSON_PATH,
                "#/layers/AGT-LAYER-001/status",
                f"AGT-LAYER-001 status must be 'normative', got '{status}'",
            )
        owner = str(layer_001.get("owner", "")).strip()
        if owner != "asupersync/authority/object owners":
            result.add_error(
                ERR_AGT_INVARIANT_VIOLATION,
                AGENT_ABSTRACTION_STACK_JSON_PATH,
                "#/layers/AGT-LAYER-001/owner",
                f"AGT-LAYER-001 owner must be 'asupersync/authority/object owners', got '{owner}'",
            )
        question = str(layer_001.get("question", "")).strip()
        if question != "What work, authority, budget, identity, time, and object custody exist?":
            result.add_error(
                ERR_AGT_INVARIANT_VIOLATION,
                AGENT_ABSTRACTION_STACK_JSON_PATH,
                "#/layers/AGT-LAYER-001/question",
                f"AGT-LAYER-001 question mismatch: got '{question}'",
            )
        out = str(layer_001.get("output", "")).strip()
        if out != "Context, grants, regions, obligations, object roots, and receipts.":
            result.add_error(
                ERR_AGT_INVARIANT_VIOLATION,
                AGENT_ABSTRACTION_STACK_JSON_PATH,
                "#/layers/AGT-LAYER-001/output",
                f"AGT-LAYER-001 output mismatch: got '{out}'",
            )

    # Semantic Invariant Enforcement for AGT-LAYER-002: source_evidence (fss-x4a.30.82.2)
    # 1. Source evidence (AGT-LAYER-002) must have invariant INV-003.
    # 2. Prohibition MUST state: "Cannot promote decode or model output into source evidence."
    # 3. Status MUST be "normative".
    # 4. Owner MUST be "fss-capture/fss-media/fss-chronicle".
    # 5. Question MUST be: "What exact packets, files, measurements, continuity, and capture-time intervals exist?"
    # 6. Output MUST be: "Immutable sensor capsules, source objects, continuity and time evidence."
    layer_002 = observed_layers.get("AGT-LAYER-002")
    if layer_002:
        inv = str(layer_002.get("invariant", "")).strip()
        if inv != "INV-003":
            result.add_error(
                ERR_AGT_INVARIANT_VIOLATION,
                AGENT_ABSTRACTION_STACK_JSON_PATH,
                "#/layers/AGT-LAYER-002/invariant",
                f"AGT-LAYER-002 invariant must be INV-003, got '{inv}'",
            )
        prohibition = str(layer_002.get("prohibition", "")).strip()
        if prohibition != "Cannot promote decode or model output into source evidence.":
            result.add_error(
                ERR_AGT_INVARIANT_VIOLATION,
                AGENT_ABSTRACTION_STACK_JSON_PATH,
                "#/layers/AGT-LAYER-002/prohibition",
                f"AGT-LAYER-002 prohibition must be 'Cannot promote decode or model output into source evidence.', got '{prohibition}'",
            )
        status = str(layer_002.get("status", "")).strip()
        if status != "normative":
            result.add_error(
                ERR_AGT_INVARIANT_VIOLATION,
                AGENT_ABSTRACTION_STACK_JSON_PATH,
                "#/layers/AGT-LAYER-002/status",
                f"AGT-LAYER-002 status must be 'normative', got '{status}'",
            )
        owner = str(layer_002.get("owner", "")).strip()
        if owner != "fss-capture/fss-media/fss-chronicle":
            result.add_error(
                ERR_AGT_INVARIANT_VIOLATION,
                AGENT_ABSTRACTION_STACK_JSON_PATH,
                "#/layers/AGT-LAYER-002/owner",
                f"AGT-LAYER-002 owner must be 'fss-capture/fss-media/fss-chronicle', got '{owner}'",
            )
        question = str(layer_002.get("question", "")).strip()
        if question != "What exact packets, files, measurements, continuity, and capture-time intervals exist?":
            result.add_error(
                ERR_AGT_INVARIANT_VIOLATION,
                AGENT_ABSTRACTION_STACK_JSON_PATH,
                "#/layers/AGT-LAYER-002/question",
                f"AGT-LAYER-002 question mismatch: got '{question}'",
            )
        out = str(layer_002.get("output", "")).strip()
        if out != "Immutable sensor capsules, source objects, continuity and time evidence.":
            result.add_error(
                ERR_AGT_INVARIANT_VIOLATION,
                AGENT_ABSTRACTION_STACK_JSON_PATH,
                "#/layers/AGT-LAYER-002/output",
                f"AGT-LAYER-002 output mismatch: got '{out}'",
            )

    # Semantic Invariant Enforcement for AGT-LAYER-003 (fss-x4a.30.82.3)
    # 1. World facts and coverage (AGT-LAYER-003) must have invariant INV-063.
    # 2. Prohibition MUST state: "Cannot include unqualified cognition as fact."
    # 3. Status MUST be "normative".
    # 4. Owner MUST be "fss-chronicle/fss-coverage".
    # 5. Question MUST be: "What did the system authoritatively observe or do at one anchor?"
    # 6. Output MUST be: "Device, geometry, calibration, coverage, policy, archive, and effect facts."
    # 7. Prohibition check: must strictly forbid unqualified cognition as fact.
    # 8. Output check: must not include speculative cognition or derived beliefs.
    layer_003 = observed_layers.get("AGT-LAYER-003")
    if layer_003:
        inv = str(layer_003.get("invariant", "")).strip()
        if inv != "INV-063":
            result.add_error(
                ERR_AGT_INVARIANT_VIOLATION,
                AGENT_ABSTRACTION_STACK_JSON_PATH,
                "#/layers/AGT-LAYER-003/invariant",
                f"AGT-LAYER-003 invariant must be INV-063, got '{inv}'",
            )
        prohibition = str(layer_003.get("prohibition", "")).strip()
        if prohibition != "Cannot include unqualified cognition as fact.":
            result.add_error(
                ERR_AGT_INVARIANT_VIOLATION,
                AGENT_ABSTRACTION_STACK_JSON_PATH,
                "#/layers/AGT-LAYER-003/prohibition",
                f"AGT-LAYER-003 prohibition must be 'Cannot include unqualified cognition as fact.', got '{prohibition}'",
            )
        status = str(layer_003.get("status", "")).strip()
        if status != "normative":
            result.add_error(
                ERR_AGT_INVARIANT_VIOLATION,
                AGENT_ABSTRACTION_STACK_JSON_PATH,
                "#/layers/AGT-LAYER-003/status",
                f"AGT-LAYER-003 status must be 'normative', got '{status}'",
            )
        owner = str(layer_003.get("owner", "")).strip()
        if owner != "fss-chronicle/fss-coverage":
            result.add_error(
                ERR_AGT_INVARIANT_VIOLATION,
                AGENT_ABSTRACTION_STACK_JSON_PATH,
                "#/layers/AGT-LAYER-003/owner",
                f"AGT-LAYER-003 owner must be 'fss-chronicle/fss-coverage', got '{owner}'",
            )
        question = str(layer_003.get("question", "")).strip()
        if question != "What did the system authoritatively observe or do at one anchor?":
            result.add_error(
                ERR_AGT_INVARIANT_VIOLATION,
                AGENT_ABSTRACTION_STACK_JSON_PATH,
                "#/layers/AGT-LAYER-003/question",
                f"AGT-LAYER-003 question mismatch: got '{question}'",
            )
        out = str(layer_003.get("output", "")).strip()
        if out != "Device, geometry, calibration, coverage, policy, archive, and effect facts.":
            result.add_error(
                ERR_AGT_INVARIANT_VIOLATION,
                AGENT_ABSTRACTION_STACK_JSON_PATH,
                "#/layers/AGT-LAYER-003/output",
                f"AGT-LAYER-003 output mismatch: got '{out}'",
            )
        out_lower = out.lower()
        if "cognition" in out_lower or "belief" in out_lower:
            result.add_error(
                ERR_AGT_INVARIANT_VIOLATION,
                AGENT_ABSTRACTION_STACK_JSON_PATH,
                "#/layers/AGT-LAYER-003/output",
                f"AGT-LAYER-003 output illegally includes cognition/beliefs: '{out}'",
            )

    # Semantic Invariant Enforcement (fss-x4a.30.82.4)
    # 1. Derived beliefs (AGT-LAYER-004) must belong to cognition plane, NOT authority plane.
    # 2. Derived beliefs prohibition MUST state: "Cannot authorize effects or certify absence beyond coverage."
    # 3. Derived beliefs invariant MUST be INV-069.
    # 4. Derived beliefs owner MUST be fss-perception/fss-association/fss-graph.
    # 5. Non-authority layers (AGT-LAYER-004 .. AGT-LAYER-011) must never claim authority ownership.
    layer_004 = observed_layers.get("AGT-LAYER-004")
    if layer_004:
        inv = str(layer_004.get("invariant", "")).strip()
        if inv != "INV-069":
            result.add_error(
                ERR_AGT_INVARIANT_VIOLATION,
                AGENT_ABSTRACTION_STACK_JSON_PATH,
                "#/layers/AGT-LAYER-004/invariant",
                f"AGT-LAYER-004 invariant must be INV-069, got '{inv}'",
            )
        prohibition = str(layer_004.get("prohibition", "")).strip()
        if prohibition != "Cannot authorize effects or certify absence beyond coverage.":
            result.add_error(
                ERR_AGT_ILLEGAL_AUTHORITY,
                AGENT_ABSTRACTION_STACK_JSON_PATH,
                "#/layers/AGT-LAYER-004/prohibition",
                f"AGT-LAYER-004 prohibition must forbid authorizing effects and absence certification beyond coverage, got '{prohibition}'",
            )
        status = str(layer_004.get("status", "")).strip()
        if status != "normative":
            result.add_error(
                ERR_AGT_INVARIANT_VIOLATION,
                AGENT_ABSTRACTION_STACK_JSON_PATH,
                "#/layers/AGT-LAYER-004/status",
                f"AGT-LAYER-004 status must be 'normative', got '{status}'",
            )
        owner = str(layer_004.get("owner", "")).strip()
        if owner != "fss-perception/fss-association/fss-graph":
            result.add_error(
                ERR_AGT_ILLEGAL_AUTHORITY,
                AGENT_ABSTRACTION_STACK_JSON_PATH,
                "#/layers/AGT-LAYER-004/owner",
                f"AGT-LAYER-004 owner must be 'fss-perception/fss-association/fss-graph', got '{owner}'",
            )
        if "authority" in owner.lower():
            result.add_error(
                ERR_AGT_ILLEGAL_AUTHORITY,
                AGENT_ABSTRACTION_STACK_JSON_PATH,
                "#/layers/AGT-LAYER-004/owner",
                f"AGT-LAYER-004 derived beliefs cannot be owned by authority plane: '{owner}'",
            )
        question = str(layer_004.get("question", "")).strip()
        if question != "What entities, tracks, events, relations, and uncertainties are supported?":
            result.add_error(
                ERR_AGT_INVARIANT_VIOLATION,
                AGENT_ABSTRACTION_STACK_JSON_PATH,
                "#/layers/AGT-LAYER-004/question",
                f"AGT-LAYER-004 question mismatch: got '{question}'",
            )
        out = str(layer_004.get("output", "")).strip()
        if out != "Generation-pinned derived beliefs and graph/search projections with receipts.":
            result.add_error(
                ERR_AGT_INVARIANT_VIOLATION,
                AGENT_ABSTRACTION_STACK_JSON_PATH,
                "#/layers/AGT-LAYER-004/output",
                f"AGT-LAYER-004 output mismatch: got '{out}'",
            )

    # Non-authority layers must not claim authority
    for lid in CANONICAL_TOWER_ORDER[3:]:
        row = observed_layers.get(lid)
        if not row:
            continue
        row_output = str(row.get("output", "")).lower()
        if "authorizes effects" in row_output or "grant authority" in row_output:
            result.add_error(
                ERR_AGT_ILLEGAL_AUTHORITY,
                AGENT_ABSTRACTION_STACK_JSON_PATH,
                f"#/layers/{lid}/output",
                f"Non-authority layer '{lid}' output claims authority or effect authorization: '{row.get('output')}'",
            )

    # Semantic Invariant Enforcement for AGT-LAYER-005: situation_capsule (fss-x4a.30.82.5)
    # 1. Situation capsule (AGT-LAYER-005) must have invariant INV-116.
    # 2. Prohibition MUST state: "Cannot hide decision-changing omissions or rebase evidence identities."
    # 3. Status MUST be "normative".
    # 4. Owner MUST be "fss-situation/fss-context-pack/fss-affordance".
    # 5. Question MUST be: "What is the smallest sufficient mission-relative driver view now, what changed, and what can safely be done next?"
    # 6. Output MUST be: "SituationCapsule containing SituationFrame with WorldEnvelope, MeaningfulDelta, obligations, resource state, categorized control envelope, ContextPack, compression proof, and affordance frontier."
    # 7. Prohibition check: must strictly forbid hiding decision-changing omissions and rebasing evidence identities.
    # 8. Output check: must include SituationCapsule, SituationFrame, WorldEnvelope, and affordance frontier.
    # 9. Cognition plane check: owner must not claim authority plane.
    layer_005 = observed_layers.get("AGT-LAYER-005")
    if layer_005:
        inv = str(layer_005.get("invariant", "")).strip()
        if inv != "INV-116":
            result.add_error(
                ERR_AGT_INVARIANT_VIOLATION,
                AGENT_ABSTRACTION_STACK_JSON_PATH,
                "#/layers/AGT-LAYER-005/invariant",
                f"AGT-LAYER-005 invariant must be INV-116, got '{inv}'",
            )
        prohibition = str(layer_005.get("prohibition", "")).strip()
        if prohibition != "Cannot hide decision-changing omissions or rebase evidence identities.":
            result.add_error(
                ERR_AGT_INVARIANT_VIOLATION,
                AGENT_ABSTRACTION_STACK_JSON_PATH,
                "#/layers/AGT-LAYER-005/prohibition",
                f"AGT-LAYER-005 prohibition must forbid hiding decision-changing omissions and rebasing evidence identities, got '{prohibition}'",
            )
        status = str(layer_005.get("status", "")).strip()
        if status != "normative":
            result.add_error(
                ERR_AGT_INVARIANT_VIOLATION,
                AGENT_ABSTRACTION_STACK_JSON_PATH,
                "#/layers/AGT-LAYER-005/status",
                f"AGT-LAYER-005 status must be 'normative', got '{status}'",
            )
        owner = str(layer_005.get("owner", "")).strip()
        if owner != "fss-situation/fss-context-pack/fss-affordance":
            result.add_error(
                ERR_AGT_INVARIANT_VIOLATION,
                AGENT_ABSTRACTION_STACK_JSON_PATH,
                "#/layers/AGT-LAYER-005/owner",
                f"AGT-LAYER-005 owner must be 'fss-situation/fss-context-pack/fss-affordance', got '{owner}'",
            )
        if "authority" in owner.lower():
            result.add_error(
                ERR_AGT_ILLEGAL_AUTHORITY,
                AGENT_ABSTRACTION_STACK_JSON_PATH,
                "#/layers/AGT-LAYER-005/owner",
                f"AGT-LAYER-005 situation capsule cannot be owned by authority plane: '{owner}'",
            )
        question = str(layer_005.get("question", "")).strip()
        if question != "What is the smallest sufficient mission-relative driver view now, what changed, and what can safely be done next?":
            result.add_error(
                ERR_AGT_INVARIANT_VIOLATION,
                AGENT_ABSTRACTION_STACK_JSON_PATH,
                "#/layers/AGT-LAYER-005/question",
                f"AGT-LAYER-005 question mismatch: got '{question}'",
            )
        out = str(layer_005.get("output", "")).strip()
        expected_output = "SituationCapsule containing SituationFrame with WorldEnvelope, MeaningfulDelta, obligations, resource state, categorized control envelope, ContextPack, compression proof, and affordance frontier."
        if out != expected_output:
            result.add_error(
                ERR_AGT_INVARIANT_VIOLATION,
                AGENT_ABSTRACTION_STACK_JSON_PATH,
                "#/layers/AGT-LAYER-005/output",
                f"AGT-LAYER-005 output mismatch: expected '{expected_output}', got '{out}'",
            )
        out_lower = out.lower()
        if "authorizes effects" in out_lower or "grant authority" in out_lower:
            result.add_error(
                ERR_AGT_ILLEGAL_AUTHORITY,
                AGENT_ABSTRACTION_STACK_JSON_PATH,
                "#/layers/AGT-LAYER-005/output",
                f"AGT-LAYER-005 output cannot claim effect authorization or grant authority: '{out}'",
            )
        if (
            "situationcapsule" not in out_lower
            or "situationframe" not in out_lower
            or "worldenvelope" not in out_lower
            or "affordance frontier" not in out_lower
        ):
            result.add_error(
                ERR_AGT_INVARIANT_VIOLATION,
                AGENT_ABSTRACTION_STACK_JSON_PATH,
                "#/layers/AGT-LAYER-005/output",
                f"AGT-LAYER-005 output must declare SituationCapsule, SituationFrame, WorldEnvelope, and affordance frontier: '{out}'",
            )

    # Semantic Invariant Enforcement for AGT-LAYER-006: investigation_and_hypotheses (fss-x4a.30.82.6)
    # 1. Investigation and hypotheses (AGT-LAYER-006) must have invariant INV-104.
    # 2. Prohibition MUST state: "Cannot collapse uncertainty into truth without adjudication."
    # 3. Status MUST be "normative".
    # 4. Owner MUST be "fss-investigation".
    # 5. Question MUST be: "Which competing explanations remain viable and how can they be discriminated?"
    # 6. Output MUST be: "Case revision, hypotheses, support, contradictions, predicted observations, falsifiers, and stop rule."
    # 7. Prohibition check: must strictly forbid collapsing uncertainty into truth without adjudication.
    # 8. Output check: must not claim authority or effect authorization.
    layer_006 = observed_layers.get("AGT-LAYER-006")
    if layer_006:
        inv = str(layer_006.get("invariant", "")).strip()
        if inv != "INV-104":
            result.add_error(
                ERR_AGT_INVARIANT_VIOLATION,
                AGENT_ABSTRACTION_STACK_JSON_PATH,
                "#/layers/AGT-LAYER-006/invariant",
                f"AGT-LAYER-006 invariant must be INV-104, got '{inv}'",
            )
        prohibition = str(layer_006.get("prohibition", "")).strip()
        if prohibition != "Cannot collapse uncertainty into truth without adjudication.":
            result.add_error(
                ERR_AGT_INVARIANT_VIOLATION,
                AGENT_ABSTRACTION_STACK_JSON_PATH,
                "#/layers/AGT-LAYER-006/prohibition",
                f"AGT-LAYER-006 prohibition must be 'Cannot collapse uncertainty into truth without adjudication.', got '{prohibition}'",
            )
        status = str(layer_006.get("status", "")).strip()
        if status != "normative":
            result.add_error(
                ERR_AGT_INVARIANT_VIOLATION,
                AGENT_ABSTRACTION_STACK_JSON_PATH,
                "#/layers/AGT-LAYER-006/status",
                f"AGT-LAYER-006 status must be 'normative', got '{status}'",
            )
        owner = str(layer_006.get("owner", "")).strip()
        if owner != "fss-investigation":
            result.add_error(
                ERR_AGT_INVARIANT_VIOLATION,
                AGENT_ABSTRACTION_STACK_JSON_PATH,
                "#/layers/AGT-LAYER-006/owner",
                f"AGT-LAYER-006 owner must be 'fss-investigation', got '{owner}'",
            )
        if "authority" in owner.lower():
            result.add_error(
                ERR_AGT_ILLEGAL_AUTHORITY,
                AGENT_ABSTRACTION_STACK_JSON_PATH,
                "#/layers/AGT-LAYER-006/owner",
                f"AGT-LAYER-006 investigation cannot be owned by authority plane: '{owner}'",
            )
        question = str(layer_006.get("question", "")).strip()
        if question != "Which competing explanations remain viable and how can they be discriminated?":
            result.add_error(
                ERR_AGT_INVARIANT_VIOLATION,
                AGENT_ABSTRACTION_STACK_JSON_PATH,
                "#/layers/AGT-LAYER-006/question",
                f"AGT-LAYER-006 question mismatch: got '{question}'",
            )
        out = str(layer_006.get("output", "")).strip()
        expected_output_006 = "Case revision, hypotheses, support, contradictions, predicted observations, falsifiers, and stop rule."
        if out != expected_output_006:
            result.add_error(
                ERR_AGT_INVARIANT_VIOLATION,
                AGENT_ABSTRACTION_STACK_JSON_PATH,
                "#/layers/AGT-LAYER-006/output",
                f"AGT-LAYER-006 output mismatch: expected '{expected_output_006}', got '{out}'",
            )
        out_lower = out.lower()
        if "authorizes effects" in out_lower or "grant authority" in out_lower:
            result.add_error(
                ERR_AGT_ILLEGAL_AUTHORITY,
                AGENT_ABSTRACTION_STACK_JSON_PATH,
                "#/layers/AGT-LAYER-006/output",
                f"AGT-LAYER-006 output cannot claim effect authorization or grant authority: '{out}'",
            )
        if (
            "hypotheses" not in out_lower
            or "support" not in out_lower
            or "contradictions" not in out_lower
            or "falsifiers" not in out_lower
            or "stop rule" not in out_lower
        ):
            result.add_error(
                ERR_AGT_INVARIANT_VIOLATION,
                AGENT_ABSTRACTION_STACK_JSON_PATH,
                "#/layers/AGT-LAYER-006/output",
                f"AGT-LAYER-006 output must declare hypotheses, support, contradictions, falsifiers, and stop rule: '{out}'",
            )

    # Semantic Invariant Enforcement for H0: identity (fss-x4a.30.82.12)
    # 1. Level ID must be H0.
    # 2. Name must be identity.
    # 3. Content MUST contain: digest, type, time/spatial bounds, source, availability, cost, and authority.
    # 4. Content elements check: all seven dimensions must be explicitly declared.
    # 5. Content prohibition check: must NOT allow raw payload bytes, decoded media, or ungrounded cognition.
    h0_row = observed_hydration.get("H0")
    if h0_row:
        h0_name = str(h0_row.get("name", "")).strip()
        if h0_name != "identity":
            result.add_error(
                ERR_AGT_INVARIANT_VIOLATION,
                AGENT_ABSTRACTION_STACK_JSON_PATH,
                "#/hydrationLevels/H0/name",
                f"H0 name must be 'identity', got '{h0_name}'",
            )
        h0_content = str(h0_row.get("content", "")).strip()
        expected_content = "digest, type, time/spatial bounds, source, availability, cost, and authority"
        if h0_content != expected_content:
            result.add_error(
                ERR_AGT_INVARIANT_VIOLATION,
                AGENT_ABSTRACTION_STACK_JSON_PATH,
                "#/hydrationLevels/H0/content",
                f"H0 content mismatch: expected '{expected_content}', got '{h0_content}'",
            )
        # Required elements check
        required_elements = ("digest", "type", "source", "availability", "cost", "authority")
        for req in required_elements:
            if req not in h0_content.lower():
                result.add_error(
                    ERR_AGT_INVARIANT_VIOLATION,
                    AGENT_ABSTRACTION_STACK_JSON_PATH,
                    "#/hydrationLevels/H0/content",
                    f"H0 content missing mandatory dimension '{req}': '{h0_content}'",
                )
        if "time" not in h0_content.lower() and "spatial" not in h0_content.lower():
            result.add_error(
                ERR_AGT_INVARIANT_VIOLATION,
                AGENT_ABSTRACTION_STACK_JSON_PATH,
                "#/hydrationLevels/H0/content",
                f"H0 content missing time/spatial bounds dimension: '{h0_content}'",
            )
        # Prohibition check: raw payloads, decodes, unredacted media strictly forbidden at H0
        prohibited_terms = ("raw packet", "raw byte", "decoded", "unredacted", "full-resolution")
        for term in prohibited_terms:
            if term in h0_content.lower():
                result.add_error(
                    ERR_AGT_INVARIANT_VIOLATION,
                    AGENT_ABSTRACTION_STACK_JSON_PATH,
                    "#/hydrationLevels/H0/content",
                    f"H0 content illegally permits raw/decoded data ('{term}'): '{h0_content}'",
                )

    return result


def main() -> int:
    parser = argparse.ArgumentParser(description="Validate agent abstraction stack registry")
    parser.add_argument("--json", action="store_true", help="Output findings in JSON format")
    parser.add_argument("--check-clean", action="store_true", help="Fail if any warning/drift detected")
    args = parser.parse_args()

    result = validate_agent_abstraction_registry(ROOT)

    if args.json:
        payload = {
            "passed": result.passed,
            "layer_count": result.layer_count,
            "hydration_level_count": result.hydration_level_count,
            "registry_digest": result.registry_digest,
            "errors": [asdict(e) for e in result.errors],
        }
        print(json.dumps(payload, indent=2))
    else:
        if result.passed:
            print(
                f"[PASS] Agent abstraction stack validated: {result.layer_count} layers, {result.hydration_level_count} hydration levels, digest {result.registry_digest}"
            )
        else:
            print(f"[FAIL] Agent abstraction stack validation failed with {len(result.errors)} error(s):")
            for err in result.errors:
                print(f"  [{err.code}] {err.file_path} ({err.target}): {err.message}")

    return 0 if result.passed else 1


if __name__ == "__main__":
    sys.exit(main())
