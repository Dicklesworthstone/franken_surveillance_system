#!/usr/bin/env python3
"""Fail-closed device adapter registry checker (fss-x4a.30.89.1).

Enforces the device adapter registry contract and SWARM RULE:
1. Pinned expected canonical freeze digest per generation.
2. Canonical digest covering all row fields and top-level metadata.
3. Mandatory generation bump on any content change.
4. Stable IDs checked against pinned baseline (no renumbering, reuse, or resurrection).
5. Semantic invariants enforced (valid tiers, valid gates, NEG-002 constraints).
6. 1:1 mirror equality with registries/DEVICE_ADAPTERS.md.
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
ERR_ADAPTER_REGISTRY_DRIFT = "ERR-ADAPTER-REGISTRY-DRIFT-001"
ERR_ADAPTER_STABLE_ID_REUSED = "ERR-ADAPTER-STABLE-ID-REUSED-001"
ERR_ADAPTER_SEMANTIC_INVARIANT = "ERR-ADAPTER-SEMANTIC-INVARIANT-001"
ERR_ADAPTER_CORRUPT_FILE = "ERR-ADAPTER-CORRUPT-FILE-001"
ERR_ADAPTER_DIGEST_MISMATCH = "ERR-ADAPTER-DIGEST-MISMATCH-001"
ERR_ADAPTER_GENERATION_MISMATCH = "ERR-ADAPTER-GENERATION-MISMATCH-001"
ERR_ADAPTER_INVALID_TIER = "ERR-ADAPTER-INVALID-TIER-001"
ERR_ADAPTER_REPLAY_DIVERGED = "ERR-ADAPTER-REPLAY-DIVERGED-001"

DEVICE_ADAPTERS_JSON_PATH = "architecture/device_adapters.json"
DEVICE_ADAPTERS_MD_PATH = "registries/DEVICE_ADAPTERS.md"

CURRENT_GENERATION = "gen:fss1:adapters-v1"
SCHEMA_DEVICE_ADAPTERS_V1 = "fss.device_adapters.v1"
SEMANTIC_PROTOCOL_V1 = "fss/1"

ALLOWED_TOP_LEVEL_KEYS = {
    "schema",
    "asOf",
    "semanticProtocol",
    "generation",
    "registryDigest",
    "adapters",
    "tombstones",
}

ALLOWED_ROW_KEYS = {
    "id",
    "surface",
    "tier",
    "currentState",
    "promotionGate",
    "generation",
}

ALLOWED_TOMBSTONE_KEYS = {"id"}

# Expected canonical freeze digests pinned per registry generation (SWARM RULE)
EXPECTED_FREEZE_DIGESTS: dict[str, str] = {
    "gen:fss1:adapters-v1": "sha256:475127cbcbdff684e7f778ab25b1c7883cfdddafd6bf07f881da50c4f4cf0ff9",
}

VALID_TIERS = {"T0", "T0/T4", "T1", "T2", "T3", "T3/T4", "T4"}
GATE_PATTERN = re.compile(r"^GATE-\d{3}$")

REQUIRED_ROW_FIELDS = (
    "id",
    "surface",
    "tier",
    "currentState",
    "promotionGate",
    "generation",
)

BASELINE_ADAPTERS: dict[str, dict[str, str]] = {
    "ADP-AOSU-P1MAX-LAB-001": {
        "currentState": "research target",
        "generation": "gen:fss1:adapters-v1",
        "id": "ADP-AOSU-P1MAX-LAB-001",
        "promotionGate": "GATE-090",
        "surface": "AOSU P1 Max owner-auth lab",
        "tier": "T3",
    },
    "ADP-DJI-FLIP-LAB-001": {
        "currentState": "research target",
        "generation": "gen:fss1:adapters-v1",
        "id": "ADP-DJI-FLIP-LAB-001",
        "promotionGate": "GATE-100",
        "surface": "DJI Flip manual capture/import lab (NEG-001 non-SDK)",
        "tier": "T3/T4",
    },
    "ADP-FILE-001": {
        "currentState": "specified",
        "generation": "gen:fss1:adapters-v1",
        "id": "ADP-FILE-001",
        "promotionGate": "GATE-010",
        "surface": "bounded media import",
        "tier": "T0/T4",
    },
    "ADP-INSTA-LINK-001": {
        "currentState": "researched, unimplemented",
        "generation": "gen:fss1:adapters-v1",
        "id": "ADP-INSTA-LINK-001",
        "promotionGate": "GATE-020",
        "surface": "Insta360 Link via UVC/UAC",
        "tier": "T1",
    },
    "ADP-ONVIF-M-001": {
        "currentState": "specified",
        "generation": "gen:fss1:adapters-v1",
        "id": "ADP-ONVIF-M-001",
        "promotionGate": "GATE-030",
        "surface": "ONVIF Profile M metadata",
        "tier": "T1",
    },
    "ADP-ONVIF-T-001": {
        "currentState": "specified",
        "generation": "gen:fss1:adapters-v1",
        "id": "ADP-ONVIF-T-001",
        "promotionGate": "GATE-030",
        "surface": "ONVIF Profile T",
        "tier": "T1",
    },
    "ADP-REPLAY-001": {
        "currentState": "specified",
        "generation": "gen:fss1:adapters-v1",
        "id": "ADP-REPLAY-001",
        "promotionGate": "GATE-010",
        "surface": "deterministic replay",
        "tier": "T0",
    },
    "ADP-RTSP-001": {
        "currentState": "specified",
        "generation": "gen:fss1:adapters-v1",
        "id": "ADP-RTSP-001",
        "promotionGate": "GATE-030",
        "surface": "RTSP/RTP",
        "tier": "T1",
    },
    "ADP-S3-IMPORT-001": {
        "currentState": "specified",
        "generation": "gen:fss1:adapters-v1",
        "id": "ADP-S3-IMPORT-001",
        "promotionGate": "GATE-040",
        "surface": "S3-compatible import",
        "tier": "T4",
    },
    "ADP-UVC-001": {
        "currentState": "specified",
        "generation": "gen:fss1:adapters-v1",
        "id": "ADP-UVC-001",
        "promotionGate": "GATE-020",
        "surface": "UVC/UAC",
        "tier": "T1",
    },
    "ADP-WYZE-V4-LAB-001": {
        "currentState": "research target",
        "generation": "gen:fss1:adapters-v1",
        "id": "ADP-WYZE-V4-LAB-001",
        "promotionGate": "GATE-090",
        "surface": "Wyze Cam v4 owner-auth lab",
        "tier": "T3",
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
    registry_digest: str = ""
    errors: list[DiagnosticError] = field(default_factory=list)

    def add_error(self, code: str, file_path: str, target: str, message: str) -> None:
        self.passed = False
        self.errors.append(
            DiagnosticError(code=code, file_path=file_path, target=target, message=message)
        )


def canonicalize_value(val: Any) -> Any:
    if isinstance(val, dict):
        return {k: canonicalize_value(v) for k, v in sorted(val.items())}
    elif isinstance(val, list):
        return [canonicalize_value(x) for x in val]
    return val


def compute_canonical_adapter_digest(data: dict[str, Any]) -> str:
    """Computes SHA-256 digest of canonically serialized device adapter registry payload.

    Binds top-level schema, generation, semanticProtocol, asOf, sorted rows,
    and tombstones. Fails closed with ValueError on unknown keys, empty or invalid metadata.
    """
    for k in data:
        if k not in ALLOWED_TOP_LEVEL_KEYS:
            raise ValueError(f"Unknown top-level key: {k}")

    schema = data.get("schema")
    generation = data.get("generation")
    semantic_protocol = data.get("semanticProtocol")
    as_of = data.get("asOf")
    if not all(
        isinstance(f, str) and f.strip()
        for f in (schema, generation, semantic_protocol, as_of)
    ):
        raise ValueError(
            "Top-level metadata (schema, generation, semanticProtocol, asOf) must be non-empty strings"
        )

    adapters = data.get("adapters", [])
    if not isinstance(adapters, list):
        raise ValueError("Adapters must be a list")

    seen_ids: set[str] = set()
    for adp in adapters:
        if not isinstance(adp, dict):
            raise ValueError("Adapter entry must be an object")
        for k in adp:
            if k not in ALLOWED_ROW_KEYS:
                raise ValueError(f"Unknown row key in adapter: {k}")
        aid = adp.get("id")
        if not aid or not isinstance(aid, str) or not aid.strip():
            raise ValueError("Adapter entry must have a non-empty string 'id'")
        if aid in seen_ids:
            raise ValueError(f"Duplicate adapter ID: {aid}")
        seen_ids.add(aid)

    tombstones = data.get("tombstones", [])
    if not isinstance(tombstones, list):
        raise ValueError("Tombstones must be a list")

    seen_tombstones: set[str] = set()
    for tomb in tombstones:
        if not isinstance(tomb, dict):
            raise ValueError("Tombstone entry must be an object")
        for k in tomb:
            if k not in ALLOWED_TOMBSTONE_KEYS:
                raise ValueError(f"Unknown key in tombstone: {k}")
        tid = tomb.get("id")
        if not tid or not isinstance(tid, str) or not tid.strip():
            raise ValueError("Tombstone entry must have a non-empty string 'id'")
        if tid in seen_tombstones:
            raise ValueError(f"Duplicate tombstone ID: {tid}")
        if tid in seen_ids:
            raise ValueError(f"Tombstone ID overlaps with active adapter ID: {tid}")
        seen_tombstones.add(tid)

    sorted_adapters = sorted(
        [canonicalize_value(r) for r in adapters], key=lambda r: str(r.get("id", ""))
    )
    sorted_tombstones = sorted(
        [canonicalize_value(r) for r in tombstones], key=lambda r: str(r.get("id", ""))
    )

    canonical_payload = {
        "adapters": sorted_adapters,
        "asOf": as_of,
        "generation": generation,
        "schema": schema,
        "semanticProtocol": semantic_protocol,
        "tombstones": sorted_tombstones,
    }
    canonical_bytes = json.dumps(
        canonical_payload, sort_keys=True, separators=(",", ":")
    ).encode("utf-8")
    return f"sha256:{hashlib.sha256(canonical_bytes).hexdigest()}"


def extract_markdown_device_adapters(
    md_path: Path,
) -> tuple[dict[str, tuple[str, str, str, str]], list[tuple[str, str]]]:
    """Extracts device adapters from markdown table: {id: (surface, tier, current_state, promotion_gate)}.

    Returns (rows, errors) where errors is a list of (target, message).
    """
    rows: dict[str, tuple[str, str, str, str]] = {}
    errors: list[tuple[str, str]] = []
    lines = md_path.read_text(encoding="utf-8").splitlines()
    in_table = False
    for line_num, line in enumerate(lines, start=1):
        stripped = line.strip()
        if not stripped.startswith("|"):
            if in_table and stripped:
                in_table = False
            continue

        if "---" in stripped:
            continue
        if "ID" in stripped and "Surface" in stripped:
            in_table = True
            continue

        in_table = True
        parts = [p.strip() for p in stripped.strip("|").split("|")]
        if len(parts) != 5:
            errors.append((
                f"line {line_num}",
                f"Markdown table row has invalid column count {len(parts)} (expected 5): '{line}'",
            ))
            continue

        aid = parts[0].replace("`", "").strip()
        if not aid.startswith("ADP-"):
            errors.append((
                f"line {line_num}",
                f"Markdown table row has invalid adapter ID format: '{aid}'",
            ))
            continue

        if aid in rows:
            errors.append((
                f"#{aid}",
                f"Duplicate adapter ID in markdown mirror: '{aid}'",
            ))
            continue

        surface = parts[1].strip()
        tier = parts[2].strip()
        current_state = parts[3].strip()
        promotion_gate = parts[4].replace("`", "").strip()
        rows[aid] = (surface, tier, current_state, promotion_gate)

    return rows, errors


def validate_device_adapter_registry(
    repo_root: Path = ROOT,
) -> ValidationResult:
    result = ValidationResult()
    json_path = repo_root / DEVICE_ADAPTERS_JSON_PATH
    md_path = repo_root / DEVICE_ADAPTERS_MD_PATH

    # 1. Existence check
    if not json_path.is_file():
        result.add_error(
            ERR_ADAPTER_CORRUPT_FILE,
            DEVICE_ADAPTERS_JSON_PATH,
            "#",
            f"Device adapter registry JSON file does not exist: {json_path}",
        )
        return result

    if not md_path.is_file():
        result.add_error(
            ERR_ADAPTER_CORRUPT_FILE,
            DEVICE_ADAPTERS_MD_PATH,
            "#",
            f"Device adapter markdown file does not exist: {md_path}",
        )
        return result

    # 2. Parse JSON
    try:
        data = json.loads(json_path.read_text(encoding="utf-8"))
    except Exception as exc:
        result.add_error(
            ERR_ADAPTER_CORRUPT_FILE,
            DEVICE_ADAPTERS_JSON_PATH,
            "#",
            f"Failed to parse device adapter JSON: {exc}",
        )
        return result

    if not isinstance(data, dict):
        result.add_error(
            ERR_ADAPTER_CORRUPT_FILE,
            DEVICE_ADAPTERS_JSON_PATH,
            "#",
            "Device adapter registry root must be a JSON object",
        )
        return result

    for k in data:
        if k not in ALLOWED_TOP_LEVEL_KEYS:
            result.add_error(
                ERR_ADAPTER_SEMANTIC_INVARIANT,
                DEVICE_ADAPTERS_JSON_PATH,
                f"#/{k}",
                f"Unknown top-level key: '{k}'",
            )

    # 3. Top-level metadata checks
    for field_name in ("schema", "asOf", "semanticProtocol", "generation", "registryDigest"):
        val = data.get(field_name)
        if not isinstance(val, str) or not val.strip():
            result.add_error(
                ERR_ADAPTER_CORRUPT_FILE,
                DEVICE_ADAPTERS_JSON_PATH,
                f"#/{field_name}",
                f"Device adapter registry top-level field '{field_name}' must be a non-empty string",
            )

    schema = str(data.get("schema", "")).strip()
    if schema and schema != SCHEMA_DEVICE_ADAPTERS_V1:
        result.add_error(
            ERR_ADAPTER_CORRUPT_FILE,
            DEVICE_ADAPTERS_JSON_PATH,
            "#/schema",
            f"Device adapter registry schema mismatch: declared '{schema}', expected '{SCHEMA_DEVICE_ADAPTERS_V1}'",
        )

    generation = str(data.get("generation", "")).strip()
    if not generation:
        result.add_error(
            ERR_ADAPTER_GENERATION_MISMATCH,
            DEVICE_ADAPTERS_JSON_PATH,
            "#/generation",
            "Device adapter registry missing or empty 'generation'",
        )
    elif generation != CURRENT_GENERATION:
        result.add_error(
            ERR_ADAPTER_GENERATION_MISMATCH,
            DEVICE_ADAPTERS_JSON_PATH,
            "#/generation",
            f"Device adapter registry generation mismatch: declared '{generation}', expected '{CURRENT_GENERATION}'",
        )

    declared_digest = str(data.get("registryDigest", "")).strip()
    result.registry_digest = declared_digest

    # 4. Pinned freeze digest check
    expected_pinned_digest = EXPECTED_FREEZE_DIGESTS.get(generation)
    if expected_pinned_digest is not None:
        if declared_digest != expected_pinned_digest:
            result.add_error(
                ERR_ADAPTER_DIGEST_MISMATCH,
                DEVICE_ADAPTERS_JSON_PATH,
                "#/registryDigest",
                f"Device adapter registry digest diverged from pinned baseline freeze digest: declared '{declared_digest}', pinned '{expected_pinned_digest}'",
            )
    else:
        result.add_error(
            ERR_ADAPTER_GENERATION_MISMATCH,
            DEVICE_ADAPTERS_JSON_PATH,
            "#/registryDigest",
            f"Device adapter registry generation '{generation}' is not in pinned freeze digests",
        )

    # 5. Computed canonical digest check
    try:
        computed_digest = compute_canonical_adapter_digest(data)
        if declared_digest != computed_digest:
            result.add_error(
                ERR_ADAPTER_DIGEST_MISMATCH,
                DEVICE_ADAPTERS_JSON_PATH,
                "#/registryDigest",
                f"Registry digest mismatch: declared '{declared_digest}', computed '{computed_digest}'",
            )
    except Exception as exc:
        result.add_error(
            ERR_ADAPTER_CORRUPT_FILE,
            DEVICE_ADAPTERS_JSON_PATH,
            "#/registryDigest",
            f"Failed to compute canonical adapter digest: {exc}",
        )

    # 6. Adapters list validation
    adapters_list = data.get("adapters")
    if not isinstance(adapters_list, list):
        result.add_error(
            ERR_ADAPTER_CORRUPT_FILE,
            DEVICE_ADAPTERS_JSON_PATH,
            "#/adapters",
            "Top-level 'adapters' must be a list",
        )
        adapters_list = []

    tombstones_list = data.get("tombstones")
    if not isinstance(tombstones_list, list):
        result.add_error(
            ERR_ADAPTER_CORRUPT_FILE,
            DEVICE_ADAPTERS_JSON_PATH,
            "#/tombstones",
            "Top-level 'tombstones' must be a list",
        )
        tombstones_list = []

    active_adapters: dict[str, dict[str, Any]] = {}
    for idx, adp in enumerate(adapters_list):
        if not isinstance(adp, dict):
            result.add_error(
                ERR_ADAPTER_CORRUPT_FILE,
                DEVICE_ADAPTERS_JSON_PATH,
                f"#/adapters/{idx}",
                "Adapter entry must be an object",
            )
            continue
        for k in adp:
            if k not in ALLOWED_ROW_KEYS:
                result.add_error(
                    ERR_ADAPTER_SEMANTIC_INVARIANT,
                    DEVICE_ADAPTERS_JSON_PATH,
                    f"#/adapters/{idx}/{k}",
                    f"Unknown row key in adapter: '{k}'",
                )
        aid = adp.get("id")
        if not isinstance(aid, str) or not aid.strip():
            result.add_error(
                ERR_ADAPTER_SEMANTIC_INVARIANT,
                DEVICE_ADAPTERS_JSON_PATH,
                f"#/adapters/{idx}/id",
                "Adapter entry missing or empty 'id'",
            )
            continue
        if aid in active_adapters:
            result.add_error(
                ERR_ADAPTER_STABLE_ID_REUSED,
                DEVICE_ADAPTERS_JSON_PATH,
                f"#/adapters/{idx}/id",
                f"Duplicate adapter ID in active adapters: '{aid}'",
            )
            continue
        active_adapters[aid] = adp

    tombstoned_ids: set[str] = set()
    for idx, tomb in enumerate(tombstones_list):
        if not isinstance(tomb, dict):
            result.add_error(
                ERR_ADAPTER_CORRUPT_FILE,
                DEVICE_ADAPTERS_JSON_PATH,
                f"#/tombstones/{idx}",
                "Tombstone entry must be an object",
            )
            continue
        for k in tomb:
            if k not in ALLOWED_TOMBSTONE_KEYS:
                result.add_error(
                    ERR_ADAPTER_SEMANTIC_INVARIANT,
                    DEVICE_ADAPTERS_JSON_PATH,
                    f"#/tombstones/{idx}/{k}",
                    f"Unknown key in tombstone: '{k}'",
                )
        tid = tomb.get("id")
        if not isinstance(tid, str) or not tid.strip():
            result.add_error(
                ERR_ADAPTER_SEMANTIC_INVARIANT,
                DEVICE_ADAPTERS_JSON_PATH,
                f"#/tombstones/{idx}/id",
                "Tombstone entry missing or empty 'id'",
            )
            continue
        if tid in tombstoned_ids:
            result.add_error(
                ERR_ADAPTER_STABLE_ID_REUSED,
                DEVICE_ADAPTERS_JSON_PATH,
                f"#/tombstones/{idx}/id",
                f"Duplicate tombstone ID: '{tid}'",
            )
            continue
        if tid in active_adapters:
            result.add_error(
                ERR_ADAPTER_STABLE_ID_REUSED,
                DEVICE_ADAPTERS_JSON_PATH,
                f"#/tombstones/{idx}/id",
                f"Tombstone ID '{tid}' is resurrected in active adapters",
            )
        tombstoned_ids.add(tid)

    # 7. Baseline stable ID check (no renumbering, reuse, missing, or resurrection)
    for base_id, base_row in BASELINE_ADAPTERS.items():
        if base_id not in active_adapters and base_id not in tombstoned_ids:
            result.add_error(
                ERR_ADAPTER_STABLE_ID_REUSED,
                DEVICE_ADAPTERS_JSON_PATH,
                f"#/adapters/{base_id}",
                f"Baseline adapter ID '{base_id}' missing from active and tombstoned adapters",
            )
        elif base_id in active_adapters:
            adp = active_adapters[base_id]
            for req_field in REQUIRED_ROW_FIELDS:
                if req_field in base_row and adp.get(req_field) != base_row[req_field]:
                    result.add_error(
                        ERR_ADAPTER_SEMANTIC_INVARIANT,
                        DEVICE_ADAPTERS_JSON_PATH,
                        f"#/adapters/{base_id}/{req_field}",
                        f"Baseline row field '{req_field}' modified without generation bump: was '{base_row[req_field]}', got '{adp.get(req_field)}'",
                    )

    # Check for unbaseline additions without generation bump
    for aid in active_adapters:
        if aid not in BASELINE_ADAPTERS and generation == CURRENT_GENERATION:
            result.add_error(
                ERR_ADAPTER_STABLE_ID_REUSED,
                DEVICE_ADAPTERS_JSON_PATH,
                f"#/adapters/{aid}",
                f"Unbaseline adapter ID '{aid}' added without generation bump",
            )

    # 8. Row-level invariant checks
    for aid, adp in active_adapters.items():
        for req_field in REQUIRED_ROW_FIELDS:
            val = adp.get(req_field)
            if not isinstance(val, str) or not val.strip():
                result.add_error(
                    ERR_ADAPTER_SEMANTIC_INVARIANT,
                    DEVICE_ADAPTERS_JSON_PATH,
                    f"#/adapters/{aid}/{req_field}",
                    f"Adapter '{aid}' missing or empty field '{req_field}'",
                )

        row_gen = adp.get("generation")
        if row_gen != generation:
            result.add_error(
                ERR_ADAPTER_GENERATION_MISMATCH,
                DEVICE_ADAPTERS_JSON_PATH,
                f"#/adapters/{aid}/generation",
                f"Adapter '{aid}' row generation '{row_gen}' disagrees with registry generation '{generation}'",
            )

        tier = str(adp.get("tier", "")).strip()
        if tier not in VALID_TIERS:
            result.add_error(
                ERR_ADAPTER_INVALID_TIER,
                DEVICE_ADAPTERS_JSON_PATH,
                f"#/adapters/{aid}/tier",
                f"Adapter '{aid}' specifies invalid tier '{tier}' (must be one of {sorted(VALID_TIERS)})",
            )

        gate = str(adp.get("promotionGate", "")).strip()
        if not GATE_PATTERN.match(gate):
            result.add_error(
                ERR_ADAPTER_SEMANTIC_INVARIANT,
                DEVICE_ADAPTERS_JSON_PATH,
                f"#/adapters/{aid}/promotionGate",
                f"Adapter '{aid}' specifies invalid promotion gate format '{gate}' (must match GATE-XXX)",
            )

        # Invariant: NEG-002: T3 adapters are owner-auth lab / research targets, never open-local production
        current_state = str(adp.get("currentState", "")).strip()
        if "T3" in tier and current_state not in ("research target", "researched, unimplemented"):
            result.add_error(
                ERR_ADAPTER_INVALID_TIER,
                DEVICE_ADAPTERS_JSON_PATH,
                f"#/adapters/{aid}/currentState",
                f"Adapter '{aid}' has tier '{tier}' but claimed current state '{current_state}', violating NEG-002 lab-only constraint",
            )

    # 9. Markdown mirror consistency
    try:
        md_adapters, md_errors = extract_markdown_device_adapters(md_path)
    except Exception as exc:
        result.add_error(
            ERR_ADAPTER_CORRUPT_FILE,
            DEVICE_ADAPTERS_MD_PATH,
            "#",
            f"Failed to extract adapters from markdown: {exc}",
        )
        return result

    for target, msg in md_errors:
        result.add_error(
            ERR_ADAPTER_REGISTRY_DRIFT,
            DEVICE_ADAPTERS_MD_PATH,
            target,
            msg,
        )

    # Check that all active JSON adapters match markdown
    for aid, adp in active_adapters.items():
        if aid not in md_adapters:
            result.add_error(
                ERR_ADAPTER_REGISTRY_DRIFT,
                DEVICE_ADAPTERS_MD_PATH,
                f"#/{aid}",
                f"Active adapter '{aid}' in JSON missing from markdown mirror",
            )
            continue
        md_surface, md_tier, md_state, md_gate = md_adapters[aid]
        json_surface = adp.get("surface", "")
        json_tier = adp.get("tier", "")
        json_state = adp.get("currentState", "")
        json_gate = adp.get("promotionGate", "")

        if (json_surface, json_tier, json_state, json_gate) != (
            md_surface,
            md_tier,
            md_state,
            md_gate,
        ):
            result.add_error(
                ERR_ADAPTER_REGISTRY_DRIFT,
                DEVICE_ADAPTERS_MD_PATH,
                f"#/{aid}",
                f"Adapter '{aid}' mismatch between JSON and markdown: "
                f"JSON=({json_surface}, {json_tier}, {json_state}, {json_gate}) vs "
                f"MD=({md_surface}, {md_tier}, {md_state}, {md_gate})",
            )

    # Check that markdown contains no extra rows
    for aid in md_adapters:
        if aid not in active_adapters:
            result.add_error(
                ERR_ADAPTER_REGISTRY_DRIFT,
                DEVICE_ADAPTERS_MD_PATH,
                f"#/{aid}",
                f"Markdown contains adapter '{aid}' not in active JSON adapters",
            )

    return result


def main() -> int:
    parser = argparse.ArgumentParser(description="Check device adapter registry consistency.")
    parser.add_argument("--repo-root", type=Path, default=ROOT, help="Repository root path")
    parser.add_argument("--json", action="store_true", help="Output JSON results")
    parser.add_argument("--verbose", action="store_true", help="Print detailed diagnostic info")
    args = parser.parse_args()

    result = validate_device_adapter_registry(args.repo_root)

    if args.json:
        payload = {
            "passed": result.passed,
            "registryDigest": result.registry_digest,
            "errors": [asdict(e) for e in result.errors],
        }
        print(json.dumps(payload, indent=2))
    else:
        if result.passed:
            print(f"PASS: Device adapter registry is consistent (digest: {result.registry_digest})")
        else:
            print(f"FAIL: Device adapter registry failed with {len(result.errors)} errors:")
            for err in result.errors:
                print(f"  [{err.code}] {err.file_path} ({err.target}): {err.message}")

    return 0 if result.passed else 1


if __name__ == "__main__":
    sys.exit(main())
