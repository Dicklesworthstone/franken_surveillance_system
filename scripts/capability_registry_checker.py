#!/usr/bin/env python3
"""Fail-closed capability registry checker (fss-x4a.30.86.1).

Enforces the capability registry contract:
1. Capability registry row drift between architecture JSON and markdown (ERR-CAPABILITY-REGISTRY-DRIFT-001)
2. Unknown or unregistered semantic plane (ERR-CAPABILITY-UNKNOWN-PLANE-001)
3. Missing default role (ERR-CAPABILITY-MISSING-DEFAULT-001)
4. Stable ID reused or duplicated (ERR-CAPABILITY-STABLE-ID-REUSED-001)
5. Canonical registry digest mismatch (ERR-CAPABILITY-DIGEST-MISMATCH-001)
6. Corrupt or missing mandatory files (ERR-CAPABILITY-CORRUPT-FILE-001)
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


def compute_canonical_capability_digest(capabilities: list[dict[str, Any]]) -> str:
    """Computes SHA-256 digest of canonically serialized sorted capability rows."""
    sorted_rows = sorted(capabilities, key=lambda r: str(r.get("id", "")))
    canonical_bytes = json.dumps(sorted_rows, sort_keys=True, separators=(",", ":")).encode("utf-8")
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

    # Validate canonical digest
    computed_digest = compute_canonical_capability_digest(capabilities_list)
    if declared_digest != computed_digest:
        result.add_error(
            ERR_CAPABILITY_DIGEST_MISMATCH,
            CAPABILITIES_JSON_PATH,
            "#/registryDigest",
            f"Registry digest mismatch: declared {declared_digest}, computed {computed_digest}",
        )

    # Check for duplicate stable IDs, missing defaults, unknown planes in JSON
    seen_ids: set[str] = set()
    json_caps: dict[str, dict[str, Any]] = {}
    for idx, cap in enumerate(capabilities_list):
        cid = cap.get("id")
        if not cid or not isinstance(cid, str):
            result.add_error(
                ERR_CAPABILITY_CORRUPT_FILE,
                CAPABILITIES_JSON_PATH,
                f"#/capabilities/{idx}",
                "Capability entry missing 'id'",
            )
            continue

        if cid in seen_ids:
            result.add_error(
                ERR_CAPABILITY_STABLE_ID_REUSED,
                CAPABILITIES_JSON_PATH,
                f"#/capabilities/{idx}/id",
                f"Duplicate or reused capability stable ID: {cid}",
            )
        seen_ids.add(cid)
        json_caps[cid] = cap

        plane = cap.get("plane", "")
        if plane not in RECOGNIZED_PLANES:
            result.add_error(
                ERR_CAPABILITY_UNKNOWN_PLANE,
                CAPABILITIES_JSON_PATH,
                f"#/capabilities/{cid}/plane",
                f"Capability '{cid}' has unknown or unregistered plane: '{plane}'",
            )

        default_role = cap.get("defaultRole", "")
        if not default_role or not isinstance(default_role, str) or not default_role.strip():
            result.add_error(
                ERR_CAPABILITY_MISSING_DEFAULT,
                CAPABILITIES_JSON_PATH,
                f"#/capabilities/{cid}/defaultRole",
                f"Capability '{cid}' missing required defaultRole",
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
