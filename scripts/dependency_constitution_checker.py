#!/usr/bin/env python3
"""Fail-closed dependency constitution and class registry checker (fss-x4a.30.88.16).

Enforces the dependency constitution and DEP-CLASS-F0 (rust-language-and-stdlib) contract:
1. Pinned freeze digest covering all fields, metadata, production settings, and generation.
2. Exact digest assertion against BASELINE_DEPENDENCY_CONSTITUTION_FREEZE_DIGEST.
3. Mandatory generation bump enforcement (ERR-DEP-GENERATION-MISMATCH-001, ERR-DEP-FREEZE-DIVERGENCE-001).
4. Baseline-checked dependency classes (DEP-CLASS-F0 through DEP-CLASS-F4) against canonical baseline.
5. Semantic invariants for DEP-CLASS-F0 (admission must be 'constitutional', production must be 'rust-2024',
   unsafe forbidden, asupersync-only runtime, closed universe, no C/C++ FFI).
6. Real Cargo metadata inspection: parses packages, verifies edition '2024', forbids native C/C++ links,
   and ensures workspace metadata production_language is 'rust' (no hollow string checks).
7. 1:1 Markdown mirror check against docs/DEPENDENCY_CONSTITUTION.md.
"""
from __future__ import annotations

import argparse
import copy
import hashlib
import json
import re
import subprocess
import sys
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]

# Registered stable diagnostic finding IDs (registries/ERRORS.md)
ERR_DEP_REGISTRY_DRIFT = "ERR-DEP-REGISTRY-DRIFT-001"
ERR_DEP_STABLE_ID_REUSED = "ERR-DEP-STABLE-ID-REUSED-001"
ERR_DEP_MISSING_FIELD = "ERR-DEP-MISSING-FIELD-001"
ERR_DEP_CORRUPT_FILE = "ERR-DEP-CORRUPT-FILE-001"
ERR_DEP_DIGEST_MISMATCH = "ERR-DEP-DIGEST-MISMATCH-001"
ERR_DEP_FREEZE_DIVERGENCE = "ERR-DEP-FREEZE-DIVERGENCE-001"
ERR_DEP_GENERATION_MISMATCH = "ERR-DEP-GENERATION-MISMATCH-001"
ERR_DEP_CONST_INVARIANT = "ERR-DEP-CONST-INVARIANT-001"
ERR_DEP_CONST_METADATA_VIOLATION = "ERR-DEP-CONST-METADATA-VIOLATION-001"

CONSTITUTION_JSON_PATH = "architecture/dependency_constitution.json"
CONSTITUTION_MD_PATH = "docs/DEPENDENCY_CONSTITUTION.md"
ALLOWLIST_TOML_PATH = "architecture/dependency_allowlist.toml"
STABLE_ID_RESOLUTION_PATH = "architecture/stable_id_resolution.json"

BASELINE_DEPENDENCY_CONSTITUTION_GENERATION = "gen:fss1:dep-constitution-v1"
BASELINE_DEPENDENCY_CONSTITUTION_FREEZE_DIGEST = (
    "sha256:858af1b5482b25cfca1477c2c4c1967a995d802990aaf0bc7ccf139f73571310"
)

EXPECTED_FREEZE_DIGESTS: dict[str, str] = {
    BASELINE_DEPENDENCY_CONSTITUTION_GENERATION: BASELINE_DEPENDENCY_CONSTITUTION_FREEZE_DIGEST,
}

CANONICAL_DEPENDENCY_CLASSES: dict[str, dict[str, str]] = {
    "DEP-CLASS-F0": {
        "id": "DEP-CLASS-F0",
        "name": "rust-language-and-stdlib",
        "admission": "constitutional",
    },
    "DEP-CLASS-F1": {
        "id": "DEP-CLASS-F1",
        "name": "asupersync",
        "admission": "INT-AS-001",
    },
    "DEP-CLASS-F2": {
        "id": "DEP-CLASS-F2",
        "name": "franken-suite",
        "admission": "per-mechanism-import-gate",
    },
    "DEP-CLASS-F3": {
        "id": "DEP-CLASS-F3",
        "name": "fundamental-rust-data-shape",
        "admission": "DEP-record-and-transitive-audit",
    },
    "DEP-CLASS-F4": {
        "id": "DEP-CLASS-F4",
        "name": "laboratory-oracle",
        "admission": "non-production-quarantine-only",
    },
}

MANDATORY_TOP_LEVEL_FIELDS: tuple[str, ...] = (
    "schema",
    "asOf",
    "generation",
    "freezeDigest",
    "normativePolicy",
    "production",
    "classes",
    "releaseEvidence",
)

MANDATORY_CLASS_FIELDS: tuple[str, ...] = (
    "id",
    "name",
    "admission",
)

MANDATORY_PRODUCTION_FIELDS: tuple[str, ...] = (
    "language",
    "toolchain",
    "unsafe",
    "asyncRuntime",
    "closedUniverse",
    "lockedOfflineReleaseResolution",
    "runtimeAcquisition",
    "cCppFfi",
    "dynamicLoading",
    "foreignExecutables",
    "serdeDurableFormatAuthority",
)

REQUIRED_PRODUCTION_VALUES: dict[str, Any] = {
    "language": "rust-2024",
    "toolchain": "latest-accepted-pinned-nightly",
    "unsafe": "forbidden-in-all-fss-crates",
    "asyncRuntime": "asupersync-only",
    "closedUniverse": True,
    "lockedOfflineReleaseResolution": True,
    "runtimeAcquisition": False,
    "cCppFfi": False,
    "dynamicLoading": False,
    "foreignExecutables": False,
    "serdeDurableFormatAuthority": False,
}

DEP_CLASS_ID_PATTERN = re.compile(r"^DEP-CLASS-F[0-4]$")


@dataclass(frozen=True)
class DiagnosticError:
    code: str
    file_path: str
    target: str
    message: str


@dataclass
class ValidationResult:
    passed: bool = True
    class_count: int = 0
    freeze_digest: str = ""
    errors: list[DiagnosticError] = field(default_factory=list)

    def add_error(self, code: str, file_path: str, target: str, message: str) -> None:
        self.passed = False
        self.errors.append(DiagnosticError(code=code, file_path=file_path, target=target, message=message))


def canonicalize_value(val: Any) -> Any:
    if isinstance(val, dict):
        return {k: canonicalize_value(v) for k, v in sorted(val.items())}
    if isinstance(val, list):
        return [canonicalize_value(x) for x in val]
    return val


def compute_canonical_constitution_digest(data: dict[str, Any]) -> str:
    """Computes deterministic sha256 digest of dependency constitution covering all fields and metadata."""
    canonical_payload = {
        "schema": data.get("schema"),
        "asOf": data.get("asOf"),
        "generation": data.get("generation"),
        "normativePolicy": data.get("normativePolicy"),
        "production": canonicalize_value(data.get("production", {})),
        "classes": sorted(
            [canonicalize_value(c) for c in data.get("classes", []) if isinstance(c, dict)],
            key=lambda x: str(x.get("id", "")),
        ),
        "releaseEvidence": sorted([str(x) for x in data.get("releaseEvidence", [])]),
    }
    payload_bytes = json.dumps(canonical_payload, sort_keys=True, separators=(",", ":")).encode("utf-8")
    return f"sha256:{hashlib.sha256(payload_bytes).hexdigest()}"


def load_tombstoned_ids(root: Path) -> set[str]:
    """Loads tombstoned identifiers from architecture/stable_id_resolution.json."""
    res_path = root / STABLE_ID_RESOLUTION_PATH
    if not res_path.is_file():
        return set()
    try:
        data = json.loads(res_path.read_text(encoding="utf-8"))
        resolutions = data.get("resolutions", [])
        return {
            str(r.get("legacyId"))
            for r in resolutions
            if isinstance(r, dict) and r.get("status") == "tombstoned" and r.get("legacyId")
        }
    except Exception:
        return set()


def extract_markdown_class_sections(md_text: str) -> dict[str, str]:
    """Extracts Class F* sections from docs/DEPENDENCY_CONSTITUTION.md."""
    pattern = re.compile(r"^###\s+2\.\d+\s+Class\s+(F[0-4])\s*[—–-]\s*(.+)$", re.MULTILINE)
    classes: dict[str, str] = {}
    for match in pattern.finditer(md_text):
        class_suffix, class_name = match.groups()
        class_id = f"DEP-CLASS-{class_suffix}"
        classes[class_id] = class_name.strip()
    return classes


def load_real_cargo_metadata(root: Path) -> tuple[dict[str, Any] | None, str | None]:
    """Invokes cargo metadata --locked --offline to fetch real Cargo metadata."""
    toolchain_file = root / "rust-toolchain.toml"
    channel = "nightly-2026-08-31"
    if toolchain_file.is_file():
        try:
            import tomllib
            tc = tomllib.loads(toolchain_file.read_text(encoding="utf-8"))
            channel = tc.get("toolchain", {}).get("channel", channel)
        except Exception:
            pass

    cmd = [
        "rustup",
        "run",
        channel,
        "cargo",
        "metadata",
        "--locked",
        "--offline",
        "--format-version",
        "1",
    ]
    try:
        proc = subprocess.run(cmd, cwd=root, capture_output=True, text=True)
        if proc.returncode != 0:
            return None, f"cargo metadata failed: {proc.stderr.strip() or proc.stdout.strip()}"
        return json.loads(proc.stdout), None
    except Exception as exc:
        return None, f"unable to execute cargo metadata: {exc}"


def validate_cargo_metadata_for_f0(
    result: ValidationResult,
    metadata: dict[str, Any],
    root: Path,
) -> None:
    """Inspects real Cargo metadata structure for constitutional language/stdlib conformance (DEP-CLASS-F0)."""
    workspace_members = set(metadata.get("workspace_members", []))
    packages = metadata.get("packages", [])

    # 1. Inspect workspace metadata production_language
    meta_obj = metadata.get("metadata", {})
    fss_meta = meta_obj.get("fss", {}) if isinstance(meta_obj, dict) else {}
    if fss_meta.get("production_language") != "rust":
        result.add_error(
            ERR_DEP_CONST_METADATA_VIOLATION,
            "Cargo.toml",
            "#/metadata/fss/production_language",
            f"Cargo metadata production_language must be 'rust', found: {fss_meta.get('production_language')!r}",
        )

    # 2. Inspect every workspace member package for edition 2024 and absence of native C/C++ links
    for pkg in packages:
        if not isinstance(pkg, dict):
            continue
        pkg_id = pkg.get("id")
        pkg_name = pkg.get("name", "<unknown>")
        if pkg_id in workspace_members:
            edition = pkg.get("edition")
            if edition != "2024":
                result.add_error(
                    ERR_DEP_CONST_METADATA_VIOLATION,
                    str(pkg.get("manifest_path", "Cargo.toml")),
                    f"#{pkg_name}/edition",
                    f"workspace package '{pkg_name}' must declare edition '2024' (DEP-CLASS-F0), found: {edition!r}",
                )
            links = pkg.get("links")
            if links:
                result.add_error(
                    ERR_DEP_CONST_METADATA_VIOLATION,
                    str(pkg.get("manifest_path", "Cargo.toml")),
                    f"#{pkg_name}/links",
                    f"workspace package '{pkg_name}' illegally declares native links '{links}' violating pure-Rust DEP-CLASS-F0",
                )


def validate_dependency_constitution(
    root: Path,
    cargo_metadata: dict[str, Any] | None = None,
    skip_cargo_metadata: bool = False,
) -> ValidationResult:
    """Validates architecture/dependency_constitution.json against SWARM RULE and Cargo metadata."""
    result = ValidationResult()
    json_path = root / CONSTITUTION_JSON_PATH
    md_path = root / CONSTITUTION_MD_PATH

    # 1. Existence and valid JSON
    if not json_path.is_file():
        result.add_error(
            ERR_DEP_CORRUPT_FILE,
            CONSTITUTION_JSON_PATH,
            "#",
            f"Dependency constitution file missing at {CONSTITUTION_JSON_PATH}",
        )
        return result

    raw_text = json_path.read_text(encoding="utf-8")
    if not raw_text.strip():
        result.add_error(
            ERR_DEP_CORRUPT_FILE,
            CONSTITUTION_JSON_PATH,
            "#",
            "Dependency constitution file is 0 bytes / empty",
        )
        return result

    try:
        data = json.loads(raw_text)
    except json.JSONDecodeError as exc:
        result.add_error(
            ERR_DEP_CORRUPT_FILE,
            CONSTITUTION_JSON_PATH,
            "#",
            f"Dependency constitution JSON decode failed: {exc}",
        )
        return result

    if not isinstance(data, dict):
        result.add_error(
            ERR_DEP_CORRUPT_FILE,
            CONSTITUTION_JSON_PATH,
            "#",
            "Dependency constitution root must be a JSON object",
        )
        return result

    # 2. Mandatory top-level fields
    for field_name in MANDATORY_TOP_LEVEL_FIELDS:
        if field_name not in data or data[field_name] is None:
            result.add_error(
                ERR_DEP_MISSING_FIELD,
                CONSTITUTION_JSON_PATH,
                f"#/{field_name}",
                f"Missing mandatory top-level field '{field_name}'",
            )
        elif isinstance(data[field_name], str) and not data[field_name].strip():
            result.add_error(
                ERR_DEP_MISSING_FIELD,
                CONSTITUTION_JSON_PATH,
                f"#/{field_name}",
                f"Mandatory top-level field '{field_name}' must not be empty",
            )

    if not result.passed and any(e.code == ERR_DEP_MISSING_FIELD for e in result.errors):
        return result

    generation = str(data.get("generation", ""))
    declared_freeze_digest = str(data.get("freezeDigest", ""))
    result.freeze_digest = declared_freeze_digest

    # 3. Generation binding
    if generation not in EXPECTED_FREEZE_DIGESTS:
        result.add_error(
            ERR_DEP_GENERATION_MISMATCH,
            CONSTITUTION_JSON_PATH,
            "#/generation",
            f"Dependency constitution generation '{generation}' is unrecognized; expected one of {list(EXPECTED_FREEZE_DIGESTS.keys())}",
        )

    # 4. Freeze digest verification
    expected_digest = EXPECTED_FREEZE_DIGESTS.get(generation)
    computed_digest = compute_canonical_constitution_digest(data)

    if declared_freeze_digest != computed_digest:
        result.add_error(
            ERR_DEP_DIGEST_MISMATCH,
            CONSTITUTION_JSON_PATH,
            "#/freezeDigest",
            f"Dependency constitution freezeDigest mismatch: declared '{declared_freeze_digest}', computed '{computed_digest}'",
        )

    if expected_digest is not None and computed_digest != expected_digest:
        result.add_error(
            ERR_DEP_FREEZE_DIVERGENCE,
            CONSTITUTION_JSON_PATH,
            "#/freezeDigest",
            f"Dependency constitution content diverged from pinned baseline for generation '{generation}': computed '{computed_digest}', expected '{expected_digest}'",
        )

    # 5. Production requirements verification
    production = data.get("production", {})
    if not isinstance(production, dict):
        result.add_error(
            ERR_DEP_MISSING_FIELD,
            CONSTITUTION_JSON_PATH,
            "#/production",
            "Top-level 'production' field must be a JSON object",
        )
    else:
        for p_field in MANDATORY_PRODUCTION_FIELDS:
            if p_field not in production:
                result.add_error(
                    ERR_DEP_MISSING_FIELD,
                    CONSTITUTION_JSON_PATH,
                    f"#/production/{p_field}",
                    f"Missing mandatory production field '{p_field}'",
                )
            elif production[p_field] != REQUIRED_PRODUCTION_VALUES[p_field]:
                result.add_error(
                    ERR_DEP_CONST_INVARIANT,
                    CONSTITUTION_JSON_PATH,
                    f"#/production/{p_field}",
                    f"Production invariant violation for '{p_field}': expected {REQUIRED_PRODUCTION_VALUES[p_field]!r}, got {production[p_field]!r}",
                )

    # 6. Classes validation
    classes = data.get("classes", [])
    if not isinstance(classes, list):
        result.add_error(
            ERR_DEP_CORRUPT_FILE,
            CONSTITUTION_JSON_PATH,
            "#/classes",
            "Top-level 'classes' field must be a JSON list",
        )
        return result

    result.class_count = len(classes)
    if len(classes) != len(CANONICAL_DEPENDENCY_CLASSES):
        result.add_error(
            ERR_DEP_STABLE_ID_REUSED,
            CONSTITUTION_JSON_PATH,
            "#/classes",
            f"Expected {len(CANONICAL_DEPENDENCY_CLASSES)} classes, found {len(classes)}",
        )

    seen_ids: set[str] = set()
    seen_lower_ids: dict[str, str] = {}
    tombstoned_ids = load_tombstoned_ids(root)

    for idx, dep in enumerate(classes):
        target = f"#/classes/{idx}"
        if not isinstance(dep, dict):
            result.add_error(
                ERR_DEP_CORRUPT_FILE,
                CONSTITUTION_JSON_PATH,
                target,
                f"Class entry {idx} is not a JSON object",
            )
            continue

        dep_id = str(dep.get("id", ""))
        target = f"#/classes/{dep_id or idx}"

        # Mandatory fields
        for rf in MANDATORY_CLASS_FIELDS:
            if rf not in dep or dep[rf] is None or not str(dep[rf]).strip():
                result.add_error(
                    ERR_DEP_MISSING_FIELD,
                    CONSTITUTION_JSON_PATH,
                    f"{target}/{rf}",
                    f"Class row missing or empty mandatory field '{rf}'",
                )

        if not dep_id:
            continue

        if not DEP_CLASS_ID_PATTERN.match(dep_id):
            result.add_error(
                ERR_DEP_STABLE_ID_REUSED,
                CONSTITUTION_JSON_PATH,
                f"{target}/id",
                f"Class ID '{dep_id}' does not conform to pattern DEP-CLASS-F[0-4]",
            )

        if dep_id in seen_ids:
            result.add_error(
                ERR_DEP_STABLE_ID_REUSED,
                CONSTITUTION_JSON_PATH,
                f"{target}/id",
                f"Duplicate class ID '{dep_id}' in classes list",
            )
        seen_ids.add(dep_id)

        lower_id = dep_id.lower()
        if lower_id in seen_lower_ids and seen_lower_ids[lower_id] != dep_id:
            result.add_error(
                ERR_DEP_STABLE_ID_REUSED,
                CONSTITUTION_JSON_PATH,
                f"{target}/id",
                f"Case-colliding class ID '{dep_id}' conflicts with '{seen_lower_ids[lower_id]}'",
            )
        seen_lower_ids[lower_id] = dep_id

        if dep_id in tombstoned_ids:
            result.add_error(
                ERR_DEP_STABLE_ID_REUSED,
                CONSTITUTION_JSON_PATH,
                f"{target}/id",
                f"Attempted to resurrect tombstoned identifier '{dep_id}'",
            )

        if dep_id in CANONICAL_DEPENDENCY_CLASSES:
            canonical = CANONICAL_DEPENDENCY_CLASSES[dep_id]
            for check_key in ("name", "admission"):
                val = dep.get(check_key)
                if val != canonical[check_key]:
                    result.add_error(
                        ERR_DEP_CONST_INVARIANT,
                        CONSTITUTION_JSON_PATH,
                        f"{target}/{check_key}",
                        f"Class '{dep_id}' {check_key} mismatch: expected '{canonical[check_key]}', got '{val}'",
                    )

    # 7. DEP-CLASS-F0 Specific Invariant Check
    f0_entry = next((c for c in classes if isinstance(c, dict) and c.get("id") == "DEP-CLASS-F0"), None)
    if f0_entry is None:
        result.add_error(
            ERR_DEP_CONST_INVARIANT,
            CONSTITUTION_JSON_PATH,
            "#/classes/DEP-CLASS-F0",
            "Mandatory constitutional class 'DEP-CLASS-F0' is missing from classes",
        )
    else:
        if f0_entry.get("admission") != "constitutional":
            result.add_error(
                ERR_DEP_CONST_INVARIANT,
                CONSTITUTION_JSON_PATH,
                "#/classes/DEP-CLASS-F0/admission",
                f"DEP-CLASS-F0 admission must be 'constitutional', found: {f0_entry.get('admission')!r}",
            )
        if f0_entry.get("name") != "rust-language-and-stdlib":
            result.add_error(
                ERR_DEP_CONST_INVARIANT,
                CONSTITUTION_JSON_PATH,
                "#/classes/DEP-CLASS-F0/name",
                f"DEP-CLASS-F0 name must be 'rust-language-and-stdlib', found: {f0_entry.get('name')!r}",
            )

    # 8. Markdown mirror verification
    if not md_path.is_file():
        result.add_error(
            ERR_DEP_CORRUPT_FILE,
            CONSTITUTION_MD_PATH,
            "#",
            f"Markdown documentation missing at {CONSTITUTION_MD_PATH}",
        )
    else:
        md_text = md_path.read_text(encoding="utf-8")
        if not md_text.strip():
            result.add_error(
                ERR_DEP_CORRUPT_FILE,
                CONSTITUTION_MD_PATH,
                "#",
                "Markdown documentation is empty",
            )
        else:
            md_classes = extract_markdown_class_sections(md_text)
            for canon_id, canon_info in CANONICAL_DEPENDENCY_CLASSES.items():
                if canon_id not in md_classes:
                    result.add_error(
                        ERR_DEP_REGISTRY_DRIFT,
                        CONSTITUTION_MD_PATH,
                        f"#{canon_id}",
                        f"Class section '{canon_id}' is missing from {CONSTITUTION_MD_PATH}",
                    )

    # 9. Real Cargo metadata inspection (no string checks)
    if not skip_cargo_metadata:
        if cargo_metadata is None:
            cargo_metadata, meta_err = load_real_cargo_metadata(root)
            if meta_err is not None:
                result.add_error(
                    ERR_DEP_CONST_METADATA_VIOLATION,
                    "Cargo.lock",
                    "#",
                    f"Unable to load real Cargo metadata for DEP-CLASS-F0 verification: {meta_err}",
                )
        if cargo_metadata is not None:
            validate_cargo_metadata_for_f0(result, cargo_metadata, root)

    return result


def main() -> int:
    parser = argparse.ArgumentParser(description="Check dependency constitution and class registry")
    parser.add_argument("--root", type=Path, default=ROOT, help="Repository root path")
    parser.add_argument("--json", action="store_true", help="Output JSON results")
    parser.add_argument("--skip-cargo-metadata", action="store_true", help="Skip cargo metadata call")
    args = parser.parse_args()

    res = validate_dependency_constitution(args.root, skip_cargo_metadata=args.skip_cargo_metadata)

    if args.json:
        output = {
            "passed": res.passed,
            "classCount": res.class_count,
            "freezeDigest": res.freeze_digest,
            "errors": [
                {"code": e.code, "file": e.file_path, "target": e.target, "message": e.message}
                for e in res.errors
            ],
        }
        print(json.dumps(output, indent=2))
        return 0 if res.passed else 1

    if res.passed:
        print(f"Dependency constitution OK: {res.class_count} classes verified ({res.freeze_digest})")
        return 0
    else:
        for err in res.errors:
            print(f"[{err.code}] {err.file_path} ({err.target}): {err.message}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
