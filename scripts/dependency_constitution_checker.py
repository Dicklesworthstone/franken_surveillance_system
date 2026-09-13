#!/usr/bin/env python3
"""Fail-closed dependency constitution and class registry checker (fss-x4a.30.88.16).

Enforces the dependency constitution and DEP-CLASS-F0 (rust-language-and-stdlib) contract:
1. Pinned freeze digest covering all fields, metadata, production settings, and generation.
2. Exact digest assertion against BASELINE_DEPENDENCY_CONSTITUTION_FREEZE_DIGEST.
3. Mandatory generation bump enforcement (ERR-DEP-GENERATION-MISMATCH-001, ERR-DEP-FREEZE-DIVERGENCE-001).
4. Baseline-checked dependency classes (DEP-CLASS-F0 through DEP-CLASS-F4) against canonical baseline.
5. Semantic invariants for DEP-CLASS-F0 (admission must be 'constitutional', production must be 'rust-2024',
   unsafe forbidden, asupersync-only runtime, closed universe, no C/C++ FFI).
6. Fail-closed toolchain identity verification: checks rust-toolchain.toml and rustc -Vv.
7. Real Cargo metadata inspection: parses packages, verifies edition '2024', forbids native C/C++ links,
   forbids custom-build / proc-macro targets in production closure, censuses unadmitted crates against allowlist,
   and ensures workspace metadata production_language is 'rust'.
8. 16-policy allowlist crosswalk and dependencies.json scope/constitutionClass consistency.
9. Substantive Markdown mirror verification against docs/DEPENDENCY_CONSTITUTION.md (titles, duplicates, semantics).
"""
from __future__ import annotations

import argparse
import fnmatch
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
ERR_DEP_CONST_DRIFT = "ERR-DEP-CONST-DRIFT-001"
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
DEPENDENCIES_JSON_PATH = "architecture/dependencies.json"
ALLOWLIST_TOML_PATH = "architecture/dependency_allowlist.toml"
STABLE_ID_RESOLUTION_PATH = "architecture/stable_id_resolution.json"
RUST_TOOLCHAIN_PATH = "rust-toolchain.toml"

BASELINE_DEPENDENCY_CONSTITUTION_GENERATION = "gen:fss1:dep-constitution-v1"
BASELINE_DEPENDENCY_CONSTITUTION_FREEZE_DIGEST = (
    "sha256:858af1b5482b25cfca1477c2c4c1967a995d802990aaf0bc7ccf139f73571310"
)

# Operational constants (ADR-0012 / DSR local execution bounds)
CARGO_METADATA_TIMEOUT_SECONDS: int = 30
REQUIRED_RUST_CHANNEL: str = "nightly-2026-08-31"

EXPECTED_FREEZE_DIGESTS: dict[str, str] = {
    BASELINE_DEPENDENCY_CONSTITUTION_GENERATION: BASELINE_DEPENDENCY_CONSTITUTION_FREEZE_DIGEST,
}

CANONICAL_CONSTITUTION_CLASSES: dict[str, dict[str, str]] = {
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

CANONICAL_CONSTITUTION_MARKDOWN_TITLES: dict[str, str] = {
    "DEP-CLASS-F0": "Rust language and standard library",
    "DEP-CLASS-F1": "Asupersync",
    "DEP-CLASS-F2": "admitted Franken-suite crates",
    "DEP-CLASS-F3": "fundamental external Rust crates",
    "DEP-CLASS-F4": "laboratory and migration oracles",
}

CANONICAL_DEPENDENCY_CLASSES = CANONICAL_CONSTITUTION_CLASSES

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
ALLOWED_TOP_LEVEL_FIELDS: set[str] = set(MANDATORY_TOP_LEVEL_FIELDS)

MANDATORY_CLASS_FIELDS: tuple[str, ...] = (
    "id",
    "name",
    "admission",
)
ALLOWED_CLASS_FIELDS: set[str] = set(MANDATORY_CLASS_FIELDS)

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
ALLOWED_PRODUCTION_FIELDS: set[str] = set(MANDATORY_PRODUCTION_FIELDS)

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

# All 16 policy flags in architecture/dependency_allowlist.toml [policy]
REQUIRED_ALLOWLIST_POLICY: dict[str, bool] = {
    "closed_universe": True,
    "direct_crates_must_be_allowlisted": True,
    "transitive_closure_must_be_censused": True,
    "new_external_dependency_requires_dep_record_and_adr": True,
    "fss_crates_must_forbid_unsafe": True,
    "fss_unsafe_exceptions_allowed": False,
    "c_or_cpp_ffi_allowed": False,
    "dynamic_loading_allowed": False,
    "foreign_runtime_production_boundary_allowed": False,
    "release_resolution_must_be_locked_and_offline": True,
    "build_scripts_may_not_use_network": True,
    "runtime_acquisition_allowed": False,
    "foreign_executables_allowed_in_production": False,
    "serde_may_not_define_durable_bytes": True,
    "hosted_ci_is_not_release_authority": True,
    "asupersync_is_only_async_runtime": True,
}

VALID_DEPENDENCY_SCOPES: set[str] = {
    "Production",
    "Production subject to audit",
    "Development only",
    "Development/migration only",
    "Not admitted",
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
    class_count: int = 0
    freeze_digest: str = ""
    errors: list[DiagnosticError] = field(default_factory=list)

    def add_error(self, code: str, file_path: str, target: str, message: str) -> None:
        self.passed = False
        self.errors.append(DiagnosticError(code=code, file_path=file_path, target=target, message=message))


def pairs_hook_reject_duplicates(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    """Rejects duplicate JSON keys during object construction."""
    d: dict[str, Any] = {}
    for k, v in pairs:
        if k in d:
            raise ValueError(f"Duplicate JSON key: {k!r}")
        d[k] = v
    return d


def canonicalize_value(val: Any) -> Any:
    """Recursively canonicalizes dict and list structures preserving typed values without arbitrary heuristics."""
    if isinstance(val, dict):
        return {k: canonicalize_value(v) for k, v in sorted(val.items())}
    if isinstance(val, list):
        return [canonicalize_value(x) for x in val]
    return val


def compute_canonical_constitution_digest(data: dict[str, Any]) -> str:
    """Computes deterministic sha256 digest of dependency constitution covering all fields and metadata.

    Preserves typed values (no str() coercion) to ensure distinct types hash distinctly.
    """
    raw_evidence = data.get("releaseEvidence")
    if isinstance(raw_evidence, list):
        canon_evidence: Any = sorted([canonicalize_value(x) for x in raw_evidence])
    else:
        canon_evidence = canonicalize_value(raw_evidence)

    raw_classes = data.get("classes")
    if isinstance(raw_classes, list):
        canon_classes = sorted(
            [canonicalize_value(c) for c in raw_classes if isinstance(c, dict)],
            key=lambda x: str(x.get("id", "")),
        )
    else:
        canon_classes = canonicalize_value(raw_classes)

    canonical_payload = {
        "schema": canonicalize_value(data.get("schema")),
        "asOf": canonicalize_value(data.get("asOf")),
        "generation": canonicalize_value(data.get("generation")),
        "normativePolicy": canonicalize_value(data.get("normativePolicy")),
        "production": canonicalize_value(data.get("production")),
        "classes": canon_classes,
        "releaseEvidence": canon_evidence,
    }
    payload_bytes = json.dumps(canonical_payload, sort_keys=True, separators=(",", ":")).encode("utf-8")
    return f"sha256:{hashlib.sha256(payload_bytes).hexdigest()}"


def load_tombstoned_ids(root: Path) -> tuple[set[str], list[DiagnosticError]]:
    """Loads tombstoned identifiers from architecture/stable_id_resolution.json, failing closed on any error."""
    res_path = root / STABLE_ID_RESOLUTION_PATH
    if not res_path.is_file():
        return set(), [
            DiagnosticError(
                code=ERR_DEP_CORRUPT_FILE,
                file_path=STABLE_ID_RESOLUTION_PATH,
                target="#",
                message=f"Stable ID resolution file missing at {STABLE_ID_RESOLUTION_PATH}",
            )
        ]
    try:
        raw_bytes = res_path.read_bytes()
        if not raw_bytes.strip():
            return set(), [
                DiagnosticError(
                    code=ERR_DEP_CORRUPT_FILE,
                    file_path=STABLE_ID_RESOLUTION_PATH,
                    target="#",
                    message="Stable ID resolution file is 0 bytes / empty",
                )
            ]
        text = raw_bytes.decode("utf-8")
        data = json.loads(text, object_pairs_hook=pairs_hook_reject_duplicates)
        if not isinstance(data, dict):
            return set(), [
                DiagnosticError(
                    code=ERR_DEP_CORRUPT_FILE,
                    file_path=STABLE_ID_RESOLUTION_PATH,
                    target="#",
                    message="Stable ID resolution root must be a JSON object",
                )
            ]
        resolutions = data.get("resolutions")
        if not isinstance(resolutions, list):
            return set(), [
                DiagnosticError(
                    code=ERR_DEP_CORRUPT_FILE,
                    file_path=STABLE_ID_RESOLUTION_PATH,
                    target="#/resolutions",
                    message="Field 'resolutions' must be a JSON list in stable_id_resolution.json",
                )
            ]
        return {
            str(r.get("legacyId")).strip()
            for r in resolutions
            if isinstance(r, dict) and r.get("status") in ("tombstoned", "tombstone", "superseded") and r.get("legacyId")
        }, []
    except Exception as exc:
        return set(), [
            DiagnosticError(
                code=ERR_DEP_CORRUPT_FILE,
                file_path=STABLE_ID_RESOLUTION_PATH,
                target="#",
                message=f"Could not load tombstoned IDs: {exc}",
            )
        ]


def extract_markdown_class_sections(md_text: str) -> tuple[dict[str, tuple[str, str]], list[str]]:
    """Extracts Class F* sections from docs/DEPENDENCY_CONSTITUTION.md, detecting duplicates.

    Returns: (classes_dict: {id: (name, body)}, duplicate_ids: [id, ...])
    """
    pattern = re.compile(r"^###\s+2\.\d+\s+Class\s+(F[0-4])\s*[—–-]\s*(.+)$", re.MULTILINE)
    matches = list(pattern.finditer(md_text))
    classes: dict[str, tuple[str, str]] = {}
    duplicates: list[str] = []
    for i, match in enumerate(matches):
        class_suffix, class_name = match.groups()
        class_id = f"DEP-CLASS-{class_suffix}"
        if class_id in classes:
            duplicates.append(class_id)
        start = match.end()
        end = matches[i + 1].start() if i + 1 < len(matches) else len(md_text)
        body = md_text[start:end].strip()
        classes[class_id] = (class_name.strip(), body)
    return classes, duplicates


def validate_toolchain_identity(root: Path, result: ValidationResult) -> str | None:
    """Fails closed if rust-toolchain.toml is missing, unparseable, or channel != REQUIRED_RUST_CHANNEL."""
    toolchain_file = root / RUST_TOOLCHAIN_PATH
    if not toolchain_file.is_file():
        result.add_error(
            ERR_DEP_CORRUPT_FILE,
            RUST_TOOLCHAIN_PATH,
            "#",
            f"Toolchain file missing at {RUST_TOOLCHAIN_PATH}",
        )
        return None

    try:
        raw_text = toolchain_file.read_text(encoding="utf-8")
        if not raw_text.strip():
            result.add_error(
                ERR_DEP_CORRUPT_FILE,
                RUST_TOOLCHAIN_PATH,
                "#",
                "Toolchain file is empty",
            )
            return None
        import tomllib
        tc = tomllib.loads(raw_text)
    except Exception as exc:
        result.add_error(
            ERR_DEP_CORRUPT_FILE,
            RUST_TOOLCHAIN_PATH,
            "#",
            f"Failed to parse rust-toolchain.toml: {exc}",
        )
        return None

    if not isinstance(tc, dict):
        result.add_error(
            ERR_DEP_CORRUPT_FILE,
            RUST_TOOLCHAIN_PATH,
            "#",
            "Toolchain TOML root must be a table",
        )
        return None

    toolchain_sec = tc.get("toolchain")
    if not isinstance(toolchain_sec, dict):
        result.add_error(
            ERR_DEP_CORRUPT_FILE,
            RUST_TOOLCHAIN_PATH,
            "#/toolchain",
            "Missing [toolchain] section in rust-toolchain.toml",
        )
        return None

    channel = toolchain_sec.get("channel")
    if channel != REQUIRED_RUST_CHANNEL:
        result.add_error(
            ERR_DEP_CONST_INVARIANT,
            RUST_TOOLCHAIN_PATH,
            "#/toolchain/channel",
            f"Toolchain channel must be {REQUIRED_RUST_CHANNEL!r}, found {channel!r}",
        )
        return None

    profile = toolchain_sec.get("profile")
    if profile != "minimal":
        result.add_error(
            ERR_DEP_CONST_INVARIANT,
            RUST_TOOLCHAIN_PATH,
            "#/toolchain/profile",
            f"Toolchain profile must be 'minimal', found {profile!r}",
        )

    # Validate rustc -Vv reports pinned nightly channel
    cmd = ["rustup", "run", REQUIRED_RUST_CHANNEL, "rustc", "-Vv"]
    try:
        proc = subprocess.run(cmd, cwd=root, capture_output=True, text=True, timeout=CARGO_METADATA_TIMEOUT_SECONDS)
        if proc.returncode != 0:
            result.add_error(
                ERR_DEP_CORRUPT_FILE,
                RUST_TOOLCHAIN_PATH,
                "#",
                f"rustc -Vv failed with exit code {proc.returncode}: {proc.stderr.strip()}",
            )
        elif "nightly" not in proc.stdout:
            result.add_error(
                ERR_DEP_CONST_INVARIANT,
                RUST_TOOLCHAIN_PATH,
                "#",
                f"rustc -Vv does not report nightly release: {proc.stdout.strip()}",
            )
    except Exception as exc:
        result.add_error(
            ERR_DEP_CORRUPT_FILE,
            RUST_TOOLCHAIN_PATH,
            "#",
            f"Unable to execute rustc -Vv: {exc}",
        )

    return channel


def load_real_cargo_metadata(root: Path, channel: str = REQUIRED_RUST_CHANNEL) -> tuple[dict[str, Any] | None, str | None]:
    """Invokes cargo metadata --locked --offline --all-features to fetch real Cargo metadata."""
    cmd = [
        "rustup",
        "run",
        channel,
        "cargo",
        "metadata",
        "--locked",
        "--offline",
        "--all-features",
        "--format-version",
        "1",
    ]
    try:
        proc = subprocess.run(
            cmd,
            cwd=root,
            capture_output=True,
            text=True,
            timeout=CARGO_METADATA_TIMEOUT_SECONDS,
        )
        if proc.returncode != 0:
            return None, f"cargo metadata failed with exit code {proc.returncode}: {proc.stderr.strip() or proc.stdout.strip()}"
        try:
            data = json.loads(proc.stdout, object_pairs_hook=pairs_hook_reject_duplicates)
            return data, None
        except Exception as exc:
            return None, f"cargo metadata output is not valid JSON: {exc}"
    except subprocess.TimeoutExpired:
        return None, f"cargo metadata timed out after {CARGO_METADATA_TIMEOUT_SECONDS}s"
    except Exception as exc:
        return None, f"cargo metadata execution error: {exc}"


def validate_cargo_metadata_for_f0(
    result: ValidationResult,
    metadata: Any,
    root: Path,
    allow_data: dict[str, Any] | None = None,
) -> None:
    """Inspects real Cargo metadata structure for constitutional language/stdlib conformance (DEP-CLASS-F0).

    Safe against non-dict metadata root, null packages/workspace_members, and non-dict workspace metadata.
    Enforces closed universe, edition 2024, no native links, no build scripts or proc macros.
    """
    if not isinstance(metadata, dict):
        result.add_error(
            ERR_DEP_CONST_METADATA_VIOLATION,
            "Cargo.lock",
            "#",
            "Cargo metadata root must be a JSON object",
        )
        return

    raw_members = metadata.get("workspace_members")
    workspace_members = set(raw_members) if isinstance(raw_members, list) else set()
    raw_packages = metadata.get("packages")
    packages = raw_packages if isinstance(raw_packages, list) else []

    # 1. Inspect workspace metadata production_language
    meta_obj = metadata.get("metadata")
    fss_meta = meta_obj.get("fss") if isinstance(meta_obj, dict) else None
    prod_lang = fss_meta.get("production_language") if isinstance(fss_meta, dict) else None
    if prod_lang != "rust":
        result.add_error(
            ERR_DEP_CONST_METADATA_VIOLATION,
            "Cargo.toml",
            "#/metadata/fss/production_language",
            f"Cargo metadata production_language must be 'rust', found: {prod_lang!r}",
        )

    # 2. Extract allowed and forbidden closure sets from allowlist
    forbidden_crates = set()
    allowed_fundamental = {"serde", "serde_json"}
    allowed_families: list[str] = []
    not_admitted_candidates: set[str] = set()

    if allow_data and isinstance(allow_data, dict):
        forb_sec = allow_data.get("forbidden", {})
        if isinstance(forb_sec, dict):
            forbidden_crates = set(forb_sec.get("crates", []))

        fund_sec = allow_data.get("fundamental", {})
        if isinstance(fund_sec, dict) and isinstance(fund_sec.get("allowed_subject_to_audit"), list):
            allowed_fundamental = set(fund_sec.get("allowed_subject_to_audit", []))

        inhouse_sec = allow_data.get("in_house", {})
        if isinstance(inhouse_sec, dict) and isinstance(inhouse_sec.get("allowed_families"), list):
            allowed_families = list(inhouse_sec.get("allowed_families", []))

        exc_sec = allow_data.get("exception_candidates", {})
        if isinstance(exc_sec, dict) and isinstance(exc_sec.get("not_admitted_without_dep_record_adr_and_release_evidence"), list):
            not_admitted_candidates = set(exc_sec.get("not_admitted_without_dep_record_adr_and_release_evidence", []))

    # 3. Inspect workspace member packages and non-member closure packages
    for pkg in packages:
        if not isinstance(pkg, dict):
            continue
        pkg_id = pkg.get("id")
        pkg_name = pkg.get("name", "<unknown>")
        targets = pkg.get("targets", [])
        if not isinstance(targets, list):
            targets = []

        # Reject custom-build (build.rs) and proc-macro targets in production closure
        has_custom_build = any(
            isinstance(t, dict) and "custom-build" in t.get("kind", [])
            for t in targets
        )
        if has_custom_build:
            result.add_error(
                ERR_DEP_CONST_METADATA_VIOLATION,
                str(pkg.get("manifest_path", "Cargo.lock")),
                f"#{pkg_name}/targets/custom-build",
                f"Package '{pkg_name}' declares custom-build (build.rs) target violating pure-Rust DEP-CLASS-F0",
            )

        has_proc_macro = any(
            isinstance(t, dict) and "proc-macro" in t.get("kind", [])
            for t in targets
        )
        if has_proc_macro:
            result.add_error(
                ERR_DEP_CONST_METADATA_VIOLATION,
                str(pkg.get("manifest_path", "Cargo.lock")),
                f"#{pkg_name}/targets/proc-macro",
                f"Package '{pkg_name}' declares proc-macro target violating pure-Rust DEP-CLASS-F0",
            )

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
        else:
            # Non-member package in closure
            if pkg_name in forbidden_crates:
                result.add_error(
                    ERR_DEP_CONST_METADATA_VIOLATION,
                    "Cargo.lock",
                    f"#{pkg_name}",
                    f"Forbidden crate '{pkg_name}' detected in dependency closure violating DEP-CLASS-F0",
                )
            elif pkg_name in not_admitted_candidates:
                result.add_error(
                    ERR_DEP_CONST_METADATA_VIOLATION,
                    "Cargo.lock",
                    f"#{pkg_name}",
                    f"Exception candidate '{pkg_name}' is not admitted without DEP record and ADR violating DEP-CLASS-F0",
                )
            else:
                # Must be admitted under fundamental or in-house families
                is_admitted = (
                    pkg_name in allowed_fundamental
                    or any(fnmatch.fnmatch(pkg_name, fam) for fam in allowed_families)
                )
                if not is_admitted:
                    result.add_error(
                        ERR_DEP_CONST_METADATA_VIOLATION,
                        "Cargo.lock",
                        f"#{pkg_name}",
                        f"Unadmitted external crate '{pkg_name}' detected in dependency closure violating pure-Rust closed universe",
                    )

            links = pkg.get("links")
            if links:
                result.add_error(
                    ERR_DEP_CONST_METADATA_VIOLATION,
                    str(pkg.get("manifest_path", "Cargo.lock")),
                    f"#{pkg_name}/links",
                    f"Non-member package '{pkg_name}' in closure declares native links '{links}' violating pure-Rust DEP-CLASS-F0",
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

    try:
        raw_bytes = json_path.read_bytes()
    except OSError as exc:
        result.add_error(
            ERR_DEP_CORRUPT_FILE,
            CONSTITUTION_JSON_PATH,
            "#",
            f"Could not read dependency constitution JSON: {exc}",
        )
        return result

    if not raw_bytes.strip():
        result.add_error(
            ERR_DEP_CORRUPT_FILE,
            CONSTITUTION_JSON_PATH,
            "#",
            "Dependency constitution file is 0 bytes / empty",
        )
        return result

    try:
        raw_text = raw_bytes.decode("utf-8")
    except UnicodeDecodeError as exc:
        result.add_error(
            ERR_DEP_CORRUPT_FILE,
            CONSTITUTION_JSON_PATH,
            "#",
            f"Invalid UTF-8 in dependency constitution JSON: {exc}",
        )
        return result

    try:
        data = json.loads(raw_text, object_pairs_hook=pairs_hook_reject_duplicates)
    except (json.JSONDecodeError, RecursionError, ValueError) as exc:
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

    # 2. Reject unexpected keys (top-level, production, class rows)
    for k in data:
        if k not in ALLOWED_TOP_LEVEL_FIELDS:
            result.add_error(
                ERR_DEP_CORRUPT_FILE,
                CONSTITUTION_JSON_PATH,
                f"#/{k}",
                f"Unexpected top-level key '{k}' in dependency constitution",
            )

    prod = data.get("production")
    if isinstance(prod, dict):
        for pk in prod:
            if pk not in ALLOWED_PRODUCTION_FIELDS:
                result.add_error(
                    ERR_DEP_CORRUPT_FILE,
                    CONSTITUTION_JSON_PATH,
                    f"#/production/{pk}",
                    f"Unexpected key '{pk}' in production object",
                )

    cls_list = data.get("classes")
    if isinstance(cls_list, list):
        for idx, dep in enumerate(cls_list):
            if isinstance(dep, dict):
                for rk in dep:
                    if rk not in ALLOWED_CLASS_FIELDS:
                        result.add_error(
                            ERR_DEP_CORRUPT_FILE,
                            CONSTITUTION_JSON_PATH,
                            f"#/classes/{idx}/{rk}",
                            f"Unexpected key '{rk}' in class row at index {idx}",
                        )

    # 3. Mandatory top-level fields
    for field_name in MANDATORY_TOP_LEVEL_FIELDS:
        if field_name not in data or data[field_name] is None:
            result.add_error(
                ERR_DEP_MISSING_FIELD,
                CONSTITUTION_JSON_PATH,
                f"#/{field_name}",
                f"Missing mandatory top-level field '{field_name}'",
            )
        elif isinstance(data[field_name], str):
            val = data[field_name]
            if not val:
                result.add_error(
                    ERR_DEP_MISSING_FIELD,
                    CONSTITUTION_JSON_PATH,
                    f"#/{field_name}",
                    f"Mandatory top-level field '{field_name}' must not be empty",
                )
            elif val != val.strip():
                result.add_error(
                    ERR_DEP_CORRUPT_FILE,
                    CONSTITUTION_JSON_PATH,
                    f"#/{field_name}",
                    f"Field '{field_name}' contains illegal leading/trailing whitespace",
                )
        elif field_name in ("schema", "asOf", "generation", "freezeDigest", "normativePolicy"):
            result.add_error(
                ERR_DEP_CORRUPT_FILE,
                CONSTITUTION_JSON_PATH,
                f"#/{field_name}",
                f"Top-level field '{field_name}' must be a string, got {type(data[field_name]).__name__}",
            )

    # Validate releaseEvidence structure
    if "releaseEvidence" in data:
        raw_ev = data.get("releaseEvidence")
        if not isinstance(raw_ev, list) or len(raw_ev) == 0:
            result.add_error(
                ERR_DEP_CORRUPT_FILE,
                CONSTITUTION_JSON_PATH,
                "#/releaseEvidence",
                "releaseEvidence must be a non-empty list of strings",
            )
        else:
            for idx, ev_item in enumerate(raw_ev):
                if not isinstance(ev_item, str) or not ev_item:
                    result.add_error(
                        ERR_DEP_CORRUPT_FILE,
                        CONSTITUTION_JSON_PATH,
                        f"#/releaseEvidence/{idx}",
                        f"releaseEvidence item at index {idx} must be a non-empty string",
                    )
                elif ev_item != ev_item.strip():
                    result.add_error(
                        ERR_DEP_CORRUPT_FILE,
                        CONSTITUTION_JSON_PATH,
                        f"#/releaseEvidence/{idx}",
                        f"releaseEvidence item at index {idx} contains whitespace padding",
                    )

    if not result.passed and any(e.code in (ERR_DEP_MISSING_FIELD, ERR_DEP_CORRUPT_FILE) for e in result.errors):
        return result

    generation = str(data.get("generation", ""))
    declared_freeze_digest = str(data.get("freezeDigest", ""))
    result.freeze_digest = declared_freeze_digest

    # 4. Generation binding
    if generation not in EXPECTED_FREEZE_DIGESTS:
        result.add_error(
            ERR_DEP_GENERATION_MISMATCH,
            CONSTITUTION_JSON_PATH,
            "#/generation",
            f"Dependency constitution generation '{generation}' is unrecognized; expected one of {list(EXPECTED_FREEZE_DIGESTS.keys())}",
        )

    # 5. Freeze digest verification
    expected_digest = EXPECTED_FREEZE_DIGESTS.get(generation)
    try:
        computed_digest = compute_canonical_constitution_digest(data)
    except Exception as exc:
        result.add_error(
            ERR_DEP_CORRUPT_FILE,
            CONSTITUTION_JSON_PATH,
            "#/freezeDigest",
            f"Failed to compute canonical constitution digest: {exc}",
        )
        return result

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

    # 6. Production requirements verification
    production = data.get("production", {})
    if not isinstance(production, dict):
        result.add_error(
            ERR_DEP_MISSING_FIELD,
            CONSTITUTION_JSON_PATH,
            "#/production",
            "Top-level 'production' field must be a JSON object",
        )
    else:
        for pk in production:
            if pk not in ALLOWED_PRODUCTION_FIELDS:
                result.add_error(
                    ERR_DEP_CORRUPT_FILE,
                    CONSTITUTION_JSON_PATH,
                    f"#/production/{pk}",
                    f"Unexpected key '{pk}' in production object",
                )
        for p_field in MANDATORY_PRODUCTION_FIELDS:
            if p_field not in production:
                result.add_error(
                    ERR_DEP_MISSING_FIELD,
                    CONSTITUTION_JSON_PATH,
                    f"#/production/{p_field}",
                    f"Missing mandatory production field '{p_field}'",
                )
            else:
                pval = production[p_field]
                if isinstance(pval, str) and pval != pval.strip():
                    result.add_error(
                        ERR_DEP_CORRUPT_FILE,
                        CONSTITUTION_JSON_PATH,
                        f"#/production/{p_field}",
                        f"Production field '{p_field}' contains illegal whitespace padding",
                    )
                elif pval != REQUIRED_PRODUCTION_VALUES[p_field]:
                    result.add_error(
                        ERR_DEP_CONST_INVARIANT,
                        CONSTITUTION_JSON_PATH,
                        f"#/production/{p_field}",
                        f"Production invariant violation for '{p_field}': expected {REQUIRED_PRODUCTION_VALUES[p_field]!r}, got {pval!r}",
                    )

    # 7. Classes validation
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
    if len(classes) != len(CANONICAL_CONSTITUTION_CLASSES):
        result.add_error(
            ERR_DEP_REGISTRY_DRIFT,
            CONSTITUTION_JSON_PATH,
            "#/classes",
            f"Expected {len(CANONICAL_CONSTITUTION_CLASSES)} classes, found {len(classes)}",
        )

    seen_ids: set[str] = set()
    seen_lower_ids: dict[str, str] = {}
    tombstoned_ids, tomb_errs = load_tombstoned_ids(root)
    for terr in tomb_errs:
        result.add_error(terr.code, terr.file_path, terr.target, terr.message)

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

        for rk in dep:
            if rk not in ALLOWED_CLASS_FIELDS:
                result.add_error(
                    ERR_DEP_CORRUPT_FILE,
                    CONSTITUTION_JSON_PATH,
                    f"{target}/{rk}",
                    f"Unexpected key '{rk}' in class row at index {idx}",
                )

        dep_id = dep.get("id")
        target = f"#/classes/{dep_id or idx}"
        if not isinstance(dep_id, str) or not dep_id:
            result.add_error(
                ERR_DEP_MISSING_FIELD,
                CONSTITUTION_JSON_PATH,
                f"{target}/id",
                f"Class row at index {idx} missing mandatory 'id' field",
            )
            continue

        if dep_id != dep_id.strip():
            result.add_error(
                ERR_DEP_CORRUPT_FILE,
                CONSTITUTION_JSON_PATH,
                f"{target}/id",
                f"Class ID '{dep_id}' contains illegal whitespace padding",
            )

        for rf in MANDATORY_CLASS_FIELDS:
            rval = dep.get(rf)
            if rval is None or not isinstance(rval, str) or not rval:
                result.add_error(
                    ERR_DEP_MISSING_FIELD,
                    CONSTITUTION_JSON_PATH,
                    f"{target}/{rf}",
                    f"Class row missing or empty mandatory field '{rf}'",
                )
            elif rval != rval.strip():
                result.add_error(
                    ERR_DEP_CORRUPT_FILE,
                    CONSTITUTION_JSON_PATH,
                    f"{target}/{rf}",
                    f"Class row field '{rf}' contains illegal whitespace padding",
                )

        if not DEP_CLASS_ID_PATTERN.match(dep_id):
            result.add_error(
                ERR_DEP_CONST_INVARIANT,
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

        if dep_id in CANONICAL_CONSTITUTION_CLASSES:
            canonical = CANONICAL_CONSTITUTION_CLASSES[dep_id]
            for check_key in ("name", "admission"):
                val = dep.get(check_key)
                if val != canonical[check_key]:
                    result.add_error(
                        ERR_DEP_CONST_INVARIANT,
                        CONSTITUTION_JSON_PATH,
                        f"{target}/{check_key}",
                        f"Class '{dep_id}' {check_key} mismatch: expected '{canonical[check_key]}', got '{val}'",
                    )

    # 8. DEP-CLASS-F0 & F4 Specific Invariant Checks
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

    f4_entry = next((c for c in classes if isinstance(c, dict) and c.get("id") == "DEP-CLASS-F4"), None)
    if f4_entry is not None:
        if f4_entry.get("admission") != "non-production-quarantine-only":
            result.add_error(
                ERR_DEP_CONST_INVARIANT,
                CONSTITUTION_JSON_PATH,
                "#/classes/DEP-CLASS-F4/admission",
                f"DEP-CLASS-F4 admission must be 'non-production-quarantine-only', found: {f4_entry.get('admission')!r}",
            )

    # 9. Cross-checks against architecture/dependencies.json
    dep_json_path = root / DEPENDENCIES_JSON_PATH
    if dep_json_path.is_file():
        try:
            dep_bytes = dep_json_path.read_bytes()
            dep_data = json.loads(dep_bytes.decode("utf-8"), object_pairs_hook=pairs_hook_reject_duplicates)
            for dep_row in dep_data.get("dependencies", []):
                if isinstance(dep_row, dict):
                    c_class = dep_row.get("constitutionClass")
                    d_id = dep_row.get("id", "<unknown>")
                    scope = dep_row.get("scope")

                    if not c_class or c_class not in CANONICAL_CONSTITUTION_CLASSES:
                        result.add_error(
                            ERR_DEP_CONST_INVARIANT,
                            DEPENDENCIES_JSON_PATH,
                            f"row/{d_id}/constitutionClass",
                            f"Dependency '{d_id}' missing or unknown constitutionClass: {c_class!r}",
                        )

                    if scope not in VALID_DEPENDENCY_SCOPES:
                        result.add_error(
                            ERR_DEP_CONST_INVARIANT,
                            DEPENDENCIES_JSON_PATH,
                            f"row/{d_id}/scope",
                            f"Dependency '{d_id}' has invalid scope {scope!r}; must be one of {sorted(VALID_DEPENDENCY_SCOPES)}",
                        )

                    if c_class == "DEP-CLASS-F3" and scope == "Production":
                        result.add_error(
                            ERR_DEP_CONST_INVARIANT,
                            DEPENDENCIES_JSON_PATH,
                            f"row/{d_id}/scope",
                            f"Dependency '{d_id}' mapped to external fundamental class DEP-CLASS-F3 cannot have unreserved Production scope",
                        )

                    if c_class == "DEP-CLASS-F4" and scope in ("Production", "Production subject to audit"):
                        result.add_error(
                            ERR_DEP_CONST_INVARIANT,
                            DEPENDENCIES_JSON_PATH,
                            f"row/{d_id}/scope",
                            f"Dependency '{d_id}' mapped to quarantine class DEP-CLASS-F4 cannot have Production scope: {scope!r}",
                        )
        except Exception as exc:
            result.add_error(
                ERR_DEP_CORRUPT_FILE,
                DEPENDENCIES_JSON_PATH,
                "#",
                f"Could not read dependencies.json during constitution cross-check: {exc}",
            )

    # 10. Cross-checks against architecture/dependency_allowlist.toml
    allow_path = root / ALLOWLIST_TOML_PATH
    allow_data: dict[str, Any] | None = None
    if allow_path.is_file():
        try:
            import tomllib
            allow_data = tomllib.loads(allow_path.read_text(encoding="utf-8"))
            pol = allow_data.get("policy", {})

            # Validate all 16 policy flags against REQUIRED_ALLOWLIST_POLICY
            for flag_name, expected_val in REQUIRED_ALLOWLIST_POLICY.items():
                actual_val = pol.get(flag_name)
                if actual_val != expected_val:
                    result.add_error(
                        ERR_DEP_CONST_INVARIANT,
                        ALLOWLIST_TOML_PATH,
                        f"#/policy/{flag_name}",
                        f"dependency_allowlist.toml policy.{flag_name} must be {expected_val!r}, found {actual_val!r}",
                    )

            # Cross-check allowlist flags against constitution production object
            if isinstance(prod, dict):
                crosswalk_checks = [
                    ("closed_universe", "closedUniverse", prod.get("closedUniverse") is True),
                    ("c_or_cpp_ffi_allowed", "cCppFfi", not prod.get("cCppFfi", True)),
                    ("dynamic_loading_allowed", "dynamicLoading", not prod.get("dynamicLoading", True)),
                    ("foreign_runtime_production_boundary_allowed", "foreignExecutables", not prod.get("foreignExecutables", True)),
                    ("release_resolution_must_be_locked_and_offline", "lockedOfflineReleaseResolution", prod.get("lockedOfflineReleaseResolution") is True),
                    ("runtime_acquisition_allowed", "runtimeAcquisition", not prod.get("runtimeAcquisition", True)),
                    ("serde_may_not_define_durable_bytes", "serdeDurableFormatAuthority", not prod.get("serdeDurableFormatAuthority", True)),
                    ("asupersync_is_only_async_runtime", "asyncRuntime", prod.get("asyncRuntime") == "asupersync-only"),
                    ("fss_crates_must_forbid_unsafe", "unsafe", prod.get("unsafe") == "forbidden-in-all-fss-crates"),
                ]
                for flag_name, prod_field, consistent in crosswalk_checks:
                    if prod_field in prod and not consistent:
                        result.add_error(
                            ERR_DEP_CONST_INVARIANT,
                            ALLOWLIST_TOML_PATH,
                            f"#/policy/{flag_name}",
                            f"Allowlist policy '{flag_name}' is inconsistent with constitution production settings",
                        )

            # Check table contents
            forb_crates = allow_data.get("forbidden", {}).get("crates", [])
            if not isinstance(forb_crates, list) or len(forb_crates) == 0:
                result.add_error(
                    ERR_DEP_CONST_INVARIANT,
                    ALLOWLIST_TOML_PATH,
                    "#/forbidden/crates",
                    "dependency_allowlist.toml [forbidden] crates must be a non-empty list",
                )

            fund_allowed = allow_data.get("fundamental", {}).get("allowed_subject_to_audit", [])
            if not isinstance(fund_allowed, list) or len(fund_allowed) == 0:
                result.add_error(
                    ERR_DEP_CONST_INVARIANT,
                    ALLOWLIST_TOML_PATH,
                    "#/fundamental/allowed_subject_to_audit",
                    "dependency_allowlist.toml [fundamental] allowed_subject_to_audit must be a non-empty list",
                )

            lab_excluded = allow_data.get("laboratory_oracles", {}).get("excluded_from_production_release_closure", [])
            if not isinstance(lab_excluded, list) or "ffmpeg" not in lab_excluded or "ffprobe" not in lab_excluded:
                result.add_error(
                    ERR_DEP_CONST_INVARIANT,
                    ALLOWLIST_TOML_PATH,
                    "#/laboratory_oracles/excluded_from_production_release_closure",
                    "laboratory_oracles.excluded_from_production_release_closure must contain ffmpeg and ffprobe",
                )

            in_house_families = allow_data.get("in_house", {}).get("allowed_families", [])
            if isinstance(in_house_families, list) and ("ffmpeg" in in_house_families or "ffprobe" in in_house_families):
                result.add_error(
                    ERR_DEP_CONST_INVARIANT,
                    ALLOWLIST_TOML_PATH,
                    "#/in_house/allowed_families",
                    "in_house.allowed_families illegally contains ffmpeg or ffprobe",
                )
        except Exception as exc:
            result.add_error(
                ERR_DEP_CORRUPT_FILE,
                ALLOWLIST_TOML_PATH,
                "#",
                f"Could not read dependency_allowlist.toml during constitution cross-check: {exc}",
            )

    # 11. Substantive Markdown mirror verification
    if not md_path.is_file():
        result.add_error(
            ERR_DEP_CORRUPT_FILE,
            CONSTITUTION_MD_PATH,
            "#",
            f"Markdown documentation missing at {CONSTITUTION_MD_PATH}",
        )
    else:
        try:
            md_bytes = md_path.read_bytes()
            if len(md_bytes) == 0:
                result.add_error(
                    ERR_DEP_CORRUPT_FILE,
                    CONSTITUTION_MD_PATH,
                    "#",
                    "Markdown documentation is 0 bytes / empty",
                )
                md_text = ""
            else:
                md_text = md_bytes.decode("utf-8")
        except UnicodeDecodeError as exc:
            result.add_error(
                ERR_DEP_CORRUPT_FILE,
                CONSTITUTION_MD_PATH,
                "#",
                f"Invalid UTF-8 in constitution markdown: {exc}",
            )
            md_text = ""
        except OSError as exc:
            result.add_error(
                ERR_DEP_CORRUPT_FILE,
                CONSTITUTION_MD_PATH,
                "#",
                f"Could not read constitution markdown: {exc}",
            )
            md_text = ""

        if md_text:
            if not md_text.strip():
                result.add_error(
                    ERR_DEP_CORRUPT_FILE,
                    CONSTITUTION_MD_PATH,
                    "#",
                    "Markdown documentation contains only whitespace",
                )
            else:
                md_classes, duplicate_ids = extract_markdown_class_sections(md_text)
                for dup_id in duplicate_ids:
                    result.add_error(
                        ERR_DEP_REGISTRY_DRIFT,
                        CONSTITUTION_MD_PATH,
                        f"#{dup_id}",
                        f"Duplicate class section header '{dup_id}' found in {CONSTITUTION_MD_PATH}",
                    )

                for canon_id, canon_info in CANONICAL_CONSTITUTION_CLASSES.items():
                    if canon_id not in md_classes:
                        result.add_error(
                            ERR_DEP_REGISTRY_DRIFT,
                            CONSTITUTION_MD_PATH,
                            f"#{canon_id}",
                            f"Class section '{canon_id}' is missing from {CONSTITUTION_MD_PATH}",
                        )
                    else:
                        c_name, c_body = md_classes[canon_id]
                        expected_title = CANONICAL_CONSTITUTION_MARKDOWN_TITLES.get(canon_id, canon_info["name"])
                        if c_name != expected_title:
                            result.add_error(
                                ERR_DEP_REGISTRY_DRIFT,
                                CONSTITUTION_MD_PATH,
                                f"#{canon_id}/name",
                                f"Class section '{canon_id}' title drifted: expected '{expected_title}', got '{c_name}'",
                            )

                        # Semantic content verification (reject lorem/hollow body, verify class keywords)
                        body_lower = c_body.lower()
                        if not c_body.strip() or "lorem" in body_lower or "placeholder" in body_lower:
                            result.add_error(
                                ERR_DEP_REGISTRY_DRIFT,
                                CONSTITUTION_MD_PATH,
                                f"#{canon_id}/body",
                                f"Class section '{canon_id}' in {CONSTITUTION_MD_PATH} contains hollow or placeholder text",
                            )
                        elif canon_id == "DEP-CLASS-F0" and ("rustc" not in body_lower or "nightly" not in body_lower):
                            result.add_error(
                                ERR_DEP_REGISTRY_DRIFT,
                                CONSTITUTION_MD_PATH,
                                f"#{canon_id}/body",
                                f"Class section '{canon_id}' body does not document rustc/nightly toolchain identity",
                            )
                        elif canon_id == "DEP-CLASS-F1" and "asupersync" not in body_lower:
                            result.add_error(
                                ERR_DEP_REGISTRY_DRIFT,
                                CONSTITUTION_MD_PATH,
                                f"#{canon_id}/body",
                                f"Class section '{canon_id}' body does not document Asupersync concurrency ownership",
                            )
                        elif canon_id == "DEP-CLASS-F2" and "franken" not in body_lower:
                            result.add_error(
                                ERR_DEP_REGISTRY_DRIFT,
                                CONSTITUTION_MD_PATH,
                                f"#{canon_id}/body",
                                f"Class section '{canon_id}' body does not document Franken-suite crate admission",
                            )
                        elif canon_id == "DEP-CLASS-F3" and ("fundamental" not in body_lower or "serde" not in body_lower):
                            result.add_error(
                                ERR_DEP_REGISTRY_DRIFT,
                                CONSTITUTION_MD_PATH,
                                f"#{canon_id}/body",
                                f"Class section '{canon_id}' body does not document fundamental crate / serde bounds",
                            )
                        elif canon_id == "DEP-CLASS-F4" and not any(k in body_lower for k in ("laboratory", "oracle", "quarantine")):
                            result.add_error(
                                ERR_DEP_REGISTRY_DRIFT,
                                CONSTITUTION_MD_PATH,
                                f"#{canon_id}/body",
                                f"Class section '{canon_id}' body does not document laboratory oracle quarantine",
                            )

    # 12. Toolchain identity and Cargo metadata inspection
    if not skip_cargo_metadata:
        channel = validate_toolchain_identity(root, result)
        if cargo_metadata is None:
            active_channel = channel or REQUIRED_RUST_CHANNEL
            cargo_metadata, meta_err = load_real_cargo_metadata(root, active_channel)
            if meta_err is not None:
                result.add_error(
                    ERR_DEP_CORRUPT_FILE,
                    "Cargo.lock",
                    "#",
                    f"Unable to load real Cargo metadata for DEP-CLASS-F0 verification: {meta_err}",
                )
        if cargo_metadata is not None:
            validate_cargo_metadata_for_f0(result, cargo_metadata, root, allow_data)

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
