#!/usr/bin/env python3
"""Fail-closed dependency-class registry checker (fss-x4a.30.88.1).

Enforces the dependency-class registry contract (REG-DEPENDENCIES-001):
1. Dependency registry row drift between architecture JSON and markdown mirror (ERR-DEP-REGISTRY-DRIFT-001)
2. Stable ID reused, duplicated, renumbered, or diverging from canonical baseline (ERR-DEP-STABLE-ID-REUSED-001)
3. Missing or empty mandatory field in a dependency row or top-level metadata (ERR-DEP-MISSING-FIELD-001)
4. Corrupt or missing mandatory registry files (ERR-DEP-CORRUPT-FILE-001)
5. Registry digest mismatch between declared and canonical computed digest (ERR-DEP-DIGEST-MISMATCH-001)
6. Registry digest diverged from pinned baseline freeze digest (ERR-DEP-FREEZE-DIVERGENCE-001)
7. Registry generation diverged from baseline generation (ERR-DEP-GENERATION-MISMATCH-001)
8. Constitutional invariant and scope violations (ERR-DEP-CONST-INVARIANT-001)
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
ERR_DEP_REGISTRY_DRIFT = "ERR-DEP-REGISTRY-DRIFT-001"
ERR_DEP_STABLE_ID_REUSED = "ERR-DEP-STABLE-ID-REUSED-001"
ERR_DEP_MISSING_FIELD = "ERR-DEP-MISSING-FIELD-001"
ERR_DEP_CORRUPT_FILE = "ERR-DEP-CORRUPT-FILE-001"
ERR_DEP_DIGEST_MISMATCH = "ERR-DEP-DIGEST-MISMATCH-001"
ERR_DEP_FREEZE_DIVERGENCE = "ERR-DEP-FREEZE-DIVERGENCE-001"
ERR_DEP_GENERATION_MISMATCH = "ERR-DEP-GENERATION-MISMATCH-001"
ERR_DEP_CONST_INVARIANT = "ERR-DEP-CONST-INVARIANT-001"

DEPENDENCIES_JSON_PATH = "architecture/dependencies.json"
DEPENDENCIES_MD_PATH = "registries/DEPENDENCIES.md"
CONSTITUTION_JSON_PATH = "architecture/dependency_constitution.json"
ALLOWLIST_TOML_PATH = "architecture/dependency_allowlist.toml"

BASELINE_DEPENDENCIES_GENERATION = "gen:fss1:dependencies-v1"
BASELINE_DEPENDENCIES_FREEZE_DIGEST = "sha256:857dd73b26f36babae2e5670674b35344efcdecbd42c0b74d9f7a827a0ad27cb"
BASELINE_CONSTITUTION_FREEZE_DIGEST = "sha256:858af1b5482b25cfca1477c2c4c1967a995d802990aaf0bc7ccf139f73571310"
BASELINE_ALLOWLIST_FREEZE_DIGEST = "sha256:4279e5106dfef17192623f8871da01b3a2c7da04c022c3f0393f8cc50be452ec"
MAX_REGISTRY_FILE_SIZE_BYTES = 10 * 1024 * 1024

EXPECTED_FREEZE_DIGESTS: dict[str, str] = {
    BASELINE_DEPENDENCIES_GENERATION: BASELINE_DEPENDENCIES_FREEZE_DIGEST,
}

# Full baseline dependency-class rows for generation gen:fss1:dependencies-v1
CANONICAL_DEPENDENCY_REGISTRY_ROWS: dict[str, dict[str, str]] = {
    "DEP-OWNED-001": {
        "id": "DEP-OWNED-001",
        "constitutionClass": "DEP-CLASS-F2",
        "class": "Owned runtime and Franken-suite families",
        "rule": "admitted after per-mechanism integration gate",
        "scope": "Production",
    },
    "DEP-FUND-001": {
        "id": "DEP-FUND-001",
        "constitutionClass": "DEP-CLASS-F3",
        "class": "serde / serde_json",
        "rule": "control-plane schemas only; never durable bytes or authority",
        "scope": "Production subject to audit",
    },
    "DEP-LAB-001": {
        "id": "DEP-LAB-001",
        "constitutionClass": "DEP-CLASS-F4",
        "class": "Pinned codec/model/vendor/reference executables",
        "rule": "sealed fixture/oracle lanes only; no production invocation path and absent from release closure",
        "scope": "Development/migration only",
    },
    "DEP-ORACLE-001": {
        "id": "DEP-ORACLE-001",
        "constitutionClass": "DEP-CLASS-F4",
        "class": "Python/reference ecosystems",
        "rule": "held-out conformance and lab fixtures only; absent from release closure",
        "scope": "Development only",
    },
    "DEP-EXCEPTION-001": {
        "id": "DEP-EXCEPTION-001",
        "constitutionClass": "DEP-CLASS-F3",
        "class": "Any other external crate",
        "rule": "requires DEP record, ADR, source/feature census, semantic owner, substitute prohibition, and removal plan",
        "scope": "Not admitted",
    },
}

# Retain alias for callers expecting CANONICAL_DEPENDENCY_CLASSES
CANONICAL_DEPENDENCY_CLASSES = CANONICAL_DEPENDENCY_REGISTRY_ROWS

MANDATORY_TOP_LEVEL_FIELDS: tuple[str, ...] = (
    "schema",
    "generation",
    "freezeDigest",
    "sourceDocument",
    "dependencies",
)
ALLOWED_TOP_LEVEL_FIELDS: set[str] = set(MANDATORY_TOP_LEVEL_FIELDS)

MANDATORY_ROW_FIELDS: tuple[str, ...] = (
    "id",
    "constitutionClass",
    "class",
    "rule",
    "scope",
)
ALLOWED_ROW_FIELDS: set[str] = set(MANDATORY_ROW_FIELDS)

DEP_ID_PATTERN = re.compile(r"^DEP-[A-Z0-9]+-[0-9]{3}$")


@dataclass(frozen=True)
class DiagnosticError:
    code: str
    file_path: str
    target: str
    message: str


@dataclass
class ValidationResult:
    passed: bool = True
    dependency_count: int = 0
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


def canonicalize_value(val: Any, depth: int = 0) -> Any:
    if depth > 20:
        raise ValueError("Value nesting depth exceeded maximum supported depth")
    if isinstance(val, dict):
        return {k: canonicalize_value(v, depth + 1) for k, v in sorted(val.items())}
    if isinstance(val, list):
        return [canonicalize_value(item, depth + 1) for item in val]
    return val


def compute_canonical_dependencies_digest(
    data_or_deps: dict[str, Any] | list[dict[str, Any]],
    schema: str = "fss.dependencies.v1",
    generation: str = BASELINE_DEPENDENCIES_GENERATION,
    source_document: str = "registries/DEPENDENCIES.md",
) -> str:
    """Computes SHA-256 digest of canonically serialized dependency registry data.

    Binds top-level metadata (schema, generation, sourceDocument) and deterministically
    sorted dependencies rows without whitespace trimming.
    """
    if isinstance(data_or_deps, dict):
        data = data_or_deps
        schema_val = str(data.get("schema", ""))
        generation_val = str(data.get("generation", ""))
        source_doc_val = str(data.get("sourceDocument", ""))
        raw_deps = data.get("dependencies", [])
        if not isinstance(raw_deps, list):
            raw_deps = []
    else:
        schema_val = schema
        generation_val = generation
        source_doc_val = source_document
        raw_deps = data_or_deps if isinstance(data_or_deps, list) else []

    valid_deps = [r for r in raw_deps if isinstance(r, dict)]
    sorted_deps = sorted(valid_deps, key=lambda r: str(r.get("id", "")))
    canonical_payload = {
        "dependencies": [
            {
                "class": str(r.get("class", "")),
                "constitutionClass": str(r.get("constitutionClass", "")),
                "id": str(r.get("id", "")),
                "rule": str(r.get("rule", "")),
                "scope": str(r.get("scope", "")),
            }
            for r in sorted_deps
        ],
        "generation": generation_val,
        "schema": schema_val,
        "sourceDocument": source_doc_val,
    }
    canonical_bytes = json.dumps(canonical_payload, sort_keys=True, separators=(",", ":")).encode("utf-8")
    return f"sha256:{hashlib.sha256(canonical_bytes).hexdigest()}"


def compute_allowlist_freeze_digest(allowlist_path: Path) -> str:
    """Computes SHA-256 digest of dependency allowlist TOML file."""
    raw = allowlist_path.read_bytes()
    return f"sha256:{hashlib.sha256(raw).hexdigest()}"


def compute_constitution_freeze_digest(constitution_path: Path) -> str:
    """Computes SHA-256 digest of dependency constitution JSON file."""
    raw = constitution_path.read_bytes()
    return f"sha256:{hashlib.sha256(raw).hexdigest()}"


def extract_markdown_dependencies(md_path: Path) -> tuple[dict[str, dict[str, str]], list[DiagnosticError]]:
    """Extracts dependency rows from markdown table: {id: {constitutionClass, class, rule, scope}}."""
    rows: dict[str, dict[str, str]] = {}
    errors: list[DiagnosticError] = []
    try:
        if md_path.stat().st_size > MAX_REGISTRY_FILE_SIZE_BYTES:
            return {}, [
                DiagnosticError(
                    code=ERR_DEP_CORRUPT_FILE,
                    file_path=str(md_path),
                    target="#",
                    message=f"Markdown mirror exceeds maximum size of {MAX_REGISTRY_FILE_SIZE_BYTES} bytes",
                )
            ]
        raw_bytes = md_path.read_bytes()
        if len(raw_bytes.strip()) == 0:
            return {}, [
                DiagnosticError(
                    code=ERR_DEP_CORRUPT_FILE,
                    file_path=str(md_path),
                    target="#",
                    message="Markdown mirror is empty (0 bytes)",
                )
            ]
        text = raw_bytes.decode("utf-8")
    except UnicodeDecodeError as exc:
        return {}, [
            DiagnosticError(
                code=ERR_DEP_CORRUPT_FILE,
                file_path=str(md_path),
                target="#",
                message=f"Markdown mirror contains invalid UTF-8: {exc}",
            )
        ]
    except OSError as exc:
        return {}, [
            DiagnosticError(
                code=ERR_DEP_CORRUPT_FILE,
                file_path=str(md_path),
                target="#",
                message=f"Could not read markdown mirror: {exc}",
            )
        ]

    lines = text.splitlines()
    seen_ids: set[str] = set()

    for line_idx, line in enumerate(lines, 1):
        stripped = line.strip()
        loose_match = re.search(r"(?i)\bdep-[a-z0-9]+-[0-9]{3}\b", stripped)
        if not stripped.startswith("|"):
            if loose_match:
                errors.append(
                    DiagnosticError(
                        code=ERR_DEP_REGISTRY_DRIFT,
                        file_path=str(md_path),
                        target=f"line/{line_idx}",
                        message=f"Dependency row missing leading pipe: {stripped!r}",
                    )
                )
            continue

        parts = [p.strip() for p in stripped.strip("|").split("|")]
        if not parts or all(len(p) == 0 for p in parts):
            continue

        first_part = parts[0]
        if first_part in ("ID", "---", ":---", ":---:", "---:") or first_part.startswith("---") or first_part.startswith(":-"):
            continue

        # Enforce exactly 5 columns (drop 4-column legacy branch)
        if len(parts) != 5:
            errors.append(
                DiagnosticError(
                    code=ERR_DEP_REGISTRY_DRIFT,
                    file_path=str(md_path),
                    target=f"line/{line_idx}",
                    message=f"Dependency table row in markdown mirror must have exactly 5 columns: observed {len(parts)} in {stripped!r}",
                )
            )
            continue

        # Column 0: ID - must be enclosed in exact single backticks and uppercase DEP-[A-Z0-9]+-[0-9]{3}
        raw_id = parts[0]
        if not (raw_id.startswith("`") and raw_id.endswith("`") and len(raw_id) >= 3):
            errors.append(
                DiagnosticError(
                    code=ERR_DEP_REGISTRY_DRIFT,
                    file_path=str(md_path),
                    target=f"line/{line_idx}/id",
                    message=f"Dependency ID in markdown mirror must be enclosed in exact backticks: observed {raw_id!r}",
                )
            )
            dep_id = raw_id.replace("`", "").strip()
        else:
            dep_id = raw_id[1:-1].strip()

        if not DEP_ID_PATTERN.match(dep_id):
            errors.append(
                DiagnosticError(
                    code=ERR_DEP_REGISTRY_DRIFT,
                    file_path=str(md_path),
                    target=f"line/{line_idx}/id",
                    message=f"Dependency ID '{dep_id}' does not match standard pattern DEP-[A-Z0-9]+-[0-9]{{3}}",
                )
            )

        # Check for rogue / misplaced ID in columns 1..4
        for col_idx, part in enumerate(parts[1:], 1):
            if re.search(r"(?i)\bdep-[a-z0-9]+-[0-9]{3}\b", part):
                errors.append(
                    DiagnosticError(
                        code=ERR_DEP_REGISTRY_DRIFT,
                        file_path=str(md_path),
                        target=f"line/{line_idx}/col{col_idx}",
                        message=f"Dependency ID found in column {col_idx} instead of column 0: {part!r}",
                    )
                )

        # Column 1: constitutionClass - must be enclosed in exact backticks
        raw_cclass = parts[1]
        if not (raw_cclass.startswith("`") and raw_cclass.endswith("`") and len(raw_cclass) >= 3):
            errors.append(
                DiagnosticError(
                    code=ERR_DEP_REGISTRY_DRIFT,
                    file_path=str(md_path),
                    target=f"line/{line_idx}/constitutionClass",
                    message=f"Constitution class in markdown mirror must be enclosed in exact backticks: observed {raw_cclass!r}",
                )
            )
            c_class = raw_cclass.replace("`", "").strip()
        else:
            c_class = raw_cclass[1:-1].strip()

        # Column 2: class name - must NOT be enclosed in backticks
        name = parts[2]
        if name.startswith("`") or name.endswith("`"):
            errors.append(
                DiagnosticError(
                    code=ERR_DEP_REGISTRY_DRIFT,
                    file_path=str(md_path),
                    target=f"line/{line_idx}/class",
                    message=f"Class name in markdown mirror must not be enclosed in backticks: observed {name!r}",
                )
            )
            name = name.replace("`", "").strip()

        # Column 3: rule - must NOT be enclosed in backticks
        rule = parts[3]
        if rule.startswith("`") or rule.endswith("`"):
            errors.append(
                DiagnosticError(
                    code=ERR_DEP_REGISTRY_DRIFT,
                    file_path=str(md_path),
                    target=f"line/{line_idx}/rule",
                    message=f"Rule in markdown mirror must not be enclosed in backticks: observed {rule!r}",
                )
            )
            rule = rule.replace("`", "").strip()

        # Column 4: scope - must be enclosed in exact backticks
        raw_scope = parts[4]
        if not (raw_scope.startswith("`") and raw_scope.endswith("`") and len(raw_scope) >= 3):
            errors.append(
                DiagnosticError(
                    code=ERR_DEP_REGISTRY_DRIFT,
                    file_path=str(md_path),
                    target=f"line/{line_idx}/scope",
                    message=f"Scope in markdown mirror must be enclosed in exact backticks: observed {raw_scope!r}",
                )
            )
            scope = raw_scope.replace("`", "").strip()
        else:
            scope = raw_scope[1:-1].strip()

        dep_id_lower = dep_id.lower()
        if dep_id_lower in seen_ids:
            errors.append(
                DiagnosticError(
                    code=ERR_DEP_STABLE_ID_REUSED,
                    file_path=str(md_path),
                    target=f"line/{line_idx}",
                    message=f"Duplicate dependency ID in markdown table: '{dep_id}'",
                )
            )
        seen_ids.add(dep_id_lower)

        rows[dep_id] = {
            "id": dep_id,
            "constitutionClass": c_class,
            "class": name,
            "rule": rule,
            "scope": scope,
        }

    return rows, errors


def resolve_dependency_row_metadata(dep_id: str, repo_root: Path = ROOT) -> dict[str, Any]:
    """Resolves scope metadata for a dependency row ID.

    Returns owner, producers, consumers, ContractBasis link, and tombstone status.
    """
    is_tombstoned = False
    canonical_id = dep_id
    res_path = repo_root / "architecture/stable_id_resolution.json"
    if res_path.is_file():
        try:
            res_data = json.loads(res_path.read_text(encoding="utf-8"))
            for res in res_data.get("resolutions", []):
                if isinstance(res, dict):
                    if res.get("legacyId") == dep_id:
                        if res.get("status") in ("tombstone", "tombstoned", "superseded"):
                            is_tombstoned = True
                        if res.get("canonicalId"):
                            canonical_id = str(res["canonicalId"])
        except Exception:
            pass

    deps_path = repo_root / DEPENDENCIES_JSON_PATH
    row: dict[str, Any] = {}
    if deps_path.is_file():
        try:
            deps_data = json.loads(deps_path.read_text(encoding="utf-8"))
            for r in deps_data.get("dependencies", []):
                if isinstance(r, dict) and r.get("id") == dep_id:
                    row = r
                    break
        except Exception:
            pass

    c_class = row.get("constitutionClass", "")
    scope = row.get("scope", "")
    contract_basis = "fss.agent_contract_basis.v1"

    owner_map = {
        "DEP-OWNED-001": "fss-runtime",
        "DEP-FUND-001": "fss-data-shape",
        "DEP-LAB-001": "fss-lab",
        "DEP-ORACLE-001": "fss-oracle",
        "DEP-EXCEPTION-001": "fss-exception-review",
    }
    owner = owner_map.get(dep_id, "fss-core")

    producers: list[str] = []
    consumers: list[str] = []

    if dep_id == "DEP-OWNED-001":
        crates_dir = repo_root / "crates"
        if crates_dir.is_dir():
            for c in sorted(crates_dir.iterdir()):
                if c.is_dir() and (c / "Cargo.toml").is_file():
                    producers.append(c.name)
                    consumers.append(c.name)

    return {
        "id": dep_id,
        "canonicalId": canonical_id,
        "constitutionClass": c_class,
        "scope": scope,
        "owner": owner,
        "producers": producers,
        "consumers": consumers,
        "contractBasis": contract_basis,
        "isTombstoned": is_tombstoned,
        "tombstone": is_tombstoned,
    }


def load_tombstone_set(root: Path = ROOT) -> tuple[set[str], list[DiagnosticError]]:
    """Loads tombstoned stable IDs from stable_id_resolution.json if present."""
    tombstones_path = root / "architecture/stable_id_resolution.json"
    if not tombstones_path.is_file():
        return set(), []
    try:
        raw_bytes = tombstones_path.read_bytes()
        text = raw_bytes.decode("utf-8")
        data = json.loads(text, object_pairs_hook=pairs_hook_reject_duplicates)
        tombstoned = set()
        for res in data.get("resolutions", []):
            if isinstance(res, dict) and res.get("status") in ("tombstone", "tombstoned", "superseded"):
                legacy = res.get("legacyId")
                if legacy:
                    tombstoned.add(str(legacy).strip())
        return tombstoned, []
    except Exception as exc:
        return set(), [
            DiagnosticError(
                code=ERR_DEP_CORRUPT_FILE,
                file_path="architecture/stable_id_resolution.json",
                target="#",
                message=f"Could not read stable-ID resolution file: {exc}",
            )
        ]


def validate_dependency_registry(
    repo_root: Path = ROOT,
    json_path: Path | None = None,
    md_path: Path | None = None,
) -> ValidationResult:
    result = ValidationResult()
    j_path = json_path or (repo_root / DEPENDENCIES_JSON_PATH)
    m_path = md_path or (repo_root / DEPENDENCIES_MD_PATH)

    j_str = str(j_path.relative_to(repo_root)) if j_path.is_relative_to(repo_root) else str(j_path)
    m_str = str(m_path.relative_to(repo_root)) if m_path.is_relative_to(repo_root) else str(m_path)

    # 1. Check existence
    if not j_path.is_file():
        result.add_error(
            ERR_DEP_CORRUPT_FILE,
            j_str,
            "#",
            f"Dependency registry JSON file does not exist: {j_path}",
        )
        return result

    if not m_path.is_file():
        result.add_error(
            ERR_DEP_CORRUPT_FILE,
            m_str,
            "#",
            f"Dependency markdown source file does not exist: {m_path}",
        )
        return result

    # 2. Check for empty file and valid bytes
    try:
        if j_path.stat().st_size > MAX_REGISTRY_FILE_SIZE_BYTES:
            result.add_error(
                ERR_DEP_CORRUPT_FILE,
                j_str,
                "#",
                f"Dependency registry JSON file exceeds maximum allowed size of {MAX_REGISTRY_FILE_SIZE_BYTES} bytes",
            )
            return result
        j_bytes = j_path.read_bytes()
    except OSError as exc:
        result.add_error(
            ERR_DEP_CORRUPT_FILE,
            j_str,
            "#",
            f"Could not read dependency registry JSON: {exc}",
        )
        return result

    if len(j_bytes.strip()) == 0:
        result.add_error(
            ERR_DEP_CORRUPT_FILE,
            j_str,
            "#",
            "Dependency registry JSON file is empty (0 bytes)",
        )
        return result

    # UTF-8 decode check
    try:
        j_text = j_bytes.decode("utf-8")
    except UnicodeDecodeError as exc:
        result.add_error(
            ERR_DEP_CORRUPT_FILE,
            j_str,
            "#",
            f"Dependency registry JSON file contains invalid UTF-8 bytes: {exc}",
        )
        return result

    # 3. Parse JSON with duplicate key detection
    try:
        data = json.loads(j_text, object_pairs_hook=pairs_hook_reject_duplicates)
    except (json.JSONDecodeError, ValueError, RecursionError) as exc:
        result.add_error(
            ERR_DEP_CORRUPT_FILE,
            j_str,
            "#",
            f"Failed to parse dependency registry JSON: {exc}",
        )
        return result

    if not isinstance(data, dict):
        result.add_error(
            ERR_DEP_CORRUPT_FILE,
            j_str,
            "#",
            "Top-level dependency registry must be a JSON object",
        )
        return result

    # 4. Check for unexpected top-level keys
    for key in data:
        if key not in ALLOWED_TOP_LEVEL_FIELDS:
            result.add_error(
                ERR_DEP_CORRUPT_FILE,
                j_str,
                f"#/{key}",
                f"Unexpected top-level key '{key}' in dependency registry",
            )

    # 5. Validate top-level mandatory fields
    for field_name in MANDATORY_TOP_LEVEL_FIELDS:
        val = data.get(field_name)
        if val is None:
            result.add_error(
                ERR_DEP_MISSING_FIELD,
                j_str,
                f"#/{field_name}",
                f"Dependency registry missing mandatory top-level field '{field_name}'",
            )
        elif field_name != "dependencies":
            if not isinstance(val, str) or not val:
                result.add_error(
                    ERR_DEP_MISSING_FIELD,
                    j_str,
                    f"#/{field_name}",
                    f"Dependency registry top-level field '{field_name}' must be a non-empty string",
                )
            elif val != val.strip():
                result.add_error(
                    ERR_DEP_REGISTRY_DRIFT,
                    j_str,
                    f"#/{field_name}",
                    f"Dependency registry field '{field_name}' contains illegal leading or trailing whitespace",
                )

    # 6. Validate dependencies array structure
    deps = data.get("dependencies")
    if deps is not None and not isinstance(deps, list):
        result.add_error(
            ERR_DEP_CORRUPT_FILE,
            j_str,
            "#/dependencies",
            f"Dependency registry 'dependencies' field must be a list, found {type(deps).__name__}",
        )
        return result

    if deps is None or len(deps) == 0:
        result.add_error(
            ERR_DEP_MISSING_FIELD,
            j_str,
            "#/dependencies",
            "Dependency registry 'dependencies' field must be a non-empty list",
        )
        return result

    for idx, row in enumerate(deps):
        if not isinstance(row, dict):
            result.add_error(
                ERR_DEP_CORRUPT_FILE,
                j_str,
                f"#/dependencies[{idx}]",
                f"Dependency row at index {idx} must be a JSON object, found {type(row).__name__}",
            )
        else:
            for rf in MANDATORY_ROW_FIELDS:
                rval = row.get(rf)
                if rval is None or not isinstance(rval, str) or not rval:
                    result.add_error(
                        ERR_DEP_MISSING_FIELD,
                        j_str,
                        f"#/dependencies[{idx}]/{rf}",
                        f"Dependency row at index {idx} missing mandatory field '{rf}'",
                    )

    # If top-level structural errors exist, halt before digest computation
    if not result.passed and any(e.code in (ERR_DEP_CORRUPT_FILE, ERR_DEP_MISSING_FIELD) for e in result.errors):
        return result

    # 7. Validate schema and sourceDocument values
    schema_val = data.get("schema")
    if schema_val and schema_val != "fss.dependencies.v1":
        result.add_error(
            ERR_DEP_REGISTRY_DRIFT,
            j_str,
            "#/schema",
            f"Dependency registry schema must be 'fss.dependencies.v1', observed '{schema_val}'",
        )

    source_doc = data.get("sourceDocument")
    if source_doc and source_doc != DEPENDENCIES_MD_PATH:
        result.add_error(
            ERR_DEP_REGISTRY_DRIFT,
            j_str,
            "#/sourceDocument",
            f"Dependency registry sourceDocument must be '{DEPENDENCIES_MD_PATH}', observed '{source_doc}'",
        )

    # 8. Validate generation
    generation = data.get("generation")
    if not isinstance(generation, str) or generation not in EXPECTED_FREEZE_DIGESTS:
        result.add_error(
            ERR_DEP_GENERATION_MISMATCH,
            j_str,
            "#/generation",
            f"Dependency registry generation '{generation}' does not match expected generation '{BASELINE_DEPENDENCIES_GENERATION}'",
        )

    # 9. Validate canonical freeze digest
    declared_digest = data.get("freezeDigest")
    computed_digest = compute_canonical_dependencies_digest(data)
    if declared_digest:
        if declared_digest != computed_digest:
            result.add_error(
                ERR_DEP_DIGEST_MISMATCH,
                j_str,
                "#/freezeDigest",
                f"Dependency registry freezeDigest mismatch: declared '{declared_digest}', computed '{computed_digest}'",
            )
        elif isinstance(generation, str) and generation in EXPECTED_FREEZE_DIGESTS:
            expected_digest = EXPECTED_FREEZE_DIGESTS[generation]
            if declared_digest != expected_digest:
                result.add_error(
                    ERR_DEP_FREEZE_DIVERGENCE,
                    j_str,
                    "#/freezeDigest",
                    f"Dependency registry freezeDigest '{declared_digest}' diverged from pinned baseline freeze digest '{expected_digest}'",
                )

    result.freeze_digest = declared_digest or computed_digest

    # 10. Load tombstones
    tombstones, tombstone_errs = load_tombstone_set(repo_root)
    for err in tombstone_errs:
        result.add_error(err.code, err.file_path, err.target, err.message)
    tombstones_lower = {t.lower() for t in tombstones}

    # 11. Validate dependency rows
    result.dependency_count = len(deps)
    seen_ids: set[str] = set()
    json_rows: dict[str, dict[str, str]] = {}

    for idx, row in enumerate(deps):
        loc = f"#/dependencies[{idx}]"
        if not isinstance(row, dict):
            continue

        # Check for unexpected row keys
        for rk in row:
            if rk not in ALLOWED_ROW_FIELDS:
                result.add_error(
                    ERR_DEP_CORRUPT_FILE,
                    j_str,
                    f"{loc}/{rk}",
                    f"Unexpected key '{rk}' in dependency row at index {idx}",
                )

        dep_id = row.get("id")
        if not isinstance(dep_id, str) or not dep_id:
            result.add_error(
                ERR_DEP_MISSING_FIELD,
                j_str,
                f"{loc}/id",
                f"Dependency row at index {idx} missing mandatory 'id' field",
            )
            continue

        if dep_id != dep_id.strip():
            result.add_error(
                ERR_DEP_REGISTRY_DRIFT,
                j_str,
                f"{loc}/id",
                f"Dependency ID '{dep_id}' contains illegal whitespace padding",
            )

        # Format check
        if not DEP_ID_PATTERN.match(dep_id):
            result.add_error(
                ERR_DEP_STABLE_ID_REUSED,
                j_str,
                f"{loc}/id",
                f"Dependency ID '{dep_id}' does not match pattern DEP-[A-Z0-9]+-[0-9]{{3}}",
            )

        # Duplicate check (case-insensitive)
        dep_id_lower = dep_id.lower()
        if dep_id_lower in seen_ids:
            result.add_error(
                ERR_DEP_STABLE_ID_REUSED,
                j_str,
                f"{loc}/id",
                f"Duplicate or case-colliding dependency ID: '{dep_id}'",
            )
        seen_ids.add(dep_id_lower)

        # Tombstone check
        if dep_id in tombstones or dep_id_lower in tombstones_lower:
            result.add_error(
                ERR_DEP_STABLE_ID_REUSED,
                j_str,
                f"{loc}/id",
                f"Dependency ID '{dep_id}' is a tombstoned identifier and cannot be used in active registry",
            )

        # Check all mandatory row fields
        row_fields: dict[str, str] = {}
        for rf in MANDATORY_ROW_FIELDS:
            rval = row.get(rf)
            if rval is None or not isinstance(rval, str) or not rval:
                result.add_error(
                    ERR_DEP_MISSING_FIELD,
                    j_str,
                    f"{loc}/{rf}",
                    f"Dependency row '{dep_id}' missing or empty mandatory field '{rf}'",
                )
            else:
                if rval != rval.strip():
                    result.add_error(
                        ERR_DEP_REGISTRY_DRIFT,
                        j_str,
                        f"{loc}/{rf}",
                        f"Dependency row '{dep_id}' field '{rf}' contains illegal whitespace padding: {rval!r}",
                    )
                row_fields[rf] = rval

        json_rows[dep_id] = row_fields

        # Baseline check against CANONICAL_DEPENDENCY_REGISTRY_ROWS
        if dep_id not in CANONICAL_DEPENDENCY_REGISTRY_ROWS:
            result.add_error(
                ERR_DEP_REGISTRY_DRIFT,
                j_str,
                f"{loc}/id",
                f"Unrecognized dependency class ID '{dep_id}' not present in canonical baseline",
            )
        else:
            baseline = CANONICAL_DEPENDENCY_REGISTRY_ROWS[dep_id]
            for rf in MANDATORY_ROW_FIELDS:
                if rf in row_fields and row_fields[rf] != baseline[rf]:
                    result.add_error(
                        ERR_DEP_REGISTRY_DRIFT,
                        j_str,
                        f"{loc}/{rf}",
                        f"Dependency row '{dep_id}' {rf} diverged from baseline: observed {row_fields[rf]!r}, expected {baseline[rf]!r}",
                    )

    # Check all canonical rows are present
    for canon_id in CANONICAL_DEPENDENCY_REGISTRY_ROWS:
        if canon_id.lower() not in seen_ids:
            result.add_error(
                ERR_DEP_REGISTRY_DRIFT,
                j_str,
                "#/dependencies",
                f"Canonical dependency class '{canon_id}' is missing from dependency registry",
            )

    # 12. Cross-check against architecture/dependency_constitution.json and allowlist
    const_path = repo_root / CONSTITUTION_JSON_PATH
    if not const_path.is_file():
        result.add_error(
            ERR_DEP_CORRUPT_FILE,
            CONSTITUTION_JSON_PATH,
            "#",
            f"Dependency constitution file does not exist: {const_path}",
        )
        return result

    try:
        const_bytes = const_path.read_bytes()
        const_text = const_bytes.decode("utf-8")
        const_data = json.loads(const_text, object_pairs_hook=pairs_hook_reject_duplicates)
    except Exception as exc:
        result.add_error(
            ERR_DEP_CORRUPT_FILE,
            CONSTITUTION_JSON_PATH,
            "#",
            f"Failed to parse dependency constitution JSON: {exc}",
        )
        return result

    const_classes = {
        c.get("id"): c for c in const_data.get("classes", []) if isinstance(c, dict)
    }

    # S3: DEP-CLASS-F2 admission must be "per-mechanism-import-gate"
    f2_class = const_classes.get("DEP-CLASS-F2", {})
    if f2_class.get("admission") != "per-mechanism-import-gate":
        result.add_error(
            ERR_DEP_CONST_INVARIANT,
            CONSTITUTION_JSON_PATH,
            "#/classes/DEP-CLASS-F2/admission",
            f"DEP-CLASS-F2 admission must be 'per-mechanism-import-gate', found: {f2_class.get('admission')!r}",
        )

    # S4: DEP-CLASS-F3 admission must be "DEP-record-and-transitive-audit"
    f3_class = const_classes.get("DEP-CLASS-F3", {})
    if f3_class.get("admission") != "DEP-record-and-transitive-audit":
        result.add_error(
            ERR_DEP_CONST_INVARIANT,
            CONSTITUTION_JSON_PATH,
            "#/classes/DEP-CLASS-F3/admission",
            f"DEP-CLASS-F3 admission must be 'DEP-record-and-transitive-audit', found: {f3_class.get('admission')!r}",
        )

    # S5: DEP-CLASS-F4 name must be "laboratory-oracle", admission must be "non-production-quarantine-only"
    f4_class = const_classes.get("DEP-CLASS-F4", {})
    if f4_class.get("name") != "laboratory-oracle":
        result.add_error(
            ERR_DEP_CONST_INVARIANT,
            CONSTITUTION_JSON_PATH,
            "#/classes/DEP-CLASS-F4/name",
            f"DEP-CLASS-F4 name must be 'laboratory-oracle', found: {f4_class.get('name')!r}",
        )
    f4_admission = f4_class.get("admission")
    if f4_admission != "non-production-quarantine-only":
        result.add_error(
            ERR_DEP_CONST_INVARIANT,
            CONSTITUTION_JSON_PATH,
            "#/classes/DEP-CLASS-F4/admission",
            f"DEP-CLASS-F4 admission in constitution must be 'non-production-quarantine-only', found: {f4_admission!r}",
        )

    for dep_id, rfields in json_rows.items():
        c_class_id = rfields.get("constitutionClass")
        if c_class_id and c_class_id not in const_classes:
            result.add_error(
                ERR_DEP_CONST_INVARIANT,
                j_str,
                f"row/{dep_id}/constitutionClass",
                f"Dependency '{dep_id}' references unknown constitution class '{c_class_id}'",
            )
        # Scope vs admission check: DEP-CLASS-F4 is quarantine-only, scope cannot be Production
        if c_class_id == "DEP-CLASS-F4":
            if rfields.get("scope") in ("Production", "Production subject to audit"):
                result.add_error(
                    ERR_DEP_CONST_INVARIANT,
                    j_str,
                    f"row/{dep_id}/scope",
                    f"Dependency '{dep_id}' mapped to quarantine class DEP-CLASS-F4 cannot have Production scope: {rfields.get('scope')!r}",
                )

    allowlist_path = repo_root / ALLOWLIST_TOML_PATH
    if not allowlist_path.is_file():
        result.add_error(
            ERR_DEP_CORRUPT_FILE,
            ALLOWLIST_TOML_PATH,
            "#",
            f"Dependency allowlist file does not exist: {allowlist_path}",
        )
        return result

    try:
        import tomllib
        allow_text = allowlist_path.read_text(encoding="utf-8")
        allow_data = tomllib.loads(allow_text)
    except Exception as exc:
        result.add_error(
            ERR_DEP_CORRUPT_FILE,
            ALLOWLIST_TOML_PATH,
            "#",
            f"Could not cross-check dependency allowlist: {exc}",
        )
        return result

    if allow_data.get("policy", {}).get("closed_universe") is not True:
        result.add_error(
            ERR_DEP_CONST_INVARIANT,
            ALLOWLIST_TOML_PATH,
            "#/policy/closed_universe",
            "dependency_allowlist.toml policy.closed_universe must be true",
        )

    # Allowlist moves:
    # Reject if serde is in forbidden.crates
    forbidden_crates = allow_data.get("forbidden", {}).get("crates", [])
    if "serde" in forbidden_crates or "serde_json" in forbidden_crates:
        result.add_error(
            ERR_DEP_CONST_INVARIANT,
            ALLOWLIST_TOML_PATH,
            "#/forbidden/crates",
            "serde/serde_json must not be in forbidden.crates (pending owner decision fss-ndxis, not permanently forbidden)",
        )

    # Reject if [laboratory_oracles] table missing
    if "laboratory_oracles" not in allow_data or not isinstance(allow_data.get("laboratory_oracles"), dict):
        result.add_error(
            ERR_DEP_CONST_INVARIANT,
            ALLOWLIST_TOML_PATH,
            "#/laboratory_oracles",
            "dependency_allowlist.toml missing mandatory [laboratory_oracles] table",
        )

    # 13. Validate markdown mirror
    md_rows, md_errs = extract_markdown_dependencies(m_path)
    for err in md_errs:
        result.add_error(err.code, err.file_path, err.target, err.message)

    if not md_rows:
        result.add_error(
            ERR_DEP_CORRUPT_FILE,
            m_str,
            "#",
            "No dependency rows found in markdown mirror registries/DEPENDENCIES.md",
        )
        return result

    if len(md_rows) != len(json_rows):
        result.add_error(
            ERR_DEP_REGISTRY_DRIFT,
            m_str,
            "#",
            f"Markdown mirror row count ({len(md_rows)}) differs from JSON row count ({len(json_rows)})",
        )

    for dep_id, m_row in md_rows.items():
        if dep_id not in json_rows:
            result.add_error(
                ERR_DEP_REGISTRY_DRIFT,
                m_str,
                f"row/{dep_id}",
                f"Markdown mirror contains dependency ID '{dep_id}' absent from JSON registry",
            )
        else:
            j_row = json_rows[dep_id]
            for field_name in ("constitutionClass", "class", "rule", "scope"):
                m_val = m_row.get(field_name, "")
                j_val = j_row.get(field_name, "")
                # Only check constitutionClass if present in markdown row (for backward compat)
                if field_name == "constitutionClass" and not m_val:
                    continue
                if j_val != m_val:
                    result.add_error(
                        ERR_DEP_REGISTRY_DRIFT,
                        m_str,
                        f"row/{dep_id}/{field_name}",
                        f"Markdown mirror {field_name} mismatch for '{dep_id}': markdown={m_val!r}, json={j_val!r}",
                    )

    for dep_id in json_rows:
        if dep_id not in md_rows:
            result.add_error(
                ERR_DEP_REGISTRY_DRIFT,
                m_str,
                f"row/{dep_id}",
                f"JSON registry contains dependency ID '{dep_id}' absent from markdown mirror",
            )

    return result


def main() -> int:
    parser = argparse.ArgumentParser(description="Validate FSS dependency-class registry consistency")
    parser.add_argument("--json", action="store_true", help="output structured JSON report")
    parser.add_argument("--repo-root", type=Path, default=ROOT, help="path to repository root")
    args = parser.parse_args()

    result = validate_dependency_registry(args.repo_root)

    if args.json:
        payload = {
            "passed": result.passed,
            "dependencyCount": result.dependency_count,
            "freezeDigest": result.freeze_digest,
            "errorCount": len(result.errors),
            "errors": [asdict(e) for e in result.errors],
        }
        print(json.dumps(payload, indent=2))
    else:
        if result.passed:
            print(f"Dependency registry OK: {result.dependency_count} classes verified ({result.freeze_digest})")
        else:
            print(f"Dependency registry verification FAILED with {len(result.errors)} error(s):", file=sys.stderr)
            for err in result.errors:
                print(f"  [{err.code}] {err.file_path} ({err.target}): {err.message}", file=sys.stderr)

    return 0 if result.passed else 1


if __name__ == "__main__":
    sys.exit(main())
