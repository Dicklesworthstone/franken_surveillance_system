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

DEPENDENCIES_JSON_PATH = "architecture/dependencies.json"
DEPENDENCIES_MD_PATH = "registries/DEPENDENCIES.md"

BASELINE_DEPENDENCIES_GENERATION = "gen:fss1:dependencies-v1"
BASELINE_DEPENDENCIES_FREEZE_DIGEST = "sha256:bb8a0b35e312015c2b286844c1d047166b64d5798319f3cfd3a61a5b5cce1da0"

EXPECTED_FREEZE_DIGESTS: dict[str, str] = {
    BASELINE_DEPENDENCIES_GENERATION: BASELINE_DEPENDENCIES_FREEZE_DIGEST,
}

# Full baseline dependency-class rows for generation gen:fss1:dependencies-v1
CANONICAL_DEPENDENCY_CLASSES: dict[str, dict[str, str]] = {
    "DEP-OWNED-001": {
        "id": "DEP-OWNED-001",
        "class": "Owned runtime and Franken-suite families",
        "rule": "admitted after per-mechanism integration gate",
        "scope": "Production",
    },
    "DEP-FUND-001": {
        "id": "DEP-FUND-001",
        "class": "serde / serde_json",
        "rule": "control-plane schemas only; never durable bytes or authority",
        "scope": "Production subject to audit",
    },
    "DEP-LAB-001": {
        "id": "DEP-LAB-001",
        "class": "Pinned codec/model/vendor/reference executables",
        "rule": "sealed fixture/oracle lanes only; no production invocation path and absent from release closure",
        "scope": "Development/migration only",
    },
    "DEP-ORACLE-001": {
        "id": "DEP-ORACLE-001",
        "class": "Python/reference ecosystems",
        "rule": "held-out conformance and lab fixtures only; absent from release closure",
        "scope": "Development only",
    },
    "DEP-EXCEPTION-001": {
        "id": "DEP-EXCEPTION-001",
        "class": "Any other external crate",
        "rule": "requires DEP record, ADR, source/feature census, semantic owner, substitute prohibition, and removal plan",
        "scope": "Not admitted",
    },
}

MANDATORY_TOP_LEVEL_FIELDS: tuple[str, ...] = (
    "schema",
    "generation",
    "freezeDigest",
    "sourceDocument",
    "dependencies",
)

MANDATORY_ROW_FIELDS: tuple[str, ...] = (
    "id",
    "class",
    "rule",
    "scope",
)

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


def canonicalize_value(val: Any) -> Any:
    if isinstance(val, dict):
        return {k: canonicalize_value(v) for k, v in sorted(val.items())}
    if isinstance(val, list):
        return [canonicalize_value(item) for item in val]
    return val


def compute_canonical_dependencies_digest(
    data_or_deps: dict[str, Any] | list[dict[str, Any]],
    schema: str = "fss.dependencies.v1",
    generation: str = BASELINE_DEPENDENCIES_GENERATION,
    source_document: str = "registries/DEPENDENCIES.md",
) -> str:
    """Computes SHA-256 digest of canonically serialized dependency registry data.

    Binds top-level metadata (schema, generation, sourceDocument) and deterministically
    sorted dependencies rows.
    """
    if isinstance(data_or_deps, dict):
        data = data_or_deps
        schema_val = str(data.get("schema", "")).strip()
        generation_val = str(data.get("generation", "")).strip()
        source_doc_val = str(data.get("sourceDocument", "")).strip()
        raw_deps = data.get("dependencies", [])
    else:
        schema_val = schema
        generation_val = generation
        source_doc_val = source_document
        raw_deps = data_or_deps

    sorted_deps = sorted(raw_deps, key=lambda r: str(r.get("id", "")))
    canonical_payload = {
        "dependencies": [
            {
                "class": str(r.get("class", "")).strip(),
                "id": str(r.get("id", "")).strip(),
                "rule": str(r.get("rule", "")).strip(),
                "scope": str(r.get("scope", "")).strip(),
            }
            for r in sorted_deps
        ],
        "generation": generation_val,
        "schema": schema_val,
        "sourceDocument": source_doc_val,
    }
    canonical_bytes = json.dumps(canonical_payload, sort_keys=True, separators=(",", ":")).encode("utf-8")
    return f"sha256:{hashlib.sha256(canonical_bytes).hexdigest()}"


def extract_markdown_dependencies(md_path: Path) -> dict[str, tuple[str, str, str]]:
    """Extracts dependency rows from markdown table: {id: (class_name, rule, scope)}."""
    rows: dict[str, tuple[str, str, str]] = {}
    lines = md_path.read_text(encoding="utf-8").splitlines()
    for line in lines:
        stripped = line.strip()
        if stripped.startswith("| `DEP-"):
            parts = [p.strip() for p in stripped.strip("|").split("|")]
            if len(parts) >= 4:
                dep_id = parts[0].replace("`", "").strip()
                dep_class = parts[1].replace("`", "").strip()
                dep_rule = parts[2].strip()
                dep_scope = parts[3].replace("`", "").strip()
                rows[dep_id] = (dep_class, dep_rule, dep_scope)
    return rows


def load_tombstone_set(root: Path = ROOT) -> tuple[set[str], list[DiagnosticError]]:
    """Loads tombstoned stable IDs from stable_id_resolution.json if present."""
    tombstones_path = root / "architecture/stable_id_resolution.json"
    if not tombstones_path.is_file():
        return set(), []
    try:
        data = json.loads(tombstones_path.read_text(encoding="utf-8"))
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

    # 2. Check for empty file
    try:
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

    # 3. Parse JSON
    try:
        data = json.loads(j_bytes.decode("utf-8"))
    except Exception as exc:
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

    # 4. Validate top-level mandatory fields
    for field_name in MANDATORY_TOP_LEVEL_FIELDS:
        val = data.get(field_name)
        if val is None:
            result.add_error(
                ERR_DEP_MISSING_FIELD,
                j_str,
                f"#/{field_name}",
                f"Dependency registry missing mandatory top-level field '{field_name}'",
            )
        elif field_name != "dependencies" and (not isinstance(val, str) or not val.strip()):
            result.add_error(
                ERR_DEP_MISSING_FIELD,
                j_str,
                f"#/{field_name}",
                f"Dependency registry top-level field '{field_name}' must be a non-empty string",
            )

    # 5. Validate schema and sourceDocument values
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

    # 6. Validate generation
    generation = data.get("generation")
    if generation and generation not in EXPECTED_FREEZE_DIGESTS:
        result.add_error(
            ERR_DEP_GENERATION_MISMATCH,
            j_str,
            "#/generation",
            f"Dependency registry generation '{generation}' does not match expected generation '{BASELINE_DEPENDENCIES_GENERATION}'",
        )

    # 7. Validate canonical freeze digest
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
        elif generation in EXPECTED_FREEZE_DIGESTS:
            expected_digest = EXPECTED_FREEZE_DIGESTS[generation]
            if declared_digest != expected_digest:
                result.add_error(
                    ERR_DEP_FREEZE_DIVERGENCE,
                    j_str,
                    "#/freezeDigest",
                    f"Dependency registry freezeDigest '{declared_digest}' diverged from pinned baseline freeze digest '{expected_digest}'",
                )

    result.freeze_digest = declared_digest or computed_digest

    # 8. Load tombstones
    tombstones, tombstone_errs = load_tombstone_set(repo_root)
    for err in tombstone_errs:
        result.add_error(err.code, err.file_path, err.target, err.message)
    tombstones_lower = {t.lower() for t in tombstones}

    # 9. Validate dependency rows
    deps = data.get("dependencies")
    if not isinstance(deps, list) or len(deps) == 0:
        result.add_error(
            ERR_DEP_MISSING_FIELD,
            j_str,
            "#/dependencies",
            "Dependency registry 'dependencies' field must be a non-empty list",
        )
        return result

    result.dependency_count = len(deps)
    seen_ids: set[str] = set()
    json_rows: dict[str, dict[str, str]] = {}

    for idx, row in enumerate(deps):
        loc = f"#/dependencies[{idx}]"
        if not isinstance(row, dict):
            result.add_error(
                ERR_DEP_CORRUPT_FILE,
                j_str,
                loc,
                f"Dependency row at index {idx} must be a JSON object",
            )
            continue

        dep_id = row.get("id")
        if not isinstance(dep_id, str) or not dep_id.strip():
            result.add_error(
                ERR_DEP_MISSING_FIELD,
                j_str,
                f"{loc}/id",
                f"Dependency row at index {idx} missing mandatory 'id' field",
            )
            continue

        dep_id = dep_id.strip()

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
            if rval is None or not isinstance(rval, str) or not rval.strip():
                result.add_error(
                    ERR_DEP_MISSING_FIELD,
                    j_str,
                    f"{loc}/{rf}",
                    f"Dependency row '{dep_id}' missing or empty mandatory field '{rf}'",
                )
            else:
                row_fields[rf] = rval.strip()

        json_rows[dep_id] = row_fields

        # Baseline check
        if dep_id not in CANONICAL_DEPENDENCY_CLASSES:
            result.add_error(
                ERR_DEP_REGISTRY_DRIFT,
                j_str,
                f"{loc}/id",
                f"Unrecognized dependency class ID '{dep_id}' not present in canonical baseline",
            )
        else:
            baseline = CANONICAL_DEPENDENCY_CLASSES[dep_id]
            for rf in ("class", "rule", "scope"):
                if rf in row_fields and row_fields[rf] != baseline[rf]:
                    result.add_error(
                        ERR_DEP_REGISTRY_DRIFT,
                        j_str,
                        f"{loc}/{rf}",
                        f"Dependency row '{dep_id}' {rf} diverged from baseline: observed {row_fields[rf]!r}, expected {baseline[rf]!r}",
                    )

    # Check all canonical rows are present
    for canon_id in CANONICAL_DEPENDENCY_CLASSES:
        if canon_id.lower() not in seen_ids:
            result.add_error(
                ERR_DEP_REGISTRY_DRIFT,
                j_str,
                "#/dependencies",
                f"Canonical dependency class '{canon_id}' is missing from dependency registry",
            )

    # 10. Validate markdown mirror
    try:
        md_rows = extract_markdown_dependencies(m_path)
    except Exception as exc:
        result.add_error(
            ERR_DEP_CORRUPT_FILE,
            m_str,
            "#",
            f"Failed to extract dependency table from markdown mirror: {exc}",
        )
        return result

    if len(md_rows) == 0:
        result.add_error(
            ERR_DEP_CORRUPT_FILE,
            m_str,
            "#",
            "No dependency rows found in markdown mirror registries/DEPENDENCIES.md",
        )
        return result

    # Check row count
    if len(md_rows) != len(json_rows):
        result.add_error(
            ERR_DEP_REGISTRY_DRIFT,
            m_str,
            "#",
            f"Markdown mirror row count ({len(md_rows)}) differs from JSON row count ({len(json_rows)})",
        )

    # Check each markdown row matches JSON row
    for dep_id, (m_class, m_rule, m_scope) in md_rows.items():
        if dep_id not in json_rows:
            result.add_error(
                ERR_DEP_REGISTRY_DRIFT,
                m_str,
                f"row/{dep_id}",
                f"Markdown mirror contains dependency ID '{dep_id}' absent from JSON registry",
            )
        else:
            j_row = json_rows[dep_id]
            if j_row.get("class") != m_class:
                result.add_error(
                    ERR_DEP_REGISTRY_DRIFT,
                    m_str,
                    f"row/{dep_id}/class",
                    f"Markdown mirror class mismatch for '{dep_id}': markdown={m_class!r}, json={j_row.get('class')!r}",
                )
            if j_row.get("rule") != m_rule:
                result.add_error(
                    ERR_DEP_REGISTRY_DRIFT,
                    m_str,
                    f"row/{dep_id}/rule",
                    f"Markdown mirror rule mismatch for '{dep_id}': markdown={m_rule!r}, json={j_row.get('rule')!r}",
                )
            if j_row.get("scope") != m_scope:
                result.add_error(
                    ERR_DEP_REGISTRY_DRIFT,
                    m_str,
                    f"row/{dep_id}/scope",
                    f"Markdown mirror scope mismatch for '{dep_id}': markdown={m_scope!r}, json={j_row.get('scope')!r}",
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
