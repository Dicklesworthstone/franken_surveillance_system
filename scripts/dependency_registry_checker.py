#!/usr/bin/env python3
"""Fail-closed dependency-class registry checker (fss-x4a.30.88.1, REG-DEPENDENCIES-001).

``architecture/dependencies.json`` rows (DEP-OWNED/FUND/LAB/ORACLE/EXCEPTION-001) are dependency
classes that each reference a DEP-CLASS id in ``architecture/dependency_constitution.json``. The policy
authority is DEPENDENCY_CONSTITUTION.md with ``architecture/dependency_allowlist.toml``; this checker
holds no policy table of its own. It verifies, through ``scripts/dependency_authority.py``:

1. every authority input (allowlist, constitution, registry, Franken import gates, local qualification,
   stable-ID resolutions) loads strictly, keeps its exact shape and types, and matches its pinned digest;
2. the allowlist flags, the constitution production object and the registry rows agree (crosswalk);
3. every row's owner, producers, consumers and ContractBasis link resolve (``ERR-DEP-TRACE-UNRESOLVED-001``);
4. tombstones and supersessions are explicit and consistent with ``stable_id_resolution.json``;
5. ``registries/DEPENDENCIES.md`` mirrors the JSON field by field in strictly parsed tables, with no
   duplicate or rogue rows in any formatting.

Every malformed input yields a registered finding; nothing raises into ``scripts/check-policy.py``.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import re
import sys
from dataclasses import asdict
from pathlib import Path
from typing import Any

sys.path.insert(0, str(Path(__file__).resolve().parent))

import dependency_authority as authority  # noqa: E402
from dependency_authority import (  # noqa: E402,F401  (re-exported for callers and tests)
    ALLOWLIST_TOML_PATH,
    AGENT_CONTRACTS_PATH,
    BASELINE_ALLOWLIST_FREEZE_DIGEST,
    BASELINE_CONSTITUTION_FREEZE_DIGEST,
    BASELINE_DEPENDENCIES_FREEZE_DIGEST,
    BASELINE_DEPENDENCIES_GENERATION,
    CONSTITUTION_JSON_PATH,
    DEPENDENCIES_JSON_PATH,
    DEPENDENCIES_MD_PATH,
    ERR_DEP_ALLOWLIST_DIGEST_DIVERGED,
    ERR_DEP_CONST_INVARIANT,
    ERR_DEP_CORRUPT_FILE,
    ERR_DEP_DIGEST_MISMATCH,
    ERR_DEP_FREEZE_DIVERGENCE,
    ERR_DEP_GENERATION_MISMATCH,
    ERR_DEP_MISSING_FIELD,
    ERR_DEP_PENDING_DECISION,
    ERR_DEP_REGISTRY_DRIFT,
    ERR_DEP_STABLE_ID_REUSED,
    ERR_DEP_TOMBSTONE_INVALID,
    ERR_DEP_TRACE_UNRESOLVED,
    ERRORS_MD_PATH,
    FRANKEN_IMPORTS_PATH,
    STABLE_ID_RESOLUTION_PATH,
    DiagnosticError,
    ValidationResult,
    compute_canonical_dependencies_digest,
    issue,
    pairs_hook_reject_duplicates,
)

ROOT = Path(__file__).resolve().parents[1]

MAX_REGISTRY_FILE_SIZE_BYTES = authority.MAX_INPUT_FILE_BYTES
EXPECTED_FREEZE_DIGESTS = authority.EXPECTED_DEPENDENCIES_DIGESTS
MANDATORY_TOP_LEVEL_FIELDS: tuple[str, ...] = tuple(authority.REGISTRY_SPEC.fields)
MANDATORY_ROW_FIELDS: tuple[str, ...] = tuple(authority.REGISTRY_ROW_SPEC.fields)
ALLOWED_TOP_LEVEL_FIELDS: set[str] = set(MANDATORY_TOP_LEVEL_FIELDS)
ALLOWED_ROW_FIELDS: set[str] = set(MANDATORY_ROW_FIELDS)

# Every code this checker can emit; each must be registered in registries/ERRORS.md.
REGISTRY_CHECKER_ERROR_CODES: tuple[str, ...] = authority.AUTHORITY_ERROR_CODES

# ---------------------------------------------------------------------------------------------
# Markdown mirror (registries/DEPENDENCIES.md)
# ---------------------------------------------------------------------------------------------

MD_NULL = "—"  # em dash marks a JSON null
META_HEADER = "| Field | Value |"
META_SEPARATOR = "|---|---|"
META_FIELDS: tuple[str, ...] = ("schema", "generation", "freezeDigest", "sourceDocument", "constitution", "policy", "contractBasis")
ROW_COLUMNS: tuple[tuple[str, str, str], ...] = (
    ("id", "ID", "code"),
    ("constitutionClass", "Constitution Class", "code"),
    ("constitutionClasses", "Constitution Classes", "code-list"),
    ("class", "Class", "text"),
    ("rule", "Rule", "text"),
    ("scope", "Scope", "code"),
    ("status", "Status", "code"),
    ("supersededBy", "Superseded By", "nullable-code"),
    ("tombstoneDecision", "Tombstone Decision", "nullable-text"),
    ("owner", "Owner", "code"),
    ("producers", "Producers", "code-list"),
    ("consumers", "Consumers", "code-list"),
)
ROW_HEADER = "| " + " | ".join(title for _, title, _ in ROW_COLUMNS) + " |"
ROW_SEPARATOR = "|" + "---|" * len(ROW_COLUMNS)
ANY_DEP_ID_RE = re.compile(r"(?i)(?<![a-z0-9])dep-[a-z0-9]+-[0-9]{3}(?![0-9])")
_CODE_RE = re.compile(r"`([^`]+)`")
_CELL_SPLIT_RE = re.compile(r"(?<!\\) \| ")


def _escape_cell(text: str) -> str:
    return text.replace("|", "\\|")


def _render_cell(value: Any, kind: str) -> str:
    if kind in ("nullable-code", "nullable-text") and value is None:
        return MD_NULL
    if kind in ("code", "nullable-code"):
        return f"`{_escape_cell(str(value))}`"
    if kind == "code-list":
        return ", ".join(f"`{_escape_cell(str(item))}`" for item in value)
    return _escape_cell(str(value))


def render_dependencies_markdown(registry: dict[str, Any]) -> str:
    """Deterministic mirror of architecture/dependencies.json; the checker parses it back strictly."""
    lines = [
        "# Dependency registry",
        "",
        "The normative doctrine is [`docs/DEPENDENCY_CONSTITUTION.md`](../docs/DEPENDENCY_CONSTITUTION.md); the machine allowlist is `architecture/dependency_allowlist.toml`.",
        "This file mirrors `architecture/dependencies.json` field by field. `scripts/dependency_registry_checker.py` parses both tables strictly and refuses drift, duplicate rows, and dependency identifiers anywhere outside the row table.",
        "",
        META_HEADER,
        META_SEPARATOR,
    ]
    for key in META_FIELDS:
        lines.append(f"| `{key}` | `{_escape_cell(str(registry.get(key)))}` |")
    lines += ["", ROW_HEADER, ROW_SEPARATOR]
    for row in registry.get("dependencies", []):
        cells = [_render_cell(row.get(key), kind) for key, _, kind in ROW_COLUMNS]
        lines.append("| " + " | ".join(cells) + " |")
    lines += [
        "",
        "No exception is implied by appearance in `Cargo.lock`. Release qualification computes and records the complete source/feature closure and fails closed on unknown provenance.",
        "",
    ]
    return "\n".join(lines)


def _split_cells(line: str) -> list[str] | None:
    if not (line.startswith("| ") and line.endswith(" |")) or len(line) < 4:
        return None
    return [cell.replace("\\|", "|") for cell in _CELL_SPLIT_RE.split(line[2:-2])]


def _decode_cell(cell: str, kind: str) -> tuple[Any, str | None]:
    if kind in ("nullable-code", "nullable-text") and cell == MD_NULL:
        return None, None
    if kind in ("code", "nullable-code"):
        match = re.fullmatch(r"`([^`]+)`", cell)
        return (match.group(1), None) if match else (None, f"must be exactly one code span, found {cell!r}")
    if kind == "code-list":
        parts = cell.split(", ")
        values = []
        for part in parts:
            match = re.fullmatch(r"`([^`]+)`", part)
            if not match:
                return None, f"must be a comma-separated list of code spans, found {cell!r}"
            values.append(match.group(1))
        return values, None
    if "`" in cell or not cell or cell != cell.strip() or cell == MD_NULL:
        return None, f"must be plain text without code spans, found {cell!r}"
    return cell, None


def parse_dependencies_markdown(text: str, rel: str = DEPENDENCIES_MD_PATH) -> tuple[dict[str, Any] | None, list[dict[str, Any]] | None, list[DiagnosticError]]:
    """Strict parse of both mirror tables. Returns (meta, rows, issues); rows is None if no row table."""
    out: list[DiagnosticError] = []
    if "\r" in text:
        out.append(issue(ERR_DEP_REGISTRY_DRIFT, rel, "#", "markdown mirror contains carriage returns; the mirror is LF-only"))
    lines = text.split("\n")
    row_headers = [i for i, line in enumerate(lines) if line == ROW_HEADER]
    if not row_headers:
        out.append(issue(ERR_DEP_CORRUPT_FILE, rel, "#", f"no dependency row table (header {ROW_HEADER!r}) in {rel}"))
        return None, None, out
    if len(row_headers) > 1:
        out.append(issue(ERR_DEP_REGISTRY_DRIFT, rel, f"line/{row_headers[1] + 1}", "markdown mirror declares the dependency row table more than once"))
    consumed: set[int] = set()
    rows: list[dict[str, Any]] = []
    seen_ids: dict[str, int] = {}

    def note_id(dep_id: str, line_no: int) -> None:
        key = dep_id.lower()
        if key in seen_ids:
            out.append(issue(ERR_DEP_STABLE_ID_REUSED, rel, f"line/{line_no}", f"Duplicate dependency ID in markdown table: {dep_id!r} (first at line {seen_ids[key]})"))
        else:
            seen_ids[key] = line_no

    header = row_headers[0]
    consumed.add(header)
    if header + 1 >= len(lines) or lines[header + 1] != ROW_SEPARATOR:
        out.append(issue(ERR_DEP_REGISTRY_DRIFT, rel, f"line/{header + 2}", f"dependency row table separator must be exactly {ROW_SEPARATOR!r}"))
    else:
        consumed.add(header + 1)
        index = header + 2
        while index < len(lines) and lines[index].startswith("|"):
            consumed.add(index)
            line_no = index + 1
            cells = _split_cells(lines[index])
            index += 1
            if cells is None or len(cells) != len(ROW_COLUMNS):
                out.append(issue(ERR_DEP_REGISTRY_DRIFT, rel, f"line/{line_no}", f"dependency table row must have exactly {len(ROW_COLUMNS)} '| '-delimited columns: {lines[line_no - 1]!r}"))
                first = lines[line_no - 1].strip().strip("|").split("|")[0]
                found = ANY_DEP_ID_RE.search(first)
                if found:
                    note_id(found.group(0), line_no)
                continue
            row: dict[str, Any] = {}
            bad = False
            for (key, title, kind), cell in zip(ROW_COLUMNS, cells):
                value, problem = _decode_cell(cell, kind)
                if problem:
                    out.append(issue(ERR_DEP_REGISTRY_DRIFT, rel, f"line/{line_no}/{key}", f"column {title!r} {problem}"))
                    bad = True
                    continue
                row[key] = value
                if key not in ("id", "supersededBy") and ANY_DEP_ID_RE.search(cell):
                    out.append(issue(ERR_DEP_REGISTRY_DRIFT, rel, f"line/{line_no}/{key}", f"dependency identifier found in column {title!r} instead of the ID column: {cell!r}"))
                    bad = True
            dep_id = row.get("id")
            if isinstance(dep_id, str):
                if not authority.DEP_ID_RE.fullmatch(dep_id):
                    out.append(issue(ERR_DEP_REGISTRY_DRIFT, rel, f"line/{line_no}/id", f"markdown ID {dep_id!r} is not an uppercase DEP-[A-Z0-9]+-[0-9]{{3}} identifier"))
                    bad = True
                note_id(dep_id, line_no)
            else:
                found = ANY_DEP_ID_RE.search(cells[0])
                if found:
                    note_id(found.group(0), line_no)
            if not bad:
                rows.append(row)

    meta: dict[str, Any] | None = None
    meta_headers = [i for i, line in enumerate(lines) if line == META_HEADER]
    if len(meta_headers) != 1:
        out.append(issue(ERR_DEP_REGISTRY_DRIFT, rel, "#", f"markdown mirror must contain exactly one metadata table (header {META_HEADER!r}); found {len(meta_headers)}"))
    else:
        start = meta_headers[0]
        consumed.add(start)
        meta = {}
        if start + 1 >= len(lines) or lines[start + 1] != META_SEPARATOR:
            out.append(issue(ERR_DEP_REGISTRY_DRIFT, rel, f"line/{start + 2}", f"metadata table separator must be exactly {META_SEPARATOR!r}"))
        else:
            consumed.add(start + 1)
            index = start + 2
            while index < len(lines) and lines[index].startswith("|"):
                consumed.add(index)
                line_no = index + 1
                cells = _split_cells(lines[index])
                index += 1
                if cells is None or len(cells) != 2:
                    out.append(issue(ERR_DEP_REGISTRY_DRIFT, rel, f"line/{line_no}", f"metadata row must have exactly 2 columns: {lines[line_no - 1]!r}"))
                    continue
                key, key_problem = _decode_cell(cells[0], "code")
                value, value_problem = _decode_cell(cells[1], "code")
                if key_problem or value_problem:
                    out.append(issue(ERR_DEP_REGISTRY_DRIFT, rel, f"line/{line_no}", f"metadata row must be `field` | `value`: {lines[line_no - 1]!r}"))
                    continue
                if key in meta:
                    out.append(issue(ERR_DEP_REGISTRY_DRIFT, rel, f"line/{line_no}", f"duplicate metadata field {key!r}"))
                    continue
                meta[key] = value

    for index, line in enumerate(lines):
        if index in consumed:
            continue
        found = ANY_DEP_ID_RE.search(line)
        if not found:
            continue
        line_no = index + 1
        out.append(issue(ERR_DEP_REGISTRY_DRIFT, rel, f"line/{line_no}", f"rogue dependency identifier {found.group(0)!r} outside the registry row table: {line!r}"))
        if line.lstrip().startswith("|"):
            first = line.strip().strip("|").split("|")[0]
            first_id = ANY_DEP_ID_RE.search(first)
            if first_id:
                note_id(first_id.group(0), line_no)
    return meta, rows, out


def extract_markdown_dependencies(md_path: Path) -> tuple[dict[str, dict[str, Any]], list[DiagnosticError]]:
    """Compatibility wrapper: parsed rows keyed by id, plus every parse finding."""
    rel = DEPENDENCIES_MD_PATH
    data, problems = authority.read_input_bytes(md_path, rel)
    if data is None:
        return {}, problems
    text, problems = authority.decode_utf8(data, rel)
    if text is None:
        return {}, problems
    _meta, rows, found = parse_dependencies_markdown(text, rel)
    by_id: dict[str, dict[str, Any]] = {}
    for row in rows or []:
        by_id.setdefault(row["id"], row)
    return by_id, found


def _compare_markdown(result: ValidationResult, auth: authority.Authority, md_path: Path) -> None:
    rel = DEPENDENCIES_MD_PATH
    data, problems = authority.read_input_bytes(md_path, rel)
    if data is None:
        result.extend(problems)
        return
    text, problems = authority.decode_utf8(data, rel)
    if text is None:
        result.extend(problems)
        return
    meta, md_rows, found = parse_dependencies_markdown(text, rel)
    result.extend(found)
    if md_rows is None or auth.registry is None:
        return
    registry = auth.registry
    if meta is not None:
        for key in META_FIELDS:
            json_value = registry.get(key)
            if key not in meta:
                result.add_error(ERR_DEP_REGISTRY_DRIFT, rel, f"meta/{key}", f"markdown metadata table lacks {key!r}")
            elif isinstance(json_value, str) and meta[key] != json_value:
                result.add_error(ERR_DEP_REGISTRY_DRIFT, rel, f"meta/{key}", f"markdown metadata {key!r} mismatch: markdown={meta[key]!r}, json={json_value!r}")
        for key in sorted(set(meta) - set(META_FIELDS)):
            result.add_error(ERR_DEP_REGISTRY_DRIFT, rel, f"meta/{key}", f"markdown metadata table has unknown field {key!r}")
    json_rows = [row for row in registry.get("dependencies", []) if isinstance(row, dict) and authority.is_str(row.get("id"))] if isinstance(registry.get("dependencies"), list) else []
    json_by_id: dict[str, dict[str, Any]] = {}
    for row in json_rows:
        json_by_id.setdefault(row["id"], row)
    md_by_id: dict[str, dict[str, Any]] = {}
    for row in md_rows:
        md_by_id.setdefault(row["id"], row)
    for dep_id in md_by_id:
        if dep_id not in json_by_id:
            result.add_error(ERR_DEP_REGISTRY_DRIFT, rel, f"row/{dep_id}", f"Markdown mirror contains dependency ID {dep_id!r} absent from the JSON registry")
    for dep_id, json_row in json_by_id.items():
        md_row = md_by_id.get(dep_id)
        if md_row is None:
            result.add_error(ERR_DEP_REGISTRY_DRIFT, rel, f"row/{dep_id}", f"JSON registry contains dependency ID {dep_id!r} absent from the markdown mirror")
            continue
        for key, title, _kind in ROW_COLUMNS:
            if key not in json_row:
                continue  # already a MISSING-FIELD finding
            if md_row.get(key) != json_row[key]:
                result.add_error(ERR_DEP_REGISTRY_DRIFT, rel, f"row/{dep_id}/{key}", f"Markdown mirror {title} mismatch for {dep_id!r}: markdown={md_row.get(key)!r}, json={json_row[key]!r}")
    shared_md = [row["id"] for row in md_rows if row["id"] in json_by_id]
    shared_json = [row["id"] for row in json_rows if row["id"] in md_by_id]
    if len(set(shared_md)) == len(shared_md) and len(set(shared_json)) == len(shared_json) and shared_md != shared_json:
        result.add_error(ERR_DEP_REGISTRY_DRIFT, rel, "#", f"markdown row order {shared_md} differs from JSON order {shared_json}")
    if len(md_rows) != len(json_rows):
        result.add_error(ERR_DEP_REGISTRY_DRIFT, rel, "#", f"Markdown mirror row count ({len(md_rows)}) differs from JSON row count ({len(json_rows)})")


# ---------------------------------------------------------------------------------------------
# Traceability (owner / producers / consumers / ContractBasis / registered error codes)
# ---------------------------------------------------------------------------------------------


def _read_text(root: Path, rel: str) -> str | None:
    data, problems = authority.read_input_bytes(root / rel, rel)
    if data is None:
        return None
    text, problems = authority.decode_utf8(data, rel)
    return text


def _registered_error_codes(root: Path, result: ValidationResult) -> set[str] | None:
    rel = ERRORS_MD_PATH
    data, problems = authority.read_input_bytes(root / rel, rel)
    if data is None:
        result.extend(problems)
        return None
    text, problems = authority.decode_utf8(data, rel)
    if text is None:
        result.extend(problems)
        return None
    return set(re.findall(r"^\| `(ERR-[A-Z0-9-]+)` \|", text, flags=re.MULTILINE))


def check_traces(result: ValidationResult, auth: authority.Authority, emitted_codes: tuple[str, ...] = REGISTRY_CHECKER_ERROR_CODES) -> None:
    root = auth.root
    rel = DEPENDENCIES_JSON_PATH
    registered = _registered_error_codes(root, result)
    if registered is not None:
        for code in emitted_codes:
            if code not in registered:
                result.add_error(ERR_DEP_TRACE_UNRESOLVED, ERRORS_MD_PATH, f"#/{code}", f"diagnostic {code} emitted by the dependency checkers is not registered in {ERRORS_MD_PATH} (ContractBasis error registry)")
    registry = auth.registry
    if registry is None:
        return
    basis = registry.get("contractBasis")
    if authority.is_str(basis):
        contracts, _raw, problems = authority.load_json_document(root / AGENT_CONTRACTS_PATH, AGENT_CONTRACTS_PATH)
        result.extend(problems)
        if contracts is not None:
            declared = authority.as_dict(contracts.get("semanticObjects")).get("ContractBasis")
            if declared != basis:
                result.add_error(ERR_DEP_TRACE_UNRESOLVED, rel, "#/contractBasis", f"contractBasis {basis!r} does not resolve: {AGENT_CONTRACTS_PATH} semanticObjects.ContractBasis is {declared!r}")
    allow_tables = set(authority.as_dict(auth.allowlist))
    cache: dict[str, str | None] = {}

    def text_of(path: str) -> str | None:
        if path not in cache:
            cache[path] = _read_text(root, path) if _safe_relative(path) else None
        return cache[path]

    for row in auth.rows():
        dep_id = row["id"]
        owner = row.get("owner")
        if authority.is_str(owner):
            text = text_of(owner)
            if text is None:
                result.add_error(ERR_DEP_TRACE_UNRESOLVED, rel, f"row/{dep_id}/owner", f"owner {owner!r} of {dep_id} is not a readable repository file")
            elif dep_id not in text and DEPENDENCIES_JSON_PATH not in text:
                result.add_error(ERR_DEP_TRACE_UNRESOLVED, rel, f"row/{dep_id}/owner", f"owner {owner!r} references neither {dep_id} nor {DEPENDENCIES_JSON_PATH}; the owning module must read the row it enforces")
        for producer in authority.str_list(row.get("producers")):
            path, sep, table = producer.partition("#")
            if text_of(path) is None:
                result.add_error(ERR_DEP_TRACE_UNRESOLVED, rel, f"row/{dep_id}/producers", f"producer {producer!r} of {dep_id} is not a readable repository file")
            elif sep and (path != ALLOWLIST_TOML_PATH or table not in allow_tables):
                result.add_error(ERR_DEP_TRACE_UNRESOLVED, rel, f"row/{dep_id}/producers", f"producer {producer!r} of {dep_id} does not name a table of {ALLOWLIST_TOML_PATH}")
        for consumer in authority.str_list(row.get("consumers")):
            text = text_of(consumer)
            if text is None:
                result.add_error(ERR_DEP_TRACE_UNRESOLVED, rel, f"row/{dep_id}/consumers", f"consumer {consumer!r} of {dep_id} is not a readable repository file")
            elif dep_id not in text and DEPENDENCIES_JSON_PATH not in text:
                result.add_error(ERR_DEP_TRACE_UNRESOLVED, rel, f"row/{dep_id}/consumers", f"consumer {consumer!r} references neither {dep_id} nor {DEPENDENCIES_JSON_PATH}")


def _safe_relative(path: str) -> bool:
    candidate = Path(path)
    return bool(path) and not candidate.is_absolute() and ".." not in candidate.parts and "\\" not in path


# ---------------------------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------------------------


def compute_allowlist_freeze_digest(allowlist_path: Path) -> str:
    """sha256 of the allowlist bytes (the pinned value is BASELINE_ALLOWLIST_FREEZE_DIGEST)."""
    return authority.sha256_prefixed(allowlist_path.read_bytes())


def compute_constitution_freeze_digest(constitution_path: Path) -> str:
    """Canonical constitution digest of the file (the pinned value is BASELINE_CONSTITUTION_FREEZE_DIGEST)."""
    data = json.loads(constitution_path.read_text(encoding="utf-8"), object_pairs_hook=pairs_hook_reject_duplicates)
    return authority.compute_canonical_constitution_digest(data)


def load_tombstone_set(root: Path = ROOT) -> tuple[set[str], list[DiagnosticError]]:
    """Retired dependency identifiers from stable_id_resolution.json; missing or corrupt fails closed."""
    auth = authority.Authority(root=root)
    authority._load_resolutions(auth, root / STABLE_ID_RESOLUTION_PATH)
    retired: set[str] = set()
    for row in auth.resolutions or []:
        legacy = row.get("legacyId")
        markers = {row.get("status"), row.get("disposition")}
        if isinstance(legacy, str) and markers & authority.RETIRING_VALUES:
            retired.add(legacy)
    return retired, list(auth.issues)


def resolve_dependency_row_metadata(dep_id: str, repo_root: Path = ROOT) -> dict[str, Any]:
    """Owner, producers, consumers, ContractBasis link and tombstone state of one row, from the registry."""
    auth = authority.load_authority(repo_root)
    rows = {row["id"]: row for row in auth.rows()}
    row = rows.get(dep_id)
    if row is None or auth.registry is None:
        return {"id": dep_id, "resolved": False, "reason": f"{dep_id} is not a row of {DEPENDENCIES_JSON_PATH}", "findings": [asdict(e) for e in auth.issues]}
    status = row.get("status")
    retired = status in ("tombstoned", "superseded")
    return {
        "id": dep_id,
        "resolved": True,
        "canonicalId": row.get("supersededBy") if status == "superseded" else dep_id,
        "constitutionClass": row.get("constitutionClass"),
        "scope": row.get("scope"),
        "status": status,
        "owner": row.get("owner"),
        "producers": list(row.get("producers") or []),
        "consumers": list(row.get("consumers") or []),
        "contractBasis": auth.registry.get("contractBasis"),
        "registryGeneration": auth.registry.get("generation"),
        "registryDigest": auth.registry_digest,
        "tombstoneDecision": row.get("tombstoneDecision"),
        "isTombstoned": retired,
        "tombstone": retired,
    }


def validate_dependency_registry(
    repo_root: Path = ROOT,
    json_path: Path | None = None,
    md_path: Path | None = None,
) -> ValidationResult:
    result = ValidationResult()
    overrides = {DEPENDENCIES_JSON_PATH: json_path} if json_path is not None else None
    auth = authority.load_authority(repo_root, overrides)
    result.extend(auth.issues)
    registry = auth.registry or {}
    deps = registry.get("dependencies")
    result.dependency_count = len(deps) if isinstance(deps, list) else 0
    declared = registry.get("freezeDigest")
    result.freeze_digest = declared if isinstance(declared, str) else (auth.registry_digest or "")
    check_traces(result, auth)
    _compare_markdown(result, auth, md_path or (repo_root / DEPENDENCIES_MD_PATH))
    view = authority.build_class_view(auth)
    result.report = {
        "registryDigest": auth.registry_digest,
        "allowlistDigest": auth.allowlist_digest,
        "constitutionDigest": auth.constitution_digest,
        "pendingOwnerDecisions": {
            decision: dict(authority.as_dict(record))
            for decision, record in authority.as_dict(authority.as_dict(auth.allowlist).get("pending_owner_decisions")).items()
        },
        "classificationTables": {k: list(v) for k, v in (view.table_rows.items() if view else [])},
    }
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
            "report": result.report,
            "errorCount": len(result.errors),
            "errors": [asdict(e) for e in result.errors],
        }
        print(json.dumps(payload, indent=2, sort_keys=True))
    elif result.passed:
        pending = ", ".join(sorted(result.report.get("pendingOwnerDecisions", {}))) or "none"
        print(f"Dependency registry OK: {result.dependency_count} classes verified ({result.freeze_digest}); pending owner decisions: {pending}")
    else:
        print(f"Dependency registry verification FAILED with {len(result.errors)} error(s):", file=sys.stderr)
        for err in result.errors:
            print(f"  [{err.code}] {err.file_path} ({err.target}): {err.message}", file=sys.stderr)
    return 0 if result.passed else 1


if __name__ == "__main__":
    sys.exit(main())
