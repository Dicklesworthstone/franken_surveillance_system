#!/usr/bin/env python3
"""Machine-checked operation registry crosswalk checker (fss-x4a.25.1 / FSS-176).

Enforces total bijective mapping between registered fss/1 operations and their
presentation surfaces across CLI commands, library entry points, and MCP tools,
carrying stable error and exit identities.

Fails closed on:
- An operation present in one surface but missing in another (ERR-CROSSWALK-SURFACE-MISSING-001)
- Name collisions across CLI, library, or MCP tool names (ERR-CROSSWALK-NAME-COLLISION-001)
- Unregistered error codes not present in registries/ERRORS.md (ERR-CROSSWALK-UNREGISTERED-ERROR-001)
- Stale entries, status mismatches, or tombstone errors in active use (ERR-CROSSWALK-STALE-ENTRY-001)
- Divergence between JSON machine source and Markdown registry (ERR-CROSSWALK-DIVERGENCE-001)
- Corrupt or missing mandatory registry files (ERR-CROSSWALK-CORRUPT-FILE-001)
"""
from __future__ import annotations

import argparse
import json
import re
import sys
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]

# Stable error identities
ERR_CROSSWALK_SURFACE_MISSING = "ERR-CROSSWALK-SURFACE-MISSING-001"
ERR_CROSSWALK_NAME_COLLISION = "ERR-CROSSWALK-NAME-COLLISION-001"
ERR_CROSSWALK_UNREGISTERED_ERROR = "ERR-CROSSWALK-UNREGISTERED-ERROR-001"
ERR_CROSSWALK_STALE_ENTRY = "ERR-CROSSWALK-STALE-ENTRY-001"
ERR_CROSSWALK_DIVERGENCE = "ERR-CROSSWALK-DIVERGENCE-001"
ERR_CROSSWALK_CORRUPT_FILE = "ERR-CROSSWALK-CORRUPT-FILE-001"

DELIMITER_ROW_RE = re.compile(r"^\s*\|(?:\s*:?-+:?\s*\|)+\s*$")
INLINE_CODE_RE = re.compile(r"`([^`]+)`")


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
    errors: list[DiagnosticError] = field(default_factory=list)

    def add_error(self, code: str, file_path: str, target: str, message: str) -> None:
        self.passed = False
        self.errors.append(DiagnosticError(code=code, file_path=file_path, target=target, message=message))


def parse_markdown_table(file_path: Path) -> list[dict[str, str]]:
    """Parses GitHub-flavored Markdown tables into a list of row dictionaries."""
    if not file_path.is_file():
        return []

    try:
        lines = file_path.read_text(encoding="utf-8").splitlines()
    except OSError:
        return []

    header: list[str] = []
    rows: list[dict[str, str]] = []

    idx = 0
    while idx < len(lines):
        line = lines[idx]
        stripped = line.strip()
        if not stripped.startswith("|") or not stripped.endswith("|"):
            idx += 1
            continue
        if DELIMITER_ROW_RE.match(stripped):
            idx += 1
            continue

        # Check if the next line is a delimiter row indicating this is a header row
        next_stripped = lines[idx + 1].strip() if idx + 1 < len(lines) else ""
        if DELIMITER_ROW_RE.match(next_stripped):
            cells = [cell.strip() for cell in stripped[1:-1].split("|")]
            clean_cells = [INLINE_CODE_RE.sub(r"\1", cell).strip() for cell in cells]
            header = [c.lower().replace(" ", "_") for c in clean_cells]
            idx += 2
            continue

        cells = [cell.strip() for cell in stripped[1:-1].split("|")]
        clean_cells = [INLINE_CODE_RE.sub(r"\1", cell).strip() for cell in cells]

        if header and len(clean_cells) == len(header):
            rows.append(dict(zip(header, clean_cells)))

        idx += 1

    return rows


def parse_error_registry(file_path: Path) -> tuple[set[str], set[str]]:
    """Parses registries/ERRORS.md returning (all_error_ids, tombstoned_error_ids)."""
    rows = parse_markdown_table(file_path)
    all_errors: set[str] = set()
    tombstones: set[str] = set()

    for row in rows:
        eid = row.get("id", "").strip()
        meaning = row.get("meaning", "").lower()
        if eid:
            all_errors.add(eid)
            if "tombstone" in meaning or "superseded" in meaning:
                tombstones.add(eid)

    return all_errors, tombstones


def parse_exit_registry(file_path: Path) -> set[str]:
    """Parses registries/ERRORS.md returning all registered exit IDs."""
    rows = parse_markdown_table(file_path)
    exit_ids: set[str] = set()
    for row in rows:
        eid = row.get("exit_id", "").strip()
        if eid:
            exit_ids.add(eid)
    return exit_ids


def safe_str(val: Any) -> str:
    """Safely extracts a stripped string or returns empty string."""
    if isinstance(val, str):
        return val.strip()
    return ""


def normalize_identifier(s: str) -> str:
    """Normalizes identifier by lowercasing and converting non-alphanumeric separators to underscore."""
    return re.sub(r"[^a-z0-9]+", "_", s.lower()).strip("_")


def normalize_cli_command(cmd: str) -> str:
    """Normalizes CLI command by collapsing whitespace and lowercasing."""
    return " ".join(cmd.lower().split())


def validate_crosswalk(repo_root: Path = ROOT) -> ValidationResult:
    """Performs full machine crosswalk validation against operations, errors, and markdown."""
    result = ValidationResult()

    agent_ops_path = repo_root / "architecture" / "agent_operations.json"
    crosswalk_json_path = repo_root / "architecture" / "operation_crosswalk.json"
    crosswalk_md_path = repo_root / "registries" / "OPERATION_CROSSWALK.md"
    errors_md_path = repo_root / "registries" / "ERRORS.md"

    for mandatory_path in (agent_ops_path, crosswalk_json_path, crosswalk_md_path, errors_md_path):
        if not mandatory_path.is_file():
            result.add_error(
                ERR_CROSSWALK_CORRUPT_FILE,
                str(mandatory_path.relative_to(repo_root)),
                "#",
                f"Mandatory file missing: {mandatory_path.name}",
            )
            return result

    try:
        agent_ops_raw = agent_ops_path.read_text(encoding="utf-8")
        agent_ops_data = json.loads(agent_ops_raw)
    except (OSError, json.JSONDecodeError) as exc:
        result.add_error(
            ERR_CROSSWALK_CORRUPT_FILE,
            "architecture/agent_operations.json",
            "#",
            f"Failed to parse agent_operations.json: {exc}",
        )
        return result

    try:
        crosswalk_raw = crosswalk_json_path.read_text(encoding="utf-8")
        crosswalk_data = json.loads(crosswalk_raw)
    except (OSError, json.JSONDecodeError) as exc:
        result.add_error(
            ERR_CROSSWALK_CORRUPT_FILE,
            "architecture/operation_crosswalk.json",
            "#",
            f"Failed to parse operation_crosswalk.json: {exc}",
        )
        return result

    if not isinstance(agent_ops_data, dict):
        result.add_error(
            ERR_CROSSWALK_CORRUPT_FILE,
            "architecture/agent_operations.json",
            "#",
            "Root of agent_operations.json must be a JSON object",
        )
        return result

    if not isinstance(crosswalk_data, dict):
        result.add_error(
            ERR_CROSSWALK_CORRUPT_FILE,
            "architecture/operation_crosswalk.json",
            "#",
            "Root of operation_crosswalk.json must be a JSON object",
        )
        return result

    crosswalk_entries = crosswalk_data.get("crosswalk")
    if not isinstance(crosswalk_entries, list) or len(crosswalk_entries) == 0:
        result.add_error(
            ERR_CROSSWALK_CORRUPT_FILE,
            "architecture/operation_crosswalk.json",
            "#/crosswalk",
            "Crosswalk entries collection is missing, not a list, or empty",
        )
        return result

    registered_ops: dict[str, dict[str, Any]] = {}
    for op in agent_ops_data.get("operations", []):
        if isinstance(op, dict):
            opid = safe_str(op.get("id"))
            if opid:
                registered_ops[opid] = op

    all_errors, tombstoned_errors = parse_error_registry(errors_md_path)
    registered_exit_ids = parse_exit_registry(errors_md_path)
    md_rows = parse_markdown_table(crosswalk_md_path)
    md_map: dict[str, dict[str, str]] = {}
    for r in md_rows:
        oid = safe_str(r.get("operation_id"))
        if oid:
            md_map[oid] = r

    crosswalk_map: dict[str, dict[str, Any]] = {}
    cli_commands: dict[str, str] = {}
    mcp_tools: dict[str, str] = {}
    library_entries: dict[str, str] = {}

    for idx, entry in enumerate(crosswalk_entries):
        if not isinstance(entry, dict):
            result.add_error(
                ERR_CROSSWALK_CORRUPT_FILE,
                "architecture/operation_crosswalk.json",
                f"#/crosswalk[{idx}]",
                "Crosswalk entry must be a JSON object",
            )
            continue

        op_id = safe_str(entry.get("operation_id"))
        op_name = safe_str(entry.get("operation_name"))
        cli_cmd = safe_str(entry.get("cli_command"))
        lib_entry = safe_str(entry.get("library_entry_point"))
        mcp_tool = safe_str(entry.get("mcp_tool_name"))
        primary_err = safe_str(entry.get("primary_error_id"))
        error_ids = entry.get("error_identities")
        exit_ids = entry.get("exit_identities")
        status = safe_str(entry.get("status"))

        if not op_id:
            result.add_error(
                ERR_CROSSWALK_SURFACE_MISSING,
                "architecture/operation_crosswalk.json",
                f"#/crosswalk[{idx}]",
                "Crosswalk entry missing operation_id",
            )
            continue

        if op_id in crosswalk_map:
            result.add_error(
                ERR_CROSSWALK_NAME_COLLISION,
                "architecture/operation_crosswalk.json",
                f"#/crosswalk/{op_id}",
                f"Duplicate operation_id in crosswalk: {op_id}",
            )
            continue

        crosswalk_map[op_id] = entry

        # Check required surface mappings
        for field_name, val in (
            ("cli_command", cli_cmd),
            ("library_entry_point", lib_entry),
            ("mcp_tool_name", mcp_tool),
        ):
            if not val:
                result.add_error(
                    ERR_CROSSWALK_SURFACE_MISSING,
                    "architecture/operation_crosswalk.json",
                    f"#/crosswalk/{op_id}/{field_name}",
                    f"Operation '{op_id}' missing mandatory surface mapping: {field_name}",
                )

        # Check CLI collisions including normalization and prefix collision
        if cli_cmd:
            norm_cli = normalize_cli_command(cli_cmd)
            curr_tokens = tuple(norm_cli.split())
            collision_found = False
            for prev_norm, prev_op in cli_commands.items():
                prev_tokens = tuple(prev_norm.split())
                if curr_tokens == prev_tokens:
                    result.add_error(
                        ERR_CROSSWALK_NAME_COLLISION,
                        "architecture/operation_crosswalk.json",
                        f"#/crosswalk/{op_id}/cli_command",
                        f"CLI command '{cli_cmd}' collision between '{prev_op}' and '{op_id}'",
                    )
                    collision_found = True
                    break
                elif len(curr_tokens) < len(prev_tokens) and prev_tokens[:len(curr_tokens)] == curr_tokens:
                    result.add_error(
                        ERR_CROSSWALK_NAME_COLLISION,
                        "architecture/operation_crosswalk.json",
                        f"#/crosswalk/{op_id}/cli_command",
                        f"CLI command '{cli_cmd}' prefix collision: prefix of '{prev_op}' ('{prev_norm}')",
                    )
                    collision_found = True
                    break
                elif len(prev_tokens) < len(curr_tokens) and curr_tokens[:len(prev_tokens)] == prev_tokens:
                    result.add_error(
                        ERR_CROSSWALK_NAME_COLLISION,
                        "architecture/operation_crosswalk.json",
                        f"#/crosswalk/{op_id}/cli_command",
                        f"CLI command '{cli_cmd}' prefix collision: prefixed by '{prev_op}' ('{prev_norm}')",
                    )
                    collision_found = True
                    break
            if not collision_found:
                cli_commands[norm_cli] = op_id

        if mcp_tool:
            norm_mcp = normalize_identifier(mcp_tool)
            if norm_mcp in mcp_tools:
                result.add_error(
                    ERR_CROSSWALK_NAME_COLLISION,
                    "architecture/operation_crosswalk.json",
                    f"#/crosswalk/{op_id}/mcp_tool_name",
                    f"MCP tool name '{mcp_tool}' collision between '{mcp_tools[norm_mcp]}' and '{op_id}'",
                )
            else:
                mcp_tools[norm_mcp] = op_id

        if lib_entry:
            norm_lib = normalize_identifier(lib_entry)
            if norm_lib in library_entries:
                result.add_error(
                    ERR_CROSSWALK_NAME_COLLISION,
                    "architecture/operation_crosswalk.json",
                    f"#/crosswalk/{op_id}/library_entry_point",
                    f"Library entry point '{lib_entry}' collision between '{library_entries[norm_lib]}' and '{op_id}'",
                )
            else:
                library_entries[norm_lib] = op_id

        # Check operation existence in agent_operations.json
        if op_id not in registered_ops:
            result.add_error(
                ERR_CROSSWALK_SURFACE_MISSING,
                "architecture/operation_crosswalk.json",
                f"#/crosswalk/{op_id}",
                f"Operation '{op_id}' exists in crosswalk but is not registered in agent_operations.json",
            )
        else:
            reg_op = registered_ops[op_id]
            reg_status = safe_str(reg_op.get("status"))
            if status != reg_status:
                result.add_error(
                    ERR_CROSSWALK_STALE_ENTRY,
                    "architecture/operation_crosswalk.json",
                    f"#/crosswalk/{op_id}/status",
                    f"Operation '{op_id}' status mismatch: crosswalk has '{status}', agent_operations has '{reg_status}'",
                )
            if reg_status in ("tombstone", "deprecated") or status in ("tombstone", "deprecated"):
                result.add_error(
                    ERR_CROSSWALK_STALE_ENTRY,
                    "architecture/operation_crosswalk.json",
                    f"#/crosswalk/{op_id}/status",
                    f"Operation '{op_id}' is tombstoned/deprecated but has an active crosswalk mapping",
                )

        # Check error codes
        if not primary_err:
            result.add_error(
                ERR_CROSSWALK_SURFACE_MISSING,
                "architecture/operation_crosswalk.json",
                f"#/crosswalk/{op_id}/primary_error_id",
                f"Operation '{op_id}' missing mandatory primary_error_id",
            )
        elif primary_err not in all_errors:
            result.add_error(
                ERR_CROSSWALK_UNREGISTERED_ERROR,
                "architecture/operation_crosswalk.json",
                f"#/crosswalk/{op_id}/primary_error_id",
                f"Operation '{op_id}' references unregistered primary error ID: {primary_err}",
            )
        elif primary_err in tombstoned_errors:
            result.add_error(
                ERR_CROSSWALK_STALE_ENTRY,
                "architecture/operation_crosswalk.json",
                f"#/crosswalk/{op_id}/primary_error_id",
                f"Operation '{op_id}' references tombstoned error ID: {primary_err}",
            )

        if not isinstance(error_ids, list):
            result.add_error(
                ERR_CROSSWALK_CORRUPT_FILE,
                "architecture/operation_crosswalk.json",
                f"#/crosswalk/{op_id}/error_identities",
                f"Operation '{op_id}' error_identities must be a list",
            )
        else:
            for err_id in error_ids:
                if not isinstance(err_id, str):
                    result.add_error(
                        ERR_CROSSWALK_CORRUPT_FILE,
                        "architecture/operation_crosswalk.json",
                        f"#/crosswalk/{op_id}/error_identities",
                        f"Operation '{op_id}' error identity must be a string",
                    )
                    continue
                err_id_str = err_id.strip()
                if err_id_str not in all_errors:
                    result.add_error(
                        ERR_CROSSWALK_UNREGISTERED_ERROR,
                        "architecture/operation_crosswalk.json",
                        f"#/crosswalk/{op_id}/error_identities",
                        f"Operation '{op_id}' references unregistered error ID: {err_id_str}",
                    )
                elif err_id_str in tombstoned_errors:
                    result.add_error(
                        ERR_CROSSWALK_STALE_ENTRY,
                        "architecture/operation_crosswalk.json",
                        f"#/crosswalk/{op_id}/error_identities",
                        f"Operation '{op_id}' references tombstoned error ID: {err_id_str}",
                    )

        # Check exit identities
        if not isinstance(exit_ids, list) or len(exit_ids) == 0:
            result.add_error(
                ERR_CROSSWALK_SURFACE_MISSING,
                "architecture/operation_crosswalk.json",
                f"#/crosswalk/{op_id}/exit_identities",
                f"Operation '{op_id}' missing exit identities",
            )
        else:
            for exit_id in exit_ids:
                if not isinstance(exit_id, str):
                    result.add_error(
                        ERR_CROSSWALK_CORRUPT_FILE,
                        "architecture/operation_crosswalk.json",
                        f"#/crosswalk/{op_id}/exit_identities",
                        f"Operation '{op_id}' exit identity must be a string",
                    )
                    continue
                exit_id_str = exit_id.strip()
                if not exit_id_str.startswith("EXIT-"):
                    result.add_error(
                        ERR_CROSSWALK_CORRUPT_FILE,
                        "architecture/operation_crosswalk.json",
                        f"#/crosswalk/{op_id}/exit_identities",
                        f"Operation '{op_id}' invalid exit identity format: {exit_id_str}",
                    )
                elif exit_id_str not in registered_exit_ids:
                    result.add_error(
                        ERR_CROSSWALK_UNREGISTERED_ERROR,
                        "architecture/operation_crosswalk.json",
                        f"#/crosswalk/{op_id}/exit_identities",
                        f"Operation '{op_id}' references unregistered exit identity: {exit_id_str}",
                    )

        # Check markdown table parity (forward check)
        if op_id not in md_map:
            result.add_error(
                ERR_CROSSWALK_DIVERGENCE,
                "registries/OPERATION_CROSSWALK.md",
                f"#{op_id}",
                f"Operation '{op_id}' present in JSON crosswalk but missing from registries/OPERATION_CROSSWALK.md",
            )
        else:
            md_row = md_map[op_id]
            if md_row.get("cli_command") != cli_cmd:
                result.add_error(
                    ERR_CROSSWALK_DIVERGENCE,
                    "registries/OPERATION_CROSSWALK.md",
                    f"#{op_id}/cli_command",
                    f"Operation '{op_id}' CLI command mismatch: markdown '{md_row.get('cli_command')}' != json '{cli_cmd}'",
                )
            if md_row.get("mcp_tool_name") != mcp_tool:
                result.add_error(
                    ERR_CROSSWALK_DIVERGENCE,
                    "registries/OPERATION_CROSSWALK.md",
                    f"#{op_id}/mcp_tool_name",
                    f"Operation '{op_id}' MCP tool mismatch: markdown '{md_row.get('mcp_tool_name')}' != json '{mcp_tool}'",
                )
            if md_row.get("library_entry_point") != lib_entry:
                result.add_error(
                    ERR_CROSSWALK_DIVERGENCE,
                    "registries/OPERATION_CROSSWALK.md",
                    f"#{op_id}/library_entry_point",
                    f"Operation '{op_id}' library entry mismatch: markdown '{md_row.get('library_entry_point')}' != json '{lib_entry}'",
                )

    # Check reverse markdown table parity
    for md_op_id in md_map:
        if md_op_id not in crosswalk_map:
            result.add_error(
                ERR_CROSSWALK_DIVERGENCE,
                "registries/OPERATION_CROSSWALK.md",
                f"#{md_op_id}",
                f"Operation '{md_op_id}' present in registries/OPERATION_CROSSWALK.md but missing from JSON crosswalk",
            )

    # Check for operations in agent_operations.json missing from crosswalk
    for reg_id in registered_ops:
        if reg_id not in crosswalk_map:
            result.add_error(
                ERR_CROSSWALK_SURFACE_MISSING,
                "architecture/operation_crosswalk.json",
                f"#/crosswalk/{reg_id}",
                f"Operation '{reg_id}' in agent_operations.json is missing from operation crosswalk",
            )

    result.operation_count = len(crosswalk_map)
    return result


def main() -> int:
    parser = argparse.ArgumentParser(description="Operation registry crosswalk checker.")
    parser.add_argument("--json", action="store_true", help="Output machine-readable JSON result.")
    args = parser.parse_args()

    result = validate_crosswalk(ROOT)

    if args.json:
        payload = {
            "status": "passed" if result.passed else "failed",
            "operationCount": result.operation_count,
            "errorCount": len(result.errors),
            "errors": [asdict(e) for e in result.errors],
        }
        print(json.dumps(payload, indent=2))
    else:
        if result.passed:
            print(f"[PASS] Operation crosswalk verified: {result.operation_count} operations with 1-to-1 surface mappings.")
        else:
            print(f"[FAIL] Operation crosswalk verification failed with {len(result.errors)} errors:")
            for err in result.errors:
                print(f"  - [{err.code}] {err.file_path} ({err.target}): {err.message}")

    return 0 if result.passed else 1


if __name__ == "__main__":
    sys.exit(main())
