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
    """Parses a GitHub-flavored Markdown table into a list of row dictionaries."""
    if not file_path.is_file():
        return []

    lines = file_path.read_text(encoding="utf-8").splitlines()
    header: list[str] = []
    rows: list[dict[str, str]] = []

    for line in lines:
        stripped = line.strip()
        if not stripped.startswith("|") or not stripped.endswith("|"):
            continue
        if DELIMITER_ROW_RE.match(stripped):
            continue

        cells = [cell.strip() for cell in stripped[1:-1].split("|")]
        # Strip backticks from cells
        clean_cells = [INLINE_CODE_RE.sub(r"\1", cell).strip() for cell in cells]

        if not header:
            header = [c.lower().replace(" ", "_") for c in clean_cells]
            continue

        if len(clean_cells) == len(header):
            rows.append(dict(zip(header, clean_cells)))

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
        agent_ops_data = json.loads(agent_ops_path.read_text(encoding="utf-8"))
    except Exception as exc:
        result.add_error(
            ERR_CROSSWALK_CORRUPT_FILE,
            "architecture/agent_operations.json",
            "#",
            f"Failed to parse agent_operations.json: {exc}",
        )
        return result

    try:
        crosswalk_data = json.loads(crosswalk_json_path.read_text(encoding="utf-8"))
    except Exception as exc:
        result.add_error(
            ERR_CROSSWALK_CORRUPT_FILE,
            "architecture/operation_crosswalk.json",
            "#",
            f"Failed to parse operation_crosswalk.json: {exc}",
        )
        return result

    crosswalk_entries = crosswalk_data.get("crosswalk")
    if not isinstance(crosswalk_entries, list) or len(crosswalk_entries) == 0:
        result.add_error(
            ERR_CROSSWALK_CORRUPT_FILE,
            "architecture/operation_crosswalk.json",
            "#/crosswalk",
            "Crosswalk entries collection is missing or empty",
        )
        return result

    registered_ops: dict[str, dict[str, Any]] = {}
    for op in agent_ops_data.get("operations", []):
        opid = op.get("id")
        if opid:
            registered_ops[opid] = op

    all_errors, tombstoned_errors = parse_error_registry(errors_md_path)
    md_rows = parse_markdown_table(crosswalk_md_path)
    md_map: dict[str, dict[str, str]] = {}
    for r in md_rows:
        oid = r.get("operation_id", "").strip()
        if oid:
            md_map[oid] = r

    crosswalk_map: dict[str, dict[str, Any]] = {}
    cli_commands: dict[str, str] = {}
    mcp_tools: dict[str, str] = {}
    library_entries: dict[str, str] = {}

    for idx, entry in enumerate(crosswalk_entries):
        op_id = entry.get("operation_id", "").strip()
        op_name = entry.get("operation_name", "").strip()
        cli_cmd = entry.get("cli_command", "").strip()
        lib_entry = entry.get("library_entry_point", "").strip()
        mcp_tool = entry.get("mcp_tool_name", "").strip()
        primary_err = entry.get("primary_error_id", "").strip()
        error_ids = entry.get("error_identities", [])
        exit_ids = entry.get("exit_identities", [])
        status = entry.get("status", "").strip()

        if not op_id:
            result.add_error(
                ERR_CROSSWALK_SURFACE_MISSING,
                "architecture/operation_crosswalk.json",
                f"#/crosswalk[{idx}]",
                "Crosswalk entry missing operation_id",
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

        # Check collisions
        if cli_cmd:
            if cli_cmd in cli_commands:
                result.add_error(
                    ERR_CROSSWALK_NAME_COLLISION,
                    "architecture/operation_crosswalk.json",
                    f"#/crosswalk/{op_id}/cli_command",
                    f"CLI command '{cli_cmd}' collision between '{cli_commands[cli_cmd]}' and '{op_id}'",
                )
            else:
                cli_commands[cli_cmd] = op_id

        if mcp_tool:
            if mcp_tool in mcp_tools:
                result.add_error(
                    ERR_CROSSWALK_NAME_COLLISION,
                    "architecture/operation_crosswalk.json",
                    f"#/crosswalk/{op_id}/mcp_tool_name",
                    f"MCP tool name '{mcp_tool}' collision between '{mcp_tools[mcp_tool]}' and '{op_id}'",
                )
            else:
                mcp_tools[mcp_tool] = op_id

        if lib_entry:
            if lib_entry in library_entries:
                result.add_error(
                    ERR_CROSSWALK_NAME_COLLISION,
                    "architecture/operation_crosswalk.json",
                    f"#/crosswalk/{op_id}/library_entry_point",
                    f"Library entry point '{lib_entry}' collision between '{library_entries[lib_entry]}' and '{op_id}'",
                )
            else:
                library_entries[lib_entry] = op_id

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
            # Check status match
            reg_status = reg_op.get("status", "").strip()
            if status != reg_status:
                result.add_error(
                    ERR_CROSSWALK_STALE_ENTRY,
                    "architecture/operation_crosswalk.json",
                    f"#/crosswalk/{op_id}/status",
                    f"Operation '{op_id}' status mismatch: crosswalk has '{status}', agent_operations has '{reg_status}'",
                )

        # Check error codes
        if primary_err:
            if primary_err not in all_errors:
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

        for err_id in error_ids:
            if err_id not in all_errors:
                result.add_error(
                    ERR_CROSSWALK_UNREGISTERED_ERROR,
                    "architecture/operation_crosswalk.json",
                    f"#/crosswalk/{op_id}/error_identities",
                    f"Operation '{op_id}' references unregistered error ID: {err_id}",
                )

        # Check exit identities
        if not exit_ids:
            result.add_error(
                ERR_CROSSWALK_SURFACE_MISSING,
                "architecture/operation_crosswalk.json",
                f"#/crosswalk/{op_id}/exit_identities",
                f"Operation '{op_id}' missing exit identities",
            )
        else:
            for exit_id in exit_ids:
                if not exit_id.startswith("EXIT-"):
                    result.add_error(
                        ERR_CROSSWALK_CORRUPT_FILE,
                        "architecture/operation_crosswalk.json",
                        f"#/crosswalk/{op_id}/exit_identities",
                        f"Operation '{op_id}' invalid exit identity format: {exit_id}",
                    )

        # Check markdown table parity
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
