#!/usr/bin/env python3
"""Fail-closed consistency and freshness checker for self-describing robot docs (fss-x4a.24.34 / FSS-234).

Verifies that on-disk robot documentation:
1. Exists at docs/ROBOT_DOCS.md and docs/ROBOT_DOCS.json.
2. Contains zero hand-written drift: is byte-identical to what is derived from
   authoritative machine registries.
3. Completely covers all registered operations (AOP-001 .. AOP-014), views (AVIEW-001 .. AVIEW-008),
   resource URI templates (ARES-001 .. ARES-015), schemas, capabilities, and errors.
4. Fails closed with typed diagnostic errors if stale or inconsistent:
   - ERR-ROBOT-DOCS-MISSING-001
   - ERR-ROBOT-DOCS-STALE-001
   - ERR-ROBOT-DOCS-DRIFT-001
   - ERR-ROBOT-DOCS-UNREGISTERED-001
   - ERR-ROBOT-DOCS-CORRUPT-001
   - ERR-ROBOT-DOCS-SECRET-DETECTED-001
"""
from __future__ import annotations

import argparse
import difflib
import json
import sys
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))

from generate_robot_docs import (
    ERR_ROBOT_DOCS_CORRUPT,
    ERR_ROBOT_DOCS_DRIFT,
    ERR_ROBOT_DOCS_MISSING,
    ERR_ROBOT_DOCS_SECRET_DETECTED,
    ERR_ROBOT_DOCS_STALE,
    ERR_ROBOT_DOCS_UNREGISTERED,
    RobotDocsError,
    collect_robot_docs_model,
    generate_docs,
    load_json,
)


@dataclass(frozen=True)
class DiagnosticError:
    code: str
    file_path: str
    target: str
    message: str


@dataclass
class ValidationResult:
    passed: bool = True
    operations_count: int = 0
    views_count: int = 0
    resources_count: int = 0
    schemas_count: int = 0
    capabilities_count: int = 0
    errors_count: int = 0
    errors: list[DiagnosticError] = field(default_factory=list)
    stats: dict[str, Any] = field(default_factory=dict)

    def add_error(self, code: str, file_path: str, target: str, message: str) -> None:
        self.passed = False
        self.errors.append(DiagnosticError(code=code, file_path=file_path, target=target, message=message))


def validate_robot_docs(root: Path, docs_dir: Path | None = None) -> ValidationResult:
    """Performs comprehensive fail-closed validation of robot docs against registries."""
    result = ValidationResult()
    target_dir = docs_dir or (root / "docs")
    md_path = target_dir / "ROBOT_DOCS.md"
    json_path = target_dir / "ROBOT_DOCS.json"

    def format_rel(p: Path) -> str:
        return str(p.relative_to(root)) if p.is_relative_to(root) else str(p)

    # 1. Check file presence
    if not md_path.is_file():
        result.add_error(
            ERR_ROBOT_DOCS_MISSING,
            format_rel(md_path),
            "ROBOT_DOCS.md",
            f"Missing required robot documentation file: {md_path.name}",
        )
    if not json_path.is_file():
        result.add_error(
            ERR_ROBOT_DOCS_MISSING,
            format_rel(json_path),
            "ROBOT_DOCS.json",
            f"Missing required robot documentation file: {json_path.name}",
        )

    if not result.passed:
        return result

    # 2. Parse on-disk JSON
    try:
        on_disk_json = load_json(json_path)
    except (ValueError, KeyError) as exc:
        result.add_error(
            ERR_ROBOT_DOCS_CORRUPT,
            format_rel(json_path),
            "json_parser",
            f"Failed to parse robot docs JSON: {exc}",
        )
        return result
    except Exception as exc:
        result.add_error(
            ERR_ROBOT_DOCS_CORRUPT,
            format_rel(json_path),
            "json_reader",
            f"Unexpected error reading robot docs JSON: {exc}",
        )
        return result

    # Read on-disk Markdown
    try:
        on_disk_md = md_path.read_text(encoding="utf-8")
    except UnicodeDecodeError as exc:
        result.add_error(
            ERR_ROBOT_DOCS_CORRUPT,
            format_rel(md_path),
            "md_reader",
            f"Failed to read robot docs markdown (invalid unicode): {exc}",
        )
        return result
    except Exception as exc:
        result.add_error(
            ERR_ROBOT_DOCS_CORRUPT,
            format_rel(md_path),
            "md_reader",
            f"Failed to read robot docs markdown: {exc}",
        )
        return result

    # 3. Derive authoritative model from registries
    try:
        auth_model = collect_robot_docs_model(root)
        expected_md, expected_json = generate_docs(root)
    except RobotDocsError as exc:
        result.add_error(
            exc.code,
            exc.target or "architecture/",
            "registry_validator",
            exc.message,
        )
        return result
    except FileNotFoundError as exc:
        result.add_error(
            ERR_ROBOT_DOCS_MISSING,
            str(exc.filename or "registry"),
            "file_reader",
            f"Missing required registry file: {exc}",
        )
        return result
    except (ValueError, KeyError) as exc:
        result.add_error(
            ERR_ROBOT_DOCS_CORRUPT,
            "architecture/",
            "registry_parser",
            f"Failed to parse machine registries: {exc}",
        )
        return result

    result.operations_count = len(auth_model["operations"])
    result.views_count = len(auth_model["views"])
    result.resources_count = len(auth_model["resources"])
    result.schemas_count = len(auth_model["schemas"])
    result.capabilities_count = len(auth_model["capabilities"])
    result.errors_count = len(auth_model["errors"])
    result.stats = {
        "operations_count": result.operations_count,
        "views_count": result.views_count,
        "resources_count": result.resources_count,
        "schemas_count": result.schemas_count,
        "capabilities_count": result.capabilities_count,
        "errors_count": result.errors_count,
        "semantic_protocol": auth_model.get("semanticProtocol"),
        "generation": auth_model.get("registryGeneration"),
        "freeze_digest": auth_model.get("freezeDigest"),
    }

    # 4. Check byte-level staleness on Markdown
    if on_disk_md != expected_md:
        diff_lines = list(difflib.unified_diff(
            expected_md.splitlines()[:20],
            on_disk_md.splitlines()[:20],
            fromfile="expected_ROBOT_DOCS.md",
            tofile="on_disk_ROBOT_DOCS.md",
            lineterm="",
        ))
        diff_summary = "\n".join(diff_lines[:10]) if diff_lines else "Content length or bytes differ"
        result.add_error(
            ERR_ROBOT_DOCS_STALE,
            format_rel(md_path),
            "ROBOT_DOCS.md",
            f"On-disk robot docs markdown is stale compared to machine registries. Diff:\n{diff_summary}",
        )

    # 5. Check byte-level staleness on JSON
    if on_disk_json != auth_model or json_path.read_text(encoding="utf-8") != expected_json:
        result.add_error(
            ERR_ROBOT_DOCS_STALE,
            format_rel(json_path),
            "ROBOT_DOCS.json",
            "On-disk robot docs JSON is stale or formatting differs compared to machine registries",
        )

    # 6. Check structural completeness and canonical ordering
    # Verify operations match and ordering
    auth_op_ids = [op["id"] for op in auth_model["operations"]]
    disk_op_ids = [op["id"] for op in on_disk_json.get("operations", [])]
    if set(auth_op_ids) != set(disk_op_ids):
        missing = sorted(set(auth_op_ids) - set(disk_op_ids))
        extra = sorted(set(disk_op_ids) - set(auth_op_ids))
        result.add_error(
            ERR_ROBOT_DOCS_DRIFT,
            format_rel(json_path),
            "operations",
            f"Operation IDs drift: missing={missing}, extra={extra}",
        )
    elif disk_op_ids != auth_op_ids:
        result.add_error(
            ERR_ROBOT_DOCS_STALE,
            format_rel(json_path),
            "operations_ordering",
            "Operation entries are not in canonical sorted order by ID",
        )

    # Verify views match and ordering
    auth_view_ids = [v["id"] for v in auth_model["views"]]
    disk_view_ids = [v["id"] for v in on_disk_json.get("views", [])]
    if set(auth_view_ids) != set(disk_view_ids):
        missing = sorted(set(auth_view_ids) - set(disk_view_ids))
        extra = sorted(set(disk_view_ids) - set(auth_view_ids))
        result.add_error(
            ERR_ROBOT_DOCS_DRIFT,
            format_rel(json_path),
            "views",
            f"View IDs drift: missing={missing}, extra={extra}",
        )
    elif disk_view_ids != auth_view_ids:
        result.add_error(
            ERR_ROBOT_DOCS_STALE,
            format_rel(json_path),
            "views_ordering",
            "View entries are not in canonical sorted order by ID",
        )

    # Verify resources match and ordering
    auth_res_ids = [r["id"] for r in auth_model["resources"]]
    disk_res_ids = [r["id"] for r in on_disk_json.get("resources", [])]
    if set(auth_res_ids) != set(disk_res_ids):
        missing = sorted(set(auth_res_ids) - set(disk_res_ids))
        extra = sorted(set(disk_res_ids) - set(auth_res_ids))
        result.add_error(
            ERR_ROBOT_DOCS_DRIFT,
            format_rel(json_path),
            "resources",
            f"Resource IDs drift: missing={missing}, extra={extra}",
        )
    elif disk_res_ids != auth_res_ids:
        result.add_error(
            ERR_ROBOT_DOCS_STALE,
            format_rel(json_path),
            "resources_ordering",
            "Resource entries are not in canonical sorted order by ID",
        )

    # Verify capabilities match and ordering
    auth_cap_ids = [c["id"] for c in auth_model["capabilities"]]
    disk_cap_ids = [c["id"] for c in on_disk_json.get("capabilities", [])]
    if set(auth_cap_ids) != set(disk_cap_ids):
        missing = sorted(set(auth_cap_ids) - set(disk_cap_ids))
        extra = sorted(set(disk_cap_ids) - set(auth_cap_ids))
        result.add_error(
            ERR_ROBOT_DOCS_DRIFT,
            format_rel(json_path),
            "capabilities",
            f"Capability IDs drift: missing={missing}, extra={extra}",
        )
    elif disk_cap_ids != auth_cap_ids:
        result.add_error(
            ERR_ROBOT_DOCS_STALE,
            format_rel(json_path),
            "capabilities_ordering",
            "Capability entries are not in canonical sorted order by ID",
        )

    return result


def main() -> int:
    parser = argparse.ArgumentParser(description="Check self-describing robot docs for freshness and consistency.")
    parser.add_argument("--docs-dir", type=Path, default=None, help="Directory containing ROBOT_DOCS.md and ROBOT_DOCS.json.")
    parser.add_argument("--json", action="store_true", help="Emit structured status JSON.")
    args = parser.parse_args()

    result = validate_robot_docs(ROOT, docs_dir=args.docs_dir)

    if args.json:
        payload = {
            "status": "passed" if result.passed else "failed",
            "operations_count": result.operations_count,
            "views_count": result.views_count,
            "resources_count": result.resources_count,
            "schemas_count": result.schemas_count,
            "capabilities_count": result.capabilities_count,
            "errors_count": result.errors_count,
            "stats": result.stats,
            "errors": [asdict(e) for e in result.errors],
        }
        print(json.dumps(payload, indent=2))
    else:
        if result.passed:
            print(f"[PASS] Robot docs are fresh and consistent ({result.operations_count} operations, "
                  f"{result.views_count} views, {result.resources_count} resources, {result.schemas_count} schemas, "
                  f"{result.capabilities_count} capabilities, {result.errors_count} errors).")
        else:
            print(f"[FAIL] Robot docs audit failed with {len(result.errors)} error(s):", file=sys.stderr)
            for err in result.errors:
                print(f"  [{err.code}] {err.file_path}:{err.target} - {err.message}", file=sys.stderr)

    return 0 if result.passed else 1


if __name__ == "__main__":
    sys.exit(main())
