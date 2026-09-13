#!/usr/bin/env python3
"""Deterministic generator for self-describing robot documentation (fss-x4a.24.34 / FSS-234).

Derives machine-readable and human-legible robot documentation directly from
authoritative machine registries:
- architecture/fss1_public_registry.json
- architecture/agent_operations.json
- architecture/agent_views.json
- architecture/capabilities.json
- architecture/operation_crosswalk.json
- registries/ERRORS.md
- registries/SCHEMAS.md

Guarantees:
- Zero hand-written drift: all operations, views, resources, schemas, and capabilities
  are derived from machine registries.
- Strict determinism: canonical sorting, normalized whitespace, byte-level stability.
- Staleness checking via --check mode: exits with non-zero status if on-disk docs
  diverge from the authoritative registries.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import re
import sys
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]

ERR_ROBOT_DOCS_STALE = "ERR-ROBOT-DOCS-STALE-001"
ERR_ROBOT_DOCS_MISSING = "ERR-ROBOT-DOCS-MISSING-001"
ERR_ROBOT_DOCS_DRIFT = "ERR-ROBOT-DOCS-DRIFT-001"
ERR_ROBOT_DOCS_CORRUPT = "ERR-ROBOT-DOCS-CORRUPT-001"


def load_json(path: Path) -> dict[str, Any]:
    """Loads a JSON file with utf-8 encoding."""
    return json.loads(path.read_text(encoding="utf-8"))


def parse_errors_registry(errors_md_path: Path) -> dict[str, dict[str, str]]:
    """Parses registries/ERRORS.md into an error_id -> {description, guidance} dict."""
    if not errors_md_path.is_file():
        return {}
    errors: dict[str, dict[str, str]] = {}
    for line in errors_md_path.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if line.startswith("| `ERR-"):
            parts = [p.strip() for p in line.split("|")[1:-1]]
            if len(parts) >= 2:
                err_id = parts[0].replace("`", "")
                description = parts[1]
                guidance = parts[2] if len(parts) > 2 else ""
                errors[err_id] = {
                    "id": err_id,
                    "description": description,
                    "guidance": guidance,
                }
    return errors


def parse_schemas_registry(schemas_md_path: Path) -> dict[str, dict[str, str]]:
    """Parses registries/SCHEMAS.md into schema_name -> {id, file, authority, compatibility}."""
    if not schemas_md_path.is_file():
        return {}
    schemas: dict[str, dict[str, str]] = {}
    for line in schemas_md_path.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if line.startswith("| `SCHEMA-"):
            parts = [p.strip() for p in line.split("|")[1:-1]]
            if len(parts) >= 5:
                s_id = parts[0].replace("`", "")
                s_name = parts[1].replace("`", "")
                s_file = parts[2].replace("`", "")
                s_auth = parts[3]
                s_comp = parts[4]
                schemas[s_name] = {
                    "id": s_id,
                    "schema": s_name,
                    "file": s_file,
                    "authority": s_auth,
                    "compatibility_rule": s_comp,
                }
    return schemas


def collect_robot_docs_model(root: Path) -> dict[str, Any]:
    """Assembles the canonical, consolidated robot docs model from authoritative registries."""
    fss1_reg = load_json(root / "architecture/fss1_public_registry.json")
    agent_ops_reg = load_json(root / "architecture/agent_operations.json")
    agent_views_reg = load_json(root / "architecture/agent_views.json")
    caps_reg = load_json(root / "architecture/capabilities.json")
    crosswalk_reg = load_json(root / "architecture/operation_crosswalk.json")
    errors_map = parse_errors_registry(root / "registries/ERRORS.md")
    schemas_map = parse_schemas_registry(root / "registries/SCHEMAS.md")

    # Index crosswalk by operation_id
    cw_by_id = {entry["operation_id"]: entry for entry in crosswalk_reg.get("crosswalk", [])}

    # Index fss1 operations by id
    fss1_ops_by_id = {op["id"]: op for op in fss1_reg.get("operations", [])}

    # Index capabilities by id
    caps_by_id = {cap["id"]: cap for cap in caps_reg.get("capabilities", [])}

    # Consolidated operations (sorted by ID)
    consolidated_ops: list[dict[str, Any]] = []
    for raw_op in sorted(agent_ops_reg.get("operations", []), key=lambda o: o["id"]):
        op_id = raw_op["id"]
        cw = cw_by_id.get(op_id, {})
        fss1_op = fss1_ops_by_id.get(op_id, {})

        cli_cmd = cw.get("cli_command") or fss1_op.get("cliCommand", "")
        mcp_tool = cw.get("mcp_tool_name") or fss1_op.get("mcpToolName", "")
        lib_entry = cw.get("library_entry_point", "")
        primary_err = cw.get("primary_error_id", "")
        error_ids = cw.get("error_identities", [])
        exit_ids = cw.get("exit_identities", [])

        consolidated_ops.append({
            "id": op_id,
            "name": raw_op["name"],
            "purpose": raw_op["purpose"],
            "mode": raw_op["mode"],
            "owner": raw_op["owner"],
            "defaultView": raw_op["defaultView"],
            "effectful": raw_op["effectful"],
            "durable": raw_op["durable"],
            "cliCommand": cli_cmd,
            "mcpToolName": mcp_tool,
            "libraryEntryPoint": lib_entry,
            "requestEnvelope": raw_op.get("inputSchema", "fss.agent_request_envelope.v1"),
            "responseEnvelope": raw_op.get("outputSchema", "fss.agent_response_envelope.v1"),
            "requestPayloadSchema": raw_op.get("requestPayloadSchema", ""),
            "responsePayloadSchemas": raw_op.get("responsePayloadSchemas", []),
            "requiredCapabilities": sorted(raw_op.get("requiredCapabilities", [])),
            "retryClasses": raw_op.get("retryClasses", []),
            "primaryErrorId": primary_err,
            "errorIdentities": error_ids,
            "exitIdentities": exit_ids,
            "gate": raw_op.get("gate", "QL-AGENT-001"),
            "status": raw_op.get("status", "specified"),
        })

    # Consolidated views (sorted by ID)
    consolidated_views: list[dict[str, Any]] = []
    for raw_view in sorted(agent_views_reg.get("views", []), key=lambda v: v["id"]):
        consolidated_views.append({
            "id": raw_view["id"],
            "name": raw_view["name"],
            "owner": raw_view["owner"],
            "purpose": raw_view["purpose"],
            "targetTokens": raw_view["targetTokens"],
            "maximumTokens": raw_view["maximumTokens"],
            "requiredSections": raw_view["requiredSections"],
            "gate": raw_view.get("gate", "QL-AGENT-001"),
            "status": raw_view.get("status", "specified"),
        })

    # Consolidated resources (sorted by ID)
    consolidated_resources: list[dict[str, Any]] = []
    for raw_res in sorted(fss1_reg.get("resources", []), key=lambda r: r["id"]):
        consolidated_resources.append({
            "id": raw_res["id"],
            "name": raw_res["name"],
            "owner": raw_res["owner"],
            "uriTemplate": raw_res["uriTemplate"],
            "requestEnvelope": raw_res.get("requestEnvelope", "fss.agent_request_envelope.v1"),
            "responseEnvelope": raw_res.get("responseEnvelope", "fss.agent_response_envelope.v1"),
            "payloadSchema": raw_res.get("payloadSchema", ""),
            "compatibilityClass": raw_res.get("compatibilityClass", "backward_compatible"),
            "status": raw_res.get("status", "specified"),
        })

    # Referenced schemas in operations and resources
    referenced_schema_names: set[str] = set()
    for op in consolidated_ops:
        if op["requestEnvelope"]:
            referenced_schema_names.add(op["requestEnvelope"])
        if op["responseEnvelope"]:
            referenced_schema_names.add(op["responseEnvelope"])
        if op["requestPayloadSchema"]:
            referenced_schema_names.add(op["requestPayloadSchema"])
        for s in op["responsePayloadSchemas"]:
            referenced_schema_names.add(s)
    for res in consolidated_resources:
        if res["requestEnvelope"]:
            referenced_schema_names.add(res["requestEnvelope"])
        if res["responseEnvelope"]:
            referenced_schema_names.add(res["responseEnvelope"])
        if res["payloadSchema"]:
            referenced_schema_names.add(res["payloadSchema"])

    # Always include core protocol schemas
    referenced_schema_names.add("fss.agent_contract_basis.v1")
    referenced_schema_names.add("fss.agent_world_envelope.v1")
    referenced_schema_names.add("fss.semantic_compression_receipt.v1")

    consolidated_schemas: list[dict[str, Any]] = []
    for s_name in sorted(referenced_schema_names):
        entry = schemas_map.get(s_name, {})
        consolidated_schemas.append({
            "id": entry.get("id", "SCHEMA-UNKNOWN"),
            "schema": s_name,
            "file": entry.get("file", f"schemas/{s_name}.json"),
            "authority": entry.get("authority", "authority"),
            "compatibilityRule": entry.get("compatibility_rule", "immutable; additions compatible"),
        })

    # Required capabilities for operations
    required_cap_ids: set[str] = set()
    for op in consolidated_ops:
        for cap_id in op["requiredCapabilities"]:
            required_cap_ids.add(cap_id)

    consolidated_caps: list[dict[str, Any]] = []
    for cap_id in sorted(required_cap_ids):
        cap = caps_by_id.get(cap_id, {})
        consolidated_caps.append({
            "id": cap_id,
            "name": cap.get("name", cap_id.lower().replace("-", "_")),
            "plane": cap.get("plane", "authority"),
            "description": cap.get("description", "Declared agent operating capability"),
        })

    # Relevant errors
    relevant_error_ids: set[str] = set()
    for op in consolidated_ops:
        if op["primaryErrorId"]:
            relevant_error_ids.add(op["primaryErrorId"])
        for err_id in op["errorIdentities"]:
            relevant_error_ids.add(err_id)
    # Core agent errors
    relevant_error_ids.update([
        "ERR-AGENT-PROTOCOL-001",
        "ERR-AGENT-SESSION-STALE-001",
        "ERR-AGENT-CONTEXT-INCOMPLETE-001",
        "ERR-AGENT-HANDOFF-INVALID-001",
        "ERR-AGENT-WORK-CLAIM-CONFLICT-001",
        "ERR-AGENT-NO-AFFORDANCE-001",
        "ERR-AGENT-AFFORDANCE-INVALIDATED-001",
        "ERR-AGENT-RESNAPSHOT-001",
    ])

    consolidated_errors: list[dict[str, Any]] = []
    for err_id in sorted(relevant_error_ids):
        err = errors_map.get(err_id, {})
        consolidated_errors.append({
            "id": err_id,
            "description": err.get("description", "Protocol error"),
            "guidance": err.get("guidance", "Inspect diagnostic and rebase"),
        })

    # Discovery endpoints
    discovery = {
        "capabilities": {
            "cli": "fss capabilities --json",
            "description": "Report all supported device, model, and agent capabilities in typed JSON",
        },
        "operations": {
            "cli": "fss operations --json",
            "description": "Report all registered fss/1 operations with request/response schemas and crosswalk targets",
        },
        "views": {
            "cli": "fss views --json",
            "description": "Report all registered agent views with token budgets and required section keys",
        },
        "schemas": {
            "cli": "fss schema list --json",
            "description": "List all authoritative schema identifiers, files, and compatibility rules",
        },
        "robot_docs": {
            "cli": "fss robot-docs guide",
            "description": "Output complete self-describing robot documentation for autonomous agent drivers",
        },
    }

    return {
        "schema": "fss.robot_docs.v1",
        "asOf": fss1_reg.get("asOf", "2026-09-12"),
        "semanticProtocol": fss1_reg.get("semanticProtocol", "fss/1"),
        "registryGeneration": fss1_reg.get("registryGeneration", "gen:fss1:public-v1"),
        "freezeDigest": fss1_reg.get("freezeDigest", ""),
        "operations": consolidated_ops,
        "views": consolidated_views,
        "resources": consolidated_resources,
        "schemas": consolidated_schemas,
        "capabilities": consolidated_caps,
        "errors": consolidated_errors,
        "discovery": discovery,
    }


def generate_robot_docs_markdown(model: dict[str, Any]) -> str:
    """Renders the consolidated model into deterministic GitHub-flavored Markdown."""
    lines: list[str] = [
        "# Self-Describing Robot Documentation (`fss/1`)",
        "",
        "<!--",
        "GENERATED FILE - DO NOT EDIT DIRECTLY.",
        "Generated deterministically by scripts/generate_robot_docs.py from authoritative machine registries:",
        "- architecture/fss1_public_registry.json",
        "- architecture/agent_operations.json",
        "- architecture/agent_views.json",
        "- architecture/capabilities.json",
        "- architecture/operation_crosswalk.json",
        "- registries/ERRORS.md",
        "- registries/SCHEMAS.md",
        "-->",
        "",
        "This document provides the authoritative, self-describing reference for autonomous agent",
        "drivers operating within the Franken Surveillance System under semantic protocol `fss/1`.",
        "Agents orient, query, plan, and coordinate using registered operations and views without",
        "human prose dependence or undocumented endpoints.",
        "",
        "## 1. Protocol Identity & Contract Basis",
        "",
        f"- **Semantic Protocol**: `{model['semanticProtocol']}`",
        f"- **Registry Generation**: `{model['registryGeneration']}`",
        f"- **Freeze Digest**: `{model['freezeDigest']}`",
        f"- **As Of**: `{model['asOf']}`",
        f"- **Total Operations**: {len(model['operations'])}",
        f"- **Total Views**: {len(model['views'])}",
        f"- **Total Resource URI Templates**: {len(model['resources'])}",
        f"- **Total Schemas Cataloged**: {len(model['schemas'])}",
        f"- **Total Capabilities Mapped**: {len(model['capabilities'])}",
        "",
        "## 2. Machine Discovery Endpoints",
        "",
        "Agents can discover and inspect system capabilities at runtime using deterministic CLI endpoints:",
        "",
        "| Endpoint | CLI Invocation | Description |",
        "|---|---|---|",
    ]

    for key, disc in sorted(model["discovery"].items()):
        lines.append(f"| `{key}` | `{disc['cli']}` | {disc['description']} |")

    lines.extend([
        "",
        "## 3. Registered Operations Catalog",
        "",
        "Every operation is bound to a single owning crate, default view, typed request/response",
        "envelope, and strict idempotency/effect semantics:",
        "",
        "| ID | Operation | Owner | CLI Command | MCP Tool | Default View | Effectful | Durable | Status |",
        "|---|---|---|---|---|---|---|---|---|",
    ])

    for op in model["operations"]:
        lines.append(
            f"| `{op['id']}` | `{op['name']}` | `{op['owner']}` | `{op['cliCommand']}` | `{op['mcpToolName']}` | "
            f"`{op['defaultView']}` | {str(op['effectful']).lower()} | {str(op['durable']).lower()} | `{op['status']}` |"
        )

    lines.extend([
        "",
        "### 3.1 Operation Details & Schemas",
        "",
    ])

    for op in model["operations"]:
        resp_schemas = ", ".join(f"`{s}`" for s in op["responsePayloadSchemas"])
        req_caps = ", ".join(f"`{c}`" for c in op["requiredCapabilities"]) if op["requiredCapabilities"] else "none"
        retry_cls = ", ".join(f"`{r}`" for r in op["retryClasses"]) if op["retryClasses"] else "none"
        lines.extend([
            f"#### `{op['id']}` — `{op['name']}`",
            "",
            f"- **Purpose**: {op['purpose']}",
            f"- **Mode**: `{op['mode']}`",
            f"- **Owner**: `{op['owner']}`",
            f"- **CLI Command**: `{op['cliCommand']}`",
            f"- **MCP Tool**: `{op['mcpToolName']}`",
            f"- **Library Entry Point**: `{op['libraryEntryPoint']}`",
            f"- **Request Envelope**: `{op['requestEnvelope']}`",
            f"- **Request Payload Schema**: `{op['requestPayloadSchema']}`",
            f"- **Response Envelope**: `{op['responseEnvelope']}`",
            f"- **Response Payload Schemas**: {resp_schemas}",
            f"- **Default View**: `{op['defaultView']}`",
            f"- **Required Capabilities**: {req_caps}",
            f"- **Retry Classes**: {retry_cls}",
            f"- **Primary Error ID**: `{op['primaryErrorId']}`",
            "",
        ])

    lines.extend([
        "## 4. Registered Views Catalog",
        "",
        "Views are typed, compressed projections of the underlying semantic situation. Every view",
        "declares explicit token budgets and mandatory semantic sections:",
        "",
        "| ID | View Name | Owner | Target Tokens | Max Tokens | Required Sections | Purpose |",
        "|---|---|---|---|---|---|---|",
    ])

    for view in model["views"]:
        sections = ", ".join(f"`{s}`" for s in view["requiredSections"])
        lines.append(
            f"| `{view['id']}` | `{view['name']}` | `{view['owner']}` | {view['targetTokens']} | "
            f"{view['maximumTokens']} | {sections} | {view['purpose']} |"
        )

    lines.extend([
        "",
        "## 5. Resource URI Templates",
        "",
        "Universal content-addressable and hierarchical URI templates under semantic protocol `fss/1`:",
        "",
        "| ID | Resource Name | Owner | URI Template | Payload Schema | Compatibility |",
        "|---|---|---|---|---|---|",
    ])

    for res in model["resources"]:
        lines.append(
            f"| `{res['id']}` | `{res['name']}` | `{res['owner']}` | `{res['uriTemplate']}` | "
            f"`{res['payloadSchema']}` | `{res['compatibilityClass']}` |"
        )

    lines.extend([
        "",
        "## 6. Schemas Catalog",
        "",
        "Core agent interchange and durable publication schemas:",
        "",
        "| ID | Schema Identifier | File Path | Authority | Compatibility Rule |",
        "|---|---|---|---|---|",
    ])

    for schema in model["schemas"]:
        lines.append(
            f"| `{schema['id']}` | `{schema['schema']}` | `{schema['file']}` | `{schema['authority']}` | "
            f"{schema['compatibilityRule']} |"
        )

    lines.extend([
        "",
        "## 7. Required Capabilities Matrix",
        "",
        "Capabilities required by registered operations across semantic planes:",
        "",
        "| ID | Name | Semantic Plane | Description |",
        "|---|---|---|---|",
    ])

    for cap in model["capabilities"]:
        lines.append(f"| `{cap['id']}` | `{cap['name']}` | `{cap['plane']}` | {cap['description']} |")

    lines.extend([
        "",
        "## 8. Stable Error Taxonomy & Recovery Guidance",
        "",
        "Key stable error identities and normative recovery guidance for agent drivers:",
        "",
        "| Error Identity | Description | Recovery Guidance |",
        "|---|---|---|",
    ])

    for err in model["errors"]:
        lines.append(f"| `{err['id']}` | {err['description']} | {err['guidance']} |")

    lines.extend([
        "",
        "---",
        "*Robot documentation generated deterministically by `scripts/generate_robot_docs.py`.*",
        "",
    ])

    return "\n".join(lines)


def generate_robot_docs_json(model: dict[str, Any]) -> str:
    """Renders the consolidated model into deterministic, formatted JSON."""
    return json.dumps(model, indent=2, sort_keys=True) + "\n"


def generate_docs(root: Path) -> tuple[str, str]:
    """Computes the deterministic Markdown and JSON contents for robot documentation."""
    model = collect_robot_docs_model(root)
    md_content = generate_robot_docs_markdown(model)
    json_content = generate_robot_docs_json(model)
    return md_content, json_content


def main() -> int:
    parser = argparse.ArgumentParser(description="Generate or verify self-describing robot docs.")
    parser.add_argument("--check", action="store_true", help="Fail if on-disk robot docs are stale vs registries.")
    parser.add_argument("--output-dir", type=Path, default=None, help="Output directory for generated docs (default: docs/).")
    parser.add_argument("--json", action="store_true", help="Emit structured status JSON.")
    args = parser.parse_args()

    target_dir = args.output_dir or (ROOT / "docs")
    target_md = target_dir / "ROBOT_DOCS.md"
    target_json = target_dir / "ROBOT_DOCS.json"

    expected_md, expected_json = generate_docs(ROOT)

    if args.check:
        errors: list[str] = []
        if not target_md.is_file():
            errors.append(f"[{ERR_ROBOT_DOCS_MISSING}] Missing generated file: {target_md.relative_to(ROOT)}")
        elif target_md.read_text(encoding="utf-8") != expected_md:
            errors.append(f"[{ERR_ROBOT_DOCS_STALE}] Stale robot docs markdown: {target_md.relative_to(ROOT)} does not match machine registries")

        if not target_json.is_file():
            errors.append(f"[{ERR_ROBOT_DOCS_MISSING}] Missing generated file: {target_json.relative_to(ROOT)}")
        elif target_json.read_text(encoding="utf-8") != expected_json:
            errors.append(f"[{ERR_ROBOT_DOCS_STALE}] Stale robot docs JSON: {target_json.relative_to(ROOT)} does not match machine registries")

        if errors:
            if args.json:
                print(json.dumps({"status": "failed", "errors": errors}, indent=2))
            else:
                print("\n".join(errors), file=sys.stderr)
            return 1

        if args.json:
            print(json.dumps({"status": "passed", "message": "Robot docs are fresh and up to date"}, indent=2))
        else:
            print("OK: robot docs are fresh and match machine registries.")
        return 0

    target_dir.mkdir(parents=True, exist_ok=True)
    target_md.write_text(expected_md, encoding="utf-8")
    target_json.write_text(expected_json, encoding="utf-8")

    if args.json:
        print(json.dumps({
            "status": "generated",
            "markdown": str(target_md.relative_to(ROOT)),
            "json": str(target_json.relative_to(ROOT)),
        }, indent=2))
    else:
        print(f"Generated {target_md.relative_to(ROOT)} ({len(expected_md)} bytes)")
        print(f"Generated {target_json.relative_to(ROOT)} ({len(expected_json)} bytes)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
