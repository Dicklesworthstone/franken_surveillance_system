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
- Fail-closed validation: unresolved references, duplicate keys, and unauthorized entries
  raise typed diagnostic error codes.
- Secret and private path scanning: detects and rejects credentials and absolute local paths.
- Markdown table escaping: prevents header injection and broken table delimiters.
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
ERR_ROBOT_DOCS_UNREGISTERED = "ERR-ROBOT-DOCS-UNREGISTERED-001"
ERR_ROBOT_DOCS_SECRET_DETECTED = "ERR-ROBOT-DOCS-SECRET-DETECTED-001"


class RobotDocsError(Exception):
    """Fail-closed error raised during robot docs model collection or generation."""

    def __init__(self, code: str, message: str, target: str = ""):
        super().__init__(message)
        self.code = code
        self.message = message
        self.target = target


SECRET_PATTERNS = [
    re.compile(r"(?i)\b(?:token|api[_-]?key|password|secret|bearer)\s*[:=]\s*[A-Za-z0-9_\-\.]{8,}"),
    re.compile(r"\bghp_[A-Za-z0-9]{20,}\b"),
    re.compile(r"\bgithub_pat_[A-Za-z0-9]{20,}\b"),
    re.compile(r"\b(?:gho|ghu|ghs|ghr)_[A-Za-z0-9]{20,}\b"),
    re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----"),
    re.compile(r"\.ssh/(?:id_rsa|id_ed25519|id_ecdsa|id_dsa)"),
    re.compile(r"/home/[a-zA-Z0-9._-]+(?:/[a-zA-Z0-9._-]+)*"),
    re.compile(r"~/[a-zA-Z0-9._-]+"),
]


def scan_for_secrets(value: Any, context: str) -> None:
    """Scans string values for potential secrets or local filesystem paths."""
    if isinstance(value, str):
        for pat in SECRET_PATTERNS:
            if pat.search(value):
                raise RobotDocsError(
                    ERR_ROBOT_DOCS_SECRET_DETECTED,
                    f"Suspected secret or local home path detected in {context} matching {pat.pattern}",
                    target=context,
                )
    elif isinstance(value, dict):
        for k, v in value.items():
            scan_for_secrets(k, f"{context}.key({k})")
            scan_for_secrets(v, f"{context}.{k}")
    elif isinstance(value, list):
        for idx, item in enumerate(value):
            scan_for_secrets(item, f"{context}[{idx}]")


def _duplicate_key_detector(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    """JSON object_pairs_hook that refuses duplicate keys."""
    res: dict[str, Any] = {}
    for key, val in pairs:
        if key in res:
            raise ValueError(f"Duplicate JSON key detected: {key!r}")
        res[key] = val
    return res


def load_json(path: Path) -> dict[str, Any]:
    """Loads a JSON file with utf-8 encoding and strict duplicate-key rejection."""
    if not path.is_file():
        raise FileNotFoundError(f"Missing required JSON file: {path}")
    text = path.read_text(encoding="utf-8")
    try:
        return json.loads(text, object_pairs_hook=_duplicate_key_detector)
    except Exception as exc:
        raise ValueError(f"Failed to parse JSON in {path}: {exc}") from exc


def escape_markdown_cell(val: Any) -> str:
    """Sanitizes text for safe inclusion in Markdown table cells."""
    if val is None:
        return ""
    s = str(val).replace("\r\n", " ").replace("\n", " ").replace("\r", " ")
    return s.replace("|", "\\|").strip()


def escape_markdown_inline(val: Any) -> str:
    """Sanitizes text for safe inclusion inline within backticks or headings."""
    if val is None:
        return ""
    s = str(val).replace("\r\n", " ").replace("\n", " ").replace("\r", " ")
    return s.replace("`", "'").strip()


def escape_markdown_text(val: Any) -> str:
    """Sanitizes text for safe inclusion in Markdown body blocks without heading injection."""
    if val is None:
        return ""
    s = str(val).replace("\r\n", "\n").replace("\r", "\n")
    # Disallow injecting top-level or secondary headings
    s = re.sub(r"(?m)^#{1,6}\s+", "\\# ", s)
    return s.strip()


def parse_errors_registry(errors_md_path: Path) -> dict[str, dict[str, str]]:
    """Parses registries/ERRORS.md into an error_id -> {id, description, guidance} dict."""
    if not errors_md_path.is_file():
        raise FileNotFoundError(f"Missing errors registry: {errors_md_path}")
    errors: dict[str, dict[str, str]] = {}
    for line in errors_md_path.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if line.startswith("| `ERR-"):
            parts = [p.strip() for p in line.split("|")[1:-1]]
            if len(parts) >= 2:
                err_id = parts[0].replace("`", "")
                if err_id in errors:
                    raise RobotDocsError(
                        ERR_ROBOT_DOCS_CORRUPT,
                        f"Duplicate error ID detected in ERRORS.md: {err_id}",
                        target="ERRORS.md",
                    )
                description = parts[1]
                guidance = parts[2] if len(parts) > 2 else ""
                scan_for_secrets(description, f"ERRORS.md:{err_id}:description")
                scan_for_secrets(guidance, f"ERRORS.md:{err_id}:guidance")
                errors[err_id] = {
                    "id": err_id,
                    "description": description,
                    "guidance": guidance,
                }
    return errors


def parse_schemas_registry(schemas_md_path: Path) -> dict[str, dict[str, str]]:
    """Parses registries/SCHEMAS.md into schema_name -> {id, schema, file, authority, compatibilityRule}."""
    if not schemas_md_path.is_file():
        raise FileNotFoundError(f"Missing schemas registry: {schemas_md_path}")
    schemas: dict[str, dict[str, str]] = {}
    seen_ids: set[str] = set()
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
                if s_id in seen_ids:
                    raise RobotDocsError(
                        ERR_ROBOT_DOCS_CORRUPT,
                        f"Duplicate schema ID detected in SCHEMAS.md: {s_id}",
                        target="SCHEMAS.md",
                    )
                seen_ids.add(s_id)
                if s_name in schemas:
                    raise RobotDocsError(
                        ERR_ROBOT_DOCS_CORRUPT,
                        f"Duplicate schema name detected in SCHEMAS.md: {s_name}",
                        target="SCHEMAS.md",
                    )
                scan_for_secrets(s_file, f"SCHEMAS.md:{s_name}:file")
                scan_for_secrets(s_auth, f"SCHEMAS.md:{s_name}:authority")
                scan_for_secrets(s_comp, f"SCHEMAS.md:{s_name}:compatibilityRule")
                schemas[s_name] = {
                    "id": s_id,
                    "schema": s_name,
                    "file": s_file,
                    "authority": s_auth,
                    "compatibilityRule": s_comp,
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

    # Scan raw registry structures for secrets
    scan_for_secrets(fss1_reg, "architecture/fss1_public_registry.json")
    scan_for_secrets(agent_ops_reg, "architecture/agent_operations.json")
    scan_for_secrets(agent_views_reg, "architecture/agent_views.json")
    scan_for_secrets(caps_reg, "architecture/capabilities.json")
    scan_for_secrets(crosswalk_reg, "architecture/operation_crosswalk.json")

    # Verify duplicate IDs within lists
    seen_agent_ops: set[str] = set()
    for op in agent_ops_reg.get("operations", []):
        op_id = op["id"]
        if op_id in seen_agent_ops:
            raise RobotDocsError(
                ERR_ROBOT_DOCS_CORRUPT,
                f"Duplicate operation ID in agent_operations.json: {op_id}",
                target="agent_operations.json",
            )
        seen_agent_ops.add(op_id)

    seen_fss1_ops: set[str] = set()
    for op in fss1_reg.get("operations", []):
        op_id = op["id"]
        if op_id in seen_fss1_ops:
            raise RobotDocsError(
                ERR_ROBOT_DOCS_CORRUPT,
                f"Duplicate operation ID in fss1_public_registry.json: {op_id}",
                target="fss1_public_registry.json",
            )
        seen_fss1_ops.add(op_id)

    seen_cw_ops: set[str] = set()
    for entry in crosswalk_reg.get("crosswalk", []):
        op_id = entry["operation_id"]
        if op_id in seen_cw_ops:
            raise RobotDocsError(
                ERR_ROBOT_DOCS_CORRUPT,
                f"Duplicate operation ID in operation_crosswalk.json: {op_id}",
                target="operation_crosswalk.json",
            )
        seen_cw_ops.add(op_id)

    # Cross-registry operation consistency check
    if seen_agent_ops != seen_fss1_ops or seen_agent_ops != seen_cw_ops:
        mismatch_fss1 = sorted(seen_agent_ops ^ seen_fss1_ops)
        mismatch_cw = sorted(seen_agent_ops ^ seen_cw_ops)
        raise RobotDocsError(
            ERR_ROBOT_DOCS_DRIFT,
            f"Cross-registry operation mismatch: differences with fss1: {mismatch_fss1}, with crosswalk: {mismatch_cw}",
            target="operations_crosswalk",
        )

    seen_views: set[str] = set()
    for v in agent_views_reg.get("views", []):
        v_id = v["id"]
        if v_id in seen_views:
            raise RobotDocsError(
                ERR_ROBOT_DOCS_CORRUPT,
                f"Duplicate view ID in agent_views.json: {v_id}",
                target="agent_views.json",
            )
        seen_views.add(v_id)

    seen_resources: set[str] = set()
    for r in fss1_reg.get("resources", []):
        r_id = r["id"]
        if r_id in seen_resources:
            raise RobotDocsError(
                ERR_ROBOT_DOCS_CORRUPT,
                f"Duplicate resource ID in fss1_public_registry.json: {r_id}",
                target="fss1_public_registry.json",
            )
        seen_resources.add(r_id)

    seen_caps: set[str] = set()
    caps_by_id: dict[str, dict[str, Any]] = {}
    for c in caps_reg.get("capabilities", []):
        c_id = c["id"]
        if c_id in seen_caps:
            raise RobotDocsError(
                ERR_ROBOT_DOCS_CORRUPT,
                f"Duplicate capability ID in capabilities.json: {c_id}",
                target="capabilities.json",
            )
        seen_caps.add(c_id)
        caps_by_id[c_id] = c

    # Index crosswalk by operation_id
    cw_by_id = {entry["operation_id"]: entry for entry in crosswalk_reg.get("crosswalk", [])}
    # Index fss1 operations by id
    fss1_ops_by_id = {op["id"]: op for op in fss1_reg.get("operations", [])}

    # Consolidated operations (sorted deterministically by ID)
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

        # Validate view reference
        default_view = raw_op["defaultView"]
        if default_view not in seen_views:
            raise RobotDocsError(
                ERR_ROBOT_DOCS_UNREGISTERED,
                f"Operation {op_id} references unregistered view: {default_view}",
                target=f"operations.{op_id}.defaultView",
            )

        # Validate envelope and payload schema references
        req_env = raw_op.get("inputSchema", "fss.agent_request_envelope.v1")
        resp_env = raw_op.get("outputSchema", "fss.agent_response_envelope.v1")
        req_payload = raw_op.get("requestPayloadSchema", "")
        resp_payloads = raw_op.get("responsePayloadSchemas", [])

        for s in [req_env, resp_env, req_payload]:
            if s and s not in schemas_map:
                raise RobotDocsError(
                    ERR_ROBOT_DOCS_UNREGISTERED,
                    f"Operation {op_id} references unregistered schema: {s}",
                    target=f"operations.{op_id}.schemas",
                )
        for s in resp_payloads:
            if s not in schemas_map:
                raise RobotDocsError(
                    ERR_ROBOT_DOCS_UNREGISTERED,
                    f"Operation {op_id} references unregistered response schema: {s}",
                    target=f"operations.{op_id}.responsePayloadSchemas",
                )

        # Validate capability references
        req_caps = raw_op.get("requiredCapabilities", [])
        for cap_id in req_caps:
            if cap_id not in caps_by_id:
                raise RobotDocsError(
                    ERR_ROBOT_DOCS_UNREGISTERED,
                    f"Operation {op_id} references unregistered capability: {cap_id}",
                    target=f"operations.{op_id}.requiredCapabilities",
                )
            cap_status = caps_by_id[cap_id].get("status")
            if cap_status in ("tombstone", "tombstoned", "superseded"):
                raise RobotDocsError(
                    ERR_ROBOT_DOCS_UNREGISTERED,
                    f"Operation {op_id} references tombstoned capability: {cap_id}",
                    target=f"operations.{op_id}.requiredCapabilities",
                )

        # Validate error references
        if primary_err and primary_err not in errors_map:
            raise RobotDocsError(
                ERR_ROBOT_DOCS_UNREGISTERED,
                f"Operation {op_id} references unregistered primary error: {primary_err}",
                target=f"operations.{op_id}.primaryErrorId",
            )
        for err_id in error_ids:
            if err_id not in errors_map:
                raise RobotDocsError(
                    ERR_ROBOT_DOCS_UNREGISTERED,
                    f"Operation {op_id} references unregistered error identity: {err_id}",
                    target=f"operations.{op_id}.errorIdentities",
                )

        consolidated_ops.append({
            "id": op_id,
            "name": raw_op["name"],
            "purpose": raw_op["purpose"],
            "mode": raw_op["mode"],
            "owner": raw_op["owner"],
            "defaultView": default_view,
            "effectful": raw_op["effectful"],
            "durable": raw_op["durable"],
            "cliCommand": cli_cmd,
            "mcpToolName": mcp_tool,
            "libraryEntryPoint": lib_entry,
            "requestEnvelope": req_env,
            "responseEnvelope": resp_env,
            "requestPayloadSchema": req_payload,
            "responsePayloadSchemas": resp_payloads,
            "requiredCapabilities": sorted(req_caps),
            "retryClasses": raw_op.get("retryClasses", []),
            "primaryErrorId": primary_err,
            "errorIdentities": error_ids,
            "exitIdentities": exit_ids,
            "gate": raw_op.get("gate", "QL-AGENT-001"),
            "status": raw_op.get("status", "specified"),
        })

    # Consolidated views (sorted deterministically by ID)
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

    # Consolidated resources (sorted deterministically by ID)
    consolidated_resources: list[dict[str, Any]] = []
    for raw_res in sorted(fss1_reg.get("resources", []), key=lambda r: r["id"]):
        res_id = raw_res["id"]
        res_req_env = raw_res.get("requestEnvelope", "fss.agent_request_envelope.v1")
        res_resp_env = raw_res.get("responseEnvelope", "fss.agent_response_envelope.v1")
        res_payload = raw_res.get("payloadSchema", "")

        for s in [res_req_env, res_resp_env, res_payload]:
            if s and s not in schemas_map:
                raise RobotDocsError(
                    ERR_ROBOT_DOCS_UNREGISTERED,
                    f"Resource {res_id} references unregistered schema: {s}",
                    target=f"resources.{res_id}.schemas",
                )

        consolidated_resources.append({
            "id": res_id,
            "name": raw_res["name"],
            "owner": raw_res["owner"],
            "uriTemplate": raw_res["uriTemplate"],
            "requestEnvelope": res_req_env,
            "responseEnvelope": res_resp_env,
            "payloadSchema": res_payload,
            "compatibilityClass": raw_res.get("compatibilityClass", "backward_compatible"),
            "status": raw_res.get("status", "specified"),
        })

    # Complete Schemas Catalog: all authoritative schemas registered in registries/SCHEMAS.md
    consolidated_schemas: list[dict[str, Any]] = []
    for s_name in sorted(schemas_map.keys()):
        entry = schemas_map[s_name]
        consolidated_schemas.append({
            "id": entry["id"],
            "schema": s_name,
            "file": entry["file"],
            "authority": entry["authority"],
            "compatibilityRule": entry["compatibilityRule"],
        })

    # Required capabilities for operations: read real fields from capabilities.json
    required_cap_ids: set[str] = set()
    for op in consolidated_ops:
        for cap_id in op["requiredCapabilities"]:
            required_cap_ids.add(cap_id)

    consolidated_caps: list[dict[str, Any]] = []
    for cap_id in sorted(required_cap_ids):
        cap = caps_by_id[cap_id]
        consolidated_caps.append({
            "id": cap_id,
            "capability": cap["capability"],
            "scope": cap["scope"],
            "plane": cap["plane"],
            "defaultRole": cap["defaultRole"],
            "denialReason": cap.get("denialReason", ""),
            "safeAlternative": cap.get("safeAlternative", ""),
            "generation": cap.get("generation", ""),
        })

    # Complete Errors Catalog: all authoritative errors registered in registries/ERRORS.md
    consolidated_errors: list[dict[str, Any]] = []
    for err_id in sorted(errors_map.keys()):
        err = errors_map[err_id]
        consolidated_errors.append({
            "id": err_id,
            "description": err["description"],
            "guidance": err["guidance"],
        })

    # Real Discovery Endpoints implemented in the fss CLI
    discovery = {
        "capabilities": {
            "cli": "fss capabilities --json",
            "description": "Report all supported device, model, and agent capabilities in typed JSON",
        },
        "doctor": {
            "cli": "fss doctor --json",
            "description": "Report system diagnostic doctor results and environment health in typed JSON",
        },
        "status": {
            "cli": "fss status --json",
            "description": "Report overall system runtime and subsystem status in typed JSON",
        },
        "negative_evidence": {
            "cli": "fss negative-evidence list --json",
            "description": "Inspect and verify negative evidence ledger and coverage witnesses",
        },
    }

    as_of = fss1_reg.get("asOf")
    if not as_of:
        raise RobotDocsError(
            ERR_ROBOT_DOCS_CORRUPT,
            "Missing mandatory asOf field in architecture/fss1_public_registry.json",
            target="fss1_public_registry.json:asOf",
        )

    return {
        "schema": "fss.robot_docs.v1",
        "asOf": as_of,
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
        f"- **Semantic Protocol**: `{escape_markdown_inline(model['semanticProtocol'])}`",
        f"- **Registry Generation**: `{escape_markdown_inline(model['registryGeneration'])}`",
        f"- **Freeze Digest**: `{escape_markdown_inline(model['freezeDigest'])}`",
        f"- **As Of**: `{escape_markdown_inline(model['asOf'])}`",
        f"- **Total Operations**: {len(model['operations'])}",
        f"- **Total Views**: {len(model['views'])}",
        f"- **Total Resource URI Templates**: {len(model['resources'])}",
        f"- **Total Schemas Cataloged**: {len(model['schemas'])}",
        f"- **Total Capabilities Mapped**: {len(model['capabilities'])}",
        f"- **Total Error Identities Cataloged**: {len(model['errors'])}",
        "",
        "## 2. Machine Discovery Endpoints",
        "",
        "Agents can discover and inspect system capabilities at runtime using deterministic CLI endpoints:",
        "",
        "| Endpoint | CLI Invocation | Description |",
        "|---|---|---|",
    ]

    for key, disc in sorted(model["discovery"].items()):
        lines.append(
            f"| `{escape_markdown_cell(key)}` | `{escape_markdown_cell(disc['cli'])}` | "
            f"{escape_markdown_cell(disc['description'])} |"
        )

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
            f"| `{escape_markdown_cell(op['id'])}` | `{escape_markdown_cell(op['name'])}` | "
            f"`{escape_markdown_cell(op['owner'])}` | `{escape_markdown_cell(op['cliCommand'])}` | "
            f"`{escape_markdown_cell(op['mcpToolName'])}` | `{escape_markdown_cell(op['defaultView'])}` | "
            f"{str(op['effectful']).lower()} | {str(op['durable']).lower()} | `{escape_markdown_cell(op['status'])}` |"
        )

    lines.extend([
        "",
        "### 3.1 Operation Details & Schemas",
        "",
    ])

    for op in model["operations"]:
        resp_schemas = ", ".join(f"`{escape_markdown_inline(s)}`" for s in op["responsePayloadSchemas"])
        req_caps = ", ".join(f"`{escape_markdown_inline(c)}`" for c in op["requiredCapabilities"]) if op["requiredCapabilities"] else "none"
        retry_cls = ", ".join(f"`{escape_markdown_inline(r)}`" for r in op["retryClasses"]) if op["retryClasses"] else "none"
        err_ids = ", ".join(f"`{escape_markdown_inline(e)}`" for e in op["errorIdentities"]) if op["errorIdentities"] else "none"
        lines.extend([
            f"#### `{escape_markdown_inline(op['id'])}` — `{escape_markdown_inline(op['name'])}`",
            "",
            f"- **Purpose**: {escape_markdown_text(op['purpose'])}",
            f"- **Mode**: `{escape_markdown_inline(op['mode'])}`",
            f"- **Owner**: `{escape_markdown_inline(op['owner'])}`",
            f"- **CLI Command**: `{escape_markdown_inline(op['cliCommand'])}`",
            f"- **MCP Tool**: `{escape_markdown_inline(op['mcpToolName'])}`",
            f"- **Library Entry Point**: `{escape_markdown_inline(op['libraryEntryPoint'])}`",
            f"- **Request Envelope**: `{escape_markdown_inline(op['requestEnvelope'])}`",
            f"- **Request Payload Schema**: `{escape_markdown_inline(op['requestPayloadSchema'])}`",
            f"- **Response Envelope**: `{escape_markdown_inline(op['responseEnvelope'])}`",
            f"- **Response Payload Schemas**: {resp_schemas}",
            f"- **Default View**: `{escape_markdown_inline(op['defaultView'])}`",
            f"- **Required Capabilities**: {req_caps}",
            f"- **Retry Classes**: {retry_cls}",
            f"- **Primary Error ID**: `{escape_markdown_inline(op['primaryErrorId'])}`",
            f"- **Error Identities**: {err_ids}",
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
        sections = ", ".join(f"`{escape_markdown_cell(s)}`" for s in view["requiredSections"])
        lines.append(
            f"| `{escape_markdown_cell(view['id'])}` | `{escape_markdown_cell(view['name'])}` | "
            f"`{escape_markdown_cell(view['owner'])}` | {view['targetTokens']} | "
            f"{view['maximumTokens']} | {sections} | {escape_markdown_cell(view['purpose'])} |"
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
            f"| `{escape_markdown_cell(res['id'])}` | `{escape_markdown_cell(res['name'])}` | "
            f"`{escape_markdown_cell(res['owner'])}` | `{escape_markdown_cell(res['uriTemplate'])}` | "
            f"`{escape_markdown_cell(res['payloadSchema'])}` | `{escape_markdown_cell(res['compatibilityClass'])}` |"
        )

    lines.extend([
        "",
        "## 6. Schemas Catalog",
        "",
        "All authoritative schemas cataloged from `registries/SCHEMAS.md`:",
        "",
        "| ID | Schema Identifier | File Path | Authority | Compatibility Rule |",
        "|---|---|---|---|---|",
    ])

    for schema in model["schemas"]:
        lines.append(
            f"| `{escape_markdown_cell(schema['id'])}` | `{escape_markdown_cell(schema['schema'])}` | "
            f"`{escape_markdown_cell(schema['file'])}` | `{escape_markdown_cell(schema['authority'])}` | "
            f"{escape_markdown_cell(schema['compatibilityRule'])} |"
        )

    lines.extend([
        "",
        "## 7. Required Capabilities Matrix",
        "",
        "Real capability specifications required by registered operations from `architecture/capabilities.json`:",
        "",
        "| ID | Capability | Scope | Semantic Plane | Default Role |",
        "|---|---|---|---|---|",
    ])

    for cap in model["capabilities"]:
        lines.append(
            f"| `{escape_markdown_cell(cap['id'])}` | {escape_markdown_cell(cap['capability'])} | "
            f"`{escape_markdown_cell(cap['scope'])}` | `{escape_markdown_cell(cap['plane'])}` | "
            f"{escape_markdown_cell(cap['defaultRole'])} |"
        )

    lines.extend([
        "",
        "## 8. Stable Error Taxonomy & Recovery Guidance",
        "",
        "All stable error identities and normative recovery guidance cataloged from `registries/ERRORS.md`:",
        "",
        "| Error Identity | Description | Recovery Guidance |",
        "|---|---|---|",
    ])

    for err in model["errors"]:
        lines.append(
            f"| `{escape_markdown_cell(err['id'])}` | {escape_markdown_cell(err['description'])} | "
            f"{escape_markdown_cell(err['guidance'])} |"
        )

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

    def format_path(p: Path) -> str:
        return str(p.relative_to(ROOT)) if p.is_relative_to(ROOT) else str(p)

    try:
        expected_md, expected_json = generate_docs(ROOT)
    except RobotDocsError as exc:
        err_msg = f"[{exc.code}] {exc.target}: {exc.message}"
        if args.json:
            print(json.dumps({"status": "failed", "errors": [err_msg], "code": exc.code}, indent=2))
        else:
            print(err_msg, file=sys.stderr)
        return 1
    except FileNotFoundError as exc:
        err_msg = f"[{ERR_ROBOT_DOCS_MISSING}] {exc}"
        if args.json:
            print(json.dumps({"status": "failed", "errors": [err_msg], "code": ERR_ROBOT_DOCS_MISSING}, indent=2))
        else:
            print(err_msg, file=sys.stderr)
        return 1
    except (ValueError, KeyError) as exc:
        err_msg = f"[{ERR_ROBOT_DOCS_CORRUPT}] {exc}"
        if args.json:
            print(json.dumps({"status": "failed", "errors": [err_msg], "code": ERR_ROBOT_DOCS_CORRUPT}, indent=2))
        else:
            print(err_msg, file=sys.stderr)
        return 1

    if args.check:
        errors: list[str] = []
        if not target_md.is_file():
            errors.append(f"[{ERR_ROBOT_DOCS_MISSING}] Missing generated file: {format_path(target_md)}")
        elif target_md.read_text(encoding="utf-8") != expected_md:
            errors.append(f"[{ERR_ROBOT_DOCS_STALE}] Stale robot docs markdown: {format_path(target_md)} does not match machine registries")

        if not target_json.is_file():
            errors.append(f"[{ERR_ROBOT_DOCS_MISSING}] Missing generated file: {format_path(target_json)}")
        elif target_json.read_text(encoding="utf-8") != expected_json:
            errors.append(f"[{ERR_ROBOT_DOCS_STALE}] Stale robot docs JSON: {format_path(target_json)} does not match machine registries")

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

    try:
        target_dir.mkdir(parents=True, exist_ok=True)
        target_md.write_text(expected_md, encoding="utf-8")
        target_json.write_text(expected_json, encoding="utf-8")
    except Exception as exc:
        err_msg = f"[{ERR_ROBOT_DOCS_CORRUPT}] Failed writing output files to {target_dir}: {exc}"
        if args.json:
            print(json.dumps({"status": "failed", "errors": [err_msg]}, indent=2))
        else:
            print(err_msg, file=sys.stderr)
        return 1

    if args.json:
        print(json.dumps({
            "status": "generated",
            "markdown": format_path(target_md),
            "json": format_path(target_json),
        }, indent=2))
    else:
        print(f"Generated {format_path(target_md)} ({len(expected_md)} bytes)")
        print(f"Generated {format_path(target_json)} ({len(expected_json)} bytes)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
