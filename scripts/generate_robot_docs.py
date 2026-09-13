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
- architecture/release_qualification.json
- crates/fss-cli/src/fss_cmd.rs

Guarantees:
- Zero hand-written drift: all operations, views, resources, schemas, capabilities,
  and discovery endpoints are derived from machine registries and source definitions.
- Strict determinism: canonical sorting, normalized whitespace, byte-level stability.
- Fail-closed validation: unresolved references, duplicate keys, unauthorized entries,
  type mismatches, cross-registry conflicts, and tombstones raise typed diagnostic error codes.
- Secret and private path scanning: detects and rejects credentials and absolute local paths.
- Markdown table and HTML escaping: prevents header injection, script injection, and broken table delimiters.
"""
from __future__ import annotations

import argparse
import html
import json
import math
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

VALID_RECOVERY_CLASSES = frozenset({
    "never_unchanged",
    "safe_read_retry",
    "refresh_and_retry",
    "rebase_required",
    "backoff",
    "reconciliation_required",
    "operator_action_required",
    "resume_from_continuation",
})


class RobotDocsError(Exception):
    """Fail-closed error raised during robot docs model collection or generation."""

    def __init__(self, code: str, message: str, target: str = ""):
        super().__init__(message)
        self.code = code
        self.message = message
        self.target = target


SECRET_PATTERNS = [
    re.compile(r"(?i)\bAuthorization:\s*Bearer\s+[A-Za-z0-9._~+/-]+"),
    re.compile(r"\bsk-proj-[A-Za-z0-9_-]{10,}\b"),
    re.compile(r"\bAKIA[0-9A-Z]{16}\b"),
    re.compile(r"\bxoxb-[0-9A-Za-z-]{10,}\b"),
    re.compile(r"\beyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\b"),
    re.compile(r"(?i)\bpassword\s+is\s+[^\s]+"),
    re.compile(r"""(?i)\b(?:password|api[_-]?key|secret)\s*[:=]\s*["']?[^"'\s]{4,}"""),
    re.compile(r"""(?i)\btoken\s*[:=]\s*["']?[^"'\s]{8,}"""),
    re.compile(r"\bghp_[A-Za-z0-9]{20,}\b"),
    re.compile(r"\bgithub_pat_[A-Za-z0-9_]{20,}\b"),
    re.compile(r"\b(?:gho|ghu|ghs|ghr)_[A-Za-z0-9]{20,}\b"),
    re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----"),
    re.compile(r"\.ssh/(?:id_rsa|id_ed25519|id_ecdsa|id_dsa)"),
    re.compile(r"/data/projects/[a-zA-Z0-9._-]+"),
    re.compile(r"/home/[a-zA-Z0-9._-]+"),
    re.compile(r"/Users/[a-zA-Z0-9._-]+"),
    re.compile(r"/root/[a-zA-Z0-9._-]+"),
    re.compile(r"/root/\.netrc"),
    re.compile(r"""(?i)[a-z]:\\Users\\[a-zA-Z0-9._-]+"""),
    re.compile(r"""(?i)[a-z]:/Users/[a-zA-Z0-9._-]+"""),
    re.compile(r"~/[a-zA-Z0-9._-]+"),
]


def scan_for_secrets(value: Any, context: str) -> None:
    """Scans string values for potential secrets or local filesystem paths."""
    if isinstance(value, str):
        for pat in SECRET_PATTERNS:
            if pat.search(value):
                raise RobotDocsError(
                    ERR_ROBOT_DOCS_SECRET_DETECTED,
                    f"Suspected secret or local path detected in {context} matching {pat.pattern}",
                    target=context,
                )
    elif isinstance(value, dict):
        for k, v in value.items():
            scan_for_secrets(k, f"{context}.key({k})")
            scan_for_secrets(v, f"{context}.{k}")
    elif isinstance(value, list):
        for idx, item in enumerate(value):
            scan_for_secrets(item, f"{context}[{idx}]")


def check_no_nan_inf(value: Any, context: str) -> None:
    """Refuses float NaN, Inf, -Inf in loaded structures."""
    if isinstance(value, float):
        if math.isnan(value) or math.isinf(value):
            raise RobotDocsError(
                ERR_ROBOT_DOCS_CORRUPT,
                f"Disallowed NaN or Infinity in {context}",
                target=context,
            )
    elif isinstance(value, dict):
        for k, v in value.items():
            check_no_nan_inf(v, f"{context}.{k}")
    elif isinstance(value, list):
        for idx, item in enumerate(value):
            check_no_nan_inf(item, f"{context}[{idx}]")


def _duplicate_key_detector(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    """JSON object_pairs_hook that refuses duplicate keys."""
    res: dict[str, Any] = {}
    for key, val in pairs:
        if key in res:
            raise ValueError(f"Duplicate JSON key detected: {key!r}")
        res[key] = val
    return res


def _fail_on_nan_constant(val: str) -> None:
    raise ValueError(f"Disallowed JSON constant: {val}")


def load_json(path: Path) -> dict[str, Any]:
    """Loads a JSON file with utf-8 encoding, duplicate-key rejection, and NaN refusal."""
    if not path.is_file():
        raise FileNotFoundError(f"Missing required JSON file: {path}")
    text = path.read_text(encoding="utf-8")
    try:
        doc = json.loads(
            text,
            object_pairs_hook=_duplicate_key_detector,
            parse_constant=_fail_on_nan_constant,
        )
    except Exception as exc:
        raise ValueError(f"Failed to parse JSON in {path}: {exc}") from exc
    if not isinstance(doc, dict):
        raise RobotDocsError(
            ERR_ROBOT_DOCS_CORRUPT,
            f"Top-level JSON in {path.name} must be a dictionary, got {type(doc).__name__}",
            target=path.name,
        )
    check_no_nan_inf(doc, path.name)
    return doc


def escape_markdown_cell(val: Any) -> str:
    """Sanitizes text for safe inclusion in Markdown table cells without HTML/script injection."""
    if val is None:
        return ""
    s = str(val).replace("\r\n", " ").replace("\n", " ").replace("\r", " ")
    # Escape HTML tags and special entities
    s = html.escape(s, quote=False)
    # Neutralize javascript: links
    s = re.sub(r"(?i)javascript\s*:", "javascript&#58;", s)
    # Escape pipes
    s = s.replace("|", "\\|")
    return s.strip()


def escape_markdown_inline(val: Any) -> str:
    """Sanitizes text for safe inclusion inline within code backticks."""
    if val is None:
        return ""
    s = str(val).replace("\r\n", " ").replace("\n", " ").replace("\r", " ")
    s = html.escape(s, quote=False)
    s = re.sub(r"(?i)javascript\s*:", "javascript&#58;", s)
    # Prevent backtick breakout of code spans: replace ` with '
    return s.replace("`", "'").strip()


def escape_markdown_text(val: Any) -> str:
    """Sanitizes text for safe inclusion in Markdown body blocks without heading/HTML injection."""
    if val is None:
        return ""
    s = str(val).replace("\r\n", "\n").replace("\r", "\n")
    # Disallow injecting top-level or secondary headings
    s = re.sub(r"(?m)^#{1,6}\s+", "\\# ", s)
    # Escape raw HTML
    s = html.escape(s, quote=False)
    return s.strip()


def split_markdown_row(line: str) -> list[str]:
    """Splits a markdown table row by unescaped pipes |."""
    line = line.strip()
    if not line.startswith("|") or not line.endswith("|"):
        return []
    content = line[1:-1]
    parts = re.split(r"(?<!\\)\|", content)
    return [p.replace(r"\|", "|").strip() for p in parts]


def parse_errors_registry(errors_md_path: Path) -> dict[str, dict[str, str]]:
    """Parses registries/ERRORS.md into an error_id -> {id, description, guidance} dict."""
    if not errors_md_path.is_file():
        raise FileNotFoundError(f"Missing errors registry: {errors_md_path}")
    errors: dict[str, dict[str, str]] = {}
    content = errors_md_path.read_text(encoding="utf-8")
    scan_for_secrets(content, "registries/ERRORS.md")
    for line in content.splitlines():
        line = line.strip()
        if line.startswith("| `ERR-"):
            parts = split_markdown_row(line)
            if len(parts) >= 2:
                err_id = parts[0].replace("`", "").strip()
                if err_id in errors:
                    raise RobotDocsError(
                        ERR_ROBOT_DOCS_CORRUPT,
                        f"Duplicate error ID detected in ERRORS.md: {err_id}",
                        target="ERRORS.md",
                    )
                description = parts[1].strip()
                guidance = parts[2].strip() if len(parts) > 2 else ""
                errors[err_id] = {
                    "id": err_id,
                    "description": description,
                    "guidance": guidance,
                }
    return errors


def parse_exit_codes_registry(errors_md_path: Path) -> set[str]:
    """Parses exit code identities (EXIT-*) declared in registries/ERRORS.md."""
    if not errors_md_path.is_file():
        raise FileNotFoundError(f"Missing errors registry: {errors_md_path}")
    exit_codes: set[str] = set()
    for line in errors_md_path.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if line.startswith("| `EXIT-"):
            parts = split_markdown_row(line)
            if parts:
                code = parts[0].replace("`", "").strip()
                exit_codes.add(code)
    return exit_codes


def parse_schemas_registry(schemas_md_path: Path) -> dict[str, dict[str, str]]:
    """Parses registries/SCHEMAS.md into schema_name -> {id, schema, file, authority, compatibilityRule}."""
    if not schemas_md_path.is_file():
        raise FileNotFoundError(f"Missing schemas registry: {schemas_md_path}")
    schemas: dict[str, dict[str, str]] = {}
    seen_ids: set[str] = set()
    content = schemas_md_path.read_text(encoding="utf-8")
    scan_for_secrets(content, "registries/SCHEMAS.md")
    for line in content.splitlines():
        line = line.strip()
        if line.startswith("| `SCHEMA-"):
            parts = split_markdown_row(line)
            if len(parts) >= 5:
                s_id = parts[0].replace("`", "").strip()
                s_name = parts[1].replace("`", "").strip()
                s_file = parts[2].replace("`", "").strip()
                s_auth = parts[3].strip()
                s_comp = parts[4].strip()
                if not s_comp:
                    raise RobotDocsError(
                        ERR_ROBOT_DOCS_CORRUPT,
                        f"Missing compatibilityRule for schema {s_id}",
                        target="SCHEMAS.md",
                    )
                if s_id in seen_ids:
                    raise RobotDocsError(
                        ERR_ROBOT_DOCS_CORRUPT,
                        f"Duplicate schema ID detected in SCHEMAS.md: {s_id}",
                        target="SCHEMAS.md",
                    )
                seen_ids.add(s_id)
                schemas[s_name] = {
                    "id": s_id,
                    "schema": s_name,
                    "file": s_file,
                    "authority": s_auth,
                    "compatibilityRule": s_comp,
                }
    return schemas


def collect_cli_discovery_endpoints(root: Path) -> dict[str, dict[str, str]]:
    """Extracts canonical CLI discovery commands and doc comments from crates/fss-cli/src/fss_cmd.rs."""
    fss_cmd_path = root / "crates/fss-cli/src/fss_cmd.rs"
    if not fss_cmd_path.is_file():
        raise FileNotFoundError(f"Missing CLI command specification: {fss_cmd_path}")
    content = fss_cmd_path.read_text(encoding="utf-8")
    enum_match = re.search(r"pub enum FssCommand\s*\{([^}]+)\}", content)
    if not enum_match:
        raise RobotDocsError(
            ERR_ROBOT_DOCS_CORRUPT,
            "Failed to find FssCommand enum in fss_cmd.rs",
            target="fss_cmd.rs",
        )
    variants = re.findall(r"///\s*(.*?)\n\s*([A-Za-z0-9_]+)", enum_match.group(1))
    var_docs = {name: doc.strip() for doc, name in variants}

    endpoints: dict[str, dict[str, str]] = {}
    if "Capabilities" in var_docs:
        endpoints["capabilities"] = {
            "cli": "fss capabilities --json",
            "description": var_docs["Capabilities"],
        }
    if "Doctor" in var_docs:
        endpoints["doctor"] = {
            "cli": "fss doctor --json",
            "description": var_docs["Doctor"],
        }
    if "Status" in var_docs:
        endpoints["status"] = {
            "cli": "fss status --json",
            "description": var_docs["Status"],
        }
    if "NegativeEvidence" in var_docs:
        endpoints["negative_evidence"] = {
            "cli": "fss negative-evidence list --json",
            "description": var_docs["NegativeEvidence"],
        }

    required = {"capabilities", "doctor", "status", "negative_evidence"}
    if set(endpoints.keys()) != required:
        raise RobotDocsError(
            ERR_ROBOT_DOCS_CORRUPT,
            f"Missing CLI discovery endpoints from fss_cmd.rs: {required - set(endpoints.keys())}",
            target="fss_cmd.rs",
        )
    return endpoints


def parse_qualification_lanes(root: Path) -> set[str]:
    """Loads registered qualification gate IDs from architecture/release_qualification.json."""
    rel_qual_path = root / "architecture/release_qualification.json"
    data = load_json(rel_qual_path)
    lanes = data.get("lanes")
    if not isinstance(lanes, list):
        raise RobotDocsError(
            ERR_ROBOT_DOCS_CORRUPT,
            "Top-level 'lanes' in release_qualification.json must be a list",
            target="release_qualification.json:lanes",
        )
    gates: set[str] = set()
    for item in lanes:
        if isinstance(item, dict) and "id" in item:
            gates.add(item["id"])
    return gates


def collect_robot_docs_model(root: Path) -> dict[str, Any]:
    """Assembles the canonical, consolidated robot docs model from authoritative registries."""
    fss1_reg = load_json(root / "architecture/fss1_public_registry.json")
    agent_ops_reg = load_json(root / "architecture/agent_operations.json")
    agent_views_reg = load_json(root / "architecture/agent_views.json")
    caps_reg = load_json(root / "architecture/capabilities.json")
    crosswalk_reg = load_json(root / "architecture/operation_crosswalk.json")
    errors_map = parse_errors_registry(root / "registries/ERRORS.md")
    exit_codes_set = parse_exit_codes_registry(root / "registries/ERRORS.md")
    schemas_map = parse_schemas_registry(root / "registries/SCHEMAS.md")
    valid_gates = parse_qualification_lanes(root)
    discovery = collect_cli_discovery_endpoints(root)

    # Scan raw registry structures for secrets
    scan_for_secrets(fss1_reg, "architecture/fss1_public_registry.json")
    scan_for_secrets(agent_ops_reg, "architecture/agent_operations.json")
    scan_for_secrets(agent_views_reg, "architecture/agent_views.json")
    scan_for_secrets(caps_reg, "architecture/capabilities.json")
    scan_for_secrets(crosswalk_reg, "architecture/operation_crosswalk.json")

    # Validate asOf metadata on all machine registries
    iso_date_pattern = re.compile(r"^\d{4}-\d{2}-\d{2}$")
    for reg_name, reg_dict in [
        ("agent_operations.json", agent_ops_reg),
        ("fss1_public_registry.json", fss1_reg),
        ("agent_views.json", agent_views_reg),
        ("capabilities.json", caps_reg),
        ("operation_crosswalk.json", crosswalk_reg),
    ]:
        as_of_val = reg_dict.get("asOf")
        if not isinstance(as_of_val, str) or not iso_date_pattern.match(as_of_val):
            raise RobotDocsError(
                ERR_ROBOT_DOCS_CORRUPT,
                f"{reg_name} missing or malformed 'asOf' date (expected YYYY-MM-DD): {as_of_val!r}",
                target=f"{reg_name}:asOf",
            )

    # Type validation of top-level containers
    raw_ops_list = agent_ops_reg.get("operations")
    if not isinstance(raw_ops_list, list):
        raise RobotDocsError(
            ERR_ROBOT_DOCS_CORRUPT,
            f"'operations' in agent_operations.json must be a list, got {type(raw_ops_list).__name__}",
            target="agent_operations.json:operations",
        )

    fss1_ops_list = fss1_reg.get("operations")
    if not isinstance(fss1_ops_list, list):
        raise RobotDocsError(
            ERR_ROBOT_DOCS_CORRUPT,
            f"'operations' in fss1_public_registry.json must be a list, got {type(fss1_ops_list).__name__}",
            target="fss1_public_registry.json:operations",
        )

    cw_list = crosswalk_reg.get("crosswalk")
    if not isinstance(cw_list, list):
        raise RobotDocsError(
            ERR_ROBOT_DOCS_CORRUPT,
            f"'crosswalk' in operation_crosswalk.json must be a list, got {type(cw_list).__name__}",
            target="operation_crosswalk.json:crosswalk",
        )

    views_list = agent_views_reg.get("views")
    if not isinstance(views_list, list):
        raise RobotDocsError(
            ERR_ROBOT_DOCS_CORRUPT,
            f"'views' in agent_views.json must be a list, got {type(views_list).__name__}",
            target="agent_views.json:views",
        )

    caps_list = caps_reg.get("capabilities")
    if not isinstance(caps_list, list):
        raise RobotDocsError(
            ERR_ROBOT_DOCS_CORRUPT,
            f"'capabilities' in capabilities.json must be a list, got {type(caps_list).__name__}",
            target="capabilities.json:capabilities",
        )

    resources_list = fss1_reg.get("resources")
    if not isinstance(resources_list, list):
        raise RobotDocsError(
            ERR_ROBOT_DOCS_CORRUPT,
            f"'resources' in fss1_public_registry.json must be a list, got {type(resources_list).__name__}",
            target="fss1_public_registry.json:resources",
        )

    # Parse tombstones
    fss1_tombstones: set[str] = set()
    raw_fss1_tombstones = fss1_reg.get("tombstones", [])
    if isinstance(raw_fss1_tombstones, list):
        for item in raw_fss1_tombstones:
            if isinstance(item, dict):
                tid = item.get("id") or item.get("operation_id")
                if tid:
                    fss1_tombstones.add(str(tid))
            elif isinstance(item, str):
                fss1_tombstones.add(item)

    caps_tombstones: set[str] = set()
    raw_caps_tombstones = caps_reg.get("tombstones", [])
    if isinstance(raw_caps_tombstones, list):
        for item in raw_caps_tombstones:
            if isinstance(item, dict):
                tid = item.get("id")
                if tid:
                    caps_tombstones.add(str(tid))
            elif isinstance(item, str):
                caps_tombstones.add(item)

    # Check views for duplicate IDs and type correctness
    seen_views: set[str] = set()
    for v in views_list:
        if not isinstance(v, dict):
            raise RobotDocsError(
                ERR_ROBOT_DOCS_CORRUPT,
                "View entry must be a dictionary",
                target="agent_views.json:views",
            )
        v_id = v.get("id")
        if not isinstance(v_id, str):
            raise RobotDocsError(
                ERR_ROBOT_DOCS_CORRUPT,
                "View id must be a string",
                target="agent_views.json:views.id",
            )
        if v_id in seen_views:
            raise RobotDocsError(
                ERR_ROBOT_DOCS_CORRUPT,
                f"Duplicate view ID in agent_views.json: {v_id}",
                target="agent_views.json",
            )
        seen_views.add(v_id)

        # Validate required view fields (no fail-open defaults)
        for req_k in ["name", "owner", "purpose", "targetTokens", "maximumTokens", "requiredSections", "gate", "status"]:
            if req_k not in v or v[req_k] is None:
                raise RobotDocsError(
                    ERR_ROBOT_DOCS_CORRUPT,
                    f"View {v_id} missing required key '{req_k}'",
                    target=f"views.{v_id}.{req_k}",
                )

        if not isinstance(v["targetTokens"], int) or isinstance(v["targetTokens"], bool):
            raise RobotDocsError(
                ERR_ROBOT_DOCS_CORRUPT,
                f"View {v_id} targetTokens must be an integer",
                target=f"views.{v_id}.targetTokens",
            )
        if not isinstance(v["maximumTokens"], int) or isinstance(v["maximumTokens"], bool):
            raise RobotDocsError(
                ERR_ROBOT_DOCS_CORRUPT,
                f"View {v_id} maximumTokens must be an integer",
                target=f"views.{v_id}.maximumTokens",
            )

        sections = v["requiredSections"]
        if not isinstance(sections, list) or len(sections) == 0:
            raise RobotDocsError(
                ERR_ROBOT_DOCS_CORRUPT,
                f"View {v_id} requiredSections must be a non-empty list",
                target=f"views.{v_id}.requiredSections",
            )
        for sec in sections:
            if not isinstance(sec, str) or not re.match(r"^[A-Za-z0-9_]+$", sec):
                raise RobotDocsError(
                    ERR_ROBOT_DOCS_CORRUPT,
                    f"View {v_id} invalid requiredSection name: {sec!r}",
                    target=f"views.{v_id}.requiredSections",
                )

        v_gate = v["gate"]
        if v_gate not in valid_gates:
            raise RobotDocsError(
                ERR_ROBOT_DOCS_UNREGISTERED,
                f"View {v_id} references unregistered gate: {v_gate}",
                target=f"views.{v_id}.gate",
            )

    # Check capabilities for duplicate IDs and index them
    caps_by_id: dict[str, dict[str, Any]] = {}
    for cap in caps_list:
        if not isinstance(cap, dict):
            raise RobotDocsError(
                ERR_ROBOT_DOCS_CORRUPT,
                "Capability entry must be a dictionary",
                target="capabilities.json:capabilities",
            )
        c_id = cap.get("id")
        if not isinstance(c_id, str):
            raise RobotDocsError(
                ERR_ROBOT_DOCS_CORRUPT,
                "Capability id must be a string",
                target="capabilities.json:capabilities.id",
            )
        if c_id in caps_by_id:
            raise RobotDocsError(
                ERR_ROBOT_DOCS_CORRUPT,
                f"Duplicate capability ID in capabilities.json: {c_id}",
                target="capabilities.json",
            )
        for req_k in ["capability", "scope", "plane", "defaultRole"]:
            if req_k not in cap or cap[req_k] is None:
                raise RobotDocsError(
                    ERR_ROBOT_DOCS_CORRUPT,
                    f"Capability {c_id} missing required key '{req_k}'",
                    target=f"capabilities.{c_id}.{req_k}",
                )
        caps_by_id[c_id] = cap

    # Index operations and verify duplicate IDs
    seen_agent_ops: set[str] = set()
    agent_ops_by_id: dict[str, dict[str, Any]] = {}
    for op in raw_ops_list:
        if not isinstance(op, dict):
            raise RobotDocsError(
                ERR_ROBOT_DOCS_CORRUPT,
                "Operation entry in agent_operations.json must be a dictionary",
                target="agent_operations.json:operations",
            )
        op_id = op.get("id")
        if not isinstance(op_id, str):
            raise RobotDocsError(
                ERR_ROBOT_DOCS_CORRUPT,
                "Operation id in agent_operations.json must be a string",
                target="agent_operations.json:operations.id",
            )
        if op_id in seen_agent_ops:
            raise RobotDocsError(
                ERR_ROBOT_DOCS_CORRUPT,
                f"Duplicate operation ID in agent_operations.json: {op_id}",
                target="agent_operations.json",
            )
        seen_agent_ops.add(op_id)
        agent_ops_by_id[op_id] = op

    seen_fss1_ops: set[str] = set()
    fss1_ops_by_id: dict[str, dict[str, Any]] = {}
    for op in fss1_ops_list:
        if not isinstance(op, dict):
            raise RobotDocsError(
                ERR_ROBOT_DOCS_CORRUPT,
                "Operation entry in fss1_public_registry.json must be a dictionary",
                target="fss1_public_registry.json:operations",
            )
        op_id = op.get("id")
        if not isinstance(op_id, str):
            raise RobotDocsError(
                ERR_ROBOT_DOCS_CORRUPT,
                "Operation id in fss1_public_registry.json must be a string",
                target="fss1_public_registry.json:operations.id",
            )
        if op_id in seen_fss1_ops:
            raise RobotDocsError(
                ERR_ROBOT_DOCS_CORRUPT,
                f"Duplicate operation ID in fss1_public_registry.json: {op_id}",
                target="fss1_public_registry.json",
            )
        seen_fss1_ops.add(op_id)
        fss1_ops_by_id[op_id] = op

    seen_cw_ops: set[str] = set()
    cw_by_id: dict[str, dict[str, Any]] = {}
    for entry in cw_list:
        if not isinstance(entry, dict):
            raise RobotDocsError(
                ERR_ROBOT_DOCS_CORRUPT,
                "Entry in operation_crosswalk.json must be a dictionary",
                target="operation_crosswalk.json:crosswalk",
            )
        op_id = entry.get("operation_id")
        if not isinstance(op_id, str):
            raise RobotDocsError(
                ERR_ROBOT_DOCS_CORRUPT,
                "operation_id in operation_crosswalk.json must be a string",
                target="operation_crosswalk.json:crosswalk.operation_id",
            )
        if op_id in seen_cw_ops:
            raise RobotDocsError(
                ERR_ROBOT_DOCS_CORRUPT,
                f"Duplicate operation ID in operation_crosswalk.json: {op_id}",
                target="operation_crosswalk.json",
            )
        seen_cw_ops.add(op_id)
        cw_by_id[op_id] = entry

    # Cross-registry operation consistency check
    if seen_agent_ops != seen_fss1_ops or seen_agent_ops != seen_cw_ops:
        mismatch_fss1 = sorted(seen_agent_ops ^ seen_fss1_ops)
        mismatch_cw = sorted(seen_agent_ops ^ seen_cw_ops)
        raise RobotDocsError(
            ERR_ROBOT_DOCS_DRIFT,
            f"Cross-registry operation mismatch: differences with fss1: {mismatch_fss1}, with crosswalk: {mismatch_cw}",
            target="operations_crosswalk",
        )

    # Filter out tombstoned operations so they never render as live
    live_op_ids = [
        op_id for op_id in seen_agent_ops
        if op_id not in fss1_tombstones and agent_ops_by_id[op_id].get("status") not in ("tombstone", "tombstoned")
    ]

    # Consolidated operations (sorted deterministically by ID)
    consolidated_ops: list[dict[str, Any]] = []
    for op_id in sorted(live_op_ids):
        raw_op = agent_ops_by_id[op_id]
        fss1_op = fss1_ops_by_id[op_id]
        cw = cw_by_id[op_id]

        # Check required fields (no fail-open defaults)
        for req_k in [
            "name", "purpose", "mode", "owner", "defaultView", "effectful", "durable",
            "inputSchema", "outputSchema", "requestPayloadSchema", "responsePayloadSchemas",
            "requiredCapabilities", "retryClasses", "gate", "status"
        ]:
            if req_k not in raw_op or raw_op[req_k] is None:
                raise RobotDocsError(
                    ERR_ROBOT_DOCS_CORRUPT,
                    f"Operation {op_id} missing required key '{req_k}'",
                    target=f"operations.{op_id}.{req_k}",
                )

        # Cross-registry field conflict detection (DRIFT)
        # 1. name
        if raw_op["name"] != fss1_op.get("name"):
            raise RobotDocsError(
                ERR_ROBOT_DOCS_DRIFT,
                f"Operation {op_id} name conflict: agent_operations has {raw_op['name']!r}, fss1 has {fss1_op.get('name')!r}",
                target=f"operations.{op_id}.name",
            )
        if cw.get("name") and raw_op["name"] != cw["name"]:
            raise RobotDocsError(
                ERR_ROBOT_DOCS_DRIFT,
                f"Operation {op_id} name conflict: agent_operations has {raw_op['name']!r}, crosswalk has {cw['name']!r}",
                target=f"operations.{op_id}.name",
            )

        # 2. cliCommand
        cli_fss1 = fss1_op.get("cliCommand")
        cli_cw = cw.get("cli_command")
        if cli_fss1 is not None and cli_cw is not None and cli_fss1 != cli_cw:
            raise RobotDocsError(
                ERR_ROBOT_DOCS_DRIFT,
                f"Operation {op_id} cliCommand conflict: fss1 has {cli_fss1!r}, crosswalk has {cli_cw!r}",
                target=f"operations.{op_id}.cliCommand",
            )
        cli_cmd = cli_cw if cli_cw is not None else (cli_fss1 or "")

        # 3. mcpToolName
        mcp_fss1 = fss1_op.get("mcpToolName")
        mcp_cw = cw.get("mcp_tool_name")
        if mcp_fss1 is not None and mcp_cw is not None and mcp_fss1 != mcp_cw:
            raise RobotDocsError(
                ERR_ROBOT_DOCS_DRIFT,
                f"Operation {op_id} mcpToolName conflict: fss1 has {mcp_fss1!r}, crosswalk has {mcp_cw!r}",
                target=f"operations.{op_id}.mcpToolName",
            )
        mcp_tool = mcp_cw if mcp_cw is not None else (mcp_fss1 or "")

        # 4. defaultView
        view_fss1 = fss1_op.get("defaultView")
        if view_fss1 is not None and raw_op["defaultView"] != view_fss1:
            raise RobotDocsError(
                ERR_ROBOT_DOCS_DRIFT,
                f"Operation {op_id} defaultView conflict: agent_operations has {raw_op['defaultView']!r}, fss1 has {view_fss1!r}",
                target=f"operations.{op_id}.defaultView",
            )

        # 5. requestPayloadSchema
        payload_fss1 = fss1_op.get("requestPayloadSchema")
        if payload_fss1 is not None and raw_op["requestPayloadSchema"] != payload_fss1:
            raise RobotDocsError(
                ERR_ROBOT_DOCS_DRIFT,
                f"Operation {op_id} requestPayloadSchema conflict: agent_operations has {raw_op['requestPayloadSchema']!r}, fss1 has {payload_fss1!r}",
                target=f"operations.{op_id}.requestPayloadSchema",
            )

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

        # Validate gate reference
        op_gate = raw_op["gate"]
        if op_gate not in valid_gates:
            raise RobotDocsError(
                ERR_ROBOT_DOCS_UNREGISTERED,
                f"Operation {op_id} references unregistered gate: {op_gate}",
                target=f"operations.{op_id}.gate",
            )

        # Validate exit identities against ERRORS.md
        if not isinstance(exit_ids, list):
            raise RobotDocsError(
                ERR_ROBOT_DOCS_CORRUPT,
                f"Operation {op_id} exit_identities must be a list",
                target=f"operations.{op_id}.exitIdentities",
            )
        for exit_id in exit_ids:
            if exit_id not in exit_codes_set:
                raise RobotDocsError(
                    ERR_ROBOT_DOCS_UNREGISTERED,
                    f"Operation {op_id} references unregistered exit identity: {exit_id}",
                    target=f"operations.{op_id}.exitIdentities",
                )

        # Validate retry classes against recovery classes enum
        retry_classes = raw_op["retryClasses"]
        if not isinstance(retry_classes, list):
            raise RobotDocsError(
                ERR_ROBOT_DOCS_CORRUPT,
                f"Operation {op_id} retryClasses must be a list",
                target=f"operations.{op_id}.retryClasses",
            )
        for r_cls in retry_classes:
            if r_cls not in VALID_RECOVERY_CLASSES:
                raise RobotDocsError(
                    ERR_ROBOT_DOCS_UNREGISTERED,
                    f"Operation {op_id} references unregistered retry class: {r_cls}",
                    target=f"operations.{op_id}.retryClasses",
                )

        # Validate schema references (envelopes and payloads)
        req_env = raw_op["inputSchema"]
        resp_env = raw_op["outputSchema"]
        req_payload = raw_op["requestPayloadSchema"]
        resp_payloads = raw_op["responsePayloadSchemas"]

        if not isinstance(resp_payloads, list):
            raise RobotDocsError(
                ERR_ROBOT_DOCS_CORRUPT,
                f"Operation {op_id} responsePayloadSchemas must be a list, got {type(resp_payloads).__name__}",
                target=f"operations.{op_id}.responsePayloadSchemas",
            )

        for s in [req_env, resp_env, req_payload]:
            if s and s not in schemas_map:
                raise RobotDocsError(
                    ERR_ROBOT_DOCS_UNREGISTERED,
                    f"Operation {op_id} references unregistered schema: {s}",
                    target=f"operations.{op_id}.schemas",
                )
        for s in resp_payloads:
            if not isinstance(s, str):
                raise RobotDocsError(
                    ERR_ROBOT_DOCS_CORRUPT,
                    f"Schema in responsePayloadSchemas for {op_id} must be a string",
                    target=f"operations.{op_id}.responsePayloadSchemas",
                )
            if s not in schemas_map:
                raise RobotDocsError(
                    ERR_ROBOT_DOCS_UNREGISTERED,
                    f"Operation {op_id} references unregistered response schema: {s}",
                    target=f"operations.{op_id}.responsePayloadSchemas",
                )

        # Validate capability references
        req_caps = raw_op["requiredCapabilities"]
        if not isinstance(req_caps, list):
            raise RobotDocsError(
                ERR_ROBOT_DOCS_CORRUPT,
                f"Operation {op_id} requiredCapabilities must be a list, got {type(req_caps).__name__}",
                target=f"operations.{op_id}.requiredCapabilities",
            )
        for cap_id in req_caps:
            if not isinstance(cap_id, str):
                raise RobotDocsError(
                    ERR_ROBOT_DOCS_CORRUPT,
                    f"Capability identifier in {op_id} must be a string",
                    target=f"operations.{op_id}.requiredCapabilities",
                )
            if cap_id not in caps_by_id:
                raise RobotDocsError(
                    ERR_ROBOT_DOCS_UNREGISTERED,
                    f"Operation {op_id} references unregistered capability: {cap_id}",
                    target=f"operations.{op_id}.requiredCapabilities",
                )
            if cap_id in caps_tombstones or caps_by_id[cap_id].get("status") in ("tombstone", "tombstoned", "superseded"):
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
        if not isinstance(error_ids, list):
            raise RobotDocsError(
                ERR_ROBOT_DOCS_CORRUPT,
                f"Operation {op_id} error_identities must be a list",
                target=f"operations.{op_id}.errorIdentities",
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
            "retryClasses": retry_classes,
            "primaryErrorId": primary_err,
            "errorIdentities": error_ids,
            "exitIdentities": exit_ids,
            "gate": op_gate,
            "status": raw_op["status"],
        })

    # Consolidated views (sorted deterministically by ID)
    consolidated_views: list[dict[str, Any]] = []
    for raw_view in sorted(views_list, key=lambda v: str(v.get("id", ""))):
        consolidated_views.append({
            "id": raw_view["id"],
            "name": raw_view["name"],
            "owner": raw_view["owner"],
            "purpose": raw_view["purpose"],
            "targetTokens": raw_view["targetTokens"],
            "maximumTokens": raw_view["maximumTokens"],
            "requiredSections": raw_view["requiredSections"],
            "gate": raw_view["gate"],
            "status": raw_view["status"],
        })

    # Consolidated resources (sorted deterministically by ID)
    consolidated_resources: list[dict[str, Any]] = []
    for raw_res in sorted(resources_list, key=lambda r: str(r.get("id", ""))):
        if not isinstance(raw_res, dict):
            raise RobotDocsError(
                ERR_ROBOT_DOCS_CORRUPT,
                "Resource entry must be a dictionary",
                target="fss1_public_registry.json:resources",
            )
        res_id = raw_res.get("id")
        if not isinstance(res_id, str):
            raise RobotDocsError(
                ERR_ROBOT_DOCS_CORRUPT,
                "Resource id must be a string",
                target="fss1_public_registry.json:resources.id",
            )
        for req_k in ["name", "owner", "uriTemplate", "payloadSchema", "requestEnvelope", "responseEnvelope", "compatibilityClass", "status"]:
            if req_k not in raw_res or raw_res[req_k] is None:
                raise RobotDocsError(
                    ERR_ROBOT_DOCS_CORRUPT,
                    f"Resource {res_id} missing required key '{req_k}'",
                    target=f"resources.{res_id}.{req_k}",
                )

        res_req_env = raw_res["requestEnvelope"]
        res_resp_env = raw_res["responseEnvelope"]
        res_payload = raw_res["payloadSchema"]

        for s in [res_req_env, res_resp_env]:
            if s and s not in schemas_map:
                raise RobotDocsError(
                    ERR_ROBOT_DOCS_UNREGISTERED,
                    f"Resource {res_id} references unregistered envelope schema: {s}",
                    target=f"resources.{res_id}.envelopes",
                )
        if res_payload and res_payload not in schemas_map:
            raise RobotDocsError(
                ERR_ROBOT_DOCS_UNREGISTERED,
                f"Resource {res_id} references unregistered payload schema: {res_payload}",
                target=f"resources.{res_id}.payloadSchema",
            )

        consolidated_resources.append({
            "id": res_id,
            "name": raw_res["name"],
            "owner": raw_res["owner"],
            "uriTemplate": raw_res["uriTemplate"],
            "requestEnvelope": res_req_env,
            "responseEnvelope": res_resp_env,
            "payloadSchema": res_payload,
            "compatibilityClass": raw_res["compatibilityClass"],
            "status": raw_res["status"],
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
            "id": err["id"],
            "description": err["description"],
            "guidance": err["guidance"],
        })

    # Required metadata keys in fss1_reg (no fail-open defaults)
    for req_k in ["asOf", "semanticProtocol", "registryGeneration", "freezeDigest"]:
        if req_k not in fss1_reg or fss1_reg[req_k] is None:
            raise RobotDocsError(
                ERR_ROBOT_DOCS_CORRUPT,
                f"fss1_public_registry.json missing required metadata key '{req_k}'",
                target=f"fss1_public_registry.json:{req_k}",
            )

    model = {
        "schema": "fss.robot_docs.v1",
        "semanticProtocol": fss1_reg["semanticProtocol"],
        "registryGeneration": fss1_reg["registryGeneration"],
        "freezeDigest": fss1_reg["freezeDigest"],
        "asOf": fss1_reg["asOf"],
        "discovery": discovery,
        "operations": consolidated_ops,
        "views": consolidated_views,
        "resources": consolidated_resources,
        "schemas": consolidated_schemas,
        "capabilities": consolidated_caps,
        "errors": consolidated_errors,
    }
    return model


def generate_robot_docs_markdown(model: dict[str, Any]) -> str:
    """Renders the consolidated model into deterministic, human-legible Markdown."""
    lines: list[str] = [
        f"# Self-Describing Robot Documentation (`{escape_markdown_inline(model['semanticProtocol'])}`)",
        "",
        "> Deterministic, evidence-native semantic control plane for owner-authorized physical sensors.",
        "> This document is mechanically derived from authoritative machine registries.",
        "",
        f"- **Schema**: `{escape_markdown_inline(model['schema'])}`",
        f"- **Semantic Protocol**: `{escape_markdown_inline(model['semanticProtocol'])}`",
        f"- **Registry Generation**: `{escape_markdown_inline(model['registryGeneration'])}`",
        f"- **Freeze Digest**: `{escape_markdown_inline(model['freezeDigest'])}`",
        f"- **As Of**: `{escape_markdown_inline(model['asOf'])}`",
        "",
        "## Table of Contents",
        "",
        "1. [Discovery Endpoints](#1-discovery-endpoints)",
        "2. [Core Protocol Error Taxonomy](#2-core-protocol-error-taxonomy)",
        "3. [Canonical Operations Catalog](#3-canonical-operations-catalog)",
        "4. [Registered Views Catalog](#4-registered-views-catalog)",
        "5. [Resource URI Templates](#5-resource-uri-templates)",
        "6. [Schemas Catalog](#6-schemas-catalog)",
        "7. [Required Capabilities](#7-required-capabilities)",
        "8. [Stable Error Taxonomy & Recovery Guidance](#8-stable-error-taxonomy--recovery-guidance)",
        "",
        "---",
        "",
        "## 1. Discovery Endpoints",
        "",
        "Standard machine introspection entrypoints available on every conforming node:",
        "",
        "| Endpoint | CLI Command | Description |",
        "|---|---|---|",
    ]

    for ep_name in sorted(model["discovery"].keys()):
        ep = model["discovery"][ep_name]
        lines.append(
            f"| `{escape_markdown_cell(ep_name)}` | `{escape_markdown_cell(ep['cli'])}` | "
            f"{escape_markdown_cell(ep['description'])} |"
        )

    lines.extend([
        "",
        "## 2. Core Protocol Error Taxonomy",
        "",
        "Core protocol errors governing session negotiation, contract basis, and presentation:",
        "",
        "| Error Identity | Meaning | Recovery Guidance |",
        "|---|---|---|",
    ])

    core_error_ids = [
        "ERR-AGENT-PROTOCOL-001",
        "ERR-AGENT-SESSION-STALE-001",
        "ERR-AGENT-CONTEXT-INCOMPLETE-001",
        "ERR-AGENT-RESNAPSHOT-001",
        "ERR-AGENT-AMBIGUOUS-001",
    ]
    errors_by_id = {err["id"]: err for err in model["errors"]}
    for err_id in core_error_ids:
        err = errors_by_id.get(err_id)
        if not err:
            raise RobotDocsError(
                ERR_ROBOT_DOCS_UNREGISTERED,
                f"Core protocol error {err_id} is not registered in ERRORS.md",
                target="core_errors",
            )
        lines.append(
            f"| `{escape_markdown_cell(err['id'])}` | {escape_markdown_cell(err['description'])} | "
            f"{escape_markdown_cell(err['guidance'])} |"
        )

    lines.extend([
        "",
        "## 3. Canonical Operations Catalog",
        "",
        "The complete suite of 14 canonical agent control plane operations under `fss/1`:",
        "",
        "| ID | Name | CLI Command | MCP Tool | Library Entry Point | Primary Error |",
        "|---|---|---|---|---|---|",
    ])

    for op in model["operations"]:
        lines.append(
            f"| `{escape_markdown_cell(op['id'])}` | `{escape_markdown_cell(op['name'])}` | "
            f"`{escape_markdown_cell(op['cliCommand'])}` | `{escape_markdown_cell(op['mcpToolName'])}` | "
            f"`{escape_markdown_cell(op['libraryEntryPoint'])}` | `{escape_markdown_cell(op['primaryErrorId'])}` |"
        )

    lines.extend([
        "",
        "### Operation Details",
        "",
    ])

    for op in model["operations"]:
        retry_cls = ", ".join(f"`{escape_markdown_inline(r)}`" for r in op["retryClasses"]) if op["retryClasses"] else "none"
        req_caps = ", ".join(f"`{escape_markdown_inline(c)}`" for c in op["requiredCapabilities"]) if op["requiredCapabilities"] else "none"
        err_ids = ", ".join(f"`{escape_markdown_inline(e)}`" for e in op["errorIdentities"]) if op["errorIdentities"] else "none"
        exit_ids = ", ".join(f"`{escape_markdown_inline(x)}`" for x in op["exitIdentities"]) if op["exitIdentities"] else "none"

        lines.extend([
            f"#### `{escape_markdown_inline(op['id'])}`: {escape_markdown_inline(op['name'])}",
            "",
            f"- **Purpose**: {escape_markdown_text(op['purpose'])}",
            f"- **Execution Mode**: `{escape_markdown_inline(op['mode'])}` | **Owner**: `{escape_markdown_inline(op['owner'])}` | **Gate**: `{escape_markdown_inline(op['gate'])}`",
            f"- **Effectful**: `{op['effectful']}` | **Durable**: `{op['durable']}`",
            f"- **Default View**: `{escape_markdown_inline(op['defaultView'])}`",
            f"- **Envelopes**: Request `{escape_markdown_inline(op['requestEnvelope'])}` → Response `{escape_markdown_inline(op['responseEnvelope'])}`",
            f"- **Payload Schema**: `{escape_markdown_inline(op['requestPayloadSchema'])}`",
            f"- **Required Capabilities**: {req_caps}",
            f"- **Retry Classes**: {retry_cls}",
            f"- **Primary Error**: `{escape_markdown_inline(op['primaryErrorId'])}`",
            f"- **Error Identities**: {err_ids}",
            f"- **Exit Identities**: {exit_ids}",
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
        sections = ", ".join(f"`{escape_markdown_inline(s)}`" for s in view["requiredSections"])
        lines.append(
            f"| `{escape_markdown_cell(view['id'])}` | `{escape_markdown_cell(view['name'])}` | "
            f"`{escape_markdown_cell(view['owner'])}` | {view['targetTokens']} | {view['maximumTokens']} | "
            f"{sections} | {escape_markdown_cell(view['purpose'])} |"
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
            f"`{escape_markdown_cell(schema['compatibilityRule'])}` |"
        )

    lines.extend([
        "",
        "## 7. Required Capabilities",
        "",
        "Capabilities required by canonical operations cataloged from `architecture/capabilities.json`:",
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
        "| ID | Meaning | Retry policy |",
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
    return json.dumps(model, indent=2, sort_keys=True, allow_nan=False) + "\n"


def generate_docs(root: Path) -> tuple[str, str]:
    """Collects authoritative model and returns (markdown_content, json_content)."""
    model = collect_robot_docs_model(root)
    md = generate_robot_docs_markdown(model)
    json_str = generate_robot_docs_json(model)
    return md, json_str


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Deterministic generator and freshness verifier for robot docs"
    )
    parser.add_argument(
        "--repo-root",
        type=Path,
        default=ROOT,
        help="Path to repository root (default: repo containing this script)",
    )
    parser.add_argument(
        "--check",
        action="store_true",
        help="Check that on-disk robot documentation matches authoritative machine registries",
    )
    parser.add_argument(
        "--output-dir",
        type=Path,
        default=None,
        help="Directory to write ROBOT_DOCS.md and ROBOT_DOCS.json (default: <repo-root>/docs)",
    )
    args = parser.parse_args()

    repo_root = args.repo_root
    output_dir = args.output_dir if args.output_dir is not None else (repo_root / "docs")

    try:
        expected_md, expected_json = generate_docs(repo_root)
    except RobotDocsError as exc:
        print(f"[{exc.code}] {exc.target}: {exc.message}", file=sys.stderr)
        return 1
    except FileNotFoundError as exc:
        print(f"[{ERR_ROBOT_DOCS_MISSING}] {exc.filename}: Missing registry file: {exc}", file=sys.stderr)
        return 1
    except (ValueError, KeyError, TypeError, AttributeError) as exc:
        print(f"[{ERR_ROBOT_DOCS_CORRUPT}] architecture/: Failed to parse machine registries: {exc}", file=sys.stderr)
        return 1

    md_path = output_dir / "ROBOT_DOCS.md"
    json_path = output_dir / "ROBOT_DOCS.json"

    if args.check:
        if not md_path.is_file() or not json_path.is_file():
            print(f"[{ERR_ROBOT_DOCS_MISSING}] Required robot docs files are missing on disk.", file=sys.stderr)
            return 1
        on_disk_md = md_path.read_text(encoding="utf-8")
        on_disk_json = json_path.read_text(encoding="utf-8")

        if on_disk_md != expected_md or on_disk_json != expected_json:
            print(f"[{ERR_ROBOT_DOCS_STALE}] On-disk robot documentation is stale compared to machine registries.", file=sys.stderr)
            return 1
        print("OK: robot docs are fresh and match machine registries.")
        return 0

    args.output_dir.mkdir(parents=True, exist_ok=True)
    md_path.write_text(expected_md, encoding="utf-8")
    json_path.write_text(expected_json, encoding="utf-8")
    print(f"Successfully generated robot docs at {md_path} and {json_path}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
