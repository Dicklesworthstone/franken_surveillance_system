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
# VALID_RECOVERY_CLASSES is dynamically derived from schemas/agent_response_envelope.v1.json below


class RobotDocsError(Exception):
    """Fail-closed error raised during robot docs model collection or generation."""

    def __init__(self, code: str, message: str, target: str = ""):
        super().__init__(message)
        self.code = code
        self.message = message
        self.target = target


SECRET_PATTERNS = [
    re.compile(r"(?i)\bAuthorization:\s*Bearer\s+[A-Za-z0-9._~+/-]{8,}"),
    re.compile(r"\bBearer\s+(?=[A-Za-z0-9._~+/-]*\d)[A-Za-z0-9._~+/-]{10,}\b"),
    re.compile(r"\bsk-ant-[A-Za-z0-9_-]{10,}\b"),
    re.compile(r"\bsk-(?:proj-)?[A-Za-z0-9_-]{10,}\b"),
    re.compile(r"\bsk-[A-Za-z0-9_-]{10,}\b"),
    re.compile(r"\bAIza[0-9A-Za-z_-]{10,}\b"),
    re.compile(r"\b(?:AKIA|ASIA)[0-9A-Z]{16}\b"),
    re.compile(r"\b(?:xoxb|xoxp|xoxr|xoxa)-[0-9A-Za-z-]{10,}\b"),
    re.compile(r"\bglpat-[0-9A-Za-z_-]{10,}\b"),
    re.compile(r"\beyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\b"),
    re.compile(r"(?i)\bpassword\s+is\s+[^\s]+"),
    re.compile(r"""(?i)\b(?:password|passwd|api[_-]?key|secret_key|secret)\s*(?::(?!:)|=)\s*["']?[^"'\s]{4,}"""),
    re.compile(r"""(?i)\bclient_secret\s*(?::(?!:)|=)\s*["']?[^"'\s]{4,}"""),
    re.compile(r"""(?i)\btoken\s*(?::(?!:)|=)\s*["']?[^"'\s]{8,}"""),
    re.compile(r"(?i)postgres(?:ql)?://[^\s:]+:[^\s@]+@"),
    re.compile(r"\bghp_[A-Za-z0-9]{20,}\b"),
    re.compile(r"\bgithub_pat_[A-Za-z0-9_]{20,}\b"),
    re.compile(r"\b(?:gho|ghu|ghs|ghr)_[A-Za-z0-9]{20,}\b"),
    re.compile(r"\bnpm_[A-Za-z0-9_]{10,}\b"),
    re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----"),
    re.compile(r"\.ssh/(?:id_rsa|id_ed25519|id_ecdsa|id_dsa)"),
    re.compile(r"~/(?:\.[a-zA-Z0-9._-]+|[a-zA-Z0-9._-]+/[a-zA-Z0-9._-]+)"),
    re.compile(r"/data/projects/[a-zA-Z0-9._-]+"),
    re.compile(r"/home/[a-zA-Z0-9._-]+"),
    re.compile(r"/Users/[a-zA-Z0-9._-]+"),
    re.compile(r"/root/[a-zA-Z0-9._-]+"),
    re.compile(r"/root/\.netrc"),
    re.compile(r"/private/var(?:/[a-zA-Z0-9._-]+)?"),
    re.compile(r"""(?i)[a-z]:\\Users\\[a-zA-Z0-9._-]+"""),
    re.compile(r"""(?i)[a-z]:/Users/[a-zA-Z0-9._-]+"""),
    re.compile(r"""\\\\[a-zA-Z0-9._$-]+\\[a-zA-Z0-9._$-]+"""),
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
    except RobotDocsError:
        raise
    except Exception as exc:
        raise RobotDocsError(
            ERR_ROBOT_DOCS_CORRUPT,
            f"Failed to parse JSON in {path.name}: {exc}",
            target=path.name,
        ) from exc
    if not isinstance(doc, dict):
        raise RobotDocsError(
            ERR_ROBOT_DOCS_CORRUPT,
            f"Top-level JSON in {path.name} must be a dictionary, got {type(doc).__name__}",
            target=path.name,
        )
    check_no_nan_inf(doc, path.name)
    return doc


def load_valid_recovery_classes(root: Path) -> frozenset[str]:
    """Derives valid recovery classes from schemas/agent_response_envelope.v1.json."""
    schema_path = root / "schemas/agent_response_envelope.v1.json"
    if not schema_path.is_file():
        raise RobotDocsError(
            ERR_ROBOT_DOCS_MISSING,
            f"Missing required schema for recovery classes: {schema_path}",
            target="schemas/agent_response_envelope.v1.json",
        )
    data = load_json(schema_path)
    classes = data.get("properties", {}).get("recoveryClass", {}).get("enum")
    if not isinstance(classes, list) or not classes:
        raise RobotDocsError(
            ERR_ROBOT_DOCS_CORRUPT,
            "Missing or invalid recoveryClass enum in agent_response_envelope.v1.json",
            target="agent_response_envelope.v1.json:recoveryClass",
        )
    return frozenset(classes)


def parse_agent_operation_modes(root: Path) -> set[str]:
    """Derives valid operation execution modes from registries/AGENT_OPERATIONS.md."""
    md_path = root / "registries/AGENT_OPERATIONS.md"
    if not md_path.is_file():
        raise RobotDocsError(
            ERR_ROBOT_DOCS_MISSING,
            f"Missing required registry for operation modes: {md_path}",
            target="registries/AGENT_OPERATIONS.md",
        )
    content = md_path.read_text(encoding="utf-8")
    scan_for_secrets(content, "registries/AGENT_OPERATIONS.md")
    modes: set[str] = set()
    for line in content.splitlines():
        line = line.strip()
        if not line.startswith("|") or line.startswith("|---") or "Mode" in line:
            continue
        parts = [c.strip().strip("`") for c in line.split("|")[1:-1]]
        if len(parts) >= 4:
            mode_val = parts[3].strip()
            if mode_val:
                modes.add(mode_val)
    if not modes:
        raise RobotDocsError(
            ERR_ROBOT_DOCS_CORRUPT,
            "Failed to parse operation modes from registries/AGENT_OPERATIONS.md",
            target="registries/AGENT_OPERATIONS.md",
        )
    return modes


def parse_registered_statuses(root: Path) -> set[str]:
    """Extracts registered status values from architecture registries and markdown tables."""
    md_path = root / "registries/AGENT_OPERATIONS.md"
    if not md_path.is_file():
        raise RobotDocsError(
            ERR_ROBOT_DOCS_MISSING,
            f"Missing required registry for operation statuses: {md_path}",
            target="registries/AGENT_OPERATIONS.md",
        )
    content = md_path.read_text(encoding="utf-8")
    scan_for_secrets(content, "registries/AGENT_OPERATIONS.md")
    statuses: set[str] = set()
    in_status_section = False
    for line in content.splitlines():
        sline = line.strip()
        if sline.startswith("## Operation lifecycle statuses"):
            in_status_section = True
            continue
        if in_status_section:
            if sline.startswith("## "):
                break
            for token in re.findall(r"`([A-Za-z0-9_]+)`", sline):
                statuses.add(token)
    for rel_path in ["registries/AGENT_OPERATIONS.md", "registries/AGENT_VIEWS.md", "registries/OPERATION_CROSSWALK.md"]:
        p = root / rel_path
        if p.is_file():
            c_text = p.read_text(encoding="utf-8")
            for line in c_text.splitlines():
                line = line.strip()
                if not line.startswith("|") or line.startswith("|---") or "Status" in line:
                    continue
                parts = [c.strip().strip("`") for c in line.split("|")[1:-1]]
                if parts:
                    val = parts[-1].strip()
                    if val and val != "-":
                        statuses.add(val)
    if not statuses:
        raise RobotDocsError(
            ERR_ROBOT_DOCS_CORRUPT,
            "Failed to parse registered operation statuses from registries/AGENT_OPERATIONS.md",
            target="registries/AGENT_OPERATIONS.md",
        )
    return statuses


def load_valid_compatibility_classes(root: Path) -> frozenset[str]:
    """Derives registered compatibility classes from registries/AGENT_OPERATIONS.md."""
    md_path = root / "registries/AGENT_OPERATIONS.md"
    if not md_path.is_file():
        raise RobotDocsError(
            ERR_ROBOT_DOCS_MISSING,
            f"Missing required registry for compatibility classes: {md_path}",
            target="registries/AGENT_OPERATIONS.md",
        )
    content = md_path.read_text(encoding="utf-8")
    scan_for_secrets(content, "registries/AGENT_OPERATIONS.md")
    classes: set[str] = set()
    in_compat_section = False
    for line in content.splitlines():
        sline = line.strip()
        if sline.startswith("## Compatibility classes"):
            in_compat_section = True
            continue
        if in_compat_section:
            if sline.startswith("## "):
                break
            for token in re.findall(r"`([A-Za-z0-9_]+)`", sline):
                classes.add(token)
    if not classes:
        fss1_path = root / "architecture/fss1_public_registry.json"
        if fss1_path.is_file():
            d = load_json(fss1_path)
            for item in d.get("resources", []) + d.get("operations", []):
                if isinstance(item, dict) and "compatibilityClass" in item:
                    classes.add(item["compatibilityClass"])
    if not classes:
        raise RobotDocsError(
            ERR_ROBOT_DOCS_CORRUPT,
            "Failed to parse compatibility classes from registries/AGENT_OPERATIONS.md",
            target="registries/AGENT_OPERATIONS.md",
        )
    return frozenset(classes)


def load_valid_view_sections(root: Path) -> frozenset[str]:
    """Derives registered view sections from registries/AGENT_VIEWS.md."""
    md_path = root / "registries/AGENT_VIEWS.md"
    if not md_path.is_file():
        raise RobotDocsError(
            ERR_ROBOT_DOCS_MISSING,
            f"Missing required registry for view sections: {md_path}",
            target="registries/AGENT_VIEWS.md",
        )
    content = md_path.read_text(encoding="utf-8")
    scan_for_secrets(content, "registries/AGENT_VIEWS.md")
    sections: set[str] = set()
    in_sec_section = False
    for line in content.splitlines():
        sline = line.strip()
        if sline.startswith("## View sections"):
            in_sec_section = True
            continue
        if in_sec_section:
            if sline.startswith("## "):
                break
            for token in re.findall(r"`([A-Za-z0-9_]+)`", sline):
                sections.add(token)
    if not sections:
        raise RobotDocsError(
            ERR_ROBOT_DOCS_CORRUPT,
            "Failed to parse view sections from registries/AGENT_VIEWS.md",
            target="registries/AGENT_VIEWS.md",
        )
    return frozenset(sections)


VALID_COMPATIBILITY_CLASSES: frozenset[str] = frozenset()
VALID_VIEW_SECTIONS: frozenset[str] = frozenset()
VALID_RECOVERY_CLASSES: frozenset[str] = frozenset()




def escape_markdown_cell(val: Any) -> str:
    """Sanitizes text for safe inclusion in Markdown table cells without HTML/script/link injection."""
    if val is None:
        return ""
    s = str(val).replace("\r\n", " ").replace("\n", " ").replace("\r", " ")
    # Escape HTML tags and special entities
    s = html.escape(s, quote=False)
    # Neutralize javascript: links
    s = re.sub(r"(?i)javascript\s*:", "javascript&#58;", s)
    # Neutralize backticks in table cells so they cannot break out of code spans or render live links
    s = s.replace("`", "'")
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
    """Sanitizes text for safe inclusion in Markdown body blocks without heading/bullet/fence/HTML injection."""
    if val is None:
        return ""
    s = str(val).replace("\r\n", "\n").replace("\r", "\n")
    # Disallow injecting top-level or secondary headings
    s = re.sub(r"(?m)^#{1,6}\s+", "\\# ", s)
    # Neutralize newlines in purpose and text blocks so they cannot create fake bullets or fences
    s = s.replace("\n", " ")
    # Neutralize code fences
    s = s.replace("```", "'''")
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
    scan_for_secrets(content, "crates/fss-cli/src/fss_cmd.rs")

    # Extract usage lines from help_text() by decoding escaped newlines and splitlines
    help_match = re.search(r'fn help_text\(\)[^{]*\{[^"0-9a-zA-Z]*"((?:[^"\\]|\\.)*)"', content, re.DOTALL)
    usage_cmds: dict[str, str] = {}
    if help_match:
        raw_help = help_match.group(1)
        for line in re.split(r"\\n|\n", raw_help):
            line = line.strip()
            m_usage = re.search(r"fss\s+([a-z0-9_-]+)(.*)", line)
            if m_usage:
                cmd_word = m_usage.group(1)
                full_cmd = f"fss {cmd_word}{m_usage.group(2)}".strip()
                usage_cmds[cmd_word] = full_cmd

    # Extract primary parser literal from parse_fss_tokens match arms
    parser_match_arms: dict[str, str] = {}
    m_fn = re.search(r"fn parse_fss_tokens\b[^{]*\{([\s\S]*?)\n\}\n", content)
    if m_fn:
        for arm in re.finditer(r'"([a-z0-9_-]+)"(?:\s*\|\s*"[a-z0-9_-]+")*\s*=>.*?FssCommand::([A-Za-z0-9_]+)', m_fn.group(1), re.DOTALL):
            var = arm.group(2)
            lit = arm.group(1)
            if var not in parser_match_arms:
                parser_match_arms[var] = lit

    enum_match = re.search(r"pub enum FssCommand\s*\{([^}]+)\}", content)
    if not enum_match:
        raise RobotDocsError(
            ERR_ROBOT_DOCS_CORRUPT,
            "Failed to find FssCommand enum in fss_cmd.rs",
            target="fss_cmd.rs",
        )

    # Parse variants and doc comments
    variant_pattern = re.compile(
        r"((?:///[^\n]*\n)+)\s*([A-Za-z0-9_]+)",
        re.MULTILINE,
    )

    var_docs: dict[str, str] = {}
    for doc_block, var_ident in variant_pattern.findall(enum_match.group(1)):
        doc = " ".join(line.strip().lstrip("/").strip() for line in doc_block.strip().splitlines())
        var_docs[var_ident] = doc

    scan_for_secrets(var_docs, "crates/fss-cli/src/fss_cmd.rs:doc_comments")

    endpoints: dict[str, dict[str, str]] = {}
    if "Capabilities" in var_docs:
        cmd_word = parser_match_arms.get("Capabilities", "capabilities")
        cli_str = usage_cmds.get(cmd_word, f"fss {cmd_word} --json")
        if "--json" not in cli_str and "--format json" not in cli_str:
            cli_str += " --json"
        endpoints["capabilities"] = {
            "cli": cli_str,
            "description": var_docs["Capabilities"],
        }
    if "Doctor" in var_docs:
        cmd_word = parser_match_arms.get("Doctor", "doctor")
        cli_str = usage_cmds.get(cmd_word, f"fss {cmd_word} --json")
        if "--json" not in cli_str and "--format json" not in cli_str:
            cli_str += " --json"
        endpoints["doctor"] = {
            "cli": cli_str,
            "description": var_docs["Doctor"],
        }
    if "Status" in var_docs:
        cmd_word = parser_match_arms.get("Status", "status")
        cli_str = usage_cmds.get(cmd_word, f"fss {cmd_word} --json")
        if "--json" not in cli_str and "--format json" not in cli_str:
            cli_str += " --json"
        endpoints["status"] = {
            "cli": cli_str,
            "description": var_docs["Status"],
        }
    if "NegativeEvidence" in var_docs:
        cmd_word = parser_match_arms.get("NegativeEvidence", "negative-evidence")
        usage_line = usage_cmds.get(cmd_word, "")
        subcmd = "list"
        m_sub = re.search(r"<[^>]*\b([a-z]+)\b[^>]*>", usage_line)
        if m_sub:
            alternatives = re.findall(r"\b([a-z0-9_-]+)\b", m_sub.group(0))
            if "list" in alternatives:
                subcmd = "list"
            elif "ls" in alternatives:
                subcmd = "ls"
            elif len(alternatives) > 1:
                subcmd = alternatives[1]
        cli_str = f"fss {cmd_word} {subcmd} --json"
        endpoints["negative_evidence"] = {
            "cli": cli_str,
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
    scan_for_secrets(data, "architecture/release_qualification.json")
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

    global VALID_RECOVERY_CLASSES, VALID_COMPATIBILITY_CLASSES, VALID_VIEW_SECTIONS
    VALID_RECOVERY_CLASSES = load_valid_recovery_classes(root)
    valid_modes = parse_agent_operation_modes(root)
    valid_statuses = parse_registered_statuses(root)
    VALID_COMPATIBILITY_CLASSES = load_valid_compatibility_classes(root)
    VALID_VIEW_SECTIONS = load_valid_view_sections(root)

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
    if "tombstones" in fss1_reg:
        raw_fss1_tombstones = fss1_reg["tombstones"]
        if not isinstance(raw_fss1_tombstones, list):
            raise RobotDocsError(
                ERR_ROBOT_DOCS_CORRUPT,
                f"'tombstones' in fss1_public_registry.json must be a list, got {type(raw_fss1_tombstones).__name__}",
                target="fss1_public_registry.json:tombstones",
            )
        for item in raw_fss1_tombstones:
            if isinstance(item, dict):
                tid = item.get("id") or item.get("operation_id")
                if not tid or not isinstance(tid, str):
                    raise RobotDocsError(
                        ERR_ROBOT_DOCS_CORRUPT,
                        "Tombstone object in fss1_public_registry.json must contain string id or operation_id",
                        target="fss1_public_registry.json:tombstones",
                    )
                fss1_tombstones.add(tid)
            elif isinstance(item, str):
                fss1_tombstones.add(item)
            else:
                raise RobotDocsError(
                    ERR_ROBOT_DOCS_CORRUPT,
                    f"Tombstone item in fss1_public_registry.json must be str or dict, got {type(item).__name__}",
                    target="fss1_public_registry.json:tombstones",
                )

    caps_tombstones: set[str] = set()
    if "tombstones" in caps_reg:
        raw_caps_tombstones = caps_reg["tombstones"]
        if not isinstance(raw_caps_tombstones, list):
            raise RobotDocsError(
                ERR_ROBOT_DOCS_CORRUPT,
                f"'tombstones' in capabilities.json must be a list, got {type(raw_caps_tombstones).__name__}",
                target="capabilities.json:tombstones",
            )
        for item in raw_caps_tombstones:
            if isinstance(item, dict):
                tid = item.get("id")
                if not tid or not isinstance(tid, str):
                    raise RobotDocsError(
                        ERR_ROBOT_DOCS_CORRUPT,
                        "Tombstone object in capabilities.json must contain string id",
                        target="capabilities.json:tombstones",
                    )
                caps_tombstones.add(tid)
            elif isinstance(item, str):
                caps_tombstones.add(item)
            else:
                raise RobotDocsError(
                    ERR_ROBOT_DOCS_CORRUPT,
                    f"Tombstone item in capabilities.json must be str or dict, got {type(item).__name__}",
                    target="capabilities.json:tombstones",
                )

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

        if not isinstance(v["name"], str):
            raise RobotDocsError(
                ERR_ROBOT_DOCS_CORRUPT,
                f"View {v_id} name must be a string, got {type(v['name']).__name__}",
                target=f"views.{v_id}.name",
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
            if sec not in VALID_VIEW_SECTIONS:
                raise RobotDocsError(
                    ERR_ROBOT_DOCS_UNREGISTERED,
                    f"View {v_id} references unregistered section: {sec}",
                    target=f"views.{v_id}.requiredSections",
                )

        v_gate = v["gate"]
        if not isinstance(v_gate, str):
            raise RobotDocsError(
                ERR_ROBOT_DOCS_CORRUPT,
                f"View {v_id} gate must be a string, got {type(v_gate).__name__}",
                target=f"views.{v_id}.gate",
            )
        if v_gate not in valid_gates:
            raise RobotDocsError(
                ERR_ROBOT_DOCS_UNREGISTERED,
                f"View {v_id} references unregistered gate: {v_gate}",
                target=f"views.{v_id}.gate",
            )

        v_status = v["status"]
        if not isinstance(v_status, str):
            raise RobotDocsError(
                ERR_ROBOT_DOCS_CORRUPT,
                f"View {v_id} status must be a string, got {type(v_status).__name__}",
                target=f"views.{v_id}.status",
            )
        if v_status not in valid_statuses:
            raise RobotDocsError(
                ERR_ROBOT_DOCS_UNREGISTERED,
                f"View {v_id} references unregistered status: {v_status}",
                target=f"views.{v_id}.status",
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
        for req_k in [
            "capability", "scope", "plane", "defaultRole",
            "denialReason", "safeAlternative", "generation"
        ]:
            if req_k not in cap or cap[req_k] is None:
                raise RobotDocsError(
                    ERR_ROBOT_DOCS_CORRUPT,
                    f"Capability {c_id} missing required key '{req_k}'",
                    target=f"capabilities.{c_id}.{req_k}",
                )
            if not isinstance(cap[req_k], str) or not cap[req_k].strip():
                raise RobotDocsError(
                    ERR_ROBOT_DOCS_CORRUPT,
                    f"Capability {c_id} field '{req_k}' must be a non-empty string, got {type(cap[req_k]).__name__}",
                    target=f"capabilities.{c_id}.{req_k}",
                )
        if "status" in cap:
            c_status = cap["status"]
            if not isinstance(c_status, str) or c_status not in valid_statuses:
                raise RobotDocsError(
                    ERR_ROBOT_DOCS_UNREGISTERED,
                    f"Capability {c_id} references unregistered status: {c_status}",
                    target=f"capabilities.{c_id}.status",
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

    # Filter out tombstoned, superseded, and deprecated operations so they never render as live
    live_op_ids = [
        op_id for op_id in seen_agent_ops
        if op_id not in fss1_tombstones and agent_ops_by_id[op_id].get("status") not in ("tombstone", "tombstoned")
        and agent_ops_by_id[op_id].get("status") not in ("superseded", "deprecated")
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

        for str_field in ["name", "purpose", "mode", "owner", "defaultView", "inputSchema", "outputSchema", "requestPayloadSchema"]:
            if not isinstance(raw_op[str_field], str) or not raw_op[str_field].strip():
                raise RobotDocsError(
                    ERR_ROBOT_DOCS_CORRUPT,
                    f"Operation {op_id} {str_field} must be a non-empty string, got {raw_op[str_field]!r}",
                    target=f"operations.{op_id}.{str_field}",
                )
        if not isinstance(raw_op["effectful"], bool):
            raise RobotDocsError(
                ERR_ROBOT_DOCS_CORRUPT,
                f"Operation {op_id} effectful must be a bool, got {type(raw_op['effectful']).__name__}",
                target=f"operations.{op_id}.effectful",
            )
        if not isinstance(raw_op["durable"], bool):
            raise RobotDocsError(
                ERR_ROBOT_DOCS_CORRUPT,
                f"Operation {op_id} durable must be a bool, got {type(raw_op['durable']).__name__}",
                target=f"operations.{op_id}.durable",
            )

        # Check required fields in fss1_op
        for fss1_k in [
            "name", "owner", "status", "responseEnvelope", "responsePayloadSchemas",
            "requestEnvelope", "requestPayloadSchema", "defaultView", "cliCommand", "mcpToolName",
            "compatibilityClass",
        ]:
            if fss1_k not in fss1_op or fss1_op[fss1_k] is None:
                raise RobotDocsError(
                    ERR_ROBOT_DOCS_CORRUPT,
                    f"Operation {op_id} missing required key '{fss1_k}' in fss1_public_registry.json",
                    target=f"fss1_public_registry.json:{op_id}.{fss1_k}",
                )

        for str_field in ["name", "owner", "status", "responseEnvelope", "requestEnvelope", "requestPayloadSchema", "defaultView", "cliCommand", "mcpToolName", "compatibilityClass"]:
            if not isinstance(fss1_op[str_field], str) or not fss1_op[str_field].strip():
                raise RobotDocsError(
                    ERR_ROBOT_DOCS_CORRUPT,
                    f"Operation {op_id} {str_field} in fss1 must be a non-empty string, got {fss1_op[str_field]!r}",
                    target=f"fss1_public_registry.json:{op_id}.{str_field}",
                )

        op_compat = fss1_op["compatibilityClass"]
        if op_compat not in VALID_COMPATIBILITY_CLASSES:
            raise RobotDocsError(
                ERR_ROBOT_DOCS_UNREGISTERED,
                f"Operation {op_id} references unregistered compatibility class: {op_compat}",
                target=f"fss1_public_registry.json:{op_id}.compatibilityClass",
            )

        # Check required fields in cw
        for cw_k in [
            "operation_name", "owner", "status", "cli_command", "mcp_tool_name",
            "library_entry_point", "primary_error_id", "error_identities", "exit_identities"
        ]:
            if cw_k not in cw or cw[cw_k] is None:
                raise RobotDocsError(
                    ERR_ROBOT_DOCS_CORRUPT,
                    f"Operation {op_id} missing required key '{cw_k}' in operation_crosswalk.json",
                    target=f"operation_crosswalk.json:{op_id}.{cw_k}",
                )

        for str_field in ["operation_name", "owner", "status", "cli_command", "mcp_tool_name", "library_entry_point", "primary_error_id"]:
            if not isinstance(cw[str_field], str) or not cw[str_field].strip():
                raise RobotDocsError(
                    ERR_ROBOT_DOCS_CORRUPT,
                    f"Operation {op_id} {str_field} in crosswalk must be a non-empty string, got {cw[str_field]!r}",
                    target=f"operation_crosswalk.json:{op_id}.{str_field}",
                )

        # Cross-registry field conflict detection (DRIFT)
        # 1. name
        if raw_op["name"] != fss1_op["name"]:
            raise RobotDocsError(
                ERR_ROBOT_DOCS_DRIFT,
                f"Operation {op_id} name conflict: agent_operations has {raw_op['name']!r}, fss1 has {fss1_op['name']!r}",
                target=f"operations.{op_id}.name",
            )
        if raw_op["name"] != cw["operation_name"]:
            raise RobotDocsError(
                ERR_ROBOT_DOCS_DRIFT,
                f"Operation {op_id} name conflict: agent_operations has {raw_op['name']!r}, crosswalk has {cw['operation_name']!r}",
                target=f"operations.{op_id}.name",
            )

        # 2. owner
        if raw_op["owner"] != fss1_op["owner"]:
            raise RobotDocsError(
                ERR_ROBOT_DOCS_DRIFT,
                f"Operation {op_id} owner conflict: agent_operations has {raw_op['owner']!r}, fss1 has {fss1_op['owner']!r}",
                target=f"operations.{op_id}.owner",
            )
        if raw_op["owner"] != cw["owner"]:
            raise RobotDocsError(
                ERR_ROBOT_DOCS_DRIFT,
                f"Operation {op_id} owner conflict: agent_operations has {raw_op['owner']!r}, crosswalk has {cw['owner']!r}",
                target=f"operations.{op_id}.owner",
            )

        # 3. status
        if raw_op["status"] not in valid_statuses:
            raise RobotDocsError(
                ERR_ROBOT_DOCS_UNREGISTERED,
                f"Operation {op_id} references unregistered status: {raw_op['status']}",
                target=f"operations.{op_id}.status",
            )
        if raw_op["status"] != fss1_op["status"]:
            raise RobotDocsError(
                ERR_ROBOT_DOCS_DRIFT,
                f"Operation {op_id} status conflict: agent_operations has {raw_op['status']!r}, fss1 has {fss1_op['status']!r}",
                target=f"operations.{op_id}.status",
            )
        if raw_op["status"] != cw["status"]:
            raise RobotDocsError(
                ERR_ROBOT_DOCS_DRIFT,
                f"Operation {op_id} status conflict: agent_operations has {raw_op['status']!r}, crosswalk has {cw['status']!r}",
                target=f"operations.{op_id}.status",
            )

        # Validate mode
        if raw_op["mode"] not in valid_modes:
            raise RobotDocsError(
                ERR_ROBOT_DOCS_UNREGISTERED,
                f"Operation {op_id} references unregistered mode: {raw_op['mode']}",
                target=f"operations.{op_id}.mode",
            )

        # 4. responseEnvelope (outputSchema in agent_operations)
        if raw_op["outputSchema"] != fss1_op["responseEnvelope"]:
            raise RobotDocsError(
                ERR_ROBOT_DOCS_DRIFT,
                f"Operation {op_id} responseEnvelope conflict: agent_operations outputSchema has {raw_op['outputSchema']!r}, fss1 has {fss1_op['responseEnvelope']!r}",
                target=f"operations.{op_id}.responseEnvelope",
            )

        # 5. responsePayloadSchemas
        if raw_op["responsePayloadSchemas"] != fss1_op["responsePayloadSchemas"]:
            raise RobotDocsError(
                ERR_ROBOT_DOCS_DRIFT,
                f"Operation {op_id} responsePayloadSchemas conflict: agent_operations has {raw_op['responsePayloadSchemas']!r}, fss1 has {fss1_op['responsePayloadSchemas']!r}",
                target=f"operations.{op_id}.responsePayloadSchemas",
            )

        # 6. requestEnvelope (inputSchema in agent_operations)
        if raw_op["inputSchema"] != fss1_op["requestEnvelope"]:
            raise RobotDocsError(
                ERR_ROBOT_DOCS_DRIFT,
                f"Operation {op_id} requestEnvelope conflict: agent_operations inputSchema has {raw_op['inputSchema']!r}, fss1 has {fss1_op['requestEnvelope']!r}",
                target=f"operations.{op_id}.requestEnvelope",
            )

        # 7. defaultView
        if raw_op["defaultView"] != fss1_op["defaultView"]:
            raise RobotDocsError(
                ERR_ROBOT_DOCS_DRIFT,
                f"Operation {op_id} defaultView conflict: agent_operations has {raw_op['defaultView']!r}, fss1 has {fss1_op['defaultView']!r}",
                target=f"operations.{op_id}.defaultView",
            )

        # 8. requestPayloadSchema
        if raw_op["requestPayloadSchema"] != fss1_op["requestPayloadSchema"]:
            raise RobotDocsError(
                ERR_ROBOT_DOCS_DRIFT,
                f"Operation {op_id} requestPayloadSchema conflict: agent_operations has {raw_op['requestPayloadSchema']!r}, fss1 has {fss1_op['requestPayloadSchema']!r}",
                target=f"operations.{op_id}.requestPayloadSchema",
            )

        # 9. cliCommand
        if fss1_op["cliCommand"] != cw["cli_command"]:
            raise RobotDocsError(
                ERR_ROBOT_DOCS_DRIFT,
                f"Operation {op_id} cliCommand conflict: fss1 has {fss1_op['cliCommand']!r}, crosswalk has {cw['cli_command']!r}",
                target=f"operations.{op_id}.cliCommand",
            )
        cli_cmd = cw["cli_command"]

        # 10. mcpToolName
        if fss1_op["mcpToolName"] != cw["mcp_tool_name"]:
            raise RobotDocsError(
                ERR_ROBOT_DOCS_DRIFT,
                f"Operation {op_id} mcpToolName conflict: fss1 has {fss1_op['mcpToolName']!r}, crosswalk has {cw['mcp_tool_name']!r}",
                target=f"operations.{op_id}.mcpToolName",
            )
        mcp_tool = cw["mcp_tool_name"]

        lib_entry = cw["library_entry_point"]
        primary_err = cw["primary_error_id"]
        error_ids = cw["error_identities"]
        exit_ids = cw["exit_identities"]

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
        if not isinstance(op_gate, str):
            raise RobotDocsError(
                ERR_ROBOT_DOCS_CORRUPT,
                f"Operation {op_id} gate must be a string, got {type(op_gate).__name__}",
                target=f"operations.{op_id}.gate",
            )
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
            if not isinstance(exit_id, str):
                raise RobotDocsError(
                    ERR_ROBOT_DOCS_CORRUPT,
                    f"Operation {op_id} exit identity must be a string, got {type(exit_id).__name__}",
                    target=f"operations.{op_id}.exitIdentities",
                )
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
            if not isinstance(r_cls, str):
                raise RobotDocsError(
                    ERR_ROBOT_DOCS_CORRUPT,
                    f"Operation {op_id} retry class must be a string, got {type(r_cls).__name__}",
                    target=f"operations.{op_id}.retryClasses",
                )
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

        for schema_label, s in [
            ("inputSchema", req_env),
            ("outputSchema", resp_env),
            ("requestPayloadSchema", req_payload),
        ]:
            if not isinstance(s, str) or not s.strip():
                raise RobotDocsError(
                    ERR_ROBOT_DOCS_CORRUPT,
                    f"Operation {op_id} {schema_label} must be a non-empty string, got {s!r}",
                    target=f"operations.{op_id}.{schema_label}",
                )
            if s not in schemas_map:
                raise RobotDocsError(
                    ERR_ROBOT_DOCS_UNREGISTERED,
                    f"Operation {op_id} references unregistered schema: {s}",
                    target=f"operations.{op_id}.schemas",
                )

        if not isinstance(resp_payloads, list) or len(resp_payloads) == 0:
            raise RobotDocsError(
                ERR_ROBOT_DOCS_CORRUPT,
                f"Operation {op_id} responsePayloadSchemas must be a non-empty list, got {type(resp_payloads).__name__}",
                target=f"operations.{op_id}.responsePayloadSchemas",
            )
        for s in resp_payloads:
            if not isinstance(s, str) or not s.strip():
                raise RobotDocsError(
                    ERR_ROBOT_DOCS_CORRUPT,
                    f"Schema in responsePayloadSchemas for {op_id} must be a non-empty string",
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
            if not isinstance(err_id, str):
                raise RobotDocsError(
                    ERR_ROBOT_DOCS_CORRUPT,
                    f"Operation {op_id} error identity must be a string, got {type(err_id).__name__}",
                    target=f"operations.{op_id}.errorIdentities",
                )
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

    # Validate resources structure before sorting
    for raw_res in resources_list:
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

    # Consolidated resources (sorted deterministically by ID)
    consolidated_resources: list[dict[str, Any]] = []
    for raw_res in sorted(resources_list, key=lambda r: r["id"]):
        res_id = raw_res["id"]
        for req_k in ["name", "owner", "uriTemplate", "payloadSchema", "requestEnvelope", "responseEnvelope", "compatibilityClass", "status"]:
            if req_k not in raw_res or raw_res[req_k] is None:
                raise RobotDocsError(
                    ERR_ROBOT_DOCS_CORRUPT,
                    f"Resource {res_id} missing required key '{req_k}'",
                    target=f"resources.{res_id}.{req_k}",
                )

        for str_k in ["name", "owner", "uriTemplate"]:
            if not isinstance(raw_res[str_k], str) or not raw_res[str_k].strip():
                raise RobotDocsError(
                    ERR_ROBOT_DOCS_CORRUPT,
                    f"Resource {res_id} {str_k} must be a non-empty string, got {type(raw_res[str_k]).__name__}",
                    target=f"resources.{res_id}.{str_k}",
                )

        res_req_env = raw_res["requestEnvelope"]
        res_resp_env = raw_res["responseEnvelope"]
        res_payload = raw_res["payloadSchema"]

        for env_k, s in [("requestEnvelope", res_req_env), ("responseEnvelope", res_resp_env)]:
            if not isinstance(s, str) or not s.strip():
                raise RobotDocsError(
                    ERR_ROBOT_DOCS_CORRUPT,
                    f"Resource {res_id} {env_k} must be a non-empty string, got {s!r}",
                    target=f"resources.{res_id}.{env_k}",
                )
            if s not in schemas_map:
                raise RobotDocsError(
                    ERR_ROBOT_DOCS_UNREGISTERED,
                    f"Resource {res_id} references unregistered envelope schema: {s}",
                    target=f"resources.{res_id}.envelopes",
                )

        if not isinstance(res_payload, str) or not res_payload.strip():
            raise RobotDocsError(
                ERR_ROBOT_DOCS_CORRUPT,
                f"Resource {res_id} payloadSchema must be a non-empty string, got {res_payload!r}",
                target=f"resources.{res_id}.payloadSchema",
            )
        if res_payload not in schemas_map:
            raise RobotDocsError(
                ERR_ROBOT_DOCS_UNREGISTERED,
                f"Resource {res_id} references unregistered payload schema: {res_payload}",
                target=f"resources.{res_id}.payloadSchema",
            )

        res_compat = raw_res["compatibilityClass"]
        if not isinstance(res_compat, str) or res_compat not in VALID_COMPATIBILITY_CLASSES:
            raise RobotDocsError(
                ERR_ROBOT_DOCS_UNREGISTERED,
                f"Resource {res_id} references unregistered compatibility class: {res_compat}",
                target=f"resources.{res_id}.compatibilityClass",
            )

        res_status = raw_res["status"]
        if not isinstance(res_status, str) or res_status not in valid_statuses:
            raise RobotDocsError(
                ERR_ROBOT_DOCS_UNREGISTERED,
                f"Resource {res_id} references unregistered status: {res_status}",
                target=f"resources.{res_id}.status",
            )

        consolidated_resources.append({
            "id": res_id,
            "name": raw_res["name"],
            "owner": raw_res["owner"],
            "uriTemplate": raw_res["uriTemplate"],
            "requestEnvelope": res_req_env,
            "responseEnvelope": res_resp_env,
            "payloadSchema": res_payload,
            "compatibilityClass": res_compat,
            "status": res_status,
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
            "denialReason": cap["denialReason"],
            "safeAlternative": cap["safeAlternative"],
            "generation": cap["generation"],
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
        f"The complete suite of {len(model['operations'])} canonical agent control plane operations under `fss/1`:",
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
    scan_for_secrets(md, "generated:ROBOT_DOCS.md")
    scan_for_secrets(json_str, "generated:ROBOT_DOCS.json")
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
        "--verify",
        dest="check",
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

    output_dir.mkdir(parents=True, exist_ok=True)
    md_path.write_text(expected_md, encoding="utf-8")
    json_path.write_text(expected_json, encoding="utf-8")
    print(f"Successfully generated robot docs at {md_path} and {json_path}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
