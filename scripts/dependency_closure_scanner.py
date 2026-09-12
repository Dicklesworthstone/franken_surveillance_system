#!/usr/bin/env python3
"""Deterministic dependency-closure scanner against allowlist v2 (fss-x4a.26.1 / FSS-181).

Enforces the dependency-closure doctrine from AGENTS.md, docs/DEPENDENCY_CONSTITUTION.md,
and architecture/dependency_allowlist.toml:
- Closed universe: every crate in resolved dependency closure must be allowlisted.
- Full closure enumeration from Cargo.lock and cargo metadata across all targets,
  features, build-dependencies, and dev-dependencies.
- Fail closed with typed error codes on:
  * unallowlisted crates (ERR-DEP-CLOSURE-UNALLOWLISTED-CRATE-001)
  * forbidden crates (ERR-DEP-CLOSURE-FORBIDDEN-CRATE-001)
  * version or source mismatches (ERR-DEP-CLOSURE-VERSION-SOURCE-MISMATCH-001)
  * unallowlisted git or escaping path dependencies (ERR-DEP-CLOSURE-UNALLOWLISTED-SOURCE-001)
  * unreadable metadata or missing/malformed lockfile (ERR-DEP-CLOSURE-METADATA-UNREADABLE-001)
  * empty or degenerate allowlist (ERR-DEP-CLOSURE-EMPTY-ALLOWLIST-001)
- Honest reporting of declared-but-unresolved runtime: Cargo.toml names sole_async_runtime = "asupersync",
  reported honestly (STATUS-DEP-CLOSURE-DECLARED-RUNTIME-UNRESOLVED-001) and never silently passed.
"""

from __future__ import annotations

import argparse
import fnmatch
import json
import os
import re
import shutil
import subprocess
import sys
import tomllib
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]

# Typed diagnostic codes
ERR_UNALLOWLISTED_CRATE = "ERR-DEP-CLOSURE-UNALLOWLISTED-CRATE-001"
ERR_FORBIDDEN_CRATE = "ERR-DEP-CLOSURE-FORBIDDEN-CRATE-001"
ERR_VERSION_SOURCE_MISMATCH = "ERR-DEP-CLOSURE-VERSION-SOURCE-MISMATCH-001"
ERR_UNALLOWLISTED_SOURCE = "ERR-DEP-CLOSURE-UNALLOWLISTED-SOURCE-001"
ERR_METADATA_UNREADABLE = "ERR-DEP-CLOSURE-METADATA-UNREADABLE-001"
ERR_EMPTY_ALLOWLIST = "ERR-DEP-CLOSURE-EMPTY-ALLOWLIST-001"
ERR_DECLARED_RUNTIME_UNRESOLVED = "ERR-DEP-CLOSURE-DECLARED-RUNTIME-UNRESOLVED-001"
STATUS_DECLARED_RUNTIME_UNRESOLVED = "STATUS-DEP-CLOSURE-DECLARED-RUNTIME-UNRESOLVED-001"
ERR_DJI_SDK_DEPENDENCY_FORBIDDEN = "ERR-DEP-CLOSURE-DJI-SDK-FORBIDDEN-001"
ERR_ADAPTER_DJI_SDK_FORBIDDEN = "ERR-ADAPTER-REGISTRY-DJI-SDK-FORBIDDEN-001"
ERR_ADAPTER_REGISTRY_UNREADABLE = "ERR-ADAPTER-REGISTRY-UNREADABLE-001"

DIAGNOSTIC_REGISTRY: dict[str, dict[str, str]] = {
    ERR_DJI_SDK_DEPENDENCY_FORBIDDEN: {
        "trigger": "A crate or dependency in the closure or allowlist declares or implies DJI Mobile/Flip SDK support, violating negative-evidence constraint NEG-001",
        "remediation": "Remove the prohibited DJI SDK dependency; FSS has no architectural dependency on unestablished DJI Mobile SDK",
        "standard_code": "NEG-001",
    },
    ERR_ADAPTER_DJI_SDK_FORBIDDEN: {
        "trigger": "A device adapter registry entry declares or implies DJI Flip Mobile SDK support or streaming readiness, violating negative-evidence constraint NEG-001",
        "remediation": "Constrain DJI Flip adapter entry to manual capture/import lab under GATE-100 without declaring Mobile SDK support or streaming",
        "standard_code": "NEG-001",
    },
    ERR_ADAPTER_REGISTRY_UNREADABLE: {
        "trigger": "Device adapter registry file registries/DEVICE_ADAPTERS.md is missing, unreadable, or contains no valid table rows",
        "remediation": "Ensure registries/DEVICE_ADAPTERS.md exists, is readable, and contains the registered adapter definitions",
        "standard_code": "DEP-AUD-001",
    },
    ERR_UNALLOWLISTED_CRATE: {
        "trigger": "A crate in the resolved dependency closure is outside the registered allowlist",
        "remediation": "Remove the unallowlisted dependency or obtain reviewed constitutional ADR admission with closure proof",
        "standard_code": "DEP-AUD-016",
    },
    ERR_FORBIDDEN_CRATE: {
        "trigger": "A crate in the resolved dependency closure is explicitly forbidden by dependency constitution or is an excluded oracle in production",
        "remediation": "Remove the forbidden crate from all workspace members and transitive dependencies; FSS allows no exceptions",
        "standard_code": "DEP-AUD-030",
    },
    ERR_VERSION_SOURCE_MISMATCH: {
        "trigger": "A package version or source mismatch detected between Cargo.lock and cargo metadata, or git revision is not a 40-hex commit",
        "remediation": "Run cargo update/metadata in locked offline mode to synchronize Cargo.lock with workspace manifests and pin exact 40-hex commit hashes",
        "standard_code": "DEP-AUD-033",
    },
    ERR_UNALLOWLISTED_SOURCE: {
        "trigger": "A git repository or path dependency is not allowlisted or escapes the workspace/sibling closure boundary",
        "remediation": "Admit the source in allowlist or move path dependency inside the verified repository or sibling closure",
        "standard_code": "DEP-AUD-012",
    },
    ERR_METADATA_UNREADABLE: {
        "trigger": "cargo metadata --offline failed, or Cargo.lock / Cargo.toml is missing, unreadable, or malformed",
        "remediation": "Ensure Cargo.toml and Cargo.lock are valid, parseable, and offline metadata generation succeeds",
        "standard_code": "DEP-AUD-040",
    },
    ERR_EMPTY_ALLOWLIST: {
        "trigger": "The dependency allowlist file is missing, empty, malformed, or contains zero allowed crate families",
        "remediation": "Restore a valid architecture/dependency_allowlist.toml with schema and allowed families/crates",
        "standard_code": "DEP-AUD-001",
    },
    ERR_DECLARED_RUNTIME_UNRESOLVED: {
        "trigger": "The declared sole async runtime is required to be resolved, but is absent from Cargo.lock / metadata",
        "remediation": "Add the declared async runtime to workspace dependencies and resolve it in Cargo.lock",
        "standard_code": "DEP-AUD-001",
    },
    STATUS_DECLARED_RUNTIME_UNRESOLVED: {
        "trigger": "Cargo.toml declares sole_async_runtime but it is not yet resolved in Cargo.lock",
        "remediation": "Informational/warning: ensure the declared runtime is introduced via audited dependency admission when ready",
        "standard_code": "DEP-AUD-001",
    },
}

DEFAULT_ALLOWED_GIT_PREFIXES = (
    "https://github.com/Dicklesworthstone/",
)


@dataclass(frozen=True)
class ClosureFinding:
    code: str
    file: str
    location: str
    message: str
    severity: str = "error"
    remediation: str = ""
    params: dict[str, Any] = field(default_factory=dict)


def sanitize_path(path: Path | str, root: Path) -> str:
    """Returns a forward-slash normalized relative path string."""
    try:
        rel = Path(path).resolve().relative_to(root.resolve())
        return str(rel).replace("\\", "/")
    except ValueError:
        return str(path).replace("\\", "/")


def is_forbidden_dji_sdk(name: str) -> bool:
    """True if crate or dependency name declares or implies DJI Mobile/Flip SDK (NEG-001)."""
    lower = name.lower()
    if (
        ("dji" in lower and ("sdk" in lower or "mobile" in lower or "flip" in lower or "msdk" in lower))
        or ("flip" in lower and ("sdk" in lower or "msdk" in lower))
        or lower in ("msdk", "dji-sdk", "dji_sdk", "dji-mobile-sdk", "dji_mobile_sdk")
    ):
        return True
    return False


def audit_adapter_registry(adapter_path: Path, root: Path) -> list[ClosureFinding]:
    """Audits device adapter registry (registries/DEVICE_ADAPTERS.md) against negative constraints (NEG-001)."""
    findings: list[ClosureFinding] = []
    rel_path = sanitize_path(adapter_path, root)

    if not adapter_path.is_file():
        findings.append(
            ClosureFinding(
                code=ERR_ADAPTER_REGISTRY_UNREADABLE,
                file=rel_path,
                location="file",
                message=f"Device adapter registry file not found: {rel_path}",
                severity="error",
                remediation=DIAGNOSTIC_REGISTRY[ERR_ADAPTER_REGISTRY_UNREADABLE]["remediation"],
            )
        )
        return findings

    try:
        content = adapter_path.read_text(encoding="utf-8")
    except OSError as exc:
        findings.append(
            ClosureFinding(
                code=ERR_ADAPTER_REGISTRY_UNREADABLE,
                file=rel_path,
                location="read",
                message=f"Could not read device adapter registry: {exc}",
                severity="error",
                remediation=DIAGNOSTIC_REGISTRY[ERR_ADAPTER_REGISTRY_UNREADABLE]["remediation"],
            )
        )
        return findings

    if not content.strip():
        findings.append(
            ClosureFinding(
                code=ERR_ADAPTER_REGISTRY_UNREADABLE,
                file=rel_path,
                location="content",
                message="Device adapter registry is empty (0 bytes)",
                severity="error",
                remediation=DIAGNOSTIC_REGISTRY[ERR_ADAPTER_REGISTRY_UNREADABLE]["remediation"],
            )
        )
        return findings

    rows: list[list[str]] = []
    for line in content.splitlines():
        stripped = line.strip()
        if stripped.startswith("|") and stripped.endswith("|"):
            cells = [c.strip().strip("`") for c in stripped.split("|")[1:-1]]
            if cells and not all(re.match(r"^:?-+:?$", c) for c in cells):
                rows.append(cells)

    if len(rows) < 2:
        findings.append(
            ClosureFinding(
                code=ERR_ADAPTER_REGISTRY_UNREADABLE,
                file=rel_path,
                location="content",
                message="Device adapter registry contains no valid table rows",
                severity="error",
                remediation=DIAGNOSTIC_REGISTRY[ERR_ADAPTER_REGISTRY_UNREADABLE]["remediation"],
            )
        )
        return findings

    for row in rows[1:]:
        if not row:
            continue
        adapter_id = row[0]
        row_text = " ".join(row).lower()

        if "dji" in row_text or "flip" in row_text:
            is_explicit_non_sdk = bool(re.search(r"\b(non[-_ ]*sdk|no[-_ ]*sdk)\b", row_text))
            has_sdk = not is_explicit_non_sdk and (
                bool(re.search(r"\bmobile[-_ ]*sdk\b", row_text))
                or bool(re.search(r"\bmsdk\b", row_text))
                or bool(re.search(r"\bsdk\b", row_text))
                or "msdk" in row_text
            )
            if has_sdk:
                findings.append(
                    ClosureFinding(
                        code=ERR_ADAPTER_DJI_SDK_FORBIDDEN,
                        file=rel_path,
                        location=f"row.{adapter_id}",
                        message=(
                            f"Adapter registry entry '{adapter_id}' declares or implies DJI Mobile SDK support: "
                            f"'{' | '.join(row)}', violating NEG-001"
                        ),
                        severity="error",
                        remediation=DIAGNOSTIC_REGISTRY[ERR_ADAPTER_DJI_SDK_FORBIDDEN]["remediation"],
                        params={"adapter_id": adapter_id, "row": row},
                    )
                )
            if any(term in row_text for term in ("streaming", "live stream", "live capture", "live feed", "rtsp")):
                findings.append(
                    ClosureFinding(
                        code=ERR_ADAPTER_DJI_SDK_FORBIDDEN,
                        file=rel_path,
                        location=f"row.{adapter_id}",
                        message=(
                            f"Adapter registry entry '{adapter_id}' claims production streaming for DJI Flip: "
                            f"'{' | '.join(row)}', violating NEG-001 (manual capture/import lab only)"
                        ),
                        severity="error",
                        remediation=DIAGNOSTIC_REGISTRY[ERR_ADAPTER_DJI_SDK_FORBIDDEN]["remediation"],
                        params={"adapter_id": adapter_id, "row": row},
                    )
                )
            current_state = row[3].lower() if len(row) > 3 else ""
            if any(term in current_state for term in ("ready", "qualified", "streaming", "accepted", "production", "implemented", "verified")):
                findings.append(
                    ClosureFinding(
                        code=ERR_ADAPTER_DJI_SDK_FORBIDDEN,
                        file=rel_path,
                        location=f"row.{adapter_id}",
                        message=(
                            f"Adapter registry entry '{adapter_id}' claims readiness for unestablished DJI Flip: "
                            f"'{' | '.join(row)}', violating NEG-001"
                        ),
                        severity="error",
                        remediation=DIAGNOSTIC_REGISTRY[ERR_ADAPTER_DJI_SDK_FORBIDDEN]["remediation"],
                        params={"adapter_id": adapter_id, "row": row},
                    )
                )

    return findings


def load_allowlist(allowlist_path: Path, root: Path) -> tuple[dict[str, Any] | None, list[ClosureFinding]]:
    """Loads and validates architecture/dependency_allowlist.toml."""
    findings: list[ClosureFinding] = []
    rel_path = sanitize_path(allowlist_path, root)

    if not allowlist_path.is_file():
        findings.append(
            ClosureFinding(
                code=ERR_EMPTY_ALLOWLIST,
                file=rel_path,
                location="file",
                message=f"Dependency allowlist file not found: {rel_path}",
                severity="error",
                remediation=DIAGNOSTIC_REGISTRY[ERR_EMPTY_ALLOWLIST]["remediation"],
            )
        )
        return None, findings

    try:
        content = allowlist_path.read_text(encoding="utf-8")
    except OSError as exc:
        findings.append(
            ClosureFinding(
                code=ERR_EMPTY_ALLOWLIST,
                file=rel_path,
                location="read",
                message=f"Could not read dependency allowlist: {exc}",
                severity="error",
                remediation=DIAGNOSTIC_REGISTRY[ERR_EMPTY_ALLOWLIST]["remediation"],
            )
        )
        return None, findings

    if not content.strip():
        findings.append(
            ClosureFinding(
                code=ERR_EMPTY_ALLOWLIST,
                file=rel_path,
                location="content",
                message="Dependency allowlist is empty (0 bytes)",
                severity="error",
                remediation=DIAGNOSTIC_REGISTRY[ERR_EMPTY_ALLOWLIST]["remediation"],
            )
        )
        return None, findings

    try:
        data = tomllib.loads(content)
    except tomllib.TOMLDecodeError as exc:
        findings.append(
            ClosureFinding(
                code=ERR_EMPTY_ALLOWLIST,
                file=rel_path,
                location="toml_syntax",
                message=f"Dependency allowlist contains invalid TOML: {exc}",
                severity="error",
                remediation=DIAGNOSTIC_REGISTRY[ERR_EMPTY_ALLOWLIST]["remediation"],
            )
        )
        return None, findings

    schema = data.get("schema", "")
    if not isinstance(schema, str) or not schema.startswith("fss.dependency_allowlist."):
        findings.append(
            ClosureFinding(
                code=ERR_EMPTY_ALLOWLIST,
                file=rel_path,
                location="schema",
                message=f"Dependency allowlist schema mismatch: expected 'fss.dependency_allowlist.v*', found '{schema}'",
                severity="error",
                remediation=DIAGNOSTIC_REGISTRY[ERR_EMPTY_ALLOWLIST]["remediation"],
            )
        )
        return None, findings

    policy = data.get("policy")
    if not isinstance(policy, dict):
        findings.append(
            ClosureFinding(
                code=ERR_EMPTY_ALLOWLIST,
                file=rel_path,
                location="policy",
                message="Dependency allowlist lacks required [policy] table",
                severity="error",
                remediation=DIAGNOSTIC_REGISTRY[ERR_EMPTY_ALLOWLIST]["remediation"],
            )
        )
        return None, findings

    allowed_families = data.get("in_house", {}).get("allowed_families", [])
    allowed_fundamental = data.get("fundamental", {}).get("allowed_subject_to_audit", [])
    if not allowed_families and not allowed_fundamental:
        findings.append(
            ClosureFinding(
                code=ERR_EMPTY_ALLOWLIST,
                file=rel_path,
                location="allowed_families",
                message="Dependency allowlist is degenerate: both allowed_families and allowed_subject_to_audit are empty",
                severity="error",
                remediation=DIAGNOSTIC_REGISTRY[ERR_EMPTY_ALLOWLIST]["remediation"],
            )
        )
        return None, findings

    return data, findings


def parse_cargo_lock(lock_path: Path, root: Path) -> tuple[dict[str, list[dict[str, Any]]] | None, list[ClosureFinding]]:
    """Loads and parses Cargo.lock, returning packages mapped by package name."""
    findings: list[ClosureFinding] = []
    rel_path = sanitize_path(lock_path, root)

    if not lock_path.is_file():
        findings.append(
            ClosureFinding(
                code=ERR_METADATA_UNREADABLE,
                file=rel_path,
                location="file",
                message=f"Required Cargo.lock not found: {rel_path}",
                severity="error",
                remediation=DIAGNOSTIC_REGISTRY[ERR_METADATA_UNREADABLE]["remediation"],
            )
        )
        return None, findings

    try:
        content = lock_path.read_text(encoding="utf-8")
    except OSError as exc:
        findings.append(
            ClosureFinding(
                code=ERR_METADATA_UNREADABLE,
                file=rel_path,
                location="read",
                message=f"Could not read Cargo.lock: {exc}",
                severity="error",
                remediation=DIAGNOSTIC_REGISTRY[ERR_METADATA_UNREADABLE]["remediation"],
            )
        )
        return None, findings

    try:
        data = tomllib.loads(content)
    except tomllib.TOMLDecodeError as exc:
        findings.append(
            ClosureFinding(
                code=ERR_METADATA_UNREADABLE,
                file=rel_path,
                location="toml_syntax",
                message=f"Cargo.lock contains invalid TOML: {exc}",
                severity="error",
                remediation=DIAGNOSTIC_REGISTRY[ERR_METADATA_UNREADABLE]["remediation"],
            )
        )
        return None, findings

    packages = data.get("package", [])
    if not isinstance(packages, list):
        findings.append(
            ClosureFinding(
                code=ERR_METADATA_UNREADABLE,
                file=rel_path,
                location="structure",
                message="Cargo.lock [[package]] table missing or not a list",
                severity="error",
                remediation=DIAGNOSTIC_REGISTRY[ERR_METADATA_UNREADABLE]["remediation"],
            )
        )
        return None, findings

    pkg_map: dict[str, list[dict[str, Any]]] = {}
    for pkg in packages:
        if isinstance(pkg, dict):
            name = pkg.get("name")
            if isinstance(name, str):
                pkg_map.setdefault(name, []).append(pkg)

    return pkg_map, findings


def parse_root_manifest(
    manifest_path: Path, root: Path
) -> tuple[dict[str, Any] | None, set[str], str | None, dict[str, Any], list[ClosureFinding]]:
    """Loads root Cargo.toml, extracts workspace members, declared async runtime, and workspace dependencies."""
    findings: list[ClosureFinding] = []
    rel_path = sanitize_path(manifest_path, root)

    if not manifest_path.is_file():
        findings.append(
            ClosureFinding(
                code=ERR_METADATA_UNREADABLE,
                file=rel_path,
                location="file",
                message=f"Required workspace root manifest not found: {rel_path}",
                severity="error",
                remediation=DIAGNOSTIC_REGISTRY[ERR_METADATA_UNREADABLE]["remediation"],
            )
        )
        return None, set(), None, {}, findings

    try:
        content = manifest_path.read_text(encoding="utf-8")
        data = tomllib.loads(content)
    except (OSError, tomllib.TOMLDecodeError) as exc:
        findings.append(
            ClosureFinding(
                code=ERR_METADATA_UNREADABLE,
                file=rel_path,
                location="read",
                message=f"Could not read or parse workspace manifest: {exc}",
                severity="error",
                remediation=DIAGNOSTIC_REGISTRY[ERR_METADATA_UNREADABLE]["remediation"],
            )
        )
        return None, set(), None, {}, findings

    member_names: set[str] = set()
    ws_members = data.get("workspace", {}).get("members", [])
    if isinstance(ws_members, list):
        for member in ws_members:
            if isinstance(member, str):
                member_manifest = root / member / "Cargo.toml"
                if member_manifest.is_file():
                    try:
                        m_data = tomllib.loads(member_manifest.read_text(encoding="utf-8"))
                        m_name = m_data.get("package", {}).get("name")
                        if isinstance(m_name, str):
                            member_names.add(m_name)
                    except (OSError, tomllib.TOMLDecodeError) as exc:
                        findings.append(
                            ClosureFinding(
                                code=ERR_METADATA_UNREADABLE,
                                file=sanitize_path(member_manifest, root),
                                location="read",
                                message=f"Workspace member manifest is unreadable or malformed: {exc}",
                                severity="error",
                                remediation=DIAGNOSTIC_REGISTRY[ERR_METADATA_UNREADABLE]["remediation"],
                            )
                        )
                else:
                    findings.append(
                        ClosureFinding(
                            code=ERR_METADATA_UNREADABLE,
                            file=sanitize_path(member_manifest, root),
                            location="file",
                            message=f"Workspace member manifest not found: {member_manifest}",
                            severity="error",
                            remediation=DIAGNOSTIC_REGISTRY[ERR_METADATA_UNREADABLE]["remediation"],
                        )
                    )

    # Single-crate package root fallback
    pkg_name = data.get("package", {}).get("name")
    if isinstance(pkg_name, str) and not member_names:
        member_names.add(pkg_name)

    declared_runtime = data.get("workspace", {}).get("metadata", {}).get("fss", {}).get("sole_async_runtime")
    if declared_runtime is not None and not isinstance(declared_runtime, str):
        declared_runtime = None

    workspace_dependencies = data.get("workspace", {}).get("dependencies", {})
    if not isinstance(workspace_dependencies, dict):
        workspace_dependencies = {}

    return data, member_names, declared_runtime, workspace_dependencies, findings


def run_cargo_metadata(root: Path, manifest_path: Path) -> tuple[dict[str, Any] | None, str | None]:
    """Invokes `cargo metadata --locked --offline --all-features --format-version 1` strictly without unlocked fallback."""
    cmd_locked = [
        "cargo",
        "metadata",
        "--locked",
        "--offline",
        "--all-features",
        "--format-version",
        "1",
        "--manifest-path",
        str(manifest_path),
    ]

    proc = subprocess.run(cmd_locked, cwd=root, capture_output=True, text=True)
    if proc.returncode != 0:
        toolchain_file = root / "rust-toolchain.toml"
        rustup_exc: Exception | None = None
        if toolchain_file.is_file() and shutil.which("rustup"):
            try:
                tc_data = tomllib.loads(toolchain_file.read_text(encoding="utf-8"))
                channel = tc_data.get("toolchain", {}).get("channel")
                if channel:
                    rustup_cmd = ["rustup", "run", channel] + cmd_locked
                    proc = subprocess.run(rustup_cmd, cwd=root, capture_output=True, text=True)
            except (OSError, tomllib.TOMLDecodeError, subprocess.SubprocessError) as exc:
                rustup_exc = exc

    if proc.returncode != 0:
        base_err = proc.stderr.strip() or proc.stdout.strip() or f"cargo metadata --locked failed with exit code {proc.returncode}"
        locked_err = f"{base_err} (rustup fallback error: {rustup_exc})" if rustup_exc else base_err
        # When --locked fails (e.g. lockfile drift), attempt unlocked to obtain package metadata
        # for downstream checks, but return locked_err so audit_dependency_closure always emits
        # ERR_METADATA_UNREADABLE and fails closed.
        cmd_unlocked = [
            "cargo",
            "metadata",
            "--offline",
            "--all-features",
            "--format-version",
            "1",
            "--manifest-path",
            str(manifest_path),
        ]
        proc_unlocked = subprocess.run(cmd_unlocked, cwd=root, capture_output=True, text=True)
        if proc_unlocked.returncode == 0:
            try:
                data = json.loads(proc_unlocked.stdout)
                if isinstance(data, dict):
                    return data, f"Lockfile drift detected: cargo metadata --locked failed: {locked_err}"
            except json.JSONDecodeError:
                pass
        return None, locked_err

    try:
        data = json.loads(proc.stdout)
        if not isinstance(data, dict):
            return None, "cargo metadata root must be a JSON object"
        return data, None
    except json.JSONDecodeError as exc:
        return None, f"cargo metadata output is invalid JSON: {exc}"


def scan_manifest_dependencies(
    manifest_path: Path,
    root: Path,
    allowed_git_prefixes: tuple[str, ...],
    sibling_root: Path | None = None,
) -> list[ClosureFinding]:
    """Directly inspects manifest dependency tables (dependencies, dev-dependencies, build-dependencies,

    target-specific tables) for untrusted git hosts and escaping path dependencies.
    """
    findings: list[ClosureFinding] = []
    if not manifest_path.is_file():
        return findings

    try:
        data = tomllib.loads(manifest_path.read_text(encoding="utf-8"))
    except (OSError, tomllib.TOMLDecodeError):
        # Already reported
        return findings

    rel_manifest = sanitize_path(manifest_path, root)
    dep_tables: list[tuple[str, dict[str, Any]]] = []

    for section in ("dependencies", "dev-dependencies", "build-dependencies"):
        tbl = data.get(section)
        if isinstance(tbl, dict):
            dep_tables.append((section, tbl))

    targets = data.get("target")
    if isinstance(targets, dict):
        for target_cfg, target_data in targets.items():
            if isinstance(target_data, dict):
                for section in ("dependencies", "dev-dependencies", "build-dependencies"):
                    tbl = target_data.get(section)
                    if isinstance(tbl, dict):
                        dep_tables.append((f"target.{target_cfg}.{section}", tbl))

    for section_name, table in dep_tables:
        for dep_name, dep_spec in table.items():
            package_name = dep_name
            if isinstance(dep_spec, dict) and "package" in dep_spec:
                package_name = str(dep_spec["package"])
            if is_forbidden_dji_sdk(dep_name) or is_forbidden_dji_sdk(package_name):
                findings.append(
                    ClosureFinding(
                        code=ERR_DJI_SDK_DEPENDENCY_FORBIDDEN,
                        file=rel_manifest,
                        location=f"{section_name}.{dep_name}",
                        message=f"DJI Mobile SDK dependency '{dep_name}' (package '{package_name}') in '{rel_manifest}' is forbidden by NEG-001",
                        severity="error",
                        remediation=DIAGNOSTIC_REGISTRY[ERR_DJI_SDK_DEPENDENCY_FORBIDDEN]["remediation"],
                        params={"dependency": dep_name, "package": package_name, "file": rel_manifest},
                    )
                )
            if isinstance(dep_spec, dict):
                if "git" in dep_spec:
                    git_url = str(dep_spec["git"])
                    if not any(git_url.startswith(prefix) for prefix in allowed_git_prefixes):
                        findings.append(
                            ClosureFinding(
                                code=ERR_UNALLOWLISTED_SOURCE,
                                file=rel_manifest,
                                location=f"{section_name}.{dep_name}",
                                message=f"Git dependency '{dep_name}' in '{rel_manifest}' points to unallowlisted host/repository: {git_url}",
                                severity="error",
                                remediation=DIAGNOSTIC_REGISTRY[ERR_UNALLOWLISTED_SOURCE]["remediation"],
                                params={"dependency": dep_name, "git": git_url, "file": rel_manifest},
                            )
                        )
                    if "rev" in dep_spec:
                        rev = str(dep_spec["rev"])
                        if not (len(rev) == 40 and all(c in "0123456789abcdefABCDEF" for c in rev)):
                            findings.append(
                                ClosureFinding(
                                    code=ERR_VERSION_SOURCE_MISMATCH,
                                    file=rel_manifest,
                                    location=f"{section_name}.{dep_name}",
                                    message=f"Git dependency '{dep_name}' revision '{rev}' in '{rel_manifest}' lacks an exact 40-hex commit hash",
                                    severity="error",
                                    remediation=DIAGNOSTIC_REGISTRY[ERR_VERSION_SOURCE_MISMATCH]["remediation"],
                                    params={"dependency": dep_name, "rev": rev, "file": rel_manifest},
                                )
                            )

                if "path" in dep_spec:
                    path_val = dep_spec["path"]
                    try:
                        resolved_p = (manifest_path.parent / path_val).resolve()
                        in_ws = False
                        try:
                            resolved_p.relative_to(root.resolve())
                            in_ws = True
                        except ValueError:
                            in_ws = False

                        if not in_ws:
                            in_sib = False
                            if sibling_root:
                                try:
                                    resolved_p.relative_to(sibling_root)
                                    in_sib = True
                                except ValueError:
                                    in_sib = False
                            if not in_sib:
                                findings.append(
                                    ClosureFinding(
                                        code=ERR_UNALLOWLISTED_SOURCE,
                                        file=rel_manifest,
                                        location=f"{section_name}.{dep_name}",
                                        message=f"Path dependency '{dep_name}' in '{rel_manifest}' escapes repository boundary: {path_val}",
                                        severity="error",
                                        remediation=DIAGNOSTIC_REGISTRY[ERR_UNALLOWLISTED_SOURCE]["remediation"],
                                        params={"dependency": dep_name, "path": path_val, "file": rel_manifest},
                                    )
                                )
                    except (OSError, ValueError) as exc:
                        findings.append(
                            ClosureFinding(
                                code=ERR_UNALLOWLISTED_SOURCE,
                                file=rel_manifest,
                                location=f"{section_name}.{dep_name}",
                                message=f"Path resolution failed for dependency '{dep_name}' in '{rel_manifest}': {exc}",
                                severity="error",
                                remediation=DIAGNOSTIC_REGISTRY[ERR_UNALLOWLISTED_SOURCE]["remediation"],
                                params={"dependency": dep_name, "error": str(exc), "file": rel_manifest},
                            )
                        )
    features = data.get("features")
    if isinstance(features, dict):
        for feat_name, feat_targets in features.items():
            if is_forbidden_dji_sdk(feat_name):
                findings.append(
                    ClosureFinding(
                        code=ERR_DJI_SDK_DEPENDENCY_FORBIDDEN,
                        file=rel_manifest,
                        location=f"features.{feat_name}",
                        message=f"Feature '{feat_name}' in '{rel_manifest}' declares or implies forbidden DJI SDK",
                        severity="error",
                        remediation=DIAGNOSTIC_REGISTRY[ERR_DJI_SDK_DEPENDENCY_FORBIDDEN]["remediation"],
                        params={"feature": feat_name, "file": rel_manifest},
                    )
                )
            if isinstance(feat_targets, list):
                for target in feat_targets:
                    if isinstance(target, str):
                        target_clean = target.removeprefix("dep:").split("/")[0]
                        if is_forbidden_dji_sdk(target_clean):
                            findings.append(
                                ClosureFinding(
                                    code=ERR_DJI_SDK_DEPENDENCY_FORBIDDEN,
                                    file=rel_manifest,
                                    location=f"features.{feat_name}",
                                    message=f"Feature '{feat_name}' target '{target}' in '{rel_manifest}' declares or implies forbidden DJI SDK",
                                    severity="error",
                                    remediation=DIAGNOSTIC_REGISTRY[ERR_DJI_SDK_DEPENDENCY_FORBIDDEN]["remediation"],
                                    params={"feature": feat_name, "target": target, "file": rel_manifest},
                                )
                            )

    return findings


def audit_dependency_closure(
    root: Path = ROOT,
    allowlist_path: Path | None = None,
    manifest_path: Path | None = None,
    lock_path: Path | None = None,
    adapter_path: Path | None = None,
    require_resolved_runtime: bool = True,
    allow_unresolved_runtime: bool = False,
) -> tuple[bool, list[ClosureFinding], dict[str, Any]]:
    """Performs the complete dependency closure audit against registered allowlist v2."""
    findings: list[ClosureFinding] = []

    target_allowlist = allowlist_path or (root / "architecture/dependency_allowlist.toml")
    target_manifest = manifest_path or (root / "Cargo.toml")
    target_lock = lock_path or (root / "Cargo.lock")
    target_adapter = adapter_path or (root / "registries/DEVICE_ADAPTERS.md")

    # 0. Audit adapter registry against negative constraints (NEG-001)
    findings.extend(audit_adapter_registry(target_adapter, root))

    summary: dict[str, Any] = {
        "status": "fail",
        "error_count": 0,
        "warning_count": 0,
        "package_count": 0,
        "workspace_member_count": 0,
        "external_dependency_count": 0,
        "declared_runtime": None,
        "declared_runtime_resolved": False,
        "declared_runtime_status": "not_declared",
    }

    # 1. Load allowlist
    allowlist_data, allowlist_findings = load_allowlist(target_allowlist, root)
    findings.extend(allowlist_findings)
    if allowlist_data is None:
        summary["error_count"] = sum(1 for f in findings if f.severity == "error")
        summary["warning_count"] = sum(1 for f in findings if f.severity == "warning")
        return False, findings, summary

    policy = allowlist_data.get("policy", {})
    allowed_families = list(allowlist_data.get("in_house", {}).get("allowed_families", []))
    allowed_fundamental = set(allowlist_data.get("fundamental", {}).get("allowed_subject_to_audit", []))
    forbidden_crates = set(allowlist_data.get("forbidden", {}).get("crates", []))
    oracle_crates = set(allowlist_data.get("laboratory_oracles", {}).get("excluded_from_production_release_closure", []))
    exception_candidates = set(
        allowlist_data.get("exception_candidates", {}).get("not_admitted_without_dep_record_adr_and_release_evidence", [])
    )
    admitted_exceptions = set(allowlist_data.get("admitted_exceptions", {}).get("crates", []))
    allowed_git_prefixes = tuple(
        allowlist_data.get("sources", {}).get("allowed_git", DEFAULT_ALLOWED_GIT_PREFIXES)
    )
    sibling_root_env = os.environ.get("FSS_DSR_SIBLING_ROOT")
    sibling_root = Path(sibling_root_env).resolve() if sibling_root_env else None

    # Helper function to test allowlist admission
    def is_crate_allowlisted(name: str) -> bool:
        if name in allowed_fundamental:
            return True
        if name in admitted_exceptions:
            return True
        for pat in allowed_families:
            if fnmatch.fnmatchcase(name, pat):
                return True
        return False

    # 2. Parse root manifest
    manifest_data, workspace_members, manifest_runtime, workspace_deps, manifest_findings = parse_root_manifest(target_manifest, root)
    findings.extend(manifest_findings)
    if manifest_data is None:
        summary["error_count"] = sum(1 for f in findings if f.severity == "error")
        summary["warning_count"] = sum(1 for f in findings if f.severity == "warning")
        return False, findings, summary

    declared_runtime = manifest_runtime
    summary["declared_runtime"] = declared_runtime

    # Scan root manifest and workspace member manifest dependency tables
    findings.extend(scan_manifest_dependencies(target_manifest, root, allowed_git_prefixes, sibling_root))
    ws_members_list = manifest_data.get("workspace", {}).get("members", [])
    if isinstance(ws_members_list, list):
        for m in ws_members_list:
            if isinstance(m, str):
                m_path = root / m / "Cargo.toml"
                findings.extend(scan_manifest_dependencies(m_path, root, allowed_git_prefixes, sibling_root))

    # Enumerate and inspect [workspace.dependencies] table
    for dep_name, dep_spec in sorted(workspace_deps.items()):
        package_name = dep_name
        if isinstance(dep_spec, dict) and "package" in dep_spec:
            package_name = str(dep_spec["package"])
        if is_forbidden_dji_sdk(dep_name) or is_forbidden_dji_sdk(package_name):
            findings.append(
                ClosureFinding(
                    code=ERR_DJI_SDK_DEPENDENCY_FORBIDDEN,
                    file=sanitize_path(target_manifest, root),
                    location=f"[workspace.dependencies].{dep_name}",
                    message=f"DJI Mobile SDK dependency '{dep_name}' in [workspace.dependencies] is forbidden by NEG-001",
                    severity="error",
                    remediation=DIAGNOSTIC_REGISTRY[ERR_DJI_SDK_DEPENDENCY_FORBIDDEN]["remediation"],
                    params={"package": dep_name},
                )
            )
            continue

        if dep_name in forbidden_crates or dep_name in oracle_crates:
            findings.append(
                ClosureFinding(
                    code=ERR_FORBIDDEN_CRATE,
                    file=sanitize_path(target_manifest, root),
                    location=f"[workspace.dependencies].{dep_name}",
                    message=f"Forbidden crate in [workspace.dependencies]: '{dep_name}'",
                    severity="error",
                    remediation=DIAGNOSTIC_REGISTRY[ERR_FORBIDDEN_CRATE]["remediation"],
                    params={"package": dep_name},
                )
            )
            continue

        if dep_name not in workspace_members and not is_crate_allowlisted(dep_name):
            findings.append(
                ClosureFinding(
                    code=ERR_UNALLOWLISTED_CRATE,
                    file=sanitize_path(target_manifest, root),
                    location=f"[workspace.dependencies].{dep_name}",
                    message=f"Crate outside closed allowlist in [workspace.dependencies]: '{dep_name}'",
                    severity="error",
                    remediation=DIAGNOSTIC_REGISTRY[ERR_UNALLOWLISTED_CRATE]["remediation"],
                    params={"package": dep_name},
                )
            )

        if isinstance(dep_spec, dict):
            if "git" in dep_spec:
                git_url = str(dep_spec["git"])
                if not any(git_url.startswith(p) for p in allowed_git_prefixes):
                    findings.append(
                        ClosureFinding(
                            code=ERR_UNALLOWLISTED_SOURCE,
                            file=sanitize_path(target_manifest, root),
                            location=f"[workspace.dependencies].{dep_name}",
                            message=f"Git dependency '{dep_name}' in [workspace.dependencies] points to unallowlisted host: {git_url}",
                            severity="error",
                            remediation=DIAGNOSTIC_REGISTRY[ERR_UNALLOWLISTED_SOURCE]["remediation"],
                            params={"dependency": dep_name, "git": git_url},
                        )
                    )
                if "rev" in dep_spec:
                    rev = str(dep_spec["rev"])
                    if not (len(rev) == 40 and all(c in "0123456789abcdefABCDEF" for c in rev)):
                        findings.append(
                            ClosureFinding(
                                code=ERR_VERSION_SOURCE_MISMATCH,
                                file=sanitize_path(target_manifest, root),
                                location=f"[workspace.dependencies].{dep_name}",
                                message=f"Git dependency '{dep_name}' revision '{rev}' in [workspace.dependencies] lacks an exact 40-hex commit hash",
                                severity="error",
                                remediation=DIAGNOSTIC_REGISTRY[ERR_VERSION_SOURCE_MISMATCH]["remediation"],
                                params={"dependency": dep_name, "rev": rev},
                            )
                        )
            if "path" in dep_spec:
                path_val = dep_spec["path"]
                try:
                    resolved_p = (target_manifest.parent / path_val).resolve()
                    in_ws = False
                    try:
                        resolved_p.relative_to(root.resolve())
                        in_ws = True
                    except ValueError:
                        in_ws = False
                    if not in_ws:
                        in_sib = False
                        if sibling_root:
                            try:
                                resolved_p.relative_to(sibling_root)
                                in_sib = True
                            except ValueError:
                                in_sib = False
                        if not in_sib:
                            findings.append(
                                ClosureFinding(
                                    code=ERR_UNALLOWLISTED_SOURCE,
                                    file=sanitize_path(target_manifest, root),
                                    location=f"[workspace.dependencies].{dep_name}",
                                    message=f"Path dependency '{dep_name}' in [workspace.dependencies] escapes repository boundary: {path_val}",
                                    severity="error",
                                    remediation=DIAGNOSTIC_REGISTRY[ERR_UNALLOWLISTED_SOURCE]["remediation"],
                                    params={"dependency": dep_name, "path": path_val},
                                )
                            )
                except (OSError, ValueError) as exc:
                    findings.append(
                        ClosureFinding(
                            code=ERR_UNALLOWLISTED_SOURCE,
                            file=sanitize_path(target_manifest, root),
                            location=f"[workspace.dependencies].{dep_name}",
                            message=f"Path resolution failed for [workspace.dependencies].'{dep_name}': {exc}",
                            severity="error",
                            remediation=DIAGNOSTIC_REGISTRY[ERR_UNALLOWLISTED_SOURCE]["remediation"],
                            params={"dependency": dep_name, "error": str(exc)},
                        )
                    )

    # 3. Parse Cargo.lock
    lock_packages, lock_findings = parse_cargo_lock(target_lock, root)
    findings.extend(lock_findings)
    if lock_packages is None:
        summary["error_count"] = sum(1 for f in findings if f.severity == "error")
        summary["warning_count"] = sum(1 for f in findings if f.severity == "warning")
        return False, findings, summary

    for pkg_name in sorted(lock_packages.keys()):
        if is_forbidden_dji_sdk(pkg_name):
            findings.append(
                ClosureFinding(
                    code=ERR_DJI_SDK_DEPENDENCY_FORBIDDEN,
                    file=sanitize_path(target_lock, root),
                    location=f"package.{pkg_name}",
                    message=f"DJI Mobile SDK crate '{pkg_name}' in Cargo.lock is forbidden by NEG-001",
                    severity="error",
                    remediation=DIAGNOSTIC_REGISTRY[ERR_DJI_SDK_DEPENDENCY_FORBIDDEN]["remediation"],
                    params={"package": pkg_name},
                )
            )

    # 4. Fetch cargo metadata
    metadata, meta_err = run_cargo_metadata(root, target_manifest)
    if meta_err is not None:
        findings.append(
            ClosureFinding(
                code=ERR_METADATA_UNREADABLE,
                file=sanitize_path(target_manifest, root),
                location="cargo_metadata",
                message=f"Locked offline resolution failed: {meta_err}",
                severity="error",
                remediation=DIAGNOSTIC_REGISTRY[ERR_METADATA_UNREADABLE]["remediation"],
            )
        )
    if metadata is None:
        summary["error_count"] = sum(1 for f in findings if f.severity == "error")
        summary["warning_count"] = sum(1 for f in findings if f.severity == "warning")
        return False, findings, summary

    # 5. Extract metadata packages and resolve nodes
    meta_packages = metadata.get("packages", [])
    meta_pkg_map: dict[str, list[dict[str, Any]]] = {}
    for pkg in meta_packages:
        if isinstance(pkg, dict):
            name = pkg.get("name")
            if isinstance(name, str):
                meta_pkg_map.setdefault(name, []).append(pkg)

    resolve_nodes = metadata.get("resolve", {}).get("nodes", []) if isinstance(metadata.get("resolve"), dict) else []
    resolved_pkg_ids = {node["id"] for node in resolve_nodes if isinstance(node, dict) and "id" in node}

    all_pkg_names = set(lock_packages.keys()) | set(meta_pkg_map.keys())
    summary["package_count"] = len(all_pkg_names)
    summary["workspace_member_count"] = len(workspace_members)
    summary["external_dependency_count"] = len(all_pkg_names - workspace_members)

    # 6. Consistency check between Cargo.lock and cargo metadata
    # Check packages in lock vs metadata
    for name, lock_pkgs in sorted(lock_packages.items()):
        if name not in meta_pkg_map:
            findings.append(
                ClosureFinding(
                    code=ERR_VERSION_SOURCE_MISMATCH,
                    file=sanitize_path(target_lock, root),
                    location=f"package.{name}",
                    message=f"Package '{name}' is present in Cargo.lock but absent from resolved cargo metadata",
                    severity="error",
                    remediation=DIAGNOSTIC_REGISTRY[ERR_VERSION_SOURCE_MISMATCH]["remediation"],
                    params={"package": name},
                )
            )
            continue

        meta_pkgs = meta_pkg_map[name]
        lock_versions = {p.get("version") for p in lock_pkgs}
        meta_versions = {p.get("version") for p in meta_pkgs}
        if lock_versions != meta_versions:
            findings.append(
                ClosureFinding(
                    code=ERR_VERSION_SOURCE_MISMATCH,
                    file=sanitize_path(target_lock, root),
                    location=f"package.{name}",
                    message=f"Package '{name}' version mismatch: Cargo.lock has {sorted(lock_versions)}, metadata has {sorted(meta_versions)}",
                    severity="error",
                    remediation=DIAGNOSTIC_REGISTRY[ERR_VERSION_SOURCE_MISMATCH]["remediation"],
                    params={"package": name, "lock_versions": sorted(lock_versions), "meta_versions": sorted(meta_versions)},
                )
            )

        def normalize_source(s: Any) -> str:
            if s is None:
                return "path/member"
            return str(s)

        lock_sources = {normalize_source(p.get("source")) for p in lock_pkgs}
        meta_sources = {normalize_source(p.get("source")) for p in meta_pkgs}
        if lock_sources != meta_sources:
            findings.append(
                ClosureFinding(
                    code=ERR_VERSION_SOURCE_MISMATCH,
                    file=sanitize_path(target_lock, root),
                    location=f"package.{name}.source",
                    message=f"Package '{name}' source mismatch: Cargo.lock has {sorted(lock_sources)}, metadata has {sorted(meta_sources)}",
                    severity="error",
                    remediation=DIAGNOSTIC_REGISTRY[ERR_VERSION_SOURCE_MISMATCH]["remediation"],
                    params={"package": name, "lock_sources": sorted(lock_sources), "meta_sources": sorted(meta_sources), "source": "mismatch"},
                )
            )

    for name in sorted(meta_pkg_map.keys() - lock_packages.keys()):
        findings.append(
            ClosureFinding(
                code=ERR_VERSION_SOURCE_MISMATCH,
                file=sanitize_path(target_lock, root),
                location=f"package.{name}",
                message=f"Package '{name}' is present in cargo metadata but absent from Cargo.lock",
                severity="error",
                remediation=DIAGNOSTIC_REGISTRY[ERR_VERSION_SOURCE_MISMATCH]["remediation"],
                params={"package": name},
            )
        )

    # 7. Check source integrity (git revisions and path boundaries)
    # Check git sources in lock
    for name, pkgs in sorted(lock_packages.items()):
        for pkg in pkgs:
            source = pkg.get("source")
            if isinstance(source, str) and source.startswith("git+"):
                # Check for exact 40-hex revision
                rev_part = source.split("#")[-1] if "#" in source else ""
                if not re.fullmatch(r"[0-9a-fA-F]{40}", rev_part):
                    findings.append(
                        ClosureFinding(
                            code=ERR_VERSION_SOURCE_MISMATCH,
                            file=sanitize_path(target_lock, root),
                            location=f"package.{name}.source",
                            message=f"Git dependency '{name}' lacks an exact 40-hex commit hash in source: {source}",
                            severity="error",
                            remediation=DIAGNOSTIC_REGISTRY[ERR_VERSION_SOURCE_MISMATCH]["remediation"],
                            params={"package": name, "source": source},
                        )
                    )
                # Check authorized repository
                repo_url = source.split("?")[0].split("#")[0].removeprefix("git+")
                if not any(repo_url.startswith(prefix) for prefix in allowed_git_prefixes):
                    findings.append(
                        ClosureFinding(
                            code=ERR_UNALLOWLISTED_SOURCE,
                            file=sanitize_path(target_lock, root),
                            location=f"package.{name}.source",
                            message=f"Git dependency '{name}' uses an unallowlisted repository URL: {source}",
                            severity="error",
                            remediation=DIAGNOSTIC_REGISTRY[ERR_UNALLOWLISTED_SOURCE]["remediation"],
                            params={"package": name, "source": source},
                        )
                    )

    # Check path sources and manifest paths in metadata
    for name, pkgs in sorted(meta_pkg_map.items()):
        for pkg in pkgs:
            manifest_p = pkg.get("manifest_path")
            if isinstance(manifest_p, str):
                try:
                    resolved_manifest = Path(manifest_p).resolve()
                    in_workspace = False
                    try:
                        resolved_manifest.relative_to(root.resolve())
                        in_workspace = True
                    except ValueError:
                        in_workspace = False

                    if not in_workspace:
                        in_sibling = False
                        if sibling_root:
                            try:
                                resolved_manifest.relative_to(sibling_root)
                                in_sibling = True
                            except ValueError:
                                in_sibling = False

                        if not in_sibling:
                            findings.append(
                                ClosureFinding(
                                    code=ERR_UNALLOWLISTED_SOURCE,
                                    file=sanitize_path(manifest_p, root),
                                    location=f"package.{name}",
                                    message=f"Path package '{name}' escapes repository boundary and sibling closure: {manifest_p}",
                                    severity="error",
                                    remediation=DIAGNOSTIC_REGISTRY[ERR_UNALLOWLISTED_SOURCE]["remediation"],
                                    params={"package": name, "manifest_path": manifest_p},
                                )
                            )
                except (OSError, ValueError) as exc:
                    findings.append(
                        ClosureFinding(
                            code=ERR_UNALLOWLISTED_SOURCE,
                            file=sanitize_path(manifest_p, root),
                            location=f"package.{name}",
                            message=f"Path resolution failed for package '{name}' manifest '{manifest_p}': {exc}",
                            severity="error",
                            remediation=DIAGNOSTIC_REGISTRY[ERR_UNALLOWLISTED_SOURCE]["remediation"],
                            params={"package": name, "manifest_path": manifest_p, "error": str(exc)},
                        )
                    )

            # Check declared dependencies inside each package for escaping paths
            for dep in pkg.get("dependencies", []):
                dep_path = dep.get("path")
                if isinstance(dep_path, str):
                    try:
                        dep_res = (Path(pkg.get("manifest_path", "")).parent / dep_path).resolve()
                        in_ws = False
                        try:
                            dep_res.relative_to(root.resolve())
                            in_ws = True
                        except ValueError:
                            in_ws = False

                        if not in_ws:
                            in_sib = False
                            if sibling_root:
                                try:
                                    dep_res.relative_to(sibling_root)
                                    in_sib = True
                                except ValueError:
                                    in_sib = False
                            if not in_sib:
                                findings.append(
                                    ClosureFinding(
                                        code=ERR_UNALLOWLISTED_SOURCE,
                                        file=sanitize_path(pkg.get("manifest_path", target_manifest), root),
                                        location=f"dependencies.{dep.get('name')}",
                                        message=f"Path dependency '{dep.get('name')}' escapes repository boundary: {dep_path}",
                                        severity="error",
                                        remediation=DIAGNOSTIC_REGISTRY[ERR_UNALLOWLISTED_SOURCE]["remediation"],
                                        params={"dependency": dep.get("name"), "path": dep_path},
                                    )
                                )
                    except (OSError, ValueError) as exc:
                        findings.append(
                            ClosureFinding(
                                code=ERR_UNALLOWLISTED_SOURCE,
                                file=sanitize_path(pkg.get("manifest_path", target_manifest), root),
                                location=f"dependencies.{dep.get('name')}",
                                message=f"Path resolution failed for dependency '{dep.get('name')}' path '{dep_path}': {exc}",
                                severity="error",
                                remediation=DIAGNOSTIC_REGISTRY[ERR_UNALLOWLISTED_SOURCE]["remediation"],
                                params={"dependency": dep.get("name"), "path": dep_path, "error": str(exc)},
                            )
                        )

    # 8. Check every crate against allowlist / forbidden list
    # Inspect packages from both lockfile and metadata closure
    checked_names: set[str] = set()
    for name in sorted(all_pkg_names):
        if name in checked_names:
            continue
        checked_names.add(name)

        if is_forbidden_dji_sdk(name):
            findings.append(
                ClosureFinding(
                    code=ERR_DJI_SDK_DEPENDENCY_FORBIDDEN,
                    file=sanitize_path(target_lock, root),
                    location=f"package.{name}",
                    message=f"DJI Mobile SDK crate '{name}' is forbidden in dependency closure by NEG-001",
                    severity="error",
                    remediation=DIAGNOSTIC_REGISTRY[ERR_DJI_SDK_DEPENDENCY_FORBIDDEN]["remediation"],
                    params={"package": name},
                )
            )
            continue

        if name in forbidden_crates:
            findings.append(
                ClosureFinding(
                    code=ERR_FORBIDDEN_CRATE,
                    file=sanitize_path(target_lock, root),
                    location=f"package.{name}",
                    message=f"Forbidden crate reachable in resolved dependency closure: '{name}'",
                    severity="error",
                    remediation=DIAGNOSTIC_REGISTRY[ERR_FORBIDDEN_CRATE]["remediation"],
                    params={"package": name},
                )
            )
            continue

        if name in oracle_crates:
            findings.append(
                ClosureFinding(
                    code=ERR_FORBIDDEN_CRATE,
                    file=sanitize_path(target_lock, root),
                    location=f"package.{name}",
                    message=f"Laboratory oracle excluded from production release closure is reachable: '{name}'",
                    severity="error",
                    remediation=DIAGNOSTIC_REGISTRY[ERR_FORBIDDEN_CRATE]["remediation"],
                    params={"package": name},
                )
            )
            continue

        if name in workspace_members:
            # Internal workspace members are allowed
            continue

        # External dependency: must be allowlisted
        if name in exception_candidates and name not in admitted_exceptions:
            findings.append(
                ClosureFinding(
                    code=ERR_UNALLOWLISTED_CRATE,
                    file=sanitize_path(target_lock, root),
                    location=f"package.{name}",
                    message=f"Unadmitted exception candidate in dependency closure: '{name}' (requires DEP record and ADR admission)",
                    severity="error",
                    remediation=DIAGNOSTIC_REGISTRY[ERR_UNALLOWLISTED_CRATE]["remediation"],
                    params={"package": name},
                )
            )
            continue

        if not is_crate_allowlisted(name):
            findings.append(
                ClosureFinding(
                    code=ERR_UNALLOWLISTED_CRATE,
                    file=sanitize_path(target_lock, root),
                    location=f"package.{name}",
                    message=f"Crate outside closed allowlist in resolved closure: '{name}'",
                    severity="error",
                    remediation=DIAGNOSTIC_REGISTRY[ERR_UNALLOWLISTED_CRATE]["remediation"],
                    params={"package": name},
                )
            )

    # 9. Honest reporting of declared-but-unresolved async runtime
    if policy.get("asupersync_is_only_async_runtime"):
        if not declared_runtime:
            findings.append(
                ClosureFinding(
                    code=ERR_DECLARED_RUNTIME_UNRESOLVED,
                    file=sanitize_path(target_manifest, root),
                    location="[workspace.metadata.fss].sole_async_runtime",
                    message="Cargo.toml lacks required '[workspace.metadata.fss].sole_async_runtime = \"asupersync\"' declaration required by dependency constitution",
                    severity="error",
                    remediation=DIAGNOSTIC_REGISTRY[ERR_DECLARED_RUNTIME_UNRESOLVED]["remediation"],
                    params={"runtime": "missing"},
                )
            )
        elif declared_runtime != "asupersync":
            findings.append(
                ClosureFinding(
                    code=ERR_FORBIDDEN_CRATE,
                    file=sanitize_path(target_manifest, root),
                    location="[workspace.metadata.fss].sole_async_runtime",
                    message=f"Declared async runtime '{declared_runtime}' is forbidden; dependency constitution mandates asupersync only",
                    severity="error",
                    remediation=DIAGNOSTIC_REGISTRY[ERR_FORBIDDEN_CRATE]["remediation"],
                    params={"runtime": declared_runtime},
                )
            )

    if declared_runtime:
        if declared_runtime in all_pkg_names:
            summary["declared_runtime_resolved"] = True
            summary["declared_runtime_status"] = "resolved"
        else:
            summary["declared_runtime_resolved"] = False
            summary["declared_runtime_status"] = "declared_but_unresolved"
            if require_resolved_runtime and not allow_unresolved_runtime:
                findings.append(
                    ClosureFinding(
                        code=ERR_DECLARED_RUNTIME_UNRESOLVED,
                        file=sanitize_path(target_manifest, root),
                        location="[workspace.metadata.fss].sole_async_runtime",
                        message=f"Required async runtime '{declared_runtime}' is declared in Cargo.toml but not resolved in Cargo.lock / metadata",
                        severity="error",
                        remediation=DIAGNOSTIC_REGISTRY[ERR_DECLARED_RUNTIME_UNRESOLVED]["remediation"],
                        params={"runtime": declared_runtime},
                    )
                )
            else:
                findings.append(
                    ClosureFinding(
                        code=STATUS_DECLARED_RUNTIME_UNRESOLVED,
                        file=sanitize_path(target_manifest, root),
                        location="[workspace.metadata.fss].sole_async_runtime",
                        message=f"Declared sole async runtime '{declared_runtime}' is not resolved in Cargo.lock / metadata (honest status)",
                        severity="warning",
                        remediation=DIAGNOSTIC_REGISTRY[STATUS_DECLARED_RUNTIME_UNRESOLVED]["remediation"],
                        params={"runtime": declared_runtime},
                    )
                )

    error_count = sum(1 for f in findings if f.severity == "error")
    warning_count = sum(1 for f in findings if f.severity == "warning")
    summary["error_count"] = error_count
    summary["warning_count"] = warning_count
    summary["status"] = "pass" if error_count == 0 else "fail"

    return error_count == 0, findings, summary


def main() -> int:
    parser = argparse.ArgumentParser(
        description="FSS-181 Dependency-closure scanner against allowlist v2."
    )
    parser.add_argument("--root", type=Path, default=ROOT, help="Repository root path")
    parser.add_argument(
        "--allowlist", type=Path, default=None, help="Path to dependency_allowlist.toml"
    )
    parser.add_argument(
        "--manifest-path", type=Path, default=None, help="Path to root Cargo.toml"
    )
    parser.add_argument(
        "--lock-path", type=Path, default=None, help="Path to Cargo.lock"
    )
    parser.add_argument(
        "--adapter-registry", type=Path, default=None, help="Path to DEVICE_ADAPTERS.md"
    )
    parser.add_argument(
        "--require-resolved-runtime",
        action="store_true",
        default=True,
        help="Fail closed if declared sole async runtime is not resolved in Cargo.lock (default)",
    )
    parser.add_argument(
        "--allow-unresolved-runtime",
        action="store_true",
        default=False,
        help="Permit declared sole async runtime to remain unresolved with a warning (for pre-integration verification)",
    )
    parser.add_argument(
        "--json", action="store_true", help="Output machine-readable JSON report"
    )
    parser.add_argument(
        "--quiet", action="store_true", help="Suppress non-error output"
    )
    args = parser.parse_args()

    is_valid, findings, summary = audit_dependency_closure(
        root=args.root,
        allowlist_path=args.allowlist,
        manifest_path=args.manifest_path,
        lock_path=args.lock_path,
        adapter_path=args.adapter_registry,
        require_resolved_runtime=args.require_resolved_runtime,
        allow_unresolved_runtime=args.allow_unresolved_runtime,
    )

    if args.json:
        report = {
            "summary": summary,
            "findings": [asdict(f) for f in findings],
        }
        print(json.dumps(report, indent=2, sort_keys=True))
    else:
        if not args.quiet or not is_valid:
            tag = "PASS" if is_valid else "FAIL"
            print(
                f"[{tag}] Dependency closure scan: {summary['package_count']} packages in resolved closure "
                f"({summary['workspace_member_count']} workspace members, {summary['external_dependency_count']} external dependencies), "
                f"{summary['error_count']} errors, {summary['warning_count']} warnings"
            )
            if summary.get("declared_runtime"):
                resolved_str = "resolved" if summary.get("declared_runtime_resolved") else "declared_but_unresolved"
                print(f"  Declared runtime: {summary['declared_runtime']} ({resolved_str})")

            for f in findings:
                sev = f.severity.upper()
                print(f"  {sev} [{f.code}] {f.file}:{f.location}: {f.message}")
                if f.remediation and f.severity == "error":
                    print(f"    Remediation: {f.remediation}")

    return 0 if is_valid else 1


if __name__ == "__main__":
    sys.exit(main())
