#!/usr/bin/env python3
"""Deterministic unsafe prohibition checker (fss-x4a.26.2 / FSS-182).

Enforces the absolute safe-Rust prohibition from AGENTS.md:
"#!forbid(unsafe_code) in every FSS workspace crate, target, example, test,
 and build helper; there is no local exception path."

Fail-closed verification invariants:
1. Target root forbid: Every Rust target enumerated from
   `cargo metadata --offline --no-deps` (lib, bins, tests, examples, benches,
   and build scripts across all features) must carry `#![forbid(unsafe_code)]`.
2. Attribute prohibition: `#![allow(unsafe_code)]`, `#[allow(unsafe_code)]`,
   `#[warn(unsafe_code)]`, `#[expect(unsafe_code)]`, or any unsafe-permitting
   attribute is forbidden anywhere in any Rust source file.
3. Construct prohibition: `unsafe` blocks, fns, impls, traits, or foreign
   constructs are strictly forbidden in any FSS Rust source file.
4. Manifest lint enforcement: Every workspace member crate must declare
   `[lints] workspace = true` (with `workspace.lints.rust.unsafe_code = 'forbid'`)
   or explicitly set `[lints.rust] unsafe_code = 'forbid'`.
5. Metadata validity: Unreadable, missing, or malformed metadata fails closed.
"""

from __future__ import annotations

import argparse
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

# Typed diagnostic error codes
ERR_TARGET_ROOT_MISSING_FORBID = "ERR-UNSAFE-TARGET-ROOT-MISSING-FORBID-001"
ERR_UNSAFE_ATTRIBUTE_PERMITTED = "ERR-UNSAFE-ATTRIBUTE-PERMITTED-001"
ERR_UNSAFE_CONSTRUCT_DETECTED = "ERR-UNSAFE-CONSTRUCT-DETECTED-001"
ERR_MANIFEST_LINT_NOT_FORBIDDEN = "ERR-UNSAFE-MANIFEST-LINT-NOT-FORBIDDEN-001"
ERR_METADATA_UNREADABLE = "ERR-UNSAFE-METADATA-UNREADABLE-001"

DIAGNOSTIC_REGISTRY: dict[str, dict[str, str]] = {
    ERR_TARGET_ROOT_MISSING_FORBID: {
        "trigger": "A Rust target root file (lib, bin, test, example, bench, or build script) enumerated from cargo metadata lacks unconditional #![forbid(unsafe_code)]",
        "remediation": "Add #![forbid(unsafe_code)] as an inner attribute at the top of the target root file; FSS permits no local exceptions",
        "standard_code": "DEP-AUD-021",
    },
    ERR_UNSAFE_ATTRIBUTE_PERMITTED: {
        "trigger": "An unsafe-permitting attribute (e.g. allow(unsafe_code), warn(unsafe_code), expect(unsafe_code)) is present in Rust source",
        "remediation": "Remove the attribute; AGENTS.md mandates forbid(unsafe_code) across all FSS crates, targets, and tests with no exception path",
        "standard_code": "DEP-AUD-021",
    },
    ERR_UNSAFE_CONSTRUCT_DETECTED: {
        "trigger": "An unsafe block, function, impl, trait, or foreign construct is detected in FSS Rust source",
        "remediation": "Refactor to pure, safe Rust. FSS production, tests, and examples are 100% safe Rust",
        "standard_code": "DEP-AUD-022",
    },
    ERR_MANIFEST_LINT_NOT_FORBIDDEN: {
        "trigger": "A crate Cargo.toml manifest does not forbid unsafe_code via [lints] workspace = true or [lints.rust] unsafe_code = 'forbid'",
        "remediation": "Add [lints] workspace = true to Cargo.toml (with workspace.lints.rust.unsafe_code = 'forbid') or explicitly set [lints.rust] unsafe_code = 'forbid'",
        "standard_code": "DEP-AUD-021",
    },
    ERR_METADATA_UNREADABLE: {
        "trigger": "cargo metadata --offline --no-deps failed, exited with non-zero status, or produced unparseable output",
        "remediation": "Fix workspace Cargo.toml, member manifests, or toolchain configuration to allow offline metadata generation",
        "standard_code": "DEP-AUD-020",
    },
}

EXCLUDED_DIR_NAMES = frozenset({
    ".git",
    "target",
    "dist",
    "qualification-artifacts",
    ".ee",
    ".beads",
    ".claude",
    ".ntm",
})

FORBID_UNSAFE_RE = re.compile(r"#\s*!\s*\[\s*forbid\s*\(\s*unsafe_code\s*\)\s*\]")
UNSAFE_PERMIT_ATTR_RE = re.compile(
    r"#\s*!?\s*\[\s*(?:allow|warn|expect)\s*\([^\]]*\bunsafe_code\b[^\]]*\)\s*\]"
)
GENERIC_FORBID_ATTR_RE = re.compile(
    r"#\s*!?\s*\[\s*forbid\s*\([^\]]*\bunsafe_code\b[^\]]*\)\s*\]"
)


@dataclass(frozen=True)
class UnsafeFinding:
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


def load_registered_crate_topology(root: Path) -> dict[str, str]:
    """Loads registered crate relative directory -> crate name from architecture/crate_topology.json."""
    topo_path = root / "architecture/crate_topology.json"
    if not topo_path.is_file():
        return {}
    try:
        data = json.loads(topo_path.read_text(encoding="utf-8"))
        # In FSS, registered topology crates reside canonically under crates/<name>
        return {
            f"crates/{c['name']}": c["name"]
            for layer in data.get("layers", [])
            for c in layer.get("crates", [])
            if isinstance(c, dict) and isinstance(c.get("name"), str) and c["name"].strip()
        }
    except Exception:
        return {}


def is_fixture_or_test_path(path: Path | str, root: Path | None = None) -> bool:
    """Returns True if the path is located inside a fixture or test directory relative to repo root."""
    p = Path(path)
    if p.is_absolute():
        repo_root = (root if root is not None else ROOT).resolve()
        try:
            p = p.resolve().relative_to(repo_root)
        except (ValueError, OSError):
            try:
                p = p.relative_to(root if root is not None else ROOT)
            except ValueError:
                pass
    elif root is not None:
        try:
            p = p.relative_to(root)
        except ValueError:
            pass
    parts = p.parts
    return any(
        part in {"fixtures", "fixture", "test_fixtures", "tests"}
        or part.startswith("test_")
        for part in parts
    )


def is_excluded_by_workspace(rel_path: str, workspace_excludes: list[str]) -> bool:
    """Returns True if the relative path matches any workspace.exclude pattern using Cargo semantics.

    Cargo matches exclude patterns by path components relative to the workspace root.
    A path matches if the pattern's path components form an exact literal prefix of the target's
    path components. Cargo workspace.exclude does not perform glob expansion or loose substring matching.
    """
    p = Path(rel_path.replace("\\", "/"))
    crate_dir = p.parent if p.name == "Cargo.toml" else p
    crate_parts = crate_dir.parts

    for pattern in workspace_excludes:
        pat_clean = pattern.strip().replace("\\", "/").rstrip("/")
        if not pat_clean:
            continue
        pat_parts = Path(pat_clean).parts
        if not pat_parts:
            continue

        if len(crate_parts) >= len(pat_parts):
            prefix_matches = True
            for c_part, p_part in zip(crate_parts, pat_parts):
                if c_part != p_part:
                    prefix_matches = False
                    break
            if prefix_matches:
                return True
    return False


def strip_rust_comments_and_strings(src: str) -> str:
    """Strips Rust comments and string/char literals, preserving line numbers and column offsets."""
    out: list[str] = []
    i = 0
    n = len(src)
    while i < n:
        c = src[i]
        # Line comment: // ...
        if c == "/" and i + 1 < n and src[i + 1] == "/":
            out.append("  ")
            i += 2
            while i < n and src[i] != "\n":
                out.append(" ")
                i += 1
            continue

        # Block comment: /* ... */ with nested block comment support
        if c == "/" and i + 1 < n and src[i + 1] == "*":
            depth = 1
            out.append("  ")
            i += 2
            while i < n and depth > 0:
                if src[i] == "/" and i + 1 < n and src[i + 1] == "*":
                    depth += 1
                    out.append("  ")
                    i += 2
                elif src[i] == "*" and i + 1 < n and src[i + 1] == "/":
                    depth -= 1
                    out.append("  ")
                    i += 2
                elif src[i] == "\n":
                    out.append("\n")
                    i += 1
                else:
                    out.append(" ")
                    i += 1
            continue

        # Raw string literal: r"..." or r#"..."#
        if c == "r" and i + 1 < n and (src[i + 1] == '"' or src[i + 1] == "#"):
            j = i + 1
            hashes = 0
            while j < n and src[j] == "#":
                hashes += 1
                j += 1
            if j < n and src[j] == '"':
                delim = '"' + ("#" * hashes)
                raw_prefix_len = j - i + 1
                out.append(" " * raw_prefix_len)
                i = j + 1
                while i < n:
                    if src[i : i + len(delim)] == delim:
                        out.append(" " * len(delim))
                        i += len(delim)
                        break
                    elif src[i] == "\n":
                        out.append("\n")
                        i += 1
                    else:
                        out.append(" ")
                        i += 1
                continue

        # Regular string literal: "..."
        if c == '"':
            out.append(" ")
            i += 1
            while i < n:
                if src[i] == "\\":
                    if i + 1 < n and src[i + 1] == "\n":
                        out.append(" \n")
                        i += 2
                    elif i + 2 < n and src[i + 1] == "\r" and src[i + 2] == "\n":
                        out.append("  \n")
                        i += 3
                    else:
                        out.append("  ")
                        i += 2
                elif src[i] == '"':
                    out.append(" ")
                    i += 1
                    break
                elif src[i] == "\n":
                    out.append("\n")
                    i += 1
                else:
                    out.append(" ")
                    i += 1
            continue

        # Character literal: 'x' (distinguished from lifetime 'a)
        if c == "'" and i + 1 < n:
            is_char = False
            char_len = 0
            if src[i + 1] != "\\" and src[i + 1] != "'" and src[i + 1] != "\n":
                if i + 2 < n and src[i + 2] == "'":
                    is_char = True
                    char_len = 3
            elif src[i + 1] == "\\":
                if i + 2 < n:
                    esc = src[i + 2]
                    if esc in "'\"\\nrt0" and i + 3 < n and src[i + 3] == "'":
                        is_char = True
                        char_len = 4
                    elif esc == "x" and i + 5 < n and src[i + 5] == "'":
                        if all(ch in "0123456789abcdefABCDEF" for ch in src[i + 3 : i + 5]):
                            is_char = True
                            char_len = 6
                    elif esc == "u" and i + 3 < n and src[i + 3] == "{":
                        close_brace = src.find("}", i + 4)
                        if (
                            close_brace != -1
                            and close_brace < min(n - 1, i + 11)
                            and src[close_brace + 1] == "'"
                        ):
                            is_char = True
                            char_len = close_brace + 2 - i

            if is_char:
                out.append(" " * char_len)
                i += char_len
                continue

        out.append(c)
        i += 1

    return "".join(out)


def run_cargo_metadata(
    root: Path, manifest_path: Path | None = None
) -> tuple[dict[str, Any] | None, str | None]:
    """Invokes `cargo metadata --offline --no-deps --all-features --format-version 1`."""
    target_manifest = manifest_path or (root / "Cargo.toml")
    cmd = [
        "cargo",
        "metadata",
        "--offline",
        "--no-deps",
        "--all-features",
        "--format-version",
        "1",
        "--manifest-path",
        str(target_manifest),
    ]

    proc = subprocess.run(cmd, cwd=root, capture_output=True, text=True)
    if proc.returncode != 0:
        # If cargo is wrapped via rustup or rust-toolchain.toml, try with rustup
        toolchain_file = root / "rust-toolchain.toml"
        rustup_exc: Exception | None = None
        if toolchain_file.is_file() and shutil.which("rustup"):
            try:
                tc_data = tomllib.loads(toolchain_file.read_text(encoding="utf-8"))
                channel = tc_data.get("toolchain", {}).get("channel")
                if channel:
                    rustup_cmd = ["rustup", "run", channel] + cmd
                    proc = subprocess.run(rustup_cmd, cwd=root, capture_output=True, text=True)
            except (OSError, tomllib.TOMLDecodeError, subprocess.SubprocessError) as exc:
                rustup_exc = exc

    if proc.returncode != 0:
        base_err = proc.stderr.strip() or proc.stdout.strip() or "cargo metadata command failed"
        err_msg = f"{base_err} (rustup fallback error: {rustup_exc})" if rustup_exc else base_err
        return None, err_msg

    try:
        data = json.loads(proc.stdout)
        if not isinstance(data, dict):
            return None, "cargo metadata root must be a JSON object"
        return data, None
    except json.JSONDecodeError as exc:
        return None, f"cargo metadata output is invalid JSON: {exc}"


def discover_disk_manifests(root: Path) -> list[Path]:
    """Discovers all Cargo.toml manifest files under root, excluding excluded directories."""
    manifests: list[Path] = []
    if not root.is_dir():
        return manifests
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = [d for d in dirnames if d not in EXCLUDED_DIR_NAMES]
        if "Cargo.toml" in filenames:
            manifests.append(Path(dirpath) / "Cargo.toml")
    return sorted(manifests)


def check_manifest_lints(
    workspace_root: Path,
    packages: list[dict[str, Any]],
    workspace_members: set[str],
    root: Path,
) -> list[UnsafeFinding]:
    """Checks that workspace and crate manifests strictly forbid unsafe_code."""
    findings: list[UnsafeFinding] = []

    # Check workspace root Cargo.toml
    root_cargo_toml = workspace_root / "Cargo.toml"
    workspace_forbids_unsafe = False
    has_workspace_table = False
    workspace_excludes: list[str] = []
    registered_topology_crates = load_registered_crate_topology(root)

    if not root_cargo_toml.is_file():
        findings.append(
            UnsafeFinding(
                code=ERR_MANIFEST_LINT_NOT_FORBIDDEN,
                file=sanitize_path(root_cargo_toml, root),
                location="manifest",
                message="Workspace root Cargo.toml not found",
                remediation=DIAGNOSTIC_REGISTRY[ERR_MANIFEST_LINT_NOT_FORBIDDEN]["remediation"],
            )
        )
    else:
        try:
            root_data = tomllib.loads(root_cargo_toml.read_text(encoding="utf-8"))
            if not isinstance(root_data, dict):
                findings.append(
                    UnsafeFinding(
                        code=ERR_MANIFEST_LINT_NOT_FORBIDDEN,
                        file=sanitize_path(root_cargo_toml, root),
                        location="manifest",
                        message="Workspace Cargo.toml must be a table",
                        remediation=DIAGNOSTIC_REGISTRY[ERR_MANIFEST_LINT_NOT_FORBIDDEN]["remediation"],
                    )
                )
                root_data = {}
            has_workspace_table = "workspace" in root_data
            ws_table = root_data.get("workspace")
            if has_workspace_table and not isinstance(ws_table, dict):
                findings.append(
                    UnsafeFinding(
                        code=ERR_MANIFEST_LINT_NOT_FORBIDDEN,
                        file=sanitize_path(root_cargo_toml, root),
                        location="[workspace]",
                        message=f"Workspace Cargo.toml [workspace] section must be a table, got {type(ws_table).__name__}",
                        remediation=DIAGNOSTIC_REGISTRY[ERR_MANIFEST_LINT_NOT_FORBIDDEN]["remediation"],
                    )
                )
                ws_table = {}
            elif not isinstance(ws_table, dict):
                ws_table = {}

            ws_members = ws_table.get("members")
            if ws_members is not None and not isinstance(ws_members, list):
                findings.append(
                    UnsafeFinding(
                        code=ERR_MANIFEST_LINT_NOT_FORBIDDEN,
                        file=sanitize_path(root_cargo_toml, root),
                        location="[workspace].members",
                        message=f"Workspace members must be a list of paths, got {type(ws_members).__name__}",
                        remediation=DIAGNOSTIC_REGISTRY[ERR_MANIFEST_LINT_NOT_FORBIDDEN]["remediation"],
                    )
                )

            ws_lints = ws_table.get("lints")
            ws_rust_lints = ws_lints.get("rust") if isinstance(ws_lints, dict) else None
            ws_unsafe_lint = ws_rust_lints.get("unsafe_code") if isinstance(ws_rust_lints, dict) else None
            workspace_forbids_unsafe = ws_unsafe_lint == "forbid"
            ws_ex = ws_table.get("exclude", [])
            if isinstance(ws_ex, list):
                workspace_excludes = [str(e) for e in ws_ex]
            elif ws_ex is not None:
                findings.append(
                    UnsafeFinding(
                        code=ERR_MANIFEST_LINT_NOT_FORBIDDEN,
                        file=sanitize_path(root_cargo_toml, root),
                        location="[workspace].exclude",
                        message=f"Workspace exclude must be a list, got {type(ws_ex).__name__}",
                        remediation=DIAGNOSTIC_REGISTRY[ERR_MANIFEST_LINT_NOT_FORBIDDEN]["remediation"],
                    )
                )
        except (OSError, tomllib.TOMLDecodeError, UnicodeDecodeError) as exc:
            findings.append(
                UnsafeFinding(
                    code=ERR_MANIFEST_LINT_NOT_FORBIDDEN,
                    file=sanitize_path(root_cargo_toml, root),
                    location="manifest",
                    message=f"Could not parse workspace Cargo.toml: {exc}",
                    remediation=DIAGNOSTIC_REGISTRY[ERR_MANIFEST_LINT_NOT_FORBIDDEN]["remediation"],
                )
            )

    known_manifest_paths: set[Path] = set()

    # Check each workspace member package
    for pkg in packages:
        pkg_id = pkg.get("id", "")
        pkg_name = pkg.get("name", "unknown")
        manifest_path_str = pkg.get("manifest_path")
        if not manifest_path_str:
            continue

        manifest_path = Path(manifest_path_str)
        try:
            known_manifest_paths.add(manifest_path.resolve())
        except OSError:
            pass

        # Only verify workspace members
        if workspace_members and pkg_id not in workspace_members:
            continue

        rel_manifest = sanitize_path(manifest_path, root)

        if not manifest_path.is_file():
            findings.append(
                UnsafeFinding(
                    code=ERR_MANIFEST_LINT_NOT_FORBIDDEN,
                    file=rel_manifest,
                    location="manifest",
                    message=f"Package '{pkg_name}' Cargo.toml not found: '{rel_manifest}'",
                    remediation=DIAGNOSTIC_REGISTRY[ERR_MANIFEST_LINT_NOT_FORBIDDEN]["remediation"],
                    params={"crate": pkg_name},
                )
            )
            continue

        try:
            pkg_toml = tomllib.loads(manifest_path.read_text(encoding="utf-8"))
        except (OSError, tomllib.TOMLDecodeError, UnicodeDecodeError) as exc:
            findings.append(
                UnsafeFinding(
                    code=ERR_MANIFEST_LINT_NOT_FORBIDDEN,
                    file=rel_manifest,
                    location="manifest",
                    message=f"Package '{pkg_name}' Cargo.toml is unparseable: {exc}",
                    remediation=DIAGNOSTIC_REGISTRY[ERR_MANIFEST_LINT_NOT_FORBIDDEN]["remediation"],
                    params={"crate": pkg_name},
                )
            )
            continue

        lints_section = pkg_toml.get("lints", {})
        crate_explicit_unsafe = lints_section.get("rust", {}).get("unsafe_code")
        crate_workspace_lints = lints_section.get("workspace") is True

        if crate_explicit_unsafe is not None:
            if crate_explicit_unsafe != "forbid":
                findings.append(
                    UnsafeFinding(
                        code=ERR_MANIFEST_LINT_NOT_FORBIDDEN,
                        file=rel_manifest,
                        location="[lints.rust].unsafe_code",
                        message=(
                            f"Package '{pkg_name}' declares lints.rust.unsafe_code = '{crate_explicit_unsafe}'; "
                            f"must be 'forbid'"
                        ),
                        remediation=DIAGNOSTIC_REGISTRY[ERR_MANIFEST_LINT_NOT_FORBIDDEN]["remediation"],
                        params={"crate": pkg_name, "actual": crate_explicit_unsafe},
                    )
                )
        elif crate_workspace_lints:
            if not workspace_forbids_unsafe:
                findings.append(
                    UnsafeFinding(
                        code=ERR_MANIFEST_LINT_NOT_FORBIDDEN,
                        file=rel_manifest,
                        location="[lints].workspace",
                        message=(
                            f"Package '{pkg_name}' inherits workspace lints, but workspace root "
                            f"Cargo.toml does not declare workspace.lints.rust.unsafe_code = 'forbid'"
                        ),
                        remediation=DIAGNOSTIC_REGISTRY[ERR_MANIFEST_LINT_NOT_FORBIDDEN]["remediation"],
                        params={"crate": pkg_name},
                    )
                )
        else:
            findings.append(
                UnsafeFinding(
                    code=ERR_MANIFEST_LINT_NOT_FORBIDDEN,
                    file=rel_manifest,
                    location="[lints]",
                    message=(
                        f"Package '{pkg_name}' manifest does not forbid unsafe_code. "
                        f"Must declare [lints] workspace = true or [lints.rust] unsafe_code = 'forbid'"
                    ),
                    remediation=DIAGNOSTIC_REGISTRY[ERR_MANIFEST_LINT_NOT_FORBIDDEN]["remediation"],
                    params={"crate": pkg_name},
                )
            )

    # Check for any unlisted / unregistered crate manifests discovered on disk
    disk_manifests = discover_disk_manifests(root)
    for disk_manifest in disk_manifests:
        try:
            resolved_manifest = disk_manifest.resolve()
        except OSError:
            continue
        if root_cargo_toml.is_file() and resolved_manifest == root_cargo_toml.resolve():
            continue
        if resolved_manifest in known_manifest_paths:
            continue

        rel_manifest = sanitize_path(disk_manifest, root)
        try:
            m_data = tomllib.loads(disk_manifest.read_text(encoding="utf-8"))
        except (OSError, tomllib.TOMLDecodeError, UnicodeDecodeError) as exc:
            findings.append(
                UnsafeFinding(
                    code=ERR_MANIFEST_LINT_NOT_FORBIDDEN,
                    file=rel_manifest,
                    location="manifest",
                    message=f"Discovered manifest '{rel_manifest}' is unparseable: {exc}",
                    remediation=DIAGNOSTIC_REGISTRY[ERR_MANIFEST_LINT_NOT_FORBIDDEN]["remediation"],
                )
            )
            continue

        if not isinstance(m_data, dict):
            findings.append(
                UnsafeFinding(
                    code=ERR_MANIFEST_LINT_NOT_FORBIDDEN,
                    file=rel_manifest,
                    location="manifest",
                    message=f"Discovered manifest '{rel_manifest}' must be a table",
                    remediation=DIAGNOSTIC_REGISTRY[ERR_MANIFEST_LINT_NOT_FORBIDDEN]["remediation"],
                )
            )
            continue

        # Check for stray type crashes: package as non-dict
        if "package" in m_data and not isinstance(m_data["package"], dict):
            findings.append(
                UnsafeFinding(
                    code=ERR_MANIFEST_LINT_NOT_FORBIDDEN,
                    file=rel_manifest,
                    location="package",
                    message=f"Manifest '{rel_manifest}' [package] must be a table, got {type(m_data['package']).__name__}",
                    remediation=DIAGNOSTIC_REGISTRY[ERR_MANIFEST_LINT_NOT_FORBIDDEN]["remediation"],
                )
            )
            continue

        # Check for stray type crashes: workspace in stray manifest with non-list members
        if "workspace" in m_data:
            if not isinstance(m_data["workspace"], dict):
                findings.append(
                    UnsafeFinding(
                        code=ERR_MANIFEST_LINT_NOT_FORBIDDEN,
                        file=rel_manifest,
                        location="workspace",
                        message=f"Manifest '{rel_manifest}' [workspace] must be a table, got {type(m_data['workspace']).__name__}",
                        remediation=DIAGNOSTIC_REGISTRY[ERR_MANIFEST_LINT_NOT_FORBIDDEN]["remediation"],
                    )
                )
            elif "members" in m_data["workspace"] and not isinstance(m_data["workspace"]["members"], list):
                findings.append(
                    UnsafeFinding(
                        code=ERR_MANIFEST_LINT_NOT_FORBIDDEN,
                        file=rel_manifest,
                        location="workspace.members",
                        message=f"Manifest '{rel_manifest}' workspace.members must be a list, got {type(m_data['workspace']['members']).__name__}",
                        remediation=DIAGNOSTIC_REGISTRY[ERR_MANIFEST_LINT_NOT_FORBIDDEN]["remediation"],
                    )
                )
            elif "members" in m_data["workspace"] and not all(isinstance(x, str) for x in m_data["workspace"]["members"]):
                findings.append(
                    UnsafeFinding(
                        code=ERR_MANIFEST_LINT_NOT_FORBIDDEN,
                        file=rel_manifest,
                        location="workspace.members",
                        message=f"Manifest '{rel_manifest}' workspace.members elements must be strings",
                        remediation=DIAGNOSTIC_REGISTRY[ERR_MANIFEST_LINT_NOT_FORBIDDEN]["remediation"],
                    )
                )

            if isinstance(m_data.get("workspace"), dict) and "exclude" in m_data["workspace"]:
                ws_ex_val = m_data["workspace"]["exclude"]
                if not isinstance(ws_ex_val, list):
                    findings.append(
                        UnsafeFinding(
                            code=ERR_MANIFEST_LINT_NOT_FORBIDDEN,
                            file=rel_manifest,
                            location="workspace.exclude",
                            message=f"Manifest '{rel_manifest}' workspace.exclude must be a list, got {type(ws_ex_val).__name__}",
                            remediation=DIAGNOSTIC_REGISTRY[ERR_MANIFEST_LINT_NOT_FORBIDDEN]["remediation"],
                        )
                    )
                elif not all(isinstance(x, str) for x in ws_ex_val):
                    findings.append(
                        UnsafeFinding(
                            code=ERR_MANIFEST_LINT_NOT_FORBIDDEN,
                            file=rel_manifest,
                            location="workspace.exclude",
                            message=f"Manifest '{rel_manifest}' workspace.exclude elements must be strings",
                            remediation=DIAGNOSTIC_REGISTRY[ERR_MANIFEST_LINT_NOT_FORBIDDEN]["remediation"],
                        )
                    )

        if "package" not in m_data:
            continue

        pkg_section = m_data["package"]
        pkg_name = pkg_section.get("name") if isinstance(pkg_section, dict) and isinstance(pkg_section.get("name"), str) else disk_manifest.parent.name

        rel_crate_dir = sanitize_path(disk_manifest.parent, root)
        is_excluded = is_excluded_by_workspace(rel_manifest, workspace_excludes)
        is_fixture = is_fixture_or_test_path(rel_manifest, root)
        # Topology exemption: path-based AND name-based
        is_in_registered_topology = (
            rel_crate_dir in registered_topology_crates
            and registered_topology_crates[rel_crate_dir] == pkg_name
        )

        lints_section = m_data.get("lints") if isinstance(m_data.get("lints"), dict) else {}
        rust_lints = lints_section.get("rust") if isinstance(lints_section.get("rust"), dict) else {}
        crate_explicit_unsafe = rust_lints.get("unsafe_code")
        crate_workspace_lints = lints_section.get("workspace") is True

        is_forbid_compliant = (
            crate_explicit_unsafe == "forbid"
            or (crate_workspace_lints and workspace_forbids_unsafe)
        )

        # Decide whether to flag as unregistered:
        # Excluded and fixture crates that ARE forbid-compliant must NOT be flagged as unregistered.
        # But an unlisted crate outside workspace members that is NOT in workspace.exclude,
        # NOT in fixture/test dirs, and NOT in registered crate topology MUST be flagged.
        if has_workspace_table or workspace_members:
            if is_excluded or is_fixture:
                # Excluded/fixture crate: do not flag as unregistered.
                pass
            elif is_in_registered_topology and is_forbid_compliant:
                # In registered crate topology at registered path and forbid-compliant.
                pass
            else:
                findings.append(
                    UnsafeFinding(
                        code=ERR_MANIFEST_LINT_NOT_FORBIDDEN,
                        file=rel_manifest,
                        location="manifest",
                        message=(
                            f"Unregistered crate '{pkg_name}' at '{rel_manifest}' is not declared in "
                            f"workspace members in '{sanitize_path(root_cargo_toml, root)}'"
                        ),
                        remediation=DIAGNOSTIC_REGISTRY[ERR_MANIFEST_LINT_NOT_FORBIDDEN]["remediation"],
                        params={"crate": pkg_name},
                    )
                )

        if crate_explicit_unsafe is not None:
            if crate_explicit_unsafe != "forbid":
                findings.append(
                    UnsafeFinding(
                        code=ERR_MANIFEST_LINT_NOT_FORBIDDEN,
                        file=rel_manifest,
                        location="[lints.rust].unsafe_code",
                        message=(
                            f"Package '{pkg_name}' declares lints.rust.unsafe_code = '{crate_explicit_unsafe}'; "
                            f"must be 'forbid'"
                        ),
                        remediation=DIAGNOSTIC_REGISTRY[ERR_MANIFEST_LINT_NOT_FORBIDDEN]["remediation"],
                        params={"crate": pkg_name, "actual": crate_explicit_unsafe},
                    )
                )
        elif crate_workspace_lints:
            if not workspace_forbids_unsafe:
                findings.append(
                    UnsafeFinding(
                        code=ERR_MANIFEST_LINT_NOT_FORBIDDEN,
                        file=rel_manifest,
                        location="[lints].workspace",
                        message=(
                            f"Package '{pkg_name}' inherits workspace lints, but workspace root "
                            f"Cargo.toml does not declare workspace.lints.rust.unsafe_code = 'forbid'"
                        ),
                        remediation=DIAGNOSTIC_REGISTRY[ERR_MANIFEST_LINT_NOT_FORBIDDEN]["remediation"],
                        params={"crate": pkg_name},
                    )
                )
        else:
            findings.append(
                UnsafeFinding(
                    code=ERR_MANIFEST_LINT_NOT_FORBIDDEN,
                    file=rel_manifest,
                    location="[lints]",
                    message=(
                        f"Package '{pkg_name}' manifest does not forbid unsafe_code. "
                        f"Must declare [lints] workspace = true or [lints.rust] unsafe_code = 'forbid'"
                    ),
                    remediation=DIAGNOSTIC_REGISTRY[ERR_MANIFEST_LINT_NOT_FORBIDDEN]["remediation"],
                    params={"crate": pkg_name},
                )
            )

    return findings


def find_rust_attributes(src: str) -> list[tuple[int, int, bool, str]]:
    """Extracts all Rust outer (#[...]) and inner (#![...]) attributes from stripped source.

    Returns list of (start_idx, end_idx, is_inner, attribute_content).
    """
    attributes: list[tuple[int, int, bool, str]] = []
    i = 0
    n = len(src)
    while i < n:
        if src[i] == "#":
            start_idx = i
            j = i + 1
            while j < n and src[j] in " \t\r\n":
                j += 1
            is_inner = False
            if j < n and src[j] == "!":
                is_inner = True
                j += 1
                while j < n and src[j] in " \t\r\n":
                    j += 1
            if j < n and src[j] == "[":
                bracket_depth = 1
                k = j + 1
                while k < n and bracket_depth > 0:
                    if src[k] == "[":
                        bracket_depth += 1
                    elif src[k] == "]":
                        bracket_depth -= 1
                    k += 1
                if bracket_depth == 0:
                    end_idx = k
                    content = src[j + 1 : end_idx - 1]
                    attributes.append((start_idx, end_idx, is_inner, content))
                    i = end_idx
                    continue
        i += 1
    return attributes


def is_unsafe_permitting_attribute(content: str) -> bool:
    """Returns True if attribute content permits or tolerates unsafe_code."""
    if not re.search(r"\bunsafe_code\b", content):
        return False
    # Check for allow(unsafe_code), warn(unsafe_code), expect(unsafe_code)
    # across newlines, inside cfg_attr, or among multiple lints
    if re.search(r"\b(?:allow|warn|expect)\s*\([^)]*\bunsafe_code\b", content, re.DOTALL):
        return True
    # Also balance parentheses to catch nested arguments e.g. allow(nested(a, b), unsafe_code)
    for m in re.finditer(r"\b(?:allow|warn|expect)\s*\(", content):
        start_paren = m.end() - 1
        depth = 1
        k = start_paren + 1
        while k < len(content) and depth > 0:
            if content[k] == "(":
                depth += 1
            elif content[k] == ")":
                depth -= 1
            k += 1
        if depth == 0:
            arg_content = content[start_paren + 1 : k - 1]
            if re.search(r"\bunsafe_code\b", arg_content):
                return True
    return False


def _collect_directory_targets(
    pkg_dir: Path,
    pkg_name: str,
    root: Path,
    seen_target_paths: set[Path],
    autotests: bool = True,
    autoexamples: bool = True,
    autobenches: bool = True,
    build_enabled: bool = True,
) -> list[dict[str, Any]]:
    """Inspects package directory for target files that might be omitted from cargo metadata."""
    targets: list[dict[str, Any]] = []
    if not pkg_dir.is_dir():
        return targets

    # tests/
    test_dir = pkg_dir / "tests"
    if autotests and test_dir.is_dir():
        for p in sorted(test_dir.iterdir()):
            if p.is_file() and p.suffix == ".rs" and p.resolve() not in seen_target_paths:
                seen_target_paths.add(p.resolve())
                targets.append({
                    "crate": pkg_name,
                    "target_name": p.stem,
                    "kinds": ["test"],
                    "src_path": sanitize_path(p, root),
                    "path": p.resolve(),
                })
            elif p.is_dir() and (p / "main.rs").is_file() and (p / "main.rs").resolve() not in seen_target_paths:
                main_p = (p / "main.rs").resolve()
                seen_target_paths.add(main_p)
                targets.append({
                    "crate": pkg_name,
                    "target_name": p.name,
                    "kinds": ["test"],
                    "src_path": sanitize_path(main_p, root),
                    "path": main_p,
                })

    # examples/
    ex_dir = pkg_dir / "examples"
    if autoexamples and ex_dir.is_dir():
        for p in sorted(ex_dir.iterdir()):
            if p.is_file() and p.suffix == ".rs" and p.resolve() not in seen_target_paths:
                seen_target_paths.add(p.resolve())
                targets.append({
                    "crate": pkg_name,
                    "target_name": p.stem,
                    "kinds": ["example"],
                    "src_path": sanitize_path(p, root),
                    "path": p.resolve(),
                })
            elif p.is_dir() and (p / "main.rs").is_file() and (p / "main.rs").resolve() not in seen_target_paths:
                main_p = (p / "main.rs").resolve()
                seen_target_paths.add(main_p)
                targets.append({
                    "crate": pkg_name,
                    "target_name": p.name,
                    "kinds": ["example"],
                    "src_path": sanitize_path(main_p, root),
                    "path": main_p,
                })

    # benches/
    bench_dir = pkg_dir / "benches"
    if autobenches and bench_dir.is_dir():
        for p in sorted(bench_dir.iterdir()):
            if p.is_file() and p.suffix == ".rs" and p.resolve() not in seen_target_paths:
                seen_target_paths.add(p.resolve())
                targets.append({
                    "crate": pkg_name,
                    "target_name": p.stem,
                    "kinds": ["bench"],
                    "src_path": sanitize_path(p, root),
                    "path": p.resolve(),
                })
            elif p.is_dir() and (p / "main.rs").is_file() and (p / "main.rs").resolve() not in seen_target_paths:
                main_p = (p / "main.rs").resolve()
                seen_target_paths.add(main_p)
                targets.append({
                    "crate": pkg_name,
                    "target_name": p.name,
                    "kinds": ["bench"],
                    "src_path": sanitize_path(main_p, root),
                    "path": main_p,
                })

    # build.rs
    build_rs = pkg_dir / "build.rs"
    if build_enabled and build_rs.is_file() and build_rs.resolve() not in seen_target_paths:
        seen_target_paths.add(build_rs.resolve())
        targets.append({
            "crate": pkg_name,
            "target_name": f"{pkg_name}-build",
            "kinds": ["custom-build"],
            "src_path": sanitize_path(build_rs, root),
            "path": build_rs.resolve(),
        })

    # build helper directories (e.g. build/, build_helper/, build_helpers/)
    for helper_name in ("build", "build_helper", "build_helpers"):
        helper_dir = pkg_dir / helper_name
        if helper_dir.is_dir():
            for p in sorted(helper_dir.iterdir()):
                if p.is_file() and p.suffix == ".rs" and p.resolve() not in seen_target_paths:
                    seen_target_paths.add(p.resolve())
                    targets.append({
                        "crate": pkg_name,
                        "target_name": p.stem,
                        "kinds": ["build-helper"],
                        "src_path": sanitize_path(p, root),
                        "path": p.resolve(),
                    })
                elif p.is_dir() and (p / "mod.rs").is_file() and (p / "mod.rs").resolve() not in seen_target_paths:
                    mod_p = (p / "mod.rs").resolve()
                    seen_target_paths.add(mod_p)
                    targets.append({
                        "crate": pkg_name,
                        "target_name": p.name,
                        "kinds": ["build-helper"],
                        "src_path": sanitize_path(mod_p, root),
                        "path": mod_p,
                    })

    return targets


def check_target_roots(
    packages: list[dict[str, Any]],
    workspace_members: set[str],
    root: Path,
) -> tuple[list[UnsafeFinding], list[dict[str, Any]]]:
    """Verifies that every target root file declares unconditional #![forbid(unsafe_code)]."""
    findings: list[UnsafeFinding] = []
    enumerated_targets: list[dict[str, Any]] = []
    seen_target_paths: set[Path] = set()
    known_pkg_dirs: set[Path] = set()

    for pkg in packages:
        pkg_id = pkg.get("id", "")
        pkg_name = pkg.get("name", "unknown")
        manifest_str = pkg.get("manifest_path")
        if manifest_str:
            try:
                known_pkg_dirs.add(Path(manifest_str).parent.resolve())
            except OSError:
                pass

        if workspace_members and pkg_id not in workspace_members:
            continue

        targets = pkg.get("targets", [])
        for t in targets:
            t_name = t.get("name", "unknown")
            t_kinds = t.get("kind", [])
            src_path_str = t.get("src_path")
            if not src_path_str:
                continue

            src_path = Path(src_path_str).resolve()
            seen_target_paths.add(src_path)
            rel_src = sanitize_path(src_path, root)

            enumerated_targets.append({
                "crate": pkg_name,
                "target_name": t_name,
                "kinds": t_kinds,
                "src_path": rel_src,
                "path": src_path,
            })

        # Also inspect package directory for target files that might be omitted from cargo metadata
        # (e.g. build helpers) while respecting explicit autotests/autoexamples/autobenches/build settings
        if manifest_str:
            pkg_dir = Path(manifest_str).parent
            m_data_member: dict[str, Any] = {}
            try:
                m_data_member = tomllib.loads(Path(manifest_str).read_text(encoding="utf-8"))
            except (OSError, tomllib.TOMLDecodeError, UnicodeDecodeError):
                pass
            pkg_sec = m_data_member.get("package") if isinstance(m_data_member, dict) else None
            if not isinstance(pkg_sec, dict):
                pkg_sec = {}

            member_autotests = pkg_sec.get("autotests", True) is not False
            member_autoexamples = pkg_sec.get("autoexamples", True) is not False
            member_autobenches = pkg_sec.get("autobenches", True) is not False
            member_pkg_build = pkg_sec.get("build")
            member_has_custom_build = (
                (isinstance(member_pkg_build, str) and bool(member_pkg_build.strip()))
                or (isinstance(member_pkg_build, list) and any(isinstance(x, str) and bool(x.strip()) for x in member_pkg_build))
                or (member_pkg_build is True)
            )
            member_build_enabled = (member_pkg_build is not False) and not member_has_custom_build

            enumerated_targets.extend(
                _collect_directory_targets(
                    pkg_dir,
                    pkg_name,
                    root,
                    seen_target_paths,
                    autotests=member_autotests,
                    autoexamples=member_autoexamples,
                    autobenches=member_autobenches,
                    build_enabled=member_build_enabled,
                )
            )

    # Also inspect any unlisted / unregistered crate directories on disk
    disk_manifests = discover_disk_manifests(root)
    for disk_manifest in disk_manifests:
        try:
            pkg_dir = disk_manifest.parent.resolve()
        except OSError:
            continue
        if pkg_dir in known_pkg_dirs:
            continue
        rel_manifest = sanitize_path(disk_manifest, root)
        try:
            m_data = tomllib.loads(disk_manifest.read_text(encoding="utf-8"))
        except (OSError, tomllib.TOMLDecodeError, UnicodeDecodeError) as exc:
            findings.append(
                UnsafeFinding(
                    code=ERR_TARGET_ROOT_MISSING_FORBID,
                    file=rel_manifest,
                    location="manifest",
                    message=f"Discovered manifest '{rel_manifest}' is unparseable: {exc}",
                    remediation=DIAGNOSTIC_REGISTRY[ERR_TARGET_ROOT_MISSING_FORBID]["remediation"],
                )
            )
            continue
        if not isinstance(m_data, dict):
            findings.append(
                UnsafeFinding(
                    code=ERR_TARGET_ROOT_MISSING_FORBID,
                    file=rel_manifest,
                    location="manifest",
                    message=f"Discovered manifest '{rel_manifest}' must be a table",
                    remediation=DIAGNOSTIC_REGISTRY[ERR_TARGET_ROOT_MISSING_FORBID]["remediation"],
                )
            )
            continue

        if "package" not in m_data:
            continue

        pkg_section = m_data.get("package")
        if not isinstance(pkg_section, dict):
            findings.append(
                UnsafeFinding(
                    code=ERR_TARGET_ROOT_MISSING_FORBID,
                    file=rel_manifest,
                    location="package",
                    message=f"Manifest '{rel_manifest}' [package] must be a table, got {type(pkg_section).__name__}",
                    remediation=DIAGNOSTIC_REGISTRY[ERR_TARGET_ROOT_MISSING_FORBID]["remediation"],
                )
            )
            continue

        pkg_name = pkg_section.get("name") if isinstance(pkg_section.get("name"), str) else disk_manifest.parent.name
        pkg_edition = str(pkg_section.get("edition", "2015")) if isinstance(pkg_section, dict) else "2015"

        # 1. Custom [lib] target path
        lib_section = m_data.get("lib")
        has_custom_lib = False
        autolib = pkg_section.get("autolib", True) is not False if isinstance(pkg_section, dict) else True
        if isinstance(lib_section, dict):
            custom_lib_path_str = lib_section.get("path")
            if isinstance(custom_lib_path_str, str) and custom_lib_path_str.strip():
                has_custom_lib = True
                custom_lib_path = (disk_manifest.parent / custom_lib_path_str.strip()).resolve()
                if custom_lib_path not in seen_target_paths:
                    seen_target_paths.add(custom_lib_path)
                    lib_t_name = lib_section.get("name", pkg_name)
                    enumerated_targets.append({
                        "crate": pkg_name,
                        "target_name": lib_t_name if isinstance(lib_t_name, str) else pkg_name,
                        "kinds": ["lib"],
                        "src_path": sanitize_path(custom_lib_path, root),
                        "path": custom_lib_path,
                    })
            else:
                has_custom_lib = True
                src_lib = disk_manifest.parent / "src" / "lib.rs"
                if src_lib.is_file() and src_lib.resolve() not in seen_target_paths:
                    seen_target_paths.add(src_lib.resolve())
                    lib_t_name = lib_section.get("name", pkg_name)
                    enumerated_targets.append({
                        "crate": pkg_name,
                        "target_name": lib_t_name if isinstance(lib_t_name, str) else pkg_name,
                        "kinds": ["lib"],
                        "src_path": sanitize_path(src_lib, root),
                        "path": src_lib.resolve(),
                    })
                elif pkg_edition == "2015":
                    lib_t_name = lib_section.get("name", pkg_name)
                    if not isinstance(lib_t_name, str) or not lib_t_name.strip():
                        lib_t_name = pkg_name
                    legacy_name = lib_t_name.strip().replace("-", "_")
                    legacy_lib = disk_manifest.parent / "src" / f"{legacy_name}.rs"
                    if legacy_lib.is_file() and legacy_lib.resolve() not in seen_target_paths:
                        seen_target_paths.add(legacy_lib.resolve())
                        enumerated_targets.append({
                            "crate": pkg_name,
                            "target_name": lib_t_name,
                            "kinds": ["lib"],
                            "src_path": sanitize_path(legacy_lib, root),
                            "path": legacy_lib.resolve(),
                        })

        # Standard lib.rs if no custom lib declared
        if not has_custom_lib:
            if autolib:
                src_lib = disk_manifest.parent / "src" / "lib.rs"
                if src_lib.is_file() and src_lib.resolve() not in seen_target_paths:
                    seen_target_paths.add(src_lib.resolve())
                    enumerated_targets.append({
                        "crate": pkg_name,
                        "target_name": pkg_name,
                        "kinds": ["lib"],
                        "src_path": sanitize_path(src_lib, root),
                        "path": src_lib.resolve(),
                    })

        # 2. Custom [[bin]] target paths
        bin_sections = m_data.get("bin")
        autobins = pkg_section.get("autobins", True) is not False if isinstance(pkg_section, dict) else True
        has_custom_bins = not autobins
        if isinstance(bin_sections, list):
            for b in bin_sections:
                if isinstance(b, dict):
                    custom_bin_path_str = b.get("path")
                    if isinstance(custom_bin_path_str, str) and custom_bin_path_str.strip():
                        custom_bin_path = (disk_manifest.parent / custom_bin_path_str.strip()).resolve()
                        if custom_bin_path not in seen_target_paths:
                            seen_target_paths.add(custom_bin_path)
                            b_t_name = b.get("name", pkg_name)
                            enumerated_targets.append({
                                "crate": pkg_name,
                                "target_name": b_t_name if isinstance(b_t_name, str) else pkg_name,
                                "kinds": ["bin"],
                                "src_path": sanitize_path(custom_bin_path, root),
                                "path": custom_bin_path,
                            })
                    elif isinstance(b.get("name"), str):
                        b_name = b["name"].strip()
                        candidates: list[Path] = []
                        if b_name == pkg_name:
                            candidates.append(disk_manifest.parent / "src" / "main.rs")
                        candidates.append(disk_manifest.parent / "src" / "bin" / f"{b_name}.rs")
                        candidates.append(disk_manifest.parent / "src" / "bin" / b_name / "main.rs")
                        if pkg_edition == "2015":
                            candidates.append(disk_manifest.parent / "src" / f"{b_name}.rs")
                            if disk_manifest.parent / "src" / "main.rs" not in candidates:
                                candidates.append(disk_manifest.parent / "src" / "main.rs")
                            candidates.append(disk_manifest.parent / "src" / "bin" / "main.rs")
                        for cand in candidates:
                            if cand.is_file() and cand.resolve() not in seen_target_paths:
                                seen_target_paths.add(cand.resolve())
                                enumerated_targets.append({
                                    "crate": pkg_name,
                                    "target_name": b_name,
                                    "kinds": ["bin"],
                                    "src_path": sanitize_path(cand, root),
                                    "path": cand.resolve(),
                                })

        # Standard main.rs and bin/ if no custom bins declared
        if not has_custom_bins:
            src_main = disk_manifest.parent / "src" / "main.rs"
            if src_main.is_file() and src_main.resolve() not in seen_target_paths:
                seen_target_paths.add(src_main.resolve())
                enumerated_targets.append({
                    "crate": pkg_name,
                    "target_name": pkg_name,
                    "kinds": ["bin"],
                    "src_path": sanitize_path(src_main, root),
                    "path": src_main.resolve(),
                })

            bin_dir = disk_manifest.parent / "src" / "bin"
            if bin_dir.is_dir():
                for p in sorted(bin_dir.iterdir()):
                    if p.is_file() and p.suffix == ".rs" and p.resolve() not in seen_target_paths:
                        seen_target_paths.add(p.resolve())
                        enumerated_targets.append({
                            "crate": pkg_name,
                            "target_name": p.stem,
                            "kinds": ["bin"],
                            "src_path": sanitize_path(p, root),
                            "path": p.resolve(),
                        })
                    elif p.is_dir() and (p / "main.rs").is_file() and (p / "main.rs").resolve() not in seen_target_paths:
                        main_p = (p / "main.rs").resolve()
                        seen_target_paths.add(main_p)
                        enumerated_targets.append({
                            "crate": pkg_name,
                            "target_name": p.name,
                            "kinds": ["bin"],
                            "src_path": sanitize_path(main_p, root),
                            "path": main_p,
                        })

        # 3. Custom [[example]] target paths
        example_sections = m_data.get("example")
        if isinstance(example_sections, list):
            for ex in example_sections:
                if isinstance(ex, dict):
                    custom_ex_path_str = ex.get("path")
                    if isinstance(custom_ex_path_str, str) and custom_ex_path_str.strip():
                        custom_ex_path = (disk_manifest.parent / custom_ex_path_str.strip()).resolve()
                        if custom_ex_path not in seen_target_paths:
                            seen_target_paths.add(custom_ex_path)
                            ex_t_name = ex.get("name", "example")
                            enumerated_targets.append({
                                "crate": pkg_name,
                                "target_name": ex_t_name if isinstance(ex_t_name, str) else "example",
                                "kinds": ["example"],
                                "src_path": sanitize_path(custom_ex_path, root),
                                "path": custom_ex_path,
                            })
                    elif isinstance(ex.get("name"), str):
                        ex_name = ex["name"].strip()
                        ex_candidates = [
                            disk_manifest.parent / "examples" / f"{ex_name}.rs",
                            disk_manifest.parent / "examples" / ex_name / "main.rs",
                        ]
                        for cand in ex_candidates:
                            if cand.is_file():
                                resolved_cand = cand.resolve()
                                if resolved_cand not in seen_target_paths:
                                    seen_target_paths.add(resolved_cand)
                                    enumerated_targets.append({
                                        "crate": pkg_name,
                                        "target_name": ex_name,
                                        "kinds": ["example"],
                                        "src_path": sanitize_path(cand, root),
                                        "path": resolved_cand,
                                    })
                                break

        # 4. Custom [[test]] and [[bench]] target paths
        for target_key, kind_name, dir_name in [("test", "test", "tests"), ("bench", "bench", "benches")]:
            sections = m_data.get(target_key)
            if isinstance(sections, list):
                for sec in sections:
                    if isinstance(sec, dict):
                        custom_path_str = sec.get("path")
                        if isinstance(custom_path_str, str) and custom_path_str.strip():
                            custom_p = (disk_manifest.parent / custom_path_str.strip()).resolve()
                            if custom_p not in seen_target_paths:
                                seen_target_paths.add(custom_p)
                                sec_t_name = sec.get("name", target_key)
                                enumerated_targets.append({
                                    "crate": pkg_name,
                                    "target_name": sec_t_name if isinstance(sec_t_name, str) else target_key,
                                    "kinds": [kind_name],
                                    "src_path": sanitize_path(custom_p, root),
                                    "path": custom_p,
                                })
                        elif isinstance(sec.get("name"), str):
                            sec_name = sec["name"].strip()
                            sec_candidates = [
                                disk_manifest.parent / dir_name / f"{sec_name}.rs",
                                disk_manifest.parent / dir_name / sec_name / "main.rs",
                            ]
                            for cand in sec_candidates:
                                if cand.is_file():
                                    resolved_cand = cand.resolve()
                                    if resolved_cand not in seen_target_paths:
                                        seen_target_paths.add(resolved_cand)
                                        enumerated_targets.append({
                                            "crate": pkg_name,
                                            "target_name": sec_name,
                                            "kinds": [kind_name],
                                            "src_path": sanitize_path(cand, root),
                                            "path": resolved_cand,
                                        })
                                    break

        # 5. Custom build script path declared in [package] build = "..." or build = ["...", ...]
        custom_build_raw = pkg_section.get("build") if isinstance(pkg_section, dict) else None
        has_custom_build = False
        if isinstance(custom_build_raw, str) and custom_build_raw.strip():
            has_custom_build = True
            custom_build_path = (disk_manifest.parent / custom_build_raw.strip()).resolve()
            if custom_build_path not in seen_target_paths:
                seen_target_paths.add(custom_build_path)
                enumerated_targets.append({
                    "crate": pkg_name,
                    "target_name": f"{pkg_name}-build",
                    "kinds": ["custom-build"],
                    "src_path": sanitize_path(custom_build_path, root),
                    "path": custom_build_path,
                })
        elif isinstance(custom_build_raw, list):
            for idx, item in enumerate(custom_build_raw):
                if isinstance(item, str) and item.strip():
                    has_custom_build = True
                    custom_build_path = (disk_manifest.parent / item.strip()).resolve()
                    if custom_build_path not in seen_target_paths:
                        seen_target_paths.add(custom_build_path)
                        enumerated_targets.append({
                            "crate": pkg_name,
                            "target_name": f"{pkg_name}-build-{idx}",
                            "kinds": ["custom-build"],
                            "src_path": sanitize_path(custom_build_path, root),
                            "path": custom_build_path,
                        })
        elif custom_build_raw is True:
            has_custom_build = True
            custom_build_path = (disk_manifest.parent / "build.rs").resolve()
            if custom_build_path not in seen_target_paths:
                seen_target_paths.add(custom_build_path)
                enumerated_targets.append({
                    "crate": pkg_name,
                    "target_name": f"{pkg_name}-build",
                    "kinds": ["custom-build"],
                    "src_path": sanitize_path(custom_build_path, root),
                    "path": custom_build_path,
                })

        autotests = pkg_section.get("autotests", True) is not False if isinstance(pkg_section, dict) else True
        autoexamples = pkg_section.get("autoexamples", True) is not False if isinstance(pkg_section, dict) else True
        autobenches = pkg_section.get("autobenches", True) is not False if isinstance(pkg_section, dict) else True
        build_enabled = (custom_build_raw is not False if isinstance(pkg_section, dict) else True) and not has_custom_build

        # Collect tests, examples, benches, build.rs, build_helpers
        enumerated_targets.extend(
            _collect_directory_targets(
                disk_manifest.parent,
                pkg_name,
                root,
                seen_target_paths,
                autotests=autotests,
                autoexamples=autoexamples,
                autobenches=autobenches,
                build_enabled=build_enabled,
            )
        )

    for target_info in enumerated_targets:
        src_path: Path = target_info["path"]
        rel_src: str = target_info["src_path"]
        pkg_name = target_info["crate"]
        t_name = target_info["target_name"]
        kind_str = ",".join(target_info["kinds"])

        if not src_path.is_file():
            findings.append(
                UnsafeFinding(
                    code=ERR_TARGET_ROOT_MISSING_FORBID,
                    file=rel_src,
                    location="target_root",
                    message=f"Target root file does not exist: '{rel_src}'",
                    remediation=DIAGNOSTIC_REGISTRY[ERR_TARGET_ROOT_MISSING_FORBID]["remediation"],
                    params={"crate": pkg_name, "target": t_name, "kind": kind_str},
                )
            )
            continue

        try:
            raw_text = src_path.read_text(encoding="utf-8")
        except (OSError, UnicodeDecodeError) as exc:
            findings.append(
                UnsafeFinding(
                    code=ERR_TARGET_ROOT_MISSING_FORBID,
                    file=rel_src,
                    location="target_root",
                    message=f"Could not read target root '{rel_src}': {exc}",
                    remediation=DIAGNOSTIC_REGISTRY[ERR_TARGET_ROOT_MISSING_FORBID]["remediation"],
                    params={"crate": pkg_name, "target": t_name, "kind": kind_str},
                )
            )
            continue

        # Check stripped content for inner #![forbid(unsafe_code)]
        stripped = strip_rust_comments_and_strings(raw_text)
        if not FORBID_UNSAFE_RE.search(stripped):
            findings.append(
                UnsafeFinding(
                    code=ERR_TARGET_ROOT_MISSING_FORBID,
                    file=rel_src,
                    location="target_root",
                    message=(
                        f"Target root '{rel_src}' ({pkg_name}::{t_name} [{kind_str}]) "
                        f"lacks unconditional #![forbid(unsafe_code)]"
                    ),
                    remediation=DIAGNOSTIC_REGISTRY[ERR_TARGET_ROOT_MISSING_FORBID]["remediation"],
                    params={"crate": pkg_name, "target": t_name, "kind": kind_str},
                )
            )

    clean_targets = [
        {
            "crate": t["crate"],
            "target_name": t["target_name"],
            "kinds": t["kinds"],
            "src_path": t["src_path"],
        }
        for t in enumerated_targets
    ]
    return findings, clean_targets


def check_rust_source_file(rs_path: Path, root: Path) -> list[UnsafeFinding]:
    """Scans a single Rust source file for unsafe-permitting attributes and unsafe constructs."""
    findings: list[UnsafeFinding] = []
    rel_path = sanitize_path(rs_path, root)

    try:
        raw_text = rs_path.read_text(encoding="utf-8")
    except (OSError, UnicodeDecodeError) as exc:
        findings.append(
            UnsafeFinding(
                code=ERR_UNSAFE_CONSTRUCT_DETECTED,
                file=rel_path,
                location="file",
                message=f"Could not read source file '{rel_path}': {exc}",
                remediation="Fix file permissions and readability",
            )
        )
        return findings

    stripped = strip_rust_comments_and_strings(raw_text)
    attributes = find_rust_attributes(stripped)

    # 1. Check for unsafe-permitting attributes (single-line, multiline, nested, cfg_attr)
    for start_idx, end_idx, _is_inner, content in attributes:
        if is_unsafe_permitting_attribute(content):
            line_idx = raw_text[:start_idx].count("\n") + 1
            raw_snippet = raw_text[start_idx:end_idx].strip()
            findings.append(
                UnsafeFinding(
                    code=ERR_UNSAFE_ATTRIBUTE_PERMITTED,
                    file=rel_path,
                    location=f"line:{line_idx}",
                    message=(
                        f"Unsafe-permitting attribute '{raw_snippet}' found at line {line_idx}. "
                        f"AGENTS.md strictly forbids allow/warn/expect on unsafe_code."
                    ),
                    remediation=DIAGNOSTIC_REGISTRY[ERR_UNSAFE_ATTRIBUTE_PERMITTED]["remediation"],
                    params={"line": line_idx, "attribute": raw_snippet},
                )
            )

    # 2. Check for unsafe constructs in code
    # Mask out ALL attributes so their contents (including valid forbid(unsafe_code))
    # do not trigger \bunsafe\b checks. Preserve newlines so line numbers remain exact.
    mask_chars = list(stripped)
    for start_idx, end_idx, _, _ in attributes:
        for k in range(start_idx, end_idx):
            if mask_chars[k] != "\n":
                mask_chars[k] = " "
    code_without_attrs = "".join(mask_chars)

    lines = code_without_attrs.splitlines()
    raw_lines = raw_text.splitlines()

    for line_idx, line in enumerate(lines, start=1):
        for m in re.finditer(r"\bunsafe\b", line):
            col = m.start() + 1
            remainder = line[m.end() :].lstrip()

            if remainder.startswith("{"):
                construct = "unsafe block"
            elif remainder.startswith("move") and remainder[4:].lstrip().startswith("{"):
                construct = "unsafe move block"
            elif remainder.startswith("async") and remainder[5:].lstrip().startswith("{"):
                construct = "unsafe async block"
            elif remainder.startswith("fn") or (
                remainder.startswith("extern") and "fn" in remainder
            ):
                construct = "unsafe function"
            elif remainder.startswith("impl"):
                construct = "unsafe impl"
            elif remainder.startswith("trait"):
                construct = "unsafe trait"
            elif remainder.startswith("extern"):
                construct = "unsafe extern block"
            else:
                construct = "unsafe construct"

            raw_snippet = (
                raw_lines[line_idx - 1].strip() if line_idx - 1 < len(raw_lines) else line.strip()
            )
            findings.append(
                UnsafeFinding(
                    code=ERR_UNSAFE_CONSTRUCT_DETECTED,
                    file=rel_path,
                    location=f"line:{line_idx}:col:{col}",
                    message=f"Forbidden {construct} detected: `{raw_snippet}`",
                    remediation=DIAGNOSTIC_REGISTRY[ERR_UNSAFE_CONSTRUCT_DETECTED]["remediation"],
                    params={
                        "line": line_idx,
                        "col": col,
                        "construct": construct,
                        "snippet": raw_snippet,
                    },
                )
            )

    return findings


def discover_rust_files(root: Path, packages: list[dict[str, Any]] | None = None) -> list[Path]:
    """Discovers all Rust source files in workspace packages and under repository root."""
    rust_files: set[Path] = set()

    # Always scan the repository root (excluding excluded dirs)
    if root.is_dir():
        for dirpath, dirnames, filenames in os.walk(root):
            dirnames[:] = [d for d in dirnames if d not in EXCLUDED_DIR_NAMES]
            for f in filenames:
                if f.endswith(".rs"):
                    rust_files.add(Path(dirpath) / f)

    # Also scan any package directories outside root if any
    if packages:
        for pkg in packages:
            manifest_str = pkg.get("manifest_path")
            if manifest_str:
                pkg_dir = Path(manifest_str).parent
                if pkg_dir.is_dir():
                    for dirpath, dirnames, filenames in os.walk(pkg_dir):
                        dirnames[:] = [d for d in dirnames if d not in EXCLUDED_DIR_NAMES]
                        for f in filenames:
                            if f.endswith(".rs"):
                                rust_files.add(Path(dirpath) / f)

    return sorted(rust_files)


def audit_unsafe_prohibition(
    root: Path = ROOT,
    manifest_path: Path | None = None,
    raw_metadata: dict[str, Any] | None = None,
) -> tuple[bool, list[UnsafeFinding], dict[str, Any]]:
    """Runs complete fail-closed verification of the unsafe prohibition across all targets and crates."""
    findings: list[UnsafeFinding] = []

    # 1. Fetch cargo metadata
    if raw_metadata is not None:
        metadata = raw_metadata
        meta_err = None
    else:
        metadata, meta_err = run_cargo_metadata(root, manifest_path=manifest_path)

    if metadata is None:
        findings.append(
            UnsafeFinding(
                code=ERR_METADATA_UNREADABLE,
                file=sanitize_path(manifest_path or (root / "Cargo.toml"), root),
                location="metadata",
                message=f"Could not read cargo metadata: {meta_err}",
                remediation=DIAGNOSTIC_REGISTRY[ERR_METADATA_UNREADABLE]["remediation"],
                params={"error": meta_err or "unknown"},
            )
        )
        summary = {
            "status": "fail",
            "error_count": 1,
            "target_count": 0,
            "crate_count": 0,
            "rust_file_count": 0,
        }
    packages = metadata.get("packages") if isinstance(metadata, dict) else None
    if not isinstance(packages, list) or len(packages) == 0:
        findings.append(
            UnsafeFinding(
                code=ERR_METADATA_UNREADABLE,
                file=sanitize_path(manifest_path or (root / "Cargo.toml"), root),
                location="metadata",
                message="Cargo metadata contains no packages or is empty/degenerate",
                remediation=DIAGNOSTIC_REGISTRY[ERR_METADATA_UNREADABLE]["remediation"],
                params={"error": "empty_or_missing_packages"},
            )
        )
        summary = {
            "status": "fail",
            "error_count": 1,
            "target_count": 0,
            "crate_count": 0,
            "rust_file_count": 0,
            "workspace_members_count": 0,
        }
        return False, findings, summary

    workspace_members = set(metadata.get("workspace_members", []))
    workspace_root_str = metadata.get("workspace_root")
    workspace_root = Path(workspace_root_str) if workspace_root_str else root

    # 2. Check manifest lints
    manifest_findings = check_manifest_lints(
        workspace_root=workspace_root,
        packages=packages,
        workspace_members=workspace_members,
        root=root,
    )
    findings.extend(manifest_findings)

    # 3. Check target roots from cargo metadata
    target_findings, enumerated_targets = check_target_roots(
        packages=packages,
        workspace_members=workspace_members,
        root=root,
    )
    findings.extend(target_findings)

    # 4. Check all Rust source files for attributes and unsafe constructs
    all_rust_files = discover_rust_files(root=root, packages=packages)
    for rs_file in all_rust_files:
        src_findings = check_rust_source_file(rs_file, root=root)
        findings.extend(src_findings)

    error_count = len(findings)
    is_valid = error_count == 0

    summary = {
        "status": "pass" if is_valid else "fail",
        "error_count": error_count,
        "target_count": len(enumerated_targets),
        "crate_count": len(packages),
        "rust_file_count": len(all_rust_files),
        "workspace_members_count": len(workspace_members),
    }

    return is_valid, findings, summary


def main() -> int:
    parser = argparse.ArgumentParser(
        description="FSS-182 Enforce FSS unsafe prohibition across targets, features, examples and tests."
    )
    parser.add_argument("--root", type=Path, default=ROOT, help="Repository root path")
    parser.add_argument(
        "--manifest-path", type=Path, default=None, help="Path to Cargo.toml"
    )
    parser.add_argument(
        "--json", action="store_true", help="Output machine-readable JSON report"
    )
    parser.add_argument(
        "--quiet", action="store_true", help="Suppress non-error output"
    )
    args = parser.parse_args()

    is_valid, findings, summary = audit_unsafe_prohibition(
        root=args.root,
        manifest_path=args.manifest_path,
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
                f"[{tag}] Unsafe prohibition audit: {summary['target_count']} targets across "
                f"{summary['crate_count']} crates ({summary['rust_file_count']} Rust files verified), "
                f"{summary['error_count']} errors"
            )
            for f in findings:
                print(f"  ERROR [{f.code}] {f.file}:{f.location}: {f.message}")
                if f.remediation:
                    print(f"    Remediation: {f.remediation}")

    return 0 if is_valid else 1


if __name__ == "__main__":
    sys.exit(main())
