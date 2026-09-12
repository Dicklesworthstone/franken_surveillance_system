#!/usr/bin/env python3
"""Cargo dependency and target root audit oracle (fss-x4a.6.18).

Enumerates the full Cargo workspace semantic surface, all target roots,
workspace globs/excludes, target cfg dependency tables, and verifies
unconditional #![forbid(unsafe_code)] enforcement across all targets.

DEP-AUD-023 (fss-x4a.9.17, FSS-110) refuses Serde-family codec crates in any FSS manifest
dependency table or Cargo.lock, and Serde derives/paths/attributes in FSS Rust source. Source is
scanned after masking comments and string/char literals (``mask_rust_source``); this is a
lexer-level deny-list, not a Rust parser, so macro-generated or ``include!``-spliced code is not seen.

DEP-AUD-026 (fss-x4a.26.3, FSS-183) scans every build script (implicit ``build.rs``, ``build = true``,
``build = "path"``, undeclared nested crates, and custom-build ``src_path`` values from resolved cargo
metadata) for network-capable constructs. It is a STATIC DENY-LIST, NOT A PROOF OF ABSENCE.
DEP-AUD-027 requires ``scripts/qualify.sh`` and ``scripts/release_qualify.sh`` to export
``CARGO_NET_OFFLINE=true`` and ``RUSTUP_AUTO_INSTALL=0`` at top level and to pass ``--offline`` to every
cargo invocation, and forbids rustup commands that fetch toolchains (``rustup install``/``update``,
``rustup toolchain install``, ``rustup run --install``, ...). That seals Cargo resolution and rustup
toolchain fetching; it is not OS-level network isolation.
DEP-AUD-028 (fss-tgwit) requires the ``rust_lane`` of ``scripts/qualify.sh`` to record a
``cargo test --workspace --doc`` step, because ``cargo test --all-targets`` never runs doctests.
"""
from __future__ import annotations

import argparse
import bisect
import fnmatch
import hashlib
import json
import re
import shutil
import subprocess
import sys
import tomllib
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
ALLOWLIST = ROOT / "architecture/dependency_allowlist.toml"
CARGO_LOCK = ROOT / "Cargo.lock"
TOOLCHAIN = ROOT / "rust-toolchain.toml"

FORBID_UNSAFE_PATTERN = re.compile(r"#\s*!\s*\[\s*forbid\s*\(\s*unsafe_code\s*\)\s*\]")

SECRET_PATTERNS = [
    re.compile(r"gh[pousr]_[A-Za-z0-9_]{36,255}"),
    re.compile(r"(?:bearer|token|password|secret|apikey)\s*[:=]\s*([^\s,;]+)", re.IGNORECASE),
    re.compile(r"-----BEGIN [A-Z ]+ PRIVATE KEY-----"),
]


def redact_user_paths(s: str) -> str:
    s = re.sub(r"([/\\]home[/\\])[^/\\\s]+", r"\1[USER]", s)
    s = re.sub(r"([/\\]Users[/\\])[^/\\\s]+", r"\1[USER]", s)
    s = re.sub(r"([a-zA-Z]:[/\\](?:Users|home)[/\\])[^/\\\s]+", r"\1[USER]", s, flags=re.IGNORECASE)
    s = re.sub(r"([/\\]var[/\\]home[/\\])[^/\\\s]+", r"\1[USER]", s)
    s = re.sub(r"([/\\]root\b)", r"[USER_ROOT]", s)
    s = re.sub(r"~[a-zA-Z0-9_-]+", "~[USER]", s)
    return s


def sanitize_string(s: str, max_len: int = 500, root: Path = ROOT) -> str:
    try:
        resolved_root = str(root.resolve())
        if resolved_root in s:
            s = s.replace(resolved_root + "/", "").replace(resolved_root + "\\", "").replace(resolved_root, "")
    except Exception:
        pass
    s = redact_user_paths(s)
    for pat in SECRET_PATTERNS:
        s = pat.sub("[REDACTED]", s)
    if len(s) > max_len:
        s = s[:max_len] + "...[TRUNCATED]"
    return s


def is_windows_or_unc_path(s: str) -> bool:
    return (len(s) >= 3 and s[0].isalpha() and s[1] == ":" and s[2] in "/\\") or s.startswith(("\\\\", "//"))


def sanitize_path(p: Path | str, root: Path = ROOT) -> str:
    s = str(p)
    if not is_windows_or_unc_path(s):
        try:
            p_obj = Path(p) if isinstance(p, str) else p
            resolved_root = root.resolve()
            resolved_p = p_obj.resolve()
            rel = resolved_p.relative_to(resolved_root).as_posix()
            return redact_user_paths(rel)
        except Exception:
            pass
    return sanitize_string(s, 200, root=root)


def sanitize_params(d: dict[str, Any], root: Path = ROOT) -> dict[str, Any]:
    sanitized: dict[str, Any] = {}
    for k, v in d.items():
        if isinstance(v, Path):
            sanitized[k] = sanitize_path(v, root)
        elif isinstance(v, str):
            if v.startswith(("/", "\\", ".")) or is_windows_or_unc_path(v) or "/home/" in v or "/Users/" in v or "\\Users\\" in v:
                sanitized[k] = sanitize_path(v, root)
            else:
                sanitized[k] = sanitize_string(v, root=root)
        elif isinstance(v, (int, float, bool)) or v is None:
            sanitized[k] = v
        elif isinstance(v, dict):
            sanitized[k] = sanitize_params(v, root)
        elif isinstance(v, (list, tuple, set)):
            sanitized[k] = [
                sanitize_path(x, root) if isinstance(x, Path)
                else (sanitize_path(x, root) if isinstance(x, str) and (x.startswith(("/", "\\", ".")) or is_windows_or_unc_path(x) or "/home/" in x or "/Users/" in x or "\\Users\\" in x)
                      else sanitize_string(str(x), root=root))
                for x in v
            ]
        else:
            sanitized[k] = sanitize_string(str(v), root=root)
    return sanitized


@dataclass(frozen=True)
class DiagnosticDef:
    code: str
    severity: str
    owner: str
    trigger: str
    remediation: str
    gate_effect: str = "GATE-000, QL-POLICY-001"
    retry_policy: str = "repair configuration before re-running qualification"


DIAGNOSTIC_REGISTRY: dict[str, DiagnosticDef] = {
    "DEP-AUD-001": DiagnosticDef(
        code="DEP-AUD-001",
        severity="error",
        owner="architecture-constitution",
        trigger="required-true dependency-policy key is absent or not true",
        remediation="correct the reviewed allowlist policy value or amend the constitution; never weaken the check",
    ),
    "DEP-AUD-002": DiagnosticDef(
        code="DEP-AUD-002",
        severity="error",
        owner="architecture-constitution",
        trigger="required-false dependency-policy key is absent or not false",
        remediation="remove the prohibited allowance or complete a reviewed constitutional change; never weaken the check",
    ),
    "DEP-AUD-010": DiagnosticDef(
        code="DEP-AUD-010",
        severity="error",
        owner="security-policy",
        trigger="a declared workspace member manifest is missing",
        remediation="restore/correct the exact member manifest and source fence before dependency claims",
    ),
    "DEP-AUD-011": DiagnosticDef(
        code="DEP-AUD-011",
        severity="error",
        owner="security-policy",
        trigger="a dependency section is not a TOML table",
        remediation="repair the manifest shape; do not ignore or coerce malformed dependency declarations",
    ),
    "DEP-AUD-012": DiagnosticDef(
        code="DEP-AUD-012",
        severity="error",
        owner="security-policy",
        trigger="a path dependency escapes the frozen repository or sibling closure",
        remediation="move it into the authorized closure or explicitly admit and pin the dependency",
    ),
    "DEP-AUD-013": DiagnosticDef(
        code="DEP-AUD-013",
        severity="error",
        owner="security-policy",
        trigger="a Git dependency lacks an exact 40-hex revision",
        remediation="pin an immutable reviewed commit and retain source/provenance evidence",
    ),
    "DEP-AUD-014": DiagnosticDef(
        code="DEP-AUD-014",
        severity="error",
        owner="security-policy",
        trigger="a build dependency is present without constitutional admission",
        remediation="remove it or complete the explicit dependency/ADR/security admission; no implicit build scripts",
    ),
    "DEP-AUD-015": DiagnosticDef(
        code="DEP-AUD-015",
        severity="error",
        owner="security-policy",
        trigger="a direct dependency names a forbidden crate",
        remediation="remove the forbidden crate and repair the design without an unsafe/foreign substitute",
    ),
    "DEP-AUD-016": DiagnosticDef(
        code="DEP-AUD-016",
        severity="error",
        owner="security-policy",
        trigger="a direct external dependency is outside the closed allowlist",
        remediation="remove it or add a reviewed exact allowlist/DEP/ADR admission with closure proof",
    ),
    "DEP-AUD-017": DiagnosticDef(
        code="DEP-AUD-017",
        severity="error",
        owner="security-policy",
        trigger="an external dependency does not disable default features",
        remediation="set default-features=false and explicitly admit only audited features",
    ),
    "DEP-AUD-018": DiagnosticDef(
        code="DEP-AUD-018",
        severity="error",
        owner="security-policy",
        trigger="workspace-inherited dependency resolution failure or missing workspace key",
        remediation="define the dependency in [workspace.dependencies] or remove workspace = true",
    ),
    "DEP-AUD-019": DiagnosticDef(
        code="DEP-AUD-019",
        severity="error",
        owner="security-policy",
        trigger="an undeclared non-member path crate was detected within the repository tree",
        remediation="declare the path crate in workspace members or remove it from the repository tree",
    ),
    "DEP-AUD-020": DiagnosticDef(
        code="DEP-AUD-020",
        severity="error",
        owner="architecture-constitution",
        trigger="a crate has no inspectable Rust target root",
        remediation="restore/register the target root so unsafe and production-boundary policy is verifiable",
    ),
    "DEP-AUD-021": DiagnosticDef(
        code="DEP-AUD-021",
        severity="error",
        owner="architecture-constitution",
        trigger="a Rust target root lacks unconditional forbid unsafe_code",
        remediation="add the unconditional crate-level prohibition; no local exception path exists",
    ),
    "DEP-AUD-022": DiagnosticDef(
        code="DEP-AUD-022",
        severity="error",
        owner="architecture-constitution",
        trigger="FSS Rust source contains a forbidden production construct",
        remediation="remove unsafe, native/dynamic/foreign runtime, second executor, or prohibited construct",
    ),
    "DEP-AUD-023": DiagnosticDef(
        code="DEP-AUD-023",
        severity="error",
        owner="architecture-constitution",
        trigger="a serde-family codec crate or Serde derive/path/attribute is present in FSS manifests, Cargo.lock, or Rust source",
        remediation="remove it and encode durable bytes with the first-party canonical codec; no non-durable serde admission path exists (FSS-110)",
    ),
    "DEP-AUD-024": DiagnosticDef(
        code="DEP-AUD-024",
        severity="error",
        owner="security-policy",
        trigger="workspace membership duplicate or ambiguous across glob and explicit patterns",
        remediation="ensure each member directory and crate name is uniquely declared once in workspace.members",
    ),
    "DEP-AUD-025": DiagnosticDef(
        code="DEP-AUD-025",
        severity="error",
        owner="security-policy",
        trigger="declared workspace root manifest lacks [workspace] table",
        remediation="add [workspace] table to root Cargo.toml or correct the workspace path",
    ),
    "DEP-AUD-026": DiagnosticDef(
        code="DEP-AUD-026",
        severity="error",
        owner="security-policy",
        trigger="a build script contains a network-capable construct on the static deny-list",
        remediation="remove the network access; build scripts must run offline and stay refused by DEP-AUD-031 (static deny-list, not proof of absence)",
    ),
    "DEP-AUD-027": DiagnosticDef(
        code="DEP-AUD-027",
        severity="error",
        owner="security-policy",
        trigger="a qualification script (scripts/qualify.sh or scripts/release_qualify.sh) does not seal Cargo and rustup offline (missing top-level CARGO_NET_OFFLINE=true or RUSTUP_AUTO_INSTALL=0 export, an override, a cargo invocation without --offline, or a network-fetching rustup command such as rustup install/update, rustup toolchain install, or rustup run --install)",
        remediation="export CARGO_NET_OFFLINE=true and RUSTUP_AUTO_INSTALL=0 at top level and pass --offline to every cargo invocation in scripts/qualify.sh and scripts/release_qualify.sh, and never install or update toolchains, components, or targets there; this is Cargo/rustup sealing, not OS network isolation",
    ),
    "DEP-AUD-028": DiagnosticDef(
        code="DEP-AUD-028",
        severity="error",
        owner="security-policy",
        trigger="the rust lane of the qualification entrypoint has no recorded cargo test --workspace --doc step, so doctests (never run by --all-targets) are unqualified",
        remediation='add `run doctest rustup run "$toolchain" cargo test --locked --offline --workspace --doc` inside rust_lane() in scripts/qualify.sh',
    ),
    "DEP-AUD-030": DiagnosticDef(
        code="DEP-AUD-030",
        severity="error",
        owner="security-policy",
        trigger="a forbidden package is reachable in resolved Cargo metadata",
        remediation="remove it from the entire transitive closure and regenerate locked evidence",
    ),
    "DEP-AUD-031": DiagnosticDef(
        code="DEP-AUD-031",
        severity="error",
        owner="security-policy",
        trigger="a resolved package has a custom build target",
        remediation="remove or constitutionally admit the build script with exact offline/security proof; pure-Rust production",
    ),
    "DEP-AUD-032": DiagnosticDef(
        code="DEP-AUD-032",
        severity="error",
        owner="security-policy",
        trigger="a resolved package declares native links",
        remediation="remove native linkage or complete a constitutional architecture change; pure-Rust production",
    ),
    "DEP-AUD-033": DiagnosticDef(
        code="DEP-AUD-033",
        severity="error",
        owner="security-policy",
        trigger="a resolved Git package source is not commit-resolved",
        remediation="pin and lock an immutable exact commit with source/provenance evidence",
    ),
    "DEP-AUD-040": DiagnosticDef(
        code="DEP-AUD-040",
        severity="error",
        owner="security-policy",
        trigger="required pinned-nightly offline Cargo metadata is unavailable",
        remediation="restore exact toolchain/cache/lock/sibling closure and rerun; policy-only execution cannot certify release",
    ),
    "DEP-AUD-041": DiagnosticDef(
        code="DEP-AUD-041",
        severity="warning",
        owner="security-policy",
        trigger="target census drift between reference model and cargo metadata",
        remediation="reconcile target roots with cargo metadata to ensure no target is hidden or missing",
    ),
}


@dataclass(frozen=True)
class Finding:
    severity: str
    code: str
    path: str
    message: str
    remediation: str = ""
    params: dict[str, Any] = field(default_factory=dict)


@dataclass(frozen=True)
class TargetRoot:
    crate_name: str
    manifest_path: str
    root_path: str
    kind: str
    target_name: str
    has_forbid_unsafe: bool


def load_toml(path: Path) -> dict[str, Any]:
    value = tomllib.loads(path.read_text(encoding="utf-8"))
    if not isinstance(value, dict):
        raise ValueError(f"top-level TOML value is not a table: {path}")
    return value


def add(
    findings: list[Finding],
    severity: str,
    code: str,
    path: Path | str,
    message: str,
    root: Path = ROOT,
    remediation: str | None = None,
    params: dict[str, Any] | None = None,
) -> None:
    rendered = sanitize_path(path, root)
    sanitized_msg = sanitize_string(message, root=root)

    diag = DIAGNOSTIC_REGISTRY.get(code)
    effective_severity = severity
    if not effective_severity and diag is not None:
        effective_severity = diag.severity
    effective_remediation = remediation
    if not effective_remediation and diag is not None:
        effective_remediation = diag.remediation

    effective_params = sanitize_params(params or {}, root)

    findings.append(Finding(
        severity=effective_severity or "error",
        code=code,
        path=rendered,
        message=sanitized_msg,
        remediation=effective_remediation or "",
        params=effective_params,
    ))


def expand_workspace_members(
    root: Path,
    root_manifest_data: dict[str, Any],
    findings: list[Finding],
) -> tuple[list[Path], set[str], dict[str, Path]]:
    ws = root_manifest_data.get("workspace")
    if not isinstance(ws, dict):
        add(findings, "error", "DEP-AUD-025", root / "Cargo.toml", "declared workspace root manifest lacks [workspace] table", root=root, params={"manifest": "Cargo.toml", "section": "workspace"})
        return [root / "Cargo.toml"], set(), {}

    members_spec = ws.get("members", [])
    if not isinstance(members_spec, list) or not all(isinstance(m, str) for m in members_spec):
        add(findings, "error", "DEP-AUD-011", root / "Cargo.toml", "workspace.members must be a list of strings", root=root, params={"manifest": "Cargo.toml", "section": "workspace.members"})
        return [root / "Cargo.toml"], set(), {}

    exclude_spec = ws.get("exclude", [])
    if not isinstance(exclude_spec, list) or not all(isinstance(e, str) for e in exclude_spec):
        add(findings, "error", "DEP-AUD-011", root / "Cargo.toml", "workspace.exclude must be a list of strings", root=root, params={"manifest": "Cargo.toml", "section": "workspace.exclude"})
        exclude_spec = []

    def is_excluded(rel_path: str) -> bool:
        normalized = rel_path.rstrip("/")
        for pattern in exclude_spec:
            pat = pattern.rstrip("/")
            if fnmatch.fnmatchcase(rel_path, pat) or fnmatch.fnmatchcase(normalized, pat):
                return True
        return False

    member_dirs: list[Path] = []
    seen_dirs: dict[Path, str] = {}

    for pattern in members_spec:
        if any(char in pattern for char in "*?["):
            matches = sorted(root.glob(pattern))
            for p in matches:
                if p.is_dir() and (p / "Cargo.toml").is_file():
                    try:
                        rel = p.relative_to(root).as_posix()
                    except ValueError:
                        add(findings, "error", "DEP-AUD-012", p / "Cargo.toml", f"workspace member escapes root: {p}", root=root, params={"member": str(p), "manifest": "Cargo.toml"})
                        continue
                    if is_excluded(rel):
                        continue
                    resolved_dir = p.resolve()
                    if resolved_dir in seen_dirs:
                        add(findings, "error", "DEP-AUD-024", p / "Cargo.toml", f"workspace membership duplicate or ambiguous: {rel}", root=root, params={"member": rel})
                    else:
                        seen_dirs[resolved_dir] = pattern
                        member_dirs.append(p)
        else:
            p = root / pattern
            rel = pattern
            if is_excluded(rel):
                continue
            manifest = p / "Cargo.toml"
            if not p.is_dir() or not manifest.is_file():
                add(findings, "error", "DEP-AUD-010", manifest, f"workspace member manifest is missing: {rel}/Cargo.toml", root=root, params={"member": rel, "manifest": f"{rel}/Cargo.toml"})
                continue
            resolved_dir = p.resolve()
            if resolved_dir in seen_dirs:
                add(findings, "error", "DEP-AUD-024", manifest, f"workspace membership duplicate or ambiguous: {rel}", root=root, params={"member": rel})
            else:
                seen_dirs[resolved_dir] = pattern
                member_dirs.append(p)

    manifests = [root / "Cargo.toml"]
    member_names: set[str] = set()
    member_map: dict[str, Path] = {}

    for m_dir in member_dirs:
        manifest_path = m_dir / "Cargo.toml"
        manifests.append(manifest_path)
        try:
            m_data = load_toml(manifest_path)
            pkg_name = m_data.get("package", {}).get("name")
            if isinstance(pkg_name, str):
                if pkg_name in member_names:
                    add(findings, "error", "DEP-AUD-024", manifest_path, f"duplicate workspace member package name: {pkg_name}", root=root, params={"package": pkg_name, "manifest": manifest_path})
                member_names.add(pkg_name)
                member_map[pkg_name] = m_dir.resolve()
        except Exception as exc:
            add(findings, "error", "DEP-AUD-011", manifest_path, f"failed to load member manifest: {exc}", root=root, params={"manifest": manifest_path, "error": str(exc)})

    return manifests, member_names, member_map


def discover_crate_targets(
    crate_dir: Path,
    data: dict[str, Any],
    crate_name: str,
    manifest_rel: str,
    root: Path,
    findings: list[Finding],
) -> list[TargetRoot]:
    pkg = data.get("package", {})
    autobins = pkg.get("autobins", True) is not False
    autoexamples = pkg.get("autoexamples", True) is not False
    autotests = pkg.get("autotests", True) is not False
    autobenches = pkg.get("autobenches", True) is not False
    build_spec = pkg.get("build")

    candidate_targets: dict[Path, tuple[str, str]] = {}

    lib_val = data.get("lib")
    if isinstance(lib_val, dict):
        path_str = lib_val.get("path")
        name_str = str(lib_val.get("name", crate_name))
        if isinstance(path_str, str):
            candidate_targets[(crate_dir / path_str).resolve()] = ("lib", name_str)
        elif (crate_dir / "src/lib.rs").is_file():
            candidate_targets[(crate_dir / "src/lib.rs").resolve()] = ("lib", name_str)
    elif (crate_dir / "src/lib.rs").is_file():
        candidate_targets[(crate_dir / "src/lib.rs").resolve()] = ("lib", crate_name)

    bins = data.get("bin", [])
    if isinstance(bins, dict):
        bins = [bins]
    if isinstance(bins, list):
        for b in bins:
            if isinstance(b, dict):
                b_name = str(b.get("name", crate_name))
                b_path = b.get("path")
                if isinstance(b_path, str):
                    candidate_targets[(crate_dir / b_path).resolve()] = ("bin", b_name)
                else:
                    for cand in (
                        crate_dir / f"src/bin/{b_name}.rs",
                        crate_dir / f"src/bin/{b_name}/main.rs",
                        crate_dir / "src/main.rs",
                    ):
                        if cand.is_file():
                            candidate_targets[cand.resolve()] = ("bin", b_name)
                            break

    if autobins:
        main_rs = (crate_dir / "src/main.rs").resolve()
        if main_rs.is_file() and main_rs not in candidate_targets:
            candidate_targets[main_rs] = ("bin", crate_name)
        src_bin = crate_dir / "src/bin"
        if src_bin.is_dir():
            for p in sorted(src_bin.iterdir()):
                if p.is_file() and p.suffix == ".rs":
                    res = p.resolve()
                    if res not in candidate_targets:
                        candidate_targets[res] = ("bin", p.stem)
                elif p.is_dir() and (p / "main.rs").is_file():
                    res = (p / "main.rs").resolve()
                    if res not in candidate_targets:
                        candidate_targets[res] = ("bin", p.name)

    examples = data.get("example", [])
    if isinstance(examples, dict):
        examples = [examples]
    if isinstance(examples, list):
        for ex in examples:
            if isinstance(ex, dict):
                ex_name = str(ex.get("name", "example"))
                ex_path = ex.get("path")
                if isinstance(ex_path, str):
                    candidate_targets[(crate_dir / ex_path).resolve()] = ("example", ex_name)
                else:
                    for cand in (
                        crate_dir / f"examples/{ex_name}.rs",
                        crate_dir / f"examples/{ex_name}/main.rs",
                    ):
                        if cand.is_file():
                            candidate_targets[cand.resolve()] = ("example", ex_name)
                            break

    ex_dir = crate_dir / "examples"
    if ex_dir.is_dir():
        for p in sorted(ex_dir.iterdir()):
            if p.is_file() and p.suffix == ".rs":
                res = p.resolve()
                if res not in candidate_targets:
                    candidate_targets[res] = ("example", p.stem)
            elif p.is_dir() and (p / "main.rs").is_file():
                res = (p / "main.rs").resolve()
                if res not in candidate_targets:
                    candidate_targets[res] = ("example", p.name)

    tests = data.get("test", [])
    if isinstance(tests, dict):
        tests = [tests]
    if isinstance(tests, list):
        for t in tests:
            if isinstance(t, dict):
                t_name = str(t.get("name", "test"))
                t_path = t.get("path")
                if isinstance(t_path, str):
                    candidate_targets[(crate_dir / t_path).resolve()] = ("test", t_name)
                else:
                    for cand in (
                        crate_dir / f"tests/{t_name}.rs",
                        crate_dir / f"tests/{t_name}/main.rs",
                    ):
                        if cand.is_file():
                            candidate_targets[cand.resolve()] = ("test", t_name)
                            break

    test_dir = crate_dir / "tests"
    if test_dir.is_dir():
        for p in sorted(test_dir.iterdir()):
            if p.is_file() and p.suffix == ".rs":
                res = p.resolve()
                if res not in candidate_targets:
                    candidate_targets[res] = ("test", p.stem)
            elif p.is_dir() and (p / "main.rs").is_file():
                res = (p / "main.rs").resolve()
                if res not in candidate_targets:
                    candidate_targets[res] = ("test", p.name)

    benches = data.get("bench", [])
    if isinstance(benches, dict):
        benches = [benches]
    if isinstance(benches, list):
        for b in benches:
            if isinstance(b, dict):
                b_name = str(b.get("name", "bench"))
                b_path = b.get("path")
                if isinstance(b_path, str):
                    candidate_targets[(crate_dir / b_path).resolve()] = ("bench", b_name)
                else:
                    for cand in (
                        crate_dir / f"benches/{b_name}.rs",
                        crate_dir / f"benches/{b_name}/main.rs",
                    ):
                        if cand.is_file():
                            candidate_targets[cand.resolve()] = ("bench", b_name)
                            break

    bench_dir = crate_dir / "benches"
    if bench_dir.is_dir():
        for p in sorted(bench_dir.iterdir()):
            if p.is_file() and p.suffix == ".rs":
                res = p.resolve()
                if res not in candidate_targets:
                    candidate_targets[res] = ("bench", p.stem)
            elif p.is_dir() and (p / "main.rs").is_file():
                res = (p / "main.rs").resolve()
                if res not in candidate_targets:
                    candidate_targets[res] = ("bench", p.name)

    if build_spec is False:
        pass
    elif isinstance(build_spec, str):
        candidate_targets[(crate_dir / build_spec).resolve()] = ("custom-build", f"{crate_name}-build")
    elif build_spec is None or build_spec is True:
        cand_build = crate_dir / "build.rs"
        if cand_build.is_file():
            candidate_targets[cand_build.resolve()] = ("custom-build", f"{crate_name}-build")

    resolved_targets: list[TargetRoot] = []
    for path, (kind, target_name) in sorted(candidate_targets.items(), key=lambda row: str(row[0])):
        if not path.is_file():
            continue
        try:
            rel_path = path.relative_to(root).as_posix()
        except ValueError:
            rel_path = str(path)
        content = path.read_text(encoding="utf-8")
        has_forbid = bool(FORBID_UNSAFE_PATTERN.search(content))
        if not has_forbid:
            add(findings, "error", "DEP-AUD-021", path, f"target root lacks unconditional #![forbid(unsafe_code)]: {rel_path}", root=root, params={"crate_name": crate_name, "target_name": target_name, "kind": kind, "path": rel_path})
        if kind == "custom-build":
            add(findings, "error", "DEP-AUD-031", path, f"resolved package has a build script: {crate_name}", root=root, params={"crate_name": crate_name, "path": rel_path})

        resolved_targets.append(
            TargetRoot(
                crate_name=crate_name,
                manifest_path=manifest_rel,
                root_path=rel_path,
                kind=kind,
                target_name=target_name,
                has_forbid_unsafe=has_forbid,
            )
        )

    if not resolved_targets:
        add(findings, "error", "DEP-AUD-020", manifest_rel, f"crate has no inspectable Rust target root: {crate_name}", root=root, params={"crate_name": crate_name, "manifest": manifest_rel})

    return resolved_targets


def target_roots(manifest: Path, data: dict[str, Any], root: Path = ROOT) -> list[Path]:
    findings: list[Finding] = []
    crate_dir = manifest.parent
    try:
        manifest_rel = manifest.relative_to(root).as_posix()
    except ValueError:
        manifest_rel = str(manifest)
    crate_name = data.get("package", {}).get("name", crate_dir.name)
    targets = discover_crate_targets(crate_dir, data, crate_name, manifest_rel, root, findings)
    return sorted(root / t.root_path for t in targets)


def extract_manifest_dependency_sections(
    data: dict[str, Any],
    is_root: bool,
    manifest: Path,
    findings: list[Finding],
    root: Path = ROOT,
) -> list[tuple[str, str | None, dict[str, Any]]]:
    sections: list[tuple[str, str | None, dict[str, Any]]] = []
    for sec in ("dependencies", "dev-dependencies", "build-dependencies"):
        if sec in data:
            val = data[sec]
            if isinstance(val, dict):
                sections.append((sec, None, val))
            else:
                add(findings, "error", "DEP-AUD-011", manifest, f"[{sec}] is not a table", root=root, params={"manifest": manifest, "section": sec})

    if is_root:
        ws = data.get("workspace", {})
        if isinstance(ws, dict) and "dependencies" in ws:
            val = ws["dependencies"]
            if isinstance(val, dict):
                sections.append(("workspace.dependencies", None, val))
            else:
                add(findings, "error", "DEP-AUD-011", manifest, "[workspace.dependencies] is not a table", root=root, params={"manifest": manifest, "section": "workspace.dependencies"})

    target_table = data.get("target")
    if target_table is not None:
        if not isinstance(target_table, dict):
            add(findings, "error", "DEP-AUD-011", manifest, "[target] must be a table", root=root, params={"manifest": manifest, "section": "target"})
        else:
            for target_spec, target_config in sorted(target_table.items()):
                if not isinstance(target_config, dict):
                    add(findings, "error", "DEP-AUD-011", manifest, f"[target.{target_spec}] must be a table", root=root, params={"manifest": manifest, "section": f"target.{target_spec}"})
                    continue
                for sec in ("dependencies", "dev-dependencies", "build-dependencies"):
                    if sec in target_config:
                        val = target_config[sec]
                        sec_name = f"target.{target_spec}.{sec}"
                        if isinstance(val, dict):
                            sections.append((sec_name, target_spec, val))
                        else:
                            add(findings, "error", "DEP-AUD-011", manifest, f"[{sec_name}] is not a table", root=root, params={"manifest": manifest, "section": sec_name})

    return sections


def enumerate_dependencies(
    root: Path,
    manifests: list[Path],
    member_names: set[str],
    member_map: dict[str, Path],
    policy: dict[str, Any],
    findings: list[Finding],
) -> list[dict[str, Any]]:
    allowed_patterns = list(policy.get("in_house", {}).get("allowed_families", []))
    allowed_patterns += list(policy.get("fundamental", {}).get("allowed_subject_to_audit", []))
    forbidden = set(policy.get("forbidden", {}).get("crates", []))
    rows: list[dict[str, Any]] = []

    root_cargo_data: dict[str, Any] = {}
    if manifests and manifests[0].is_file():
        try:
            root_cargo_data = load_toml(manifests[0])
        except Exception:
            pass
    ws_dependencies: dict[str, Any] = {}
    ws_table = root_cargo_data.get("workspace")
    if isinstance(ws_table, dict) and isinstance(ws_table.get("dependencies"), dict):
        ws_dependencies = ws_table["dependencies"]

    def is_allowed(name: str) -> bool:
        return name in member_names or any(fnmatch.fnmatchcase(name, pattern) for pattern in allowed_patterns)

    for manifest in sorted(set(manifests)):
        if not manifest.is_file():
            add(findings, "error", "DEP-AUD-010", manifest, "workspace member manifest is missing", root=root, params={"manifest": manifest})
            continue
        try:
            data = load_toml(manifest)
        except Exception as exc:
            add(findings, "error", "DEP-AUD-011", manifest, f"cannot parse TOML: {exc}", root=root, params={"manifest": manifest, "error": str(exc)})
            continue

        try:
            relative = manifest.relative_to(root).as_posix()
        except ValueError:
            relative = str(manifest)

        is_root = (manifest == root / "Cargo.toml")
        sections = extract_manifest_dependency_sections(data, is_root, manifest, findings, root=root)

        for section, target_predicate, table in sections:
            for local_name, specification in sorted(table.items()):
                package = local_name
                kind = "registry"
                source: str | None = None
                default_features: bool | None = None
                features: list[str] = []
                optional = False
                workspace_inherited = False

                if not isinstance(specification, (dict, str)):
                    add(findings, "error", "DEP-AUD-011", manifest, f"dependency '{local_name}' in [{section}] must be a table or string", root=root, params={"manifest": manifest, "section": section, "local_name": local_name})
                    continue

                if isinstance(specification, dict):
                    package = str(specification.get("package", local_name))
                    optional = bool(specification.get("optional", False))
                    default_features = specification.get("default-features")
                    features = [str(item) for item in specification.get("features", [])]
                    suppress_017 = False
                    if specification.get("workspace") is True:
                        workspace_inherited = True
                        ws_spec = ws_dependencies.get(local_name) or ws_dependencies.get(package)
                        if ws_spec is None:
                            suppress_017 = True
                            add(findings, "error", "DEP-AUD-018", manifest, f"workspace-inherited dependency is missing in workspace.dependencies: {package}", root=root, params={"package": package, "manifest": manifest})
                        elif isinstance(ws_spec, dict):
                            if "package" in ws_spec:
                                package = str(ws_spec["package"])
                            if "default-features" in ws_spec and default_features is None:
                                default_features = ws_spec.get("default-features")
                            if "features" in ws_spec:
                                features = sorted(set(features + [str(item) for item in ws_spec.get("features", [])]))
                            if "path" in ws_spec and "path" not in specification:
                                specification = {**ws_spec, **specification}
                            elif "git" in ws_spec and "git" not in specification:
                                specification = {**ws_spec, **specification}
                            elif "version" in ws_spec and "version" not in specification:
                                specification = {**ws_spec, **specification}
                        elif isinstance(ws_spec, str):
                            source = ws_spec

                    if "path" in specification:
                        kind = "path"
                        raw_path = str(specification["path"])
                        source = raw_path
                        manifest_dir = manifest.parent.resolve()
                        resolved_path = (manifest_dir / raw_path).resolve()

                        is_in_tree = False
                        try:
                            resolved_path.relative_to(root.resolve())
                            is_in_tree = True
                        except ValueError:
                            is_allowed_sibling = False
                            try:
                                rel_sibling = resolved_path.relative_to(root.resolve().parent)
                                sibling_top = rel_sibling.parts[0] if rel_sibling.parts else ""
                                if any(fnmatch.fnmatchcase(sibling_top, pat) for pat in allowed_patterns):
                                    is_allowed_sibling = True
                            except ValueError:
                                pass
                            if not is_allowed_sibling:
                                add(
                                    findings,
                                    "error",
                                    "DEP-AUD-012",
                                    manifest,
                                    f"path dependency escapes the frozen repository/sibling closure: {package} -> {raw_path}",
                                    root=root,
                                    params={"package": package, "raw_path": raw_path, "manifest": manifest},
                                )

                        target_manifest = resolved_path / "Cargo.toml" if resolved_path.is_dir() else resolved_path
                        if not target_manifest.is_file():
                            add(findings, "error", "DEP-AUD-019", manifest, f"path dependency target manifest is missing: {package} -> {raw_path}", root=root, params={"package": package, "raw_path": raw_path, "manifest": manifest})
                        else:
                            try:
                                target_data = load_toml(target_manifest)
                                target_pkg_name = target_data.get("package", {}).get("name")
                                if target_pkg_name != package:
                                    add(
                                        findings,
                                        "error",
                                        "DEP-AUD-019",
                                        manifest,
                                        f"path dependency package name mismatch: expected '{package}', found '{target_pkg_name}' at {raw_path}",
                                        root=root,
                                        params={"package": package, "found": target_pkg_name, "raw_path": raw_path, "manifest": manifest},
                                    )
                            except Exception:
                                add(findings, "error", "DEP-AUD-019", manifest, f"path dependency target manifest is invalid: {package} -> {raw_path}", root=root, params={"package": package, "raw_path": raw_path, "manifest": manifest})

                        if is_in_tree and package not in member_names and not is_allowed(package):
                            add(findings, "error", "DEP-AUD-019", manifest, f"path dependency points to undeclared non-member crate: {package} -> {raw_path}", root=root, params={"package": package, "raw_path": raw_path, "manifest": manifest})

                    elif "git" in specification:
                        kind = "git"
                        source = str(specification["git"])
                        rev = specification.get("rev")
                        if not isinstance(rev, str) or re.fullmatch(r"[0-9a-f]{40}", rev) is None:
                            add(findings, "error", "DEP-AUD-013", manifest, f"Git dependency lacks an exact 40-hex rev: {package}", root=root, params={"package": package, "git": str(specification.get("git", "")), "manifest": manifest})
                    elif "version" in specification:
                        source = str(specification["version"])

                elif isinstance(specification, str):
                    source = specification

                if package in member_names:
                    admission_status = "member"
                elif package in forbidden:
                    admission_status = "forbidden"
                elif is_allowed(package):
                    admission_status = "admitted_in_house"
                else:
                    admission_status = "unallowlisted"

                rows.append(
                    {
                        "name": package,
                        "localName": local_name,
                        "manifest": relative,
                        "section": section,
                        "targetPredicate": target_predicate,
                        "kind": kind,
                        "source": source,
                        "defaultFeatures": default_features,
                        "features": sorted(features),
                        "optional": optional,
                        "workspaceInherited": workspace_inherited,
                        "admissionStatus": admission_status,
                    }
                )

                if section == "build-dependencies" or section.endswith(".build-dependencies"):
                    add(findings, "error", "DEP-AUD-014", manifest, f"build dependency is prohibited without a constitutional amendment: {package}", root=root, params={"package": package, "manifest": manifest, "section": section})

                if package in forbidden:
                    add(findings, "error", "DEP-AUD-015", manifest, f"forbidden direct dependency: {package}", root=root, params={"package": package, "manifest": manifest})
                elif not is_allowed(package):
                    add(findings, "error", "DEP-AUD-016", manifest, f"direct dependency is outside the closed allowlist: {package}", root=root, params={"package": package, "manifest": manifest})

                if not suppress_017 and kind != "path" and default_features is not False:
                    add(findings, "error", "DEP-AUD-017", manifest, f"external dependency must set default-features = false: {package}", root=root, params={"package": package, "manifest": manifest})

    return rows


def direct_dependency_rows(findings: list[Finding], policy: dict[str, Any], root: Path = ROOT) -> list[dict[str, Any]]:
    root_manifest = load_toml(root / "Cargo.toml")
    manifests, member_names, member_map = expand_workspace_members(root, root_manifest, findings)
    return enumerate_dependencies(root, manifests, member_names, member_map, policy, findings)


@dataclass(frozen=True)
class RustLiteral:
    """One string-like Rust literal found by ``mask_rust_source``."""

    start: int  # offset of the literal's first character, prefix (b/c/r/#) included
    end: int  # offset one past the closing delimiter
    line: int  # 1-based line of ``start``
    content: str  # raw text between the delimiters; escapes are not decoded


_RUST_IDENT_CHARS = frozenset("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_")
_RUST_RAW_STRING_START = re.compile(r'[bc]?r(#*)"')
_RUST_PREFIXED_STRING_START = re.compile(r'[bc]"')
_RUST_MAX_CHAR_LITERAL = 12  # len("'\\u{10FFFF}'")


def mask_rust_source(text: str, mask_literals: bool = True) -> tuple[str, list[RustLiteral]]:
    """Mask comments and literals in Rust source text.

    Returns ``(masked, literals)``. ``masked`` has exactly the length and newline positions of
    ``text``; every line/block/nested-block/doc comment and every string, byte-string, C-string,
    raw-string, char, and byte-char literal is overwritten with spaces, except that the first
    character of each string-like literal becomes ``"`` so callers can see that a literal argument
    sits there. ``literals`` lists the string-like literals (not char literals) with raw contents.

    This is a lexer-level approximation, not a Rust parser: it does not expand macros, follow
    ``include!``/``include_str!``, or evaluate ``concat!``/``stringify!``. An unterminated comment
    or literal masks to end of file (so it can hide, but never invent, code).
    """
    n = len(text)
    out = list(text)
    literals: list[RustLiteral] = []
    newlines = [index for index, char in enumerate(text) if char == "\n"]

    def line_of(offset: int) -> int:
        return bisect.bisect_left(newlines, offset) + 1

    def blank(start: int, end: int) -> None:
        for k in range(start, min(end, n)):
            if out[k] != "\n":
                out[k] = " "

    def record(start: int, body_start: int, body_end: int, end: int) -> None:
        literals.append(RustLiteral(start=start, end=end, line=line_of(start), content=text[body_start:body_end]))
        if mask_literals:
            blank(start, end)
            out[start] = '"'

    def char_literal_end(quote: int) -> int | None:
        nxt = text[quote + 1] if quote + 1 < n else ""
        if nxt == "\\":
            close = text.find("'", quote + 3)
            if close < 0 or close - quote >= _RUST_MAX_CHAR_LITERAL or "\n" in text[quote:close]:
                return None
            return close + 1
        if quote + 2 < n and text[quote + 2] == "'" and nxt not in ("\n", "'", ""):
            return quote + 3
        return None  # lifetime or loop label

    def string_end(quote: int) -> tuple[int, int]:
        j = quote + 1
        while j < n:
            if text[j] == "\\":
                j += 2
            elif text[j] == '"':
                return j, j + 1
            else:
                j += 1
        return n, n

    i = 0
    while i < n:
        char = text[i]
        nxt = text[i + 1] if i + 1 < n else ""
        if char == "/" and nxt == "/":
            end = text.find("\n", i)
            end = n if end < 0 else end
            blank(i, end)
            i = end
            continue
        if char == "/" and nxt == "*":
            depth, j = 1, i + 2
            while j < n and depth:
                if text.startswith("/*", j):
                    depth, j = depth + 1, j + 2
                elif text.startswith("*/", j):
                    depth, j = depth - 1, j + 2
                else:
                    j += 1
            blank(i, j)
            i = j
            continue
        if char in _RUST_IDENT_CHARS and (i == 0 or text[i - 1] not in _RUST_IDENT_CHARS):
            raw = _RUST_RAW_STRING_START.match(text, i)
            if raw:
                terminator = '"' + raw.group(1)
                close = text.find(terminator, raw.end())
                body_end, end = (n, n) if close < 0 else (close, close + len(terminator))
                record(i, raw.end(), body_end, end)
                i = end
                continue
            if _RUST_PREFIXED_STRING_START.match(text, i):
                body_end, end = string_end(i + 1)
                record(i, i + 2, body_end, end)
                i = end
                continue
            if char == "b" and nxt == "'":
                end = char_literal_end(i + 1)
                if end is not None:
                    if mask_literals:
                        blank(i, end)
                    i = end
                    continue
            j = i
            while j < n and text[j] in _RUST_IDENT_CHARS:
                j += 1
            i = j
            continue
        if char == '"':
            body_end, end = string_end(i)
            record(i, i + 1, body_end, end)
            i = end
            continue
        if char == "'":
            end = char_literal_end(i)
            if end is not None:
                if mask_literals:
                    blank(i, end)
                i = end
                continue
        i += 1
    return "".join(out), literals


def source_line(text: str, offset: int) -> int:
    return text.count("\n", 0, offset) + 1


def display_path(path: Path, root: Path) -> str:
    try:
        return path.resolve().relative_to(root.resolve()).as_posix()
    except ValueError:
        return sanitize_path(path, root)


# Serde-family and serde-ecosystem binary codec crates (fss-x4a.9.17 / FSS-110). Names are compared
# after lower-casing and mapping ``_`` to ``-`` (Cargo treats them as the same crate name).
SERDE_CODEC_CRATE_PATTERNS = ("serde*", "bincode", "postcard", "ciborium", "rmp-serde")
_SERDE_IDENT_BASE = r"(?:serde\w*|bincode|postcard|ciborium|rmp_serde)"
_SERDE_CODEC_IDENT = rf"(?:r#)?{_SERDE_IDENT_BASE}"
_SERDE_CODEC_IDENT_RE = re.compile(rf"\b{_SERDE_CODEC_IDENT}\b")
_USE_DECL = re.compile(r"\b(?:pub(?:\s*\([^)]*\))?\s+)?use\s+([^;]+);", re.DOTALL)
SERDE_SOURCE_PATTERNS: tuple[tuple[str, re.Pattern[str]], ...] = (
    ("serde-family crate path", re.compile(rf"\b{_SERDE_CODEC_IDENT}\s*::")),
    ("serde attribute", re.compile(r"\bserde\s*\(")),
    ("extern crate of a serde-family codec", re.compile(rf"\bextern\s+crate\s+{_SERDE_CODEC_IDENT}\b")),
)
_DERIVE_OPEN = re.compile(r"\bderive\s*\(")
_SERDE_DERIVE_TRAIT = re.compile(r"\b(?:Serialize|Deserialize)\b")


def is_serde_codec_crate(name: str) -> bool:
    normalized = name.strip().lower().replace("_", "-")
    return any(fnmatch.fnmatchcase(normalized, pattern) for pattern in SERDE_CODEC_CRATE_PATTERNS)


def scan_serde_source(text: str) -> list[tuple[int, str]]:
    """Return sorted, de-duplicated ``(line, label)`` Serde hits in comment/literal-masked source.

    Conservative on purpose: a derive list naming *any* ``Serialize``/``Deserialize`` (even a
    first-party derive macro of that name) and any call to a function named ``serde(`` are refused.
    """
    masked, _ = mask_rust_source(text)
    hits: set[tuple[int, str]] = set()
    for match in _DERIVE_OPEN.finditer(masked):
        depth, j = 1, match.end()
        while j < len(masked) and depth:
            if masked[j] == "(":
                depth += 1
            elif masked[j] == ")":
                depth -= 1
            j += 1
        if _SERDE_DERIVE_TRAIT.search(masked, match.end(), j):
            hits.add((source_line(masked, match.start()), "derive(Serialize/Deserialize)"))
    for label, pattern in SERDE_SOURCE_PATTERNS:
        for match in pattern.finditer(masked):
            hits.add((source_line(masked, match.start()), label))
    for match in _USE_DECL.finditer(masked):
        tree = match.group(1)
        tree_start = match.start(1)
        for hit in _SERDE_CODEC_IDENT_RE.finditer(tree):
            hits.add((source_line(masked, tree_start + hit.start()), "use of a serde-family codec"))
    return sorted(hits)


def fss_rust_source_files(root: Path, manifests: list[Path]) -> list[Path]:
    """Every ``*.rs`` under ``crates/`` and under each workspace member directory (``target`` skipped)."""
    directories = [root / "crates"] + [manifest.parent for manifest in manifests if manifest != root / "Cargo.toml"]
    seen: dict[Path, Path] = {}
    for directory in directories:
        if not directory.is_dir():
            continue
        for candidate in directory.rglob("*.rs"):
            if "target" in candidate.relative_to(directory).parts or not candidate.is_file():
                continue
            seen.setdefault(candidate.resolve(), candidate)
    return sorted(seen.values(), key=lambda p: display_path(p, root))


def _toml_key_line(text: str, key: str) -> int | None:
    quoted = re.escape(key)
    assignment = re.compile(rf"""^\s*(?:{quoted}|"{quoted}"|'{quoted}')\s*=""")
    header = re.compile(rf"""^\s*\[[^\]]*\.(?:{quoted}|"{quoted}"|'{quoted}')\s*\]\s*$""")
    for number, line in enumerate(text.splitlines(), 1):
        if assignment.match(line) or header.match(line):
            return number
    return None


def serde_durable_bytes_audit(
    findings: list[Finding],
    root: Path = ROOT,
    direct_rows: list[dict[str, Any]] | None = None,
    manifests: list[Path] | None = None,
    resolved_names: list[str] | None = None,
) -> int:
    """Fail closed on Serde-defined durable bytes (DEP-AUD-023, fss-x4a.9.17 / FSS-110).

    Refused, each with ``file:line`` in the message and ``line`` in params:
    (a) a Serde-family codec crate (``SERDE_CODEC_CRATE_PATTERNS``) named, by package identity or
        local key, in any FSS ``[dependencies]``/``[dev-dependencies]``/``[build-dependencies]``/
        ``[target.*.*]``/``[workspace.dependencies]`` table, in Cargo.lock, or in resolved metadata.
        No allowlist entry type admits a "non-durable" Serde use, so every occurrence is refused;
        ``[fundamental].allowed_subject_to_audit`` does not override this check;
    (b) ``derive(...Serialize|Deserialize...)``, Serde-family crate paths, ``serde(`` attributes,
        ``extern crate``/``use`` of a Serde-family codec in any FSS Rust source file, after
        comments and literals are masked.
    Returns the number of Rust source files scanned.
    """
    manifest_text: dict[str, str] = {}
    for row in direct_rows or []:
        package = str(row.get("name", ""))
        local_name = str(row.get("localName", package))
        offending = package if is_serde_codec_crate(package) else local_name if is_serde_codec_crate(local_name) else None
        if offending is None:
            continue
        manifest_rel = str(row.get("manifest", ""))
        if manifest_rel not in manifest_text:
            try:
                manifest_text[manifest_rel] = (root / manifest_rel).read_text(encoding="utf-8")
            except (OSError, UnicodeDecodeError):
                manifest_text[manifest_rel] = ""
        line = _toml_key_line(manifest_text[manifest_rel], local_name)
        location = f"{manifest_rel}:{line}" if line is not None else manifest_rel
        add(
            findings,
            "error",
            "DEP-AUD-023",
            root / manifest_rel,
            f"{location}: serde-family codec crate '{offending}' declared in [{row.get('section')}]; durable bytes must come from the first-party canonical codec",
            root=root,
            params={"package": offending, "section": str(row.get("section")), "path": manifest_rel, "line": line},
        )

    lock_path = root / "Cargo.lock"
    if lock_path.is_file():
        try:
            lock_text = lock_path.read_text(encoding="utf-8")
            lock_data = tomllib.loads(lock_text)
        except (OSError, UnicodeDecodeError, tomllib.TOMLDecodeError) as exc:
            add(findings, "error", "DEP-AUD-011", lock_path, f"cannot parse Cargo.lock; serde-family absence is unproven: {exc}", root=root, params={"manifest": "Cargo.lock", "error": str(exc)})
        else:
            lock_packages = lock_data.get("package", [])
            for package in lock_packages if isinstance(lock_packages, list) else []:
                name = package.get("name") if isinstance(package, dict) else None
                if isinstance(name, str) and is_serde_codec_crate(name):
                    line = None
                    name_line = re.compile(rf"""^\s*name\s*=\s*"{re.escape(name)}"\s*$""")
                    for number, text_line in enumerate(lock_text.splitlines(), 1):
                        if name_line.match(text_line):
                            line = number
                            break
                    location = f"Cargo.lock:{line}" if line is not None else "Cargo.lock"
                    add(findings, "error", "DEP-AUD-023", lock_path, f"{location}: serde-family codec package '{name}' is in the locked closure", root=root, params={"package": name, "path": "Cargo.lock", "line": line})

    for name in resolved_names or []:
        if is_serde_codec_crate(name):
            add(findings, "error", "DEP-AUD-023", lock_path, f"Cargo.lock: serde-family codec package '{name}' is resolved by cargo metadata", root=root, params={"package": name, "path": "Cargo.lock", "line": None})

    files = fss_rust_source_files(root, manifests or [])
    for source in files:
        rel = display_path(source, root)
        try:
            source_text = source.read_text(encoding="utf-8")
        except (OSError, UnicodeDecodeError) as exc:
            add(findings, "error", "DEP-AUD-023", source, f"{rel}: unreadable Rust source; Serde absence is unproven: {exc}", root=root, params={"path": rel, "line": None})
            continue
        for line, label in scan_serde_source(source_text):
            add(
                findings,
                "error",
                "DEP-AUD-023",
                source,
                f"{rel}:{line}: {label} in FSS Rust source; Serde may not define durable bytes",
                root=root,
                params={"path": rel, "line": line, "label": label},
            )
    return len(files)


# Network-capable constructs refused in build scripts (fss-x4a.26.3 / FSS-183). STATIC DENY-LIST:
# token-level matching over comment/literal-masked source; a clean result is not a proof of absence.
BUILD_SCRIPT_NETWORK_PATTERNS: tuple[tuple[str, re.Pattern[str]], ...] = (
    ("std::net", re.compile(r"\bstd\s*::\s*net\b")),
    ("grouped std::{..net..} import", re.compile(r"\bstd\s*::\s*\{[^{}]*\bnet\b")),
    ("TcpStream", re.compile(r"\bTcpStream\b")),
    ("TcpListener", re.compile(r"\bTcpListener\b")),
    ("UdpSocket", re.compile(r"\bUdpSocket\b")),
    ("ToSocketAddrs", re.compile(r"\bToSocketAddrs\b")),
)
BUILD_SCRIPT_NETWORK_COMMANDS = frozenset(
    {"curl", "wget", "git", "ssh", "nc", "ncat", "netcat", "scp", "sftp", "rsync", "ftp", "telnet"}
)
_COMMAND_NEW_CALL = re.compile(r"\bCommand\s*::\s*new\s*\(\s*")
_URL_SCHEME = re.compile(r"\b(?:https?|ftp|sftp|ssh|git|wss?)://", re.IGNORECASE)
_BINDING = re.compile(r"\b(?:pub(?:\s*\([^)]*\))?\s+)?(?:const|let(?:\s+mut)?)\s+([A-Za-z0-9_]+)\s*(?::\s*[^=]+)?=\s*", re.DOTALL)


def scan_build_script_network(text: str) -> list[tuple[int, str]]:
    """Return sorted ``(line, label)`` deny-list hits in one build script's source text."""
    masked, literals = mask_rust_source(text)
    by_start = {literal.start: literal for literal in literals}
    bindings: dict[str, str] = {}
    for m in _BINDING.finditer(masked):
        name = m.group(1)
        idx = m.end()
        while idx < len(masked) and masked[idx] in " \t\r\n&(":
            idx += 1
        lit = by_start.get(idx)
        if lit is not None:
            bindings[name] = lit.content

    hits: set[tuple[int, str]] = set()
    for label, pattern in BUILD_SCRIPT_NETWORK_PATTERNS:
        for match in pattern.finditer(masked):
            hits.add((source_line(masked, match.start()), label))
    for match in _COMMAND_NEW_CALL.finditer(masked):
        idx = match.end()
        while idx < len(masked) and masked[idx] in " \t\r\n&(":
            idx += 1
        raw_cmd: str | None = None
        literal = by_start.get(idx)
        if literal is not None:
            raw_cmd = literal.content
        else:
            ident_match = re.match(r"[A-Za-z0-9_]+", masked[idx:])
            if ident_match and ident_match.group(0) in bindings:
                raw_cmd = bindings[ident_match.group(0)]
        if raw_cmd is None:
            continue  # non-literal program (e.g. env!("RUSTC")) is not resolved: see docstring
        program = re.split(r"[\\/]", raw_cmd.strip())[-1].lower()
        if program.endswith(".exe"):
            program = program[: -len(".exe")]
        if program in BUILD_SCRIPT_NETWORK_COMMANDS:
            hits.add((source_line(masked, match.start()), f'Command::new("{program}")'))
    for literal in literals:
        match = _URL_SCHEME.search(literal.content)
        if match:
            hits.add((literal.line + literal.content.count("\n", 0, match.start()), f"URL literal {match.group(0)}"))
    return sorted(hits)


def build_script_network_audit(
    findings: list[Finding],
    root: Path = ROOT,
    manifests: list[Path] | None = None,
    extra_paths: list[Path] | None = None,
) -> int:
    """Refuse network-capable constructs in build scripts (DEP-AUD-026, fss-x4a.26.3 / FSS-183).

    Build scripts are the implicit ``build.rs`` (unless ``build = false``), ``build = true``, or
    ``build = "path"`` of every package manifest in ``manifests``, plus ``extra_paths`` (custom-build
    ``src_path`` values from resolved cargo metadata, which covers non-workspace packages). A declared
    but missing or unreadable build script fails closed. Each hit is reported as ``file:line``.

    STATIC DENY-LIST, NOT A PROOF OF ABSENCE. The scan matches ``BUILD_SCRIPT_NETWORK_PATTERNS``,
    ``Command::new`` of a literal program in ``BUILD_SCRIPT_NETWORK_COMMANDS``, and URL-scheme string
    literals, after comments and literals are masked. It does not see macro-generated code, files
    pulled in by ``include!``/``mod``/``#[path]``, non-literal ``Command::new`` arguments, network use
    inside crates the build script calls, or a spawned program not named literally. Build scripts stay
    refused outright by DEP-AUD-031; this check adds file:line evidence and keeps the network rule
    meaningful if a build script is ever constitutionally admitted. Returns the number scanned.
    """
    scripts: dict[Path, Path] = {}
    for manifest in manifests or []:
        try:
            data = load_toml(manifest)
        except (OSError, UnicodeDecodeError, tomllib.TOMLDecodeError, ValueError):
            continue  # unreadable manifests are reported as DEP-AUD-010/011 by the manifest walk
        package = data.get("package")
        if not isinstance(package, dict):
            continue
        spec = package.get("build")
        if spec is False:
            continue
        if spec is None or spec is True:
            candidate, declared = manifest.parent / "build.rs", spec is True
        elif isinstance(spec, str):
            candidate, declared = manifest.parent / spec, True
        else:
            rel = display_path(manifest, root)
            add(findings, "error", "DEP-AUD-026", manifest, f"{rel}: package.build must be a boolean or a path string; build-script network absence is unproven", root=root, params={"path": rel, "line": None})
            continue
        if not candidate.is_file():
            if declared:
                rel = display_path(candidate, root)
                add(findings, "error", "DEP-AUD-026", candidate, f"{rel}: declared build script is missing; build-script network absence is unproven", root=root, params={"path": rel, "line": None})
            continue
        scripts.setdefault(candidate.resolve(), candidate)
    for extra in extra_paths or []:
        if not extra.is_file():
            rel = display_path(extra, root)
            add(findings, "error", "DEP-AUD-026", extra, f"{rel}: resolved build script source is not readable; build-script network absence is unproven", root=root, params={"path": rel, "line": None})
            continue
        scripts.setdefault(extra.resolve(), extra)

    for resolved in sorted(scripts, key=str):
        script = scripts[resolved]
        rel = display_path(script, root)
        try:
            script_text = script.read_text(encoding="utf-8")
        except (OSError, UnicodeDecodeError) as exc:
            add(findings, "error", "DEP-AUD-026", script, f"{rel}: unreadable build script; network absence is unproven: {exc}", root=root, params={"path": rel, "line": None})
            continue
        for line, label in scan_build_script_network(script_text):
            add(
                findings,
                "error",
                "DEP-AUD-026",
                script,
                f"{rel}:{line}: build script uses network-capable construct {label} (static deny-list)",
                root=root,
                params={"path": rel, "line": line, "label": label},
            )
    return len(scripts)


_SHELL_CARGO_WORD = re.compile(r"(?<![\w.-])cargo(?![\w.-])")
_SHELL_COMMAND_BREAK = re.compile(r"&&|\|\||;|\|")
_SEALED_OFFLINE_EXPORT = re.compile(r"""^export\s+CARGO_NET_OFFLINE=(?:true|"true"|'true')\s*$""")
_CARGO_NET_OFFLINE_WORD = re.compile(r"\bCARGO_NET_OFFLINE\b")
_SEALED_AUTO_INSTALL_EXPORT = re.compile(r"""^export\s+RUSTUP_AUTO_INSTALL=(?:0|"0"|'0')\s*$""")
_RUSTUP_AUTO_INSTALL_WORD = re.compile(r"\bRUSTUP_AUTO_INSTALL\b")
_RUST_LANE_OPEN = re.compile(r"^rust_lane\s*\(\s*\)\s*\{\s*$")
_SHELL_OPERATORS = ("&&", "||", ";;", ";", "|", "&", "(", ")")
_SHELL_C_SHELLS = frozenset({"bash", "sh", "dash", "ksh", "zsh"})
# rustup subcommands that download toolchains, components, targets, or rustup itself.
_RUSTUP_FETCHING_COMMANDS = frozenset(
    {("install",), ("update",), ("toolchain", "install"), ("toolchain", "add"), ("component", "add"), ("target", "add"), ("self", "update")}
)


class _ShellSyntaxError(ValueError):
    """An unterminated quote or command substitution on one logical shell line."""


def _shell_quote_end(text: str, start: int) -> int:
    """Index just past the quote closing the one at ``start`` (``\\`` escapes honoured inside ``"``)."""
    quote = text[start]
    i = start + 1
    while i < len(text):
        if quote == '"' and text[i] == "\\":
            i += 2
            continue
        if text[i] == quote:
            return i + 1
        i += 1
    raise _ShellSyntaxError(f"unterminated {quote}")


def _shell_substitution(text: str, start: int, subs: list[str]) -> int:
    """Record the body of the ``$(...)`` or backtick substitution at ``start``; return its end index."""
    if text[start] == "`":
        end = _shell_quote_end(text, start)
        subs.append(text[start + 1 : end - 1])
        return end
    depth = 0
    i = start + 1
    while i < len(text):
        char = text[i]
        if char == "\\":
            i += 2
            continue
        if char in "'\"`":
            i = _shell_quote_end(text, i)
            continue
        if char == "(":
            depth += 1
        elif char == ")":
            depth -= 1
            if depth == 0:
                subs.append(text[start + 2 : i])
                return i + 1
        i += 1
    raise _ShellSyntaxError("unterminated $(")


def _shell_double_quoted(text: str, start: int, word: list[str], subs: list[str]) -> int:
    """Append the unquoted value of the ``"..."`` at ``start`` to ``word``; return its end index."""
    i = start + 1
    while i < len(text):
        char = text[i]
        if char == '"':
            return i + 1
        if char == "\\":
            word.append(text[i + 1 : i + 2])
            i += 2
        elif char == "`" or text.startswith("$(", i):
            end = _shell_substitution(text, i, subs)
            word.append(text[i:end])
            i = end
        else:
            word.append(char)
            i += 1
    raise _ShellSyntaxError('unterminated "')


def _shell_split(text: str) -> tuple[list[list[str]], list[str], bool]:
    """Split one logical shell line into simple commands of quote-removed words.

    Quoted text stays inside its word, so ``printf 'cargo metadata missing'`` yields the single
    argument ``cargo metadata missing``. ``$(...)`` and backtick bodies (bare or inside ``"..."``)
    are returned separately for re-parsing, and an unquoted ``#`` at the start of a word begins a
    comment. Returns (commands, substitution bodies, ended_in_comment). Raises _ShellSyntaxError on
    an unterminated quote or substitution.
    """
    commands: list[list[str]] = [[]]
    subs: list[str] = []
    word: list[str] = []
    started = False
    i = 0
    while i < len(text):
        char = text[i]
        if char in " \t":
            if started:
                commands[-1].append("".join(word))
            word, started = [], False
            i += 1
        elif char == "#" and not started:
            return [command for command in commands if command], subs, True
        elif char == "\\":
            word.append(text[i + 1 : i + 2])
            started, i = True, i + 2
        elif char == "'":
            end = _shell_quote_end(text, i)
            word.append(text[i + 1 : end - 1])
            started, i = True, end
        elif char == '"':
            i = _shell_double_quoted(text, i, word, subs)
            started = True
        elif char == "`" or text.startswith("$(", i):
            end = _shell_substitution(text, i, subs)
            word.append(text[i:end])
            started, i = True, end
        else:
            operator = next((op for op in _SHELL_OPERATORS if text.startswith(op, i)), "")
            redirect = char == "&" and ((bool(word) and word[-1].endswith(("<", ">"))) or text.startswith(">", i + 1))
            if operator and not redirect:
                if started:
                    commands[-1].append("".join(word))
                word, started = [], False
                commands.append([])
                i += len(operator)
            else:
                word.append(char)
                started, i = True, i + 1
    if started:
        commands[-1].append("".join(word))
    return [command for command in commands if command], subs, False


def _shell_ends_in_comment(text: str) -> bool:
    """True when ``text`` ends inside an unquoted ``#`` comment, where a trailing ``\\`` is literal."""
    try:
        return _shell_split(text)[2]
    except _ShellSyntaxError:
        return False


def _shell_c_argument(words: list[str], index: int) -> int | None:
    """Index of the command string passed with ``-c`` (or a cluster such as ``-ec``) to the shell at ``index``."""
    position = index + 1
    while position < len(words) - 1:
        flag = words[position]
        if flag in ("-o", "+o", "-O", "+O"):
            position += 2
            continue
        if flag == "--" or not flag.startswith(("-", "+")):
            return None
        if not flag.startswith("--") and "c" in flag[1:]:
            return position + 1
        position += 1
    return None


def _shell_simple_commands(text: str) -> list[list[str]]:
    """Simple commands on one logical line, plus those in its ``$(...)``/backtick substitutions and in
    the command strings given to ``bash|sh|dash|ksh|zsh -c`` and ``eval``, which are re-parsed instead
    of being read as one quoted word. Raises _ShellSyntaxError."""
    commands, subs, _ = _shell_split(text)
    direct: list[list[str]] = []
    nested: list[list[str]] = []
    for words in commands:
        for index, word in enumerate(words):
            if word == "eval":
                nested.extend(_shell_simple_commands(" ".join(words[index + 1 :])))
                words = words[: index + 1]
                break
            if word.rsplit("/", 1)[-1] in _SHELL_C_SHELLS:
                script_index = _shell_c_argument(words, index)
                if script_index is not None:
                    nested.extend(_shell_simple_commands(words[script_index]))
                    words = words[:script_index] + words[script_index + 1 :]
                    break
        direct.append(words)
    for body in subs:
        nested.extend(_shell_simple_commands(body))
    return direct + nested


def _shell_fallback_commands(text: str) -> list[list[str]]:
    """Conservative split for a line that cannot be tokenized: quotes and parentheses become blanks."""
    crude = re.sub(r"[\"'`()]", " ", text)
    return [segment.split() for segment in _SHELL_COMMAND_BREAK.split(crude) if segment.split()]


def _shell_word_names(word: str, tool: str) -> bool:
    """True for a word ``tool`` or ``.../tool`` (quotes already removed). A word holding whitespace is
    quoted prose such as ``'cargo metadata receipt missing'``, never a command name."""
    return word.rsplit("/", 1)[-1] == tool and not any(char.isspace() for char in word)


def _rustup_fetching_form(args: list[str]) -> str | None:
    """The network-fetching rustup form in ``args`` (the words after ``rustup``), or None."""
    rest = list(args)
    while rest and rest[0].startswith(("-", "+")):
        rest.pop(0)
    if tuple(rest[:1]) in _RUSTUP_FETCHING_COMMANDS:
        return rest[0]
    if tuple(rest[:2]) in _RUSTUP_FETCHING_COMMANDS:
        return " ".join(rest[:2])
    if rest[:1] == ["run"] and "--install" in rest:
        return "run --install"
    return None


def _shell_logical_lines(script_text: str) -> list[tuple[int, str]]:
    """Join ``\\``-continued lines; each entry is (first physical line number, joined text).

    A trailing ``\\`` inside a ``#`` comment is literal in the shell, so it does not continue the line.
    """
    logical: list[tuple[int, str]] = []
    pending: list[str] = []
    start = 1
    for number, raw_line in enumerate(script_text.splitlines(), 1):
        if not pending:
            start = number
        if raw_line.endswith("\\") and not _shell_ends_in_comment(" ".join([*pending, raw_line[:-1]])):
            pending.append(raw_line[:-1])
            continue
        pending.append(raw_line)
        logical.append((start, " ".join(pending)))
        pending = []
    if pending:
        logical.append((start, " ".join(pending)))
    return logical


def qualify_offline_audit(findings: list[Finding], script: Path, root: Path = ROOT) -> int:
    """Require sealed-offline Cargo and rustup use in a qualification script (DEP-AUD-027, fss-x4a.26.3).

    Applied to ``scripts/qualify.sh`` and ``scripts/release_qualify.sh``. Refused, each with
    ``file:line`` where one exists:
    - a missing/unreadable script;
    - no unindented top-level ``export CARGO_NET_OFFLINE=true`` textually before the first cargo
      invocation (both scripts dispatch at the bottom, so the export runs first);
    - no unindented top-level ``export RUSTUP_AUTO_INSTALL=0`` textually before the first ``rustup``
      or cargo word, so rustup cannot fetch a missing toolchain;
    - any other non-comment line naming ``CARGO_NET_OFFLINE`` or ``RUSTUP_AUTO_INSTALL`` (unset,
      override, ``env -u``, re-export), checked on the raw line text;
    - any command word ``cargo`` (also ``/path/to/cargo``) whose own simple command (up to
      ``&&``/``||``/``;``/``|``/``&``) lacks ``--offline``. There is no ``cargo fmt`` exemption: the
      script uses ``cargo --offline fmt``;
    - any rustup command that can fetch over the network: ``rustup install``/``update``,
      ``rustup toolchain install|add``, ``rustup component add``, ``rustup target add``,
      ``rustup self update``, or ``rustup run`` with ``--install`` anywhere in its command.
    Lines are tokenized by ``_shell_split``: quoted text such as ``printf 'cargo metadata missing'``
    and text after an unquoted ``#`` are not commands, while ``$(...)``/backtick bodies and the
    command strings of ``bash|sh|dash|ksh|zsh -c`` and ``eval`` are re-parsed and checked. Command
    strings handed to any other wrapper (``su -c``, ``ssh host '...'``, ``watch '...'``) are not
    re-parsed. A line with an unterminated quote or substitution falls back to scanning every word.
    Full-line ``#`` comments are ignored and ``\\``-continued lines are joined (not inside comments).
    Heredoc bodies are scanned as ordinary lines. This seals Cargo's own resolution and fetching and
    rustup's toolchain fetching only. It is NOT OS-level network isolation (no network namespace or
    ``unshare -n``), it does not govern network use by other commands or by scripts that qualify.sh
    calls, and it inspects only this one file. Returns the number of cargo invocations checked.
    """
    rel = display_path(script, root)
    if not script.is_file():
        add(findings, "error", "DEP-AUD-027", script, f"{rel}: qualification script is missing; sealed-offline qualification is unproven", root=root, params={"path": rel, "line": None})
        return 0
    try:
        script_text = script.read_text(encoding="utf-8")
    except (OSError, UnicodeDecodeError) as exc:
        add(findings, "error", "DEP-AUD-027", script, f"{rel}: unreadable qualification script: {exc}", root=root, params={"path": rel, "line": None})
        return 0

    logical = _shell_logical_lines(script_text)

    export_line: int | None = None
    auto_install_line: int | None = None
    first_cargo_line: int | None = None
    first_rustup_line: int | None = None
    invocations = 0
    for number, line in logical:
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            continue
        if export_line is None and _SEALED_OFFLINE_EXPORT.match(line):
            export_line = number
            continue
        if auto_install_line is None and _SEALED_AUTO_INSTALL_EXPORT.match(line):
            auto_install_line = number
            continue
        if _CARGO_NET_OFFLINE_WORD.search(line):
            add(findings, "error", "DEP-AUD-027", script, f"{rel}:{number}: CARGO_NET_OFFLINE may be set only once, by the top-level `export CARGO_NET_OFFLINE=true`: {stripped[:160]}", root=root, params={"path": rel, "line": number})
        if _RUSTUP_AUTO_INSTALL_WORD.search(line):
            add(findings, "error", "DEP-AUD-027", script, f"{rel}:{number}: RUSTUP_AUTO_INSTALL may be set only once, by the top-level `export RUSTUP_AUTO_INSTALL=0`: {stripped[:160]}", root=root, params={"path": rel, "line": number})
        try:
            commands = _shell_simple_commands(line)
        except _ShellSyntaxError:
            commands = _shell_fallback_commands(line)
        for words in commands:
            for index, word in enumerate(words):
                if _shell_word_names(word, "rustup"):
                    if first_rustup_line is None:
                        first_rustup_line = number
                    form = _rustup_fetching_form(words[index + 1 :])
                    if form is not None:
                        add(findings, "error", "DEP-AUD-027", script, f"{rel}:{number}: `rustup {form}` can fetch a toolchain over the network; qualification may only use the installed pinned toolchain: {stripped[:160]}", root=root, params={"path": rel, "line": number})
                elif _shell_word_names(word, "cargo"):
                    invocations += 1
                    if first_cargo_line is None:
                        first_cargo_line = number
                    if "--offline" not in words[index + 1 :]:
                        add(findings, "error", "DEP-AUD-027", script, f"{rel}:{number}: cargo invocation lacks --offline: {stripped[:160]}", root=root, params={"path": rel, "line": number})
    if export_line is None or (first_cargo_line is not None and export_line > first_cargo_line):
        add(findings, "error", "DEP-AUD-027", script, f"{rel}: no unindented top-level `export CARGO_NET_OFFLINE=true` precedes the first cargo invocation", root=root, params={"path": rel, "line": export_line})
    first_tool_line = min((n for n in (first_cargo_line, first_rustup_line) if n is not None), default=None)
    if auto_install_line is None or (first_tool_line is not None and auto_install_line > first_tool_line):
        add(findings, "error", "DEP-AUD-027", script, f"{rel}: no unindented top-level `export RUSTUP_AUTO_INSTALL=0` precedes the first rustup or cargo invocation; rustup could fetch a missing toolchain", root=root, params={"path": rel, "line": auto_install_line})
    return invocations


def _recorded_workspace_doctest_step(line: str) -> bool:
    """True for ``run <step> ... cargo ... test ... --workspace ... --doc`` within one command segment.

    ``--doc`` must precede any ``--`` (after it the flag goes to the test binary, not Cargo), and
    ``--no-run`` disqualifies the step because it would build without running the doctests.
    """
    try:
        commands, _, _ = _shell_split(line)
    except _ShellSyntaxError:
        return False
    if not commands:
        return False
    words = commands[0]
    if len(words) < 3 or words[0] != "run":
        return False
    cmd = words[2:]
    if not cmd:
        return False
    if _shell_word_names(cmd[0], "rustup"):
        i = 1
        while i < len(cmd) and cmd[i].startswith("-"):
            i += 1
        if i >= len(cmd) or cmd[i] != "run":
            return False
        i += 1
        if i >= len(cmd):
            return False
        i += 1
        cmd = cmd[i:]
    if not cmd or not _shell_word_names(cmd[0], "cargo"):
        return False
    cargo_args = cmd[1:]
    if "--" in cargo_args:
        cargo_args = cargo_args[: cargo_args.index("--")]
    if "test" not in cargo_args:
        return False
    after = cargo_args[cargo_args.index("test") + 1 :]
    return "--doc" in after and "--workspace" in after and "--no-run" not in after


def qualify_doctest_audit(findings: list[Finding], script: Path, root: Path = ROOT) -> bool:
    """Require a recorded workspace doctest step in the rust lane (DEP-AUD-028, fss-tgwit).

    ``cargo test --all-targets`` runs lib/bin/test/bench/example targets but never doctests, so a
    broken doctest, or a ``compile_fail`` doctest failing for the wrong reason, passes that step.
    Refused, with ``file:line`` where one exists: a missing/unreadable script; no unindented
    ``rust_lane() {`` function; or a ``rust_lane`` body (up to its unindented closing ``}``) with no
    non-comment ``run <step> ... cargo test ... --workspace ... --doc`` line (see
    ``_recorded_workspace_doctest_step``). This proves the step is declared and recorded in the
    lane; it does not prove the doctests pass, which only running the lane does. Returns True when
    the step is present.
    """
    rel = display_path(script, root)
    if not script.is_file():
        add(findings, "error", "DEP-AUD-028", script, f"{rel}: qualification script is missing; the rust-lane doctest step is unproven", root=root, params={"path": rel, "line": None})
        return False
    try:
        script_text = script.read_text(encoding="utf-8")
    except (OSError, UnicodeDecodeError) as exc:
        add(findings, "error", "DEP-AUD-028", script, f"{rel}: unreadable qualification script: {exc}", root=root, params={"path": rel, "line": None})
        return False

    lane_line: int | None = None
    for number, line in _shell_logical_lines(script_text):
        if lane_line is None:
            if _RUST_LANE_OPEN.match(line):
                lane_line = number
            continue
        if line.rstrip() == "}":
            break
        stripped = line.strip()
        if stripped and not stripped.startswith("#") and _recorded_workspace_doctest_step(stripped):
            return True
    if lane_line is None:
        add(findings, "error", "DEP-AUD-028", script, f"{rel}: no unindented `rust_lane() {{` function; the rust-lane doctest step is unproven", root=root, params={"path": rel, "line": None})
    else:
        add(findings, "error", "DEP-AUD-028", script, f"{rel}:{lane_line}: rust_lane has no recorded `run <step> ... cargo test --workspace --doc` step; --all-targets never runs doctests", root=root, params={"path": rel, "line": lane_line})
    return False


def rust_source_audit(findings: list[Finding], root: Path = ROOT, manifests: list[Path] | None = None) -> dict[str, Any]:
    if manifests is None:
        root_manifest = load_toml(root / "Cargo.toml")
        local_findings: list[Finding] = []
        manifests, _, _ = expand_workspace_members(root, root_manifest, local_findings)
        for f in local_findings:
            if not any(existing.code == f.code and existing.path == f.path for existing in findings):
                findings.append(f)
    member_manifests = [m for m in manifests if m != root / "Cargo.toml"]

    all_targets: list[TargetRoot] = []
    for manifest in member_manifests:
        try:
            data = load_toml(manifest)
            manifest_rel = sanitize_path(manifest, root)
        except Exception:
            continue
        crate_name = data.get("package", {}).get("name", manifest.parent.name)
        targets = discover_crate_targets(manifest.parent, data, crate_name, manifest_rel, root, findings)
        all_targets.extend(targets)

    rust_files = sorted(
        path
        for path in root.rglob("*.rs")
        if not any(part in {".git", "target", "dist", "qualification-artifacts", ".claude"} for part in path.parts)
    )

    patterns = {
        "unsafe token": re.compile(r"\bunsafe\b"),
        "C ABI": re.compile(r"extern\s+\"C\""),
        "native link attribute": re.compile(r"#\s*\[\s*link\s*\("),
        "dynamic loading": re.compile(r"\b(?:libloading|dlopen|LoadLibrary)\b"),
        "second async runtime": re.compile(r"\b(?:tokio|async_std|async-std|smol|glommio|monoio)\b"),
        "foreign media/model binding": re.compile(r"\b(?:pyo3|opencv|ffmpeg_next|gstreamer|onnxruntime|ort|tch)\b", re.I),
        "foreign production command": re.compile(r"Command::new\s*\(\s*\"(?:ffmpeg|ffprobe|python|python3|node)\""),
    }
    for path in rust_files:
        text = path.read_text(encoding="utf-8")
        masked, _ = mask_rust_source(text, mask_literals=False)
        scan = masked.replace("#![forbid(unsafe_code)]", "")
        for label, pattern in patterns.items():
            if label == "foreign production command" and ("tests" in path.parts or "examples" in path.parts):
                continue
            if pattern.search(scan):
                add(findings, "error", "DEP-AUD-022", path, f"forbidden production construct: {label}", root=root, params={"label": label, "path": path})

    return {
        "rustFileCount": len(rust_files),
        "targetRootCount": len(all_targets),
        "targetRoots": [asdict(t) for t in sorted(all_targets, key=lambda t: t.root_path)],
    }


def metadata_audit(
    findings: list[Finding],
    policy: dict[str, Any],
    root: Path = ROOT,
    reference_targets: list[TargetRoot] | None = None,
    raw_metadata: dict[str, Any] | None = None,
    build_script_paths: list[Path] | None = None,
) -> tuple[bool, str | None, list[dict[str, Any]]]:
    if raw_metadata is not None:
        metadata = raw_metadata
    else:
        lock_file = root / "Cargo.lock"
        toolchain_file = root / "rust-toolchain.toml"
        if not lock_file.is_file():
            return False, "Cargo.lock is absent", []
        if not toolchain_file.is_file():
            return False, "rust-toolchain.toml is absent", []
        if shutil.which("rustup") is None:
            return False, "rustup is unavailable", []
        try:
            channel = load_toml(toolchain_file).get("toolchain", {}).get("channel")
        except Exception as exc:
            return False, f"cannot load rust-toolchain.toml: {exc}", []
        if not isinstance(channel, str):
            return False, "pinned nightly channel is unreadable", []

        command = [
            "rustup",
            "run",
            channel,
            "cargo",
            "metadata",
            "--locked",
            "--offline",
            "--format-version",
            "1",
        ]
        proc = subprocess.run(command, cwd=root, text=True, capture_output=True)
        if proc.returncode != 0:
            detail = proc.stderr.strip() or proc.stdout.strip() or "cargo metadata failed"
            return False, detail, []
        try:
            metadata = json.loads(proc.stdout)
        except json.JSONDecodeError as exc:
            return False, f"cargo metadata emitted invalid JSON: {exc}", []

    packages = metadata.get("packages", [])
    workspace_members = set(metadata.get("workspace_members", []))
    forbidden = set(policy.get("forbidden", {}).get("crates", []))
    census: list[dict[str, Any]] = []

    cargo_target_paths: set[str] = set()
    for package in sorted(packages, key=lambda row: (str(row.get("name")), str(row.get("version")))):
        name = str(package.get("name", ""))
        source = package.get("source")
        targets = package.get("targets", [])
        custom_build = any("custom-build" in target.get("kind", []) for target in targets if isinstance(target, dict))
        links = package.get("links")

        if package.get("id") in workspace_members:
            for t in targets:
                if isinstance(t, dict) and "src_path" in t:
                    try:
                        rel = Path(t["src_path"]).resolve().relative_to(root.resolve()).as_posix()
                        if Path(t["src_path"]).is_file():
                            cargo_target_paths.add(rel)
                    except ValueError:
                        pass

        census.append(
            {
                "name": name,
                "version": str(package.get("version", "")),
                "source": source,
                "manifestPath": package.get("manifest_path"),
                "customBuild": custom_build,
                "links": links,
            }
        )
        if name in forbidden:
            add(findings, "error", "DEP-AUD-030", "Cargo.lock", f"forbidden package is reachable: {name}", root=root, params={"package": name, "version": str(package.get("version", ""))})
        if custom_build:
            add(findings, "error", "DEP-AUD-031", str(package.get("manifest_path", name)), f"resolved package has a build script: {name}", root=root, params={"package": name, "version": str(package.get("version", ""))})
            if build_script_paths is not None:
                for target in targets:
                    if isinstance(target, dict) and "custom-build" in target.get("kind", []) and isinstance(target.get("src_path"), str):
                        build_script_paths.append(Path(target["src_path"]))
        if links:
            add(findings, "error", "DEP-AUD-032", str(package.get("manifest_path", name)), f"resolved package declares native links={links}: {name}", root=root, params={"package": name, "links": links, "version": str(package.get("version", ""))})
        if isinstance(source, str) and source.startswith("git+") and "#" not in source:
            add(findings, "error", "DEP-AUD-033", "Cargo.lock", f"Git package is not commit-resolved: {name}", root=root, params={"package": name, "source": str(source)})

    if reference_targets is not None:
        ref_paths = {t.root_path for t in reference_targets}
        missing_in_cargo = sorted(ref_paths - cargo_target_paths)
        missing_in_ref = sorted(cargo_target_paths - ref_paths)
        if missing_in_cargo or missing_in_ref:
            detail = f"reference target census differs from cargo metadata (extra in ref: {missing_in_cargo}, extra in cargo: {missing_in_ref})"
            add(findings, "warning", "DEP-AUD-041", "Cargo.toml", detail, root=root, params={"detail": detail})

    return True, None, census


def audit_workspace(
    root: Path = ROOT,
    policy_path: Path = ALLOWLIST,
    require_metadata: bool = False,
    qualify_script: Path | None = None,
    release_script: Path | None = None,
) -> tuple[dict[str, Any], int]:
    findings: list[Finding] = []
    try:
        policy = load_toml(policy_path)
    except Exception as exc:
        fatal_report = {"schema": "fss.dependency_audit.v4", "fatal": str(exc)}
        return fatal_report, 2

    rules = policy.get("policy", {})
    required_true = {
        "closed_universe",
        "direct_crates_must_be_allowlisted",
        "transitive_closure_must_be_censused",
        "new_external_dependency_requires_dep_record_and_adr",
        "fss_crates_must_forbid_unsafe",
        "release_resolution_must_be_locked_and_offline",
        "build_scripts_may_not_use_network",
        "serde_may_not_define_durable_bytes",
        "hosted_ci_is_not_release_authority",
        "asupersync_is_only_async_runtime",
    }
    required_false = {
        "fss_unsafe_exceptions_allowed",
        "c_or_cpp_ffi_allowed",
        "dynamic_loading_allowed",
        "foreign_runtime_production_boundary_allowed",
        "runtime_acquisition_allowed",
    }
    for key in sorted(required_true):
        if rules.get(key) is not True:
            add(findings, "error", "DEP-AUD-001", policy_path, f"policy.{key} must be true", root=root, params={"key": key, "expected": True, "actual": rules.get(key)})
    for key in sorted(required_false):
        if rules.get(key) is not False:
            add(findings, "error", "DEP-AUD-002", policy_path, f"policy.{key} must be false", root=root, params={"key": key, "expected": False, "actual": rules.get(key)})

    root_manifest_path = root / "Cargo.toml"
    if not root_manifest_path.is_file():
        add(findings, "error", "DEP-AUD-010", root_manifest_path, "root Cargo.toml is missing", root=root, params={"manifest": root_manifest_path})
        manifests = []
        member_names: set[str] = set()
        member_map: dict[str, Path] = {}
    else:
        root_cargo_data = load_toml(root_manifest_path)
        manifests, member_names, member_map = expand_workspace_members(root, root_cargo_data, findings)

    known_manifests = {m.resolve() for m in manifests}
    if root_manifest_path.is_file():
        known_manifests.add(root_manifest_path.resolve())

    if isinstance(root_cargo_data.get("workspace"), dict):
        for excl in root_cargo_data["workspace"].get("exclude", []):
            for excl_path in root.glob(excl):
                if (excl_path / "Cargo.toml").is_file():
                    known_manifests.add((excl_path / "Cargo.toml").resolve())

    vendored_fixture_dirs = set(policy.get("fixtures", {}).get("directories", []) or policy.get("vendored_fixtures", {}).get("directories", []))
    undeclared_manifests: list[Path] = []
    for cand_cargo in sorted(root.rglob("Cargo.toml")):
        parts = cand_cargo.parts
        if "target" in parts or ".git" in parts or ".claude" in parts or any(v in parts for v in vendored_fixture_dirs):
            continue
        if cand_cargo.resolve() not in known_manifests:
            undeclared_manifests.append(cand_cargo)
            add(
                findings,
                "error",
                "DEP-AUD-019",
                cand_cargo,
                f"undeclared non-member crate detected in repository tree: {cand_cargo}",
                root=root,
                params={"manifest": cand_cargo, "path": cand_cargo},
            )
            try:
                cand_data = load_toml(cand_cargo)
                crate_name = cand_data.get("package", {}).get("name", cand_cargo.parent.name)
                cand_manifest_rel = sanitize_path(cand_cargo, root)
                discover_crate_targets(cand_cargo.parent, cand_data, crate_name, cand_manifest_rel, root, findings)
            except Exception as exc:
                add(findings, "error", "DEP-AUD-011", cand_cargo, f"cannot parse TOML: {exc}", root=root, params={"manifest": cand_cargo, "error": str(exc)})

    direct = enumerate_dependencies(root, manifests, member_names, member_map, policy, findings)
    source_census = rust_source_audit(findings, root=root, manifests=manifests)
    serde_durable_bytes_audit(findings, root=root, direct_rows=direct, manifests=manifests)

    ref_targets: list[TargetRoot] = []
    for tr_dict in source_census.get("targetRoots", []):
        ref_targets.append(TargetRoot(**tr_dict))

    resolved_build_scripts: list[Path] = []
    metadata_available, metadata_error, resolved = metadata_audit(findings, policy, root=root, reference_targets=ref_targets, build_script_paths=resolved_build_scripts)
    serde_durable_bytes_audit(findings, root=root, resolved_names=[str(row.get("name", "")) for row in resolved])
    build_script_network_audit(findings, root=root, manifests=manifests + undeclared_manifests, extra_paths=resolved_build_scripts)
    if qualify_script is not None:
        qualify_offline_audit(findings, qualify_script, root=root)
        qualify_doctest_audit(findings, qualify_script, root=root)
    if release_script is not None:
        qualify_offline_audit(findings, release_script, root=root)
    if not metadata_available:
        lock_file = root / "Cargo.lock"
        if lock_file.is_file():
            try:
                lock_data = load_toml(lock_file)
                forbidden_crates = set(policy.get("forbidden", {}).get("crates", []))
                for pkg in lock_data.get("package", []):
                    pkg_name = pkg.get("name")
                    if isinstance(pkg_name, str) and pkg_name in forbidden_crates:
                        add(
                            findings,
                            "error",
                            "DEP-AUD-030",
                            "Cargo.lock",
                            f"forbidden package is reachable: {pkg_name}",
                            root=root,
                            params={"package": pkg_name, "version": str(pkg.get("version", ""))},
                        )
            except Exception:
                pass
    if require_metadata and not metadata_available:
        add(findings, "error", "DEP-AUD-040", "Cargo.lock", f"offline pinned-nightly metadata is required: {metadata_error}", root=root, params={"error": str(metadata_error)})

    error_count = sum(f.severity == "error" for f in findings)
    try:
        policy_rendered = policy_path.relative_to(root).as_posix()
    except ValueError:
        policy_rendered = str(policy_path)

    toolchain_file = root / "rust-toolchain.toml"
    toolchain_channel = None
    if toolchain_file.is_file():
        try:
            toolchain_channel = load_toml(toolchain_file).get("toolchain", {}).get("channel")
        except Exception:
            pass

    sorted_findings = sorted([asdict(f) for f in findings], key=lambda row: (row["severity"], row["code"], row["path"], row["message"]))
    sorted_direct = sorted(direct, key=lambda row: (row["manifest"], row["section"], row["name"], row["localName"]))
    sorted_resolved = sorted(resolved, key=lambda row: (row["name"], row["version"]))

    digest_content = {
        "directDependencies": sorted_direct,
        "targetRoots": source_census.get("targetRoots", []),
        "resolvedPackages": sorted_resolved,
    }
    census_digest = "sha256:" + hashlib.sha256(json.dumps(digest_content, sort_keys=True).encode("utf-8")).hexdigest()

    workspace_members_list = sorted(member_names)

    report = {
        "schema": "fss.dependency_audit.v4",
        "policy": policy_rendered,
        "toolchain": toolchain_channel,
        "qualificationStatus": "qualified" if metadata_available and error_count == 0 else "policy_only" if error_count == 0 else "failed",
        "metadataAvailable": metadata_available,
        "metadataError": metadata_error,
        "workspaceMemberCount": len(workspace_members_list),
        "workspaceMembers": workspace_members_list,
        "directDependencyCount": len(sorted_direct),
        "directDependencies": sorted_direct,
        "resolvedPackageCount": len(sorted_resolved),
        "resolvedPackages": sorted_resolved,
        "rustFileCount": source_census["rustFileCount"],
        "targetRootCount": source_census["targetRootCount"],
        "targetRoots": source_census.get("targetRoots", []),
        "censusDigest": census_digest,
        "findingCount": len(sorted_findings),
        "errorCount": error_count,
        "findings": sorted_findings,
    }
    return report, (1 if error_count else 0)


def main() -> int:
    parser = argparse.ArgumentParser(description="Audit FSS's closed Rust dependency universe")
    parser.add_argument("--require-metadata", action="store_true", help="fail unless pinned-nightly cargo metadata succeeds offline")
    parser.add_argument("--output", type=Path, help="also write the JSON report to this path")
    args = parser.parse_args()

    report, rc = audit_workspace(
        root=ROOT,
        policy_path=ALLOWLIST,
        require_metadata=args.require_metadata,
        qualify_script=ROOT / "scripts/qualify.sh",
        release_script=ROOT / "scripts/release_qualify.sh",
    )
    rendered = json.dumps(report, indent=2, sort_keys=True) + "\n"
    print(rendered, end="")
    if args.output is not None:
        output = args.output if args.output.is_absolute() else ROOT / args.output
        output.parent.mkdir(parents=True, exist_ok=True)
        output.write_text(rendered, encoding="utf-8")
    return rc


if __name__ == "__main__":
    raise SystemExit(main())
