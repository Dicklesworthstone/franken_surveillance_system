#!/usr/bin/env python3
"""Cargo dependency and target root audit oracle (fss-x4a.6.18).

Enumerates the full Cargo workspace semantic surface, all target roots,
workspace globs/excludes, target cfg dependency tables, and verifies
unconditional #![forbid(unsafe_code)] enforcement across all targets.
"""
from __future__ import annotations

import argparse
import fnmatch
import hashlib
import json
import re
import shutil
import subprocess
import sys
import tomllib
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
ALLOWLIST = ROOT / "architecture/dependency_allowlist.toml"
CARGO_LOCK = ROOT / "Cargo.lock"
TOOLCHAIN = ROOT / "rust-toolchain.toml"


FORBID_UNSAFE_PATTERN = re.compile(r"#\s*!\s*\[\s*forbid\s*\(\s*unsafe_code\s*\)\s*\]")


@dataclass(frozen=True)
class Finding:
    severity: str
    code: str
    path: str
    message: str


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


def add(findings: list[Finding], severity: str, code: str, path: Path | str, message: str, root: Path = ROOT) -> None:
    if isinstance(path, Path):
        try:
            rendered = path.relative_to(root).as_posix()
        except ValueError:
            rendered = str(path)
    else:
        rendered = path
    findings.append(Finding(severity, code, rendered, message))


def expand_workspace_members(
    root: Path,
    root_manifest_data: dict[str, Any],
    findings: list[Finding],
) -> tuple[list[Path], set[str], dict[str, Path]]:
    ws = root_manifest_data.get("workspace")
    if not isinstance(ws, dict):
        add(findings, "error", "DEP-AUD-011", root / "Cargo.toml", "[workspace] must be a table", root=root)
        return [root / "Cargo.toml"], set(), {}

    members_spec = ws.get("members", [])
    if not isinstance(members_spec, list) or not all(isinstance(m, str) for m in members_spec):
        add(findings, "error", "DEP-AUD-011", root / "Cargo.toml", "workspace.members must be a list of strings", root=root)
        return [root / "Cargo.toml"], set(), {}

    exclude_spec = ws.get("exclude", [])
    if not isinstance(exclude_spec, list) or not all(isinstance(e, str) for e in exclude_spec):
        add(findings, "error", "DEP-AUD-011", root / "Cargo.toml", "workspace.exclude must be a list of strings", root=root)
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
                        add(findings, "error", "DEP-AUD-012", p / "Cargo.toml", f"workspace member escapes root: {p}", root=root)
                        continue
                    if is_excluded(rel):
                        continue
                    resolved_dir = p.resolve()
                    if resolved_dir in seen_dirs:
                        add(findings, "error", "DEP-AUD-024", p / "Cargo.toml", f"workspace membership duplicate or ambiguous: {rel}", root=root)
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
                add(findings, "error", "DEP-AUD-010", manifest, f"workspace member manifest is missing: {rel}/Cargo.toml", root=root)
                continue
            resolved_dir = p.resolve()
            if resolved_dir in seen_dirs:
                add(findings, "error", "DEP-AUD-024", manifest, f"workspace membership duplicate or ambiguous: {rel}", root=root)
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
                    add(findings, "error", "DEP-AUD-024", manifest_path, f"duplicate workspace member package name: {pkg_name}", root=root)
                member_names.add(pkg_name)
                member_map[pkg_name] = m_dir.resolve()
        except Exception as exc:
            add(findings, "error", "DEP-AUD-011", manifest_path, f"failed to load member manifest: {exc}", root=root)

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

    if autoexamples:
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

    if autotests:
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

    if autobenches:
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
    elif build_spec is None:
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
            add(findings, "error", "DEP-AUD-021", path, f"target root lacks unconditional #![forbid(unsafe_code)]: {rel_path}", root=root)
        if kind == "custom-build":
            add(findings, "error", "DEP-AUD-031", path, f"resolved package has a build script: {crate_name}", root=root)

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
        add(findings, "error", "DEP-AUD-020", manifest_rel, f"crate has no inspectable Rust target root: {crate_name}", root=root)

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
                add(findings, "error", "DEP-AUD-011", manifest, f"[{sec}] is not a table", root=root)

    if is_root:
        ws = data.get("workspace", {})
        if isinstance(ws, dict) and "dependencies" in ws:
            val = ws["dependencies"]
            if isinstance(val, dict):
                sections.append(("workspace.dependencies", None, val))
            else:
                add(findings, "error", "DEP-AUD-011", manifest, "[workspace.dependencies] is not a table", root=root)

    target_table = data.get("target")
    if target_table is not None:
        if not isinstance(target_table, dict):
            add(findings, "error", "DEP-AUD-025", manifest, "[target] must be a table", root=root)
        else:
            for target_spec, target_config in sorted(target_table.items()):
                if not isinstance(target_config, dict):
                    add(findings, "error", "DEP-AUD-025", manifest, f"[target.{target_spec}] must be a table", root=root)
                    continue
                for sec in ("dependencies", "dev-dependencies", "build-dependencies"):
                    if sec in target_config:
                        val = target_config[sec]
                        sec_name = f"target.{target_spec}.{sec}"
                        if isinstance(val, dict):
                            sections.append((sec_name, target_spec, val))
                        else:
                            add(findings, "error", "DEP-AUD-011", manifest, f"[{sec_name}] is not a table", root=root)

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
            add(findings, "error", "DEP-AUD-010", manifest, "workspace member manifest is missing", root=root)
            continue
        try:
            data = load_toml(manifest)
        except Exception as exc:
            add(findings, "error", "DEP-AUD-011", manifest, f"cannot parse TOML: {exc}", root=root)
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
                    add(findings, "error", "DEP-AUD-011", manifest, f"dependency '{local_name}' in [{section}] must be a table or string", root=root)
                    continue

                if isinstance(specification, dict):
                    package = str(specification.get("package", local_name))
                    optional = bool(specification.get("optional", False))
                    default_features = specification.get("default-features")
                    features = [str(item) for item in specification.get("features", [])]
                    if specification.get("workspace") is True:
                        workspace_inherited = True
                        ws_spec = ws_dependencies.get(local_name) or ws_dependencies.get(package)
                        if ws_spec is None:
                            add(findings, "error", "DEP-AUD-018", manifest, f"workspace-inherited dependency is missing in workspace.dependencies: {package}", root=root)
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
                                )

                        target_manifest = resolved_path / "Cargo.toml" if resolved_path.is_dir() else resolved_path
                        if not target_manifest.is_file():
                            add(findings, "error", "DEP-AUD-019", manifest, f"path dependency target manifest is missing: {package} -> {raw_path}", root=root)
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
                                    )
                            except Exception:
                                add(findings, "error", "DEP-AUD-019", manifest, f"path dependency target manifest is invalid: {package} -> {raw_path}", root=root)

                        if is_in_tree and package not in member_names and not is_allowed(package):
                            add(findings, "error", "DEP-AUD-019", manifest, f"path dependency points to undeclared non-member crate: {package} -> {raw_path}", root=root)

                    elif "git" in specification:
                        kind = "git"
                        source = str(specification["git"])
                        rev = specification.get("rev")
                        if not isinstance(rev, str) or re.fullmatch(r"[0-9a-f]{40}", rev) is None:
                            add(findings, "error", "DEP-AUD-013", manifest, f"Git dependency lacks an exact 40-hex rev: {package}", root=root)
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
                    add(findings, "error", "DEP-AUD-014", manifest, f"build dependency is prohibited without a constitutional amendment: {package}", root=root)

                if package in forbidden:
                    add(findings, "error", "DEP-AUD-015", manifest, f"forbidden direct dependency: {package}", root=root)
                elif not is_allowed(package):
                    add(findings, "error", "DEP-AUD-016", manifest, f"direct dependency is outside the closed allowlist: {package}", root=root)

                if kind != "path" and default_features is not False:
                    add(findings, "error", "DEP-AUD-017", manifest, f"external dependency must set default-features = false: {package}", root=root)

    return rows


def direct_dependency_rows(findings: list[Finding], policy: dict[str, Any], root: Path = ROOT) -> list[dict[str, Any]]:
    root_manifest = load_toml(root / "Cargo.toml")
    manifests, member_names, member_map = expand_workspace_members(root, root_manifest, findings)
    return enumerate_dependencies(root, manifests, member_names, member_map, policy, findings)


def rust_source_audit(findings: list[Finding], root: Path = ROOT) -> dict[str, Any]:
    root_manifest = load_toml(root / "Cargo.toml")
    manifests, _, _ = expand_workspace_members(root, root_manifest, findings)
    member_manifests = [m for m in manifests if m != root / "Cargo.toml"]

    all_targets: list[TargetRoot] = []
    for manifest in member_manifests:
        try:
            data = load_toml(manifest)
            manifest_rel = manifest.relative_to(root).as_posix()
        except Exception:
            continue
        crate_name = data.get("package", {}).get("name", manifest.parent.name)
        targets = discover_crate_targets(manifest.parent, data, crate_name, manifest_rel, root, findings)
        all_targets.extend(targets)

    rust_files = sorted(path for path in root.rglob("*.rs") if not any(part in {".git", "target", "dist", "qualification-artifacts"} for part in path.parts))

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
        scan = text.replace("#![forbid(unsafe_code)]", "")
        for label, pattern in patterns.items():
            if pattern.search(scan):
                add(findings, "error", "DEP-AUD-022", path, f"forbidden production construct: {label}", root=root)

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
) -> tuple[bool, str | None, list[dict[str, Any]]]:
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
            add(findings, "error", "DEP-AUD-030", "Cargo.lock", f"forbidden package is reachable: {name}", root=root)
        if custom_build:
            add(findings, "error", "DEP-AUD-031", str(package.get("manifest_path", name)), f"resolved package has a build script: {name}", root=root)
        if links:
            add(findings, "error", "DEP-AUD-032", str(package.get("manifest_path", name)), f"resolved package declares native links={links}: {name}", root=root)
        if isinstance(source, str) and source.startswith("git+") and "#" not in source:
            add(findings, "error", "DEP-AUD-033", "Cargo.lock", f"Git package is not commit-resolved: {name}", root=root)

    if reference_targets is not None:
        ref_paths = {t.root_path for t in reference_targets}
        missing_in_cargo = sorted(ref_paths - cargo_target_paths)
        missing_in_ref = sorted(cargo_target_paths - ref_paths)
        if missing_in_cargo or missing_in_ref:
            detail = f"reference target census differs from cargo metadata (extra in ref: {missing_in_cargo}, extra in cargo: {missing_in_ref})"
            add(findings, "warning", "DEP-AUD-041", "Cargo.toml", detail, root=root)

    return True, None, census


def audit_workspace(
    root: Path = ROOT,
    policy_path: Path = ALLOWLIST,
    require_metadata: bool = False,
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
            add(findings, "error", "DEP-AUD-001", policy_path, f"policy.{key} must be true", root=root)
    for key in sorted(required_false):
        if rules.get(key) is not False:
            add(findings, "error", "DEP-AUD-002", policy_path, f"policy.{key} must be false", root=root)

    root_manifest_path = root / "Cargo.toml"
    if not root_manifest_path.is_file():
        add(findings, "error", "DEP-AUD-010", root_manifest_path, "root Cargo.toml is missing", root=root)
        manifests = []
        member_names: set[str] = set()
        member_map: dict[str, Path] = {}
    else:
        root_cargo_data = load_toml(root_manifest_path)
        manifests, member_names, member_map = expand_workspace_members(root, root_cargo_data, findings)

    direct = enumerate_dependencies(root, manifests, member_names, member_map, policy, findings)
    source_census = rust_source_audit(findings, root=root)

    ref_targets: list[TargetRoot] = []
    for tr_dict in source_census.get("targetRoots", []):
        ref_targets.append(TargetRoot(**tr_dict))

    metadata_available, metadata_error, resolved = metadata_audit(findings, policy, root=root, reference_targets=ref_targets)
    if require_metadata and not metadata_available:
        add(findings, "error", "DEP-AUD-040", "Cargo.lock", f"offline pinned-nightly metadata is required: {metadata_error}", root=root)

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

    report, rc = audit_workspace(root=ROOT, policy_path=ALLOWLIST, require_metadata=args.require_metadata)
    rendered = json.dumps(report, indent=2, sort_keys=True) + "\n"
    print(rendered, end="")
    if args.output is not None:
        output = args.output if args.output.is_absolute() else ROOT / args.output
        output.parent.mkdir(parents=True, exist_ok=True)
        output.write_text(rendered, encoding="utf-8")
    return rc


if __name__ == "__main__":
    raise SystemExit(main())
