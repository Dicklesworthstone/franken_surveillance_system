#!/usr/bin/env python3
from __future__ import annotations

import argparse
import fnmatch
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


@dataclass(frozen=True)
class Finding:
    severity: str
    code: str
    path: str
    message: str


def load_toml(path: Path) -> dict[str, Any]:
    value = tomllib.loads(path.read_text(encoding="utf-8"))
    if not isinstance(value, dict):
        raise ValueError(f"top-level TOML value is not a table: {path}")
    return value


def add(findings: list[Finding], severity: str, code: str, path: Path | str, message: str) -> None:
    if isinstance(path, Path):
        try:
            rendered = path.relative_to(ROOT).as_posix()
        except ValueError:
            rendered = str(path)
    else:
        rendered = path
    findings.append(Finding(severity, code, rendered, message))


def target_roots(manifest: Path, data: dict[str, Any]) -> list[Path]:
    crate = manifest.parent
    roots = [crate / "src/lib.rs", crate / "src/main.rs"]
    for target_kind in ("bin", "example", "test", "bench"):
        targets = data.get(target_kind, [])
        if isinstance(targets, dict):
            targets = [targets]
        if isinstance(targets, list):
            for target in targets:
                if isinstance(target, dict) and isinstance(target.get("path"), str):
                    roots.append(crate / target["path"])
    return sorted({path for path in roots if path.is_file()})


def direct_dependency_rows(findings: list[Finding], policy: dict[str, Any]) -> list[dict[str, Any]]:
    allowed_patterns = list(policy.get("in_house", {}).get("allowed_families", []))
    allowed_patterns += list(policy.get("fundamental", {}).get("allowed_subject_to_audit", []))
    forbidden = set(policy.get("forbidden", {}).get("crates", []))
    rows: list[dict[str, Any]] = []

    root_manifest = load_toml(ROOT / "Cargo.toml")
    members = root_manifest.get("workspace", {}).get("members", [])
    manifests = [ROOT / "Cargo.toml"]
    for member in members:
        if isinstance(member, str):
            manifests.append(ROOT / member / "Cargo.toml")

    member_names: set[str] = set()
    for manifest in manifests[1:]:
        if manifest.is_file():
            name = load_toml(manifest).get("package", {}).get("name")
            if isinstance(name, str):
                member_names.add(name)

    def allowed(name: str) -> bool:
        return name in member_names or any(fnmatch.fnmatchcase(name, pattern) for pattern in allowed_patterns)

    for manifest in sorted(set(manifests)):
        if not manifest.is_file():
            add(findings, "error", "DEP-AUD-010", manifest, "workspace member manifest is missing")
            continue
        data = load_toml(manifest)
        relative = manifest.relative_to(ROOT).as_posix()
        sections: list[tuple[str, Any]] = [
            ("dependencies", data.get("dependencies", {})),
            ("dev-dependencies", data.get("dev-dependencies", {})),
            ("build-dependencies", data.get("build-dependencies", {})),
        ]
        if manifest == ROOT / "Cargo.toml":
            sections.append(("workspace.dependencies", data.get("workspace", {}).get("dependencies", {})))
        for section, table in sections:
            if not isinstance(table, dict):
                add(findings, "error", "DEP-AUD-011", manifest, f"[{section}] is not a table")
                continue
            for local_name, specification in sorted(table.items()):
                package = local_name
                kind = "registry"
                source: str | None = None
                default_features: bool | None = None
                features: list[str] = []
                if isinstance(specification, dict):
                    package = str(specification.get("package", local_name))
                    default_features = specification.get("default-features")
                    features = [str(item) for item in specification.get("features", [])]
                    if "path" in specification:
                        kind = "path"
                        raw_path = str(specification["path"])
                        resolved = (manifest.parent / raw_path).resolve()
                        source = raw_path
                        try:
                            resolved.relative_to(ROOT)
                        except ValueError:
                            add(
                                findings,
                                "error",
                                "DEP-AUD-012",
                                manifest,
                                f"path dependency escapes the frozen repository/sibling closure: {package} -> {raw_path}",
                            )
                    elif "git" in specification:
                        kind = "git"
                        source = str(specification["git"])
                        rev = specification.get("rev")
                        if not isinstance(rev, str) or re.fullmatch(r"[0-9a-f]{40}", rev) is None:
                            add(findings, "error", "DEP-AUD-013", manifest, f"Git dependency lacks an exact 40-hex rev: {package}")
                    elif "version" in specification:
                        source = str(specification["version"])
                elif isinstance(specification, str):
                    source = specification
                rows.append(
                    {
                        "name": package,
                        "localName": local_name,
                        "manifest": relative,
                        "section": section,
                        "kind": kind,
                        "source": source,
                        "defaultFeatures": default_features,
                        "features": features,
                    }
                )
                if section == "build-dependencies":
                    add(findings, "error", "DEP-AUD-014", manifest, f"build dependency is prohibited without a constitutional amendment: {package}")
                if package in forbidden:
                    add(findings, "error", "DEP-AUD-015", manifest, f"forbidden direct dependency: {package}")
                elif kind != "path" and not allowed(package):
                    add(findings, "error", "DEP-AUD-016", manifest, f"direct dependency is outside the closed allowlist: {package}")
                if kind != "path" and default_features is not False:
                    add(findings, "error", "DEP-AUD-017", manifest, f"external dependency must set default-features = false: {package}")
    return rows


def rust_source_audit(findings: list[Finding]) -> dict[str, Any]:
    manifests = sorted((ROOT / "crates").glob("*/Cargo.toml"))
    target_root_count = 0
    rust_files = sorted((ROOT / "crates").rglob("*.rs"))
    for manifest in manifests:
        data = load_toml(manifest)
        roots = target_roots(manifest, data)
        if not roots:
            add(findings, "error", "DEP-AUD-020", manifest, "crate has no inspectable Rust target root")
        for root in roots:
            target_root_count += 1
            if "#![forbid(unsafe_code)]" not in root.read_text(encoding="utf-8"):
                add(findings, "error", "DEP-AUD-021", root, "target root lacks unconditional #![forbid(unsafe_code)]")

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
                add(findings, "error", "DEP-AUD-022", path, f"forbidden production construct: {label}")
    return {"rustFileCount": len(rust_files), "targetRootCount": target_root_count}


def metadata_audit(findings: list[Finding], policy: dict[str, Any]) -> tuple[bool, str | None, list[dict[str, Any]]]:
    if not CARGO_LOCK.is_file():
        return False, "Cargo.lock is absent", []
    if not TOOLCHAIN.is_file():
        return False, "rust-toolchain.toml is absent", []
    if shutil.which("rustup") is None:
        return False, "rustup is unavailable", []
    channel = load_toml(TOOLCHAIN).get("toolchain", {}).get("channel")
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
    proc = subprocess.run(command, cwd=ROOT, text=True, capture_output=True)
    if proc.returncode != 0:
        detail = proc.stderr.strip() or proc.stdout.strip() or "cargo metadata failed"
        return False, detail, []
    try:
        metadata = json.loads(proc.stdout)
    except json.JSONDecodeError as exc:
        return False, f"cargo metadata emitted invalid JSON: {exc}", []
    packages = metadata.get("packages", [])
    forbidden = set(policy.get("forbidden", {}).get("crates", []))
    census: list[dict[str, Any]] = []
    for package in sorted(packages, key=lambda row: (str(row.get("name")), str(row.get("version")))):
        name = str(package.get("name", ""))
        source = package.get("source")
        targets = package.get("targets", [])
        custom_build = any("custom-build" in target.get("kind", []) for target in targets if isinstance(target, dict))
        links = package.get("links")
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
            add(findings, "error", "DEP-AUD-030", "Cargo.lock", f"forbidden package is reachable: {name}")
        if custom_build:
            add(findings, "error", "DEP-AUD-031", str(package.get("manifest_path", name)), f"resolved package has a build script: {name}")
        if links:
            add(findings, "error", "DEP-AUD-032", str(package.get("manifest_path", name)), f"resolved package declares native links={links}: {name}")
        if isinstance(source, str) and source.startswith("git+") and "#" not in source:
            add(findings, "error", "DEP-AUD-033", "Cargo.lock", f"Git package is not commit-resolved: {name}")
    return True, None, census


def main() -> int:
    parser = argparse.ArgumentParser(description="Audit FSS's closed Rust dependency universe")
    parser.add_argument("--require-metadata", action="store_true", help="fail unless pinned-nightly cargo metadata succeeds offline")
    parser.add_argument("--output", type=Path, help="also write the JSON report to this path")
    args = parser.parse_args()

    findings: list[Finding] = []
    try:
        policy = load_toml(ALLOWLIST)
    except Exception as exc:
        print(json.dumps({"schema": "fss.dependency_audit.v3", "fatal": str(exc)}, indent=2), file=sys.stderr)
        return 2

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
            add(findings, "error", "DEP-AUD-001", ALLOWLIST, f"policy.{key} must be true")
    for key in sorted(required_false):
        if rules.get(key) is not False:
            add(findings, "error", "DEP-AUD-002", ALLOWLIST, f"policy.{key} must be false")

    direct = direct_dependency_rows(findings, policy)
    source_census = rust_source_audit(findings)
    metadata_available, metadata_error, resolved = metadata_audit(findings, policy)
    if args.require_metadata and not metadata_available:
        add(findings, "error", "DEP-AUD-040", "Cargo.lock", f"offline pinned-nightly metadata is required: {metadata_error}")

    error_count = sum(finding.severity == "error" for finding in findings)
    report = {
        "schema": "fss.dependency_audit.v3",
        "policy": ALLOWLIST.relative_to(ROOT).as_posix(),
        "toolchain": load_toml(TOOLCHAIN).get("toolchain", {}).get("channel") if TOOLCHAIN.is_file() else None,
        "qualificationStatus": "qualified" if metadata_available and error_count == 0 else "policy_only" if error_count == 0 else "failed",
        "metadataAvailable": metadata_available,
        "metadataError": metadata_error,
        "directDependencies": direct,
        "resolvedPackages": resolved,
        "resolvedPackageCount": len(resolved),
        **source_census,
        "findingCount": len(findings),
        "errorCount": error_count,
        "findings": [asdict(finding) for finding in findings],
    }
    rendered = json.dumps(report, indent=2, sort_keys=True) + "\n"
    print(rendered, end="")
    if args.output is not None:
        output = args.output if args.output.is_absolute() else ROOT / args.output
        output.parent.mkdir(parents=True, exist_ok=True)
        output.write_text(rendered, encoding="utf-8")
    return 1 if error_count else 0


if __name__ == "__main__":
    raise SystemExit(main())
