#!/usr/bin/env python3
from __future__ import annotations

import argparse
import fnmatch
import hashlib
import json
import re
import sys
import tomllib
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
EXCLUDED_TOP_LEVEL = {
    ".git",
    "target",
    "dist",
    "secrets",
    "credentials",
    "captures",
    "archive-spool",
    "model-cache",
}
EXCLUDED_PREFIXES = {
    Path("device-fixtures/private"),
    Path("qualification-artifacts"),
}
TEXT_SUFFIXES = {".md", ".json", ".toml", ".py", ".sh", ".yml", ".yaml", ".rs"}
errors: list[str] = []
notes: list[str] = []


def fail(message: str) -> None:
    errors.append(message)


def included(path: Path) -> bool:
    relative = path.relative_to(ROOT)
    if "__pycache__" in relative.parts or path.suffix in {".pyc", ".pyo"}:
        return False
    if relative.parts and relative.parts[0] in EXCLUDED_TOP_LEVEL:
        return False
    return not any(relative == prefix or prefix in relative.parents for prefix in EXCLUDED_PREFIXES)


def source_files(suffix: str | None = None) -> list[Path]:
    files = [path for path in ROOT.rglob("*") if path.is_file() and included(path)]
    if suffix is not None:
        files = [path for path in files if path.suffix == suffix]
    return sorted(files)


def load_json(relative: str) -> dict[str, Any]:
    path = ROOT / relative
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except Exception as exc:
        fail(f"cannot parse {relative}: {exc}")
        return {}
    if not isinstance(value, dict):
        fail(f"top-level JSON value must be an object: {relative}")
        return {}
    return value


def load_toml(relative: str) -> dict[str, Any]:
    path = ROOT / relative
    try:
        value = tomllib.loads(path.read_text(encoding="utf-8"))
    except Exception as exc:
        fail(f"cannot parse {relative}: {exc}")
        return {}
    if not isinstance(value, dict):
        fail(f"top-level TOML value must be a table: {relative}")
        return {}
    return value


def unique_rows(rows: Any, field: str, relative: str) -> dict[str, dict[str, Any]]:
    if not isinstance(rows, list):
        fail(f"{relative} must contain a list for its registry rows")
        return {}
    result: dict[str, dict[str, Any]] = {}
    for index, row in enumerate(rows):
        if not isinstance(row, dict):
            fail(f"{relative} row {index} is not an object")
            continue
        identifier = row.get(field)
        if not isinstance(identifier, str) or not identifier:
            fail(f"{relative} row {index} lacks string {field}")
            continue
        if identifier in result:
            fail(f"duplicate {field} {identifier} in {relative}")
        result[identifier] = row
    return result


def markdown_table_rows(relative: str, regex: str) -> dict[str, tuple[str, ...]]:
    path = ROOT / relative
    if not path.is_file():
        fail(f"missing Markdown registry: {relative}")
        return {}
    matches = re.findall(regex, path.read_text(encoding="utf-8"), flags=re.MULTILINE)
    result: dict[str, tuple[str, ...]] = {}
    for match in matches:
        values = (match,) if isinstance(match, str) else tuple(match)
        identifier = values[0]
        if identifier in result:
            fail(f"duplicate Markdown registry ID {identifier} in {relative}")
        result[identifier] = values[1:]
    return result


def compare_ids(machine: dict[str, Any], markdown: dict[str, Any], label: str) -> None:
    missing_markdown = sorted(set(machine) - set(markdown))
    missing_machine = sorted(set(markdown) - set(machine))
    if missing_markdown:
        fail(f"{label} IDs missing from Markdown: {', '.join(missing_markdown)}")
    if missing_machine:
        fail(f"{label} IDs missing from machine registry: {', '.join(missing_machine)}")


def resolve_markdown_links() -> None:
    link_pattern = re.compile(r"(?<!!)\[[^\]]*\]\(([^)]+)\)")
    for path in source_files(".md"):
        text = path.read_text(encoding="utf-8")
        for raw_target in link_pattern.findall(text):
            target = raw_target.strip()
            if target.startswith("<") and target.endswith(">"):
                target = target[1:-1]
            if not target or target.startswith(("#", "http://", "https://", "mailto:", "data:")):
                continue
            target = target.split("#", 1)[0].split("?", 1)[0]
            if not target:
                continue
            # Markdown titles after a URL are unsupported in repository-local links by policy.
            if " \"" in target or " '" in target:
                target = target.split(" ", 1)[0]
            candidate = (path.parent / target).resolve()
            try:
                candidate.relative_to(ROOT.resolve())
            except ValueError:
                fail(f"Markdown link escapes repository in {path.relative_to(ROOT)}: {raw_target}")
                continue
            if not candidate.exists():
                fail(f"broken Markdown link in {path.relative_to(ROOT)}: {raw_target}")


def canonical_mirror_policy() -> None:
    pairs = {
        "DEPENDENCY_CONSTITUTION.md": "docs/DEPENDENCY_CONSTITUTION.md",
        "GRAPH_ANALYTICS_AND_SENSOR_MESH.md": "docs/GRAPH_ANALYTICS_AND_SENSOR_MESH.md",
        "ATP_AND_DISTRIBUTED_EVIDENCE.md": "docs/ATP_AND_DISTRIBUTED_EVIDENCE.md",
        "PURE_RUST_MODEL_RUNTIME.md": "docs/PURE_RUST_MODEL_RUNTIME.md",
        "LOCAL_QUALIFICATION_AND_RELEASE.md": "docs/LOCAL_QUALIFICATION_AND_RELEASE.md",
    }
    for canonical, mirror in pairs.items():
        canonical_path = ROOT / canonical
        mirror_path = ROOT / mirror
        if not canonical_path.is_file() or not mirror_path.is_file():
            fail(f"canonical/mirror pair is incomplete: {canonical} <-> {mirror}")
            continue
        if canonical_path.read_bytes() != mirror_path.read_bytes():
            fail(f"canonical/mirror drift: {canonical} <-> {mirror}")


def cargo_policy(dependency_policy: dict[str, Any]) -> None:
    root_cargo = load_toml("Cargo.toml")
    rust_lints = root_cargo.get("workspace", {}).get("lints", {}).get("rust", {})
    if rust_lints.get("unsafe_code") != "forbid":
        fail("Cargo workspace must set workspace.lints.rust.unsafe_code = 'forbid'")

    allowed_patterns = dependency_policy.get("in_house", {}).get("allowed_families", [])
    allowed_patterns += dependency_policy.get("fundamental", {}).get("allowed_subject_to_audit", [])
    forbidden = set(dependency_policy.get("forbidden", {}).get("crates", []))
    workspace_members = set(root_cargo.get("workspace", {}).get("members", []))
    member_names: set[str] = set()
    for member in workspace_members:
        member_manifest = ROOT / member / "Cargo.toml"
        if not member_manifest.is_file():
            fail(f"workspace member manifest missing: {member}/Cargo.toml")
            continue
        data = load_toml(f"{member}/Cargo.toml")
        name = data.get("package", {}).get("name")
        if isinstance(name, str):
            member_names.add(name)

    def is_allowed(name: str) -> bool:
        return name in member_names or any(fnmatch.fnmatchcase(name, pattern) for pattern in allowed_patterns)

    for manifest in sorted(ROOT.rglob("Cargo.toml")):
        if not included(manifest):
            continue
        relative = manifest.relative_to(ROOT).as_posix()
        data = load_toml(relative)
        for section in ("dependencies", "dev-dependencies", "build-dependencies"):
            dependencies = data.get(section, {})
            if not isinstance(dependencies, dict):
                fail(f"{relative} [{section}] must be a table")
                continue
            for local_name, specification in dependencies.items():
                package_name = local_name
                path_dependency = False
                if isinstance(specification, dict):
                    package_name = str(specification.get("package", local_name))
                    path_dependency = "path" in specification
                    if specification.get("git") and not specification.get("rev"):
                        fail(f"unpinned Git dependency {package_name} in {relative}")
                    if specification.get("default-features") is not False and not path_dependency:
                        fail(f"external dependency {package_name} in {relative} must set default-features = false")
                if path_dependency:
                    continue
                if package_name in forbidden:
                    fail(f"forbidden crate {package_name} in {relative}")
                elif not is_allowed(package_name):
                    fail(f"unallowlisted direct crate {package_name} in {relative}")
        if data.get("build-dependencies"):
            fail(f"build dependencies are prohibited by default: {relative}")

    lock_path = ROOT / "Cargo.lock"
    if not lock_path.is_file():
        fail("Cargo.lock is required for locked/offline qualification")
    else:
        try:
            lock = tomllib.loads(lock_path.read_text(encoding="utf-8"))
            for package in lock.get("package", []):
                name = package.get("name")
                if isinstance(name, str) and name in forbidden:
                    fail(f"forbidden crate is reachable in Cargo.lock: {name}")
        except Exception as exc:
            fail(f"invalid Cargo.lock: {exc}")

    for crate_manifest in sorted((ROOT / "crates").glob("*/Cargo.toml")):
        crate_dir = crate_manifest.parent
        roots = [crate_dir / "src/lib.rs", crate_dir / "src/main.rs"]
        data = load_toml(crate_manifest.relative_to(ROOT).as_posix())
        for target_kind in ("bin", "example", "test", "bench"):
            targets = data.get(target_kind, [])
            if isinstance(targets, dict):
                targets = [targets]
            if isinstance(targets, list):
                for target in targets:
                    if isinstance(target, dict) and isinstance(target.get("path"), str):
                        roots.append(crate_dir / target["path"])
        roots = [path for path in roots if path.is_file()]
        if not roots:
            fail(f"crate has no inspectable Rust target root: {crate_dir.relative_to(ROOT)}")
        for path in roots:
            if "#![forbid(unsafe_code)]" not in path.read_text(encoding="utf-8"):
                fail(f"Rust target root lacks unconditional unsafe prohibition: {path.relative_to(ROOT)}")

    unsafe_patterns = {
        "unsafe token": re.compile(r"\bunsafe\b"),
        "C ABI": re.compile(r"extern\s+\"C\""),
        "native link attribute": re.compile(r"#\s*\[\s*link\s*\("),
        "dynamic loader": re.compile(r"\b(?:libloading|dlopen|LoadLibrary)\b"),
    }
    for path in source_files(".rs"):
        text = path.read_text(encoding="utf-8")
        # The required crate attribute itself contains the word unsafe; remove it before scanning.
        scan = text.replace("#![forbid(unsafe_code)]", "")
        for label, pattern in unsafe_patterns.items():
            if pattern.search(scan):
                fail(f"{label} in FSS Rust source: {path.relative_to(ROOT)}")


def workflow_policy() -> None:
    workflows = sorted((ROOT / ".github/workflows").glob("*.y*ml"))
    if not workflows:
        fail("at least one portable workflow specification is required")
        return
    forbidden_fragments = [
        "actions/setup-python",
        "dtolnay/rust-toolchain",
        "actions-rs/toolchain",
        "rustup toolchain",
        "rustup override",
        "cargo fmt",
        "cargo check",
        "cargo clippy",
        "cargo test",
        "python3 scripts/check-policy.py",
    ]
    for path in workflows:
        text = path.read_text(encoding="utf-8")
        if "scripts/qualify.sh" not in text and "scripts/release_qualify.sh" not in text:
            fail(f"workflow does not delegate to repository qualifier: {path.relative_to(ROOT)}")
        lowered = text.lower()
        if "local" not in lowered or "authoritative" not in lowered or "supplement" not in lowered:
            fail(f"workflow does not declare local-authoritative/supplementary role: {path.relative_to(ROOT)}")
        for fragment in forbidden_fragments:
            if fragment in text:
                fail(f"workflow contains unique setup/qualification logic ({fragment}): {path.relative_to(ROOT)}")


def validate_manifest() -> int:
    manifest_path = ROOT / "MANIFEST.sha256"
    if not manifest_path.is_file():
        fail("MANIFEST.sha256 is missing")
        return 0
    entries: dict[str, str] = {}
    line_pattern = re.compile(r"([0-9a-f]{64})  ([^\r\n]+)")
    for line_number, line in enumerate(manifest_path.read_text(encoding="utf-8").splitlines(), 1):
        match = line_pattern.fullmatch(line)
        if match is None:
            fail(f"malformed MANIFEST.sha256 line {line_number}")
            continue
        expected_digest, relative_text = match.groups()
        relative = Path(relative_text)
        if relative.is_absolute() or ".." in relative.parts:
            fail(f"unsafe manifest path: {relative_text}")
            continue
        if relative_text in entries:
            fail(f"duplicate manifest path: {relative_text}")
            continue
        entries[relative_text] = expected_digest
        path = ROOT / relative
        if not path.is_file():
            fail(f"manifest target missing: {relative_text}")
            continue
        actual = hashlib.sha256(path.read_bytes()).hexdigest()
        if actual != expected_digest:
            fail(f"manifest digest mismatch: {relative_text}")
    expected_paths = {
        path.relative_to(ROOT).as_posix()
        for path in source_files()
        if path != manifest_path
    }
    for relative in sorted(expected_paths - set(entries)):
        fail(f"source file missing from manifest: {relative}")
    for relative in sorted(set(entries) - expected_paths):
        fail(f"manifest lists excluded or unknown file: {relative}")
    return len(entries)


def main() -> int:
    parser = argparse.ArgumentParser(description="Validate FSS constitutional repository policy")
    parser.add_argument("--skip-manifest", action="store_true", help="used only while regenerating the manifest")
    args = parser.parse_args()

    json_files = source_files(".json")
    toml_files = source_files(".toml")
    for path in json_files:
        try:
            json.loads(path.read_text(encoding="utf-8"))
        except Exception as exc:
            fail(f"invalid JSON {path.relative_to(ROOT)}: {exc}")
    for path in toml_files:
        try:
            tomllib.loads(path.read_text(encoding="utf-8"))
        except Exception as exc:
            fail(f"invalid TOML {path.relative_to(ROOT)}: {exc}")

    required = [
        "README.md",
        "COMPREHENSIVE_PLAN_FOR_FRANKEN_SURVEILLANCE_SYSTEM.md",
        "FRANKENSTACK_DEEP_DIVE.md",
        "ARCHITECTURE.md",
        "IMPLEMENTATION_STATUS.md",
        "AGENTS.md",
        "SECURITY.md",
        "PRIVACY.md",
        "DATA_FORMATS.md",
        "DEVICE_ADAPTER_MATRIX.md",
        "MODEL_REGISTRY.md",
        "DIGITAL_TWIN_AND_CALIBRATION.md",
        "INTEROPERABILITY_LAB.md",
        "DEPENDENCY_CONSTITUTION.md",
        "GRAPH_ANALYTICS_AND_SENSOR_MESH.md",
        "ATP_AND_DISTRIBUTED_EVIDENCE.md",
        "PURE_RUST_MODEL_RUNTIME.md",
        "LOCAL_QUALIFICATION_AND_RELEASE.md",
        "docs/DEPENDENCY_CONSTITUTION.md",
        "docs/ONE_VERSION_UNIVERSE.md",
        "docs/STREAMING_AND_MEDIA_KERNEL.md",
        "docs/PURE_RUST_MODEL_RUNTIME.md",
        "docs/MVCC_EVIDENCE_LEDGER.md",
        "docs/GRAPH_INTELLIGENCE_ARCHITECTURE.md",
        "docs/GRAPH_ALGORITHM_ATLAS.md",
        "docs/GRAPH_ANALYTICS_AND_SENSOR_MESH.md",
        "docs/ATP_AND_DISTRIBUTED_EVIDENCE.md",
        "docs/ATP_ARCHIVE_AND_REPLICATION.md",
        "docs/ATP_MEDIA_GRAPH_AND_REPLICATION.md",
        "docs/DECISION_CARDS_AND_EXPERIMENTS.md",
        "docs/PERFORMANCE_AND_MECHANICAL_SYMPATHY.md",
        "docs/RESEARCH_LEDGER.md",
        "docs/LOCAL_QUALIFICATION_AND_RELEASE.md",
        "docs/LOCAL_QUALIFICATION_WITH_DSR.md",
        "docs/FRANKEN_IMPORT_ADMISSION_GATES.md",
        "docs/deep-dives/INDEX.md",
        "architecture/dependency_allowlist.toml",
        "architecture/dependency_constitution.json",
        "architecture/franken_imports.json",
        "architecture/model_runtime_registry.json",
        "architecture/invariants.json",
        "architecture/graph_algorithms.json",
        "architecture/publication_primitives.json",
        "architecture/decision_cards.json",
        "architecture/operation_cost_registry.toml",
        "architecture/crate_topology.json",
        "architecture/local_qualification.toml",
        "architecture/release_qualification.json",
        "architecture/readiness_dimensions.json",
        "architecture/repository_manifest.json",
        "registries/INVARIANTS.md",
        "registries/IMPORTS.md",
        "registries/GRAPH_ALGORITHMS.md",
        "registries/PUBLICATION_PRIMITIVES.md",
        "registries/DEPENDENCIES.md",
        "registries/QUALIFICATION_LANES.md",
        "registries/OPERATION_COSTS.md",
        "registries/SCHEMAS.md",
        "scripts/dependency_audit.py",
        "scripts/release_artifacts.py",
        "scripts/release_qualify.sh",
        "MANIFEST.sha256",
        "Cargo.lock",
    ]
    for relative in required:
        if not (ROOT / relative).is_file():
            fail(f"missing required file: {relative}")

    repository_manifest = load_json("architecture/repository_manifest.json")
    normative_rows = repository_manifest.get("normative", [])
    if not isinstance(normative_rows, list):
        fail("repository manifest normative field must be a list")
        normative_rows = []
    normative: set[str] = set()
    for relative in normative_rows:
        if not isinstance(relative, str) or not relative:
            fail(f"invalid normative manifest entry: {relative!r}")
            continue
        if relative in normative:
            fail(f"duplicate normative manifest entry: {relative}")
        normative.add(relative)
        if not (ROOT / relative).is_file():
            fail(f"normative manifest target missing: {relative}")
    required_normative = {
        "README.md",
        "COMPREHENSIVE_PLAN_FOR_FRANKEN_SURVEILLANCE_SYSTEM.md",
        "FRANKENSTACK_DEEP_DIVE.md",
        "DEPENDENCY_CONSTITUTION.md",
        "GRAPH_ANALYTICS_AND_SENSOR_MESH.md",
        "ATP_AND_DISTRIBUTED_EVIDENCE.md",
        "PURE_RUST_MODEL_RUNTIME.md",
        "LOCAL_QUALIFICATION_AND_RELEASE.md",
        "docs/DEPENDENCY_CONSTITUTION.md",
        "docs/ONE_VERSION_UNIVERSE.md",
        "docs/STREAMING_AND_MEDIA_KERNEL.md",
        "docs/PURE_RUST_MODEL_RUNTIME.md",
        "docs/MVCC_EVIDENCE_LEDGER.md",
        "docs/GRAPH_INTELLIGENCE_ARCHITECTURE.md",
        "docs/GRAPH_ALGORITHM_ATLAS.md",
        "docs/ATP_ARCHIVE_AND_REPLICATION.md",
        "docs/LOCAL_QUALIFICATION_WITH_DSR.md",
        "architecture/dependency_allowlist.toml",
        "architecture/dependency_constitution.json",
        "architecture/franken_imports.json",
        "architecture/model_runtime_registry.json",
        "architecture/invariants.json",
        "architecture/graph_algorithms.json",
        "architecture/publication_primitives.json",
        "architecture/decision_cards.json",
        "architecture/crate_topology.json",
        "architecture/release_qualification.json",
        "registries/INVARIANTS.md",
        "registries/IMPORTS.md",
        "registries/GRAPH_ALGORITHMS.md",
        "registries/PUBLICATION_PRIMITIVES.md",
        "registries/DEPENDENCIES.md",
        "registries/QUALIFICATION_LANES.md",
        "registries/SCHEMAS.md",
    }
    for relative in sorted(required_normative - normative):
        fail(f"canonical file missing from repository normative manifest: {relative}")
    if repository_manifest.get("releaseAuthority") != "local DSR qualification receipts":
        fail("repository manifest must name local DSR qualification receipts as release authority")

    invariants = unique_rows(load_json("architecture/invariants.json").get("invariants"), "id", "architecture/invariants.json")
    invariant_md = markdown_table_rows(
        "registries/INVARIANTS.md",
        r"^\| `((?:INV)-[A-Z0-9-]+)` \| (.*?) \| `([^`]+)` \|$",
    )
    compare_ids(invariants, invariant_md, "invariant")
    for identifier, row in invariants.items():
        if identifier in invariant_md:
            text, status = invariant_md[identifier]
            if row.get("text") != text.replace("\\|", "|") or row.get("status") != status:
                fail(f"machine and Markdown invariant row disagree: {identifier}")
    texts: dict[str, str] = {}
    for identifier, row in invariants.items():
        text = row.get("text")
        if not isinstance(text, str) or not text:
            fail(f"invariant lacks text: {identifier}")
        elif text in texts:
            fail(f"duplicate invariant semantics: {texts[text]} and {identifier}")
        else:
            texts[text] = identifier

    costs_doc = load_toml("architecture/operation_cost_registry.toml")
    costs = unique_rows(costs_doc.get("operation"), "id", "architecture/operation_cost_registry.toml")
    cost_md = markdown_table_rows(
        "registries/OPERATION_COSTS.md",
        r"^\| `((?:COST)-[A-Z0-9-]+)` \|",
    )
    compare_ids(costs, cost_md, "operation-cost")

    algorithms = unique_rows(load_json("architecture/graph_algorithms.json").get("algorithms"), "id", "architecture/graph_algorithms.json")
    algorithm_md = markdown_table_rows(
        "registries/GRAPH_ALGORITHMS.md",
        r"^\| `((?:ALG)-[A-Z0-9-]+)` \| `([^`]+)` \| .* \| `([^`]+)` \| `([^`]+)` \|$",
    )
    compare_ids(algorithms, algorithm_md, "graph algorithm")
    required_algorithm_fields = {"name", "owner", "projection", "decision", "authoritativeness", "tieBreak", "complexityWitness", "exactness", "gate", "status"}
    for identifier, row in algorithms.items():
        missing = sorted(required_algorithm_fields - row.keys())
        if missing:
            fail(f"algorithm {identifier} lacks fields: {', '.join(missing)}")
        if identifier in algorithm_md:
            name, exactness, gate = algorithm_md[identifier]
            if (row.get("name"), row.get("exactness"), row.get("gate")) != (name, exactness, gate):
                fail(f"machine and Markdown graph algorithm row disagree: {identifier}")

    publications = unique_rows(load_json("architecture/publication_primitives.json").get("primitives"), "id", "architecture/publication_primitives.json")
    publication_md = markdown_table_rows(
        "registries/PUBLICATION_PRIMITIVES.md",
        r"^\| `((?:PUB)-[A-Z0-9-]+)` \| `([^`]+)` \| `([^`]+)` \| .* \| `([^`]+)` \|$",
    )
    compare_ids(publications, publication_md, "publication primitive")
    for identifier, row in publications.items():
        if identifier in publication_md:
            name, owner, status = publication_md[identifier]
            if (row.get("name"), row.get("owner"), row.get("status")) != (name, owner, status):
                fail(f"machine and Markdown publication row disagree: {identifier}")

    imports = unique_rows(load_json("architecture/franken_imports.json").get("imports"), "id", "architecture/franken_imports.json")
    import_md = markdown_table_rows(
        "registries/IMPORTS.md",
        r"^\| `((?:IMP)-[A-Z0-9-]+)` \| `([^`]+)` \| (.*?) \| `([^`]+)` \| `([^`]+)` \| `([^`]+)` \|$",
    )
    compare_ids(imports, import_md, "Franken import")
    required_import_fields = {"project", "mechanism", "mode", "owner", "substituteProhibition", "referenceModel", "failureBoundary", "gate", "source", "status"}
    for identifier, row in imports.items():
        missing = sorted(required_import_fields - row.keys())
        if missing:
            fail(f"import {identifier} lacks fields: {', '.join(missing)}")
        if identifier in import_md:
            project, mechanism, owner, gate, status = import_md[identifier]
            expected = (row.get("project"), row.get("mechanism"), row.get("owner"), row.get("gate"), row.get("status"))
            if expected != (project, mechanism.replace("\\|", "|"), owner, gate, status):
                fail(f"machine and Markdown import row disagree: {identifier}")

    decisions = unique_rows(load_json("architecture/decision_cards.json").get("decisionFamily"), "id", "architecture/decision_cards.json")
    for identifier, row in decisions.items():
        for field in ("purpose", "hardClamp", "safeFallback", "promotion", "status"):
            if not isinstance(row.get(field), str) or not row[field]:
                fail(f"decision family {identifier} lacks {field}")

    release_doc = load_json("architecture/release_qualification.json")
    lanes = unique_rows(release_doc.get("lanes"), "id", "architecture/release_qualification.json")
    lane_md = markdown_table_rows(
        "registries/QUALIFICATION_LANES.md",
        r"^\| `((?:QL)-[A-Z0-9-]+)` \| `([^`]+)` \| `([^`]+)` \| (.*?) \| `([^`]+)` \|$",
    )
    compare_ids(lanes, lane_md, "qualification lane")
    if release_doc.get("releaseAuthority") != "local_dsr":
        fail("release qualification authority must be local_dsr")
    if release_doc.get("hostedActionsRole") != "portable_supplementary_specification":
        fail("hosted workflow role must be portable_supplementary_specification")
    for identifier, row in lanes.items():
        if row.get("authority") != "local":
            fail(f"qualification lane is not locally authoritative: {identifier}")

    local_qualification = load_toml("architecture/local_qualification.toml")
    required_local_values = {
        "authority": "local_dsr_receipt",
        "repository_entrypoint": "scripts/qualify.sh",
        "workflow_yaml_role": "portable_executable_specification_only",
        "github_hosted_required": False,
        "clean_snapshot_required": True,
        "exact_sibling_revision_closure": True,
        "locked_resolution": True,
        "offline_after_provisioning": True,
        "partial_target_matrix_may_publish": False,
        "download_and_verify_after_upload": True,
        "signing_separate_from_build": True,
    }
    for key, expected in required_local_values.items():
        if local_qualification.get(key) != expected:
            fail(f"local qualification policy mismatch for {key}")
    local_lane_ids = {row.get("id") for row in local_qualification.get("lane", []) if isinstance(row, dict)}
    if local_lane_ids != set(lanes):
        fail("local qualification TOML and release qualification JSON lane IDs disagree")

    dependency_constitution = load_json("architecture/dependency_constitution.json")
    production_dependency = dependency_constitution.get("production", {})
    required_dependency_constitution = {
        "language": "rust-2024",
        "toolchain": "latest-accepted-pinned-nightly",
        "unsafe": "forbidden-in-all-fss-crates",
        "asyncRuntime": "asupersync-only",
        "closedUniverse": True,
        "lockedOfflineReleaseResolution": True,
        "runtimeAcquisition": False,
        "cCppFfi": False,
        "dynamicLoading": False,
        "foreignExecutables": False,
        "serdeDurableFormatAuthority": False,
    }
    for key, expected in required_dependency_constitution.items():
        if production_dependency.get(key) != expected:
            fail(f"dependency constitution JSON mismatch for production.{key}")

    toolchain = load_toml("rust-toolchain.toml").get("toolchain", {})
    channel = toolchain.get("channel")
    if not isinstance(channel, str) or re.fullmatch(r"nightly-\d{4}-\d{2}-\d{2}", channel) is None:
        fail("rust-toolchain.toml must pin one exact dated nightly")
    if toolchain.get("profile") != "minimal":
        fail("rust-toolchain.toml must use the minimal profile")
    components = set(toolchain.get("components", [])) if isinstance(toolchain.get("components"), list) else set()
    if not {"rustfmt", "clippy", "rust-src"}.issubset(components):
        fail("pinned nightly must include rustfmt, clippy, and rust-src")

    dependency_policy = load_toml("architecture/dependency_allowlist.toml")
    policy = dependency_policy.get("policy", {})
    required_dependency_values = {
        "closed_universe": True,
        "direct_crates_must_be_allowlisted": True,
        "transitive_closure_must_be_censused": True,
        "new_external_dependency_requires_dep_record_and_adr": True,
        "fss_crates_must_forbid_unsafe": True,
        "fss_unsafe_exceptions_allowed": False,
        "c_or_cpp_ffi_allowed": False,
        "dynamic_loading_allowed": False,
        "foreign_runtime_production_boundary_allowed": False,
        "release_resolution_must_be_locked_and_offline": True,
        "build_scripts_may_not_use_network": True,
        "runtime_acquisition_allowed": False,
        "serde_may_not_define_durable_bytes": True,
        "asupersync_is_only_async_runtime": True,
        "hosted_ci_is_not_release_authority": True,
    }
    for key, expected in required_dependency_values.items():
        if policy.get(key) != expected:
            fail(f"dependency constitution machine policy mismatch for {key}")
    cargo_policy(dependency_policy)

    model_runtime = load_json("architecture/model_runtime_registry.json")
    model_contracts = unique_rows(model_runtime.get("contracts"), "id", "architecture/model_runtime_registry.json")
    required_model_fields = {"owner", "schema", "invariant", "gate", "status"}
    for identifier, row in model_contracts.items():
        missing = sorted(required_model_fields - row.keys())
        if missing:
            fail(f"model runtime contract {identifier} lacks fields: {', '.join(missing)}")
    runtime = model_runtime.get("runtime", {})
    if runtime.get("productionLanguage") != "rust-2024" or runtime.get("asyncRuntime") != "asupersync":
        fail("model runtime registry must name Rust 2024 and Asupersync production execution")
    if runtime.get("unsafePolicy") != "forbid-without-exceptions" or runtime.get("foreignRuntimePolicy") != "laboratory-oracle-only":
        fail("model runtime registry violates unsafe/foreign-runtime constitution")

    topology = load_json("architecture/crate_topology.json")
    crate_names: set[str] = set()
    crate_status: dict[str, str] = {}
    for layer in topology.get("layers", []):
        if not isinstance(layer, dict):
            fail("crate topology layer is not an object")
            continue
        for crate in layer.get("crates", []):
            if not isinstance(crate, dict):
                fail("crate topology entry is not an object")
                continue
            name = crate.get("name")
            if not isinstance(name, str):
                fail("crate topology entry lacks name")
                continue
            if name in crate_names:
                fail(f"duplicate crate topology name: {name}")
            crate_names.add(name)
            status = crate.get("status")
            if status not in {"skeleton", "planned", "implemented", "qualified"}:
                fail(f"crate topology has invalid status for {name}: {status!r}")
            else:
                crate_status[name] = status
            if crate.get("unsafe") != "forbid":
                fail(f"crate topology does not forbid unsafe: {name}")
    root_cargo = load_toml("Cargo.toml")
    actual_workspace_names: set[str] = set()
    for member in root_cargo.get("workspace", {}).get("members", []):
        if not isinstance(member, str):
            continue
        manifest = ROOT / member / "Cargo.toml"
        if manifest.is_file():
            name = load_toml(f"{member}/Cargo.toml").get("package", {}).get("name")
            if isinstance(name, str):
                actual_workspace_names.add(name)
    for name in sorted(actual_workspace_names - crate_names):
        fail(f"workspace crate absent from crate topology: {name}")
    for name in sorted(actual_workspace_names):
        if crate_status.get(name) not in {"skeleton", "implemented", "qualified"}:
            fail(f"workspace crate is not marked present in crate topology: {name}")

    schema_registry_text = (ROOT / "registries/SCHEMAS.md").read_text(encoding="utf-8")
    schema_rows = re.findall(
        r"^\| `((?:SCHEMA)-[A-Z0-9-]+)` \| `([^`]+)` \| `([^`]+)` \|",
        schema_registry_text,
        flags=re.MULTILINE,
    )
    registered_schema_files: set[str] = set()
    for stable_id, schema_name, relative in schema_rows:
        if not relative.startswith("schemas/"):
            continue
        registered_schema_files.add(relative)
        schema_path = ROOT / relative
        if not schema_path.is_file():
            fail(f"{stable_id} references missing schema: {relative}")
            continue
        schema = load_json(relative)
        if schema.get("$schema") != "https://json-schema.org/draft/2020-12/schema":
            fail(f"{stable_id} does not declare JSON Schema Draft 2020-12")
        if schema.get("type") != "object":
            fail(f"{stable_id} top-level schema type must be object")
        if schema.get("properties", {}).get("schema", {}).get("const") != schema_name:
            fail(f"{stable_id} registry name disagrees with schema const")
        if not str(schema.get("$id", "")).endswith("/" + Path(relative).name):
            fail(f"{stable_id} has a nonmatching $id")
    actual_schema_files = {path.relative_to(ROOT).as_posix() for path in source_files(".json") if path.parent == ROOT / "schemas"}
    if registered_schema_files != actual_schema_files:
        for relative in sorted(actual_schema_files - registered_schema_files):
            fail(f"schema file missing from registry: {relative}")
        for relative in sorted(registered_schema_files - actual_schema_files):
            fail(f"schema registry lists unknown file: {relative}")

    # Basic JSON-Schema self-validation when the optional validator is already available.
    try:
        import jsonschema  # type: ignore
    except ImportError:
        notes.append("jsonschema package unavailable; Draft 2020-12 meta-schema validation skipped")
    else:
        for relative in sorted(actual_schema_files):
            schema = load_json(relative)
            try:
                jsonschema.Draft202012Validator.check_schema(schema)
            except Exception as exc:
                fail(f"invalid Draft 2020-12 schema {relative}: {exc}")

    stable_pattern = re.compile(
        r"\b(?:INV|GOAL|NONGOAL|CAP|EFFECT|ERR|SCHEMA|ADR|WP|GATE|TEST|SLO|RISK|OPEN|INT|COST|SEC|PRIV|FORMAL|NEG|FSS|LAB|ADP|MOD|ALG|PUB|DEC|DEP|REL|FMT|TRACE|ATP|IMP|QL|MODEL|XFER|GRAPH)(?:-[A-Z0-9]+)*-[0-9]{3}\b"
    )
    stable_ids: set[str] = set()
    for path in source_files(".md"):
        stable_ids.update(stable_pattern.findall(path.read_text(encoding="utf-8")))

    canonical_mirror_policy()
    resolve_markdown_links()
    workflow_policy()

    manifest_entries = 0 if args.skip_manifest else validate_manifest()

    if errors:
        print("policy check failed", file=sys.stderr)
        for error in errors:
            print(f"- {error}", file=sys.stderr)
        for note in notes:
            print(f"note: {note}", file=sys.stderr)
        return 1

    print(
        "policy check passed: "
        f"{len(json_files)} JSON files, {len(toml_files)} TOML files, "
        f"{len(stable_ids)} stable IDs, {len(invariants)} invariants, "
        f"{len(imports)} imports, {len(algorithms)} graph algorithms, "
        f"{len(publications)} publication primitives, {len(lanes)} local lanes, "
        f"{manifest_entries} manifest entries"
    )
    for note in notes:
        print(f"note: {note}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
