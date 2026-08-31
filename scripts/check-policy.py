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
    ".ee",
    ".beads",
    ".claude",
    ".ntm",
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
    if path.name == ".DS_Store" or "__pycache__" in relative.parts or path.suffix in {".pyc", ".pyo"}:
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


def validate_local_json_schema_refs(schema_files: set[str]) -> None:
    """Resolve repository-local JSON Schema references and their JSON Pointer fragments."""
    by_relative = {relative: load_json(relative) for relative in sorted(schema_files)}

    def resolve_pointer(document: Any, pointer: str, origin: str, ref: str) -> None:
        if not pointer:
            return
        if not pointer.startswith("/"):
            fail(f"unsupported non-pointer JSON Schema fragment in {origin}: {ref}")
            return
        current: Any = document
        for raw_token in pointer[1:].split("/"):
            token = raw_token.replace("~1", "/").replace("~0", "~")
            if isinstance(current, dict) and token in current:
                current = current[token]
            elif isinstance(current, list) and token.isdigit() and int(token) < len(current):
                current = current[int(token)]
            else:
                fail(f"unresolved JSON Schema pointer in {origin}: {ref}")
                return

    def walk(value: Any, origin: str) -> None:
        if isinstance(value, dict):
            ref = value.get("$ref")
            if isinstance(ref, str) and not ref.startswith(("http://", "https://")):
                file_part, separator, fragment = ref.partition("#")
                target_relative = origin if not file_part else (Path(origin).parent / file_part).as_posix()
                target = by_relative.get(target_relative)
                if target is None:
                    fail(f"unresolved local JSON Schema file reference in {origin}: {ref}")
                elif separator:
                    resolve_pointer(target, fragment, origin, ref)
            for child in value.values():
                walk(child, origin)
        elif isinstance(value, list):
            for child in value:
                walk(child, origin)

    for relative, schema in by_relative.items():
        walk(schema, relative)


def canonical_mirror_policy() -> None:
    pairs = {
        "DEPENDENCY_CONSTITUTION.md": "docs/DEPENDENCY_CONSTITUTION.md",
        "GRAPH_ANALYTICS_AND_SENSOR_MESH.md": "docs/GRAPH_ANALYTICS_AND_SENSOR_MESH.md",
        "ATP_AND_DISTRIBUTED_EVIDENCE.md": "docs/ATP_AND_DISTRIBUTED_EVIDENCE.md",
        "PURE_RUST_MODEL_RUNTIME.md": "docs/PURE_RUST_MODEL_RUNTIME.md",
        "LOCAL_QUALIFICATION_AND_RELEASE.md": "docs/LOCAL_QUALIFICATION_AND_RELEASE.md",
        "AGENT_COGNITION_AND_CONTROL.md": "docs/AGENT_COGNITION_AND_CONTROL.md",
        "AGENT_COGNITIVE_CONTROL_PLANE.md": "docs/AGENT_COGNITIVE_CONTROL_PLANE.md",
        "AGENT_OPERATING_MODEL.md": "docs/AGENT_OPERATING_MODEL.md",
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
        "AGENT_COGNITION_AND_CONTROL.md",
        "AGENT_COGNITIVE_CONTROL_PLANE.md",
        "AGENT_OPERATING_MODEL.md",
        "docs/AGENT_COGNITION_AND_CONTROL.md",
        "docs/AGENT_COGNITIVE_CONTROL_PLANE.md",
        "docs/AGENT_OPERATING_MODEL.md",
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
        "docs/adr/ADR-0011-agent-cognitive-operating-membrane.md",
        "docs/FRANKEN_IMPORT_ADMISSION_GATES.md",
        "docs/deep-dives/INDEX.md",
        "architecture/dependency_allowlist.toml",
        "architecture/dependency_constitution.json",
        "architecture/franken_imports.json",
        "architecture/model_runtime_registry.json",
        "architecture/agent_contracts.json",
        "architecture/agent_abstraction_stack.json",
        "architecture/agent_operating_model.json",
        "architecture/agent_operations.json",
        "architecture/agent_views.json",
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
        "registries/AGENT_CONTRACTS.md",
        "registries/AGENT_ABSTRACTIONS.md",
        "registries/AGENT_OPERATIONS.md",
        "registries/AGENT_VIEWS.md",
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
        "AGENT_COGNITION_AND_CONTROL.md",
        "AGENT_COGNITIVE_CONTROL_PLANE.md",
        "AGENT_OPERATING_MODEL.md",
        "docs/AGENT_COGNITION_AND_CONTROL.md",
        "docs/AGENT_COGNITIVE_CONTROL_PLANE.md",
        "docs/AGENT_OPERATING_MODEL.md",
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
        "architecture/agent_contracts.json",
        "architecture/agent_abstraction_stack.json",
        "architecture/agent_operating_model.json",
        "architecture/agent_operations.json",
        "architecture/agent_views.json",
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
        "registries/AGENT_CONTRACTS.md",
        "registries/AGENT_ABSTRACTIONS.md",
        "registries/AGENT_OPERATIONS.md",
        "registries/AGENT_VIEWS.md",
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

    agent_contracts = load_json("architecture/agent_contracts.json")
    if agent_contracts.get("semanticProtocol") != "fss/1":
        fail("agent contract umbrella must freeze semantic protocol fss/1")
    if agent_contracts.get("primaryReadSurface") != "SituationCapsule":
        fail("agent contract umbrella must name SituationCapsule as primary read surface")
    if agent_contracts.get("gate") != "GATE-115" or agent_contracts.get("qualificationLane") != "QL-AGENT-001":
        fail("agent contract umbrella must bind GATE-115 and QL-AGENT-001")
    canonical_response_composition = {
        "primaryDriverPublication": "SituationCapsule",
        "innerWorldProjection": "SituationFrame",
        "worldModel": "WorldEnvelope",
        "controlProjection": "SituationCapsule.controlEnvelope",
    }
    contract_response = agent_contracts.get("responseComposition", {})
    for key, expected in canonical_response_composition.items():
        if contract_response.get(key) != expected:
            fail(f"agent contract response composition mismatch for {key}: {contract_response.get(key)!r}")
    world_doctrine = agent_contracts.get("worldEnvelopeDoctrine", {})
    for field in ("evidenceEnvelope", "possibilityEnvelope", "controlEnvelope", "monotonicity", "decisionRule"):
        if not isinstance(world_doctrine.get(field), str) or not world_doctrine[field]:
            fail(f"agent WorldEnvelope doctrine lacks {field}")
    facet_contract = agent_contracts.get("subsystemProjectionContract", {})
    if facet_contract.get("name") != "CognitiveFacet" or facet_contract.get("owner") != "fss-agent-core":
        fail("agent subsystem projection contract must be the fss-agent-core-owned CognitiveFacet")
    expected_facet_coordinates = {
        "facet_identity", "semantic_owner", "basis_anchor_and_high_water", "scope_and_validity",
        "knowledge_cells", "coverage_and_health", "contradictions_and_unknowns", "evidence_handles",
        "open_obligations_and_indeterminate_effects", "resource_state_and_cost", "affordance_seeds",
        "invalidators_and_degradation", "proof_and_continuation",
    }
    if set(facet_contract.get("requiredCoordinates", [])) != expected_facet_coordinates:
        fail("CognitiveFacet required coordinates disagree with the semantic narrow waist")
    for field in ("compositionRule", "forbidden"):
        if not isinstance(facet_contract.get(field), str) or not facet_contract[field]:
            fail(f"CognitiveFacet contract lacks {field}")

    knowledge_states = unique_rows(agent_contracts.get("knowledgeStates"), "id", "architecture/agent_contracts.json")
    provenance_classes = unique_rows(agent_contracts.get("provenanceClasses"), "id", "architecture/agent_contracts.json")
    expected_knowledge_names = [
        "known", "estimated", "unknown", "conflicted", "stale",
        "not_observable", "redacted", "indeterminate", "not_applicable",
    ]
    if [row.get("name") for row in knowledge_states.values()] != expected_knowledge_names:
        fail("agent knowledge-state registry order/names disagree with the canonical nine-state universe")
    expected_provenance_names = [
        "observed", "derived", "predicted", "remembered",
        "operator_asserted", "vendor_claimed", "policy",
    ]
    if [row.get("name") for row in provenance_classes.values()] != expected_provenance_names:
        fail("agent provenance registry order/names disagree with the canonical seven-class universe")
    contract_md = (ROOT / "registries/AGENT_CONTRACTS.md").read_text(encoding="utf-8")
    for identifier, row in {**knowledge_states, **provenance_classes}.items():
        if f"`{identifier}`" not in contract_md or f"`{row.get('name')}`" not in contract_md:
            fail(f"agent contract Markdown lacks {identifier} / {row.get('name')}")

    capability_ids = set(re.findall(r"^\| `(CAP-[A-Z0-9-]+)` \|", (ROOT / "registries/CAPABILITIES.md").read_text(encoding="utf-8"), flags=re.MULTILINE))

    agent_doc = load_json("architecture/agent_abstraction_stack.json")
    agent_layers = unique_rows(agent_doc.get("layers"), "id", "architecture/agent_abstraction_stack.json")
    agent_layer_md = markdown_table_rows(
        "registries/AGENT_ABSTRACTIONS.md",
        r"^\| `((?:AGT-LAYER)-[A-Z0-9-]+)` \| `([^`]+)` \| `([^`]+)` \| .* \| `([^`]+)` \| `([^`]+)` \|$",
    )
    compare_ids(agent_layers, agent_layer_md, "agent abstraction layer")
    required_agent_layer_fields = {"name", "owner", "question", "output", "prohibition", "invariant", "status"}
    for identifier, row in agent_layers.items():
        missing = sorted(required_agent_layer_fields - row.keys())
        if missing:
            fail(f"agent abstraction layer {identifier} lacks fields: {', '.join(missing)}")
        if identifier in agent_layer_md:
            name, owner, invariant, status = agent_layer_md[identifier]
            if (row.get("name"), row.get("owner"), row.get("invariant"), row.get("status")) != (name, owner, invariant, status):
                fail(f"machine and Markdown agent layer row disagree: {identifier}")
    if agent_doc.get("constitutionalRole") != "orthogonal_control_membrane" or agent_doc.get("gate") != "GATE-115":
        fail("agent abstraction stack must declare the orthogonal control membrane and GATE-115")
    canonical_tower_lines = [
        "L10 Workspace and handoff",
        "L9  Learning and memory",
        "L8  Outcome and episode",
        "L7  Plan and effect",
        "L6  Affordance frontier",
        "L5  Investigation and hypotheses",
        "L4  Situation capsule",
        "L3  Derived beliefs",
        "L2  World facts and coverage",
        "L1  Source evidence",
        "L0  Runtime authority and custody",
    ]
    for relative in (
        "AGENT_COGNITION_AND_CONTROL.md",
        "AGENT_COGNITIVE_CONTROL_PLANE.md",
        "AGENT_OPERATING_MODEL.md",
    ):
        text = (ROOT / relative).read_text(encoding="utf-8")
        positions = [text.find(line) for line in canonical_tower_lines]
        if any(position < 0 for position in positions) or positions != sorted(positions):
            fail(f"{relative} does not render the one canonical agent abstraction tower")
    stack_response = agent_doc.get("responseComposition", {})
    for key, expected in canonical_response_composition.items():
        if stack_response.get(key) != expected:
            fail(f"agent abstraction response composition mismatch for {key}: {stack_response.get(key)!r}")
    if (
        "WorldEnvelope" not in set(agent_doc.get("semanticObjectSchemas", []))
        and "fss.agent_world_envelope.v1" not in set(agent_doc.get("semanticObjectSchemas", []))
    ):
        fail("agent abstraction stack must include the WorldEnvelope semantic schema")

    agent_operations = unique_rows(load_json("architecture/agent_operations.json").get("operations"), "id", "architecture/agent_operations.json")
    agent_operation_md = markdown_table_rows(
        "registries/AGENT_OPERATIONS.md",
        r"^\| `((?:AOP)-[A-Z0-9-]+)` \| `([^`]+)` \| `([^`]+)` \| `([^`]+)` \| `([^`]+)` \| `([^`]+)` \| (yes|no) \| (yes|no) \| `([^`]+)` \| `([^`]+)` \|$",
    )
    compare_ids(agent_operations, agent_operation_md, "agent operation")
    required_agent_operation_fields = {"name", "purpose", "mode", "owner", "defaultView", "effectful", "durable", "requiredCapabilities", "inputSchema", "requestPayloadSchema", "outputSchema", "responsePayloadSchemas", "retryClasses", "gate", "status"}
    for identifier, row in agent_operations.items():
        missing = sorted(required_agent_operation_fields - row.keys())
        if missing:
            fail(f"agent operation {identifier} lacks fields: {', '.join(missing)}")
        if identifier in agent_operation_md:
            name, owner, mode, view, request_payload, effectful, durable, gate, status = agent_operation_md[identifier]
            expected=(row.get("name"),row.get("owner"),row.get("mode"),row.get("defaultView"),row.get("requestPayloadSchema"),"yes" if row.get("effectful") else "no","yes" if row.get("durable") else "no",row.get("gate"),row.get("status"))
            if expected != (name, owner, mode, view, request_payload, effectful, durable, gate, status):
                fail(f"machine and Markdown agent operation row disagree: {identifier}")
    if set(agent_doc.get("operationRefs", [])) != set(agent_operations):
        fail("agent abstraction operationRefs and agent operation registry disagree")
    if set(agent_contracts.get("publicOperationIds", [])) != set(agent_operations):
        fail("agent contract publicOperationIds and operation registry disagree")
    for identifier, row in agent_operations.items():
        if row.get("defaultView") not in {view.get("id") for view in load_json("architecture/agent_views.json").get("views", []) if isinstance(view, dict)}:
            fail(f"agent operation {identifier} references unknown default view: {row.get('defaultView')}")
        for capability in row.get("requiredCapabilities", []):
            if capability not in capability_ids:
                fail(f"agent operation {identifier} references unregistered capability: {capability}")

    agent_views = unique_rows(load_json("architecture/agent_views.json").get("views"), "id", "architecture/agent_views.json")
    agent_view_md = markdown_table_rows(
        "registries/AGENT_VIEWS.md",
        r"^\| `((?:AVIEW)-[A-Z0-9-]+)` \| `([^`]+)` \| `([^`]+)` \| .* \| ([0-9]+) \| ([0-9]+) \| `([^`]+)` \| `([^`]+)` \|$",
    )
    compare_ids(agent_views, agent_view_md, "agent view")
    required_agent_view_fields = {"name", "purpose", "targetTokens", "maximumTokens", "requiredSections", "owner", "gate", "status"}
    for identifier, row in agent_views.items():
        missing = sorted(required_agent_view_fields - row.keys())
        if missing:
            fail(f"agent view {identifier} lacks fields: {', '.join(missing)}")
        if identifier in agent_view_md:
            name, owner, target, maximum, gate, status = agent_view_md[identifier]
            if (row.get("name"),row.get("owner"),str(row.get("targetTokens")),str(row.get("maximumTokens")),row.get("gate"),row.get("status")) != (name,owner,target,maximum,gate,status):
                fail(f"machine and Markdown agent view row disagree: {identifier}")

    brief_view = agent_views.get("AVIEW-002", {})
    if brief_view.get("targetTokens") != 800 or brief_view.get("maximumTokens") != 1600:
        fail("AVIEW-002 brief must target 800 tokens with a 1,600-token hard maximum")

    if set(agent_contracts.get("publicViewIds", [])) != set(agent_views):
        fail("agent contract publicViewIds and view registry disagree")
    if set(agent_doc.get("viewRefs", [])) != set(agent_views):
        fail("agent abstraction viewRefs and view registry disagree")

    agent_operating_model = load_json("architecture/agent_operating_model.json")
    if agent_operating_model.get("primaryReadSurface") != "situation_capsule":
        fail("agent operating model must name situation_capsule as primary driver publication")
    response_composition = agent_operating_model.get("responseComposition", {})
    for key, expected in canonical_response_composition.items():
        if response_composition.get(key) != expected:
            fail(f"agent operating-model response composition mismatch for {key}: {response_composition.get(key)!r}")
    if response_composition.get("boundedMaterialization") != "ContextPack + SemanticCompressionReceipt":
        fail("agent operating model must name ContextPack + SemanticCompressionReceipt as bounded materialization")
    if response_composition.get("semanticPayload") != "AgentCognitiveEnvelope":
        fail("agent operating model must name AgentCognitiveEnvelope as the semantic payload")
    if response_composition.get("transportEnvelope") != "AgentResponseEnvelope":
        fail("agent operating model must name AgentResponseEnvelope as the transport envelope")
    if agent_operating_model.get("qualificationLane") != "QL-AGENT-001":
        fail("agent operating model must use QL-AGENT-001")
    if agent_operating_model.get("semanticProtocol") != "fss/1":
        fail("agent operating model must use semantic protocol fss/1")
    if set(agent_operating_model.get("knowledgeStateRefs", [])) != set(knowledge_states):
        fail("agent operating model knowledge-state references disagree with umbrella")
    if set(agent_operating_model.get("provenanceClassRefs", [])) != set(provenance_classes):
        fail("agent operating model provenance references disagree with umbrella")

    decisions = unique_rows(load_json("architecture/decision_cards.json").get("decisionFamily"), "id", "architecture/decision_cards.json")
    for identifier, row in decisions.items():
        for field in ("purpose", "hardClamp", "safeFallback", "promotion", "status"):
            if not isinstance(row.get(field), str) or not row[field]:
                fail(f"decision family {identifier} lacks {field}")
    if "DEC-AGENT-ROBUST-001" not in decisions:
        fail("agent robust-control WorldEnvelope decision card is missing")
    decision_doc_text = (ROOT / "docs/DECISION_CARDS_AND_EXPERIMENTS.md").read_text(encoding="utf-8")
    for identifier in sorted(identifier for identifier in decisions if identifier.startswith("DEC-AGENT-")):
        if f"`{identifier}`" not in decision_doc_text:
            fail(f"agent decision-card documentation lacks {identifier}")
    tests_text = (ROOT / "registries/TESTS.md").read_text(encoding="utf-8")
    slos_text = (ROOT / "registries/SLOS.md").read_text(encoding="utf-8")
    if "TEST-AGENT-WORLD-ENVELOPE-001" not in tests_text:
        fail("agent WorldEnvelope qualification family is missing")
    if "SLO-AGENT-ROBUSTNESS-001" not in slos_text:
        fail("agent WorldEnvelope robustness SLO is missing")

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

    registered_schema_names = {schema_name for _, schema_name, _ in schema_rows}
    for identifier, row in agent_operations.items():
        if row.get("inputSchema") != "fss.agent_request_envelope.v1":
            fail(f"agent operation {identifier} must use the universal request envelope")
        if row.get("outputSchema") != "fss.agent_response_envelope.v1":
            fail(f"agent operation {identifier} must use the universal response envelope")
        if row.get("inputSchema") not in registered_schema_names:
            fail(f"agent operation {identifier} input schema is not registered: {row.get('inputSchema')}")
        if row.get("outputSchema") not in registered_schema_names:
            fail(f"agent operation {identifier} output schema is not registered: {row.get('outputSchema')}")
        if row.get("requestPayloadSchema") not in registered_schema_names:
            fail(f"agent operation {identifier} request payload schema is not registered: {row.get('requestPayloadSchema')}")
        response_payloads = row.get("responsePayloadSchemas")
        if not isinstance(response_payloads, list) or not response_payloads:
            fail(f"agent operation {identifier} must declare at least one response payload schema")
        else:
            for schema_name in response_payloads:
                if schema_name not in registered_schema_names:
                    fail(f"agent operation {identifier} response payload schema is not registered: {schema_name}")
    for object_name, schema_name in agent_contracts.get("semanticObjects", {}).items():
        if schema_name not in registered_schema_names:
            fail(f"agent semantic object {object_name} references unregistered schema: {schema_name}")

    expected_envelope_objects = {
        "ContractBasis": "fss.agent_contract_basis.v1",
        "AgentRequestEnvelope": "fss.agent_request_envelope.v1",
        "AgentResponseEnvelope": "fss.agent_response_envelope.v1",
        "AgentCognitiveEnvelope": "fss.agent_cognitive_envelope.v1",
        "AgentSessionCapsule": "fss.agent_session_capsule.v1",
        "WorldEnvelope": "fss.agent_world_envelope.v1",
    }
    for object_name, schema_name in expected_envelope_objects.items():
        if agent_contracts.get("semanticObjects", {}).get(object_name) != schema_name:
            fail(f"agent semantic object {object_name} must map to {schema_name}")
    for legacy_name in ("RequestEnvelope", "ResponseEnvelope", "CognitiveEnvelope", "AgentWorkspaceRevision"):
        if legacy_name in agent_contracts.get("semanticObjects", {}):
            fail(f"agent semantic object registry still contains legacy alias: {legacy_name}")

    contract_basis_schema = load_json("schemas/agent_contract_basis.v1.json")
    required_contract_basis = {
        "semanticProtocol", "schemaCatalogDigest", "ontologyGenerationId",
        "operationRegistryDigest", "viewRegistryDigest", "capabilityRegistryDigest",
        "errorRegistryDigest", "costRegistryDigest", "producerReleaseId",
    }
    if not required_contract_basis.issubset(set(contract_basis_schema.get("required", []))):
        fail("ContractBasis lacks one or more canonical registry/release identities")
    if contract_basis_schema.get("properties", {}).get("semanticProtocol", {}).get("const") != "fss/1":
        fail("ContractBasis must freeze semantic protocol fss/1")

    request_schema = load_json("schemas/agent_request_envelope.v1.json")
    response_schema = load_json("schemas/agent_response_envelope.v1.json")
    universal_request_fields = {
        "contractBasis", "operationId", "requestId", "principalId", "sessionId",
        "missionId", "inputAnchor", "expectedWorkspaceRevision", "viewId", "targetUris",
        "payloadSchema", "payload", "budget", "deadlineNs", "requestedCapabilities",
        "requestedPrivacyProjection", "idempotencyKey", "continuation",
        "expectedDecisionFingerprint", "maxHydrationLevel", "acceptCompression", "taint",
    }
    if not universal_request_fields.issubset(set(request_schema.get("required", []))):
        fail("AgentRequestEnvelope lacks canonical identity/basis/budget/authority/payload fields")
    if request_schema.get("properties", {}).get("contractBasis", {}).get("$ref") != "agent_contract_basis.v1.json":
        fail("AgentRequestEnvelope must reuse ContractBasis")
    universal_response_fields = {
        "contractBasis", "operationId", "requestId", "responseRevision", "principalId",
        "sessionId", "missionId", "inputAnchor", "outputAnchor", "workspaceRevision",
        "effectiveViewId", "effectiveCapabilities", "effectivePrivacyProjection", "outcome",
        "taskState", "errorId", "payloadSchema", "payload", "payloadDigest",
        "epistemicState", "completeness", "budgets", "proofPointers", "affordances",
        "decisionFingerprint", "continuation", "recoveryClass", "safeRetry",
        "resnapshotRequired", "executionBoundary",
    }
    if not universal_response_fields.issubset(set(response_schema.get("required", []))):
        fail("AgentResponseEnvelope lacks canonical basis/lifecycle/effect/recovery/payload fields")
    if response_schema.get("properties", {}).get("contractBasis", {}).get("$ref") != "agent_contract_basis.v1.json":
        fail("AgentResponseEnvelope must reuse ContractBasis")

    canonical_knowledge_names = [row.get("name") for row in knowledge_states.values()]
    cognitive_schema = load_json("schemas/agent_cognitive_envelope.v1.json")
    proposition_states = cognitive_schema.get("properties", {}).get("epistemic", {}).get("properties", {}).get("propositions", {}).get("items", {}).get("properties", {}).get("state", {}).get("enum")
    if proposition_states != canonical_knowledge_names:
        fail("agent cognitive-envelope proposition states disagree with knowledge-state registry")
    next_action_ref = cognitive_schema.get("properties", {}).get("nextActions", {}).get("items", {}).get("$ref")
    if next_action_ref != "agent_affordance.v1.json":
        fail("agent cognitive envelope must reuse the registered AgentAffordance schema")
    for field in ("operationId", "viewId"):
        if field not in cognitive_schema.get("required", []):
            fail(f"agent cognitive envelope must require {field}")

    situation_schema = load_json("schemas/situation_capsule.v1.json")
    required_situation_fields = {
        "situationFrame", "obligations", "resourceState", "affordances",
        "contextPack", "compressionReceipt", "validity", "decisionFingerprint",
    }
    missing_situation_fields = sorted(required_situation_fields - set(situation_schema.get("required", [])))
    if missing_situation_fields:
        fail("SituationCapsule lacks required linked objects: " + ", ".join(missing_situation_fields))

    world_envelope_schema = load_json("schemas/agent_world_envelope.v1.json")
    required_world_fields = {
        "nominalClaimIds", "certifiedCoreClaimIds", "certifiedAbsences",
        "materialAlternativeWorlds", "adversarialResiduals", "commonInvariants",
        "unresolvedDimensions", "collapseAffordanceIds", "coverageBoundaryHandles",
        "selectionWitness", "digest",
    }
    missing_world_fields = sorted(required_world_fields - set(world_envelope_schema.get("required", [])))
    if missing_world_fields:
        fail("WorldEnvelope lacks required evidence/possibility fields: " + ", ".join(missing_world_fields))
    situation_frame_schema = load_json("schemas/agent_situation_frame.v1.json")
    if "worldEnvelope" not in situation_frame_schema.get("required", []):
        fail("SituationFrame must require WorldEnvelope")
    if situation_frame_schema.get("properties", {}).get("worldEnvelope", {}).get("$ref") != "agent_world_envelope.v1.json":
        fail("SituationFrame worldEnvelope must reuse the registered WorldEnvelope schema")
    if "controlEnvelope" not in situation_schema.get("required", []):
        fail("SituationCapsule must require the categorized control envelope")
    required_situation_refs = {
        "situationFrame": "agent_situation_frame.v1.json",
        "contextPack": "semantic_context_pack.v1.json",
        "compressionReceipt": "semantic_compression_receipt.v1.json",
    }
    for field, expected_ref in required_situation_refs.items():
        if situation_schema.get("properties", {}).get(field, {}).get("$ref") != expected_ref:
            fail(f"SituationCapsule {field} must reuse {expected_ref}")
    control_schema = situation_schema.get("properties", {}).get("controlEnvelope", {})
    required_control_fields = {
        "robustAffordanceIds", "conditionalAffordanceIds",
        "informationGatheringAffordanceIds", "waitAffordanceIds",
        "blockedAffordanceIds", "robustInvariants", "branchConditions", "envelopeDigest",
    }
    if not required_control_fields.issubset(set(control_schema.get("required", []))):
        fail("SituationCapsule controlEnvelope lacks canonical control classifications")

    affordance_schema = load_json("schemas/agent_affordance.v1.json")
    required_affordance_robustness = {"worldEnvelopeId", "robustnessClass", "compatibleWorldIds", "unsafeWorldIds"}
    if not required_affordance_robustness.issubset(set(affordance_schema.get("required", []))):
        fail("AgentAffordance must bind its WorldEnvelope and robustness/unsafe-world classification")
    control_plan_schema = load_json("schemas/agent_control_plan.v1.json")
    if "worldEnvelopeDigest" not in control_plan_schema.get("required", []):
        fail("ControlPlan must bind an exact WorldEnvelope digest")
    plan_step = control_plan_schema.get("properties", {}).get("steps", {}).get("items", {})
    if not {"robustnessClass", "supportedWorldIds", "unsafeWorldIds"}.issubset(set(plan_step.get("required", []))):
        fail("ControlPlan steps must declare belief-space robustness and unsafe worlds")

    known_irreversible = [row.get("name") for row in knowledge_states.values() if row.get("mayAuthorizeIrreversibleEffect") is True]
    if known_irreversible != ["known"]:
        fail("only known propositions may authorize an irreversible effect premise")
    for identifier, row in knowledge_states.items():
        for field in ("maySupportPlanning", "mayAuthorizeIrreversibleEffect", "requiresExplicitAssumptions"):
            if not isinstance(row.get(field), bool):
                fail(f"knowledge state {identifier} lacks boolean {field}")

    validate_local_json_schema_refs(actual_schema_files)

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
        r"\b(?:INV|GOAL|NONGOAL|CAP|EFFECT|ERR|SCHEMA|ADR|WP|GATE|TEST|SLO|RISK|OPEN|INT|COST|SEC|PRIV|FORMAL|NEG|FSS|LAB|ADP|MOD|ALG|PUB|DEC|DEP|REL|FMT|TRACE|ATP|IMP|QL|MODEL|XFER|GRAPH|AGT|AOP|AVIEW|KSTATE|PROV)(?:-[A-Z0-9]+)*-[0-9]{3}\b"
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
        f"{len(publications)} publication primitives, {len(agent_layers)} agent layers, "
        f"{len(agent_operations)} agent operations, {len(agent_views)} agent views, {len(lanes)} local lanes, "
        f"{manifest_entries} manifest entries"
    )
    for note in notes:
        print(f"note: {note}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
