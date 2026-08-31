#!/usr/bin/env python3
from __future__ import annotations

import hashlib
import json
import re
import sys
import tomllib
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
EXCLUDED_TOP_LEVEL = {
    ".git",
    "target",
    "secrets",
    "credentials",
    "captures",
    "archive-spool",
    "model-cache",
}
EXCLUDED_PREFIXES = {
    Path("device-fixtures/private"),
    Path("qualification-artifacts/local"),
}
errors: list[str] = []


def included(path: Path) -> bool:
    relative = path.relative_to(ROOT)
    if relative.parts and relative.parts[0] in EXCLUDED_TOP_LEVEL:
        return False
    return not any(relative == prefix or prefix in relative.parents for prefix in EXCLUDED_PREFIXES)


def source_files(suffix: str | None = None) -> list[Path]:
    files = [path for path in ROOT.rglob("*") if path.is_file() and included(path)]
    if suffix is not None:
        files = [path for path in files if path.suffix == suffix]
    return sorted(files)


json_files = source_files(".json")
for path in json_files:
    try:
        json.loads(path.read_text(encoding="utf-8"))
    except Exception as exc:
        errors.append(f"invalid JSON {path.relative_to(ROOT)}: {exc}")

toml_files = source_files(".toml")
for path in toml_files:
    try:
        tomllib.loads(path.read_text(encoding="utf-8"))
    except Exception as exc:
        errors.append(f"invalid TOML {path.relative_to(ROOT)}: {exc}")

stable_ids: set[str] = set()
pattern = re.compile(
    r"\b(?:INV|GOAL|NONGOAL|CAP|EFFECT|ERR|SCHEMA|ADR|WP|GATE|TEST|SLO|RISK|OPEN|"
    r"INT|COST|SEC|PRIV|FORMAL|NEG|FSS)-[A-Z0-9-]+\b"
)
for path in source_files(".md"):
    stable_ids.update(pattern.findall(path.read_text(encoding="utf-8")))

required = [
    "README.md",
    "COMPREHENSIVE_PLAN_FOR_FRANKEN_SURVEILLANCE_SYSTEM.md",
    "FRANKENSTACK_DEEP_DIVE.md",
    "IMPLEMENTATION_STATUS.md",
    "SECURITY.md",
    "PRIVACY.md",
    "MANIFEST.sha256",
    "architecture/invariants.json",
    "architecture/readiness_dimensions.json",
    "schemas/sensor_capsule.v1.json",
    "schemas/event_hypothesis.v1.json",
]
for rel in required:
    if not (ROOT / rel).is_file():
        errors.append(f"missing required file: {rel}")

for path in source_files(".rs"):
    text = path.read_text(encoding="utf-8")
    if "#![forbid(unsafe_code)]" not in text:
        errors.append(f"missing unsafe prohibition: {path.relative_to(ROOT)}")
    if re.search(r"\bunsafe\s*\{", text):
        errors.append(f"unsafe block in core workspace: {path.relative_to(ROOT)}")

try:
    repository_manifest = json.loads(
        (ROOT / "architecture/repository_manifest.json").read_text(encoding="utf-8")
    )
except Exception as exc:
    repository_manifest = None
    errors.append(f"cannot inspect repository manifest: {exc}")
if repository_manifest is not None:
    for rel in repository_manifest.get("normative", []):
        if not (ROOT / rel).is_file():
            errors.append(f"normative manifest target missing: {rel}")

try:
    invariant_document = json.loads((ROOT / "architecture/invariants.json").read_text(encoding="utf-8"))
    machine_invariants = {row["id"]: row["text"] for row in invariant_document["invariants"]}
    registry_invariants = {
        stable_id: text
        for stable_id, text in re.findall(
            r"^\| `((?:INV)-[A-Z0-9-]+)` \| (.*?) \| `[^`]+` \|$",
            (ROOT / "registries/INVARIANTS.md").read_text(encoding="utf-8"),
            flags=re.MULTILINE,
        )
    }
    if machine_invariants != registry_invariants:
        errors.append("machine and Markdown invariant registries disagree")
except Exception as exc:
    errors.append(f"cannot compare invariant registries: {exc}")

try:
    cost_document = tomllib.loads(
        (ROOT / "architecture/operation_cost_registry.toml").read_text(encoding="utf-8")
    )
    machine_cost_ids = {row["id"] for row in cost_document["operation"]}
    markdown_cost_ids = set(
        re.findall(
            r"^\| `((?:COST)-[A-Z0-9-]+)` \|",
            (ROOT / "registries/OPERATION_COSTS.md").read_text(encoding="utf-8"),
            flags=re.MULTILINE,
        )
    )
    if machine_cost_ids != markdown_cost_ids:
        errors.append("machine and Markdown operation-cost registries disagree")
except Exception as exc:
    errors.append(f"cannot compare operation-cost registries: {exc}")

try:
    schema_registry_text = (ROOT / "registries/SCHEMAS.md").read_text(encoding="utf-8")
    schema_rows = re.findall(
        r"^\| `((?:SCHEMA)-[A-Z0-9-]+)` \| `([^`]+)` \| `([^`]+)` \|",
        schema_registry_text,
        flags=re.MULTILINE,
    )
    for stable_id, schema_name, rel in schema_rows:
        if not rel.startswith("schemas/"):
            continue
        schema_path = ROOT / rel
        if not schema_path.is_file():
            errors.append(f"{stable_id} references missing schema: {rel}")
            continue
        schema = json.loads(schema_path.read_text(encoding="utf-8"))
        if schema.get("$schema") != "https://json-schema.org/draft/2020-12/schema":
            errors.append(f"{stable_id} does not declare JSON Schema Draft 2020-12")
        if schema.get("properties", {}).get("schema", {}).get("const") != schema_name:
            errors.append(f"{stable_id} registry name disagrees with schema const")
        if not str(schema.get("$id", "")).endswith("/" + Path(rel).name):
            errors.append(f"{stable_id} has a nonmatching $id")
except Exception as exc:
    errors.append(f"cannot validate schema registry: {exc}")

for rel in [
    "architecture/readiness_dimensions.json",
    "architecture/claims.json",
    "architecture/franken_imports.json",
]:
    try:
        document = json.loads((ROOT / rel).read_text(encoding="utf-8"))
        collections = [value for value in document.values() if isinstance(value, list)]
        for collection in collections:
            identifiers = [row.get("id") or row.get("gate") for row in collection if isinstance(row, dict)]
            identifiers = [identifier for identifier in identifiers if identifier is not None]
            if len(identifiers) != len(set(identifiers)):
                errors.append(f"duplicate machine-readable identifier in {rel}")
    except Exception as exc:
        errors.append(f"cannot inspect {rel}: {exc}")

manifest_path = ROOT / "MANIFEST.sha256"
manifest_entries: dict[str, str] = {}
if manifest_path.is_file():
    line_pattern = re.compile(r"([0-9a-f]{64})  ([^\r\n]+)")
    for line_number, line in enumerate(manifest_path.read_text(encoding="utf-8").splitlines(), 1):
        match = line_pattern.fullmatch(line)
        if match is None:
            errors.append(f"malformed MANIFEST.sha256 line {line_number}")
            continue
        expected_digest, rel = match.groups()
        relative = Path(rel)
        if relative.is_absolute() or ".." in relative.parts:
            errors.append(f"unsafe manifest path: {rel}")
            continue
        if rel in manifest_entries:
            errors.append(f"duplicate manifest path: {rel}")
            continue
        manifest_entries[rel] = expected_digest
        path = ROOT / relative
        if not path.is_file():
            errors.append(f"manifest target missing: {rel}")
            continue
        actual_digest = hashlib.sha256(path.read_bytes()).hexdigest()
        if actual_digest != expected_digest:
            errors.append(f"manifest digest mismatch: {rel}")
    expected_paths = {
        path.relative_to(ROOT).as_posix()
        for path in source_files()
        if path != manifest_path
    }
    listed_paths = set(manifest_entries)
    for rel in sorted(expected_paths - listed_paths):
        errors.append(f"source file missing from manifest: {rel}")
    for rel in sorted(listed_paths - expected_paths):
        errors.append(f"manifest lists excluded or unknown file: {rel}")

if errors:
    print("policy check failed", file=sys.stderr)
    for error in errors:
        print(f"- {error}", file=sys.stderr)
    raise SystemExit(1)

print(
    "policy check passed: "
    f"{len(json_files)} JSON files, {len(toml_files)} TOML files, "
    f"{len(stable_ids)} stable IDs, {len(manifest_entries)} manifest entries"
)
