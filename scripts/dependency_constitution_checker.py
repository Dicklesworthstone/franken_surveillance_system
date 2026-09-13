#!/usr/bin/env python3
"""Fail-closed dependency constitution and DEP-CLASS-F0 checker (fss-x4a.30.88.16).

``architecture/dependency_constitution.json`` is the machine class registry (DEP-CLASS-F0..F4) under the
single authority DEPENDENCY_CONSTITUTION.md + ``architecture/dependency_allowlist.toml``. The shared
loader ``scripts/dependency_authority.py`` reads, pins and cross-checks every authority input, including the
dependency registry rows of ``architecture/dependencies.json`` against their DEP-CLASS (no policy table
lives in this checker). On top of that this checker verifies:

1. the constitution Markdown mirror (``docs/DEPENDENCY_CONSTITUTION.md``): a strictly parsed machine
   mirror table compared value-by-value (typed) with the JSON, and exactly one machine-row binding per
   ``### 2.N Class Fk`` section compared field-by-field with the JSON row; duplicate, missing, renamed,
   hollow or rogue sections are drift (``ERR-DEP-CONST-DRIFT-001``), and so is any byte difference
   between that docs copy and the canonical root ``DEPENDENCY_CONSTITUTION.md``;
2. DEP-CLASS-F0 toolchain identity, single-sourced in ``architecture/local_qualification.toml``
   ``[toolchain]`` (accepted channel, rustc release, commit hash and date, components, and the accepted
   host triples with their platform scopes): ``rust-toolchain.toml`` (exact keys; that channel; minimal
   profile; those components; no unregistered targets; no legacy ``rust-toolchain`` override) and a
   parsed ``rustc -Vv`` (that release, commit identity and date; a host triple of that table whose scope
   is a native_release scope of ``architecture/release_qualification.json``). No identity lives in code;
3. the DEP-CLASS-F0 closure census over real ``cargo metadata --locked --offline --all-features``: members by
   package id (each declared in ``architecture/crate_topology.json`` and an explicit root
   ``[workspace].members`` entry, so implicit path members are refused), production reachability over the
   resolve graph (normal and build edges), member edition
   derived from the constitution language, native links, custom-build, proc-macro and dynamic/C-ABI crate
   types, and the shared classifier for every non-member package (pending owner decisions stay neutral);
4. unstable features anywhere in the repository: no unstable-feature registry exists, so ``#![feature]``
   (also inside ``cfg_attr``), ``-Z`` rustflags in ``.cargo/config*`` or RUSTFLAGS-style variables of
   checked-in env/shell files, cargo ``[unstable]`` tables, ``cargo-features`` and ``-Z`` literals in build
   scripts are findings. ``Cargo.lock`` is read through the bounded, symlink-refusing reader before cargo
   runs.

Tool execution failures (cannot run, timeout, non-zero exit, unparseable output) are
``ERR-DEP-EXEC-FAILED-001``, never CORRUPT-FILE. Nothing raises for malformed input.
"""
from __future__ import annotations

import argparse
import datetime as _dt
import fnmatch
import json
import os
import re
import subprocess
import sys
from pathlib import Path
from typing import Any

sys.path.insert(0, str(Path(__file__).resolve().parent))

import dependency_authority as authority  # noqa: E402
from dependency_authority import (  # noqa: E402,F401  (re-exported for callers and tests)
    ALLOWLIST_TOML_PATH,
    BASELINE_CONSTITUTION_FREEZE_DIGEST as BASELINE_DEPENDENCY_CONSTITUTION_FREEZE_DIGEST,
    BASELINE_CONSTITUTION_GENERATION as BASELINE_DEPENDENCY_CONSTITUTION_GENERATION,
    CONSTITUTION_JSON_PATH,
    DEPENDENCIES_JSON_PATH,
    ERR_DEP_ALLOWLIST_DIGEST_DIVERGED,
    ERR_DEP_CONST_INVARIANT,
    ERR_DEP_CORRUPT_FILE,
    ERR_DEP_DIGEST_MISMATCH,
    ERR_DEP_FREEZE_DIVERGENCE,
    ERR_DEP_GENERATION_MISMATCH,
    ERR_DEP_MISSING_FIELD,
    ERR_DEP_PENDING_DECISION,
    ERR_DEP_REGISTRY_DRIFT,
    ERR_DEP_STABLE_ID_REUSED,
    ERR_DEP_TOMBSTONE_INVALID,
    ERR_DEP_TRACE_UNRESOLVED,
    LOCAL_QUALIFICATION_PATH,
    STABLE_ID_RESOLUTION_PATH,
    DiagnosticError,
    ValidationResult,
    canonicalize_value,
    compute_canonical_constitution_digest,
    issue,
    pairs_hook_reject_duplicates,
)

ROOT = Path(__file__).resolve().parents[1]

ERR_DEP_CONST_DRIFT = "ERR-DEP-CONST-DRIFT-001"
ERR_DEP_CONST_METADATA_VIOLATION = "ERR-DEP-CONST-METADATA-VIOLATION-001"
ERR_DEP_EXEC_FAILED = "ERR-DEP-EXEC-FAILED-001"
ERR_DEP_UNSTABLE_FEATURE = "ERR-DEP-UNSTABLE-FEATURE-001"

CONSTITUTION_CHECKER_ERROR_CODES: tuple[str, ...] = authority.AUTHORITY_ERROR_CODES + (
    ERR_DEP_CONST_DRIFT,
    ERR_DEP_CONST_METADATA_VIOLATION,
    ERR_DEP_EXEC_FAILED,
    ERR_DEP_UNSTABLE_FEATURE,
)

CONSTITUTION_MD_PATH = "docs/DEPENDENCY_CONSTITUTION.md"
RUST_TOOLCHAIN_PATH = "rust-toolchain.toml"
LEGACY_RUST_TOOLCHAIN_PATH = "rust-toolchain"
RELEASE_QUALIFICATION_PATH = "architecture/release_qualification.json"

# Operational bound on each rustup/cargo invocation (a hung toolchain must not stall the policy lane).
TOOLCHAIN_COMMAND_TIMEOUT_SECONDS: int = 30
CARGO_METADATA_TIMEOUT_SECONDS: int = TOOLCHAIN_COMMAND_TIMEOUT_SECONDS

# The accepted toolchain identity (channel, rustc release, commit hash, commit date, accepted host
# triples and their platform scopes) is single-sourced in architecture/local_qualification.toml
# [toolchain]; this checker holds none of it. A toolchain bump edits that table and rust-toolchain.toml.
TOOLCHAIN_CONTRACT_KEYS: dict[str, Any] = {
    "channel": authority.Str(),
    "rustc_release": authority.Str(),
    "rustc_commit_hash": authority.Str(),
    "rustc_commit_date": authority.Str(),
    "components": authority.List(authority.Str()),
    "host_triples": authority.Map(authority.Str()),
}
NIGHTLY_CHANNEL_RE = re.compile(r"nightly-(\d{4}-\d{2}-\d{2})")
CRATE_TOPOLOGY_PATH = "architecture/crate_topology.json"
CONSTITUTION_ROOT_COPY_PATH = "DEPENDENCY_CONSTITUTION.md"


def accepted_channel(root: Path) -> str | None:
    """The accepted nightly channel registered in local_qualification.toml (None when unreadable)."""
    data, _raw, _problems = authority.load_toml_document(root / LOCAL_QUALIFICATION_PATH, LOCAL_QUALIFICATION_PATH, root)
    channel = authority.as_dict(authority.as_dict(data).get("toolchain")).get("channel")
    return channel if isinstance(channel, str) and channel else None


REQUIRED_RUST_CHANNEL: str | None = accepted_channel(ROOT)
# rustup's minimal profile installs no components beyond those listed explicitly, so the registered
# component list in local_qualification.toml is the complete component set only under this profile.
TOOLCHAIN_PROFILE_WITHOUT_IMPLICIT_COMPONENTS = "minimal"
TOOLCHAIN_FILE_KEYS = frozenset({"channel", "profile", "components", "targets"})

# Pinned mirror titles of the class sections (change detection; titles are prose, not JSON fields).
CANONICAL_CONSTITUTION_MARKDOWN_TITLES: dict[str, str] = {
    "DEP-CLASS-F0": "Rust language and standard library",
    "DEP-CLASS-F1": "Asupersync",
    "DEP-CLASS-F2": "admitted Franken-suite crates",
    "DEP-CLASS-F3": "fundamental external Rust crates",
    "DEP-CLASS-F4": "laboratory and migration oracles",
}
CANONICAL_CONSTITUTION_CLASSES = authority.PINNED_CONSTITUTION_CLASSES[BASELINE_DEPENDENCY_CONSTITUTION_GENERATION]
CANONICAL_DEPENDENCY_CLASSES = CANONICAL_CONSTITUTION_CLASSES
REQUIRED_PRODUCTION_VALUES = authority.PINNED_CONSTITUTION_PRODUCTION[BASELINE_DEPENDENCY_CONSTITUTION_GENERATION]
EXPECTED_FREEZE_DIGESTS = authority.EXPECTED_CONSTITUTION_DIGESTS
MANDATORY_TOP_LEVEL_FIELDS: tuple[str, ...] = tuple(authority.CONSTITUTION_SPEC.fields)
MANDATORY_CLASS_FIELDS: tuple[str, ...] = tuple(authority.CONSTITUTION_CLASS_SPEC.fields)
MANDATORY_PRODUCTION_FIELDS: tuple[str, ...] = tuple(authority.CONSTITUTION_PRODUCTION_SPEC.fields)
ALLOWED_TOP_LEVEL_FIELDS: set[str] = set(MANDATORY_TOP_LEVEL_FIELDS)
ALLOWED_CLASS_FIELDS: set[str] = set(MANDATORY_CLASS_FIELDS)
ALLOWED_PRODUCTION_FIELDS: set[str] = set(MANDATORY_PRODUCTION_FIELDS)

# ---------------------------------------------------------------------------------------------
# Constitution Markdown mirror
# ---------------------------------------------------------------------------------------------

CLASS_HEADING_RE = re.compile(r"### 2\.(\d+) Class F(\d+) — (.+)")
ROGUE_CLASS_HEADING_RE = re.compile(r"(?i)#{1,6}\s.*\bclass\s+f\d+\b")
BINDING_RE = re.compile(r"Machine row: `(DEP-CLASS-F\d+)` · name `([^`]+)` · admission `([^`]+)`")
BINDING_PREFIX = "Machine row:"
MIRROR_HEADER = "| Constitution field | Value |"
MIRROR_SEPARATOR = "|---|---|"
MIRROR_ROW_RE = re.compile(r"\| `([A-Za-z][A-Za-z0-9.\[\]]*)` \| `([^`]*)` \|")


def render_binding(row: dict[str, Any]) -> str:
    return f"Machine row: `{row['id']}` · name `{row['name']}` · admission `{row['admission']}`"


def flatten_constitution(data: dict[str, Any]) -> dict[str, Any]:
    """Mirror paths -> typed JSON values for every mirrored field (all but freezeDigest and classes)."""
    flat: dict[str, Any] = {}
    for key in ("schema", "asOf", "generation", "normativePolicy"):
        if key in data and not isinstance(data[key], (dict, list)):
            flat[key] = data[key]
    production = data.get("production")
    if isinstance(production, dict):
        for key, value in production.items():
            if not isinstance(value, (dict, list)):
                flat[f"production.{key}"] = value
    evidence = data.get("releaseEvidence")
    if isinstance(evidence, list):
        for index, value in enumerate(evidence):
            if not isinstance(value, (dict, list)):
                flat[f"releaseEvidence[{index}]"] = value
    return flat


def render_constitution_mirror(data: dict[str, Any]) -> str:
    lines = [MIRROR_HEADER, MIRROR_SEPARATOR]
    for path, value in flatten_constitution(data).items():
        lines.append(f"| `{path}` | `{json.dumps(value, ensure_ascii=False)}` |")
    return "\n".join(lines)


def extract_markdown_class_sections(md_text: str) -> tuple[dict[str, tuple[str, str]], list[str]]:
    """Strict ``### 2.N Class Fk — Title`` sections: ({class_id: (title, body)}, duplicate_ids)."""
    lines = md_text.split("\n")
    classes: dict[str, tuple[str, str]] = {}
    duplicates: list[str] = []
    index = 0
    while index < len(lines):
        match = CLASS_HEADING_RE.fullmatch(lines[index])
        if not match:
            index += 1
            continue
        class_id = f"DEP-CLASS-F{match.group(2)}"
        end = index + 1
        while end < len(lines) and not lines[end].startswith("#"):
            end += 1
        body = "\n".join(lines[index + 1:end]).strip()
        if class_id in classes:
            duplicates.append(class_id)
        else:
            classes[class_id] = (match.group(3), body)
        index = end
    return classes, duplicates


def check_constitution_markdown(result: ValidationResult, auth: authority.Authority, md_path: Path) -> None:
    rel = CONSTITUTION_MD_PATH
    data, problems = authority.read_input_bytes(md_path, rel, auth.root)
    if data is None:
        result.extend(problems)
        return
    root_data, root_problems = authority.read_input_bytes(auth.root / CONSTITUTION_ROOT_COPY_PATH, CONSTITUTION_ROOT_COPY_PATH, auth.root)
    if root_data is None:
        result.extend(root_problems)
    elif root_data != data:
        result.add_error(ERR_DEP_CONST_DRIFT, CONSTITUTION_ROOT_COPY_PATH, "#", f"{CONSTITUTION_ROOT_COPY_PATH} and {rel} differ; the docs copy must be byte-identical to the canonical constitution")
    text, problems = authority.decode_utf8(data, rel)
    if text is None:
        result.extend(problems)
        return
    if "\r" in text:
        result.add_error(ERR_DEP_CONST_DRIFT, rel, "#", "constitution mirror contains carriage returns; the mirror is LF-only")
    lines = text.split("\n")

    # Rogue or duplicate class headings, and binding lines outside class sections.
    in_class = False
    for number, line in enumerate(lines, 1):
        if line.startswith("#"):
            in_class = bool(CLASS_HEADING_RE.fullmatch(line))
            if not in_class and ROGUE_CLASS_HEADING_RE.match(line):
                result.add_error(ERR_DEP_CONST_DRIFT, rel, f"line/{number}", f"rogue class heading outside the '### 2.N Class Fk — Title' form: {line!r}")
        elif line.startswith(BINDING_PREFIX) and not in_class:
            result.add_error(ERR_DEP_CONST_DRIFT, rel, f"line/{number}", f"machine row binding outside a class section: {line!r}")

    sections, duplicates = extract_markdown_class_sections(text)
    for class_id in duplicates:
        result.add_error(ERR_DEP_CONST_DRIFT, rel, f"#{class_id}", f"Duplicate class section header {class_id!r} found in {rel}")

    constitution = auth.constitution
    if constitution is None:
        return
    classes = constitution.get("classes")
    json_rows = [row for row in classes if isinstance(row, dict) and authority.is_str(row.get("id"))] if isinstance(classes, list) else []
    json_ids = [row["id"] for row in json_rows]
    json_by_id: dict[str, dict[str, Any]] = {}
    for row in json_rows:
        json_by_id.setdefault(row["id"], row)
    if isinstance(classes, list) and len(json_ids) != len(sections):
        result.add_error(ERR_DEP_CONST_DRIFT, rel, "#", f"markdown has {len(sections)} class sections but the JSON has {len(json_ids)} class rows")
    for class_id, row in json_by_id.items():
        section = sections.get(class_id)
        if section is None:
            result.add_error(ERR_DEP_CONST_DRIFT, rel, f"#{class_id}", f"Class section {class_id!r} is missing from {rel}")
            continue
        title, body = section
        pinned_title = CANONICAL_CONSTITUTION_MARKDOWN_TITLES.get(class_id)
        if pinned_title is not None and title != pinned_title:
            result.add_error(ERR_DEP_CONST_DRIFT, rel, f"#{class_id}/title", f"Class section {class_id!r} title drifted: pinned {pinned_title!r}, got {title!r}")
        bindings = [line for line in body.split("\n") if line.startswith(BINDING_PREFIX)]
        if not bindings:
            result.add_error(ERR_DEP_CONST_DRIFT, rel, f"#{class_id}/body", f"Class section {class_id!r} contains hollow or placeholder text: no machine row binding line")
            continue
        if len(bindings) > 1:
            result.add_error(ERR_DEP_CONST_DRIFT, rel, f"#{class_id}/body", f"Class section {class_id!r} declares {len(bindings)} machine row bindings; exactly one is allowed")
        match = BINDING_RE.fullmatch(bindings[0])
        if match is None:
            result.add_error(ERR_DEP_CONST_DRIFT, rel, f"#{class_id}/body", f"Class section {class_id!r} machine row is malformed: {bindings[0]!r}")
            continue
        bound_id, name, admission = match.groups()
        if bound_id != class_id:
            result.add_error(ERR_DEP_CONST_DRIFT, rel, f"#{class_id}/body", f"Class section {class_id!r} binds machine row {bound_id!r}")
        for key, value in (("name", name), ("admission", admission)):
            if key in row and row[key] != value:
                result.add_error(ERR_DEP_CONST_DRIFT, rel, f"#{class_id}/{key}", f"Class section {class_id!r} {key} mismatch with JSON: markdown={value!r}, json={row[key]!r}")
    for class_id in sections:
        if class_id not in json_by_id:
            result.add_error(ERR_DEP_CONST_DRIFT, rel, f"#{class_id}", f"markdown class section {class_id!r} has no JSON class row")

    headers = [i for i, line in enumerate(lines) if line == MIRROR_HEADER]
    if len(headers) != 1:
        result.add_error(ERR_DEP_CONST_DRIFT, rel, "#", f"constitution mirror must contain exactly one machine mirror table (header {MIRROR_HEADER!r}); found {len(headers)}")
        return
    start = headers[0]
    if start + 1 >= len(lines) or lines[start + 1] != MIRROR_SEPARATOR:
        result.add_error(ERR_DEP_CONST_DRIFT, rel, f"line/{start + 2}", f"machine mirror separator must be exactly {MIRROR_SEPARATOR!r}")
        return
    mirrored: dict[str, Any] = {}
    index = start + 2
    while index < len(lines) and lines[index].startswith("|"):
        number = index + 1
        match = MIRROR_ROW_RE.fullmatch(lines[index])
        index += 1
        if match is None:
            result.add_error(ERR_DEP_CONST_DRIFT, rel, f"line/{number}", f"machine mirror row must be `field` | `json-literal`: {lines[number - 1]!r}")
            continue
        path, literal = match.groups()
        value, problems = authority.parse_json_text(literal, rel)
        if problems:
            result.add_error(ERR_DEP_CONST_DRIFT, rel, f"line/{number}", f"machine mirror value for {path!r} is not a JSON literal: {literal!r}")
            continue
        if path in mirrored:
            result.add_error(ERR_DEP_CONST_DRIFT, rel, f"line/{number}", f"duplicate machine mirror row {path!r}")
            continue
        mirrored[path] = value
    expected = flatten_constitution(constitution)
    for path, value in expected.items():
        if path not in mirrored:
            result.add_error(ERR_DEP_CONST_DRIFT, rel, f"mirror/{path}", f"machine mirror lacks {path!r}")
        elif not authority._typed_equal(mirrored[path], value):
            result.add_error(ERR_DEP_CONST_DRIFT, rel, f"mirror/{path}", f"machine mirror {path!r} mismatch: markdown={mirrored[path]!r}, json={value!r}")
    for path in mirrored:
        if path not in expected:
            result.add_error(ERR_DEP_CONST_DRIFT, rel, f"mirror/{path}", f"machine mirror row {path!r} has no JSON counterpart")


# ---------------------------------------------------------------------------------------------
# Tombstones
# ---------------------------------------------------------------------------------------------


def load_tombstoned_ids(root: Path) -> tuple[set[str], list[DiagnosticError]]:
    """Retired dependency-class identifiers; a missing or corrupt resolution file fails closed."""
    auth = authority.Authority(root=root)
    authority._load_resolutions(auth, root / STABLE_ID_RESOLUTION_PATH)
    retired = {
        row["legacyId"]
        for row in auth.resolutions or []
        if isinstance(row.get("legacyId"), str) and {row.get("status"), row.get("disposition")} & authority.RETIRING_VALUES
    }
    return retired, list(auth.issues)


# ---------------------------------------------------------------------------------------------
# DEP-CLASS-F0 toolchain identity
# ---------------------------------------------------------------------------------------------


def _run(cmd: list[str], root: Path) -> tuple[subprocess.CompletedProcess[str] | None, str | None]:
    try:
        proc = subprocess.run(cmd, cwd=root, capture_output=True, text=True, timeout=TOOLCHAIN_COMMAND_TIMEOUT_SECONDS)
    except subprocess.TimeoutExpired:
        return None, f"{' '.join(cmd[3:5]) or cmd[0]} timed out after {TOOLCHAIN_COMMAND_TIMEOUT_SECONDS}s"
    except (OSError, ValueError) as exc:
        return None, f"{' '.join(cmd[3:5]) or cmd[0]} execution error: {exc}"
    return proc, None


def registered_host_scopes(root: Path, result: ValidationResult) -> set[str] | None:
    data, _raw, problems = authority.load_json_document(root / RELEASE_QUALIFICATION_PATH, RELEASE_QUALIFICATION_PATH, root)
    result.extend(problems)
    if data is None:
        return None
    scopes: set[str] = set()
    for value in data.values():
        for row in value if isinstance(value, list) else []:
            if isinstance(row, dict) and row.get("kind") == "native_release" and authority.is_str(row.get("scope")):
                scopes.add(row["scope"])
    if not scopes:
        result.add_error(ERR_DEP_CORRUPT_FILE, RELEASE_QUALIFICATION_PATH, "#", "no native_release platform scopes are registered")
        return None
    return scopes


def parse_rustc_verbose(stdout: str) -> tuple[dict[str, str] | None, str | None]:
    lines = [line for line in stdout.split("\n") if line]
    if not lines:
        return None, "rustc -Vv produced no output"
    first = re.fullmatch(r"rustc (\S+) \(([0-9a-f]{7,40}) (\d{4}-\d{2}-\d{2})\)", lines[0])
    if first is None:
        return None, f"rustc -Vv first line is not 'rustc <release> (<hash> <date>)': {lines[0]!r}"
    fields: dict[str, str] = {}
    for line in lines[1:]:
        key, sep, value = line.partition(": ")
        if not sep or key in fields:
            return None, f"rustc -Vv line is malformed or repeated: {line!r}"
        fields[key] = value
    missing = [key for key in ("binary", "commit-hash", "commit-date", "host", "release") if key not in fields]
    if missing:
        return None, f"rustc -Vv lacks {missing}"
    if fields["release"] != first.group(1) or fields["commit-date"] != first.group(3) or not fields["commit-hash"].startswith(first.group(2)):
        return None, "rustc -Vv header line disagrees with its release/commit fields"
    if not re.fullmatch(r"[0-9a-f]{40}", fields["commit-hash"]):
        return None, f"rustc -Vv commit-hash {fields['commit-hash']!r} is not a full 40-hex hash"
    return fields, None


def load_toolchain_contract(root: Path, result: ValidationResult, scopes: set[str] | None = None) -> dict[str, Any] | None:
    """The accepted toolchain identity from architecture/local_qualification.toml [toolchain].

    Every ``[toolchain.host_triples]`` entry, not only the running host, must map to a native_release
    platform scope of architecture/release_qualification.json (``scopes``)."""
    rel = LOCAL_QUALIFICATION_PATH
    data, _raw, problems = authority.load_toml_document(root / rel, rel, root)
    if data is None:
        result.extend(problems)
        return None
    toolchain = data.get("toolchain")
    if not isinstance(toolchain, dict):
        result.add_error(ERR_DEP_CORRUPT_FILE, rel, "#/toolchain", f"{rel} lacks a [toolchain] table")
        return None
    problems = []
    for key, spec in TOOLCHAIN_CONTRACT_KEYS.items():
        if key not in toolchain:
            problems.append(issue(ERR_DEP_MISSING_FIELD, rel, f"#/toolchain/{key}", f"{rel} [toolchain] lacks {key!r}"))
        else:
            authority.validate_shape(toolchain[key], spec, rel, f"#/toolchain/{key}", problems)
    if problems:
        result.extend(problems)
        return None
    channel_match = NIGHTLY_CHANNEL_RE.fullmatch(toolchain["channel"])
    if channel_match is None or _date(channel_match.group(1)) is None:
        result.add_error(ERR_DEP_CONST_INVARIANT, rel, "#/toolchain/channel", f"accepted channel {toolchain['channel']!r} is not a dated nightly (production.toolchain latest-accepted-pinned-nightly)")
        return None
    if not toolchain["rustc_release"].endswith("-nightly"):
        result.add_error(ERR_DEP_CONST_INVARIANT, rel, "#/toolchain/rustc_release", f"accepted rustc release {toolchain['rustc_release']!r} is not a nightly release")
        return None
    if not re.fullmatch(r"[0-9a-f]{40}", toolchain["rustc_commit_hash"]) or _date(toolchain["rustc_commit_date"]) is None:
        result.add_error(ERR_DEP_CORRUPT_FILE, rel, "#/toolchain", "accepted rustc commit hash must be 40 hex digits and the commit date an ISO date")
        return None
    if scopes is not None:
        for triple, scope in sorted(toolchain["host_triples"].items()):
            if scope not in scopes:
                result.add_error(ERR_DEP_CONST_INVARIANT, rel, f"#/toolchain/host_triples/{triple}", f"host triple {triple!r} maps to platform {scope!r}, which is not a native_release scope {sorted(scopes)} of {RELEASE_QUALIFICATION_PATH}")
    return toolchain


def validate_toolchain_identity(root: Path, result: ValidationResult) -> str | None:
    """Toolchain file + ``rustc -Vv`` identity against local_qualification.toml. Returns the verified channel."""
    rel = RUST_TOOLCHAIN_PATH
    if (root / LEGACY_RUST_TOOLCHAIN_PATH).exists():
        result.add_error(ERR_DEP_CONST_INVARIANT, LEGACY_RUST_TOOLCHAIN_PATH, "#", "a legacy rust-toolchain override file exists beside rust-toolchain.toml; rustup would prefer it over the pinned channel")
    scopes = registered_host_scopes(root, result)
    contract = load_toolchain_contract(root, result, scopes)
    data, _raw, problems = authority.load_toml_document(root / rel, rel, root)
    if data is None:
        result.extend(problems)
        return None
    for key in data:
        if key != "toolchain":
            result.add_error(ERR_DEP_CORRUPT_FILE, rel, f"#/{key}", f"unexpected top-level key {key!r} in {rel}")
    toolchain = data.get("toolchain")
    if not isinstance(toolchain, dict):
        result.add_error(ERR_DEP_CORRUPT_FILE, rel, "#/toolchain", f"{rel} lacks a [toolchain] table")
        return None
    for key in toolchain:
        if key not in TOOLCHAIN_FILE_KEYS:
            result.add_error(ERR_DEP_CORRUPT_FILE, rel, f"#/toolchain/{key}", f"unexpected [toolchain] key {key!r}; it would override the pinned toolchain source")
    channel = toolchain.get("channel")
    channel_match = NIGHTLY_CHANNEL_RE.fullmatch(channel) if isinstance(channel, str) else None
    channel_date = _date(channel_match.group(1)) if channel_match else None
    if channel_date is None:
        result.add_error(ERR_DEP_CONST_INVARIANT, rel, "#/toolchain/channel", f"Toolchain channel must be a dated nightly (production.toolchain latest-accepted-pinned-nightly), found {channel!r}")
        return None
    if contract is None:
        return None
    if channel != contract["channel"]:
        result.add_error(ERR_DEP_CONST_INVARIANT, rel, "#/toolchain/channel", f"Toolchain channel {channel!r} differs from the accepted channel {contract['channel']!r} in {LOCAL_QUALIFICATION_PATH}")
        return None
    profile = toolchain.get("profile")
    if profile != TOOLCHAIN_PROFILE_WITHOUT_IMPLICIT_COMPONENTS:
        result.add_error(ERR_DEP_CONST_INVARIANT, rel, "#/toolchain/profile", f"Toolchain profile must be {TOOLCHAIN_PROFILE_WITHOUT_IMPLICIT_COMPONENTS!r} so no unregistered component is installed, found {profile!r}")
    components = toolchain.get("components")
    registered = contract["components"]
    if not isinstance(components, list) or not all(isinstance(c, str) for c in components) or len(set(components)) != len(components):
        result.add_error(ERR_DEP_CORRUPT_FILE, rel, "#/toolchain/components", f"[toolchain].components must be a list of unique strings, found {components!r}")
    elif set(components) != set(registered):
        result.add_error(ERR_DEP_CONST_INVARIANT, rel, "#/toolchain/components", f"toolchain components {sorted(components)} differ from the registered components {sorted(registered)} in {LOCAL_QUALIFICATION_PATH}")
    if "targets" in toolchain:
        result.add_error(ERR_DEP_CONST_INVARIANT, rel, "#/toolchain/targets", f"toolchain targets {toolchain.get('targets')!r} are not registered anywhere; no extra target may be installed")

    proc, error = _run(["rustup", "run", channel, "rustc", "-Vv"], root)
    if error is not None or proc is None:
        result.add_error(ERR_DEP_EXEC_FAILED, rel, "#", f"Unable to execute rustc -Vv for {channel}: {error}")
        return None
    if proc.returncode != 0:
        result.add_error(ERR_DEP_EXEC_FAILED, rel, "#", f"rustc -Vv failed with exit code {proc.returncode}: {(proc.stderr or '').strip()[:300]}")
        return None
    fields, parse_error = parse_rustc_verbose(proc.stdout or "")
    if fields is None:
        result.add_error(ERR_DEP_EXEC_FAILED, rel, "#", f"rustc -Vv output is unparseable: {parse_error}")
        return None
    if not fields["release"].endswith("-nightly"):
        result.add_error(ERR_DEP_CONST_INVARIANT, rel, "#/rustc/release", f"rustc -Vv reports release {fields['release']!r}, not the nightly release channel")
    for key, contract_key in (("release", "rustc_release"), ("commit-hash", "rustc_commit_hash"), ("commit-date", "rustc_commit_date")):
        if fields[key] != contract[contract_key]:
            result.add_error(ERR_DEP_CONST_INVARIANT, rel, f"#/rustc/{key}", f"rustc -Vv {key} {fields[key]!r} differs from the accepted {contract_key} {contract[contract_key]!r} in {LOCAL_QUALIFICATION_PATH}")
    commit_date = _date(fields["commit-date"])
    if commit_date is None or commit_date > channel_date:
        result.add_error(ERR_DEP_CONST_INVARIANT, rel, "#/rustc/commit-date", f"rustc commit-date {fields['commit-date']!r} is later than the pinned channel date {channel_date}")
    scope = contract["host_triples"].get(fields["host"])
    if scope is None:
        result.add_error(ERR_DEP_CONST_INVARIANT, rel, "#/rustc/host", f"rustc host {fields['host']!r} is not an accepted host triple in {LOCAL_QUALIFICATION_PATH} [toolchain.host_triples]")
    elif scopes is not None and scope not in scopes:
        result.add_error(ERR_DEP_CONST_INVARIANT, rel, "#/rustc/host", f"rustc host {fields['host']!r} maps to platform {scope!r}, which is not a registered native_release scope {sorted(scopes)} in {RELEASE_QUALIFICATION_PATH}")
    return channel


def _date(value: str) -> _dt.date | None:
    try:
        return _dt.date.fromisoformat(value)
    except (TypeError, ValueError):
        return None


# ---------------------------------------------------------------------------------------------
# DEP-CLASS-F0 closure census over cargo metadata
# ---------------------------------------------------------------------------------------------


def load_real_cargo_metadata(root: Path, channel: str | None = REQUIRED_RUST_CHANNEL) -> tuple[dict[str, Any] | None, str | None]:
    """``cargo metadata --locked --offline --all-features`` (every feature, every target platform)."""
    if not channel:
        return None, f"no accepted toolchain channel is registered in {LOCAL_QUALIFICATION_PATH}"
    cmd = ["rustup", "run", channel, "cargo", "metadata", "--locked", "--offline", "--all-features", "--format-version", "1"]
    try:
        proc = subprocess.run(cmd, cwd=root, capture_output=True, text=True, timeout=CARGO_METADATA_TIMEOUT_SECONDS)
    except subprocess.TimeoutExpired:
        return None, f"cargo metadata timed out after {CARGO_METADATA_TIMEOUT_SECONDS}s"
    except (OSError, ValueError) as exc:
        return None, f"cargo metadata execution error: {exc}"
    if proc.returncode != 0:
        return None, f"cargo metadata failed with exit code {proc.returncode}: {((proc.stderr or '') or (proc.stdout or '')).strip()[:300]}"
    stdout = proc.stdout or ""
    if len(stdout.encode("utf-8", "replace")) > authority.MAX_INPUT_FILE_BYTES:
        return None, f"cargo metadata output exceeds the operational bound of {authority.MAX_INPUT_FILE_BYTES} bytes"
    data, problems = authority.parse_json_text(stdout, "cargo metadata")
    if problems:
        return None, f"cargo metadata output is not valid JSON: {problems[0].message}"
    if not isinstance(data, dict):
        return None, "cargo metadata output is not valid JSON object"
    return data, None


DYNAMIC_CRATE_TYPES = frozenset({"cdylib", "dylib", "staticlib"})


def _git_ignored(root: Path, rels: list[str], result: ValidationResult) -> set[str]:
    """The subset of ``rels`` git ignores (untracked and matching an ignore rule); empty outside git."""
    if not rels or not (root / ".git").exists():
        return set()
    try:
        proc = subprocess.run(["git", "-C", str(root), "check-ignore", "--stdin", "-z"], input="\0".join(rels) + "\0",
                              capture_output=True, text=True, timeout=TOOLCHAIN_COMMAND_TIMEOUT_SECONDS)
    except subprocess.TimeoutExpired:
        result.add_error(ERR_DEP_EXEC_FAILED, ".gitignore", "#", f"git check-ignore timed out after {TOOLCHAIN_COMMAND_TIMEOUT_SECONDS}s")
        return set()
    except (OSError, ValueError) as exc:
        result.add_error(ERR_DEP_EXEC_FAILED, ".gitignore", "#", f"git check-ignore could not run: {exc}")
        return set()
    if proc.returncode not in (0, 1):
        result.add_error(ERR_DEP_EXEC_FAILED, ".gitignore", "#", f"git check-ignore failed with exit code {proc.returncode}: {(proc.stderr or '').strip()[:300]}")
        return set()
    return {path for path in (proc.stdout or "").split("\0") if path}


def _target_source_problem(src: str, root: Path, ignored: set[str]) -> str | None:
    try:
        rel = Path(src).resolve().relative_to(root.resolve()).as_posix()
    except (ValueError, OSError):
        return f"has its source {src!r} outside the repository, where no scan reaches it"
    top = rel.split("/", 1)[0]
    if top in UNSCANNED_TOP_LEVEL_DIRS:
        return f"has its source {rel!r} in the unscanned directory {top}/"
    if rel in ignored:
        return f"has its source {rel!r} in a git-ignored path that is never checked in"
    return None


def _member_target_sources(packages: dict[str, dict[str, Any]], members: set[str], root: Path) -> list[str]:
    rels: list[str] = []
    for pkg_id in members:
        for target in packages.get(pkg_id, {}).get("targets", []) if isinstance(packages.get(pkg_id, {}).get("targets"), list) else []:
            src = target.get("src_path") if isinstance(target, dict) else None
            if authority.is_str(src):
                try:
                    rels.append(Path(src).resolve().relative_to(root.resolve()).as_posix())
                except (ValueError, OSError):
                    continue
    return sorted(set(rels))


def workspace_contract(root: Path, result: ValidationResult) -> tuple[set[str] | None, list[str] | None]:
    """Crate names declared in crate_topology.json and the explicit [workspace].members patterns."""
    declared: set[str] | None = None
    topology, _raw, problems = authority.load_json_document(root / CRATE_TOPOLOGY_PATH, CRATE_TOPOLOGY_PATH, root)
    result.extend(problems)
    if topology is not None:
        declared = set()
        for layer in topology.get("layers", []) if isinstance(topology.get("layers"), list) else []:
            for crate in authority.as_dict(layer).get("crates", []) if isinstance(authority.as_dict(layer).get("crates"), list) else []:
                if authority.is_str(authority.as_dict(crate).get("name")):
                    declared.add(crate["name"])
        if not declared:
            result.add_error(ERR_DEP_CORRUPT_FILE, CRATE_TOPOLOGY_PATH, "#/layers", "crate topology declares no crates")
            declared = None
    explicit: list[str] | None = None
    manifest, _raw, problems = authority.load_toml_document(root / "Cargo.toml", "Cargo.toml", root)
    result.extend(problems)
    if manifest is not None:
        members = authority.as_dict(manifest.get("workspace")).get("members")
        if isinstance(members, list) and members and all(authority.is_str(m) for m in members):
            explicit = [m.rstrip("/") for m in members]
        else:
            _metadata_violation(result, "#/workspace/members", f"root Cargo.toml [workspace].members must be a non-empty list of paths, found {members!r}", "Cargo.toml")
    return declared, explicit


def _relative_dir(manifest_path: Any, root: Path) -> str | None:
    if not authority.is_str(manifest_path):
        return None
    try:
        return Path(manifest_path).resolve().parent.relative_to(root.resolve()).as_posix()
    except (ValueError, OSError):
        return None


def _metadata_violation(result: ValidationResult, target: str, message: str, file_path: str = "Cargo.lock") -> None:
    result.add_error(ERR_DEP_CONST_METADATA_VIOLATION, file_path, target, message)


def validate_cargo_metadata_for_f0(
    result: ValidationResult,
    metadata: Any,
    root: Path,
    allow_data: dict[str, Any] | None = None,
) -> None:
    """Closure census of real Cargo metadata for DEP-CLASS-F0; every shape problem is a finding."""
    if not isinstance(metadata, dict):
        _metadata_violation(result, "#", "Cargo metadata root must be a JSON object")
        return
    auth = authority.load_authority(root)
    view = authority.class_view_from_policy(allow_data, fallback=auth)
    admitted_projects = auth.admitted_projects()
    language = auth.production().get("language")
    edition_match = authority.CONSTITUTION_LANGUAGE_RE.fullmatch(language) if isinstance(language, str) else None
    expected_edition = edition_match.group(1) if edition_match else None
    expected_language = language.split("-", 1)[0] if edition_match else None
    if expected_edition is None:
        _metadata_violation(result, "#/production/language", f"cannot derive the Rust edition from the constitution production language {language!r}", CONSTITUTION_JSON_PATH)
    if view is None:
        _metadata_violation(result, "#", "the dependency authority cannot drive classification; the closure census fails closed", DEPENDENCIES_JSON_PATH)

    fss_meta = authority.as_dict(metadata.get("metadata")).get("fss")
    prod_lang = fss_meta.get("production_language") if isinstance(fss_meta, dict) else None
    if expected_language is not None and prod_lang != expected_language:
        _metadata_violation(result, "#/metadata/fss/production_language", f"Cargo metadata production_language must be {expected_language!r}, found: {prod_lang!r}", "Cargo.toml")

    raw_members = metadata.get("workspace_members")
    members: set[str] = set()
    if not isinstance(raw_members, list) or not raw_members:
        _metadata_violation(result, "#/workspace_members", f"workspace_members must be a non-empty list of package ids, found {raw_members!r}")
    else:
        for member in raw_members:
            if authority.is_str(member):
                members.add(member)
            else:
                _metadata_violation(result, "#/workspace_members", f"workspace member id must be a string, found {member!r}")
    raw_packages = metadata.get("packages")
    if not isinstance(raw_packages, list):
        _metadata_violation(result, "#/packages", f"packages must be a list, found {type(raw_packages).__name__}")
        raw_packages = []
    packages: dict[str, dict[str, Any]] = {}
    for index, pkg in enumerate(raw_packages):
        if not isinstance(pkg, dict):
            _metadata_violation(result, f"#/packages[{index}]", f"package entry must be an object, found {type(pkg).__name__}")
            continue
        pkg_id, name = pkg.get("id"), pkg.get("name")
        if not authority.is_str(pkg_id) or not authority.is_str(name):
            _metadata_violation(result, f"#/packages[{index}]", f"package entry lacks a string id/name: id={pkg_id!r}, name={name!r}")
            continue
        if pkg_id in packages:
            _metadata_violation(result, f"#/packages[{index}]", f"package id {pkg_id!r} appears twice")
            continue
        for key in ("version", "source", "targets", "edition", "links"):
            if key not in pkg:
                _metadata_violation(result, f"#{name}/{key}", f"package '{name}' lacks metadata field {key!r}")
        if pkg.get("source") is not None and not authority.is_str(pkg.get("source")):
            _metadata_violation(result, f"#{name}/source", f"package '{name}' source must be a string or null")
        packages[pkg_id] = pkg
    for member in sorted(members - set(packages)):
        _metadata_violation(result, "#/workspace_members", f"workspace member {member!r} has no package entry")
    declared_crates, explicit_members = workspace_contract(root, result)

    # Production reachability over the resolve graph: normal and build edges are production.
    production: set[str] | None = None
    development: set[str] = set()
    resolve = metadata.get("resolve")
    nodes = resolve.get("nodes") if isinstance(resolve, dict) else None
    if not isinstance(nodes, list):
        _metadata_violation(result, "#/resolve", "cargo metadata has no resolve graph; production reachability is unproven, so every package is treated as production")
    else:
        edges: dict[str, list[tuple[str, bool]]] = {}
        for node in nodes:
            if not isinstance(node, dict) or not authority.is_str(node.get("id")) or not isinstance(node.get("deps", []), list):
                _metadata_violation(result, "#/resolve/nodes", f"malformed resolve node {str(node)[:120]!r}")
                continue
            out: list[tuple[str, bool]] = []
            for dep in node.get("deps", []):
                kinds = dep.get("dep_kinds") if isinstance(dep, dict) else None
                if not isinstance(dep, dict) or not authority.is_str(dep.get("pkg")) or not isinstance(kinds, list) or not kinds:
                    _metadata_violation(result, "#/resolve/nodes", f"malformed resolve edge from {node['id']!r}: {str(dep)[:120]!r}")
                    continue
                is_prod_edge = any(isinstance(k, dict) and k.get("kind") in (None, "build") for k in kinds)
                out.append((dep["pkg"], is_prod_edge))
            edges[node["id"]] = out
        production = set()
        stack = [m for m in members]
        while stack:
            current = stack.pop()
            if current in production:
                continue
            production.add(current)
            stack.extend(pkg for pkg, is_prod in edges.get(current, []) if is_prod)
        stack = [pkg for member in members for pkg, is_prod in edges.get(member, []) if not is_prod]
        while stack:
            current = stack.pop()
            if current in production or current in development:
                continue
            development.add(current)
            stack.extend(pkg for pkg, _ in edges.get(current, []))
        for pkg_id in sorted((production | development) - set(packages)):
            _metadata_violation(result, "#/resolve", f"resolve graph references unknown package id {pkg_id!r}")

    ignored = _git_ignored(root, _member_target_sources(packages, members, root), result)
    for pkg_id, pkg in sorted(packages.items()):
        name = pkg["name"]
        is_member = pkg_id in members
        if production is None:
            is_prod = True
        elif is_member or pkg_id in production:
            is_prod = True
        elif pkg_id in development:
            is_prod = False
        else:
            _metadata_violation(result, f"#{name}", f"package '{name}' ({pkg_id}) is not reachable from any workspace member")
            is_prod = True
        manifest = str(pkg.get("manifest_path", "Cargo.lock")) if isinstance(pkg.get("manifest_path"), str) else "Cargo.lock"
        targets = pkg.get("targets", [])
        if not isinstance(targets, list):
            _metadata_violation(result, f"#{name}/targets", f"package '{name}' targets must be a list")
            targets = []
        kinds: set[str] = set()
        crate_types: set[str] = set()
        for target in targets:
            if not isinstance(target, dict):
                _metadata_violation(result, f"#{name}/targets", f"package '{name}' has a non-object target")
                continue
            for field_name, bucket in (("kind", kinds), ("crate_types", crate_types)):
                values = target.get(field_name, [])
                if not isinstance(values, list) or not all(isinstance(v, str) for v in values):
                    _metadata_violation(result, f"#{name}/targets/{field_name}", f"package '{name}' target {field_name} must be a list of strings, found {values!r}")
                    continue
                bucket.update(values)
        if "custom-build" in kinds:
            _metadata_violation(result, f"#{name}/targets/custom-build", f"Package '{name}' declares custom-build (build.rs) target violating pure-Rust DEP-CLASS-F0", manifest)
        if "proc-macro" in kinds or "proc-macro" in crate_types:
            _metadata_violation(result, f"#{name}/targets/proc-macro", f"Package '{name}' declares proc-macro target violating pure-Rust DEP-CLASS-F0", manifest)
        dynamic = sorted((kinds | crate_types) & DYNAMIC_CRATE_TYPES)
        if dynamic:
            _metadata_violation(result, f"#{name}/targets/crate_types", f"Package '{name}' declares dynamic/C-ABI crate types {dynamic} violating DEP-CLASS-F0 (no dynamic loading or C FFI)", manifest)
        links = pkg.get("links")
        if is_member:
            for target in targets:
                src = target.get("src_path") if isinstance(target, dict) else None
                problem = _target_source_problem(src, root, ignored) if authority.is_str(src) else None
                if problem is not None:
                    _metadata_violation(result, f"#{name}/targets/{target.get('name')}/src_path", f"workspace member '{name}' target {target.get('name')!r} {problem}", manifest)
            if declared_crates is not None and name not in declared_crates:
                _metadata_violation(result, f"#{name}/topology", f"workspace member '{name}' is not declared in {CRATE_TOPOLOGY_PATH}", manifest)
            member_dir = _relative_dir(pkg.get("manifest_path"), root)
            if explicit_members is not None and (member_dir is None or not any(fnmatch.fnmatchcase(member_dir, pattern) for pattern in explicit_members)):
                _metadata_violation(result, f"#{name}/workspace-member", f"workspace member '{name}' ({member_dir or pkg.get('manifest_path')!r}) is not an explicit [workspace].members entry; implicit members such as in-repository path dependencies are refused", manifest)
            edition = pkg.get("edition")
            if expected_edition is not None and edition != expected_edition:
                _metadata_violation(result, f"#{name}/edition", f"workspace package '{name}' must declare edition '{expected_edition}' (DEP-CLASS-F0), found: {edition!r}", manifest)
            if links is not None:
                _metadata_violation(result, f"#{name}/links", f"workspace package '{name}' illegally declares native links {links!r} violating pure-Rust DEP-CLASS-F0", manifest)
            continue
        if links is not None:
            _metadata_violation(result, f"#{name}/links", f"Non-member package '{name}' in closure declares native links {links!r} violating pure-Rust DEP-CLASS-F0", manifest)
        if view is None:
            continue
        outcome = authority.classify_package(name, view, is_production=is_prod, is_member=False, admitted_projects=admitted_projects)
        lane = "production" if is_prod else "development-only"
        if outcome.kind == "pending":
            result.add_error(ERR_DEP_PENDING_DECISION, "Cargo.lock", f"#{name}", f"crate '{name}' is in the {lane} closure while {outcome.reason}")
        elif outcome.kind == "forbidden":
            _metadata_violation(result, f"#{name}", f"Forbidden crate '{name}' detected in the {lane} dependency closure violating DEP-CLASS-F0")
        elif outcome.kind == "unclassified":
            _metadata_violation(result, f"#{name}", f"Unadmitted external crate '{name}' detected in the {lane} dependency closure violating the pure-Rust closed universe")
        elif outcome.kind == "scope" and outcome.row in view.table_rows.get("exception_candidates", ()):
            _metadata_violation(result, f"#{name}", f"Exception candidate '{name}' is not admitted without DEP record and ADR ({outcome.row}) violating DEP-CLASS-F0")
        elif outcome.kind in ("gate", "scope", "unassigned"):
            _metadata_violation(result, f"#{name}", f"crate '{name}' is not admitted in the {lane} closure: {outcome.reason}")


# ---------------------------------------------------------------------------------------------
# Unstable features
# ---------------------------------------------------------------------------------------------

# Only the workspace's own build output and tool state are skipped; a directory named "target" anywhere
# else (for example a crate root under src/target/) is scanned.
UNSCANNED_TOP_LEVEL_DIRS = frozenset({".git", ".claude", ".beads", ".ntm", ".ee", "target"})
RUSTFLAG_KEYS = frozenset({"rustflags", "rustdocflags", "RUSTFLAGS", "RUSTDOCFLAGS", "CARGO_ENCODED_RUSTFLAGS",
                           "CARGO_ENCODED_RUSTDOCFLAGS", "CARGO_BUILD_RUSTFLAGS", "CARGO_BUILD_RUSTDOCFLAGS"})
ENV_RUSTFLAGS_RE = re.compile(r"\b(?:CARGO_ENCODED_RUSTFLAGS|CARGO_ENCODED_RUSTDOCFLAGS|CARGO_BUILD_RUSTFLAGS|CARGO_BUILD_RUSTDOCFLAGS|RUSTFLAGS|RUSTDOCFLAGS)\b.*?(?<![\w-])-Z")
TOOL_Z_FLAG_RE = re.compile(r"\b(?:cargo|rustc|rustdoc)\b[^#\n]*?(?<![\w-])-Z")
# Compiler overrides: cargo config keys and environment variables that replace the rustc/rustdoc that
# rustup runs, so the accepted identity in local_qualification.toml would not be what builds.
COMPILER_OVERRIDE_KEYS = frozenset({"rustc", "rustc-wrapper", "rustc-workspace-wrapper", "rustdoc"})
COMPILER_OVERRIDE_ENV = frozenset({"RUSTC", "RUSTC_WRAPPER", "RUSTC_WORKSPACE_WRAPPER", "RUSTDOC", "CARGO_BUILD_RUSTC",
                                   "CARGO_BUILD_RUSTC_WRAPPER", "CARGO_BUILD_RUSTC_WORKSPACE_WRAPPER", "CARGO_BUILD_RUSTDOC"})
COMPILER_OVERRIDE_ENV_RE = re.compile(r"\b(?:CARGO_BUILD_)?(?:RUSTC|RUSTC_WRAPPER|RUSTC_WORKSPACE_WRAPPER|RUSTDOC)\s*=")
BOOTSTRAP_ENV_RE = re.compile(r"\bRUSTC_BOOTSTRAP\s*=")
TASK_RUNNER_NAMES = frozenset({"Makefile", "makefile", "GNUmakefile", "justfile", "Justfile", ".justfile"})
SHELL_LIKE_SUFFIXES = frozenset({".sh", ".bash", ".zsh", ".mk", ".just"})
TOOLCHAIN_FILE_NAMES = frozenset({"rust-toolchain", "rust-toolchain.toml"})
# rustdoc compiles a fenced block when its info string is empty or made only of these tags.
RUSTDOC_CODE_TAGS = frozenset({"rust", "ignore", "should_panic", "no_run", "compile_fail", "test_harness", "standalone_crate", "allow_fail"})
DOC_LINE_RE = re.compile(r"^\s*//[/!](?!/)")
DOC_BLOCK_RE = re.compile(r"/\*[*!](?![*/])(.*?)\*/", re.S)
FENCE_RE = re.compile(r"^\s*(`{3,}|~{3,})\s*(.*?)\s*$")
MANIFEST_CARGO_FEATURES_RE = re.compile(r"^\s*cargo-features\s*=", re.MULTILINE)
MANIFEST_RUSTFLAGS_Z_RE = re.compile(r"^\s*rustflags\s*=.*?(?<![\w-])-Z", re.MULTILINE)
INNER_ATTRIBUTE_RE = re.compile(r"#\s*!\s*\[")
ATTRIBUTE_PATH_RE = re.compile(r"\s*(?:r#)?([A-Za-z_][A-Za-z0-9_]*)(?:\s*::\s*(?:r#)?[A-Za-z_][A-Za-z0-9_]*)*\s*")


def repository_files(root: Path, predicate: Any) -> list[Path]:
    found: list[Path] = []
    for dirpath, dirnames, filenames in os.walk(root, followlinks=False):
        current = Path(dirpath)
        if current == root:
            dirnames[:] = [d for d in dirnames if d not in UNSCANNED_TOP_LEVEL_DIRS]
        for filename in filenames:
            path = current / filename
            if predicate(path):
                found.append(path)
    return sorted(found)


def _split_top_level(text: str) -> list[str]:
    parts, depth, start = [], 0, 0
    for index, char in enumerate(text):
        if char in "([{":
            depth += 1
        elif char in ")]}":
            depth -= 1
        elif char == "," and depth == 0:
            parts.append(text[start:index])
            start = index + 1
    parts.append(text[start:])
    return [part for part in parts if part.strip()]


def attribute_enables_feature(content: str) -> bool:
    """True when an inner attribute's content is ``feature(...)`` or a ``cfg_attr`` that applies one."""
    match = ATTRIBUTE_PATH_RE.match(content)
    if match is None:
        return False
    rest = content[match.end():]
    if not rest.startswith("("):
        return False
    if match.group(1) == "feature" and "::" not in match.group(0):
        return True
    if match.group(1) == "cfg_attr" and "::" not in match.group(0):
        depth, end = 0, None
        for index, char in enumerate(rest):
            depth += char == "("
            depth -= char == ")"
            if depth == 0:
                end = index
                break
        arguments = _split_top_level(rest[1:end if end is not None else len(rest)])
        return any(attribute_enables_feature(argument) for argument in arguments[1:])
    return False


def inner_attributes(masked: str) -> list[tuple[int, str]]:
    attributes = []
    for match in INNER_ATTRIBUTE_RE.finditer(masked):
        depth, index = 1, match.end()
        while index < len(masked) and depth:
            depth += masked[index] == "["
            depth -= masked[index] == "]"
            index += 1
        attributes.append((match.start(), masked[match.end():index - 1]))
    return attributes


def _z_tokens(value: Any) -> list[str]:
    if isinstance(value, dict):
        value = value.get("value")
    if isinstance(value, str):
        tokens = re.split(r"[\s\x1f]+", value)
    elif isinstance(value, list):
        tokens = [v for v in value if isinstance(v, str)]
    else:
        return []
    return [token for token in tokens if token.startswith("-Z")]


def _config_rustflags(node: Any, path: str = "") -> list[tuple[str, str]]:
    hits: list[tuple[str, str]] = []
    if isinstance(node, dict):
        for key, value in node.items():
            here = f"{path}.{key}" if path else key
            if key in RUSTFLAG_KEYS:
                hits.extend((here, token) for token in _z_tokens(value))
            else:
                hits.extend(_config_rustflags(value, here))
    return hits


def _config_keys(node: Any, keys: frozenset[str], path: str = "") -> list[str]:
    """Dotted paths of ``keys`` anywhere in a cargo config table, outside [alias] and [env]."""
    hits: list[str] = []
    if isinstance(node, dict):
        for key, value in node.items():
            here = f"{path}.{key}" if path else key
            if not path and key in ("alias", "env"):
                continue
            if key in keys:
                hits.append(here)
            else:
                hits.extend(_config_keys(value, keys, here))
    return hits


def _is_rustdoc_code(info: str) -> bool:
    tokens = [token for token in re.split(r"[\s,]+", info.strip().strip("{}").lstrip(".")) if token]
    return all(token in RUSTDOC_CODE_TAGS or token.startswith("edition") or re.fullmatch(r"E\d{4}", token) for token in tokens)


def doctest_blocks(text: str) -> list[list[tuple[int, str]]]:
    """Rust code blocks of rustdoc comments as lists of (file line, code line).

    Doc comments are ``///``/``//!`` line runs and ``/** */``/``/*! */`` blocks. A fenced block is Rust
    when rustdoc would compile it (empty info string or only rustdoc tags); hidden ``# `` lines are
    compiled too, so the marker is removed."""
    segments: list[list[tuple[int, str]]] = []
    current: list[tuple[int, str]] = []
    for number, line in enumerate(text.split("\n"), 1):
        match = DOC_LINE_RE.match(line)
        if match:
            current.append((number, line[match.end():]))
        elif current:
            segments.append(current)
            current = []
    if current:
        segments.append(current)
    for match in DOC_BLOCK_RE.finditer(text):
        start = text.count("\n", 0, match.start()) + 1
        segments.append([(start + offset, re.sub(r"^\s*\*?", "", raw, count=1)) for offset, raw in enumerate(match.group(1).split("\n"))])
    blocks: list[list[tuple[int, str]]] = []
    for segment in segments:
        fence: str | None = None
        rust = False
        body: list[tuple[int, str]] = []
        for number, content in segment:
            fence_match = FENCE_RE.match(content)
            if fence is None:
                if fence_match:
                    fence, rust, body = fence_match.group(1), _is_rustdoc_code(fence_match.group(2)), []
                continue
            if fence_match and fence_match.group(1)[0] == fence[0] and len(fence_match.group(1)) >= len(fence) and not fence_match.group(2):
                if rust:
                    blocks.append(body)
                fence = None
                continue
            code = content[1:] if content.startswith(" ") else content
            stripped = code.lstrip()
            if stripped == "#":
                code = ""
            elif stripped.startswith("# "):
                code = stripped[2:]
            body.append((number, code))
        if fence is not None and rust:
            blocks.append(body)  # an unclosed fence runs to the end of the comment
    return blocks


def scan_unstable_features(root: Path, result: ValidationResult) -> int:
    """Refuses every way of enabling nightly unstable features: no unstable-feature registry exists.

    Scanned: ``#![feature(...)]`` and ``#![cfg_attr(<pred>, feature(...))]`` inner attributes in every
    Rust file of the repository (build scripts included; only the workspace's own target/ and tool
    directories are skipped) and in the rustdoc code blocks of their doc comments (doctests are
    compiled); ``-Z`` flags in ``.cargo/config[.toml]`` rustflags/env tables and [alias] values, any
    ``[unstable]`` table or config ``include``; ``cargo-features`` and ``-Z`` profile rustflags in
    Cargo.toml files; ``-Z`` in RUSTFLAGS-style assignments and ``RUSTC_BOOTSTRAP`` in checked-in env,
    shell, Makefile and justfile files and cargo/rustc/rustdoc ``-Z`` invocations in the shell-like ones;
    and ``-Z`` string literals in build scripts. Compiler overrides (cargo config ``rustc``/
    ``rustc-wrapper``/``rustdoc`` keys, ``RUSTC``/``RUSTC_WRAPPER``/``RUSTDOC`` settings) and nested
    ``rust-toolchain(.toml)`` files are CONST-INVARIANT: they replace the compiler whose identity
    local_qualification.toml accepts.
    """
    import dependency_audit  # local import: dependency_audit imports this checker's authority module

    def emit(rel: str, target: str, message: str) -> None:
        result.add_error(ERR_DEP_UNSTABLE_FEATURE, rel, target, f"{message}; no registered unstable-feature allowlist exists (DEPENDENCY_CONSTITUTION 2.1 requires enabled unstable features to be recorded)")

    def read_text(path: Path) -> str | None:
        rel = path.relative_to(root).as_posix()
        data, problems = authority.read_input_bytes(path, rel, root)
        text, decode_problems = (authority.decode_utf8(data, rel) if data is not None else (None, []))
        if text is None:
            result.extend(problems or decode_problems)
        return text

    rust_files = repository_files(root, lambda p: p.suffix == ".rs")
    for path in rust_files:
        text = read_text(path)
        if text is None:
            continue
        rel = path.relative_to(root).as_posix()
        masked, literals = dependency_audit.mask_rust_source(text)
        for offset, content in inner_attributes(masked):
            if attribute_enables_feature(content):
                line = masked.count("\n", 0, offset) + 1
                emit(rel, f"line/{line}", f"{rel}:{line}: an inner attribute enables an unstable feature")
        for block in doctest_blocks(text):
            code_masked, _ = dependency_audit.mask_rust_source("\n".join(code for _number, code in block))
            for offset, content in inner_attributes(code_masked):
                if attribute_enables_feature(content):
                    line = block[code_masked.count("\n", 0, offset)][0]
                    emit(rel, f"line/{line}", f"{rel}:{line}: a rustdoc code block enables an unstable feature (doctests are compiled)")
        if path.name == "build.rs":
            for literal in literals:
                if re.search(r"(?<![\w-])-Z", literal.content):
                    emit(rel, f"line/{literal.line}", f"{rel}:{literal.line}: build script passes an unstable -Z flag")
    for path in repository_files(root, lambda p: p.parent.name == ".cargo" and p.name in ("config", "config.toml")):
        rel = path.relative_to(root).as_posix()
        data, _raw, problems = authority.load_toml_document(path, rel, root)
        if data is None:
            result.extend(problems)
            continue
        if "unstable" in data:
            emit(rel, "#/unstable", f"{rel} enables cargo [unstable] options")
        if "include" in data:
            emit(rel, "#/include", f"{rel} includes further config files (cargo -Zconfig-include); their contents are not vetted")
        for key_path, token in _config_rustflags(data):
            emit(rel, f"#/{key_path}", f"{rel} {key_path} passes the unstable flag {token}")
        for alias, value in sorted(authority.as_dict(data.get("alias")).items()):
            for token in _z_tokens(value):
                emit(rel, f"#/alias.{alias}", f"{rel} alias {alias!r} passes the unstable flag {token}")
        for key_path in _config_keys(data, COMPILER_OVERRIDE_KEYS):
            result.add_error(ERR_DEP_CONST_INVARIANT, rel, f"#/{key_path}", f"{rel} {key_path} replaces the compiler rustup runs, so the accepted rustc identity of {LOCAL_QUALIFICATION_PATH} would not be what builds the workspace")
        for key in sorted(authority.as_dict(data.get("env"))):
            if key == "RUSTC_BOOTSTRAP":
                emit(rel, "#/env.RUSTC_BOOTSTRAP", f"{rel} [env] sets RUSTC_BOOTSTRAP, which unlocks unstable features on any compiler")
            elif key in COMPILER_OVERRIDE_ENV:
                result.add_error(ERR_DEP_CONST_INVARIANT, rel, f"#/env.{key}", f"{rel} [env] sets {key}, which replaces the compiler whose identity {LOCAL_QUALIFICATION_PATH} accepts")
    for path in repository_files(root, lambda p: p.name == "Cargo.toml"):
        text = read_text(path)
        if text is None:
            continue
        rel = path.relative_to(root).as_posix()
        if MANIFEST_CARGO_FEATURES_RE.search(text):
            emit(rel, "#/cargo-features", f"{rel} declares unstable cargo-features")
        if MANIFEST_RUSTFLAGS_Z_RE.search(text):
            emit(rel, "#/profile/rustflags", f"{rel} passes an unstable -Z flag in profile rustflags")
    def shell_like(p: Path) -> bool:
        return p.suffix in SHELL_LIKE_SUFFIXES or p.name in TASK_RUNNER_NAMES

    for path in repository_files(root, lambda p: shell_like(p) or p.name.startswith(".env") or p.name.endswith(".env")):
        text = read_text(path)
        if text is None:
            continue
        rel = path.relative_to(root).as_posix()
        for number, line in enumerate(text.split("\n"), 1):
            if line.lstrip().startswith("#"):
                continue
            if ENV_RUSTFLAGS_RE.search(line) or (shell_like(path) and TOOL_Z_FLAG_RE.search(line)):
                emit(rel, f"line/{number}", f"{rel}:{number}: sets RUSTFLAGS-style flags or passes cargo/rustc an unstable -Z option")
            elif BOOTSTRAP_ENV_RE.search(line):
                emit(rel, f"line/{number}", f"{rel}:{number}: sets RUSTC_BOOTSTRAP, which unlocks unstable features on any compiler")
            elif COMPILER_OVERRIDE_ENV_RE.search(line):
                result.add_error(ERR_DEP_CONST_INVARIANT, rel, f"line/{number}", f"{rel}:{number}: overrides the compiler rustup runs, so the accepted rustc identity of {LOCAL_QUALIFICATION_PATH} would not be what builds")
    for path in repository_files(root, lambda p: p.name in TOOLCHAIN_FILE_NAMES and p.parent != root):
        rel = path.relative_to(root).as_posix()
        result.add_error(ERR_DEP_CONST_INVARIANT, rel, "#", f"{rel} overrides the toolchain for its subtree; only the root {RUST_TOOLCHAIN_PATH} pins the accepted channel")
    return len(rust_files)


# ---------------------------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------------------------


def check_error_registration(result: ValidationResult, root: Path) -> None:
    rel = authority.ERRORS_MD_PATH
    data, problems = authority.read_input_bytes(root / rel, rel, root)
    text, decode_problems = (authority.decode_utf8(data, rel) if data is not None else (None, []))
    if text is None:
        result.extend(problems or decode_problems)
        return
    registered = set(re.findall(r"^\| `(ERR-[A-Z0-9-]+)` \|", text, flags=re.MULTILINE))
    for code in CONSTITUTION_CHECKER_ERROR_CODES:
        if code not in registered:
            result.add_error(ERR_DEP_TRACE_UNRESOLVED, rel, f"#/{code}", f"diagnostic {code} emitted by the constitution checker is not registered in {rel}")


def validate_dependency_constitution(
    root: Path,
    cargo_metadata: dict[str, Any] | None = None,
    skip_cargo_metadata: bool = False,
) -> ValidationResult:
    """Validates the constitution, its mirror, the authority crosswalk and (unless skipped) DEP-CLASS-F0."""
    result = ValidationResult()
    auth = authority.load_authority(root)
    result.extend(auth.issues)
    constitution = auth.constitution or {}
    classes = constitution.get("classes")
    result.class_count = len(classes) if isinstance(classes, list) else 0
    declared = constitution.get("freezeDigest")
    result.freeze_digest = declared if isinstance(declared, str) else (auth.constitution_digest or "")
    check_constitution_markdown(result, auth, root / CONSTITUTION_MD_PATH)
    if not skip_cargo_metadata:
        check_error_registration(result, root)
        channel = validate_toolchain_identity(root, result)
        lock_data, lock_problems = authority.read_input_bytes(root / "Cargo.lock", "Cargo.lock", root)
        if lock_data is None:
            result.extend(lock_problems)  # cargo metadata is not run over a missing, symlinked or oversized lock
        elif cargo_metadata is None:
            cargo_metadata, meta_err = load_real_cargo_metadata(root, channel or accepted_channel(root))
            if meta_err is not None:
                result.add_error(ERR_DEP_EXEC_FAILED, "Cargo.lock", "#", f"Unable to load real Cargo metadata for DEP-CLASS-F0 verification: {meta_err}")
        if cargo_metadata is not None:
            validate_cargo_metadata_for_f0(result, cargo_metadata, root)
        scan_unstable_features(root, result)
    return result


def main() -> int:
    parser = argparse.ArgumentParser(description="Check the dependency constitution and DEP-CLASS-F0")
    parser.add_argument("--root", type=Path, default=ROOT, help="Repository root path")
    parser.add_argument("--json", action="store_true", help="Output JSON results")
    parser.add_argument("--skip-cargo-metadata", action="store_true", help="Skip toolchain identity, cargo metadata and source scans")
    args = parser.parse_args()

    res = validate_dependency_constitution(args.root, skip_cargo_metadata=args.skip_cargo_metadata)
    if args.json:
        print(json.dumps({
            "passed": res.passed,
            "classCount": res.class_count,
            "freezeDigest": res.freeze_digest,
            "errors": [{"code": e.code, "file": e.file_path, "target": e.target, "message": e.message} for e in res.errors],
        }, indent=2))
        return 0 if res.passed else 1
    if res.passed:
        print(f"Dependency constitution OK: {res.class_count} classes verified ({res.freeze_digest})")
        return 0
    for err in res.errors:
        print(f"[{err.code}] {err.file_path} ({err.target}): {err.message}", file=sys.stderr)
    return 1


if __name__ == "__main__":
    sys.exit(main())
