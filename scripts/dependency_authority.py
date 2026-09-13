#!/usr/bin/env python3
"""Single dependency-policy authority for the FSS dependency checkers (fss-x4a.30.88.1, fss-x4a.30.88.16).

COMPREHENSIVE_PLAN section 1.3 names one authority: DEPENDENCY_CONSTITUTION.md together with
``architecture/dependency_allowlist.toml``. ``architecture/dependency_constitution.json`` is the machine
class registry (DEP-CLASS-F0..F4) and every ``architecture/dependencies.json`` row (DEP-*-001) references
one of those classes. This module is the only reader of those files for the dependency checkers and
the dependency-class census in ``scripts/dependency_audit.py``:

* every input is read with a bounded size, strict UTF-8, duplicate-key-free JSON/TOML parsing, exact
  key sets and exact value types (a bool is a bool; ``1`` is not ``true``);
* the allowlist bytes, the constitution content and the registry content are pinned to reviewed
  digests, so any change needs a reviewed pin update (and, for the JSON registries, a generation bump);
* the allowlist, the constitution, the dependency registry, the Franken import gates and the local
  qualification contract are cross-checked against each other;
* packages are classified from those files only. Policy lists, family-to-project mappings, oracle row
  splits and pending owner decisions all come from the allowlist; row scopes and row-to-table producers
  come from the registry. The constants below are schema vocabulary (key names, value vocabularies,
  types) and pinned digests, never admission lists.

Nothing here raises for malformed input: every problem becomes a registered ``DiagnosticError``.
"""
from __future__ import annotations

import datetime as _dt
import fnmatch
import functools
import hashlib
import json
import os
import re
import stat
import tomllib
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Callable

ROOT = Path(__file__).resolve().parents[1]

DEPENDENCIES_JSON_PATH = "architecture/dependencies.json"
DEPENDENCIES_MD_PATH = "registries/DEPENDENCIES.md"
CONSTITUTION_JSON_PATH = "architecture/dependency_constitution.json"
ALLOWLIST_TOML_PATH = "architecture/dependency_allowlist.toml"
FRANKEN_IMPORTS_PATH = "architecture/franken_imports.json"
STABLE_ID_RESOLUTION_PATH = "architecture/stable_id_resolution.json"
LOCAL_QUALIFICATION_PATH = "architecture/local_qualification.toml"
AGENT_CONTRACTS_PATH = "architecture/agent_contracts.json"
ERRORS_MD_PATH = "registries/ERRORS.md"

# Operational bound on any single policy input or tool output read by the dependency checkers.
# It exists so a runaway or hostile file cannot exhaust the in-process policy lane; it is not a
# policy threshold. tests/test_dependency_registry_checker.py pins it.
MAX_INPUT_FILE_BYTES = 10 * 1024 * 1024

# Registered diagnostic codes (registries/ERRORS.md).
ERR_DEP_REGISTRY_DRIFT = "ERR-DEP-REGISTRY-DRIFT-001"
ERR_DEP_STABLE_ID_REUSED = "ERR-DEP-STABLE-ID-REUSED-001"
ERR_DEP_MISSING_FIELD = "ERR-DEP-MISSING-FIELD-001"
ERR_DEP_CORRUPT_FILE = "ERR-DEP-CORRUPT-FILE-001"
ERR_DEP_DIGEST_MISMATCH = "ERR-DEP-DIGEST-MISMATCH-001"
ERR_DEP_FREEZE_DIVERGENCE = "ERR-DEP-FREEZE-DIVERGENCE-001"
ERR_DEP_GENERATION_MISMATCH = "ERR-DEP-GENERATION-MISMATCH-001"
ERR_DEP_CONST_INVARIANT = "ERR-DEP-CONST-INVARIANT-001"
ERR_DEP_ALLOWLIST_DIGEST_DIVERGED = "ERR-DEP-ALLOWLIST-DIGEST-DIVERGED-001"
ERR_DEP_PENDING_DECISION = "ERR-DEP-PENDING-DECISION-001"
ERR_DEP_TRACE_UNRESOLVED = "ERR-DEP-TRACE-UNRESOLVED-001"
ERR_DEP_TOMBSTONE_INVALID = "ERR-DEP-TOMBSTONE-INVALID-001"

AUTHORITY_ERROR_CODES: tuple[str, ...] = (
    ERR_DEP_REGISTRY_DRIFT,
    ERR_DEP_STABLE_ID_REUSED,
    ERR_DEP_MISSING_FIELD,
    ERR_DEP_CORRUPT_FILE,
    ERR_DEP_DIGEST_MISMATCH,
    ERR_DEP_FREEZE_DIVERGENCE,
    ERR_DEP_GENERATION_MISMATCH,
    ERR_DEP_CONST_INVARIANT,
    ERR_DEP_ALLOWLIST_DIGEST_DIVERGED,
    ERR_DEP_PENDING_DECISION,
    ERR_DEP_TRACE_UNRESOLVED,
    ERR_DEP_TOMBSTONE_INVALID,
)

# ---------------------------------------------------------------------------------------------
# Pinned digests (change detection). Updating one is a reviewed policy change; the JSON registries
# also need a generation bump because each generation has exactly one pinned digest.
# ---------------------------------------------------------------------------------------------
BASELINE_DEPENDENCIES_GENERATION = "gen:fss1:dependencies-v2"
BASELINE_DEPENDENCIES_FREEZE_DIGEST = "sha256:8f198c9ce7b3eca519c678beb4bde773fe42d8bc93b55b9f0af375d38208a9c1"
EXPECTED_DEPENDENCIES_DIGESTS: dict[str, str] = {
    BASELINE_DEPENDENCIES_GENERATION: BASELINE_DEPENDENCIES_FREEZE_DIGEST,
}

BASELINE_CONSTITUTION_GENERATION = "gen:fss1:dep-constitution-v1"
BASELINE_CONSTITUTION_FREEZE_DIGEST = "sha256:858af1b5482b25cfca1477c2c4c1967a995d802990aaf0bc7ccf139f73571310"
EXPECTED_CONSTITUTION_DIGESTS: dict[str, str] = {
    BASELINE_CONSTITUTION_GENERATION: BASELINE_CONSTITUTION_FREEZE_DIGEST,
}

# The allowlist carries no self-declared digest, so its raw bytes are pinned per schema version.
BASELINE_ALLOWLIST_SCHEMA = "fss.dependency_allowlist.v3"
BASELINE_ALLOWLIST_FREEZE_DIGEST = "sha256:0efdadd6174cf3658e9ea78568c4700093a744c284a443f1e6707146eb8b9ce9"
EXPECTED_ALLOWLIST_DIGESTS: dict[str, str] = {
    BASELINE_ALLOWLIST_SCHEMA: BASELINE_ALLOWLIST_FREEZE_DIGEST,
}

# Pinned class baseline for field-level change detection (the digest pin already covers it; this
# names which field drifted). Keyed by constitution generation.
PINNED_CONSTITUTION_CLASSES: dict[str, dict[str, dict[str, str]]] = {
    BASELINE_CONSTITUTION_GENERATION: {
        "DEP-CLASS-F0": {"id": "DEP-CLASS-F0", "name": "rust-language-and-stdlib", "admission": "constitutional"},
        "DEP-CLASS-F1": {"id": "DEP-CLASS-F1", "name": "asupersync", "admission": "INT-AS-001"},
        "DEP-CLASS-F2": {"id": "DEP-CLASS-F2", "name": "franken-suite", "admission": "per-mechanism-import-gate"},
        "DEP-CLASS-F3": {"id": "DEP-CLASS-F3", "name": "fundamental-rust-data-shape", "admission": "DEP-record-and-transitive-audit"},
        "DEP-CLASS-F4": {"id": "DEP-CLASS-F4", "name": "laboratory-oracle", "admission": "non-production-quarantine-only"},
    },
}
PINNED_CONSTITUTION_PRODUCTION: dict[str, dict[str, Any]] = {
    BASELINE_CONSTITUTION_GENERATION: {
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
    },
}

# ---------------------------------------------------------------------------------------------
# Diagnostics
# ---------------------------------------------------------------------------------------------


@dataclass(frozen=True)
class DiagnosticError:
    code: str
    file_path: str
    target: str
    message: str


@dataclass
class ValidationResult:
    passed: bool = True
    dependency_count: int = 0
    class_count: int = 0
    freeze_digest: str = ""
    errors: list[DiagnosticError] = field(default_factory=list)
    report: dict[str, Any] = field(default_factory=dict)

    def add_error(self, code: str, file_path: str, target: str, message: str) -> None:
        self.passed = False
        self.errors.append(DiagnosticError(code=code, file_path=file_path, target=target, message=message))

    def extend(self, issues: list[DiagnosticError]) -> None:
        for item in issues:
            self.add_error(item.code, item.file_path, item.target, item.message)


def issue(code: str, file_path: str, target: str, message: str) -> DiagnosticError:
    return DiagnosticError(code=code, file_path=file_path, target=target, message=message)


# ---------------------------------------------------------------------------------------------
# Bounded strict readers
# ---------------------------------------------------------------------------------------------


def _symlinked_ancestor(path: Path, root: Path) -> str | None:
    """Names the first directory between ``root`` and ``path`` that is a symbolic link, if any."""
    try:
        parts = path.parent.relative_to(root).parts
    except ValueError:
        return None  # an explicit override outside the root is checked only for its own final component
    current = root
    for part in parts:
        current = current / part
        if os.path.islink(current):
            return f"directory {current.relative_to(root).as_posix()} on the path to it is a symbolic link"
    return None


def read_input_bytes(path: Path, rel: str, root: Path, *, allow_empty: bool = False) -> tuple[bytes | None, list[DiagnosticError]]:
    """Reads at most MAX_INPUT_FILE_BYTES + 1 bytes of a regular, non-symlinked file.

    ``root`` is mandatory: every directory between the repository root and the input is checked, so a
    symlinked ``docs/`` or ``registries/`` directory is refused even when the file itself is regular.
    Missing, symlinked, non-regular, oversized, unreadable or (unless ``allow_empty``, for formats where
    an empty file is valid such as Cargo manifests) blank inputs are CORRUPT-FILE. The final component is
    opened with O_NOFOLLOW and the open descriptor is re-checked, so a symlink swapped in after lstat is
    refused too.
    """
    limit = MAX_INPUT_FILE_BYTES
    # Lexical containment: no ``..`` component, and the path (resolved without following symlinks, which
    # are refused below) must stay under the repository root. Defensive: no data path reaches it today.
    if ".." in path.parts:
        return None, [issue(ERR_DEP_CORRUPT_FILE, rel, "#", f"{rel} contains a '..' path component; authority inputs are named by a direct path under the repository")]
    try:
        root_resolved = os.path.realpath(root)
        candidate = os.path.normpath(path if path.is_absolute() else os.path.join(root_resolved, path))
        if os.path.commonpath([candidate, root_resolved]) != root_resolved:
            return None, [issue(ERR_DEP_CORRUPT_FILE, rel, "#", f"{rel} resolves outside the repository root; authority inputs must live inside it")]
    except (ValueError, OSError) as exc:
        return None, [issue(ERR_DEP_CORRUPT_FILE, rel, "#", f"could not locate {rel} within the repository root: {exc}")]
    try:
        try:
            st = os.lstat(path)
        except FileNotFoundError:
            return None, [issue(ERR_DEP_CORRUPT_FILE, rel, "#", f"required input {rel} is missing")]
        if stat.S_ISLNK(st.st_mode):
            return None, [issue(ERR_DEP_CORRUPT_FILE, rel, "#", f"{rel} is a symbolic link; authority inputs must be regular files inside the repository")]
        if not stat.S_ISREG(st.st_mode):
            return None, [issue(ERR_DEP_CORRUPT_FILE, rel, "#", f"{rel} is not a regular file")]
        ancestor = _symlinked_ancestor(path, root)
        if ancestor is not None:
            return None, [issue(ERR_DEP_CORRUPT_FILE, rel, "#", f"{rel} is not read: {ancestor}")]
        if path.stat().st_size > limit:
            return None, [issue(ERR_DEP_CORRUPT_FILE, rel, "#", f"{rel} exceeds the operational input bound of {limit} bytes")]
        fd = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_CLOEXEC", 0))
        with os.fdopen(fd, "rb") as handle:
            if not stat.S_ISREG(os.fstat(handle.fileno()).st_mode):
                return None, [issue(ERR_DEP_CORRUPT_FILE, rel, "#", f"{rel} is not a regular file")]
            data = handle.read(limit + 1)
    except (OSError, ValueError) as exc:
        return None, [issue(ERR_DEP_CORRUPT_FILE, rel, "#", f"could not read {rel}: {exc}")]
    if len(data) > limit:
        return None, [issue(ERR_DEP_CORRUPT_FILE, rel, "#", f"{rel} exceeds the operational input bound of {limit} bytes")]
    if not allow_empty and not data.strip():
        return None, [issue(ERR_DEP_CORRUPT_FILE, rel, "#", f"{rel} is empty (0 bytes or whitespace only)")]
    return data, []


def decode_utf8(data: bytes, rel: str) -> tuple[str | None, list[DiagnosticError]]:
    if data.startswith(b"\xef\xbb\xbf"):
        return None, [issue(ERR_DEP_CORRUPT_FILE, rel, "#", f"{rel} starts with a UTF-8 byte-order mark")]
    try:
        return data.decode("utf-8"), []
    except UnicodeDecodeError as exc:
        return None, [issue(ERR_DEP_CORRUPT_FILE, rel, "#", f"{rel} is not valid UTF-8: {exc}")]


def pairs_hook_reject_duplicates(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    """object_pairs_hook refusing duplicate JSON keys."""
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError(f"duplicate JSON key {key!r}")
        result[key] = value
    return result


def _reject_constant(name: str) -> Any:
    raise ValueError(f"non-finite JSON number {name} is not permitted")


def parse_json_text(text: str, rel: str) -> tuple[Any, list[DiagnosticError]]:
    try:
        return json.loads(text, object_pairs_hook=pairs_hook_reject_duplicates, parse_constant=_reject_constant), []
    except RecursionError:
        return None, [issue(ERR_DEP_CORRUPT_FILE, rel, "#", f"{rel} nests deeper than the JSON parser can represent")]
    except ValueError as exc:
        return None, [issue(ERR_DEP_CORRUPT_FILE, rel, "#", f"{rel} is not valid JSON: {exc}")]


def load_json_document(path: Path, rel: str, root: Path) -> tuple[Any, bytes | None, list[DiagnosticError]]:
    data, problems = read_input_bytes(path, rel, root)
    if data is None:
        return None, None, problems
    text, problems = decode_utf8(data, rel)
    if text is None:
        return None, data, problems
    value, problems = parse_json_text(text, rel)
    if problems:
        return None, data, problems
    if not isinstance(value, dict):
        return None, data, [issue(ERR_DEP_CORRUPT_FILE, rel, "#", f"{rel} root must be a JSON object, found {type(value).__name__}")]
    return value, data, []


def load_toml_document(path: Path, rel: str, root: Path, *, allow_empty: bool = False) -> tuple[dict[str, Any] | None, bytes | None, list[DiagnosticError]]:
    data, problems = read_input_bytes(path, rel, root, allow_empty=allow_empty)
    if data is None:
        return None, None, problems
    text, problems = decode_utf8(data, rel)
    if text is None:
        return None, data, problems
    try:
        value = tomllib.loads(text)
    except RecursionError:
        return None, data, [issue(ERR_DEP_CORRUPT_FILE, rel, "#", f"{rel} nests deeper than the TOML parser can represent")]
    except (tomllib.TOMLDecodeError, ValueError) as exc:
        return None, data, [issue(ERR_DEP_CORRUPT_FILE, rel, "#", f"{rel} is not valid TOML (duplicate keys included): {exc}")]
    return value, data, []


def sha256_prefixed(data: bytes) -> str:
    return "sha256:" + hashlib.sha256(data).hexdigest()


# ---------------------------------------------------------------------------------------------
# Exact-shape validation
# ---------------------------------------------------------------------------------------------

_CONTROL_CHARS = re.compile(r"[\x00-\x1f\x7f]")


@dataclass(frozen=True)
class Str:
    """Non-empty string without surrounding whitespace or control characters."""


@dataclass(frozen=True)
class NullableStr:
    """``null`` or a ``Str``."""


@dataclass(frozen=True)
class Bool:
    """A real boolean (``1``/``0`` are refused)."""


@dataclass(frozen=True)
class List:
    item: Any
    nonempty: bool = True


@dataclass(frozen=True)
class Map:
    """Table/object with free keys (each a clean string) and uniformly typed values."""

    value: Any


@dataclass(frozen=True)
class Obj:
    """Table/object with an exact key set; every key is required."""

    fields: dict[str, Any]


def spec_depth(spec: Any) -> int:
    """Maximum container nesting a document of this spec can have (scalars are depth 0)."""
    if isinstance(spec, Obj):
        return 1 + max((spec_depth(sub) for sub in spec.fields.values()), default=0)
    if isinstance(spec, (List, Map)):
        return 1 + spec_depth(spec.item if isinstance(spec, List) else spec.value)
    return 0


def _clean_string_problem(value: str) -> str | None:
    if value != value.strip():
        return "has leading or trailing whitespace"
    if _CONTROL_CHARS.search(value):
        return "contains a control character"
    return None


def validate_shape(value: Any, spec: Any, rel: str, target: str, out: list[DiagnosticError]) -> None:
    """Appends CORRUPT-FILE (wrong type, unknown key, bad value) and MISSING-FIELD (absent/null/empty)."""
    if isinstance(spec, Obj):
        if not isinstance(value, dict):
            out.append(issue(ERR_DEP_CORRUPT_FILE, rel, target, f"{target} must be an object/table, found {type(value).__name__}"))
            return
        for key in value:
            if key not in spec.fields:
                out.append(issue(ERR_DEP_CORRUPT_FILE, rel, f"{target}/{key}", f"unexpected key {key!r} at {target}"))
        for key, sub in spec.fields.items():
            if key not in value:
                out.append(issue(ERR_DEP_MISSING_FIELD, rel, f"{target}/{key}", f"missing mandatory field {key!r} at {target}"))
            else:
                validate_shape(value[key], sub, rel, f"{target}/{key}", out)
        return
    if isinstance(spec, Map):
        if not isinstance(value, dict):
            out.append(issue(ERR_DEP_CORRUPT_FILE, rel, target, f"{target} must be an object/table, found {type(value).__name__}"))
            return
        for key, sub_value in value.items():
            problem = _clean_string_problem(key) if key else "is empty"
            if problem:
                out.append(issue(ERR_DEP_CORRUPT_FILE, rel, f"{target}/{key}", f"key {key!r} at {target} {problem}"))
            validate_shape(sub_value, spec.value, rel, f"{target}/{key}", out)
        return
    if value is None and not isinstance(spec, NullableStr):
        out.append(issue(ERR_DEP_MISSING_FIELD, rel, target, f"{target} is null"))
        return
    if isinstance(spec, List):
        if not isinstance(value, list):
            out.append(issue(ERR_DEP_CORRUPT_FILE, rel, target, f"{target} must be a list, found {type(value).__name__}"))
            return
        if spec.nonempty and not value:
            out.append(issue(ERR_DEP_MISSING_FIELD, rel, target, f"{target} must be a non-empty list"))
        seen: set[str] = set()
        for index, item in enumerate(value):
            validate_shape(item, spec.item, rel, f"{target}[{index}]", out)
            if isinstance(spec.item, Str) and isinstance(item, str):
                if item in seen:
                    out.append(issue(ERR_DEP_CORRUPT_FILE, rel, f"{target}[{index}]", f"duplicate entry {item!r} in {target}"))
                seen.add(item)
        return
    if isinstance(spec, Bool):
        if type(value) is not bool:
            out.append(issue(ERR_DEP_CORRUPT_FILE, rel, target, f"{target} must be a boolean, found {type(value).__name__} {value!r}"))
        return
    if isinstance(spec, NullableStr) and value is None:
        return
    if isinstance(spec, (Str, NullableStr)):
        if not isinstance(value, str):
            out.append(issue(ERR_DEP_CORRUPT_FILE, rel, target, f"{target} must be a string, found {type(value).__name__}"))
            return
        if not value:
            out.append(issue(ERR_DEP_MISSING_FIELD, rel, target, f"{target} is an empty string"))
            return
        problem = _clean_string_problem(value)
        if problem:
            out.append(issue(ERR_DEP_CORRUPT_FILE, rel, target, f"{target} value {value!r} {problem}"))
        return
    raise TypeError(f"unknown spec {spec!r}")  # programming error, not input-dependent


def is_str(value: Any) -> bool:
    return isinstance(value, str) and bool(value)


def str_list(value: Any) -> list[str]:
    """Strings of a list, ignoring non-strings (shape validation already reported them)."""
    return [item for item in value if isinstance(item, str) and item] if isinstance(value, list) else []


def as_dict(value: Any) -> dict[str, Any]:
    return value if isinstance(value, dict) else {}


def _iso_date(value: Any) -> _dt.date | None:
    if not isinstance(value, str) or not re.fullmatch(r"\d{4}-\d{2}-\d{2}", value):
        return None
    try:
        return _dt.date.fromisoformat(value)
    except ValueError:
        return None


# ---------------------------------------------------------------------------------------------
# Schemas (vocabulary only)
# ---------------------------------------------------------------------------------------------

ALLOWLIST_POLICY_FLAGS: tuple[str, ...] = (
    "closed_universe",
    "direct_crates_must_be_allowlisted",
    "transitive_closure_must_be_censused",
    "new_external_dependency_requires_dep_record_and_adr",
    "fss_crates_must_forbid_unsafe",
    "fss_unsafe_exceptions_allowed",
    "c_or_cpp_ffi_allowed",
    "dynamic_loading_allowed",
    "foreign_runtime_production_boundary_allowed",
    "release_resolution_must_be_locked_and_offline",
    "build_scripts_may_not_use_network",
    "runtime_acquisition_allowed",
    "foreign_executables_allowed_in_production",
    "serde_may_not_define_durable_bytes",
    "hosted_ci_is_not_release_authority",
    "asupersync_is_only_async_runtime",
)

ALLOWLIST_SPEC = Obj({
    "schema": Str(),
    "as_of": Str(),
    "policy": Obj({flag: Bool() for flag in ALLOWLIST_POLICY_FLAGS}),
    "in_house": Obj({"allowed_families": List(Str()), "rule": Str(), "projects": Map(List(Str()))}),
    "fundamental": Obj({"allowed_subject_to_audit": List(Str(), nonempty=False), "rule": Str()}),
    "exception_candidates": Obj({"not_admitted_without_dep_record_adr_and_release_evidence": List(Str(), nonempty=False)}),
    "resolved_drifts": Map(Str()),
    "laboratory_oracles": Obj({
        "excluded_from_production_release_closure": List(Str(), nonempty=False),
        "requirements": List(Str()),
        "rows": Map(List(Str(), nonempty=False)),
    }),
    "forbidden": Obj({"crates": List(Str(), nonempty=False), "patterns": List(Str(), nonempty=False)}),
    "pending_owner_decisions": Map(Obj({"registry_row": Str(), "crates": List(Str()), "question": Str()})),
})

# Allowlist tables whose entries are classified into dependency registry rows. A registry row names
# the tables that populate it in its ``producers`` list (``architecture/dependency_allowlist.toml#<table>``).
CLASSIFICATION_TABLES: tuple[str, ...] = (
    "in_house",
    "fundamental",
    "pending_owner_decisions",
    "laboratory_oracles",
    "exception_candidates",
)

CONSTITUTION_PRODUCTION_SPEC = Obj({
    "language": Str(),
    "toolchain": Str(),
    "unsafe": Str(),
    "asyncRuntime": Str(),
    "closedUniverse": Bool(),
    "lockedOfflineReleaseResolution": Bool(),
    "runtimeAcquisition": Bool(),
    "cCppFfi": Bool(),
    "dynamicLoading": Bool(),
    "foreignExecutables": Bool(),
    "serdeDurableFormatAuthority": Bool(),
})
CONSTITUTION_CLASS_SPEC = Obj({"id": Str(), "name": Str(), "admission": Str()})
CONSTITUTION_SPEC = Obj({
    "schema": Str(),
    "asOf": Str(),
    "generation": Str(),
    "freezeDigest": Str(),
    "normativePolicy": Str(),
    "production": CONSTITUTION_PRODUCTION_SPEC,
    "classes": List(CONSTITUTION_CLASS_SPEC),
    "releaseEvidence": List(Str()),
})
CONSTITUTION_SCHEMA_MAX_DEPTH = spec_depth(CONSTITUTION_SPEC)

# Value vocabularies the checkers know how to interpret; anything else fails closed.
CONSTITUTION_TOOLCHAIN_VALUES = frozenset({"latest-accepted-pinned-nightly"})
CONSTITUTION_UNSAFE_VALUES = frozenset({"forbidden-in-all-fss-crates"})
CONSTITUTION_ASYNC_RUNTIME_VALUES = frozenset({"asupersync-only"})
CONSTITUTION_LANGUAGE_RE = re.compile(r"rust-(\d{4})")
CLASS_ID_RE = re.compile(r"DEP-CLASS-F(?:0|[1-9][0-9]*)")
GATE_ID_RE = re.compile(r"INT-[A-Z0-9]+-[0-9]{3}")
ADMISSION_CONSTITUTIONAL = "constitutional"
ADMISSION_IMPORT_GATE = "per-mechanism-import-gate"
ADMISSION_DEP_RECORD = "DEP-record-and-transitive-audit"
ADMISSION_QUARANTINE = "non-production-quarantine-only"

REGISTRY_ROW_SPEC = Obj({
    "id": Str(),
    "constitutionClass": Str(),
    "constitutionClasses": List(Str()),
    "class": Str(),
    "rule": Str(),
    "scope": Str(),
    "status": Str(),
    "supersededBy": NullableStr(),
    "tombstoneDecision": NullableStr(),
    "owner": Str(),
    "producers": List(Str()),
    "consumers": List(Str()),
})
REGISTRY_SPEC = Obj({
    "schema": Str(),
    "generation": Str(),
    "freezeDigest": Str(),
    "sourceDocument": Str(),
    "constitution": Str(),
    "policy": Str(),
    "contractBasis": Str(),
    "ownerRationale": Str(),
    "futureOwner": Str(),
    "dependencies": List(REGISTRY_ROW_SPEC),
})
REGISTRY_SCHEMA = "fss.dependencies.v2"
DEP_ID_RE = re.compile(r"DEP-[A-Z0-9]+-[0-9]{3}")
ROW_STATUSES = ("active", "tombstoned", "superseded")
# Scope vocabulary and the lanes each scope admits.
SCOPE_LANES: dict[str, frozenset[str]] = {
    "Production": frozenset({"production", "development"}),
    "Production subject to audit": frozenset({"production", "development"}),
    "Development only": frozenset({"development"}),
    "Development/migration only": frozenset({"development"}),
    "Not admitted": frozenset(),
}

IMPORT_ROW_SPEC = Obj({key: Str() for key in (
    "failureBoundary", "gate", "id", "mechanism", "mode", "owner", "project",
    "referenceModel", "source", "status", "substituteProhibition",
)})
IMPORTS_SPEC = Obj({"schema": Str(), "asOf": Str(), "imports": List(IMPORT_ROW_SPEC)})
# docs/FRANKEN_IMPORT_ADMISSION_GATES.md section 1 lifecycle (plus the registry's pre-census "planned").
IMPORT_STATUSES: tuple[str, ...] = (
    "planned",
    "censused",
    "contracted",
    "reference-implemented",
    "adapter-implemented",
    "differentially-verified",
    "fault-verified",
    "performance-measured",
    "production-admitted",
)
PRODUCTION_ADMITTED_IMPORT_STATUS = "production-admitted"

# stable_id_resolution.json vocabulary (scripts/stable_id_audit.py TOMBSTONE_STATES plus the live values).
RESOLUTION_STATUSES = frozenset({"active", "tombstone", "tombstoned", "superseded"})
RESOLUTION_DISPOSITIONS = frozenset({"retained", "legacy-collision-remapped", "tombstone", "tombstoned", "superseded"})
RETIRING_VALUES = frozenset({"tombstone", "tombstoned", "superseded"})
DEP_SHAPED_RE = re.compile(r"(?i)dep-(?:class-f[0-9]+|[a-z0-9]+-[0-9]{3})")

FAMILY_ENTRY_RE = re.compile(r"[a-z0-9][a-z0-9_-]*\*?")
PENDING_DECISION_ID_RE = re.compile(r"fss-[a-z0-9]+(?:\.[a-z0-9]+)*")


# ---------------------------------------------------------------------------------------------
# Canonical digests
# ---------------------------------------------------------------------------------------------


def canonicalize_value(val: Any, depth: int = 0, max_depth: int = CONSTITUTION_SCHEMA_MAX_DEPTH) -> Any:
    """Typed canonical form. Nesting deeper than the schema permits is refused (ValueError)."""
    if isinstance(val, (dict, list)) and depth >= max_depth:
        raise ValueError(f"value nests deeper than the schema's structural depth of {max_depth}")
    if isinstance(val, dict):
        return {k: canonicalize_value(v, depth + 1, max_depth) for k, v in sorted(val.items())}
    if isinstance(val, list):
        return [canonicalize_value(x, depth + 1, max_depth) for x in val]
    return val


def _canonical_bytes(payload: Any) -> bytes:
    return json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")


def _sort_rows_by_id(rows: Any) -> Any:
    if not isinstance(rows, list):
        return rows
    return sorted(rows, key=lambda row: (0, str(row.get("id"))) if isinstance(row, dict) else (1, json.dumps(row, sort_keys=True, default=str)))


def compute_canonical_constitution_digest(data: dict[str, Any]) -> str:
    """Digest of every constitution field except freezeDigest; typed values, classes sorted by id."""
    raw_evidence = data.get("releaseEvidence")
    # Evidence items are an unordered set of strings; anything else is digested as given (and is
    # already a shape finding).
    if isinstance(raw_evidence, list) and all(isinstance(x, str) for x in raw_evidence):
        evidence: Any = sorted(raw_evidence)
    else:
        evidence = raw_evidence
    payload = {
        "schema": data.get("schema"),
        "asOf": data.get("asOf"),
        "generation": data.get("generation"),
        "normativePolicy": data.get("normativePolicy"),
        "production": data.get("production"),
        "classes": _sort_rows_by_id(data.get("classes")),
        "releaseEvidence": evidence,
    }
    extra = {k: v for k, v in data.items() if k not in payload and k != "freezeDigest"}
    payload.update(extra)
    return sha256_prefixed(_canonical_bytes(payload))


def compute_canonical_dependencies_digest(data: dict[str, Any]) -> str:
    """Digest of every registry field except freezeDigest; typed values, rows sorted by id."""
    payload = {k: v for k, v in data.items() if k != "freezeDigest"} if isinstance(data, dict) else {}
    if "dependencies" in payload:
        payload["dependencies"] = _sort_rows_by_id(payload["dependencies"])
    return sha256_prefixed(_canonical_bytes(payload))


# ---------------------------------------------------------------------------------------------
# Authority
# ---------------------------------------------------------------------------------------------


@dataclass
class Authority:
    root: Path
    issues: list[DiagnosticError] = field(default_factory=list)
    allowlist: dict[str, Any] | None = None
    allowlist_digest: str | None = None
    constitution: dict[str, Any] | None = None
    constitution_digest: str | None = None
    registry: dict[str, Any] | None = None
    registry_digest: str | None = None
    imports: dict[str, Any] | None = None
    local_qualification: dict[str, Any] | None = None
    resolutions: list[dict[str, Any]] | None = None

    # Derived, well-typed views (empty when the source is unusable).
    def classes(self) -> dict[str, dict[str, Any]]:
        rows = as_dict(self.constitution).get("classes")
        out: dict[str, dict[str, Any]] = {}
        for row in rows if isinstance(rows, list) else []:
            if isinstance(row, dict) and is_str(row.get("id")) and row["id"] not in out:
                out[row["id"]] = row
        return out

    def rows(self) -> list[dict[str, Any]]:
        rows = as_dict(self.registry).get("dependencies")
        return [row for row in rows if isinstance(row, dict) and is_str(row.get("id"))] if isinstance(rows, list) else []

    def production(self) -> dict[str, Any]:
        return as_dict(as_dict(self.constitution).get("production"))

    def admitted_projects(self) -> frozenset[str] | None:
        imports = as_dict(self.imports).get("imports")
        if self.imports is None or not isinstance(imports, list):
            return None
        return frozenset(
            row["project"]
            for row in imports
            if isinstance(row, dict) and row.get("status") == PRODUCTION_ADMITTED_IMPORT_STATUS and is_str(row.get("project"))
        )


def _check_pin(out: list[DiagnosticError], rel: str, generation: Any, computed: str, declared: Any, pins: dict[str, str]) -> None:
    if not isinstance(generation, str) or generation not in pins:
        out.append(issue(ERR_DEP_GENERATION_MISMATCH, rel, "#/generation", f"{rel} generation {generation!r} is not a pinned generation; expected one of {sorted(pins)}"))
    if isinstance(declared, str) and declared != computed:
        out.append(issue(ERR_DEP_DIGEST_MISMATCH, rel, "#/freezeDigest", f"{rel} freezeDigest mismatch: declared {declared!r}, computed {computed!r}"))
    if isinstance(generation, str) and generation in pins and computed != pins[generation]:
        out.append(issue(ERR_DEP_FREEZE_DIVERGENCE, rel, "#/freezeDigest", f"{rel} content diverged from the pinned digest for generation {generation!r}: computed {computed!r}, pinned {pins[generation]!r}"))


def _load_allowlist(auth: Authority, path: Path) -> None:
    rel = ALLOWLIST_TOML_PATH
    value, raw, problems = load_toml_document(path, rel, auth.root)
    auth.issues.extend(problems)
    if raw is not None:
        auth.allowlist_digest = sha256_prefixed(raw)
        schema = value.get("schema") if isinstance(value, dict) else None
        pinned = EXPECTED_ALLOWLIST_DIGESTS.get(schema) if isinstance(schema, str) else None
        if pinned is None or auth.allowlist_digest != pinned:
            auth.issues.append(issue(
                ERR_DEP_ALLOWLIST_DIGEST_DIVERGED, rel, "#",
                f"{rel} bytes diverged from the pinned allowlist digest: computed {auth.allowlist_digest!r}, "
                f"pinned {pinned!r} for schema {schema!r}; an allowlist change needs a reviewed pin update",
            ))
    if value is None:
        return
    validate_shape(value, ALLOWLIST_SPEC, rel, "#", auth.issues)
    auth.allowlist = value
    _check_allowlist_semantics(auth, value)


def _check_allowlist_semantics(auth: Authority, data: dict[str, Any]) -> None:
    rel = ALLOWLIST_TOML_PATH
    out = auth.issues
    if _iso_date(data.get("as_of")) is None and is_str(data.get("as_of")):
        out.append(issue(ERR_DEP_CORRUPT_FILE, rel, "#/as_of", f"as_of {data.get('as_of')!r} is not an ISO calendar date"))
    in_house = as_dict(data.get("in_house"))
    families = str_list(in_house.get("allowed_families"))
    for entry in families:
        if not FAMILY_ENTRY_RE.fullmatch(entry):
            out.append(issue(ERR_DEP_CONST_INVARIANT, rel, "#/in_house/allowed_families", f"in-house family entry {entry!r} is not a crate name or a single trailing-'*' prefix glob; a bare or interior glob would admit unrelated crates"))
    projects = as_dict(in_house.get("projects"))
    mapped: dict[str, str] = {}
    for project, globs in projects.items():
        for glob in str_list(globs):
            if glob in mapped:
                out.append(issue(ERR_DEP_CONST_INVARIANT, rel, f"#/in_house/projects/{project}", f"family entry {glob!r} is mapped to both {mapped[glob]!r} and {project!r}"))
            mapped.setdefault(glob, project)
    if isinstance(in_house.get("projects"), dict) and isinstance(in_house.get("allowed_families"), list):
        for entry in sorted(set(families) - set(mapped)):
            out.append(issue(ERR_DEP_CONST_INVARIANT, rel, "#/in_house/projects", f"in-house family entry {entry!r} has no franken_imports project mapping in [in_house.projects]"))
        for entry in sorted(set(mapped) - set(families)):
            out.append(issue(ERR_DEP_CONST_INVARIANT, rel, "#/in_house/projects", f"[in_house.projects] maps {entry!r}, which is not in allowed_families"))

    fundamental = set(str_list(as_dict(data.get("fundamental")).get("allowed_subject_to_audit")))
    exception = set(str_list(as_dict(data.get("exception_candidates")).get("not_admitted_without_dep_record_adr_and_release_evidence")))
    lab_table = as_dict(data.get("laboratory_oracles"))
    lab = set(str_list(lab_table.get("excluded_from_production_release_closure")))
    forbidden_table = as_dict(data.get("forbidden"))
    forbidden = set(str_list(forbidden_table.get("crates")))

    def family_hits(names: set[str]) -> list[tuple[str, str]]:
        return sorted((name, glob) for name in names for glob in families if fnmatch.fnmatchcase(normalize_crate(name), normalize_crate(glob)))

    for label, names in (("fundamental", fundamental), ("exception_candidates", exception), ("laboratory_oracles", lab), ("forbidden", forbidden)):
        for name, glob in family_hits(names):
            out.append(issue(ERR_DEP_CONST_INVARIANT, rel, "#/in_house/allowed_families", f"in-house family {glob!r} also admits {name!r}, which [{label}] classifies differently"))
    for left_label, left, right_label, right in (
        ("fundamental", fundamental, "forbidden", forbidden),
        ("fundamental", fundamental, "exception_candidates", exception),
        ("fundamental", fundamental, "laboratory_oracles", lab),
        ("exception_candidates", exception, "forbidden", forbidden),
        ("exception_candidates", exception, "laboratory_oracles", lab),
    ):
        for name in sorted(_norm_set(left) & _norm_set(right)):
            out.append(issue(ERR_DEP_CONST_INVARIANT, rel, f"#/{left_label}", f"crate {name!r} is listed in both [{left_label}] and [{right_label}]"))

    if isinstance(forbidden_table.get("crates"), list) and not forbidden:
        out.append(issue(ERR_DEP_CONST_INVARIANT, rel, "#/forbidden/crates", "the closed-universe forbidden crate census is empty"))
    if isinstance(forbidden_table.get("patterns"), list) and not str_list(forbidden_table.get("patterns")):
        out.append(issue(ERR_DEP_CONST_INVARIANT, rel, "#/forbidden/patterns", "the forbidden production pattern census is empty"))

    rows_table = lab_table.get("rows")
    if isinstance(rows_table, dict) and isinstance(lab_table.get("excluded_from_production_release_closure"), list):
        assigned: dict[str, str] = {}
        for row_id, names in rows_table.items():
            for name in str_list(names):
                if name in assigned:
                    out.append(issue(ERR_DEP_CONST_INVARIANT, rel, f"#/laboratory_oracles/rows/{row_id}", f"laboratory oracle {name!r} is assigned to both {assigned[name]!r} and {row_id!r}"))
                assigned.setdefault(name, row_id)
        for name in sorted(lab - set(assigned)):
            out.append(issue(ERR_DEP_CONST_INVARIANT, rel, "#/laboratory_oracles/rows", f"laboratory oracle {name!r} is not assigned to a DEP-CLASS-F4 registry row"))
        for name in sorted(set(assigned) - lab):
            out.append(issue(ERR_DEP_CONST_INVARIANT, rel, "#/laboratory_oracles/rows", f"[laboratory_oracles.rows] assigns {name!r}, which is not in excluded_from_production_release_closure"))

    pending_owner: dict[str, str] = {}
    for decision, record in as_dict(data.get("pending_owner_decisions")).items():
        if not PENDING_DECISION_ID_RE.fullmatch(decision):
            out.append(issue(ERR_DEP_CONST_INVARIANT, rel, f"#/pending_owner_decisions/{decision}", f"pending decision id {decision!r} is not a tracker id (fss-...)"))
        record = as_dict(record)
        for crate in str_list(record.get("crates")):
            if crate in pending_owner:
                out.append(issue(ERR_DEP_CONST_INVARIANT, rel, f"#/pending_owner_decisions/{decision}", f"crate {crate!r} is pending under both {pending_owner[crate]!r} and {decision!r}"))
            pending_owner.setdefault(crate, decision)
            if crate not in fundamental:
                out.append(issue(ERR_DEP_CONST_INVARIANT, rel, f"#/pending_owner_decisions/{decision}", f"pending crate {crate!r} is not in [fundamental]; the open decision concerns a fundamental admission"))
            if normalize_crate(crate) in _norm_set(forbidden):
                out.append(issue(ERR_DEP_CONST_INVARIANT, rel, "#/forbidden/crates", f"crate {crate!r} is pending owner decision {decision!r} but [forbidden] already rejects it; that decides the open question"))
            if normalize_crate(crate) in _norm_set(exception | lab):
                out.append(issue(ERR_DEP_CONST_INVARIANT, rel, f"#/pending_owner_decisions/{decision}", f"pending crate {crate!r} is also classified by another allowlist table"))


def normalize_crate(name: str) -> str:
    """Cargo treats '-' and '_' in package names as the same name."""
    return name.strip().lower().replace("_", "-")


def _norm_set(names: set[str]) -> set[str]:
    return {normalize_crate(name) for name in names}


def _load_constitution(auth: Authority, path: Path) -> None:
    rel = CONSTITUTION_JSON_PATH
    value, _raw, problems = load_json_document(path, rel, auth.root)
    auth.issues.extend(problems)
    if value is None:
        return
    validate_shape(value, CONSTITUTION_SPEC, rel, "#", auth.issues)
    auth.constitution = value
    auth.constitution_digest = compute_canonical_constitution_digest(value)
    _check_pin(auth.issues, rel, value.get("generation"), auth.constitution_digest, value.get("freezeDigest"), EXPECTED_CONSTITUTION_DIGESTS)
    _check_constitution_semantics(auth, value)


def _check_constitution_semantics(auth: Authority, data: dict[str, Any]) -> None:
    rel = CONSTITUTION_JSON_PATH
    out = auth.issues
    if is_str(data.get("asOf")) and _iso_date(data.get("asOf")) is None:
        out.append(issue(ERR_DEP_CORRUPT_FILE, rel, "#/asOf", f"asOf {data.get('asOf')!r} is not an ISO calendar date"))
    if is_str(data.get("normativePolicy")) and data["normativePolicy"] != ALLOWLIST_TOML_PATH:
        out.append(issue(ERR_DEP_CONST_INVARIANT, rel, "#/normativePolicy", f"normativePolicy {data['normativePolicy']!r} is not the machine allowlist {ALLOWLIST_TOML_PATH!r}"))

    generation = data.get("generation")
    baseline_classes = PINNED_CONSTITUTION_CLASSES.get(generation) if isinstance(generation, str) else None
    baseline_production = PINNED_CONSTITUTION_PRODUCTION.get(generation) if isinstance(generation, str) else None

    production = as_dict(data.get("production"))
    language = production.get("language")
    if is_str(language) and not CONSTITUTION_LANGUAGE_RE.fullmatch(language):
        out.append(issue(ERR_DEP_CONST_INVARIANT, rel, "#/production/language", f"DEP-CLASS-F0 production language {language!r} is not a Rust edition (rust-YYYY)"))
    for key, vocabulary in (("toolchain", CONSTITUTION_TOOLCHAIN_VALUES), ("unsafe", CONSTITUTION_UNSAFE_VALUES), ("asyncRuntime", CONSTITUTION_ASYNC_RUNTIME_VALUES)):
        if is_str(production.get(key)) and production[key] not in vocabulary:
            out.append(issue(ERR_DEP_CONST_INVARIANT, rel, f"#/production/{key}", f"production.{key} value {production[key]!r} is outside the interpreted vocabulary {sorted(vocabulary)}"))
    if baseline_production is not None:
        for key, pinned in baseline_production.items():
            if key in production and not _typed_equal(production[key], pinned):
                out.append(issue(ERR_DEP_CONST_INVARIANT, rel, f"#/production/{key}", f"Production invariant violation for {key!r}: pinned {pinned!r}, got {production[key]!r}"))

    classes = data.get("classes")
    seen: dict[str, str] = {}
    constitutional: list[str] = []
    for index, row in enumerate(classes if isinstance(classes, list) else []):
        if not isinstance(row, dict) or not is_str(row.get("id")):
            continue
        class_id = row["id"]
        target = f"#/classes/{class_id}"
        if not CLASS_ID_RE.fullmatch(class_id):
            out.append(issue(ERR_DEP_CONST_INVARIANT, rel, f"{target}/id", f"Class ID {class_id!r} does not conform to DEP-CLASS-F<n>"))
        if class_id in seen:
            out.append(issue(ERR_DEP_STABLE_ID_REUSED, rel, f"{target}/id", f"Duplicate class ID {class_id!r} in classes list"))
        elif class_id.lower() in {k.lower() for k in seen}:
            out.append(issue(ERR_DEP_STABLE_ID_REUSED, rel, f"{target}/id", f"Case-colliding class ID {class_id!r} conflicts with an existing class"))
        seen.setdefault(class_id, class_id)
        admission = row.get("admission")
        if is_str(admission):
            if admission == ADMISSION_CONSTITUTIONAL:
                constitutional.append(class_id)
            elif admission not in (ADMISSION_IMPORT_GATE, ADMISSION_DEP_RECORD, ADMISSION_QUARANTINE) and not GATE_ID_RE.fullmatch(admission):
                out.append(issue(ERR_DEP_CONST_INVARIANT, rel, f"{target}/admission", f"Class {class_id!r} admission {admission!r} is outside the interpreted admission vocabulary"))
        if baseline_classes is not None:
            pinned = baseline_classes.get(class_id)
            if pinned is None:
                out.append(issue(ERR_DEP_CONST_INVARIANT, rel, f"{target}/id", f"Class {class_id!r} is not in the pinned class baseline for generation {generation!r}"))
            else:
                for key in ("name", "admission"):
                    if row.get(key) != pinned[key]:
                        out.append(issue(ERR_DEP_CONST_INVARIANT, rel, f"{target}/{key}", f"Class {class_id!r} {key} mismatch: pinned {pinned[key]!r}, got {row.get(key)!r}"))
    if baseline_classes is not None and isinstance(classes, list):
        for class_id in baseline_classes:
            if class_id not in seen:
                out.append(issue(ERR_DEP_CONST_INVARIANT, rel, f"#/classes/{class_id}", f"Pinned class {class_id!r} is missing from classes"))
        if len(classes) != len(baseline_classes):
            out.append(issue(ERR_DEP_CONST_INVARIANT, rel, "#/classes", f"Class count {len(classes)} differs from the pinned baseline count {len(baseline_classes)}"))
    if isinstance(classes, list) and len(constitutional) != 1:
        out.append(issue(ERR_DEP_CONST_INVARIANT, rel, "#/classes", f"exactly one class must carry the 'constitutional' admission (DEP-CLASS-F0 rust-language-and-stdlib); found {constitutional}"))


def _typed_equal(left: Any, right: Any) -> bool:
    return type(left) is type(right) and left == right


def _load_registry(auth: Authority, path: Path) -> None:
    rel = DEPENDENCIES_JSON_PATH
    value, _raw, problems = load_json_document(path, rel, auth.root)
    auth.issues.extend(problems)
    if value is None:
        return
    validate_shape(value, REGISTRY_SPEC, rel, "#", auth.issues)
    auth.registry = value
    auth.registry_digest = compute_canonical_dependencies_digest(value)
    _check_pin(auth.issues, rel, value.get("generation"), auth.registry_digest, value.get("freezeDigest"), EXPECTED_DEPENDENCIES_DIGESTS)
    out = auth.issues
    if is_str(value.get("schema")) and value["schema"] != REGISTRY_SCHEMA:
        out.append(issue(ERR_DEP_REGISTRY_DRIFT, rel, "#/schema", f"registry schema must be {REGISTRY_SCHEMA!r}, observed {value['schema']!r}"))
    if is_str(value.get("sourceDocument")) and value["sourceDocument"] != DEPENDENCIES_MD_PATH:
        out.append(issue(ERR_DEP_REGISTRY_DRIFT, rel, "#/sourceDocument", f"sourceDocument must be {DEPENDENCIES_MD_PATH!r}, observed {value['sourceDocument']!r}"))
    if is_str(value.get("constitution")) and value["constitution"] != CONSTITUTION_JSON_PATH:
        out.append(issue(ERR_DEP_CONST_INVARIANT, rel, "#/constitution", f"constitution must reference the class registry {CONSTITUTION_JSON_PATH!r}, observed {value['constitution']!r}"))
    if is_str(value.get("policy")) and value["policy"] != ALLOWLIST_TOML_PATH:
        out.append(issue(ERR_DEP_CONST_INVARIANT, rel, "#/policy", f"policy must reference the machine allowlist {ALLOWLIST_TOML_PATH!r}, observed {value['policy']!r}"))

    rows = value.get("dependencies")
    seen: set[str] = set()
    seen_lower: set[str] = set()
    for index, row in enumerate(rows if isinstance(rows, list) else []):
        if not isinstance(row, dict) or not is_str(row.get("id")):
            continue
        dep_id = row["id"]
        target = f"#/dependencies[{index}]"
        if not DEP_ID_RE.fullmatch(dep_id):
            out.append(issue(ERR_DEP_STABLE_ID_REUSED, rel, f"{target}/id", f"Dependency ID {dep_id!r} does not match DEP-[A-Z0-9]+-[0-9]{{3}}"))
        if dep_id in seen or dep_id.lower() in seen_lower:
            out.append(issue(ERR_DEP_STABLE_ID_REUSED, rel, f"{target}/id", f"Duplicate or case-colliding dependency ID {dep_id!r}"))
        seen.add(dep_id)
        seen_lower.add(dep_id.lower())
        scope = row.get("scope")
        if is_str(scope) and scope not in SCOPE_LANES:
            out.append(issue(ERR_DEP_CONST_INVARIANT, rel, f"{target}/scope", f"Dependency {dep_id!r} scope {scope!r} is outside the scope vocabulary {sorted(SCOPE_LANES)}"))
        status = row.get("status")
        if is_str(status):
            if status not in ROW_STATUSES:
                out.append(issue(ERR_DEP_TOMBSTONE_INVALID, rel, f"{target}/status", f"Dependency {dep_id!r} status {status!r} is outside {list(ROW_STATUSES)}"))
            superseded_by = row.get("supersededBy")
            decision = row.get("tombstoneDecision")
            if status == "active" and (superseded_by is not None or decision is not None):
                out.append(issue(ERR_DEP_TOMBSTONE_INVALID, rel, target, f"active dependency {dep_id!r} carries supersededBy/tombstoneDecision"))
            if status in ("tombstoned", "superseded") and not is_str(decision):
                out.append(issue(ERR_DEP_TOMBSTONE_INVALID, rel, f"{target}/tombstoneDecision", f"retired dependency {dep_id!r} must name its tombstone decision (ADR/compatibility record)"))
            if status == "tombstoned" and superseded_by is not None:
                out.append(issue(ERR_DEP_TOMBSTONE_INVALID, rel, f"{target}/supersededBy", f"tombstoned dependency {dep_id!r} has a successor; use status 'superseded'"))
            if status == "superseded" and not is_str(superseded_by):
                out.append(issue(ERR_DEP_TOMBSTONE_INVALID, rel, f"{target}/supersededBy", f"superseded dependency {dep_id!r} must name its successor"))
    by_id = {row["id"]: row for row in auth.rows()}
    for row in auth.rows():
        successor = row.get("supersededBy")
        if row.get("status") == "superseded" and is_str(successor):
            target_row = by_id.get(successor)
            if successor == row["id"] or target_row is None or target_row.get("status") != "active":
                out.append(issue(ERR_DEP_TOMBSTONE_INVALID, rel, f"#/{row['id']}/supersededBy", f"superseded dependency {row['id']!r} successor {successor!r} is not a different active row"))


def _load_imports(auth: Authority, path: Path) -> None:
    rel = FRANKEN_IMPORTS_PATH
    value, _raw, problems = load_json_document(path, rel, auth.root)
    auth.issues.extend(problems)
    if value is None:
        return
    validate_shape(value, IMPORTS_SPEC, rel, "#", auth.issues)
    auth.imports = value
    seen: set[str] = set()
    for index, row in enumerate(value.get("imports") if isinstance(value.get("imports"), list) else []):
        if not isinstance(row, dict):
            continue
        if is_str(row.get("id")):
            if row["id"] in seen:
                auth.issues.append(issue(ERR_DEP_STABLE_ID_REUSED, rel, f"#/imports[{index}]/id", f"duplicate import id {row['id']!r}"))
            seen.add(row["id"])
        status = row.get("status")
        if is_str(status) and status not in IMPORT_STATUSES:
            auth.issues.append(issue(ERR_DEP_CORRUPT_FILE, rel, f"#/imports[{index}]/status", f"import {row.get('id')!r} status {status!r} is outside the admission lifecycle {list(IMPORT_STATUSES)}"))


LOCAL_QUALIFICATION_KEYS: dict[str, Any] = {
    "authority": Str(),
    "github_hosted_required": Bool(),
    "offline_after_provisioning": Bool(),
}


def _load_local_qualification(auth: Authority, path: Path) -> None:
    rel = LOCAL_QUALIFICATION_PATH
    value, _raw, problems = load_toml_document(path, rel, auth.root)
    auth.issues.extend(problems)
    if value is None:
        return
    # Only the keys this authority reads are typed here; the file is owned by the qualification contract.
    for key, spec in LOCAL_QUALIFICATION_KEYS.items():
        if key not in value:
            auth.issues.append(issue(ERR_DEP_MISSING_FIELD, rel, f"#/{key}", f"{rel} lacks {key!r}"))
        else:
            validate_shape(value[key], spec, rel, f"#/{key}", auth.issues)
    toolchain = value.get("toolchain")
    if not isinstance(toolchain, dict) or "components" not in toolchain:
        auth.issues.append(issue(ERR_DEP_MISSING_FIELD, rel, "#/toolchain/components", f"{rel} lacks [toolchain].components"))
    else:
        validate_shape(toolchain["components"], List(Str()), rel, "#/toolchain/components", auth.issues)
    auth.local_qualification = value


def _load_resolutions(auth: Authority, path: Path) -> None:
    rel = STABLE_ID_RESOLUTION_PATH
    value, _raw, problems = load_json_document(path, rel, auth.root)
    auth.issues.extend(problems)
    if value is None:
        return
    resolutions = value.get("resolutions")
    if not isinstance(resolutions, list):
        auth.issues.append(issue(ERR_DEP_CORRUPT_FILE, rel, "#/resolutions", "Field 'resolutions' must be a JSON list"))
        return
    good: list[dict[str, Any]] = []
    for index, row in enumerate(resolutions):
        if not isinstance(row, dict):
            auth.issues.append(issue(ERR_DEP_CORRUPT_FILE, rel, f"#/resolutions[{index}]", f"resolution entry {index} must be an object, found {type(row).__name__}"))
            continue
        if not is_str(row.get("legacyId")):
            # Without a string legacyId the entry's scope is unknowable; it could retire a dependency id.
            auth.issues.append(issue(ERR_DEP_CORRUPT_FILE, rel, f"#/resolutions[{index}]/legacyId", f"resolution entry {index} lacks a string legacyId, found {row.get('legacyId')!r}"))
            continue
        good.append(row)
    auth.resolutions = good


# Allowlist flag -> expected value derived from the constitution production object and the local
# qualification contract. This is the crosswalk between the two vocabularies; the values come from
# the files, not from this table.
FLAG_RELATIONS: dict[str, tuple[str, Callable[[dict[str, Any], dict[str, Any]], Any]]] = {
    "closed_universe": ("production.closedUniverse", lambda p, q: p.get("closedUniverse")),
    "direct_crates_must_be_allowlisted": ("production.closedUniverse", lambda p, q: p.get("closedUniverse")),
    "transitive_closure_must_be_censused": ("production.closedUniverse", lambda p, q: p.get("closedUniverse")),
    "new_external_dependency_requires_dep_record_and_adr": ("production.closedUniverse", lambda p, q: p.get("closedUniverse")),
    "fss_crates_must_forbid_unsafe": ("production.unsafe", lambda p, q: _in(p.get("unsafe"), CONSTITUTION_UNSAFE_VALUES)),
    "fss_unsafe_exceptions_allowed": ("production.unsafe", lambda p, q: _negate(_in(p.get("unsafe"), CONSTITUTION_UNSAFE_VALUES))),
    "c_or_cpp_ffi_allowed": ("production.cCppFfi", lambda p, q: p.get("cCppFfi")),
    "dynamic_loading_allowed": ("production.dynamicLoading", lambda p, q: p.get("dynamicLoading")),
    "foreign_runtime_production_boundary_allowed": ("production.foreignExecutables", lambda p, q: p.get("foreignExecutables")),
    "foreign_executables_allowed_in_production": ("production.foreignExecutables", lambda p, q: p.get("foreignExecutables")),
    "release_resolution_must_be_locked_and_offline": ("production.lockedOfflineReleaseResolution", lambda p, q: p.get("lockedOfflineReleaseResolution")),
    "build_scripts_may_not_use_network": (
        "production.lockedOfflineReleaseResolution and local_qualification.offline_after_provisioning",
        lambda p, q: _and(p.get("lockedOfflineReleaseResolution"), q.get("offline_after_provisioning")),
    ),
    "runtime_acquisition_allowed": ("production.runtimeAcquisition", lambda p, q: p.get("runtimeAcquisition")),
    "serde_may_not_define_durable_bytes": ("production.serdeDurableFormatAuthority", lambda p, q: _negate(p.get("serdeDurableFormatAuthority"))),
    "hosted_ci_is_not_release_authority": (
        "local_qualification.github_hosted_required == false and authority == local_dsr_receipt",
        lambda p, q: _and(_negate(q.get("github_hosted_required")), q.get("authority") == "local_dsr_receipt" if is_str(q.get("authority")) else None),
    ),
    "asupersync_is_only_async_runtime": ("production.asyncRuntime", lambda p, q: _in(p.get("asyncRuntime"), CONSTITUTION_ASYNC_RUNTIME_VALUES)),
}


def _in(value: Any, vocabulary: frozenset[str]) -> bool | None:
    return value in vocabulary if isinstance(value, str) else None


def _negate(value: Any) -> bool | None:
    return (not value) if type(value) is bool else None


def _and(left: Any, right: Any) -> bool | None:
    if type(left) is not bool or type(right) is not bool:
        return None
    return left and right


def expected_policy_flags(auth: Authority) -> dict[str, bool] | None:
    """The 16 allowlist flag values the constitution and the local qualification contract require.

    This is the single derivation used by the crosswalk, dependency_audit (DEP-AUD-001/002) and
    check-policy; None when a source value is missing or untyped (callers fail closed).
    """
    if auth.constitution is None or auth.local_qualification is None:
        return None
    production = auth.production()
    localq = as_dict(auth.local_qualification)
    expected: dict[str, bool] = {}
    for flag, (_source, relation) in FLAG_RELATIONS.items():
        value = relation(production, localq)
        if type(value) is not bool:
            return None
        expected[flag] = value
    return expected


def load_policy_document(path: Path, root: Path) -> tuple[dict[str, Any] | None, list[DiagnosticError]]:
    """Strict allowlist read for dependency_audit and check-policy (no plain TOML reads remain).

    Every allowlist is read bounded, UTF-8-strict, duplicate-key-free and symlink-refusing. The
    repository's own allowlist is additionally held to the authority's pinned digest, exact shape and
    semantics; any finding makes it unusable (None). Fixture allowlists elsewhere are only parsed strictly.
    """
    try:
        is_repository_allowlist = path.resolve() == (ROOT / ALLOWLIST_TOML_PATH).resolve()
    except OSError:
        is_repository_allowlist = False
    if is_repository_allowlist:
        auth = Authority(root=ROOT)
        _load_allowlist(auth, ROOT / ALLOWLIST_TOML_PATH)
        return (auth.allowlist if not auth.issues else None), list(auth.issues)
    try:
        rel = path.relative_to(root).as_posix()
    except ValueError:
        rel = str(path)
    value, _raw, problems = load_toml_document(path, rel, root)
    return value, problems


def _check_row_class(auth: Authority, out: list[DiagnosticError], row: dict[str, Any], class_id: str, field: str,
                     producers: list[str], scope: Any, lanes: Any) -> None:
    """Admission consequences of one constitution class a registry row maps to."""
    registry_rel = DEPENDENCIES_JSON_PATH
    dep_id = row["id"]
    klass = auth.classes().get(class_id)
    if klass is None:
        if auth.constitution is not None:
            out.append(issue(ERR_DEP_CONST_INVARIANT, registry_rel, f"row/{dep_id}/{field}", f"Dependency {dep_id!r} references unknown constitution class {class_id!r}"))
        return
    admission = klass.get("admission")
    if not is_str(admission):
        return
    if admission == ADMISSION_CONSTITUTIONAL:
        out.append(issue(ERR_DEP_CONST_INVARIANT, registry_rel, f"row/{dep_id}/{field}", f"Dependency {dep_id!r} maps to the constitutional language class {class_id!r}; F0 is the Rust language and standard library, not a crate dependency class"))
    if admission == ADMISSION_QUARANTINE and lanes is not None and "production" in lanes:
        out.append(issue(ERR_DEP_CONST_INVARIANT, registry_rel, f"row/{dep_id}/scope", f"Dependency {dep_id!r} maps to quarantine class {class_id!r} but scope {scope!r} admits production"))
    if admission == ADMISSION_DEP_RECORD and scope == "Production":
        out.append(issue(ERR_DEP_CONST_INVARIANT, registry_rel, f"row/{dep_id}/scope", f"Dependency {dep_id!r} maps to {class_id!r} (admission {admission!r}) but its scope 'Production' drops the audit condition"))
    if (admission == ADMISSION_IMPORT_GATE or GATE_ID_RE.fullmatch(admission)) and FRANKEN_IMPORTS_PATH not in producers:
        out.append(issue(ERR_DEP_CONST_INVARIANT, registry_rel, f"row/{dep_id}/producers", f"Dependency {dep_id!r} maps to gated class {class_id!r} but does not name the import-gate registry {FRANKEN_IMPORTS_PATH!r} as a producer"))


def _check_crosswalk(auth: Authority) -> None:
    out = auth.issues
    allow = as_dict(auth.allowlist)
    policy = as_dict(allow.get("policy"))
    production = auth.production()
    localq = as_dict(auth.local_qualification)
    if auth.allowlist is not None and auth.constitution is not None:
        for flag, (source, relation) in FLAG_RELATIONS.items():
            expected = relation(production, localq)
            actual = policy.get(flag)
            if type(actual) is not bool or type(expected) is not bool:
                continue  # type problems are already reported by shape validation
            if actual != expected:
                out.append(issue(ERR_DEP_CONST_INVARIANT, ALLOWLIST_TOML_PATH, f"#/policy/{flag}", f"dependency_allowlist.toml policy.{flag} = {actual!r} contradicts {source} (expected {expected!r})"))

    classes = auth.classes()
    rows = auth.rows()
    registry_rel = DEPENDENCIES_JSON_PATH
    table_claims: dict[str, list[str]] = {}
    covered: set[str] = set()
    for row in rows:
        if not is_str(row.get("constitutionClass")):
            out.append(issue(ERR_DEP_CONST_INVARIANT, registry_rel, f"row/{row['id']}/constitutionClass", f"Dependency {row['id']!r} has no DEP-CLASS reference; every registry row must map to a constitution class"))
        dep_id = row["id"]
        active = row.get("status") == "active"
        primary = row.get("constitutionClass")
        listed = row.get("constitutionClasses")
        row_classes = [c for c in listed if is_str(c)] if isinstance(listed, list) else ([primary] if is_str(primary) else [])
        if isinstance(listed, list) and is_str(primary) and (not row_classes or row_classes[0] != primary or len(set(row_classes)) != len(row_classes)):
            out.append(issue(ERR_DEP_CONST_INVARIANT, registry_rel, f"row/{dep_id}/constitutionClasses", f"Dependency {dep_id!r} constitutionClasses {listed!r} must be unique class ids led by its primary constitutionClass {primary!r}"))
        if active:
            covered.update(row_classes)
        producers = str_list(row.get("producers"))
        scope = row.get("scope")
        lanes = SCOPE_LANES.get(scope) if is_str(scope) else None
        for class_id in dict.fromkeys(row_classes):
            _check_row_class(auth, out, row, class_id, "constitutionClass" if class_id == primary else "constitutionClasses", producers, scope, lanes)
        for producer in producers:
            path, _, table = producer.partition("#")
            if table and path == ALLOWLIST_TOML_PATH:
                if table not in CLASSIFICATION_TABLES:
                    out.append(issue(ERR_DEP_CONST_INVARIANT, registry_rel, f"row/{dep_id}/producers", f"Dependency {dep_id!r} producer {producer!r} names allowlist table {table!r}, which classifies nothing"))
                elif active and dep_id not in table_claims.setdefault(table, []):
                    table_claims[table].append(dep_id)
    if auth.registry is not None and auth.allowlist is not None:
        lab_rows = sorted(as_dict(as_dict(allow.get("laboratory_oracles")).get("rows")))
        for table in CLASSIFICATION_TABLES:
            claimants = sorted(table_claims.get(table, []))
            if not claimants:
                out.append(issue(ERR_DEP_CONST_INVARIANT, registry_rel, "#/dependencies", f"allowlist table [{table}] is not produced into any active dependency row"))
            elif table == "laboratory_oracles":
                if claimants != lab_rows:
                    out.append(issue(ERR_DEP_CONST_INVARIANT, ALLOWLIST_TOML_PATH, "#/laboratory_oracles/rows", f"[laboratory_oracles.rows] keys {lab_rows} differ from the registry rows producing [laboratory_oracles] {claimants}"))
                for row_id in claimants:
                    klass = classes.get(next((r.get("constitutionClass") for r in rows if r["id"] == row_id), ""), {})
                    if klass and klass.get("admission") != ADMISSION_QUARANTINE:
                        out.append(issue(ERR_DEP_CONST_INVARIANT, registry_rel, f"row/{row_id}/constitutionClass", f"laboratory oracle row {row_id!r} is not mapped to the quarantine class"))
            elif len(claimants) > 1:
                out.append(issue(ERR_DEP_CONST_INVARIANT, registry_rel, "#/dependencies", f"allowlist table [{table}] is produced into several rows {claimants}; only [laboratory_oracles] has a per-row split"))
        fundamental_row = table_claims.get("fundamental", [None])[0]
        for decision, record in as_dict(allow.get("pending_owner_decisions")).items():
            row_id = as_dict(record).get("registry_row")
            if is_str(row_id) and (row_id != fundamental_row or row_id not in table_claims.get("pending_owner_decisions", [])):
                out.append(issue(ERR_DEP_CONST_INVARIANT, ALLOWLIST_TOML_PATH, f"#/pending_owner_decisions/{decision}/registry_row", f"pending decision {decision!r} names registry row {row_id!r}, which is not the active row producing both [fundamental] and [pending_owner_decisions]"))
    if auth.registry is not None and auth.constitution is not None:
        gates = {r.get("gate") for r in as_dict(auth.imports).get("imports", []) if isinstance(r, dict)} if isinstance(as_dict(auth.imports).get("imports"), list) else None
        for class_id, klass in classes.items():
            admission = klass.get("admission")
            if admission != ADMISSION_CONSTITUTIONAL and class_id not in covered:
                out.append(issue(ERR_DEP_CONST_INVARIANT, registry_rel, "#/dependencies", f"constitution class {class_id!r} ({klass.get('name')!r}) is not mapped by any active registry row; every non-constitutional class needs one"))
            if is_str(admission) and GATE_ID_RE.fullmatch(admission) and gates is not None and admission not in gates:
                out.append(issue(ERR_DEP_CONST_INVARIANT, FRANKEN_IMPORTS_PATH, "#/imports", f"constitution class {class_id!r} is admitted by gate {admission!r}, but no import record in {FRANKEN_IMPORTS_PATH} carries that gate"))
        policy_ref = as_dict(auth.registry).get("policy")
        normative = as_dict(auth.constitution).get("normativePolicy")
        if is_str(policy_ref) and is_str(normative) and policy_ref != normative:
            out.append(issue(ERR_DEP_CONST_INVARIANT, registry_rel, "#/policy", f"registry policy {policy_ref!r} differs from constitution normativePolicy {normative!r}"))


def _check_tombstones(auth: Authority) -> None:
    if auth.resolutions is None:
        return
    rel = STABLE_ID_RESOLUTION_PATH
    out = auth.issues
    rows = {row["id"]: row for row in auth.rows()}
    classes = auth.classes()
    retired_resolutions: dict[str, dict[str, Any]] = {}
    for index, row in enumerate(auth.resolutions):
        legacy = row.get("legacyId")
        canonical = row.get("canonicalId")
        dep_scope = any(isinstance(v, str) and DEP_SHAPED_RE.fullmatch(v.strip()) for v in (legacy, canonical))
        if not dep_scope:
            continue
        target = f"#/resolutions[{index}]"
        problems: list[str] = []
        for key in ("legacyId", "canonicalId", "status", "disposition"):
            if key in row and not isinstance(row[key], str):
                problems.append(f"{key} must be a string")
        status = row.get("status")
        disposition = row.get("disposition")
        if not is_str(legacy) or not (DEP_ID_RE.fullmatch(legacy) or CLASS_ID_RE.fullmatch(legacy)):
            problems.append(f"legacyId {legacy!r} is not an exact dependency identifier")
        if not isinstance(status, str) or status not in RESOLUTION_STATUSES:
            problems.append(f"status {status!r} is outside {sorted(RESOLUTION_STATUSES)} (exact lowercase)")
        if disposition is not None and (not isinstance(disposition, str) or disposition not in RESOLUTION_DISPOSITIONS):
            problems.append(f"disposition {disposition!r} is outside {sorted(RESOLUTION_DISPOSITIONS)} (exact lowercase)")
        status_retires = isinstance(status, str) and status in RETIRING_VALUES
        disposition_retires = isinstance(disposition, str) and disposition in RETIRING_VALUES
        if isinstance(status, str) and isinstance(disposition, str) and status_retires != disposition_retires:
            problems.append(f"status {status!r} and disposition {disposition!r} contradict each other")
        if problems:
            out.append(issue(ERR_DEP_TOMBSTONE_INVALID, rel, target, f"stable-ID resolution for {legacy!r} is malformed: " + "; ".join(problems)))
            continue
        if not (status_retires or disposition_retires):
            continue
        retired_resolutions[legacy] = row
        if legacy in classes:
            out.append(issue(ERR_DEP_STABLE_ID_REUSED, CONSTITUTION_JSON_PATH, f"#/classes/{legacy}", f"Attempted to resurrect tombstoned identifier {legacy!r} as an active class"))
        dep_row = rows.get(legacy)
        if dep_row is not None and dep_row.get("status") == "active":
            out.append(issue(ERR_DEP_STABLE_ID_REUSED, DEPENDENCIES_JSON_PATH, f"row/{legacy}", f"Dependency ID {legacy!r} is tombstoned in {rel} and cannot be used as an active row"))
        if "superseded" in (status, disposition) and dep_row is not None and dep_row.get("status") == "superseded" and canonical != dep_row.get("supersededBy"):
            out.append(issue(ERR_DEP_TOMBSTONE_INVALID, rel, target, f"supersession of {legacy!r} names {canonical!r} but the registry row names {dep_row.get('supersededBy')!r}"))
    for dep_id, row in rows.items():
        if row.get("status") in ("tombstoned", "superseded") and dep_id not in retired_resolutions:
            out.append(issue(ERR_DEP_TOMBSTONE_INVALID, DEPENDENCIES_JSON_PATH, f"row/{dep_id}/status", f"retired dependency {dep_id!r} has no explicit tombstone/supersession record in {rel}"))


def load_authority(root: Path = ROOT, overrides: dict[str, Path] | None = None) -> Authority:
    """Loads, pins and cross-checks the whole dependency authority rooted at ``root``."""
    overrides = overrides or {}
    auth = Authority(root=root)

    def path_of(rel: str) -> Path:
        return overrides.get(rel, root / rel)

    _load_allowlist(auth, path_of(ALLOWLIST_TOML_PATH))
    _load_constitution(auth, path_of(CONSTITUTION_JSON_PATH))
    _load_registry(auth, path_of(DEPENDENCIES_JSON_PATH))
    _load_imports(auth, path_of(FRANKEN_IMPORTS_PATH))
    _load_local_qualification(auth, path_of(LOCAL_QUALIFICATION_PATH))
    _load_resolutions(auth, path_of(STABLE_ID_RESOLUTION_PATH))
    _check_crosswalk(auth)
    _check_tombstones(auth)
    return auth


# ---------------------------------------------------------------------------------------------
# Classification (the single implementation shared by dependency_audit and the checkers)
# ---------------------------------------------------------------------------------------------


@dataclass(frozen=True)
class ClassView:
    families: tuple[str, ...]
    project_of_entry: dict[str, str]
    fundamental: frozenset[str]
    pending: dict[str, tuple[str, str]]  # normalized crate -> (decision, registry row)
    lab: frozenset[str]
    lab_row_of: dict[str, str]
    exception: frozenset[str]
    forbidden: frozenset[str]
    table_rows: dict[str, tuple[str, ...]]
    row_scope: dict[str, str]
    row_order: tuple[str, ...]


@dataclass(frozen=True)
class Classification:
    kind: str  # member | admitted | pending | forbidden | gate | scope | unassigned | unclassified
    row: str | None
    reason: str | None
    decision: str | None = None


def _view_parts_from_allowlist(data: dict[str, Any]) -> dict[str, Any]:
    parts: dict[str, Any] = {}
    in_house = data.get("in_house")
    if isinstance(in_house, dict):
        if isinstance(in_house.get("allowed_families"), list):
            parts["families"] = tuple(str_list(in_house["allowed_families"]))
        if isinstance(in_house.get("projects"), dict):
            parts["project_of_entry"] = {entry: project for project, entries in in_house["projects"].items() for entry in str_list(entries)}
    fundamental = data.get("fundamental")
    if isinstance(fundamental, dict) and isinstance(fundamental.get("allowed_subject_to_audit"), list):
        parts["fundamental"] = frozenset(_norm_set(set(str_list(fundamental["allowed_subject_to_audit"]))))
    if isinstance(data.get("pending_owner_decisions"), dict):
        pending: dict[str, tuple[str, str]] = {}
        for decision, record in data["pending_owner_decisions"].items():
            record = as_dict(record)
            row = record.get("registry_row") if is_str(record.get("registry_row")) else ""
            for crate in str_list(record.get("crates")):
                pending.setdefault(normalize_crate(crate), (decision, row))
        parts["pending"] = pending
    lab = data.get("laboratory_oracles")
    if isinstance(lab, dict):
        if isinstance(lab.get("excluded_from_production_release_closure"), list):
            parts["lab"] = frozenset(_norm_set(set(str_list(lab["excluded_from_production_release_closure"]))))
        if isinstance(lab.get("rows"), dict):
            parts["lab_row_of"] = {normalize_crate(name): row for row, names in lab["rows"].items() for name in str_list(names)}
    exception = data.get("exception_candidates")
    if isinstance(exception, dict) and isinstance(exception.get("not_admitted_without_dep_record_adr_and_release_evidence"), list):
        parts["exception"] = frozenset(_norm_set(set(str_list(exception["not_admitted_without_dep_record_adr_and_release_evidence"]))))
    forbidden = data.get("forbidden")
    if isinstance(forbidden, dict) and isinstance(forbidden.get("crates"), list):
        parts["forbidden"] = frozenset(_norm_set(set(str_list(forbidden["crates"]))))
    return parts


def _view_parts_from_registry(auth: Authority) -> dict[str, Any]:
    table_rows: dict[str, list[str]] = {}
    row_scope: dict[str, str] = {}
    order: list[str] = []
    for row in auth.rows():
        order.append(row["id"])
        if is_str(row.get("scope")):
            row_scope[row["id"]] = row["scope"]
        if row.get("status") != "active":
            continue
        for producer in str_list(row.get("producers")):
            path, _, table = producer.partition("#")
            if path == ALLOWLIST_TOML_PATH and table in CLASSIFICATION_TABLES:
                table_rows.setdefault(table, []).append(row["id"])
    return {"table_rows": {k: tuple(v) for k, v in table_rows.items()}, "row_scope": row_scope, "row_order": tuple(order)}


def build_class_view(auth: Authority) -> ClassView | None:
    """Class view from a loaded authority; None when the authority cannot drive classification."""
    if auth.allowlist is None or auth.registry is None:
        return None
    parts = _view_parts_from_allowlist(auth.allowlist)
    parts.update(_view_parts_from_registry(auth))
    return _complete_view(parts)


_VIEW_DEFAULTS: dict[str, Any] = {
    "families": (),
    "project_of_entry": {},
    "fundamental": frozenset(),
    "pending": {},
    "lab": frozenset(),
    "lab_row_of": {},
    "exception": frozenset(),
    "forbidden": frozenset(),
    "table_rows": {},
    "row_scope": {},
    "row_order": (),
}


def _complete_view(parts: dict[str, Any]) -> ClassView | None:
    if any(key not in parts for key in ("table_rows", "row_scope", "row_order")):
        return None
    merged = {key: parts.get(key, default) for key, default in _VIEW_DEFAULTS.items()}
    return ClassView(**merged)


@functools.lru_cache(maxsize=1)
def live_authority() -> Authority:
    """The repository's own authority (cached); callers that lack a structural table fall back to it."""
    return load_authority(ROOT)


def class_view_from_policy(policy: Any, fallback: Authority | None = None) -> ClassView | None:
    """Lenient view for callers holding a raw allowlist dict (dependency_audit, fixtures).

    Lists and tables present in ``policy`` are used as given. Anything absent is taken from the live
    authority, which only ever adds restrictions (pending decisions, gate mappings, row scopes); an
    omitted table can never admit a crate. Returns None when no usable authority exists (fail closed).
    """
    auth = fallback if fallback is not None else live_authority()
    base: dict[str, Any] = {}
    if auth.allowlist is not None:
        base.update(_view_parts_from_allowlist(auth.allowlist))
    if auth.registry is not None:
        base.update(_view_parts_from_registry(auth))
    if isinstance(policy, dict):
        base.update(_view_parts_from_allowlist(policy))
    return _complete_view(base)


def _first_row(view: ClassView, table: str) -> str | None:
    rows = view.table_rows.get(table)
    return rows[0] if rows else None


def _lane_allows(view: ClassView, row: str | None, is_production: bool) -> bool:
    lanes = SCOPE_LANES.get(view.row_scope.get(row or ""), frozenset())
    return ("production" if is_production else "development") in lanes


def classify_package(
    name: str,
    view: ClassView,
    *,
    is_production: bool,
    is_member: bool,
    admitted_projects: frozenset[str] | set[str] | None,
) -> Classification:
    """Classifies one package into exactly one registry row, or a typed refusal."""
    norm = normalize_crate(name)
    if is_member:
        return Classification("member", _first_row(view, "in_house"), None)
    in_lab = norm in view.lab
    if norm in view.forbidden and (is_production or not in_lab):
        if is_production:
            return Classification("forbidden", None, f"forbidden package is reachable: {name}")
        return Classification("forbidden", None, f"forbidden package '{name}' cannot be admitted into any dependency class")
    if norm in view.pending:
        decision, row = view.pending[norm]
        return Classification("pending", row or _first_row(view, "pending_owner_decisions"), f"crate '{name}' ({row}) is pending owner decision {decision}; it is neither admitted nor rejected until the owner decides", decision)
    matches = [entry for entry in view.families if fnmatch.fnmatchcase(norm, normalize_crate(entry))]
    if matches:
        row = _first_row(view, "in_house")
        projects = sorted({view.project_of_entry.get(entry, "") for entry in matches})
        if "" in projects or len(projects) != 1:
            return Classification("gate", row, f"in-house family package '{name}' has no unique franken_imports project mapping ({matches}); per-mechanism import gate unresolved")
        project = projects[0]
        if admitted_projects is None or project not in admitted_projects:
            return Classification("gate", row, f"in-house family package '{name}' lacks per-mechanism import gate in architecture/franken_imports.json (project '{project}' has no {PRODUCTION_ADMITTED_IMPORT_STATUS} import)")
        if not _lane_allows(view, row, is_production):
            return Classification("scope", row, f"in-house package '{name}' ({row}) is outside the scope of its registry row")
        return Classification("admitted", row, None)
    if norm in view.fundamental:
        row = _first_row(view, "fundamental")
        if not _lane_allows(view, row, is_production):
            return Classification("scope", row, f"fundamental crate '{name}' ({row}) is outside the scope of its registry row")
        return Classification("admitted", row, None)
    if in_lab:
        row = view.lab_row_of.get(norm)
        if row is None:
            return Classification("unassigned", None, f"laboratory oracle '{name}' is not assigned to a DEP-CLASS-F4 registry row")
        if not _lane_allows(view, row, is_production):
            return Classification("scope", row, f"laboratory oracle package '{name}' ({row}) is reachable from production closure")
        return Classification("admitted", row, None)
    if norm in view.exception:
        row = _first_row(view, "exception_candidates")
        if not _lane_allows(view, row, is_production):
            return Classification("scope", row, f"unadmitted exception candidate package '{name}' ({row}) lacks approved DEP record and ADR")
        return Classification("admitted", row, None)
    return Classification("unclassified", None, f"package '{name}' does not map to any recognized dependency constitution class")
