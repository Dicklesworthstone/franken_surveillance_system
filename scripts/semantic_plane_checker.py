#!/usr/bin/env python3
"""Deterministic ADR-0001 three semantic planes checker (fss-x4a.1.9).

Enforces ADR-0001 three semantic planes doctrine from AGENTS.md:
- Authority, cognition, and effect planes are type-distinct.
- A value from one plane must not convert into another plane's type without an explicit,
  audited boundary type.
- A cognition output (model score, recommendation) can never grant effect authority.
- Every existing plane type in fss-core (effect.rs, event.rs, belief.rs, region.rs) is mapped.
- Ambiguous types (EvidenceGraph, AlertEffectRecord, EvidenceNode, EventState) are reported
  as findings rather than guessed.
- Compile-fail doctests prove forbidden cross-plane conversions do not compile.
- Fails closed when a module declared for one plane imports another plane's authority or
  effect types outside registered boundary modules.
"""

from __future__ import annotations

import argparse
import json
import os
import re
import sys
import tomllib
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]

# Typed diagnostic codes
ERR_COGNITION_GRANTS_EFFECT = "ERR-SEMPLANE-COGNITION-GRANTS-EFFECT-001"
ERR_DOCTEST_FAILED = "ERR-SEMPLANE-DOCTEST-FAILED-001"
ERR_REGISTRY_INVALID = "ERR-SEMPLANE-REGISTRY-INVALID-001"
ERR_UNAUTHORIZED_CROSS_PLANE_IMPORT = "ERR-SEMPLANE-UNAUTHORIZED-CROSS-PLANE-IMPORT-001"
ERR_UNMAPPED_CORE_TYPE = "ERR-SEMPLANE-UNMAPPED-CORE-TYPE-001"
INFO_AMBIGUOUS_TYPE = "INFO-SEMPLANE-AMBIGUOUS-TYPE-001"

# NEG-003 Decomposed model-cascade constraint codes
ERR_MODEL_OUTPUT_REACHES_EFFECT = "ERR-SEMPLANE-MODEL-OUTPUT-REACHES-EFFECT-001"
ERR_SINGLE_MODEL_CORROBORATION = "ERR-SEMPLANE-SINGLE-MODEL-CORROBORATION-001"
ERR_ABSTENTION_AS_NEGATIVE_EVIDENCE = "ERR-SEMPLANE-ABSTENTION-AS-NEGATIVE-EVIDENCE-001"
ERR_MUTABLE_MODEL_GENERATION = "ERR-SEMPLANE-MUTABLE-MODEL-GENERATION-001"
ERR_CONTRACT_DOC_INVALID = "ERR-SEMPLANE-CONTRACT-DOC-INVALID-001"

DIAGNOSTIC_REGISTRY: dict[str, dict[str, str]] = {
    ERR_COGNITION_GRANTS_EFFECT: {
        "trigger": "A cognition module contains a function or conversion granting EffectAuthority",
        "remediation": "Remove the conversion; cognition outputs can never grant effect execution authority",
        "standard_code": "SEMPLANE-001",
    },
    ERR_DOCTEST_FAILED: {
        "trigger": "Compile-fail doctest mapping in docs/enforcement/three_semantic_planes_contract.md failed or missing",
        "remediation": "Ensure forbidden cross-plane conversions are mapped and proven by crate doctests",
        "standard_code": "SEMPLANE-002",
    },
    ERR_REGISTRY_INVALID: {
        "trigger": "architecture/semantic_plane_registry.json is missing, empty, invalid JSON, or lacks required schema fields",
        "remediation": "Restore a valid architecture/semantic_plane_registry.json with schema fss.semantic_plane_registry.v1",
        "standard_code": "SEMPLANE-003",
    },
    ERR_UNAUTHORIZED_CROSS_PLANE_IMPORT: {
        "trigger": "A module declared for one plane imports another plane's authority or effect types outside registered boundary modules",
        "remediation": "Route interaction through an audited boundary module or register the boundary in semantic_plane_registry.json",
        "standard_code": "SEMPLANE-004",
    },
    ERR_UNMAPPED_CORE_TYPE: {
        "trigger": "A public type declared in fss-core (effect.rs, event.rs, belief.rs, region.rs) is omitted from semantic_plane_registry.json",
        "remediation": "Register the type and its plane classification in architecture/semantic_plane_registry.json",
        "standard_code": "SEMPLANE-005",
    },
    INFO_AMBIGUOUS_TYPE: {
        "trigger": "A registered type bridges multiple planes or couples evidence anchors with hypotheses",
        "remediation": "Informational audit finding: verify boundary handling meets ADR-0001 invariants",
        "standard_code": "SEMPLANE-006",
    },
    ERR_MODEL_OUTPUT_REACHES_EFFECT: {
        "trigger": "A model or VLM output type directly converts to or constructs an effect type without plan/authority mediation",
        "remediation": "NEG-003: Model output is derived cognition; route through situation capsule, affordance frontier, and witnessed plan before effect preparation",
        "standard_code": "SEMPLANE-007",
    },
    ERR_SINGLE_MODEL_CORROBORATION: {
        "trigger": "A corroboration policy or specification permits fewer than 2 distinct sources/sensors/models",
        "remediation": "INV-055 and NEG-003 require corroboration to name >= 2 distinct sources with independent failure domains; min_sources must be >= 2",
        "standard_code": "SEMPLANE-008",
    },
    ERR_ABSTENTION_AS_NEGATIVE_EVIDENCE: {
        "trigger": "Model abstention or failure is coerced into negative evidence or coverage witness",
        "remediation": "Negative evidence requires a verified CoverageWitness over sensor custody; model abstention is epistemic Unknown, not evidence of absence",
        "standard_code": "SEMPLANE-009",
    },
    ERR_MUTABLE_MODEL_GENERATION: {
        "trigger": "A model generation references a mutable alias (e.g. 'latest', 'HEAD') instead of an immutable qualified generation",
        "remediation": "ADR-0004 and NEG-003 require model generations to be pinned, immutable identifiers with content digests",
        "standard_code": "SEMPLANE-010",
    },
    ERR_CONTRACT_DOC_INVALID: {
        "trigger": "Contract document contains dummy types, fictitious structs, or claims unbacked by code enforcement",
        "remediation": "Import real workspace types from fss_core/fss_reference in doctests and claim only what the code enforces.",
        "standard_code": "SEMPLANE-011",
    },
}


@dataclass(frozen=True)
class SemanticPlaneFinding:
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


def load_semantic_plane_registry(
    path: Path, root: Path
) -> tuple[dict[str, Any] | None, list[SemanticPlaneFinding]]:
    """Loads and validates architecture/semantic_plane_registry.json."""
    findings: list[SemanticPlaneFinding] = []
    rel_path = sanitize_path(path, root)

    if not path.is_file():
        findings.append(
            SemanticPlaneFinding(
                code=ERR_REGISTRY_INVALID,
                file=rel_path,
                location="file_system",
                message=f"Semantic plane registry file does not exist: '{rel_path}'",
                severity="error",
                remediation=DIAGNOSTIC_REGISTRY[ERR_REGISTRY_INVALID]["remediation"],
            )
        )
        return None, findings

    try:
        content = path.read_text(encoding="utf-8")
    except (OSError, UnicodeDecodeError) as exc:
        findings.append(
            SemanticPlaneFinding(
                code=ERR_REGISTRY_INVALID,
                file=rel_path,
                location="file_system",
                message=f"Failed to read semantic plane registry: {exc}",
                severity="error",
                remediation=DIAGNOSTIC_REGISTRY[ERR_REGISTRY_INVALID]["remediation"],
            )
        )
        return None, findings

    if not content.strip():
        findings.append(
            SemanticPlaneFinding(
                code=ERR_REGISTRY_INVALID,
                file=rel_path,
                location="root",
                message="Semantic plane registry file is empty",
                severity="error",
                remediation=DIAGNOSTIC_REGISTRY[ERR_REGISTRY_INVALID]["remediation"],
            )
        )
        return None, findings

    try:
        data = json.loads(content)
    except json.JSONDecodeError as exc:
        findings.append(
            SemanticPlaneFinding(
                code=ERR_REGISTRY_INVALID,
                file=rel_path,
                location=f"line {exc.lineno}",
                message=f"Invalid JSON in semantic plane registry: {exc.msg}",
                severity="error",
                remediation=DIAGNOSTIC_REGISTRY[ERR_REGISTRY_INVALID]["remediation"],
            )
        )
        return None, findings

    if not isinstance(data, dict):
        findings.append(
            SemanticPlaneFinding(
                code=ERR_REGISTRY_INVALID,
                file=rel_path,
                location="root",
                message="Semantic plane registry root must be a JSON object",
                severity="error",
                remediation=DIAGNOSTIC_REGISTRY[ERR_REGISTRY_INVALID]["remediation"],
            )
        )
        return None, findings

    schema = data.get("schema", "")
    if not isinstance(schema, str) or not schema.startswith("fss.semantic_plane_registry"):
        findings.append(
            SemanticPlaneFinding(
                code=ERR_REGISTRY_INVALID,
                file=rel_path,
                location="schema",
                message=f"Invalid schema in semantic plane registry: '{schema}'",
                severity="error",
                remediation=DIAGNOSTIC_REGISTRY[ERR_REGISTRY_INVALID]["remediation"],
            )
        )
        return None, findings

    types = data.get("types")
    if not isinstance(types, dict) or not types:
        findings.append(
            SemanticPlaneFinding(
                code=ERR_REGISTRY_INVALID,
                file=rel_path,
                location="types",
                message="Semantic plane registry must declare a non-empty 'types' map",
                severity="error",
                remediation=DIAGNOSTIC_REGISTRY[ERR_REGISTRY_INVALID]["remediation"],
            )
        )
        return None, findings

    module_decls = data.get("module_declarations")
    if module_decls is None or not isinstance(module_decls, dict):
        findings.append(
            SemanticPlaneFinding(
                code=ERR_REGISTRY_INVALID,
                file=rel_path,
                location="module_declarations",
                message="Semantic plane registry must declare a 'module_declarations' map",
                severity="error",
                remediation=DIAGNOSTIC_REGISTRY[ERR_REGISTRY_INVALID]["remediation"],
            )
        )
        return None, findings

    boundary_mods = data.get("registered_boundary_modules")
    if boundary_mods is not None and not isinstance(boundary_mods, list):
        findings.append(
            SemanticPlaneFinding(
                code=ERR_REGISTRY_INVALID,
                file=rel_path,
                location="registered_boundary_modules",
                message="Semantic plane registry 'registered_boundary_modules' must be a list",
                severity="error",
                remediation=DIAGNOSTIC_REGISTRY[ERR_REGISTRY_INVALID]["remediation"],
            )
        )
        return None, findings

    return data, findings


def verify_compile_fail_doctests(
    contract_path: Path, root: Path | None = None
) -> tuple[bool, int, str]:
    """Verifies that docs/enforcement/three_semantic_planes_contract.md maps every invariant to a real doctest/test."""
    if not contract_path.is_file():
        return False, 0, f"Contract doctest file missing: {contract_path}"

    try:
        doc = contract_path.read_text(encoding="utf-8")
    except (OSError, UnicodeDecodeError) as exc:
        return False, 0, f"Failed to read contract document: {exc}"

    effective_root = root
    if effective_root is None:
        for parent in contract_path.resolve().parents:
            if (parent / "Cargo.toml").is_file():
                effective_root = parent
                break
        if effective_root is None:
            effective_root = contract_path.resolve().parent

    errors: list[str] = []

    for line_no, line in enumerate(doc.splitlines(), start=1):
        stripped = line.strip()
        if stripped.startswith("```") or stripped.startswith("~~~"):
            info = stripped[3:].strip()
            if info != "text":
                errors.append(
                    f"{contract_path}:{line_no}: code fence {stripped!r} would be an untested rustdoc block"
                )

    invariants = set(re.findall(r"^## Invariant (\d+):", doc, re.MULTILINE))
    if not invariants:
        errors.append(f"{contract_path}: no '## Invariant N:' sections found")

    row_re = re.compile(
        r"^\|\s*(?P<inv>[^|`]+?)\s*\|\s*`(?P<kind>[^`]+)`\s*\|\s*`(?P<path>[^`]+)`\s*\|"
        r"\s*`(?P<item>[^`]+)`\s*\|\s*`(?P<marker>[^`]+)`\s*\|\s*$",
        re.MULTILINE,
    )
    rows = [m.groupdict() for m in row_re.finditer(doc)]
    mapped = {row["inv"] for row in rows}
    for inv in sorted(invariants - mapped):
        errors.append(f"{contract_path}: Invariant {inv} has no enforcement row")
    for inv in sorted(mapped - invariants - {"legal-path"}):
        errors.append(f"{contract_path}: enforcement row names unknown invariant {inv!r}")
    if not any(row["inv"] == "legal-path" and row["kind"] == "doctest" for row in rows):
        errors.append(f"{contract_path}: no compiling legal-path doctest row")

    def attached_doc_blocks(lines: list[str], item: str) -> list[list[tuple[str, str]]]:
        decl = re.compile(
            r"^\s*(?:pub(?:\([^)]*\))?\s+)?(?:const\s+)?(?:struct|enum|fn|type|trait|mod)\s+"
            + re.escape(item)
            + r"\b"
        )
        all_blocks: list[list[tuple[str, str]]] = []
        for index, line in enumerate(lines):
            if not decl.match(line):
                continue
            start = index
            while start > 0 and lines[start - 1].lstrip().startswith(("///", "#[")):
                start -= 1
            docs = [l.lstrip()[3:] for l in lines[start:index] if l.lstrip().startswith("///")]
            docs = [d[1:] if d.startswith(" ") else d for d in docs]
            blocks: list[tuple[str, str]] = []
            info: str | None = None
            body: list[str] = []
            for text in docs:
                if text.strip().startswith("```"):
                    if info is None:
                        info, body = text.strip()[3:].strip(), []
                    else:
                        blocks.append((info, "\n".join(body)))
                        info = None
                elif info is not None:
                    body.append(text)
            all_blocks.append(blocks)
        return all_blocks

    markers_seen: set[str] = set()
    for row in rows:
        rel_path = Path(row["path"])
        path = (effective_root / rel_path) if not rel_path.is_absolute() else rel_path
        label = f"Invariant {row['inv']} ({row['marker']})"
        if row["marker"] in markers_seen:
            errors.append(f"{label}: marker listed twice")
        markers_seen.add(row["marker"])
        if not path.is_file():
            errors.append(f"{label}: {path} does not exist")
            continue
        try:
            lines = path.read_text(encoding="utf-8").splitlines()
        except (OSError, UnicodeDecodeError) as exc:
            errors.append(f"{label}: unreadable file {path}: {exc}")
            continue

        if row["kind"] == "test":
            if not re.search(
                r"#\[test\]\s*\n\s*fn\s+" + re.escape(row["item"]) + r"\s*\(", "\n".join(lines)
            ):
                errors.append(f"{label}: no #[test] fn {row['item']} in {path}")
            continue

        if row["kind"] == "doctest":
            ok_kind = lambda info: info in ("", "rust")
        elif re.fullmatch(r"compile_fail,E\d{4}", row["kind"]):
            ok_kind = lambda info, kind=row["kind"]: info == kind
        else:
            errors.append(f"{label}: unsupported kind {row['kind']!r}")
            continue

        found = False
        any_item = False
        for blocks in attached_doc_blocks(lines, row["item"]):
            any_item = True
            for info, body in blocks:
                if ok_kind(info) and re.search(r"//\s*" + re.escape(row["marker"]) + r"\b", body):
                    if "fss_core::" not in body and "fss_reference::" not in body:
                        errors.append(f"{label}: doctest does not exercise real fss types")
                    found = True
        if not any_item:
            errors.append(f"{label}: item {row['item']} not declared in {path}")
        elif not found:
            errors.append(
                f"{label}: no `{row['kind']}` doctest carrying the marker is attached to {row['item']} in {path}"
            )

    if errors:
        return False, 0, "; ".join(errors)

    return True, len(rows), ""


def audit_contract_doc_claims(
    root: Path, contract_path: Path | None = None
) -> list[SemanticPlaneFinding]:
    """Audits docs/enforcement/three_semantic_planes_contract.md to ensure claims match code enforcement.

    Enforces:
    1. Doctests must NOT declare fictitious dummy structs/enums (F1).
    2. Doctests must import real workspace types from fss_core or fss_reference (F1).
    3. Contract doc must NOT claim effect dispatch strictly requires EffectAuthority parameter,
       since dispatch_reference_alert takes &ReferenceAlertPlan (F8).
    4. Contract doc claims must accurately reflect witnessed plan effect execution (F8).
    """
    findings: list[SemanticPlaneFinding] = []
    if contract_path is None:
        contract_path = root / "docs/enforcement/three_semantic_planes_contract.md"

    rel_path = sanitize_path(contract_path, root)
    if not contract_path.is_file():
        return findings

    try:
        content = contract_path.read_text(encoding="utf-8")
    except (OSError, UnicodeDecodeError) as exc:
        findings.append(
            SemanticPlaneFinding(
                code=ERR_CONTRACT_DOC_INVALID,
                file=rel_path,
                location="file_system",
                message=f"Failed to read contract document: {exc}",
                severity="error",
                remediation=DIAGNOSTIC_REGISTRY[ERR_CONTRACT_DOC_INVALID]["remediation"],
            )
        )
        return findings

    # Check for unbacked claims regarding EffectAuthority on effect dispatch (Finding 8)
    dispatch_auth_pattern = re.compile(
        r"(?:strictly\s+requires|requires\s+an\s+explicit)\s+`?EffectAuthority`?\s+parameter",
        re.IGNORECASE,
    )
    if dispatch_auth_pattern.search(content):
        findings.append(
            SemanticPlaneFinding(
                code=ERR_CONTRACT_DOC_INVALID,
                file=rel_path,
                location="Invariant 4",
                message=(
                    "Contract doc claims effect dispatch strictly requires an EffectAuthority parameter, "
                    "but dispatch_reference_alert accepts &ReferenceAlertPlan without EffectAuthority (Finding 8)."
                ),
                severity="error",
                remediation=DIAGNOSTIC_REGISTRY[ERR_CONTRACT_DOC_INVALID]["remediation"],
            )
        )

    # Extract rust code blocks
    code_block_pattern = re.compile(r"```rust(?:,[^\n]*)?\n(.*?)```", re.DOTALL)
    blocks = code_block_pattern.findall(content)

    dummy_struct_pattern = re.compile(
        r"^\s*(?:pub\s+)?(?:struct|enum)\s+([A-Za-z0-9_]+)",
        re.MULTILINE,
    )

    for idx, block in enumerate(blocks, start=1):
        # Check for dummy struct definitions (Finding 1)
        for match in dummy_struct_pattern.finditer(block):
            struct_name = match.group(1)
            findings.append(
                SemanticPlaneFinding(
                    code=ERR_CONTRACT_DOC_INVALID,
                    file=rel_path,
                    location=f"doctest_block_{idx}:{struct_name}",
                    message=(
                        f"Doctest block {idx} declares dummy local type '{struct_name}'. "
                        "Contract doctests must import and verify actual workspace types from fss_core or fss_reference."
                    ),
                    severity="error",
                    remediation=DIAGNOSTIC_REGISTRY[ERR_CONTRACT_DOC_INVALID]["remediation"],
                    params={"block_index": idx, "type_name": struct_name},
                )
            )

        # Check that doctest block imports from real workspace crates (fss_core or fss_reference)
        if not ("use fss_core::" in block or "use fss_reference::" in block):
            findings.append(
                SemanticPlaneFinding(
                    code=ERR_CONTRACT_DOC_INVALID,
                    file=rel_path,
                    location=f"doctest_block_{idx}",
                    message=(
                        f"Doctest block {idx} does not import from workspace crates (fss_core or fss_reference). "
                        "Doctests must verify real workspace types."
                    ),
                    severity="error",
                    remediation=DIAGNOSTIC_REGISTRY[ERR_CONTRACT_DOC_INVALID]["remediation"],
                    params={"block_index": idx},
                )
            )

    return findings


def audit_fss_core_type_census(
    root: Path, registry: dict[str, Any]
) -> list[SemanticPlaneFinding]:
    """Audits public types in fss-core (effect.rs, event.rs, belief.rs, region.rs) against registry."""
    findings: list[SemanticPlaneFinding] = []
    registered_types = registry.get("types", {})
    type_decl_pattern = re.compile(
        r"^\s*pub\s+(?:struct|enum|type)\s+([A-Za-z0-9_]+)", re.MULTILINE
    )

    core_files = [
        "crates/fss-core/src/effect.rs",
        "crates/fss-core/src/event.rs",
        "crates/fss-core/src/belief.rs",
        "crates/fss-core/src/region.rs",
    ]

    for rel_path in core_files:
        abs_path = root / rel_path
        if not abs_path.is_file():
            findings.append(
                SemanticPlaneFinding(
                    code=ERR_UNMAPPED_CORE_TYPE,
                    file=rel_path,
                    location="file_system",
                    message=f"Mandatory core file '{rel_path}' is missing",
                    severity="error",
                    remediation=DIAGNOSTIC_REGISTRY[ERR_UNMAPPED_CORE_TYPE]["remediation"],
                    params={"file": rel_path},
                )
            )
            continue

        try:
            content = abs_path.read_text(encoding="utf-8")
        except (OSError, UnicodeDecodeError) as exc:
            findings.append(
                SemanticPlaneFinding(
                    code=ERR_UNMAPPED_CORE_TYPE,
                    file=rel_path,
                    location="file_system",
                    message=f"Failed to read core file '{rel_path}': {exc}",
                    severity="error",
                    remediation=DIAGNOSTIC_REGISTRY[ERR_UNMAPPED_CORE_TYPE]["remediation"],
                )
            )
            continue

        for line_no, line in enumerate(content.splitlines(), start=1):
            match = type_decl_pattern.match(line)
            if match:
                type_name = match.group(1)
                if type_name not in registered_types:
                    findings.append(
                        SemanticPlaneFinding(
                            code=ERR_UNMAPPED_CORE_TYPE,
                            file=rel_path,
                            location=f"line {line_no}",
                            message=f"Public type '{type_name}' in '{rel_path}' is not mapped in semantic plane registry",
                            severity="error",
                            remediation=DIAGNOSTIC_REGISTRY[ERR_UNMAPPED_CORE_TYPE]["remediation"],
                            params={"type_name": type_name, "file": rel_path},
                        )
                    )

    return findings


def audit_workspace_module_census(
    root: Path, registry: dict[str, Any]
) -> list[SemanticPlaneFinding]:
    """Audits workspace Rust source files to ensure every module in audited crates is declared in module_declarations."""
    findings: list[SemanticPlaneFinding] = []
    module_declarations = registry.get("module_declarations", {})

    audited_crates = ["crates/fss-core", "crates/fss-reference"]
    for mod in module_declarations:
        parts = mod.replace("\\", "/").split("/")
        if len(parts) >= 2 and parts[0] == "crates":
            crate_path = f"crates/{parts[1]}"
            if crate_path not in audited_crates:
                audited_crates.append(crate_path)

    for crate_rel in audited_crates:
        crate_src = root / crate_rel / "src"
        if not crate_src.is_dir():
            continue
        for rs_file in sorted(crate_src.rglob("*.rs")):
            rel_path = sanitize_path(rs_file, root)
            if rel_path not in module_declarations:
                findings.append(
                    SemanticPlaneFinding(
                        code=ERR_REGISTRY_INVALID,
                        file=rel_path,
                        location="module_declarations",
                        message=f"Source module '{rel_path}' is present on disk but omitted from 'module_declarations' in semantic plane registry",
                        severity="error",
                        remediation=DIAGNOSTIC_REGISTRY[ERR_REGISTRY_INVALID]["remediation"],
                        params={"file": rel_path},
                    )
                )

    return findings


MODEL_OUTPUT_TYPES: set[str] = {
    "ModelOutput",
    "MockModelOutput",
    "VlmOutput",
    "PerceptionOutput",
    "ModelFinding",
    "CorroboratedModelFinding",
    "MockModelResult",
    "MockDetection",
}

EFFECT_TYPES: set[str] = {
    "EffectAuthority",
    "EffectIntent",
    "PreparedEffect",
    "AlertIntent",
    "AlertEffectRecord",
    "PreparedOperation",
    "Obligation",
    "ObligationState",
    "EffectJournalTransition",
    "OperationReceipt",
    "EffectJournal",
}


AUTHORITY_TYPES: set[str] = {
    "EffectAuthority",
}


def is_effect_or_authority_type(
    ty_str: str,
    registered_types: dict[str, Any],
    effective_effect_types: set[str] | None = None,
    alias_map: dict[str, str] | None = None,
) -> bool:
    """Checks if a type string refers to an effect or authority plane type."""
    eff = EFFECT_TYPES if effective_effect_types is None else effective_effect_types
    tokens = re.findall(r"\b[A-Za-z0-9_]+\b", ty_str)
    for t in tokens:
        if (
            t in eff
            or t in AUTHORITY_TYPES
            or registered_types.get(t, {}).get("plane") in ("effect", "authority")
        ):
            return True
        if alias_map:
            norm_t = normalise_type_name(t, alias_map)
            if (
                norm_t in eff
                or norm_t in AUTHORITY_TYPES
                or registered_types.get(norm_t, {}).get("plane") in ("effect", "authority")
            ):
                return True
    return False


ABSTENTION_TYPES: set[str] = {
    "MockModelOutcome",
    "MockAbstentionReason",
    "MockExecutorOutcome",
}

NEGATIVE_EVIDENCE_TYPES: set[str] = {
    "CoverageWitness",
    "AbsenceWitness",
    "AbsenceConfirmed",
}

MUTABLE_GENERATION_TOKENS: set[str] = {
    "latest",
    "latest.weights",
    "head",
    "master",
    "main",
    "current",
    "nightly",
    "trunk",
}


def mask_comments_and_strings(source: str) -> str:
    """Masks comments and strings with spaces, preserving character offsets and newlines."""
    result = list(source)
    n = len(source)
    i = 0
    while i < n:
        if i + 1 < n and source[i : i + 2] == "//":
            j = i
            while j < n and source[j] != "\n":
                if result[j] != "\n":
                    result[j] = " "
                j += 1
            i = j
        elif i + 1 < n and source[i : i + 2] == "/*":
            j = i + 2
            depth = 1
            while j < n and depth > 0:
                if j + 1 < n and source[j : j + 2] == "/*":
                    depth += 1
                    j += 2
                elif j + 1 < n and source[j : j + 2] == "*/":
                    depth -= 1
                    j += 2
                else:
                    j += 1
            for k in range(i, min(j, n)):
                if result[k] != "\n":
                    result[k] = " "
            i = j
        elif source[i] == "r" and (i + 1 < n and source[i + 1] in ('"', "#")):
            j = i + 1
            hashes = 0
            while j < n and source[j] == "#":
                hashes += 1
                j += 1
            if j < n and source[j] == '"':
                j += 1
                end_marker = '"' + "#" * hashes
                found = source.find(end_marker, j)
                if found != -1:
                    j = found + len(end_marker)
                else:
                    j = n
                for k in range(i, min(j, n)):
                    if result[k] != "\n":
                        result[k] = " "
                i = j
            else:
                i += 1
        elif source[i] == '"':
            j = i + 1
            while j < n:
                if source[j] == "\\":
                    j += 2
                elif source[j] == '"':
                    j += 1
                    break
                else:
                    j += 1
            for k in range(i, min(j, n)):
                if result[k] != "\n":
                    result[k] = " "
            i = j
        elif source[i] == "'":
            if i + 1 < n and source[i + 1] != "\\" and i + 2 < n and source[i + 2] == "'":
                for k in range(i, i + 3):
                    if result[k] != "\n":
                        result[k] = " "
                i += 3
            elif i + 1 < n and source[i + 1] == "\\" and i + 3 < n and source[i + 3] == "'":
                for k in range(i, i + 4):
                    if result[k] != "\n":
                        result[k] = " "
                i += 4
            else:
                i += 1
        else:
            i += 1
    return "".join(result)


def split_top_level(text: str, delimiter: str = ",") -> list[str]:
    """Splits text by delimiter at top level of delimiters (<>, (), [], {})."""
    parts: list[str] = []
    current: list[str] = []
    depth_angle = 0
    depth_paren = 0
    depth_bracket = 0
    depth_brace = 0
    n = len(text)
    for idx, ch in enumerate(text):
        if ch == "<":
            depth_angle += 1
        elif ch == ">":
            depth_angle = max(0, depth_angle - 1)
        elif ch == "(":
            depth_paren += 1
        elif ch == ")":
            depth_paren = max(0, depth_paren - 1)
        elif ch == "[":
            depth_bracket += 1
        elif ch == "]":
            depth_bracket = max(0, depth_bracket - 1)
        elif ch == "{":
            depth_brace += 1
        elif ch == "}":
            depth_brace = max(0, depth_brace - 1)
        elif (
            ch == delimiter
            and depth_angle == 0
            and depth_paren == 0
            and depth_bracket == 0
            and depth_brace == 0
        ):
            if delimiter == ":" and (
                (idx > 0 and text[idx - 1] == ":")
                or (idx + 1 < n and text[idx + 1] == ":")
            ):
                current.append(ch)
                continue
            part = "".join(current).strip()
            if part:
                parts.append(part)
            current = []
            continue
        current.append(ch)
    if current:
        part = "".join(current).strip()
        if part:
            parts.append(part)
    return parts


def parse_use_tree(prefix: str, text: str) -> list[tuple[str, str]]:
    """Recursively parse a use tree into (full_path, alias) pairs for any 'as' renames."""
    results: list[tuple[str, str]] = []
    text = text.strip()
    if not text:
        return results

    items = split_top_level(text, ",")
    if len(items) > 1:
        for item in items:
            results.extend(parse_use_tree(prefix, item))
        return results

    item = items[0].strip()
    brace_idx = item.find("{")
    if brace_idx != -1 and item.endswith("}"):
        head = item[:brace_idx].strip()
        head = re.sub(r"::+$", "", head).strip()
        body = item[brace_idx + 1 : -1].strip()
        new_prefix = (prefix + "::" + head).strip(":") if head else prefix
        results.extend(parse_use_tree(new_prefix, body))
        return results

    m = re.search(r"\bas\s+([A-Za-z0-9_#]+)$", item)
    if m:
        alias = m.group(1).lstrip("r#")
        raw_path = item[: m.start()].strip()
        full_path = (prefix + "::" + raw_path).strip(":") if prefix else raw_path
        results.append((full_path, alias))
    return results


def extract_use_renames(content: str, pub_only: bool = False) -> dict[str, str]:
    """Extracts 'use ... as ...;' renames from Rust source code.

    Returns dict mapping alias name to target path string.
    """
    masked = mask_comments_and_strings(content)
    renames: dict[str, str] = {}
    pattern = (
        r"\bpub(?:\s*\([^)]*\))?\s+use\s+([^;]+);"
        if pub_only
        else r"\b(?:pub(?:\s*\([^)]*\))?\s+)?use\s+([^;]+);"
    )
    for m in re.finditer(pattern, masked, re.DOTALL):
        decl = m.group(1).strip()
        decl = " ".join(decl.split())
        for path, alias in parse_use_tree("", decl):
            if alias and alias != "_" and re.fullmatch(r"[A-Za-z0-9_]+", alias):
                clean_path = re.sub(r"\br#", "", path)
                renames[alias] = clean_path
    return renames


def normalise_type_name(ty_str: str, alias_map: dict[str, str] | None = None) -> str:
    """Normalises a type name by stripping references, path prefixes (crate::, super::, self::, ::crate::),

    r# raw identifier prefixes, and resolving use-renames/type aliases.
    """
    current = ty_str.strip()
    if not current:
        return ""

    current = re.sub(r"^&(?:\s*'[A-Za-z0-9_]+\s+)?(?:\s*mut\s+)?", "", current).strip()

    seen: set[str] = set()
    for _ in range(10):
        base = current.split("<")[0].strip()
        if "::" in base:
            base = base.split("::")[-1].strip()
        base = re.sub(r"^r#", "", base)

        if not base or base in seen:
            break
        seen.add(base)

        if alias_map and base in alias_map:
            current = alias_map[base].strip()
            continue
        current = base
        break

    final_base = current.split("<")[0].strip()
    if "::" in final_base:
        final_base = final_base.split("::")[-1].strip()
    final_base = re.sub(r"^r#", "", final_base)
    return final_base


def parse_all_generic_bounds(
    generics: str,
    where_clause: str,
    impl_header: str | None,
    alias_map: dict[str, str] | None = None,
) -> dict[str, list[str]]:
    """Extracts type bounds from generic parameter list, where clause, and impl header."""
    bounds: dict[str, list[str]] = {}

    def ingest_generic_params(gen_str: str) -> None:
        g = gen_str.strip()
        if g.startswith("<") and g.endswith(">"):
            g = g[1:-1].strip()
        for item in split_top_level(g, ","):
            colon_parts = split_top_level(item, ":")
            if len(colon_parts) >= 2:
                raw_param = colon_parts[0].strip().split()[0]
                norm_param = normalise_type_name(raw_param, alias_map)
                targets = {
                    p
                    for p in (raw_param, norm_param)
                    if p and not p.startswith("'") and re.fullmatch(r"[A-Za-z0-9_]+", p)
                }
                rest = ":".join(colon_parts[1:])
                b_items = [b.strip() for b in split_top_level(rest, "+") if b.strip()]
                for target in targets:
                    bounds.setdefault(target, []).extend(b_items)
                for b in b_items:
                    m_into = re.search(r"\b(?:Into|TryInto)<([^>]+)>", b)
                    if m_into:
                        raw_dest = m_into.group(1).strip()
                        norm_dest = normalise_type_name(raw_dest, alias_map)
                        if norm_dest and norm_dest != raw_dest:
                            for target in targets:
                                bounds.setdefault(target, []).append(f"Into<{norm_dest}>")
            else:
                raw_param = item.strip().split()[0] if item.strip() else ""
                norm_param = normalise_type_name(raw_param, alias_map)
                for p in (raw_param, norm_param):
                    if p and not p.startswith("'") and re.fullmatch(r"[A-Za-z0-9_]+", p):
                        bounds.setdefault(p, [])

    def ingest_where_clause(wh_str: str) -> None:
        w = wh_str.strip()
        if w.startswith("where"):
            w = w[5:].strip()
        for item in split_top_level(w, ","):
            colon_parts = split_top_level(item, ":")
            if len(colon_parts) >= 2:
                raw_target = colon_parts[0].strip()
                norm_target = normalise_type_name(raw_target, alias_map)
                rest = ":".join(colon_parts[1:])
                b_items = [b.strip() for b in split_top_level(rest, "+") if b.strip()]
                targets = {
                    t
                    for t in (raw_target, norm_target)
                    if t and re.fullmatch(r"[A-Za-z0-9_]+", t)
                }
                for target in targets:
                    bounds.setdefault(target, []).extend(b_items)

                for b in b_items:
                    m_from = re.search(r"\b(?:From|TryFrom)<([^>]+)>", b)
                    if m_from:
                        raw_src = m_from.group(1).strip()
                        norm_src = normalise_type_name(raw_src, alias_map)
                        src_targets = {
                            s
                            for s in (raw_src, norm_src)
                            if s and re.fullmatch(r"[A-Za-z0-9_]+", s)
                        }
                        target_names = {t for t in (raw_target, norm_target) if t}
                        for src in src_targets:
                            for tgt in target_names:
                                bounds.setdefault(src, []).append(f"Into<{tgt}>")

                    m_into = re.search(r"\b(?:Into|TryInto)<([^>]+)>", b)
                    if m_into:
                        raw_dest = m_into.group(1).strip()
                        norm_dest = normalise_type_name(raw_dest, alias_map)
                        if norm_dest and norm_dest != raw_dest:
                            for target in targets:
                                bounds.setdefault(target, []).append(f"Into<{norm_dest}>")
                        if norm_dest and re.fullmatch(r"[A-Za-z0-9_]+", norm_dest):
                            for tgt in (raw_target, norm_target):
                                if tgt:
                                    bounds.setdefault(norm_dest, []).append(f"From<{tgt}>")

    if generics:
        ingest_generic_params(generics)
    if where_clause:
        ingest_where_clause(where_clause)

    if impl_header:
        m_gen = re.search(r"<[^>]*>", impl_header)
        if m_gen:
            ingest_generic_params(m_gen.group(0))
        if "where" in impl_header:
            wh_part = impl_header.split("where", 1)[1]
            ingest_where_clause(wh_part)

    return bounds


def extract_type_aliases(content: str) -> dict[str, str]:
    """Extracts type aliases from Rust source code.

    Returns dict mapping alias name to clean target type string.
    """
    masked = mask_comments_and_strings(content)
    n = len(masked)
    aliases: dict[str, str] = {}
    i = 0
    while i < n:
        idx = masked.find("type", i)
        if idx == -1:
            break
        if (idx > 0 and (masked[idx - 1].isalnum() or masked[idx - 1] == "_")) or (
            idx + 4 < n and (masked[idx + 4].isalnum() or masked[idx + 4] == "_")
        ):
            i = idx + 4
            continue

        line_start = masked.rfind("\n", 0, idx)
        line_start = 0 if line_start == -1 else line_start + 1
        prefix = masked[line_start:idx].strip()
        if prefix and not re.fullmatch(r"(?:pub(?:\([^\)]*\))?\s*)?", prefix):
            i = idx + 4
            continue

        m_name = re.match(r"\s+([A-Za-z0-9_]+)", masked[idx + 4 :])
        if not m_name:
            i = idx + 4
            continue

        alias_name = m_name.group(1)
        after_name = idx + 4 + m_name.end()

        if after_name < n and masked[after_name] == "<":
            depth = 1
            j = after_name + 1
            while j < n and depth > 0:
                if masked[j] == "<":
                    depth += 1
                elif masked[j] == ">":
                    depth -= 1
                j += 1
            after_name = j

        while after_name < n and masked[after_name].isspace():
            after_name += 1

        if after_name < n and masked[after_name] == "=":
            target_start = after_name + 1
            target_end = masked.find(";", target_start)
            if target_end != -1:
                raw_target = content[target_start:target_end].strip()
                clean_target = re.split(r"\bwhere\b", raw_target)[0].strip()
                aliases[alias_name] = clean_target
                i = target_end + 1
                continue

        i = idx + 4

    return aliases


def build_effective_plane_types(
    alias_map: dict[str, str],
    registered_types: dict[str, Any],
) -> tuple[set[str], set[str], set[str], set[str]]:
    """Resolves type aliases and returns (effective_model_outputs, effective_effects, effective_abstentions, effective_neg_evidence)."""
    eff_model = set(MODEL_OUTPUT_TYPES)
    eff_effect = set(EFFECT_TYPES)
    eff_absten = set(ABSTENTION_TYPES)
    eff_neg = set(NEGATIVE_EVIDENCE_TYPES)

    for _ in range(10):
        changed = False
        for alias, target in alias_map.items():
            tokens = re.findall(r"\b[A-Za-z0-9_]+\b", target)
            if alias not in eff_model:
                if any(
                    t in eff_model or "model" in t.lower() or "vlm" in t.lower()
                    for t in tokens
                ):
                    eff_model.add(alias)
                    changed = True
            if alias not in eff_effect:
                if any(
                    t in eff_effect
                    or registered_types.get(t, {}).get("plane") in ("effect", "authority")
                    for t in tokens
                ):
                    eff_effect.add(alias)
                    changed = True
            if alias not in eff_absten:
                if any(t in eff_absten or "absten" in t.lower() for t in tokens):
                    eff_absten.add(alias)
                    changed = True
            if alias not in eff_neg:
                if any(t in eff_neg or t == "CoverageWitness" for t in tokens):
                    eff_neg.add(alias)
                    changed = True
        if not changed:
            break

    return eff_model, eff_effect, eff_absten, eff_neg


def extract_rust_functions(
    content: str,
) -> list[tuple[str, str, str, str, str, str | None, str | None, int, str]]:
    """Extracts Rust function declarations with balanced parens, generics, where clauses, and enclosing impl.

    Returns list of tuples:
    (fn_name, generics, params, ret_type, where_clause, impl_type, impl_header, start_pos, full_sig)
    """
    masked = mask_comments_and_strings(content)
    n = len(masked)
    functions: list[
        tuple[str, str, str, str, str, str | None, str | None, int, str]
    ] = []

    brace_depth = 0
    impl_stack: list[tuple[int, str, str]] = []
    pending_impl: tuple[str, str] | None = None
    i = 0
    while i < n:
        if (
            (i == 0 or not (masked[i - 1].isalnum() or masked[i - 1] == "_"))
            and masked[i : i + 4] == "impl"
            and (i + 4 == n or not (masked[i + 4].isalnum() or masked[i + 4] == "_"))
        ):
            open_brace = masked.find("{", i + 4)
            if open_brace != -1:
                header = masked[i + 4 : open_brace]
                raw_header = content[i + 4 : open_brace]
                h_clean = re.sub(r"<[^>]*>", "", header).split("where")[0].strip()
                m = re.search(
                    r"(?:[A-Za-z0-9_:]+\s+for\s+)?([A-Za-z0-9_:]+)\s*$", h_clean
                )
                if m:
                    target = m.group(1).split("::")[-1].strip()
                    pending_impl = (target, raw_header)
            i += 4
            continue

        char = masked[i]
        if char == "{":
            brace_depth += 1
            if pending_impl:
                impl_stack.append((brace_depth, pending_impl[0], pending_impl[1]))
                pending_impl = None
            i += 1
            continue
        elif char == "}":
            if impl_stack and brace_depth <= impl_stack[-1][0]:
                impl_stack.pop()
            brace_depth = max(0, brace_depth - 1)
            i += 1
            continue

        if (
            (i == 0 or not (masked[i - 1].isalnum() or masked[i - 1] == "_"))
            and masked[i : i + 2] == "fn"
            and (i + 2 == n or not (masked[i + 2].isalnum() or masked[i + 2] == "_"))
        ):
            start_pos = i
            line_start = masked.rfind("\n", 0, i)
            line_start = 0 if line_start == -1 else line_start + 1
            prefix = masked[line_start:i].strip()
            if prefix and re.fullmatch(
                r"(?:pub(?:\([^\)]*\))?\s+)?(?:async\s+)?(?:const\s+)?(?:unsafe\s+)?",
                prefix + " ",
            ):
                start_pos = line_start + (
                    len(masked[line_start:i]) - len(masked[line_start:i].lstrip())
                )

            name_match = re.match(r"fn\s+([A-Za-z0-9_]+)", masked[i:])
            if not name_match:
                i += 2
                continue
            fn_name = name_match.group(1)
            after_name = i + name_match.end()

            generics = ""
            if after_name < n and masked[after_name] == "<":
                gen_start = after_name
                gen_depth = 1
                j = after_name + 1
                while j < n and gen_depth > 0:
                    if masked[j] == "<":
                        gen_depth += 1
                    elif masked[j] == ">":
                        gen_depth -= 1
                    j += 1
                generics = content[gen_start:j].strip()
                after_name = j

            open_paren = masked.find("(", after_name)
            if open_paren == -1:
                i += 2
                continue

            paren_depth = 1
            j = open_paren + 1
            while j < n and paren_depth > 0:
                if masked[j] == "(":
                    paren_depth += 1
                elif masked[j] == ")":
                    paren_depth -= 1
                j += 1
            if paren_depth != 0:
                i += 2
                continue

            close_paren = j - 1
            params = content[open_paren + 1 : close_paren].strip()
            ret_type = ""
            where_clause = ""
            k = close_paren + 1
            while k < n and masked[k].isspace():
                k += 1
            if k + 1 < n and masked[k : k + 2] == "->":
                ret_start = k + 2
                end_k = ret_start
                while end_k < n and masked[end_k] not in ("{", ";"):
                    if masked[end_k : end_k + 5] == "where" and (
                        end_k + 5 == n
                        or not (masked[end_k + 5].isalnum() or masked[end_k + 5] == "_")
                    ):
                        break
                    end_k += 1
                ret_type = content[ret_start:end_k].strip()

                where_k = end_k
                while where_k < n and masked[where_k].isspace():
                    where_k += 1
                if where_k + 5 <= n and masked[where_k : where_k + 5] == "where" and (
                    where_k + 5 == n
                    or not (masked[where_k + 5].isalnum() or masked[where_k + 5] == "_")
                ):
                    clause_start = where_k
                    clause_end = clause_start + 5
                    while clause_end < n and masked[clause_end] not in ("{", ";"):
                        clause_end += 1
                    where_clause = content[clause_start:clause_end].strip()
                    full_sig_end = clause_end
                else:
                    full_sig_end = end_k
            else:
                where_k = k
                while where_k < n and masked[where_k].isspace():
                    where_k += 1
                if where_k + 5 <= n and masked[where_k : where_k + 5] == "where" and (
                    where_k + 5 == n
                    or not (masked[where_k + 5].isalnum() or masked[where_k + 5] == "_")
                ):
                    clause_start = where_k
                    clause_end = clause_start + 5
                    while clause_end < n and masked[clause_end] not in ("{", ";"):
                        clause_end += 1
                    where_clause = content[clause_start:clause_end].strip()
                    full_sig_end = clause_end
                else:
                    full_sig_end = close_paren + 1

            current_impl = impl_stack[-1][1] if impl_stack else None
            current_impl_header = impl_stack[-1][2] if impl_stack else None
            full_sig = content[start_pos:full_sig_end].strip()
            functions.append(
                (
                    fn_name,
                    generics,
                    params,
                    ret_type,
                    where_clause,
                    current_impl,
                    current_impl_header,
                    start_pos,
                    full_sig,
                )
            )
            i = full_sig_end
            continue

        i += 1

    return functions



def check_module_imports(
    root: Path, registry: dict[str, Any]
) -> list[SemanticPlaneFinding]:
    """Checks that modules declared for a plane do not import foreign plane types or grant effect authority outside boundary modules."""
    findings: list[SemanticPlaneFinding] = []
    registered_types = registry.get("types", {})
    boundary_modules = set(registry.get("registered_boundary_modules", []))
    module_declarations = registry.get("module_declarations", {})

    use_pattern = re.compile(r"\buse\s+([^;]+);", re.MULTILINE)
    from_pattern = re.compile(
        r"impl(?:<[^>]*>)?\s+(?:Try)?From<([^>]+)>\s+for\s+([A-Za-z0-9_:]+)",
        re.MULTILINE,
    )
    into_pattern = re.compile(
        r"impl(?:<[^>]*>)?\s+(?:Try)?Into<([^>]+)>\s+for\s+([A-Za-z0-9_:]+)",
        re.MULTILINE,
    )

    workspace_alias_map: dict[str, str] = {}
    for m_decl in module_declarations:
        m_abs = root / m_decl
        if m_abs.is_file():
            try:
                m_content = m_abs.read_text(encoding="utf-8")
                workspace_alias_map.update(extract_type_aliases(m_content))
                workspace_alias_map.update(extract_use_renames(m_content, pub_only=True))
            except Exception:
                pass

    for mod_rel, mod_plane in module_declarations.items():
        abs_path = root / mod_rel
        if not abs_path.is_file():
            findings.append(
                SemanticPlaneFinding(
                    code=ERR_REGISTRY_INVALID,
                    file=mod_rel,
                    location="file_system",
                    message=f"Declared module '{mod_rel}' does not exist on disk",
                    severity="error",
                    remediation=DIAGNOSTIC_REGISTRY[ERR_REGISTRY_INVALID]["remediation"],
                    params={"module": mod_rel},
                )
            )
            continue

        try:
            content = abs_path.read_text(encoding="utf-8")
        except (OSError, UnicodeDecodeError) as exc:
            findings.append(
                SemanticPlaneFinding(
                    code=ERR_REGISTRY_INVALID,
                    file=mod_rel,
                    location="file_system",
                    message=f"Failed to read declared module '{mod_rel}': {exc}",
                    severity="error",
                    remediation=DIAGNOSTIC_REGISTRY[ERR_REGISTRY_INVALID]["remediation"],
                    params={"module": mod_rel},
                )
            )
            continue

        if mod_rel in boundary_modules:
            continue

        local_aliases = extract_type_aliases(content)
        local_use_renames = extract_use_renames(content)
        file_alias_map = dict(workspace_alias_map)
        file_alias_map.update(local_use_renames)
        file_alias_map.update(local_aliases)

        eff_model, eff_effect, eff_absten, eff_neg = build_effective_plane_types(
            file_alias_map, registered_types
        )
        eff_auth = {
            ty
            for ty in eff_effect
            if ty in AUTHORITY_TYPES
            or registered_types.get(ty, {}).get("plane") == "authority"
            or "authority" in ty.lower()
        }

        # Check for functions directly returning EffectAuthority in cognition modules,
        # or bridging model outputs directly to effects, or abstention to negative evidence
        for (
            fn_name,
            generics,
            params,
            ret_type,
            where_clause,
            impl_type,
            impl_header,
            start_pos,
            full_fn,
        ) in extract_rust_functions(content):
            bounds = parse_all_generic_bounds(generics, where_clause, impl_header, file_alias_map)

            # NEG-003: Model/VLM output can never reach an effect type directly
            is_model_input = (
                any(
                    re.search(r"\b" + re.escape(m_ty) + r"\b", params)
                    for m_ty in eff_model
                )
                or any(
                    m_ty == impl_type
                    or (
                        impl_type
                        and re.search(r"\b" + re.escape(m_ty) + r"\b", impl_type)
                    )
                    for m_ty in eff_model
                )
                or any(
                    re.search(r"\b" + re.escape(m_ty) + r"\b", full_fn)
                    for m_ty in eff_model
                )
                or "vlm" in fn_name.lower()
                or "model" in fn_name.lower()
            )
            if not is_model_input:
                param_tokens = re.findall(r"\b[A-Za-z0-9_]+\b", params)
                for pt in param_tokens:
                    candidates = {pt, normalise_type_name(pt, file_alias_map)}
                    for cand in candidates:
                        if cand in bounds:
                            for b in bounds[cand]:
                                b_tokens = re.findall(r"\b[A-Za-z0-9_]+\b", b)
                                if any(
                                    bt in eff_model
                                    or normalise_type_name(bt, file_alias_map) in eff_model
                                    for bt in b_tokens
                                ):
                                    is_model_input = True
                                    break
                        if is_model_input:
                            break
                    if is_model_input:
                        break

            is_effect_ret = is_effect_or_authority_type(
                ret_type, registered_types, eff_effect, file_alias_map
            )
            if not is_effect_ret:
                ret_tokens = re.findall(r"\b[A-Za-z0-9_]+\b", ret_type)
                for t in ret_tokens:
                    candidates = {t, normalise_type_name(t, file_alias_map)}
                    for cand in candidates:
                        if cand in bounds:
                            for b in bounds[cand]:
                                m_into = re.search(
                                    r"\b(?:Into|TryInto|AsRef|Borrow)<([^>]+)>", b
                                )
                                if m_into:
                                    inner_tokens = re.findall(
                                        r"\b[A-Za-z0-9_]+\b", m_into.group(1)
                                    )
                                    if any(
                                        it in eff_effect
                                        or normalise_type_name(it, file_alias_map) in eff_effect
                                        or registered_types.get(it, {}).get("plane")
                                        in ("effect", "authority")
                                        or registered_types.get(
                                            normalise_type_name(it, file_alias_map), {}
                                        ).get("plane")
                                        in ("effect", "authority")
                                        for it in inner_tokens
                                    ):
                                        is_effect_ret = True
                                        break
                                b_tokens = re.findall(r"\b[A-Za-z0-9_]+\b", b)
                                if any(
                                    bt in eff_effect
                                    or normalise_type_name(bt, file_alias_map) in eff_effect
                                    or registered_types.get(bt, {}).get("plane")
                                    in ("effect", "authority")
                                    or registered_types.get(
                                        normalise_type_name(bt, file_alias_map), {}
                                    ).get("plane")
                                    in ("effect", "authority")
                                    for bt in b_tokens
                                ):
                                    is_effect_ret = True
                                    break
                        if is_effect_ret:
                            break
                    if is_effect_ret:
                        break

            if is_model_input and is_effect_ret:
                line_no = content[:start_pos].count("\n") + 1
                findings.append(
                    SemanticPlaneFinding(
                        code=ERR_MODEL_OUTPUT_REACHES_EFFECT,
                        file=mod_rel,
                        location=f"line {line_no}",
                        message=f"Prohibited direct model-to-effect bridge (NEG-003): function '{fn_name}' takes model output and returns effect type ({ret_type})",
                        severity="error",
                        remediation=DIAGNOSTIC_REGISTRY[ERR_MODEL_OUTPUT_REACHES_EFFECT]["remediation"],
                        params={"module": mod_rel, "function": fn_name, "return_type": ret_type},
                    )
                )
            elif mod_plane == "cognition" and (
                re.search(r"\bEffectAuthority\b", ret_type)
                or any(
                    t in eff_auth
                    or normalise_type_name(t, file_alias_map) in eff_auth
                    for t in re.findall(r"\b[A-Za-z0-9_]+\b", ret_type)
                )
                or any(
                    any(
                        "EffectAuthority" in b
                        or any(
                            bt in eff_auth
                            or normalise_type_name(bt, file_alias_map) in eff_auth
                            for bt in re.findall(r"\b[A-Za-z0-9_]+\b", b)
                        )
                        for b in bounds.get(cand, [])
                    )
                    for t in re.findall(r"\b[A-Za-z0-9_]+\b", ret_type)
                    for cand in (t, normalise_type_name(t, file_alias_map))
                )
            ):
                line_no = content[:start_pos].count("\n") + 1
                findings.append(
                    SemanticPlaneFinding(
                        code=ERR_COGNITION_GRANTS_EFFECT,
                        file=mod_rel,
                        location=f"line {line_no}",
                        message=f"Prohibited cognition-to-effect bridge: module '{mod_rel}' has function '{fn_name}' returning EffectAuthority ({ret_type})",
                        severity="error",
                        remediation=DIAGNOSTIC_REGISTRY[ERR_COGNITION_GRANTS_EFFECT]["remediation"],
                        params={"module": mod_rel, "type_name": "EffectAuthority", "function": fn_name},
                    )
                )

            # NEG-003: Abstention/failure is never negative evidence
            is_absten_input = (
                any(
                    re.search(r"\b" + re.escape(a_ty) + r"\b", params)
                    for a_ty in eff_absten
                )
                or any(
                    m_ty == impl_type
                    or (
                        impl_type
                        and re.search(r"\b" + re.escape(m_ty) + r"\b", impl_type)
                    )
                    for m_ty in eff_absten
                )
                or any(
                    re.search(r"\b" + re.escape(a_ty) + r"\b", full_fn)
                    for a_ty in eff_absten
                )
                or "absten" in fn_name.lower()
            )
            is_negative_evidence_ret = any(
                re.search(r"\b" + re.escape(n_ty) + r"\b", ret_type)
                for n_ty in eff_neg
            )
            if is_absten_input and is_negative_evidence_ret:
                line_no = content[:start_pos].count("\n") + 1
                findings.append(
                    SemanticPlaneFinding(
                        code=ERR_ABSTENTION_AS_NEGATIVE_EVIDENCE,
                        file=mod_rel,
                        location=f"line {line_no}",
                        message=f"Prohibited model abstention as negative evidence (NEG-003): function '{fn_name}' returns '{ret_type}' from model abstention",
                        severity="error",
                        remediation=DIAGNOSTIC_REGISTRY[ERR_ABSTENTION_AS_NEGATIVE_EVIDENCE]["remediation"],
                        params={"module": mod_rel, "function": fn_name, "return_type": ret_type},
                    )
                )

        # Check From/Into cross-plane implementations
        for m in from_pattern.finditer(content):
            from_ty = normalise_type_name(m.group(1), file_alias_map)
            to_ty = normalise_type_name(m.group(2), file_alias_map)
            from_plane = registered_types.get(from_ty, {}).get("plane")
            to_plane = registered_types.get(to_ty, {}).get("plane")

            is_model_output = (
                from_ty in eff_model
                or "vlm" in from_ty.lower()
                or "model" in from_ty.lower()
            )
            is_effect_type = is_effect_or_authority_type(
                to_ty, registered_types, eff_effect, file_alias_map
            )
            is_abstention = from_ty in eff_absten or "absten" in from_ty.lower()
            is_negative_evidence = to_ty in eff_neg or to_ty == "CoverageWitness"

            if is_model_output and is_effect_type:
                line_no = content[: m.start()].count("\n") + 1
                findings.append(
                    SemanticPlaneFinding(
                        code=ERR_MODEL_OUTPUT_REACHES_EFFECT,
                        file=mod_rel,
                        location=f"line {line_no}",
                        message=f"Forbidden model-to-effect conversion (NEG-003): From<{from_ty}> for {to_ty} in non-boundary module '{mod_rel}'",
                        severity="error",
                        remediation=DIAGNOSTIC_REGISTRY[ERR_MODEL_OUTPUT_REACHES_EFFECT]["remediation"],
                        params={"module": mod_rel, "from_type": from_ty, "to_type": to_ty},
                    )
                )
            elif is_abstention and is_negative_evidence:
                line_no = content[: m.start()].count("\n") + 1
                findings.append(
                    SemanticPlaneFinding(
                        code=ERR_ABSTENTION_AS_NEGATIVE_EVIDENCE,
                        file=mod_rel,
                        location=f"line {line_no}",
                        message=f"Forbidden abstention-to-negative-evidence conversion (NEG-003): From<{from_ty}> for {to_ty} in non-boundary module '{mod_rel}'",
                        severity="error",
                        remediation=DIAGNOSTIC_REGISTRY[ERR_ABSTENTION_AS_NEGATIVE_EVIDENCE]["remediation"],
                        params={"module": mod_rel, "from_type": from_ty, "to_type": to_ty},
                    )
                )
            elif from_plane and to_plane and from_plane != to_plane:
                if from_plane not in ("support", "ambiguous") and to_plane not in ("support", "ambiguous"):
                    line_no = content[: m.start()].count("\n") + 1
                    code = (
                        ERR_COGNITION_GRANTS_EFFECT
                        if (from_plane == "cognition" and to_plane in ("authority", "effect"))
                        else ERR_UNAUTHORIZED_CROSS_PLANE_IMPORT
                    )
                    findings.append(
                        SemanticPlaneFinding(
                            code=code,
                            file=mod_rel,
                            location=f"line {line_no}",
                            message=f"Forbidden cross-plane conversion: From<{from_ty}> ({from_plane}) for {to_ty} ({to_plane}) in non-boundary module '{mod_rel}'",
                            severity="error",
                            remediation=DIAGNOSTIC_REGISTRY[code]["remediation"],
                            params={"module": mod_rel, "from_type": from_ty, "to_type": to_ty},
                        )
                    )

        for m in into_pattern.finditer(content):
            to_ty = normalise_type_name(m.group(1), file_alias_map)
            from_ty = normalise_type_name(m.group(2), file_alias_map)
            from_plane = registered_types.get(from_ty, {}).get("plane")
            to_plane = registered_types.get(to_ty, {}).get("plane")

            is_model_output = (
                from_ty in eff_model
                or "vlm" in from_ty.lower()
                or "model" in from_ty.lower()
            )
            is_effect_type = is_effect_or_authority_type(
                to_ty, registered_types, eff_effect, file_alias_map
            )
            is_abstention = from_ty in eff_absten or "absten" in from_ty.lower()
            is_negative_evidence = to_ty in eff_neg or to_ty == "CoverageWitness"

            if is_model_output and is_effect_type:
                line_no = content[: m.start()].count("\n") + 1
                findings.append(
                    SemanticPlaneFinding(
                        code=ERR_MODEL_OUTPUT_REACHES_EFFECT,
                        file=mod_rel,
                        location=f"line {line_no}",
                        message=f"Forbidden model-to-effect conversion (NEG-003): Into<{to_ty}> for {from_ty} in non-boundary module '{mod_rel}'",
                        severity="error",
                        remediation=DIAGNOSTIC_REGISTRY[ERR_MODEL_OUTPUT_REACHES_EFFECT]["remediation"],
                        params={"module": mod_rel, "from_type": from_ty, "to_type": to_ty},
                    )
                )

            elif is_abstention and is_negative_evidence:
                line_no = content[: m.start()].count("\n") + 1
                findings.append(
                    SemanticPlaneFinding(
                        code=ERR_ABSTENTION_AS_NEGATIVE_EVIDENCE,
                        file=mod_rel,
                        location=f"line {line_no}",
                        message=f"Forbidden abstention-to-negative-evidence conversion (NEG-003): Into<{to_ty}> for {from_ty} in non-boundary module '{mod_rel}'",
                        severity="error",
                        remediation=DIAGNOSTIC_REGISTRY[ERR_ABSTENTION_AS_NEGATIVE_EVIDENCE]["remediation"],
                        params={"module": mod_rel, "from_type": from_ty, "to_type": to_ty},
                    )
                )
            elif from_plane and to_plane and from_plane != to_plane:
                if from_plane not in ("support", "ambiguous") and to_plane not in ("support", "ambiguous"):
                    line_no = content[: m.start()].count("\n") + 1
                    code = (
                        ERR_COGNITION_GRANTS_EFFECT
                        if (from_plane == "cognition" and to_plane in ("authority", "effect"))
                        else ERR_UNAUTHORIZED_CROSS_PLANE_IMPORT
                    )
                    findings.append(
                        SemanticPlaneFinding(
                            code=code,
                            file=mod_rel,
                            location=f"line {line_no}",
                            message=f"Forbidden cross-plane conversion: Into<{to_ty}> ({to_plane}) for {from_ty} ({from_plane}) in non-boundary module '{mod_rel}'",
                            severity="error",
                            remediation=DIAGNOSTIC_REGISTRY[code]["remediation"],
                            params={"module": mod_rel, "from_type": from_ty, "to_type": to_ty},
                        )
                    )

        # Skip use-statement cross-plane import restrictions for support or ambiguous modules
        if mod_plane in ("support", "ambiguous"):
            continue

        # Check use statements for unauthorized cross-plane imports
        for match in use_pattern.finditer(content):
            stmt = match.group(0)
            line_no = content[: match.start()].count("\n") + 1

            for type_name, type_info in registered_types.items():
                type_plane = type_info.get("plane")
                if type_plane in (mod_plane, "support", "ambiguous"):
                    continue

                is_cross = False
                if mod_plane == "cognition" and type_plane in ("authority", "effect"):
                    is_cross = True
                elif mod_plane == "effect" and type_plane in ("cognition",):
                    is_cross = True
                elif mod_plane == "authority" and type_plane in ("cognition", "effect"):
                    is_cross = True

                if is_cross and re.search(r"\b" + re.escape(type_name) + r"\b", stmt):
                    findings.append(
                        SemanticPlaneFinding(
                            code=ERR_UNAUTHORIZED_CROSS_PLANE_IMPORT,
                            file=mod_rel,
                            location=f"line {line_no}",
                            message=f"Unauthorized cross-plane import: module '{mod_rel}' declared for '{mod_plane}' imports {type_plane}-plane type '{type_name}' outside registered boundary modules",
                            severity="error",
                            remediation=DIAGNOSTIC_REGISTRY[ERR_UNAUTHORIZED_CROSS_PLANE_IMPORT]["remediation"],
                            params={
                                "module": mod_rel,
                                "declared_plane": mod_plane,
                                "imported_type": type_name,
                                "type_plane": type_plane,
                            },
                        )
                    )

            # Wildcard import check (e.g. use fss_core::effect::* or use crate::effect::*)
            if "::*" in stmt:
                for other_mod_rel, other_plane in module_declarations.items():
                    if other_plane in (mod_plane, "support", "ambiguous"):
                        continue
                    mod_stem = Path(other_mod_rel).stem
                    if mod_stem in ("lib", "mod"):
                        continue

                    is_cross = False
                    if mod_plane == "cognition" and other_plane in ("authority", "effect"):
                        is_cross = True
                    elif mod_plane == "effect" and other_plane in ("cognition",):
                        is_cross = True
                    elif mod_plane == "authority" and other_plane in ("cognition", "effect"):
                        is_cross = True

                    if is_cross and re.search(r"\b" + re.escape(mod_stem) + r"::\*", stmt):
                        findings.append(
                            SemanticPlaneFinding(
                                code=ERR_UNAUTHORIZED_CROSS_PLANE_IMPORT,
                                file=mod_rel,
                                location=f"line {line_no}",
                                message=f"Unauthorized cross-plane wildcard import: module '{mod_rel}' declared for '{mod_plane}' imports all symbols from {other_plane}-plane module '{mod_stem}' outside registered boundary modules",
                                severity="error",
                                remediation=DIAGNOSTIC_REGISTRY[ERR_UNAUTHORIZED_CROSS_PLANE_IMPORT]["remediation"],
                                params={
                                    "module": mod_rel,
                                    "declared_plane": mod_plane,
                                    "imported_module": mod_stem,
                                    "type_plane": other_plane,
                                },
                            )
                        )

    return findings


def check_model_corroboration_policy(root: Path) -> list[SemanticPlaneFinding]:
    """Audits corroboration policies to enforce NEG-003 / INV-055: single model is never independent corroboration."""
    findings: list[SemanticPlaneFinding] = []

    search_dirs = [root / "architecture", root / "schemas"]
    json_files: list[Path] = []
    for d in search_dirs:
        if d.is_dir():
            json_files.extend(sorted(d.glob("*.json")))

    for jf in json_files:
        rel_path = sanitize_path(jf, root)
        try:
            content = jf.read_text(encoding="utf-8")
        except (OSError, UnicodeDecodeError) as exc:
            findings.append(
                SemanticPlaneFinding(
                    code=ERR_SINGLE_MODEL_CORROBORATION,
                    file=rel_path,
                    location="file_system",
                    message=f"Failed to read file for corroboration policy check: {exc}",
                    severity="error",
                    remediation=DIAGNOSTIC_REGISTRY[ERR_SINGLE_MODEL_CORROBORATION]["remediation"],
                )
            )
            continue
        try:
            data = json.loads(content)
        except json.JSONDecodeError as exc:
            findings.append(
                SemanticPlaneFinding(
                    code=ERR_SINGLE_MODEL_CORROBORATION,
                    file=rel_path,
                    location="file_system",
                    message=f"Failed to parse JSON for corroboration policy check: {exc}",
                    severity="error",
                    remediation=DIAGNOSTIC_REGISTRY[ERR_SINGLE_MODEL_CORROBORATION]["remediation"],
                )
            )
            continue

        def inspect_obj(obj: Any, path: str) -> None:
            if isinstance(obj, dict):
                for k, v in obj.items():
                    current_path = f"{path}/{k}" if path else k
                    if k in (
                        "min_sources",
                        "min_sensors",
                        "min_models",
                        "min_failure_domains",
                        "min_corroboration_sources",
                    ):
                        if isinstance(v, int) and v < 2:
                            findings.append(
                                SemanticPlaneFinding(
                                    code=ERR_SINGLE_MODEL_CORROBORATION,
                                    file=rel_path,
                                    location=current_path,
                                    message=(
                                        f"Single model corroboration prohibited (NEG-003 / INV-055): "
                                        f"'{current_path}' is {v}, but corroboration requires >= 2 distinct sources"
                                    ),
                                    severity="error",
                                    remediation=DIAGNOSTIC_REGISTRY[ERR_SINGLE_MODEL_CORROBORATION]["remediation"],
                                    params={"file": rel_path, "field": current_path, "value": v},
                                )
                            )
                    if k in (
                        "allow_single_model",
                        "allow_single_sensor",
                        "single_model_corroboration",
                    ):
                        if v is True:
                            findings.append(
                                SemanticPlaneFinding(
                                    code=ERR_SINGLE_MODEL_CORROBORATION,
                                    file=rel_path,
                                    location=current_path,
                                    message=(
                                        f"Single model corroboration prohibited (NEG-003 / INV-055): "
                                        f"'{current_path}' permits single-model corroboration"
                                    ),
                                    severity="error",
                                    remediation=DIAGNOSTIC_REGISTRY[ERR_SINGLE_MODEL_CORROBORATION]["remediation"],
                                    params={"file": rel_path, "field": current_path},
                                )
                            )
                    inspect_obj(v, current_path)
            elif isinstance(obj, list):
                for idx, item in enumerate(obj):
                    inspect_obj(item, f"{path}[{idx}]")

        inspect_obj(data, "")

    return findings


def is_mutable_generation_str(gen: str) -> bool:
    trimmed = gen.strip()
    if not trimmed:
        return False
    lower = trimmed.lower()
    if lower in MUTABLE_GENERATION_TOKENS:
        return True
    tokens = re.split(r"[^a-zA-Z0-9]+", lower)
    return any(t in MUTABLE_GENERATION_TOKENS for t in tokens if t)


def check_model_generation_immutability(root: Path) -> list[SemanticPlaneFinding]:
    """Audits model configurations and manifests to enforce ADR-0004 / NEG-003 immutability."""
    findings: list[SemanticPlaneFinding] = []

    search_dirs = [root / "architecture", root / "models"]
    json_files: list[Path] = []
    for d in search_dirs:
        if d.is_dir():
            json_files.extend(sorted(d.glob("*.json")))

    for jf in json_files:
        rel_path = sanitize_path(jf, root)
        try:
            content = jf.read_text(encoding="utf-8")
        except (OSError, UnicodeDecodeError) as exc:
            findings.append(
                SemanticPlaneFinding(
                    code=ERR_MUTABLE_MODEL_GENERATION,
                    file=rel_path,
                    location="file_system",
                    message=f"Failed to read file for model generation immutability check: {exc}",
                    severity="error",
                    remediation=DIAGNOSTIC_REGISTRY[ERR_MUTABLE_MODEL_GENERATION]["remediation"],
                )
            )
            continue
        try:
            data = json.loads(content)
        except json.JSONDecodeError as exc:
            findings.append(
                SemanticPlaneFinding(
                    code=ERR_MUTABLE_MODEL_GENERATION,
                    file=rel_path,
                    location="file_system",
                    message=f"Failed to parse JSON for model generation immutability check: {exc}",
                    severity="error",
                    remediation=DIAGNOSTIC_REGISTRY[ERR_MUTABLE_MODEL_GENERATION]["remediation"],
                )
            )
            continue

        def inspect_obj(obj: Any, path: str) -> None:
            if isinstance(obj, dict):
                for k, v in obj.items():
                    current_path = f"{path}/{k}" if path else k
                    if k in ("generation", "model_generation", "generation_id", "weights_generation"):
                        if isinstance(v, str) and is_mutable_generation_str(v):
                            findings.append(
                                SemanticPlaneFinding(
                                    code=ERR_MUTABLE_MODEL_GENERATION,
                                    file=rel_path,
                                    location=current_path,
                                    message=(
                                        f"Mutable model generation alias prohibited (ADR-0004 / NEG-003): "
                                        f"'{current_path}' is '{v}'; generations must be immutable qualified identifiers"
                                    ),
                                    severity="error",
                                    remediation=DIAGNOSTIC_REGISTRY[ERR_MUTABLE_MODEL_GENERATION]["remediation"],
                                    params={"file": rel_path, "field": current_path, "value": v},
                                )
                            )
                    inspect_obj(v, current_path)
            elif isinstance(obj, list):
                for idx, item in enumerate(obj):
                    inspect_obj(item, f"{path}[{idx}]")

        inspect_obj(data, "")

    return findings


def audit_subsystem_generation_constructors(root: Path) -> list[SemanticPlaneFinding]:
    """Audits subsystem generation constructors to ensure unvalidated test helpers are strictly feature-gated (review-749 #6)."""
    findings: list[SemanticPlaneFinding] = []

    # 1. Check crates/fss-core/src/ids.rs for ungated from_unvalidated_for_test
    core_ids = root / "crates" / "fss-core" / "src" / "ids.rs"
    if core_ids.is_file():
        rel_path = sanitize_path(core_ids, root)
        try:
            content = core_ids.read_text(encoding="utf-8")
        except (OSError, UnicodeDecodeError) as exc:
            findings.append(
                SemanticPlaneFinding(
                    code=ERR_MUTABLE_MODEL_GENERATION,
                    file=rel_path,
                    location="file_system",
                    message=f"Failed to read '{rel_path}': {exc}",
                    severity="error",
                    remediation=DIAGNOSTIC_REGISTRY[ERR_MUTABLE_MODEL_GENERATION]["remediation"],
                )
            )
            content = ""

        if "from_unvalidated_for_test" in content:
            lines = content.splitlines()
            for idx, line in enumerate(lines):
                if "fn from_unvalidated_for_test" in line:
                    window = lines[max(0, idx - 6) : idx]
                    has_cfg = any(
                        re.search(r'#\[cfg\(feature\s*=\s*"test-support"\)\]', prev)
                        for prev in window
                    )
                    if not has_cfg:
                        findings.append(
                            SemanticPlaneFinding(
                                code=ERR_MUTABLE_MODEL_GENERATION,
                                file=rel_path,
                                location=f"line {idx + 1}",
                                message=(
                                    "Unrestricted public constructor 'from_unvalidated_for_test' bypasses validation "
                                    "in production (review-749 #6); must be gated with #[cfg(feature = \"test-support\")]"
                                ),
                                severity="error",
                                remediation="Gate from_unvalidated_for_test behind #[cfg(feature = \"test-support\")]",
                                params={"file": rel_path, "line": idx + 1},
                            )
                        )

    # 2. Check that no production code in crates/*/src/ calls from_unvalidated_for_test
    crates_dir = root / "crates"
    if crates_dir.is_dir():
        for crate_dir in sorted(crates_dir.iterdir()):
            if not crate_dir.is_dir():
                continue
            src_dir = crate_dir / "src"
            if src_dir.is_dir():
                for rs_file in sorted(src_dir.rglob("*.rs")):
                    if core_ids.is_file() and rs_file.resolve() == core_ids.resolve():
                        continue
                    rel_rs = sanitize_path(rs_file, root)
                    try:
                        rs_content = rs_file.read_text(encoding="utf-8")
                    except (OSError, UnicodeDecodeError):
                        continue
                    if "from_unvalidated_for_test" in rs_content:
                        for l_idx, l_str in enumerate(rs_content.splitlines()):
                            if "from_unvalidated_for_test" in l_str and not l_str.strip().startswith("//"):
                                findings.append(
                                    SemanticPlaneFinding(
                                        code=ERR_MUTABLE_MODEL_GENERATION,
                                        file=rel_rs,
                                        location=f"line {l_idx + 1}",
                                        message=(
                                            f"Production code in '{rel_rs}' calls test-only constructor "
                                            f"'from_unvalidated_for_test'; production code must use validated parse/try_from"
                                        ),
                                        severity="error",
                                        remediation="Remove call to from_unvalidated_for_test in production code; use parse",
                                        params={"file": rel_rs, "line": l_idx + 1},
                                    )
                                )

    # 3. Check crates/fss-core/Cargo.toml has test-support declared under [features] and NOT in default
    core_cargo = root / "crates" / "fss-core" / "Cargo.toml"
    if core_cargo.is_file():
        rel_cargo = sanitize_path(core_cargo, root)
        try:
            cargo_content = core_cargo.read_text(encoding="utf-8")
            parsed = tomllib.loads(cargo_content)
            features = parsed.get("features", {})
            if "test-support" not in features:
                findings.append(
                    SemanticPlaneFinding(
                        code=ERR_MUTABLE_MODEL_GENERATION,
                        file=rel_cargo,
                        location="[features]",
                        message="crates/fss-core/Cargo.toml must declare 'test-support' feature under [features]",
                        severity="error",
                        remediation="Add 'test-support = []' under [features] in crates/fss-core/Cargo.toml",
                    )
                )
            if "test-support" in features.get("default", []):
                findings.append(
                    SemanticPlaneFinding(
                        code=ERR_MUTABLE_MODEL_GENERATION,
                        file=rel_cargo,
                        location="[features].default",
                        message="crates/fss-core/Cargo.toml default features must NOT include 'test-support'",
                        severity="error",
                        remediation="Remove 'test-support' from default features in crates/fss-core/Cargo.toml",
                    )
                )
        except Exception as exc:
            findings.append(
                SemanticPlaneFinding(
                    code=ERR_MUTABLE_MODEL_GENERATION,
                    file=rel_cargo,
                    location="Cargo.toml",
                    message=f"Failed to parse '{rel_cargo}': {exc}",
                    severity="error",
                    remediation="Ensure crates/fss-core/Cargo.toml is valid TOML",
                )
            )

    # 4. Check all crate Cargo.tomls: non-dev [dependencies] cannot enable test-support on fss-core
    if crates_dir.is_dir():
        for crate_dir in sorted(crates_dir.iterdir()):
            cargo_file = crate_dir / "Cargo.toml"
            if cargo_file.is_file():
                rel_cf = sanitize_path(cargo_file, root)
                try:
                    c_data = tomllib.loads(cargo_file.read_text(encoding="utf-8"))
                    prod_deps = c_data.get("dependencies", {})
                    fss_core_dep = prod_deps.get("fss-core")
                    if isinstance(fss_core_dep, dict):
                        f_list = fss_core_dep.get("features", [])
                        if "test-support" in f_list:
                            findings.append(
                                SemanticPlaneFinding(
                                    code=ERR_MUTABLE_MODEL_GENERATION,
                                    file=rel_cf,
                                    location="[dependencies].fss-core",
                                    message=f"Production dependency in '{rel_cf}' enables 'test-support' feature on fss-core",
                                    severity="error",
                                    remediation="Move 'test-support' feature to [dev-dependencies] only",
                                )
                            )
                except Exception:
                    pass

    return findings



def audit_semantic_planes(
    root: Path,
    registry_path: Path | None = None,
    check_doctests: bool = True,
) -> tuple[bool, list[SemanticPlaneFinding], dict[str, Any]]:
    """Runs full deterministic semantic plane audit."""
    if registry_path is None:
        registry_path = root / "architecture/semantic_plane_registry.json"

    findings: list[SemanticPlaneFinding] = []
    registry, reg_findings = load_semantic_plane_registry(registry_path, root)
    findings.extend(reg_findings)

    if registry is None:
        summary = {
            "status": "fail",
            "error_count": len([f for f in findings if f.severity == "error"]),
            "warning_count": 0,
            "types_mapped": 0,
            "authority_types": 0,
            "cognition_types": 0,
            "effect_types": 0,
            "ambiguous_types": 0,
            "doctests_passed": 0,
        }
        return False, findings, summary

    # Report ambiguous types honestly
    for type_name, type_info in registry.get("types", {}).items():
        if type_info.get("plane") == "ambiguous":
            reason = type_info.get(
                "ambiguity_reason",
                type_info.get("description", "Cross-plane boundary representation"),
            )
            findings.append(
                SemanticPlaneFinding(
                    code=INFO_AMBIGUOUS_TYPE,
                    file=type_info.get("file", "unknown"),
                    location="registry",
                    message=f"Boundary type '{type_name}' bridges multiple planes: {reason}",
                    severity="info",
                    remediation=DIAGNOSTIC_REGISTRY[INFO_AMBIGUOUS_TYPE]["remediation"],
                    params={
                        "type_name": type_name,
                        "file": type_info.get("file", ""),
                        "reason": reason,
                    },
                )
            )

    # Workspace module census audit
    findings.extend(audit_workspace_module_census(root, registry))

    # Core type census audit
    findings.extend(audit_fss_core_type_census(root, registry))

    # Cross-plane import policy audit
    findings.extend(check_module_imports(root, registry))

    # NEG-003 Corroboration policy audit (min_sources >= 2)
    findings.extend(check_model_corroboration_policy(root))

    # NEG-003 Model generation immutability audit (no mutable aliases like 'latest')
    findings.extend(check_model_generation_immutability(root))

    # NEG-003 Subsystem generation constructor audit (review-749 #6)
    findings.extend(audit_subsystem_generation_constructors(root))

    # Contract doc claims audit (F1, F8)
    contract_path = root / "docs/enforcement/three_semantic_planes_contract.md"
    findings.extend(audit_contract_doc_claims(root, contract_path))

    # Compile-fail doctests verification
    doctests_passed = 0
    if check_doctests:
        if not contract_path.is_file():
            findings.append(
                SemanticPlaneFinding(
                    code=ERR_DOCTEST_FAILED,
                    file=sanitize_path(contract_path, root),
                    location="file_system",
                    message=f"Contract doctest file missing: '{sanitize_path(contract_path, root)}'",
                    severity="error",
                    remediation=DIAGNOSTIC_REGISTRY[ERR_DOCTEST_FAILED]["remediation"],
                )
            )
        else:
            success, count, err = verify_compile_fail_doctests(contract_path, root)
            if success:
                doctests_passed = count
            else:
                findings.append(
                    SemanticPlaneFinding(
                        code=ERR_DOCTEST_FAILED,
                        file=sanitize_path(contract_path, root),
                        location="contract_map",
                        message=f"Compile-fail doctest verification failed: {err}",
                        severity="error",
                        remediation=DIAGNOSTIC_REGISTRY[ERR_DOCTEST_FAILED]["remediation"],
                    )
                )

    types_dict = registry.get("types", {})
    authority_count = sum(1 for v in types_dict.values() if v.get("plane") == "authority")
    cognition_count = sum(1 for v in types_dict.values() if v.get("plane") == "cognition")
    effect_count = sum(1 for v in types_dict.values() if v.get("plane") == "effect")
    ambiguous_count = sum(1 for v in types_dict.values() if v.get("plane") == "ambiguous")
    error_count = sum(1 for f in findings if f.severity == "error")
    warning_count = sum(1 for f in findings if f.severity == "warning")

    is_valid = error_count == 0
    summary = {
        "status": "pass" if is_valid else "fail",
        "error_count": error_count,
        "warning_count": warning_count,
        "types_mapped": len(types_dict),
        "authority_types": authority_count,
        "cognition_types": cognition_count,
        "effect_types": effect_count,
        "ambiguous_types": ambiguous_count,
        "doctests_verified": doctests_passed,
    }

    return is_valid, findings, summary


def main() -> int:
    parser = argparse.ArgumentParser(description="Audit ADR-0001 three semantic planes enforcement")
    parser.add_argument("--root", type=Path, default=ROOT, help="Project root directory")
    parser.add_argument(
        "--registry",
        type=Path,
        default=None,
        help="Path to semantic_plane_registry.json",
    )
    parser.add_argument("--json", action="store_true", help="Output results in JSON format")
    parser.add_argument("--quiet", action="store_true", help="Suppress non-error output")
    parser.add_argument(
        "--skip-doctests",
        action="store_true",
        help="Skip verifying ADR-0001 compile-fail doctest mappings",
    )
    args = parser.parse_args()

    root = args.root.resolve()
    reg_path = args.registry.resolve() if args.registry else None

    is_valid, findings, summary = audit_semantic_planes(
        root=root,
        registry_path=reg_path,
        check_doctests=not args.skip_doctests,
    )

    if args.json:
        payload = {
            "summary": summary,
            "findings": [asdict(f) for f in findings],
        }
        print(json.dumps(payload, indent=2))
    else:
        if not args.quiet:
            print("================================================================================")
            print("Deterministic ADR-0001 Three Semantic Planes Audit")
            print("================================================================================")
            print(f"Status:            {summary['status'].upper()}")
            print(f"Types Mapped:      {summary['types_mapped']}")
            print(f"  Authority:       {summary['authority_types']}")
            print(f"  Cognition:       {summary['cognition_types']}")
            print(f"  Effect:          {summary['effect_types']}")
            print(f"  Ambiguous:       {summary['ambiguous_types']}")
            print(f"Doctests Verified: {summary['doctests_verified']}")
            print(f"Errors:            {summary['error_count']}")
            print("================================================================================")

        for finding in findings:
            if finding.severity == "error":
                print(f"[ERROR] [{finding.code}] {finding.file}:{finding.location} - {finding.message}")
            elif finding.severity == "warning":
                print(f"[WARN]  [{finding.code}] {finding.file}:{finding.location} - {finding.message}")
            elif not args.quiet:
                print(f"[INFO]  [{finding.code}] {finding.file}:{finding.location} - {finding.message}")

        if is_valid:
            if not args.quiet:
                print(f"\n[PASS] Three semantic planes audit passed ({summary['types_mapped']} types mapped, {summary['doctests_verified']} doctests verified)")
        else:
            print(f"\n[FAIL] Three semantic planes audit failed with {summary['error_count']} error(s)")

    return 0 if is_valid else 1


if __name__ == "__main__":
    sys.exit(main())
