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
import subprocess
import sys
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
        "trigger": "Compile-fail doctests in docs/enforcement/three_semantic_planes_contract.md failed to run or passed compilation",
        "remediation": "Ensure forbidden cross-plane conversions trigger compilation failure under rustdoc --test",
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


def resolve_workspace_doctest_flags(root: Path) -> list[str]:
    """Resolves compiler flags (--extern and -L) for workspace crates needed by contract doctests."""
    target_dirs: list[Path] = []
    if "CARGO_TARGET_DIR" in os.environ:
        target_dirs.append(Path(os.environ["CARGO_TARGET_DIR"]))
    target_dirs.extend([
        Path("/data/tmp/cargo-target"),
        Path("/data/tmp/cargo-semantic-plane-doctests"),
        root / "target",
    ])

    crates = ["fss_core", "fss_reference", "fss_ledger", "fss_object", "fss_publication"]
    found_crates: dict[str, Path] = {}
    dep_dirs: set[str] = set()

    for td in target_dirs:
        build_dir = td / "debug" / "build"
        if not build_dir.is_dir():
            continue
        for crate in crates:
            if crate in found_crates:
                continue
            crate_kebab = crate.replace("_", "-")
            pattern = f"{crate_kebab}/*/out/lib{crate}-*.rmeta"
            matches = sorted(
                build_dir.glob(pattern),
                key=lambda p: p.stat().st_mtime,
                reverse=True,
            )
            if matches:
                found_crates[crate] = matches[0]
                dep_dirs.add(str(matches[0].parent))

    missing_crates = [c for c in crates if c not in found_crates]
    if missing_crates:
        try:
            cargo_cmd = ["cargo", "check", "-p", "fss-reference"]
            env = dict(os.environ)
            env["RCH_CARGO_WRAPPER_BYPASS"] = "1"
            subprocess.run(
                cargo_cmd,
                capture_output=True,
                text=True,
                cwd=str(root),
                env=env,
                timeout=60,
            )
            for td in target_dirs:
                build_dir = td / "debug" / "build"
                if not build_dir.is_dir():
                    continue
                for crate in missing_crates:
                    if crate in found_crates:
                        continue
                    crate_kebab = crate.replace("_", "-")
                    pattern = f"{crate_kebab}/*/out/lib{crate}-*.rmeta"
                    matches = sorted(
                        build_dir.glob(pattern),
                        key=lambda p: p.stat().st_mtime,
                        reverse=True,
                    )
                    if matches:
                        found_crates[crate] = matches[0]
                        dep_dirs.add(str(matches[0].parent))
        except (subprocess.TimeoutExpired, OSError, subprocess.SubprocessError):
            pass

    flags: list[str] = []
    for crate, path in found_crates.items():
        flags.extend(["--extern", f"{crate}={path}"])
    for d in sorted(dep_dirs):
        flags.extend(["-L", f"dependency={d}"])

    return flags


def verify_compile_fail_doctests(
    contract_path: Path, root: Path | None = None
) -> tuple[bool, int, str]:
    """Runs rustdoc --test on compile-fail contract and verifies all tests fail compilation as expected."""
    if not contract_path.is_file():
        return False, 0, f"Contract doctest file missing: {contract_path}"

    cmd = ["rustdoc", "--test", str(contract_path), "--edition", "2024"]
    effective_root = root
    if effective_root is None:
        for parent in contract_path.parents:
            if (parent / "Cargo.toml").is_file():
                effective_root = parent
                break
    if effective_root is not None:
        flags = resolve_workspace_doctest_flags(effective_root)
        cmd.extend(flags)

    try:
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            cwd=str(contract_path.parent),
            timeout=30,
        )
    except (subprocess.TimeoutExpired, OSError, subprocess.SubprocessError) as exc:
        return False, 0, f"Failed to execute rustdoc: {exc}"

    if result.returncode != 0:
        return False, 0, f"rustdoc --test failed with code {result.returncode}:\n{result.stdout}\n{result.stderr}"

    # Parse passed test count
    match = re.search(r"test result:\s*ok\.\s*(\d+)\s*passed", result.stdout)
    if not match:
        return False, 0, f"Could not determine test count from rustdoc output:\n{result.stdout}"

    test_count = int(match.group(1))
    if test_count == 0:
        return False, 0, "Zero doctests were executed by rustdoc"

    return True, test_count, ""


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
}

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


def check_module_imports(
    root: Path, registry: dict[str, Any]
) -> list[SemanticPlaneFinding]:
    """Checks that modules declared for a plane do not import foreign plane types or grant effect authority outside boundary modules."""
    findings: list[SemanticPlaneFinding] = []
    registered_types = registry.get("types", {})
    boundary_modules = set(registry.get("registered_boundary_modules", []))
    module_declarations = registry.get("module_declarations", {})

    use_pattern = re.compile(r"\buse\s+([^;]+);", re.MULTILINE)
    fn_sig_pattern = re.compile(
        r"(?:pub(?:\([^\)]*\))?\s+)?fn\s+([A-Za-z0-9_]+)\s*\([^)]*\)\s*->\s*([^;{]+)",
        re.DOTALL,
    )
    from_pattern = re.compile(
        r"impl(?:<[^>]*>)?\s+From<([^>]+)>\s+for\s+([A-Za-z0-9_:]+)",
        re.MULTILINE,
    )
    into_pattern = re.compile(
        r"impl(?:<[^>]*>)?\s+Into<([^>]+)>\s+for\s+([A-Za-z0-9_:]+)",
        re.MULTILINE,
    )

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

        if mod_rel in boundary_modules or mod_plane in ("support", "ambiguous"):
            continue

        # Check for functions directly returning EffectAuthority in cognition modules,
        # or bridging model outputs directly to effects, or abstention to negative evidence
        if mod_plane == "cognition":
            for match in fn_sig_pattern.finditer(content):
                fn_name = match.group(1)
                ret_type = match.group(2).strip()
                full_fn = match.group(0)

                # NEG-003: Model/VLM output can never reach an effect type directly
                is_model_input = any(
                    re.search(r"\b" + re.escape(m_ty) + r"\b", full_fn)
                    for m_ty in MODEL_OUTPUT_TYPES
                ) or "vlm" in fn_name.lower() or "model" in fn_name.lower()
                is_effect_ret = any(
                    re.search(r"\b" + re.escape(e_ty) + r"\b", ret_type)
                    for e_ty in EFFECT_TYPES
                )
                if is_model_input and is_effect_ret:
                    line_no = content[: match.start()].count("\n") + 1
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
                elif re.search(r"\bEffectAuthority\b", ret_type):
                    line_no = content[: match.start()].count("\n") + 1
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
                is_absten_input = any(
                    re.search(r"\b" + re.escape(a_ty) + r"\b", full_fn)
                    for a_ty in ABSTENTION_TYPES
                ) or "absten" in fn_name.lower()
                is_negative_evidence_ret = any(
                    re.search(r"\b" + re.escape(n_ty) + r"\b", ret_type)
                    for n_ty in NEGATIVE_EVIDENCE_TYPES
                )
                if is_absten_input and is_negative_evidence_ret:
                    line_no = content[: match.start()].count("\n") + 1
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
            from_ty = m.group(1).split("::")[-1].strip().lstrip("&").strip()
            to_ty = m.group(2).split("::")[-1].strip().lstrip("&").strip()
            from_plane = registered_types.get(from_ty, {}).get("plane")
            to_plane = registered_types.get(to_ty, {}).get("plane")

            is_model_output = from_ty in MODEL_OUTPUT_TYPES or "vlm" in from_ty.lower()
            is_effect_type = to_ty in EFFECT_TYPES or to_plane == "effect"
            is_abstention = from_ty in ABSTENTION_TYPES or "absten" in from_ty.lower()
            is_negative_evidence = to_ty in NEGATIVE_EVIDENCE_TYPES or to_ty == "CoverageWitness"

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
            to_ty = m.group(1).split("::")[-1].strip().lstrip("&").strip()
            from_ty = m.group(2).split("::")[-1].strip().lstrip("&").strip()
            from_plane = registered_types.get(from_ty, {}).get("plane")
            to_plane = registered_types.get(to_ty, {}).get("plane")

            is_model_output = from_ty in MODEL_OUTPUT_TYPES or "vlm" in from_ty.lower()
            is_effect_type = to_ty in EFFECT_TYPES or to_plane == "effect"
            is_abstention = from_ty in ABSTENTION_TYPES or "absten" in from_ty.lower()
            is_negative_evidence = to_ty in NEGATIVE_EVIDENCE_TYPES or to_ty == "CoverageWitness"

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
        except json.JSONDecodeError:
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
        except json.JSONDecodeError:
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
                        location="rustdoc",
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
        "doctests_passed": doctests_passed,
    }

    return is_valid, findings, summary


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Deterministic ADR-0001 three semantic planes enforcement checker"
    )
    parser.add_argument("--root", type=Path, default=ROOT, help="Repository root directory")
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
        help="Skip executing rustdoc compile-fail doctests",
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
            print(f"Doctests Verified: {summary['doctests_passed']}")
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
                print(f"\n[PASS] Three semantic planes audit passed ({summary['types_mapped']} types mapped, {summary['doctests_passed']} doctests verified)")
        else:
            print(f"\n[FAIL] Three semantic planes audit failed with {summary['error_count']} error(s)")

    return 0 if is_valid else 1


if __name__ == "__main__":
    sys.exit(main())
