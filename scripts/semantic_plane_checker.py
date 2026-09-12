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

    return data, findings


def verify_compile_fail_doctests(contract_path: Path) -> tuple[bool, int, str]:
    """Runs rustdoc --test on compile-fail contract and verifies all tests fail compilation as expected."""
    if not contract_path.is_file():
        return False, 0, f"Contract doctest file missing: {contract_path}"

    cmd = ["rustdoc", "--test", str(contract_path), "--edition", "2024"]
    try:
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            cwd=str(contract_path.parent),
            timeout=30,
        )
    except (subprocess.TimeoutExpired, OSError) as exc:
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
        except (OSError, UnicodeDecodeError):
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


def check_module_imports(
    root: Path, registry: dict[str, Any]
) -> list[SemanticPlaneFinding]:
    """Checks that modules declared for a plane do not import foreign plane types outside boundary modules."""
    findings: list[SemanticPlaneFinding] = []
    registered_types = registry.get("types", {})
    boundary_modules = set(registry.get("registered_boundary_modules", []))
    module_declarations = registry.get("module_declarations", {})

    use_pattern = re.compile(r"use\s+([^;]+);", re.MULTILINE)
    grant_fn_pattern = re.compile(
        r"pub\s+fn\s+[A-Za-z0-9_]+\s*\([^)]*\)\s*->\s*([A-Za-z0-9_:]*EffectAuthority)\b"
    )

    for mod_rel, mod_plane in module_declarations.items():
        if mod_rel in boundary_modules:
            continue

        abs_path = root / mod_rel
        if not abs_path.is_file():
            continue

        try:
            content = abs_path.read_text(encoding="utf-8")
        except (OSError, UnicodeDecodeError):
            continue

        # Check for functions directly returning EffectAuthority in cognition modules
        if mod_plane == "cognition":
            for line_no, line in enumerate(content.splitlines(), start=1):
                if grant_fn_pattern.search(line):
                    findings.append(
                        SemanticPlaneFinding(
                            code=ERR_COGNITION_GRANTS_EFFECT,
                            file=mod_rel,
                            location=f"line {line_no}",
                            message=f"Prohibited cognition-to-effect bridge: module '{mod_rel}' has function granting EffectAuthority",
                            severity="error",
                            remediation=DIAGNOSTIC_REGISTRY[ERR_COGNITION_GRANTS_EFFECT]["remediation"],
                            params={"module": mod_rel, "type_name": "EffectAuthority"},
                        )
                    )

        # Check use statements for unauthorized cross-plane imports
        for line_no, line in enumerate(content.splitlines(), start=1):
            if not line.strip().startswith("use "):
                continue

            for type_name, type_info in registered_types.items():
                type_plane = type_info.get("plane")
                if type_plane in (mod_plane, "support", "ambiguous"):
                    continue

                # Cross-plane restriction applies to authority and effect types
                if type_plane in ("authority", "effect"):
                    # Check if type_name is an imported symbol
                    if re.search(r"\b" + re.escape(type_name) + r"\b", line):
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

    # Core type census audit
    findings.extend(audit_fss_core_type_census(root, registry))

    # Cross-plane import policy audit
    findings.extend(check_module_imports(root, registry))

    # Compile-fail doctests verification
    contract_path = root / "docs/enforcement/three_semantic_planes_contract.md"
    doctests_passed = 0
    if check_doctests and contract_path.is_file():
        success, count, err = verify_compile_fail_doctests(contract_path)
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
