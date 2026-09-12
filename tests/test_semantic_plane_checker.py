#!/usr/bin/env python3
"""Planted-negative and positive test suite for three semantic planes enforcement (fss-x4a.1.9 / ADR-0001).

Enforces ADR-0001 three semantic planes doctrine from AGENTS.md:
"Authority, cognition, and effect planes are type-distinct:
 - A value from one plane must not convert into another plane's type without an explicit, audited boundary type.
 - A cognition output (model score, recommendation) can never grant effect authority."

Verification invariants:
1. Positive controls: Real repository passes with 0 errors; compile-fail doctests pass.
2. Compile-fail doctests: Forbidden cross-plane conversions (cognition -> effect authority,
   cognition -> effect intent, effect authority -> cognition belief) fail to compile.
3. Cross-plane import policy: A module declared for one plane (e.g. cognition) cannot import
   authority or effect types outside registered boundary modules.
4. Core type census: Every existing plane type in fss-core (effect.rs, event.rs, belief.rs, region.rs)
   is mapped in architecture/semantic_plane_registry.json.
5. Ambiguous types: Types bridging planes (e.g. AlertEffectRecord, EvidenceGraph) are honestly
   reported as ambiguous findings, never guessed.
6. Fail closed: Corrupt, missing, or empty registry fails closed.
"""

from __future__ import annotations

import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))

try:
    from semantic_plane_checker import (
        ERR_COGNITION_GRANTS_EFFECT,
        ERR_DOCTEST_FAILED,
        ERR_REGISTRY_INVALID,
        ERR_UNAUTHORIZED_CROSS_PLANE_IMPORT,
        ERR_UNMAPPED_CORE_TYPE,
        INFO_AMBIGUOUS_TYPE,
        audit_semantic_planes,
        load_semantic_plane_registry,
        verify_compile_fail_doctests,
    )
except ImportError:
    # Will fail when tests run first before implementation
    pass


class TestSemanticPlanesPositiveControls(unittest.TestCase):
    """Positive controls asserting real repo passes all semantic plane checks."""

    def test_real_repo_passes(self) -> None:
        """The real repository passes semantic plane audit with zero errors."""
        is_valid, findings, summary = audit_semantic_planes(ROOT)
        errors = [f.message for f in findings if f.severity == "error"]
        self.assertTrue(is_valid, f"Real repo failed semantic planes audit: {errors}")
        self.assertEqual(summary["status"], "pass")
        self.assertEqual(summary["error_count"], 0)
        self.assertGreaterEqual(summary["types_mapped"], 40)
        self.assertGreater(summary["authority_types"], 0)
        self.assertGreater(summary["cognition_types"], 0)
        self.assertGreater(summary["effect_types"], 0)
        self.assertGreater(summary["ambiguous_types"], 0)

    def test_cli_real_repo_passes(self) -> None:
        """CLI invocation on the real repository exits with code 0."""
        cmd = [sys.executable, str(ROOT / "scripts/semantic_plane_checker.py")]
        result = subprocess.run(cmd, capture_output=True, text=True, cwd=str(ROOT))
        self.assertEqual(result.returncode, 0, f"CLI failed:\n{result.stderr}\n{result.stdout}")
        self.assertIn("[PASS]", result.stdout)

    def test_cli_json_mode(self) -> None:
        """CLI --json emits valid JSON matching summary and findings structure."""
        cmd = [sys.executable, str(ROOT / "scripts/semantic_plane_checker.py"), "--json"]
        result = subprocess.run(cmd, capture_output=True, text=True, cwd=str(ROOT))
        self.assertEqual(result.returncode, 0, f"CLI JSON mode failed:\n{result.stderr}")
        data = json.loads(result.stdout)
        self.assertIn("summary", data)
        self.assertIn("findings", data)
        self.assertEqual(data["summary"]["status"], "pass")
        self.assertEqual(data["summary"]["error_count"], 0)

    def test_doctests_compile_fail_pass(self) -> None:
        """Compile-fail doctests in docs/enforcement/three_semantic_planes_contract.md pass."""
        contract_path = ROOT / "docs/enforcement/three_semantic_planes_contract.md"
        self.assertTrue(contract_path.is_file(), f"Contract doctest file missing: {contract_path}")
        success, test_count, err = verify_compile_fail_doctests(contract_path)
        self.assertTrue(success, f"Compile-fail doctest execution failed: {err}")
        self.assertGreaterEqual(test_count, 4)


class TestPlantedNegativeCrossPlaneImports(unittest.TestCase):
    """Tests failure when unauthorized cross-plane imports occur outside boundary modules."""

    def test_unauthorized_cross_plane_import_fails(self) -> None:
        """A module declared for cognition importing effect types outside boundary fails closed."""
        with tempfile.TemporaryDirectory() as td:
            tmp_root = Path(td)
            src_dir = tmp_root / "crates" / "fss-cognition" / "src"
            src_dir.mkdir(parents=True, exist_ok=True)
            bad_module = src_dir / "unauthorized_planner.rs"
            bad_module.write_text(
                """//! Unauthorized planner attempting direct effect imports
use fss_core::effect::EffectAuthority;
use fss_core::effect::EffectIntent;

pub fn trigger_unauthorized_effect(auth: EffectAuthority) {
    // violation
}
""",
                encoding="utf-8",
            )

            # Minimal registry mapping unauthorized_planner.rs to cognition
            reg_dir = tmp_root / "architecture"
            reg_dir.mkdir(parents=True, exist_ok=True)
            registry_path = reg_dir / "semantic_plane_registry.json"
            registry_path.write_text(
                json.dumps({
                    "schema": "fss.semantic_plane_registry.v1",
                    "as_of": "2026-09-01",
                    "registered_boundary_modules": [
                        "crates/fss-core/src/effect.rs"
                    ],
                    "module_declarations": {
                        "crates/fss-cognition/src/unauthorized_planner.rs": "cognition"
                    },
                    "types": {
                        "EffectAuthority": {"file": "crates/fss-core/src/effect.rs", "plane": "authority"},
                        "EffectIntent": {"file": "crates/fss-core/src/effect.rs", "plane": "effect"}
                    }
                }),
                encoding="utf-8",
            )

            is_valid, findings, summary = audit_semantic_planes(tmp_root, registry_path=registry_path)
            self.assertFalse(is_valid)
            self.assertEqual(summary["status"], "fail")
            codes = [f.code for f in findings]
            self.assertIn(ERR_UNAUTHORIZED_CROSS_PLANE_IMPORT, codes)
            import_finding = next(f for f in findings if f.code == ERR_UNAUTHORIZED_CROSS_PLANE_IMPORT)
            self.assertIn("EffectAuthority", import_finding.message)

    def test_cognition_output_cannot_grant_effect_authority_fails(self) -> None:
        """A cognition output directly converting to EffectAuthority fails closed."""
        with tempfile.TemporaryDirectory() as td:
            tmp_root = Path(td)
            src_dir = tmp_root / "crates" / "fss-cognition" / "src"
            src_dir.mkdir(parents=True, exist_ok=True)
            bad_module = src_dir / "model_escalator.rs"
            bad_module.write_text(
                """//! Prohibited cognition-to-effect bridge
use fss_core::belief::BeliefInterval;
use fss_core::effect::EffectAuthority;

pub fn grant_authority_from_model(belief: BeliefInterval) -> EffectAuthority {
    // Prohibited shortcut
    EffectAuthority::new()
}
""",
                encoding="utf-8",
            )

            reg_dir = tmp_root / "architecture"
            reg_dir.mkdir(parents=True, exist_ok=True)
            registry_path = reg_dir / "semantic_plane_registry.json"
            registry_path.write_text(
                json.dumps({
                    "schema": "fss.semantic_plane_registry.v1",
                    "as_of": "2026-09-01",
                    "registered_boundary_modules": [],
                    "module_declarations": {
                        "crates/fss-cognition/src/model_escalator.rs": "cognition"
                    },
                    "types": {
                        "BeliefInterval": {"file": "crates/fss-core/src/belief.rs", "plane": "cognition"},
                        "EffectAuthority": {"file": "crates/fss-core/src/effect.rs", "plane": "authority"}
                    }
                }),
                encoding="utf-8",
            )

            is_valid, findings, summary = audit_semantic_planes(tmp_root, registry_path=registry_path)
            self.assertFalse(is_valid)
            codes = [f.code for f in findings]
            self.assertTrue(
                ERR_UNAUTHORIZED_CROSS_PLANE_IMPORT in codes or ERR_COGNITION_GRANTS_EFFECT in codes,
                f"Expected cross-plane import or cognition-grants-effect error, got {codes}",
            )


class TestPlantedNegativeCoreTypeCensus(unittest.TestCase):
    """Tests failure when types in fss-core are missing from the registry."""

    def test_unmapped_core_type_fails(self) -> None:
        """A public type in fss-core omitted from registry fails closed with ERR_UNMAPPED_CORE_TYPE."""
        with tempfile.TemporaryDirectory() as td:
            tmp_root = Path(td)
            # Create a mock fss-core with an unmapped type
            core_dir = tmp_root / "crates" / "fss-core" / "src"
            core_dir.mkdir(parents=True, exist_ok=True)
            (core_dir / "belief.rs").write_text(
                """pub struct BeliefInterval { pub lower: f64, pub upper: f64 }
pub struct UnmappedGhostBelief { pub value: f64 }
""",
                encoding="utf-8",
            )
            (core_dir / "effect.rs").write_text("pub struct EffectIntent;", encoding="utf-8")
            (core_dir / "event.rs").write_text("pub struct EventHypothesis;", encoding="utf-8")
            (core_dir / "region.rs").write_text("pub struct ContextAuthority;", encoding="utf-8")

            reg_dir = tmp_root / "architecture"
            reg_dir.mkdir(parents=True, exist_ok=True)
            registry_path = reg_dir / "semantic_plane_registry.json"
            registry_path.write_text(
                json.dumps({
                    "schema": "fss.semantic_plane_registry.v1",
                    "as_of": "2026-09-01",
                    "registered_boundary_modules": [],
                    "module_declarations": {},
                    "types": {
                        "BeliefInterval": {"file": "crates/fss-core/src/belief.rs", "plane": "cognition"},
                        "EffectIntent": {"file": "crates/fss-core/src/effect.rs", "plane": "effect"},
                        "EventHypothesis": {"file": "crates/fss-core/src/event.rs", "plane": "cognition"},
                        "ContextAuthority": {"file": "crates/fss-core/src/region.rs", "plane": "authority"}
                    }
                }),
                encoding="utf-8",
            )

            is_valid, findings, summary = audit_semantic_planes(tmp_root, registry_path=registry_path)
            self.assertFalse(is_valid)
            codes = [f.code for f in findings]
            self.assertIn(ERR_UNMAPPED_CORE_TYPE, codes)
            unmapped_finding = next(f for f in findings if f.code == ERR_UNMAPPED_CORE_TYPE)
            self.assertIn("UnmappedGhostBelief", unmapped_finding.message)


class TestAmbiguousTypesReporting(unittest.TestCase):
    """Tests honest reporting of ambiguous/boundary types without guessing."""

    def test_ambiguous_types_reported_honestly(self) -> None:
        """Ambiguous types (e.g. AlertEffectRecord, EvidenceGraph) are reported as findings."""
        is_valid, findings, summary = audit_semantic_planes(ROOT)
        self.assertTrue(is_valid)
        ambiguous_findings = [f for f in findings if f.code == INFO_AMBIGUOUS_TYPE]
        self.assertGreaterEqual(len(ambiguous_findings), 2)
        reported_names = [f.params.get("type_name") for f in ambiguous_findings]
        self.assertIn("AlertEffectRecord", reported_names)
        self.assertIn("EvidenceGraph", reported_names)
        # All ambiguous findings should have non-empty explanation of ambiguity
        for f in ambiguous_findings:
            self.assertTrue(len(f.message) > 10)


class TestPlantedNegativeRegistryIntegrity(unittest.TestCase):
    """Tests failure when registry is missing, corrupt, or empty."""

    def test_missing_registry_fails_closed(self) -> None:
        """Missing registry file fails closed with ERR_REGISTRY_INVALID."""
        with tempfile.TemporaryDirectory() as td:
            tmp_root = Path(td)
            nonexistent = tmp_root / "architecture" / "nonexistent.json"
            is_valid, findings, summary = audit_semantic_planes(tmp_root, registry_path=nonexistent)
            self.assertFalse(is_valid)
            self.assertIn(ERR_REGISTRY_INVALID, [f.code for f in findings])

    def test_corrupt_registry_fails_closed(self) -> None:
        """Corrupt JSON in registry fails closed with ERR_REGISTRY_INVALID."""
        with tempfile.TemporaryDirectory() as td:
            tmp_root = Path(td)
            reg_dir = tmp_root / "architecture"
            reg_dir.mkdir(parents=True, exist_ok=True)
            reg_file = reg_dir / "semantic_plane_registry.json"
            reg_file.write_text("{not valid json", encoding="utf-8")
            is_valid, findings, summary = audit_semantic_planes(tmp_root, registry_path=reg_file)
            self.assertFalse(is_valid)
            self.assertIn(ERR_REGISTRY_INVALID, [f.code for f in findings])

    def test_empty_registry_fails_closed(self) -> None:
        """Empty (0 bytes or empty dict) registry fails closed with ERR_REGISTRY_INVALID."""
        with tempfile.TemporaryDirectory() as td:
            tmp_root = Path(td)
            reg_dir = tmp_root / "architecture"
            reg_dir.mkdir(parents=True, exist_ok=True)
            reg_file = reg_dir / "semantic_plane_registry.json"
            reg_file.write_text("", encoding="utf-8")
            is_valid, findings, summary = audit_semantic_planes(tmp_root, registry_path=reg_file)
            self.assertFalse(is_valid)
            self.assertIn(ERR_REGISTRY_INVALID, [f.code for f in findings])


class TestReviewFindings(unittest.TestCase):
    """Failing tests first corresponding to review-670 findings F1 - F8."""

    def test_finding_1_and_8_contract_doc_typed_effect_authority(self) -> None:
        """Contract doc Invariant 4 must use typed EffectAuthority, not primitive &str (F1, F8)."""
        contract_path = ROOT / "docs/enforcement/three_semantic_planes_contract.md"
        content = contract_path.read_text(encoding="utf-8")
        self.assertNotIn(
            "dispatch(&self, auth: &str)",
            content,
            "Invariant 4 must not use primitive &str while claiming to require EffectAuthority",
        )
        self.assertIn(
            "EffectAuthority",
            content,
            "Invariant 4 must use EffectAuthority token",
        )

    def test_finding_2_multiline_cross_plane_import_detected(self) -> None:
        """Multiline grouped imports of authority/effect types must be detected (F2)."""
        with tempfile.TemporaryDirectory() as td:
            tmp_root = Path(td)
            src_dir = tmp_root / "crates" / "fss-cognition" / "src"
            src_dir.mkdir(parents=True, exist_ok=True)
            (src_dir / "multiline_planner.rs").write_text(
                """use fss_core::effect::{
    EffectAuthority,
};
pub fn bad(auth: EffectAuthority) {}
""",
                encoding="utf-8",
            )
            reg_dir = tmp_root / "architecture"
            reg_dir.mkdir(parents=True, exist_ok=True)
            (reg_dir / "semantic_plane_registry.json").write_text(
                json.dumps({
                    "schema": "fss.semantic_plane_registry.v1",
                    "planes": {"authority": {}, "cognition": {}, "effect": {}, "ambiguous": {}, "support": {}},
                    "registered_boundary_modules": [],
                    "module_declarations": {
                        "crates/fss-cognition/src/multiline_planner.rs": "cognition"
                    },
                    "types": {
                        "EffectAuthority": {"file": "crates/fss-core/src/effect.rs", "plane": "authority"}
                    },
                }),
                encoding="utf-8",
            )
            is_valid, findings, _ = audit_semantic_planes(tmp_root, check_doctests=False)
            self.assertFalse(is_valid, "Multiline cross-plane import was not caught!")
            codes = [f.code for f in findings]
            self.assertIn(ERR_UNAUTHORIZED_CROSS_PLANE_IMPORT, codes)

    def test_finding_2_wildcard_cross_plane_import_detected(self) -> None:
        """Wildcard imports of authority/effect modules from cognition must be detected (F2)."""
        with tempfile.TemporaryDirectory() as td:
            tmp_root = Path(td)
            src_dir = tmp_root / "crates" / "fss-cognition" / "src"
            src_dir.mkdir(parents=True, exist_ok=True)
            (src_dir / "wildcard_planner.rs").write_text(
                """use fss_core::effect::*;
pub fn bad() {}
""",
                encoding="utf-8",
            )
            reg_dir = tmp_root / "architecture"
            reg_dir.mkdir(parents=True, exist_ok=True)
            (reg_dir / "semantic_plane_registry.json").write_text(
                json.dumps({
                    "schema": "fss.semantic_plane_registry.v1",
                    "planes": {"authority": {}, "cognition": {}, "effect": {}, "ambiguous": {}, "support": {}},
                    "registered_boundary_modules": [],
                    "module_declarations": {
                        "crates/fss-cognition/src/wildcard_planner.rs": "cognition",
                        "crates/fss-core/src/effect.rs": "effect",
                    },
                    "types": {
                        "EffectAuthority": {"file": "crates/fss-core/src/effect.rs", "plane": "authority"}
                    },
                }),
                encoding="utf-8",
            )
            is_valid, findings, _ = audit_semantic_planes(tmp_root, check_doctests=False)
            self.assertFalse(is_valid, "Wildcard cross-plane import was not caught!")
            codes = [f.code for f in findings]
            self.assertIn(ERR_UNAUTHORIZED_CROSS_PLANE_IMPORT, codes)

    def test_finding_2_cross_plane_from_into_impl_detected(self) -> None:
        """Cross-plane From/Into implementations outside boundary modules must be detected (F2)."""
        with tempfile.TemporaryDirectory() as td:
            tmp_root = Path(td)
            src_dir = tmp_root / "crates" / "fss-cognition" / "src"
            src_dir.mkdir(parents=True, exist_ok=True)
            (src_dir / "bad_conversion.rs").write_text(
                """pub struct Belief;
pub struct EffectAuthority;
impl From<Belief> for EffectAuthority {
    fn from(_: Belief) -> Self { EffectAuthority }
}
""",
                encoding="utf-8",
            )
            reg_dir = tmp_root / "architecture"
            reg_dir.mkdir(parents=True, exist_ok=True)
            (reg_dir / "semantic_plane_registry.json").write_text(
                json.dumps({
                    "schema": "fss.semantic_plane_registry.v1",
                    "planes": {"authority": {}, "cognition": {}, "effect": {}, "ambiguous": {}, "support": {}},
                    "registered_boundary_modules": [],
                    "module_declarations": {
                        "crates/fss-cognition/src/bad_conversion.rs": "cognition"
                    },
                    "types": {
                        "Belief": {"file": "crates/fss-cognition/src/bad_conversion.rs", "plane": "cognition"},
                        "EffectAuthority": {"file": "crates/fss-core/src/effect.rs", "plane": "authority"}
                    },
                }),
                encoding="utf-8",
            )
            is_valid, findings, _ = audit_semantic_planes(tmp_root, check_doctests=False)
            self.assertFalse(is_valid, "Cross-plane From impl was not caught!")
            codes = [f.code for f in findings]
            self.assertTrue(
                ERR_COGNITION_GRANTS_EFFECT in codes or ERR_UNAUTHORIZED_CROSS_PLANE_IMPORT in codes,
                f"Expected cross-plane error, got {codes}",
            )

    def test_finding_3_cognition_grants_effect_multiline_and_result(self) -> None:
        """Functions returning Result<EffectAuthority, E> and multiline signatures must be caught (F3)."""
        with tempfile.TemporaryDirectory() as td:
            tmp_root = Path(td)
            src_dir = tmp_root / "crates" / "fss-cognition" / "src"
            src_dir.mkdir(parents=True, exist_ok=True)
            (src_dir / "sneaky_grant.rs").write_text(
                """pub fn grant_result(
    score: f64,
) -> Result<EffectAuthority, String> {
    Ok(EffectAuthority::new())
}
""",
                encoding="utf-8",
            )
            reg_dir = tmp_root / "architecture"
            reg_dir.mkdir(parents=True, exist_ok=True)
            (reg_dir / "semantic_plane_registry.json").write_text(
                json.dumps({
                    "schema": "fss.semantic_plane_registry.v1",
                    "planes": {"authority": {}, "cognition": {}, "effect": {}, "ambiguous": {}, "support": {}},
                    "registered_boundary_modules": [],
                    "module_declarations": {
                        "crates/fss-cognition/src/sneaky_grant.rs": "cognition"
                    },
                    "types": {
                        "EffectAuthority": {"file": "crates/fss-core/src/effect.rs", "plane": "authority"}
                    },
                }),
                encoding="utf-8",
            )
            is_valid, findings, _ = audit_semantic_planes(tmp_root, check_doctests=False)
            self.assertFalse(is_valid, "Multiline Result<EffectAuthority> grant was not caught!")
            codes = [f.code for f in findings]
            self.assertIn(ERR_COGNITION_GRANTS_EFFECT, codes)

    def test_finding_4_all_workspace_modules_must_be_declared(self) -> None:
        """All source modules in audited crates must be declared in module_declarations (F4)."""
        with tempfile.TemporaryDirectory() as td:
            tmp_root = Path(td)
            src_dir = tmp_root / "crates" / "fss-core" / "src"
            src_dir.mkdir(parents=True, exist_ok=True)
            (src_dir / "unmapped_mod.rs").write_text("pub struct Ghost;", encoding="utf-8")
            reg_dir = tmp_root / "architecture"
            reg_dir.mkdir(parents=True, exist_ok=True)
            (reg_dir / "semantic_plane_registry.json").write_text(
                json.dumps({
                    "schema": "fss.semantic_plane_registry.v1",
                    "planes": {"authority": {}, "cognition": {}, "effect": {}, "ambiguous": {}, "support": {}},
                    "registered_boundary_modules": [],
                    "module_declarations": {},
                    "types": {"Ghost": {"file": "crates/fss-core/src/unmapped_mod.rs", "plane": "support"}},
                }),
                encoding="utf-8",
            )
            is_valid, findings, _ = audit_semantic_planes(tmp_root, check_doctests=False)
            self.assertFalse(is_valid, "Unmapped module in audited crate was not caught!")
            codes = [f.code for f in findings]
            self.assertTrue(
                ERR_REGISTRY_INVALID in codes or ERR_UNMAPPED_CORE_TYPE in codes,
                f"Expected registry invalid or unmapped error, got {codes}",
            )

    def test_finding_5_missing_contract_file_fails_closed(self) -> None:
        """Missing three_semantic_planes_contract.md must fail closed with ERR_DOCTEST_FAILED (F5)."""
        with tempfile.TemporaryDirectory() as td:
            tmp_root = Path(td)
            reg_dir = tmp_root / "architecture"
            reg_dir.mkdir(parents=True, exist_ok=True)
            (reg_dir / "semantic_plane_registry.json").write_text(
                json.dumps({
                    "schema": "fss.semantic_plane_registry.v1",
                    "planes": {"authority": {}, "cognition": {}, "effect": {}, "ambiguous": {}, "support": {}},
                    "registered_boundary_modules": [],
                    "module_declarations": {},
                    "types": {"A": {"file": "crates/fss-core/src/effect.rs", "plane": "support"}},
                }),
                encoding="utf-8",
            )
            is_valid, findings, _ = audit_semantic_planes(tmp_root, check_doctests=True)
            self.assertFalse(is_valid, "Missing contract file must fail closed!")
            codes = [f.code for f in findings]
            self.assertIn(ERR_DOCTEST_FAILED, codes)

    def test_finding_5_missing_declared_module_fails_closed(self) -> None:
        """Declared module that does not exist on disk must fail closed (F5)."""
        with tempfile.TemporaryDirectory() as td:
            tmp_root = Path(td)
            reg_dir = tmp_root / "architecture"
            reg_dir.mkdir(parents=True, exist_ok=True)
            (reg_dir / "semantic_plane_registry.json").write_text(
                json.dumps({
                    "schema": "fss.semantic_plane_registry.v1",
                    "planes": {"authority": {}, "cognition": {}, "effect": {}, "ambiguous": {}, "support": {}},
                    "registered_boundary_modules": [],
                    "module_declarations": {
                        "crates/fss-core/src/nonexistent_file.rs": "cognition"
                    },
                    "types": {"A": {"file": "crates/fss-core/src/effect.rs", "plane": "support"}},
                }),
                encoding="utf-8",
            )
            is_valid, findings, _ = audit_semantic_planes(tmp_root, check_doctests=False)
            self.assertFalse(is_valid, "Nonexistent declared module must fail closed!")
            codes = [f.code for f in findings]
            self.assertTrue(
                ERR_REGISTRY_INVALID in codes or ERR_UNAUTHORIZED_CROSS_PLANE_IMPORT in codes,
                f"Expected error for missing declared module, got {codes}",
            )

    def test_finding_6_composite_multiplane_types_are_ambiguous(self) -> None:
        """EventLineage and EventHypothesis must be declared ambiguous in registry (F6)."""
        registry_path = ROOT / "architecture/semantic_plane_registry.json"
        data = json.loads(registry_path.read_text(encoding="utf-8"))
        types = data.get("types", {})
        self.assertEqual(
            types["EventLineage"]["plane"],
            "ambiguous",
            "EventLineage aggregates cognition and ambiguous types; cannot be pure authority",
        )
        self.assertTrue(len(types["EventLineage"].get("ambiguity_reason", "")) > 10)
        self.assertEqual(
            types["EventHypothesis"]["plane"],
            "ambiguous",
            "EventHypothesis embeds authority evidence and kind; cannot be pure cognition",
        )
        self.assertTrue(len(types["EventHypothesis"].get("ambiguity_reason", "")) > 10)
        self.assertEqual(
            types["EventRevision"]["plane"],
            "ambiguous",
            "EventRevision is type alias for EventHypothesis; cannot be pure cognition",
        )
        self.assertTrue(len(types["EventRevision"].get("ambiguity_reason", "")) > 10)

    def test_finding_7_registry_missing_sections_fails_closed(self) -> None:
        """Registry missing module_declarations or planes must fail closed (F7)."""
        with tempfile.TemporaryDirectory() as td:
            tmp_root = Path(td)
            reg_dir = tmp_root / "architecture"
            reg_dir.mkdir(parents=True, exist_ok=True)
            # Missing module_declarations
            (reg_dir / "semantic_plane_registry.json").write_text(
                json.dumps({
                    "schema": "fss.semantic_plane_registry.v1",
                    "types": {"A": {"file": "crates/fss-core/src/effect.rs", "plane": "support"}},
                }),
                encoding="utf-8",
            )
            is_valid, findings, _ = audit_semantic_planes(tmp_root, check_doctests=False)
            self.assertFalse(is_valid, "Registry missing module_declarations must fail closed!")
            codes = [f.code for f in findings]
            self.assertIn(ERR_REGISTRY_INVALID, codes)


# Fallbacks for NEG-003 diagnostic codes during test execution
ERR_MODEL_OUTPUT_REACHES_EFFECT = getattr(
    sys.modules.get("semantic_plane_checker"),
    "ERR_MODEL_OUTPUT_REACHES_EFFECT",
    "ERR-SEMPLANE-MODEL-OUTPUT-REACHES-EFFECT-001",
)
ERR_SINGLE_MODEL_CORROBORATION = getattr(
    sys.modules.get("semantic_plane_checker"),
    "ERR_SINGLE_MODEL_CORROBORATION",
    "ERR-SEMPLANE-SINGLE-MODEL-CORROBORATION-001",
)
ERR_ABSTENTION_AS_NEGATIVE_EVIDENCE = getattr(
    sys.modules.get("semantic_plane_checker"),
    "ERR_ABSTENTION_AS_NEGATIVE_EVIDENCE",
    "ERR-SEMPLANE-ABSTENTION-AS-NEGATIVE-EVIDENCE-001",
)
ERR_MUTABLE_MODEL_GENERATION = getattr(
    sys.modules.get("semantic_plane_checker"),
    "ERR_MUTABLE_MODEL_GENERATION",
    "ERR-SEMPLANE-MUTABLE-MODEL-GENERATION-001",
)


class TestPlantedNegativeDecomposedModelCascade(unittest.TestCase):
    """Planted-negative tests enforcing NEG-003 decomposed model-cascade constraints.

    NEG-003 mandates:
    1. A VLM/model output can never reach an effect type directly.
    2. A single model is never independent corroboration (policy check: min_sources >= 2).
    3. Model abstention/failure is never negative evidence (requires CoverageWitness).
    4. Model generations stay immutable (no 'latest' or mutable alias).
    """

    def test_vlm_or_model_output_directly_reaching_effect_fails_closed(self) -> None:
        """A VLM or model output type directly converting to an effect type fails closed."""
        with tempfile.TemporaryDirectory() as td:
            tmp_root = Path(td)
            src_dir = tmp_root / "crates" / "fss-cognition" / "src"
            src_dir.mkdir(parents=True, exist_ok=True)
            bad_module = src_dir / "direct_vlm_effect.rs"
            bad_module.write_text(
                """//! Forbidden direct VLM-to-effect bridge
pub struct VlmOutput {
    pub text: String,
    pub score: f64,
}

pub struct EffectIntent {
    pub action: String,
}

impl From<VlmOutput> for EffectIntent {
    fn from(vlm: VlmOutput) -> Self {
        EffectIntent { action: vlm.text }
    }
}

pub fn trigger_alert_directly(vlm: VlmOutput) -> EffectIntent {
    EffectIntent { action: vlm.text }
}
""",
                encoding="utf-8",
            )
            reg_dir = tmp_root / "architecture"
            reg_dir.mkdir(parents=True, exist_ok=True)
            (reg_dir / "semantic_plane_registry.json").write_text(
                json.dumps({
                    "schema": "fss.semantic_plane_registry.v1",
                    "planes": {"authority": {}, "cognition": {}, "effect": {}, "ambiguous": {}, "support": {}},
                    "registered_boundary_modules": [],
                    "module_declarations": {
                        "crates/fss-cognition/src/direct_vlm_effect.rs": "cognition"
                    },
                    "types": {
                        "VlmOutput": {"file": "crates/fss-cognition/src/direct_vlm_effect.rs", "plane": "cognition"},
                        "EffectIntent": {"file": "crates/fss-cognition/src/direct_vlm_effect.rs", "plane": "effect"}
                    },
                }),
                encoding="utf-8",
            )
            is_valid, findings, _ = audit_semantic_planes(tmp_root, check_doctests=False)
            self.assertFalse(is_valid, "Direct VLM-to-effect bridge must fail closed!")
            codes = [f.code for f in findings]
            self.assertIn(ERR_MODEL_OUTPUT_REACHES_EFFECT, codes)

    def test_single_model_corroboration_policy_fails_closed(self) -> None:
        """A policy or configuration permitting single-model corroboration (< 2 sources) fails closed."""
        with tempfile.TemporaryDirectory() as td:
            tmp_root = Path(td)
            arch_dir = tmp_root / "architecture"
            arch_dir.mkdir(parents=True, exist_ok=True)
            # Corroboration policy declaring single-model corroboration
            (arch_dir / "corroboration_policy.json").write_text(
                json.dumps({
                    "schema": "fss.corroboration_policy.v1",
                    "corroboration": {
                        "min_sources": 1,
                        "allow_single_model": True
                    }
                }),
                encoding="utf-8",
            )
            (arch_dir / "semantic_plane_registry.json").write_text(
                json.dumps({
                    "schema": "fss.semantic_plane_registry.v1",
                    "planes": {"authority": {}, "cognition": {}, "effect": {}, "ambiguous": {}, "support": {}},
                    "registered_boundary_modules": [],
                    "module_declarations": {},
                    "types": {},
                }),
                encoding="utf-8",
            )
            is_valid, findings, _ = audit_semantic_planes(tmp_root, check_doctests=False)
            self.assertFalse(is_valid, "Single-model corroboration policy (min_sources < 2) must fail closed!")
            codes = [f.code for f in findings]
            self.assertIn(ERR_SINGLE_MODEL_CORROBORATION, codes)

    def test_model_abstention_as_negative_evidence_fails_closed(self) -> None:
        """Coercing model abstention or failure into negative evidence / CoverageWitness fails closed."""
        with tempfile.TemporaryDirectory() as td:
            tmp_root = Path(td)
            src_dir = tmp_root / "crates" / "fss-cognition" / "src"
            src_dir.mkdir(parents=True, exist_ok=True)
            bad_module = src_dir / "abstention_leak.rs"
            bad_module.write_text(
                """//! Prohibited: treating model abstention as absence
pub struct MockModelOutcome;
pub struct CoverageWitness;

pub fn abstention_to_coverage_witness(_outcome: MockModelOutcome) -> CoverageWitness {
    CoverageWitness
}

impl From<MockModelOutcome> for CoverageWitness {
    fn from(_: MockModelOutcome) -> Self {
        CoverageWitness
    }
}
""",
                encoding="utf-8",
            )
            reg_dir = tmp_root / "architecture"
            reg_dir.mkdir(parents=True, exist_ok=True)
            (reg_dir / "semantic_plane_registry.json").write_text(
                json.dumps({
                    "schema": "fss.semantic_plane_registry.v1",
                    "planes": {"authority": {}, "cognition": {}, "effect": {}, "ambiguous": {}, "support": {}},
                    "registered_boundary_modules": [],
                    "module_declarations": {
                        "crates/fss-cognition/src/abstention_leak.rs": "cognition"
                    },
                    "types": {
                        "MockModelOutcome": {"file": "crates/fss-cognition/src/abstention_leak.rs", "plane": "cognition"},
                        "CoverageWitness": {"file": "crates/fss-cognition/src/abstention_leak.rs", "plane": "authority"}
                    },
                }),
                encoding="utf-8",
            )
            is_valid, findings, _ = audit_semantic_planes(tmp_root, check_doctests=False)
            self.assertFalse(is_valid, "Treating model abstention as negative evidence must fail closed!")
            codes = [f.code for f in findings]
            self.assertIn(ERR_ABSTENTION_AS_NEGATIVE_EVIDENCE, codes)

    def test_mutable_model_generation_fails_closed(self) -> None:
        """Declaring or referencing a mutable model generation alias (e.g. 'latest') fails closed."""
        with tempfile.TemporaryDirectory() as td:
            tmp_root = Path(td)
            arch_dir = tmp_root / "architecture"
            arch_dir.mkdir(parents=True, exist_ok=True)
            # Model runtime registry with forbidden mutable generation
            (arch_dir / "model_runtime_registry.json").write_text(
                json.dumps({
                    "schema": "fss.model_runtime_registry.v1",
                    "asOf": "2026-08-31",
                    "models": [
                        {
                            "name": "yolo-frontier",
                            "generation": "yolo26:latest",
                            "status": "active"
                        }
                    ]
                }),
                encoding="utf-8",
            )
            (arch_dir / "semantic_plane_registry.json").write_text(
                json.dumps({
                    "schema": "fss.semantic_plane_registry.v1",
                    "planes": {"authority": {}, "cognition": {}, "effect": {}, "ambiguous": {}, "support": {}},
                    "registered_boundary_modules": [],
                    "module_declarations": {},
                    "types": {},
                }),
                encoding="utf-8",
            )
            is_valid, findings, _ = audit_semantic_planes(tmp_root, check_doctests=False)
            self.assertFalse(is_valid, "Mutable model generation ('latest') must fail closed!")
            codes = [f.code for f in findings]
            self.assertIn(ERR_MUTABLE_MODEL_GENERATION, codes)


if __name__ == "__main__":
    unittest.main()

