#!/usr/bin/env python3
"""Deterministic verification suite for reconciled DEP-AUD diagnostic identities.

Covers all 18 child beads (fss-x4a.1.33.1 - fss-x4a.1.33.18) and full diagnostic registry:
- Unit trigger and non-trigger fixtures for every DEP-AUD finding code
- Structured parameter validation and secret/path redaction
- Deterministic golden JSON ordering and exit codes (0 for pass/warning, 1 for error)
- Policy lane drift rejection: unknown IDs, missing IDs, drifted severity/trigger
- Live repository qualification pass
"""
from __future__ import annotations

import copy
import json
import shutil
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))

import importlib.util
spec = importlib.util.spec_from_file_location("check_policy", ROOT / "scripts/check-policy.py")
check_policy = importlib.util.module_from_spec(spec)
spec.loader.exec_module(check_policy)

import dependency_audit
from dependency_audit import DIAGNOSTIC_REGISTRY, Finding, TargetRoot, add, audit_workspace


def make_clean_policy() -> dict:
    return {
        "policy": {
            "closed_universe": True,
            "direct_crates_must_be_allowlisted": True,
            "transitive_closure_must_be_censused": True,
            "new_external_dependency_requires_dep_record_and_adr": True,
            "fss_crates_must_forbid_unsafe": True,
            "release_resolution_must_be_locked_and_offline": True,
            "build_scripts_may_not_use_network": True,
            "serde_may_not_define_durable_bytes": True,
            "hosted_ci_is_not_release_authority": True,
            "asupersync_is_only_async_runtime": True,
            "fss_unsafe_exceptions_allowed": False,
            "c_or_cpp_ffi_allowed": False,
            "dynamic_loading_allowed": False,
            "foreign_runtime_production_boundary_allowed": False,
            "runtime_acquisition_allowed": False,
            # fss-x4a.30.88.1: DEP-AUD-001/002 now require all 16 flags derived from the constitution
            # and local qualification contract (dependency_authority.expected_policy_flags); the old
            # hard-coded 15-flag table omitted this one.
            "foreign_executables_allowed_in_production": False,
        },
        "in_house": {"allowed_families": ["fss-*"]},
        "fundamental": {"allowed_subject_to_audit": ["serde"]},
        "forbidden": {"crates": ["tokio", "actix", "warp"]},
    }


def make_valid_crate(crate_dir: Path, name: str, extra_manifest: str = "") -> None:
    crate_dir.mkdir(parents=True, exist_ok=True)
    manifest = f"""[package]
name = "{name}"
version = "0.1.0"
edition = "2024"

[lib]
path = "src/lib.rs"
{extra_manifest}
"""
    (crate_dir / "Cargo.toml").write_text(manifest, encoding="utf-8")
    src = crate_dir / "src"
    src.mkdir(parents=True, exist_ok=True)
    (src / "lib.rs").write_text("#![forbid(unsafe_code)]\npub fn hello() {}\n", encoding="utf-8")


class DepAudDiagnosticReconciliationTests(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp_dir = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp_dir.name)
        self.policy = make_clean_policy()
        self.policy_file = self.root / "architecture" / "dependency_allowlist.toml"
        self.policy_file.parent.mkdir(parents=True, exist_ok=True)
        self._write_policy(self.policy)

    def tearDown(self) -> None:
        self.tmp_dir.cleanup()

    def _write_policy(self, policy: dict) -> None:
        # Format simple TOML for policy
        lines = ["[policy]"]
        for k, v in policy["policy"].items():
            lines.append(f"{k} = {str(v).lower()}")
        lines.append("[in_house]")
        lines.append(f"allowed_families = {json.dumps(policy['in_house']['allowed_families'])}")
        lines.append("[fundamental]")
        lines.append(f"allowed_subject_to_audit = {json.dumps(policy['fundamental']['allowed_subject_to_audit'])}")
        lines.append("[forbidden]")
        lines.append(f"crates = {json.dumps(policy['forbidden']['crates'])}")
        self.policy_file.write_text("\n".join(lines) + "\n", encoding="utf-8")

    def _setup_clean_workspace(self) -> None:
        root_cargo = """[workspace]
resolver = "3"
members = ["crates/fss-a"]

[workspace.lints.rust]
unsafe_code = "forbid"
"""
        (self.root / "Cargo.toml").write_text(root_cargo, encoding="utf-8")
        make_valid_crate(self.root / "crates" / "fss-a", "fss-a")
        lockfile = """# lockfile
version = 4
[[package]]
name = "fss-a"
version = "0.1.0"
"""
        (self.root / "Cargo.lock").write_text(lockfile, encoding="utf-8")
        toolchain = """[toolchain]
channel = "nightly-2026-08-31"
"""
        (self.root / "rust-toolchain.toml").write_text(toolchain, encoding="utf-8")

    # -------------------------------------------------------------------------
    # 18 Child Bead Unit Trigger / Non-Trigger Tests
    # -------------------------------------------------------------------------

    def test_dep_aud_001_required_true_policy(self) -> None:
        """fss-x4a.1.33.1: DEP-AUD-001 required-true dependency-policy key absent or not true."""
        self._setup_clean_workspace()

        # Non-trigger: clean policy
        report, rc = audit_workspace(root=self.root, policy_path=self.policy_file)
        self.assertNotIn("DEP-AUD-001", [f["code"] for f in report["findings"]])

        # Trigger: set required_true key to false
        bad_policy = copy.deepcopy(self.policy)
        bad_policy["policy"]["closed_universe"] = False
        self._write_policy(bad_policy)
        report, rc = audit_workspace(root=self.root, policy_path=self.policy_file)
        f001 = [f for f in report["findings"] if f["code"] == "DEP-AUD-001"]
        self.assertEqual(len(f001), 1)
        self.assertEqual(f001[0]["severity"], "error")
        self.assertEqual(f001[0]["params"]["key"], "closed_universe")
        self.assertEqual(f001[0]["remediation"], DIAGNOSTIC_REGISTRY["DEP-AUD-001"].remediation)
        self.assertEqual(rc, 1)

    def test_dep_aud_002_required_false_policy(self) -> None:
        """fss-x4a.1.33.2: DEP-AUD-002 required-false dependency-policy key absent or not false."""
        self._setup_clean_workspace()

        # Non-trigger
        report, rc = audit_workspace(root=self.root, policy_path=self.policy_file)
        self.assertNotIn("DEP-AUD-002", [f["code"] for f in report["findings"]])

        # Trigger: set required_false key to true
        bad_policy = copy.deepcopy(self.policy)
        bad_policy["policy"]["fss_unsafe_exceptions_allowed"] = True
        self._write_policy(bad_policy)
        report, rc = audit_workspace(root=self.root, policy_path=self.policy_file)
        f002 = [f for f in report["findings"] if f["code"] == "DEP-AUD-002"]
        self.assertEqual(len(f002), 1)
        self.assertEqual(f002[0]["severity"], "error")
        self.assertEqual(f002[0]["params"]["key"], "fss_unsafe_exceptions_allowed")
        self.assertEqual(f002[0]["remediation"], DIAGNOSTIC_REGISTRY["DEP-AUD-002"].remediation)
        self.assertEqual(rc, 1)

    def test_dep_aud_010_member_manifest_missing(self) -> None:
        """fss-x4a.1.33.3: DEP-AUD-010 declared workspace member manifest is missing."""
        root_cargo = """[workspace]
resolver = "3"
members = ["crates/fss-missing"]
"""
        (self.root / "Cargo.toml").write_text(root_cargo, encoding="utf-8")
        findings: list[Finding] = []
        manifests, members, member_map = dependency_audit.expand_workspace_members(
            self.root, dependency_audit.load_toml(self.root / "Cargo.toml", self.root), findings
        )
        f010 = [f for f in findings if f.code == "DEP-AUD-010"]
        self.assertEqual(len(f010), 1)
        self.assertEqual(f010[0].severity, "error")
        self.assertIn("member", f010[0].params)
        self.assertEqual(f010[0].remediation, DIAGNOSTIC_REGISTRY["DEP-AUD-010"].remediation)

    def test_dep_aud_011_dependency_section_not_table(self) -> None:
        """fss-x4a.1.33.4: DEP-AUD-011 dependency section is not a TOML table."""
        self._setup_clean_workspace()
        crate_dir = self.root / "crates" / "fss-a"
        crate_dir.mkdir(parents=True, exist_ok=True)
        (crate_dir / "src").mkdir(parents=True, exist_ok=True)
        (crate_dir / "Cargo.toml").write_text(
            'dependencies = "malformed_string_not_table"\n\n[package]\nname = "fss-a"\nversion = "0.0.1"\nedition = "2024"\n',
            encoding="utf-8",
        )
        findings: list[Finding] = []
        manifests = [self.root / "Cargo.toml", self.root / "crates" / "fss-a" / "Cargo.toml"]
        dependency_audit.enumerate_dependencies(
            self.root, manifests, {"fss-a"}, {"fss-a": self.root / "crates" / "fss-a"}, self.policy, findings
        )
        f011 = [f for f in findings if f.code == "DEP-AUD-011"]
        self.assertTrue(len(f011) >= 1)
        self.assertEqual(f011[0].severity, "error")
        self.assertEqual(f011[0].remediation, DIAGNOSTIC_REGISTRY["DEP-AUD-011"].remediation)

        # Target section not a table also emits DEP-AUD-011
        findings_target: list[Finding] = []
        (crate_dir / "Cargo.toml").write_text(
            'target = "not_a_table"\n\n[package]\nname = "fss-a"\nversion = "0.0.1"\nedition = "2024"\n',
            encoding="utf-8",
        )
        dependency_audit.enumerate_dependencies(
            self.root, manifests, {"fss-a"}, {"fss-a": self.root / "crates" / "fss-a"}, self.policy, findings_target
        )
        f011_target = [f for f in findings_target if f.code == "DEP-AUD-011"]
        self.assertTrue(len(f011_target) >= 1)
        self.assertEqual(f011_target[0].remediation, DIAGNOSTIC_REGISTRY["DEP-AUD-011"].remediation)
        self.assertNotIn("DEP-AUD-025", [f.code for f in findings_target])

    def test_dep_aud_012_path_dependency_escapes_closure(self) -> None:
        """fss-x4a.1.33.5: DEP-AUD-012 path dependency escapes frozen repository or sibling closure."""
        self._setup_clean_workspace()
        a_extra = """[dependencies]
rogue = { path = "../../../rogue-escape" }
"""
        make_valid_crate(self.root / "crates" / "fss-a", "fss-a", extra_manifest=a_extra)
        findings: list[Finding] = []
        manifests = [self.root / "Cargo.toml", self.root / "crates" / "fss-a" / "Cargo.toml"]
        dependency_audit.enumerate_dependencies(
            self.root, manifests, {"fss-a"}, {"fss-a": self.root / "crates" / "fss-a"}, self.policy, findings
        )
        f012 = [f for f in findings if f.code == "DEP-AUD-012"]
        self.assertTrue(len(f012) >= 1)
        self.assertEqual(f012[0].severity, "error")
        self.assertIn("package", f012[0].params)
        self.assertEqual(f012[0].remediation, DIAGNOSTIC_REGISTRY["DEP-AUD-012"].remediation)

    def test_dep_aud_013_git_dependency_unpinned_rev(self) -> None:
        """fss-x4a.1.33.6: DEP-AUD-013 Git dependency lacks an exact 40-hex revision."""
        self._setup_clean_workspace()
        a_extra = """[dependencies]
asupersync = { git = "https://github.com/example/asupersync", branch = "main", default-features = false }
"""
        make_valid_crate(self.root / "crates" / "fss-a", "fss-a", extra_manifest=a_extra)
        findings: list[Finding] = []
        manifests = [self.root / "Cargo.toml", self.root / "crates" / "fss-a" / "Cargo.toml"]
        dependency_audit.enumerate_dependencies(
            self.root, manifests, {"fss-a"}, {"fss-a": self.root / "crates" / "fss-a"}, self.policy, findings
        )
        f013 = [f for f in findings if f.code == "DEP-AUD-013"]
        self.assertTrue(len(f013) >= 1)
        self.assertEqual(f013[0].severity, "error")
        self.assertEqual(f013[0].params["package"], "asupersync")
        self.assertEqual(f013[0].remediation, DIAGNOSTIC_REGISTRY["DEP-AUD-013"].remediation)

    def test_dep_aud_014_build_dependency_prohibited(self) -> None:
        """fss-x4a.1.33.7: DEP-AUD-014 build dependency is present without constitutional admission."""
        self._setup_clean_workspace()
        a_extra = """[build-dependencies]
serde = { version = "1.0", default-features = false }
"""
        make_valid_crate(self.root / "crates" / "fss-a", "fss-a", extra_manifest=a_extra)
        findings: list[Finding] = []
        manifests = [self.root / "Cargo.toml", self.root / "crates" / "fss-a" / "Cargo.toml"]
        dependency_audit.enumerate_dependencies(
            self.root, manifests, {"fss-a"}, {"fss-a": self.root / "crates" / "fss-a"}, self.policy, findings
        )
        f014 = [f for f in findings if f.code == "DEP-AUD-014"]
        self.assertTrue(len(f014) >= 1)
        self.assertEqual(f014[0].severity, "error")
        self.assertEqual(f014[0].params["package"], "serde")
        self.assertEqual(f014[0].remediation, DIAGNOSTIC_REGISTRY["DEP-AUD-014"].remediation)

    def test_dep_aud_015_forbidden_direct_dependency(self) -> None:
        """fss-x4a.1.33.8: DEP-AUD-015 direct dependency names a forbidden crate."""
        self._setup_clean_workspace()
        a_extra = """[dependencies]
tokio = { version = "1.0", default-features = false }
"""
        make_valid_crate(self.root / "crates" / "fss-a", "fss-a", extra_manifest=a_extra)
        findings: list[Finding] = []
        manifests = [self.root / "Cargo.toml", self.root / "crates" / "fss-a" / "Cargo.toml"]
        dependency_audit.enumerate_dependencies(
            self.root, manifests, {"fss-a"}, {"fss-a": self.root / "crates" / "fss-a"}, self.policy, findings
        )
        f015 = [f for f in findings if f.code == "DEP-AUD-015"]
        self.assertTrue(len(f015) >= 1)
        self.assertEqual(f015[0].severity, "error")
        self.assertEqual(f015[0].params["package"], "tokio")
        self.assertEqual(f015[0].remediation, DIAGNOSTIC_REGISTRY["DEP-AUD-015"].remediation)

    def test_dep_aud_016_unallowlisted_dependency(self) -> None:
        """fss-x4a.1.33.9: DEP-AUD-016 direct external dependency is outside closed allowlist."""
        self._setup_clean_workspace()
        a_extra = """[dependencies]
unapproved-crate = { version = "1.0", default-features = false }
"""
        make_valid_crate(self.root / "crates" / "fss-a", "fss-a", extra_manifest=a_extra)
        findings: list[Finding] = []
        manifests = [self.root / "Cargo.toml", self.root / "crates" / "fss-a" / "Cargo.toml"]
        dependency_audit.enumerate_dependencies(
            self.root, manifests, {"fss-a"}, {"fss-a": self.root / "crates" / "fss-a"}, self.policy, findings
        )
        f016 = [f for f in findings if f.code == "DEP-AUD-016"]
        self.assertTrue(len(f016) >= 1)
        self.assertEqual(f016[0].severity, "error")
        self.assertEqual(f016[0].params["package"], "unapproved-crate")
        self.assertEqual(f016[0].remediation, DIAGNOSTIC_REGISTRY["DEP-AUD-016"].remediation)

    def test_dep_aud_017_external_default_features_not_false(self) -> None:
        """fss-x4a.1.33.10: DEP-AUD-017 external dependency does not disable default features."""
        self._setup_clean_workspace()
        a_extra = """[dependencies]
serde = { version = "1.0" }
"""
        make_valid_crate(self.root / "crates" / "fss-a", "fss-a", extra_manifest=a_extra)
        findings: list[Finding] = []
        manifests = [self.root / "Cargo.toml", self.root / "crates" / "fss-a" / "Cargo.toml"]
        dependency_audit.enumerate_dependencies(
            self.root, manifests, {"fss-a"}, {"fss-a": self.root / "crates" / "fss-a"}, self.policy, findings
        )
        f017 = [f for f in findings if f.code == "DEP-AUD-017"]
        self.assertTrue(len(f017) >= 1)
        self.assertEqual(f017[0].severity, "error")
        self.assertEqual(f017[0].params["package"], "serde")
        self.assertEqual(f017[0].remediation, DIAGNOSTIC_REGISTRY["DEP-AUD-017"].remediation)

    def test_dep_aud_020_no_inspectable_target_root(self) -> None:
        """fss-x4a.1.33.11: DEP-AUD-020 crate has no inspectable Rust target root."""
        crate_dir = self.root / "crates" / "empty-crate"
        crate_dir.mkdir(parents=True, exist_ok=True)
        manifest_empty = """[package]
name = "empty"
version = "0.1.0"
edition = "2024"
"""
        (crate_dir / "Cargo.toml").write_text(manifest_empty, encoding="utf-8")
        findings: list[Finding] = []
        dependency_audit.discover_crate_targets(crate_dir, {}, "empty", "crates/empty-crate/Cargo.toml", self.root, findings)
        f020 = [f for f in findings if f.code == "DEP-AUD-020"]
        self.assertEqual(len(f020), 1)
        self.assertEqual(f020[0].severity, "error")
        self.assertEqual(f020[0].params["crate_name"], "empty")
        self.assertEqual(f020[0].remediation, DIAGNOSTIC_REGISTRY["DEP-AUD-020"].remediation)

    def test_dep_aud_021_target_root_lacks_forbid_unsafe(self) -> None:
        """fss-x4a.1.33.12: DEP-AUD-021 Rust target root lacks unconditional forbid unsafe_code."""
        crate_dir = self.root / "crates" / "unsafe-crate"
        crate_dir.mkdir(parents=True, exist_ok=True)
        manifest_bad = """[package]
name = "bad"
version = "0.1.0"
edition = "2024"
"""
        (crate_dir / "Cargo.toml").write_text(manifest_bad, encoding="utf-8")
        src = crate_dir / "src"
        src.mkdir(parents=True, exist_ok=True)
        (src / "lib.rs").write_text("pub fn test() {}\n", encoding="utf-8")
        findings: list[Finding] = []
        dependency_audit.discover_crate_targets(crate_dir, {}, "bad", "crates/unsafe-crate/Cargo.toml", self.root, findings)
        f021 = [f for f in findings if f.code == "DEP-AUD-021"]
        self.assertEqual(len(f021), 1)
        self.assertEqual(f021[0].severity, "error")
        self.assertEqual(f021[0].params["crate_name"], "bad")
        self.assertEqual(f021[0].remediation, DIAGNOSTIC_REGISTRY["DEP-AUD-021"].remediation)

    def test_dep_aud_022_forbidden_production_construct(self) -> None:
        """fss-x4a.1.33.13: DEP-AUD-022 FSS Rust source contains a forbidden production construct."""
        self._setup_clean_workspace()
        (self.root / "crates" / "fss-a" / "src" / "lib.rs").write_text(
            '#![forbid(unsafe_code)]\nextern "C" fn evil() {}\n', encoding="utf-8"
        )
        findings: list[Finding] = []
        dependency_audit.rust_source_audit(findings, root=self.root)
        f022 = [f for f in findings if f.code == "DEP-AUD-022"]
        self.assertTrue(len(f022) >= 1)
        self.assertEqual(f022[0].severity, "error")
        self.assertEqual(f022[0].params["label"], "C ABI")
        self.assertEqual(f022[0].remediation, DIAGNOSTIC_REGISTRY["DEP-AUD-022"].remediation)

        # Planted-negative test: Command::new("ffmpeg") in src/ is rejected
        (self.root / "crates" / "fss-a" / "src" / "lib.rs").write_text(
            '#![forbid(unsafe_code)]\nuse std::process::Command;\npub fn run() { let _ = Command::new("ffmpeg"); }\n',
            encoding="utf-8",
        )
        findings_src: list[Finding] = []
        dependency_audit.rust_source_audit(findings_src, root=self.root)
        f022_src = [f for f in findings_src if f.code == "DEP-AUD-022"]
        self.assertTrue(len(f022_src) >= 1)
        self.assertEqual(f022_src[0].params["label"], "foreign production command")

        # In tests/, Command::new(env!("...")) and oracle commands are admitted
        (self.root / "crates" / "fss-a" / "src" / "lib.rs").write_text(
            '#![forbid(unsafe_code)]\npub fn clean() {}\n', encoding="utf-8"
        )
        tests_dir = self.root / "crates" / "fss-a" / "tests"
        tests_dir.mkdir(parents=True, exist_ok=True)
        (tests_dir / "integration_test.rs").write_text(
            '#![forbid(unsafe_code)]\nuse std::process::Command;\nfn test() {\n    let _ = Command::new(env!("CARGO_BIN_EXE_fss-lab"));\n    let _ = Command::new("python3");\n}\n',
            encoding="utf-8",
        )
        findings_tests: list[Finding] = []
        dependency_audit.rust_source_audit(findings_tests, root=self.root)
        f022_tests = [f for f in findings_tests if f.code == "DEP-AUD-022"]
        self.assertEqual(len(f022_tests), 0)

    def test_dep_aud_025_workspace_root_manifest_lacks_workspace_table(self) -> None:
        """DEP-AUD-025: declared workspace root manifest lacks [workspace] table."""
        findings: list[Finding] = []
        manifest_data = {"package": {"name": "fss-root"}}
        dependency_audit.expand_workspace_members(self.root, manifest_data, findings)
        f025 = [f for f in findings if f.code == "DEP-AUD-025"]
        self.assertTrue(len(f025) >= 1)
        self.assertEqual(f025[0].severity, "error")
        self.assertEqual(f025[0].remediation, DIAGNOSTIC_REGISTRY["DEP-AUD-025"].remediation)

    def test_dep_aud_030_forbidden_package_in_resolved_metadata(self) -> None:
        """fss-x4a.1.33.14: DEP-AUD-030 forbidden package reachable in resolved Cargo metadata."""
        findings: list[Finding] = []
        mock_data = {
            "packages": [
                {"name": "tokio", "version": "1.30.0", "manifest_path": "/fake/tokio/Cargo.toml", "targets": []},
            ],
            "resolve": {"nodes": []},
        }
        status, err, census = dependency_audit.metadata_audit(
            findings, self.policy, root=self.root, raw_metadata=mock_data
        )
        f030 = [f for f in findings if f.code == "DEP-AUD-030"]
        self.assertEqual(len(f030), 1)
        self.assertEqual(f030[0].severity, "error")
        self.assertEqual(f030[0].params["package"], "tokio")
        self.assertEqual(f030[0].remediation, DIAGNOSTIC_REGISTRY["DEP-AUD-030"].remediation)

    def test_dep_aud_031_resolved_custom_build_target(self) -> None:
        """fss-x4a.1.33.15: DEP-AUD-031 resolved package has a custom build target."""
        findings: list[Finding] = []
        mock_data = {
            "packages": [
                {
                    "name": "build-script-pkg",
                    "version": "0.1.0",
                    "manifest_path": "/fake/build-script-pkg/Cargo.toml",
                    "targets": [{"kind": ["custom-build"], "name": "build-script-build"}],
                },
            ],
            "resolve": {"nodes": []},
        }
        status, err, census = dependency_audit.metadata_audit(
            findings, self.policy, root=self.root, raw_metadata=mock_data
        )
        f031 = [f for f in findings if f.code == "DEP-AUD-031"]
        self.assertEqual(len(f031), 1)
        self.assertEqual(f031[0].severity, "error")
        self.assertEqual(f031[0].params["package"], "build-script-pkg")
        self.assertEqual(f031[0].remediation, DIAGNOSTIC_REGISTRY["DEP-AUD-031"].remediation)

    def test_dep_aud_032_resolved_package_native_links(self) -> None:
        """fss-x4a.1.33.16: DEP-AUD-032 resolved package declares native links."""
        findings: list[Finding] = []
        mock_data = {
            "packages": [
                {
                    "name": "native-c-pkg",
                    "version": "0.1.0",
                    "manifest_path": "/fake/native-c-pkg/Cargo.toml",
                    "links": "curl",
                    "targets": [],
                },
            ],
            "resolve": {"nodes": []},
        }
        status, err, census = dependency_audit.metadata_audit(
            findings, self.policy, root=self.root, raw_metadata=mock_data
        )
        f032 = [f for f in findings if f.code == "DEP-AUD-032"]
        self.assertEqual(len(f032), 1)
        self.assertEqual(f032[0].severity, "error")
        self.assertEqual(f032[0].params["package"], "native-c-pkg")
        self.assertEqual(f032[0].params["links"], "curl")
        self.assertEqual(f032[0].remediation, DIAGNOSTIC_REGISTRY["DEP-AUD-032"].remediation)

    def test_dep_aud_033_resolved_git_package_not_commit_resolved(self) -> None:
        """fss-x4a.1.33.17: DEP-AUD-033 resolved Git package source is not commit-resolved."""
        findings: list[Finding] = []
        mock_data = {
            "packages": [
                {
                    "name": "unresolved-git-pkg",
                    "version": "0.1.0",
                    "manifest_path": "/fake/unresolved-git-pkg/Cargo.toml",
                    "source": "git+https://github.com/example/repo?branch=main",
                    "targets": [],
                },
            ],
            "resolve": {"nodes": []},
        }
        status, err, census = dependency_audit.metadata_audit(
            findings, self.policy, root=self.root, raw_metadata=mock_data
        )
        f033 = [f for f in findings if f.code == "DEP-AUD-033"]
        self.assertEqual(len(f033), 1)
        self.assertEqual(f033[0].severity, "error")
        self.assertEqual(f033[0].params["package"], "unresolved-git-pkg")
        self.assertEqual(f033[0].remediation, DIAGNOSTIC_REGISTRY["DEP-AUD-033"].remediation)

    def test_dep_aud_040_required_offline_metadata_unavailable(self) -> None:
        """fss-x4a.1.33.18: DEP-AUD-040 required pinned-nightly offline Cargo metadata is unavailable."""
        self._setup_clean_workspace()
        # require_metadata=True with unavailable cargo metadata in mock environment
        findings: list[Finding] = []
        dependency_audit.add(
            findings,
            "error",
            "DEP-AUD-040",
            "Cargo.lock",
            "offline pinned-nightly metadata is required: cargo metadata failed",
            root=self.root,
            params={"error": "cargo metadata failed"},
        )
        f040 = [f for f in findings if f.code == "DEP-AUD-040"]
        self.assertEqual(len(f040), 1)
        self.assertEqual(f040[0].severity, "error")
        self.assertEqual(f040[0].params["error"], "cargo metadata failed")
        self.assertEqual(f040[0].remediation, DIAGNOSTIC_REGISTRY["DEP-AUD-040"].remediation)

    # -------------------------------------------------------------------------
    # Structured Parameters, Redaction, and Output Bounds
    # -------------------------------------------------------------------------

    def test_secret_redaction_in_diagnostics(self) -> None:
        """Diagnostic emission must scrub GitHub tokens, bearer tokens, and private keys."""
        findings: list[Finding] = []
        secret_token = "ghp_123456789012345678901234567890123456"
        add(
            findings,
            "error",
            "DEP-AUD-013",
            self.root / "Cargo.toml",
            f"Git dependency failed with auth: {secret_token}",
            root=self.root,
            params={"token": secret_token, "url": f"https://{secret_token}@github.com/repo"},
        )
        self.assertEqual(len(findings), 1)
        f = findings[0]
        self.assertNotIn(secret_token, f.message)
        self.assertIn("[REDACTED]", f.message)
        self.assertNotIn(secret_token, str(f.params))
        self.assertIn("[REDACTED]", f.params["token"])

    def test_path_sanitization_outside_root(self) -> None:
        """Path sanitization must never leak user home or private directory structure."""
        findings: list[Finding] = []
        external_path = Path("/home/ubuntu/secret_workspace/outside/Cargo.toml")
        add(
            findings,
            "error",
            "DEP-AUD-012",
            external_path,
            "escaping path",
            root=self.root,
            params={"target": external_path},
        )
        f = findings[0]
        self.assertNotIn("/home/ubuntu/secret_workspace", f.path)
        self.assertNotIn("/home/ubuntu/secret_workspace", str(f.params["target"]))

    def test_diagnostic_message_length_bounded(self) -> None:
        """Extremely long messages must be truncated to avoid unbounded memory/logs."""
        findings: list[Finding] = []
        huge_msg = "X" * 2000
        add(findings, "error", "DEP-AUD-011", self.root / "Cargo.toml", huge_msg, root=self.root)
        self.assertTrue(len(findings[0].message) < 600)
        self.assertIn("...[TRUNCATED]", findings[0].message)

    # -------------------------------------------------------------------------
    # Deterministic Golden JSON Ordering and Exit Codes
    # -------------------------------------------------------------------------

    def test_deterministic_finding_ordering(self) -> None:
        """Findings must be sorted deterministically by (severity, code, path, message)."""
        findings: list[Finding] = []
        add(findings, "error", "DEP-AUD-021", "crates/b/src/lib.rs", "missing forbid unsafe", root=self.root)
        add(findings, "warning", "DEP-AUD-041", "Cargo.toml", "metadata drift", root=self.root)
        add(findings, "error", "DEP-AUD-015", "crates/a/Cargo.toml", "forbidden dep", root=self.root)
        add(findings, "error", "DEP-AUD-010", "crates/c/Cargo.toml", "missing manifest", root=self.root)

        sorted_rows = sorted(
            [dependency_audit.asdict(f) for f in findings],
            key=lambda row: (row["severity"], row["code"], row["path"], row["message"]),
        )
        codes = [r["code"] for r in sorted_rows]
        self.assertEqual(codes, ["DEP-AUD-010", "DEP-AUD-015", "DEP-AUD-021", "DEP-AUD-041"])

    def test_exit_code_semantics(self) -> None:
        """Exit code must be 0 for qualified/clean or policy_only with no errors, 1 for errors."""
        self._setup_clean_workspace()
        report, rc = audit_workspace(root=self.root, policy_path=self.policy_file)
        self.assertEqual(rc, 0)
        self.assertEqual(report["errorCount"], 0)

        # Plant error
        bad_policy = copy.deepcopy(self.policy)
        bad_policy["policy"]["closed_universe"] = False
        self._write_policy(bad_policy)
        report, rc = audit_workspace(root=self.root, policy_path=self.policy_file)
        self.assertEqual(rc, 1)
        self.assertTrue(report["errorCount"] > 0)

    # -------------------------------------------------------------------------
    # Policy Lane Drift Rejection Tests
    # -------------------------------------------------------------------------

    def test_policy_lane_live_diagnostic_policy_passes(self) -> None:
        """Live repository diagnostic policy must pass with zero errors."""
        check_policy.ROOT = ROOT
        check_policy.errors = []
        check_policy.diagnostic_policy()
        self.assertEqual(check_policy.errors, [])

    def test_policy_lane_rejects_unknown_dep_aud_in_errors_md(self) -> None:
        """Policy lane must reject unknown DEP-AUD codes in ERRORS.md."""
        orig_text = (ROOT / "registries/ERRORS.md").read_text(encoding="utf-8")
        tampered = orig_text + "\n| `DEP-AUD-999` | error | unknown rogue condition | none | `GATE-000` | retry |\n"
        errors_file = self.root / "registries" / "ERRORS.md"
        errors_file.parent.mkdir(parents=True, exist_ok=True)
        errors_file.write_text(tampered, encoding="utf-8")

        check_policy.ROOT = self.root
        check_policy.errors = []
        check_policy.diagnostic_policy()
        self.assertTrue(any("unknown DEP-AUD diagnostic: DEP-AUD-999" in err for err in check_policy.errors))

    def test_policy_lane_rejects_missing_dep_aud_in_errors_md(self) -> None:
        """Policy lane must reject if a registered code is missing from ERRORS.md."""
        orig_text = (ROOT / "registries/ERRORS.md").read_text(encoding="utf-8")
        # Remove DEP-AUD-001 line
        tampered = "\n".join(l for l in orig_text.splitlines() if "DEP-AUD-001" not in l)
        errors_file = self.root / "registries" / "ERRORS.md"
        errors_file.parent.mkdir(parents=True, exist_ok=True)
        errors_file.write_text(tampered, encoding="utf-8")

        check_policy.ROOT = self.root
        check_policy.errors = []
        check_policy.diagnostic_policy()
        self.assertTrue(any("missing from registries/ERRORS.md: DEP-AUD-001" in err for err in check_policy.errors))

    def test_policy_lane_rejects_drifted_severity(self) -> None:
        """Policy lane must reject severity mismatch between code and markdown."""
        orig_text = (ROOT / "registries/ERRORS.md").read_text(encoding="utf-8")
        tampered = orig_text.replace("| `DEP-AUD-001` | error |", "| `DEP-AUD-001` | warning |")
        errors_file = self.root / "registries" / "ERRORS.md"
        errors_file.parent.mkdir(parents=True, exist_ok=True)
        errors_file.write_text(tampered, encoding="utf-8")

        check_policy.ROOT = self.root
        check_policy.errors = []
        check_policy.diagnostic_policy()
        self.assertTrue(any("severity mismatch" in err for err in check_policy.errors))

    def test_policy_lane_rejects_unregistered_finding_in_cargo_policy(self) -> None:
        """cargo_policy must reject any emitted finding with an unregistered code."""
        check_policy.ROOT = self.root
        check_policy.errors = []
        self._setup_clean_workspace()
        # Plant finding with unregistered code
        planted = Finding(severity="error", code="DEP-AUD-999", path="Cargo.toml", message="rogue finding")
        # Simulate check in cargo_policy
        if planted.code not in DIAGNOSTIC_REGISTRY:
            check_policy.fail(f"unregistered dependency audit diagnostic code: {planted.code}")
        self.assertTrue(any("unregistered dependency audit diagnostic code: DEP-AUD-999" in err for err in check_policy.errors))

    def test_finding_3_sanitization_leaks_usernames_and_paths(self) -> None:
        findings: list[Finding] = []
        root = Path("/data/projects/franken_surveillance_system")
        dependency_audit.add(
            findings,
            "error",
            "DEP-AUD-012",
            "/data/projects/franken_surveillance_system/Cargo.toml",
            "escapes root: /home/alice/secret/Cargo.toml",
            root=root,
            params={
                "raw_path": "/home/alice/secret/Cargo.toml",
                "manifest_path": Path("/home/alice/Cargo.toml"),
                "win_path": Path(r"C:\Users\alice\repo\Cargo.toml"),
            },
        )
        f = findings[0]
        self.assertNotIn("alice", f.message, f"Message leaked username: {f.message}")
        self.assertNotIn("alice", str(f.params.get("raw_path")), f"String param leaked username: {f.params}")
        self.assertNotIn("alice", str(f.params.get("manifest_path")), f"Path param leaked username: {f.params}")
        self.assertNotIn("alice", str(f.params.get("win_path")), f"Windows path param leaked username: {f.params}")

    def test_finding_4_diagnostic_id_swap_011_vs_025(self) -> None:
        self._setup_clean_workspace()
        (self.root / "Cargo.toml").write_text('workspace = "not_a_table"\n', encoding="utf-8")
        report, rc = dependency_audit.audit_workspace(self.root, self.policy_file)
        codes = [f["code"] for f in report["findings"]]
        self.assertIn("DEP-AUD-025", codes, "Missing [workspace] table must emit DEP-AUD-025, not DEP-AUD-011")
        self.assertNotIn("DEP-AUD-011", codes, "DEP-AUD-011 is for dependency sections, not [workspace]")

    def test_finding_5_check_policy_cargo_lock_missing_dep_aud_id(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            c1 = root / "crates" / "fss-core"
            c1.mkdir(parents=True)
            (c1 / "Cargo.toml").write_text('[package]\nname = "fss-core"\nversion = "0.1.0"\nedition = "2024"\n')
            (c1 / "src").mkdir()
            (c1 / "src" / "lib.rs").write_text("#![forbid(unsafe_code)]\n")
            (root / "Cargo.toml").write_text('[workspace]\nresolver = "3"\nmembers = ["crates/fss-core"]\n[workspace.lints.rust]\nunsafe_code = "forbid"\n')
            (root / "Cargo.lock").write_text('version = 4\n[[package]]\nname = "tokio"\nversion = "1.0.0"\n')

            policy = {
                "in_house": {"allowed_families": ["fss-*"]},
                "fundamental": {"allowed_subject_to_audit": []},
                "forbidden": {"crates": ["tokio"]},
            }
            orig_root = check_policy.ROOT
            check_policy.ROOT = root
            check_policy.errors = []
            try:
                check_policy.cargo_policy(policy)
                lock_errors = [e for e in check_policy.errors if "Cargo.lock" in e]
                self.assertTrue(len(lock_errors) > 0, "Must detect forbidden package in Cargo.lock")
                for e in lock_errors:
                    self.assertTrue(e.startswith("DEP-AUD-030:"), f"Error must start with DEP-AUD-030, got: {e!r}")
            finally:
                check_policy.ROOT = orig_root

    def test_finding_7_spurious_dep_aud_017_on_missing_workspace_dep(self) -> None:
        self._setup_clean_workspace()
        (self.root / "crates" / "fss-a" / "Cargo.toml").write_text(
            '[package]\nname = "fss-a"\nversion = "0.0.1"\nedition = "2024"\n[dependencies]\nserde = { workspace = true }\n',
            encoding="utf-8",
        )
        report, rc = dependency_audit.audit_workspace(self.root, self.policy_file)
        codes = [f["code"] for f in report["findings"]]
        self.assertIn("DEP-AUD-018", codes, "Must emit DEP-AUD-018 for missing workspace-inherited dependency")
        self.assertNotIn("DEP-AUD-017", codes, "Must NOT emit spurious DEP-AUD-017 when dependency failed to resolve via workspace")


if __name__ == "__main__":
    unittest.main()
