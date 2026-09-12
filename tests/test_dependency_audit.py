#!/usr/bin/env python3
from __future__ import annotations

import json
import os
import shutil
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
import sys
sys.path.insert(0, str(ROOT / "scripts"))
import dependency_audit


def make_clean_policy(dest: Path) -> Path:
    policy_path = dest / "architecture" / "dependency_allowlist.toml"
    policy_path.parent.mkdir(parents=True, exist_ok=True)
    policy_text = """schema = "fss.dependency_allowlist.v3"
as_of = "2026-09-01"

[policy]
closed_universe = true
direct_crates_must_be_allowlisted = true
transitive_closure_must_be_censused = true
new_external_dependency_requires_dep_record_and_adr = true
fss_crates_must_forbid_unsafe = true
fss_unsafe_exceptions_allowed = false
c_or_cpp_ffi_allowed = false
dynamic_loading_allowed = false
foreign_runtime_production_boundary_allowed = false
release_resolution_must_be_locked_and_offline = true
build_scripts_may_not_use_network = true
runtime_acquisition_allowed = false
foreign_executables_allowed_in_production = false
serde_may_not_define_durable_bytes = true
hosted_ci_is_not_release_authority = true
asupersync_is_only_async_runtime = true

[in_house]
allowed_families = [
  "asupersync",
  "frankensqlite", "fsqlite-*",
  "frankenfs", "ffs-*",
  "frankensearch", "frankensearch-*",
  "franken_markdown", "fmd-*",
  "frankengraphdb", "fgdb-*",
  "franken_networkx", "fnx-*",
  "frankentorch", "ft-*",
  "fastmcp_rust", "fastmcp-*",
  "eidetic_engine_cli", "ee-*",
  "frankentui", "frankentui-*"
]

[fundamental]
allowed_subject_to_audit = ["serde", "serde_json"]

[forbidden]
crates = [
  "tokio", "async-std", "smol", "glommio", "monoio", "rayon",
  "reqwest", "hyper", "rusqlite", "sqlx", "diesel", "rocksdb",
  "pyo3", "opencv", "ffmpeg-next", "gstreamer", "ort", "tch"
]
"""
    policy_path.write_text(policy_text, encoding="utf-8")
    return policy_path


def make_valid_crate(crate_dir: Path, name: str, extra_manifest: str = "") -> None:
    crate_dir.mkdir(parents=True, exist_ok=True)
    manifest = f"""[package]
name = "{name}"
version = "0.0.1"
edition = "2024"
{extra_manifest}
"""
    (crate_dir / "Cargo.toml").write_text(manifest, encoding="utf-8")
    src_dir = crate_dir / "src"
    src_dir.mkdir(parents=True, exist_ok=True)
    (src_dir / "lib.rs").write_text("#![forbid(unsafe_code)]\npub fn ok() {}\n", encoding="utf-8")


class DependencyAuditTests(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name)
        self.policy_path = make_clean_policy(self.root)
        (self.root / "rust-toolchain.toml").write_text('[toolchain]\nchannel = "nightly-2026-08-31"\n', encoding="utf-8")
        (self.root / "Cargo.lock").write_text('version = 3\n', encoding="utf-8")

    def tearDown(self) -> None:
        self.tmp.cleanup()

    def test_clean_workspace_qualifies(self) -> None:
        root_cargo = """[workspace]
resolver = "3"
members = ["crates/crate-a", "crates/crate-b"]

[workspace.lints.rust]
unsafe_code = "forbid"
"""
        (self.root / "Cargo.toml").write_text(root_cargo, encoding="utf-8")
        make_valid_crate(self.root / "crates" / "crate-a", "crate-a")
        make_valid_crate(
            self.root / "crates" / "crate-b",
            "crate-b",
            extra_manifest="""[dependencies]\ncrate-a = { path = \"../crate-a\" }\n""",
        )

        report, rc = dependency_audit.audit_workspace(self.root, self.policy_path)
        self.assertEqual(rc, 0)
        self.assertEqual(report["errorCount"], 0)
        self.assertEqual(report["targetRootCount"], 2)
        self.assertEqual(report["workspaceMemberCount"], 2)
        self.assertIn("censusDigest", report)
        self.assertTrue(report["censusDigest"].startswith("sha256:"))

    def test_all_dependency_sections_walked(self) -> None:
        root_cargo = """[workspace]
resolver = "3"
members = ["crates/crate-a", "crates/crate-b"]

[workspace.dependencies]
asupersync = { version = "1.0", default-features = false }
"""
        (self.root / "Cargo.toml").write_text(root_cargo, encoding="utf-8")
        make_valid_crate(self.root / "crates" / "crate-a", "crate-a")
        b_extra = """[dependencies]
crate-a = { path = "../crate-a" }

[dev-dependencies]
asupersync = { workspace = true }
"""
        make_valid_crate(self.root / "crates" / "crate-b", "crate-b", extra_manifest=b_extra)

        report, rc = dependency_audit.audit_workspace(self.root, self.policy_path)
        self.assertEqual(rc, 0)
        sections = {row["section"] for row in report["directDependencies"]}
        self.assertIn("dependencies", sections)
        self.assertIn("dev-dependencies", sections)
        self.assertIn("workspace.dependencies", sections)

    def test_target_cfg_dependencies_walked_and_censused(self) -> None:
        root_cargo = """[workspace]
resolver = "3"
members = ["crates/crate-a"]
"""
        (self.root / "Cargo.toml").write_text(root_cargo, encoding="utf-8")
        a_extra = """[target.'cfg(windows)'.dependencies]
asupersync = { version = "1.0", default-features = false }

[target.'cfg(target_os = "linux")'.dev-dependencies]
frankensqlite = { version = "1.0", default-features = false }
"""
        make_valid_crate(self.root / "crates" / "crate-a", "crate-a", extra_manifest=a_extra)

        report, rc = dependency_audit.audit_workspace(self.root, self.policy_path)
        self.assertEqual(rc, 0)
        target_rows = [row for row in report["directDependencies"] if row["targetPredicate"] is not None]
        self.assertEqual(len(target_rows), 2)
        predicates = {row["targetPredicate"] for row in target_rows}
        self.assertIn("cfg(windows)", predicates)
        self.assertIn('cfg(target_os = "linux")', predicates)

    def test_target_cfg_forbidden_dependency_fails(self) -> None:
        root_cargo = """[workspace]
resolver = "3"
members = ["crates/crate-a"]
"""
        (self.root / "Cargo.toml").write_text(root_cargo, encoding="utf-8")
        a_extra = """[target.'cfg(windows)'.dependencies]
tokio = { version = "1.0", default-features = false }
"""
        make_valid_crate(self.root / "crates" / "crate-a", "crate-a", extra_manifest=a_extra)

        report, rc = dependency_audit.audit_workspace(self.root, self.policy_path)
        self.assertEqual(rc, 1)
        codes = [f["code"] for f in report["findings"] if f["severity"] == "error"]
        self.assertIn("DEP-AUD-015", codes)

    def test_target_cfg_unallowlisted_dependency_fails(self) -> None:
        root_cargo = """[workspace]
resolver = "3"
members = ["crates/crate-a"]
"""
        (self.root / "Cargo.toml").write_text(root_cargo, encoding="utf-8")
        a_extra = """[target.'cfg(unix)'.dependencies]
unapproved_crate = { version = "1.0", default-features = false }
"""
        make_valid_crate(self.root / "crates" / "crate-a", "crate-a", extra_manifest=a_extra)

        report, rc = dependency_audit.audit_workspace(self.root, self.policy_path)
        self.assertEqual(rc, 1)
        codes = [f["code"] for f in report["findings"] if f["severity"] == "error"]
        self.assertIn("DEP-AUD-016", codes)

    def test_target_cfg_build_dependency_fails(self) -> None:
        root_cargo = """[workspace]
resolver = "3"
members = ["crates/crate-a"]
"""
        (self.root / "Cargo.toml").write_text(root_cargo, encoding="utf-8")
        a_extra = """[target.'cfg(target_os = "linux")'.build-dependencies]
serde = { version = "1.0", default-features = false }
"""
        make_valid_crate(self.root / "crates" / "crate-a", "crate-a", extra_manifest=a_extra)

        report, rc = dependency_audit.audit_workspace(self.root, self.policy_path)
        self.assertEqual(rc, 1)
        codes = [f["code"] for f in report["findings"] if f["severity"] == "error"]
        self.assertIn("DEP-AUD-014", codes)

    def test_top_level_build_dependency_fails(self) -> None:
        root_cargo = """[workspace]
resolver = "3"
members = ["crates/crate-a"]
"""
        (self.root / "Cargo.toml").write_text(root_cargo, encoding="utf-8")
        a_extra = """[build-dependencies]
serde = { version = "1.0", default-features = false }
"""
        make_valid_crate(self.root / "crates" / "crate-a", "crate-a", extra_manifest=a_extra)

        report, rc = dependency_audit.audit_workspace(self.root, self.policy_path)
        self.assertEqual(rc, 1)
        codes = [f["code"] for f in report["findings"] if f["severity"] == "error"]
        self.assertIn("DEP-AUD-014", codes)

    def test_renamed_dependency_audited_by_package_identity(self) -> None:
        root_cargo = """[workspace]
resolver = "3"
members = ["crates/crate-a"]
"""
        (self.root / "Cargo.toml").write_text(root_cargo, encoding="utf-8")
        a_extra = """[dependencies]
innocent_name = { package = "tokio", version = "1.0", default-features = false }
"""
        make_valid_crate(self.root / "crates" / "crate-a", "crate-a", extra_manifest=a_extra)

        report, rc = dependency_audit.audit_workspace(self.root, self.policy_path)
        self.assertEqual(rc, 1)
        codes = [f["code"] for f in report["findings"] if f["severity"] == "error"]
        self.assertIn("DEP-AUD-015", codes)
        matching = [r for r in report["directDependencies"] if r["localName"] == "innocent_name"]
        self.assertEqual(len(matching), 1)
        self.assertEqual(matching[0]["name"], "tokio")

    def test_workspace_inheritance_resolution_and_missing(self) -> None:
        root_cargo = """[workspace]
resolver = "3"
members = ["crates/crate-a"]

[workspace.dependencies]
serde = { version = "1.0", default-features = false }
"""
        (self.root / "Cargo.toml").write_text(root_cargo, encoding="utf-8")
        a_extra = """[dependencies]
serde = { workspace = true }
missing_dep = { workspace = true }
"""
        make_valid_crate(self.root / "crates" / "crate-a", "crate-a", extra_manifest=a_extra)

        report, rc = dependency_audit.audit_workspace(self.root, self.policy_path)
        self.assertEqual(rc, 1)
        codes = [f["code"] for f in report["findings"] if f["severity"] == "error"]
        self.assertIn("DEP-AUD-018", codes)

    def test_git_dependency_rev_validation(self) -> None:
        root_cargo = """[workspace]
resolver = "3"
members = ["crates/crate-a"]
"""
        (self.root / "Cargo.toml").write_text(root_cargo, encoding="utf-8")
        a_extra = """[dependencies]
asupersync = { git = "https://github.com/example/asupersync", rev = "not-a-40-hex-sha", default-features = false }
"""
        make_valid_crate(self.root / "crates" / "crate-a", "crate-a", extra_manifest=a_extra)

        report, rc = dependency_audit.audit_workspace(self.root, self.policy_path)
        self.assertEqual(rc, 1)
        codes = [f["code"] for f in report["findings"] if f["severity"] == "error"]
        self.assertIn("DEP-AUD-013", codes)

    def test_external_dependency_default_features(self) -> None:
        root_cargo = """[workspace]
resolver = "3"
members = ["crates/crate-a"]
"""
        (self.root / "Cargo.toml").write_text(root_cargo, encoding="utf-8")
        a_extra = """[dependencies]
serde = { version = "1.0" }
"""
        make_valid_crate(self.root / "crates" / "crate-a", "crate-a", extra_manifest=a_extra)

        report, rc = dependency_audit.audit_workspace(self.root, self.policy_path)
        self.assertEqual(rc, 1)
        codes = [f["code"] for f in report["findings"] if f["severity"] == "error"]
        self.assertIn("DEP-AUD-017", codes)

    def test_path_dependency_undeclared_non_member_fails(self) -> None:
        root_cargo = """[workspace]
resolver = "3"
members = ["crates/crate-a"]
"""
        (self.root / "Cargo.toml").write_text(root_cargo, encoding="utf-8")
        make_valid_crate(self.root / "crates" / "rogue-crate", "rogue-crate")
        a_extra = """[dependencies]
rogue-crate = { path = "../rogue-crate" }
"""
        make_valid_crate(self.root / "crates" / "crate-a", "crate-a", extra_manifest=a_extra)

        report, rc = dependency_audit.audit_workspace(self.root, self.policy_path)
        self.assertEqual(rc, 1)
        codes = [f["code"] for f in report["findings"] if f["severity"] == "error"]
        self.assertTrue("DEP-AUD-019" in codes or "DEP-AUD-016" in codes)

    def test_path_dependency_escaping_closure_fails(self) -> None:
        root_cargo = """[workspace]
resolver = "3"
members = ["crates/crate-a"]
"""
        (self.root / "Cargo.toml").write_text(root_cargo, encoding="utf-8")
        a_extra = """[dependencies]
escaped = { path = "../../../../../etc/passwd" }
"""
        make_valid_crate(self.root / "crates" / "crate-a", "crate-a", extra_manifest=a_extra)

        report, rc = dependency_audit.audit_workspace(self.root, self.policy_path)
        self.assertEqual(rc, 1)
        codes = [f["code"] for f in report["findings"] if f["severity"] == "error"]
        self.assertIn("DEP-AUD-012", codes)

    def test_path_dependency_forbidden_fails(self) -> None:
        root_cargo = """[workspace]
resolver = "3"
members = ["crates/crate-a"]
"""
        (self.root / "Cargo.toml").write_text(root_cargo, encoding="utf-8")
        make_valid_crate(self.root / "crates" / "tokio", "tokio")
        a_extra = """[dependencies]
tokio = { path = "../tokio" }
"""
        make_valid_crate(self.root / "crates" / "crate-a", "crate-a", extra_manifest=a_extra)

        report, rc = dependency_audit.audit_workspace(self.root, self.policy_path)
        self.assertEqual(rc, 1)
        codes = [f["code"] for f in report["findings"] if f["severity"] == "error"]
        self.assertIn("DEP-AUD-015", codes)

    def test_workspace_glob_expansion_and_excludes(self) -> None:
        root_cargo = """[workspace]
resolver = "3"
members = ["crates/*"]
exclude = ["crates/excluded"]
"""
        (self.root / "Cargo.toml").write_text(root_cargo, encoding="utf-8")
        make_valid_crate(self.root / "crates" / "one", "one")
        make_valid_crate(self.root / "crates" / "two", "two")
        make_valid_crate(self.root / "crates" / "excluded", "excluded")

        report, rc = dependency_audit.audit_workspace(self.root, self.policy_path)
        self.assertEqual(rc, 0)
        self.assertEqual(report["workspaceMemberCount"], 2)
        self.assertEqual(set(report["workspaceMembers"]), {"one", "two"})

    def test_workspace_duplicate_or_ambiguous_fails(self) -> None:
        root_cargo = """[workspace]
resolver = "3"
members = ["crates/crate-a", "crates/*"]
"""
        (self.root / "Cargo.toml").write_text(root_cargo, encoding="utf-8")
        make_valid_crate(self.root / "crates" / "crate-a", "crate-a")

        report, rc = dependency_audit.audit_workspace(self.root, self.policy_path)
        self.assertEqual(rc, 1)
        codes = [f["code"] for f in report["findings"] if f["severity"] == "error"]
        self.assertIn("DEP-AUD-024", codes)

    def test_auto_discovered_bin_missing_forbid_unsafe_fails(self) -> None:
        root_cargo = """[workspace]
resolver = "3"
members = ["crates/crate-a"]
"""
        (self.root / "Cargo.toml").write_text(root_cargo, encoding="utf-8")
        make_valid_crate(self.root / "crates" / "crate-a", "crate-a")
        bin_dir = self.root / "crates" / "crate-a" / "src" / "bin"
        bin_dir.mkdir(parents=True, exist_ok=True)
        (bin_dir / "unmarked.rs").write_text('fn main() { println!("bypass"); }\n', encoding="utf-8")

        report, rc = dependency_audit.audit_workspace(self.root, self.policy_path)
        self.assertEqual(rc, 1)
        codes = [f["code"] for f in report["findings"] if f["severity"] == "error"]
        self.assertIn("DEP-AUD-021", codes)

    def test_auto_discovered_test_missing_forbid_unsafe_fails(self) -> None:
        root_cargo = """[workspace]
resolver = "3"
members = ["crates/crate-a"]
"""
        (self.root / "Cargo.toml").write_text(root_cargo, encoding="utf-8")
        make_valid_crate(self.root / "crates" / "crate-a", "crate-a")
        test_dir = self.root / "crates" / "crate-a" / "tests"
        test_dir.mkdir(parents=True, exist_ok=True)
        (test_dir / "integration.rs").write_text("#[test]\nfn test_bypass() {}\n", encoding="utf-8")

        report, rc = dependency_audit.audit_workspace(self.root, self.policy_path)
        self.assertEqual(rc, 1)
        codes = [f["code"] for f in report["findings"] if f["severity"] == "error"]
        self.assertIn("DEP-AUD-021", codes)

    def test_auto_discovered_example_missing_forbid_unsafe_fails(self) -> None:
        root_cargo = """[workspace]
resolver = "3"
members = ["crates/crate-a"]
"""
        (self.root / "Cargo.toml").write_text(root_cargo, encoding="utf-8")
        make_valid_crate(self.root / "crates" / "crate-a", "crate-a")
        ex_dir = self.root / "crates" / "crate-a" / "examples"
        ex_dir.mkdir(parents=True, exist_ok=True)
        (ex_dir / "demo.rs").write_text("fn main() {}\n", encoding="utf-8")

        report, rc = dependency_audit.audit_workspace(self.root, self.policy_path)
        self.assertEqual(rc, 1)
        codes = [f["code"] for f in report["findings"] if f["severity"] == "error"]
        self.assertIn("DEP-AUD-021", codes)

    def test_auto_discovered_bench_missing_forbid_unsafe_fails(self) -> None:
        root_cargo = """[workspace]
resolver = "3"
members = ["crates/crate-a"]
"""
        (self.root / "Cargo.toml").write_text(root_cargo, encoding="utf-8")
        make_valid_crate(self.root / "crates" / "crate-a", "crate-a")
        bench_dir = self.root / "crates" / "crate-a" / "benches"
        bench_dir.mkdir(parents=True, exist_ok=True)
        (bench_dir / "speed.rs").write_text("fn main() {}\n", encoding="utf-8")

        report, rc = dependency_audit.audit_workspace(self.root, self.policy_path)
        self.assertEqual(rc, 1)
        codes = [f["code"] for f in report["findings"] if f["severity"] == "error"]
        self.assertIn("DEP-AUD-021", codes)

    def test_custom_build_script_fails(self) -> None:
        root_cargo = """[workspace]
resolver = "3"
members = ["crates/crate-a"]
"""
        (self.root / "Cargo.toml").write_text(root_cargo, encoding="utf-8")
        make_valid_crate(self.root / "crates" / "crate-a", "crate-a")
        (self.root / "crates" / "crate-a" / "build.rs").write_text("fn main() {}\n", encoding="utf-8")

        report, rc = dependency_audit.audit_workspace(self.root, self.policy_path)
        self.assertEqual(rc, 1)
        codes = [f["code"] for f in report["findings"] if f["severity"] == "error"]
        self.assertIn("DEP-AUD-031", codes)

    def test_autobins_autoexamples_autotests_flags_honored(self) -> None:
        root_cargo = """[workspace]
resolver = "3"
members = ["crates/crate-a"]
"""
        (self.root / "Cargo.toml").write_text(root_cargo, encoding="utf-8")
        a_extra = """autobins = false
"""
        make_valid_crate(self.root / "crates" / "crate-a", "crate-a", extra_manifest=a_extra)
        # Add files that would be auto-discovered
        (self.root / "crates" / "crate-a" / "src" / "bin").mkdir(parents=True, exist_ok=True)
        (self.root / "crates" / "crate-a" / "src" / "bin" / "ignored.rs").write_text("fn main() {}\n", encoding="utf-8")

        report, rc = dependency_audit.audit_workspace(self.root, self.policy_path)
        # Because autobins is false, those files are not targets and do not fail the audit!
        self.assertEqual(rc, 0)
        self.assertEqual(report["targetRootCount"], 1)

    def test_crate_no_target_roots_fails(self) -> None:
        root_cargo = """[workspace]
resolver = "3"
members = ["crates/crate-empty"]
"""
        (self.root / "Cargo.toml").write_text(root_cargo, encoding="utf-8")
        empty_dir = self.root / "crates" / "crate-empty"
        empty_dir.mkdir(parents=True, exist_ok=True)
        (empty_dir / "Cargo.toml").write_text("[package]\nname = \"crate-empty\"\nversion = \"0.0.1\"\nedition = \"2024\"\n", encoding="utf-8")

        report, rc = dependency_audit.audit_workspace(self.root, self.policy_path)
        self.assertEqual(rc, 1)
        codes = [f["code"] for f in report["findings"] if f["severity"] == "error"]
        self.assertIn("DEP-AUD-020", codes)

    def test_forbidden_production_constructs_fail(self) -> None:
        root_cargo = """[workspace]
resolver = "3"
members = ["crates/crate-a"]
"""
        (self.root / "Cargo.toml").write_text(root_cargo, encoding="utf-8")
        make_valid_crate(self.root / "crates" / "crate-a", "crate-a")
        mod_file = self.root / "crates" / "crate-a" / "src" / "danger.rs"
        mod_file.write_text("pub unsafe fn danger() {}\n", encoding="utf-8")

        report, rc = dependency_audit.audit_workspace(self.root, self.policy_path)
        self.assertEqual(rc, 1)
        codes = [f["code"] for f in report["findings"] if f["severity"] == "error"]
        self.assertIn("DEP-AUD-022", codes)

    def test_foreign_production_command_src_rejected_tests_admitted(self) -> None:
        """Planted-negative test: Command::new("ffmpeg") in src/ rejected with DEP-AUD-022;

        Command::new(env!("CARGO_BIN_EXE_x")) and oracle commands in tests/ admitted.
        """
        root_cargo = """[workspace]
resolver = "3"
members = ["crates/crate-a"]
"""
        (self.root / "Cargo.toml").write_text(root_cargo, encoding="utf-8")
        make_valid_crate(self.root / "crates" / "crate-a", "crate-a")

        # In tests/, Command::new(env!("CARGO_BIN_EXE_crate-a")) and oracle commands are admitted
        (self.root / "crates" / "crate-a" / "tests").mkdir(parents=True, exist_ok=True)
        test_file = self.root / "crates" / "crate-a" / "tests" / "test_bin.rs"
        test_file.write_text(
            '#![forbid(unsafe_code)]\nuse std::process::Command;\nfn test() {\n    let _ = Command::new(env!("CARGO_BIN_EXE_crate-a"));\n    let _ = Command::new("python3");\n}\n',
            encoding="utf-8",
        )
        report_ok, rc_ok = dependency_audit.audit_workspace(self.root, self.policy_path)
        self.assertEqual(rc_ok, 0, f"Expected clean audit with tests/ Command::new, got {report_ok.get('findings')}")

        # In src/, Command::new("ffmpeg") is rejected with DEP-AUD-022
        bad_src = self.root / "crates" / "crate-a" / "src" / "foreign.rs"
        bad_src.write_text(
            '#![forbid(unsafe_code)]\nuse std::process::Command;\npub fn run_ffmpeg() {\n    let _ = Command::new("ffmpeg");\n}\n',
            encoding="utf-8",
        )
        report_bad, rc_bad = dependency_audit.audit_workspace(self.root, self.policy_path)
        self.assertEqual(rc_bad, 1)
        codes = [f["code"] for f in report_bad["findings"] if f["severity"] == "error"]
        self.assertIn("DEP-AUD-022", codes)
        bad_findings = [f for f in report_bad["findings"] if f["code"] == "DEP-AUD-022"]
        self.assertTrue(any("foreign production command" in f.get("message", "") for f in bad_findings))

    def test_property_monotonic_violation(self) -> None:
        root_cargo = """[workspace]
resolver = "3"
members = ["crates/crate-a"]
"""
        (self.root / "Cargo.toml").write_text(root_cargo, encoding="utf-8")
        make_valid_crate(self.root / "crates" / "crate-a", "crate-a")

        report_clean, rc_clean = dependency_audit.audit_workspace(self.root, self.policy_path)
        self.assertEqual(rc_clean, 0)
        clean_errors = report_clean["errorCount"]

        # Add a forbidden target
        (self.root / "crates" / "crate-a" / "tests").mkdir(parents=True, exist_ok=True)
        (self.root / "crates" / "crate-a" / "tests" / "unsafe_test.rs").write_text("fn test() {}\n", encoding="utf-8")

        report_bad, rc_bad = dependency_audit.audit_workspace(self.root, self.policy_path)
        self.assertEqual(rc_bad, 1)
        self.assertGreater(report_bad["errorCount"], clean_errors)

    def test_census_digest_deterministic(self) -> None:
        root_cargo = """[workspace]
resolver = "3"
members = ["crates/crate-a"]
"""
        (self.root / "Cargo.toml").write_text(root_cargo, encoding="utf-8")
        make_valid_crate(self.root / "crates" / "crate-a", "crate-a")

        report1, _ = dependency_audit.audit_workspace(self.root, self.policy_path)
        report2, _ = dependency_audit.audit_workspace(self.root, self.policy_path)
        self.assertEqual(report1["censusDigest"], report2["censusDigest"])

    def test_live_repository_audit(self) -> None:
        report, rc = dependency_audit.audit_workspace(ROOT, ROOT / "architecture/dependency_allowlist.toml")
        self.assertEqual(rc, 0)
        self.assertEqual(report["errorCount"], 0)
        self.assertEqual(report["schema"], "fss.dependency_audit.v4")
        self.assertGreaterEqual(report["targetRootCount"], 20)
        self.assertEqual(report["workspaceMemberCount"], 6)

    def test_finding_1_undeclared_nested_crate_false_green(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            pol = make_clean_policy(root)
            (root / "Cargo.toml").write_text('[workspace]\nresolver = "3"\nmembers = ["crates/fss-core"]\n')
            c1 = root / "crates" / "fss-core"
            c1.mkdir(parents=True)
            (c1 / "Cargo.toml").write_text('[package]\nname = "fss-core"\nversion = "0.1.0"\nedition = "2024"\n')
            (c1 / "src").mkdir()
            (c1 / "src" / "lib.rs").write_text("#![forbid(unsafe_code)]\n")

            # Undeclared nested crate with build.rs and no forbid
            nested = root / "crates" / "fss-core" / "nested-rogue"
            nested.mkdir(parents=True)
            (nested / "Cargo.toml").write_text('[package]\nname = "nested-rogue"\nversion = "0.1.0"\nedition = "2024"\n')
            (nested / "build.rs").write_text("fn main() {}\n")
            (nested / "src").mkdir()
            (nested / "src" / "lib.rs").write_text("pub fn foo() {}\n")

            report, rc = dependency_audit.audit_workspace(root, pol)
            codes = [f["code"] for f in report["findings"]]
            self.assertIn("DEP-AUD-019", codes, "Must detect undeclared non-member crate in repository tree")
            self.assertIn("DEP-AUD-021", codes, "Must enforce forbid(unsafe_code) on undeclared crate")
            self.assertIn("DEP-AUD-031", codes, "Must detect custom build script on undeclared crate")
            self.assertNotEqual(rc, 0, "Audit must not return 0 for undeclared crate with build script")

    def test_finding_2_autoexamples_false_bypasses_forbid_unsafe(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            pol = make_clean_policy(root)
            (root / "Cargo.toml").write_text('[workspace]\nresolver = "3"\nmembers = ["crates/fss-core"]\n')
            c1 = root / "crates" / "fss-core"
            c1.mkdir(parents=True)
            (c1 / "Cargo.toml").write_text('[package]\nname = "fss-core"\nversion = "0.1.0"\nedition = "2024"\nautoexamples = false\nautobenches = false\n')
            (c1 / "src").mkdir()
            (c1 / "src" / "lib.rs").write_text("#![forbid(unsafe_code)]\n")

            (c1 / "examples").mkdir()
            (c1 / "examples" / "ex.rs").write_text("fn main() {}\n")  # no forbid!
            (c1 / "benches").mkdir()
            (c1 / "benches" / "bn.rs").write_text("fn main() {}\n")  # no forbid!

            report, rc = dependency_audit.audit_workspace(root, pol)
            codes = [f["code"] for f in report["findings"]]
            self.assertIn("DEP-AUD-021", codes, "Must enforce forbid(unsafe_code) even when autoexamples=false")
            self.assertNotEqual(rc, 0, "Audit must not pass when example lacks forbid(unsafe_code)")

    def test_finding_6_dependency_audit_ignores_cargo_lock_without_metadata(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            pol = make_clean_policy(root)
            (root / "Cargo.toml").write_text('[workspace]\nresolver = "3"\nmembers = ["crates/fss-core"]\n')
            c1 = root / "crates" / "fss-core"
            c1.mkdir(parents=True)
            (c1 / "Cargo.toml").write_text('[package]\nname = "fss-core"\nversion = "0.1.0"\nedition = "2024"\n')
            (c1 / "src").mkdir()
            (c1 / "src" / "lib.rs").write_text("#![forbid(unsafe_code)]\n")
            (root / "Cargo.lock").write_text('version = 4\n[[package]]\nname = "tokio"\nversion = "1.0.0"\n')

            report, rc = dependency_audit.audit_workspace(root, pol)
            codes = [f["code"] for f in report["findings"]]
            self.assertIn("DEP-AUD-030", codes, "Audit must detect forbidden package in Cargo.lock even in policy_only mode")
            self.assertNotEqual(rc, 0, "Audit must fail when Cargo.lock contains a forbidden crate")


SERDE_CODE = "DEP-AUD-023"


class SerdeDurableBytesTests(unittest.TestCase):
    """fss-x4a.9.17 (FSS-110): Serde (or a serde-adjacent codec) may not define durable bytes.

    The scanner masks Rust comments and string/char literals before matching, so commented-out or
    quoted derives do not fail, while code hidden behind a literal that merely contains a comment
    opener still fails.
    """

    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name)
        self.policy_path = make_clean_policy(self.root)
        (self.root / "rust-toolchain.toml").write_text('[toolchain]\nchannel = "nightly-2026-08-31"\n', encoding="utf-8")
        (self.root / "Cargo.lock").write_text("version = 3\n", encoding="utf-8")
        (self.root / "Cargo.toml").write_text('[workspace]\nresolver = "3"\nmembers = ["crates/crate-a"]\n', encoding="utf-8")
        self.crate = self.root / "crates" / "crate-a"

    def tearDown(self) -> None:
        self.tmp.cleanup()

    def audit(self, extra_manifest: str = "", lib_body: str | None = None) -> tuple[dict, int]:
        make_valid_crate(self.crate, "crate-a", extra_manifest=extra_manifest)
        if lib_body is not None:
            (self.crate / "src" / "lib.rs").write_text("#![forbid(unsafe_code)]\n" + lib_body, encoding="utf-8")
        return dependency_audit.audit_workspace(self.root, self.policy_path)

    @staticmethod
    def serde_findings(report: dict) -> list[dict]:
        return [f for f in report["findings"] if f["code"] == SERDE_CODE]

    def test_positive_control_first_party_canonical_codec_passes(self) -> None:
        body = (
            "/// Serializes to canonical bytes; Deserialize is spelled out only in this comment.\n"
            "pub trait CanonicalSerialize { fn canonical_bytes(&self) -> Vec<u8>; }\n"
            "pub struct Deserializer;\n"
            "#[derive(Debug, Clone, PartialEq, Eq)]\n"
            "pub struct Frame { pub id: u64 }\n"
            "pub fn serialize_canonical(v: u8) -> [u8; 1] { [v] }\n"
        )
        report, rc = self.audit(lib_body=body)
        self.assertEqual(self.serde_findings(report), [])
        self.assertEqual(rc, 0, report["findings"])

    def test_manifest_codec_crates_refused_in_every_dependency_section(self) -> None:
        crates = ["serde", "serde_json", "serde_derive", "serde-cbor", "bincode", "postcard", "ciborium", "rmp-serde", "rmp_serde"]
        sections = ["dependencies", "dev-dependencies", "build-dependencies", "target.'cfg(unix)'.dependencies"]
        for crate in crates:
            for section in sections:
                with self.subTest(crate=crate, section=section):
                    extra = f'[{section}]\n{crate} = {{ version = "1", default-features = false }}\n'
                    report, rc = self.audit(extra_manifest=extra)
                    self.assertEqual(rc, 1)
                    hits = self.serde_findings(report)
                    self.assertTrue(any(f["params"].get("package") == crate for f in hits), hits)
                    self.assertTrue(any("crates/crate-a/Cargo.toml:" in f["message"] for f in hits), hits)

    def test_renamed_codec_dependency_refused_by_package_identity(self) -> None:
        extra = '[dependencies]\ncanon = { package = "bincode", version = "1", default-features = false }\n'
        report, rc = self.audit(extra_manifest=extra)
        self.assertEqual(rc, 1)
        self.assertTrue(any(f["params"].get("package") == "bincode" for f in self.serde_findings(report)))

    def test_workspace_dependencies_codec_refused(self) -> None:
        (self.root / "Cargo.toml").write_text(
            '[workspace]\nresolver = "3"\nmembers = ["crates/crate-a"]\n\n[workspace.dependencies]\npostcard = { version = "1", default-features = false }\n',
            encoding="utf-8",
        )
        report, rc = self.audit()
        self.assertEqual(rc, 1)
        hits = self.serde_findings(report)
        self.assertTrue(any(f["params"].get("package") == "postcard" and "Cargo.toml:6" in f["message"] for f in hits), hits)

    def test_cargo_lock_codec_package_refused(self) -> None:
        (self.root / "Cargo.lock").write_text(
            'version = 4\n\n[[package]]\nname = "ciborium"\nversion = "0.2.2"\n', encoding="utf-8"
        )
        report, rc = self.audit()
        self.assertEqual(rc, 1)
        hits = self.serde_findings(report)
        self.assertTrue(any(f["path"] == "Cargo.lock" and "Cargo.lock:4" in f["message"] for f in hits), hits)

    def test_unparseable_cargo_lock_fails_closed(self) -> None:
        (self.root / "Cargo.lock").write_text("version = [unterminated\n", encoding="utf-8")
        report, rc = self.audit()
        self.assertEqual(rc, 1)
        self.assertTrue(any(f["code"] == "DEP-AUD-011" and f["path"] == "Cargo.lock" for f in report["findings"]), report["findings"])

    def test_source_serde_forms_refused_with_file_and_line(self) -> None:
        cases = {
            "derive": ("#[derive(Debug, Serialize)]\npub struct A;\n", 2),
            "multiline derive with path": ("#[derive(\n    Clone,\n    serde::Deserialize,\n)]\npub struct A;\n", 2),
            "cfg_attr derive": ('#[cfg_attr(feature = "x", derive(Serialize))]\npub struct A;\n', 2),
            "serde attribute": ('#[serde(rename_all = "camelCase")]\npub struct A;\n', 2),
            "serde_json path": ("pub fn f() -> Vec<u8> { serde_json::to_vec(&1).unwrap() }\n", 2),
            "extern crate bincode": ("extern crate bincode;\n", 2),
            "use postcard": ("use postcard::to_slice;\n", 2),
            "absolute serde path": ("pub fn g() {}\nimpl ::serde::Serialize for X {}\n", 3),
            "use serde bare": ("use serde;\n", 2),
            "rmp_serde path": ("pub fn h() { let _ = rmp_serde::to_vec(&1); }\n", 2),
            "ciborium path": ("pub fn k() { let _ = ciborium::into_writer; }\n", 2),
        }
        for label, (body, line) in cases.items():
            with self.subTest(label=label):
                report, rc = self.audit(lib_body=body)
                self.assertEqual(rc, 1, label)
                hits = self.serde_findings(report)
                self.assertTrue(
                    any(f"crates/crate-a/src/lib.rs:{line}" in f["message"] and f["params"].get("line") == line for f in hits),
                    (label, hits),
                )

    def test_non_root_module_and_integration_test_are_scanned(self) -> None:
        make_valid_crate(self.crate, "crate-a")
        (self.crate / "src" / "codec.rs").write_text("pub fn f() {}\n#[derive(Deserialize)]\npub struct Wire;\n", encoding="utf-8")
        (self.crate / "tests").mkdir()
        (self.crate / "tests" / "roundtrip.rs").write_text("#![forbid(unsafe_code)]\nuse serde_json as j;\n", encoding="utf-8")
        report, rc = dependency_audit.audit_workspace(self.root, self.policy_path)
        self.assertEqual(rc, 1)
        messages = " ".join(f["message"] for f in self.serde_findings(report))
        self.assertIn("crates/crate-a/src/codec.rs:2", messages)
        self.assertIn("crates/crate-a/tests/roundtrip.rs:2", messages)

    def test_commented_out_or_quoted_serde_does_not_fail(self) -> None:
        body = (
            "//! inner doc: serde_json::to_vec is not used here\n"
            "// #[derive(Serialize)]\n"
            "/// ```\n"
            "/// #[derive(Deserialize)] struct Doc;\n"
            "/// ```\n"
            "/* #[derive(Serialize)]\n"
            "   /* nested serde::Value */ still a comment #[serde(skip)] extern crate bincode; */\n"
            'pub const A: &str = "#[derive(Serialize)] serde::x use serde;";\n'
            'pub const B: &str = r#"#[serde(rename = "x")] bincode::"#;\n'
            'pub const C: &[u8] = b"serde::";\n'
            'pub const C2: &[u8] = br##"postcard:: "# still raw"##;\n'
            "pub const D: char = '\"';\n"
            "pub const E: char = '\\'';\n"
            "pub const F: u8 = b'\"';\n"
            "pub fn f<'a>(x: &'a str) -> &'a str { x }\n"
        )
        report, rc = self.audit(lib_body=body)
        self.assertEqual(self.serde_findings(report), [])
        self.assertEqual(rc, 0, report["findings"])

    def test_literal_containing_comment_opener_does_not_hide_code(self) -> None:
        cases = {
            "block opener in string": ('pub const U: &str = "http://example.invalid/*";\n#[derive(Serialize)]\npub struct A;\n', 3),
            "line comment in string": ('pub const U: &str = "a // b";\n#[derive(Serialize)]\npub struct A;\n', 3),
            "quote inside raw string": ('pub const R: &str = r#"a "quoted" // not comment"#;\n#[derive(Serialize)]\npub struct A;\n', 3),
            "lifetime then derive": ("pub fn f<'a>(x: &'a str) -> &'a str { x } #[derive(Deserialize)] pub struct B;\n", 2),
            "char quote then derive": ("pub const Q: char = '\"'; #[derive(Serialize)] pub struct C;\n", 2),
        }
        for label, (body, line) in cases.items():
            with self.subTest(label=label):
                report, rc = self.audit(lib_body=body)
                self.assertEqual(rc, 1, label)
                hits = self.serde_findings(report)
                self.assertTrue(any(f"src/lib.rs:{line}" in f["message"] for f in hits), (label, hits))

    def test_live_repository_has_no_serde_durable_bytes(self) -> None:
        report, _ = dependency_audit.audit_workspace(ROOT, ROOT / "architecture/dependency_allowlist.toml")
        self.assertEqual(self.serde_findings(report), [])


class RustLexerTests(unittest.TestCase):
    """Pins the comment/literal masking the durable-bytes and build-script scanners rely on."""

    def test_mask_preserves_length_and_newlines(self) -> None:
        text = 'a /* x\ny */ "s\nt" // c\nb\n'
        masked, literals = dependency_audit.mask_rust_source(text)
        self.assertEqual(len(masked), len(text))
        self.assertEqual([i for i, ch in enumerate(masked) if ch == "\n"], [i for i, ch in enumerate(text) if ch == "\n"])
        self.assertNotIn("x", masked)
        self.assertNotIn("c", masked.replace("\n", ""))
        self.assertEqual([lit.content for lit in literals], ["s\nt"])
        self.assertEqual(literals[0].line, 2)

    def test_raw_and_byte_literals_recorded(self) -> None:
        text = 'let a = r##"x"#y"##; let b = b"z"; let c = cr"w";'
        masked, literals = dependency_audit.mask_rust_source(text)
        self.assertEqual([lit.content for lit in literals], ['x"#y', "z", "w"])
        self.assertNotIn("y", masked.replace("let", ""))

    def test_unterminated_block_comment_masks_to_eof(self) -> None:
        masked, _ = dependency_audit.mask_rust_source("a /* serde::x\n#[derive(Serialize)]")
        self.assertNotIn("serde", masked)


NET_CODE = "DEP-AUD-026"
OFFLINE_CODE = "DEP-AUD-027"


class BuildScriptNetworkTests(unittest.TestCase):
    """fss-x4a.26.3 (FSS-183): static deny-list of network-capable constructs in build scripts.

    A pass is not a proof of network absence: only literal tokens in comment/literal-masked source
    are matched; macro expansion, non-literal Command::new arguments, and indirect I/O are not seen.
    """

    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name)
        self.policy_path = make_clean_policy(self.root)
        (self.root / "rust-toolchain.toml").write_text('[toolchain]\nchannel = "nightly-2026-08-31"\n', encoding="utf-8")
        (self.root / "Cargo.lock").write_text("version = 3\n", encoding="utf-8")
        (self.root / "Cargo.toml").write_text('[workspace]\nresolver = "3"\nmembers = ["crates/crate-a"]\n', encoding="utf-8")
        self.crate = self.root / "crates" / "crate-a"

    def tearDown(self) -> None:
        self.tmp.cleanup()

    def audit_build(self, body: str, manifest_extra: str = "", build_rel: str = "build.rs") -> tuple[dict, int]:
        make_valid_crate(self.crate, "crate-a", extra_manifest=manifest_extra)
        script = self.crate / build_rel
        script.parent.mkdir(parents=True, exist_ok=True)
        script.write_text("#![forbid(unsafe_code)]\n" + body, encoding="utf-8")
        return dependency_audit.audit_workspace(self.root, self.policy_path)

    @staticmethod
    def net(report: dict) -> list[dict]:
        return [f for f in report["findings"] if f["code"] == NET_CODE]

    def test_positive_control_offline_build_script_has_no_network_finding(self) -> None:
        body = 'fn main() {\n    println!("cargo:rerun-if-changed=build.rs");\n    let _ = std::env::var("OUT_DIR");\n}\n'
        report, rc = self.audit_build(body)
        self.assertEqual(self.net(report), [])
        # Build scripts stay constitutionally refused (DEP-AUD-031) whether or not they touch the network.
        self.assertIn("DEP-AUD-031", [f["code"] for f in report["findings"]])
        self.assertEqual(rc, 1)

    def test_each_network_pattern_fails_with_file_and_line(self) -> None:
        cases = {
            "std::net": ("use std::net::TcpStream as _;\nfn main() {}\n", 2),
            "grouped std net": ("use std::{io, net};\nfn main() {}\n", 2),
            "TcpStream": ('fn main() {\n    let _ = TcpStream::connect("127.0.0.1:1");\n}\n', 3),
            "TcpListener": ('fn main() { let _ = TcpListener::bind("0.0.0.0:0"); }\n', 2),
            "UdpSocket": ('fn main() { let _ = UdpSocket::bind("0.0.0.0:0"); }\n', 2),
            "ToSocketAddrs": ("fn main() { fn f<T: ToSocketAddrs>(_: T) {} }\n", 2),
            "curl": ('fn main() { let _ = std::process::Command::new("curl").arg("-O"); }\n', 2),
            "wget": ('fn main() { let _ = Command::new("wget"); }\n', 2),
            "git": ('fn main() {\n\n    let _ = Command::new( "git" ).arg("fetch");\n}\n', 4),
            "ssh": ('fn main() { let _ = Command::new("ssh"); }\n', 2),
            "nc": ('fn main() { let _ = Command::new("nc"); }\n', 2),
            "absolute curl path": ('fn main() { let _ = Command::new("/usr/bin/curl"); }\n', 2),
            "raw string command": ('fn main() { let _ = Command::new(r"wget"); }\n', 2),
            "https literal": ('fn main() { let _u = "https://example.invalid/blob"; }\n', 2),
            "http literal inside macro": ('fn main() {\n    let _u = concat!(\n        "http://example.invalid"\n    );\n}\n', 4),
        }
        for label, (body, line) in cases.items():
            with self.subTest(label=label):
                report, rc = self.audit_build(body)
                self.assertEqual(rc, 1)
                hits = self.net(report)
                self.assertTrue(
                    any(f"crates/crate-a/build.rs:{line}" in f["message"] and f["params"].get("line") == line for f in hits),
                    (label, hits),
                )

    def test_commented_or_quoted_network_tokens_do_not_fail(self) -> None:
        body = (
            "// TcpStream::connect and std::net are only mentioned here\n"
            '/* Command::new("curl") https://example.invalid */\n'
            "/// see https://doc.rust-lang.org/cargo/reference/build-scripts.html\n"
            "fn main() {\n"
            '    println!("cargo:warning=TcpStream UdpSocket std::net are only words here");\n'
            '    let _ = std::process::Command::new(env!("RUSTC")).arg("-V");\n'
            '    let _ = std::process::Command::new("rustc").arg("curl");\n'
            "}\n"
        )
        report, _ = self.audit_build(body)
        self.assertEqual(self.net(report), [])

    def test_custom_build_path_is_scanned(self) -> None:
        report, rc = self.audit_build(
            "fn main() { let _ = std::net::UdpSocket::bind(\"0.0.0.0:0\"); }\n",
            manifest_extra='build = "tools/gen.rs"\n',
            build_rel="tools/gen.rs",
        )
        self.assertEqual(rc, 1)
        self.assertTrue(any("crates/crate-a/tools/gen.rs:2" in f["message"] for f in self.net(report)), self.net(report))

    def test_build_true_scans_default_build_rs(self) -> None:
        report, rc = self.audit_build("fn main() { let _ = TcpStream::connect(\"x:1\"); }\n", manifest_extra="build = true\n")
        self.assertEqual(rc, 1)
        self.assertTrue(any("crates/crate-a/build.rs:2" in f["message"] for f in self.net(report)), self.net(report))
        self.assertIn("DEP-AUD-031", [f["code"] for f in report["findings"]])

    def test_build_false_disables_default_build_rs(self) -> None:
        report, _ = self.audit_build("fn main() { let _ = TcpStream::connect(\"x:1\"); }\n", manifest_extra="build = false\n")
        self.assertEqual(self.net(report), [])

    def test_declared_but_missing_build_script_fails_closed(self) -> None:
        make_valid_crate(self.crate, "crate-a", extra_manifest='build = "tools/missing.rs"\n')
        report, rc = dependency_audit.audit_workspace(self.root, self.policy_path)
        self.assertEqual(rc, 1)
        self.assertTrue(any("tools/missing.rs" in f["message"] for f in self.net(report)), self.net(report))

    def test_undeclared_crate_build_script_is_scanned(self) -> None:
        make_valid_crate(self.crate, "crate-a")
        rogue = self.root / "crates" / "crate-a" / "nested-rogue"
        make_valid_crate(rogue, "nested-rogue")
        (rogue / "build.rs").write_text('#![forbid(unsafe_code)]\nfn main() { let _ = Command::new("curl"); }\n', encoding="utf-8")
        report, rc = dependency_audit.audit_workspace(self.root, self.policy_path)
        self.assertEqual(rc, 1)
        self.assertTrue(any("nested-rogue/build.rs:2" in f["message"] for f in self.net(report)), self.net(report))

    def test_resolved_package_build_script_from_metadata_is_scanned(self) -> None:
        external = self.root / "vendor-src" / "netty-1.0.0"
        external.mkdir(parents=True)
        (external / "build.rs").write_text('fn main() { let _ = std::net::TcpStream::connect("x:1"); }\n', encoding="utf-8")
        raw_metadata = {
            "workspace_members": [],
            "packages": [
                {
                    "id": "netty 1.0.0",
                    "name": "netty",
                    "version": "1.0.0",
                    "source": "registry+https://github.com/rust-lang/crates.io-index",
                    "manifest_path": str(external / "Cargo.toml"),
                    "targets": [{"kind": ["custom-build"], "name": "build-script-build", "src_path": str(external / "build.rs")}],
                }
            ],
        }
        findings: list = []
        paths: list = []
        dependency_audit.metadata_audit(findings, {}, root=self.root, raw_metadata=raw_metadata, build_script_paths=paths)
        dependency_audit.build_script_network_audit(findings, root=self.root, extra_paths=paths)
        codes = [f.code for f in findings]
        self.assertIn("DEP-AUD-031", codes)
        self.assertTrue(any(f.code == NET_CODE and "vendor-src/netty-1.0.0/build.rs:1" in f.message for f in findings), findings)

    def test_network_tokens_outside_build_scripts_are_out_of_scope(self) -> None:
        make_valid_crate(self.crate, "crate-a")
        (self.crate / "src" / "lib.rs").write_text("#![forbid(unsafe_code)]\npub use std::net::TcpStream;\n", encoding="utf-8")
        report, _ = dependency_audit.audit_workspace(self.root, self.policy_path)
        self.assertEqual(self.net(report), [])


SEALED_QUALIFY = (
    "#!/usr/bin/env bash\n"
    "export RUSTUP_AUTO_INSTALL=0\n"
    "export CARGO_NET_OFFLINE=true\n"
    "# cargo build is mentioned in a comment only\n"
    "rust_lane() {\n"
    '  run cargo-version rustup run "$tc" cargo --offline -V\n'
    '  run metadata rustup run "$tc" cargo metadata --locked --offline --format-version 1\n'
    '  run fmt rustup run "$tc" cargo --offline fmt --all --check\n'
    '  run test rustup run "$tc" cargo test --locked \\\n'
    "    --offline --workspace\n"
    "}\n"
    'run manifest python3 scripts/check.py --cargo-lock "$ROOT/Cargo.lock"\n'
)


class QualifyOfflineTests(unittest.TestCase):
    """fss-x4a.26.3 (FSS-183): scripts/qualify.sh must run every cargo invocation sealed offline.

    This is Cargo resolution sealing (--offline plus CARGO_NET_OFFLINE=true), not OS-level network
    isolation: no network namespace (`unshare -n`) is required or claimed.
    """

    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name)
        self.script = self.root / "scripts" / "qualify.sh"
        self.script.parent.mkdir(parents=True)

    def tearDown(self) -> None:
        self.tmp.cleanup()

    def audit(self, text: str | None) -> list:
        if text is not None:
            self.script.write_text(text, encoding="utf-8")
        findings: list = []
        dependency_audit.qualify_offline_audit(findings, self.script, root=self.root)
        return [f for f in findings if f.code == OFFLINE_CODE]

    def test_positive_control_sealed_script_passes(self) -> None:
        self.assertEqual(self.audit(SEALED_QUALIFY), [])

    def test_cargo_invocation_without_offline_fails_with_line(self) -> None:
        hits = self.audit(SEALED_QUALIFY + '  run clippy rustup run "$tc" cargo clippy --locked --workspace\n')
        self.assertEqual(len(hits), 1, hits)
        self.assertIn("scripts/qualify.sh:13", hits[0].message)
        self.assertEqual(hits[0].params.get("line"), 13)

    def test_fmt_without_offline_is_not_exempt(self) -> None:
        hits = self.audit(SEALED_QUALIFY.replace("cargo --offline fmt", "cargo fmt"))
        self.assertTrue(any("scripts/qualify.sh:8" in f.message for f in hits), hits)

    def test_version_query_without_offline_fails(self) -> None:
        hits = self.audit(SEALED_QUALIFY.replace("cargo --offline -V", "cargo -V"))
        self.assertTrue(any("scripts/qualify.sh:6" in f.message for f in hits), hits)

    def test_missing_export_fails(self) -> None:
        hits = self.audit(SEALED_QUALIFY.replace("export CARGO_NET_OFFLINE=true\n", ""))
        self.assertTrue(any("CARGO_NET_OFFLINE" in f.message for f in hits), hits)

    def test_export_not_at_top_level_before_first_cargo_fails(self) -> None:
        moved = SEALED_QUALIFY.replace("export CARGO_NET_OFFLINE=true\n", "").replace("rust_lane() {\n", "rust_lane() {\n  export CARGO_NET_OFFLINE=true\n")
        self.assertTrue(self.audit(moved))
        late = SEALED_QUALIFY.replace("export CARGO_NET_OFFLINE=true\n", "") + "export CARGO_NET_OFFLINE=true\n"
        self.assertTrue(self.audit(late))

    def test_override_or_unset_fails(self) -> None:
        for extra in (
            "unset CARGO_NET_OFFLINE\n",
            'CARGO_NET_OFFLINE=false rustup run "$tc" cargo build --offline\n',
            'env -u CARGO_NET_OFFLINE rustup run "$tc" cargo build --offline\n',
            "export CARGO_NET_OFFLINE=false\n",
        ):
            with self.subTest(extra=extra):
                self.assertTrue(self.audit(SEALED_QUALIFY + extra))

    def test_cargo_inside_quoted_bash_c_is_checked(self) -> None:
        self.assertTrue(self.audit(SEALED_QUALIFY + "run build bash -c 'cargo build --locked'\n"))

    def test_offline_in_a_later_command_does_not_satisfy(self) -> None:
        self.assertTrue(self.audit(SEALED_QUALIFY + 'rustup run "$tc" cargo build --locked && echo --offline\n'))

    def test_absolute_cargo_path_is_checked(self) -> None:
        self.assertTrue(self.audit(SEALED_QUALIFY + '"$HOME/.cargo/bin/cargo" build --locked\n'))

    def test_missing_script_fails_closed(self) -> None:
        hits = self.audit(None)
        self.assertEqual(len(hits), 1)
        self.assertIn("missing", hits[0].message)

    def test_audit_workspace_wires_qualify_script(self) -> None:
        make_clean_policy(self.root)
        (self.root / "Cargo.lock").write_text("version = 3\n", encoding="utf-8")
        (self.root / "Cargo.toml").write_text('[workspace]\nresolver = "3"\nmembers = ["crates/crate-a"]\n', encoding="utf-8")
        make_valid_crate(self.root / "crates" / "crate-a", "crate-a")
        self.script.write_text(SEALED_QUALIFY.replace("cargo test --locked", "cargo test --locked --no-run").replace("--offline --workspace", "--workspace"), encoding="utf-8")
        policy = self.root / "architecture" / "dependency_allowlist.toml"
        report, rc = dependency_audit.audit_workspace(self.root, policy, qualify_script=self.script)
        self.assertEqual(rc, 1)
        self.assertTrue(any(f["code"] == OFFLINE_CODE and "scripts/qualify.sh:9" in f["message"] for f in report["findings"]), report["findings"])

    def test_live_qualify_script_is_sealed_offline(self) -> None:
        findings: list = []
        dependency_audit.qualify_offline_audit(findings, ROOT / "scripts" / "qualify.sh", root=ROOT)
        self.assertEqual(findings, [])

    def test_live_repository_audit_with_qualify_script_passes(self) -> None:
        report, rc = dependency_audit.audit_workspace(ROOT, ROOT / "architecture/dependency_allowlist.toml", qualify_script=ROOT / "scripts" / "qualify.sh")
        self.assertEqual([f for f in report["findings"] if f["severity"] == "error"], [])
        self.assertEqual(rc, 0)


DOCTEST_CODE = "DEP-AUD-028"
DOCTEST_QUALIFY = (
    "#!/usr/bin/env bash\n"
    "export CARGO_NET_OFFLINE=true\n"
    "rust_lane() {\n"
    '  run test rustup run "$tc" cargo test --locked --offline --workspace --all-targets\n'
    '  run doctest rustup run "$tc" cargo test --locked --offline --workspace --doc\n'
    "}\n"
    'case "$LANE" in\n'
    "  rust) rust_lane ;;\n"
    "esac\n"
)
DOCTEST_LINE = '  run doctest rustup run "$tc" cargo test --locked --offline --workspace --doc\n'


class QualifyDoctestTests(unittest.TestCase):
    """fss-tgwit: `cargo test --all-targets` never runs doctests, so the rust lane of
    scripts/qualify.sh must carry a separately recorded `cargo test --workspace --doc` step."""

    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name)
        self.script = self.root / "scripts" / "qualify.sh"
        self.script.parent.mkdir(parents=True)

    def tearDown(self) -> None:
        self.tmp.cleanup()

    def audit(self, text: str | None) -> list:
        if text is not None:
            self.script.write_text(text, encoding="utf-8")
        findings: list = []
        dependency_audit.qualify_doctest_audit(findings, self.script, root=self.root)
        return [f for f in findings if f.code == DOCTEST_CODE]

    def test_positive_control_recorded_doctest_step_passes(self) -> None:
        self.assertEqual(self.audit(DOCTEST_QUALIFY), [])

    def test_continued_line_doctest_step_passes(self) -> None:
        continued = DOCTEST_QUALIFY.replace(DOCTEST_LINE, '  run doctest rustup run "$tc" cargo test --locked \\\n    --offline --workspace --doc\n')
        self.assertEqual(self.audit(continued), [])

    def test_missing_doctest_step_fails_at_rust_lane(self) -> None:
        hits = self.audit(DOCTEST_QUALIFY.replace(DOCTEST_LINE, ""))
        self.assertEqual(len(hits), 1, hits)
        self.assertIn("scripts/qualify.sh:3", hits[0].message)
        self.assertEqual(hits[0].params.get("line"), 3)

    def test_all_targets_test_step_alone_does_not_count(self) -> None:
        self.assertTrue(self.audit(DOCTEST_QUALIFY.replace(DOCTEST_LINE, "")))

    def test_commented_doctest_step_does_not_count(self) -> None:
        self.assertTrue(self.audit(DOCTEST_QUALIFY.replace(DOCTEST_LINE, "  # " + DOCTEST_LINE.lstrip())))

    def test_unrecorded_doctest_command_does_not_count(self) -> None:
        self.assertTrue(self.audit(DOCTEST_QUALIFY.replace(DOCTEST_LINE, '  rustup run "$tc" cargo test --locked --offline --workspace --doc\n')))

    def test_doctest_step_outside_rust_lane_does_not_count(self) -> None:
        moved = DOCTEST_QUALIFY.replace(DOCTEST_LINE, "").replace("rust_lane() {\n", "policy_lane() {\n" + DOCTEST_LINE + "}\nrust_lane() {\n")
        self.assertTrue(self.audit(moved))

    def test_doc_flag_passed_to_test_binary_does_not_count(self) -> None:
        self.assertTrue(self.audit(DOCTEST_QUALIFY.replace("--workspace --doc\n", "--workspace -- --doc\n")))

    def test_doc_flag_in_a_later_command_does_not_count(self) -> None:
        self.assertTrue(self.audit(DOCTEST_QUALIFY.replace("--workspace --doc\n", "--workspace && echo --doc\n")))

    def test_single_package_doctest_step_does_not_count(self) -> None:
        self.assertTrue(self.audit(DOCTEST_QUALIFY.replace("--workspace --doc\n", "-p fss-core --doc\n")))

    def test_no_run_doctest_step_does_not_count(self) -> None:
        self.assertTrue(self.audit(DOCTEST_QUALIFY.replace("--workspace --doc\n", "--workspace --doc --no-run\n")))

    def test_missing_rust_lane_fails(self) -> None:
        self.assertTrue(self.audit(DOCTEST_QUALIFY.replace("rust_lane() {\n", "other_lane() {\n")))

    def test_missing_script_fails_closed(self) -> None:
        hits = self.audit(None)
        self.assertEqual(len(hits), 1)
        self.assertIn("missing", hits[0].message)

    def test_audit_workspace_wires_doctest_check(self) -> None:
        make_clean_policy(self.root)
        (self.root / "Cargo.lock").write_text("version = 3\n", encoding="utf-8")
        (self.root / "Cargo.toml").write_text('[workspace]\nresolver = "3"\nmembers = ["crates/crate-a"]\n', encoding="utf-8")
        make_valid_crate(self.root / "crates" / "crate-a", "crate-a")
        self.script.write_text(DOCTEST_QUALIFY.replace(DOCTEST_LINE, ""), encoding="utf-8")
        policy = self.root / "architecture" / "dependency_allowlist.toml"
        report, rc = dependency_audit.audit_workspace(self.root, policy, qualify_script=self.script)
        self.assertEqual(rc, 1)
        self.assertTrue(any(f["code"] == DOCTEST_CODE and "scripts/qualify.sh:3" in f["message"] for f in report["findings"]), report["findings"])

    def test_live_qualify_script_runs_doctests(self) -> None:
        findings: list = []
        dependency_audit.qualify_doctest_audit(findings, ROOT / "scripts" / "qualify.sh", root=ROOT)
        self.assertEqual(findings, [])


class QualifyRustupAutoInstallTests(unittest.TestCase):
    """fss-x4a.26.3 follow-up: DEP-AUD-027 also requires a top-level `export RUSTUP_AUTO_INSTALL=0`
    so rustup cannot fetch a missing toolchain. rustup sealing, not OS-level network isolation."""

    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name)
        self.script = self.root / "scripts" / "qualify.sh"
        self.script.parent.mkdir(parents=True)

    def tearDown(self) -> None:
        self.tmp.cleanup()

    def audit(self, text: str) -> list:
        self.script.write_text(text, encoding="utf-8")
        findings: list = []
        dependency_audit.qualify_offline_audit(findings, self.script, root=self.root)
        return [f for f in findings if f.code == OFFLINE_CODE]

    def test_missing_rustup_export_fails(self) -> None:
        hits = self.audit(SEALED_QUALIFY.replace("export RUSTUP_AUTO_INSTALL=0\n", ""))
        self.assertEqual(len(hits), 1, hits)
        self.assertIn("RUSTUP_AUTO_INSTALL", hits[0].message)

    def test_rustup_export_must_disable_auto_install(self) -> None:
        for value in ("1", "true", "yes", ""):
            with self.subTest(value=value):
                self.assertTrue(self.audit(SEALED_QUALIFY.replace("RUSTUP_AUTO_INSTALL=0\n", f"RUSTUP_AUTO_INSTALL={value}\n")))

    def test_rustup_export_not_at_top_level_before_first_rustup_fails(self) -> None:
        moved = SEALED_QUALIFY.replace("export RUSTUP_AUTO_INSTALL=0\n", "").replace("rust_lane() {\n", "rust_lane() {\n  export RUSTUP_AUTO_INSTALL=0\n")
        self.assertTrue(self.audit(moved))
        late = SEALED_QUALIFY.replace("export RUSTUP_AUTO_INSTALL=0\n", "") + "export RUSTUP_AUTO_INSTALL=0\n"
        self.assertTrue(self.audit(late))

    def test_rustup_use_before_export_fails_even_without_cargo(self) -> None:
        self.assertTrue(self.audit(SEALED_QUALIFY.replace("#!/usr/bin/env bash\n", "#!/usr/bin/env bash\nrustup show active-toolchain\n")))

    def test_rustup_override_or_unset_fails(self) -> None:
        for extra in (
            "unset RUSTUP_AUTO_INSTALL\n",
            'RUSTUP_AUTO_INSTALL=1 rustup run "$tc" cargo build --offline\n',
            'env -u RUSTUP_AUTO_INSTALL rustup run "$tc" cargo build --offline\n',
            "export RUSTUP_AUTO_INSTALL=1\n",
        ):
            with self.subTest(extra=extra):
                self.assertTrue(self.audit(SEALED_QUALIFY + extra))

    def test_live_qualify_script_seals_rustup(self) -> None:
        text = (ROOT / "scripts" / "qualify.sh").read_text(encoding="utf-8")
        self.assertEqual(self.audit(text), [])


SEALED_RELEASE_QUALIFY = (
    "#!/usr/bin/env bash\n"
    "set -euo pipefail\n"
    "export CARGO_NET_OFFLINE=true\n"
    "export RUSTUP_AUTO_INSTALL=0\n"
    "host_triple() {\n"
    "  rustup run \"$1\" rustc -Vv | sed -n 's/^host: //p'\n"
    "}\n"
    "build_release() {\n"
    '  rustup run "$TOOLCHAIN" cargo build --release --workspace --locked --offline --target "$TARGET"\n'
    "}\n"
)


class ReleaseQualifyOfflineTests(unittest.TestCase):
    """fss-x4a.26.3 follow-up: scripts/release_qualify.sh runs cargo and rustup directly, so the whole
    DEP-AUD-027 check applies to it as well as to scripts/qualify.sh."""

    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name)
        self.script = self.root / "scripts" / "release_qualify.sh"
        self.script.parent.mkdir(parents=True)

    def tearDown(self) -> None:
        self.tmp.cleanup()

    def audit(self, text: str) -> list:
        self.script.write_text(text, encoding="utf-8")
        findings: list = []
        dependency_audit.qualify_offline_audit(findings, self.script, root=self.root)
        return [f for f in findings if f.code == OFFLINE_CODE]

    def test_positive_control_sealed_release_script_passes(self) -> None:
        self.assertEqual(self.audit(SEALED_RELEASE_QUALIFY), [])

    def test_release_cargo_without_offline_fails_with_line(self) -> None:
        hits = self.audit(SEALED_RELEASE_QUALIFY.replace("--locked --offline --target", "--locked --target"))
        self.assertEqual(len(hits), 1, hits)
        self.assertIn("scripts/release_qualify.sh:9", hits[0].message)

    def test_release_script_missing_exports_fails(self) -> None:
        hits = self.audit(SEALED_RELEASE_QUALIFY.replace("export CARGO_NET_OFFLINE=true\n", "").replace("export RUSTUP_AUTO_INSTALL=0\n", ""))
        self.assertTrue(any("CARGO_NET_OFFLINE" in f.message for f in hits), hits)
        self.assertTrue(any("RUSTUP_AUTO_INSTALL" in f.message for f in hits), hits)

    def test_audit_workspace_wires_release_script(self) -> None:
        make_clean_policy(self.root)
        (self.root / "Cargo.lock").write_text("version = 3\n", encoding="utf-8")
        (self.root / "Cargo.toml").write_text('[workspace]\nresolver = "3"\nmembers = ["crates/crate-a"]\n', encoding="utf-8")
        make_valid_crate(self.root / "crates" / "crate-a", "crate-a")
        self.script.write_text(SEALED_RELEASE_QUALIFY.replace("export CARGO_NET_OFFLINE=true\n", ""), encoding="utf-8")
        policy = self.root / "architecture" / "dependency_allowlist.toml"
        report, rc = dependency_audit.audit_workspace(self.root, policy, release_script=self.script)
        self.assertEqual(rc, 1)
        self.assertTrue(any(f["code"] == OFFLINE_CODE and "scripts/release_qualify.sh" in f["message"] for f in report["findings"]), report["findings"])

    def test_main_audits_both_qualification_scripts(self) -> None:
        import contextlib
        import io
        from unittest import mock

        seen: dict = {}

        def record(**kwargs):
            seen.update(kwargs)
            return {"findings": []}, 0

        with mock.patch.object(dependency_audit, "audit_workspace", side_effect=record), mock.patch.object(sys, "argv", ["dependency_audit.py"]), contextlib.redirect_stdout(io.StringIO()):
            self.assertEqual(dependency_audit.main(), 0)
        self.assertEqual(seen.get("qualify_script"), ROOT / "scripts" / "qualify.sh")
        self.assertEqual(seen.get("release_script"), ROOT / "scripts" / "release_qualify.sh")

    def test_live_release_script_is_sealed_offline(self) -> None:
        findings: list = []
        dependency_audit.qualify_offline_audit(findings, ROOT / "scripts" / "release_qualify.sh", root=ROOT)
        self.assertEqual(findings, [])

    def test_live_repository_audit_with_both_scripts_passes(self) -> None:
        report, rc = dependency_audit.audit_workspace(
            ROOT,
            ROOT / "architecture/dependency_allowlist.toml",
            qualify_script=ROOT / "scripts" / "qualify.sh",
            release_script=ROOT / "scripts" / "release_qualify.sh",
        )
        self.assertEqual([f for f in report["findings"] if f["severity"] == "error"], [])
        self.assertEqual(rc, 0)


class QualifyShellQuotingAndRustupInstallTests(unittest.TestCase):
    """fss-x4a.26.3 follow-up: DEP-AUD-027 rejects rustup commands that can fetch a toolchain over the
    network, and its shell-line analysis ignores quoted text and `#` comments while still re-parsing
    the command strings of `bash -c` / `sh -c`, `eval`, and `$(...)` substitutions."""

    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name)
        self.script = self.root / "scripts" / "qualify.sh"
        self.script.parent.mkdir(parents=True)

    def tearDown(self) -> None:
        self.tmp.cleanup()

    def audit(self, text: str) -> list:
        self.script.write_text(text, encoding="utf-8")
        findings: list = []
        dependency_audit.qualify_offline_audit(findings, self.script, root=self.root)
        return [f for f in findings if f.code == OFFLINE_CODE]

    def assert_one_hit_at(self, extra: str, line: int) -> None:
        hits = self.audit(SEALED_QUALIFY + extra)
        self.assertEqual(len(hits), 1, hits)
        self.assertIn(f"scripts/qualify.sh:{line}:", hits[0].message)
        self.assertEqual(hits[0].params.get("line"), line)

    def test_rustup_install_forms_fail_with_line(self) -> None:
        for extra in (
            'rustup run --install "$tc" cargo build --offline\n',
            'rustup run "$tc" --install cargo build --offline\n',
            'rustup toolchain install "$tc"\n',
            'rustup toolchain add "$tc"\n',
            'rustup install "$tc"\n',
            "rustup update\n",
            'rustup update "$tc"\n',
            "rustup -v update\n",
            '"$HOME/.cargo/bin/rustup" toolchain install "$tc"\n',
            'run fetch bash -c \'rustup toolchain install "$tc"\'\n',
            'test -n "$tc" && rustup install "$tc"\n',
            'rustup toolchain \\\n  install "$tc"\n',
        ):
            with self.subTest(extra=extra):
                self.assert_one_hit_at(extra, 13)
                self.assertIn("rustup", self.audit(SEALED_QUALIFY + extra)[0].message)

    def test_other_network_fetching_rustup_forms_fail(self) -> None:
        for extra in ('rustup component add clippy --toolchain "$tc"\n', 'rustup target add "$target"\n', "rustup self update\n"):
            with self.subTest(extra=extra):
                self.assert_one_hit_at(extra, 13)

    def test_rustup_install_words_in_quotes_or_comments_pass(self) -> None:
        for extra in (
            "printf '%s\\n' 'run rustup toolchain install to repair' >&2\n",
            'echo "rustup update is forbidden here"\n',
            "# rustup toolchain install nightly\n",
            'rustup run "$tc" rustc -Vv # rustup update would fetch\n',
        ):
            with self.subTest(extra=extra):
                self.assertEqual(self.audit(SEALED_QUALIFY + extra), [])

    def test_quoted_cargo_text_does_not_fail(self) -> None:
        for extra in (
            "printf 'cargo metadata receipt missing: %s\\n' \"$RECEIPT_DIR/cargo-metadata.json\" >&2\n",
            'printf "cargo build failed: %s\\n" "$status" >&2\n',
            "echo 'see cargo test --doc'\n",
            'echo "cargo metadata receipt missing"\n',
            "[ -f \"$d/x\" ] || { printf '%s\\n' 'cargo metadata missing' >&2; exit 7; }\n",
        ):
            with self.subTest(extra=extra):
                self.assertEqual(self.audit(SEALED_QUALIFY + extra), [])

    def test_unquoted_cargo_after_quoted_string_still_fails(self) -> None:
        for extra in (
            "printf 'cargo is fine\\n'; rustup run \"$tc\" cargo build --locked\n",
            'echo "cargo is fine" && cargo build --locked\n',
            "printf '%s' 'cargo --offline' | cargo build --locked\n",
        ):
            with self.subTest(extra=extra):
                self.assert_one_hit_at(extra, 13)

    def test_cargo_inside_shell_c_strings_still_fails(self) -> None:
        for extra in (
            'run build bash -c "cargo build --locked"\n',
            "run build sh -c 'cargo build --locked'\n",
            'run build bash -ec "cd crates && cargo build --locked"\n',
            'run build /bin/bash --norc -c "rustup run \\"$tc\\" cargo build --locked"\n',
            'eval "cargo build --locked"\n',
        ):
            with self.subTest(extra=extra):
                self.assert_one_hit_at(extra, 13)
        self.assertEqual(self.audit(SEALED_QUALIFY + 'run build bash -c "cargo build --locked --offline"\n'), [])

    def test_cargo_inside_command_substitution_still_fails(self) -> None:
        for extra in (
            'meta="$(rustup run "$tc" cargo metadata --locked)"\n',
            "meta=`cargo metadata --locked`\n",
            'echo "$(cargo metadata --locked)"\n',
        ):
            with self.subTest(extra=extra):
                self.assert_one_hit_at(extra, 13)
        self.assertEqual(self.audit(SEALED_QUALIFY + 'meta="$(rustup run "$tc" cargo metadata --locked --offline)"\n'), [])

    def test_trailing_comment_text_does_not_fail(self) -> None:
        for extra in ("echo done # cargo build without offline\n", "true;# cargo build\n"):
            with self.subTest(extra=extra):
                self.assertEqual(self.audit(SEALED_QUALIFY + extra), [])

    def test_hash_inside_a_word_is_not_a_comment(self) -> None:
        self.assert_one_hit_at('echo "${#arr[@]}" a#b cargo build --locked\n', 13)

    def test_comment_ending_in_backslash_does_not_hide_the_next_line(self) -> None:
        self.assert_one_hit_at('# a comment is not continued by a trailing backslash \\\nrustup run "$tc" cargo build --locked\n', 14)

    def test_unterminated_quote_falls_back_to_a_conservative_scan(self) -> None:
        self.assert_one_hit_at("echo 'unbalanced cargo build --locked\n", 13)

    def test_live_release_script_names_cargo_in_a_quoted_message(self) -> None:
        text = (ROOT / "scripts" / "release_qualify.sh").read_text(encoding="utf-8")
        self.assertIn("printf 'cargo metadata receipt missing: %s\\n'", text)
        self.assertEqual(self.audit(text), [])

    def test_live_qualification_scripts_pass(self) -> None:
        for script in ("qualify.sh", "release_qualify.sh"):
            with self.subTest(script=script):
                findings: list = []
                dependency_audit.qualify_offline_audit(findings, ROOT / "scripts" / script, root=ROOT)
                self.assertEqual(findings, [])


if __name__ == "__main__":
    unittest.main()
