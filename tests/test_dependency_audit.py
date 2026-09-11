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
serde = { version = "1.0", default-features = false }
"""
        (self.root / "Cargo.toml").write_text(root_cargo, encoding="utf-8")
        make_valid_crate(self.root / "crates" / "crate-a", "crate-a")
        b_extra = """[dependencies]
crate-a = { path = "../crate-a" }

[dev-dependencies]
serde = { workspace = true }
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
serde = { version = "1.0", default-features = false }

[target.'cfg(target_os = "linux")'.dev-dependencies]
serde_json = { version = "1.0", default-features = false }
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
autoexamples = false
autotests = false
autobenches = false
"""
        make_valid_crate(self.root / "crates" / "crate-a", "crate-a", extra_manifest=a_extra)
        # Add files that would be auto-discovered
        (self.root / "crates" / "crate-a" / "src" / "bin").mkdir(parents=True, exist_ok=True)
        (self.root / "crates" / "crate-a" / "src" / "bin" / "ignored.rs").write_text("fn main() {}\n", encoding="utf-8")
        (self.root / "crates" / "crate-a" / "tests").mkdir(parents=True, exist_ok=True)
        (self.root / "crates" / "crate-a" / "tests" / "ignored.rs").write_text("fn test() {}\n", encoding="utf-8")

        report, rc = dependency_audit.audit_workspace(self.root, self.policy_path)
        # Because autobins/autotests are false, those files are not targets and do not fail the audit!
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


if __name__ == "__main__":
    unittest.main()
