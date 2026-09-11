#!/usr/bin/env python3
from __future__ import annotations

import os
import shutil
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
import sys
sys.path.insert(0, str(ROOT / "scripts"))
import importlib.util
spec = importlib.util.spec_from_file_location("check_policy", ROOT / "scripts/check-policy.py")
check_policy = importlib.util.module_from_spec(spec)
spec.loader.exec_module(check_policy)
import dependency_audit


def make_clean_policy_dict() -> dict:
    return {
        "policy": {
            "closed_universe": True,
            "direct_crates_must_be_allowlisted": True,
            "transitive_closure_must_be_censused": True,
            "new_external_dependency_requires_dep_record_and_adr": True,
            "fss_crates_must_forbid_unsafe": True,
            "fss_unsafe_exceptions_allowed": False,
            "c_or_cpp_ffi_allowed": False,
            "dynamic_loading_allowed": False,
            "foreign_runtime_production_boundary_allowed": False,
            "release_resolution_must_be_locked_and_offline": True,
            "build_scripts_may_not_use_network": True,
            "runtime_acquisition_allowed": False,
            "foreign_executables_allowed_in_production": False,
            "serde_may_not_define_durable_bytes": True,
            "hosted_ci_is_not_release_authority": True,
            "asupersync_is_only_async_runtime": True,
        },
        "in_house": {
            "allowed_families": [
                "asupersync", "frankensqlite", "fsqlite-*", "frankenfs", "ffs-*",
                "frankensearch", "frankensearch-*", "franken_markdown", "fmd-*",
                "frankengraphdb", "fgdb-*", "franken_networkx", "fnx-*",
                "frankentorch", "ft-*", "fastmcp_rust", "fastmcp-*",
                "eidetic_engine_cli", "ee-*", "frankentui", "frankentui-*"
            ]
        },
        "fundamental": {
            "allowed_subject_to_audit": ["serde", "serde_json"]
        },
        "forbidden": {
            "crates": [
                "tokio", "async-std", "smol", "glommio", "monoio", "rayon",
                "reqwest", "hyper", "rusqlite", "sqlx", "diesel", "rocksdb",
                "pyo3", "opencv", "ffmpeg-next", "gstreamer", "ort", "tch"
            ]
        },
    }


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


class CheckPolicyTests(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name)
        (self.root / "rust-toolchain.toml").write_text('[toolchain]\nchannel = "nightly-2026-08-31"\n', encoding="utf-8")
        (self.root / "Cargo.lock").write_text('version = 3\n', encoding="utf-8")
        self.old_root = check_policy.ROOT
        self.old_errors = list(check_policy.errors)
        check_policy.ROOT = self.root
        check_policy.errors = []

    def tearDown(self) -> None:
        check_policy.ROOT = self.old_root
        check_policy.errors = self.old_errors
        self.tmp.cleanup()

    def test_cargo_policy_clean_passes(self) -> None:
        root_cargo = """[workspace]
resolver = "3"
members = ["crates/crate-a", "crates/crate-b"]

[workspace.lints.rust]
unsafe_code = "forbid"
"""
        (self.root / "Cargo.toml").write_text(root_cargo, encoding="utf-8")
        make_valid_crate(self.root / "crates" / "crate-a", "crate-a")
        make_valid_crate(self.root / "crates" / "crate-b", "crate-b", extra_manifest='[dependencies]\ncrate-a = { path = "../crate-a" }\n')

        check_policy.cargo_policy(make_clean_policy_dict())
        self.assertEqual(check_policy.errors, [])

    def test_cargo_policy_target_cfg_forbidden_dependency_fails(self) -> None:
        root_cargo = """[workspace]
resolver = "3"
members = ["crates/crate-a"]

[workspace.lints.rust]
unsafe_code = "forbid"
"""
        (self.root / "Cargo.toml").write_text(root_cargo, encoding="utf-8")
        a_extra = """[target.'cfg(windows)'.dependencies]
tokio = { version = "1.0", default-features = false }
"""
        make_valid_crate(self.root / "crates" / "crate-a", "crate-a", extra_manifest=a_extra)

        check_policy.cargo_policy(make_clean_policy_dict())
        self.assertTrue(any("forbidden direct dependency: tokio" in err or "DEP-AUD-015" in err for err in check_policy.errors))

    def test_cargo_policy_target_cfg_build_dependency_fails(self) -> None:
        root_cargo = """[workspace]
resolver = "3"
members = ["crates/crate-a"]

[workspace.lints.rust]
unsafe_code = "forbid"
"""
        (self.root / "Cargo.toml").write_text(root_cargo, encoding="utf-8")
        a_extra = """[target.'cfg(target_os = "linux")'.build-dependencies]
serde = { version = "1.0", default-features = false }
"""
        make_valid_crate(self.root / "crates" / "crate-a", "crate-a", extra_manifest=a_extra)

        check_policy.cargo_policy(make_clean_policy_dict())
        self.assertTrue(any("build dependency is prohibited" in err or "DEP-AUD-014" in err for err in check_policy.errors))

    def test_cargo_policy_target_root_missing_forbid_unsafe_fails(self) -> None:
        root_cargo = """[workspace]
resolver = "3"
members = ["crates/crate-a"]

[workspace.lints.rust]
unsafe_code = "forbid"
"""
        (self.root / "Cargo.toml").write_text(root_cargo, encoding="utf-8")
        make_valid_crate(self.root / "crates" / "crate-a", "crate-a")
        bin_dir = self.root / "crates" / "crate-a" / "src" / "bin"
        bin_dir.mkdir(parents=True, exist_ok=True)
        (bin_dir / "bypass.rs").write_text('fn main() { println!("no forbid"); }\n', encoding="utf-8")

        check_policy.cargo_policy(make_clean_policy_dict())
        self.assertTrue(any("target root lacks unconditional #![forbid(unsafe_code)]" in err or "DEP-AUD-021" in err for err in check_policy.errors))

    def test_cargo_policy_path_dependency_undeclared_fails(self) -> None:
        root_cargo = """[workspace]
resolver = "3"
members = ["crates/crate-a"]

[workspace.lints.rust]
unsafe_code = "forbid"
"""
        (self.root / "Cargo.toml").write_text(root_cargo, encoding="utf-8")
        make_valid_crate(self.root / "crates" / "rogue", "rogue")
        a_extra = """[dependencies]
rogue = { path = "../rogue" }
"""
        make_valid_crate(self.root / "crates" / "crate-a", "crate-a", extra_manifest=a_extra)

        check_policy.cargo_policy(make_clean_policy_dict())
        self.assertTrue(any("undeclared non-member crate" in err or "DEP-AUD-019" in err or "DEP-AUD-016" in err for err in check_policy.errors))

    def test_cargo_policy_path_dependency_escaping_fails(self) -> None:
        root_cargo = """[workspace]
resolver = "3"
members = ["crates/crate-a"]

[workspace.lints.rust]
unsafe_code = "forbid"
"""
        (self.root / "Cargo.toml").write_text(root_cargo, encoding="utf-8")
        a_extra = """[dependencies]
outside = { path = "../../../outside" }
"""
        make_valid_crate(self.root / "crates" / "crate-a", "crate-a", extra_manifest=a_extra)

        check_policy.cargo_policy(make_clean_policy_dict())
        self.assertTrue(any("escapes the frozen repository/sibling closure" in err or "DEP-AUD-012" in err for err in check_policy.errors))

    def test_cargo_policy_git_unpinned_fails(self) -> None:
        root_cargo = """[workspace]
resolver = "3"
members = ["crates/crate-a"]

[workspace.lints.rust]
unsafe_code = "forbid"
"""
        (self.root / "Cargo.toml").write_text(root_cargo, encoding="utf-8")
        a_extra = """[dependencies]
asupersync = { git = "https://github.com/example/asupersync", default-features = false }
"""
        make_valid_crate(self.root / "crates" / "crate-a", "crate-a", extra_manifest=a_extra)

        check_policy.cargo_policy(make_clean_policy_dict())
        self.assertTrue(any("Git dependency lacks an exact 40-hex rev" in err or "DEP-AUD-013" in err for err in check_policy.errors))

    def test_cargo_policy_external_without_default_features_false_fails(self) -> None:
        root_cargo = """[workspace]
resolver = "3"
members = ["crates/crate-a"]

[workspace.lints.rust]
unsafe_code = "forbid"
"""
        (self.root / "Cargo.toml").write_text(root_cargo, encoding="utf-8")
        a_extra = """[dependencies]
serde = { version = "1.0" }
"""
        make_valid_crate(self.root / "crates" / "crate-a", "crate-a", extra_manifest=a_extra)

        check_policy.cargo_policy(make_clean_policy_dict())
        self.assertTrue(any("external dependency must set default-features = false" in err or "DEP-AUD-017" in err for err in check_policy.errors))

    def test_cargo_policy_duplicate_member_fails(self) -> None:
        root_cargo = """[workspace]
resolver = "3"
members = ["crates/crate-a", "crates/*"]

[workspace.lints.rust]
unsafe_code = "forbid"
"""
        (self.root / "Cargo.toml").write_text(root_cargo, encoding="utf-8")
        make_valid_crate(self.root / "crates" / "crate-a", "crate-a")

        check_policy.cargo_policy(make_clean_policy_dict())
        self.assertTrue(any("workspace membership duplicate or ambiguous" in err or "DEP-AUD-024" in err for err in check_policy.errors))

    def test_manifest_files_excluded_from_source_files(self) -> None:
        manifest_files = check_policy.MANIFEST_FILES
        self.assertIn(Path("MANIFEST.sha256"), manifest_files)
        self.assertIn(Path("MANIFEST.delta.sha256"), manifest_files)
        self.assertFalse(check_policy.included(self.root / "MANIFEST.sha256"))
        self.assertFalse(check_policy.included(self.root / "MANIFEST.delta.sha256"))

    def test_live_check_policy_cargo_policy_passes(self) -> None:
        check_policy.ROOT = ROOT
        check_policy.errors = []
        policy_dict = check_policy.load_toml("architecture/dependency_allowlist.toml")
        check_policy.cargo_policy(policy_dict)
        self.assertEqual(check_policy.errors, [])

    def test_live_workflow_policy_passes(self) -> None:
        check_policy.ROOT = ROOT
        check_policy.errors = []
        check_policy.workflow_policy()
        self.assertEqual(check_policy.errors, [])

    def test_workflow_policy_unpinned_action_fails(self) -> None:
        workflows_dir = self.root / ".github" / "workflows"
        workflows_dir.mkdir(parents=True, exist_ok=True)
        bad_wf = """name: test
on: push
jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - run: bash scripts/qualify.sh
"""
        (workflows_dir / "ci.yml").write_text(bad_wf, encoding="utf-8")
        check_policy.ROOT = self.root
        check_policy.errors = []
        check_policy.workflow_policy()
        self.assertTrue(any("unpinned or comment-lacking workflow action" in err for err in check_policy.errors))

    def test_slo_validate_failure_fails_policy_even_without_error_severity(self) -> None:
        import slo_validate
        orig_validate = slo_validate.validate_slos
        try:
            slo_validate.validate_slos = lambda root=ROOT, slos_path=None, costs_path=None, claims_path=None: (
                False, [slo_validate.SloFinding("warning", "CODE-WARN-001", "path/to/file", "warning message")], {}
            )
            check_policy.ROOT = ROOT
            check_policy.errors = []
            check_policy.check_slo_policy(ROOT)
            self.assertTrue(
                any("SLO-VAL-FAILED" in err or "CODE-WARN-001" in err for err in check_policy.errors),
                f"check-policy must record an error when slo_valid is False even with only warnings, got: {check_policy.errors}",
            )
        finally:
            slo_validate.validate_slos = orig_validate


if __name__ == "__main__":
    unittest.main()
