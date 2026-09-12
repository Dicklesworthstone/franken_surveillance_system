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


class CheckPolicyFixtureCase(unittest.TestCase):
    """Temp-root fixture shared by the enforcement tests below (no inherited test methods)."""

    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name)
        (self.root / "rust-toolchain.toml").write_text('[toolchain]\nchannel = "nightly-2026-08-31"\n', encoding="utf-8")
        (self.root / "Cargo.lock").write_text("version = 3\n", encoding="utf-8")
        self.old_root = check_policy.ROOT
        self.old_errors = list(check_policy.errors)
        check_policy.ROOT = self.root
        check_policy.errors = []

    def tearDown(self) -> None:
        check_policy.ROOT = self.old_root
        check_policy.errors = self.old_errors
        self.tmp.cleanup()


class CheckPolicySerdeDurableBytesTests(CheckPolicyFixtureCase):
    """fss-x4a.9.17: check-policy's cargo_policy enforces DEP-AUD-023, not just the policy boolean."""

    def _workspace(self, lib_body: str) -> None:
        (self.root / "Cargo.toml").write_text(
            '[workspace]\nresolver = "3"\nmembers = ["crates/crate-a"]\n\n[workspace.lints.rust]\nunsafe_code = "forbid"\n',
            encoding="utf-8",
        )
        make_valid_crate(self.root / "crates" / "crate-a", "crate-a")
        (self.root / "crates" / "crate-a" / "src" / "lib.rs").write_text("#![forbid(unsafe_code)]\n" + lib_body, encoding="utf-8")

    def test_cargo_policy_serde_derive_fails(self) -> None:
        self._workspace("#[derive(serde::Serialize)]\npub struct Durable;\n")
        check_policy.cargo_policy(make_clean_policy_dict())
        self.assertTrue(any(err.startswith("DEP-AUD-023") and "src/lib.rs:2" in err for err in check_policy.errors), check_policy.errors)

    def test_cargo_policy_commented_serde_derive_passes(self) -> None:
        self._workspace("// #[derive(serde::Serialize)]\npub struct Durable;\n")
        check_policy.cargo_policy(make_clean_policy_dict())
        self.assertEqual(check_policy.errors, [])

    def test_cargo_policy_serde_grouped_use_and_raw_ident_fails(self) -> None:
        cases = [
            "use {bincode};\n",
            "pub use {postcard};\n",
            "use {serde, rmp_serde};\n",
            "use {postcard as pc};\n",
            "use r#bincode;\n",
            "extern crate r#serde;\n",
        ]
        for src in cases:
            with self.subTest(src=src):
                check_policy.errors.clear()
                self._workspace(src)
                check_policy.cargo_policy(make_clean_policy_dict())
                self.assertTrue(
                    any(err.startswith("DEP-AUD-023") and "src/lib.rs:2" in err for err in check_policy.errors),
                    (src, check_policy.errors),
                )



class CheckPolicyOfflineBuildTests(CheckPolicyFixtureCase):
    """fss-x4a.26.3: check-policy enforces DEP-AUD-026 (build-script network deny-list) and
    DEP-AUD-027 (sealed-offline qualify.sh), not just build_scripts_may_not_use_network = true."""

    def test_cargo_policy_build_script_network_fails(self) -> None:
        (self.root / "Cargo.toml").write_text(
            '[workspace]\nresolver = "3"\nmembers = ["crates/crate-a"]\n\n[workspace.lints.rust]\nunsafe_code = "forbid"\n',
            encoding="utf-8",
        )
        make_valid_crate(self.root / "crates" / "crate-a", "crate-a")
        (self.root / "crates" / "crate-a" / "build.rs").write_text(
            '#![forbid(unsafe_code)]\nfn main() { let _ = std::process::Command::new("curl"); }\n', encoding="utf-8"
        )
        check_policy.cargo_policy(make_clean_policy_dict())
        self.assertTrue(any(err.startswith("DEP-AUD-026") and "build.rs:2" in err for err in check_policy.errors), check_policy.errors)

    def test_qualify_offline_policy_missing_offline_fails(self) -> None:
        script = self.root / "scripts" / "qualify.sh"
        script.parent.mkdir(parents=True)
        script.write_text(
            '#!/usr/bin/env bash\nexport CARGO_NET_OFFLINE=true\nrun check rustup run "$tc" cargo check --locked --workspace\n',
            encoding="utf-8",
        )
        check_policy.qualify_offline_policy()
        self.assertTrue(any(err.startswith("DEP-AUD-027") and "scripts/qualify.sh:3" in err for err in check_policy.errors), check_policy.errors)

    def test_qualify_offline_policy_missing_script_fails(self) -> None:
        check_policy.qualify_offline_policy()
        self.assertTrue(any(err.startswith("DEP-AUD-027") for err in check_policy.errors), check_policy.errors)

    def test_live_qualify_offline_policy_passes(self) -> None:
        check_policy.ROOT = ROOT
        check_policy.qualify_offline_policy()
        self.assertEqual(check_policy.errors, [])


class CheckPolicyDoctestStepTests(CheckPolicyFixtureCase):
    """fss-tgwit: check-policy mirrors DEP-AUD-028, the recorded `cargo test --workspace --doc` step
    that scripts/qualify.sh's rust lane needs because `--all-targets` never runs doctests."""

    def test_qualify_doctest_policy_missing_step_fails(self) -> None:
        script = self.root / "scripts" / "qualify.sh"
        script.parent.mkdir(parents=True)
        script.write_text(
            '#!/usr/bin/env bash\nexport CARGO_NET_OFFLINE=true\nrust_lane() {\n'
            '  run test rustup run "$tc" cargo test --locked --offline --workspace --all-targets\n}\n',
            encoding="utf-8",
        )
        check_policy.qualify_doctest_policy()
        self.assertTrue(any(err.startswith("DEP-AUD-028") and "scripts/qualify.sh:3" in err for err in check_policy.errors), check_policy.errors)

    def test_qualify_doctest_policy_missing_script_fails(self) -> None:
        check_policy.qualify_doctest_policy()
        self.assertTrue(any(err.startswith("DEP-AUD-028") for err in check_policy.errors), check_policy.errors)

    def test_live_qualify_doctest_policy_passes(self) -> None:
        check_policy.ROOT = ROOT
        check_policy.qualify_doctest_policy()
        self.assertEqual(check_policy.errors, [])


SEALED_QUALIFY_SH = (
    "#!/usr/bin/env bash\nexport CARGO_NET_OFFLINE=true\nexport RUSTUP_AUTO_INSTALL=0\n"
    'run check rustup run "$tc" cargo check --locked --offline --workspace\n'
)


class CheckPolicyRustupAndReleaseSealTests(CheckPolicyFixtureCase):
    """fss-x4a.26.3 follow-up: check-policy's DEP-AUD-027 mirror requires the top-level
    `export RUSTUP_AUTO_INSTALL=0` and polices scripts/release_qualify.sh as well as qualify.sh."""

    def write(self, name: str, text: str) -> None:
        script = self.root / "scripts" / name
        script.parent.mkdir(parents=True, exist_ok=True)
        script.write_text(text, encoding="utf-8")

    def test_qualify_offline_policy_requires_rustup_export(self) -> None:
        self.write("qualify.sh", SEALED_QUALIFY_SH.replace("export RUSTUP_AUTO_INSTALL=0\n", ""))
        self.write("release_qualify.sh", SEALED_QUALIFY_SH)
        check_policy.qualify_offline_policy()
        self.assertTrue(any(err.startswith("DEP-AUD-027") and "RUSTUP_AUTO_INSTALL" in err and "scripts/qualify.sh" in err for err in check_policy.errors), check_policy.errors)

    def test_qualify_offline_policy_polices_release_script(self) -> None:
        self.write("qualify.sh", SEALED_QUALIFY_SH)
        self.write("release_qualify.sh", SEALED_QUALIFY_SH.replace("--locked --offline --workspace", "--locked --workspace"))
        check_policy.qualify_offline_policy()
        self.assertTrue(any(err.startswith("DEP-AUD-027") and "scripts/release_qualify.sh:4" in err for err in check_policy.errors), check_policy.errors)

    def test_qualify_offline_policy_missing_release_script_fails(self) -> None:
        self.write("qualify.sh", SEALED_QUALIFY_SH)
        check_policy.qualify_offline_policy()
        self.assertTrue(any(err.startswith("DEP-AUD-027") and "release_qualify.sh" in err for err in check_policy.errors), check_policy.errors)

    def test_positive_control_both_sealed_scripts_pass(self) -> None:
        self.write("qualify.sh", SEALED_QUALIFY_SH)
        self.write("release_qualify.sh", SEALED_QUALIFY_SH)
        check_policy.qualify_offline_policy()
        self.assertEqual(check_policy.errors, [])


class CheckPolicyRustupInstallAndQuotingTests(CheckPolicyFixtureCase):
    """fss-x4a.26.3 follow-up: check-policy's DEP-AUD-027 mirror rejects network-fetching rustup
    commands with file:line and ignores quoted `cargo ...` text in messages."""

    def write(self, name: str, text: str) -> None:
        script = self.root / "scripts" / name
        script.parent.mkdir(parents=True, exist_ok=True)
        script.write_text(text, encoding="utf-8")

    def test_rustup_install_forms_fail_with_line(self) -> None:
        for extra in ('rustup run --install "$tc" cargo build --offline\n', 'rustup toolchain install "$tc"\n', 'rustup install "$tc"\n', "rustup update\n"):
            with self.subTest(extra=extra):
                check_policy.errors = []
                self.write("qualify.sh", SEALED_QUALIFY_SH)
                self.write("release_qualify.sh", SEALED_QUALIFY_SH + extra)
                check_policy.qualify_offline_policy()
                self.assertEqual(len(check_policy.errors), 1, check_policy.errors)
                self.assertTrue(check_policy.errors[0].startswith("DEP-AUD-027"), check_policy.errors)
                self.assertIn("scripts/release_qualify.sh:5:", check_policy.errors[0])

    def test_quoted_cargo_text_passes_but_unquoted_cargo_after_it_fails(self) -> None:
        self.write("qualify.sh", SEALED_QUALIFY_SH + "printf 'cargo metadata receipt missing: %s\\n' \"$f\" >&2 # cargo build\n")
        self.write("release_qualify.sh", SEALED_QUALIFY_SH)
        check_policy.qualify_offline_policy()
        self.assertEqual(check_policy.errors, [])
        self.write("release_qualify.sh", SEALED_QUALIFY_SH + "printf 'cargo ok\\n'; bash -c \"cargo build --locked\"\n")
        check_policy.qualify_offline_policy()
        self.assertTrue(any(err.startswith("DEP-AUD-027") and "scripts/release_qualify.sh:5:" in err for err in check_policy.errors), check_policy.errors)


if __name__ == "__main__":
    unittest.main()
