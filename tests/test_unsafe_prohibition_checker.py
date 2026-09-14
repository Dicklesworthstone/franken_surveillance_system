#!/usr/bin/env python3
"""Planted-negative and positive test suite for unsafe prohibition checker (fss-x4a.26.2 / FSS-182).

Enforces the absolute safe-Rust prohibition from AGENTS.md:
"#!forbid(unsafe_code) in every FSS workspace crate, target, example, test,
 and build helper; there is no local exception path."

Test coverage:
1. Positive controls: Real repository passes with 0 errors; minimal temp crates
   with all target types (lib, bin, test, example, bench, build script) pass.
2. Target root forbid: Every target root missing `#![forbid(unsafe_code)]`
   (lib, bin, test, example, bench, build script, or commented-out/outer attribute)
   fails with ERR-UNSAFE-TARGET-ROOT-MISSING-FORBID-001.
3. Attribute prohibition: `#![allow(unsafe_code)]`, `#[allow(unsafe_code)]`,
   `#[warn(unsafe_code)]`, `#[expect(unsafe_code)]`, or multi-lint lists fail with
   ERR-UNSAFE-ATTRIBUTE-PERMITTED-001.
4. Construct prohibition: `unsafe` blocks, `unsafe move`, `unsafe async`,
   `unsafe fn`, `pub unsafe fn`, `unsafe impl`, `unsafe trait`, or `unsafe extern`
   fail with ERR-UNSAFE-CONSTRUCT-DETECTED-001.
   Comments and string literals mentioning 'unsafe' pass without error.
5. Manifest lint enforcement: Missing `[lints]`, explicit allow/warn, or
   workspace inherit without workspace forbid fail with
   ERR-UNSAFE-MANIFEST-LINT-NOT-FORBIDDEN-001.
6. Metadata validity: Corrupt/missing Cargo.toml or unreadable metadata
   fails with ERR-UNSAFE-METADATA-UNREADABLE-001.
"""

from __future__ import annotations

import json
import os
import subprocess
import sys
import tempfile
import tomllib
import unittest
import unittest.mock
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))

from unsafe_prohibition_checker import (
    ERR_MANIFEST_LINT_NOT_FORBIDDEN,
    ERR_METADATA_UNREADABLE,
    ERR_TARGET_ROOT_MISSING_FORBID,
    ERR_UNSAFE_ATTRIBUTE_PERMITTED,
    ERR_UNSAFE_CONSTRUCT_DETECTED,
    audit_unsafe_prohibition,
    check_manifest_lints,
    check_rust_source_file,
    strip_rust_comments_and_strings,
)


def create_minimal_valid_crate(tmp_dir: Path) -> Path:
    """Creates an isolated, valid workspace and crate in a temp directory."""
    manifest = tmp_dir / "Cargo.toml"
    manifest.write_text(
        """[package]
name = "fixture-valid"
version = "0.1.0"
edition = "2024"

[lints.rust]
unsafe_code = "forbid"
""",
        encoding="utf-8",
    )
    src_dir = tmp_dir / "src"
    src_dir.mkdir(parents=True, exist_ok=True)
    (src_dir / "lib.rs").write_text(
        "//! Valid safe crate\n#![forbid(unsafe_code)]\n\npub fn valid() -> u32 { 42 }\n",
        encoding="utf-8",
    )
    return manifest


class TestUnsafeProhibitionPositiveControls(unittest.TestCase):
    """Positive controls asserting valid crates and the real repository pass."""

    def test_real_repo_passes(self) -> None:
        """The real repository passes the unsafe prohibition audit with zero errors."""
        is_valid, findings, summary = audit_unsafe_prohibition(ROOT)
        self.assertTrue(
            is_valid,
            f"Real repository failed unsafe audit with {len(findings)} findings: {[f.message for f in findings]}",
        )
        self.assertEqual(summary["status"], "pass")
        self.assertEqual(summary["error_count"], 0)
        self.assertGreaterEqual(summary["target_count"], 50)

        # Derive expected crate count from workspace members / registered crate topology
        manifest_data = tomllib.loads((ROOT / "Cargo.toml").read_text(encoding="utf-8"))
        workspace_members = manifest_data.get("workspace", {}).get("members", [])
        expected_crate_count = len(workspace_members)

        topo_data = json.loads((ROOT / "architecture/crate_topology.json").read_text(encoding="utf-8"))
        registered_crates = {
            c["name"]: c
            for layer in topo_data.get("layers", [])
            for c in layer.get("crates", [])
        }
        for member in workspace_members:
            crate_name = Path(member).name
            self.assertIn(
                crate_name,
                registered_crates,
                f"Workspace member '{crate_name}' must be declared in crate_topology.json",
            )
            self.assertEqual(
                registered_crates[crate_name].get("unsafe"),
                "forbid",
                f"Crate '{crate_name}' in crate_topology.json must declare unsafe=forbid",
            )

        # Ensure crates on disk under crates/ match registered workspace members
        crates_dir = ROOT / "crates"
        disk_crates = {
            p.name for p in crates_dir.iterdir() if p.is_dir() and (p / "Cargo.toml").is_file()
        }
        self.assertEqual(
            len(disk_crates),
            expected_crate_count,
            f"Disk crates count {len(disk_crates)} does not match expected {expected_crate_count}",
        )

        self.assertGreaterEqual(expected_crate_count, 6)
        self.assertEqual(summary["crate_count"], expected_crate_count)
        self.assertEqual(summary["workspace_members_count"], expected_crate_count)
        self.assertGreaterEqual(summary["rust_file_count"], 150)

    def test_cli_real_repo_passes(self) -> None:
        """CLI invocation on the real repository exits with code 0."""
        cmd = [sys.executable, str(ROOT / "scripts/unsafe_prohibition_checker.py")]
        result = subprocess.run(cmd, capture_output=True, text=True, cwd=str(ROOT))
        self.assertEqual(result.returncode, 0, f"CLI failed:\n{result.stderr}\n{result.stdout}")
        self.assertIn("[PASS]", result.stdout)

    def test_cli_json_mode(self) -> None:
        """CLI --json emits valid JSON matching summary structure."""
        cmd = [sys.executable, str(ROOT / "scripts/unsafe_prohibition_checker.py"), "--json"]
        result = subprocess.run(cmd, capture_output=True, text=True, cwd=str(ROOT))
        self.assertEqual(result.returncode, 0)
        report = json.loads(result.stdout)
        self.assertIn("summary", report)
        self.assertIn("findings", report)
        self.assertEqual(report["summary"]["status"], "pass")
        self.assertEqual(report["summary"]["error_count"], 0)

    def test_cli_quiet_mode(self) -> None:
        """CLI --quiet suppresses non-error stdout on passing repo."""
        cmd = [sys.executable, str(ROOT / "scripts/unsafe_prohibition_checker.py"), "--quiet"]
        result = subprocess.run(cmd, capture_output=True, text=True, cwd=str(ROOT))
        self.assertEqual(result.returncode, 0)
        self.assertEqual(result.stdout.strip(), "")

    def test_valid_minimal_temp_crate_passes(self) -> None:
        """A minimal valid crate in a temp directory passes completely."""
        with tempfile.TemporaryDirectory() as td:
            tmp_root = Path(td)
            manifest = create_minimal_valid_crate(tmp_root)
            is_valid, findings, summary = audit_unsafe_prohibition(
                root=tmp_root, manifest_path=manifest
            )
            self.assertTrue(
                is_valid, f"Expected pass, got findings: {[f.message for f in findings]}"
            )
            self.assertEqual(len(findings), 0)
            self.assertEqual(summary["status"], "pass")
            self.assertEqual(summary["target_count"], 1)

    def test_valid_crate_with_all_target_types_passes(self) -> None:
        """A crate with lib, bin, test, example, bench, and build script all passing."""
        with tempfile.TemporaryDirectory() as td:
            tmp_root = Path(td)
            manifest = create_minimal_valid_crate(tmp_root)

            # Add main.rs (bin)
            (tmp_root / "src" / "main.rs").write_text(
                "#![forbid(unsafe_code)]\nfn main() {}\n", encoding="utf-8"
            )
            # Add build.rs (custom-build)
            (tmp_root / "build.rs").write_text(
                "#![forbid(unsafe_code)]\nfn main() {}\n", encoding="utf-8"
            )
            # Add tests/t1.rs (test)
            tests_dir = tmp_root / "tests"
            tests_dir.mkdir()
            (tests_dir / "t1.rs").write_text(
                "#![forbid(unsafe_code)]\n#[test]\nfn test_it() {}\n", encoding="utf-8"
            )
            # Add examples/ex1.rs (example)
            ex_dir = tmp_root / "examples"
            ex_dir.mkdir()
            (ex_dir / "ex1.rs").write_text(
                "#![forbid(unsafe_code)]\nfn main() {}\n", encoding="utf-8"
            )
            # Add benches/b1.rs (bench)
            benches_dir = tmp_root / "benches"
            benches_dir.mkdir()
            (benches_dir / "b1.rs").write_text(
                "#![forbid(unsafe_code)]\nfn main() {}\n", encoding="utf-8"
            )

            is_valid, findings, summary = audit_unsafe_prohibition(
                root=tmp_root, manifest_path=manifest
            )
            self.assertTrue(
                is_valid, f"Expected pass, got findings: {[f.message for f in findings]}"
            )
            self.assertEqual(len(findings), 0)
            self.assertEqual(summary["target_count"], 6)

    def test_comments_and_strings_with_unsafe_word_pass(self) -> None:
        """English comments and string literals mentioning the prohibited word do not trigger false positives."""
        with tempfile.TemporaryDirectory() as td:
            tmp_root = Path(td)
            manifest = create_minimal_valid_crate(tmp_root)
            (tmp_root / "src" / "lib.rs").write_text(
                """#![forbid(unsafe_code)]
// This comment discusses forbidden blocks and forbidden fn behavior.
/* A block comment with forbidden { nested /* comment with forbidden impl */ } */
pub fn safe_function() -> &'static str {
    let msg = "forbidden { do_something(); }";
    let raw = r#"forbidden fn fake() {}"#;
    let _ = 'u';
    msg
}
""".replace("forbidden", "unsafe"),
                encoding="utf-8",
            )

            is_valid, findings, _ = audit_unsafe_prohibition(root=tmp_root, manifest_path=manifest)
            self.assertTrue(
                is_valid,
                f"Comments/strings should not trigger errors, got: {[f.message for f in findings]}",
            )
            self.assertEqual(len(findings), 0)

    def test_lifetime_in_generics_does_not_mangle_code(self) -> None:
        """Multiple lifetimes in generic parameter lists <'a, 'b> are preserved without mangling."""
        src = "#![forbid(unsafe_code)]\npub fn foo<'a, 'b>(x: &'a str, y: &'b str) -> &'a str { x }\n"
        stripped = strip_rust_comments_and_strings(src)
        self.assertIn("<'a, 'b>", stripped, "Lifetimes in generics must not be treated as char literals")



class TestPlantedNegativeTargetRootsMissingForbid(unittest.TestCase):
    """Planted-negative tests for ERR-UNSAFE-TARGET-ROOT-MISSING-FORBID-001."""

    def test_planted_lib_root_missing_forbid_fails(self) -> None:
        """lib root missing #![forbid(unsafe_code)] fails with ERR_TARGET_ROOT_MISSING_FORBID."""
        with tempfile.TemporaryDirectory() as td:
            tmp_root = Path(td)
            manifest = create_minimal_valid_crate(tmp_root)
            (tmp_root / "src" / "lib.rs").write_text("pub fn missing_forbid() {}\n", encoding="utf-8")

            is_valid, findings, _ = audit_unsafe_prohibition(root=tmp_root, manifest_path=manifest)
            self.assertFalse(is_valid)
            self.assertEqual({f.code for f in findings}, {ERR_TARGET_ROOT_MISSING_FORBID})
            self.assertTrue(any("lacks unconditional #![forbid(unsafe_code)]" in f.message for f in findings))

    def test_planted_bin_root_missing_forbid_fails(self) -> None:
        """bin root missing #![forbid(unsafe_code)] fails with ERR_TARGET_ROOT_MISSING_FORBID."""
        with tempfile.TemporaryDirectory() as td:
            tmp_root = Path(td)
            manifest = create_minimal_valid_crate(tmp_root)
            (tmp_root / "src" / "main.rs").write_text("fn main() {}\n", encoding="utf-8")

            is_valid, findings, _ = audit_unsafe_prohibition(root=tmp_root, manifest_path=manifest)
            self.assertFalse(is_valid)
            self.assertEqual({f.code for f in findings}, {ERR_TARGET_ROOT_MISSING_FORBID})

    def test_planted_test_root_missing_forbid_fails(self) -> None:
        """test target missing #![forbid(unsafe_code)] fails with ERR_TARGET_ROOT_MISSING_FORBID."""
        with tempfile.TemporaryDirectory() as td:
            tmp_root = Path(td)
            manifest = create_minimal_valid_crate(tmp_root)
            tests_dir = tmp_root / "tests"
            tests_dir.mkdir()
            (tests_dir / "contract.rs").write_text("#[test]\nfn t() {}\n", encoding="utf-8")

            is_valid, findings, _ = audit_unsafe_prohibition(root=tmp_root, manifest_path=manifest)
            self.assertFalse(is_valid)
            self.assertEqual({f.code for f in findings}, {ERR_TARGET_ROOT_MISSING_FORBID})

    def test_planted_example_root_missing_forbid_fails(self) -> None:
        """example target missing #![forbid(unsafe_code)] fails with ERR_TARGET_ROOT_MISSING_FORBID."""
        with tempfile.TemporaryDirectory() as td:
            tmp_root = Path(td)
            manifest = create_minimal_valid_crate(tmp_root)
            ex_dir = tmp_root / "examples"
            ex_dir.mkdir()
            (ex_dir / "demo.rs").write_text("fn main() {}\n", encoding="utf-8")

            is_valid, findings, _ = audit_unsafe_prohibition(root=tmp_root, manifest_path=manifest)
            self.assertFalse(is_valid)
            self.assertEqual({f.code for f in findings}, {ERR_TARGET_ROOT_MISSING_FORBID})

    def test_planted_bench_root_missing_forbid_fails(self) -> None:
        """bench target missing #![forbid(unsafe_code)] fails with ERR_TARGET_ROOT_MISSING_FORBID."""
        with tempfile.TemporaryDirectory() as td:
            tmp_root = Path(td)
            manifest = create_minimal_valid_crate(tmp_root)
            benches_dir = tmp_root / "benches"
            benches_dir.mkdir()
            (benches_dir / "perf.rs").write_text("fn main() {}\n", encoding="utf-8")

            is_valid, findings, _ = audit_unsafe_prohibition(root=tmp_root, manifest_path=manifest)
            self.assertFalse(is_valid)
            self.assertEqual({f.code for f in findings}, {ERR_TARGET_ROOT_MISSING_FORBID})

    def test_planted_build_script_missing_forbid_fails(self) -> None:
        """build script (build.rs) missing #![forbid(unsafe_code)] fails with ERR_TARGET_ROOT_MISSING_FORBID."""
        with tempfile.TemporaryDirectory() as td:
            tmp_root = Path(td)
            manifest = create_minimal_valid_crate(tmp_root)
            (tmp_root / "build.rs").write_text("fn main() {}\n", encoding="utf-8")

            is_valid, findings, _ = audit_unsafe_prohibition(root=tmp_root, manifest_path=manifest)
            self.assertFalse(is_valid)
            self.assertEqual({f.code for f in findings}, {ERR_TARGET_ROOT_MISSING_FORBID})

    def test_planted_commented_out_forbid_fails(self) -> None:
        """Target with // #![forbid(unsafe_code)] inside a comment fails with ERR_TARGET_ROOT_MISSING_FORBID."""
        with tempfile.TemporaryDirectory() as td:
            tmp_root = Path(td)
            manifest = create_minimal_valid_crate(tmp_root)
            (tmp_root / "src" / "lib.rs").write_text(
                "// #![forbid(unsafe_code)]\npub fn ok() {}\n", encoding="utf-8"
            )

            is_valid, findings, _ = audit_unsafe_prohibition(root=tmp_root, manifest_path=manifest)
            self.assertFalse(is_valid)
            self.assertEqual({f.code for f in findings}, {ERR_TARGET_ROOT_MISSING_FORBID})

    def test_planted_outer_attribute_forbid_fails(self) -> None:
        """Target with outer #[forbid(unsafe_code)] instead of inner #! fails with ERR_TARGET_ROOT_MISSING_FORBID."""
        with tempfile.TemporaryDirectory() as td:
            tmp_root = Path(td)
            manifest = create_minimal_valid_crate(tmp_root)
            (tmp_root / "src" / "lib.rs").write_text(
                "#[forbid(unsafe_code)]\npub fn ok() {}\n", encoding="utf-8"
            )

            is_valid, findings, _ = audit_unsafe_prohibition(root=tmp_root, manifest_path=manifest)
            self.assertFalse(is_valid)
            self.assertEqual({f.code for f in findings}, {ERR_TARGET_ROOT_MISSING_FORBID})

    def test_autoexamples_false_does_not_check_omitted_example_for_forbid(self) -> None:
        """Example file missing forbid is not checked when autoexamples = false."""
        with tempfile.TemporaryDirectory() as td:
            tmp_root = Path(td)
            manifest = tmp_root / "Cargo.toml"
            manifest.write_text(
                """[package]
name = "fixture-autoexample"
version = "0.1.0"
edition = "2024"
autoexamples = false

[lints.rust]
unsafe_code = "forbid"
""",
                encoding="utf-8",
            )
            src_dir = tmp_root / "src"
            src_dir.mkdir()
            (src_dir / "lib.rs").write_text("#![forbid(unsafe_code)]\n", encoding="utf-8")
            ex_dir = tmp_root / "examples"
            ex_dir.mkdir()
            (ex_dir / "ex1.rs").write_text("fn main() {}\n", encoding="utf-8")

            is_valid, findings, _ = audit_unsafe_prohibition(root=tmp_root, manifest_path=manifest)
            self.assertTrue(is_valid, f"Expected valid when autoexamples=false, got findings: {findings}")
            self.assertEqual(findings, [])

    def test_autotests_false_does_not_check_omitted_test_for_forbid(self) -> None:
        """Test file missing forbid is not checked when autotests = false."""
        with tempfile.TemporaryDirectory() as td:
            tmp_root = Path(td)
            manifest = tmp_root / "Cargo.toml"
            manifest.write_text(
                """[package]
name = "fixture-autotest"
version = "0.1.0"
edition = "2024"
autotests = false

[lints.rust]
unsafe_code = "forbid"
""",
                encoding="utf-8",
            )
            src_dir = tmp_root / "src"
            src_dir.mkdir()
            (src_dir / "lib.rs").write_text("#![forbid(unsafe_code)]\n", encoding="utf-8")
            t_dir = tmp_root / "tests"
            t_dir.mkdir()
            (t_dir / "t1.rs").write_text("fn test() {}\n", encoding="utf-8")

            is_valid, findings, _ = audit_unsafe_prohibition(root=tmp_root, manifest_path=manifest)
            self.assertTrue(is_valid, f"Expected valid when autotests=false, got findings: {findings}")
            self.assertEqual(findings, [])

    def test_build_helper_missing_forbid_fails(self) -> None:
        """Build helper file under build/ missing forbid is detected and rejected."""
        with tempfile.TemporaryDirectory() as td:
            tmp_root = Path(td)
            manifest = create_minimal_valid_crate(tmp_root)
            (tmp_root / "build.rs").write_text("#![forbid(unsafe_code)]\nfn main() {}\n", encoding="utf-8")
            build_dir = tmp_root / "build"
            build_dir.mkdir()
            (build_dir / "helper.rs").write_text("pub fn helper() {}\n", encoding="utf-8")

            is_valid, findings, _ = audit_unsafe_prohibition(root=tmp_root, manifest_path=manifest)
            self.assertFalse(is_valid)
            self.assertEqual({f.code for f in findings}, {ERR_TARGET_ROOT_MISSING_FORBID})

    def test_planted_unregistered_crate_missing_forbid_fails(self) -> None:
        """An unregistered crate on disk missing #![forbid(unsafe_code)] fails fail-closed."""
        with tempfile.TemporaryDirectory() as td:
            tmp_root = Path(td)
            root_manifest = tmp_root / "Cargo.toml"
            root_manifest.write_text(
                """[workspace]
resolver = "3"
members = ["crates/valid"]

[workspace.lints.rust]
unsafe_code = "forbid"
""",
                encoding="utf-8",
            )
            valid_dir = tmp_root / "crates" / "valid"
            (valid_dir / "src").mkdir(parents=True)
            (valid_dir / "Cargo.toml").write_text(
                """[package]
name = "valid"
version = "0.1.0"
edition = "2024"

[lints]
workspace = true
""",
                encoding="utf-8",
            )
            (valid_dir / "src" / "lib.rs").write_text(
                "#![forbid(unsafe_code)]\npub fn valid() {}\n", encoding="utf-8"
            )

            # Plant an unregistered crate without #![forbid(unsafe_code)]
            unreg_dir = tmp_root / "crates" / "unregistered"
            (unreg_dir / "src").mkdir(parents=True)
            (unreg_dir / "Cargo.toml").write_text(
                """[package]
name = "unregistered"
version = "0.1.0"
edition = "2024"
""",
                encoding="utf-8",
            )
            (unreg_dir / "src" / "lib.rs").write_text(
                "pub fn missing_forbid() {}\n", encoding="utf-8"
            )

            is_valid, findings, _ = audit_unsafe_prohibition(root=tmp_root, manifest_path=root_manifest)
            self.assertFalse(is_valid, "Unregistered crate missing forbid must fail audit")
            self.assertEqual(
                {f.code for f in findings},
                {ERR_MANIFEST_LINT_NOT_FORBIDDEN, ERR_TARGET_ROOT_MISSING_FORBID},
            )
            self.assertEqual(len(findings), 3)
            manifest_findings = [f for f in findings if f.code == ERR_MANIFEST_LINT_NOT_FORBIDDEN]
            self.assertEqual(len(manifest_findings), 2)
            target_findings = [f for f in findings if f.code == ERR_TARGET_ROOT_MISSING_FORBID]
            self.assertEqual(len(target_findings), 1)
            self.assertEqual(target_findings[0].file, "crates/unregistered/src/lib.rs")



class TestPlantedNegativeUnsafePermittingAttributes(unittest.TestCase):
    """Planted-negative tests for ERR-UNSAFE-ATTRIBUTE-PERMITTED-001."""

    def test_planted_inner_allow_unsafe_code_fails(self) -> None:
        """#![allow(unsafe_code)] anywhere fails with ERR_UNSAFE_ATTRIBUTE_PERMITTED."""
        with tempfile.TemporaryDirectory() as td:
            tmp_root = Path(td)
            manifest = create_minimal_valid_crate(tmp_root)
            (tmp_root / "src" / "sub.rs").write_text(
                "//! Submodule\n#![allow(unsafe_code)]\n", encoding="utf-8"
            )

            is_valid, findings, _ = audit_unsafe_prohibition(root=tmp_root, manifest_path=manifest)
            self.assertFalse(is_valid)
            self.assertEqual({f.code for f in findings}, {ERR_UNSAFE_ATTRIBUTE_PERMITTED})

    def test_planted_outer_allow_unsafe_code_fails(self) -> None:
        """#[allow(unsafe_code)] on a fn or block fails with ERR_UNSAFE_ATTRIBUTE_PERMITTED."""
        with tempfile.TemporaryDirectory() as td:
            tmp_root = Path(td)
            manifest = create_minimal_valid_crate(tmp_root)
            (tmp_root / "src" / "lib.rs").write_text(
                "![forbid(unsafe_code)]\n#[allow(unsafe_code)]\npub fn bypass() {}\n".replace("![", "#!["),
                encoding="utf-8",
            )

            is_valid, findings, _ = audit_unsafe_prohibition(root=tmp_root, manifest_path=manifest)
            self.assertFalse(is_valid)
            self.assertEqual({f.code for f in findings}, {ERR_UNSAFE_ATTRIBUTE_PERMITTED})

    def test_planted_warn_unsafe_code_fails(self) -> None:
        """#[warn(unsafe_code)] fails with ERR_UNSAFE_ATTRIBUTE_PERMITTED."""
        with tempfile.TemporaryDirectory() as td:
            tmp_root = Path(td)
            manifest = create_minimal_valid_crate(tmp_root)
            (tmp_root / "src" / "lib.rs").write_text(
                "![forbid(unsafe_code)]\n#[warn(unsafe_code)]\npub fn f() {}\n".replace("![", "#!["),
                encoding="utf-8",
            )

            is_valid, findings, _ = audit_unsafe_prohibition(root=tmp_root, manifest_path=manifest)
            self.assertFalse(is_valid)
            self.assertEqual({f.code for f in findings}, {ERR_UNSAFE_ATTRIBUTE_PERMITTED})

    def test_planted_expect_unsafe_code_fails(self) -> None:
        """#![expect(unsafe_code)] fails with ERR_UNSAFE_ATTRIBUTE_PERMITTED."""
        with tempfile.TemporaryDirectory() as td:
            tmp_root = Path(td)
            manifest = create_minimal_valid_crate(tmp_root)
            (tmp_root / "src" / "lib.rs").write_text(
                "![forbid(unsafe_code)]\n#![expect(unsafe_code)]\n".replace("![", "#!["),
                encoding="utf-8",
            )

            is_valid, findings, _ = audit_unsafe_prohibition(root=tmp_root, manifest_path=manifest)
            self.assertFalse(is_valid)
            self.assertEqual({f.code for f in findings}, {ERR_UNSAFE_ATTRIBUTE_PERMITTED})

    def test_planted_multi_lint_allow_unsafe_code_fails(self) -> None:
        """#[allow(unused, unsafe_code, dead_code)] fails with ERR_UNSAFE_ATTRIBUTE_PERMITTED."""
        with tempfile.TemporaryDirectory() as td:
            tmp_root = Path(td)
            manifest = create_minimal_valid_crate(tmp_root)
            (tmp_root / "src" / "lib.rs").write_text(
                "![forbid(unsafe_code)]\n#[allow(unused, unsafe_code, dead_code)]\npub fn f() {}\n".replace("![", "#!["),
                encoding="utf-8",
            )

            is_valid, findings, _ = audit_unsafe_prohibition(root=tmp_root, manifest_path=manifest)
            self.assertFalse(is_valid)
            self.assertEqual({f.code for f in findings}, {ERR_UNSAFE_ATTRIBUTE_PERMITTED})

    def test_planted_cfg_attr_allow_unsafe_code_fails(self) -> None:
        """#[cfg_attr(..., allow(unsafe_code))] must be detected and rejected."""
        with tempfile.TemporaryDirectory() as td:
            tmp_root = Path(td)
            manifest = create_minimal_valid_crate(tmp_root)
            (tmp_root / "src" / "lib.rs").write_text(
                "![forbid(unsafe_code)]\n#[cfg_attr(test, allow(unsafe_code))]\npub fn bypass() {}\n".replace("![", "#!["),
                encoding="utf-8",
            )
            is_valid, findings, _ = audit_unsafe_prohibition(root=tmp_root, manifest_path=manifest)
            self.assertFalse(is_valid, "cfg_attr allowing unsafe_code was not detected")
            self.assertEqual({f.code for f in findings}, {ERR_UNSAFE_ATTRIBUTE_PERMITTED})

    def test_planted_cfg_attr_inner_allow_unsafe_code_fails(self) -> None:
        """#![cfg_attr(..., allow(unsafe_code))] inner attribute must be detected and rejected."""
        with tempfile.TemporaryDirectory() as td:
            tmp_root = Path(td)
            manifest = create_minimal_valid_crate(tmp_root)
            (tmp_root / "src" / "lib.rs").write_text(
                "![forbid(unsafe_code)]\n![cfg_attr(all(), allow(unsafe_code))]\npub fn bypass() {}\n".replace("![", "#!["),
                encoding="utf-8",
            )
            is_valid, findings, _ = audit_unsafe_prohibition(root=tmp_root, manifest_path=manifest)
            self.assertFalse(is_valid, "inner cfg_attr allowing unsafe_code was not detected")
            self.assertEqual({f.code for f in findings}, {ERR_UNSAFE_ATTRIBUTE_PERMITTED})

    def test_planted_multiline_allow_unsafe_code_fails(self) -> None:
        """Multiline #[allow(...)] must be detected and rejected."""
        with tempfile.TemporaryDirectory() as td:
            tmp_root = Path(td)
            manifest = create_minimal_valid_crate(tmp_root)
            (tmp_root / "src" / "lib.rs").write_text(
                "![forbid(unsafe_code)]\n#[allow(\n    unsafe_code\n)]\npub fn bypass() {}\n".replace("![", "#!["),
                encoding="utf-8",
            )
            is_valid, findings, _ = audit_unsafe_prohibition(root=tmp_root, manifest_path=manifest)
            self.assertFalse(is_valid, "Multiline allow(unsafe_code) was not detected")
            self.assertEqual({f.code for f in findings}, {ERR_UNSAFE_ATTRIBUTE_PERMITTED})

    def test_planted_multiline_cfg_attr_fails(self) -> None:
        """Multiline #[cfg_attr(..., allow(...))] must be detected and rejected."""
        with tempfile.TemporaryDirectory() as td:
            tmp_root = Path(td)
            manifest = create_minimal_valid_crate(tmp_root)
            (tmp_root / "src" / "lib.rs").write_text(
                "![forbid(unsafe_code)]\n#[cfg_attr(\n    test,\n    allow(\n        unsafe_code\n    )\n)]\npub fn bypass() {}\n".replace("![", "#!["),
                encoding="utf-8",
            )
            is_valid, findings, _ = audit_unsafe_prohibition(root=tmp_root, manifest_path=manifest)
            self.assertFalse(is_valid, "Multiline cfg_attr allowing unsafe_code was not detected")
            self.assertEqual({f.code for f in findings}, {ERR_UNSAFE_ATTRIBUTE_PERMITTED})



class TestPlantedNegativeUnsafeConstructs(unittest.TestCase):
    """Planted-negative tests for ERR-UNSAFE-CONSTRUCT-DETECTED-001."""

    def test_planted_unsafe_block_fails(self) -> None:
        """unsafe { ... } block fails with ERR_UNSAFE_CONSTRUCT_DETECTED."""
        with tempfile.TemporaryDirectory() as td:
            tmp_root = Path(td)
            manifest = create_minimal_valid_crate(tmp_root)
            (tmp_root / "src" / "lib.rs").write_text(
                "![forbid(unsafe_code)]\npub fn bad() { unsafe { let _ = 1; } }\n".replace("![", "#!["),
                encoding="utf-8",
            )

            is_valid, findings, _ = audit_unsafe_prohibition(root=tmp_root, manifest_path=manifest)
            self.assertFalse(is_valid)
            self.assertEqual({f.code for f in findings}, {ERR_UNSAFE_CONSTRUCT_DETECTED})
            self.assertTrue(any("unsafe block" in f.message for f in findings))

    def test_planted_unsafe_fn_fails(self) -> None:
        """unsafe fn fails with ERR_UNSAFE_CONSTRUCT_DETECTED."""
        with tempfile.TemporaryDirectory() as td:
            tmp_root = Path(td)
            manifest = create_minimal_valid_crate(tmp_root)
            (tmp_root / "src" / "lib.rs").write_text(
                "![forbid(unsafe_code)]\npub unsafe fn dangerous() {}\n".replace("![", "#!["),
                encoding="utf-8",
            )

            is_valid, findings, _ = audit_unsafe_prohibition(root=tmp_root, manifest_path=manifest)
            self.assertFalse(is_valid)
            self.assertEqual({f.code for f in findings}, {ERR_UNSAFE_CONSTRUCT_DETECTED})
            self.assertTrue(any("unsafe function" in f.message for f in findings))

    def test_planted_unsafe_impl_fails(self) -> None:
        """unsafe impl fails with ERR_UNSAFE_CONSTRUCT_DETECTED."""
        with tempfile.TemporaryDirectory() as td:
            tmp_root = Path(td)
            manifest = create_minimal_valid_crate(tmp_root)
            (tmp_root / "src" / "lib.rs").write_text(
                "![forbid(unsafe_code)]\npub struct S;\nunsafe impl Send for S {}\n".replace("![", "#!["),
                encoding="utf-8",
            )

            is_valid, findings, _ = audit_unsafe_prohibition(root=tmp_root, manifest_path=manifest)
            self.assertFalse(is_valid)
            self.assertEqual({f.code for f in findings}, {ERR_UNSAFE_CONSTRUCT_DETECTED})
            self.assertTrue(any("unsafe impl" in f.message for f in findings))

    def test_planted_unsafe_trait_fails(self) -> None:
        """unsafe trait fails with ERR_UNSAFE_CONSTRUCT_DETECTED."""
        with tempfile.TemporaryDirectory() as td:
            tmp_root = Path(td)
            manifest = create_minimal_valid_crate(tmp_root)
            (tmp_root / "src" / "lib.rs").write_text(
                "![forbid(unsafe_code)]\npub unsafe trait DangerousTrait {}\n".replace("![", "#!["),
                encoding="utf-8",
            )

            is_valid, findings, _ = audit_unsafe_prohibition(root=tmp_root, manifest_path=manifest)
            self.assertFalse(is_valid)
            self.assertEqual({f.code for f in findings}, {ERR_UNSAFE_CONSTRUCT_DETECTED})
            self.assertTrue(any("unsafe trait" in f.message for f in findings))

    def test_planted_unsafe_extern_block_fails(self) -> None:
        """unsafe extern \"C\" { ... } fails with ERR_UNSAFE_CONSTRUCT_DETECTED."""
        with tempfile.TemporaryDirectory() as td:
            tmp_root = Path(td)
            manifest = create_minimal_valid_crate(tmp_root)
            (tmp_root / "src" / "lib.rs").write_text(
                "![forbid(unsafe_code)]\nunsafe extern \"C\" { fn c_fn(); }\n".replace("![", "#!["),
                encoding="utf-8",
            )

            is_valid, findings, _ = audit_unsafe_prohibition(root=tmp_root, manifest_path=manifest)
            self.assertFalse(is_valid)
            self.assertEqual({f.code for f in findings}, {ERR_UNSAFE_CONSTRUCT_DETECTED})

    def test_string_continuation_preserves_line_number(self) -> None:
        """String continuation \\ must not alter line count in stripped source."""
        src = 'let s = "hello \\\nworld";\n// line 3\nunsafe { bar(); }\n'
        with tempfile.NamedTemporaryFile(suffix=".rs", mode="w", delete=False) as f:
            f.write(src)
            f.flush()
            findings = check_rust_source_file(Path(f.name), Path(f.name).parent)
            self.assertEqual(len(findings), 1)
            self.assertEqual(findings[0].location, "line:4:col:1")

    def test_root_level_rust_file_scanned_when_packages_exist(self) -> None:
        """Rust files at root/scripts must be discovered even when workspace packages exist."""
        with tempfile.TemporaryDirectory() as td:
            tmp_root = Path(td)
            manifest = create_minimal_valid_crate(tmp_root)
            script_dir = tmp_root / "scripts"
            script_dir.mkdir()
            (script_dir / "helper.rs").write_text("unsafe fn evil() {}\n", encoding="utf-8")
            is_valid, findings, _ = audit_unsafe_prohibition(root=tmp_root, manifest_path=manifest)
            self.assertFalse(is_valid)
            self.assertEqual({f.code for f in findings}, {ERR_UNSAFE_CONSTRUCT_DETECTED})



class TestPlantedNegativeManifestLints(unittest.TestCase):
    """Planted-negative tests for ERR-UNSAFE-MANIFEST-LINT-NOT-FORBIDDEN-001."""

    def test_planted_crate_missing_lints_section_fails(self) -> None:
        """Crate without [lints] table fails with ERR_MANIFEST_LINT_NOT_FORBIDDEN."""
        with tempfile.TemporaryDirectory() as td:
            tmp_root = Path(td)
            manifest = tmp_root / "Cargo.toml"
            manifest.write_text(
                """[package]
name = "fixture-missing-lints"
version = "0.1.0"
edition = "2024"
""",
                encoding="utf-8",
            )
            src_dir = tmp_root / "src"
            src_dir.mkdir()
            (src_dir / "lib.rs").write_text("#![forbid(unsafe_code)]\n", encoding="utf-8")

            is_valid, findings, _ = audit_unsafe_prohibition(root=tmp_root, manifest_path=manifest)
            self.assertFalse(is_valid)
            self.assertEqual({f.code for f in findings}, {ERR_MANIFEST_LINT_NOT_FORBIDDEN})

    def test_planted_crate_explicit_allow_unsafe_code_fails(self) -> None:
        """Crate declaring [lints.rust] unsafe_code = 'allow' fails with ERR_MANIFEST_LINT_NOT_FORBIDDEN."""
        with tempfile.TemporaryDirectory() as td:
            tmp_root = Path(td)
            manifest = tmp_root / "Cargo.toml"
            manifest.write_text(
                """[package]
name = "fixture-allow-lints"
version = "0.1.0"
edition = "2024"

[lints.rust]
unsafe_code = "allow"
""",
                encoding="utf-8",
            )
            src_dir = tmp_root / "src"
            src_dir.mkdir()
            (src_dir / "lib.rs").write_text("#![forbid(unsafe_code)]\n", encoding="utf-8")

            is_valid, findings, _ = audit_unsafe_prohibition(root=tmp_root, manifest_path=manifest)
            self.assertFalse(is_valid)
            self.assertEqual({f.code for f in findings}, {ERR_MANIFEST_LINT_NOT_FORBIDDEN})

    def test_planted_crate_explicit_warn_unsafe_code_fails(self) -> None:
        """Crate declaring [lints.rust] unsafe_code = 'warn' fails with ERR_MANIFEST_LINT_NOT_FORBIDDEN."""
        with tempfile.TemporaryDirectory() as td:
            tmp_root = Path(td)
            manifest = tmp_root / "Cargo.toml"
            manifest.write_text(
                """[package]
name = "fixture-warn-lints"
version = "0.1.0"
edition = "2024"

[lints.rust]
unsafe_code = "warn"
""",
                encoding="utf-8",
            )
            src_dir = tmp_root / "src"
            src_dir.mkdir()
            (src_dir / "lib.rs").write_text("#![forbid(unsafe_code)]\n", encoding="utf-8")

            is_valid, findings, _ = audit_unsafe_prohibition(root=tmp_root, manifest_path=manifest)
            self.assertFalse(is_valid)
            self.assertEqual({f.code for f in findings}, {ERR_MANIFEST_LINT_NOT_FORBIDDEN})

    def test_planted_workspace_inherit_without_workspace_forbid_fails(self) -> None:
        """Crate with [lints] workspace=true when workspace doesn't forbid unsafe fails."""
        with tempfile.TemporaryDirectory() as td:
            tmp_root = Path(td)
            root_manifest = tmp_root / "Cargo.toml"
            root_manifest.write_text(
                """[workspace]
resolver = "3"
members = ["crates/sub"]

[workspace.lints.rust]
unsafe_code = "warn"
""",
                encoding="utf-8",
            )
            sub_dir = tmp_root / "crates" / "sub"
            sub_dir.mkdir(parents=True)
            (sub_dir / "Cargo.toml").write_text(
                """[package]
name = "sub-crate"
version = "0.1.0"
edition = "2024"

[lints]
workspace = true
""",
                encoding="utf-8",
            )
            (sub_dir / "src").mkdir()
            (sub_dir / "src" / "lib.rs").write_text("#![forbid(unsafe_code)]\n", encoding="utf-8")

            is_valid, findings, _ = audit_unsafe_prohibition(root=tmp_root, manifest_path=root_manifest)
            self.assertFalse(is_valid)
            self.assertEqual({f.code for f in findings}, {ERR_MANIFEST_LINT_NOT_FORBIDDEN})

    def test_planted_unregistered_crate_manifest_not_forbidden_fails(self) -> None:
        """An unregistered crate not declared in workspace.members fails manifest lint audit."""
        with tempfile.TemporaryDirectory() as td:
            tmp_root = Path(td)
            root_manifest = tmp_root / "Cargo.toml"
            root_manifest.write_text(
                """[workspace]
resolver = "3"
members = ["crates/valid"]

[workspace.lints.rust]
unsafe_code = "forbid"
""",
                encoding="utf-8",
            )
            valid_dir = tmp_root / "crates" / "valid"
            (valid_dir / "src").mkdir(parents=True)
            (valid_dir / "Cargo.toml").write_text(
                """[package]
name = "valid"
version = "0.1.0"
edition = "2024"

[lints]
workspace = true
""",
                encoding="utf-8",
            )
            (valid_dir / "src" / "lib.rs").write_text(
                "#![forbid(unsafe_code)]\npub fn valid() {}\n", encoding="utf-8"
            )

            # Plant an unregistered crate even if it declares explicit forbid
            unreg_dir = tmp_root / "crates" / "unregistered"
            (unreg_dir / "src").mkdir(parents=True)
            (unreg_dir / "Cargo.toml").write_text(
                """[package]
name = "unregistered"
version = "0.1.0"
edition = "2024"

[lints.rust]
unsafe_code = "forbid"
""",
                encoding="utf-8",
            )
            (unreg_dir / "src" / "lib.rs").write_text(
                "#![forbid(unsafe_code)]\npub fn ok() {}\n", encoding="utf-8"
            )

            is_valid, findings, _ = audit_unsafe_prohibition(root=tmp_root, manifest_path=root_manifest)
            self.assertFalse(is_valid, "Unregistered crate in workspace must fail audit")
            self.assertEqual({f.code for f in findings}, {ERR_MANIFEST_LINT_NOT_FORBIDDEN})
            self.assertEqual(len(findings), 1)
            self.assertEqual(findings[0].file, "crates/unregistered/Cargo.toml")
            self.assertEqual(findings[0].location, "manifest")
            self.assertEqual(findings[0].params.get("crate"), "unregistered")


class TestPlantedNegativeMetadataUnreadable(unittest.TestCase):
    """Planted-negative tests for ERR-UNSAFE-METADATA-UNREADABLE-001."""

    def test_planted_corrupt_cargo_toml_fails(self) -> None:
        """Corrupt syntax in Cargo.toml fails with ERR_METADATA_UNREADABLE."""
        with tempfile.TemporaryDirectory() as td:
            tmp_root = Path(td)
            manifest = tmp_root / "Cargo.toml"
            manifest.write_text("[package\nname = invalid_toml", encoding="utf-8")

            is_valid, findings, _ = audit_unsafe_prohibition(root=tmp_root, manifest_path=manifest)
            self.assertFalse(is_valid)
            self.assertEqual({f.code for f in findings}, {ERR_METADATA_UNREADABLE})

    def test_planted_missing_cargo_toml_fails(self) -> None:
        """Missing Cargo.toml fails with ERR_METADATA_UNREADABLE."""
        with tempfile.TemporaryDirectory() as td:
            tmp_root = Path(td)
            manifest = tmp_root / "nonexistent" / "Cargo.toml"

            is_valid, findings, _ = audit_unsafe_prohibition(root=tmp_root, manifest_path=manifest)
            self.assertFalse(is_valid)
            self.assertEqual({f.code for f in findings}, {ERR_METADATA_UNREADABLE})

    def test_empty_metadata_fails_closed(self) -> None:
        """Degenerate empty metadata dict must not pass verification."""
        with tempfile.TemporaryDirectory() as td:
            tmp_root = Path(td)
            is_valid, findings, summary = audit_unsafe_prohibition(
                root=tmp_root, raw_metadata={}
            )
            self.assertFalse(is_valid, "Empty metadata must fail closed")
            self.assertGreater(len(findings), 0)
            self.assertEqual({f.code for f in findings}, {ERR_METADATA_UNREADABLE})


    def test_cli_fails_on_corrupt_manifest_arg(self) -> None:
        """CLI invocation with --manifest-path pointing to corrupt file exits with code 1."""
        with tempfile.NamedTemporaryFile(suffix=".toml", mode="w", delete=False) as f:
            f.write("corrupt toml content [[")
            f_path = f.name
        try:
            cmd = [
                sys.executable,
                str(ROOT / "scripts/unsafe_prohibition_checker.py"),
                "--manifest-path",
                f_path,
            ]
            result = subprocess.run(cmd, capture_output=True, text=True, cwd=str(ROOT))
            self.assertEqual(result.returncode, 1)
            self.assertIn("[FAIL]", result.stdout)
            self.assertIn(ERR_METADATA_UNREADABLE, result.stdout)
        finally:
            Path(f_path).unlink(missing_ok=True)


class TestInvalidUtf8Handling(unittest.TestCase):
    """Verifies that invalid UTF-8 in Cargo.toml and Rust source files produces registered findings rather than crashing."""

    def test_invalid_utf8_stray_cargo_toml_emits_registered_finding(self) -> None:
        """A stray Cargo.toml with invalid UTF-8 bytes must not crash with UnicodeDecodeError and must emit registered findings."""
        with tempfile.TemporaryDirectory() as td:
            tmp_root = Path(td)
            root_manifest = tmp_root / "Cargo.toml"
            root_manifest.write_text(
                """[workspace]
resolver = "3"
members = ["crates/valid"]

[workspace.lints.rust]
unsafe_code = "forbid"
""",
                encoding="utf-8",
            )
            valid_dir = tmp_root / "crates" / "valid"
            (valid_dir / "src").mkdir(parents=True)
            (valid_dir / "Cargo.toml").write_text(
                """[package]
name = "valid"
version = "0.1.0"
edition = "2024"

[lints]
workspace = true
""",
                encoding="utf-8",
            )
            (valid_dir / "src" / "lib.rs").write_text(
                "#![forbid(unsafe_code)]\npub fn valid() {}\n", encoding="utf-8"
            )

            # Stray Cargo.toml with non-UTF-8 bytes
            stray_dir = tmp_root / "crates" / "stray"
            stray_dir.mkdir(parents=True)
            (stray_dir / "Cargo.toml").write_bytes(b"[package]\nname = \xff\xfe\ninvalid_utf8")

            is_valid, findings, _ = audit_unsafe_prohibition(root=tmp_root, manifest_path=root_manifest)
            self.assertFalse(is_valid, "Invalid UTF-8 Cargo.toml must fail audit")
            self.assertEqual(
                {f.code for f in findings},
                {ERR_MANIFEST_LINT_NOT_FORBIDDEN, ERR_TARGET_ROOT_MISSING_FORBID},
            )
            self.assertTrue(any("unparseable" in f.message for f in findings))

    def test_invalid_utf8_rust_source_file_emits_registered_finding(self) -> None:
        """A Rust source file with invalid UTF-8 bytes must not crash with UnicodeDecodeError and must emit registered findings."""
        with tempfile.TemporaryDirectory() as td:
            tmp_root = Path(td)
            manifest = create_minimal_valid_crate(tmp_root)
            # Write invalid UTF-8 to a secondary rust source file
            (tmp_root / "src" / "invalid.rs").write_bytes(b"// comment\n\xff\xfe\npub fn f() {}\n")

            is_valid, findings, _ = audit_unsafe_prohibition(root=tmp_root, manifest_path=manifest)
            self.assertFalse(is_valid, "Invalid UTF-8 .rs file must fail audit")
            self.assertEqual({f.code for f in findings}, {ERR_UNSAFE_CONSTRUCT_DETECTED})
            self.assertTrue(any("Could not read source file" in f.message for f in findings))


class TestExcludedAndFixtureCrates(unittest.TestCase):
    """Verifies that forbid-compliant excluded and fixture crates pass while non-compliant ones fail closed."""

    def test_forbid_compliant_excluded_crate_passes(self) -> None:
        """An explicitly excluded crate that forbids unsafe code must pass without being flagged as unregistered."""
        with tempfile.TemporaryDirectory() as td:
            tmp_root = Path(td)
            root_manifest = tmp_root / "Cargo.toml"
            root_manifest.write_text(
                """[workspace]
resolver = "3"
members = ["crates/valid"]
exclude = ["crates/excluded"]

[workspace.lints.rust]
unsafe_code = "forbid"
""",
                encoding="utf-8",
            )
            valid_dir = tmp_root / "crates" / "valid"
            (valid_dir / "src").mkdir(parents=True)
            (valid_dir / "Cargo.toml").write_text(
                """[package]
name = "valid"
version = "0.1.0"
edition = "2024"

[lints]
workspace = true
""",
                encoding="utf-8",
            )
            (valid_dir / "src" / "lib.rs").write_text(
                "#![forbid(unsafe_code)]\npub fn valid() {}\n", encoding="utf-8"
            )

            # Excluded crate with forbid
            ex_dir = tmp_root / "crates" / "excluded"
            (ex_dir / "src").mkdir(parents=True)
            (ex_dir / "Cargo.toml").write_text(
                """[package]
name = "excluded-helper"
version = "0.1.0"
edition = "2024"

[lints.rust]
unsafe_code = "forbid"
""",
                encoding="utf-8",
            )
            (ex_dir / "src" / "lib.rs").write_text(
                "#![forbid(unsafe_code)]\npub fn helper() {}\n", encoding="utf-8"
            )

            is_valid, findings, _ = audit_unsafe_prohibition(root=tmp_root, manifest_path=root_manifest)
            self.assertTrue(is_valid, f"Forbid-compliant excluded crate must pass: {[f.message for f in findings]}")
            self.assertEqual(len(findings), 0)

    def test_excluded_crate_missing_forbid_fails_closed(self) -> None:
        """An explicitly excluded crate missing forbid must fail closed."""
        with tempfile.TemporaryDirectory() as td:
            tmp_root = Path(td)
            root_manifest = tmp_root / "Cargo.toml"
            root_manifest.write_text(
                """[workspace]
resolver = "3"
members = ["crates/valid"]
exclude = ["crates/excluded"]

[workspace.lints.rust]
unsafe_code = "forbid"
""",
                encoding="utf-8",
            )
            valid_dir = tmp_root / "crates" / "valid"
            (valid_dir / "src").mkdir(parents=True)
            (valid_dir / "Cargo.toml").write_text(
                """[package]
name = "valid"
version = "0.1.0"
edition = "2024"

[lints]
workspace = true
""",
                encoding="utf-8",
            )
            (valid_dir / "src" / "lib.rs").write_text(
                "#![forbid(unsafe_code)]\npub fn valid() {}\n", encoding="utf-8"
            )

            # Excluded crate missing forbid
            ex_dir = tmp_root / "crates" / "excluded"
            (ex_dir / "src").mkdir(parents=True)
            (ex_dir / "Cargo.toml").write_text(
                """[package]
name = "excluded-helper"
version = "0.1.0"
edition = "2024"
""",
                encoding="utf-8",
            )
            (ex_dir / "src" / "lib.rs").write_text(
                "pub fn missing_forbid() {}\n", encoding="utf-8"
            )

            is_valid, findings, _ = audit_unsafe_prohibition(root=tmp_root, manifest_path=root_manifest)
            self.assertFalse(is_valid, "Excluded crate missing forbid must fail")
            self.assertEqual(
                {f.code for f in findings},
                {ERR_MANIFEST_LINT_NOT_FORBIDDEN, ERR_TARGET_ROOT_MISSING_FORBID},
            )

    def test_forbid_compliant_fixture_crate_passes(self) -> None:
        """A test fixture crate outside workspace members that forbids unsafe code must pass."""
        with tempfile.TemporaryDirectory() as td:
            tmp_root = Path(td)
            root_manifest = tmp_root / "Cargo.toml"
            root_manifest.write_text(
                """[workspace]
resolver = "3"
members = ["crates/valid"]

[workspace.lints.rust]
unsafe_code = "forbid"
""",
                encoding="utf-8",
            )
            valid_dir = tmp_root / "crates" / "valid"
            (valid_dir / "src").mkdir(parents=True)
            (valid_dir / "Cargo.toml").write_text(
                """[package]
name = "valid"
version = "0.1.0"
edition = "2024"

[lints]
workspace = true
""",
                encoding="utf-8",
            )
            (valid_dir / "src" / "lib.rs").write_text(
                "#![forbid(unsafe_code)]\npub fn valid() {}\n", encoding="utf-8"
            )

            # Fixture crate under tests/fixtures/
            fixture_dir = tmp_root / "tests" / "fixtures" / "sample"
            (fixture_dir / "src").mkdir(parents=True)
            (fixture_dir / "Cargo.toml").write_text(
                """[package]
name = "sample-fixture"
version = "0.1.0"
edition = "2024"

[lints.rust]
unsafe_code = "forbid"
""",
                encoding="utf-8",
            )
            (fixture_dir / "src" / "lib.rs").write_text(
                "#![forbid(unsafe_code)]\npub fn fixture_fn() {}\n", encoding="utf-8"
            )

            is_valid, findings, _ = audit_unsafe_prohibition(root=tmp_root, manifest_path=root_manifest)
            self.assertTrue(is_valid, f"Forbid-compliant fixture crate must pass: {[f.message for f in findings]}")
            self.assertEqual(len(findings), 0)

    def test_fixture_crate_missing_forbid_fails_closed(self) -> None:
        """A test fixture crate missing forbid must fail closed."""
        with tempfile.TemporaryDirectory() as td:
            tmp_root = Path(td)
            root_manifest = tmp_root / "Cargo.toml"
            root_manifest.write_text(
                """[workspace]
resolver = "3"
members = ["crates/valid"]

[workspace.lints.rust]
unsafe_code = "forbid"
""",
                encoding="utf-8",
            )
            valid_dir = tmp_root / "crates" / "valid"
            (valid_dir / "src").mkdir(parents=True)
            (valid_dir / "Cargo.toml").write_text(
                """[package]
name = "valid"
version = "0.1.0"
edition = "2024"

[lints]
workspace = true
""",
                encoding="utf-8",
            )
            (valid_dir / "src" / "lib.rs").write_text(
                "#![forbid(unsafe_code)]\npub fn valid() {}\n", encoding="utf-8"
            )

            # Fixture crate missing forbid
            fixture_dir = tmp_root / "tests" / "fixtures" / "sample"
            (fixture_dir / "src").mkdir(parents=True)
            (fixture_dir / "Cargo.toml").write_text(
                """[package]
name = "sample-fixture"
version = "0.1.0"
edition = "2024"
""",
                encoding="utf-8",
            )
            (fixture_dir / "src" / "lib.rs").write_text(
                "pub fn missing_forbid() {}\n", encoding="utf-8"
            )

            is_valid, findings, _ = audit_unsafe_prohibition(root=tmp_root, manifest_path=root_manifest)
            self.assertFalse(is_valid, "Fixture crate missing forbid must fail")
            self.assertEqual(
                {f.code for f in findings},
                {ERR_MANIFEST_LINT_NOT_FORBIDDEN, ERR_TARGET_ROOT_MISSING_FORBID},
            )


class TestSurvivingMutantsKillers(unittest.TestCase):
    """Targeted tests killing mutants M2b (custom target paths) and M3a (crate_count pin)."""

    def test_planted_custom_target_path_missing_forbid_kills_m2b(self) -> None:
        """Mutant M2b killer: target with a custom path (e.g. [[test]] or build=) missing forbid must fail."""
        with tempfile.TemporaryDirectory() as td:
            tmp_root = Path(td)
            root_manifest = tmp_root / "Cargo.toml"
            root_manifest.write_text(
                """[workspace]
resolver = "3"
members = ["crates/custom_target_pkg"]

[workspace.lints.rust]
unsafe_code = "forbid"
""",
                encoding="utf-8",
            )
            pkg_dir = tmp_root / "crates" / "custom_target_pkg"
            (pkg_dir / "src").mkdir(parents=True)
            (pkg_dir / "custom_tests").mkdir(parents=True)
            (pkg_dir / "Cargo.toml").write_text(
                """[package]
name = "custom_target_pkg"
version = "0.1.0"
edition = "2024"

[lints]
workspace = true

[[test]]
name = "my_custom_integration_test"
path = "custom_tests/integration.rs"
""",
                encoding="utf-8",
            )
            (pkg_dir / "src" / "lib.rs").write_text(
                "#![forbid(unsafe_code)]\npub fn ok() {}\n", encoding="utf-8"
            )
            # Custom test target root MISSING #![forbid(unsafe_code)]
            (pkg_dir / "custom_tests" / "integration.rs").write_text(
                "#[test]\nfn test_something() {}\n", encoding="utf-8"
            )

            is_valid, findings, _ = audit_unsafe_prohibition(root=tmp_root, manifest_path=root_manifest)
            self.assertFalse(is_valid, "Custom target path missing forbid must be caught by checker")
            self.assertEqual({f.code for f in findings}, {ERR_TARGET_ROOT_MISSING_FORBID})
            self.assertEqual(len(findings), 1)
            self.assertIn("custom_tests/integration.rs", findings[0].file)

    def test_planted_custom_build_script_path_missing_forbid_kills_m2b(self) -> None:
        """Mutant M2b killer: custom build script path (build = 'custom_build/build.rs') missing forbid must fail."""
        with tempfile.TemporaryDirectory() as td:
            tmp_root = Path(td)
            root_manifest = tmp_root / "Cargo.toml"
            root_manifest.write_text(
                """[workspace]
resolver = "3"
members = ["crates/custom_build_pkg"]

[workspace.lints.rust]
unsafe_code = "forbid"
""",
                encoding="utf-8",
            )
            pkg_dir = tmp_root / "crates" / "custom_build_pkg"
            (pkg_dir / "src").mkdir(parents=True)
            (pkg_dir / "custom_build").mkdir(parents=True)
            (pkg_dir / "Cargo.toml").write_text(
                """[package]
name = "custom_build_pkg"
version = "0.1.0"
edition = "2024"
build = "custom_build/build.rs"

[lints]
workspace = true
""",
                encoding="utf-8",
            )
            (pkg_dir / "src" / "lib.rs").write_text(
                "#![forbid(unsafe_code)]\npub fn ok() {}\n", encoding="utf-8"
            )
            (pkg_dir / "custom_build" / "build.rs").write_text(
                "fn main() {}\n", encoding="utf-8"
            )

            is_valid, findings, _ = audit_unsafe_prohibition(root=tmp_root, manifest_path=root_manifest)
            self.assertFalse(is_valid, "Custom build script target missing forbid must fail")
            self.assertEqual({f.code for f in findings}, {ERR_TARGET_ROOT_MISSING_FORBID})
            self.assertEqual(len(findings), 1)
            self.assertIn("custom_build/build.rs", findings[0].file)

    def test_synthetic_workspace_crate_count_not_pinned_kills_m3a(self) -> None:
        """Mutant M3a killer: synthetic workspace with 2 crates must report crate_count == 2, not hard-coded 9."""
        with tempfile.TemporaryDirectory() as td:
            tmp_root = Path(td)
            root_manifest = tmp_root / "Cargo.toml"
            root_manifest.write_text(
                """[workspace]
resolver = "3"
members = ["crates/alpha", "crates/beta"]

[workspace.lints.rust]
unsafe_code = "forbid"
""",
                encoding="utf-8",
            )
            for cname in ["alpha", "beta"]:
                cdir = tmp_root / "crates" / cname
                (cdir / "src").mkdir(parents=True)
                (cdir / "Cargo.toml").write_text(
                    f"""[package]
name = "{cname}"
version = "0.1.0"
edition = "2024"

[lints]
workspace = true
""",
                    encoding="utf-8",
                )
                (cdir / "src" / "lib.rs").write_text(
                    f"#![forbid(unsafe_code)]\npub fn f_{cname}() {{}}\n", encoding="utf-8"
                )

            is_valid, findings, summary = audit_unsafe_prohibition(root=tmp_root, manifest_path=root_manifest)
            self.assertTrue(is_valid, f"Synthetic workspace must pass: {[f.message for f in findings]}")
            self.assertEqual(len(findings), 0)
            self.assertEqual(summary["crate_count"], 2)
            self.assertEqual(summary["workspace_members_count"], 2)
            self.assertNotEqual(summary["crate_count"], 9, "crate_count must be dynamically derived, not pinned to 9")

    def test_planted_repo_in_tests_dir_relative_predicate_kills_n4(self) -> None:
        """Mutant N4 killer: repo inside a directory named tests/test_x must not exempt unlisted crates."""
        with tempfile.TemporaryDirectory() as td:
            repo_root = Path(td) / "tests" / "test_x" / "my_repo"
            repo_root.mkdir(parents=True)
            root_manifest = repo_root / "Cargo.toml"
            root_manifest.write_text(
                """[workspace]
resolver = "3"
members = ["crates/member"]

[workspace.lints.rust]
unsafe_code = "forbid"
""",
                encoding="utf-8",
            )
            member_dir = repo_root / "crates" / "member"
            (member_dir / "src").mkdir(parents=True)
            (member_dir / "Cargo.toml").write_text(
                """[package]
name = "member"
version = "0.1.0"
edition = "2024"

[lints]
workspace = true
""",
                encoding="utf-8",
            )
            (member_dir / "src" / "lib.rs").write_text(
                "#![forbid(unsafe_code)]\npub fn ok() {}\n", encoding="utf-8"
            )

            # Unlisted crate missing forbid inside crates/unlisted
            unlisted_dir = repo_root / "crates" / "unlisted"
            (unlisted_dir / "src").mkdir(parents=True)
            (unlisted_dir / "Cargo.toml").write_text(
                """[package]
name = "unlisted"
version = "0.1.0"
edition = "2024"
""",
                encoding="utf-8",
            )
            (unlisted_dir / "src" / "lib.rs").write_text(
                "pub fn unlisted_func() {}\n", encoding="utf-8"
            )

            is_valid, findings, _ = audit_unsafe_prohibition(root=repo_root, manifest_path=root_manifest)
            self.assertFalse(is_valid, "Unlisted crate missing forbid must fail even when repo is in tests/test_x")
            self.assertEqual(
                {f.code for f in findings},
                {ERR_MANIFEST_LINT_NOT_FORBIDDEN, ERR_TARGET_ROOT_MISSING_FORBID},
            )
            self.assertEqual(len(findings), 3)
            found_files = {f.file for f in findings}
            self.assertEqual(found_files, {"crates/unlisted/Cargo.toml", "crates/unlisted/src/lib.rs"})

    def test_planted_custom_lib_path_nonmember_kills_m2b_lib(self) -> None:
        """Mutant M2b-lib killer: non-member crate with custom [lib] path missing forbid must fail."""
        with tempfile.TemporaryDirectory() as td:
            tmp_root = Path(td)
            root_manifest = tmp_root / "Cargo.toml"
            root_manifest.write_text(
                """[workspace]
resolver = "3"
members = ["crates/member"]

[workspace.lints.rust]
unsafe_code = "forbid"
""",
                encoding="utf-8",
            )
            m_dir = tmp_root / "crates" / "member"
            (m_dir / "src").mkdir(parents=True)
            (m_dir / "Cargo.toml").write_text(
                """[package]
name = "member"
version = "0.1.0"
edition = "2024"

[lints]
workspace = true
""",
                encoding="utf-8",
            )
            (m_dir / "src" / "lib.rs").write_text(
                "#![forbid(unsafe_code)]\npub fn ok() {}\n", encoding="utf-8"
            )

            pkg_dir = tmp_root / "extra" / "custom_lib_crate"
            (pkg_dir / "custom_src").mkdir(parents=True)
            (pkg_dir / "Cargo.toml").write_text(
                """[package]
name = "custom_lib_crate"
version = "0.1.0"
edition = "2024"

[lib]
path = "custom_src/my_lib.rs"

[lints.rust]
unsafe_code = "forbid"
""",
                encoding="utf-8",
            )
            # Custom lib root missing forbid
            (pkg_dir / "custom_src" / "my_lib.rs").write_text(
                "pub fn my_func() {}\n", encoding="utf-8"
            )

            is_valid, findings, _ = audit_unsafe_prohibition(root=tmp_root, manifest_path=root_manifest)
            self.assertFalse(is_valid, "Custom [lib] target path missing forbid must fail")
            self.assertEqual(
                {f.code for f in findings},
                {ERR_MANIFEST_LINT_NOT_FORBIDDEN, ERR_TARGET_ROOT_MISSING_FORBID},
            )
            self.assertEqual(len(findings), 2)
            self.assertEqual(
                {f.file for f in findings},
                {"extra/custom_lib_crate/Cargo.toml", "extra/custom_lib_crate/custom_src/my_lib.rs"},
            )

    def test_planted_custom_bin_path_nonmember_kills_m2b_bin(self) -> None:
        """Mutant M2b-bin killer: non-member crate with custom [[bin]] path missing forbid must fail."""
        with tempfile.TemporaryDirectory() as td:
            tmp_root = Path(td)
            root_manifest = tmp_root / "Cargo.toml"
            root_manifest.write_text(
                """[workspace]
resolver = "3"
members = ["crates/member"]

[workspace.lints.rust]
unsafe_code = "forbid"
""",
                encoding="utf-8",
            )
            m_dir = tmp_root / "crates" / "member"
            (m_dir / "src").mkdir(parents=True)
            (m_dir / "Cargo.toml").write_text(
                """[package]
name = "member"
version = "0.1.0"
edition = "2024"

[lints]
workspace = true
""",
                encoding="utf-8",
            )
            (m_dir / "src" / "lib.rs").write_text(
                "#![forbid(unsafe_code)]\npub fn ok() {}\n", encoding="utf-8"
            )

            pkg_dir = tmp_root / "extra" / "custom_bin_crate"
            (pkg_dir / "custom_bin").mkdir(parents=True)
            (pkg_dir / "Cargo.toml").write_text(
                """[package]
name = "custom_bin_crate"
version = "0.1.0"
edition = "2024"

[[bin]]
name = "custom_app"
path = "custom_bin/app.rs"

[lints.rust]
unsafe_code = "forbid"
""",
                encoding="utf-8",
            )
            # Custom bin root missing forbid
            (pkg_dir / "custom_bin" / "app.rs").write_text(
                "fn main() {}\n", encoding="utf-8"
            )

            is_valid, findings, _ = audit_unsafe_prohibition(root=tmp_root, manifest_path=root_manifest)
            self.assertFalse(is_valid, "Custom [[bin]] target path missing forbid must fail")
            self.assertEqual(
                {f.code for f in findings},
                {ERR_MANIFEST_LINT_NOT_FORBIDDEN, ERR_TARGET_ROOT_MISSING_FORBID},
            )
            self.assertEqual(len(findings), 2)
            self.assertEqual(
                {f.file for f in findings},
                {"extra/custom_bin_crate/Cargo.toml", "extra/custom_bin_crate/custom_bin/app.rs"},
            )

    def test_planted_custom_example_path_nonmember_kills_m2b_example(self) -> None:
        """Mutant M2b-example killer: non-member crate with custom [[example]] path missing forbid must fail."""
        with tempfile.TemporaryDirectory() as td:
            tmp_root = Path(td)
            root_manifest = tmp_root / "Cargo.toml"
            root_manifest.write_text(
                """[workspace]
resolver = "3"
members = ["crates/member"]

[workspace.lints.rust]
unsafe_code = "forbid"
""",
                encoding="utf-8",
            )
            m_dir = tmp_root / "crates" / "member"
            (m_dir / "src").mkdir(parents=True)
            (m_dir / "Cargo.toml").write_text(
                """[package]
name = "member"
version = "0.1.0"
edition = "2024"

[lints]
workspace = true
""",
                encoding="utf-8",
            )
            (m_dir / "src" / "lib.rs").write_text(
                "#![forbid(unsafe_code)]\npub fn ok() {}\n", encoding="utf-8"
            )

            pkg_dir = tmp_root / "extra" / "custom_ex_crate"
            (pkg_dir / "custom_examples").mkdir(parents=True)
            (pkg_dir / "Cargo.toml").write_text(
                """[package]
name = "custom_ex_crate"
version = "0.1.0"
edition = "2024"

[[example]]
name = "custom_demo"
path = "custom_examples/demo.rs"

[lints.rust]
unsafe_code = "forbid"
""",
                encoding="utf-8",
            )
            # Custom example root missing forbid
            (pkg_dir / "custom_examples" / "demo.rs").write_text(
                "fn main() {}\n", encoding="utf-8"
            )

            is_valid, findings, _ = audit_unsafe_prohibition(root=tmp_root, manifest_path=root_manifest)
            self.assertFalse(is_valid, "Custom [[example]] target path missing forbid must fail")
            self.assertEqual(
                {f.code for f in findings},
                {ERR_MANIFEST_LINT_NOT_FORBIDDEN, ERR_TARGET_ROOT_MISSING_FORBID},
            )
            self.assertEqual(len(findings), 2)
            self.assertEqual(
                {f.file for f in findings},
                {"extra/custom_ex_crate/Cargo.toml", "extra/custom_ex_crate/custom_examples/demo.rs"},
            )

    def test_planted_cargo_exclude_lookalike_name_kills_r3_r3b(self) -> None:
        """Mutant R3/R3b killer: cargo workspace.exclude path-prefix must not match lookalike name."""
        with tempfile.TemporaryDirectory() as td:
            tmp_root = Path(td)
            root_manifest = tmp_root / "Cargo.toml"
            root_manifest.write_text(
                """[workspace]
resolver = "3"
members = ["crates/member"]
exclude = ["crates/vendor"]

[workspace.lints.rust]
unsafe_code = "forbid"
""",
                encoding="utf-8",
            )
            member_dir = tmp_root / "crates" / "member"
            (member_dir / "src").mkdir(parents=True)
            (member_dir / "Cargo.toml").write_text(
                """[package]
name = "member"
version = "0.1.0"
edition = "2024"

[lints]
workspace = true
""",
                encoding="utf-8",
            )
            (member_dir / "src" / "lib.rs").write_text(
                "#![forbid(unsafe_code)]\npub fn ok() {}\n", encoding="utf-8"
            )

            # Lookalike crate: crates/vendor_lookalike should NOT be excluded by "crates/vendor"
            lookalike_dir = tmp_root / "crates" / "vendor_lookalike"
            (lookalike_dir / "src").mkdir(parents=True)
            (lookalike_dir / "Cargo.toml").write_text(
                """[package]
name = "vendor_lookalike"
version = "0.1.0"
edition = "2024"
""",
                encoding="utf-8",
            )
            (lookalike_dir / "src" / "lib.rs").write_text(
                "pub fn rogue() {}\n", encoding="utf-8"
            )

            is_valid, findings, _ = audit_unsafe_prohibition(root=tmp_root, manifest_path=root_manifest)
            self.assertFalse(is_valid, "Lookalike directory crates/vendor_lookalike must not be excluded by crates/vendor")
            self.assertEqual(
                {f.code for f in findings},
                {ERR_MANIFEST_LINT_NOT_FORBIDDEN, ERR_TARGET_ROOT_MISSING_FORBID},
            )
            self.assertEqual(len(findings), 3)
            found_files = {f.file for f in findings}
            self.assertEqual(
                found_files,
                {"crates/vendor_lookalike/Cargo.toml", "crates/vendor_lookalike/src/lib.rs"},
            )

    def test_planted_renamed_crate_at_different_path_kills_r4(self) -> None:
        """Mutant R4 killer: crate given a registered topology name at a non-registered path must not be exempt."""
        with tempfile.TemporaryDirectory() as td:
            tmp_root = Path(td)
            root_manifest = tmp_root / "Cargo.toml"
            root_manifest.write_text(
                """[workspace]
resolver = "3"
members = ["crates/member"]

[workspace.lints.rust]
unsafe_code = "forbid"
""",
                encoding="utf-8",
            )
            # Create topology where "fss-core" is registered at "crates/fss-core"
            topo_dir = tmp_root / "architecture"
            topo_dir.mkdir(parents=True)
            (topo_dir / "crate_topology.json").write_text(
                json.dumps({
                    "layers": [
                        {
                            "name": "foundation",
                            "crates": [
                                {"name": "fss-core", "path": "crates/fss-core"}
                            ]
                        }
                    ]
                }),
                encoding="utf-8",
            )
            member_dir = tmp_root / "crates" / "member"
            (member_dir / "src").mkdir(parents=True)
            (member_dir / "Cargo.toml").write_text(
                """[package]
name = "member"
version = "0.1.0"
edition = "2024"

[lints]
workspace = true
""",
                encoding="utf-8",
            )
            (member_dir / "src" / "lib.rs").write_text(
                "#![forbid(unsafe_code)]\npub fn ok() {}\n", encoding="utf-8"
            )

            # Rogue crate named "fss-core" at an unregistered path "other/fss-core"
            rogue_dir = tmp_root / "other" / "fss-core"
            (rogue_dir / "src").mkdir(parents=True)
            (rogue_dir / "Cargo.toml").write_text(
                """[package]
name = "fss-core"
version = "0.1.0"
edition = "2024"

[lints.rust]
unsafe_code = "forbid"
""",
                encoding="utf-8",
            )
            (rogue_dir / "src" / "lib.rs").write_text(
                "#![forbid(unsafe_code)]\npub fn rogue() {}\n", encoding="utf-8"
            )

            is_valid, findings, _ = audit_unsafe_prohibition(root=tmp_root, manifest_path=root_manifest)
            self.assertFalse(is_valid, "Crate with registered name at unregistered path must be flagged as unregistered")
            self.assertEqual({f.code for f in findings}, {ERR_MANIFEST_LINT_NOT_FORBIDDEN})
            self.assertEqual(len(findings), 1)
            self.assertEqual(findings[0].file, "other/fss-core/Cargo.toml")
            self.assertIn("Unregistered crate 'fss-core'", findings[0].message)

    def test_planted_stray_manifest_type_crashes_kill_r5a_r5b_r5d(self) -> None:
        """Mutants R5a, R5b, R5d killers: stray manifest type crashes (package as string, members as non-list) must produce typed findings, not tracebacks."""
        with tempfile.TemporaryDirectory() as td:
            tmp_root = Path(td)
            root_manifest = tmp_root / "Cargo.toml"
            root_manifest.write_text(
                """[workspace]
resolver = "3"
members = ["crates/member"]

[workspace.lints.rust]
unsafe_code = "forbid"
""",
                encoding="utf-8",
            )
            m_dir = tmp_root / "crates" / "member"
            (m_dir / "src").mkdir(parents=True)
            (m_dir / "Cargo.toml").write_text(
                """[package]
name = "member"
version = "0.1.0"
edition = "2024"

[lints]
workspace = true
""",
                encoding="utf-8",
            )
            (m_dir / "src" / "lib.rs").write_text(
                "#![forbid(unsafe_code)]\npub fn ok() {}\n", encoding="utf-8"
            )

            # N5: package is a string
            stray_n5 = tmp_root / "stray_n5"
            stray_n5.mkdir(parents=True)
            (stray_n5 / "Cargo.toml").write_text('package = "invalid_not_a_table"\n', encoding="utf-8")

            # N8: workspace.members is a string (not a list)
            stray_n8 = tmp_root / "stray_n8"
            stray_n8.mkdir(parents=True)
            (stray_n8 / "Cargo.toml").write_text(
                """[workspace]
members = "not_a_list"
""",
                encoding="utf-8",
            )

            is_valid, findings, _ = audit_unsafe_prohibition(root=tmp_root, manifest_path=root_manifest)
            self.assertFalse(is_valid, "Stray manifest type issues must be caught as typed findings")
            self.assertEqual(
                {f.code for f in findings},
                {ERR_MANIFEST_LINT_NOT_FORBIDDEN, ERR_TARGET_ROOT_MISSING_FORBID},
            )
            self.assertEqual(len(findings), 3)
            found_files = {f.file for f in findings}
            self.assertEqual(found_files, {"stray_n5/Cargo.toml", "stray_n8/Cargo.toml"})

    def test_planted_n3_test_prefix_dir_compliant_kills_n3(self) -> None:
        """Mutant N3 killer: crate under a directory with prefix test_ must be recognized as test fixture."""
        with tempfile.TemporaryDirectory() as td:
            tmp_root = Path(td)
            root_manifest = tmp_root / "Cargo.toml"
            root_manifest.write_text(
                """[workspace]
resolver = "3"
members = ["crates/member"]

[workspace.lints.rust]
unsafe_code = "forbid"
""",
                encoding="utf-8",
            )
            m_dir = tmp_root / "crates" / "member"
            (m_dir / "src").mkdir(parents=True)
            (m_dir / "Cargo.toml").write_text(
                """[package]
name = "member"
version = "0.1.0"
edition = "2024"

[lints]
workspace = true
""",
                encoding="utf-8",
            )
            (m_dir / "src" / "lib.rs").write_text("#![forbid(unsafe_code)]\npub fn ok() {}\n", encoding="utf-8")

            # Crate inside directory with test_ prefix
            tc_dir = tmp_root / "test_crates" / "tc"
            (tc_dir / "src").mkdir(parents=True)
            (tc_dir / "Cargo.toml").write_text(
                """[package]
name = "tc"
version = "0.1.0"
edition = "2024"

[lints.rust]
unsafe_code = "forbid"
""",
                encoding="utf-8",
            )
            (tc_dir / "src" / "lib.rs").write_text("#![forbid(unsafe_code)]\npub fn f() {}\n", encoding="utf-8")

            is_valid, findings, _ = audit_unsafe_prohibition(root=tmp_root, manifest_path=root_manifest)
            self.assertTrue(is_valid, f"Compliant crate in test_ directory must be accepted: {[f.message for f in findings]}")
            self.assertEqual(len(findings), 0)

    def test_planted_n3b_tests_dir_fixture_kills_n3b(self) -> None:
        """Mutant N3b killer: crate under tests/ directory must be recognized as test fixture."""
        with tempfile.TemporaryDirectory() as td:
            tmp_root = Path(td)
            root_manifest = tmp_root / "Cargo.toml"
            root_manifest.write_text(
                """[workspace]
resolver = "3"
members = ["crates/member"]

[workspace.lints.rust]
unsafe_code = "forbid"
""",
                encoding="utf-8",
            )
            m_dir = tmp_root / "crates" / "member"
            (m_dir / "src").mkdir(parents=True)
            (m_dir / "Cargo.toml").write_text(
                """[package]
name = "member"
version = "0.1.0"
edition = "2024"

[lints]
workspace = true
""",
                encoding="utf-8",
            )
            (m_dir / "src" / "lib.rs").write_text("#![forbid(unsafe_code)]\npub fn ok() {}\n", encoding="utf-8")

            # Crate inside tests/
            t_dir = tmp_root / "tests" / "foo"
            (t_dir / "src").mkdir(parents=True)
            (t_dir / "Cargo.toml").write_text(
                """[package]
name = "foo"
version = "0.1.0"
edition = "2024"

[lints.rust]
unsafe_code = "forbid"
""",
                encoding="utf-8",
            )
            (t_dir / "src" / "lib.rs").write_text("#![forbid(unsafe_code)]\npub fn f() {}\n", encoding="utf-8")

            is_valid, findings, _ = audit_unsafe_prohibition(root=tmp_root, manifest_path=root_manifest)
            self.assertTrue(is_valid, f"Compliant crate under tests/ must be accepted: {[f.message for f in findings]}")
            self.assertEqual(len(findings), 0)

    def test_planted_n4c_cwd_in_tests_dir_unlisted_crate_kills_n4c(self) -> None:
        """Mutant N4c killer: CWD inside tests/ must not exempt unlisted crates via relative path resolution."""
        with tempfile.TemporaryDirectory() as td:
            tmp_root = Path(td)
            root_manifest = tmp_root / "Cargo.toml"
            root_manifest.write_text(
                """[workspace]
resolver = "3"
members = ["crates/member"]

[workspace.lints.rust]
unsafe_code = "forbid"
""",
                encoding="utf-8",
            )
            m_dir = tmp_root / "crates" / "member"
            (m_dir / "src").mkdir(parents=True)
            (m_dir / "Cargo.toml").write_text(
                """[package]
name = "member"
version = "0.1.0"
edition = "2024"

[lints]
workspace = true
""",
                encoding="utf-8",
            )
            (m_dir / "src" / "lib.rs").write_text("#![forbid(unsafe_code)]\npub fn ok() {}\n", encoding="utf-8")

            # Unlisted compliant crate
            u_dir = tmp_root / "crates" / "unlisted"
            (u_dir / "src").mkdir(parents=True)
            (u_dir / "Cargo.toml").write_text(
                """[package]
name = "unlisted"
version = "0.1.0"
edition = "2024"

[lints.rust]
unsafe_code = "forbid"
""",
                encoding="utf-8",
            )
            (u_dir / "src" / "lib.rs").write_text("#![forbid(unsafe_code)]\npub fn f() {}\n", encoding="utf-8")

            tests_dir = tmp_root / "tests"
            tests_dir.mkdir(parents=True)

            old_cwd = os.getcwd()
            try:
                os.chdir(str(tests_dir))
                is_valid, findings, _ = audit_unsafe_prohibition(root=tmp_root, manifest_path=root_manifest)
                self.assertFalse(is_valid, "Unlisted crate must not be exempted when CWD is inside tests/")
                self.assertEqual({f.code for f in findings}, {ERR_MANIFEST_LINT_NOT_FORBIDDEN})
                self.assertEqual(len(findings), 1)
                self.assertEqual(findings[0].file, "crates/unlisted/Cargo.toml")
                self.assertIn("Unregistered crate 'unlisted'", findings[0].message)
            finally:
                os.chdir(old_cwd)

    def test_planted_n5_topology_loader_empty_kills_n5(self) -> None:
        """Mutant N5 killer: registered topology crate must pass without unregistered finding."""
        with tempfile.TemporaryDirectory() as td:
            tmp_root = Path(td)
            root_manifest = tmp_root / "Cargo.toml"
            root_manifest.write_text(
                """[workspace]
resolver = "3"
members = ["crates/member"]

[workspace.lints.rust]
unsafe_code = "forbid"
""",
                encoding="utf-8",
            )
            m_dir = tmp_root / "crates" / "member"
            (m_dir / "src").mkdir(parents=True)
            (m_dir / "Cargo.toml").write_text(
                """[package]
name = "member"
version = "0.1.0"
edition = "2024"

[lints]
workspace = true
""",
                encoding="utf-8",
            )
            (m_dir / "src" / "lib.rs").write_text("#![forbid(unsafe_code)]\npub fn ok() {}\n", encoding="utf-8")

            # Architecture topology file declaring fss-core
            arch_dir = tmp_root / "architecture"
            arch_dir.mkdir(parents=True)
            (arch_dir / "crate_topology.json").write_text(
                json.dumps({"layers": [{"name": "core", "crates": [{"name": "fss-core"}]}]}),
                encoding="utf-8",
            )

            # Crate fss-core at crates/fss-core
            core_dir = tmp_root / "crates" / "fss-core"
            (core_dir / "src").mkdir(parents=True)
            (core_dir / "Cargo.toml").write_text(
                """[package]
name = "fss-core"
version = "0.1.0"
edition = "2024"

[lints.rust]
unsafe_code = "forbid"
""",
                encoding="utf-8",
            )
            (core_dir / "src" / "lib.rs").write_text("#![forbid(unsafe_code)]\npub fn f() {}\n", encoding="utf-8")

            is_valid, findings, _ = audit_unsafe_prohibition(root=tmp_root, manifest_path=root_manifest)
            self.assertTrue(is_valid, f"Registered topology crate must pass: {[f.message for f in findings]}")
            self.assertEqual(len(findings), 0)

    def test_planted_n6_topology_clause_drops_is_forbid_compliant_kills_n6(self) -> None:
        """Mutant N6 killer: registered topology crate missing forbid must fail closed."""
        with tempfile.TemporaryDirectory() as td:
            tmp_root = Path(td)
            root_manifest = tmp_root / "Cargo.toml"
            root_manifest.write_text(
                """[workspace]
resolver = "3"
members = ["crates/member"]

[workspace.lints.rust]
unsafe_code = "forbid"
""",
                encoding="utf-8",
            )
            m_dir = tmp_root / "crates" / "member"
            (m_dir / "src").mkdir(parents=True)
            (m_dir / "Cargo.toml").write_text(
                """[package]
name = "member"
version = "0.1.0"
edition = "2024"

[lints]
workspace = true
""",
                encoding="utf-8",
            )
            (m_dir / "src" / "lib.rs").write_text("#![forbid(unsafe_code)]\npub fn ok() {}\n", encoding="utf-8")

            arch_dir = tmp_root / "architecture"
            arch_dir.mkdir(parents=True)
            (arch_dir / "crate_topology.json").write_text(
                json.dumps({"layers": [{"name": "core", "crates": [{"name": "fss-core"}]}]}),
                encoding="utf-8",
            )

            # Crate fss-core missing forbid
            core_dir = tmp_root / "crates" / "fss-core"
            (core_dir / "src").mkdir(parents=True)
            (core_dir / "Cargo.toml").write_text(
                """[package]
name = "fss-core"
version = "0.1.0"
edition = "2024"
""",
                encoding="utf-8",
            )
            (core_dir / "src" / "lib.rs").write_text("pub fn f() {}\n", encoding="utf-8")

            is_valid, findings, _ = audit_unsafe_prohibition(root=tmp_root, manifest_path=root_manifest)
            self.assertFalse(is_valid, "Registered topology crate missing forbid must fail")
            self.assertEqual(len(findings), 3)
            self.assertEqual({f.code for f in findings}, {ERR_MANIFEST_LINT_NOT_FORBIDDEN, ERR_TARGET_ROOT_MISSING_FORBID})

    def test_planted_n8_target_root_read_unicode_decode_error_kills_n8(self) -> None:
        """Mutant N8 killer: target root with invalid UTF-8 bytes must produce typed finding without crash."""
        with tempfile.TemporaryDirectory() as td:
            tmp_root = Path(td)
            root_manifest = tmp_root / "Cargo.toml"
            root_manifest.write_text(
                """[workspace]
resolver = "3"
members = ["crates/member"]

[workspace.lints.rust]
unsafe_code = "forbid"
""",
                encoding="utf-8",
            )
            m_dir = tmp_root / "crates" / "member"
            (m_dir / "src").mkdir(parents=True)
            (m_dir / "Cargo.toml").write_text(
                """[package]
name = "member"
version = "0.1.0"
edition = "2024"

[lints]
workspace = true
""",
                encoding="utf-8",
            )
            (m_dir / "src" / "lib.rs").write_bytes(b"#![forbid(unsafe_code)]\n// \xff\xfe\n")

            is_valid, findings, _ = audit_unsafe_prohibition(root=tmp_root, manifest_path=root_manifest)
            self.assertFalse(is_valid, "Invalid UTF-8 in target root must produce typed finding")
            self.assertEqual({f.code for f in findings}, {ERR_TARGET_ROOT_MISSING_FORBID, ERR_UNSAFE_CONSTRUCT_DETECTED})
            self.assertTrue(any("crates/member/src/lib.rs" in f.file for f in findings))

    def test_planted_m2b_lib_meta_kills_m2b_lib_meta(self) -> None:
        """Mutant M2b-lib(meta) killer: member crate custom [lib] path missing forbid must be caught."""
        with tempfile.TemporaryDirectory() as td:
            tmp_root = Path(td)
            root_manifest = tmp_root / "Cargo.toml"
            root_manifest.write_text(
                """[workspace]
resolver = "3"
members = ["crates/member"]

[workspace.lints.rust]
unsafe_code = "forbid"
""",
                encoding="utf-8",
            )
            m_dir = tmp_root / "crates" / "member"
            (m_dir / "csrc").mkdir(parents=True)
            (m_dir / "Cargo.toml").write_text(
                """[package]
name = "member"
version = "0.1.0"
edition = "2024"

[lints]
workspace = true

[lib]
path = "csrc/l.rs"
""",
                encoding="utf-8",
            )
            (m_dir / "csrc" / "l.rs").write_text("pub fn f() {}\n", encoding="utf-8")

            is_valid, findings, _ = audit_unsafe_prohibition(root=tmp_root, manifest_path=root_manifest)
            self.assertFalse(is_valid, "Member custom lib missing forbid must be caught")
            self.assertTrue(any(f.code == ERR_TARGET_ROOT_MISSING_FORBID and "crates/member/csrc/l.rs" in f.file for f in findings))

    def test_planted_m2b_bin_meta_kills_m2b_bin_meta(self) -> None:
        """Mutant M2b-bin(meta) killer: member crate custom [[bin]] path missing forbid must be caught."""
        with tempfile.TemporaryDirectory() as td:
            tmp_root = Path(td)
            root_manifest = tmp_root / "Cargo.toml"
            root_manifest.write_text(
                """[workspace]
resolver = "3"
members = ["crates/member"]

[workspace.lints.rust]
unsafe_code = "forbid"
""",
                encoding="utf-8",
            )
            m_dir = tmp_root / "crates" / "member"
            (m_dir / "cbin").mkdir(parents=True)
            (m_dir / "Cargo.toml").write_text(
                """[package]
name = "member"
version = "0.1.0"
edition = "2024"

[lints]
workspace = true

[[bin]]
name = "app"
path = "cbin/app.rs"
""",
                encoding="utf-8",
            )
            (m_dir / "cbin" / "app.rs").write_text("fn main() {}\n", encoding="utf-8")

            is_valid, findings, _ = audit_unsafe_prohibition(root=tmp_root, manifest_path=root_manifest)
            self.assertFalse(is_valid, "Member custom bin missing forbid must be caught")
            self.assertTrue(any(f.code == ERR_TARGET_ROOT_MISSING_FORBID and "crates/member/cbin/app.rs" in f.file for f in findings))

    def test_planted_m2b_example_meta_kills_m2b_example_meta(self) -> None:
        """Mutant M2b-example(meta) killer: member crate custom [[example]] path missing forbid must be caught."""
        with tempfile.TemporaryDirectory() as td:
            tmp_root = Path(td)
            root_manifest = tmp_root / "Cargo.toml"
            root_manifest.write_text(
                """[workspace]
resolver = "3"
members = ["crates/member"]

[workspace.lints.rust]
unsafe_code = "forbid"
""",
                encoding="utf-8",
            )
            m_dir = tmp_root / "crates" / "member"
            (m_dir / "cex").mkdir(parents=True)
            (m_dir / "Cargo.toml").write_text(
                """[package]
name = "member"
version = "0.1.0"
edition = "2024"

[lints]
workspace = true

[[example]]
name = "d"
path = "cex/d.rs"
""",
                encoding="utf-8",
            )
            (m_dir / "cex" / "d.rs").write_text("fn main() {}\n", encoding="utf-8")

            is_valid, findings, _ = audit_unsafe_prohibition(root=tmp_root, manifest_path=root_manifest)
            self.assertFalse(is_valid, "Member custom example missing forbid must be caught")
            self.assertTrue(any(f.code == ERR_TARGET_ROOT_MISSING_FORBID and "crates/member/cex/d.rs" in f.file for f in findings))

    def test_planted_m2b_test_bench_disk_kills_m2b_test_bench_disk(self) -> None:
        """Mutant M2b-test/bench(disk) killer: non-member [[test]] custom path missing forbid must be caught."""
        with tempfile.TemporaryDirectory() as td:
            tmp_root = Path(td)
            root_manifest = tmp_root / "Cargo.toml"
            root_manifest.write_text(
                """[workspace]
resolver = "3"
members = ["crates/member"]

[workspace.lints.rust]
unsafe_code = "forbid"
""",
                encoding="utf-8",
            )
            m_dir = tmp_root / "crates" / "member"
            (m_dir / "src").mkdir(parents=True)
            (m_dir / "Cargo.toml").write_text(
                """[package]
name = "member"
version = "0.1.0"
edition = "2024"

[lints]
workspace = true
""",
                encoding="utf-8",
            )
            (m_dir / "src" / "lib.rs").write_text("#![forbid(unsafe_code)]\npub fn ok() {}\n", encoding="utf-8")

            # Non-member extra/ct with custom [[test]]
            ct_dir = tmp_root / "extra" / "ct"
            (ct_dir / "ctest").mkdir(parents=True)
            (ct_dir / "Cargo.toml").write_text(
                """[package]
name = "ct"
version = "0.1.0"
edition = "2024"

[lints.rust]
unsafe_code = "forbid"

[[test]]
name = "it"
path = "ctest/it.rs"
""",
                encoding="utf-8",
            )
            (ct_dir / "ctest" / "it.rs").write_text("#[test] fn t() {}\n", encoding="utf-8")

            is_valid, findings, _ = audit_unsafe_prohibition(root=tmp_root, manifest_path=root_manifest)
            self.assertFalse(is_valid, "Non-member custom test target missing forbid must be caught")
            self.assertTrue(any(f.code == ERR_TARGET_ROOT_MISSING_FORBID and "extra/ct/ctest/it.rs" in f.file for f in findings))

    def test_planted_m2b_build_disk_kills_m2b_build_disk(self) -> None:
        """Mutant M2b-build(disk) killer: non-member build = path missing forbid must be caught."""
        with tempfile.TemporaryDirectory() as td:
            tmp_root = Path(td)
            root_manifest = tmp_root / "Cargo.toml"
            root_manifest.write_text(
                """[workspace]
resolver = "3"
members = ["crates/member"]

[workspace.lints.rust]
unsafe_code = "forbid"
""",
                encoding="utf-8",
            )
            m_dir = tmp_root / "crates" / "member"
            (m_dir / "src").mkdir(parents=True)
            (m_dir / "Cargo.toml").write_text(
                """[package]
name = "member"
version = "0.1.0"
edition = "2024"

[lints]
workspace = true
""",
                encoding="utf-8",
            )
            (m_dir / "src" / "lib.rs").write_text("#![forbid(unsafe_code)]\npub fn ok() {}\n", encoding="utf-8")

            # Non-member extra/cbu with custom build
            cbu_dir = tmp_root / "extra" / "cbu"
            (cbu_dir / "tools").mkdir(parents=True)
            (cbu_dir / "src").mkdir(parents=True)
            (cbu_dir / "Cargo.toml").write_text(
                """[package]
name = "cbu"
version = "0.1.0"
edition = "2024"
build = "tools/gen.rs"

[lints.rust]
unsafe_code = "forbid"
""",
                encoding="utf-8",
            )
            (cbu_dir / "src" / "lib.rs").write_text("#![forbid(unsafe_code)]\npub fn f() {}\n", encoding="utf-8")
            (cbu_dir / "tools" / "gen.rs").write_text("fn main() {}\n", encoding="utf-8")

            is_valid, findings, _ = audit_unsafe_prohibition(root=tmp_root, manifest_path=root_manifest)
            self.assertFalse(is_valid, "Non-member custom build script missing forbid must be caught")
            self.assertTrue(any(f.code == ERR_TARGET_ROOT_MISSING_FORBID and "extra/cbu/tools/gen.rs" in f.file for f in findings))

    def test_planted_r_autobins_skip_src_main_kills_r_autobins(self) -> None:
        """Mutant R-autobins killer: autodiscovered src/main.rs missing forbid must be caught."""
        with tempfile.TemporaryDirectory() as td:
            tmp_root = Path(td)
            root_manifest = tmp_root / "Cargo.toml"
            root_manifest.write_text(
                """[workspace]
resolver = "3"
members = ["crates/member"]

[workspace.lints.rust]
unsafe_code = "forbid"
""",
                encoding="utf-8",
            )
            m_dir = tmp_root / "crates" / "member"
            (m_dir / "src").mkdir(parents=True)
            (m_dir / "Cargo.toml").write_text(
                """[package]
name = "member"
version = "0.1.0"
edition = "2024"

[lints]
workspace = true
""",
                encoding="utf-8",
            )
            (m_dir / "src" / "lib.rs").write_text("#![forbid(unsafe_code)]\npub fn ok() {}\n", encoding="utf-8")

            # Non-member with src/main.rs missing forbid
            app_dir = tmp_root / "extra" / "app"
            (app_dir / "src").mkdir(parents=True)
            (app_dir / "Cargo.toml").write_text(
                """[package]
name = "app"
version = "0.1.0"
edition = "2024"

[lints.rust]
unsafe_code = "forbid"
""",
                encoding="utf-8",
            )
            (app_dir / "src" / "main.rs").write_text("fn main() {}\n", encoding="utf-8")

            is_valid, findings, _ = audit_unsafe_prohibition(root=tmp_root, manifest_path=root_manifest)
            self.assertFalse(is_valid, "Autodiscovered src/main.rs missing forbid must be caught")
            self.assertTrue(any(f.code == ERR_TARGET_ROOT_MISSING_FORBID and "extra/app/src/main.rs" in f.file for f in findings))

    def test_planted_r4b_topology_path_only_kills_r4b(self) -> None:
        """Mutant R4b killer: topology path with wrong package name must be rejected."""
        with tempfile.TemporaryDirectory() as td:
            tmp_root = Path(td)
            root_manifest = tmp_root / "Cargo.toml"
            root_manifest.write_text(
                """[workspace]
resolver = "3"
members = ["crates/member"]

[workspace.lints.rust]
unsafe_code = "forbid"
""",
                encoding="utf-8",
            )
            m_dir = tmp_root / "crates" / "member"
            (m_dir / "src").mkdir(parents=True)
            (m_dir / "Cargo.toml").write_text(
                """[package]
name = "member"
version = "0.1.0"
edition = "2024"

[lints]
workspace = true
""",
                encoding="utf-8",
            )
            (m_dir / "src" / "lib.rs").write_text("#![forbid(unsafe_code)]\npub fn ok() {}\n", encoding="utf-8")

            arch_dir = tmp_root / "architecture"
            arch_dir.mkdir(parents=True)
            (arch_dir / "crate_topology.json").write_text(
                json.dumps({"layers": [{"crates": [{"name": "fss-core"}]}]}),
                encoding="utf-8",
            )

            # Crate at crates/fss-core but named 'rogue'
            core_dir = tmp_root / "crates" / "fss-core"
            (core_dir / "src").mkdir(parents=True)
            (core_dir / "Cargo.toml").write_text(
                """[package]
name = "rogue"
version = "0.1.0"
edition = "2024"

[lints.rust]
unsafe_code = "forbid"
""",
                encoding="utf-8",
            )
            (core_dir / "src" / "lib.rs").write_text("#![forbid(unsafe_code)]\npub fn f() {}\n", encoding="utf-8")

            is_valid, findings, _ = audit_unsafe_prohibition(root=tmp_root, manifest_path=root_manifest)
            self.assertFalse(is_valid, "Topology path with mismatched package name must be rejected as unlisted")
            self.assertEqual({f.code for f in findings}, {ERR_MANIFEST_LINT_NOT_FORBIDDEN})
            self.assertEqual(findings[0].file, "crates/fss-core/Cargo.toml")
            self.assertIn("Unregistered crate 'rogue'", findings[0].message)

    def test_planted_r5c_lints_drop_stray_workspace_type_kills_r5c(self) -> None:
        """Mutant R5c killer: stray manifest workspace = string must produce typed finding."""
        with tempfile.TemporaryDirectory() as td:
            tmp_root = Path(td)
            root_manifest = tmp_root / "Cargo.toml"
            root_manifest.write_text(
                """[workspace]
resolver = "3"
members = ["crates/member"]

[workspace.lints.rust]
unsafe_code = "forbid"
""",
                encoding="utf-8",
            )
            m_dir = tmp_root / "crates" / "member"
            (m_dir / "src").mkdir(parents=True)
            (m_dir / "Cargo.toml").write_text(
                """[package]
name = "member"
version = "0.1.0"
edition = "2024"

[lints]
workspace = true
""",
                encoding="utf-8",
            )
            (m_dir / "src" / "lib.rs").write_text("#![forbid(unsafe_code)]\npub fn ok() {}\n", encoding="utf-8")

            stray_dir = tmp_root / "stray"
            stray_dir.mkdir(parents=True)
            (stray_dir / "Cargo.toml").write_text('workspace = "not_a_table"\n', encoding="utf-8")

            is_valid, findings, _ = audit_unsafe_prohibition(root=tmp_root, manifest_path=root_manifest)
            self.assertFalse(is_valid, "Stray manifest workspace = string must be caught")
            self.assertTrue(any(f.code == ERR_MANIFEST_LINT_NOT_FORBIDDEN and f.location == "workspace" for f in findings))

    def test_planted_r5e_lints_drop_non_table_manifest_kills_r5e(self) -> None:
        """Mutant R5e killer: stray manifest that is not a table must produce typed finding."""
        with tempfile.TemporaryDirectory() as td:
            tmp_root = Path(td)
            root_manifest = tmp_root / "Cargo.toml"
            root_manifest.write_text(
                """[workspace]
resolver = "3"
members = ["crates/member"]

[workspace.lints.rust]
unsafe_code = "forbid"
""",
                encoding="utf-8",
            )
            m_dir = tmp_root / "crates" / "member"
            (m_dir / "src").mkdir(parents=True)
            (m_dir / "Cargo.toml").write_text(
                """[package]
name = "member"
version = "0.1.0"
edition = "2024"

[lints]
workspace = true
""",
                encoding="utf-8",
            )
            (m_dir / "src" / "lib.rs").write_text("#![forbid(unsafe_code)]\npub fn ok() {}\n", encoding="utf-8")

            stray_dir = tmp_root / "stray"
            stray_dir.mkdir(parents=True)
            (stray_dir / "Cargo.toml").write_text("dummy = 1\n", encoding="utf-8")

            orig_loads = tomllib.loads
            def mock_loads(s: str) -> Any:
                if "dummy = 1" in s:
                    return "not_a_dict"
                return orig_loads(s)

            with unittest.mock.patch("tomllib.loads", side_effect=mock_loads):
                findings = check_manifest_lints(
                    workspace_root=tmp_root,
                    packages=[],
                    workspace_members=set(),
                    root=tmp_root,
                )
                self.assertTrue(any(f.code == ERR_MANIFEST_LINT_NOT_FORBIDDEN and "must be a table" in f.message for f in findings))

    def test_planted_r5f_root_ws_members_non_list_kills_r5f(self) -> None:
        """Mutant R5f killer: root workspace members as non-list must produce typed finding."""
        with tempfile.TemporaryDirectory() as td:
            tmp_root = Path(td)
            root_manifest = tmp_root / "Cargo.toml"
            root_manifest.write_text(
                """[workspace]
resolver = "3"
members = "not_a_list"

[workspace.lints.rust]
unsafe_code = "forbid"
""",
                encoding="utf-8",
            )
            findings = check_manifest_lints(
                workspace_root=tmp_root,
                packages=[],
                workspace_members=set(),
                root=tmp_root,
            )
            self.assertTrue(any(f.code == ERR_MANIFEST_LINT_NOT_FORBIDDEN and f.location == "[workspace].members" for f in findings))

    def test_planted_b5i_and_b5j_stray_workspace_members_and_exclude_types(self) -> None:
        """Item 5: stray manifest with workspace.members = [1, 2] or workspace.exclude = 'x' gets typed finding."""
        with tempfile.TemporaryDirectory() as td:
            tmp_root = Path(td)
            root_manifest = tmp_root / "Cargo.toml"
            root_manifest.write_text(
                """[workspace]
resolver = "3"
members = ["crates/member"]

[workspace.lints.rust]
unsafe_code = "forbid"
""",
                encoding="utf-8",
            )
            m_dir = tmp_root / "crates" / "member"
            (m_dir / "src").mkdir(parents=True)
            (m_dir / "Cargo.toml").write_text(
                """[package]
name = "member"
version = "0.1.0"
edition = "2024"

[lints]
workspace = true
""",
                encoding="utf-8",
            )
            (m_dir / "src" / "lib.rs").write_text("#![forbid(unsafe_code)]\npub fn ok() {}\n", encoding="utf-8")

            # B5i: members = [1, 2]
            stray_i = tmp_root / "stray_i"
            stray_i.mkdir(parents=True)
            (stray_i / "Cargo.toml").write_text("[workspace]\nmembers = [1, 2]\n", encoding="utf-8")

            # B5j: exclude = "x"
            stray_j = tmp_root / "stray_j"
            stray_j.mkdir(parents=True)
            (stray_j / "Cargo.toml").write_text('[workspace]\nexclude = "x"\n', encoding="utf-8")

            is_valid, findings, _ = audit_unsafe_prohibition(root=tmp_root, manifest_path=root_manifest)
            self.assertFalse(is_valid, "Non-string members or non-list exclude must be caught")
            self.assertTrue(any(f.file == "stray_i/Cargo.toml" and f.location == "workspace.members" for f in findings))
            self.assertTrue(any(f.file == "stray_j/Cargo.toml" and f.location == "workspace.exclude" for f in findings))

    # --- Round 3 Item 1: Name-derived paths for example, test, bench without path (C5, D4, E3) ---

    def test_planted_c5_example_name_without_path_autoexamples_false_kills_c5(self) -> None:
        """Name-derived fallback for [[example]] name='ex' without path when autoexamples=false."""
        with tempfile.TemporaryDirectory() as td:
            tmp_root = Path(td)
            root_manifest = tmp_root / "Cargo.toml"
            root_manifest.write_text(
                """[workspace]
resolver = "3"
members = ["crates/member"]
exclude = ["extra"]

[workspace.lints.rust]
unsafe_code = "forbid"
""",
                encoding="utf-8",
            )
            m_dir = tmp_root / "crates" / "member"
            (m_dir / "src").mkdir(parents=True)
            (m_dir / "Cargo.toml").write_text(
                """[package]
name = "member"
version = "0.1.0"
edition = "2024"

[lints]
workspace = true
""",
                encoding="utf-8",
            )
            (m_dir / "src" / "lib.rs").write_text("#![forbid(unsafe_code)]\npub fn ok() {}\n", encoding="utf-8")

            # Non-member crate C5
            c_dir = tmp_root / "extra" / "c"
            (c_dir / "src").mkdir(parents=True)
            (c_dir / "examples").mkdir(parents=True)
            (c_dir / "Cargo.toml").write_text(
                """[package]
name = "c"
version = "0.1.0"
edition = "2024"
autoexamples = false

[[example]]
name = "ex"

[lints.rust]
unsafe_code = "forbid"
""",
                encoding="utf-8",
            )
            (c_dir / "src" / "lib.rs").write_text("#![forbid(unsafe_code)]\npub fn f() {}\n", encoding="utf-8")
            (c_dir / "examples" / "ex.rs").write_text("fn main() {}\n", encoding="utf-8")

            is_valid, findings, _ = audit_unsafe_prohibition(root=tmp_root, manifest_path=root_manifest)
            self.assertFalse(is_valid, "Plant C5: name-derived example without forbid must be refused")
            self.assertTrue(any(f.code == ERR_TARGET_ROOT_MISSING_FORBID and "extra/c/examples/ex.rs" in f.file for f in findings))

    def test_planted_d4_test_name_without_path_autotests_false_kills_d4(self) -> None:
        """Name-derived fallback for [[test]] name='t' without path when autotests=false."""
        with tempfile.TemporaryDirectory() as td:
            tmp_root = Path(td)
            root_manifest = tmp_root / "Cargo.toml"
            root_manifest.write_text(
                """[workspace]
resolver = "3"
members = ["crates/member"]
exclude = ["extra"]

[workspace.lints.rust]
unsafe_code = "forbid"
""",
                encoding="utf-8",
            )
            m_dir = tmp_root / "crates" / "member"
            (m_dir / "src").mkdir(parents=True)
            (m_dir / "Cargo.toml").write_text(
                """[package]
name = "member"
version = "0.1.0"
edition = "2024"

[lints]
workspace = true
""",
                encoding="utf-8",
            )
            (m_dir / "src" / "lib.rs").write_text("#![forbid(unsafe_code)]\npub fn ok() {}\n", encoding="utf-8")

            # Non-member crate D4
            c_dir = tmp_root / "extra" / "c"
            (c_dir / "src").mkdir(parents=True)
            (c_dir / "tests").mkdir(parents=True)
            (c_dir / "Cargo.toml").write_text(
                """[package]
name = "c"
version = "0.1.0"
edition = "2024"
autotests = false

[[test]]
name = "t"

[lints.rust]
unsafe_code = "forbid"
""",
                encoding="utf-8",
            )
            (c_dir / "src" / "lib.rs").write_text("#![forbid(unsafe_code)]\npub fn f() {}\n", encoding="utf-8")
            (c_dir / "tests" / "t.rs").write_text("fn main() {}\n", encoding="utf-8")

            is_valid, findings, _ = audit_unsafe_prohibition(root=tmp_root, manifest_path=root_manifest)
            self.assertFalse(is_valid, "Plant D4: name-derived test without forbid must be refused")
            self.assertTrue(any(f.code == ERR_TARGET_ROOT_MISSING_FORBID and "extra/c/tests/t.rs" in f.file for f in findings))

    def test_planted_e3_bench_name_without_path_autobenches_false_kills_e3(self) -> None:
        """Name-derived fallback for [[bench]] name='b' without path when autobenches=false."""
        with tempfile.TemporaryDirectory() as td:
            tmp_root = Path(td)
            root_manifest = tmp_root / "Cargo.toml"
            root_manifest.write_text(
                """[workspace]
resolver = "3"
members = ["crates/member"]
exclude = ["extra"]

[workspace.lints.rust]
unsafe_code = "forbid"
""",
                encoding="utf-8",
            )
            m_dir = tmp_root / "crates" / "member"
            (m_dir / "src").mkdir(parents=True)
            (m_dir / "Cargo.toml").write_text(
                """[package]
name = "member"
version = "0.1.0"
edition = "2024"

[lints]
workspace = true
""",
                encoding="utf-8",
            )
            (m_dir / "src" / "lib.rs").write_text("#![forbid(unsafe_code)]\npub fn ok() {}\n", encoding="utf-8")

            # Non-member crate E3
            c_dir = tmp_root / "extra" / "c"
            (c_dir / "src").mkdir(parents=True)
            (c_dir / "benches").mkdir(parents=True)
            (c_dir / "Cargo.toml").write_text(
                """[package]
name = "c"
version = "0.1.0"
edition = "2024"
autobenches = false

[[bench]]
name = "b"

[lints.rust]
unsafe_code = "forbid"
""",
                encoding="utf-8",
            )
            (c_dir / "src" / "lib.rs").write_text("#![forbid(unsafe_code)]\npub fn f() {}\n", encoding="utf-8")
            (c_dir / "benches" / "b.rs").write_text("fn main() {}\n", encoding="utf-8")

            is_valid, findings, _ = audit_unsafe_prohibition(root=tmp_root, manifest_path=root_manifest)
            self.assertFalse(is_valid, "Plant E3: name-derived bench without forbid must be refused")
            self.assertTrue(any(f.code == ERR_TARGET_ROOT_MISSING_FORBID and "extra/c/benches/b.rs" in f.file for f in findings))

    # --- Round 3 Item 2: CWD inside tests/test_x/ and fixtures/ ---

    def test_planted_cwd_inside_tests_test_x_unlisted_crate_emits_unregistered_finding(self) -> None:
        """CWD inside tests/test_x/ must not exempt unlisted crates from Unregistered finding."""
        with tempfile.TemporaryDirectory() as td:
            tmp_root = Path(td)
            root_manifest = tmp_root / "Cargo.toml"
            root_manifest.write_text(
                """[workspace]
resolver = "3"
members = ["crates/member"]

[workspace.lints.rust]
unsafe_code = "forbid"
""",
                encoding="utf-8",
            )
            m_dir = tmp_root / "crates" / "member"
            (m_dir / "src").mkdir(parents=True)
            (m_dir / "Cargo.toml").write_text(
                """[package]
name = "member"
version = "0.1.0"
edition = "2024"

[lints]
workspace = true
""",
                encoding="utf-8",
            )
            (m_dir / "src" / "lib.rs").write_text("#![forbid(unsafe_code)]\npub fn ok() {}\n", encoding="utf-8")

            # Unlisted compliant crate
            u_dir = tmp_root / "crates" / "unlisted"
            (u_dir / "src").mkdir(parents=True)
            (u_dir / "Cargo.toml").write_text(
                """[package]
name = "unlisted"
version = "0.1.0"
edition = "2024"

[lints.rust]
unsafe_code = "forbid"
""",
                encoding="utf-8",
            )
            (u_dir / "src" / "lib.rs").write_text("#![forbid(unsafe_code)]\npub fn f() {}\n", encoding="utf-8")

            nested_dir = tmp_root / "tests" / "test_x"
            nested_dir.mkdir(parents=True)

            old_cwd = os.getcwd()
            try:
                os.chdir(str(nested_dir))
                is_valid, findings, _ = audit_unsafe_prohibition(root=tmp_root, manifest_path=root_manifest)
                self.assertFalse(is_valid, "Unlisted crate must be caught when CWD is inside tests/test_x/")
                self.assertEqual({f.code for f in findings}, {ERR_MANIFEST_LINT_NOT_FORBIDDEN})
                self.assertEqual(len(findings), 1)
                self.assertEqual(findings[0].file, "crates/unlisted/Cargo.toml")
                self.assertIn("Unregistered crate 'unlisted'", findings[0].message)
            finally:
                os.chdir(old_cwd)

    def test_planted_cwd_inside_fixtures_unlisted_crate_emits_unregistered_finding(self) -> None:
        """CWD inside fixtures/ must not exempt unlisted crates from Unregistered finding."""
        with tempfile.TemporaryDirectory() as td:
            tmp_root = Path(td)
            root_manifest = tmp_root / "Cargo.toml"
            root_manifest.write_text(
                """[workspace]
resolver = "3"
members = ["crates/member"]

[workspace.lints.rust]
unsafe_code = "forbid"
""",
                encoding="utf-8",
            )
            m_dir = tmp_root / "crates" / "member"
            (m_dir / "src").mkdir(parents=True)
            (m_dir / "Cargo.toml").write_text(
                """[package]
name = "member"
version = "0.1.0"
edition = "2024"

[lints]
workspace = true
""",
                encoding="utf-8",
            )
            (m_dir / "src" / "lib.rs").write_text("#![forbid(unsafe_code)]\npub fn ok() {}\n", encoding="utf-8")

            # Unlisted compliant crate
            u_dir = tmp_root / "crates" / "unlisted"
            (u_dir / "src").mkdir(parents=True)
            (u_dir / "Cargo.toml").write_text(
                """[package]
name = "unlisted"
version = "0.1.0"
edition = "2024"

[lints.rust]
unsafe_code = "forbid"
""",
                encoding="utf-8",
            )
            (u_dir / "src" / "lib.rs").write_text("#![forbid(unsafe_code)]\npub fn f() {}\n", encoding="utf-8")

            fix_dir = tmp_root / "fixtures"
            fix_dir.mkdir(parents=True)

            old_cwd = os.getcwd()
            try:
                os.chdir(str(fix_dir))
                is_valid, findings, _ = audit_unsafe_prohibition(root=tmp_root, manifest_path=root_manifest)
                self.assertFalse(is_valid, "Unlisted crate must be caught when CWD is inside fixtures/")
                self.assertEqual({f.code for f in findings}, {ERR_MANIFEST_LINT_NOT_FORBIDDEN})
                self.assertEqual(len(findings), 1)
                self.assertEqual(findings[0].file, "crates/unlisted/Cargo.toml")
                self.assertIn("Unregistered crate 'unlisted'", findings[0].message)
            finally:
                os.chdir(old_cwd)

    # --- Round 3 Item 3: Kill M2b-bench, M2b-build, R-autobins-r1, autotests/autoexamples/autobenches/build, R-binname ---

    def test_planted_m2b_bench_meta_kills_m2b_bench_meta(self) -> None:
        """Mutant M2b-bench(meta) killer: member crate custom [[bench]] path missing forbid must be caught."""
        with tempfile.TemporaryDirectory() as td:
            tmp_root = Path(td)
            root_manifest = tmp_root / "Cargo.toml"
            root_manifest.write_text(
                """[workspace]
resolver = "3"
members = ["crates/member"]

[workspace.lints.rust]
unsafe_code = "forbid"
""",
                encoding="utf-8",
            )
            m_dir = tmp_root / "crates" / "member"
            (m_dir / "src").mkdir(parents=True)
            (m_dir / "src" / "lib.rs").write_text("#![forbid(unsafe_code)]\npub fn ok() {}\n", encoding="utf-8")
            (m_dir / "cbench").mkdir(parents=True)
            (m_dir / "Cargo.toml").write_text(
                """[package]
name = "member"
version = "0.1.0"
edition = "2024"

[lints]
workspace = true

[[bench]]
name = "my_bench"
path = "cbench/bench.rs"
""",
                encoding="utf-8",
            )
            (m_dir / "cbench" / "bench.rs").write_text("fn main() {}\n", encoding="utf-8")

            is_valid, findings, _ = audit_unsafe_prohibition(root=tmp_root, manifest_path=root_manifest)
            self.assertFalse(is_valid, "Member custom bench missing forbid must be caught")
            self.assertTrue(any(f.code == ERR_TARGET_ROOT_MISSING_FORBID and "crates/member/cbench/bench.rs" in f.file for f in findings))

    def test_planted_m2b_build_meta_kills_m2b_build_meta(self) -> None:
        """Mutant M2b-build(meta) killer: member crate custom build script path missing forbid must be caught."""
        with tempfile.TemporaryDirectory() as td:
            tmp_root = Path(td)
            root_manifest = tmp_root / "Cargo.toml"
            root_manifest.write_text(
                """[workspace]
resolver = "3"
members = ["crates/member"]

[workspace.lints.rust]
unsafe_code = "forbid"
""",
                encoding="utf-8",
            )
            m_dir = tmp_root / "crates" / "member"
            (m_dir / "src").mkdir(parents=True)
            (m_dir / "src" / "lib.rs").write_text("#![forbid(unsafe_code)]\npub fn ok() {}\n", encoding="utf-8")
            (m_dir / "tools").mkdir(parents=True)
            (m_dir / "Cargo.toml").write_text(
                """[package]
name = "member"
version = "0.1.0"
edition = "2024"
build = "tools/custom_gen.rs"

[lints]
workspace = true
""",
                encoding="utf-8",
            )
            (m_dir / "tools" / "custom_gen.rs").write_text("fn main() {}\n", encoding="utf-8")

            is_valid, findings, _ = audit_unsafe_prohibition(root=tmp_root, manifest_path=root_manifest)
            self.assertFalse(is_valid, "Member custom build script missing forbid must be caught")
            self.assertTrue(any(f.code == ERR_TARGET_ROOT_MISSING_FORBID and "crates/member/tools/custom_gen.rs" in f.file for f in findings))

    def test_planted_r_autobins_r1_kills_r_autobins_r1(self) -> None:
        """Mutant R-autobins-r1 killer: custom [[bin]] must not disable autodiscovery of src/main.rs."""
        with tempfile.TemporaryDirectory() as td:
            tmp_root = Path(td)
            root_manifest = tmp_root / "Cargo.toml"
            root_manifest.write_text(
                """[workspace]
resolver = "3"
members = ["crates/member"]
exclude = ["extra"]

[workspace.lints.rust]
unsafe_code = "forbid"
""",
                encoding="utf-8",
            )
            m_dir = tmp_root / "crates" / "member"
            (m_dir / "src").mkdir(parents=True)
            (m_dir / "Cargo.toml").write_text(
                """[package]
name = "member"
version = "0.1.0"
edition = "2024"

[lints]
workspace = true
""",
                encoding="utf-8",
            )
            (m_dir / "src" / "lib.rs").write_text("#![forbid(unsafe_code)]\npub fn ok() {}\n", encoding="utf-8")

            # Non-member crate with custom bin + missing forbid in src/main.rs
            c_dir = tmp_root / "extra" / "c"
            (c_dir / "src").mkdir(parents=True)
            (c_dir / "cbin").mkdir(parents=True)
            (c_dir / "Cargo.toml").write_text(
                """[package]
name = "c"
version = "0.1.0"
edition = "2024"

[[bin]]
name = "other"
path = "cbin/other.rs"

[lints.rust]
unsafe_code = "forbid"
""",
                encoding="utf-8",
            )
            (c_dir / "cbin" / "other.rs").write_text("#![forbid(unsafe_code)]\nfn main() {}\n", encoding="utf-8")
            (c_dir / "src" / "main.rs").write_text("fn main() {}\n", encoding="utf-8")

            is_valid, findings, _ = audit_unsafe_prohibition(root=tmp_root, manifest_path=root_manifest)
            self.assertFalse(is_valid, "Plant R-autobins-r1: autodiscovered src/main.rs missing forbid must be caught")
            self.assertTrue(any(f.code == ERR_TARGET_ROOT_MISSING_FORBID and "extra/c/src/main.rs" in f.file for f in findings))

    def test_planted_nonmember_autotests_kills_r_autotests(self) -> None:
        """Mutant R-autotests killer: non-member autotests directory scanning must not be forced to False."""
        with tempfile.TemporaryDirectory() as td:
            tmp_root = Path(td)
            root_manifest = tmp_root / "Cargo.toml"
            root_manifest.write_text(
                """[workspace]
resolver = "3"
members = ["crates/member"]
exclude = ["extra"]

[workspace.lints.rust]
unsafe_code = "forbid"
""",
                encoding="utf-8",
            )
            m_dir = tmp_root / "crates" / "member"
            (m_dir / "src").mkdir(parents=True)
            (m_dir / "Cargo.toml").write_text(
                """[package]
name = "member"
version = "0.1.0"
edition = "2024"

[lints]
workspace = true
""",
                encoding="utf-8",
            )
            (m_dir / "src" / "lib.rs").write_text("#![forbid(unsafe_code)]\npub fn ok() {}\n", encoding="utf-8")

            # Non-member crate with tests/t.rs lacking forbid
            c_dir = tmp_root / "extra" / "c"
            (c_dir / "src").mkdir(parents=True)
            (c_dir / "tests").mkdir(parents=True)
            (c_dir / "Cargo.toml").write_text(
                """[package]
name = "c"
version = "0.1.0"
edition = "2024"

[lints.rust]
unsafe_code = "forbid"
""",
                encoding="utf-8",
            )
            (c_dir / "src" / "lib.rs").write_text("#![forbid(unsafe_code)]\npub fn f() {}\n", encoding="utf-8")
            (c_dir / "tests" / "t.rs").write_text("fn main() {}\n", encoding="utf-8")

            is_valid, findings, _ = audit_unsafe_prohibition(root=tmp_root, manifest_path=root_manifest)
            self.assertFalse(is_valid, "Plant R-autotests: tests/t.rs missing forbid must be caught")
            self.assertTrue(any(f.code == ERR_TARGET_ROOT_MISSING_FORBID and "extra/c/tests/t.rs" in f.file for f in findings))

    def test_planted_nonmember_autoexamples_kills_r_autoexamples(self) -> None:
        """Mutant R-autoexamples killer: non-member autoexamples directory scanning must not be forced to False."""
        with tempfile.TemporaryDirectory() as td:
            tmp_root = Path(td)
            root_manifest = tmp_root / "Cargo.toml"
            root_manifest.write_text(
                """[workspace]
resolver = "3"
members = ["crates/member"]
exclude = ["extra"]

[workspace.lints.rust]
unsafe_code = "forbid"
""",
                encoding="utf-8",
            )
            m_dir = tmp_root / "crates" / "member"
            (m_dir / "src").mkdir(parents=True)
            (m_dir / "Cargo.toml").write_text(
                """[package]
name = "member"
version = "0.1.0"
edition = "2024"

[lints]
workspace = true
""",
                encoding="utf-8",
            )
            (m_dir / "src" / "lib.rs").write_text("#![forbid(unsafe_code)]\npub fn ok() {}\n", encoding="utf-8")

            # Non-member crate with examples/e.rs lacking forbid
            c_dir = tmp_root / "extra" / "c"
            (c_dir / "src").mkdir(parents=True)
            (c_dir / "examples").mkdir(parents=True)
            (c_dir / "Cargo.toml").write_text(
                """[package]
name = "c"
version = "0.1.0"
edition = "2024"

[lints.rust]
unsafe_code = "forbid"
""",
                encoding="utf-8",
            )
            (c_dir / "src" / "lib.rs").write_text("#![forbid(unsafe_code)]\npub fn f() {}\n", encoding="utf-8")
            (c_dir / "examples" / "e.rs").write_text("fn main() {}\n", encoding="utf-8")

            is_valid, findings, _ = audit_unsafe_prohibition(root=tmp_root, manifest_path=root_manifest)
            self.assertFalse(is_valid, "Plant R-autoexamples: examples/e.rs missing forbid must be caught")
            self.assertTrue(any(f.code == ERR_TARGET_ROOT_MISSING_FORBID and "extra/c/examples/e.rs" in f.file for f in findings))

    def test_planted_nonmember_autobenches_kills_r_autobenches(self) -> None:
        """Mutant R-autobenches killer: non-member autobenches directory scanning must not be forced to False."""
        with tempfile.TemporaryDirectory() as td:
            tmp_root = Path(td)
            root_manifest = tmp_root / "Cargo.toml"
            root_manifest.write_text(
                """[workspace]
resolver = "3"
members = ["crates/member"]
exclude = ["extra"]

[workspace.lints.rust]
unsafe_code = "forbid"
""",
                encoding="utf-8",
            )
            m_dir = tmp_root / "crates" / "member"
            (m_dir / "src").mkdir(parents=True)
            (m_dir / "Cargo.toml").write_text(
                """[package]
name = "member"
version = "0.1.0"
edition = "2024"

[lints]
workspace = true
""",
                encoding="utf-8",
            )
            (m_dir / "src" / "lib.rs").write_text("#![forbid(unsafe_code)]\npub fn ok() {}\n", encoding="utf-8")

            # Non-member crate with benches/b.rs lacking forbid
            c_dir = tmp_root / "extra" / "c"
            (c_dir / "src").mkdir(parents=True)
            (c_dir / "benches").mkdir(parents=True)
            (c_dir / "Cargo.toml").write_text(
                """[package]
name = "c"
version = "0.1.0"
edition = "2024"

[lints.rust]
unsafe_code = "forbid"
""",
                encoding="utf-8",
            )
            (c_dir / "src" / "lib.rs").write_text("#![forbid(unsafe_code)]\npub fn f() {}\n", encoding="utf-8")
            (c_dir / "benches" / "b.rs").write_text("fn main() {}\n", encoding="utf-8")

            is_valid, findings, _ = audit_unsafe_prohibition(root=tmp_root, manifest_path=root_manifest)
            self.assertFalse(is_valid, "Plant R-autobenches: benches/b.rs missing forbid must be caught")
            self.assertTrue(any(f.code == ERR_TARGET_ROOT_MISSING_FORBID and "extra/c/benches/b.rs" in f.file for f in findings))

    def test_planted_nonmember_build_kills_r_build(self) -> None:
        """Mutant R-build killer: non-member build_enabled scanning must not be forced to False."""
        with tempfile.TemporaryDirectory() as td:
            tmp_root = Path(td)
            root_manifest = tmp_root / "Cargo.toml"
            root_manifest.write_text(
                """[workspace]
resolver = "3"
members = ["crates/member"]
exclude = ["extra"]

[workspace.lints.rust]
unsafe_code = "forbid"
""",
                encoding="utf-8",
            )
            m_dir = tmp_root / "crates" / "member"
            (m_dir / "src").mkdir(parents=True)
            (m_dir / "Cargo.toml").write_text(
                """[package]
name = "member"
version = "0.1.0"
edition = "2024"

[lints]
workspace = true
""",
                encoding="utf-8",
            )
            (m_dir / "src" / "lib.rs").write_text("#![forbid(unsafe_code)]\npub fn ok() {}\n", encoding="utf-8")

            # Non-member crate with build.rs lacking forbid
            c_dir = tmp_root / "extra" / "c"
            (c_dir / "src").mkdir(parents=True)
            (c_dir / "Cargo.toml").write_text(
                """[package]
name = "c"
version = "0.1.0"
edition = "2024"

[lints.rust]
unsafe_code = "forbid"
""",
                encoding="utf-8",
            )
            (c_dir / "src" / "lib.rs").write_text("#![forbid(unsafe_code)]\npub fn f() {}\n", encoding="utf-8")
            (c_dir / "build.rs").write_text("fn main() {}\n", encoding="utf-8")

            is_valid, findings, _ = audit_unsafe_prohibition(root=tmp_root, manifest_path=root_manifest)
            self.assertFalse(is_valid, "Plant R-build: build.rs missing forbid must be caught")
            self.assertTrue(any(f.code == ERR_TARGET_ROOT_MISSING_FORBID and "extra/c/build.rs" in f.file for f in findings))

    def test_planted_nonmember_build_true_kills_q3a(self) -> None:
        """Mutant Q3a killer: non-member build_enabled scanning must flag build.rs when build=true is explicit."""
        with tempfile.TemporaryDirectory() as td:
            tmp_root = Path(td)
            root_manifest = tmp_root / "Cargo.toml"
            root_manifest.write_text(
                """[workspace]
resolver = "3"
members = ["crates/member"]
exclude = ["extra"]

[workspace.lints.rust]
unsafe_code = "forbid"
""",
                encoding="utf-8",
            )
            m_dir = tmp_root / "crates" / "member"
            (m_dir / "src").mkdir(parents=True)
            (m_dir / "Cargo.toml").write_text(
                """[package]
name = "member"
version = "0.1.0"
edition = "2024"

[lints]
workspace = true
""",
                encoding="utf-8",
            )
            (m_dir / "src" / "lib.rs").write_text("#![forbid(unsafe_code)]\npub fn ok() {}\n", encoding="utf-8")

            # Non-member crate with explicit build = true and build.rs lacking forbid
            c_dir = tmp_root / "extra" / "c"
            (c_dir / "src").mkdir(parents=True)
            (c_dir / "Cargo.toml").write_text(
                """[package]
name = "c"
version = "0.1.0"
edition = "2024"
build = true

[lints.rust]
unsafe_code = "forbid"
""",
                encoding="utf-8",
            )
            (c_dir / "src" / "lib.rs").write_text("#![forbid(unsafe_code)]\npub fn f() {}\n", encoding="utf-8")
            (c_dir / "build.rs").write_text("fn main() {}\n", encoding="utf-8")

            is_valid, findings, _ = audit_unsafe_prohibition(root=tmp_root, manifest_path=root_manifest)
            self.assertFalse(is_valid, "Plant Q3a: non-member build=true with build.rs missing forbid must be caught")
            self.assertTrue(any(f.code == ERR_TARGET_ROOT_MISSING_FORBID and "extra/c/build.rs" in f.file for f in findings))

    def test_planted_bin_name_only_no_path_kills_r_binname(self) -> None:
        """Mutant R-binname killer: [[bin]] candidate loop must not be dropped."""
        with tempfile.TemporaryDirectory() as td:
            tmp_root = Path(td)
            root_manifest = tmp_root / "Cargo.toml"
            root_manifest.write_text(
                """[workspace]
resolver = "3"
members = ["crates/member"]
exclude = ["extra"]

[workspace.lints.rust]
unsafe_code = "forbid"
""",
                encoding="utf-8",
            )
            m_dir = tmp_root / "crates" / "member"
            (m_dir / "src").mkdir(parents=True)
            (m_dir / "Cargo.toml").write_text(
                """[package]
name = "member"
version = "0.1.0"
edition = "2024"

[lints]
workspace = true
""",
                encoding="utf-8",
            )
            (m_dir / "src" / "lib.rs").write_text("#![forbid(unsafe_code)]\npub fn ok() {}\n", encoding="utf-8")

            # Non-member crate with autobins=false, [[bin]] name="foo" no path, src/bin/foo.rs lacking forbid
            c_dir = tmp_root / "extra" / "c"
            (c_dir / "src" / "bin").mkdir(parents=True)
            (c_dir / "Cargo.toml").write_text(
                """[package]
name = "c"
version = "0.1.0"
edition = "2024"
autobins = false

[[bin]]
name = "foo"

[lints.rust]
unsafe_code = "forbid"
""",
                encoding="utf-8",
            )
            (c_dir / "src" / "lib.rs").write_text("#![forbid(unsafe_code)]\npub fn f() {}\n", encoding="utf-8")
            (c_dir / "src" / "bin" / "foo.rs").write_text("fn main() {}\n", encoding="utf-8")

            is_valid, findings, _ = audit_unsafe_prohibition(root=tmp_root, manifest_path=root_manifest)
            self.assertFalse(is_valid, "Plant R-binname: [[bin]] name='foo' without forbid must be caught")
            self.assertTrue(any(f.code == ERR_TARGET_ROOT_MISSING_FORBID and "extra/c/src/bin/foo.rs" in f.file for f in findings))

    # --- fss-na476: 7 f2plants rows that cargo does not build must not be flagged ---

    def test_f2plant_nonmember_b3_autolib_false_stale_lib_not_flagged(self) -> None:
        """Non-member crate with autolib=false does not build src/lib.rs; missing forbid is not flagged."""
        with tempfile.TemporaryDirectory() as td:
            tmp_root = Path(td)
            root_manifest = tmp_root / "Cargo.toml"
            root_manifest.write_text(
                """[workspace]
resolver = "3"
members = ["crates/member"]
exclude = ["extra"]

[workspace.lints.rust]
unsafe_code = "forbid"
""",
                encoding="utf-8",
            )
            m_dir = tmp_root / "crates" / "member"
            (m_dir / "src").mkdir(parents=True)
            (m_dir / "Cargo.toml").write_text(
                """[package]
name = "member"
version = "0.1.0"
edition = "2024"

[lints]
workspace = true
""",
                encoding="utf-8",
            )
            (m_dir / "src" / "lib.rs").write_text("#![forbid(unsafe_code)]\npub fn ok() {}\n", encoding="utf-8")

            c_dir = tmp_root / "extra" / "c"
            (c_dir / "src").mkdir(parents=True)
            (c_dir / "Cargo.toml").write_text(
                """[package]
name = "c"
version = "0.1.0"
edition = "2024"
autolib = false

[lints.rust]
unsafe_code = "forbid"
""",
                encoding="utf-8",
            )
            (c_dir / "src" / "main.rs").write_text("#![forbid(unsafe_code)]\nfn main() {}\n", encoding="utf-8")
            # src/lib.rs lacks forbid, but autolib=false so cargo does not build it
            (c_dir / "src" / "lib.rs").write_text("pub fn stale_lib() {}\n", encoding="utf-8")

            is_valid, findings, _ = audit_unsafe_prohibition(root=tmp_root, manifest_path=root_manifest)
            self.assertTrue(is_valid, f"Expected valid when non-member autolib=false, got: {findings}")
            self.assertEqual(findings, [])

    def test_f2plant_nonmember_f4_custom_build_stale_build_rs_not_flagged(self) -> None:
        """Non-member crate with custom build path ignores stale build.rs; missing forbid on build.rs is not flagged."""
        with tempfile.TemporaryDirectory() as td:
            tmp_root = Path(td)
            root_manifest = tmp_root / "Cargo.toml"
            root_manifest.write_text(
                """[workspace]
resolver = "3"
members = ["crates/member"]
exclude = ["extra"]

[workspace.lints.rust]
unsafe_code = "forbid"
""",
                encoding="utf-8",
            )
            m_dir = tmp_root / "crates" / "member"
            (m_dir / "src").mkdir(parents=True)
            (m_dir / "Cargo.toml").write_text(
                """[package]
name = "member"
version = "0.1.0"
edition = "2024"

[lints]
workspace = true
""",
                encoding="utf-8",
            )
            (m_dir / "src" / "lib.rs").write_text("#![forbid(unsafe_code)]\npub fn ok() {}\n", encoding="utf-8")

            c_dir = tmp_root / "extra" / "c"
            (c_dir / "src").mkdir(parents=True)
            (c_dir / "tools").mkdir(parents=True)
            (c_dir / "Cargo.toml").write_text(
                """[package]
name = "c"
version = "0.1.0"
edition = "2024"
build = "tools/gen.rs"

[lints.rust]
unsafe_code = "forbid"
""",
                encoding="utf-8",
            )
            (c_dir / "src" / "lib.rs").write_text("#![forbid(unsafe_code)]\npub fn f() {}\n", encoding="utf-8")
            (c_dir / "tools" / "gen.rs").write_text("#![forbid(unsafe_code)]\nfn main() {}\n", encoding="utf-8")
            # stale build.rs lacks forbid, but custom build="tools/gen.rs" means cargo does not build build.rs
            (c_dir / "build.rs").write_text("fn main() {}\n", encoding="utf-8")

            is_valid, findings, _ = audit_unsafe_prohibition(root=tmp_root, manifest_path=root_manifest)
            self.assertTrue(is_valid, f"Expected valid when non-member custom build ignores build.rs, got: {findings}")
            self.assertEqual(findings, [])

    def test_f2plant_member_c3_autoexamples_false_stale_example_not_flagged(self) -> None:
        """Workspace member crate with autoexamples=false does not build examples/; missing forbid is not flagged."""
        with tempfile.TemporaryDirectory() as td:
            tmp_root = Path(td)
            root_manifest = tmp_root / "Cargo.toml"
            root_manifest.write_text(
                """[workspace]
resolver = "3"
members = ["crates/member"]

[workspace.lints.rust]
unsafe_code = "forbid"
""",
                encoding="utf-8",
            )
            m_dir = tmp_root / "crates" / "member"
            (m_dir / "src").mkdir(parents=True)
            (m_dir / "examples").mkdir(parents=True)
            (m_dir / "Cargo.toml").write_text(
                """[package]
name = "member"
version = "0.1.0"
edition = "2024"
autoexamples = false

[lints]
workspace = true
""",
                encoding="utf-8",
            )
            (m_dir / "src" / "lib.rs").write_text("#![forbid(unsafe_code)]\npub fn ok() {}\n", encoding="utf-8")
            # examples/e.rs lacks forbid, but autoexamples=false so cargo does not build it
            (m_dir / "examples" / "e.rs").write_text("fn main() {}\n", encoding="utf-8")

            is_valid, findings, _ = audit_unsafe_prohibition(root=tmp_root, manifest_path=root_manifest)
            self.assertTrue(is_valid, f"Expected valid when member autoexamples=false, got: {findings}")
            self.assertEqual(findings, [])

    def test_f2plant_member_d3_autotests_false_stale_test_not_flagged(self) -> None:
        """Workspace member crate with autotests=false does not build tests/; missing forbid is not flagged."""
        with tempfile.TemporaryDirectory() as td:
            tmp_root = Path(td)
            root_manifest = tmp_root / "Cargo.toml"
            root_manifest.write_text(
                """[workspace]
resolver = "3"
members = ["crates/member"]

[workspace.lints.rust]
unsafe_code = "forbid"
""",
                encoding="utf-8",
            )
            m_dir = tmp_root / "crates" / "member"
            (m_dir / "src").mkdir(parents=True)
            (m_dir / "tests").mkdir(parents=True)
            (m_dir / "Cargo.toml").write_text(
                """[package]
name = "member"
version = "0.1.0"
edition = "2024"
autotests = false

[lints]
workspace = true
""",
                encoding="utf-8",
            )
            (m_dir / "src" / "lib.rs").write_text("#![forbid(unsafe_code)]\npub fn ok() {}\n", encoding="utf-8")
            # tests/t.rs lacks forbid, but autotests=false so cargo does not build it
            (m_dir / "tests" / "t.rs").write_text("fn main() {}\n", encoding="utf-8")

            is_valid, findings, _ = audit_unsafe_prohibition(root=tmp_root, manifest_path=root_manifest)
            self.assertTrue(is_valid, f"Expected valid when member autotests=false, got: {findings}")
            self.assertEqual(findings, [])

    def test_f2plant_member_e2_autobenches_false_stale_bench_not_flagged(self) -> None:
        """Workspace member crate with autobenches=false does not build benches/; missing forbid is not flagged."""
        with tempfile.TemporaryDirectory() as td:
            tmp_root = Path(td)
            root_manifest = tmp_root / "Cargo.toml"
            root_manifest.write_text(
                """[workspace]
resolver = "3"
members = ["crates/member"]

[workspace.lints.rust]
unsafe_code = "forbid"
""",
                encoding="utf-8",
            )
            m_dir = tmp_root / "crates" / "member"
            (m_dir / "src").mkdir(parents=True)
            (m_dir / "benches").mkdir(parents=True)
            (m_dir / "Cargo.toml").write_text(
                """[package]
name = "member"
version = "0.1.0"
edition = "2024"
autobenches = false

[lints]
workspace = true
""",
                encoding="utf-8",
            )
            (m_dir / "src" / "lib.rs").write_text("#![forbid(unsafe_code)]\npub fn ok() {}\n", encoding="utf-8")
            # benches/b.rs lacks forbid, but autobenches=false so cargo does not build it
            (m_dir / "benches" / "b.rs").write_text("fn main() {}\n", encoding="utf-8")

            is_valid, findings, _ = audit_unsafe_prohibition(root=tmp_root, manifest_path=root_manifest)
            self.assertTrue(is_valid, f"Expected valid when member autobenches=false, got: {findings}")
            self.assertEqual(findings, [])

    def test_f2plant_member_f2_build_false_stale_build_rs_not_flagged(self) -> None:
        """Workspace member crate with build=false does not build build.rs; missing forbid is not flagged."""
        with tempfile.TemporaryDirectory() as td:
            tmp_root = Path(td)
            root_manifest = tmp_root / "Cargo.toml"
            root_manifest.write_text(
                """[workspace]
resolver = "3"
members = ["crates/member"]

[workspace.lints.rust]
unsafe_code = "forbid"
""",
                encoding="utf-8",
            )
            m_dir = tmp_root / "crates" / "member"
            (m_dir / "src").mkdir(parents=True)
            (m_dir / "Cargo.toml").write_text(
                """[package]
name = "member"
version = "0.1.0"
edition = "2024"
build = false

[lints]
workspace = true
""",
                encoding="utf-8",
            )
            (m_dir / "src" / "lib.rs").write_text("#![forbid(unsafe_code)]\npub fn ok() {}\n", encoding="utf-8")
            # build.rs lacks forbid, but build=false so cargo does not build it
            (m_dir / "build.rs").write_text("fn main() {}\n", encoding="utf-8")

            is_valid, findings, _ = audit_unsafe_prohibition(root=tmp_root, manifest_path=root_manifest)
            self.assertTrue(is_valid, f"Expected valid when member build=false, got: {findings}")
            self.assertEqual(findings, [])

    def test_f2plant_member_f4_custom_build_stale_build_rs_not_flagged(self) -> None:
        """Workspace member crate with custom build path ignores build.rs; missing forbid on build.rs is not flagged."""
        with tempfile.TemporaryDirectory() as td:
            tmp_root = Path(td)
            root_manifest = tmp_root / "Cargo.toml"
            root_manifest.write_text(
                """[workspace]
resolver = "3"
members = ["crates/member"]

[workspace.lints.rust]
unsafe_code = "forbid"
""",
                encoding="utf-8",
            )
            m_dir = tmp_root / "crates" / "member"
            (m_dir / "src").mkdir(parents=True)
            (m_dir / "tools").mkdir(parents=True)
            (m_dir / "Cargo.toml").write_text(
                """[package]
name = "member"
version = "0.1.0"
edition = "2024"
build = "tools/gen.rs"

[lints]
workspace = true
""",
                encoding="utf-8",
            )
            (m_dir / "src" / "lib.rs").write_text("#![forbid(unsafe_code)]\npub fn ok() {}\n", encoding="utf-8")
            (m_dir / "tools" / "gen.rs").write_text("#![forbid(unsafe_code)]\nfn main() {}\n", encoding="utf-8")
            # build.rs lacks forbid, but build="tools/gen.rs" so cargo does not build build.rs
            (m_dir / "build.rs").write_text("fn main() {}\n", encoding="utf-8")

            is_valid, findings, _ = audit_unsafe_prohibition(root=tmp_root, manifest_path=root_manifest)
            self.assertTrue(is_valid, f"Expected valid when member custom build ignores build.rs, got: {findings}")
            self.assertEqual(findings, [])

    def test_planted_member_autoexamples_false_declared_example_flagged_kills_q2d(self) -> None:
        """Mutant Q2d killer: member with autoexamples=false but declared [[example]] (name-only and explicit path) must be flagged."""
        with tempfile.TemporaryDirectory() as td:
            tmp_root = Path(td)
            root_manifest = tmp_root / "Cargo.toml"
            root_manifest.write_text(
                """[workspace]
resolver = "3"
members = ["crates/member"]

[workspace.lints.rust]
unsafe_code = "forbid"
""",
                encoding="utf-8",
            )
            m_dir = tmp_root / "crates" / "member"
            (m_dir / "src").mkdir(parents=True)
            (m_dir / "examples").mkdir(parents=True)
            (m_dir / "Cargo.toml").write_text(
                """[package]
name = "member"
version = "0.1.0"
edition = "2024"
autoexamples = false

[lints]
workspace = true

[[example]]
name = "ex_name"

[[example]]
name = "ex_path"
path = "examples/custom_ex.rs"
""",
                encoding="utf-8",
            )
            (m_dir / "src" / "lib.rs").write_text("#![forbid(unsafe_code)]\npub fn ok() {}\n", encoding="utf-8")
            (m_dir / "examples" / "ex_name.rs").write_text("fn main() {}\n", encoding="utf-8")
            (m_dir / "examples" / "custom_ex.rs").write_text("fn main() {}\n", encoding="utf-8")

            is_valid, findings, _ = audit_unsafe_prohibition(root=tmp_root, manifest_path=root_manifest)
            self.assertFalse(is_valid, "Declared examples on member with autoexamples=false must be flagged when missing forbid")
            flagged_files = {f.file for f in findings if f.code == ERR_TARGET_ROOT_MISSING_FORBID}
            self.assertTrue(any("crates/member/examples/ex_name.rs" in f for f in flagged_files), f"ex_name.rs not flagged in {flagged_files}")
            self.assertTrue(any("crates/member/examples/custom_ex.rs" in f for f in flagged_files), f"custom_ex.rs not flagged in {flagged_files}")

    def test_planted_member_autotests_false_declared_test_flagged_kills_q2d(self) -> None:
        """Mutant Q2d killer: member with autotests=false but declared [[test]] (name-only and explicit path) must be flagged."""
        with tempfile.TemporaryDirectory() as td:
            tmp_root = Path(td)
            root_manifest = tmp_root / "Cargo.toml"
            root_manifest.write_text(
                """[workspace]
resolver = "3"
members = ["crates/member"]

[workspace.lints.rust]
unsafe_code = "forbid"
""",
                encoding="utf-8",
            )
            m_dir = tmp_root / "crates" / "member"
            (m_dir / "src").mkdir(parents=True)
            (m_dir / "tests").mkdir(parents=True)
            (m_dir / "Cargo.toml").write_text(
                """[package]
name = "member"
version = "0.1.0"
edition = "2024"
autotests = false

[lints]
workspace = true

[[test]]
name = "t_name"

[[test]]
name = "t_path"
path = "tests/custom_t.rs"
""",
                encoding="utf-8",
            )
            (m_dir / "src" / "lib.rs").write_text("#![forbid(unsafe_code)]\npub fn ok() {}\n", encoding="utf-8")
            (m_dir / "tests" / "t_name.rs").write_text("fn main() {}\n", encoding="utf-8")
            (m_dir / "tests" / "custom_t.rs").write_text("fn main() {}\n", encoding="utf-8")

            is_valid, findings, _ = audit_unsafe_prohibition(root=tmp_root, manifest_path=root_manifest)
            self.assertFalse(is_valid, "Declared tests on member with autotests=false must be flagged when missing forbid")
            flagged_files = {f.file for f in findings if f.code == ERR_TARGET_ROOT_MISSING_FORBID}
            self.assertTrue(any("crates/member/tests/t_name.rs" in f for f in flagged_files), f"t_name.rs not flagged in {flagged_files}")
            self.assertTrue(any("crates/member/tests/custom_t.rs" in f for f in flagged_files), f"custom_t.rs not flagged in {flagged_files}")

    def test_planted_member_autobenches_false_declared_bench_flagged_kills_q2d(self) -> None:
        """Mutant Q2d killer: member with autobenches=false but declared [[bench]] (name-only and explicit path) must be flagged."""
        with tempfile.TemporaryDirectory() as td:
            tmp_root = Path(td)
            root_manifest = tmp_root / "Cargo.toml"
            root_manifest.write_text(
                """[workspace]
resolver = "3"
members = ["crates/member"]

[workspace.lints.rust]
unsafe_code = "forbid"
""",
                encoding="utf-8",
            )
            m_dir = tmp_root / "crates" / "member"
            (m_dir / "src").mkdir(parents=True)
            (m_dir / "benches").mkdir(parents=True)
            (m_dir / "Cargo.toml").write_text(
                """[package]
name = "member"
version = "0.1.0"
edition = "2024"
autobenches = false

[lints]
workspace = true

[[bench]]
name = "b_name"

[[bench]]
name = "b_path"
path = "benches/custom_b.rs"
""",
                encoding="utf-8",
            )
            (m_dir / "src" / "lib.rs").write_text("#![forbid(unsafe_code)]\npub fn ok() {}\n", encoding="utf-8")
            (m_dir / "benches" / "b_name.rs").write_text("fn main() {}\n", encoding="utf-8")
            (m_dir / "benches" / "custom_b.rs").write_text("fn main() {}\n", encoding="utf-8")

            is_valid, findings, _ = audit_unsafe_prohibition(root=tmp_root, manifest_path=root_manifest)
            self.assertFalse(is_valid, "Declared benches on member with autobenches=false must be flagged when missing forbid")
            flagged_files = {f.file for f in findings if f.code == ERR_TARGET_ROOT_MISSING_FORBID}
            self.assertTrue(any("crates/member/benches/b_name.rs" in f for f in flagged_files), f"b_name.rs not flagged in {flagged_files}")
            self.assertTrue(any("crates/member/benches/custom_b.rs" in f for f in flagged_files), f"custom_b.rs not flagged in {flagged_files}")


if __name__ == "__main__":
    unittest.main()
