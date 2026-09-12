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
import subprocess
import sys
import tempfile
import unittest
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
        self.assertEqual(summary["crate_count"], 6)
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
            codes = [f.code for f in findings]
            self.assertIn(ERR_TARGET_ROOT_MISSING_FORBID, codes)
            self.assertTrue(any("lacks unconditional #![forbid(unsafe_code)]" in f.message for f in findings))

    def test_planted_bin_root_missing_forbid_fails(self) -> None:
        """bin root missing #![forbid(unsafe_code)] fails with ERR_TARGET_ROOT_MISSING_FORBID."""
        with tempfile.TemporaryDirectory() as td:
            tmp_root = Path(td)
            manifest = create_minimal_valid_crate(tmp_root)
            (tmp_root / "src" / "main.rs").write_text("fn main() {}\n", encoding="utf-8")

            is_valid, findings, _ = audit_unsafe_prohibition(root=tmp_root, manifest_path=manifest)
            self.assertFalse(is_valid)
            codes = [f.code for f in findings]
            self.assertIn(ERR_TARGET_ROOT_MISSING_FORBID, codes)

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
            codes = [f.code for f in findings]
            self.assertIn(ERR_TARGET_ROOT_MISSING_FORBID, codes)

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
            codes = [f.code for f in findings]
            self.assertIn(ERR_TARGET_ROOT_MISSING_FORBID, codes)

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
            codes = [f.code for f in findings]
            self.assertIn(ERR_TARGET_ROOT_MISSING_FORBID, codes)

    def test_planted_build_script_missing_forbid_fails(self) -> None:
        """build script (build.rs) missing #![forbid(unsafe_code)] fails with ERR_TARGET_ROOT_MISSING_FORBID."""
        with tempfile.TemporaryDirectory() as td:
            tmp_root = Path(td)
            manifest = create_minimal_valid_crate(tmp_root)
            (tmp_root / "build.rs").write_text("fn main() {}\n", encoding="utf-8")

            is_valid, findings, _ = audit_unsafe_prohibition(root=tmp_root, manifest_path=manifest)
            self.assertFalse(is_valid)
            codes = [f.code for f in findings]
            self.assertIn(ERR_TARGET_ROOT_MISSING_FORBID, codes)

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
            codes = [f.code for f in findings]
            self.assertIn(ERR_TARGET_ROOT_MISSING_FORBID, codes)

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
            codes = [f.code for f in findings]
            self.assertIn(ERR_TARGET_ROOT_MISSING_FORBID, codes)


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
            codes = [f.code for f in findings]
            self.assertIn(ERR_UNSAFE_ATTRIBUTE_PERMITTED, codes)

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
            codes = [f.code for f in findings]
            self.assertIn(ERR_UNSAFE_ATTRIBUTE_PERMITTED, codes)

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
            codes = [f.code for f in findings]
            self.assertIn(ERR_UNSAFE_ATTRIBUTE_PERMITTED, codes)

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
            codes = [f.code for f in findings]
            self.assertIn(ERR_UNSAFE_ATTRIBUTE_PERMITTED, codes)

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
            codes = [f.code for f in findings]
            self.assertIn(ERR_UNSAFE_ATTRIBUTE_PERMITTED, codes)


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
            codes = [f.code for f in findings]
            self.assertIn(ERR_UNSAFE_CONSTRUCT_DETECTED, codes)
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
            codes = [f.code for f in findings]
            self.assertIn(ERR_UNSAFE_CONSTRUCT_DETECTED, codes)
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
            codes = [f.code for f in findings]
            self.assertIn(ERR_UNSAFE_CONSTRUCT_DETECTED, codes)
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
            codes = [f.code for f in findings]
            self.assertIn(ERR_UNSAFE_CONSTRUCT_DETECTED, codes)
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
            codes = [f.code for f in findings]
            self.assertIn(ERR_UNSAFE_CONSTRUCT_DETECTED, codes)

    def test_comments_and_strings_with_unsafe_word_pass(self) -> None:
        """English comments and string literals mentioning 'unsafe' do not trigger false positives."""
        with tempfile.TemporaryDirectory() as td:
            tmp_root = Path(td)
            manifest = create_minimal_valid_crate(tmp_root)
            (tmp_root / "src" / "lib.rs").write_text(
                """#![forbid(unsafe_code)]
// This comment discusses unsafe blocks and unsafe fn behavior.
/* A block comment with unsafe { nested /* comment with unsafe impl */ } */
pub fn safe_function() -> &'static str {
    let msg = "unsafe { do_something(); }";
    let raw = r#"unsafe fn fake() {}"#;
    let _ = 'u';
    msg
}
""",
                encoding="utf-8",
            )

            is_valid, findings, _ = audit_unsafe_prohibition(root=tmp_root, manifest_path=manifest)
            self.assertTrue(
                is_valid,
                f"Comments/strings should not trigger errors, got: {[f.message for f in findings]}",
            )
            self.assertEqual(len(findings), 0)


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
            codes = [f.code for f in findings]
            self.assertIn(ERR_MANIFEST_LINT_NOT_FORBIDDEN, codes)

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
            codes = [f.code for f in findings]
            self.assertIn(ERR_MANIFEST_LINT_NOT_FORBIDDEN, codes)

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
            codes = [f.code for f in findings]
            self.assertIn(ERR_MANIFEST_LINT_NOT_FORBIDDEN, codes)

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
            codes = [f.code for f in findings]
            self.assertIn(ERR_MANIFEST_LINT_NOT_FORBIDDEN, codes)


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
            codes = [f.code for f in findings]
            self.assertIn(ERR_METADATA_UNREADABLE, codes)

    def test_planted_missing_cargo_toml_fails(self) -> None:
        """Missing Cargo.toml fails with ERR_METADATA_UNREADABLE."""
        with tempfile.TemporaryDirectory() as td:
            tmp_root = Path(td)
            manifest = tmp_root / "nonexistent" / "Cargo.toml"

            is_valid, findings, _ = audit_unsafe_prohibition(root=tmp_root, manifest_path=manifest)
            self.assertFalse(is_valid)
            codes = [f.code for f in findings]
            self.assertIn(ERR_METADATA_UNREADABLE, codes)

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


if __name__ == "__main__":
    unittest.main()
