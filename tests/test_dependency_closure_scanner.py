#!/usr/bin/env python3
"""Planted-negative and positive test suite for dependency-closure scanner (fss-x4a.26.1 / FSS-181).

Enforces the dependency-closure doctrine from AGENTS.md, docs/DEPENDENCY_CONSTITUTION.md,
and architecture/dependency_allowlist.toml:
- Closed universe: every crate in resolved dependency closure must be allowlisted.
- Full closure enumeration from Cargo.lock and cargo metadata across all targets,
  features, build-dependencies, and dev-dependencies.
- Fail closed with typed error codes on:
  * unallowlisted crates (ERR-DEP-CLOSURE-UNALLOWLISTED-CRATE-001)
  * forbidden crates (ERR-DEP-CLOSURE-FORBIDDEN-CRATE-001)
  * version or source mismatches (ERR-DEP-CLOSURE-VERSION-SOURCE-MISMATCH-001)
  * unallowlisted git or escaping path dependencies (ERR-DEP-CLOSURE-UNALLOWLISTED-SOURCE-001)
  * unreadable metadata or missing/malformed lockfile (ERR-DEP-CLOSURE-METADATA-UNREADABLE-001)
  * empty or degenerate allowlist (ERR-DEP-CLOSURE-EMPTY-ALLOWLIST-001)
- Honest reporting of declared-but-unresolved runtime: Cargo.toml names sole_async_runtime = "asupersync",
  reported honestly (STATUS-DEP-CLOSURE-DECLARED-RUNTIME-UNRESOLVED-001) and never silently passed.
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
    from dependency_closure_scanner import (
        ERR_DECLARED_RUNTIME_UNRESOLVED,
        ERR_EMPTY_ALLOWLIST,
        ERR_FORBIDDEN_CRATE,
        ERR_METADATA_UNREADABLE,
        ERR_UNALLOWLISTED_CRATE,
        ERR_UNALLOWLISTED_SOURCE,
        ERR_VERSION_SOURCE_MISMATCH,
        STATUS_DECLARED_RUNTIME_UNRESOLVED,
        audit_dependency_closure,
        load_allowlist,
    )
except ImportError:
    # Will fail when tests run first before implementation
    pass


def make_minimal_allowlist(tmp_path: Path, allowed_families: list[str] | None = None) -> Path:
    """Creates a minimal valid allowlist file in a temp directory."""
    families = allowed_families or ["asupersync", "frankensqlite", "fsqlite-*"]
    families_toml = ", ".join(f'"{f}"' for f in families)
    content = f"""schema = "fss.dependency_allowlist.v3"
as_of = "2026-09-01"

[policy]
closed_universe = true
direct_crates_must_be_allowlisted = true
transitive_closure_must_be_censused = true
new_external_dependency_requires_dep_record_and_adr = true
asupersync_is_only_async_runtime = true

[in_house]
allowed_families = [{families_toml}]

[fundamental]
allowed_subject_to_audit = ["serde", "serde_json"]

[exception_candidates]
not_admitted_without_dep_record_adr_and_release_evidence = ["blake3", "thiserror"]

[laboratory_oracles]
excluded_from_production_release_closure = ["ffmpeg", "pytorch"]

[forbidden]
crates = ["tokio", "async-std", "smol", "reqwest", "hyper"]
"""
    allowlist_path = tmp_path / "dependency_allowlist.toml"
    allowlist_path.write_text(content, encoding="utf-8")
    return allowlist_path


def make_valid_isolated_workspace(tmp_path: Path) -> tuple[Path, Path]:
    """Creates a minimal valid Cargo workspace with a valid Cargo.lock and allowlist."""
    allowlist_path = make_minimal_allowlist(tmp_path)
    cargo_toml = tmp_path / "Cargo.toml"
    cargo_toml.write_text(
        """[workspace]
resolver = "3"
members = ["crates/test-core"]

[workspace.metadata.fss]
sole_async_runtime = "asupersync"
""",
        encoding="utf-8",
    )
    core_dir = tmp_path / "crates" / "test-core"
    core_dir.mkdir(parents=True, exist_ok=True)
    (core_dir / "Cargo.toml").write_text(
        """[package]
name = "test-core"
version = "0.0.1"
edition = "2024"
""",
        encoding="utf-8",
    )
    src_dir = core_dir / "src"
    src_dir.mkdir(parents=True, exist_ok=True)
    (src_dir / "lib.rs").write_text("// safe core\n", encoding="utf-8")

    cargo_lock = tmp_path / "Cargo.lock"
    cargo_lock.write_text(
        """# Automatically generated
version = 4

[[package]]
name = "test-core"
version = "0.0.1"
""",
        encoding="utf-8",
    )
    return tmp_path, allowlist_path


class TestDependencyClosurePositiveControls(unittest.TestCase):
    """Positive controls asserting real repo and valid isolated fixtures pass."""

    def test_real_repo_passes(self) -> None:
        """The real repository passes the dependency closure audit with zero errors."""
        is_valid, findings, summary = audit_dependency_closure(ROOT)
        self.assertTrue(
            is_valid,
            f"Real repo failed dependency closure audit: {[f.message for f in findings if f.severity == 'error']}",
        )
        self.assertEqual(summary["status"], "pass")
        self.assertEqual(summary["error_count"], 0)
        self.assertGreaterEqual(summary["package_count"], 6)

    def test_cli_real_repo_passes(self) -> None:
        """CLI invocation on the real repository exits with code 0."""
        cmd = [sys.executable, str(ROOT / "scripts/dependency_closure_scanner.py")]
        result = subprocess.run(cmd, capture_output=True, text=True, cwd=str(ROOT))
        self.assertEqual(result.returncode, 0, f"CLI failed:\n{result.stderr}\n{result.stdout}")
        self.assertIn("[PASS]", result.stdout)

    def test_cli_json_mode(self) -> None:
        """CLI --json emits valid JSON matching summary and findings structure."""
        cmd = [sys.executable, str(ROOT / "scripts/dependency_closure_scanner.py"), "--json"]
        result = subprocess.run(cmd, capture_output=True, text=True, cwd=str(ROOT))
        self.assertEqual(result.returncode, 0, f"CLI JSON mode failed:\n{result.stderr}")
        data = json.loads(result.stdout)
        self.assertIn("summary", data)
        self.assertIn("findings", data)
        self.assertEqual(data["summary"]["status"], "pass")
        self.assertEqual(data["summary"]["error_count"], 0)


class TestPlantedNegativeUnallowlistedCrate(unittest.TestCase):
    """Tests failure when unallowlisted or forbidden crates appear in resolved closure."""

    def test_unallowlisted_crate_in_lock_fails(self) -> None:
        """An unallowlisted crate in Cargo.lock/metadata closure fails closed."""
        with tempfile.TemporaryDirectory() as td:
            ws_root, allowlist_path = make_valid_isolated_workspace(Path(td))
            # Add an unallowlisted path crate
            unallowed_dir = ws_root / "crates" / "unapproved-crate"
            unallowed_dir.mkdir(parents=True, exist_ok=True)
            (unallowed_dir / "Cargo.toml").write_text(
                """[package]
name = "unapproved-crate"
version = "0.0.1"
edition = "2024"
""",
                encoding="utf-8",
            )
            (unallowed_dir / "src").mkdir(parents=True, exist_ok=True)
            (unallowed_dir / "src" / "lib.rs").write_text("// unapproved\n", encoding="utf-8")

            # Depend on it from test-core
            (ws_root / "crates" / "test-core" / "Cargo.toml").write_text(
                """[package]
name = "test-core"
version = "0.0.1"
edition = "2024"

[dependencies]
unapproved-crate = { path = "../unapproved-crate" }
""",
                encoding="utf-8",
            )
            # Update workspace members
            (ws_root / "Cargo.toml").write_text(
                """[workspace]
resolver = "3"
members = ["crates/test-core"]

[workspace.metadata.fss]
sole_async_runtime = "asupersync"
""",
                encoding="utf-8",
            )
            # Update Cargo.lock
            (ws_root / "Cargo.lock").write_text(
                """version = 4

[[package]]
name = "test-core"
version = "0.0.1"
dependencies = ["unapproved-crate"]

[[package]]
name = "unapproved-crate"
version = "0.0.1"
""",
                encoding="utf-8",
            )

            is_valid, findings, summary = audit_dependency_closure(ws_root, allowlist_path=allowlist_path)
            self.assertFalse(is_valid)
            self.assertEqual(summary["status"], "fail")
            codes = [f.code for f in findings]
            self.assertIn(ERR_UNALLOWLISTED_CRATE, codes)
            unallowed_finding = next(f for f in findings if f.code == ERR_UNALLOWLISTED_CRATE)
            self.assertIn("unapproved-crate", unallowed_finding.message)

    def test_forbidden_crate_fails(self) -> None:
        """A forbidden crate (e.g. tokio) in the resolved closure fails closed with ERR_FORBIDDEN_CRATE."""
        with tempfile.TemporaryDirectory() as td:
            ws_root, allowlist_path = make_valid_isolated_workspace(Path(td))
            tokio_dir = ws_root / "crates" / "tokio"
            tokio_dir.mkdir(parents=True, exist_ok=True)
            (tokio_dir / "Cargo.toml").write_text(
                """[package]
name = "tokio"
version = "1.0.0"
edition = "2024"
""",
                encoding="utf-8",
            )
            (tokio_dir / "src").mkdir(parents=True, exist_ok=True)
            (tokio_dir / "src" / "lib.rs").write_text("// forbidden\n", encoding="utf-8")

            (ws_root / "crates" / "test-core" / "Cargo.toml").write_text(
                """[package]
name = "test-core"
version = "0.0.1"
edition = "2024"

[dependencies]
tokio = { path = "../tokio" }
""",
                encoding="utf-8",
            )
            (ws_root / "Cargo.toml").write_text(
                """[workspace]
resolver = "3"
members = ["crates/test-core"]

[workspace.metadata.fss]
sole_async_runtime = "asupersync"
""",
                encoding="utf-8",
            )
            (ws_root / "Cargo.lock").write_text(
                """version = 4

[[package]]
name = "test-core"
version = "0.0.1"
dependencies = ["tokio"]

[[package]]
name = "tokio"
version = "1.0.0"
""",
                encoding="utf-8",
            )

            is_valid, findings, summary = audit_dependency_closure(ws_root, allowlist_path=allowlist_path)
            self.assertFalse(is_valid)
            codes = [f.code for f in findings]
            self.assertIn(ERR_FORBIDDEN_CRATE, codes)
            forbidden_finding = next(f for f in findings if f.code == ERR_FORBIDDEN_CRATE)
            self.assertIn("tokio", forbidden_finding.message)

    def test_oracle_crate_excluded_from_production_closure_fails(self) -> None:
        """An oracle crate (e.g. ffmpeg) in the closure fails with ERR_FORBIDDEN_CRATE."""
        with tempfile.TemporaryDirectory() as td:
            ws_root, allowlist_path = make_valid_isolated_workspace(Path(td))
            ffmpeg_dir = ws_root / "crates" / "ffmpeg"
            ffmpeg_dir.mkdir(parents=True, exist_ok=True)
            (ffmpeg_dir / "Cargo.toml").write_text(
                """[package]
name = "ffmpeg"
version = "0.1.0"
edition = "2024"
""",
                encoding="utf-8",
            )
            (ffmpeg_dir / "src").mkdir(parents=True, exist_ok=True)
            (ffmpeg_dir / "src" / "lib.rs").write_text("// ffmpeg\n", encoding="utf-8")

            (ws_root / "crates" / "test-core" / "Cargo.toml").write_text(
                """[package]
name = "test-core"
version = "0.0.1"
edition = "2024"

[dependencies]
ffmpeg = { path = "../ffmpeg" }
""",
                encoding="utf-8",
            )
            (ws_root / "Cargo.toml").write_text(
                """[workspace]
resolver = "3"
members = ["crates/test-core"]

[workspace.metadata.fss]
sole_async_runtime = "asupersync"
""",
                encoding="utf-8",
            )
            (ws_root / "Cargo.lock").write_text(
                """version = 4

[[package]]
name = "ffmpeg"
version = "0.1.0"

[[package]]
name = "test-core"
version = "0.0.1"
dependencies = ["ffmpeg"]
""",
                encoding="utf-8",
            )

            is_valid, findings, summary = audit_dependency_closure(ws_root, allowlist_path=allowlist_path)
            self.assertFalse(is_valid)
            codes = [f.code for f in findings]
            self.assertIn(ERR_FORBIDDEN_CRATE, codes)

    def test_exception_candidate_unadmitted_fails(self) -> None:
        """An exception candidate (e.g. blake3) without explicit admission fails closed."""
        with tempfile.TemporaryDirectory() as td:
            ws_root, allowlist_path = make_valid_isolated_workspace(Path(td))
            blake3_dir = ws_root / "crates" / "blake3"
            blake3_dir.mkdir(parents=True, exist_ok=True)
            (blake3_dir / "Cargo.toml").write_text(
                """[package]
name = "blake3"
version = "1.5.0"
edition = "2024"
""",
                encoding="utf-8",
            )
            (blake3_dir / "src").mkdir(parents=True, exist_ok=True)
            (blake3_dir / "src" / "lib.rs").write_text("// blake3\n", encoding="utf-8")

            (ws_root / "crates" / "test-core" / "Cargo.toml").write_text(
                """[package]
name = "test-core"
version = "0.0.1"
edition = "2024"

[dependencies]
blake3 = { path = "../blake3" }
""",
                encoding="utf-8",
            )
            (ws_root / "Cargo.toml").write_text(
                """[workspace]
resolver = "3"
members = ["crates/test-core"]

[workspace.metadata.fss]
sole_async_runtime = "asupersync"
""",
                encoding="utf-8",
            )
            (ws_root / "Cargo.lock").write_text(
                """version = 4

[[package]]
name = "blake3"
version = "1.5.0"

[[package]]
name = "test-core"
version = "0.0.1"
dependencies = ["blake3"]
""",
                encoding="utf-8",
            )

            is_valid, findings, summary = audit_dependency_closure(ws_root, allowlist_path=allowlist_path)
            self.assertFalse(is_valid)
            codes = [f.code for f in findings]
            self.assertIn(ERR_UNALLOWLISTED_CRATE, codes)


class TestPlantedNegativeBuildDevAndTargetDependencies(unittest.TestCase):
    """Verifies scanner inspects build, dev, and target-specific dependencies across features."""

    def test_unallowlisted_build_dependency_fails(self) -> None:
        """An unallowlisted build dependency fails closed with ERR_UNALLOWLISTED_CRATE."""
        with tempfile.TemporaryDirectory() as td:
            ws_root, allowlist_path = make_valid_isolated_workspace(Path(td))
            build_dep_dir = ws_root / "crates" / "bad-build-dep"
            build_dep_dir.mkdir(parents=True, exist_ok=True)
            (build_dep_dir / "Cargo.toml").write_text(
                """[package]
name = "bad-build-dep"
version = "0.1.0"
edition = "2024"
""",
                encoding="utf-8",
            )
            (build_dep_dir / "src").mkdir(parents=True, exist_ok=True)
            (build_dep_dir / "src" / "lib.rs").write_text("// bad build dep\n", encoding="utf-8")

            (ws_root / "crates" / "test-core" / "Cargo.toml").write_text(
                """[package]
name = "test-core"
version = "0.0.1"
edition = "2024"

[build-dependencies]
bad-build-dep = { path = "../bad-build-dep" }
""",
                encoding="utf-8",
            )
            (ws_root / "Cargo.toml").write_text(
                """[workspace]
resolver = "3"
members = ["crates/test-core"]

[workspace.metadata.fss]
sole_async_runtime = "asupersync"
""",
                encoding="utf-8",
            )
            (ws_root / "Cargo.lock").write_text(
                """version = 4

[[package]]
name = "bad-build-dep"
version = "0.1.0"

[[package]]
name = "test-core"
version = "0.0.1"
dependencies = ["bad-build-dep"]
""",
                encoding="utf-8",
            )

            is_valid, findings, summary = audit_dependency_closure(ws_root, allowlist_path=allowlist_path)
            self.assertFalse(is_valid)
            self.assertIn(ERR_UNALLOWLISTED_CRATE, [f.code for f in findings])

    def test_unallowlisted_dev_dependency_fails(self) -> None:
        """An unallowlisted dev dependency fails closed with ERR_UNALLOWLISTED_CRATE."""
        with tempfile.TemporaryDirectory() as td:
            ws_root, allowlist_path = make_valid_isolated_workspace(Path(td))
            dev_dep_dir = ws_root / "crates" / "bad-dev-dep"
            dev_dep_dir.mkdir(parents=True, exist_ok=True)
            (dev_dep_dir / "Cargo.toml").write_text(
                """[package]
name = "bad-dev-dep"
version = "0.1.0"
edition = "2024"
""",
                encoding="utf-8",
            )
            (dev_dep_dir / "src").mkdir(parents=True, exist_ok=True)
            (dev_dep_dir / "src" / "lib.rs").write_text("// bad dev dep\n", encoding="utf-8")

            (ws_root / "crates" / "test-core" / "Cargo.toml").write_text(
                """[package]
name = "test-core"
version = "0.0.1"
edition = "2024"

[dev-dependencies]
bad-dev-dep = { path = "../bad-dev-dep" }
""",
                encoding="utf-8",
            )
            (ws_root / "Cargo.toml").write_text(
                """[workspace]
resolver = "3"
members = ["crates/test-core"]

[workspace.metadata.fss]
sole_async_runtime = "asupersync"
""",
                encoding="utf-8",
            )
            (ws_root / "Cargo.lock").write_text(
                """version = 4

[[package]]
name = "bad-dev-dep"
version = "0.1.0"

[[package]]
name = "test-core"
version = "0.0.1"
dependencies = ["bad-dev-dep"]
""",
                encoding="utf-8",
            )

            is_valid, findings, summary = audit_dependency_closure(ws_root, allowlist_path=allowlist_path)
            self.assertFalse(is_valid)
            self.assertIn(ERR_UNALLOWLISTED_CRATE, [f.code for f in findings])

    def test_unallowlisted_target_specific_dependency_fails(self) -> None:
        """An unallowlisted target-specific dependency fails closed with ERR_UNALLOWLISTED_CRATE."""
        with tempfile.TemporaryDirectory() as td:
            ws_root, allowlist_path = make_valid_isolated_workspace(Path(td))
            target_dep_dir = ws_root / "crates" / "bad-target-dep"
            target_dep_dir.mkdir(parents=True, exist_ok=True)
            (target_dep_dir / "Cargo.toml").write_text(
                """[package]
name = "bad-target-dep"
version = "0.1.0"
edition = "2024"
""",
                encoding="utf-8",
            )
            (target_dep_dir / "src").mkdir(parents=True, exist_ok=True)
            (target_dep_dir / "src" / "lib.rs").write_text("// bad target dep\n", encoding="utf-8")

            (ws_root / "crates" / "test-core" / "Cargo.toml").write_text(
                """[package]
name = "test-core"
version = "0.0.1"
edition = "2024"

[target.'cfg(unix)'.dependencies]
bad-target-dep = { path = "../bad-target-dep" }
""",
                encoding="utf-8",
            )
            (ws_root / "Cargo.toml").write_text(
                """[workspace]
resolver = "3"
members = ["crates/test-core"]

[workspace.metadata.fss]
sole_async_runtime = "asupersync"
""",
                encoding="utf-8",
            )
            (ws_root / "Cargo.lock").write_text(
                """version = 4

[[package]]
name = "bad-target-dep"
version = "0.1.0"

[[package]]
name = "test-core"
version = "0.0.1"
dependencies = ["bad-target-dep"]
""",
                encoding="utf-8",
            )

            is_valid, findings, summary = audit_dependency_closure(ws_root, allowlist_path=allowlist_path)
            self.assertFalse(is_valid)
            self.assertIn(ERR_UNALLOWLISTED_CRATE, [f.code for f in findings])


class TestPlantedNegativeVersionSourceAndOrigin(unittest.TestCase):
    """Tests version/source mismatches, unallowlisted git sources, and escaping paths."""

    def test_version_mismatch_between_lock_and_metadata_fails(self) -> None:
        """Mismatch between Cargo.lock version and Cargo.toml/metadata version fails closed."""
        with tempfile.TemporaryDirectory() as td:
            ws_root, allowlist_path = make_valid_isolated_workspace(Path(td))
            # Put version 0.0.2 in Cargo.lock while Cargo.toml has 0.0.1
            (ws_root / "Cargo.lock").write_text(
                """version = 4

[[package]]
name = "test-core"
version = "0.0.2"
""",
                encoding="utf-8",
            )

            is_valid, findings, summary = audit_dependency_closure(ws_root, allowlist_path=allowlist_path)
            self.assertFalse(is_valid)
            self.assertIn(ERR_VERSION_SOURCE_MISMATCH, [f.code for f in findings])

    def test_missing_package_in_lock_or_metadata_fails(self) -> None:
        """A package in Cargo.lock but missing from metadata (or vice versa) fails closed."""
        with tempfile.TemporaryDirectory() as td:
            ws_root, allowlist_path = make_valid_isolated_workspace(Path(td))
            # Extra package in Cargo.lock not in Cargo.toml
            (ws_root / "Cargo.lock").write_text(
                """version = 4

[[package]]
name = "test-core"
version = "0.0.1"

[[package]]
name = "ghost-package"
version = "0.0.1"
""",
                encoding="utf-8",
            )

            is_valid, findings, summary = audit_dependency_closure(ws_root, allowlist_path=allowlist_path)
            self.assertFalse(is_valid)
            self.assertIn(ERR_VERSION_SOURCE_MISMATCH, [f.code for f in findings])

    def test_git_dependency_without_40_hex_revision_fails(self) -> None:
        """Git dependency without exact 40-hex commit hash fails closed."""
        with tempfile.TemporaryDirectory() as td:
            ws_root, allowlist_path = make_valid_isolated_workspace(Path(td))
            (ws_root / "Cargo.lock").write_text(
                """version = 4

[[package]]
name = "test-core"
version = "0.0.1"

[[package]]
name = "fsqlite-sys"
version = "0.1.0"
source = "git+https://github.com/example/fsqlite?branch=main"
""",
                encoding="utf-8",
            )

            is_valid, findings, summary = audit_dependency_closure(ws_root, allowlist_path=allowlist_path)
            self.assertFalse(is_valid)
            codes = [f.code for f in findings]
            self.assertTrue(
                ERR_VERSION_SOURCE_MISMATCH in codes or ERR_UNALLOWLISTED_SOURCE in codes,
                f"Expected source mismatch or unallowlisted source code, got: {codes}",
            )

    def test_unallowlisted_git_source_fails(self) -> None:
        """A git dependency from an unauthorized host/repository fails closed."""
        with tempfile.TemporaryDirectory() as td:
            ws_root, allowlist_path = make_valid_isolated_workspace(Path(td))
            (ws_root / "Cargo.lock").write_text(
                """version = 4

[[package]]
name = "test-core"
version = "0.0.1"

[[package]]
name = "fsqlite-sys"
version = "0.1.0"
source = "git+https://malicious.example.com/untrusted/repo#0123456789abcdef0123456789abcdef01234567"
""",
                encoding="utf-8",
            )

            is_valid, findings, summary = audit_dependency_closure(ws_root, allowlist_path=allowlist_path)
            self.assertFalse(is_valid)
            codes = [f.code for f in findings]
            self.assertTrue(
                ERR_UNALLOWLISTED_SOURCE in codes or ERR_VERSION_SOURCE_MISMATCH in codes,
                f"Expected unallowlisted source error, got {codes}",
            )

    def test_path_dependency_escaping_repository_fails(self) -> None:
        """A path dependency escaping workspace boundary without sibling admission fails closed."""
        with tempfile.TemporaryDirectory() as td:
            ws_root, allowlist_path = make_valid_isolated_workspace(Path(td))
            outside_dir = Path(td).parent / "outside-escape-crate"
            try:
                outside_dir.mkdir(parents=True, exist_ok=True)
                (outside_dir / "Cargo.toml").write_text(
                    """[package]
name = "outside-escape-crate"
version = "0.1.0"
edition = "2024"
""",
                    encoding="utf-8",
                )
                (outside_dir / "src").mkdir(parents=True, exist_ok=True)
                (outside_dir / "src" / "lib.rs").write_text("// escaping\n", encoding="utf-8")

                (ws_root / "crates" / "test-core" / "Cargo.toml").write_text(
                    f"""[package]
name = "test-core"
version = "0.0.1"
edition = "2024"

[dependencies]
outside-escape-crate = {{ path = "{outside_dir.as_posix()}" }}
""",
                    encoding="utf-8",
                )
                (ws_root / "Cargo.lock").write_text(
                    """version = 4

[[package]]
name = "test-core"
version = "0.0.1"
dependencies = ["outside-escape-crate"]

[[package]]
name = "outside-escape-crate"
version = "0.1.0"
""",
                    encoding="utf-8",
                )

                is_valid, findings, summary = audit_dependency_closure(ws_root, allowlist_path=allowlist_path)
                self.assertFalse(is_valid)
                codes = [f.code for f in findings]
                self.assertTrue(
                    ERR_UNALLOWLISTED_SOURCE in codes or ERR_UNALLOWLISTED_CRATE in codes,
                    f"Expected unallowlisted source or crate error, got: {codes}",
                )
            finally:
                if outside_dir.exists():
                    import shutil

                    shutil.rmtree(outside_dir, ignore_errors=True)


class TestPlantedNegativeMetadataAndAllowlistValidity(unittest.TestCase):
    """Tests failure when Cargo.lock, Cargo.toml, or allowlist are missing, corrupt, or empty."""

    def test_missing_cargo_lock_fails_closed(self) -> None:
        """Missing Cargo.lock fails closed with ERR_METADATA_UNREADABLE."""
        with tempfile.TemporaryDirectory() as td:
            ws_root, allowlist_path = make_valid_isolated_workspace(Path(td))
            (ws_root / "Cargo.lock").unlink()
            is_valid, findings, summary = audit_dependency_closure(ws_root, allowlist_path=allowlist_path)
            self.assertFalse(is_valid)
            self.assertIn(ERR_METADATA_UNREADABLE, [f.code for f in findings])

    def test_corrupt_cargo_lock_fails_closed(self) -> None:
        """Corrupt/unparseable Cargo.lock fails closed with ERR_METADATA_UNREADABLE."""
        with tempfile.TemporaryDirectory() as td:
            ws_root, allowlist_path = make_valid_isolated_workspace(Path(td))
            (ws_root / "Cargo.lock").write_text("<<<not valid toml>>>", encoding="utf-8")
            is_valid, findings, summary = audit_dependency_closure(ws_root, allowlist_path=allowlist_path)
            self.assertFalse(is_valid)
            self.assertIn(ERR_METADATA_UNREADABLE, [f.code for f in findings])

    def test_missing_cargo_toml_fails_closed(self) -> None:
        """Missing Cargo.toml fails closed with ERR_METADATA_UNREADABLE."""
        with tempfile.TemporaryDirectory() as td:
            ws_root, allowlist_path = make_valid_isolated_workspace(Path(td))
            (ws_root / "Cargo.toml").unlink()
            is_valid, findings, summary = audit_dependency_closure(ws_root, allowlist_path=allowlist_path)
            self.assertFalse(is_valid)
            self.assertIn(ERR_METADATA_UNREADABLE, [f.code for f in findings])

    def test_missing_allowlist_fails_closed(self) -> None:
        """Missing allowlist file fails closed with ERR_EMPTY_ALLOWLIST."""
        with tempfile.TemporaryDirectory() as td:
            ws_root, allowlist_path = make_valid_isolated_workspace(Path(td))
            allowlist_path.unlink()
            is_valid, findings, summary = audit_dependency_closure(ws_root, allowlist_path=allowlist_path)
            self.assertFalse(is_valid)
            self.assertIn(ERR_EMPTY_ALLOWLIST, [f.code for f in findings])

    def test_empty_allowlist_fails_closed(self) -> None:
        """An empty (0 bytes or empty dict) allowlist fails closed with ERR_EMPTY_ALLOWLIST."""
        with tempfile.TemporaryDirectory() as td:
            ws_root, allowlist_path = make_valid_isolated_workspace(Path(td))
            allowlist_path.write_text("", encoding="utf-8")
            is_valid, findings, summary = audit_dependency_closure(ws_root, allowlist_path=allowlist_path)
            self.assertFalse(is_valid)
            self.assertIn(ERR_EMPTY_ALLOWLIST, [f.code for f in findings])

    def test_allowlist_with_zero_allowed_families_fails_closed(self) -> None:
        """An allowlist with empty allowed_families and empty allowed_subject_to_audit fails closed."""
        with tempfile.TemporaryDirectory() as td:
            ws_root, allowlist_path = make_valid_isolated_workspace(Path(td))
            allowlist_path.write_text(
                """schema = "fss.dependency_allowlist.v3"
[policy]
closed_universe = true
[in_house]
allowed_families = []
[fundamental]
allowed_subject_to_audit = []
""",
                encoding="utf-8",
            )
            is_valid, findings, summary = audit_dependency_closure(ws_root, allowlist_path=allowlist_path)
            self.assertFalse(is_valid)
            self.assertIn(ERR_EMPTY_ALLOWLIST, [f.code for f in findings])


class TestDeclaredRuntimeReporting(unittest.TestCase):
    """Tests honest reporting of declared-but-unresolved async runtime."""

    def test_declared_runtime_unresolved_honestly_reported(self) -> None:
        """When sole_async_runtime = 'asupersync' is declared but absent from Cargo.lock,

        it is honestly reported in diagnostics/summary, never silently passed.
        """
        is_valid, findings, summary = audit_dependency_closure(ROOT)
        self.assertTrue(is_valid)
        self.assertEqual(summary["declared_runtime"], "asupersync")
        self.assertFalse(summary["declared_runtime_resolved"])
        self.assertEqual(summary["declared_runtime_status"], "declared_but_unresolved")

        # Must have a diagnostic status finding
        statuses = [f.code for f in findings if f.code == STATUS_DECLARED_RUNTIME_UNRESOLVED]
        self.assertTrue(
            len(statuses) > 0,
            f"Expected STATUS_DECLARED_RUNTIME_UNRESOLVED in findings: {[f.code for f in findings]}",
        )
        status_finding = next(f for f in findings if f.code == STATUS_DECLARED_RUNTIME_UNRESOLVED)
        self.assertIn("asupersync", status_finding.message)

    def test_require_resolved_runtime_flag_fails_when_unresolved(self) -> None:
        """When require_resolved_runtime=True and runtime is unresolved, audit fails closed."""
        is_valid, findings, summary = audit_dependency_closure(ROOT, require_resolved_runtime=True)
        self.assertFalse(is_valid)
        self.assertEqual(summary["status"], "fail")
        codes = [f.code for f in findings]
        self.assertIn(ERR_DECLARED_RUNTIME_UNRESOLVED, codes)


if __name__ == "__main__":
    unittest.main()
