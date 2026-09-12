#!/usr/bin/env python3
from __future__ import annotations

import hashlib
import json
import os
import subprocess
import sys
import tarfile
import tempfile
import unittest
import zipfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "scripts" / "release_artifacts.py"
RECEIPT_FILES = ["STAGE_SHA256SUMS.txt", "build.json", "verification.json"]
FSIZE_LIMIT = 2048

# Runs the real `release_artifacts.py verify` entry point. With "after-verification-json" the
# RLIMIT_FSIZE ceiling is lowered only once verification.json has been written, so the injected
# EFBIG lands inside the STAGE_SHA256SUMS.txt write (Python ignores SIGXFSZ, so the oversized
# write fails with EFBIG part-way instead of killing the process).
VERIFY_HARNESS = """
import pathlib, resource, sys
script, limit, mode, argv = sys.argv[1], int(sys.argv[2]), sys.argv[3], sys.argv[4:]
sys.path.insert(0, str(pathlib.Path(script).parent))
import release_artifacts
if mode == "immediately":
    resource.setrlimit(resource.RLIMIT_FSIZE, (limit, limit))
else:
    original_write_json = release_artifacts.write_json
    def write_json_then_limit(path, value):
        original_write_json(path, value)
        if path.name == "verification.json":
            resource.setrlimit(resource.RLIMIT_FSIZE, (limit, limit))
    release_artifacts.write_json = write_json_then_limit
sys.argv = [script, *argv]
raise SystemExit(release_artifacts.main())
"""
EPOCH = 1_700_000_000
COMMIT = "0000000000000000000000000000000000000001"


def digest(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


class ReleaseArtifactTests(unittest.TestCase):
    def make_input(self, root: Path) -> None:
        stage = root / "stage"
        receipts = root / "receipts"
        artifacts = root / "artifacts"
        (stage / "docs").mkdir(parents=True)
        receipts.mkdir()
        artifacts.mkdir()
        binary = stage / "fss"
        binary.write_text('#!/usr/bin/env sh\nprintf "fss fixture\\n"\n', encoding="utf-8")
        binary.chmod(0o755)
        (stage / "README.md").write_text("fixture readme\n", encoding="utf-8")
        (stage / "docs" / "fixture.txt").write_text("nested fixture\n", encoding="utf-8")
        (receipts / "build.json").write_text(
            json.dumps(
                {
                    "schema": "fss.release_build_receipt.v1",
                    "version": "0.0.1",
                    "target": "fixture",
                    "hostTarget": "fixture",
                    "toolchain": "nightly-2026-08-31",
                    "sourceCommit": COMMIT,
                    "sourceDateEpoch": EPOCH,
                    "cargoLockSha256": "0" * 64,
                    "repositoryManifestSha256": "0" * 64,
                    "cargoMetadataSha256": "0" * 64,
                    "smokeHelpSha256": "0" * 64,
                    "capabilitiesSha256": "0" * 64,
                    "claimBoundary": "design_skeleton",
                },
                sort_keys=True,
            )
            + "\n",
            encoding="utf-8",
        )
        (root / "metadata.json").write_text(
            json.dumps(
                {
                    "packages": [
                        {
                            "id": "path+file:///fss-core#0.0.1",
                            "name": "fss-core",
                            "version": "0.0.1",
                            "source": None,
                            "license": "LicenseRef-MIT-OpenAI-Anthropic-Rider",
                            "license_file": None,
                        },
                        {
                            "id": "path+file:///fss-cli#0.0.1",
                            "name": "fss-cli",
                            "version": "0.0.1",
                            "source": None,
                            "license": "LicenseRef-MIT-OpenAI-Anthropic-Rider",
                            "license_file": None,
                        },
                    ]
                },
                sort_keys=True,
            )
            + "\n",
            encoding="utf-8",
        )

    def run_case(self, root: Path, target: str) -> Path:
        self.make_input(root)
        common = [
            "--version",
            "0.0.1",
            "--target",
            target,
            "--stage",
            str(root / "stage"),
            "--artifacts",
            str(root / "artifacts"),
            "--receipts",
            str(root / "receipts"),
            "--source-date-epoch",
            str(EPOCH),
        ]
        subprocess.run([os.fspath(SCRIPT), "verify", *common], cwd=ROOT, check=True)
        subprocess.run(
            [
                os.fspath(SCRIPT),
                "package",
                *common,
                "--metadata",
                str(root / "metadata.json"),
                "--source-commit",
                COMMIT,
            ],
            cwd=ROOT,
            check=True,
        )
        artifacts = root / "artifacts"
        sums = artifacts / f"fss-{target}.sha256sums.txt"
        for line in sums.read_text(encoding="utf-8").splitlines():
            expected, name = line.split("  ", 1)
            self.assertEqual(expected, digest(artifacts / name))
        qualification = json.loads((artifacts / f"fss-{target}.qualification.json").read_text(encoding="utf-8"))
        for row in [qualification["primaryArtifact"], *qualification["supportArtifacts"]]:
            path = artifacts / row["name"]
            self.assertTrue(path.is_file())
            self.assertEqual(row["sha256"], digest(path))
            self.assertEqual(row["bytes"], path.stat().st_size)
        return artifacts

    def assert_trees_equal(self, left: Path, right: Path) -> None:
        left_files = sorted(path.relative_to(left) for path in left.iterdir() if path.is_file())
        right_files = sorted(path.relative_to(right) for path in right.iterdir() if path.is_file())
        self.assertEqual(left_files, right_files)
        for relative in left_files:
            self.assertEqual((left / relative).read_bytes(), (right / relative).read_bytes(), relative)

    def test_deterministic_native_packages_and_common_authority(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            base = Path(temporary)
            auth1 = self.run_case(base / "auth1", "x86_64-unknown-linux-gnu")
            auth2 = self.run_case(base / "auth2", "x86_64-unknown-linux-gnu")
            arm1 = self.run_case(base / "arm1", "aarch64-unknown-linux-gnu")
            arm2 = self.run_case(base / "arm2", "aarch64-unknown-linux-gnu")
            win1 = self.run_case(base / "win1", "x86_64-pc-windows-msvc")
            win2 = self.run_case(base / "win2", "x86_64-pc-windows-msvc")
            self.assert_trees_equal(auth1, auth2)
            self.assert_trees_equal(arm1, arm2)
            self.assert_trees_equal(win1, win2)
            self.assertTrue((auth1 / "fss-source.tar.xz").is_file())
            self.assertFalse((arm1 / "fss-source.tar.xz").exists())
            self.assertFalse((win1 / "fss-source.tar.xz").exists())
            auth_q = json.loads((auth1 / "fss-x86_64-unknown-linux-gnu.qualification.json").read_text())
            arm_q = json.loads((arm1 / "fss-aarch64-unknown-linux-gnu.qualification.json").read_text())
            self.assertIs(auth_q["commonAssetAuthority"], True)
            self.assertIs(arm_q["commonAssetAuthority"], False)
            with tarfile.open(auth1 / "fss-x86_64-unknown-linux-gnu.tar.xz", "r:xz") as archive:
                self.assertIn("fss", archive.getnames())
            with zipfile.ZipFile(win1 / "fss-x86_64-pc-windows-msvc.zip") as archive:
                self.assertIn("fss", archive.namelist())


    def verify_args(self, root: Path, target: str = "x86_64-unknown-linux-gnu") -> list[str]:
        return [
            "verify", "--version", "0.0.1", "--target", target,
            "--stage", str(root / "stage"), "--artifacts", str(root / "artifacts"),
            "--receipts", str(root / "receipts"), "--source-date-epoch", str(EPOCH),
        ]

    def grow_stage(self, root: Path, count: int) -> None:
        for index in range(count):
            (root / "stage" / "docs" / f"grown-fixture-{index:03d}.txt").write_text(f"grown {index}\n", encoding="utf-8")

    def run_verify_with_limit(self, root: Path, mode: str) -> subprocess.CompletedProcess[str]:
        env = {**os.environ, "PYTHONDONTWRITEBYTECODE": "1"}
        return subprocess.run(
            [sys.executable, "-c", VERIFY_HARNESS, os.fspath(SCRIPT), str(FSIZE_LIMIT), mode, *self.verify_args(root)],
            cwd=ROOT, env=env, capture_output=True, text=True, timeout=120,
        )

    def test_verify_efbig_mid_verification_json_keeps_previous_receipt(self) -> None:
        """fss-xhxwh: verification.json is rewritten atomically. A write that fails part-way
        (RLIMIT_FSIZE -> EFBIG after 2 KiB of a much larger document) must leave the previous
        verification.json byte-identical and no partial or temp file in the receipt directory."""
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            self.make_input(root)
            subprocess.run([os.fspath(SCRIPT), *self.verify_args(root)], cwd=ROOT, check=True)
            receipts = root / "receipts"
            previous_verification = (receipts / "verification.json").read_bytes()
            previous_sums = (receipts / "STAGE_SHA256SUMS.txt").read_bytes()
            self.grow_stage(root, 40)

            crashed = self.run_verify_with_limit(root, "immediately")
            self.assertNotEqual(crashed.returncode, 0, "a verify whose receipt could not be written must fail")
            self.assertIn("File too large", crashed.stderr)
            self.assertEqual((receipts / "verification.json").read_bytes(), previous_verification, crashed.stderr)
            self.assertEqual((receipts / "STAGE_SHA256SUMS.txt").read_bytes(), previous_sums)
            self.assertEqual(sorted(path.name for path in receipts.iterdir()), RECEIPT_FILES, "no partial or temp file may remain")

            # Control: without the limit the same verify writes the new, complete receipts.
            subprocess.run([os.fspath(SCRIPT), *self.verify_args(root)], cwd=ROOT, check=True)
            verification = json.loads((receipts / "verification.json").read_text(encoding="utf-8"))
            self.assertEqual(verification["fileCount"], 43)
            self.assertGreater(len((receipts / "verification.json").read_bytes()), FSIZE_LIMIT)

    def test_verify_efbig_mid_stage_sums_keeps_previous_checksums(self) -> None:
        """fss-xhxwh: STAGE_SHA256SUMS.txt is rewritten atomically. EFBIG part-way through it must
        leave the previous checksum file byte-identical and no partial or temp file behind."""
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            self.make_input(root)
            subprocess.run([os.fspath(SCRIPT), *self.verify_args(root)], cwd=ROOT, check=True)
            receipts = root / "receipts"
            previous_sums = (receipts / "STAGE_SHA256SUMS.txt").read_bytes()
            self.grow_stage(root, 40)

            crashed = self.run_verify_with_limit(root, "after-verification-json")
            self.assertNotEqual(crashed.returncode, 0, "a verify whose checksums could not be written must fail")
            self.assertIn("File too large", crashed.stderr)
            self.assertEqual((receipts / "STAGE_SHA256SUMS.txt").read_bytes(), previous_sums, crashed.stderr)
            self.assertEqual(json.loads((receipts / "verification.json").read_text(encoding="utf-8"))["fileCount"], 43)
            self.assertEqual(sorted(path.name for path in receipts.iterdir()), RECEIPT_FILES, "no partial or temp file may remain")

            subprocess.run([os.fspath(SCRIPT), *self.verify_args(root)], cwd=ROOT, check=True)
            self.assertEqual(len((receipts / "STAGE_SHA256SUMS.txt").read_text(encoding="utf-8").splitlines()), 43)
            self.assertGreater(len((receipts / "STAGE_SHA256SUMS.txt").read_bytes()), FSIZE_LIMIT)

    def test_release_artifacts_uses_the_shared_atomic_writer(self) -> None:
        """fss-xhxwh: no second copy of the atomic-write logic and no in-place receipt writes."""
        text = SCRIPT.read_text(encoding="utf-8")
        self.assertTrue("from qualification_receipt import" in text, "release_artifacts.py must import the shared writer")
        for forbidden in ("tempfile", ".write_text(", ".write_bytes(", "os.replace"):
            self.assertFalse(forbidden in text, f"release_artifacts.py must not write in place or copy the writer: {forbidden}")

    def run_verify_then_package(self, root: Path, target: str = "x86_64-unknown-linux-gnu") -> subprocess.CompletedProcess[str]:
        """Runs the real `verify` then `package` entry points; returns the package process."""
        subprocess.run([os.fspath(SCRIPT), *self.verify_args(root, target)], cwd=ROOT, check=True)
        package_args = [
            "package", *self.verify_args(root, target)[1:],
            "--metadata", str(root / "metadata.json"), "--source-commit", COMMIT,
        ]
        env = {**os.environ, "PYTHONDONTWRITEBYTECODE": "1"}
        return subprocess.run(
            [os.fspath(SCRIPT), *package_args], cwd=ROOT, env=env, capture_output=True, text=True, timeout=300
        )

    def checksum_listings(self, root: Path) -> dict[str, list[str]]:
        """Every checksum receipt package() may have written, mapped to the names it lists."""
        candidates = [*sorted((root / "artifacts").glob("*.sha256sums.txt")), root / "receipts" / "ARTIFACT_SHA256SUMS.txt"]
        return {
            path.name: [line.split("  ", 1)[1] for line in path.read_text(encoding="utf-8").splitlines()]
            for path in candidates
            if path.is_file()
        }

    def test_package_refuses_leftover_atomic_writer_temp_file(self) -> None:
        """fss-0uofb: a `.<name>.tmp.<suffix>` file left in the artifacts directory by a killed
        atomic write must make package fail closed, naming the file, instead of checksumming it
        into <target>.sha256sums.txt / ARTIFACT_SHA256SUMS.txt (or silently skipping it)."""
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            self.make_input(root)
            leftover_name = ".fss-x86_64-unknown-linux-gnu.sbom.spdx.json.tmp.stale"
            leftover = root / "artifacts" / leftover_name
            leftover.write_text('{"partial": ', encoding="utf-8")

            packaged = self.run_verify_then_package(root)
            self.assertNotEqual(packaged.returncode, 0, packaged.stderr)
            self.assertIn(leftover_name, packaged.stderr)
            self.assertIn("LeftoverAtomicTempFileError", packaged.stderr)
            self.assertNotIn("Traceback", packaged.stderr, "the refusal must be a clear typed error, not a crash")
            for name, listed in self.checksum_listings(root).items():
                self.assertFalse([entry for entry in listed if ".tmp." in entry], f"{name} lists a temp file: {listed}")
            self.assertTrue(leftover.is_file(), "package must not silently delete the evidence of the killed write")

    def test_package_clean_artifacts_directory_still_packages(self) -> None:
        """fss-0uofb positive control: without a leftover temp file the same inputs package, and
        both checksum receipts list only real release assets."""
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            self.make_input(root)
            packaged = self.run_verify_then_package(root)
            self.assertEqual(packaged.returncode, 0, packaged.stderr)
            listings = self.checksum_listings(root)
            self.assertEqual(sorted(listings), ["ARTIFACT_SHA256SUMS.txt", "fss-x86_64-unknown-linux-gnu.sha256sums.txt"])
            for name, listed in listings.items():
                self.assertIn("fss-x86_64-unknown-linux-gnu.sbom.spdx.json", listed, name)
                self.assertFalse([entry for entry in listed if ".tmp." in entry or entry.startswith(".")], f"{name}: {listed}")


if __name__ == "__main__":
    unittest.main()
