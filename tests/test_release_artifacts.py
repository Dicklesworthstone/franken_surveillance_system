#!/usr/bin/env python3
from __future__ import annotations

import hashlib
import json
import os
import subprocess
import tarfile
import tempfile
import unittest
import zipfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "scripts" / "release_artifacts.py"
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


if __name__ == "__main__":
    unittest.main()
