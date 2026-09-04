from __future__ import annotations

import importlib.util
import pathlib
import shutil
import subprocess
import sys
import tempfile
import unittest

ROOT = pathlib.Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location("manifest_audit_generator_test", ROOT / "scripts/manifest_audit.py")
assert SPEC is not None and SPEC.loader is not None
AUDIT = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(AUDIT)


class ManifestGeneratorTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = pathlib.Path(self.temporary.name)
        (self.root / "scripts").mkdir()
        shutil.copyfile(ROOT / "scripts/generate-manifest.py", self.root / "scripts/generate-manifest.py")
        (self.root / "README.md").write_text("reference fixture\n")
        (self.root / "MANIFEST.sha256").write_text("0" * 64 + "  removed.txt\n")
        (self.root / "MANIFEST.delta.sha256").write_text("stale prior overlay\n")

    def generate_and_audit(self):
        result = subprocess.run([sys.executable, str(self.root / "scripts/generate-manifest.py")], capture_output=True, text=True)
        self.assertEqual(result.returncode, 0, result.stderr)
        previous = AUDIT.ROOT
        AUDIT.ROOT = self.root
        try:
            return AUDIT.audit(self.root / "MANIFEST.sha256", self.root / "MANIFEST.delta.sha256")
        finally:
            AUDIT.ROOT = previous

    def test_compaction_excludes_both_manifests_and_clears_overlay(self):
        report = self.generate_and_audit()
        text = (self.root / "MANIFEST.sha256").read_text()
        self.assertNotIn("MANIFEST.sha256", text)
        self.assertNotIn("MANIFEST.delta.sha256", text)
        self.assertEqual((self.root / "MANIFEST.delta.sha256").read_bytes(), b"")
        self.assertEqual(report["deltaEntries"], 0)
        self.assertEqual(report["status"], "passed")

    def test_compaction_is_byte_idempotent(self):
        self.generate_and_audit()
        original = (self.root / "MANIFEST.sha256").read_bytes()
        self.generate_and_audit()
        self.assertEqual((self.root / "MANIFEST.sha256").read_bytes(), original)

    def test_compaction_accounts_for_deleted_source(self):
        old = self.root / "obsolete.txt"
        old.write_text("obsolete\n")
        self.generate_and_audit()
        old.unlink()
        self.generate_and_audit()
        self.assertNotIn("obsolete.txt", (self.root / "MANIFEST.sha256").read_text())

    def test_compaction_preserves_private_and_build_exclusions(self):
        for directory in (".beads", "target", "credentials", "qualification-artifacts"):
            (self.root / directory).mkdir()
            (self.root / directory / "ignored.txt").write_text("not part of source integrity\n")
        self.generate_and_audit()
        self.assertNotIn("ignored.txt", (self.root / "MANIFEST.sha256").read_text())


if __name__ == "__main__":
    unittest.main()
