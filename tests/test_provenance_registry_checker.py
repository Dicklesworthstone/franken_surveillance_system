#!/usr/bin/env python3
"""Planted-negative test suite for provenance-class registry checker (fss-x4a.30.83.10).

Verifies fail-closed enforcement of:
1. Live repository passes with 0 errors across all 7 provenance-class rows and exact pinned freeze digest
2. Freeze divergence and self-referential digest bypass prevention (ERR-PROV-FREEZE-DIVERGENCE-001)
3. Canonical registry digest mismatch on metadata or row mutation (ERR-PROV-DIGEST-MISMATCH-001)
4. Generation mismatch and missing generation identity (ERR-PROV-GENERATION-MISMATCH-001)
5. Missing, duplicate, malformed, or renumbered stable IDs (ERR-PROV-STABLE-ID-REUSED-001)
6. Mandatory top-level or row field missing or empty (ERR-PROV-MISSING-FIELD-001)
7. Row drift between architecture JSON, baseline, and Markdown mirror (ERR-PROV-REGISTRY-DRIFT-001)
8. Missing, corrupt, or invalid structure files (ERR-PROV-CORRUPT-FILE-001)
"""
from __future__ import annotations

import json
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))

import provenance_registry_checker
from provenance_registry_checker import (
    BASELINE_FREEZE_DIGEST,
    BASELINE_GENERATION,
    ERR_PROV_CORRUPT_FILE,
    ERR_PROV_DIGEST_MISMATCH,
    ERR_PROV_FREEZE_DIVERGENCE,
    ERR_PROV_GENERATION_MISMATCH,
    ERR_PROV_MISSING_FIELD,
    ERR_PROV_REGISTRY_DRIFT,
    ERR_PROV_STABLE_ID_REUSED,
    compute_canonical_provenance_digest,
    validate_provenance_registry,
)


class ProvenanceRegistryCheckerTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp_dir = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp_dir.cleanup)
        self.fake_root = Path(self.temp_dir.name)

        # Replicate file hierarchy
        (self.fake_root / "architecture").mkdir(parents=True, exist_ok=True)
        (self.fake_root / "registries").mkdir(parents=True, exist_ok=True)

        shutil.copyfile(
            ROOT / "registries/AGENT_CONTRACTS.md",
            self.fake_root / "registries/AGENT_CONTRACTS.md",
        )
        shutil.copyfile(
            ROOT / "architecture/provenance_classes.json",
            self.fake_root / "architecture/provenance_classes.json",
        )

    def _read_json(self) -> dict:
        return json.loads((self.fake_root / "architecture/provenance_classes.json").read_text(encoding="utf-8"))

    def _write_json(self, data: dict) -> None:
        (self.fake_root / "architecture/provenance_classes.json").write_text(
            json.dumps(data, indent=2), encoding="utf-8"
        )

    def test_live_repository_passes_with_zero_errors(self) -> None:
        """The live repository must satisfy the provenance registry contract with 0 errors and pinned digest."""
        res = validate_provenance_registry(ROOT)
        self.assertTrue(res.passed, f"Live repository failed validation: {res.errors}")
        self.assertEqual(len(res.errors), 0)
        self.assertEqual(res.provenance_class_count, 7)
        self.assertEqual(res.registry_digest, BASELINE_FREEZE_DIGEST)

    def test_planted_negative_freeze_divergence(self) -> None:
        """Declared digest differing from pinned freeze digest must emit ERR-PROV-FREEZE-DIVERGENCE-001."""
        data = self._read_json()
        data["registryDigest"] = "sha256:0000000000000000000000000000000000000000000000000000000000000000"
        self._write_json(data)

        res = validate_provenance_registry(self.fake_root)
        self.assertFalse(res.passed)
        error_codes = [e.code for e in res.errors]
        self.assertIn(ERR_PROV_FREEZE_DIVERGENCE, error_codes)
        self.assertIn(ERR_PROV_DIGEST_MISMATCH, error_codes)

    def test_planted_negative_self_referential_bypass_prevented(self) -> None:
        """Tampering a definition and recomputing digest must NOT bypass the pinned freeze digest."""
        data = self._read_json()
        data["provenanceClasses"][0]["meaning"] = "compromised definition"
        data["registryDigest"] = compute_canonical_provenance_digest(data)
        self._write_json(data)

        res = validate_provenance_registry(self.fake_root)
        self.assertFalse(res.passed)
        error_codes = [e.code for e in res.errors]
        self.assertIn(ERR_PROV_FREEZE_DIVERGENCE, error_codes)
        self.assertIn(ERR_PROV_REGISTRY_DRIFT, error_codes)

    def test_planted_negative_generation_mismatch(self) -> None:
        """Unrecognized or unpinned generation must emit ERR-PROV-GENERATION-MISMATCH-001."""
        data = self._read_json()
        data["generation"] = "gen:fss1:provenance-v2"
        data["registryDigest"] = compute_canonical_provenance_digest(data)
        self._write_json(data)

        res = validate_provenance_registry(self.fake_root)
        self.assertFalse(res.passed)
        error_codes = [e.code for e in res.errors]
        self.assertIn(ERR_PROV_GENERATION_MISMATCH, error_codes)

    def test_planted_negative_missing_generation(self) -> None:
        """Missing generation property must emit ERR-PROV-GENERATION-MISMATCH-001 and ERR-PROV-MISSING-FIELD-001."""
        data = self._read_json()
        del data["generation"]
        self._write_json(data)

        res = validate_provenance_registry(self.fake_root)
        self.assertFalse(res.passed)
        error_codes = [e.code for e in res.errors]
        self.assertIn(ERR_PROV_GENERATION_MISMATCH, error_codes)
        self.assertIn(ERR_PROV_MISSING_FIELD, error_codes)

    def test_planted_negative_missing_baseline_id(self) -> None:
        """Omitting a baseline ID must emit ERR-PROV-STABLE-ID-REUSED-001."""
        data = self._read_json()
        data["provenanceClasses"] = [r for r in data["provenanceClasses"] if r["id"] != "PROV-003"]
        self._write_json(data)

        res = validate_provenance_registry(self.fake_root)
        self.assertFalse(res.passed)
        error_codes = [e.code for e in res.errors]
        self.assertIn(ERR_PROV_STABLE_ID_REUSED, error_codes)

    def test_planted_negative_renumbered_id_to_non_baseline(self) -> None:
        """Renumbering a baseline ID to a non-baseline ID (PROV-010) must emit ERR-PROV-STABLE-ID-REUSED-001."""
        data = self._read_json()
        data["provenanceClasses"][0]["id"] = "PROV-010"
        self._write_json(data)

        res = validate_provenance_registry(self.fake_root)
        self.assertFalse(res.passed)
        error_codes = [e.code for e in res.errors]
        self.assertIn(ERR_PROV_STABLE_ID_REUSED, error_codes)

    def test_planted_negative_top_level_metadata_missing(self) -> None:
        """Missing top-level metadata field must emit ERR-PROV-MISSING-FIELD-001."""
        data = self._read_json()
        del data["constitutionalDocument"]
        self._write_json(data)

        res = validate_provenance_registry(self.fake_root)
        self.assertFalse(res.passed)
        error_codes = [e.code for e in res.errors]
        self.assertIn(ERR_PROV_MISSING_FIELD, error_codes)

    def test_planted_negative_top_level_metadata_tampered_digest_mismatch(self) -> None:
        """Mutating top-level metadata must invalidate the canonical digest."""
        data = self._read_json()
        data["constitutionalDocument"] = "OTHER_DOC.md"
        self._write_json(data)

        res = validate_provenance_registry(self.fake_root)
        self.assertFalse(res.passed)
        error_codes = [e.code for e in res.errors]
        self.assertIn(ERR_PROV_DIGEST_MISMATCH, error_codes)

    def test_planted_negative_row_missing_in_json(self) -> None:
        data = self._read_json()
        data["provenanceClasses"] = [r for r in data["provenanceClasses"] if r["id"] != "PROV-003"]
        self._write_json(data)

        res = validate_provenance_registry(self.fake_root)
        self.assertFalse(res.passed)
        error_codes = [e.code for e in res.errors]
        self.assertIn(ERR_PROV_REGISTRY_DRIFT, error_codes)

    def test_planted_negative_row_missing_in_markdown(self) -> None:
        md_path = self.fake_root / "registries/AGENT_CONTRACTS.md"
        lines = md_path.read_text(encoding="utf-8").splitlines()
        filtered = [l for l in lines if "PROV-001" not in l]
        md_path.write_text("\n".join(filtered) + "\n", encoding="utf-8")

        res = validate_provenance_registry(self.fake_root)
        self.assertFalse(res.passed)
        error_codes = [e.code for e in res.errors]
        self.assertIn(ERR_PROV_REGISTRY_DRIFT, error_codes)

    def test_planted_negative_class_name_mismatch(self) -> None:
        data = self._read_json()
        data["provenanceClasses"][0]["class"] = "tampered_class"
        self._write_json(data)

        res = validate_provenance_registry(self.fake_root)
        self.assertFalse(res.passed)
        error_codes = [e.code for e in res.errors]
        self.assertIn(ERR_PROV_REGISTRY_DRIFT, error_codes)

    def test_planted_negative_meaning_mismatch(self) -> None:
        data = self._read_json()
        data["provenanceClasses"][0]["meaning"] = "tampered meaning"
        self._write_json(data)

        res = validate_provenance_registry(self.fake_root)
        self.assertFalse(res.passed)
        error_codes = [e.code for e in res.errors]
        self.assertIn(ERR_PROV_REGISTRY_DRIFT, error_codes)

    def test_planted_negative_duplicate_stable_id(self) -> None:
        data = self._read_json()
        data["provenanceClasses"].append(dict(data["provenanceClasses"][0]))
        self._write_json(data)

        res = validate_provenance_registry(self.fake_root)
        self.assertFalse(res.passed)
        error_codes = [e.code for e in res.errors]
        self.assertIn(ERR_PROV_STABLE_ID_REUSED, error_codes)

    def test_planted_negative_malformed_stable_id(self) -> None:
        data = self._read_json()
        data["provenanceClasses"][0]["id"] = "PROV-1"
        self._write_json(data)

        res = validate_provenance_registry(self.fake_root)
        self.assertFalse(res.passed)
        error_codes = [e.code for e in res.errors]
        self.assertIn(ERR_PROV_STABLE_ID_REUSED, error_codes)

    def test_planted_negative_renumbered_stable_id(self) -> None:
        data = self._read_json()
        # Swap class names between PROV-001 and PROV-002
        data["provenanceClasses"][0]["class"] = "derived"
        data["provenanceClasses"][1]["class"] = "observed"
        self._write_json(data)

        res = validate_provenance_registry(self.fake_root)
        self.assertFalse(res.passed)
        error_codes = [e.code for e in res.errors]
        self.assertIn(ERR_PROV_REGISTRY_DRIFT, error_codes)

    def test_planted_negative_missing_mandatory_field(self) -> None:
        data = self._read_json()
        del data["provenanceClasses"][0]["meaning"]
        self._write_json(data)

        res = validate_provenance_registry(self.fake_root)
        self.assertFalse(res.passed)
        error_codes = [e.code for e in res.errors]
        self.assertIn(ERR_PROV_MISSING_FIELD, error_codes)

    def test_planted_negative_empty_mandatory_field(self) -> None:
        data = self._read_json()
        data["provenanceClasses"][0]["meaning"] = "  "
        self._write_json(data)

        res = validate_provenance_registry(self.fake_root)
        self.assertFalse(res.passed)
        error_codes = [e.code for e in res.errors]
        self.assertIn(ERR_PROV_MISSING_FIELD, error_codes)

    def test_planted_negative_missing_json_file(self) -> None:
        (self.fake_root / "architecture/provenance_classes.json").unlink()
        res = validate_provenance_registry(self.fake_root)
        self.assertFalse(res.passed)
        error_codes = [e.code for e in res.errors]
        self.assertIn(ERR_PROV_CORRUPT_FILE, error_codes)

    def test_planted_negative_missing_markdown_file(self) -> None:
        (self.fake_root / "registries/AGENT_CONTRACTS.md").unlink()
        res = validate_provenance_registry(self.fake_root)
        self.assertFalse(res.passed)
        error_codes = [e.code for e in res.errors]
        self.assertIn(ERR_PROV_CORRUPT_FILE, error_codes)

    def test_planted_negative_corrupt_json(self) -> None:
        (self.fake_root / "architecture/provenance_classes.json").write_text("{invalid json", encoding="utf-8")
        res = validate_provenance_registry(self.fake_root)
        self.assertFalse(res.passed)
        error_codes = [e.code for e in res.errors]
        self.assertIn(ERR_PROV_CORRUPT_FILE, error_codes)

    def test_planted_negative_json_not_object(self) -> None:
        (self.fake_root / "architecture/provenance_classes.json").write_text("[]", encoding="utf-8")
        res = validate_provenance_registry(self.fake_root)
        self.assertFalse(res.passed)
        error_codes = [e.code for e in res.errors]
        self.assertIn(ERR_PROV_CORRUPT_FILE, error_codes)

    def test_cli_execution(self) -> None:
        cmd = [sys.executable, "-B", str(ROOT / "scripts/provenance_registry_checker.py"), "--json"]
        proc = subprocess.run(cmd, capture_output=True, text=True)
        self.assertEqual(proc.returncode, 0, f"CLI stderr: {proc.stderr}")
        parsed = json.loads(proc.stdout)
        self.assertTrue(parsed["passed"])
        self.assertEqual(parsed["provenanceClassCount"], 7)
        self.assertEqual(parsed["registryDigest"], BASELINE_FREEZE_DIGEST)
        self.assertEqual(parsed["errorCount"], 0)


if __name__ == "__main__":
    unittest.main()
