#!/usr/bin/env python3
"""Planted-negative test suite for knowledge-state registry checker (fss-x4a.30.83.1).

Verifies fail-closed enforcement of:
1. Live repository passes with 0 errors across all 9 knowledge-state rows
2. Row added, removed, or count mismatch (ERR-KSTATE-REGISTRY-DRIFT-001)
3. Text or flag mismatch between JSON and Markdown mirror (ERR-KSTATE-REGISTRY-DRIFT-001)
4. Canonical registry digest mismatch (ERR-KSTATE-REGISTRY-DRIFT-001)
5. Stable ID duplicate, malformed, or renumbered (ERR-KSTATE-STABLE-ID-REUSED-001)
6. Mandatory field missing or empty in row (ERR-KSTATE-MISSING-FIELD-001)
7. Missing, corrupt, or invalid structure files (ERR-KSTATE-CORRUPT-FILE-001)
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

import knowledge_state_checker
from knowledge_state_checker import (
    ERR_KSTATE_CORRUPT_FILE,
    ERR_KSTATE_MISSING_FIELD,
    ERR_KSTATE_REGISTRY_DRIFT,
    ERR_KSTATE_STABLE_ID_REUSED,
    compute_canonical_knowledge_state_digest,
    validate_knowledge_state_registry,
)


class KnowledgeStateRegistryCheckerTests(unittest.TestCase):
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
            ROOT / "architecture/knowledge_states.json",
            self.fake_root / "architecture/knowledge_states.json",
        )

    def _read_json(self) -> dict:
        return json.loads((self.fake_root / "architecture/knowledge_states.json").read_text(encoding="utf-8"))

    def _write_json(self, data: dict) -> None:
        (self.fake_root / "architecture/knowledge_states.json").write_text(
            json.dumps(data, indent=2), encoding="utf-8"
        )

    def test_live_repository_passes_with_zero_errors(self) -> None:
        """The live repository must satisfy the knowledge-state registry contract with 0 errors."""
        res = validate_knowledge_state_registry(ROOT)
        self.assertTrue(res.passed, f"Live repository failed validation: {res.errors}")
        self.assertEqual(len(res.errors), 0)
        self.assertEqual(res.knowledge_state_count, 9)

    def test_planted_negative_row_missing_in_json(self) -> None:
        data = self._read_json()
        data["knowledgeStates"] = [r for r in data["knowledgeStates"] if r["id"] != "KSTATE-003"]
        data["registryDigest"] = compute_canonical_knowledge_state_digest(data["knowledgeStates"])
        self._write_json(data)

        res = validate_knowledge_state_registry(self.fake_root)
        self.assertFalse(res.passed)
        error_codes = [e.code for e in res.errors]
        self.assertIn(ERR_KSTATE_REGISTRY_DRIFT, error_codes)

    def test_planted_negative_row_missing_in_markdown(self) -> None:
        md_path = self.fake_root / "registries/AGENT_CONTRACTS.md"
        lines = md_path.read_text(encoding="utf-8").splitlines()
        filtered = [l for l in lines if "KSTATE-001" not in l]
        md_path.write_text("\n".join(filtered) + "\n", encoding="utf-8")

        res = validate_knowledge_state_registry(self.fake_root)
        self.assertFalse(res.passed)
        error_codes = [e.code for e in res.errors]
        self.assertIn(ERR_KSTATE_REGISTRY_DRIFT, error_codes)

    def test_planted_negative_state_name_mismatch(self) -> None:
        data = self._read_json()
        data["knowledgeStates"][0]["state"] = "tampered_state"
        data["registryDigest"] = compute_canonical_knowledge_state_digest(data["knowledgeStates"])
        self._write_json(data)

        res = validate_knowledge_state_registry(self.fake_root)
        self.assertFalse(res.passed)
        error_codes = [e.code for e in res.errors]
        self.assertIn(ERR_KSTATE_REGISTRY_DRIFT, error_codes)

    def test_planted_negative_meaning_mismatch(self) -> None:
        data = self._read_json()
        data["knowledgeStates"][0]["meaning"] = "tampered meaning"
        data["registryDigest"] = compute_canonical_knowledge_state_digest(data["knowledgeStates"])
        self._write_json(data)

        res = validate_knowledge_state_registry(self.fake_root)
        self.assertFalse(res.passed)
        error_codes = [e.code for e in res.errors]
        self.assertIn(ERR_KSTATE_REGISTRY_DRIFT, error_codes)

    def test_planted_negative_may_support_planning_mismatch(self) -> None:
        data = self._read_json()
        data["knowledgeStates"][0]["may_support_planning"] = "no"
        data["registryDigest"] = compute_canonical_knowledge_state_digest(data["knowledgeStates"])
        self._write_json(data)

        res = validate_knowledge_state_registry(self.fake_root)
        self.assertFalse(res.passed)
        error_codes = [e.code for e in res.errors]
        self.assertIn(ERR_KSTATE_REGISTRY_DRIFT, error_codes)

    def test_planted_negative_may_authorize_irreversible_effect_mismatch(self) -> None:
        data = self._read_json()
        data["knowledgeStates"][1]["may_authorize_irreversible_effect"] = "yes"
        data["registryDigest"] = compute_canonical_knowledge_state_digest(data["knowledgeStates"])
        self._write_json(data)

        res = validate_knowledge_state_registry(self.fake_root)
        self.assertFalse(res.passed)
        error_codes = [e.code for e in res.errors]
        self.assertIn(ERR_KSTATE_REGISTRY_DRIFT, error_codes)

    def test_planted_negative_explicit_assumptions_required_mismatch(self) -> None:
        data = self._read_json()
        data["knowledgeStates"][0]["explicit_assumptions_required"] = "yes"
        data["registryDigest"] = compute_canonical_knowledge_state_digest(data["knowledgeStates"])
        self._write_json(data)

        res = validate_knowledge_state_registry(self.fake_root)
        self.assertFalse(res.passed)
        error_codes = [e.code for e in res.errors]
        self.assertIn(ERR_KSTATE_REGISTRY_DRIFT, error_codes)

    def test_planted_negative_digest_mismatch(self) -> None:
        data = self._read_json()
        data["registryDigest"] = "sha256:0000000000000000000000000000000000000000000000000000000000000000"
        self._write_json(data)

        res = validate_knowledge_state_registry(self.fake_root)
        self.assertFalse(res.passed)
        error_codes = [e.code for e in res.errors]
        self.assertIn(ERR_KSTATE_REGISTRY_DRIFT, error_codes)

    def test_planted_negative_duplicate_stable_id(self) -> None:
        data = self._read_json()
        data["knowledgeStates"].append(dict(data["knowledgeStates"][0]))
        data["registryDigest"] = compute_canonical_knowledge_state_digest(data["knowledgeStates"])
        self._write_json(data)

        res = validate_knowledge_state_registry(self.fake_root)
        self.assertFalse(res.passed)
        error_codes = [e.code for e in res.errors]
        self.assertIn(ERR_KSTATE_STABLE_ID_REUSED, error_codes)

    def test_planted_negative_malformed_stable_id(self) -> None:
        data = self._read_json()
        data["knowledgeStates"][0]["id"] = "KSTATE-1"
        data["registryDigest"] = compute_canonical_knowledge_state_digest(data["knowledgeStates"])
        self._write_json(data)

        res = validate_knowledge_state_registry(self.fake_root)
        self.assertFalse(res.passed)
        error_codes = [e.code for e in res.errors]
        self.assertIn(ERR_KSTATE_STABLE_ID_REUSED, error_codes)

    def test_planted_negative_renumbered_stable_id(self) -> None:
        data = self._read_json()
        # Swap state names between KSTATE-001 and KSTATE-002
        data["knowledgeStates"][0]["state"] = "estimated"
        data["knowledgeStates"][1]["state"] = "known"
        data["registryDigest"] = compute_canonical_knowledge_state_digest(data["knowledgeStates"])
        self._write_json(data)

        res = validate_knowledge_state_registry(self.fake_root)
        self.assertFalse(res.passed)
        error_codes = [e.code for e in res.errors]
        self.assertIn(ERR_KSTATE_STABLE_ID_REUSED, error_codes)

    def test_planted_negative_missing_mandatory_field(self) -> None:
        data = self._read_json()
        del data["knowledgeStates"][0]["meaning"]
        data["registryDigest"] = compute_canonical_knowledge_state_digest(data["knowledgeStates"])
        self._write_json(data)

        res = validate_knowledge_state_registry(self.fake_root)
        self.assertFalse(res.passed)
        error_codes = [e.code for e in res.errors]
        self.assertIn(ERR_KSTATE_MISSING_FIELD, error_codes)

    def test_planted_negative_empty_mandatory_field(self) -> None:
        data = self._read_json()
        data["knowledgeStates"][0]["may_support_planning"] = "  "
        data["registryDigest"] = compute_canonical_knowledge_state_digest(data["knowledgeStates"])
        self._write_json(data)

        res = validate_knowledge_state_registry(self.fake_root)
        self.assertFalse(res.passed)
        error_codes = [e.code for e in res.errors]
        self.assertIn(ERR_KSTATE_MISSING_FIELD, error_codes)

    def test_planted_negative_missing_json_file(self) -> None:
        (self.fake_root / "architecture/knowledge_states.json").unlink()
        res = validate_knowledge_state_registry(self.fake_root)
        self.assertFalse(res.passed)
        error_codes = [e.code for e in res.errors]
        self.assertIn(ERR_KSTATE_CORRUPT_FILE, error_codes)

    def test_planted_negative_missing_markdown_file(self) -> None:
        (self.fake_root / "registries/AGENT_CONTRACTS.md").unlink()
        res = validate_knowledge_state_registry(self.fake_root)
        self.assertFalse(res.passed)
        error_codes = [e.code for e in res.errors]
        self.assertIn(ERR_KSTATE_CORRUPT_FILE, error_codes)

    def test_planted_negative_corrupt_json(self) -> None:
        (self.fake_root / "architecture/knowledge_states.json").write_text("{invalid json", encoding="utf-8")
        res = validate_knowledge_state_registry(self.fake_root)
        self.assertFalse(res.passed)
        error_codes = [e.code for e in res.errors]
        self.assertIn(ERR_KSTATE_CORRUPT_FILE, error_codes)

    def test_planted_negative_json_not_object(self) -> None:
        (self.fake_root / "architecture/knowledge_states.json").write_text("[]", encoding="utf-8")
        res = validate_knowledge_state_registry(self.fake_root)
        self.assertFalse(res.passed)
        error_codes = [e.code for e in res.errors]
        self.assertIn(ERR_KSTATE_CORRUPT_FILE, error_codes)

    def test_cli_execution(self) -> None:
        # CLI run on live repo passes with exit code 0
        cmd = [sys.executable, "-B", str(ROOT / "scripts/knowledge_state_checker.py"), "--json"]
        proc = subprocess.run(cmd, capture_output=True, text=True)
        self.assertEqual(proc.returncode, 0, f"CLI stderr: {proc.stderr}")
        parsed = json.loads(proc.stdout)
        self.assertTrue(parsed["passed"])
        self.assertEqual(parsed["knowledgeStateCount"], 9)
        self.assertEqual(parsed["errorCount"], 0)


if __name__ == "__main__":
    unittest.main()
