#!/usr/bin/env python3
"""Planted-negative test suite for knowledge-state registry checker (fss-x4a.30.83.1).

Verifies fail-closed enforcement of:
1. Live repository passes with 0 errors across all 9 knowledge-state rows and exact pinned freeze digest
2. Freeze divergence and self-referential digest bypass prevention (ERR-KSTATE-FREEZE-DIVERGENCE-001)
3. Canonical registry digest mismatch on metadata or row mutation (ERR-KSTATE-DIGEST-MISMATCH-001)
4. Generation mismatch and missing generation identity (ERR-KSTATE-GENERATION-MISMATCH-001)
5. Non-known knowledge state illegally authorizing irreversible effect (ERR-KSTATE-ILLEGAL-IRREVERSIBLE-AUTH-001)
6. Known state missing full qualification for irreversible effect (ERR-KSTATE-ILLEGAL-IRREVERSIBLE-AUTH-001)
7. Missing, duplicate, malformed, or renumbered stable IDs (ERR-KSTATE-STABLE-ID-REUSED-001)
8. Mandatory top-level or row field missing or empty (ERR-KSTATE-MISSING-FIELD-001)
9. Row drift between architecture JSON, baseline, and Markdown mirror (ERR-KSTATE-REGISTRY-DRIFT-001)
10. Missing, corrupt, or invalid structure files (ERR-KSTATE-CORRUPT-FILE-001)
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
    BASELINE_FREEZE_DIGEST,
    BASELINE_GENERATION,
    ERR_KSTATE_CORRUPT_FILE,
    ERR_KSTATE_DIGEST_MISMATCH,
    ERR_KSTATE_FREEZE_DIVERGENCE,
    ERR_KSTATE_GENERATION_MISMATCH,
    ERR_KSTATE_ILLEGAL_IRREVERSIBLE_AUTH,
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
        """The live repository must satisfy the knowledge-state registry contract with 0 errors and pinned digest."""
        res = validate_knowledge_state_registry(ROOT)
        self.assertTrue(res.passed, f"Live repository failed validation: {res.errors}")
        self.assertEqual(len(res.errors), 0)
        self.assertEqual(res.knowledge_state_count, 9)
        self.assertEqual(res.registry_digest, BASELINE_FREEZE_DIGEST)

    def test_planted_negative_freeze_divergence(self) -> None:
        """Declared digest differing from pinned freeze digest must emit ERR-KSTATE-FREEZE-DIVERGENCE-001."""
        data = self._read_json()
        data["registryDigest"] = "sha256:0000000000000000000000000000000000000000000000000000000000000000"
        self._write_json(data)

        res = validate_knowledge_state_registry(self.fake_root)
        self.assertFalse(res.passed)
        error_codes = [e.code for e in res.errors]
        self.assertIn(ERR_KSTATE_FREEZE_DIVERGENCE, error_codes)
        self.assertIn(ERR_KSTATE_DIGEST_MISMATCH, error_codes)

    def test_planted_negative_self_referential_bypass_prevented(self) -> None:
        """Tampering a definition and recomputing digest must NOT bypass the pinned freeze digest."""
        data = self._read_json()
        data["knowledgeStates"][0]["meaning"] = "compromised definition"
        data["registryDigest"] = compute_canonical_knowledge_state_digest(data)
        self._write_json(data)

        res = validate_knowledge_state_registry(self.fake_root)
        self.assertFalse(res.passed)
        error_codes = [e.code for e in res.errors]
        self.assertIn(ERR_KSTATE_FREEZE_DIVERGENCE, error_codes)
        self.assertIn(ERR_KSTATE_REGISTRY_DRIFT, error_codes)

    def test_planted_negative_generation_mismatch(self) -> None:
        """Unrecognized or unpinned generation must emit ERR-KSTATE-GENERATION-MISMATCH-001."""
        data = self._read_json()
        data["generation"] = "gen:fss1:kstate-v2"
        data["registryDigest"] = compute_canonical_knowledge_state_digest(data)
        self._write_json(data)

        res = validate_knowledge_state_registry(self.fake_root)
        self.assertFalse(res.passed)
        error_codes = [e.code for e in res.errors]
        self.assertIn(ERR_KSTATE_GENERATION_MISMATCH, error_codes)

    def test_planted_negative_missing_generation(self) -> None:
        """Missing generation property must emit ERR-KSTATE-GENERATION-MISMATCH-001 and ERR-KSTATE-MISSING-FIELD-001."""
        data = self._read_json()
        del data["generation"]
        self._write_json(data)

        res = validate_knowledge_state_registry(self.fake_root)
        self.assertFalse(res.passed)
        error_codes = [e.code for e in res.errors]
        self.assertIn(ERR_KSTATE_GENERATION_MISMATCH, error_codes)
        self.assertIn(ERR_KSTATE_MISSING_FIELD, error_codes)

    def test_planted_negative_non_known_authorizes_irreversible_effect_json(self) -> None:
        """A non-known state (e.g. unknown) authorizing irreversible effects must fail closed."""
        data = self._read_json()
        data["knowledgeStates"][2]["may_authorize_irreversible_effect"] = "yes"
        self._write_json(data)

        res = validate_knowledge_state_registry(self.fake_root)
        self.assertFalse(res.passed)
        error_codes = [e.code for e in res.errors]
        self.assertIn(ERR_KSTATE_ILLEGAL_IRREVERSIBLE_AUTH, error_codes)

    def test_planted_negative_non_known_authorizes_irreversible_effect_both_json_and_md(self) -> None:
        """Synchronously setting may_authorize_irreversible_effect to yes on unknown in JSON and MD must fail closed."""
        data = self._read_json()
        data["knowledgeStates"][2]["may_authorize_irreversible_effect"] = "yes"
        self._write_json(data)

        md_path = self.fake_root / "registries/AGENT_CONTRACTS.md"
        content = md_path.read_text(encoding="utf-8")
        # Replace KSTATE-003 row with may_authorize_irreversible_effect = yes
        content = content.replace(
            "| `KSTATE-003` | `unknown` | The authorized evidence acquired so far does not establish the proposition. | yes, as an explicit branch or open variable | no | yes |",
            "| `KSTATE-003` | `unknown` | The authorized evidence acquired so far does not establish the proposition. | yes, as an explicit branch or open variable | yes | yes |",
        )
        md_path.write_text(content, encoding="utf-8")

        res = validate_knowledge_state_registry(self.fake_root)
        self.assertFalse(res.passed)
        error_codes = [e.code for e in res.errors]
        self.assertIn(ERR_KSTATE_ILLEGAL_IRREVERSIBLE_AUTH, error_codes)

    def test_planted_negative_known_tampered_irreversible_effect(self) -> None:
        """Tampering known state irreversible effect qualifier must fail closed."""
        data = self._read_json()
        data["knowledgeStates"][0]["may_authorize_irreversible_effect"] = "yes"
        self._write_json(data)

        res = validate_knowledge_state_registry(self.fake_root)
        self.assertFalse(res.passed)
        error_codes = [e.code for e in res.errors]
        self.assertIn(ERR_KSTATE_ILLEGAL_IRREVERSIBLE_AUTH, error_codes)

    def test_planted_negative_missing_baseline_id(self) -> None:
        """Omitting a baseline ID must emit ERR-KSTATE-STABLE-ID-REUSED-001."""
        data = self._read_json()
        data["knowledgeStates"] = [r for r in data["knowledgeStates"] if r["id"] != "KSTATE-003"]
        self._write_json(data)

        res = validate_knowledge_state_registry(self.fake_root)
        self.assertFalse(res.passed)
        error_codes = [e.code for e in res.errors]
        self.assertIn(ERR_KSTATE_STABLE_ID_REUSED, error_codes)

    def test_planted_negative_renumbered_id_to_non_baseline(self) -> None:
        """Renumbering a baseline ID to a non-baseline ID (KSTATE-010) must emit ERR-KSTATE-STABLE-ID-REUSED-001."""
        data = self._read_json()
        data["knowledgeStates"][0]["id"] = "KSTATE-010"
        self._write_json(data)

        res = validate_knowledge_state_registry(self.fake_root)
        self.assertFalse(res.passed)
        error_codes = [e.code for e in res.errors]
        self.assertIn(ERR_KSTATE_STABLE_ID_REUSED, error_codes)

    def test_planted_negative_top_level_metadata_missing(self) -> None:
        """Missing top-level metadata field must emit ERR-KSTATE-MISSING-FIELD-001."""
        data = self._read_json()
        del data["constitutionalDocument"]
        self._write_json(data)

        res = validate_knowledge_state_registry(self.fake_root)
        self.assertFalse(res.passed)
        error_codes = [e.code for e in res.errors]
        self.assertIn(ERR_KSTATE_MISSING_FIELD, error_codes)

    def test_planted_negative_top_level_metadata_tampered_digest_mismatch(self) -> None:
        """Mutating top-level metadata must invalidate the canonical digest."""
        data = self._read_json()
        data["constitutionalDocument"] = "OTHER_DOC.md"
        self._write_json(data)

        res = validate_knowledge_state_registry(self.fake_root)
        self.assertFalse(res.passed)
        error_codes = [e.code for e in res.errors]
        self.assertIn(ERR_KSTATE_DIGEST_MISMATCH, error_codes)

    def test_planted_negative_row_missing_in_json(self) -> None:
        data = self._read_json()
        data["knowledgeStates"] = [r for r in data["knowledgeStates"] if r["id"] != "KSTATE-003"]
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
        self._write_json(data)

        res = validate_knowledge_state_registry(self.fake_root)
        self.assertFalse(res.passed)
        error_codes = [e.code for e in res.errors]
        self.assertIn(ERR_KSTATE_REGISTRY_DRIFT, error_codes)

    def test_planted_negative_meaning_mismatch(self) -> None:
        data = self._read_json()
        data["knowledgeStates"][0]["meaning"] = "tampered meaning"
        self._write_json(data)

        res = validate_knowledge_state_registry(self.fake_root)
        self.assertFalse(res.passed)
        error_codes = [e.code for e in res.errors]
        self.assertIn(ERR_KSTATE_REGISTRY_DRIFT, error_codes)

    def test_planted_negative_may_support_planning_mismatch(self) -> None:
        data = self._read_json()
        data["knowledgeStates"][0]["may_support_planning"] = "no"
        self._write_json(data)

        res = validate_knowledge_state_registry(self.fake_root)
        self.assertFalse(res.passed)
        error_codes = [e.code for e in res.errors]
        self.assertIn(ERR_KSTATE_REGISTRY_DRIFT, error_codes)

    def test_planted_negative_may_authorize_irreversible_effect_mismatch(self) -> None:
        data = self._read_json()
        data["knowledgeStates"][1]["may_authorize_irreversible_effect"] = "yes"
        self._write_json(data)

        res = validate_knowledge_state_registry(self.fake_root)
        self.assertFalse(res.passed)
        error_codes = [e.code for e in res.errors]
        self.assertIn(ERR_KSTATE_ILLEGAL_IRREVERSIBLE_AUTH, error_codes)

    def test_planted_negative_explicit_assumptions_required_mismatch(self) -> None:
        data = self._read_json()
        data["knowledgeStates"][0]["explicit_assumptions_required"] = "yes"
        self._write_json(data)

        res = validate_knowledge_state_registry(self.fake_root)
        self.assertFalse(res.passed)
        error_codes = [e.code for e in res.errors]
        self.assertIn(ERR_KSTATE_REGISTRY_DRIFT, error_codes)

    def test_planted_negative_duplicate_stable_id(self) -> None:
        data = self._read_json()
        data["knowledgeStates"].append(dict(data["knowledgeStates"][0]))
        self._write_json(data)

        res = validate_knowledge_state_registry(self.fake_root)
        self.assertFalse(res.passed)
        error_codes = [e.code for e in res.errors]
        self.assertIn(ERR_KSTATE_STABLE_ID_REUSED, error_codes)

    def test_planted_negative_malformed_stable_id(self) -> None:
        data = self._read_json()
        data["knowledgeStates"][0]["id"] = "KSTATE-1"
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
        self._write_json(data)

        res = validate_knowledge_state_registry(self.fake_root)
        self.assertFalse(res.passed)
        error_codes = [e.code for e in res.errors]
        self.assertIn(ERR_KSTATE_REGISTRY_DRIFT, error_codes)

    def test_planted_negative_missing_mandatory_field(self) -> None:
        data = self._read_json()
        del data["knowledgeStates"][0]["meaning"]
        self._write_json(data)

        res = validate_knowledge_state_registry(self.fake_root)
        self.assertFalse(res.passed)
        error_codes = [e.code for e in res.errors]
        self.assertIn(ERR_KSTATE_MISSING_FIELD, error_codes)

    def test_planted_negative_empty_mandatory_field(self) -> None:
        data = self._read_json()
        data["knowledgeStates"][0]["may_support_planning"] = "  "
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
        # CLI run on live repo passes with exit code 0 and exact digest
        cmd = [sys.executable, "-B", str(ROOT / "scripts/knowledge_state_checker.py"), "--json"]
        proc = subprocess.run(cmd, capture_output=True, text=True)
        self.assertEqual(proc.returncode, 0, f"CLI stderr: {proc.stderr}")
        parsed = json.loads(proc.stdout)
        self.assertTrue(parsed["passed"])
        self.assertEqual(parsed["knowledgeStateCount"], 9)
        self.assertEqual(parsed["registryDigest"], BASELINE_FREEZE_DIGEST)
        self.assertEqual(parsed["errorCount"], 0)


if __name__ == "__main__":
    unittest.main()
