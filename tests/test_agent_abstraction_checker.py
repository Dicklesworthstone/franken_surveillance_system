#!/usr/bin/env python3
"""Planted-negative test suite for agent abstraction stack registry checker (fss-x4a.30.82.4).

Verifies fail-closed enforcement of:
1. Live repository passes with 0 errors across all 11 abstraction layers and exact pinned freeze digest
2. Freeze divergence and self-referential digest bypass prevention (ERR-AGT-FREEZE-DIVERGENCE-001)
3. Canonical registry digest mismatch on metadata or row mutation (ERR-AGT-DIGEST-MISMATCH-001)
4. Generation mismatch and missing generation identity (ERR-AGT-GENERATION-MISMATCH-001)
5. Derived beliefs (AGT-LAYER-004) cannot claim authority ownership (ERR-AGT-ILLEGAL-AUTHORITY-001)
6. Derived beliefs (AGT-LAYER-004) cannot authorize effects (ERR-AGT-ILLEGAL-AUTHORITY-001)
7. Derived beliefs (AGT-LAYER-004) invariant must be INV-069 (ERR-AGT-INVARIANT-VIOLATION-001)
8. Missing, duplicate, malformed, or renumbered stable IDs (ERR-AGT-STABLE-ID-REUSED-001)
9. Canonical tower ordering violation (ERR-AGT-REGISTRY-DRIFT-001)
10. Mandatory top-level or row field missing or empty (ERR-AGT-MISSING-FIELD-001)
11. Row drift between architecture JSON, baseline, and Markdown mirror (ERR-AGT-REGISTRY-DRIFT-001)
12. Missing, corrupt, or invalid structure files (ERR-AGT-CORRUPT-FILE-001)
"""
from __future__ import annotations

import json
import shutil
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))

import agent_abstraction_checker
from agent_abstraction_checker import (
    BASELINE_FREEZE_DIGEST,
    BASELINE_GENERATION,
    ERR_AGT_CORRUPT_FILE,
    ERR_AGT_DIGEST_MISMATCH,
    ERR_AGT_FREEZE_DIVERGENCE,
    ERR_AGT_GENERATION_MISMATCH,
    ERR_AGT_ILLEGAL_AUTHORITY,
    ERR_AGT_INVARIANT_VIOLATION,
    ERR_AGT_MISSING_FIELD,
    ERR_AGT_REGISTRY_DRIFT,
    ERR_AGT_STABLE_ID_REUSED,
    compute_canonical_agent_abstraction_digest,
    validate_agent_abstraction_registry,
)


class AgentAbstractionRegistryCheckerTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp_dir = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp_dir.cleanup)
        self.fake_root = Path(self.temp_dir.name)

        # Replicate file hierarchy
        (self.fake_root / "architecture").mkdir(parents=True, exist_ok=True)
        (self.fake_root / "registries").mkdir(parents=True, exist_ok=True)

        shutil.copyfile(
            ROOT / "registries/AGENT_ABSTRACTIONS.md",
            self.fake_root / "registries/AGENT_ABSTRACTIONS.md",
        )
        shutil.copyfile(
            ROOT / "architecture/agent_abstraction_stack.json",
            self.fake_root / "architecture/agent_abstraction_stack.json",
        )

    def _read_json(self) -> dict:
        return json.loads((self.fake_root / "architecture/agent_abstraction_stack.json").read_text(encoding="utf-8"))

    def _write_json(self, data: dict) -> None:
        (self.fake_root / "architecture/agent_abstraction_stack.json").write_text(
            json.dumps(data, indent=2), encoding="utf-8"
        )

    def test_live_repository_passes_with_zero_errors(self) -> None:
        """The live repository must satisfy the agent abstraction registry contract with 0 errors and pinned digest."""
        res = validate_agent_abstraction_registry(ROOT)
        self.assertTrue(res.passed, f"Live repository failed validation: {res.errors}")
        self.assertEqual(len(res.errors), 0)
        self.assertEqual(res.layer_count, 11)
        self.assertEqual(res.registry_digest, BASELINE_FREEZE_DIGEST)

    def test_planted_negative_freeze_divergence(self) -> None:
        """Declared digest differing from pinned freeze digest must emit ERR-AGT-FREEZE-DIVERGENCE-001."""
        data = self._read_json()
        data["registryDigest"] = "sha256:0000000000000000000000000000000000000000000000000000000000000000"
        self._write_json(data)

        res = validate_agent_abstraction_registry(self.fake_root)
        self.assertFalse(res.passed)
        error_codes = [e.code for e in res.errors]
        self.assertIn(ERR_AGT_FREEZE_DIVERGENCE, error_codes)
        self.assertIn(ERR_AGT_DIGEST_MISMATCH, error_codes)

    def test_planted_negative_self_referential_bypass_prevented(self) -> None:
        """Tampering a definition and recomputing digest must NOT bypass the pinned freeze digest."""
        data = self._read_json()
        # Tamper AGT-LAYER-004 question
        for layer in data["layers"]:
            if layer["id"] == "AGT-LAYER-004":
                layer["question"] = "Tampered question attempting self-referential bypass"
                break
        data["registryDigest"] = compute_canonical_agent_abstraction_digest(data)
        self._write_json(data)

        res = validate_agent_abstraction_registry(self.fake_root)
        self.assertFalse(res.passed)
        error_codes = [e.code for e in res.errors]
        self.assertIn(ERR_AGT_FREEZE_DIVERGENCE, error_codes)
        self.assertIn(ERR_AGT_REGISTRY_DRIFT, error_codes)

    def test_planted_negative_generation_mismatch(self) -> None:
        """Unrecognized or unpinned generation must emit ERR-AGT-GENERATION-MISMATCH-001."""
        data = self._read_json()
        data["generation"] = "gen:fss1:abstraction-v2"
        data["registryDigest"] = compute_canonical_agent_abstraction_digest(data)
        self._write_json(data)

        res = validate_agent_abstraction_registry(self.fake_root)
        self.assertFalse(res.passed)
        error_codes = [e.code for e in res.errors]
        self.assertIn(ERR_AGT_GENERATION_MISMATCH, error_codes)

    def test_planted_negative_missing_generation(self) -> None:
        """Missing generation property must emit ERR-AGT-GENERATION-MISMATCH-001 and ERR-AGT-MISSING-FIELD-001."""
        data = self._read_json()
        del data["generation"]
        self._write_json(data)

        res = validate_agent_abstraction_registry(self.fake_root)
        self.assertFalse(res.passed)
        error_codes = [e.code for e in res.errors]
        self.assertIn(ERR_AGT_GENERATION_MISMATCH, error_codes)
        self.assertIn(ERR_AGT_MISSING_FIELD, error_codes)

    def test_planted_negative_derived_beliefs_cannot_claim_authority(self) -> None:
        """Derived beliefs claiming authority owner must emit ERR-AGT-ILLEGAL-AUTHORITY-001."""
        data = self._read_json()
        for layer in data["layers"]:
            if layer["id"] == "AGT-LAYER-004":
                layer["owner"] = "asupersync/authority/derived_authority"
                break
        data["registryDigest"] = compute_canonical_agent_abstraction_digest(data)
        self._write_json(data)

        res = validate_agent_abstraction_registry(self.fake_root)
        self.assertFalse(res.passed)
        error_codes = [e.code for e in res.errors]
        self.assertIn(ERR_AGT_ILLEGAL_AUTHORITY, error_codes)

    def test_planted_negative_derived_beliefs_cannot_authorize_effects(self) -> None:
        """Derived beliefs prohibition weakened to allow effect authorization must emit ERR-AGT-ILLEGAL-AUTHORITY-001."""
        data = self._read_json()
        for layer in data["layers"]:
            if layer["id"] == "AGT-LAYER-004":
                layer["prohibition"] = "May authorize non-reversible effects directly."
                break
        data["registryDigest"] = compute_canonical_agent_abstraction_digest(data)
        self._write_json(data)

        res = validate_agent_abstraction_registry(self.fake_root)
        self.assertFalse(res.passed)
        error_codes = [e.code for e in res.errors]
        self.assertIn(ERR_AGT_ILLEGAL_AUTHORITY, error_codes)

    def test_planted_negative_derived_beliefs_invariant_must_be_inv069(self) -> None:
        """Derived beliefs invariant set to wrong invariant must emit ERR-AGT-INVARIANT-VIOLATION-001."""
        data = self._read_json()
        for layer in data["layers"]:
            if layer["id"] == "AGT-LAYER-004":
                layer["invariant"] = "INV-001"
                break
        data["registryDigest"] = compute_canonical_agent_abstraction_digest(data)
        self._write_json(data)

        res = validate_agent_abstraction_registry(self.fake_root)
        self.assertFalse(res.passed)
        error_codes = [e.code for e in res.errors]
        self.assertIn(ERR_AGT_INVARIANT_VIOLATION, error_codes)

    def test_planted_negative_missing_mandatory_top_level_field(self) -> None:
        """Missing top-level field must emit ERR-AGT-MISSING-FIELD-001."""
        data = self._read_json()
        del data["constitutionalRole"]
        self._write_json(data)

        res = validate_agent_abstraction_registry(self.fake_root)
        self.assertFalse(res.passed)
        error_codes = [e.code for e in res.errors]
        self.assertIn(ERR_AGT_MISSING_FIELD, error_codes)

    def test_planted_negative_missing_mandatory_layer_field(self) -> None:
        """Missing mandatory layer field must emit ERR-AGT-MISSING-FIELD-001."""
        data = self._read_json()
        for layer in data["layers"]:
            if layer["id"] == "AGT-LAYER-004":
                del layer["output"]
                break
        self._write_json(data)

        res = validate_agent_abstraction_registry(self.fake_root)
        self.assertFalse(res.passed)
        error_codes = [e.code for e in res.errors]
        self.assertIn(ERR_AGT_MISSING_FIELD, error_codes)

    def test_planted_negative_empty_layer_field(self) -> None:
        """Empty layer field must emit ERR-AGT-MISSING-FIELD-001."""
        data = self._read_json()
        for layer in data["layers"]:
            if layer["id"] == "AGT-LAYER-004":
                layer["question"] = "   "
                break
        self._write_json(data)

        res = validate_agent_abstraction_registry(self.fake_root)
        self.assertFalse(res.passed)
        error_codes = [e.code for e in res.errors]
        self.assertIn(ERR_AGT_MISSING_FIELD, error_codes)

    def test_planted_negative_duplicate_layer_id(self) -> None:
        """Duplicate layer ID must emit ERR-AGT-STABLE-ID-REUSED-001."""
        data = self._read_json()
        dup = dict(data["layers"][3])  # AGT-LAYER-004
        data["layers"].append(dup)
        self._write_json(data)

        res = validate_agent_abstraction_registry(self.fake_root)
        self.assertFalse(res.passed)
        error_codes = [e.code for e in res.errors]
        self.assertIn(ERR_AGT_STABLE_ID_REUSED, error_codes)

    def test_planted_negative_renumbered_layer_id(self) -> None:
        """Renumbered layer ID must emit ERR-AGT-STABLE-ID-REUSED-001."""
        data = self._read_json()
        for layer in data["layers"]:
            if layer["id"] == "AGT-LAYER-004":
                layer["id"] = "AGT-LAYER-999"
                break
        self._write_json(data)

        res = validate_agent_abstraction_registry(self.fake_root)
        self.assertFalse(res.passed)
        error_codes = [e.code for e in res.errors]
        self.assertIn(ERR_AGT_STABLE_ID_REUSED, error_codes)

    def test_planted_negative_extra_unknown_layer(self) -> None:
        """Un-baselined layer ID introduced must emit ERR-AGT-STABLE-ID-REUSED-001."""
        data = self._read_json()
        new_layer = {
            "id": "AGT-LAYER-012",
            "name": "speculative_future_layer",
            "owner": "fss-future",
            "question": "What future capability exists?",
            "output": "Projections",
            "prohibition": "Cannot do anything",
            "invariant": "INV-001",
            "status": "draft",
        }
        data["layers"].append(new_layer)
        self._write_json(data)

        res = validate_agent_abstraction_registry(self.fake_root)
        self.assertFalse(res.passed)
        error_codes = [e.code for e in res.errors]
        self.assertIn(ERR_AGT_STABLE_ID_REUSED, error_codes)

    def test_planted_negative_canonical_tower_ordering_violated(self) -> None:
        """Swapping tower order of layers must emit ERR-AGT-REGISTRY-DRIFT-001."""
        data = self._read_json()
        # Swap AGT-LAYER-003 and AGT-LAYER-004
        data["layers"][2], data["layers"][3] = data["layers"][3], data["layers"][2]
        self._write_json(data)

        res = validate_agent_abstraction_registry(self.fake_root)
        self.assertFalse(res.passed)
        error_codes = [e.code for e in res.errors]
        self.assertIn(ERR_AGT_REGISTRY_DRIFT, error_codes)

    def test_planted_negative_markdown_mirror_drift(self) -> None:
        """Markdown mirror disagreement must emit ERR-AGT-REGISTRY-DRIFT-001."""
        md_file = self.fake_root / "registries/AGENT_ABSTRACTIONS.md"
        content = md_file.read_text(encoding="utf-8")
        # Tamper owner in markdown table for AGT-LAYER-004
        tampered = content.replace(
            "| `AGT-LAYER-004` | `derived_beliefs` | `fss-perception/fss-association/fss-graph` |",
            "| `AGT-LAYER-004` | `derived_beliefs` | `fss-rogue-owner` |",
        )
        md_file.write_text(tampered, encoding="utf-8")

        res = validate_agent_abstraction_registry(self.fake_root)
        self.assertFalse(res.passed)
        error_codes = [e.code for e in res.errors]
        self.assertIn(ERR_AGT_REGISTRY_DRIFT, error_codes)

    def test_planted_negative_corrupt_file(self) -> None:
        """Malformed JSON must emit ERR-AGT-CORRUPT-FILE-001."""
        (self.fake_root / "architecture/agent_abstraction_stack.json").write_text(
            "{ invalid json ...", encoding="utf-8"
        )
        res = validate_agent_abstraction_registry(self.fake_root)
        self.assertFalse(res.passed)
        error_codes = [e.code for e in res.errors]
        self.assertIn(ERR_AGT_CORRUPT_FILE, error_codes)

    def test_planted_negative_missing_json_file(self) -> None:
        """Missing JSON file must emit ERR-AGT-CORRUPT-FILE-001."""
        (self.fake_root / "architecture/agent_abstraction_stack.json").unlink()
        res = validate_agent_abstraction_registry(self.fake_root)
        self.assertFalse(res.passed)
        error_codes = [e.code for e in res.errors]
        self.assertIn(ERR_AGT_CORRUPT_FILE, error_codes)

    def test_planted_negative_missing_markdown_file(self) -> None:
        """Missing Markdown file must emit ERR-AGT-CORRUPT-FILE-001."""
        (self.fake_root / "registries/AGENT_ABSTRACTIONS.md").unlink()
        res = validate_agent_abstraction_registry(self.fake_root)
        self.assertFalse(res.passed)
        error_codes = [e.code for e in res.errors]
        self.assertIn(ERR_AGT_CORRUPT_FILE, error_codes)

    def test_planted_negative_runtime_authority_invariant_must_be_inv006(self) -> None:
        """AGT-LAYER-001 invariant altered from INV-006 must emit ERR-AGT-INVARIANT-VIOLATION-001."""
        data = self._read_json()
        for layer in data["layers"]:
            if layer["id"] == "AGT-LAYER-001":
                layer["invariant"] = "INV-001"
                break
        data["registryDigest"] = compute_canonical_agent_abstraction_digest(data)
        self._write_json(data)

        res = validate_agent_abstraction_registry(self.fake_root)
        self.assertFalse(res.passed)
        error_codes = [e.code for e in res.errors]
        self.assertIn(ERR_AGT_INVARIANT_VIOLATION, error_codes)

    def test_planted_negative_runtime_authority_prohibition_cannot_infer_truth(self) -> None:
        """AGT-LAYER-001 prohibition weakened to allow inferring truth must emit ERR-AGT-INVARIANT-VIOLATION-001."""
        data = self._read_json()
        for layer in data["layers"]:
            if layer["id"] == "AGT-LAYER-001":
                layer["prohibition"] = "May infer physical truth and mission meaning directly."
                break
        data["registryDigest"] = compute_canonical_agent_abstraction_digest(data)
        self._write_json(data)

        res = validate_agent_abstraction_registry(self.fake_root)
        self.assertFalse(res.passed)
        error_codes = [e.code for e in res.errors]
        self.assertIn(ERR_AGT_INVARIANT_VIOLATION, error_codes)

    def test_planted_negative_runtime_authority_status_must_be_normative(self) -> None:
        """AGT-LAYER-001 status set to non-normative must emit ERR-AGT-INVARIANT-VIOLATION-001."""
        data = self._read_json()
        for layer in data["layers"]:
            if layer["id"] == "AGT-LAYER-001":
                layer["status"] = "draft"
                break
        data["registryDigest"] = compute_canonical_agent_abstraction_digest(data)
        self._write_json(data)

        res = validate_agent_abstraction_registry(self.fake_root)
        self.assertFalse(res.passed)
        error_codes = [e.code for e in res.errors]
        self.assertIn(ERR_AGT_INVARIANT_VIOLATION, error_codes)

    def test_planted_negative_runtime_authority_owner_must_reference_asupersync_authority(self) -> None:
        """AGT-LAYER-001 owner changed away from asupersync/authority must emit ERR-AGT-INVARIANT-VIOLATION-001."""
        data = self._read_json()
        for layer in data["layers"]:
            if layer["id"] == "AGT-LAYER-001":
                layer["owner"] = "fss-cognition/perception"
                break
        data["registryDigest"] = compute_canonical_agent_abstraction_digest(data)
        self._write_json(data)

        res = validate_agent_abstraction_registry(self.fake_root)
        self.assertFalse(res.passed)
        error_codes = [e.code for e in res.errors]
        self.assertIn(ERR_AGT_INVARIANT_VIOLATION, error_codes)

    def test_planted_negative_runtime_authority_markdown_mirror_drift(self) -> None:
        """AGT-LAYER-001 owner mismatch in Markdown mirror must emit ERR-AGT-REGISTRY-DRIFT-001."""
        md_file = self.fake_root / "registries/AGENT_ABSTRACTIONS.md"
        content = md_file.read_text(encoding="utf-8")
        tampered = content.replace(
            "| `AGT-LAYER-001` | `runtime_authority_and_custody` | `asupersync/authority/object owners` |",
            "| `AGT-LAYER-001` | `runtime_authority_and_custody` | `rogue/unauthorized` |",
        )
        md_file.write_text(tampered, encoding="utf-8")

        res = validate_agent_abstraction_registry(self.fake_root)
        self.assertFalse(res.passed)
        error_codes = [e.code for e in res.errors]
        self.assertIn(ERR_AGT_REGISTRY_DRIFT, error_codes)

    def test_planted_negative_markdown_generation_mismatch(self) -> None:
        """Markdown generation mismatch against JSON generation must emit ERR-AGT-GENERATION-MISMATCH-001."""
        md_file = self.fake_root / "registries/AGENT_ABSTRACTIONS.md"
        content = md_file.read_text(encoding="utf-8")
        tampered = content.replace(
            "Generation: `gen:fss1:abstraction-v1`.",
            "Generation: `gen:fss1:diverged-generation-v99`.",
        )
        md_file.write_text(tampered, encoding="utf-8")

        res = validate_agent_abstraction_registry(self.fake_root)
        self.assertFalse(res.passed)
        error_codes = [e.code for e in res.errors]
        self.assertIn(ERR_AGT_GENERATION_MISMATCH, error_codes)

    def test_planted_negative_markdown_digest_mismatch(self) -> None:
        """Markdown digest mismatch against JSON declared digest must emit ERR-AGT-DIGEST-MISMATCH-001."""
        md_file = self.fake_root / "registries/AGENT_ABSTRACTIONS.md"
        content = md_file.read_text(encoding="utf-8")
        tampered = content.replace(
            f"Registry digest: `{BASELINE_FREEZE_DIGEST}`.",
            "Registry digest: `sha256:0000000000000000000000000000000000000000000000000000000000000000`.",
        )
        md_file.write_text(tampered, encoding="utf-8")

        res = validate_agent_abstraction_registry(self.fake_root)
        self.assertFalse(res.passed)
        error_codes = [e.code for e in res.errors]
        self.assertIn(ERR_AGT_DIGEST_MISMATCH, error_codes)


    def test_planted_negative_world_facts_invariant_must_be_inv063(self) -> None:
        """AGT-LAYER-003 invariant altered from INV-063 must emit ERR-AGT-INVARIANT-VIOLATION-001."""
        data = self._read_json()
        for layer in data["layers"]:
            if layer["id"] == "AGT-LAYER-003":
                layer["invariant"] = "INV-001"
                break
        data["registryDigest"] = compute_canonical_agent_abstraction_digest(data)
        self._write_json(data)

        res = validate_agent_abstraction_registry(self.fake_root)
        self.assertFalse(res.passed)
        error_codes = [e.code for e in res.errors]
        self.assertIn(ERR_AGT_INVARIANT_VIOLATION, error_codes)

    def test_planted_negative_world_facts_prohibition_cannot_include_unqualified_cognition(self) -> None:
        """AGT-LAYER-003 prohibition weakened to allow unqualified cognition must emit ERR-AGT-INVARIANT-VIOLATION-001."""
        data = self._read_json()
        for layer in data["layers"]:
            if layer["id"] == "AGT-LAYER-003":
                layer["prohibition"] = "May include model detections and cognitive beliefs as authoritative facts."
                break
        data["registryDigest"] = compute_canonical_agent_abstraction_digest(data)
        self._write_json(data)

        res = validate_agent_abstraction_registry(self.fake_root)
        self.assertFalse(res.passed)
        error_codes = [e.code for e in res.errors]
        self.assertIn(ERR_AGT_INVARIANT_VIOLATION, error_codes)

    def test_planted_negative_world_facts_status_must_be_normative(self) -> None:
        """AGT-LAYER-003 status set to draft must emit ERR-AGT-INVARIANT-VIOLATION-001."""
        data = self._read_json()
        for layer in data["layers"]:
            if layer["id"] == "AGT-LAYER-003":
                layer["status"] = "draft"
                break
        data["registryDigest"] = compute_canonical_agent_abstraction_digest(data)
        self._write_json(data)

        res = validate_agent_abstraction_registry(self.fake_root)
        self.assertFalse(res.passed)
        error_codes = [e.code for e in res.errors]
        self.assertIn(ERR_AGT_INVARIANT_VIOLATION, error_codes)

    def test_planted_negative_world_facts_owner_must_be_chronicle_coverage(self) -> None:
        """AGT-LAYER-003 owner changed away from fss-chronicle/fss-coverage must emit ERR-AGT-INVARIANT-VIOLATION-001."""
        data = self._read_json()
        for layer in data["layers"]:
            if layer["id"] == "AGT-LAYER-003":
                layer["owner"] = "fss-cognition/fss-vlm"
                break
        data["registryDigest"] = compute_canonical_agent_abstraction_digest(data)
        self._write_json(data)

        res = validate_agent_abstraction_registry(self.fake_root)
        self.assertFalse(res.passed)
        error_codes = [e.code for e in res.errors]
        self.assertIn(ERR_AGT_INVARIANT_VIOLATION, error_codes)

    def test_planted_negative_world_facts_output_illegally_includes_cognition(self) -> None:
        """AGT-LAYER-003 output altered to include cognition/beliefs must emit ERR-AGT-INVARIANT-VIOLATION-001."""
        data = self._read_json()
        for layer in data["layers"]:
            if layer["id"] == "AGT-LAYER-003":
                layer["output"] = "Device, geometry, calibration, coverage, policy, archive, cognition and effect facts."
                break
        data["registryDigest"] = compute_canonical_agent_abstraction_digest(data)
        self._write_json(data)

        res = validate_agent_abstraction_registry(self.fake_root)
        self.assertFalse(res.passed)
        error_codes = [e.code for e in res.errors]
        self.assertIn(ERR_AGT_INVARIANT_VIOLATION, error_codes)

    def test_planted_negative_world_facts_markdown_mirror_drift(self) -> None:
        """AGT-LAYER-003 owner mismatch in Markdown mirror must emit ERR-AGT-REGISTRY-DRIFT-001."""
        md_file = self.fake_root / "registries/AGENT_ABSTRACTIONS.md"
        content = md_file.read_text(encoding="utf-8")
        tampered = content.replace(
            "| `AGT-LAYER-003` | `world_facts_and_coverage` | `fss-chronicle/fss-coverage` |",
            "| `AGT-LAYER-003` | `world_facts_and_coverage` | `rogue/unauthorized` |",
        )
        md_file.write_text(tampered, encoding="utf-8")

        res = validate_agent_abstraction_registry(self.fake_root)
        self.assertFalse(res.passed)
        error_codes = [e.code for e in res.errors]
        self.assertIn(ERR_AGT_REGISTRY_DRIFT, error_codes)


if __name__ == "__main__":
    unittest.main()

