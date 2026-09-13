#!/usr/bin/env python3
"""Planted-negative test suite for agent abstraction stack registry checker (fss-x4a.30.82.3).

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
        self.assertEqual(
            {e.code for e in res.errors},
            {
                ERR_AGT_DIGEST_MISMATCH,
                ERR_AGT_FREEZE_DIVERGENCE,
            },
        )

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
        self.assertEqual(
            {e.code for e in res.errors},
            {
                ERR_AGT_DIGEST_MISMATCH,
                ERR_AGT_FREEZE_DIVERGENCE,
                ERR_AGT_INVARIANT_VIOLATION,
                ERR_AGT_REGISTRY_DRIFT,
            },
        )

    def test_planted_negative_generation_mismatch(self) -> None:
        """Unrecognized or unpinned generation must emit ERR-AGT-GENERATION-MISMATCH-001."""
        data = self._read_json()
        data["generation"] = "gen:fss1:abstraction-v2"
        data["registryDigest"] = compute_canonical_agent_abstraction_digest(data)
        self._write_json(data)

        res = validate_agent_abstraction_registry(self.fake_root)
        self.assertFalse(res.passed)
        self.assertEqual(
            {e.code for e in res.errors},
            {
                ERR_AGT_DIGEST_MISMATCH,
                ERR_AGT_GENERATION_MISMATCH,
            },
        )

    def test_planted_negative_missing_generation(self) -> None:
        """Missing generation property must emit ERR-AGT-GENERATION-MISMATCH-001 and ERR-AGT-MISSING-FIELD-001."""
        data = self._read_json()
        del data["generation"]
        self._write_json(data)

        res = validate_agent_abstraction_registry(self.fake_root)
        self.assertFalse(res.passed)
        self.assertEqual(
            {e.code for e in res.errors},
            {
                ERR_AGT_DIGEST_MISMATCH,
                ERR_AGT_GENERATION_MISMATCH,
                ERR_AGT_MISSING_FIELD,
            },
        )

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
        error_codes = set(e.code for e in res.errors)
        self.assertEqual(
            error_codes,
            {
                ERR_AGT_DIGEST_MISMATCH,
                ERR_AGT_FREEZE_DIVERGENCE,
                ERR_AGT_ILLEGAL_AUTHORITY,
                ERR_AGT_REGISTRY_DRIFT,
            },
        )

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
        error_codes = set(e.code for e in res.errors)
        self.assertEqual(
            error_codes,
            {
                ERR_AGT_DIGEST_MISMATCH,
                ERR_AGT_FREEZE_DIVERGENCE,
                ERR_AGT_ILLEGAL_AUTHORITY,
                ERR_AGT_REGISTRY_DRIFT,
            },
        )

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
        error_codes = set(e.code for e in res.errors)
        self.assertEqual(
            error_codes,
            {
                ERR_AGT_DIGEST_MISMATCH,
                ERR_AGT_FREEZE_DIVERGENCE,
                ERR_AGT_INVARIANT_VIOLATION,
                ERR_AGT_REGISTRY_DRIFT,
            },
        )

    def test_planted_negative_missing_mandatory_top_level_field(self) -> None:
        """Missing top-level field must emit ERR-AGT-MISSING-FIELD-001."""
        data = self._read_json()
        del data["constitutionalRole"]
        self._write_json(data)

        res = validate_agent_abstraction_registry(self.fake_root)
        self.assertFalse(res.passed)
        self.assertEqual(
            {e.code for e in res.errors},
            {
                ERR_AGT_DIGEST_MISMATCH,
                ERR_AGT_MISSING_FIELD,
            },
        )

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
        self.assertEqual(
            {e.code for e in res.errors},
            {
                ERR_AGT_DIGEST_MISMATCH,
                ERR_AGT_INVARIANT_VIOLATION,
                ERR_AGT_MISSING_FIELD,
                ERR_AGT_REGISTRY_DRIFT,
            },
        )

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
        self.assertEqual(
            {e.code for e in res.errors},
            {
                ERR_AGT_DIGEST_MISMATCH,
                ERR_AGT_INVARIANT_VIOLATION,
                ERR_AGT_MISSING_FIELD,
                ERR_AGT_REGISTRY_DRIFT,
            },
        )

    def test_planted_negative_duplicate_layer_id(self) -> None:
        """Duplicate layer ID must emit ERR-AGT-STABLE-ID-REUSED-001."""
        data = self._read_json()
        dup = dict(data["layers"][3])  # AGT-LAYER-004
        data["layers"].append(dup)
        self._write_json(data)

        res = validate_agent_abstraction_registry(self.fake_root)
        self.assertFalse(res.passed)
        self.assertEqual(
            {e.code for e in res.errors},
            {
                ERR_AGT_DIGEST_MISMATCH,
                ERR_AGT_REGISTRY_DRIFT,
                ERR_AGT_STABLE_ID_REUSED,
            },
        )

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
        self.assertEqual(
            {e.code for e in res.errors},
            {
                ERR_AGT_DIGEST_MISMATCH,
                ERR_AGT_REGISTRY_DRIFT,
                ERR_AGT_STABLE_ID_REUSED,
            },
        )

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
        self.assertEqual(
            {e.code for e in res.errors},
            {
                ERR_AGT_DIGEST_MISMATCH,
                ERR_AGT_REGISTRY_DRIFT,
                ERR_AGT_STABLE_ID_REUSED,
            },
        )

    def test_planted_negative_canonical_tower_ordering_violated(self) -> None:
        """Swapping tower order of layers must emit ERR-AGT-REGISTRY-DRIFT-001."""
        data = self._read_json()
        # Swap AGT-LAYER-003 and AGT-LAYER-004
        data["layers"][2], data["layers"][3] = data["layers"][3], data["layers"][2]
        self._write_json(data)

        res = validate_agent_abstraction_registry(self.fake_root)
        self.assertFalse(res.passed)
        self.assertEqual(
            {e.code for e in res.errors},
            {
                ERR_AGT_REGISTRY_DRIFT,
            },
        )

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
        self.assertEqual(
            {e.code for e in res.errors},
            {
                ERR_AGT_REGISTRY_DRIFT,
            },
        )

    def test_planted_negative_corrupt_file(self) -> None:
        """Malformed JSON must emit ERR-AGT-CORRUPT-FILE-001."""
        (self.fake_root / "architecture/agent_abstraction_stack.json").write_text(
            "{ invalid json ...", encoding="utf-8"
        )
        res = validate_agent_abstraction_registry(self.fake_root)
        self.assertFalse(res.passed)
        self.assertEqual(
            {e.code for e in res.errors},
            {
                ERR_AGT_CORRUPT_FILE,
            },
        )

    def test_planted_negative_missing_json_file(self) -> None:
        """Missing JSON file must emit ERR-AGT-CORRUPT-FILE-001."""
        (self.fake_root / "architecture/agent_abstraction_stack.json").unlink()
        res = validate_agent_abstraction_registry(self.fake_root)
        self.assertFalse(res.passed)
        self.assertEqual(
            {e.code for e in res.errors},
            {
                ERR_AGT_CORRUPT_FILE,
            },
        )

    def test_planted_negative_missing_markdown_file(self) -> None:
        """Missing Markdown file must emit ERR-AGT-CORRUPT-FILE-001."""
        (self.fake_root / "registries/AGENT_ABSTRACTIONS.md").unlink()
        res = validate_agent_abstraction_registry(self.fake_root)
        self.assertFalse(res.passed)
        self.assertEqual(
            {e.code for e in res.errors},
            {
                ERR_AGT_CORRUPT_FILE,
            },
        )

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
        self.assertEqual(
            {e.code for e in res.errors},
            {
                ERR_AGT_DIGEST_MISMATCH,
                ERR_AGT_FREEZE_DIVERGENCE,
                ERR_AGT_INVARIANT_VIOLATION,
                ERR_AGT_REGISTRY_DRIFT,
            },
        )

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
        self.assertEqual(
            {e.code for e in res.errors},
            {
                ERR_AGT_DIGEST_MISMATCH,
                ERR_AGT_FREEZE_DIVERGENCE,
                ERR_AGT_INVARIANT_VIOLATION,
                ERR_AGT_REGISTRY_DRIFT,
            },
        )

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
        self.assertEqual(
            {e.code for e in res.errors},
            {
                ERR_AGT_DIGEST_MISMATCH,
                ERR_AGT_FREEZE_DIVERGENCE,
                ERR_AGT_INVARIANT_VIOLATION,
                ERR_AGT_REGISTRY_DRIFT,
            },
        )

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
        self.assertEqual(
            {e.code for e in res.errors},
            {
                ERR_AGT_DIGEST_MISMATCH,
                ERR_AGT_FREEZE_DIVERGENCE,
                ERR_AGT_INVARIANT_VIOLATION,
                ERR_AGT_REGISTRY_DRIFT,
            },
        )

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
        self.assertEqual(
            {e.code for e in res.errors},
            {
                ERR_AGT_REGISTRY_DRIFT,
            },
        )

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
        self.assertEqual(
            {e.code for e in res.errors},
            {
                ERR_AGT_GENERATION_MISMATCH,
            },
        )

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
        self.assertEqual(
            {e.code for e in res.errors},
            {
                ERR_AGT_DIGEST_MISMATCH,
            },
        )


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
        self.assertEqual(
            {e.code for e in res.errors},
            {
                ERR_AGT_DIGEST_MISMATCH,
                ERR_AGT_FREEZE_DIVERGENCE,
                ERR_AGT_INVARIANT_VIOLATION,
                ERR_AGT_REGISTRY_DRIFT,
            },
        )

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
        self.assertEqual(
            {e.code for e in res.errors},
            {
                ERR_AGT_DIGEST_MISMATCH,
                ERR_AGT_FREEZE_DIVERGENCE,
                ERR_AGT_INVARIANT_VIOLATION,
                ERR_AGT_REGISTRY_DRIFT,
            },
        )

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
        self.assertEqual(
            {e.code for e in res.errors},
            {
                ERR_AGT_DIGEST_MISMATCH,
                ERR_AGT_FREEZE_DIVERGENCE,
                ERR_AGT_INVARIANT_VIOLATION,
                ERR_AGT_REGISTRY_DRIFT,
            },
        )

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
        self.assertEqual(
            {e.code for e in res.errors},
            {
                ERR_AGT_DIGEST_MISMATCH,
                ERR_AGT_FREEZE_DIVERGENCE,
                ERR_AGT_INVARIANT_VIOLATION,
                ERR_AGT_REGISTRY_DRIFT,
            },
        )

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
        self.assertEqual(
            {e.code for e in res.errors},
            {
                ERR_AGT_DIGEST_MISMATCH,
                ERR_AGT_FREEZE_DIVERGENCE,
                ERR_AGT_INVARIANT_VIOLATION,
                ERR_AGT_REGISTRY_DRIFT,
            },
        )

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
        self.assertEqual(
            {e.code for e in res.errors},
            {
                ERR_AGT_REGISTRY_DRIFT,
            },
        )


    def test_planted_negative_h0_missing_from_hydration_levels_fails(self) -> None:
        """H0 missing from hydrationLevels must emit ERR-AGT-STABLE-ID-REUSED-001."""
        data = self._read_json()
        data["hydrationLevels"] = [h for h in data["hydrationLevels"] if h["id"] != "H0"]
        data["registryDigest"] = compute_canonical_agent_abstraction_digest(data)
        self._write_json(data)

        res = validate_agent_abstraction_registry(self.fake_root)
        self.assertFalse(res.passed)
        self.assertEqual(
            {e.code for e in res.errors},
            {
                ERR_AGT_DIGEST_MISMATCH,
                ERR_AGT_FREEZE_DIVERGENCE,
                ERR_AGT_REGISTRY_DRIFT,
                ERR_AGT_STABLE_ID_REUSED,
            },
        )

    def test_planted_negative_h0_name_tampered_fails(self) -> None:
        """H0 name changed away from 'identity' must emit ERR-AGT-INVARIANT-VIOLATION-001."""
        data = self._read_json()
        for h in data["hydrationLevels"]:
            if h["id"] == "H0":
                h["name"] = "entity_summary"
                break
        data["registryDigest"] = compute_canonical_agent_abstraction_digest(data)
        self._write_json(data)

        res = validate_agent_abstraction_registry(self.fake_root)
        self.assertFalse(res.passed)
        self.assertEqual(
            {e.code for e in res.errors},
            {
                ERR_AGT_DIGEST_MISMATCH,
                ERR_AGT_FREEZE_DIVERGENCE,
                ERR_AGT_INVARIANT_VIOLATION,
                ERR_AGT_REGISTRY_DRIFT,
            },
        )

    def test_planted_negative_h0_content_missing_dimension_fails(self) -> None:
        """H0 content missing a required dimension (e.g. authority) must emit ERR-AGT-INVARIANT-VIOLATION-001."""
        data = self._read_json()
        for h in data["hydrationLevels"]:
            if h["id"] == "H0":
                h["content"] = "digest, type, time/spatial bounds, source, availability, and cost"
                break
        data["registryDigest"] = compute_canonical_agent_abstraction_digest(data)
        self._write_json(data)

        res = validate_agent_abstraction_registry(self.fake_root)
        self.assertFalse(res.passed)
        self.assertEqual(
            {e.code for e in res.errors},
            {
                ERR_AGT_DIGEST_MISMATCH,
                ERR_AGT_FREEZE_DIVERGENCE,
                ERR_AGT_INVARIANT_VIOLATION,
                ERR_AGT_REGISTRY_DRIFT,
            },
        )

    def test_planted_negative_h0_content_missing_time_spatial_bounds_fails(self) -> None:
        """H0 content missing time/spatial bounds must emit ERR-AGT-INVARIANT-VIOLATION-001."""
        data = self._read_json()
        for h in data["hydrationLevels"]:
            if h["id"] == "H0":
                h["content"] = "digest, type, source, availability, cost, and authority"
                break
        data["registryDigest"] = compute_canonical_agent_abstraction_digest(data)
        self._write_json(data)

        res = validate_agent_abstraction_registry(self.fake_root)
        self.assertFalse(res.passed)
        self.assertEqual(
            {e.code for e in res.errors},
            {
                ERR_AGT_DIGEST_MISMATCH,
                ERR_AGT_FREEZE_DIVERGENCE,
                ERR_AGT_INVARIANT_VIOLATION,
                ERR_AGT_REGISTRY_DRIFT,
            },
        )

    def test_planted_negative_h0_illegally_permits_raw_payload_fails(self) -> None:
        """H0 content modified to permit raw packet/bytes must emit ERR-AGT-INVARIANT-VIOLATION-001."""
        data = self._read_json()
        for h in data["hydrationLevels"]:
            if h["id"] == "H0":
                h["content"] = "digest, type, time/spatial bounds, source, availability, cost, authority, and raw packets"
                break
        data["registryDigest"] = compute_canonical_agent_abstraction_digest(data)
        self._write_json(data)

        res = validate_agent_abstraction_registry(self.fake_root)
        self.assertFalse(res.passed)
        self.assertEqual(
            {e.code for e in res.errors},
            {
                ERR_AGT_DIGEST_MISMATCH,
                ERR_AGT_FREEZE_DIVERGENCE,
                ERR_AGT_INVARIANT_VIOLATION,
                ERR_AGT_REGISTRY_DRIFT,
            },
        )

    def test_planted_negative_hydration_levels_order_scrambled_fails(self) -> None:
        """Hydration levels not in canonical ladder order (H0..H4) must emit ERR-AGT-REGISTRY-DRIFT-001."""
        data = self._read_json()
        data["hydrationLevels"].reverse()
        data["registryDigest"] = compute_canonical_agent_abstraction_digest(data)
        self._write_json(data)

        res = validate_agent_abstraction_registry(self.fake_root)
        self.assertFalse(res.passed)
        self.assertEqual(
            {e.code for e in res.errors},
            {
                ERR_AGT_REGISTRY_DRIFT,
            },
        )

    def test_planted_negative_duplicate_hydration_level_fails(self) -> None:
        """Duplicate hydration level ID must emit ERR-AGT-STABLE-ID-REUSED-001."""
        data = self._read_json()
        data["hydrationLevels"].append(dict(data["hydrationLevels"][0]))
        data["registryDigest"] = compute_canonical_agent_abstraction_digest(data)
        self._write_json(data)

        res = validate_agent_abstraction_registry(self.fake_root)
        self.assertFalse(res.passed)
        self.assertEqual(
            {e.code for e in res.errors},
            {
                ERR_AGT_DIGEST_MISMATCH,
                ERR_AGT_FREEZE_DIVERGENCE,
                ERR_AGT_REGISTRY_DRIFT,
                ERR_AGT_STABLE_ID_REUSED,
            },
        )

    def test_planted_negative_unbaselined_hydration_level_fails(self) -> None:
        """Un-baselined hydration level ID introduced without generation bump must emit ERR-AGT-STABLE-ID-REUSED-001."""
        data = self._read_json()
        data["hydrationLevels"].append({
            "id": "H5",
            "name": "quantum_expansion",
            "content": "quantum states and multiverse branching",
        })
        data["registryDigest"] = compute_canonical_agent_abstraction_digest(data)
        self._write_json(data)

        res = validate_agent_abstraction_registry(self.fake_root)
        self.assertFalse(res.passed)
        self.assertEqual(
            {e.code for e in res.errors},
            {
                ERR_AGT_DIGEST_MISMATCH,
                ERR_AGT_FREEZE_DIVERGENCE,
                ERR_AGT_REGISTRY_DRIFT,
                ERR_AGT_STABLE_ID_REUSED,
            },
        )

    def test_planted_negative_h0_markdown_mirror_name_drift_fails(self) -> None:
        """H0 name mismatch in Markdown mirror must emit ERR-AGT-REGISTRY-DRIFT-001."""
        md_file = self.fake_root / "registries/AGENT_ABSTRACTIONS.md"
        content = md_file.read_text(encoding="utf-8")
        tampered = content.replace(
            "| `H0` | `identity` |",
            "| `H0` | `shallow_descriptor` |",
        )
        md_file.write_text(tampered, encoding="utf-8")

        res = validate_agent_abstraction_registry(self.fake_root)
        self.assertFalse(res.passed)
        self.assertEqual(
            {e.code for e in res.errors},
            {
                ERR_AGT_REGISTRY_DRIFT,
            },
        )

    def test_planted_negative_h0_markdown_mirror_content_drift_fails(self) -> None:
        """H0 content mismatch in Markdown mirror must emit ERR-AGT-REGISTRY-DRIFT-001."""
        md_file = self.fake_root / "registries/AGENT_ABSTRACTIONS.md"
        content = md_file.read_text(encoding="utf-8")
        tampered = content.replace(
            "| `H0` | `identity` | digest, type, time/spatial bounds, source, availability, cost, and authority |",
            "| `H0` | `identity` | truncated content |",
        )
        md_file.write_text(tampered, encoding="utf-8")

        res = validate_agent_abstraction_registry(self.fake_root)
        self.assertFalse(res.passed)
        self.assertEqual(
            {e.code for e in res.errors},
            {
                ERR_AGT_REGISTRY_DRIFT,
            },
        )

    def test_planted_negative_situation_capsule_invariant_must_be_inv116(self) -> None:
        """AGT-LAYER-005 invariant altered from INV-116 must emit exact error set."""
        data = self._read_json()
        for layer in data["layers"]:
            if layer["id"] == "AGT-LAYER-005":
                layer["invariant"] = "INV-001"
                break
        data["registryDigest"] = compute_canonical_agent_abstraction_digest(data)
        self._write_json(data)

        res = validate_agent_abstraction_registry(self.fake_root)
        self.assertFalse(res.passed)
        error_codes = set(e.code for e in res.errors)
        self.assertEqual(
            error_codes,
            {
                ERR_AGT_DIGEST_MISMATCH,
                ERR_AGT_FREEZE_DIVERGENCE,
                ERR_AGT_INVARIANT_VIOLATION,
                ERR_AGT_REGISTRY_DRIFT,
            },
        )

    def test_planted_negative_situation_capsule_prohibition_must_forbid_hiding_omissions(self) -> None:
        """AGT-LAYER-005 prohibition weakened to allow hiding omissions must emit exact error set."""
        data = self._read_json()
        for layer in data["layers"]:
            if layer["id"] == "AGT-LAYER-005":
                layer["prohibition"] = "May hide decision-changing omissions and rebase evidence identities."
                break
        data["registryDigest"] = compute_canonical_agent_abstraction_digest(data)
        self._write_json(data)

        res = validate_agent_abstraction_registry(self.fake_root)
        self.assertFalse(res.passed)
        error_codes = set(e.code for e in res.errors)
        self.assertEqual(
            error_codes,
            {
                ERR_AGT_DIGEST_MISMATCH,
                ERR_AGT_FREEZE_DIVERGENCE,
                ERR_AGT_INVARIANT_VIOLATION,
                ERR_AGT_REGISTRY_DRIFT,
            },
        )

    def test_planted_negative_situation_capsule_status_must_be_normative(self) -> None:
        """AGT-LAYER-005 status altered from normative must emit exact error set."""
        data = self._read_json()
        for layer in data["layers"]:
            if layer["id"] == "AGT-LAYER-005":
                layer["status"] = "draft"
                break
        data["registryDigest"] = compute_canonical_agent_abstraction_digest(data)
        self._write_json(data)

        res = validate_agent_abstraction_registry(self.fake_root)
        self.assertFalse(res.passed)
        error_codes = set(e.code for e in res.errors)
        self.assertEqual(
            error_codes,
            {
                ERR_AGT_DIGEST_MISMATCH,
                ERR_AGT_FREEZE_DIVERGENCE,
                ERR_AGT_INVARIANT_VIOLATION,
                ERR_AGT_REGISTRY_DRIFT,
            },
        )

    def test_planted_negative_situation_capsule_owner_must_be_cognition_plane(self) -> None:
        """AGT-LAYER-005 owner illegally claiming authority plane must emit exact error set."""
        data = self._read_json()
        for layer in data["layers"]:
            if layer["id"] == "AGT-LAYER-005":
                layer["owner"] = "asupersync/authority/effect owners"
                break
        data["registryDigest"] = compute_canonical_agent_abstraction_digest(data)
        self._write_json(data)

        res = validate_agent_abstraction_registry(self.fake_root)
        self.assertFalse(res.passed)
        error_codes = set(e.code for e in res.errors)
        self.assertEqual(
            error_codes,
            {
                ERR_AGT_DIGEST_MISMATCH,
                ERR_AGT_FREEZE_DIVERGENCE,
                ERR_AGT_ILLEGAL_AUTHORITY,
                ERR_AGT_INVARIANT_VIOLATION,
                ERR_AGT_REGISTRY_DRIFT,
            },
        )

    def test_planted_negative_situation_capsule_output_cannot_claim_authority(self) -> None:
        """AGT-LAYER-005 output illegally claiming authority must emit exact error set."""
        data = self._read_json()
        for layer in data["layers"]:
            if layer["id"] == "AGT-LAYER-005":
                layer["output"] = "SituationCapsule directly authorizes effects and execution."
                break
        data["registryDigest"] = compute_canonical_agent_abstraction_digest(data)
        self._write_json(data)

        res = validate_agent_abstraction_registry(self.fake_root)
        self.assertFalse(res.passed)
        error_codes = set(e.code for e in res.errors)
        self.assertEqual(
            error_codes,
            {
                ERR_AGT_DIGEST_MISMATCH,
                ERR_AGT_FREEZE_DIVERGENCE,
                ERR_AGT_ILLEGAL_AUTHORITY,
                ERR_AGT_INVARIANT_VIOLATION,
                ERR_AGT_REGISTRY_DRIFT,
            },
        )

    def test_planted_negative_situation_capsule_markdown_mirror_drift(self) -> None:
        """AGT-LAYER-005 owner mismatch in Markdown mirror must emit exact error set."""
        md_file = self.fake_root / "registries/AGENT_ABSTRACTIONS.md"
        content = md_file.read_text(encoding="utf-8")
        tampered = content.replace(
            "| `AGT-LAYER-005` | `situation_capsule` | `fss-situation/fss-context-pack/fss-affordance` |",
            "| `AGT-LAYER-005` | `situation_capsule` | `rogue/unauthorized` |",
        )
        md_file.write_text(tampered, encoding="utf-8")

        res = validate_agent_abstraction_registry(self.fake_root)
        self.assertFalse(res.passed)
        error_codes = set(e.code for e in res.errors)
        self.assertEqual(error_codes, {ERR_AGT_REGISTRY_DRIFT})

    def test_planted_negative_investigation_hypotheses_invariant_must_be_inv104(self) -> None:
        """AGT-LAYER-006 invariant altered from INV-104 must emit exact error set."""
        data = self._read_json()
        for layer in data["layers"]:
            if layer["id"] == "AGT-LAYER-006":
                layer["invariant"] = "INV-001"
                break
        data["registryDigest"] = compute_canonical_agent_abstraction_digest(data)
        self._write_json(data)

        res = validate_agent_abstraction_registry(self.fake_root)
        self.assertFalse(res.passed)
        error_codes = set(e.code for e in res.errors)
        self.assertEqual(
            error_codes,
            {
                ERR_AGT_DIGEST_MISMATCH,
                ERR_AGT_FREEZE_DIVERGENCE,
                ERR_AGT_INVARIANT_VIOLATION,
                ERR_AGT_REGISTRY_DRIFT,
            },
        )

    def test_planted_negative_investigation_hypotheses_prohibition_must_forbid_uncertainty_collapse(self) -> None:
        """AGT-LAYER-006 prohibition weakened to allow uncertainty collapse must emit exact error set."""
        data = self._read_json()
        for layer in data["layers"]:
            if layer["id"] == "AGT-LAYER-006":
                layer["prohibition"] = "May collapse uncertainty into truth without adjudication."
                break
        data["registryDigest"] = compute_canonical_agent_abstraction_digest(data)
        self._write_json(data)

        res = validate_agent_abstraction_registry(self.fake_root)
        self.assertFalse(res.passed)
        error_codes = set(e.code for e in res.errors)
        self.assertEqual(
            error_codes,
            {
                ERR_AGT_DIGEST_MISMATCH,
                ERR_AGT_FREEZE_DIVERGENCE,
                ERR_AGT_INVARIANT_VIOLATION,
                ERR_AGT_REGISTRY_DRIFT,
            },
        )

    def test_planted_negative_investigation_hypotheses_status_must_be_normative(self) -> None:
        """AGT-LAYER-006 status altered from normative must emit exact error set."""
        data = self._read_json()
        for layer in data["layers"]:
            if layer["id"] == "AGT-LAYER-006":
                layer["status"] = "experimental"
                break
        data["registryDigest"] = compute_canonical_agent_abstraction_digest(data)
        self._write_json(data)

        res = validate_agent_abstraction_registry(self.fake_root)
        self.assertFalse(res.passed)
        error_codes = set(e.code for e in res.errors)
        self.assertEqual(
            error_codes,
            {
                ERR_AGT_DIGEST_MISMATCH,
                ERR_AGT_FREEZE_DIVERGENCE,
                ERR_AGT_INVARIANT_VIOLATION,
                ERR_AGT_REGISTRY_DRIFT,
            },
        )

    def test_planted_negative_investigation_hypotheses_owner_must_be_cognition_plane(self) -> None:
        """AGT-LAYER-006 owner illegally claiming authority plane must emit exact error set."""
        data = self._read_json()
        for layer in data["layers"]:
            if layer["id"] == "AGT-LAYER-006":
                layer["owner"] = "asupersync/authority/investigation_authority"
                break
        data["registryDigest"] = compute_canonical_agent_abstraction_digest(data)
        self._write_json(data)

        res = validate_agent_abstraction_registry(self.fake_root)
        self.assertFalse(res.passed)
        error_codes = set(e.code for e in res.errors)
        self.assertEqual(
            error_codes,
            {
                ERR_AGT_DIGEST_MISMATCH,
                ERR_AGT_FREEZE_DIVERGENCE,
                ERR_AGT_ILLEGAL_AUTHORITY,
                ERR_AGT_INVARIANT_VIOLATION,
                ERR_AGT_REGISTRY_DRIFT,
            },
        )

    def test_planted_negative_investigation_hypotheses_output_cannot_claim_authority(self) -> None:
        """AGT-LAYER-006 output illegally claiming authority must emit exact error set."""
        data = self._read_json()
        for layer in data["layers"]:
            if layer["id"] == "AGT-LAYER-006":
                layer["output"] = "Investigation directly authorizes effects and execution."
                break
        data["registryDigest"] = compute_canonical_agent_abstraction_digest(data)
        self._write_json(data)

        res = validate_agent_abstraction_registry(self.fake_root)
        self.assertFalse(res.passed)
        error_codes = set(e.code for e in res.errors)
        self.assertEqual(
            error_codes,
            {
                ERR_AGT_DIGEST_MISMATCH,
                ERR_AGT_FREEZE_DIVERGENCE,
                ERR_AGT_ILLEGAL_AUTHORITY,
                ERR_AGT_INVARIANT_VIOLATION,
                ERR_AGT_REGISTRY_DRIFT,
            },
        )

    def test_planted_negative_investigation_hypotheses_markdown_mirror_drift(self) -> None:
        """AGT-LAYER-006 owner mismatch in Markdown mirror must emit exact error set."""
        md_file = self.fake_root / "registries/AGENT_ABSTRACTIONS.md"
        content = md_file.read_text(encoding="utf-8")
        tampered = content.replace(
            "| `AGT-LAYER-006` | `investigation_and_hypotheses` | `fss-investigation` |",
            "| `AGT-LAYER-006` | `investigation_and_hypotheses` | `rogue/unauthorized` |",
        )
        md_file.write_text(tampered, encoding="utf-8")

        res = validate_agent_abstraction_registry(self.fake_root)
        self.assertFalse(res.passed)
        error_codes = set(e.code for e in res.errors)
        self.assertEqual(error_codes, {ERR_AGT_REGISTRY_DRIFT})


    def test_planted_negative_duplicate_json_keys(self) -> None:
        """Duplicate JSON keys must fail closed with ERR-AGT-CORRUPT-FILE-001."""
        json_file = self.fake_root / "architecture/agent_abstraction_stack.json"
        text = json_file.read_text(encoding="utf-8")
        text = text.replace(
            '"generation": "gen:fss1:abstraction-v1",',
            '"generation": "gen:fss1:abstraction-v1",\n  "generation": "gen:fss1:abstraction-v1",',
        )
        json_file.write_text(text, encoding="utf-8")

        res = validate_agent_abstraction_registry(self.fake_root)
        self.assertFalse(res.passed)
        self.assertEqual({e.code for e in res.errors}, {ERR_AGT_CORRUPT_FILE})

    def test_planted_negative_unknown_top_level_key(self) -> None:
        """Unknown top-level JSON key must emit ERR-AGT-INVARIANT-VIOLATION-001."""
        data = self._read_json()
        data["unknownTopLevelKey"] = "prohibited"
        self._write_json(data)

        res = validate_agent_abstraction_registry(self.fake_root)
        self.assertFalse(res.passed)
        self.assertEqual({e.code for e in res.errors}, {ERR_AGT_INVARIANT_VIOLATION})
        self.assertEqual(len(res.errors), 1)
        self.assertEqual(res.errors[0].target, "#/unknownTopLevelKey")
        self.assertIn("Unknown top-level key 'unknownTopLevelKey'", res.errors[0].message)

    def test_planted_negative_unknown_layer_key(self) -> None:
        """Unknown layer JSON key must emit ERR-AGT-INVARIANT-VIOLATION-001."""
        data = self._read_json()
        data["layers"][0]["unknownLayerKey"] = "prohibited"
        self._write_json(data)

        res = validate_agent_abstraction_registry(self.fake_root)
        self.assertFalse(res.passed)
        self.assertEqual({e.code for e in res.errors}, {ERR_AGT_INVARIANT_VIOLATION})
        self.assertEqual(len(res.errors), 1)
        self.assertEqual(res.errors[0].target, "#/layers/AGT-LAYER-001/unknownLayerKey")
        self.assertIn("Unknown layer key 'unknownLayerKey'", res.errors[0].message)

    def test_planted_negative_unknown_hydration_key(self) -> None:
        """Unknown hydration JSON key must emit ERR-AGT-INVARIANT-VIOLATION-001."""
        data = self._read_json()
        data["hydrationLevels"][0]["unknownHydrationKey"] = "prohibited"
        self._write_json(data)

        res = validate_agent_abstraction_registry(self.fake_root)
        self.assertFalse(res.passed)
        self.assertEqual({e.code for e in res.errors}, {ERR_AGT_INVARIANT_VIOLATION})
        self.assertEqual(len(res.errors), 1)
        self.assertEqual(res.errors[0].target, "#/hydrationLevels/H0/unknownHydrationKey")
        self.assertIn("Unknown hydration level key 'unknownHydrationKey'", res.errors[0].message)

    def test_canonical_agent_abstraction_digest_computes_without_raising_on_unknown_keys(self) -> None:
        """compute_canonical_agent_abstraction_digest does not duplicate validation, delegating to validator loop."""
        data = self._read_json()
        data["unknownTopKey"] = "extra"
        data["layers"][0]["unknownLayerKey"] = "extra"
        data["hydrationLevels"][0]["unknownHydKey"] = "extra"
        d = compute_canonical_agent_abstraction_digest(data)
        self.assertTrue(d.startswith("sha256:"))

    def test_planted_negative_duplicate_markdown_layer_row(self) -> None:
        """Duplicate layer row in markdown mirror must emit ERR-AGT-STABLE-ID-REUSED-001."""
        md_file = self.fake_root / "registries/AGENT_ABSTRACTIONS.md"
        md = md_file.read_text(encoding="utf-8")
        target = "| `AGT-LAYER-003` | `world_facts_and_coverage` | `fss-chronicle/fss-coverage` | What did the system authoritatively observe or do at one anchor? | `INV-063` | `normative` |"
        self.assertTrue(target in md)
        md = md.replace(target, target + "\n" + target)
        md_file.write_text(md, encoding="utf-8")

        res = validate_agent_abstraction_registry(self.fake_root)
        self.assertFalse(res.passed)
        self.assertEqual({e.code for e in res.errors}, {ERR_AGT_STABLE_ID_REUSED})

    def test_planted_negative_duplicate_markdown_hydration_row(self) -> None:
        """Duplicate hydration row in markdown mirror must emit ERR-AGT-STABLE-ID-REUSED-001."""
        md_file = self.fake_root / "registries/AGENT_ABSTRACTIONS.md"
        md = md_file.read_text(encoding="utf-8")
        target = "| `H0` | `identity` | digest, type, time/spatial bounds, source, availability, cost, and authority |"
        self.assertTrue(target in md)
        md = md.replace(target, target + "\n" + target)
        md_file.write_text(md, encoding="utf-8")

        res = validate_agent_abstraction_registry(self.fake_root)
        self.assertFalse(res.passed)
        self.assertEqual({e.code for e in res.errors}, {ERR_AGT_STABLE_ID_REUSED})

    def test_planted_negative_missing_markdown_generation(self) -> None:
        """Missing Generation line in markdown mirror must emit ERR-AGT-MISSING-FIELD-001."""
        md_file = self.fake_root / "registries/AGENT_ABSTRACTIONS.md"
        md = md_file.read_text(encoding="utf-8")
        md = "\n".join([line for line in md.splitlines() if not line.startswith("Generation:")])
        md_file.write_text(md, encoding="utf-8")

        res = validate_agent_abstraction_registry(self.fake_root)
        self.assertFalse(res.passed)
        self.assertEqual({e.code for e in res.errors}, {ERR_AGT_MISSING_FIELD})

    def test_planted_negative_missing_markdown_registry_digest(self) -> None:
        """Missing Registry digest line in markdown mirror must emit ERR-AGT-MISSING-FIELD-001."""
        md_file = self.fake_root / "registries/AGENT_ABSTRACTIONS.md"
        md = md_file.read_text(encoding="utf-8")
        md = "\n".join([line for line in md.splitlines() if not line.startswith("Registry digest:")])
        md_file.write_text(md, encoding="utf-8")

        res = validate_agent_abstraction_registry(self.fake_root)
        self.assertFalse(res.passed)
        self.assertEqual({e.code for e in res.errors}, {ERR_AGT_MISSING_FIELD})

    def test_planted_negative_source_evidence_invariant_must_be_inv003(self) -> None:
        """AGT-LAYER-002 invariant altered from INV-003 must emit exact error set."""
        data = self._read_json()
        for layer in data["layers"]:
            if layer["id"] == "AGT-LAYER-002":
                layer["invariant"] = "INV-001"
                break
        data["registryDigest"] = compute_canonical_agent_abstraction_digest(data)
        self._write_json(data)

        res = validate_agent_abstraction_registry(self.fake_root)
        self.assertFalse(res.passed)
        self.assertEqual(
            {e.code for e in res.errors},
            {
                ERR_AGT_DIGEST_MISMATCH,
                ERR_AGT_FREEZE_DIVERGENCE,
                ERR_AGT_INVARIANT_VIOLATION,
                ERR_AGT_REGISTRY_DRIFT,
            },
        )

    def test_planted_negative_source_evidence_prohibition_cannot_promote_decode_or_model(self) -> None:
        """AGT-LAYER-002 prohibition weakened to allow promotion must emit exact error set."""
        data = self._read_json()
        for layer in data["layers"]:
            if layer["id"] == "AGT-LAYER-002":
                layer["prohibition"] = "May promote decode or model output into source evidence."
                break
        data["registryDigest"] = compute_canonical_agent_abstraction_digest(data)
        self._write_json(data)

        res = validate_agent_abstraction_registry(self.fake_root)
        self.assertFalse(res.passed)
        self.assertEqual(
            {e.code for e in res.errors},
            {
                ERR_AGT_DIGEST_MISMATCH,
                ERR_AGT_FREEZE_DIVERGENCE,
                ERR_AGT_INVARIANT_VIOLATION,
                ERR_AGT_REGISTRY_DRIFT,
            },
        )

    def test_planted_negative_source_evidence_owner_must_be_media_chronicle(self) -> None:
        """AGT-LAYER-002 owner altered away from fss-capture/fss-media/fss-chronicle must emit exact error set."""
        data = self._read_json()
        for layer in data["layers"]:
            if layer["id"] == "AGT-LAYER-002":
                layer["owner"] = "fss-cognition/perception"
                break
        data["registryDigest"] = compute_canonical_agent_abstraction_digest(data)
        self._write_json(data)

        res = validate_agent_abstraction_registry(self.fake_root)
        self.assertFalse(res.passed)
        self.assertEqual(
            {e.code for e in res.errors},
            {
                ERR_AGT_DIGEST_MISMATCH,
                ERR_AGT_FREEZE_DIVERGENCE,
                ERR_AGT_INVARIANT_VIOLATION,
                ERR_AGT_REGISTRY_DRIFT,
            },
        )

    def test_planted_negative_source_evidence_status_must_be_normative(self) -> None:
        """AGT-LAYER-002 status altered from normative must emit exact error set."""
        data = self._read_json()
        for layer in data["layers"]:
            if layer["id"] == "AGT-LAYER-002":
                layer["status"] = "draft"
                break
        data["registryDigest"] = compute_canonical_agent_abstraction_digest(data)
        self._write_json(data)

        res = validate_agent_abstraction_registry(self.fake_root)
        self.assertFalse(res.passed)
        self.assertEqual(
            {e.code for e in res.errors},
            {
                ERR_AGT_DIGEST_MISMATCH,
                ERR_AGT_FREEZE_DIVERGENCE,
                ERR_AGT_INVARIANT_VIOLATION,
                ERR_AGT_REGISTRY_DRIFT,
            },
        )

    def test_planted_negative_source_evidence_markdown_mirror_drift(self) -> None:
        """AGT-LAYER-002 owner mismatch in Markdown mirror must emit exact error set."""
        md_file = self.fake_root / "registries/AGENT_ABSTRACTIONS.md"
        content = md_file.read_text(encoding="utf-8")
        tampered = content.replace(
            "| `AGT-LAYER-002` | `source_evidence` | `fss-capture/fss-media/fss-chronicle` |",
            "| `AGT-LAYER-002` | `source_evidence` | `rogue/unauthorized` |",
        )
        md_file.write_text(tampered, encoding="utf-8")

        res = validate_agent_abstraction_registry(self.fake_root)
        self.assertFalse(res.passed)
        self.assertEqual({e.code for e in res.errors}, {ERR_AGT_REGISTRY_DRIFT})

    def test_planted_negative_markdown_question_mismatch(self) -> None:
        """Agent question mismatch between markdown mirror and JSON must emit ERR-AGT-REGISTRY-DRIFT-001."""
        md_file = self.fake_root / "registries/AGENT_ABSTRACTIONS.md"
        md = md_file.read_text(encoding="utf-8")
        tampered = md.replace(
            "What did the system authoritatively observe or do at one anchor?",
            "What did the system unauthoritatively guess at one anchor?",
        )
        md_file.write_text(tampered, encoding="utf-8")

        res = validate_agent_abstraction_registry(self.fake_root)
        self.assertFalse(res.passed)
        self.assertIn(ERR_AGT_REGISTRY_DRIFT, {e.code for e in res.errors})
        self.assertTrue(any("question mismatch" in e.message for e in res.errors))

    def test_planted_negative_misplaced_hydration_row(self) -> None:
        """Hydration row outside '## Hydration ladder' section must emit ERR-AGT-REGISTRY-DRIFT-001."""
        md_file = self.fake_root / "registries/AGENT_ABSTRACTIONS.md"
        md = md_file.read_text(encoding="utf-8")
        lines = md.splitlines()
        lines.insert(12, "| `H0` | `identity` | digest, type, time/spatial bounds, source, availability, cost, and authority |")
        md_file.write_text("\n".join(lines), encoding="utf-8")

        res = validate_agent_abstraction_registry(self.fake_root)
        self.assertFalse(res.passed)
        self.assertIn(ERR_AGT_REGISTRY_DRIFT, {e.code for e in res.errors})
        self.assertTrue(any("outside '## Hydration ladder'" in e.message for e in res.errors))

    def test_markdown_row_strips_padded_whitespace(self) -> None:
        """Whitespace padding around cells or leading spaces must be stripped and not cause false drift."""
        md_file = self.fake_root / "registries/AGENT_ABSTRACTIONS.md"
        md = md_file.read_text(encoding="utf-8")
        target = "| `AGT-LAYER-001` | `runtime_authority_and_custody` | `asupersync/authority/object owners` | What work, authority, budget, identity, time, and object custody exist? | `INV-006` | `normative` |"
        padded = "   |   `AGT-LAYER-001`   |   `runtime_authority_and_custody`   |   `asupersync/authority/object owners`   |   What work, authority, budget, identity, time, and object custody exist?   |   `INV-006`   |   `normative`   |  "
        md_padded = md.replace(target, padded)
        md_file.write_text(md_padded, encoding="utf-8")

        res = validate_agent_abstraction_registry(self.fake_root)
        self.assertTrue(res.passed, f"Padded markdown table row must be stripped cleanly: {res.errors}")

    def test_planted_negative_layer_006_prohibition_exact_match(self) -> None:
        """AGT-LAYER-006 prohibition must match exactly; appended or prepended text fails."""
        data = self._read_json()
        for layer in data["layers"]:
            if layer["id"] == "AGT-LAYER-006":
                layer["prohibition"] = "Cannot collapse uncertainty into truth without adjudication. But maybe sometimes allowed."
                break
        self._write_json(data)

        res = validate_agent_abstraction_registry(self.fake_root)
        self.assertFalse(res.passed)
        self.assertIn(ERR_AGT_INVARIANT_VIOLATION, {e.code for e in res.errors})
        self.assertTrue(any("AGT-LAYER-006 prohibition must be" in e.message for e in res.errors))


if __name__ == "__main__":
    unittest.main()


