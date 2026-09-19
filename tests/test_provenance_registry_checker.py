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
    ALL_PROVENANCE_CLASSES,
    AUTHORIZING_CLASSES,
    BASELINE_FREEZE_DIGEST,
    BASELINE_GENERATION,
    ERR_PROV_CORRUPT_FILE,
    ERR_PROV_DIGEST_MISMATCH,
    ERR_PROV_FREEZE_DIVERGENCE,
    ERR_PROV_GENERATION_MISMATCH,
    ERR_PROV_LAUUNDERING_UNWIRED,
    ERR_PROV_MISSING_FIELD,
    ERR_PROV_REGISTRY_DRIFT,
    ERR_PROV_SEMANTIC_INVARIANT,
    ERR_PROV_STABLE_ID_REUSED,
    NON_AUTHORIZING_CLASSES,
    STATES_PERMITTING_EMPTY_EVIDENCE,
    STATES_REQUIRING_EVIDENCE,
    compute_canonical_provenance_digest,
    extract_rust_may_launder_matrix,
    validate_cell_provenance_invariants,
    validate_laundering_wiring,
    validate_provenance_authorization,
    validate_provenance_registry,
    validate_state_aware_evidence,
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
        shutil.copyfile(
            ROOT / "architecture/agent_contracts.json",
            self.fake_root / "architecture/agent_contracts.json",
        )
        (self.fake_root / "crates/fss-core/src").mkdir(parents=True, exist_ok=True)
        shutil.copyfile(
            ROOT / "crates/fss-core/src/contract.rs",
            self.fake_root / "crates/fss-core/src/contract.rs",
        )

    def _read_json(self) -> dict:
        return json.loads((self.fake_root / "architecture/provenance_classes.json").read_text(encoding="utf-8"))

    def _write_json(self, data: dict) -> None:
        (self.fake_root / "architecture/provenance_classes.json").write_text(
            json.dumps(data, indent=2), encoding="utf-8"
        )

    def _read_agent_contracts(self) -> dict:
        return json.loads((self.fake_root / "architecture/agent_contracts.json").read_text(encoding="utf-8"))

    def _write_agent_contracts(self, data: dict) -> None:
        (self.fake_root / "architecture/agent_contracts.json").write_text(
            json.dumps(data, indent=2), encoding="utf-8"
        )

    def test_live_repository_passes_with_zero_errors(self) -> None:
        """The live repository must satisfy the provenance registry contract with 0 errors and pinned digest."""
        res = validate_provenance_registry(ROOT)
        self.assertTrue(res.passed, f"Live repository failed validation: {res.errors}")
        self.assertEqual({e.code for e in res.errors}, set())
        self.assertEqual(res.provenance_class_count, 7)
        self.assertEqual(res.registry_digest, BASELINE_FREEZE_DIGEST)

    def test_planted_negative_freeze_divergence(self) -> None:
        """Declared digest differing from pinned freeze digest must emit ERR-PROV-FREEZE-DIVERGENCE-001."""
        data = self._read_json()
        data["registryDigest"] = "sha256:0000000000000000000000000000000000000000000000000000000000000000"
        self._write_json(data)

        res = validate_provenance_registry(self.fake_root)
        self.assertFalse(res.passed)
        self.assertEqual({e.code for e in res.errors}, {ERR_PROV_FREEZE_DIVERGENCE, ERR_PROV_DIGEST_MISMATCH})

    def test_planted_negative_self_referential_bypass_prevented(self) -> None:
        """Tampering a definition and recomputing digest must NOT bypass the pinned freeze digest."""
        data = self._read_json()
        data["provenanceClasses"][0]["meaning"] = "compromised definition"
        data["registryDigest"] = compute_canonical_provenance_digest(data)
        self._write_json(data)

        res = validate_provenance_registry(self.fake_root)
        self.assertFalse(res.passed)
        self.assertEqual({e.code for e in res.errors}, {ERR_PROV_FREEZE_DIVERGENCE, ERR_PROV_REGISTRY_DRIFT})

    def test_planted_negative_generation_mismatch(self) -> None:
        """Unrecognized or unpinned generation must emit ERR-PROV-GENERATION-MISMATCH-001."""
        data = self._read_json()
        data["generation"] = "gen:fss1:provenance-v2"
        data["registryDigest"] = compute_canonical_provenance_digest(data)
        self._write_json(data)

        res = validate_provenance_registry(self.fake_root)
        self.assertFalse(res.passed)
        self.assertEqual({e.code for e in res.errors}, {ERR_PROV_GENERATION_MISMATCH, ERR_PROV_FREEZE_DIVERGENCE})

    def test_planted_negative_missing_generation(self) -> None:
        """Missing generation property must emit ERR-PROV-GENERATION-MISMATCH-001 and ERR-PROV-MISSING-FIELD-001."""
        data = self._read_json()
        del data["generation"]
        self._write_json(data)

        res = validate_provenance_registry(self.fake_root)
        self.assertFalse(res.passed)
        self.assertEqual(
            {e.code for e in res.errors},
            {ERR_PROV_GENERATION_MISMATCH, ERR_PROV_MISSING_FIELD, ERR_PROV_FREEZE_DIVERGENCE, ERR_PROV_CORRUPT_FILE},
        )

    def test_planted_negative_missing_baseline_id(self) -> None:
        """Omitting a baseline ID must emit ERR-PROV-STABLE-ID-REUSED-001."""
        data = self._read_json()
        data["provenanceClasses"] = [r for r in data["provenanceClasses"] if r["id"] != "PROV-003"]
        self._write_json(data)

        res = validate_provenance_registry(self.fake_root)
        self.assertFalse(res.passed)
        self.assertEqual(
            {e.code for e in res.errors},
            {ERR_PROV_STABLE_ID_REUSED, ERR_PROV_DIGEST_MISMATCH, ERR_PROV_REGISTRY_DRIFT},
        )

    def test_planted_negative_renumbered_id_to_non_baseline(self) -> None:
        """Renumbering a baseline ID to a non-baseline ID (PROV-010) must emit ERR-PROV-STABLE-ID-REUSED-001."""
        data = self._read_json()
        data["provenanceClasses"][0]["id"] = "PROV-010"
        self._write_json(data)

        res = validate_provenance_registry(self.fake_root)
        self.assertFalse(res.passed)
        self.assertEqual(
            {e.code for e in res.errors},
            {ERR_PROV_STABLE_ID_REUSED, ERR_PROV_DIGEST_MISMATCH, ERR_PROV_REGISTRY_DRIFT},
        )

    def test_planted_negative_top_level_metadata_missing(self) -> None:
        """Missing top-level metadata field must emit ERR-PROV-MISSING-FIELD-001."""
        data = self._read_json()
        del data["constitutionalDocument"]
        self._write_json(data)

        res = validate_provenance_registry(self.fake_root)
        self.assertFalse(res.passed)
        self.assertEqual(
            {e.code for e in res.errors},
            {ERR_PROV_MISSING_FIELD, ERR_PROV_CORRUPT_FILE},
        )

    def test_planted_negative_top_level_metadata_tampered_digest_mismatch(self) -> None:
        """Mutating top-level metadata must invalidate the canonical digest."""
        data = self._read_json()
        data["constitutionalDocument"] = "OTHER_DOC.md"
        self._write_json(data)

        res = validate_provenance_registry(self.fake_root)
        self.assertFalse(res.passed)
        self.assertEqual({e.code for e in res.errors}, {ERR_PROV_DIGEST_MISMATCH})

    def test_planted_negative_row_missing_in_json(self) -> None:
        data = self._read_json()
        data["provenanceClasses"] = [r for r in data["provenanceClasses"] if r["id"] != "PROV-003"]
        self._write_json(data)

        res = validate_provenance_registry(self.fake_root)
        self.assertFalse(res.passed)
        self.assertEqual(
            {e.code for e in res.errors},
            {ERR_PROV_STABLE_ID_REUSED, ERR_PROV_DIGEST_MISMATCH, ERR_PROV_REGISTRY_DRIFT},
        )

    def test_planted_negative_row_missing_in_markdown(self) -> None:
        md_path = self.fake_root / "registries/AGENT_CONTRACTS.md"
        lines = md_path.read_text(encoding="utf-8").splitlines()
        filtered = [l for l in lines if "PROV-001" not in l]
        md_path.write_text("\n".join(filtered) + "\n", encoding="utf-8")

        res = validate_provenance_registry(self.fake_root)
        self.assertFalse(res.passed)
        self.assertEqual({e.code for e in res.errors}, {ERR_PROV_REGISTRY_DRIFT})

    def test_planted_negative_class_name_mismatch(self) -> None:
        data = self._read_json()
        data["provenanceClasses"][0]["class"] = "tampered_class"
        self._write_json(data)

        res = validate_provenance_registry(self.fake_root)
        self.assertFalse(res.passed)
        self.assertEqual(
            {e.code for e in res.errors},
            {ERR_PROV_SEMANTIC_INVARIANT, ERR_PROV_DIGEST_MISMATCH, ERR_PROV_REGISTRY_DRIFT},
        )

    def test_planted_negative_meaning_mismatch(self) -> None:
        data = self._read_json()
        data["provenanceClasses"][0]["meaning"] = "tampered meaning"
        self._write_json(data)

        res = validate_provenance_registry(self.fake_root)
        self.assertFalse(res.passed)
        self.assertEqual(
            {e.code for e in res.errors},
            {ERR_PROV_DIGEST_MISMATCH, ERR_PROV_REGISTRY_DRIFT},
        )

    def test_planted_negative_duplicate_stable_id(self) -> None:
        data = self._read_json()
        data["provenanceClasses"].append(dict(data["provenanceClasses"][0]))
        self._write_json(data)

        res = validate_provenance_registry(self.fake_root)
        self.assertFalse(res.passed)
        self.assertEqual(
            {e.code for e in res.errors},
            {ERR_PROV_STABLE_ID_REUSED, ERR_PROV_DIGEST_MISMATCH},
        )

    def test_planted_negative_malformed_stable_id(self) -> None:
        data = self._read_json()
        data["provenanceClasses"][0]["id"] = "PROV-1"
        self._write_json(data)

        res = validate_provenance_registry(self.fake_root)
        self.assertFalse(res.passed)
        self.assertEqual(
            {e.code for e in res.errors},
            {ERR_PROV_STABLE_ID_REUSED, ERR_PROV_DIGEST_MISMATCH, ERR_PROV_REGISTRY_DRIFT},
        )

    def test_planted_negative_renumbered_stable_id(self) -> None:
        data = self._read_json()
        # Swap class names between PROV-001 and PROV-002
        data["provenanceClasses"][0]["class"] = "derived"
        data["provenanceClasses"][1]["class"] = "observed"
        self._write_json(data)

        res = validate_provenance_registry(self.fake_root)
        self.assertFalse(res.passed)
        self.assertEqual(
            {e.code for e in res.errors},
            {ERR_PROV_DIGEST_MISMATCH, ERR_PROV_REGISTRY_DRIFT},
        )

    def test_planted_negative_missing_mandatory_field(self) -> None:
        data = self._read_json()
        del data["provenanceClasses"][0]["meaning"]
        self._write_json(data)

        res = validate_provenance_registry(self.fake_root)
        self.assertFalse(res.passed)
        self.assertEqual(
            {e.code for e in res.errors},
            {ERR_PROV_MISSING_FIELD, ERR_PROV_DIGEST_MISMATCH, ERR_PROV_REGISTRY_DRIFT},
        )

    def test_planted_negative_empty_mandatory_field(self) -> None:
        data = self._read_json()
        data["provenanceClasses"][0]["meaning"] = "  "
        self._write_json(data)

        res = validate_provenance_registry(self.fake_root)
        self.assertFalse(res.passed)
        self.assertEqual(
            {e.code for e in res.errors},
            {ERR_PROV_DIGEST_MISMATCH, ERR_PROV_REGISTRY_DRIFT},
        )

    def test_planted_negative_missing_json_file(self) -> None:
        (self.fake_root / "architecture/provenance_classes.json").unlink()
        res = validate_provenance_registry(self.fake_root)
        self.assertFalse(res.passed)
        self.assertEqual({e.code for e in res.errors}, {ERR_PROV_CORRUPT_FILE})

    def test_planted_negative_missing_markdown_file(self) -> None:
        (self.fake_root / "registries/AGENT_CONTRACTS.md").unlink()
        res = validate_provenance_registry(self.fake_root)
        self.assertFalse(res.passed)
        self.assertEqual({e.code for e in res.errors}, {ERR_PROV_CORRUPT_FILE})

    def test_planted_negative_corrupt_json(self) -> None:
        (self.fake_root / "architecture/provenance_classes.json").write_text("{invalid json", encoding="utf-8")
        res = validate_provenance_registry(self.fake_root)
        self.assertFalse(res.passed)
        self.assertEqual({e.code for e in res.errors}, {ERR_PROV_CORRUPT_FILE})

    def test_planted_negative_json_not_object(self) -> None:
        (self.fake_root / "architecture/provenance_classes.json").write_text("[]", encoding="utf-8")
        res = validate_provenance_registry(self.fake_root)
        self.assertFalse(res.passed)
        self.assertEqual({e.code for e in res.errors}, {ERR_PROV_CORRUPT_FILE})

    # Finding 1: Cross-check architecture/agent_contracts.json
    def test_planted_negative_missing_agent_contracts_file(self) -> None:
        """Missing architecture/agent_contracts.json must emit ERR-PROV-CORRUPT-FILE-001."""
        (self.fake_root / "architecture/agent_contracts.json").unlink()
        res = validate_provenance_registry(self.fake_root)
        self.assertFalse(res.passed)
        self.assertEqual({e.code for e in res.errors}, {ERR_PROV_CORRUPT_FILE})

    def test_planted_negative_agent_contracts_name_drift(self) -> None:
        """Mismatch in class name between provenance_classes.json and agent_contracts.json must emit ERR-PROV-REGISTRY-DRIFT-001."""
        ac = self._read_agent_contracts()
        ac["provenanceClasses"][0]["name"] = "tampered_observed"
        self._write_agent_contracts(ac)

        res = validate_provenance_registry(self.fake_root)
        self.assertFalse(res.passed)
        self.assertEqual({e.code for e in res.errors}, {ERR_PROV_REGISTRY_DRIFT})

    def test_planted_negative_agent_contracts_meaning_drift(self) -> None:
        """Mismatch in meaning between provenance_classes.json and agent_contracts.json must emit ERR-PROV-REGISTRY-DRIFT-001."""
        ac = self._read_agent_contracts()
        ac["provenanceClasses"][0]["meaning"] = "tampered meaning in umbrella"
        self._write_agent_contracts(ac)

        res = validate_provenance_registry(self.fake_root)
        self.assertFalse(res.passed)
        self.assertEqual({e.code for e in res.errors}, {ERR_PROV_REGISTRY_DRIFT})

    def test_planted_negative_agent_contracts_extra_row(self) -> None:
        """Extra row in agent_contracts.json must emit ERR-PROV-REGISTRY-DRIFT-001."""
        ac = self._read_agent_contracts()
        ac["provenanceClasses"].append({
            "id": "PROV-008",
            "name": "custom",
            "meaning": "Custom class",
        })
        self._write_agent_contracts(ac)

        res = validate_provenance_registry(self.fake_root)
        self.assertFalse(res.passed)
        self.assertEqual({e.code for e in res.errors}, {ERR_PROV_REGISTRY_DRIFT})

    # Finding 2: Traceback prevention on malformed types and deep recursion
    def test_compute_digest_bad_types_prevent_tracebacks(self) -> None:
        """compute_canonical_provenance_digest must type-check before sorting and never raise AttributeError or RecursionError."""
        with self.assertRaises(TypeError):
            compute_canonical_provenance_digest([1])  # type: ignore

        with self.assertRaises(TypeError):
            compute_canonical_provenance_digest(None)  # type: ignore

        with self.assertRaises(TypeError):
            compute_canonical_provenance_digest("abc")  # type: ignore

        with self.assertRaises(TypeError):
            compute_canonical_provenance_digest([["PROV-001"]])  # type: ignore

        with self.assertRaises(ValueError):
            compute_canonical_provenance_digest({"a": 1})

        # Deep nesting 2000 levels
        deep_row: dict = {"id": "PROV-001", "class": "observed", "meaning": "m"}
        curr = deep_row
        for _ in range(2000):
            nxt = {}
            curr["nested"] = nxt
            curr = nxt
        with self.assertRaises(ValueError) as ctx:
            compute_canonical_provenance_digest([deep_row])
        self.assertIn("Maximum nesting depth", str(ctx.exception))

    def test_validate_registry_bad_types_emit_registered_findings_without_crash(self) -> None:
        """validate_provenance_registry must catch malformed types cleanly in-process and emit ERR-PROV-CORRUPT-FILE-001."""
        for bad_val in [[1], None, "abc", [["PROV-001"]]]:
            self.setUp()
            data = self._read_json()
            data["provenanceClasses"] = bad_val
            self._write_json(data)
            res = validate_provenance_registry(self.fake_root)
            self.assertFalse(res.passed)
            self.assertIn(ERR_PROV_CORRUPT_FILE, {e.code for e in res.errors})

        # 2000 deep row in json
        self.setUp()
        data = self._read_json()
        deep_row = dict(data["provenanceClasses"][0])
        curr = deep_row
        for _ in range(2000):
            nxt = {}
            curr["nested"] = nxt
            curr = nxt
        data["provenanceClasses"][0] = deep_row
        self._write_json(data)
        res = validate_provenance_registry(self.fake_root)
        self.assertFalse(res.passed)
        self.assertIn(ERR_PROV_CORRUPT_FILE, {e.code for e in res.errors})

    # Finding 3: Refuse unknown keys & byte-exact metadata
    def test_planted_negative_unknown_top_level_key(self) -> None:
        """Unknown top-level keys must be refused and emit ERR-PROV-CORRUPT-FILE-001."""
        data = self._read_json()
        data["unrecognizedExtraKey"] = "not_allowed"
        self._write_json(data)

        res = validate_provenance_registry(self.fake_root)
        self.assertFalse(res.passed)
        self.assertEqual(
            {e.code for e in res.errors},
            {ERR_PROV_CORRUPT_FILE},
        )

    def test_planted_negative_unknown_row_key(self) -> None:
        """Unknown row keys must be refused and emit ERR-PROV-CORRUPT-FILE-001."""
        data = self._read_json()
        data["provenanceClasses"][0]["unrecognizedRowKey"] = "not_allowed"
        self._write_json(data)

        res = validate_provenance_registry(self.fake_root)
        self.assertFalse(res.passed)
        self.assertEqual(
            {e.code for e in res.errors},
            {ERR_PROV_CORRUPT_FILE, ERR_PROV_DIGEST_MISMATCH},
        )

    def test_planted_negative_irreversible_authorizers_top_level_key(self) -> None:
        """Planting irreversibleAuthorizers top-level key must emit semantic invariant and corrupt file errors."""
        data = self._read_json()
        data["irreversibleAuthorizers"] = ["predicted", "remembered"]
        self._write_json(data)

        res = validate_provenance_registry(self.fake_root)
        self.assertFalse(res.passed)
        self.assertEqual(
            {e.code for e in res.errors},
            {ERR_PROV_CORRUPT_FILE, ERR_PROV_SEMANTIC_INVARIANT},
        )

    def test_planted_negative_byte_exact_metadata_padding(self) -> None:
        """Padding metadata strings with spaces must not be stripped and must fail digest verification."""
        data = self._read_json()
        data["schema"] = "fss.provenance_classes.v1 "
        self._write_json(data)

        res = validate_provenance_registry(self.fake_root)
        self.assertFalse(res.passed)
        self.assertEqual({e.code for e in res.errors}, {ERR_PROV_DIGEST_MISMATCH})

    # Finding 4: Refuse duplicates in Markdown mirror
    def test_planted_negative_duplicate_row_in_markdown_mirror(self) -> None:
        """Duplicate rows in markdown mirror must be refused with ERR-PROV-STABLE-ID-REUSED-001."""
        md_path = self.fake_root / "registries/AGENT_CONTRACTS.md"
        content = md_path.read_text(encoding="utf-8")
        # Duplicate PROV-001 row
        dup_line = "| `PROV-001` | `observed` | Directly supported by canonical sensor, device, operator, or effect evidence. |\n"
        content = content.replace(dup_line, dup_line + dup_line)
        md_path.write_text(content, encoding="utf-8")

        res = validate_provenance_registry(self.fake_root)
        self.assertFalse(res.passed)
        self.assertEqual({e.code for e in res.errors}, {ERR_PROV_STABLE_ID_REUSED})

    def test_planted_negative_tampered_first_duplicate_in_markdown_mirror(self) -> None:
        """Placing a tampered row before an honest row in markdown mirror must not pass via last-wins."""
        md_path = self.fake_root / "registries/AGENT_CONTRACTS.md"
        content = md_path.read_text(encoding="utf-8")
        honest_line = "| `PROV-001` | `observed` | Directly supported by canonical sensor, device, operator, or effect evidence. |\n"
        tampered_line = "| `PROV-001` | `tampered_observed` | Tampered definition. |\n"
        content = content.replace(honest_line, tampered_line + honest_line)
        md_path.write_text(content, encoding="utf-8")

        res = validate_provenance_registry(self.fake_root)
        self.assertFalse(res.passed)
        self.assertEqual({e.code for e in res.errors}, {ERR_PROV_STABLE_ID_REUSED, ERR_PROV_REGISTRY_DRIFT})

    # Finding 5: ERR-PROV-SEMANTIC-INVARIANT-001 and class invariants
    def test_planted_negative_non_authorizing_class_illegal_irreversible_auth(self) -> None:
        """Declaring may_authorize_irreversible_effect for a non-authorizing class must emit ERR-PROV-SEMANTIC-INVARIANT-001."""
        data = self._read_json()
        data["provenanceClasses"][2]["may_authorize_irreversible_effect"] = True
        self._write_json(data)

        res = validate_provenance_registry(self.fake_root)
        self.assertFalse(res.passed)
        self.assertEqual(
            {e.code for e in res.errors},
            {ERR_PROV_SEMANTIC_INVARIANT, ERR_PROV_CORRUPT_FILE, ERR_PROV_DIGEST_MISMATCH},
        )

    def test_semantic_invariants_irreversible_authorization(self) -> None:
        """Unit test for validate_provenance_authorization."""
        # Non-authorizing classes cannot authorize irreversible effects
        for cls in NON_AUTHORIZING_CLASSES:
            ok, msg = validate_provenance_authorization(cls, "known", is_irreversible=True)
            self.assertFalse(ok)
            self.assertIn("ERR-PROV-SEMANTIC-INVARIANT-001", str(msg))

        # Authorizing classes can authorize when known
        for cls in AUTHORIZING_CLASSES:
            ok, msg = validate_provenance_authorization(cls, "known", is_irreversible=True)
            self.assertTrue(ok)
            self.assertIsNone(msg)

        # Authorizing classes cannot authorize when not known
        for cls in AUTHORIZING_CLASSES:
            ok, msg = validate_provenance_authorization(cls, "estimated", is_irreversible=True)
            self.assertFalse(ok)
            self.assertIn("require knowledge state 'known'", str(msg))

    def test_semantic_invariants_state_aware_evidence(self) -> None:
        """Unit test for validate_state_aware_evidence."""
        # Observed requires evidence for asserted states
        for st in STATES_REQUIRING_EVIDENCE:
            ok, msg = validate_state_aware_evidence("observed", st, evidence_count=0)
            self.assertFalse(ok)
            self.assertIn("ERR-PROV-SEMANTIC-INVARIANT-001", str(msg))
            ok_with_ev, _ = validate_state_aware_evidence("observed", st, evidence_count=1)
            self.assertTrue(ok_with_ev)

        # Honest absence / non-asserted states legitimately permit empty evidence
        for st in STATES_PERMITTING_EMPTY_EVIDENCE:
            ok, msg = validate_state_aware_evidence("observed", st, evidence_count=0)
            self.assertTrue(ok, f"State '{st}' should permit empty evidence for observed")
            self.assertIsNone(msg)

        # Derived requires derivation inputs for asserted states
        for st in STATES_REQUIRING_EVIDENCE:
            ok, msg = validate_state_aware_evidence("derived", st, evidence_count=0)
            self.assertFalse(ok)
            self.assertIn("ERR-PROV-SEMANTIC-INVARIANT-001", str(msg))

        for st in STATES_PERMITTING_EMPTY_EVIDENCE:
            ok, msg = validate_state_aware_evidence("derived", st, evidence_count=0)
            self.assertTrue(ok)

    def test_cell_provenance_invariants_comprehensive(self) -> None:
        """Unit test for validate_cell_provenance_invariants."""
        # Honest Unknown cell with Observed provenance and 0 evidence MUST PASS
        errs = validate_cell_provenance_invariants("observed", "unknown", evidence_count=0)
        self.assertEqual(len(errs), 0)

        # Honest NotObservable cell with Observed provenance and 0 evidence MUST PASS
        errs = validate_cell_provenance_invariants("observed", "not_observable", evidence_count=0)
        self.assertEqual(len(errs), 0)

        # Known cell with Observed provenance and 0 evidence MUST FAIL
        errs = validate_cell_provenance_invariants("observed", "known", evidence_count=0)
        self.assertEqual({e.code for e in errs}, {ERR_PROV_SEMANTIC_INVARIANT})

        # Predicted cell attempting irreversible effect MUST FAIL
        errs = validate_cell_provenance_invariants(
            "predicted", "known", evidence_count=1, authorizes_irreversible_effect=True
        )
        self.assertEqual({e.code for e in errs}, {ERR_PROV_SEMANTIC_INVARIANT})

    # Finding 6: Kills mutants M4b (extra-ID check) and M4c (row immutability)
    def test_planted_negative_extra_id_without_generation_bump(self) -> None:
        """Mutant M4b killer: adding an extra ID to all mirrors without generation bump must fail exact extra-ID check."""
        data = self._read_json()
        extra_row = {
            "id": "PROV-008",
            "class": "policy",
            "meaning": "An auxiliary policy generation threshold.",
        }
        data["provenanceClasses"].append(extra_row)
        data["registryDigest"] = compute_canonical_provenance_digest(data)
        self._write_json(data)

        # Also update agent_contracts.json
        ac = self._read_agent_contracts()
        ac["provenanceClasses"].append({
            "id": "PROV-008",
            "name": "policy",
            "meaning": "An auxiliary policy generation threshold.",
        })
        self._write_agent_contracts(ac)

        # Also update Markdown mirror
        md_path = self.fake_root / "registries/AGENT_CONTRACTS.md"
        content = md_path.read_text(encoding="utf-8")
        extra_md = "| `PROV-008` | `policy` | An auxiliary policy generation threshold. |\n"
        md_path.write_text(content + extra_md, encoding="utf-8")

        res = validate_provenance_registry(self.fake_root)
        self.assertFalse(res.passed)
        # If mutant M4b removes the extra-ID check, ERR_PROV_STABLE_ID_REUSED is absent!
        self.assertEqual(
            {e.code for e in res.errors},
            {ERR_PROV_FREEZE_DIVERGENCE, ERR_PROV_STABLE_ID_REUSED},
        )

    def test_planted_negative_baseline_row_immutability_with_mirror_updated(self) -> None:
        """Mutant M4c killer: mutating a baseline row across all mirrors must fail exact baseline row immutability check."""
        data = self._read_json()
        new_meaning = "Tampered definition synchronized across JSON and Markdown."
        data["provenanceClasses"][0]["meaning"] = new_meaning
        data["registryDigest"] = compute_canonical_provenance_digest(data)
        self._write_json(data)

        # Also update agent_contracts.json
        ac = self._read_agent_contracts()
        ac["provenanceClasses"][0]["meaning"] = new_meaning
        self._write_agent_contracts(ac)

        # Also update Markdown mirror
        md_path = self.fake_root / "registries/AGENT_CONTRACTS.md"
        content = md_path.read_text(encoding="utf-8")
        old_line = "| `PROV-001` | `observed` | Directly supported by canonical sensor, device, operator, or effect evidence. |\n"
        new_line = f"| `PROV-001` | `observed` | {new_meaning} |\n"
        content = content.replace(old_line, new_line)
        md_path.write_text(content, encoding="utf-8")

        res = validate_provenance_registry(self.fake_root)
        self.assertFalse(res.passed)
        # If mutant M4c removes the baseline row immutability check, ERR_PROV_REGISTRY_DRIFT is absent!
        self.assertEqual(
            {e.code for e in res.errors},
            {ERR_PROV_FREEZE_DIVERGENCE, ERR_PROV_REGISTRY_DRIFT},
        )

    def test_cli_execution(self) -> None:
        cmd = [sys.executable, "-B", str(ROOT / "scripts/provenance_registry_checker.py"), "--json"]
        proc = subprocess.run(cmd, capture_output=True, text=True)
        self.assertEqual(proc.returncode, 0, f"CLI stderr: {proc.stderr}")
        parsed = json.loads(proc.stdout)
        self.assertTrue(parsed["passed"])
        self.assertEqual(parsed["provenanceClassCount"], 7)
        self.assertEqual(parsed["registryDigest"], BASELINE_FREEZE_DIGEST)
        self.assertEqual(parsed["errorCount"], 0)

    def test_may_launder_evidence_table_matches_contract_rs(self) -> None:
        """The mayLaunderEvidenceInto table in agent_contracts.json must match may_launder_evidence_into in contract.rs."""
        matrix = extract_rust_may_launder_matrix(ROOT / "crates/fss-core/src/contract.rs")
        ac_data = self._read_agent_contracts()
        json_table = ac_data.get("mayLaunderEvidenceInto")
        self.assertIsInstance(json_table, dict)
        self.assertEqual(matrix, json_table)

    def test_planted_negative_may_launder_evidence_missing(self) -> None:
        """Missing mayLaunderEvidenceInto in agent_contracts.json must emit ERR-PROV-MISSING-FIELD-001."""
        ac_data = self._read_agent_contracts()
        del ac_data["mayLaunderEvidenceInto"]
        self._write_agent_contracts(ac_data)

        res = validate_provenance_registry(self.fake_root)
        self.assertFalse(res.passed)
        self.assertIn(ERR_PROV_MISSING_FIELD, {e.code for e in res.errors})

    def test_planted_negative_may_launder_evidence_drift(self) -> None:
        """Tampered mayLaunderEvidenceInto in agent_contracts.json must emit ERR-PROV-REGISTRY-DRIFT-001."""
        ac_data = self._read_agent_contracts()
        # Illegally declare that observed may launder into predicted
        ac_data["mayLaunderEvidenceInto"]["observed"] = ["predicted"]
        self._write_agent_contracts(ac_data)

        res = validate_provenance_registry(self.fake_root)
        self.assertFalse(res.passed)
        self.assertIn(ERR_PROV_REGISTRY_DRIFT, {e.code for e in res.errors})


class LaunderingWiringTests(unittest.TestCase):
    """Fail-closed enforcement of the production laundering-call guard (fss-2nwxm)."""

    def setUp(self) -> None:
        self.temp_dir = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp_dir.cleanup)
        self.fake_root = Path(self.temp_dir.name)

    def test_live_repository_has_non_test_caller(self) -> None:
        """The live repository must wire the refusal into at least one production path."""
        sites = provenance_registry_checker.production_laundering_call_sites(ROOT)
        self.assertTrue(
            sites,
            "KnowledgeCell::verify_no_evidence_laundering must keep at least one non-test caller",
        )
        res = validate_laundering_wiring(ROOT)
        self.assertTrue(res.passed, f"{res.errors}")

    def _write_crate_source(self, rel: str, text: str) -> None:
        path = self.fake_root / rel
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(text, encoding="utf-8")

    DEFINITION_ONLY = """
pub struct Cell;
impl Cell {
    pub fn verify_no_evidence_laundering(&self, prior: &Cell) -> Result<(), ()> { Ok(()) }
}
"""

    PRODUCTION_CALLER = DEFINITION_ONLY + """
pub fn admit(current: &Cell, prior: &Cell) -> Result<(), ()> {
    current.verify_no_evidence_laundering(prior)
}
"""

    def test_repository_without_any_caller_fails(self) -> None:
        """A definition without any call site must emit ERR-PROV-LAUUNDERING-UNWIRED-001."""
        self._write_crate_source("crates/fss-core/src/agent.rs", self.DEFINITION_ONLY)
        res = validate_laundering_wiring(self.fake_root)
        self.assertFalse(res.passed)
        self.assertEqual({e.code for e in res.errors}, {ERR_PROV_LAUUNDERING_UNWIRED})

    def test_test_only_callers_do_not_satisfy(self) -> None:
        """Calls confined to test modules, *_tests.rs files, or tests/ dirs must not satisfy the guard."""
        cfg_test = """
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn laundering_is_refused() {
        let current = Cell;
        let prior = Cell;
        let _ = current.verify_no_evidence_laundering(&prior);
    }
}
"""
        self._write_crate_source("crates/fss-core/src/agent.rs", self.DEFINITION_ONLY + cfg_test)
        self._write_crate_source(
            "crates/fss-core/src/delta_tests.rs",
            "use super::*;\n#[test]\nfn t() { let _ = Cell().verify_no_evidence_laundering(&Cell()); }\n",
        )
        self._write_crate_source(
            "crates/fss-core/tests/integration.rs",
            "#[test]\nfn t() { let _ = Cell().verify_no_evidence_laundering(&Cell()); }\n",
        )
        res = validate_laundering_wiring(self.fake_root)
        self.assertFalse(res.passed)
        self.assertEqual({e.code for e in res.errors}, {ERR_PROV_LAUUNDERING_UNWIRED})

    def test_production_caller_satisfies(self) -> None:
        """One genuine non-test call site satisfies the guard."""
        self._write_crate_source("crates/fss-reference/src/meaningful_delta.rs", self.PRODUCTION_CALLER)
        res = validate_laundering_wiring(self.fake_root)
        self.assertTrue(res.passed, f"{res.errors}")

    def test_cfg_test_mention_in_comment_does_not_suppress_or_count(self) -> None:
        """A comment mentioning the attribute must not hide production code; comments never count as callers."""
        commented = """
// The #[cfg(test)] module below (removed) once held the only call.
pub fn admit(current: &Cell, prior: &Cell) -> Result<(), ()> {
    current.verify_no_evidence_laundering(prior)
}
"""
        self._write_crate_source("crates/fss-core/src/agent.rs", commented)
        res = validate_laundering_wiring(self.fake_root)
        self.assertTrue(res.passed, f"{res.errors}")


if __name__ == "__main__":
    unittest.main()

