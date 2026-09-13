#!/usr/bin/env python3
"""Deterministic verification suite for the dependency-class registry checker (fss-x4a.30.88.1).

The registry holds no policy of its own: DEPENDENCY_CONSTITUTION.md with
architecture/dependency_allowlist.toml is the authority and architecture/dependency_constitution.json is
the class registry (scripts/dependency_authority.py). Every test asserts an exact finding-code set.

Every test name that existed at e4ec37f, 01dbde8 and 5291d07 is kept. Where the round-3 review showed an
old expectation encoded a defect (fail-open halting, a wrong code, member-inflated consumers), the test
now asserts the stricter, correct set and says why in its docstring.
"""
from __future__ import annotations

import copy
import json
import shutil
import sys
import tempfile
import unittest
from pathlib import Path
from typing import Any
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))

import dependency_audit  # noqa: E402
import dependency_authority  # noqa: E402
import dependency_registry_checker  # noqa: E402
from dependency_registry_checker import (  # noqa: E402
    BASELINE_ALLOWLIST_FREEZE_DIGEST,
    BASELINE_CONSTITUTION_FREEZE_DIGEST,
    BASELINE_DEPENDENCIES_FREEZE_DIGEST,
    BASELINE_DEPENDENCIES_GENERATION,
    ERR_DEP_ALLOWLIST_DIGEST_DIVERGED,
    ERR_DEP_CONST_INVARIANT,
    ERR_DEP_CORRUPT_FILE,
    ERR_DEP_DIGEST_MISMATCH,
    ERR_DEP_FREEZE_DIVERGENCE,
    ERR_DEP_GENERATION_MISMATCH,
    ERR_DEP_MISSING_FIELD,
    ERR_DEP_REGISTRY_DRIFT,
    ERR_DEP_STABLE_ID_REUSED,
    ERR_DEP_TOMBSTONE_INVALID,
    ERR_DEP_TRACE_UNRESOLVED,
    EXPECTED_FREEZE_DIGESTS,
    MANDATORY_ROW_FIELDS,
    MANDATORY_TOP_LEVEL_FIELDS,
    MAX_REGISTRY_FILE_SIZE_BYTES,
    compute_allowlist_freeze_digest,
    compute_canonical_dependencies_digest,
    compute_constitution_freeze_digest,
    load_tombstone_set,
    parse_dependencies_markdown,
    render_dependencies_markdown,
    resolve_dependency_row_metadata,
    validate_dependency_registry,
)

AUTHORITY_FILES = (
    "architecture/dependencies.json",
    "architecture/dependency_constitution.json",
    "architecture/dependency_allowlist.toml",
    "architecture/franken_imports.json",
    "architecture/local_qualification.toml",
    "architecture/stable_id_resolution.json",
    "architecture/agent_contracts.json",
    "registries/DEPENDENCIES.md",
    "registries/ERRORS.md",
    "scripts/dependency_audit.py",
    "scripts/dependency_registry_checker.py",
    "scripts/dependency_constitution_checker.py",
    "scripts/check-policy.py",
)
DJ = "architecture/dependencies.json"
CJ = "architecture/dependency_constitution.json"
AL = "architecture/dependency_allowlist.toml"
MD = "registries/DEPENDENCIES.md"
TS = "architecture/stable_id_resolution.json"
IMPORTS = "architecture/franken_imports.json"

D = ERR_DEP_DIGEST_MISMATCH
F = ERR_DEP_FREEZE_DIVERGENCE
G = ERR_DEP_GENERATION_MISMATCH
M = ERR_DEP_MISSING_FIELD
C = ERR_DEP_CORRUPT_FILE
R = ERR_DEP_REGISTRY_DRIFT
S = ERR_DEP_STABLE_ID_REUSED
I = ERR_DEP_CONST_INVARIANT
A = ERR_DEP_ALLOWLIST_DIGEST_DIVERGED
T = ERR_DEP_TRACE_UNRESOLVED
X = ERR_DEP_TOMBSTONE_INVALID


def copy_authority(dest: Path) -> Path:
    for rel in AUTHORITY_FILES:
        (dest / rel).parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(ROOT / rel, dest / rel)
    return dest


def codes(result: Any) -> set[str]:
    return {e.code for e in result.errors}


class AuthorityCase(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp_dir = tempfile.TemporaryDirectory()
        self.tmp_root = copy_authority(Path(self.tmp_dir.name))

    def tearDown(self) -> None:
        self.tmp_dir.cleanup()

    # helpers -------------------------------------------------------------------------------
    def path(self, rel: str) -> Path:
        return self.tmp_root / rel

    def load(self, rel: str = DJ) -> dict[str, Any]:
        return json.loads(self.path(rel).read_text(encoding="utf-8"))

    def save(self, data: Any, rel: str = DJ, redigest: bool = False) -> None:
        if redigest and rel == DJ:
            data["freezeDigest"] = compute_canonical_dependencies_digest(data)
        if redigest and rel == CJ:
            data["freezeDigest"] = dependency_authority.compute_canonical_constitution_digest(data)
        self.path(rel).write_text(json.dumps(data, indent=2), encoding="utf-8")

    def text(self, rel: str) -> str:
        return self.path(rel).read_text(encoding="utf-8")

    def write(self, rel: str, text: str) -> None:
        self.path(rel).write_text(text, encoding="utf-8")

    def replace(self, rel: str, old: str, new: str) -> None:
        text = self.text(rel)
        self.assertIn(old, text)
        self.write(rel, text.replace(old, new, 1))

    def row(self, data: dict[str, Any], dep_id: str) -> dict[str, Any]:
        return next(r for r in data["dependencies"] if r["id"] == dep_id)

    def check(self) -> Any:
        return validate_dependency_registry(self.tmp_root)

    def assertCodes(self, expected: set[str], result: Any | None = None) -> Any:
        result = result if result is not None else self.check()
        self.assertEqual(codes(result), expected, [f"{e.code} {e.target}: {e.message}" for e in result.errors])
        self.assertEqual(result.passed, not expected)
        return result


class TestDependencyRegistryChecker(AuthorityCase):
    """Verifies the registry checker against the live repository and planted faults (exact code sets)."""

    def test_live_registry_passes(self) -> None:
        """Live repository dependencies.json passes validation with 0 errors."""
        result = validate_dependency_registry(ROOT)
        self.assertTrue(result.passed, f"Live registry validation failed: {[e.message for e in result.errors]}")
        self.assertEqual(len(result.errors), 0)
        self.assertEqual(result.dependency_count, 5)
        self.assertEqual(result.freeze_digest, BASELINE_DEPENDENCIES_FREEZE_DIGEST)
        self.assertEqual(result.report["pendingOwnerDecisions"]["fss-ndxis"]["crates"], ["serde", "serde_json"])

    def test_exact_freeze_digest_assertion(self) -> None:
        """Freeze digests match the exact pinned constants byte-for-byte (registry, allowlist, constitution)."""
        result = self.assertCodes(set())
        self.assertEqual(result.freeze_digest, BASELINE_DEPENDENCIES_FREEZE_DIGEST)
        self.assertEqual(EXPECTED_FREEZE_DIGESTS, {BASELINE_DEPENDENCIES_GENERATION: BASELINE_DEPENDENCIES_FREEZE_DIGEST})
        self.assertTrue(result.freeze_digest.startswith("sha256:"))
        self.assertEqual(len(result.freeze_digest), 7 + 64)
        self.assertEqual(compute_allowlist_freeze_digest(self.path(AL)), BASELINE_ALLOWLIST_FREEZE_DIGEST)
        self.assertEqual(compute_constitution_freeze_digest(self.path(CJ)), BASELINE_CONSTITUTION_FREEZE_DIGEST)
        self.assertEqual(result.report["allowlistDigest"], BASELINE_ALLOWLIST_FREEZE_DIGEST)

    def test_canonical_digest_deterministic(self) -> None:
        """Canonical digest is deterministic, invariant to row permutation, and typed (5 differs from "5")."""
        data = self.load()
        digest1 = compute_canonical_dependencies_digest(data)
        data_rev = copy.deepcopy(data)
        data_rev["dependencies"] = list(reversed(data_rev["dependencies"]))
        self.assertEqual(digest1, compute_canonical_dependencies_digest(data_rev))
        self.assertEqual(digest1, BASELINE_DEPENDENCIES_FREEZE_DIGEST)
        self.assertNotEqual(compute_canonical_dependencies_digest(dict(data, schema=5)), compute_canonical_dependencies_digest(dict(data, schema="5")))
        self.assertNotEqual(digest1, compute_canonical_dependencies_digest(dict(data, extra={"a": 1})))

    def test_tampered_digest_rejected(self) -> None:
        """A tampered freezeDigest is refused; the markdown mirror of freezeDigest also drifts."""
        data = self.load()
        data["freezeDigest"] = "sha256:" + "0" * 64
        self.save(data)
        self.assertCodes({D, R})

    def test_row_mutation_without_generation_bump_rejected(self) -> None:
        """Row mutated and re-digested without a generation bump fails freeze divergence."""
        data = self.load()
        self.row(data, "DEP-OWNED-001")["rule"] = "tampered rule without approval"
        self.save(data, redigest=True)
        self.assertCodes({F, R})

    def test_unpinned_generation_rejected(self) -> None:
        """An unpinned generation is refused (the mirror's generation/freezeDigest rows drift too)."""
        data = self.load()
        data["generation"] = "gen:fss1:dependencies-unauthorized-v99"
        self.save(data, redigest=True)
        self.assertCodes({G, R})
        data["generation"] = "gen:fss1:dependencies-v1"  # the superseded generation is stale, not accepted
        self.save(data, redigest=True)
        self.assertCodes({G, R})

    def test_missing_top_level_field_rejected(self) -> None:
        """Missing any top-level field is MISSING-FIELD; the digest and crosswalk keep checking (no fail-open halt)."""
        original = self.load()
        expected = {
            "schema": {M, D, F},
            "generation": {M, G, D},
            "freezeDigest": {M},
            "sourceDocument": {M, D, F},
            "constitution": {M, D, F},
            "policy": {M, D, F},
            "contractBasis": {M, D, F},
            "dependencies": {M, D, F, I, R},
        }
        self.assertEqual(set(expected), set(MANDATORY_TOP_LEVEL_FIELDS))
        for field_name in MANDATORY_TOP_LEVEL_FIELDS:
            with self.subTest(field=field_name):
                data = copy.deepcopy(original)
                del data[field_name]
                self.save(data)
                self.assertCodes(expected[field_name])

    def test_missing_row_field_rejected(self) -> None:
        """Missing any row field is MISSING-FIELD; field-specific crosswalk consequences are exact."""
        original = self.load()
        base = {M, F, R}
        expected = {
            "id": base | {I},
            "constitutionClass": base | {I},
            "constitutionClasses": base | {I},  # DEP-OWNED-001 is the only row mapping DEP-CLASS-F1
            "class": base,
            "rule": base,
            "scope": base,
            "status": base | {I},
            "supersededBy": base,
            "tombstoneDecision": base,
            "owner": base,
            "producers": base | {I},
            "consumers": base,
        }
        self.assertEqual(set(expected), set(MANDATORY_ROW_FIELDS))
        for row_field in MANDATORY_ROW_FIELDS:
            with self.subTest(field=row_field):
                data = copy.deepcopy(original)
                del data["dependencies"][0][row_field]
                self.save(data, redigest=True)
                self.assertCodes(expected[row_field])

    def test_duplicate_id_rejected(self) -> None:
        """A duplicate row ID is STABLE-ID-REUSED (and drifts from the pin and the mirror)."""
        data = self.load()
        data["dependencies"].append(copy.deepcopy(data["dependencies"][0]))
        self.save(data, redigest=True)
        self.assertCodes({S, F, R})

    def test_case_colliding_id_rejected(self) -> None:
        """A case-colliding row ID is STABLE-ID-REUSED; the colliding row also double-produces [in_house]."""
        data = self.load()
        dupe = copy.deepcopy(data["dependencies"][0])
        dupe["id"] = dupe["id"].lower()
        data["dependencies"].append(dupe)
        self.save(data, redigest=True)
        self.assertCodes({S, F, R, I})

    def test_tombstoned_id_rejected(self) -> None:
        """Resurrecting a tombstoned identifier fails with exact ERR-DEP-STABLE-ID-REUSED-001."""
        self.write(TS, json.dumps({
            "schema": "fss.stable_id_resolution.v1",
            "asOf": "2026-09-01",
            "resolutions": [{"legacyId": "DEP-OWNED-001", "status": "tombstoned", "canonicalId": "DEP-OWNED-999"}],
        }))
        self.assertCodes({S})
        retired, errs = load_tombstone_set(self.tmp_root)
        self.assertEqual((retired, errs), ({"DEP-OWNED-001"}, []))

    # Mutant M4: the deleted baseline-id table is replaced by the pin + mirror + crosswalk.
    def test_mutant_m4_baseline_id_compare(self) -> None:
        """A renumbered row ID diverges from the pin and from the mirror."""
        data = self.load()
        data["dependencies"][0]["id"] = "DEP-ROGUE-001"
        self.save(data, redigest=True)
        self.assertCodes({F, R})

    def test_mutant_m4b_missing_canonical_row(self) -> None:
        """Dropping DEP-OWNED-001 diverges and leaves [in_house] produced into no row."""
        data = self.load()
        data["dependencies"] = [d for d in data["dependencies"] if d["id"] != "DEP-OWNED-001"]
        self.save(data, redigest=True)
        self.assertCodes({F, R, I})

    def test_mutant_m4c_missing_canonical_row(self) -> None:
        """Dropping DEP-EXCEPTION-001 diverges and leaves [exception_candidates] produced into no row."""
        data = self.load()
        data["dependencies"] = [d for d in data["dependencies"] if d["id"] != "DEP-EXCEPTION-001"]
        self.save(data, redigest=True)
        self.assertCodes({F, R, I})

    def test_unknown_top_level_key_rejected(self) -> None:
        """An unknown top-level key is refused and is covered by the digest (no silent override)."""
        data = self.load()
        data["overrides"] = {"DEP-FUND-001": "allowed"}
        self.save(data)
        self.assertCodes({C, D, F})

    def test_unknown_row_key_rejected(self) -> None:
        """An unknown row key is refused and is covered by the digest."""
        data = self.load()
        data["dependencies"][0]["extraAdmission"] = "bypass"
        self.save(data)
        self.assertCodes({C, D, F})

    def test_duplicate_json_keys_rejected(self) -> None:
        """Duplicate JSON keys fail closed with ERR-DEP-CORRUPT-FILE-001."""
        self.write(DJ, '{\n  "schema": "fss.dependencies.v2",\n' + self.text(DJ)[1:])
        self.assertCodes({C})

    def test_whitespace_padding_rejected(self) -> None:
        """'Production ' is refused without stripping: bad value, unknown scope, pin and mirror drift."""
        data = self.load()
        data["dependencies"][0]["scope"] = "Production "
        self.save(data, redigest=True)
        self.assertCodes({C, F, I, R})

    def test_non_backticked_markdown_row_parsed(self) -> None:
        """Non-backticked markdown rows like | DEP-ROGUE-001 | are refused, not ignored."""
        self.write(MD, self.text(MD) + "| DEP-ROGUE-001 | DEP-CLASS-F4 | Rogue package | test | Development only |\n")
        self.assertCodes({R})

    def test_duplicate_markdown_row_rejected(self) -> None:
        """A duplicated markdown row is STABLE-ID-REUSED (and a rogue row outside the table)."""
        dup_row = "| `DEP-OWNED-001` | `DEP-CLASS-F2` | Owned runtime and Franken-suite families | admitted after per-mechanism integration gate | `Production` |\n"
        self.write(MD, self.text(MD) + dup_row)
        self.assertCodes({S, R})

    def test_scope_constitution_cross_check_failure(self) -> None:
        """DEP-LAB-001 (DEP-CLASS-F4, quarantine) with Production scope fails the crosswalk."""
        data = self.load()
        self.row(data, "DEP-LAB-001")["scope"] = "Production"
        self.save(data, redigest=True)
        self.assertCodes({I, F, R})

    def test_malformed_generation_list_handled_safely(self) -> None:
        """A list generation never raises; it is a corrupt (wrong-type) value and an unpinned generation.

        Code correction: 01dbde8 asserted MISSING-FIELD, but a present value of the wrong type is CORRUPT-FILE.
        """
        data = self.load()
        data["generation"] = ["invalid-list"]
        self.save(data)
        self.assertCodes({C, G, D})

    def test_malformed_dependencies_types_handled_safely(self) -> None:
        """dependencies as dict, string, list of ints, or list with null never raise; exact code sets."""
        for bad_deps in ({"a": 1}, "abc", [1], [None]):
            with self.subTest(bad_deps=bad_deps):
                data = self.load(DJ) if False else json.loads((ROOT / DJ).read_text(encoding="utf-8"))
                data["dependencies"] = bad_deps
                self.save(data)
                self.assertCodes({C, D, F, I, R})

    def test_invalid_utf8_json_handled_safely(self) -> None:
        """Invalid UTF-8 bytes fail closed with exact ERR-DEP-CORRUPT-FILE-001."""
        self.path(DJ).write_bytes(b"\xff\xfe{\"schema\": 1}")
        self.assertCodes({C})

    def test_markdown_mirror_drift_rejected(self) -> None:
        """Markdown mirror disagreement in class, scope, or a dropped row is exact REGISTRY-DRIFT."""
        original = self.text(MD)
        for tampered in (
            original.replace("Owned runtime and Franken-suite families", "Drifted Class Name"),
            original.replace("`Production`", "`Experimental`"),
            "\n".join(line for line in original.splitlines() if "DEP-EXCEPTION-001" not in line) + "\n",
            original.replace("`active` | — | — | `scripts/dependency_audit.py` | `architecture/dependency_allowlist.toml#fundamental`", "`tombstoned` | — | — | `scripts/dependency_audit.py` | `architecture/dependency_allowlist.toml#fundamental`"),
            original.replace("| `gen:fss1:dependencies-v2` |", "| `gen:fss1:dependencies-v3` |"),
        ):
            with self.subTest(tampered=tampered[-200:]):
                self.assertNotEqual(tampered, original)
                self.write(MD, tampered)
                self.assertCodes({R})
        # A dropped markdown row is reported against that row, not only as a row-count mismatch (M4c).
        self.write(MD, "\n".join(line for line in original.splitlines() if "DEP-EXCEPTION-001" not in line) + "\n")
        result = self.check()
        self.assertEqual(sorted(e.target for e in result.errors), ["#", "row/DEP-EXCEPTION-001"])

    def test_corrupt_or_empty_files_rejected(self) -> None:
        """Corrupt or 0-byte JSON and Markdown files fail closed with exact ERR-DEP-CORRUPT-FILE-001."""
        for content in ("", "   \n", "{ unquoted_key: ]", "[]", "﻿{}"):
            with self.subTest(content=content):
                self.write(DJ, content)
                self.assertCodes({C})
        shutil.copy2(ROOT / DJ, self.path(DJ))
        for content in ("", "# Empty dependencies\n"):
            with self.subTest(md=content):
                self.write(MD, content)
                self.assertCodes({C})

    def test_prefix_only_digest_bypass_prevented(self) -> None:
        """A digest that keeps the prefix but changes the tail is refused (M-prefix)."""
        data = self.load()
        data["freezeDigest"] = BASELINE_DEPENDENCIES_FREEZE_DIGEST[:-8] + "deadbeef"
        self.save(data)
        self.assertCodes({D, R})

    def test_mutant_m4b_constitution_class_mismatch(self) -> None:
        """A row referencing an unknown DEP-CLASS id fails the crosswalk, the pin and the mirror."""
        data = self.load()
        data["dependencies"][0]["constitutionClass"] = "DEP-CLASS-F99"
        self.save(data, redigest=True)
        self.assertCodes({I, F, R})

    def test_mutant_m4c_rule_mismatch(self) -> None:
        """Mutating a rule diverges from the pin and the mirror."""
        data = self.load()
        data["dependencies"][0]["rule"] = "tampered rule divergence"
        self.save(data, redigest=True)
        self.assertCodes({F, R})

    def test_mutant_m4d_scope_mismatch(self) -> None:
        """Mutating a scope diverges from the pin and the mirror."""
        data = self.load()
        data["dependencies"][0]["scope"] = "Development only"
        self.save(data, redigest=True)
        self.assertCodes({F, R})

    def test_mutant_m_f4adm_admission_mutated(self) -> None:
        """DEP-CLASS-F4 admission mutated in the constitution fails its pin and the F4-row crosswalk."""
        data = self.load(CJ)
        for c in data["classes"]:
            if c["id"] == "DEP-CLASS-F4":
                c["admission"] = "production-allowed"
        self.save(data, CJ)
        result = self.assertCodes({I, D, F})
        self.assertTrue(any("not mapped to the quarantine class" in e.message for e in result.errors))

    def test_mutant_m_closed_allowlist_closed_universe(self) -> None:
        """closed_universe=false contradicts the constitution and diverges from the allowlist pin."""
        self.replace(AL, "closed_universe = true", "closed_universe = false")
        self.assertCodes({I, A})

    def test_mutant_m10b_missing_mandatory_row_field(self) -> None:
        """A row missing a field without a digest update is MISSING-FIELD plus digest mismatch/divergence."""
        data = self.load()
        del data["dependencies"][0]["rule"]
        self.save(data)
        self.assertCodes({M, D, F})

    def test_mutant_m12c_case_colliding_id(self) -> None:
        """Case-colliding dependency ID fails with ERR-DEP-STABLE-ID-REUSED-001 (pattern and collision)."""
        data = self.load()
        dupe = copy.deepcopy(data["dependencies"][0])
        dupe["id"] = dupe["id"].lower()
        data["dependencies"].append(dupe)
        self.save(data, redigest=True)
        result = self.assertCodes({S, F, R, I})
        self.assertEqual(sum(e.code == S for e in result.errors), 2)

    def test_mutant_m13b_duplicate_id_in_json(self) -> None:
        """Duplicate ID in the JSON rows fails with ERR-DEP-STABLE-ID-REUSED-001."""
        data = self.load()
        data["dependencies"].append(copy.deepcopy(data["dependencies"][0]))
        self.save(data, redigest=True)
        result = self.assertCodes({S, F, R})
        self.assertEqual(sum(e.code == S for e in result.errors), 1)

    def test_mutant_m13c_duplicate_id_in_markdown(self) -> None:
        """A duplicate ID inside the markdown table (valid 12-column row) is STABLE-ID-REUSED."""
        lines = self.text(MD).split("\n")
        index = next(i for i, line in enumerate(lines) if line.startswith("| `DEP-OWNED-001`"))
        lines.insert(index + 1, lines[index])
        self.write(MD, "\n".join(lines))
        result = self.assertCodes({S, R})
        self.assertTrue(any("row count" in e.message for e in result.errors))

    def test_scenarios_s3_s4_s5_crosswalk(self) -> None:
        """S3/S4/S5 (F2/F3 admission, F4 name), allowlist moves, duplicate keys and deleted inputs fail closed."""
        cases = {
            "S3 F2 admission": ("DEP-CLASS-F2", "admission", "unadmitted"),
            "S4 F3 admission": ("DEP-CLASS-F3", "admission", "unadmitted"),
            "S5 F4 name": ("DEP-CLASS-F4", "name", "wrong-name"),
        }
        for label, (class_id, key, value) in cases.items():
            with self.subTest(label):
                data = json.loads((ROOT / CJ).read_text(encoding="utf-8"))
                next(c for c in data["classes"] if c["id"] == class_id)[key] = value
                self.save(data, CJ)
                self.assertCodes({I, D, F})
        shutil.copy2(ROOT / CJ, self.path(CJ))

        orig_allow = self.text(AL)
        self.write(AL, orig_allow.replace('crates = [\n  "tokio",', 'crates = [\n  "serde", "tokio",'))
        result = self.assertCodes({A, I})
        self.assertTrue(any("decides the open question" in e.message for e in result.errors))
        self.write(AL, orig_allow.replace("[laboratory_oracles]", "[disabled_laboratory_oracles]").replace("[laboratory_oracles.rows]", "[disabled_laboratory_oracles.rows]"))
        self.assertCodes({A, C, M, I, T})
        self.write(AL, orig_allow)

        self.write(CJ, '{\n  "schema": "fss.dependency_constitution.v1",\n' + self.text(CJ)[1:])
        self.assertCodes({C})
        shutil.copy2(ROOT / CJ, self.path(CJ))

        for rel, expected in ((CJ, {C}), (AL, {C, T}), (IMPORTS, {C, T}), ("architecture/local_qualification.toml", {C}), (TS, {C}), ("architecture/agent_contracts.json", {C})):
            with self.subTest(missing=rel):
                self.path(rel).unlink()
                self.assertCodes(expected)
                shutil.copy2(ROOT / rel, self.path(rel))
        self.assertCodes(set())

    def test_file_size_bound(self) -> None:
        """Inputs larger than the operational bound fail closed with exact ERR-DEP-CORRUPT-FILE-001."""
        self.assertEqual(MAX_REGISTRY_FILE_SIZE_BYTES, 10 * 1024 * 1024)
        orig_stat = Path.stat

        def fake_stat(path: Path, *args: Any, **kwargs: Any) -> Any:
            st = orig_stat(path, *args, **kwargs)
            if str(path).endswith("dependencies.json"):
                class FakeStat:
                    st_size = 11 * 1024 * 1024
                return FakeStat()
            return st

        with mock.patch.object(Path, "stat", fake_stat):
            self.assertCodes({C})
        with mock.patch.object(dependency_authority, "MAX_INPUT_FILE_BYTES", 64):
            result = self.check()
        self.assertEqual(codes(result), {C})
        self.assertTrue(all("operational input bound of 64 bytes" in e.message for e in result.errors))

        # stat may under-report (growing file, special file): the bounded read itself must refuse.
        def lying_stat(path: Path, *args: Any, **kwargs: Any) -> Any:
            st = orig_stat(path, *args, **kwargs)
            if str(path).endswith("dependencies.json"):
                class Small:
                    st_size = 1
                    st_mode = st.st_mode
                return Small()
            return st

        with mock.patch.object(Path, "stat", lying_stat), mock.patch.object(dependency_authority, "MAX_INPUT_FILE_BYTES", 256):
            data, problems = dependency_authority.read_input_bytes(self.path(DJ), DJ)
        self.assertIsNone(data)
        self.assertEqual([(e.code, "exceeds the operational input bound of 256 bytes" in e.message) for e in problems], [(C, True)])

    def test_markdown_rogue_rows_detected(self) -> None:
        """Rogue ids in any formatting, inside or outside the table, are exact REGISTRY-DRIFT."""
        base_md = self.text(MD)
        appended = [
            "| `dep-rogue-001` | `DEP-CLASS-F2` | Rogue | none | `Production` |\n",
            "| **`DEP-ROGUE-001`** | `DEP-CLASS-F2` | Rogue | none | `Production` |\n",
            "DEP-ROGUE-001 | `DEP-CLASS-F2` | Rogue | none | `Production`\n",
            "| `DEP-CLASS-F2` | `DEP-ROGUE-001` | Rogue | none | `Production` |\n",
            "| DEP-ROGUE-001 | `DEP-CLASS-F2` | Rogue | none | `Production` |\n",
            "| `DEP-ROGUE-001` | `DEP-CLASS-F2` | `Rogue` | none | `Production` |\n",
            "| `DEP-ROGUE-001` | `DEP-CLASS-F2` | Rogue | `Production` |\n",
            "See [DEP-ROGUE-001](x) for the admission.\n",
            "<b>DEP-ROGUE-001</b>\n",
            "```\n| `DEP-ROGUE-001` |\n```\n",
        ]
        for idx, extra in enumerate(appended):
            with self.subTest(case_idx=idx):
                self.write(MD, base_md + extra)
                self.assertCodes({R})
        lines = base_md.split("\n")
        owned = next(i for i, line in enumerate(lines) if line.startswith("| `DEP-OWNED-001`"))
        inside = [
            lines[owned].replace("`DEP-OWNED-001`", "**`DEP-ROGUE-001`**"),
            lines[owned].replace("`DEP-OWNED-001`", "`DEP-ROGUE-001`"),
            lines[owned].replace("Owned runtime", "DEP-ROGUE-001 runtime"),
            lines[owned].replace("`Production`", "Production"),
            lines[owned].replace(" | ", " |  ", 1),
        ]
        for idx, row_line in enumerate(inside):
            with self.subTest(inside_idx=idx):
                tampered = list(lines)
                tampered.insert(owned + 1, row_line)
                self.write(MD, "\n".join(tampered))
                # rows 2-4 keep the DEP-OWNED-001 id, so they are also duplicates of the real row
                self.assertCodes({R} if idx < 2 else {R, S})

    def test_scope_metadata_resolution(self) -> None:
        """Owner, producers, consumers, ContractBasis link and tombstone state resolve from the registry."""
        meta = resolve_dependency_row_metadata("DEP-OWNED-001", repo_root=ROOT)
        registry_row = self.row(json.loads((ROOT / DJ).read_text(encoding="utf-8")), "DEP-OWNED-001")
        self.assertTrue(meta["resolved"])
        self.assertEqual(meta["id"], "DEP-OWNED-001")
        self.assertEqual(meta["canonicalId"], "DEP-OWNED-001")
        self.assertEqual(meta["owner"], "scripts/dependency_audit.py")
        self.assertEqual(meta["producers"], registry_row["producers"])
        self.assertIn("architecture/franken_imports.json", meta["producers"])
        self.assertEqual(meta["consumers"], registry_row["consumers"])
        self.assertIn("scripts/check-policy.py", meta["consumers"])
        self.assertEqual(meta["contractBasis"], "fss.agent_contract_basis.v1")
        self.assertEqual(meta["registryDigest"], BASELINE_DEPENDENCIES_FREEZE_DIGEST)
        self.assertFalse(meta["isTombstoned"])
        self.assertFalse(meta["tombstone"])
        meta_fund = resolve_dependency_row_metadata("DEP-FUND-001", repo_root=ROOT)
        self.assertEqual(meta_fund["id"], "DEP-FUND-001")
        self.assertIn("architecture/dependency_allowlist.toml#pending_owner_decisions", meta_fund["producers"])
        self.assertFalse(meta_fund["isTombstoned"])
        missing = resolve_dependency_row_metadata("DEP-NOPE-001", repo_root=ROOT)
        self.assertFalse(missing["resolved"])

    # --- review round-3 additions -----------------------------------------------------------

    def test_allowlist_every_policy_flag_flip_rejected(self) -> None:
        """Each of the 16 allowlist flags, flipped, contradicts the constitution/local contract and the pin."""
        original = self.text(AL)
        live = dependency_authority.live_authority().allowlist["policy"]
        self.assertEqual(set(live), set(dependency_authority.ALLOWLIST_POLICY_FLAGS))
        for flag, value in live.items():
            with self.subTest(flag=flag):
                lit, neg = ("true", "false") if value else ("false", "true")
                self.write(AL, original.replace(f"{flag} = {lit}", f"{flag} = {neg}", 1))
                result = self.assertCodes({I, A})
                self.assertTrue(any(e.target == f"#/policy/{flag}" for e in result.errors))

    def test_allowlist_types_are_exact(self) -> None:
        """closed_universe = 1 is an int, not a bool; strings and lists are typed too."""
        original = self.text(AL)
        for old, new in (
            ("closed_universe = true", "closed_universe = 1"),
            ("c_or_cpp_ffi_allowed = false", "c_or_cpp_ffi_allowed = 0"),
            ("c_or_cpp_ffi_allowed = false", 'c_or_cpp_ffi_allowed = "false"'),
            ('crates = [\n  "tokio",', 'crates = [\n  {a = 1}, "tokio",'),
            ('"asupersync",\n', '"asupersync", 5,\n'),
        ):
            with self.subTest(new=new):
                self.write(AL, original.replace(old, new, 1))
                self.assertCodes({C, A})
        self.write(AL, original.replace("closed_universe = true", "closed_universe = true\nunsafe_everything_allowed = true"))
        self.assertCodes({C, A})
        # A duplicated table is a TOML error: the whole allowlist is unusable, so no producer table resolves.
        self.write(AL, original + "\n[policy]\nclosed_universe = false\n")
        self.assertCodes({C, A, T})

    def test_allowlist_non_semantic_byte_change_is_pinned(self) -> None:
        """Even a comment change needs a reviewed pin update (byte-exact allowlist pin)."""
        self.write(AL, self.text(AL) + "# harmless comment\n")
        self.assertCodes({A})

    def test_in_house_globs_and_lab_membership(self) -> None:
        """The '*' glob, oracle names in [in_house], and dropped oracle memberships all fail."""
        original = self.text(AL)
        cases = {
            "star glob": original.replace('"asupersync",\n', '"asupersync", "*",\n', 1),
            "lib* glob": original.replace('"asupersync",\n', '"asupersync", "lib*",\n', 1),
            "interior glob": original.replace('"ft-*",', '"f*t",', 1),
            "ffmpeg in in_house": original.replace('"asupersync",\n', '"asupersync", "ffmpeg",\n', 1),
            "pytorch in in_house": original.replace('"asupersync",\n', '"asupersync", "pytorch",\n', 1),
            "drop ffmpeg": original.replace('"ffmpeg", "ffprobe", "networkx"', '"ffprobe", "networkx"', 1),
            "drop pytorch": original.replace('"networkx", "pytorch",', '"networkx",', 1),
            "drop opencv": original.replace('"onnxruntime", "opencv",\n', '"onnxruntime",\n', 1),
            "oracle double row": original.replace('"DEP-ORACLE-001" = ["networkx", "pytorch"]', '"DEP-ORACLE-001" = ["networkx", "pytorch", "ffmpeg"]', 1),
            "fundamental adds libc": original.replace('allowed_subject_to_audit = ["serde", "serde_json"]', 'allowed_subject_to_audit = ["serde", "serde_json", "tokio"]', 1),
            "empty forbidden": original.replace('"pyo3", "opencv", "ffmpeg-next", "gstreamer", "ort", "tch"\n]', ']', 1).replace('crates = [\n  "tokio", "async-std", "smol", "glommio", "monoio", "rayon",\n  "reqwest", "hyper", "rusqlite", "sqlx", "diesel", "rocksdb",\n  ]', "crates = []", 1),
            "exception also fundamental": original.replace('"blake3", "thiserror"', '"blake3", "serde", "thiserror"', 1),
            "pending crate not fundamental": original.replace('allowed_subject_to_audit = ["serde", "serde_json"]', 'allowed_subject_to_audit = ["serde_json"]', 1),
            "pending row wrong": original.replace('registry_row = "DEP-FUND-001"', 'registry_row = "DEP-LAB-001"', 1),
            "pending id not tracker": original.replace("[pending_owner_decisions.fss-ndxis]", "[pending_owner_decisions.someday]", 1),
        }
        for label, tampered in cases.items():
            with self.subTest(label):
                self.assertNotEqual(tampered, original, label)
                self.write(AL, tampered)
                self.assertCodes({I, A})
        # An interior glob mapped consistently in both lists is refused by the glob syntax rule alone.
        consistent = original.replace('"frankentorch", "ft-*",', '"frankentorch", "ft*core",', 1).replace('frankentorch = ["frankentorch", "ft-*"]', 'frankentorch = ["frankentorch", "ft*core"]', 1)
        self.write(AL, consistent)
        result = self.assertCodes({I, A})
        self.assertEqual([e.message for e in result.errors if e.code == I], ["in-house family entry 'ft*core' is not a crate name or a single trailing-'*' prefix glob; a bare or interior glob would admit unrelated crates"])
        # An oracle listed but assigned to no F4 row is refused by the row-split rule alone (N12).
        unassigned = original.replace('"cuda-frameworks", "vendor-sdk"', '"cuda-frameworks", "new-oracle", "vendor-sdk"', 1)
        self.assertNotEqual(unassigned, original)
        self.write(AL, unassigned)
        result = self.assertCodes({I, A})
        self.assertEqual([e.message for e in result.errors if e.code == I], ["laboratory oracle 'new-oracle' is not assigned to a DEP-CLASS-F4 registry row"])
        # An oracle admitted as an in-house family, even with a project mapping, is refused by the
        # cross-table rule alone (N13).
        mapped = original.replace('"eidetic_engine_cli", "ee-*",', '"eidetic_engine_cli", "ee-*", "ffmpeg",', 1).replace('eidetic_engine_cli = ["eidetic_engine_cli", "ee-*"]', 'eidetic_engine_cli = ["eidetic_engine_cli", "ee-*", "ffmpeg"]', 1)
        self.assertNotEqual(mapped, original)
        self.write(AL, mapped)
        result = self.assertCodes({I, A})
        self.assertEqual([e.message for e in result.errors if e.code == I], ["in-house family 'ffmpeg' also admits 'ffmpeg', which [laboratory_oracles] classifies differently"])

    def test_serde_is_neutral_in_the_registry(self) -> None:
        """fss-ndxis stays open: serde is neither admitted nor forbidden, and the registry reports it as pending."""
        result = self.assertCodes(set())
        self.assertEqual(result.report["pendingOwnerDecisions"], {
            "fss-ndxis": {"registry_row": "DEP-FUND-001", "crates": ["serde", "serde_json"], "question": dependency_authority.live_authority().allowlist["pending_owner_decisions"]["fss-ndxis"]["question"]},
        })
        view = dependency_authority.build_class_view(dependency_authority.load_authority(self.tmp_root))
        for crate in ("serde", "serde_json", "serde-json"):
            outcome = dependency_authority.classify_package(crate, view, is_production=True, is_member=False, admitted_projects=frozenset())
            self.assertEqual((outcome.kind, outcome.row, outcome.decision), ("pending", "DEP-FUND-001", "fss-ndxis"))
            outcome = dependency_authority.classify_package(crate, view, is_production=False, is_member=False, admitted_projects=frozenset())
            self.assertEqual(outcome.kind, "pending")

    def test_trace_links_resolve(self) -> None:
        """Owner, producers, consumers, ContractBasis and registered codes must resolve (TRACE-UNRESOLVED)."""
        original = self.load()
        mutations = {
            "owner missing": lambda d: self.row(d, "DEP-OWNED-001").update(owner="scripts/nope.py"),
            "owner unrelated": lambda d: self.row(d, "DEP-OWNED-001").update(owner="architecture/local_qualification.toml"),
            "producer file missing": lambda d: self.row(d, "DEP-OWNED-001")["producers"].append("architecture/nope.json"),
            "producer path traversal": lambda d: self.row(d, "DEP-OWNED-001")["producers"].append("../etc/passwd"),
            "consumer missing": lambda d: self.row(d, "DEP-LAB-001")["consumers"].append("scripts/nope.py"),
            "consumer unrelated": lambda d: self.row(d, "DEP-LAB-001")["consumers"].append("architecture/local_qualification.toml"),
            "contract basis unresolved": lambda d: d.update(contractBasis="fss.agent_contract_basis.v9"),
        }
        for label, mutate in mutations.items():
            with self.subTest(label):
                data = copy.deepcopy(original)
                mutate(data)
                self.save(data, redigest=True)
                self.assertCodes({T, F, R})
        self.save(original)
        self.replace("registries/ERRORS.md", "| `ERR-DEP-TOMBSTONE-INVALID-001` |", "| `ERR-DEP-TOMBSTONE-INVALID-999` |")
        self.assertCodes({T})

    def test_classification_producer_tables_are_crosswalked(self) -> None:
        """A row producing a non-classifying table, or an F2 row without the import-gate producer, fails."""
        original = self.load()
        for label, mutate in {
            "forbidden as producer": lambda d: self.row(d, "DEP-EXCEPTION-001")["producers"].append("architecture/dependency_allowlist.toml#forbidden"),
            "F2 row without gate registry": lambda d: self.row(d, "DEP-OWNED-001")["producers"].remove("architecture/franken_imports.json"),
            "fundamental double-produced": lambda d: self.row(d, "DEP-EXCEPTION-001")["producers"].append("architecture/dependency_allowlist.toml#fundamental"),
            "row mapped to F0": lambda d: self.row(d, "DEP-OWNED-001").update(constitutionClass="DEP-CLASS-F0"),
            "F3 row with plain Production": lambda d: self.row(d, "DEP-FUND-001").update(scope="Production"),
            "unknown scope vocabulary": lambda d: self.row(d, "DEP-OWNED-001").update(scope="production"),
            "policy path mismatch": lambda d: d.update(policy="architecture/other.toml"),
            "constitution path mismatch": lambda d: d.update(constitution="architecture/other.json"),
        }.items():
            with self.subTest(label):
                data = copy.deepcopy(original)
                mutate(data)
                self.save(data, redigest=True)
                expected = {I, F, R}
                if label == "forbidden as producer":
                    expected = {I, F, R}
                self.assertCodes(expected)

    def test_tombstone_and_supersession_path(self) -> None:
        """A real supersession passes; odd or inconsistent retirement records are TOMBSTONE-INVALID."""
        data = self.load()
        successor = copy.deepcopy(self.row(data, "DEP-EXCEPTION-001"))
        successor["id"] = "DEP-EXCEPTION-002"
        retired = self.row(data, "DEP-EXCEPTION-001")
        retired.update(status="superseded", supersededBy="DEP-EXCEPTION-002", tombstoneDecision="ADR-0012 compatibility decision and consumer audit")
        data["dependencies"].append(successor)
        data["freezeDigest"] = compute_canonical_dependencies_digest(data)
        self.save(data)
        self.write(MD, render_dependencies_markdown(data))
        resolutions = self.load(TS)
        resolutions["resolutions"].append({"legacyId": "DEP-EXCEPTION-001", "canonicalId": "DEP-EXCEPTION-002", "status": "superseded", "disposition": "superseded"})
        self.save(resolutions, TS)
        pins = {BASELINE_DEPENDENCIES_GENERATION: data["freezeDigest"]}
        with mock.patch.dict(dependency_authority.EXPECTED_DEPENDENCIES_DIGESTS, pins, clear=True):
            self.assertCodes(set())
            meta = resolve_dependency_row_metadata("DEP-EXCEPTION-001", repo_root=self.tmp_root)
            self.assertEqual((meta["canonicalId"], meta["isTombstoned"], meta["status"]), ("DEP-EXCEPTION-002", True, "superseded"))
            odd = {
                "resolution names another successor": {"legacyId": "DEP-EXCEPTION-001", "canonicalId": "DEP-OWNED-001", "status": "superseded", "disposition": "superseded"},
                "uppercase status": {"legacyId": "DEP-EXCEPTION-001", "canonicalId": "DEP-EXCEPTION-002", "status": "SUPERSEDED"},
                "unknown status": {"legacyId": "DEP-EXCEPTION-001", "canonicalId": "DEP-EXCEPTION-002", "status": "retired"},
                "contradictory status/disposition": {"legacyId": "DEP-EXCEPTION-001", "canonicalId": "DEP-EXCEPTION-002", "status": "active", "disposition": "tombstoned"},
                "non-string status": {"legacyId": "DEP-EXCEPTION-001", "canonicalId": "DEP-EXCEPTION-002", "status": 1},
                "lowercase legacy id": {"legacyId": "dep-exception-001", "canonicalId": "DEP-EXCEPTION-002", "status": "superseded"},
            }
            base_resolutions = copy.deepcopy(resolutions)
            for label, entry in odd.items():
                with self.subTest(label):
                    rs = copy.deepcopy(base_resolutions)
                    rs["resolutions"][-1] = entry
                    self.save(rs, TS)
                    self.assertCodes({X})
            rs = copy.deepcopy(base_resolutions)
            rs["resolutions"].pop()
            self.save(rs, TS)
            self.assertCodes({X})
            rs["resolutions"] = [1, "x", None]
            self.save(rs, TS)
            self.assertCodes({C, X})
            self.save(base_resolutions, TS)
            for label, change in {
                "successor unknown": {"supersededBy": "DEP-EXCEPTION-777"},
                "successor self": {"supersededBy": "DEP-EXCEPTION-001"},
                "no decision": {"tombstoneDecision": None},
                "active with successor": {"status": "active"},
                "unknown status": {"status": "retired"},
            }.items():
                with self.subTest(label):
                    d2 = copy.deepcopy(data)
                    self.row(d2, "DEP-EXCEPTION-001").update(change)
                    d2["freezeDigest"] = compute_canonical_dependencies_digest(d2)
                    self.save(d2)
                    self.write(MD, render_dependencies_markdown(d2))
                    with mock.patch.dict(dependency_authority.EXPECTED_DEPENDENCIES_DIGESTS, {BASELINE_DEPENDENCIES_GENERATION: d2["freezeDigest"]}, clear=True):
                        result = self.check()
                    self.assertIn(X, codes(result), label)
                    self.assertTrue(codes(result) <= {X, S, I}, (label, codes(result)))
                    if label in ("successor unknown", "successor self"):
                        self.assertIn("#/DEP-EXCEPTION-001/supersededBy", [e.target for e in result.errors if e.code == X], label)

    def test_type_confusion_inputs_never_raise(self) -> None:
        """Every traceback input from the review notes becomes a registered finding (never an exception)."""
        registered = set(dependency_registry_checker.REGISTRY_CHECKER_ERROR_CODES)
        payloads = {
            DJ: ['{"generation": ["x"]}', '{"dependencies": {"a": 1}}', '{"dependencies": [1]}', '{"dependencies": [null]}',
                 '{"a": NaN}', "[" * 100000, '{"dependencies": [{"id": 5}]}', '{"dependencies": [{"id": "DEP-OWNED-001", "producers": "x", "consumers": {}}]}'],
            CJ: ['{"classes": "x"}', '{"classes": [1, null]}', '{"production": []}', '{"releaseEvidence": 5}', "{" * 100000],
            TS: ['{"resolutions": "x"}', '[]', '{"resolutions": [{"legacyId": ["DEP-OWNED-001"], "status": "tombstoned"}]}'],
            IMPORTS: ['{"imports": [{"project": 5}]}', '{"imports": "x"}'],
        }
        for rel, bodies in payloads.items():
            for body in bodies:
                with self.subTest(rel=rel, body=body[:40]):
                    self.write(rel, body)
                    result = self.check()
                    self.assertFalse(result.passed)
                    self.assertTrue(codes(result) <= registered, codes(result))
                shutil.copy2(ROOT / rel, self.path(rel))
        for body in ("[policy]\nclosed_universe = true\n" * 2, "x = [", "\xff"):
            with self.subTest(allowlist=body[:20]):
                self.path(AL).write_bytes(body.encode("utf-8", "surrogateescape") if body != "\xff" else b"\xff")
                result = self.check()
                self.assertFalse(result.passed)
                self.assertTrue(codes(result) <= registered)

    def test_parse_dependencies_markdown_round_trip(self) -> None:
        """The rendered mirror parses back to the JSON rows exactly (canonical parse/serialize)."""
        data = json.loads((ROOT / DJ).read_text(encoding="utf-8"))
        rendered = render_dependencies_markdown(data)
        self.assertEqual(rendered, (ROOT / MD).read_text(encoding="utf-8"))
        meta, rows, problems = parse_dependencies_markdown(rendered)
        self.assertEqual(problems, [])
        self.assertEqual(rows, data["dependencies"])
        self.assertEqual(meta, {k: data[k] for k in dependency_registry_checker.META_FIELDS})


class TestDependencyClassification(unittest.TestCase):
    """dependency_audit classifies packages into registry rows from the authority and reports consumers."""

    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name)

    def tearDown(self) -> None:
        self.tmp.cleanup()

    def imports_with(self, project: str, status: str) -> None:
        data = json.loads((ROOT / IMPORTS).read_text(encoding="utf-8"))
        for row in data["imports"]:
            if row["project"] == project:
                row["status"] = status
                break
        (self.root / "architecture").mkdir(exist_ok=True)
        (self.root / IMPORTS).write_text(json.dumps(data, indent=2), encoding="utf-8")

    def lock(self, packages: list[dict[str, Any]]) -> None:
        lines = ["version = 4", ""]
        for pkg in packages:
            lines.append("[[package]]")
            for key in ("name", "version", "source"):
                if key in pkg:
                    lines.append(f'{key} = "{pkg[key]}"')
            if pkg.get("dependencies"):
                lines.append("dependencies = [" + ", ".join(f'"{d}"' for d in pkg["dependencies"]) + "]")
            lines.append("")
        (self.root / "Cargo.lock").write_text("\n".join(lines), encoding="utf-8")

    @staticmethod
    def found(findings: list[Any]) -> set[tuple[str, str]]:
        return {(f.code, f.params.get("package", f.path)) for f in findings}

    # Restored test (e4ec37f): owned classification
    def test_classify_owned_crates(self) -> None:
        """Members and admitted in-house families map to DEP-OWNED-001; the gate is keyed by project."""
        policy = {
            "in_house": {"allowed_families": ["asupersync", "frankensqlite", "fsqlite-*", "fss-*"]},
            "fundamental": {"allowed_subject_to_audit": ["serde"]},
            "laboratory_oracles": {"excluded_from_production_release_closure": ["opencv"]},
            "exception_candidates": {"not_admitted_without_dep_record_adr_and_release_evidence": ["blake3"]},
            "forbidden": {"crates": ["tokio"]},
        }
        members = {"fss-core", "fss-cli", "fss-ledger"}
        admitted = {"asupersync", "frankensqlite"}
        for crate_name in ("fss-core", "fss-cli", "fss-ledger", "asupersync", "frankensqlite", "fsqlite-wal"):
            self.assertEqual(
                dependency_audit.classify_dependency_package(crate_name, policy, members, is_production=True, admitted_in_house=admitted),
                ("DEP-OWNED-001", None, None),
                crate_name,
            )
        for crate_name in ("asupersync", "fsqlite-wal"):
            dep_id, code, reason = dependency_audit.classify_dependency_package(crate_name, policy, members, is_production=True, admitted_in_house=set())
            self.assertEqual((dep_id, code), ("DEP-OWNED-001", "DEP-AUD-043"))
            self.assertIn("lacks per-mechanism import gate", reason)

    # Restored test (e4ec37f): unclassified crate (M-042)
    def test_unclassified_crate_rejected(self) -> None:
        """An unrecognized external crate fails with exactly one DEP-AUD-042 finding."""
        policy = {
            "in_house": {"allowed_families": ["fss-*"]},
            "fundamental": {"allowed_subject_to_audit": []},
            "laboratory_oracles": {"excluded_from_production_release_closure": []},
            "exception_candidates": {"not_admitted_without_dep_record_adr_and_release_evidence": []},
            "forbidden": {"crates": []},
        }
        findings: list[dependency_audit.Finding] = []
        dependency_audit.audit_dependency_classes(findings, ROOT, policy, {"fss-core"}, [{"name": "totally-unrecognized-crate", "version": "1.0.0"}])
        self.assertEqual([(f.code, f.severity) for f in findings], [("DEP-AUD-042", "error")])
        self.assertIn("totally-unrecognized-crate", findings[0].message)

    # Restored test (e4ec37f), strengthened: consumers are members that depend on an admitted package.
    def test_census_counts_owned_consumers(self) -> None:
        """Nine members consuming an admitted Franken package give consumerCount 9 with no findings.

        Strengthened: e4ec37f counted the members themselves as consumers (the M-census defect found in
        round 3). The same numbers now come from real consumer edges, and the members-only input reports
        the members as memberPackages with consumerCount 0.
        """
        members = {"fss-cli", "fss-core", "fss-ledger", "fss-model-ir", "fss-object", "fss-packet", "fss-publication", "fss-reference", "fss-tensor"}
        self.imports_with("asupersync", "production-admitted")
        self.lock([{"name": m, "version": "0.0.1", "dependencies": ["asupersync"]} for m in sorted(members)] + [{"name": "asupersync", "version": "0.3.0", "source": "registry+https://example.invalid/index"}])
        direct = [{"manifest": f"crates/{m}/Cargo.toml", "section": "dependencies", "name": "asupersync"} for m in sorted(members)]
        findings: list[dependency_audit.Finding] = []
        res = dependency_audit.audit_dependency_classes(findings, self.root, {"in_house": {"allowed_families": ["asupersync"]}}, members, [], direct=direct)
        self.assertEqual(findings, [])
        owned = res["census"]["DEP-OWNED-001"]
        self.assertEqual(owned["consumerCount"], 9)
        self.assertEqual(owned["packages"], ["asupersync"])
        self.assertEqual(owned["memberPackages"], sorted(members))
        self.assertTrue(owned["hasRealConsumer"])
        self.assertIsNone(owned["drift"])

        findings = []
        res = dependency_audit.audit_dependency_classes(findings, ROOT, {"in_house": {"allowed_families": ["fss-*"]}}, members, [{"name": m, "version": "0.0.1"} for m in members])
        self.assertEqual(findings, [])
        owned = res["census"]["DEP-OWNED-001"]
        self.assertEqual((owned["consumerCount"], owned["packages"], owned["memberPackages"]), (0, [], sorted(members)))
        self.assertTrue(owned["hasRealConsumer"])

    # Restored test (e4ec37f): unconsumed rows drift
    def test_unconsumed_rows_drift_reported(self) -> None:
        """Unconsumed rows return explicit drift explanations derived from the registry scope and decisions."""
        findings: list[dependency_audit.Finding] = []
        res = dependency_audit.audit_dependency_classes(findings, ROOT, {"in_house": {"allowed_families": ["fss-*"]}}, {"fss-core"}, [{"name": "fss-core", "version": "0.0.1"}])
        census = res["census"]
        self.assertEqual(list(census), ["DEP-OWNED-001", "DEP-FUND-001", "DEP-LAB-001", "DEP-ORACLE-001", "DEP-EXCEPTION-001"])
        for dep_id in ("DEP-FUND-001", "DEP-LAB-001", "DEP-ORACLE-001", "DEP-EXCEPTION-001"):
            self.assertEqual(census[dep_id]["consumerCount"], 0)
            self.assertFalse(census[dep_id]["hasRealConsumer"])
            self.assertIsNotNone(census[dep_id]["drift"])
            self.assertIn("no real consumer", census[dep_id]["drift"])
        self.assertIn("pending owner decision fss-ndxis", census["DEP-FUND-001"]["drift"])
        self.assertIn("'Not admitted'", census["DEP-EXCEPTION-001"]["drift"])
        self.assertEqual([u["id"] for u in res["unconsumed"]], ["DEP-FUND-001", "DEP-LAB-001", "DEP-ORACLE-001", "DEP-EXCEPTION-001"])

    # Restored test (e4ec37f): DEP-AUD-044 (M-044)
    def test_warn_unconsumed_emits_warning(self) -> None:
        """warn_unconsumed=True emits exactly one DEP-AUD-044 warning per unconsumed row, and none otherwise."""
        findings: list[dependency_audit.Finding] = []
        dependency_audit.audit_dependency_classes(findings, ROOT, {"in_house": {"allowed_families": ["fss-*"]}}, {"fss-core"}, [{"name": "fss-core", "version": "0.0.1"}], warn_unconsumed=True)
        self.assertEqual(sorted((f.code, f.severity, f.params["class"]) for f in findings), [
            ("DEP-AUD-044", "warning", "DEP-EXCEPTION-001"),
            ("DEP-AUD-044", "warning", "DEP-FUND-001"),
            ("DEP-AUD-044", "warning", "DEP-LAB-001"),
            ("DEP-AUD-044", "warning", "DEP-ORACLE-001"),
        ])
        findings = []
        dependency_audit.audit_dependency_classes(findings, ROOT, {"in_house": {"allowed_families": ["fss-*"]}}, {"fss-core"}, [{"name": "fss-core", "version": "0.0.1"}])
        self.assertEqual(findings, [])

    # Mutant M12: serde neutral pending fss-ndxis, driven by the allowlist
    def test_mutant_m12_serde_pending_fss_ndxis(self) -> None:
        """serde/serde_json are refused as pending fss-ndxis (DEP-AUD-047): never admitted, never silently rejected.

        DEP-AUD-045 keeps its original warning meaning (round-2 review d); the refusal is the new DEP-AUD-047.
        """
        policy = {"in_house": {"allowed_families": ["fss-*"]}, "fundamental": {"allowed_subject_to_audit": ["serde", "serde_json"]}, "forbidden": {"crates": []}}
        for serde_pkg in ("serde", "serde_json"):
            for production in (True, False):
                dep_id, code, reason = dependency_audit.classify_dependency_package(serde_pkg, policy, {"fss-core"}, is_production=production)
                self.assertEqual((dep_id, code), ("DEP-FUND-001", "DEP-AUD-047"))
                self.assertIn("pending owner decision fss-ndxis", reason)
                self.assertIn("neither admitted nor rejected", reason)
        # The allowlist, not code, decides: an explicit empty pending table admits the fundamental crate,
        # and a crate added to [fundamental] is not labelled pending.
        explicit = dict(policy, pending_owner_decisions={})
        self.assertEqual(dependency_audit.classify_dependency_package("serde", explicit, {"fss-core"}), ("DEP-FUND-001", None, None))
        other = dict(policy, fundamental={"allowed_subject_to_audit": ["serde", "serde_json", "bytes"]})
        self.assertEqual(dependency_audit.classify_dependency_package("bytes", other, {"fss-core"}), ("DEP-FUND-001", None, None))
        removed = dict(policy, fundamental={"allowed_subject_to_audit": []}, pending_owner_decisions={})
        self.assertEqual(dependency_audit.classify_dependency_package("serde", removed, {"fss-core"})[1], "DEP-AUD-042")

    def test_serde_consistent_across_mechanisms(self) -> None:
        """enumerate, classify, DEP-AUD-023 and the census all report serde as pending fss-ndxis."""
        (self.root / "architecture").mkdir()
        shutil.copy2(ROOT / AL, self.root / AL)
        (self.root / "rust-toolchain.toml").write_text('[toolchain]\nchannel = "nightly-2026-08-31"\n', encoding="utf-8")
        (self.root / "Cargo.toml").write_text('[workspace]\nresolver = "3"\nmembers = ["crates/fss-a"]\n\n[workspace.lints.rust]\nunsafe_code = "forbid"\n', encoding="utf-8")
        crate = self.root / "crates" / "fss-a"
        (crate / "src").mkdir(parents=True)
        (crate / "Cargo.toml").write_text('[package]\nname = "fss-a"\nversion = "0.0.1"\nedition = "2024"\n\n[dependencies]\nserde = { version = "1", default-features = false }\n', encoding="utf-8")
        (crate / "src" / "lib.rs").write_text("#![forbid(unsafe_code)]\npub fn ok() {}\n", encoding="utf-8")
        self.lock([{"name": "fss-a", "version": "0.0.1", "dependencies": ["serde"]}, {"name": "serde", "version": "1.0.0", "source": "registry+https://example.invalid/index"}])
        report, rc = dependency_audit.audit_workspace(self.root, self.root / AL)
        self.assertEqual(rc, 1)
        # (the pre-existing serde audit scans Cargo.lock in both of its passes, so the set is compared)
        serde_findings = sorted({(f["code"], f["path"]) for f in report["findings"] if f.get("params", {}).get("package") == "serde"})
        self.assertEqual(serde_findings, [
            ("DEP-AUD-023", "Cargo.lock"),
            ("DEP-AUD-023", "crates/fss-a/Cargo.toml"),
            ("DEP-AUD-045", "Cargo.lock"),
            ("DEP-AUD-045", "crates/fss-a/Cargo.toml"),
            ("DEP-AUD-047", "Cargo.lock"),
            ("DEP-AUD-047", "crates/fss-a/Cargo.toml"),
        ])
        severities = {(f["code"], f["severity"]) for f in report["findings"] if f.get("params", {}).get("package") == "serde"}
        self.assertEqual(severities, {("DEP-AUD-023", "error"), ("DEP-AUD-045", "warning"), ("DEP-AUD-047", "error")})
        for f in report["findings"]:
            if f.get("params", {}).get("package") == "serde":
                self.assertIn("pending owner decision fss-ndxis", f["message"])
        self.assertNotIn("DEP-AUD-016", {f["code"] for f in report["findings"]})
        self.assertNotIn("DEP-AUD-042", {f["code"] for f in report["findings"]})
        direct = [row for row in report["directDependencies"] if row["name"] == "serde"]
        self.assertEqual([row["admissionStatus"] for row in direct], ["pending_owner_decision"])
        fund = report["dependencyClassCensus"]["DEP-FUND-001"]
        self.assertEqual((fund["packages"], fund["pendingPackages"], fund["consumerCount"], fund["hasRealConsumer"]), ([], ["serde"], 0, False))
        self.assertIn("pending owner decision fss-ndxis", fund["drift"])

    # Mutant M13: lab/oracle quarantine
    def test_mutant_m13_lab_oracle_quarantine(self) -> None:
        """Oracles are DEP-AUD-043 when production-reachable and admitted to their F4 row in dev-only lanes."""
        policy = {
            "in_house": {"allowed_families": ["fss-*"]},
            "fundamental": {"allowed_subject_to_audit": []},
            "laboratory_oracles": {"excluded_from_production_release_closure": ["opencv", "ffmpeg", "pytorch"]},
            "forbidden": {"crates": []},
        }
        for name, row in (("opencv", "DEP-LAB-001"), ("ffmpeg", "DEP-LAB-001"), ("pytorch", "DEP-ORACLE-001")):
            dep_id, code, reason = dependency_audit.classify_dependency_package(name, policy, {"fss-core"}, is_production=True)
            self.assertEqual((dep_id, code), (row, "DEP-AUD-043"))
            self.assertIn("reachable from production", reason)
            self.assertEqual(dependency_audit.classify_dependency_package(name, policy, {"fss-core"}, is_production=False), (row, None, None))
        # A forbidden crate that is also a lab oracle stays refused in production and is lab-only otherwise.
        live = dependency_audit.load_toml(ROOT / AL)
        self.assertEqual(dependency_audit.classify_dependency_package("opencv", live, set(), is_production=True)[1], "DEP-AUD-030")
        self.assertEqual(dependency_audit.classify_dependency_package("opencv", live, set(), is_production=False), ("DEP-LAB-001", None, None))
        self.assertEqual(dependency_audit.classify_dependency_package("tokio", live, set(), is_production=False)[1], "DEP-AUD-043")

    # Mutant M10: production reachability over the Cargo.lock graph
    def test_mutant_m10_production_reachability(self) -> None:
        """A dev-only oracle is admitted; the same oracle pulled transitively from [dependencies] is DEP-AUD-043."""
        policy = {"in_house": {"allowed_families": ["fss-*"]}, "fundamental": {"allowed_subject_to_audit": []}, "laboratory_oracles": {"excluded_from_production_release_closure": ["ffmpeg"]}, "forbidden": {"crates": []}}
        shutil.copytree(ROOT / "architecture", self.root / "architecture", dirs_exist_ok=True)
        self.lock([{"name": "ffmpeg", "version": "4.4.0", "source": "registry+https://example.invalid/index"}])
        findings: list[dependency_audit.Finding] = []
        direct = [{"manifest": "crates/fss-core/Cargo.toml", "section": "dev-dependencies", "name": "ffmpeg"}]
        dependency_audit.audit_dependency_classes(findings, self.root, policy, {"fss-core"}, [{"name": "ffmpeg", "version": "4.4.0"}], direct=direct)
        self.assertEqual([f.code for f in findings], [])
        self.lock([
            {"name": "fss-core", "version": "0.0.1", "dependencies": ["media-wrapper", "ffmpeg"]},
            {"name": "media-wrapper", "version": "1.0.0", "source": "registry+https://example.invalid/index", "dependencies": ["ffmpeg"]},
            {"name": "ffmpeg", "version": "4.4.0", "source": "registry+https://example.invalid/index"},
        ])
        direct = direct + [{"manifest": "crates/fss-core/Cargo.toml", "section": "dependencies", "name": "media-wrapper"}]
        findings = []
        dependency_audit.audit_dependency_classes(findings, self.root, policy, {"fss-core"}, [], direct=direct)
        self.assertEqual(self.found(findings), {("DEP-AUD-042", "media-wrapper"), ("DEP-AUD-043", "ffmpeg")})
        findings = []
        direct = [{"manifest": "crates/fss-core/Cargo.toml", "section": "target.'cfg(unix)'.build-dependencies", "name": "ffmpeg"}]
        dependency_audit.audit_dependency_classes(findings, self.root, policy, {"fss-core"}, [], direct=direct)
        # media-wrapper is no longer a production root but is still an unclassified locked package.
        self.assertEqual(self.found(findings), {("DEP-AUD-042", "media-wrapper"), ("DEP-AUD-043", "ffmpeg")})
        production = [f for f in findings if f.code == "DEP-AUD-043"]
        self.assertTrue(all(f.params["production"] for f in production))

    # Mutant M11: class audit wired into audit_workspace
    def test_mutant_m11_class_audit_wired_into_audit_workspace(self) -> None:
        """audit_workspace reports the census in registry order and fails on a planted unclassified crate."""
        report, rc = dependency_audit.audit_workspace(ROOT, policy_path=ROOT / AL)
        self.assertEqual(report["schema"], "fss.dependency_audit.v4")
        self.assertEqual(list(report["dependencyClassCensus"]), ["DEP-OWNED-001", "DEP-FUND-001", "DEP-LAB-001", "DEP-ORACLE-001", "DEP-EXCEPTION-001"])
        self.assertEqual(report["dependencyClassCensus"]["DEP-OWNED-001"]["memberPackages"], report["workspaceMembers"])
        self.assertEqual([u["id"] for u in report["unconsumedDependencyClasses"]], ["DEP-FUND-001", "DEP-LAB-001", "DEP-ORACLE-001", "DEP-EXCEPTION-001"])
        (self.root / "architecture").mkdir()
        shutil.copy2(ROOT / AL, self.root / AL)
        (self.root / "rust-toolchain.toml").write_text('[toolchain]\nchannel = "nightly-2026-08-31"\n', encoding="utf-8")
        (self.root / "Cargo.toml").write_text('[workspace]\nresolver = "3"\nmembers = ["crates/fss-a"]\n\n[workspace.lints.rust]\nunsafe_code = "forbid"\n', encoding="utf-8")
        crate = self.root / "crates" / "fss-a"
        (crate / "src").mkdir(parents=True)
        (crate / "Cargo.toml").write_text('[package]\nname = "fss-a"\nversion = "0.0.1"\nedition = "2024"\n', encoding="utf-8")
        (crate / "src" / "lib.rs").write_text("#![forbid(unsafe_code)]\npub fn ok() {}\n", encoding="utf-8")
        self.lock([{"name": "fss-a", "version": "0.0.1"}, {"name": "planted-crate", "version": "1.0.0", "source": "registry+https://example.invalid/index"}])
        report, rc = dependency_audit.audit_workspace(self.root, self.root / AL)
        self.assertEqual(rc, 1)
        self.assertIn(("DEP-AUD-042", "planted-crate"), {(f["code"], f.get("params", {}).get("package")) for f in report["findings"]})

    def test_forbidden_crates_never_exception_candidates(self) -> None:
        """tokio is forbidden and cannot be classified as DEP-EXCEPTION-001, in any lane."""
        policy = {
            "in_house": {"allowed_families": ["fss-*"]},
            "fundamental": {"allowed_subject_to_audit": []},
            "forbidden": {"crates": ["tokio"]},
            "exception_candidates": {"not_admitted_without_dep_record_adr_and_release_evidence": ["tokio"]},
        }
        self.assertEqual(dependency_audit.classify_dependency_package("tokio", policy, {"fss-core"}, is_production=True)[:2], (None, "DEP-AUD-030"))
        self.assertEqual(dependency_audit.classify_dependency_package("tokio", policy, {"fss-core"}, is_production=False)[:2], (None, "DEP-AUD-043"))

    # Mutant M-gate: in-house gate keyed by franken_imports project and status
    def test_mutant_m_gate_in_house_import_gate(self) -> None:
        """The gate maps crates to projects from the allowlist and admits only production-admitted imports."""
        policy = {"in_house": {"allowed_families": ["ft-*", "fsqlite-*", "asupersync*"]}, "fundamental": {"allowed_subject_to_audit": []}, "forbidden": {"crates": []}}
        self.assertEqual(dependency_audit.classify_dependency_package("ft-kernel", policy, {"fss-core"}, admitted_in_house=None)[1], "DEP-AUD-043")
        self.assertEqual(dependency_audit.classify_dependency_package("ft-kernel", policy, {"fss-core"}, admitted_in_house={"frankensqlite"})[1], "DEP-AUD-043")
        self.assertEqual(dependency_audit.classify_dependency_package("ft-kernel", policy, {"fss-core"}, admitted_in_house={"frankentorch"}), ("DEP-OWNED-001", None, None))
        dep_id, code, reason = dependency_audit.classify_dependency_package("asupersync-extra", policy, {"fss-core"}, admitted_in_house={"asupersync"})
        self.assertEqual(code, "DEP-AUD-043")
        self.assertIn("no unique franken_imports project mapping", reason)
        for status, expected in (("censused", "DEP-AUD-043"), ("performance-measured", "DEP-AUD-043"), ("production-admitted", None)):
            with self.subTest(status=status):
                self.imports_with("frankentorch", status)
                gates, problems = dependency_audit.load_import_gates(self.root)
                self.assertEqual(problems, [])
                self.assertEqual(dependency_audit.classify_dependency_package("ft-core", policy, set(), admitted_in_house=gates)[1], expected)
                self.assertEqual(dependency_audit.classify_dependency_package("frankentorch", {"in_house": {"allowed_families": ["frankentorch"]}}, set(), admitted_in_house=gates)[1], expected)
        self.imports_with("frankentorch", "rejected")
        gates, problems = dependency_audit.load_import_gates(self.root)
        self.assertIsNone(gates)
        self.assertTrue(any("status 'rejected'" in p for p in problems))

    # Mutant M-census: member identity and no member inflation
    def test_mutant_m_census_consumer_count_without_member_inflation(self) -> None:
        """Sibling member edges never count as consumers; members are identified by path source, not name."""
        policy = {"in_house": {"allowed_families": ["fss-*"]}, "fundamental": {"allowed_subject_to_audit": []}, "forbidden": {"crates": []}}
        findings: list[dependency_audit.Finding] = []
        res = dependency_audit.audit_dependency_classes(findings, ROOT, policy, {"fss-cli", "fss-core"}, [{"name": "fss-cli", "version": "0.0.1"}, {"name": "fss-core", "version": "0.0.1"}], direct=[{"manifest": "crates/fss-cli/Cargo.toml", "section": "dependencies", "name": "fss-core"}])
        self.assertEqual(findings, [])
        self.assertEqual(res["census"]["DEP-OWNED-001"]["consumerCount"], 0)
        # A path edge to a member counts for nothing even when an admitted registry crate shares its name;
        # a registry edge to that crate is a real consumer.
        self.imports_with("asupersync", "production-admitted")
        self.lock([{"name": "fss-cli", "version": "0.0.1"}, {"name": "asupersync", "version": "0.0.1"}, {"name": "asupersync", "version": "0.3.0", "source": "registry+https://example.invalid/index"}])
        for kind, count in (("path", 0), ("registry", 1)):
            with self.subTest(kind=kind):
                findings = []
                res = dependency_audit.audit_dependency_classes(findings, self.root, {"in_house": {"allowed_families": ["asupersync"]}}, {"fss-cli", "asupersync"}, [], direct=[{"manifest": "crates/fss-cli/Cargo.toml", "section": "dependencies", "name": "asupersync", "kind": kind}])
                self.assertEqual(findings, [])
                owned = res["census"]["DEP-OWNED-001"]
                self.assertEqual((owned["consumerCount"], owned["packages"], owned["memberPackages"]), (count, ["asupersync"], ["asupersync", "fss-cli"]))
        shutil.copytree(ROOT / "architecture", self.root / "architecture", dirs_exist_ok=True)
        self.lock([
            {"name": "fss-core", "version": "0.0.1"},
            {"name": "fss-core", "version": "9.9.9", "source": "registry+https://example.invalid/index"},
            {"name": "tokio", "version": "1.0.0", "source": "registry+https://example.invalid/index"},
        ])
        findings = []
        res = dependency_audit.audit_dependency_classes(findings, self.root, dependency_audit.load_toml(ROOT / AL), {"fss-core", "tokio"}, [])
        self.assertEqual(self.found(findings), {("DEP-AUD-042", "fss-core"), ("DEP-AUD-030", "tokio")})
        self.assertEqual(res["census"]["DEP-OWNED-001"]["memberPackages"], ["fss-core"])

    # Mutant M-lock: Cargo.lock and franken_imports.json fail closed with registered findings
    def test_mutant_m_lock_validation(self) -> None:
        """Missing, empty, or odd Cargo.lock and corrupt imports fail closed with DEP-AUD-046.

        Code correction: 5291d07 reported these as DEP-AUD-010 ("a declared workspace member manifest is
        missing"); DEP-AUD-046 is the registered census-input failure.
        """
        policy = {"in_house": {"allowed_families": ["fss-*"]}}
        members = {"fss-core"}

        def run() -> list[str]:
            findings: list[dependency_audit.Finding] = []
            dependency_audit.audit_dependency_classes(findings, self.root, policy, members, [])
            return sorted({f.code for f in findings})

        self.assertEqual(run(), ["DEP-AUD-046"])  # missing Cargo.lock
        for body in ("", "   \n", 'package = "invalid"\n', "package = [1, 2]\n", 'version = "4"\n', "version = [\n",
                     '[[package]]\nname = "a"\n', '[[package]]\nname = "a"\nversion = "1"\ndependencies = ["b"]\n',
                     '[[package]]\nname = "a"\nversion = "1"\n\n[[package]]\nname = "a"\nversion = "1"\n',
                     '[[package]]\nname = "a"\nversion = "1"\ndependencies = "b"\n', '[[package]]\nname = "a"\nversion = "1"\nsource = 5\n'):
            with self.subTest(lock=body):
                (self.root / "Cargo.lock").write_text(body, encoding="utf-8")
                self.assertEqual(run(), ["DEP-AUD-046"])
        (self.root / "Cargo.lock").write_text("version = 3\n", encoding="utf-8")
        (self.root / "architecture").mkdir(exist_ok=True)
        for body in ('{"invalid": json}', "", '{"imports": [1]}', '{"schema": "x", "asOf": "x", "imports": [{"project": "a"}]}'):
            with self.subTest(imports=body):
                (self.root / IMPORTS).write_text(body, encoding="utf-8")
                self.assertEqual(run(), ["DEP-AUD-046"])
        (self.root / IMPORTS).unlink()
        self.assertEqual(run(), [])  # fixture roots without their own gate registry use the repository's
        with mock.patch.object(dependency_audit, "ROOT", self.root):
            self.assertEqual(run(), ["DEP-AUD-046"])  # missing everywhere fails closed


def load_check_policy() -> Any:
    import importlib.util
    spec = importlib.util.spec_from_file_location("check_policy_under_test", ROOT / "scripts/check-policy.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def make_workspace(root: Path, manifest_deps: str = "", lock_packages: list[dict[str, Any]] | None = None) -> None:
    (root / "architecture").mkdir(parents=True, exist_ok=True)
    (root / "rust-toolchain.toml").write_text('[toolchain]\nchannel = "nightly-2026-08-31"\n', encoding="utf-8")
    (root / "Cargo.toml").write_text('[workspace]\nresolver = "3"\nmembers = ["crates/fss-a"]\n\n[workspace.lints.rust]\nunsafe_code = "forbid"\n', encoding="utf-8")
    crate = root / "crates" / "fss-a"
    (crate / "src").mkdir(parents=True, exist_ok=True)
    (crate / "Cargo.toml").write_text('[package]\nname = "fss-a"\nversion = "0.0.1"\nedition = "2024"\n' + manifest_deps, encoding="utf-8")
    (crate / "src" / "lib.rs").write_text("#![forbid(unsafe_code)]\npub fn ok() {}\n", encoding="utf-8")
    lines = ["version = 4", ""]
    for pkg in lock_packages or [{"name": "fss-a", "version": "0.0.1"}]:
        lines.append("[[package]]")
        for key in ("name", "version", "source"):
            if key in pkg:
                lines.append(f'{key} = "{pkg[key]}"')
        if pkg.get("dependencies"):
            lines.append("dependencies = [" + ", ".join(f'"{d}"' for d in pkg["dependencies"]) + "]")
        lines.append("")
    (root / "Cargo.lock").write_text("\n".join(lines), encoding="utf-8")


class TestRoundTwoAuthorityHardening(AuthorityCase):
    """Round-2 review of bcc24b5 (fss-x4a.30.88.1): findings a-g."""

    # a) symlinked inputs are refused
    def test_symlinked_authority_inputs_are_refused(self) -> None:
        outside = Path(self.tmp_dir.name).parent / (Path(self.tmp_dir.name).name + "-outside")
        outside.mkdir()
        self.addCleanup(shutil.rmtree, outside, True)
        for rel, expected in ((AL, {C, T}), (IMPORTS, {C, T}), (DJ, {C}), (CJ, {C}), (TS, {C}), ("architecture/local_qualification.toml", {C})):
            with self.subTest(rel=rel):
                target = outside / Path(rel).name
                shutil.copy2(ROOT / rel, target)
                self.path(rel).unlink()
                self.path(rel).symlink_to(target)
                result = self.assertCodes(expected)
                self.assertTrue(any("symbolic link" in e.message for e in result.errors))
                self.path(rel).unlink()
                shutil.copy2(ROOT / rel, self.path(rel))
        self.assertCodes(set())
        # a symlinked directory between the root and the input is refused too
        moved = outside / "architecture"
        shutil.move(str(self.path("architecture")), moved)
        self.path("architecture").symlink_to(moved)
        result = self.assertCodes({C})
        self.assertTrue(all("symbolic link" in e.message for e in result.errors))

    def test_non_regular_inputs_are_refused(self) -> None:
        import os
        import signal
        fifo = self.path("architecture/fifo.json")
        os.mkfifo(fifo)

        def blocked(signum: int, frame: Any) -> None:
            raise AssertionError("read_input_bytes opened a FIFO and blocked; non-regular inputs must be refused before open")

        previous = signal.signal(signal.SIGALRM, blocked)
        signal.alarm(10)  # operational guard: turns a blocking open into a test failure instead of a hang
        try:
            data, problems = dependency_authority.read_input_bytes(fifo, "architecture/fifo.json", self.tmp_root)
        finally:
            signal.alarm(0)
            signal.signal(signal.SIGALRM, previous)
        self.assertIsNone(data)
        self.assertEqual([(e.code, "not a regular file" in e.message) for e in problems], [(C, True)])
        lock = self.tmp_root / "Cargo.lock"
        lock.symlink_to(ROOT / "Cargo.lock")
        graph, problems = dependency_audit.load_lock_graph(self.tmp_root)
        self.assertIsNone(graph)
        self.assertTrue(any("symbolic link" in p for p in problems))

    # b) no plain allowlist/imports reads remain in the audit or check-policy
    def test_audit_and_check_policy_read_the_allowlist_strictly(self) -> None:
        with mock.patch.dict(dependency_authority.EXPECTED_ALLOWLIST_DIGESTS, {"fss.dependency_allowlist.v3": "sha256:" + "0" * 64}):
            report, rc = dependency_audit.audit_workspace(ROOT, ROOT / AL)
        self.assertEqual(rc, 2)
        self.assertIn("ERR-DEP-ALLOWLIST-DIGEST-DIVERGED-001", report["fatal"])
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            make_workspace(root)
            (root / AL).write_text("[policy]\nclosed_universe = true\n[policy]\nclosed_universe = false\n", encoding="utf-8")
            report, rc = dependency_audit.audit_workspace(root, root / AL)
            self.assertEqual(rc, 2)
            self.assertIn("ERR-DEP-CORRUPT-FILE-001", report["fatal"])
            outside = Path(tmp + "-policy.toml")
            self.addCleanup(outside.unlink, True)
            shutil.copy2(ROOT / AL, outside)
            (root / AL).unlink()
            (root / AL).symlink_to(outside)
            report, rc = dependency_audit.audit_workspace(root, root / AL)
            self.assertEqual(rc, 2)
            self.assertIn("symbolic link", report["fatal"])
        check_policy = load_check_policy()
        check_policy.ROOT = self.tmp_root
        check_policy.errors = []
        self.write(IMPORTS, '{"schema": "a", "schema": "b"}')
        self.assertEqual(check_policy.authority_json(IMPORTS), {})
        self.assertEqual(len(check_policy.errors), 1)
        self.assertTrue(check_policy.errors[0].startswith("ERR-DEP-CORRUPT-FILE-001"))

    # c) all 16 flags, production values and components are derived, never tabled
    def test_policy_tables_are_derived_from_the_authority(self) -> None:
        live = dependency_authority.live_authority()
        expected = dependency_authority.expected_policy_flags(live)
        self.assertEqual(set(expected), set(dependency_authority.ALLOWLIST_POLICY_FLAGS))
        self.assertEqual(expected, live.allowlist["policy"])
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            make_workspace(root)
            text = (ROOT / AL).read_text(encoding="utf-8").replace("foreign_executables_allowed_in_production = false\n", "")
            (root / AL).write_text(text, encoding="utf-8")
            report, rc = dependency_audit.audit_workspace(root, root / AL)
            flag_findings = sorted((f["code"], f["params"]["key"]) for f in report["findings"] if f["code"] in ("DEP-AUD-001", "DEP-AUD-002"))
            self.assertEqual(flag_findings, [("DEP-AUD-002", "foreign_executables_allowed_in_production")])
            # Changing the constitution changes the requirement: the audit follows the authority.
            flipped = copy.deepcopy(live)
            flipped.constitution = copy.deepcopy(live.constitution)
            flipped.constitution["production"]["cCppFfi"] = True
            shutil.copy2(ROOT / AL, root / AL)
            with mock.patch.object(dependency_authority, "live_authority", return_value=flipped):
                report, rc = dependency_audit.audit_workspace(root, root / AL)
            flag_findings = sorted((f["code"], f["params"]["key"]) for f in report["findings"] if f["code"] in ("DEP-AUD-001", "DEP-AUD-002"))
            self.assertEqual(flag_findings, [("DEP-AUD-001", "c_or_cpp_ffi_allowed")])
        check_policy = load_check_policy()
        constitution = json.loads((ROOT / CJ).read_text(encoding="utf-8"))
        localq = dependency_authority.load_toml_document(ROOT / "architecture/local_qualification.toml", "lq")[0]
        toolchain = dependency_authority.load_toml_document(ROOT / "rust-toolchain.toml", "tc")[0]["toolchain"]
        policy = dependency_audit.load_toml(ROOT / AL)
        check_policy.errors = []
        check_policy.dependency_policy_consistency(constitution, localq, toolchain, policy, live)
        self.assertEqual(check_policy.errors, [])
        cases = {
            "flag": (constitution, localq, toolchain, dict(policy, policy=dict(policy["policy"], dynamic_loading_allowed=True))),
            "int flag": (constitution, localq, toolchain, dict(policy, policy=dict(policy["policy"], closed_universe=1))),
            "component": (constitution, localq, dict(toolchain, components=["rustfmt", "clippy"]), policy),
            "production": (dict(constitution, production=dict(constitution["production"], closedUniverse=1)), localq, toolchain, policy),
            "production language": (dict(constitution, production=dict(constitution["production"], language="rust-2021")), localq, toolchain, policy),
        }
        for label, args in cases.items():
            with self.subTest(label):
                check_policy.errors = []
                check_policy.dependency_policy_consistency(*args, live)
                self.assertEqual(len(check_policy.errors), 1, check_policy.errors)
        # The registered components, not a list in check-policy, decide: a different registration passes.
        check_policy.errors = []
        narrowed = dict(localq, toolchain=dict(localq["toolchain"], components=["rustfmt"]))
        check_policy.dependency_policy_consistency(constitution, narrowed, dict(toolchain, components=["rustfmt"]), policy, live)
        self.assertEqual(check_policy.errors, [])
        check_policy.errors = []
        with mock.patch.object(dependency_authority, "expected_policy_flags", return_value=dict(expected, dynamic_loading_allowed=True)):
            check_policy.dependency_policy_consistency(constitution, localq, toolchain, policy, live)
        self.assertEqual(check_policy.errors, ["dependency constitution machine policy mismatch for dynamic_loading_allowed"])

    def test_check_policy_has_no_plain_authority_reads(self) -> None:
        """Every dependency-authority input in check-policy goes through dependency_authority (finding b)."""
        import ast
        source = (ROOT / "scripts/check-policy.py").read_text(encoding="utf-8")
        authority_inputs = {AL, IMPORTS, CJ, DJ, "architecture/local_qualification.toml", TS}
        plain = []
        for node in ast.walk(ast.parse(source)):
            if isinstance(node, ast.Call) and isinstance(node.func, ast.Name) and node.func.id in ("load_json", "load_toml"):
                if node.args and isinstance(node.args[0], ast.Constant) and node.args[0].value in authority_inputs:
                    plain.append((node.func.id, node.args[0].value, node.lineno))
        self.assertEqual(plain, [])
        self.assertIn('authority_json("architecture/franken_imports.json")', source)
        self.assertIn('authority_toml("architecture/local_qualification.toml")', source)
        self.assertIn('authority_json("architecture/dependency_constitution.json")', source)
        self.assertIn('dependency_authority.load_policy_document(ROOT / "architecture/dependency_allowlist.toml", ROOT)', source)
        self.assertNotIn("tomllib.loads(lock_path.read_text", source)

    # d) DEP-AUD-045 keeps its original meaning; DEP-AUD-047 is the refusal
    def test_dep_aud_045_is_unchanged_and_047_is_the_refusal(self) -> None:
        original = "| `DEP-AUD-045` | warning | fundamental crate is pending owner decision fss-ndxis | keep crate quarantined until user decision fss-ndxis is resolved; never admit as production authority | `GATE-000`, `QL-POLICY-001` | await decision fss-ndxis before re-running qualification |"
        errors_md = (ROOT / "registries/ERRORS.md").read_text(encoding="utf-8").splitlines()
        self.assertIn(original, errors_md)
        self.assertEqual([line for line in errors_md if line.startswith("| `DEP-AUD-045` |")], [original])
        registry = dependency_audit.DIAGNOSTIC_REGISTRY
        self.assertEqual((registry["DEP-AUD-045"].severity, registry["DEP-AUD-045"].trigger), ("warning", "fundamental crate is pending owner decision fss-ndxis"))
        self.assertEqual(registry["DEP-AUD-047"].severity, "error")
        self.assertTrue(any(line.startswith("| `DEP-AUD-047` | error |") for line in errors_md))
        self.assertEqual(dependency_audit.classify_dependency_package("serde", {}, set())[1], "DEP-AUD-047")

    # e) DEP-AUD-023 yields to the allowlist's admission; the owner decision alone decides
    def test_serde_023_follows_the_allowlist_decision(self) -> None:
        deps = '\n[dependencies]\nserde = { version = "1", default-features = false }\nserde_derive = { version = "1", default-features = false }\n'
        lock = [
            {"name": "fss-a", "version": "0.0.1", "dependencies": ["serde", "serde_derive"]},
            {"name": "serde", "version": "1.0.0", "source": "registry+https://example.invalid/index"},
            {"name": "serde_derive", "version": "1.0.0", "source": "registry+https://example.invalid/index"},
        ]
        live_text = (ROOT / AL).read_text(encoding="utf-8")
        decided = live_text.split("\n[pending_owner_decisions.fss-ndxis]")[0] + "\n[pending_owner_decisions]\n"
        for label, text, serde_codes in (
            ("pending (current)", live_text, {"DEP-AUD-023", "DEP-AUD-045", "DEP-AUD-047"}),
            ("owner admits serde", decided, set()),
        ):
            with self.subTest(label), tempfile.TemporaryDirectory() as tmp:
                root = Path(tmp)
                make_workspace(root, deps, lock)
                (root / "policy.toml").write_text(text, encoding="utf-8")
                report, rc = dependency_audit.audit_workspace(root, root / "policy.toml")
                self.assertEqual({f["code"] for f in report["findings"] if f.get("params", {}).get("package") == "serde"}, serde_codes)
                derive_codes = {f["code"] for f in report["findings"] if f.get("params", {}).get("package") == "serde_derive"}
                self.assertIn("DEP-AUD-023", derive_codes)
                if serde_codes:
                    self.assertTrue(all("pending owner decision fss-ndxis" in f["message"] for f in report["findings"] if f.get("params", {}).get("package") == "serde" and f["code"] == "DEP-AUD-023"))

    # f) the policy lane itself catches an oversized or odd Cargo.lock
    def test_check_policy_runs_the_bounded_census(self) -> None:
        check_policy = load_check_policy()
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            make_workspace(root)
            check_policy.ROOT = root
            policy = dependency_audit.load_toml(ROOT / AL)
            check_policy.errors = []
            check_policy.cargo_policy(policy)
            self.assertEqual(check_policy.errors, [])
            with mock.patch.object(dependency_authority, "MAX_INPUT_FILE_BYTES", 16):
                check_policy.errors = []
                check_policy.cargo_policy(policy)
            self.assertTrue(any(e.startswith("invalid Cargo.lock:") and "operational input bound" in e for e in check_policy.errors), check_policy.errors)
            self.assertTrue(any(e.startswith("DEP-AUD-046:") for e in check_policy.errors), check_policy.errors)
            make_workspace(root, "", [{"name": "fss-a", "version": "0.0.1"}, {"name": "stray-crate", "version": "1.0.0", "source": "registry+https://example.invalid/index"}])
            check_policy.errors = []
            check_policy.cargo_policy(policy)
            self.assertTrue(any(e.startswith("DEP-AUD-042:") and "stray-crate" in e for e in check_policy.errors), check_policy.errors)

    # g) end-to-end conformance through the real entry points, with a JSONL transcript
    def test_end_to_end_transcript(self) -> None:
        import subprocess
        with tempfile.TemporaryDirectory() as tmp:
            outs = [Path(tmp) / "a", Path(tmp) / "b"]
            for out in outs:
                proc = subprocess.run([sys.executable, "-B", str(ROOT / "scripts/dependency_registry_e2e.py"), "--out", str(out)], capture_output=True, text=True, timeout=600)
                self.assertEqual(proc.returncode, 0, proc.stdout + proc.stderr)
            transcript = (outs[0] / "transcript.jsonl").read_bytes()
            self.assertEqual(transcript, (outs[1] / "transcript.jsonl").read_bytes())
            records = [json.loads(line) for line in transcript.decode("utf-8").splitlines()]
            self.assertEqual([r["step"] for r in records], ["S0", "S1", "S2", "S3", "S4", "S5", "END"])
            required = {"requirement", "scenario", "step", "seed", "schedule", "authority", "privacy", "registryGeneration", "sourceDigests", "contractBasis", "budget"}
            for record in records:
                self.assertTrue(required <= set(record), record)
                self.assertEqual(record["requirement"], "DEP-OWNED-001")
                self.assertEqual(record["sourceDigests"]["registry"], BASELINE_DEPENDENCIES_FREEZE_DIGEST)
            for record in records[:-1]:
                self.assertTrue(record["matched"], record)
                self.assertEqual(record["actual"], record["expected"])
                artifact = outs[0] / "artifacts" / ("sha256-" + record["artifact"].split(":", 1)[1] + ".json")
                self.assertEqual("sha256:" + __import__("hashlib").sha256(artifact.read_bytes()).hexdigest(), record["artifact"])
                self.assertEqual(set(record["repair"]), set(record["actual"]["codes"]))
                self.assertNotIn("unregistered code", record["repair"].values())
            self.assertEqual((records[-1]["outcome"], records[-1]["mismatches"]), ("pass", 0))
            self.assertEqual(records[4]["actual"]["codes"], ["DEP-AUD-023", "DEP-AUD-047"])
            # A broken authority makes the nominal steps miss their expectation: the script exits 1.
            broken = Path(tmp) / "broken"
            import dependency_registry_e2e
            dependency_registry_e2e.copy_authority(ROOT, broken)
            text = (broken / AL).read_text(encoding="utf-8").replace("dynamic_loading_allowed = false", "dynamic_loading_allowed = true", 1)
            (broken / AL).write_text(text, encoding="utf-8")
            proc = subprocess.run([sys.executable, "-B", str(ROOT / "scripts/dependency_registry_e2e.py"), "--out", str(Path(tmp) / "c"), "--repo-root", str(broken)], capture_output=True, text=True, timeout=600)
            self.assertEqual(proc.returncode, 1, proc.stdout + proc.stderr)
            records = [json.loads(line) for line in (Path(tmp) / "c" / "transcript.jsonl").read_text(encoding="utf-8").splitlines()]
            # S0 and S5 (recovery restores the broken source allowlist) fail instead of passing; S2 gains the
            # flag's findings. S1, S3 and S4 still match: their expected codes already cover the damage.
            self.assertEqual([r["step"] for r in records if r["step"] != "END" and not r["matched"]], ["S0", "S2", "S5"])
            self.assertEqual((records[-1]["outcome"], records[-1]["mismatches"]), ("fail", 3))


class TestSecondIndependentMutantTests(unittest.TestCase):
    """Second, independent tests for mutants previously held by a single test (hard-coded map, lock walk, dev-as-production)."""

    def test_project_mapping_comes_from_the_allowlist(self) -> None:
        policy = {"in_house": {"allowed_families": ["zz-*"], "projects": {"frankentorch": ["zz-*"]}}, "fundamental": {"allowed_subject_to_audit": []}, "forbidden": {"crates": []}}
        self.assertEqual(dependency_audit.classify_dependency_package("zz-core", policy, set(), admitted_in_house={"frankentorch"}), ("DEP-OWNED-001", None, None))
        moved = dict(policy, in_house={"allowed_families": ["zz-*"], "projects": {"frankensqlite": ["zz-*"]}})
        dep_id, code, reason = dependency_audit.classify_dependency_package("zz-core", moved, set(), admitted_in_house={"frankentorch"})
        self.assertEqual(code, "DEP-AUD-043")
        self.assertIn("project 'frankensqlite'", reason)

    def test_lock_walk_is_transitive_and_edge_aware(self) -> None:
        policy = {"in_house": {"allowed_families": ["fss-*"]}, "fundamental": {"allowed_subject_to_audit": []}, "laboratory_oracles": {"excluded_from_production_release_closure": ["ffmpeg"]}, "forbidden": {"crates": []}}
        src = "registry+https://example.invalid/index"
        chain = [
            {"name": "fss-a", "version": "0.0.1", "dependencies": ["alpha"]},
            {"name": "alpha", "version": "1.0.0", "source": src, "dependencies": ["beta"]},
            {"name": "beta", "version": "1.0.0", "source": src, "dependencies": ["ffmpeg"]},
            {"name": "ffmpeg", "version": "4.4.0", "source": src},
        ]
        for section, expected in (("dependencies", {("DEP-AUD-042", "alpha"), ("DEP-AUD-042", "beta"), ("DEP-AUD-043", "ffmpeg")}), ("dev-dependencies", {("DEP-AUD-042", "alpha"), ("DEP-AUD-042", "beta")})):
            with self.subTest(section), tempfile.TemporaryDirectory() as tmp:
                root = Path(tmp)
                make_workspace(root, "", chain)
                findings: list[Any] = []
                dependency_audit.audit_dependency_classes(findings, root, policy, {"fss-a"}, [], direct=[{"manifest": "crates/fss-a/Cargo.toml", "section": section, "name": "alpha"}])
                self.assertEqual({(f.code, f.params["package"]) for f in findings}, expected)

    def test_stray_locked_package_counts_as_production(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            make_workspace(root, "", [{"name": "fss-a", "version": "0.0.1"}, {"name": "tokio", "version": "1.0.0", "source": "registry+https://example.invalid/index"}])
            findings: list[Any] = []
            dependency_audit.audit_dependency_classes(findings, root, dependency_audit.load_toml(ROOT / AL), {"fss-a"}, [], direct=[])
            self.assertEqual([(f.code, f.params["package"], f.params["production"]) for f in findings], [("DEP-AUD-030", "tokio", True)])

    def test_stray_locked_package_is_production_through_the_full_audit(self) -> None:
        """Second, independent killer of the dev-as-production mutant: the full audit_workspace pipeline
        (manifest enumeration and lock walk) codes a stray locked forbidden crate as production (030),
        and the same crate reached only by a [dev-dependencies] edge as development (043)."""
        registry = "registry+https://example.invalid/index"
        cases = {
            "stray (no manifest edge)": ("", [{"name": "fss-a", "version": "0.0.1"}, {"name": "tokio", "version": "1.0.0", "source": registry}], "DEP-AUD-030"),
            "dev-only edge": ('\n[dev-dependencies]\ntokio = "1"\n', [{"name": "fss-a", "version": "0.0.1", "dependencies": ["tokio"]}, {"name": "tokio", "version": "1.0.0", "source": registry}], "DEP-AUD-043"),
        }
        for label, (deps, lock, expected) in cases.items():
            with self.subTest(label), tempfile.TemporaryDirectory() as tmp:
                root = Path(tmp)
                make_workspace(root, deps, lock)
                report, _rc = dependency_audit.audit_workspace(root, ROOT / AL)
                self.assertIn("findings", report, report)
                # the class-census finding (params carry the class) is the one the production walk decides
                tokio = sorted(f["code"] for f in report["findings"] if f["code"] in ("DEP-AUD-030", "DEP-AUD-043") and f["params"].get("package") == "tokio" and "class" in f["params"])
                self.assertEqual(tokio, [expected], report["findings"])

    def test_lock_walk_transitive_production_edge_beats_a_dev_edge(self) -> None:
        """Second, independent killer of the non-transitive lock walk: ffmpeg is reached in production only
        through alpha -> beta, and directly through a dev edge. Only a transitive production walk keeps it
        production (043); a one-hop walk would leave it dev-reachable and silently allowed."""
        policy = {"in_house": {"allowed_families": ["fss-*"]}, "fundamental": {"allowed_subject_to_audit": []}, "laboratory_oracles": {"excluded_from_production_release_closure": ["ffmpeg"]}, "forbidden": {"crates": []}}
        src = "registry+https://example.invalid/index"
        chain = [
            {"name": "fss-a", "version": "0.0.1", "dependencies": ["alpha", "ffmpeg"]},
            {"name": "alpha", "version": "1.0.0", "source": src, "dependencies": ["beta"]},
            {"name": "beta", "version": "1.0.0", "source": src, "dependencies": ["ffmpeg"]},
            {"name": "ffmpeg", "version": "4.4.0", "source": src},
        ]
        direct = [{"manifest": "crates/fss-a/Cargo.toml", "section": "dependencies", "name": "alpha"},
                  {"manifest": "crates/fss-a/Cargo.toml", "section": "dev-dependencies", "name": "ffmpeg"}]
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            make_workspace(root, "", chain)
            findings: list[Any] = []
            dependency_audit.audit_dependency_classes(findings, root, policy, {"fss-a"}, [], direct=direct)
            self.assertEqual({(f.code, f.params["package"], f.params["production"]) for f in findings},
                             {("DEP-AUD-042", "alpha", True), ("DEP-AUD-042", "beta", True), ("DEP-AUD-043", "ffmpeg", True)})


class TestConstitutionClassCoverage(AuthorityCase):
    """Finding m: every non-constitutional constitution class has an active registry row."""

    def owned(self, data: dict[str, Any]) -> dict[str, Any]:
        return next(row for row in data["dependencies"] if row["id"] == "DEP-OWNED-001")

    def test_live_registry_covers_every_class(self) -> None:
        """Live data: each class other than F0 is mapped by an active row; F1 through DEP-OWNED-001."""
        auth = dependency_authority.load_authority(ROOT)
        self.assertEqual(auth.issues, [])
        covered = {cls for row in auth.rows() if row["status"] == "active" for cls in row["constitutionClasses"]}
        needed = {cid for cid, klass in auth.classes().items() if klass["admission"] != "constitutional"}
        self.assertEqual(needed, {"DEP-CLASS-F1", "DEP-CLASS-F2", "DEP-CLASS-F3", "DEP-CLASS-F4"})
        self.assertEqual(covered, needed)
        self.assertEqual(self.owned(auth.registry)["constitutionClasses"], ["DEP-CLASS-F2", "DEP-CLASS-F1"])
        for row in auth.rows():
            self.assertEqual(row["constitutionClasses"][0], row["constitutionClass"])

    def test_uncovered_or_malformed_class_lists_are_refused(self) -> None:
        """Dropping F1, reordering, duplicating, naming F0 or an unknown class, or emptying is CONST-INVARIANT."""
        original = self.load()
        for label, (classes, shape) in {
            "F1 dropped (no row maps asupersync)": (["DEP-CLASS-F2"], set()),
            "primary not first": (["DEP-CLASS-F1", "DEP-CLASS-F2"], set()),
            "duplicate": (["DEP-CLASS-F2", "DEP-CLASS-F2", "DEP-CLASS-F1"], {C}),  # the exact-shape loader also refuses duplicate entries
            "constitutional F0 listed": (["DEP-CLASS-F2", "DEP-CLASS-F1", "DEP-CLASS-F0"], set()),
            "unknown class": (["DEP-CLASS-F2", "DEP-CLASS-F1", "DEP-CLASS-F9"], set()),
            "empty": ([], {M}),  # and empty lists
        }.items():
            with self.subTest(label):
                data = copy.deepcopy(original)
                self.owned(data)["constitutionClasses"] = classes
                self.save(data, redigest=True)
                result = self.assertCodes({I, F, R} | shape)
                self.assertTrue(any(e.code == I and ("constitutionClasses" in e.target or e.target == "#/dependencies") for e in result.errors), [(e.code, e.target) for e in result.errors])

    def test_class_mapped_only_by_a_non_active_row_is_uncovered(self) -> None:
        """A class mapped only by a superseded row is uncovered."""
        data = self.load()
        clone = dict(copy.deepcopy(self.owned(data)), id="DEP-OWNED-002", status="superseded")
        self.owned(data)["constitutionClasses"] = ["DEP-CLASS-F2"]
        data["dependencies"].append(clone)
        self.save(data, redigest=True)
        result = self.check()
        self.assertTrue(any(e.code == I and e.target == "#/dependencies" and "DEP-CLASS-F1" in e.message for e in result.errors), [(e.code, e.target, e.message) for e in result.errors])

    def test_gate_admission_must_exist_in_the_import_registry(self) -> None:
        """F1's admission gate INT-AS-001 must be carried by an import record."""
        self.write(IMPORTS, self.text(IMPORTS).replace('"INT-AS-001"', '"INT-AS-999"'))
        result = self.assertCodes({I})
        self.assertEqual([(e.file_path, e.target) for e in result.errors if e.code == I], [(IMPORTS, "#/imports")])


class TestStrictMarkdownMirror(AuthorityCase):
    """Bypass-harness rows e10a-e10c: registries/DEPENDENCIES.md must equal its deterministic rendering."""

    def test_anything_outside_the_rendering_is_drift(self) -> None:
        base = self.text(MD)
        self.assertCodes(set())
        for label, text in {
            "e10a html comment row": base + "<!--\n| `DEP-ROGUE-001` | `DEP-CLASS-F3` | Rogue |\n-->\n",
            "e10b fenced row": base + "```\n| `DEP-ROGUE-002` | `DEP-CLASS-F3` | Rogue |\n```\n",
            "e10c homoglyph id in a comment": base + "<!-- | `DEP\u2010ROGUE\u2010003` | admitted | -->\n",
            "plain prose": base + "\nEditorial note.\n",
        }.items():
            with self.subTest(label):
                self.write(MD, text)
                result = self.assertCodes({R})
                targets = [e.target for e in result.errors]
                if label.startswith(("e10a", "e10b")):
                    # the ASCII rogue id is also caught by the rogue-id scan at its line
                    self.assertEqual(sorted(targets), ["#/rendering", "line/26"])
                else:
                    self.assertEqual(targets, ["#/rendering"])  # the former bypasses: only the rendering check sees them
        # CRLF was already refused (LF-only rule, then no parsable table); it stays exactly that.
        self.write(MD, base.replace("\n", "\r\n"))
        self.assertCodes({R, C})


if __name__ == "__main__":
    unittest.main()
