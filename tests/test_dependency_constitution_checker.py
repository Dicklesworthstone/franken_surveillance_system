#!/usr/bin/env python3
"""Deterministic verification suite for the dependency constitution and DEP-CLASS-F0 (fss-x4a.30.88.16).

The constitution checker holds no policy table: scripts/dependency_authority.py reads and pins the
allowlist, the constitution, the dependency registry, the import gates and the local qualification
contract. Every test asserts an exact finding-code set (or an exact (code, target) list where two guards
share a code).

Every test name that existed at 1343af3, f0a2beb and dcf1b4f is kept. Where the round-3 review showed an
old expectation encoded a defect (constitution drift reported as registry drift, execution failures
reported as corrupt files, fail-open null metadata), the test asserts the corrected, stricter result.
"""
from __future__ import annotations

import copy
import json
import tomllib
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from typing import Any
from unittest.mock import MagicMock, patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))

import dependency_authority  # noqa: E402
import dependency_constitution_checker  # noqa: E402
from dependency_constitution_checker import (  # noqa: E402
    BASELINE_DEPENDENCY_CONSTITUTION_FREEZE_DIGEST,
    BASELINE_DEPENDENCY_CONSTITUTION_GENERATION,
    CANONICAL_CONSTITUTION_CLASSES,
    CANONICAL_CONSTITUTION_MARKDOWN_TITLES,
    CARGO_METADATA_TIMEOUT_SECONDS,
    EXPECTED_FREEZE_DIGESTS,
    MANDATORY_CLASS_FIELDS,
    MANDATORY_PRODUCTION_FIELDS,
    MANDATORY_TOP_LEVEL_FIELDS,
    REQUIRED_PRODUCTION_VALUES,
    REQUIRED_RUST_CHANNEL,
    TOOLCHAIN_COMMAND_TIMEOUT_SECONDS,
    ERR_DEP_ALLOWLIST_DIGEST_DIVERGED,
    ERR_DEP_CONST_DRIFT,
    ERR_DEP_CONST_INVARIANT,
    ERR_DEP_CONST_METADATA_VIOLATION,
    ERR_DEP_CORRUPT_FILE,
    ERR_DEP_DIGEST_MISMATCH,
    ERR_DEP_EXEC_FAILED,
    ERR_DEP_FREEZE_DIVERGENCE,
    ERR_DEP_GENERATION_MISMATCH,
    ERR_DEP_MISSING_FIELD,
    ERR_DEP_PENDING_DECISION,
    ERR_DEP_REGISTRY_DRIFT,
    ERR_DEP_STABLE_ID_REUSED,
    ERR_DEP_TRACE_UNRESOLVED,
    ERR_DEP_UNSTABLE_FEATURE,
    compute_canonical_constitution_digest,
    extract_markdown_class_sections,
    load_real_cargo_metadata,
    load_tombstoned_ids,
    scan_unstable_features,
    validate_cargo_metadata_for_f0,
    validate_dependency_constitution,
    validate_toolchain_identity,
)

AUTHORITY_FILES = (
    "architecture/dependency_constitution.json",
    "architecture/dependencies.json",
    "architecture/dependency_allowlist.toml",
    "architecture/stable_id_resolution.json",
    "architecture/franken_imports.json",
    "architecture/local_qualification.toml",
    "architecture/release_qualification.json",
    "docs/DEPENDENCY_CONSTITUTION.md",
    "DEPENDENCY_CONSTITUTION.md",
    "architecture/crate_topology.json",
    "Cargo.toml",
    "Cargo.lock",
    "rust-toolchain.toml",
    "registries/ERRORS.md",
)
CJ = "architecture/dependency_constitution.json"
DJ = "architecture/dependencies.json"
AL = "architecture/dependency_allowlist.toml"
MD = "docs/DEPENDENCY_CONSTITUTION.md"
TC = "rust-toolchain.toml"
TS = "architecture/stable_id_resolution.json"

C = ERR_DEP_CORRUPT_FILE
M = ERR_DEP_MISSING_FIELD
D = ERR_DEP_DIGEST_MISMATCH
F = ERR_DEP_FREEZE_DIVERGENCE
G = ERR_DEP_GENERATION_MISMATCH
I = ERR_DEP_CONST_INVARIANT
CD = ERR_DEP_CONST_DRIFT
S = ERR_DEP_STABLE_ID_REUSED
A = ERR_DEP_ALLOWLIST_DIGEST_DIVERGED
MV = ERR_DEP_CONST_METADATA_VIOLATION
EX = ERR_DEP_EXEC_FAILED
PD = ERR_DEP_PENDING_DECISION

GOOD_RUSTC = (
    "rustc 1.100.0-nightly (908501772 2026-08-30)\n"
    "binary: rustc\n"
    "commit-hash: 90850177249efe0321573c569aec5d12b257f8d6\n"
    "commit-date: 2026-08-30\n"
    "host: x86_64-unknown-linux-gnu\n"
    "release: 1.100.0-nightly\n"
    "LLVM version: 23.1.0\n"
)
REGISTRY = "registry+https://github.com/rust-lang/crates.io-index"


def codes(result: Any) -> set[str]:
    return {e.code for e in result.errors}


def completed(stdout: str = "", returncode: int = 0, stderr: str = "") -> MagicMock:
    proc = MagicMock()
    proc.stdout, proc.returncode, proc.stderr = stdout, returncode, stderr
    return proc


def pkg(name: str, *, member: bool = False, edition: str | None = None, links: str | None = None,
        kinds: tuple[str, ...] = ("lib",), crate_types: tuple[str, ...] | None = None, version: str = "1.0.0") -> dict[str, Any]:
    pkg_id = f"path+file:///ws/{name}#0.0.1" if member else f"{REGISTRY}#{name}@{version}"
    targets = [{"kind": list(kinds), "crate_types": list(crate_types or kinds), "name": name}]
    return {
        "name": name, "id": pkg_id, "version": "0.0.1" if member else version, "source": None if member else REGISTRY,
        "edition": edition or ("2024" if member else "2021"), "links": links, "targets": targets,
        # Members live where the real workspace declares them, so the topology and
        # [workspace].members checks of finding j see a declared, explicit member.
        "manifest_path": f"{ROOT}/crates/{name}/Cargo.toml" if member else f"/registry/{name}-{version}/Cargo.toml",
    }


def metadata(packages: list[dict[str, Any]], edges: dict[str, list[tuple[str, str | None]]], fss: Any = None) -> dict[str, Any]:
    by_name = {p["name"]: p["id"] for p in packages}
    members = [p["id"] for p in packages if p["source"] is None]
    nodes = []
    for p in packages:
        deps = [{"name": dep.replace("-", "_"), "pkg": by_name[dep], "dep_kinds": [{"kind": kind, "target": None}]} for dep, kind in edges.get(p["name"], [])]
        nodes.append({"id": p["id"], "dependencies": [d["pkg"] for d in deps], "deps": deps})
    return {
        "packages": packages,
        "workspace_members": members,
        "resolve": {"nodes": nodes, "root": None},
        "metadata": {"fss": {"production_language": "rust"} if fss is None else fss},
    }


# Members whose crate_topology.json status is not a present status (skeleton/implemented/qualified).
# The owner registered the last pending pair (fss-packet, fss-geometry) as implemented in f541d72, so
# every live member must now be marked present. If a new member is ever left unregistered, list it here
# until the owner registers it, never by bumping a member count.
LIVE_MEMBERS_NOT_MARKED_PRESENT: set[str] = set()
PRESENT_TOPOLOGY_STATUSES = {"skeleton", "implemented", "qualified"}


def live_workspace_members(root: Path) -> set[str]:
    """Package names of the root [workspace].members manifests (the live member set, never a count)."""
    import tomllib as _tomllib
    members = _tomllib.loads((root / "Cargo.toml").read_text(encoding="utf-8"))["workspace"]["members"]
    return {_tomllib.loads((root / member / "Cargo.toml").read_text(encoding="utf-8"))["package"]["name"] for member in members}


def topology_statuses(root: Path) -> dict[str, str]:
    import json as _json
    topology = _json.loads((root / "architecture/crate_topology.json").read_text(encoding="utf-8"))
    return {crate["name"]: crate.get("status") for layer in topology["layers"] for crate in layer["crates"]}


def assert_live_members_match_topology(test: "unittest.TestCase", members: set[str], root: Path) -> None:
    """Every live member is declared in the topology; the members not marked present are exactly the
    owner's pending set."""
    statuses = topology_statuses(root)
    test.assertEqual(sorted(members - set(statuses)), [], "workspace members undeclared in architecture/crate_topology.json")
    test.assertEqual({m for m in members if statuses.get(m) not in PRESENT_TOPOLOGY_STATUSES}, LIVE_MEMBERS_NOT_MARKED_PRESENT)


class ConstitutionCase(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp_dir = tempfile.TemporaryDirectory()
        self.tmp_root = Path(self.tmp_dir.name)
        for rel in AUTHORITY_FILES:
            (self.tmp_root / rel).parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(ROOT / rel, self.tmp_root / rel)

    def tearDown(self) -> None:
        self.tmp_dir.cleanup()

    def path(self, rel: str) -> Path:
        return self.tmp_root / rel

    def load(self, rel: str = CJ) -> dict[str, Any]:
        return json.loads(self.path(rel).read_text(encoding="utf-8"))

    def save(self, data: Any, rel: str = CJ, redigest: bool = False) -> None:
        if redigest:
            data["freezeDigest"] = compute_canonical_constitution_digest(data)
        self.path(rel).write_text(json.dumps(data, indent=2), encoding="utf-8")

    def text(self, rel: str) -> str:
        return self.path(rel).read_text(encoding="utf-8")

    def write(self, rel: str, text: str) -> None:
        self.path(rel).write_text(text, encoding="utf-8")

    def replace(self, rel: str, old: str, new: str) -> None:
        text = self.text(rel)
        self.assertIn(old, text)
        self.write(rel, text.replace(old, new, 1))

    def klass(self, data: dict[str, Any], class_id: str) -> dict[str, Any]:
        return next(c for c in data["classes"] if c["id"] == class_id)

    def check(self) -> Any:
        return validate_dependency_constitution(self.tmp_root, skip_cargo_metadata=True)

    def assertCodes(self, expected: set[str], result: Any | None = None) -> Any:
        result = result if result is not None else self.check()
        self.assertEqual(codes(result), expected, [f"{e.code} {e.target}: {e.message}" for e in result.errors])
        self.assertEqual(result.passed, not expected)
        return result

    def census(self, meta: Any, allow_data: dict[str, Any] | None = None) -> list[tuple[str, str]]:
        res = dependency_constitution_checker.ValidationResult()
        validate_cargo_metadata_for_f0(res, meta, ROOT, allow_data=allow_data) if allow_data is not None else validate_cargo_metadata_for_f0(res, meta, ROOT)
        return sorted((e.code, e.target) for e in res.errors)

    def fake_run(self, rustc: str = GOOD_RUSTC, rustc_rc: int = 0, cargo: Any = None, calls: list[Any] | None = None):
        cargo_payload = cargo if cargo is not None else json.dumps(metadata([pkg("fss-core", member=True)], {}))

        def run(cmd: list[str], *args: Any, **kwargs: Any) -> Any:
            if calls is not None:
                calls.append((cmd, kwargs))
            if "cargo" in cmd:
                if isinstance(cargo_payload, BaseException):
                    raise cargo_payload
                if isinstance(cargo_payload, MagicMock):
                    return cargo_payload
                # cargo reports absolute manifest paths under the directory it runs in.
                return completed(cargo_payload.replace(f"{ROOT}/", f"{kwargs.get('cwd', ROOT)}/"))
            return completed(rustc, rustc_rc)
        return run


class TestDependencyConstitutionChecker(ConstitutionCase):
    """Constitution JSON, pins, crosswalk and Markdown mirror (exact code sets)."""

    def test_live_constitution_passes(self) -> None:
        """The live repository passes end to end, including real rustc -Vv and cargo metadata."""
        result = validate_dependency_constitution(ROOT)
        self.assertTrue(result.passed, f"Live constitution validation failed: {[e.message for e in result.errors]}")
        self.assertEqual(len(result.errors), 0)
        self.assertEqual(result.class_count, 5)
        self.assertEqual(result.freeze_digest, BASELINE_DEPENDENCY_CONSTITUTION_FREEZE_DIGEST)

    def test_cargo_metadata_inspection_live_passes(self) -> None:
        """Real cargo metadata of the live repository passes the DEP-CLASS-F0 closure census."""
        meta, err = load_real_cargo_metadata(ROOT)
        self.assertIsNone(err)
        res = dependency_constitution_checker.ValidationResult()
        validate_cargo_metadata_for_f0(res, meta, ROOT)
        self.assertEqual(res.errors, [])
        # The member set is derived from the live Cargo.toml and held to crate_topology.json, never a count.
        live = live_workspace_members(ROOT)
        self.assertEqual({p["name"] for p in meta["packages"] if p["id"] in meta["workspace_members"]}, live)
        assert_live_members_match_topology(self, live, ROOT)

    def test_exact_freeze_digest_assertion(self) -> None:
        """Freeze digest matches the exact pinned constant byte-for-byte; no prefix-only matching."""
        result = self.assertCodes(set())
        self.assertEqual(result.freeze_digest, BASELINE_DEPENDENCY_CONSTITUTION_FREEZE_DIGEST)
        self.assertEqual(EXPECTED_FREEZE_DIGESTS, {BASELINE_DEPENDENCY_CONSTITUTION_GENERATION: BASELINE_DEPENDENCY_CONSTITUTION_FREEZE_DIGEST})
        self.assertEqual(len(result.freeze_digest), 7 + 64)

    def test_canonical_digest_deterministic(self) -> None:
        """Canonical digest is deterministic and invariant to class row permutation."""
        data = self.load()
        data_rev = copy.deepcopy(data)
        data_rev["classes"] = list(reversed(data_rev["classes"]))
        self.assertEqual(compute_canonical_constitution_digest(data), compute_canonical_constitution_digest(data_rev))
        self.assertEqual(compute_canonical_constitution_digest(data), BASELINE_DEPENDENCY_CONSTITUTION_FREEZE_DIGEST)

    def test_tampered_digest_rejected(self) -> None:
        """A tampered freezeDigest is refused with exact DIGEST-MISMATCH."""
        data = self.load()
        data["freezeDigest"] = "sha256:" + "0" * 64
        self.save(data)
        self.assertCodes({D})

    def test_prefix_only_digest_bypass_prevented(self) -> None:
        """A digest that only shares the prefix is refused."""
        data = self.load()
        data["freezeDigest"] = BASELINE_DEPENDENCY_CONSTITUTION_FREEZE_DIGEST[:-8] + "deadbeef"
        self.save(data)
        self.assertCodes({D})

    def test_row_mutation_without_generation_bump_rejected(self) -> None:
        """A class mutated and re-digested without a generation bump diverges; the mirror drifts."""
        data = self.load()
        self.klass(data, "DEP-CLASS-F0")["admission"] = "tampered-admission"
        self.save(data, redigest=True)
        self.assertCodes({F, I, CD})

    def test_unpinned_generation_rejected(self) -> None:
        """An unpinned generation is refused; the mirror's generation row drifts."""
        data = self.load()
        data["generation"] = "gen:fss1:dep-constitution-v99"
        self.save(data, redigest=True)
        self.assertCodes({G, CD})

    def test_missing_top_level_field_rejected(self) -> None:
        """Missing top-level fields are MISSING-FIELD and the remaining guards still run (exact per field)."""
        original = self.load()
        expected = {
            "schema": {M, D, F, CD}, "asOf": {M, D, F, CD}, "generation": {M, G, D, CD}, "freezeDigest": {M},
            "normativePolicy": {M, D, F, CD}, "production": {M, D, F, CD}, "classes": {M, D, F, I, CD},
            "releaseEvidence": {M, D, F, CD},
        }
        self.assertEqual(set(expected), set(MANDATORY_TOP_LEVEL_FIELDS))
        for field_name in MANDATORY_TOP_LEVEL_FIELDS:
            with self.subTest(field=field_name):
                data = copy.deepcopy(original)
                del data[field_name]
                self.save(data)
                self.assertCodes(expected[field_name])

    def test_missing_class_field_rejected(self) -> None:
        """Missing class fields are MISSING-FIELD plus freeze divergence and the pinned-baseline invariant."""
        original = self.load()
        expected = {"id": {M, F, I, CD}, "name": {M, F, I}, "admission": {M, F, I}}
        self.assertEqual(set(expected), set(MANDATORY_CLASS_FIELDS))
        for c_field in MANDATORY_CLASS_FIELDS:
            with self.subTest(field=c_field):
                data = copy.deepcopy(original)
                del data["classes"][0][c_field]
                self.save(data, redigest=True)
                self.assertCodes(expected[c_field])

    def test_missing_production_field_rejected(self) -> None:
        """Missing production fields are MISSING-FIELD, freeze divergence and mirror drift."""
        original = self.load()
        for p_field in MANDATORY_PRODUCTION_FIELDS:
            with self.subTest(field=p_field):
                data = copy.deepcopy(original)
                del data["production"][p_field]
                self.save(data, redigest=True)
                self.assertCodes({M, F, CD})

    def test_duplicate_class_id_rejected(self) -> None:
        """Duplicate class ID is rejected with ERR-DEP-STABLE-ID-REUSED-001 (1343af3 name)."""
        data = self.load()
        data["classes"].append(copy.deepcopy(data["classes"][0]))
        self.save(data, redigest=True)
        self.assertCodes({S, F, I, CD})

    def test_case_colliding_class_id_rejected(self) -> None:
        """Case-colliding class ID is rejected with ERR-DEP-STABLE-ID-REUSED-001 (1343af3 name)."""
        data = self.load()
        dupe = copy.deepcopy(data["classes"][0])
        dupe["id"] = dupe["id"].lower()
        data["classes"].append(dupe)
        self.save(data, redigest=True)
        self.assertCodes({S, F, I, CD})

    def test_mutant_m13_duplicate_class_id_rejected(self) -> None:
        """Duplicate class ID: STABLE-ID-REUSED, divergence, baseline count, and mirror section count.

        Code correction: the mirror mismatch is ERR-DEP-CONST-DRIFT-001, not REGISTRY-DRIFT.
        """
        data = self.load()
        data["classes"].append(copy.deepcopy(data["classes"][0]))
        self.save(data, redigest=True)
        result = self.assertCodes({S, F, I, CD})
        self.assertTrue(any("Duplicate class ID" in e.message for e in result.errors))

    def test_mutant_m12_case_colliding_class_id_rejected(self) -> None:
        """Case-colliding class ID: pattern and collision findings, and mirror drift (CONST-DRIFT)."""
        data = self.load()
        dupe = copy.deepcopy(data["classes"][0])
        dupe["id"] = dupe["id"].lower()
        data["classes"].append(dupe)
        self.save(data, redigest=True)
        result = self.assertCodes({S, F, I, CD})
        self.assertTrue(any("Case-colliding" in e.message for e in result.errors))

    def test_id_pattern_violation_rejected_as_invariant(self) -> None:
        """A class ID outside the pinned baseline is CONST-INVARIANT (not STABLE-ID-REUSED)."""
        data = self.load()
        data["classes"][0]["id"] = "DEP-CLASS-F99"
        self.save(data, redigest=True)
        self.assertCodes({I, F, CD})
        data["classes"][0]["id"] = "DEP-CLASS-X0"
        self.save(data, redigest=True)
        result = self.assertCodes({I, F, CD})
        self.assertTrue(any("does not conform" in e.message for e in result.errors))

    def test_mutant_m14_id_pattern_violation_rejected(self) -> None:
        """f0a2beb name kept; the pattern violation is CONST-INVARIANT per review item 8, plus mirror drift."""
        data = self.load()
        data["classes"][0]["id"] = "DEP-CLASS-F99"
        self.save(data, redigest=True)
        self.assertCodes({I, F, CD})

    def test_mutant_m11_class_count_mismatch_reported_as_drift(self) -> None:
        """Dropping F4: baseline count/missing class (CONST-INVARIANT), F4 rows orphaned, mirror drift."""
        data = self.load()
        data["classes"] = [c for c in data["classes"] if c["id"] != "DEP-CLASS-F4"]
        self.save(data, redigest=True)
        result = self.assertCodes({F, I, CD})
        self.assertTrue(any("Class count 4 differs" in e.message for e in result.errors))
        self.assertTrue(any("references unknown constitution class 'DEP-CLASS-F4'" in e.message for e in result.errors))

    def test_mutant_m6_name_mismatch_rejected(self) -> None:
        """A renamed F1 class drifts from the pinned baseline and from its mirror binding."""
        data = self.load()
        self.klass(data, "DEP-CLASS-F1")["name"] = "wrong-asupersync-name"
        self.save(data, redigest=True)
        result = self.assertCodes({I, F, CD})
        self.assertTrue(any("Class 'DEP-CLASS-F1' name mismatch" in e.message for e in result.errors))

    def test_mutant_m10_admission_mismatch_rejected(self) -> None:
        """An F1 admission change is outside the vocabulary and drifts from the baseline and the mirror."""
        data = self.load()
        self.klass(data, "DEP-CLASS-F1")["admission"] = "unauthorized-admission-rule"
        self.save(data, redigest=True)
        self.assertCodes({I, F, CD})

    def test_dep_class_f0_admission_invariant(self) -> None:
        """A non-constitutional F0 admission is CONST-INVARIANT (1343af3 name)."""
        data = self.load()
        self.klass(data, "DEP-CLASS-F0")["admission"] = "permissive"
        self.save(data, redigest=True)
        result = self.assertCodes({I, F, CD})
        self.assertTrue(any("exactly one class must carry the 'constitutional' admission" in e.message for e in result.errors))

    def test_dep_class_f0_production_invariants(self) -> None:
        """A non-Rust production language is CONST-INVARIANT (edition form and pinned baseline)."""
        data = self.load()
        data["production"]["language"] = "c++"
        self.save(data, redigest=True)
        result = self.assertCodes({I, F, CD})
        self.assertTrue(any("is not a Rust edition" in e.message for e in result.errors))

    def test_mutant_x15_typed_digest_comparison(self) -> None:
        """schema: 5 and "5" digest differently; an int schema is corrupt and drifts from the mirror."""
        data = self.load()
        self.assertNotEqual(compute_canonical_constitution_digest(dict(data, schema=5)), compute_canonical_constitution_digest(dict(data, schema="5")))
        self.save(dict(data, schema=5))
        self.assertCodes({C, D, F, CD})

    def test_constitution_bool_is_not_int(self) -> None:
        """closedUniverse: 1 is refused even when re-digested (1 != true)."""
        data = self.load()
        data["production"]["closedUniverse"] = 1
        self.save(data, redigest=True)
        self.assertCodes({C, F, I, CD})

    def test_whitespace_padding_rejected(self) -> None:
        """'constitutional ' is refused without stripping (f0a2beb name)."""
        data = self.load()
        data["classes"][0]["admission"] = "constitutional "
        self.save(data, redigest=True)
        self.assertCodes({C, F, I, CD})

    def test_whitespace_padding_rejected_as_corrupt_file(self) -> None:
        """Whitespace padding is ERR-DEP-CORRUPT-FILE-001 together with its consequences."""
        data = self.load()
        data["classes"][0]["admission"] = "constitutional "
        self.save(data, redigest=True)
        result = self.assertCodes({C, F, I, CD})
        self.assertTrue(any(e.code == C and "whitespace" in e.message for e in result.errors))

    def test_corrupt_or_empty_files_rejected(self) -> None:
        """Corrupt or 0-byte files fail closed with exact ERR-DEP-CORRUPT-FILE-001."""
        for content in ("", "  \n", "{ syntax_error: [", "[]", '{"a": NaN}'):
            with self.subTest(content=content):
                self.write(CJ, content)
                self.assertCodes({C})

    def test_invalid_utf8_json_handled_safely(self) -> None:
        """Invalid UTF-8 JSON fails closed with ERR-DEP-CORRUPT-FILE-001."""
        self.path(CJ).write_bytes(b"\xff\xfe{\"schema\": 1}")
        self.assertCodes({C})

    def test_deep_json_recursion_handled_safely(self) -> None:
        """Deep or pathological JSON never raises RecursionError."""
        for body in ("{" * 500 + '"a": 1' + "}" * 500, "[" * 200000, '{"a":' * 100000):
            with self.subTest(size=len(body)):
                self.write(CJ, body)
                self.assertCodes({C})

    def test_canonicalize_value_depth_limit(self) -> None:
        """Nesting deeper than the constitution schema's structural depth raises ValueError (no invented bound)."""
        self.assertEqual(dependency_constitution_checker.canonicalize_value({"a": [{"b": 1}]}), {"a": [{"b": 1}]})
        deep: dict = {}
        cursor = deep
        for _ in range(25):
            cursor["next"] = {}
            cursor = cursor["next"]
        with self.assertRaises(ValueError):
            dependency_constitution_checker.canonicalize_value(deep)
        self.assertEqual(dependency_authority.CONSTITUTION_SCHEMA_MAX_DEPTH, dependency_authority.spec_depth(dependency_authority.CONSTITUTION_SPEC))

    def test_release_evidence_non_list_handled_safely(self) -> None:
        """releaseEvidence: 5 never raises; exact set."""
        data = self.load()
        data["releaseEvidence"] = 5
        self.save(data)
        self.assertCodes({C, D, F, CD})

    def test_unknown_top_level_key_rejected(self) -> None:
        """An unknown top-level key is refused and digested."""
        data = self.load()
        data["extraProductionAdmissions"] = ["tokio", "libc"]
        self.save(data)
        self.assertCodes({C, D, F})

    def test_unknown_production_key_rejected(self) -> None:
        """An unknown production key is refused, digested and absent from the mirror."""
        data = self.load()
        data["production"]["unauthorizedMode"] = True
        self.save(data)
        self.assertCodes({C, D, F, CD})

    def test_unknown_class_row_key_rejected(self) -> None:
        """An unknown class-row key is refused and digested."""
        data = self.load()
        data["classes"][0]["extraField"] = "bypass"
        self.save(data)
        self.assertCodes({C, D, F})

    def test_duplicate_json_keys_rejected(self) -> None:
        """Duplicate JSON keys fail closed with ERR-DEP-CORRUPT-FILE-001."""
        self.write(CJ, '{\n  "schema": "fss.dependency_constitution.v1",\n' + self.text(CJ)[1:])
        self.assertCodes({C})

    # --- Markdown mirror ------------------------------------------------------------------

    def test_markdown_mirror_drift_rejected(self) -> None:
        """A missing F0 section is exact CONST-DRIFT (its binding line is then outside any class section)."""
        self.replace(MD, "### 2.1 Class F0 — Rust language and standard library", "### 2.1 Dropped Section")
        result = self.assertCodes({CD})
        self.assertTrue(any("is missing" in e.message for e in result.errors))

    def test_renamed_markdown_section_rejected(self) -> None:
        """Renaming a class section title is CONST-DRIFT."""
        self.replace(MD, "### 2.1 Class F0 — Rust language and standard library", "### 2.1 Class F0 — Renamed Class Title")
        self.assertCodes({CD})

    def test_emptied_markdown_section_rejected(self) -> None:
        """An emptied class section (no machine row) is CONST-DRIFT."""
        content = self.text(MD)
        f0 = "### 2.1 Class F0 — Rust language and standard library"
        f1 = "### 2.2 Class F1 — Asupersync"
        self.write(MD, content[:content.find(f0) + len(f0)] + "\n\n" + content[content.find(f1):])
        self.assertCodes({CD})

    def test_mutant_x7_markdown_0_byte_rejected(self) -> None:
        """A 0-byte constitution mirror fails closed with exact CORRUPT-FILE."""
        self.path(MD).write_bytes(b"")
        self.assertCodes({C})

    def test_mutant_x7_markdown_duplicate_section_rejected(self) -> None:
        """A duplicated F0 section is CONST-DRIFT."""
        self.write(MD, self.text(MD) + "\n\n### 2.1 Class F0 — Rust language and standard library\nDuplicate body.\n")
        result = self.assertCodes({CD})
        self.assertTrue(any("Duplicate class section header" in e.message for e in result.errors))

    def test_mutant_x7_markdown_lorem_body_rejected(self) -> None:
        """A lorem body without the machine row is hollow (CONST-DRIFT)."""
        content = self.text(MD)
        f0 = "### 2.1 Class F0 — Rust language and standard library"
        f1 = "### 2.2 Class F1 — Asupersync"
        self.write(MD, content[:content.find(f0) + len(f0)] + "\n\nLorem ipsum dolor sit amet, consectetur adipiscing elit.\n\n" + content[content.find(f1):])
        result = self.assertCodes({CD})
        self.assertTrue(any("contains hollow or placeholder text" in e.message for e in result.errors))

    def test_invalid_utf8_markdown_handled_safely(self) -> None:
        """Invalid UTF-8 in the mirror fails closed with CORRUPT-FILE (and it now differs from the root copy: CONST-DRIFT)."""
        self.path(MD).write_bytes(b"\xff\xfe# Constitution")
        self.assertCodes({C, CD})

    def test_markdown_bodies_bind_the_json_meaning(self) -> None:
        """Class sections and the machine table are compared with the JSON value by value, not by keyword."""
        original = self.text(MD)
        cases = {
            "binding admission drift": original.replace("admission `constitutional`", "admission `permissive`", 1),
            "binding names another class": original.replace("Machine row: `DEP-CLASS-F0`", "Machine row: `DEP-CLASS-F1`", 1),
            "two bindings in one section": original.replace("Machine row: `DEP-CLASS-F0` · name `rust-language-and-stdlib` · admission `constitutional`", "Machine row: `DEP-CLASS-F0` · name `rust-language-and-stdlib` · admission `constitutional`\nMachine row: `DEP-CLASS-F0` · name `rust-language-and-stdlib` · admission `constitutional`", 1),
            "malformed binding": original.replace("· admission `constitutional`", "admission constitutional", 1),
            "binding outside a class": original + "\nMachine row: `DEP-CLASS-F0` · name `rust-language-and-stdlib` · admission `constitutional`\n",
            "rogue level-4 class heading": original + "\n#### 2.1 Class F0 — Rust language and standard library\nCONTRADICTION: unsafe allowed\n",
            "renumbered duplicate section": original + "\n### 2.9 Class F0 — Rust language and standard library\nMachine row: `DEP-CLASS-F0` · name `rust-language-and-stdlib` · admission `constitutional`\n",
            "typed mirror value 1 for true": original.replace("| `production.closedUniverse` | `true` |", "| `production.closedUniverse` | `1` |", 1),
            "mirror string for bool": original.replace("| `production.cCppFfi` | `false` |", '| `production.cCppFfi` | `"false"` |', 1),
            "mirror row dropped": original.replace("| `production.dynamicLoading` | `false` |\n", "", 1),
            "mirror row duplicated": original.replace("| `production.dynamicLoading` | `false` |\n", "| `production.dynamicLoading` | `false` |\n| `production.dynamicLoading` | `false` |\n", 1),
            "mirror extra row": original.replace("| `production.dynamicLoading` | `false` |\n", "| `production.dynamicLoading` | `false` |\n| `production.pluginLoading` | `true` |\n", 1),
            "mirror evidence reordered": original.replace('| `releaseEvidence[0]` | `"exact source and sibling commits"` |', '| `releaseEvidence[0]` | `"DSR local lane receipts"` |', 1),
            "mirror not a JSON literal": original.replace("| `production.cCppFfi` | `false` |", "| `production.cCppFfi` | `no` |", 1),
            "mirror table twice": original + "\n| Constitution field | Value |\n|---|---|\n",
            "mirror separator": original.replace("| Constitution field | Value |\n|---|---|", "| Constitution field | Value |\n|--|--|", 1),
            "carriage returns": original.replace("\n", "\r\n"),
        }
        for label, tampered in cases.items():
            with self.subTest(label):
                self.assertNotEqual(tampered, original, label)
                self.write(MD, tampered)
                self.assertCodes({CD})

    def test_extract_markdown_class_sections_is_strict(self) -> None:
        """Only exact '### 2.N Class Fk — Title' headings are sections; duplicates are reported."""
        sections, duplicates = extract_markdown_class_sections(self.text(MD))
        self.assertEqual(sorted(sections), sorted(CANONICAL_CONSTITUTION_CLASSES))
        self.assertEqual(duplicates, [])
        self.assertEqual({k: v[0] for k, v in sections.items()}, CANONICAL_CONSTITUTION_MARKDOWN_TITLES)
        for class_id, (_title, body) in sections.items():
            self.assertIn(dependency_constitution_checker.render_binding(CANONICAL_CONSTITUTION_CLASSES[class_id]), body)
        sections, _ = extract_markdown_class_sections("#### 2.1 Class F0 — X\n###  2.1 Class F0 — Y\n### 2.1 Class F0 -- Z\n")
        self.assertEqual(sections, {})

    # --- Tombstones ---------------------------------------------------------------------

    def test_tombstoned_id_rejected(self) -> None:
        """Resurrecting a tombstoned class identifier fails with exact STABLE-ID-REUSED."""
        self.write(TS, json.dumps({"schema": "fss.stable_id_resolution.v1", "asOf": "2026-09-01", "resolutions": [{"legacyId": "DEP-CLASS-F0", "status": "tombstoned", "canonicalId": "DEP-CLASS-F99"}]}))
        self.assertCodes({S})
        ids, errs = load_tombstoned_ids(self.tmp_root)
        self.assertEqual((ids, errs), ({"DEP-CLASS-F0"}, []))

    def test_tombstone_file_missing_fails_closed(self) -> None:
        """A missing stable_id_resolution.json fails closed (loader and checker)."""
        self.path(TS).unlink()
        ids, errs = load_tombstoned_ids(self.tmp_root)
        self.assertEqual(ids, set())
        self.assertEqual({e.code for e in errs}, {C})
        self.assertCodes({C})

    def test_tombstone_resolutions_not_list_fails_closed(self) -> None:
        """'resolutions' as a string, or entries that are not objects, fail closed with CORRUPT-FILE."""
        for body in ({"schema": "v1", "resolutions": "not a list"}, {"resolutions": [1, "x", None]}, {"resolutions": [{"status": "tombstoned"}]}):
            with self.subTest(body=body):
                self.write(TS, json.dumps(body))
                ids, errs = load_tombstoned_ids(self.tmp_root)
                self.assertEqual(ids, set())
                self.assertEqual({e.code for e in errs}, {C})

    def test_tombstone_file_corrupt_fails_closed(self) -> None:
        """A corrupt stable_id_resolution.json fails closed with CORRUPT-FILE, never swallowed."""
        self.write(TS, "{ corrupt json: [")
        self.assertCodes({C})

    def test_odd_class_resolutions_are_findings(self) -> None:
        """Case-variant, unknown or contradictory retirement records for class ids are TOMBSTONE-INVALID."""
        base = self.load(TS)
        for entry in (
            {"legacyId": "DEP-CLASS-F0", "status": "TOMBSTONED"},
            {"legacyId": "DEP-CLASS-F0", "status": "retired"},
            {"legacyId": "DEP-CLASS-F0", "status": "active", "disposition": "tombstoned"},
        ):
            with self.subTest(entry=entry):
                data = copy.deepcopy(base)
                data["resolutions"].append(entry)
                self.save(data, TS)
                self.assertCodes({dependency_authority.ERR_DEP_TOMBSTONE_INVALID})

    # --- Allowlist crosswalk --------------------------------------------------------------

    def test_allowlist_policy_flag_divergences_rejected(self) -> None:
        """All 16 allowlist flags, flipped, contradict the constitution crosswalk (and the allowlist pin)."""
        original = self.text(AL)
        live = dependency_authority.live_authority().allowlist["policy"]
        self.assertEqual(len(live), 16)
        for flag, value in live.items():
            with self.subTest(flag=flag):
                lit, neg = ("true", "false") if value else ("false", "true")
                self.write(AL, original.replace(f"{flag} = {lit}", f"{flag} = {neg}", 1))
                result = self.assertCodes({I, A})
                self.assertEqual([e.target for e in result.errors if e.code == I], [f"#/policy/{flag}"])

    def test_cross_check_allowlist_closed_universe_fails(self) -> None:
        """closed_universe = false contradicts production.closedUniverse."""
        self.replace(AL, "closed_universe = true", "closed_universe = false")
        self.assertCodes({I, A})

    def test_allowlist_dropping_ffmpeg_from_oracles_rejected(self) -> None:
        """Dropping ffmpeg or ffprobe from the oracle list breaks the F4 row split."""
        original = self.text(AL)
        for old, new in (('"ffmpeg", "ffprobe", "networkx"', '"ffprobe", "networkx"'), ('"ffmpeg", "ffprobe", "networkx"', '"ffmpeg", "networkx"')):
            with self.subTest(new=new):
                self.write(AL, original.replace(old, new, 1))
                self.assertCodes({I, A})

    def test_allowlist_adding_ffmpeg_to_in_house_rejected(self) -> None:
        """Adding ffmpeg or ffprobe to in_house.allowed_families is refused."""
        original = self.text(AL)
        for name in ("ffmpeg", "ffprobe"):
            with self.subTest(name=name):
                self.write(AL, original.replace('"asupersync",\n', f'"asupersync", "{name}",\n', 1))
                self.assertCodes({I, A})

    def test_allowlist_empty_forbidden_or_fundamental_rejected(self) -> None:
        """Emptying [forbidden].crates or [fundamental] (still pending fss-ndxis) is refused."""
        original = self.text(AL)
        forbidden_block = 'crates = [\n  "tokio", "async-std", "smol", "glommio", "monoio", "rayon",\n  "reqwest", "hyper", "rusqlite", "sqlx", "diesel", "rocksdb",\n  "pyo3", "opencv", "ffmpeg-next", "gstreamer", "ort", "tch"\n]'
        for label, tampered in (
            ("forbidden", original.replace(forbidden_block, "crates = []", 1)),
            ("fundamental", original.replace('allowed_subject_to_audit = ["serde", "serde_json"]', "allowed_subject_to_audit = []", 1)),
        ):
            with self.subTest(label):
                self.assertNotEqual(tampered, original)
                self.write(AL, tampered)
                self.assertCodes({I, A})

    # --- Dependency registry crosswalk -------------------------------------------------

    def row(self, data: dict[str, Any], dep_id: str) -> dict[str, Any]:
        return next(r for r in data["dependencies"] if r["id"] == dep_id)

    def test_cross_check_dep_lab_001_scope_production_fails(self) -> None:
        """DEP-LAB-001 with Production scope contradicts its quarantine class."""
        data = self.load(DJ)
        self.row(data, "DEP-LAB-001")["scope"] = "Production"
        self.save(data, DJ)
        self.assertCodes({I, D, F})

    def test_cross_check_constitution_f4_production_allowed_fails(self) -> None:
        """An F4 admission of 'production-helper-allowed' is refused, also by the F4-row crosswalk."""
        data = self.load()
        self.klass(data, "DEP-CLASS-F4")["admission"] = "production-helper-allowed"
        self.save(data, redigest=True)
        result = self.assertCodes({I, F, CD})
        self.assertTrue(any("not mapped to the quarantine class" in e.message for e in result.errors))

    def test_dependencies_scope_lowercase_production_rejected(self) -> None:
        """Scope 'production' (lowercase) is outside the scope vocabulary."""
        data = self.load(DJ)
        data["dependencies"][0]["scope"] = "production"
        self.save(data, DJ)
        self.assertCodes({I, D, F})

    def test_dependencies_scope_production_helper_rejected(self) -> None:
        """Scope 'Production helper' is outside the scope vocabulary."""
        data = self.load(DJ)
        data["dependencies"][0]["scope"] = "Production helper"
        self.save(data, DJ)
        self.assertCodes({I, D, F})

    def test_dependencies_relabel_f3_production_rejected(self) -> None:
        """An F3 row with plain 'Production' scope drops the audit condition."""
        data = self.load(DJ)
        self.row(data, "DEP-FUND-001")["scope"] = "Production"
        self.save(data, DJ)
        self.assertCodes({I, D, F})

    def test_dependencies_removed_constitution_class_rejected(self) -> None:
        """A row without constitutionClass is MISSING-FIELD and a crosswalk failure."""
        data = self.load(DJ)
        del data["dependencies"][0]["constitutionClass"]
        self.save(data, DJ)
        self.assertCodes({M, I, D, F})

    def test_dependencies_registry_missing_fails_closed(self) -> None:
        """A deleted dependencies.json is a CORRUPT-FILE finding, never skipped (N17)."""
        self.path(DJ).unlink()
        self.assertCodes({C})
        self.write(DJ, "{ not json")
        self.assertCodes({C})

    # --- Toolchain identity ---------------------------------------------------------------

    def toolchain(self, text: str | None = None, rustc: str = GOOD_RUSTC, rustc_rc: int = 0) -> list[tuple[str, str]]:
        if text is not None:
            self.write(TC, text)
        res = dependency_constitution_checker.ValidationResult()
        with patch("subprocess.run", side_effect=self.fake_run(rustc=rustc, rustc_rc=rustc_rc)):
            validate_toolchain_identity(self.tmp_root, res)
        return sorted((e.code, e.target) for e in res.errors)

    def test_toolchain_channel_stable_rejected(self) -> None:
        """channel = 'stable' is not a pinned dated nightly."""
        res = dependency_constitution_checker.ValidationResult()
        self.write(TC, '[toolchain]\nchannel = "stable"\nprofile = "minimal"\n')
        self.assertIsNone(validate_toolchain_identity(self.tmp_root, res))
        self.assertEqual(codes(res), {I})

    def test_toolchain_file_missing_fails_closed(self) -> None:
        """A missing rust-toolchain.toml fails closed with CORRUPT-FILE."""
        self.path(TC).unlink()
        res = dependency_constitution_checker.ValidationResult()
        self.assertIsNone(validate_toolchain_identity(self.tmp_root, res))
        self.assertEqual(codes(res), {C})

    def test_toolchain_file_unparseable_fails_closed(self) -> None:
        """An unparseable or invalid-UTF-8 rust-toolchain.toml fails closed with CORRUPT-FILE."""
        for body in (b"invalid toml [ [ [", b"\xff\xfe[toolchain]", b"", b'channel = "nightly-2026-08-31"\n'):
            with self.subTest(body=body):
                self.path(TC).write_bytes(body)
                res = dependency_constitution_checker.ValidationResult()
                self.assertIsNone(validate_toolchain_identity(self.tmp_root, res))
                self.assertEqual(codes(res), {C})

    def test_toolchain_identity_is_exact(self) -> None:
        """Release channel, pinned commit identity, host platform, components, targets and overrides."""
        good = self.text(TC)
        self.assertEqual(self.toolchain(), [])
        self.assertEqual(self.toolchain(rustc=GOOD_RUSTC.replace("x86_64-unknown-linux-gnu", "aarch64-apple-darwin")), [])
        stable = "rustc 1.80.0 (0123456 2024-01-01)\nbinary: rustc\ncommit-hash: 0123456789abcdef0123456789abcdef01234567\ncommit-date: 2024-01-01\nhost: x86_64-unknown-linux-gnu\nrelease: 1.80.0\n"
        self.assertEqual(self.toolchain(rustc=stable), [(I, "#/rustc/commit-date"), (I, "#/rustc/commit-hash"), (I, "#/rustc/release"), (I, "#/rustc/release")])
        other = GOOD_RUSTC.replace("908501772 2026-08-30", "dead00000 2025-01-01").replace("commit-date: 2026-08-30", "commit-date: 2025-01-01").replace("90850177249efe0321573c569aec5d12b257f8d6", "dead000000000000000000000000000000000000")
        self.assertEqual(self.toolchain(rustc=other), [(I, "#/rustc/commit-date"), (I, "#/rustc/commit-hash")])
        future = GOOD_RUSTC.replace("2026-08-30", "2026-09-05")
        self.assertEqual(self.toolchain(rustc=future), [(I, "#/rustc/commit-date"), (I, "#/rustc/commit-date")])
        for host in ("i686-pc-windows-gnu", "riscv64gc-unknown-linux-gnu", "x86_64-unknown-freebsd"):
            with self.subTest(host=host):
                self.assertEqual(self.toolchain(rustc=GOOD_RUSTC.replace("x86_64-unknown-linux-gnu", host)), [(I, "#/rustc/host")])
        for label, text in {
            "extra components": good.replace('"rust-src"]', '"rust-src", "miri", "rustc-dev"]'),
            "missing component": good.replace(', "rust-src"]', "]"),
        }.items():
            with self.subTest(label):
                self.assertEqual(self.toolchain(text), [(I, "#/toolchain/components")])
        self.assertEqual(self.toolchain(good + 'targets = ["wasm32-unknown-unknown"]\n'), [(I, "#/toolchain/targets")])
        self.assertEqual(self.toolchain(good.replace('"minimal"', '"complete"')), [(I, "#/toolchain/profile")])
        self.assertEqual(self.toolchain(good + 'path = "/opt/evil"\n'), [(C, "#/toolchain/path")])
        self.assertEqual(self.toolchain(good + "[extra]\nx = 1\n"), [(C, "#/extra")])
        for channel in ("nightly", "nightly-2026-09-01", "nightly-2026-02-30", "beta-2026-08-31"):
            with self.subTest(channel=channel):
                self.assertEqual(self.toolchain(good.replace("nightly-2026-08-31", channel)), [(I, "#/toolchain/channel")])
        self.write(TC, good)
        self.write("rust-toolchain", "stable\n")
        self.assertEqual(self.toolchain(), [(I, "#")])

    def test_rustc_execution_failures_are_exec_failed(self) -> None:
        """rustc that cannot run, times out, exits non-zero, or prints garbage is EXEC-FAILED."""
        for rustc, rc in (("garbage\n", 0), (GOOD_RUSTC.replace("host: x86_64-unknown-linux-gnu\n", ""), 0), ("", 0), (GOOD_RUSTC, 1),
                          (GOOD_RUSTC.replace("commit-hash: 90850177249efe0321573c569aec5d12b257f8d6", "commit-hash: 9085"), 0),
                          (GOOD_RUSTC + "host: aarch64-apple-darwin\n", 0)):
            with self.subTest(rustc=rustc[:30], rc=rc):
                self.assertEqual(self.toolchain(rustc=rustc, rustc_rc=rc), [(EX, "#")])
        for error in (subprocess.TimeoutExpired(cmd="rustc", timeout=30), FileNotFoundError("rustup")):
            with self.subTest(error=type(error).__name__):
                res = dependency_constitution_checker.ValidationResult()
                with patch("subprocess.run", side_effect=error):
                    self.assertIsNone(validate_toolchain_identity(self.tmp_root, res))
                self.assertEqual(sorted((e.code, e.target) for e in res.errors), [(EX, "#")])

    def test_toolchain_commands_are_bounded(self) -> None:
        """Both rustc -Vv and cargo metadata run with the named operational timeout (X11, X11b)."""
        self.assertEqual(TOOLCHAIN_COMMAND_TIMEOUT_SECONDS, 30)
        self.assertEqual(CARGO_METADATA_TIMEOUT_SECONDS, TOOLCHAIN_COMMAND_TIMEOUT_SECONDS)
        calls: list[Any] = []
        with patch("subprocess.run", side_effect=self.fake_run(calls=calls)):
            result = validate_dependency_constitution(self.tmp_root)
        self.assertEqual(codes(result), set())
        self.assertEqual(sorted(cmd[3] for cmd, _ in calls), ["cargo", "rustc"])
        for cmd, kwargs in calls:
            self.assertEqual(kwargs.get("timeout"), TOOLCHAIN_COMMAND_TIMEOUT_SECONDS, cmd)
            self.assertEqual(cmd[:3], ["rustup", "run", REQUIRED_RUST_CHANNEL])

    def test_toolchain_identity_runs_in_the_entry_point(self) -> None:
        """validate_dependency_constitution checks the toolchain file (N11): a stable channel fails."""
        self.write(TC, '[toolchain]\nchannel = "stable"\nprofile = "minimal"\ncomponents = ["rustfmt", "clippy", "rust-src"]\n')
        with patch("subprocess.run", side_effect=self.fake_run()):
            result = validate_dependency_constitution(self.tmp_root)
        self.assertEqual(codes(result), {I})

    # --- cargo metadata loading --------------------------------------------------------

    def test_mutant_m5_metadata_load_failure(self) -> None:
        """A cargo metadata load failure is EXEC-FAILED (execution failure, not a corrupt file)."""
        with patch("dependency_constitution_checker.load_real_cargo_metadata", return_value=(None, "cargo metadata failed")):
            result = validate_dependency_constitution(self.tmp_root, skip_cargo_metadata=False)
        self.assertEqual(codes(result), {EX})

    def test_cannot_run_cargo_reported_as_exec_failed_not_corrupt_file(self) -> None:
        """Formerly test_cannot_run_cargo_reported_as_corrupt_file (dcf1b4f); renamed to what it asserts: cannot-run cargo is EXEC-FAILED, never CORRUPT-FILE."""
        with patch("subprocess.run", side_effect=self.fake_run(cargo=FileNotFoundError("cargo not found"))):
            meta, meta_err = load_real_cargo_metadata(self.tmp_root)
            self.assertIsNone(meta)
            self.assertIn("cargo metadata execution error", meta_err or "")
            result = validate_dependency_constitution(self.tmp_root, skip_cargo_metadata=False)
        self.assertEqual(codes(result), {EX})

    def test_cannot_run_cargo_reported_as_exec_failed_not_metadata_violation(self) -> None:
        """Formerly test_cannot_run_cargo_reported_as_metadata_violation (f0a2beb, whose body was tautological); renamed to what it asserts: EXEC-FAILED, not METADATA-VIOLATION."""
        with patch("subprocess.run", side_effect=self.fake_run(cargo=OSError("exec format error"))):
            result = validate_dependency_constitution(self.tmp_root, skip_cargo_metadata=False)
        self.assertEqual(codes(result), {EX})
        self.assertNotIn(MV, codes(result))

    def test_cargo_metadata_non_json_output_rejected(self) -> None:
        """Non-JSON cargo metadata output is EXEC-FAILED (X5b)."""
        with patch("subprocess.run", side_effect=self.fake_run(cargo="not json at all")):
            meta, meta_err = load_real_cargo_metadata(self.tmp_root)
            self.assertIsNone(meta)
            self.assertIn("not valid JSON", meta_err or "")
            result = validate_dependency_constitution(self.tmp_root, skip_cargo_metadata=False)
        self.assertEqual(codes(result), {EX})

    def test_cargo_metadata_nonzero_exit_rejected(self) -> None:
        """A non-zero cargo exit is EXEC-FAILED, never empty metadata (X5b')."""
        with patch("subprocess.run", side_effect=self.fake_run(cargo=completed("{}", 101, "error: lock file needs update"))):
            meta, meta_err = load_real_cargo_metadata(self.tmp_root)
            self.assertEqual((meta, "exit code 101" in (meta_err or "")), (None, True))
            result = validate_dependency_constitution(self.tmp_root, skip_cargo_metadata=False)
        self.assertEqual(codes(result), {EX})

    def test_mutant_x11_cargo_metadata_timeout(self) -> None:
        """A cargo metadata timeout is EXEC-FAILED and the bound is the named 30s constant."""
        self.assertEqual(CARGO_METADATA_TIMEOUT_SECONDS, 30)
        with patch("subprocess.run", side_effect=self.fake_run(cargo=subprocess.TimeoutExpired(cmd="cargo", timeout=30))):
            meta, meta_err = load_real_cargo_metadata(self.tmp_root)
            self.assertIsNone(meta)
            self.assertIn("timed out after 30s", meta_err or "")
            result = validate_dependency_constitution(self.tmp_root, skip_cargo_metadata=False)
        self.assertEqual(codes(result), {EX})

    def test_unregistered_error_code_is_a_trace_finding(self) -> None:
        """Every code the constitution checker can emit must be registered in registries/ERRORS.md."""
        self.replace("registries/ERRORS.md", "| `ERR-DEP-EXEC-FAILED-001` |", "| `ERR-DEP-EXEC-FAILED-999` |")
        with patch("subprocess.run", side_effect=self.fake_run()):
            result = validate_dependency_constitution(self.tmp_root)
        self.assertEqual(codes(result), {ERR_DEP_TRACE_UNRESOLVED})

    # --- DEP-CLASS-F0 closure census ---------------------------------------------------

    def test_cargo_metadata_edition_violation_rejected(self) -> None:
        """A member declaring edition '2021' fails closed (edition derived from production.language)."""
        res = dependency_constitution_checker.ValidationResult()
        mock_metadata = {"packages": [{"name": "fss-core", "id": "fss-core 0.0.1", "edition": "2021", "manifest_path": f"{ROOT}/crates/fss-core/Cargo.toml", "links": None}], "workspace_members": ["fss-core 0.0.1"], "metadata": {"fss": {"production_language": "rust"}}}
        validate_cargo_metadata_for_f0(res, mock_metadata, ROOT)
        self.assertEqual(codes(res), {MV})
        self.assertTrue(any("must declare edition '2024'" in e.message for e in res.errors))
        self.assertIn((MV, "#fss-core/edition"), self.census(metadata([pkg("fss-core", member=True, edition="2021")], {})))

    def test_cargo_metadata_native_links_rejected(self) -> None:
        """A member declaring native links fails closed."""
        res = dependency_constitution_checker.ValidationResult()
        mock_metadata = {"packages": [{"name": "fss-core", "id": "fss-core 0.0.1", "edition": "2024", "manifest_path": f"{ROOT}/crates/fss-core/Cargo.toml", "links": "system_c_runtime"}], "workspace_members": ["fss-core 0.0.1"], "metadata": {"fss": {"production_language": "rust"}}}
        validate_cargo_metadata_for_f0(res, mock_metadata, ROOT)
        self.assertEqual(codes(res), {MV})
        self.assertTrue(any("declares native links" in e.message for e in res.errors))
        self.assertEqual(self.census(metadata([pkg("fss-core", member=True, links="c")], {})), [(MV, "#fss-core/links")])

    def test_cargo_metadata_production_language_violation(self) -> None:
        """Workspace metadata declaring a non-Rust production language fails closed."""
        res = dependency_constitution_checker.ValidationResult()
        mock_metadata = {"packages": [{"name": "fss-core", "id": "fss-core 0.0.1", "edition": "2024", "manifest_path": f"{ROOT}/crates/fss-core/Cargo.toml", "links": None}], "workspace_members": ["fss-core 0.0.1"], "metadata": {"fss": {"production_language": "python"}}}
        validate_cargo_metadata_for_f0(res, mock_metadata, ROOT)
        self.assertEqual(codes(res), {MV})
        self.assertTrue(any("production_language must be 'rust'" in e.message for e in res.errors))
        self.assertEqual(self.census(metadata([pkg("fss-core", member=True)], {}, fss={"production_language": "python"})), [(MV, "#/metadata/fss/production_language")])

    def test_cargo_metadata_list_root_handled_safely(self) -> None:
        """A JSON-list metadata root fails closed without AttributeError."""
        res = dependency_constitution_checker.ValidationResult()
        validate_cargo_metadata_for_f0(res, [{"package": 1}], ROOT)
        self.assertEqual(codes(res), {MV})
        self.assertTrue(any("must be a JSON object" in e.message for e in res.errors))

    def test_cargo_metadata_null_members_and_packages_handled_safely(self) -> None:
        """Null workspace_members/packages never raise and now FAIL CLOSED.

        Strengthened: dcf1b4f asserted this input passed, which the round-3 probe showed is fail-open.
        """
        res = dependency_constitution_checker.ValidationResult()
        validate_cargo_metadata_for_f0(res, {"packages": None, "workspace_members": None, "metadata": {"fss": {"production_language": "rust"}}}, ROOT)
        self.assertFalse(res.passed)
        self.assertEqual(sorted((e.code, e.target) for e in res.errors), [(MV, "#/packages"), (MV, "#/resolve"), (MV, "#/workspace_members")])

    def test_cargo_metadata_string_fss_metadata_handled_safely(self) -> None:
        """[workspace.metadata] fss = 'x' never raises and fails closed."""
        res = dependency_constitution_checker.ValidationResult()
        validate_cargo_metadata_for_f0(res, {"packages": [], "workspace_members": [], "metadata": {"fss": "corrupted-string"}}, ROOT)
        self.assertEqual(codes(res), {MV})
        self.assertTrue(any("production_language must be 'rust'" in e.message for e in res.errors))

    def test_f0_closure_unadmitted_crate_rejected(self) -> None:
        """libc (unlisted) in the closure fails closed."""
        res = dependency_constitution_checker.ValidationResult()
        validate_cargo_metadata_for_f0(res, {"packages": [{"name": "fss-core", "id": "fss-core 0.0.1", "edition": "2024", "manifest_path": f"{ROOT}/crates/fss-core/Cargo.toml", "links": None}, {"name": "libc", "id": "libc 0.2.140", "edition": "2021", "manifest_path": "/p/libc/Cargo.toml", "links": None}], "workspace_members": ["fss-core 0.0.1"], "metadata": {"fss": {"production_language": "rust"}}}, ROOT)
        self.assertEqual(codes(res), {MV})
        self.assertTrue(any("Unadmitted external crate 'libc'" in e.message for e in res.errors))

    def test_f0_closure_exception_candidate_blake3_rejected(self) -> None:
        """blake3 (exception candidate) is not admitted without a DEP record."""
        res = dependency_constitution_checker.ValidationResult()
        meta = {"packages": [{"name": "fss-core", "id": "fss-core 0.0.1", "edition": "2024", "manifest_path": f"{ROOT}/crates/fss-core/Cargo.toml", "links": None}, {"name": "blake3", "id": "blake3 1.5.0", "edition": "2021", "manifest_path": "/p/blake3/Cargo.toml", "links": None}], "workspace_members": ["fss-core 0.0.1"], "metadata": {"fss": {"production_language": "rust"}}}
        validate_cargo_metadata_for_f0(res, meta, ROOT, allow_data={"exception_candidates": {"not_admitted_without_dep_record_adr_and_release_evidence": ["blake3"]}})
        self.assertEqual(codes(res), {MV})
        self.assertTrue(any("Exception candidate 'blake3'" in e.message for e in res.errors))

    def test_f0_closure_custom_build_target_rejected(self) -> None:
        """A custom-build (build.rs) target fails closed."""
        res = dependency_constitution_checker.ValidationResult()
        validate_cargo_metadata_for_f0(res, {"packages": [{"name": "fss-core", "id": "fss-core 0.0.1", "edition": "2024", "manifest_path": f"{ROOT}/crates/fss-core/Cargo.toml", "links": None, "targets": [{"kind": ["custom-build"], "name": "build-script-build"}]}], "workspace_members": ["fss-core 0.0.1"], "metadata": {"fss": {"production_language": "rust"}}}, ROOT)
        self.assertEqual(codes(res), {MV})
        self.assertTrue(any("declares custom-build" in e.message for e in res.errors))

    def test_f0_closure_proc_macro_target_rejected(self) -> None:
        """A proc-macro target fails closed."""
        res = dependency_constitution_checker.ValidationResult()
        validate_cargo_metadata_for_f0(res, {"packages": [{"name": "fss-core", "id": "fss-core 0.0.1", "edition": "2024", "manifest_path": f"{ROOT}/crates/fss-core/Cargo.toml", "links": None, "targets": [{"kind": ["proc-macro"], "name": "fss-macros"}]}], "workspace_members": ["fss-core 0.0.1"], "metadata": {"fss": {"production_language": "rust"}}}, ROOT)
        self.assertEqual(codes(res), {MV})
        self.assertTrue(any("declares proc-macro" in e.message for e in res.errors))

    def test_non_member_forbidden_crate_in_closure_rejected(self) -> None:
        """tokio in the closure fails closed as a forbidden crate."""
        res = dependency_constitution_checker.ValidationResult()
        validate_cargo_metadata_for_f0(res, {"packages": [{"name": "fss-core", "id": "fss-core 0.0.1", "edition": "2024", "manifest_path": f"{ROOT}/crates/fss-core/Cargo.toml", "links": None}, {"name": "tokio", "id": "tokio 1.30.0", "edition": "2021", "manifest_path": "/p/tokio/Cargo.toml", "links": None}], "workspace_members": ["fss-core 0.0.1"], "metadata": {"fss": {"production_language": "rust"}}}, ROOT)
        self.assertEqual(codes(res), {MV})
        self.assertTrue(any("Forbidden crate 'tokio'" in e.message for e in res.errors))

    def test_non_member_native_links_in_closure_rejected(self) -> None:
        """A non-member crate declaring native links fails closed."""
        res = dependency_constitution_checker.ValidationResult()
        validate_cargo_metadata_for_f0(res, {"packages": [{"name": "fss-core", "id": "fss-core 0.0.1", "edition": "2024", "manifest_path": f"{ROOT}/crates/fss-core/Cargo.toml", "links": None}, {"name": "some-c-lib", "id": "some-c-lib 1.0.0", "edition": "2024", "manifest_path": "/p/c/Cargo.toml", "links": "clib"}], "workspace_members": ["fss-core 0.0.1"], "metadata": {"fss": {"production_language": "rust"}}}, ROOT)
        self.assertEqual(codes(res), {MV})
        self.assertTrue(any("Non-member package 'some-c-lib' in closure declares native links" in e.message for e in res.errors))

    def test_f0_census_targets_are_exact(self) -> None:
        """Each closure guard fires on its own target over a complete metadata graph (N1, N2, N16, reachability)."""
        core = pkg("fss-core", member=True)
        cases = {
            "tokio (forbidden)": ([pkg("tokio")], {"fss-core": [("tokio", None)]}, [(MV, "#tokio")]),
            "libc (unlisted)": ([pkg("libc")], {"fss-core": [("libc", None)]}, [(MV, "#libc")]),
            "libloading (unlisted)": ([pkg("libloading")], {"fss-core": [("libloading", None)]}, [(MV, "#libloading")]),
            "blake3 (exception)": ([pkg("blake3")], {"fss-core": [("blake3", None)]}, [(MV, "#blake3")]),
            "serde (pending, build.rs)": ([pkg("serde", kinds=("lib", "custom-build"))], {"fss-core": [("serde", None)]}, [(PD, "#serde"), (MV, "#serde/targets/custom-build")]),
            "serde_json dev-only (still pending)": ([pkg("serde_json")], {"fss-core": [("serde_json", "dev")]}, [(PD, "#serde_json")]),
            "serde_derive proc-macro": ([pkg("serde_derive", kinds=("proc-macro",))], {"fss-core": [("serde_derive", None)]}, [(MV, "#serde_derive"), (MV, "#serde_derive/targets/proc-macro")]),
            "ffmpeg dev-only oracle": ([pkg("ffmpeg")], {"fss-core": [("ffmpeg", "dev")]}, []),
            "ffmpeg dev-only with native links": ([pkg("ffmpeg", links="avcodec")], {"fss-core": [("ffmpeg", "dev")]}, [(MV, "#ffmpeg/links")]),
            "ffmpeg via build edge": ([pkg("ffmpeg")], {"fss-core": [("ffmpeg", "build")]}, [(MV, "#ffmpeg")]),
            "ffmpeg via dev then normal": ([pkg("media"), pkg("ffmpeg")], {"fss-core": [("media", None)], "media": [("ffmpeg", None)]}, [(MV, "#ffmpeg"), (MV, "#media")]),
            "opencv dev-only (forbidden + oracle)": ([pkg("opencv")], {"fss-core": [("opencv", "dev")]}, []),
            "opencv production": ([pkg("opencv")], {"fss-core": [("opencv", None)]}, [(MV, "#opencv")]),
            "fsqlite-core without gate": ([pkg("fsqlite-core")], {"fss-core": [("fsqlite-core", None)]}, [(MV, "#fsqlite-core")]),
            "ft-evil without gate": ([pkg("ft-evil")], {"fss-core": [("ft-evil", None)]}, [(MV, "#ft-evil")]),
            "openssl-sys": ([pkg("openssl-sys", links="openssl", kinds=("lib", "custom-build"))], {"fss-core": [("openssl-sys", None)]}, [(MV, "#openssl-sys"), (MV, "#openssl-sys/links"), (MV, "#openssl-sys/targets/custom-build")]),
            "unreachable package": ([pkg("orphan")], {}, [(MV, "#orphan"), (MV, "#orphan")]),
        }
        for label, (extra, edges, expected) in cases.items():
            with self.subTest(label):
                self.assertEqual(self.census(metadata([core] + extra, edges)), sorted(expected))
        members = {
            "member proc-macro": (pkg("fss-tensor", member=True, kinds=("proc-macro",)), [(MV, "#fss-tensor/targets/proc-macro")]),
            "member cdylib": (pkg("fss-model-ir", member=True, kinds=("lib",), crate_types=("cdylib",)), [(MV, "#fss-model-ir/targets/crate_types")]),
            "member build.rs": (pkg("fss-reference", member=True, kinds=("lib", "custom-build")), [(MV, "#fss-reference/targets/custom-build")]),
        }
        for label, (member, expected) in members.items():
            with self.subTest(label):
                self.assertEqual(self.census(metadata([core, member], {})), expected)
        registry_named_like_member = dict(pkg("fss-core"), id=f"{REGISTRY}#fss-core@9.9.9")
        self.assertEqual(self.census(metadata([core, registry_named_like_member], {"fss-core": [("fss-core", None)]}) if False else {
            "packages": [core, registry_named_like_member], "workspace_members": [core["id"]],
            "resolve": {"nodes": [{"id": core["id"], "deps": [{"pkg": registry_named_like_member["id"], "dep_kinds": [{"kind": None}]}]}, {"id": registry_named_like_member["id"], "deps": []}]},
            "metadata": {"fss": {"production_language": "rust"}},
        }), [(MV, "#fss-core")])

    def test_f0_census_malformed_metadata_never_raises(self) -> None:
        """Every traceback input from the round-3 probe becomes a registered finding."""
        registered = set(dependency_constitution_checker.CONSTITUTION_CHECKER_ERROR_CODES)
        core = pkg("fss-core", member=True)
        good = metadata([core, pkg("serde")], {"fss-core": [("serde", None)]})
        variants: dict[str, Any] = {
            "packages missing": {k: v for k, v in good.items() if k != "packages"},
            "packages dict": dict(good, packages={"tokio": {}}),
            "package entries not dicts": dict(good, packages=["tokio"]),
            "package without name": dict(good, packages=[core, {"id": "x 1.0.0", "links": None}]),
            "targets string": dict(good, packages=[core, dict(pkg("serde"), targets="custom-build")]),
            "kind string": dict(good, packages=[core, dict(pkg("serde"), targets=[{"kind": "proc-macro"}])]),
            "kind None": dict(good, packages=[core, dict(pkg("serde"), targets=[{"kind": None}])]),
            "kind int": dict(good, packages=[core, dict(pkg("serde"), targets=[{"kind": 5}])]),
            "name list": dict(good, packages=[core, dict(pkg("serde"), name=["tokio"])]),
            "name int": dict(good, packages=[core, dict(pkg("x"), name=5)]),
            "id list": dict(good, packages=[core, dict(pkg("serde"), id=["x"])]),
            "duplicate id": dict(good, packages=[core, core]),
            "workspace_members contains list": dict(good, workspace_members=[["x"]]),
            "member without package": dict(good, workspace_members=[core["id"], "ghost 1.0.0"]),
            "production_language list": dict(good, metadata={"fss": {"production_language": ["rust"]}}),
            "resolve nodes dict": dict(good, resolve={"nodes": {}}),
            "resolve edge without kinds": dict(good, resolve={"nodes": [{"id": core["id"], "deps": [{"pkg": "x"}]}]}),
            "resolve unknown package": dict(good, resolve={"nodes": [{"id": core["id"], "deps": [{"pkg": "ghost", "dep_kinds": [{"kind": None}]}]}]}),
            "source int": dict(good, packages=[core, dict(pkg("serde"), source=5)]),
        }
        for label, meta in variants.items():
            with self.subTest(label):
                res = dependency_constitution_checker.ValidationResult()
                validate_cargo_metadata_for_f0(res, meta, ROOT)
                self.assertFalse(res.passed)
                self.assertTrue(codes(res) <= registered, codes(res))
        for label, allow in {
            "forbidden [{a:1}]": {"forbidden": {"crates": [{"a": 1}]}},
            "forbidden string": {"forbidden": {"crates": "tokio"}},
            "families [5]": {"in_house": {"allowed_families": [5]}},
            "fundamental [[serde]]": {"fundamental": {"allowed_subject_to_audit": [["serde"]]}},
            "exception [{}]": {"exception_candidates": {"not_admitted_without_dep_record_adr_and_release_evidence": [{}]}},
        }.items():
            with self.subTest(label):
                res = dependency_constitution_checker.ValidationResult()
                validate_cargo_metadata_for_f0(res, metadata([core, pkg("tokio")], {"fss-core": [("tokio", None)]}), ROOT, allow_data=allow)
                self.assertEqual(sorted((e.code, e.target) for e in res.errors), [(MV, "#tokio")])

    # --- Unstable features ----------------------------------------------------------------

    def test_unstable_features_without_registry_are_findings(self) -> None:
        """#![feature(...)] is refused (no unstable-feature registry exists); comments and strings are masked."""
        src = self.tmp_root / "crates" / "fss-x" / "src"
        src.mkdir(parents=True)
        (src / "lib.rs").write_text("#![forbid(unsafe_code)]\n// #![feature(never)]\npub const S: &str = \"#![feature(x)]\";\n", encoding="utf-8")
        res = dependency_constitution_checker.ValidationResult()
        self.assertEqual(scan_unstable_features(self.tmp_root, res), 1)
        self.assertEqual(res.errors, [])
        (src / "simd.rs").write_text("#![feature(portable_simd)]\n", encoding="utf-8")
        (src / "bad.rs").write_bytes(b"\xff")
        res = dependency_constitution_checker.ValidationResult()
        scan_unstable_features(self.tmp_root, res)
        self.assertEqual(sorted((e.code, e.file_path, e.target) for e in res.errors), [(C, "crates/fss-x/src/bad.rs", "#"), (ERR_DEP_UNSTABLE_FEATURE, "crates/fss-x/src/simd.rs", "line/1")])
        with patch("subprocess.run", side_effect=self.fake_run()):
            result = validate_dependency_constitution(self.tmp_root)
        self.assertEqual(codes(result), {C, ERR_DEP_UNSTABLE_FEATURE})

    def test_pinned_baselines_are_views_of_the_authority(self) -> None:
        """The checker's baselines are the authority's pins, and the constitution matches them."""
        live = json.loads((ROOT / CJ).read_text(encoding="utf-8"))
        self.assertEqual(CANONICAL_CONSTITUTION_CLASSES, {c["id"]: c for c in live["classes"]})
        self.assertEqual(REQUIRED_PRODUCTION_VALUES, live["production"])
        self.assertIs(CANONICAL_CONSTITUTION_CLASSES, dependency_authority.PINNED_CONSTITUTION_CLASSES[BASELINE_DEPENDENCY_CONSTITUTION_GENERATION])
        self.assertEqual(ERR_DEP_REGISTRY_DRIFT, "ERR-DEP-REGISTRY-DRIFT-001")
        self.assertNotEqual(ERR_DEP_CONST_DRIFT, ERR_DEP_REGISTRY_DRIFT)
        self.assertNotEqual(ERR_DEP_EXEC_FAILED, ERR_DEP_CORRUPT_FILE)


class TestRoundTwoConstitutionFindings(ConstitutionCase):
    """Round-2 review findings i-l of fss-x4a.30.88.16 (exact findings per scenario)."""

    LQ = "architecture/local_qualification.toml"
    toolchain = TestDependencyConstitutionChecker.toolchain

    def uf(self) -> list[tuple[str, str, str]]:
        res = dependency_constitution_checker.ValidationResult()
        scan_unstable_features(self.tmp_root, res)
        return sorted((e.code, e.file_path, e.target) for e in res.errors)

    def put(self, rel: str, text: str) -> None:
        self.path(rel).parent.mkdir(parents=True, exist_ok=True)
        self.write(rel, text)

    # --- i: unstable features -------------------------------------------------------------

    def test_i_cfg_attr_and_spaced_feature_attributes_are_findings(self) -> None:
        """cfg_attr-wrapped (nested, multi-attribute, multi-line) and spaced #![feature] are refused; lookalikes are not."""
        self.put("crates/fss-x/src/lib.rs", "\n".join([
            "#![forbid(unsafe_code)]",
            "#![cfg_attr(all(), feature(x))]",
            "#![cfg_attr(unix, cfg_attr(all(), feature(y)))]",
            "# ! [ feature ( z ) ]",
            '#![cfg_attr(feature = "std", no_std)]',
            "#![cfg_attr(all(), forbid(unsafe_code), feature(w))]",
            '#[cfg(feature = "x")]',
            "fn f() {}",
            "// #![cfg_attr(all(), feature(q))]",
            "#![cfg_attr(",
            "    all(),",
            "    feature(multi)",
            ")]",
            'pub const S: &str = "#![cfg_attr(all(), feature(s))]";',
            "",
        ]))
        U, f = ERR_DEP_UNSTABLE_FEATURE, "crates/fss-x/src/lib.rs"
        self.assertEqual(self.uf(), [(U, f, "line/10"), (U, f, "line/2"), (U, f, "line/3"), (U, f, "line/4"), (U, f, "line/6")])
        self.assertTrue(dependency_constitution_checker.attribute_enables_feature("cfg_attr(any(), feature(a))"))
        self.assertFalse(dependency_constitution_checker.attribute_enables_feature('cfg_attr(feature = "a", no_std)'))
        self.assertFalse(dependency_constitution_checker.attribute_enables_feature("featured(a)"))

    def test_i_only_the_workspace_target_dir_is_skipped(self) -> None:
        """A crate root under src/target/ is scanned; the workspace's own target/ directory is not."""
        self.put("crates/fss-x/src/target/mod.rs", "#![feature(hidden)]\n")
        self.put("crates/target/src/lib.rs", "#![feature(hidden_crate)]\n")
        self.put("target/debug/build/out.rs", "#![feature(generated)]\n")
        self.assertEqual(self.uf(), [(ERR_DEP_UNSTABLE_FEATURE, "crates/fss-x/src/target/mod.rs", "line/1"), (ERR_DEP_UNSTABLE_FEATURE, "crates/target/src/lib.rs", "line/1")])

    def test_i_cargo_config_rustflags_and_unstable_tables_are_findings(self) -> None:
        """-Z in .cargo/config[.toml] rustflags/rustdocflags/env (any nesting) and any [unstable] table are refused."""
        self.put(".cargo/config.toml", "\n".join([
            "[build]",
            'rustflags = ["-C", "target-cpu=native", "-Zcrate-attr=feature(x)"]',
            "[target.x86_64-unknown-linux-gnu]",
            'rustflags = "-Z crate-attr=feature(y)"',
            "[env]",
            'RUSTFLAGS = { value = "-Zshare-generics", force = true }',
            "[unstable]",
            'build-std = ["std"]',
            "",
        ]))
        self.put("crates/fss-x/.cargo/config", '[build]\nrustdocflags = ["-Zunstable-options"]\n')
        self.put("crates/fss-y/.cargo/config.toml", '[build]\nrustflags = ["-C", "opt-level=3"]\n')
        U, c = ERR_DEP_UNSTABLE_FEATURE, ".cargo/config.toml"
        self.assertEqual(self.uf(), sorted([(U, c, "#/build.rustflags"), (U, c, "#/target.x86_64-unknown-linux-gnu.rustflags"), (U, c, "#/env.RUSTFLAGS"), (U, c, "#/unstable"), (U, "crates/fss-x/.cargo/config", "#/build.rustdocflags")]))
        self.put(".cargo/config.toml", "[build\n")
        self.assertIn((C, ".cargo/config.toml", "#"), self.uf())

    def test_i_manifests_env_files_scripts_and_build_scripts_are_findings(self) -> None:
        """cargo-features, profile -Z rustflags, RUSTFLAGS in .env/shell files, cargo -Z in shell, and -Z literals in build.rs."""
        self.put("crates/fss-x/Cargo.toml", 'cargo-features = ["codegen-backend"]\n[package]\nname = "fss-x"\n[profile.release]\nrustflags = ["-Zshare-generics"]\n')
        self.put(".env", 'RUSTFLAGS="-Zcrate-attr=feature(x)"\n# RUSTFLAGS="-Zcommented"\nCARGO_ENCODED_RUSTFLAGS=-Zfoo\nOTHER="-Zignored-not-a-flag-variable"\n')
        self.put("scripts/build.sh", '#!/bin/bash\nexport RUSTFLAGS="-C opt-level=3"\nRUSTFLAGS="$RUSTFLAGS -Zcrate-attr=feature(x)" cargo build\ncargo build -Zbuild-std\ncase "$x" in *[!A-Za-z0-9._+-]*) ;; esac\n')
        self.put("crates/fss-x/build.rs", 'fn main() {\n    println!("cargo:rustc-env=RUSTFLAGS=-Zcrate-attr=feature(x)");\n    println!("cargo:rerun-if-changed=build.rs");\n}\n')
        U = ERR_DEP_UNSTABLE_FEATURE
        self.assertEqual(self.uf(), sorted([
            (U, "crates/fss-x/Cargo.toml", "#/cargo-features"), (U, "crates/fss-x/Cargo.toml", "#/profile/rustflags"),
            (U, ".env", "line/1"), (U, ".env", "line/3"),
            (U, "scripts/build.sh", "line/3"), (U, "scripts/build.sh", "line/4"),
            (U, "crates/fss-x/build.rs", "line/2"),
        ]))

    def test_i_scan_runs_in_the_entry_point(self) -> None:
        """A config-level -Z bypass fails the full constitution check, not only the scanner."""
        self.put(".cargo/config.toml", '[build]\nrustflags = ["-Zcrate-attr=feature(x)"]\n')
        with patch("subprocess.run", side_effect=self.fake_run()):
            result = validate_dependency_constitution(self.tmp_root)
        self.assertEqual(codes(result), {ERR_DEP_UNSTABLE_FEATURE})

    # --- j: workspace members ---------------------------------------------------------------

    def test_j_members_must_be_declared_in_topology_and_explicit(self) -> None:
        """An implicit or undeclared workspace member is a METADATA-VIOLATION even though cargo lists it."""
        core = pkg("fss-core", member=True)
        rogue = pkg("fss-rogue", member=True)
        undeclared_dir = pkg("fss-api", member=True)
        nested = dict(pkg("evil", member=True), manifest_path=f"{ROOT}/crates/fss-core/vendor/evil/Cargo.toml")
        outside = dict(pkg("fss-cli", member=True), manifest_path="/elsewhere/fss-cli/Cargo.toml")
        self.assertEqual(self.census(metadata([core], {})), [])
        self.assertEqual(self.census(metadata([core, rogue], {})), [(MV, "#fss-rogue/topology"), (MV, "#fss-rogue/workspace-member")])
        self.assertEqual(self.census(metadata([core, undeclared_dir], {})), [(MV, "#fss-api/workspace-member")])
        self.assertEqual(self.census(metadata([core, nested], {})), [(MV, "#evil/topology"), (MV, "#evil/workspace-member")])
        self.assertEqual(self.census(metadata([core, outside], {})), [(MV, "#fss-cli/workspace-member")])

    def test_j_member_contract_inputs_fail_closed(self) -> None:
        """A corrupt topology or a root manifest without [workspace].members fails closed."""
        meta = json.loads(json.dumps(metadata([pkg("fss-core", member=True)], {})).replace(f"{ROOT}/", f"{self.tmp_root}/"))
        res = dependency_constitution_checker.ValidationResult()
        validate_cargo_metadata_for_f0(res, meta, self.tmp_root)
        self.assertEqual(res.errors, [])
        self.write("architecture/crate_topology.json", "{ not json")
        res = dependency_constitution_checker.ValidationResult()
        validate_cargo_metadata_for_f0(res, meta, self.tmp_root)
        self.assertEqual(sorted((e.code, e.file_path) for e in res.errors), [(C, "architecture/crate_topology.json")])
        shutil.copy2(ROOT / "architecture/crate_topology.json", self.path("architecture/crate_topology.json"))
        cargo = self.text("Cargo.toml")
        start = cargo.index("members = [")
        self.write("Cargo.toml", cargo[:start] + cargo[cargo.index("]", start) + 1:])
        res = dependency_constitution_checker.ValidationResult()
        validate_cargo_metadata_for_f0(res, meta, self.tmp_root)
        self.assertEqual(sorted((e.code, e.file_path, e.target) for e in res.errors), [(MV, "Cargo.toml", "#/workspace/members")])

    def test_j_implicit_member_fails_the_entry_point(self) -> None:
        """cargo metadata naming an implicit in-repository member fails validate_dependency_constitution."""
        payload = json.dumps(metadata([pkg("fss-core", member=True), pkg("fss-rogue", member=True)], {}))
        with patch("subprocess.run", side_effect=self.fake_run(cargo=payload)):
            result = validate_dependency_constitution(self.tmp_root)
        self.assertEqual(sorted((e.code, e.target) for e in result.errors), [(MV, "#fss-rogue/topology"), (MV, "#fss-rogue/workspace-member")])

    # --- k: toolchain identity single-sourced -------------------------------------------------

    def test_k_identity_comes_from_local_qualification(self) -> None:
        """Editing only local_qualification.toml changes what rustc -Vv must report; no code-side table exists."""
        self.assertFalse(hasattr(dependency_constitution_checker, "PINNED_TOOLCHAIN_IDENTITIES"))
        self.assertFalse(hasattr(dependency_constitution_checker, "host_platform_scope"))
        self.assertEqual(REQUIRED_RUST_CHANNEL, tomllib.loads((ROOT / self.LQ).read_text(encoding="utf-8"))["toolchain"]["channel"])
        good = self.text(self.LQ)
        for label, old, new, expected in (
            ("hash", 'rustc_commit_hash = "90850177249efe0321573c569aec5d12b257f8d6"', 'rustc_commit_hash = "' + "ab" * 20 + '"', [(I, "#/rustc/commit-hash")]),
            ("release", 'rustc_release = "1.100.0-nightly"', 'rustc_release = "1.99.0-nightly"', [(I, "#/rustc/release")]),
            ("date", 'rustc_commit_date = "2026-08-30"', 'rustc_commit_date = "2026-08-29"', [(I, "#/rustc/commit-date")]),
            ("channel", 'channel = "nightly-2026-08-31"', 'channel = "nightly-2026-08-30"', [(I, "#/toolchain/channel")]),
            ("linux triple removed", '"x86_64-unknown-linux-gnu" = "linux-x86_64"\n', "", [(I, "#/rustc/host")]),
            ("triple mapped to an unregistered scope", '"x86_64-unknown-linux-gnu" = "linux-x86_64"', '"x86_64-unknown-linux-gnu" = "linux-riscv"', [(I, "#/rustc/host"), (I, "#/toolchain/host_triples/x86_64-unknown-linux-gnu")]),
        ):
            with self.subTest(label):
                self.write(self.LQ, good.replace(old, new, 1))
                self.assertNotEqual(self.text(self.LQ), good)
                self.assertEqual(self.toolchain(), expected)
        self.write(self.LQ, good.replace('"aarch64-apple-darwin" = "darwin-arm64"', '"aarch64-apple-darwin" = "darwin-arm64"\n"x86_64-unknown-freebsd" = "linux-x86_64"', 1))
        self.assertEqual(self.toolchain(rustc=GOOD_RUSTC.replace("x86_64-unknown-linux-gnu", "x86_64-unknown-freebsd")), [])

    def test_k_consistent_bump_needs_only_data(self) -> None:
        """Moving both rust-toolchain.toml and local_qualification.toml to a new identity passes with no code change."""
        self.write(TC, self.text(TC).replace("nightly-2026-08-31", "nightly-2026-09-10"))
        self.write(self.LQ, self.text(self.LQ).replace('channel = "nightly-2026-08-31"', 'channel = "nightly-2026-09-10"').replace("1.100.0-nightly", "1.101.0-nightly").replace("90850177249efe0321573c569aec5d12b257f8d6", "ab" * 20).replace('rustc_commit_date = "2026-08-30"', 'rustc_commit_date = "2026-09-09"'))
        bumped = GOOD_RUSTC.replace("1.100.0-nightly", "1.101.0-nightly").replace("908501772 2026-08-30", "ababababa 2026-09-09").replace("90850177249efe0321573c569aec5d12b257f8d6", "ab" * 20).replace("commit-date: 2026-08-30", "commit-date: 2026-09-09")
        self.assertEqual(self.toolchain(rustc=bumped), [])
        self.assertEqual(self.toolchain(), [(I, "#/rustc/commit-date"), (I, "#/rustc/commit-hash"), (I, "#/rustc/release")])

    def test_k_toolchain_contract_fails_closed(self) -> None:
        """A missing, mistyped or malformed identity key in local_qualification.toml is refused, never defaulted."""
        good = self.text(self.LQ)
        windows = '"x86_64-pc-windows-msvc" = "windows-x86_64"\n'
        for label, text, expected in (
            ("no channel", good.replace('channel = "nightly-2026-08-31"\n', "", 1), [(M, "#/toolchain/channel")]),
            ("no host table", good[:good.index("[toolchain.host_triples]")] + good[good.index(windows) + len(windows):], [(M, "#/toolchain/host_triples")]),
            ("hash not hex", good.replace("90850177249efe0321573c569aec5d12b257f8d6", "not-a-hash"), [(C, "#/toolchain")]),
            ("stable channel", good.replace('channel = "nightly-2026-08-31"', 'channel = "stable"', 1), [(I, "#/toolchain/channel")]),
        ):
            with self.subTest(label):
                self.write(self.LQ, text)
                res = dependency_constitution_checker.ValidationResult()
                with patch("subprocess.run", side_effect=self.fake_run()):
                    self.assertIsNone(validate_toolchain_identity(self.tmp_root, res))
                self.assertEqual(sorted((e.code, e.target) for e in res.errors), expected)
        self.write(self.LQ, good.replace('channel = "nightly-2026-08-31"', "channel = 5", 1))
        res = dependency_constitution_checker.ValidationResult()
        with patch("subprocess.run", side_effect=self.fake_run()):
            self.assertIsNone(validate_toolchain_identity(self.tmp_root, res))
        self.assertTrue(res.errors and all(e.file_path == self.LQ for e in res.errors), [(e.code, e.target) for e in res.errors])

    def test_k_check_policy_compares_the_channel(self) -> None:
        """check-policy refuses a rust-toolchain.toml channel that differs from the accepted channel."""
        import importlib.util
        spec = importlib.util.spec_from_file_location("check_policy_k", ROOT / "scripts" / "check-policy.py")
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        constitution = json.loads((ROOT / CJ).read_text(encoding="utf-8"))
        localq = tomllib.loads((ROOT / self.LQ).read_text(encoding="utf-8"))
        toolchain = tomllib.loads((ROOT / TC).read_text(encoding="utf-8"))["toolchain"]
        policy = tomllib.loads((ROOT / AL).read_text(encoding="utf-8"))
        state = dependency_authority.load_authority(ROOT)
        module.errors.clear()
        module.dependency_policy_consistency(constitution, localq, toolchain, policy, state)
        self.assertEqual(module.errors, [])
        module.dependency_policy_consistency(constitution, localq, dict(toolchain, channel="nightly-2026-09-01"), policy, state)
        self.assertEqual(len(module.errors), 1)
        self.assertIn("differs from the accepted channel", module.errors[0])

    # --- l: the two constitution copies ----------------------------------------------------------

    def test_l_editing_either_copy_alone_is_drift(self) -> None:
        """The docs copy must be byte-identical to DEPENDENCY_CONSTITUTION.md; editing either alone fails."""
        root_copy = "DEPENDENCY_CONSTITUTION.md"
        original = self.text(MD)
        self.assertEqual(original, self.text(root_copy))
        self.assertCodes(set())
        self.write(MD, original + "\nEditorial note.\n")
        result = self.assertCodes({CD})
        self.assertEqual([(e.file_path, e.target) for e in result.errors], [(root_copy, "#")])
        self.write(MD, original)
        self.write(root_copy, original.replace("# ", "#  ", 1))
        self.assertCodes({CD})
        self.write(root_copy, original + "\nEditorial note.\n")
        self.write(MD, original + "\nEditorial note.\n")
        self.assertCodes(set())
        self.path(root_copy).unlink()
        self.assertCodes({C})
        self.path(root_copy).symlink_to(self.path(MD))
        self.assertCodes({C})

    # --- Cargo.lock is read through the bounded reader before cargo runs -------------------------

    def test_oversized_symlinked_or_missing_lock_fails_before_cargo(self) -> None:
        """An oversized, symlinked or missing Cargo.lock is CORRUPT-FILE and cargo metadata never runs."""
        lock = self.path("Cargo.lock")
        real = self.tmp_root / "real.lock"
        real.write_bytes((ROOT / "Cargo.lock").read_bytes())
        for label in ("oversized", "symlink", "missing"):
            with self.subTest(label):
                lock.unlink(missing_ok=True)
                if label == "oversized":
                    lock.write_bytes(b"#" * (dependency_authority.MAX_INPUT_FILE_BYTES + 1))
                elif label == "symlink":
                    lock.symlink_to(real)
                calls: list[Any] = []
                with patch("subprocess.run", side_effect=self.fake_run(calls=calls)):
                    result = validate_dependency_constitution(self.tmp_root)
                self.assertEqual(sorted((e.code, e.file_path) for e in result.errors), [(C, "Cargo.lock")])
                self.assertEqual([cmd[3] for cmd, _ in calls], ["rustc"])


class TestRoundThreeConstitutionFindings(ConstitutionCase):
    """Round-3 review findings i and k of fss-x4a.30.88.16 (exact findings per scenario)."""

    LQ = "architecture/local_qualification.toml"
    toolchain = TestDependencyConstitutionChecker.toolchain
    uf = TestRoundTwoConstitutionFindings.uf
    put = TestRoundTwoConstitutionFindings.put

    # --- i: unstable features in rustdoc code blocks (doctests are compiled) -------------------

    def test_i_doctest_code_blocks_are_scanned(self) -> None:
        self.put("crates/fss-x/src/lib.rs", "\n".join([
            "//! Crate docs.",
            "//! ```",
            "//! #![feature(never_type)]",
            "//! ```",
            "/// ```rust,no_run",
            "/// # #![feature(hidden)]",
            "/// fn f() {}",
            "/// ```",
            "/// ```text",
            "/// #![feature(not_code)]",
            "/// ```",
            "/**",
            " * ```",
            " * #![cfg_attr(all(), feature(block))]",
            " * ```",
            " */",
            "//// ```",
            "//// #![feature(not_a_doc_comment)]",
            "//// ```",
            "pub fn f() {}",
            "",
        ]))
        self.put("crates/fss-x/src/doc_attr.rs", '#![doc = "#![feature(never_type)] is not used here"]\n')
        U, f = ERR_DEP_UNSTABLE_FEATURE, "crates/fss-x/src/lib.rs"
        self.assertEqual(self.uf(), [(U, f, "line/14"), (U, f, "line/3"), (U, f, "line/6")])
        self.assertEqual([[line for line, _ in block] for block in dependency_constitution_checker.doctest_blocks("/// ~~~\n/// #![feature(x)]\n/// ~~~\n")], [[2]])

    # --- i: cargo config aliases, compiler overrides, include, RUSTC_BOOTSTRAP ---------------------

    def test_i_cargo_config_alias_override_include_and_bootstrap(self) -> None:
        self.put(".cargo/config.toml", "\n".join([
            'include = ["extra.cfg"]',
            "[alias]",
            'b = "build -Zbuild-std"',
            'c = ["check", "-Z", "unstable-options"]',
            'ok = "build --release"',
            "[build]",
            'rustc-wrapper = "tools-wrap"',
            'rustc = "/opt/rustc"',
            "[target.x86_64-unknown-linux-gnu]",
            'rustdoc = "/opt/rustdoc"',
            "[env]",
            'RUSTC_BOOTSTRAP = "1"',
            'RUSTC_WRAPPER = "w"',
            "",
        ]))
        U, c = ERR_DEP_UNSTABLE_FEATURE, ".cargo/config.toml"
        self.assertEqual(self.uf(), sorted([
            (U, c, "#/include"), (U, c, "#/alias.b"), (U, c, "#/alias.c"), (U, c, "#/env.RUSTC_BOOTSTRAP"),
            (I, c, "#/build.rustc-wrapper"), (I, c, "#/build.rustc"), (I, c, "#/target.x86_64-unknown-linux-gnu.rustdoc"), (I, c, "#/env.RUSTC_WRAPPER"),
        ]))

    def test_i_makefile_justfile_and_env_files(self) -> None:
        self.put("Makefile", "unstable:\n\tcargo build -Zunstable-options\nok:\n\tcargo build --release\n# cargo build -Zcommented\n")
        self.put("justfile", "build:\n    cargo build -Zunstable-options\n")
        self.put("tools/build.mk", "all:\n\tRUSTC_BOOTSTRAP=1 cargo build\n")
        self.put(".envrc", 'export RUSTC_BOOTSTRAP=1\nexport RUSTC_WRAPPER=/opt/wrap\nexport RUSTFLAGS="-Z crate-attr=feature(x)"\nexport FSS_LOG=info\n')
        U = ERR_DEP_UNSTABLE_FEATURE
        self.assertEqual(self.uf(), sorted([
            (U, "Makefile", "line/2"), (U, "justfile", "line/2"), (U, "tools/build.mk", "line/2"),
            (U, ".envrc", "line/1"), (I, ".envrc", "line/2"), (U, ".envrc", "line/3"),
        ]))

    def test_i_nested_toolchain_files_are_refused(self) -> None:
        self.put("crates/fss-core/rust-toolchain.toml", '[toolchain]\nchannel = "nightly-2026-09-10"\n')
        self.put("crates/fss-x/rust-toolchain", "nightly-2026-09-10\n")
        self.assertEqual(self.uf(), [(I, "crates/fss-core/rust-toolchain.toml", "#"), (I, "crates/fss-x/rust-toolchain", "#")])

    def test_i_toolchain_bypasses_fail_the_entry_point(self) -> None:
        self.put("crates/fss-core/rust-toolchain.toml", '[toolchain]\nchannel = "nightly-2026-09-10"\n')
        self.put(".cargo/config.toml", '[build]\nrustc-wrapper = "tools-wrap"\n')
        with patch("subprocess.run", side_effect=self.fake_run()):
            result = validate_dependency_constitution(self.tmp_root)
        self.assertEqual(sorted((e.file_path, e.target) for e in result.errors), [(".cargo/config.toml", "#/build.rustc-wrapper"), ("crates/fss-core/rust-toolchain.toml", "#")])
        self.assertEqual(codes(result), {I})

    # --- i-low: member target sources ---------------------------------------------------------------

    def test_i_member_target_sources_must_be_scanned_repository_files(self) -> None:
        core = pkg("fss-core", member=True)

        def with_bin(src: str) -> dict[str, Any]:
            return dict(core, targets=[{"kind": ["lib"], "crate_types": ["lib"], "name": "fss_core", "src_path": f"{ROOT}/crates/fss-core/src/lib.rs"},
                                       {"kind": ["bin"], "crate_types": ["bin"], "name": "fss-core-x", "src_path": src}])

        self.assertEqual(self.census(metadata([with_bin(f"{ROOT}/crates/fss-core/src/bin/x.rs")], {})), [])
        for label, src in {
            "unscanned tool directory": f"{ROOT}/.ntm/x.rs",
            "workspace target directory": f"{ROOT}/target/x.rs",
            "outside the repository": "/elsewhere/outside_root.rs",
        }.items():
            with self.subTest(label):
                self.assertEqual(self.census(metadata([with_bin(src)], {})), [(MV, "#fss-core/targets/fss-core-x/src_path")])

    def test_i_member_target_source_in_a_git_ignored_path(self) -> None:
        """Self-contained (independent of the checkout having .git): a repository whose .gitignore covers
        the target source, decided by git check-ignore."""
        import shutil as _shutil
        if _shutil.which("git") is None:
            self.skipTest("git is not installed")
        subprocess.run(["git", "init", "-q", str(self.tmp_root)], check=True, capture_output=True)
        self.write(".gitignore", "/captures/\n")
        core = pkg("fss-core", member=True)

        def census_with(src: str) -> list[tuple[str, str]]:
            meta = metadata([dict(core, targets=[{"kind": ["bin"], "crate_types": ["bin"], "name": "fss-core-x", "src_path": src}])], {})
            meta = json.loads(json.dumps(meta).replace(f"{ROOT}/", f"{self.tmp_root}/"))
            res = dependency_constitution_checker.ValidationResult()
            validate_cargo_metadata_for_f0(res, meta, self.tmp_root)
            return sorted((e.code, e.target) for e in res.errors)

        self.assertEqual(census_with(f"{ROOT}/crates/fss-core/src/bin/x.rs"), [])
        self.assertEqual(census_with(f"{ROOT}/captures/x.rs"), [(MV, "#fss-core/targets/fss-core-x/src_path")])

    # --- k: every host triple ------------------------------------------------------------------------

    def test_k_every_host_triple_is_validated(self) -> None:
        """An unregistered scope anywhere in host_triples fails, even when the running host is fine."""
        good = self.text(self.LQ)
        self.write(self.LQ, good.replace('"x86_64-pc-windows-msvc" = "windows-x86_64"', '"x86_64-pc-windows-msvc" = "windows-x86_64"\n"riscv64gc-unknown-linux-gnu" = "linux-riscv"', 1))
        self.assertEqual(self.toolchain(), [(I, "#/toolchain/host_triples/riscv64gc-unknown-linux-gnu")])
        self.write(self.LQ, good.replace('"aarch64-apple-darwin" = "darwin-arm64"', '"aarch64-apple-darwin" = "darwin-arm65"', 1))
        self.assertEqual(self.toolchain(), [(I, "#/toolchain/host_triples/aarch64-apple-darwin")])
        self.write(self.LQ, good)
        self.assertEqual(self.toolchain(), [])


class TestRoundFourConstitutionFindings(ConstitutionCase):
    """Round-4 (final) findings 1-4 of fss-x4a.30.88.16 (exps3.py rows n2b, n2c, n3a-e, n4a, n4c, n4d)."""

    toolchain = TestDependencyConstitutionChecker.toolchain
    uf = TestRoundTwoConstitutionFindings.uf
    put = TestRoundTwoConstitutionFindings.put

    # --- 1: RUSTUP_TOOLCHAIN and CARGO_UNSTABLE_* in env files and config [env] ---------------

    def test_rustup_toolchain_and_cargo_unstable_env_files(self) -> None:
        self.put(".envrc", "export RUSTUP_TOOLCHAIN=nightly-2026-09-10\nexport CARGO_UNSTABLE_BUILD_STD=std\nexport FSS_LOG=info\n")
        self.put(".env", "CARGO_UNSTABLE_BUILD_STD=std\n# RUSTUP_TOOLCHAIN=commented\n")
        U, I2 = ERR_DEP_UNSTABLE_FEATURE, ERR_DEP_CONST_INVARIANT
        self.assertEqual(self.uf(), sorted([(I2, ".envrc", "line/1"), (U, ".envrc", "line/2"), (U, ".env", "line/1")]))

    def test_cargo_unstable_and_rustup_toolchain_in_config_env(self) -> None:
        self.put(".cargo/config.toml", '[env]\nRUSTUP_TOOLCHAIN = "nightly-2026-09-10"\nCARGO_UNSTABLE_BUILD_STD = "std"\nFSS_LOG = "info"\n')
        U, I2 = ERR_DEP_UNSTABLE_FEATURE, ERR_DEP_CONST_INVARIANT
        self.assertEqual(self.uf(), sorted([(I2, ".cargo/config.toml", "#/env.RUSTUP_TOOLCHAIN"), (U, ".cargo/config.toml", "#/env.CARGO_UNSTABLE_BUILD_STD")]))

    # --- 2: literal toolchain overrides in scripts --------------------------------------------

    def test_literal_toolchain_overrides_in_scripts(self) -> None:
        self.put("scripts/a.sh", "#!/bin/sh\ncargo +nightly-2026-09-10 build\n")
        self.put("scripts/b.sh", "#!/bin/sh\nrustup run nightly-2026-09-10 cargo build\n")
        self.put("scripts/c.sh", "#!/bin/sh\nrustup override set nightly-2026-09-10\n")
        self.put("Makefile", "nightly:\n\tcargo +nightly-2026-09-10 build\n")
        I2 = ERR_DEP_CONST_INVARIANT
        self.assertEqual(self.uf(), sorted([(I2, "scripts/a.sh", "line/2"), (I2, "scripts/b.sh", "line/2"), (I2, "scripts/c.sh", "line/2"), (I2, "Makefile", "line/2")]))

    def test_pinned_channel_and_variable_toolchains_are_allowed(self) -> None:
        channel = REQUIRED_RUST_CHANNEL
        self.put("scripts/ok.sh", f'#!/bin/sh\ntc="{channel}"\nrustup run "$tc" cargo build --locked --offline\nrustup run --install "$tc" cargo build\ncargo +{channel} build\nrustup override set {channel}\n')
        self.assertEqual(self.uf(), [])

    def test_override_string_helper(self) -> None:
        channel = REQUIRED_RUST_CHANNEL
        self.assertIsNone(dependency_constitution_checker._override_toolchain_problem('rustup run "$tc" cargo build', channel))
        self.assertIsNone(dependency_constitution_checker._override_toolchain_problem(f"cargo +{channel} build", channel))
        self.assertIsNotNone(dependency_constitution_checker._override_toolchain_problem("cargo +nightly-2020-01-01 build", channel))

    # --- 3: doctests from included markdown, doc-attribute strings, and the ignore exemption ----

    def test_doctests_from_included_markdown_and_doc_strings(self) -> None:
        self.put("crates/fss-core/src/lib.rs", '#![doc = include_str!("../DOCS.md")]\n#[doc = "```\\n#![feature(attr_string)]\\nfn f() {}\\n```"]\npub fn f() {}\n')
        self.put("crates/fss-core/DOCS.md", "# Docs\n\n```rust\n#![feature(included_md)]\nfn f() -> ! { loop {} }\n```\n")
        U = ERR_DEP_UNSTABLE_FEATURE
        self.assertEqual(self.uf(), sorted([(U, "crates/fss-core/DOCS.md", "line/4"), (U, "crates/fss-core/src/lib.rs", "line/2")]))

    def test_ignore_and_text_blocks_are_not_doctests(self) -> None:
        body = "\n".join([
            "/// ```rust,ignore",
            "/// #![feature(ignored)]",
            "/// ```",
            "/// ```text",
            "/// #![feature(texty)]",
            "/// ```",
            "/// ```ignore",
            "/// #![feature(bare_ignore)]",
            "/// ```",
            "/// ```no_run",
            "/// #![feature(compiled)]",
            "/// ```",
            "pub fn f() {}",
            "",
        ])
        self.put("crates/fss-core/src/lib.rs", body)
        self.assertEqual(self.uf(), [(ERR_DEP_UNSTABLE_FEATURE, "crates/fss-core/src/lib.rs", "line/11")])

    def test_included_markdown_ignore_block_is_exempt(self) -> None:
        self.put("crates/fss-core/src/lib.rs", '#![doc = include_str!("../DOCS.md")]\npub fn f() {}\n')
        self.put("crates/fss-core/DOCS.md", "```rust,ignore\n#![feature(ignored)]\n```\n\n```rust\n#![feature(live)]\n```\n")
        self.assertEqual(self.uf(), [(ERR_DEP_UNSTABLE_FEATURE, "crates/fss-core/DOCS.md", "line/6")])

    # --- 4: extensionless shell scripts ---------------------------------------------------------

    def test_extensionless_shell_scripts_are_scanned(self) -> None:
        self.put("scripts/nightly", "#!/bin/sh\ncargo build -Zbuild-std\n")
        self.put("scripts/envwrap", "#!/usr/bin/env bash\nexport RUSTFLAGS=-Zcrate-attr=feature(x)\n")
        self.put("scripts/notashell", "#!/usr/bin/env python3\nprint('cargo build -Zbuild-std')\n")
        self.put("LICENSE", "cargo build -Zbuild-std is only text here\n")
        U = ERR_DEP_UNSTABLE_FEATURE
        self.assertEqual(self.uf(), sorted([(U, "scripts/nightly", "line/2"), (U, "scripts/envwrap", "line/2")]))

    def test_round_four_bypasses_fail_the_entry_point(self) -> None:
        self.put(".envrc", "export RUSTUP_TOOLCHAIN=nightly-2026-09-10\n")
        with patch("subprocess.run", side_effect=self.fake_run()):
            result = validate_dependency_constitution(self.tmp_root)
        self.assertEqual(codes(result), {ERR_DEP_CONST_INVARIANT})
        self.assertEqual([(e.file_path, e.target) for e in result.errors], [(".envrc", "line/1")])


if __name__ == "__main__":
    unittest.main()
