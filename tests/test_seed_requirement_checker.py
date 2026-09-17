#!/usr/bin/env python3
"""DRIFT-003 seed identity, corpus, privacy, and proof regression contracts."""

import copy
import hashlib
import json
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))

import architecture_registry_consistency as architecture_checker
import seed_requirement_checker as checker


SECRET = "planted-seed-secret-do-not-disclose"


def freeze_digest(rows):
    raw = json.dumps(rows, sort_keys=True, separators=(",", ":")).encode("utf-8")
    return "sha256:" + hashlib.sha256(raw).hexdigest()


def copy_corpus(destination):
    """Copy public checker inputs, never the Rust workspace or mutable symlinks."""
    sources = set(checker.ROOT.glob("*.md"))
    for directory in ("architecture", "registries", "docs", "schemas"):
        for suffix in ("*.md", "*.json", "*.toml"):
            sources.update((checker.ROOT / directory).rglob(suffix))
    sources.add(checker.ROOT / "tests/fixtures/seed_requirements/before.json")
    for source in sorted(sources):
        target = destination / source.relative_to(checker.ROOT)
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(source.read_bytes())


class SeedRegistryTests(unittest.TestCase):
    def setUp(self):
        self.document = json.loads((checker.ROOT / checker.REGISTRY).read_text(encoding="utf-8"))

    def assert_codes(self, document, *expected):
        findings = checker.validate_registry(document)
        codes = {finding["code"] for finding in findings}
        self.assertTrue(set(expected).issubset(codes), findings)
        for finding in findings:
            self.assertEqual(set(finding), {"code", "file", "location", "message"})
            self.assertTrue(finding["code"].startswith("ERR-SEED-"))
        return findings

    def test_live_registry_admits_exact_published_extent(self):
        self.assertEqual(checker.validate_registry(self.document), [])
        self.assertEqual(self.document["expectedCount"], 250)
        self.assertEqual(
            [row["id"] for row in self.document["requirements"]],
            [f"FSS-{number:03}" for number in range(1, 251)],
        )

    def test_every_removal_including_first_last_and_internal_gaps_is_rejected(self):
        for index in range(250):
            with self.subTest(removed=f"FSS-{index + 1:03}"):
                document = copy.deepcopy(self.document)
                document["requirements"].pop(index)
                document["freezeDigest"] = freeze_digest(document["requirements"])
                self.assert_codes(document, "ERR-SEED-IDENTITIES-001", "ERR-SEED-COUNT-001")

    def test_duplicate_cannot_replace_an_identity_at_unchanged_count(self):
        document = copy.deepcopy(self.document)
        document["requirements"][100] = copy.deepcopy(document["requirements"][99])
        document["freezeDigest"] = freeze_digest(document["requirements"])
        self.assert_codes(document, "ERR-SEED-IDENTITIES-001")

    def test_reordering_preserves_membership_but_is_not_admitted(self):
        document = copy.deepcopy(self.document)
        rows = document["requirements"]
        rows[100], rows[101] = rows[101], rows[100]
        document["freezeDigest"] = freeze_digest(rows)
        self.assert_codes(document, "ERR-SEED-ORDER-001")

    def test_declared_counts_240_249_and_251_are_rejected(self):
        for count in (240, 249, 251):
            with self.subTest(count=count):
                document = copy.deepcopy(self.document)
                document["expectedCount"] = count
                self.assert_codes(document, "ERR-SEED-COUNT-001", "ERR-SEED-MIGRATION-001")

    def test_self_consistent_changed_extent_does_not_redefine_admission(self):
        for count in (240, 249, 251):
            with self.subTest(count=count):
                document = copy.deepcopy(self.document)
                document["requirements"] = document["requirements"][:count]
                if count == 251:
                    document["requirements"].append({"id": "FSS-251", "title": "Unreviewed addition."})
                document["expectedCount"] = count
                document["freezeDigest"] = freeze_digest(document["requirements"])
                self.assert_codes(document, "ERR-SEED-MIGRATION-001")

    def test_version_schema_and_freeze_tamper_require_migration(self):
        for field, value in (("version", 2), ("schema", "fss.seed_requirements.v2"),
                             ("freezeDigest", "sha256:" + "0" * 64)):
            with self.subTest(field=field):
                document = copy.deepcopy(self.document)
                document[field] = value
                self.assert_codes(document, "ERR-SEED-MIGRATION-001")

    def test_title_tamper_is_rejected_even_with_recomputed_freeze(self):
        for recompute in (False, True):
            with self.subTest(recompute=recompute):
                document = copy.deepcopy(self.document)
                document["requirements"][0]["title"] = SECRET
                if recompute:
                    document["freezeDigest"] = freeze_digest(document["requirements"])
                findings = self.assert_codes(document, "ERR-SEED-MIGRATION-001")
                self.assertNotIn(SECRET, json.dumps(findings))

    def test_history_cannot_silently_authorize_a_new_migration(self):
        document = copy.deepcopy(self.document)
        document["history"]["tombstones"] = ["FSS-250"]
        document["history"]["migration"] = "Unreviewed migration"
        self.assert_codes(document, "ERR-SEED-MIGRATION-001")

    def test_malformed_documents_and_rows_fail_without_throwing(self):
        for document in (None, [], "not a registry", {}, {"requirements": None, "expectedCount": 250}):
            with self.subTest(document=document):
                self.assert_codes(document, "ERR-SEED-INPUT-001")
        for row in (None, [], "not a row", {}, {"id": "FSS-001", "title": None},
                    {"id": ["FSS-001"], "title": "Malformed identity"},
                    {"id": "FSS-001", "title": ""}):
            with self.subTest(row=row):
                document = copy.deepcopy(self.document)
                document["requirements"][0] = row
                self.assert_codes(document, "ERR-SEED-INPUT-001")


class SeedCorpusTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = type(checker.ROOT)(temporary.name) / "repository"
        copy_corpus(self.root)
        self.document = json.loads((self.root / checker.REGISTRY).read_text(encoding="utf-8"))

    def assert_failure(self, code):
        report = checker.check(self.root)
        self.assertEqual(report["status"], "failed", report["findings"])
        self.assertIn(code, {finding["code"] for finding in report["findings"]})
        return report

    def test_live_corpus_and_isolated_replica_pass(self):
        for root in (checker.ROOT, self.root):
            with self.subTest(root=str(root)):
                report = checker.check(root)
                self.assertEqual(report["status"], "passed", report["findings"])
                self.assertEqual(report["findings"], [])
                self.assertEqual((report["expectedCount"], report["actualCount"]), (250, 250))

    def test_each_canonical_mirror_detects_stale_count_and_recovers(self):
        for mirror in self.document["mirrors"]:
            with self.subTest(mirror=mirror):
                path = self.root / mirror["path"]
                original = path.read_text(encoding="utf-8")
                current = mirror["template"].format(count=250)
                self.assertEqual(original.splitlines().count(current), 1)
                try:
                    path.write_text(original.replace(current, mirror["template"].format(count=240), 1), encoding="utf-8")
                    self.assert_failure("ERR-SEED-MIRROR-001")
                    checker.generate(self.root)
                    report = checker.check(self.root)
                    self.assertEqual(report["status"], "passed", report["findings"])
                finally:
                    path.write_text(original, encoding="utf-8")

    def test_unknown_reference_and_conflicting_definition_have_no_owner(self):
        path = self.root / "docs/seed-planted.md"
        for prose in ("This requirement depends on FSS-999.\n",
                      "### `FSS-001` — A conflicting definition.\n"):
            with self.subTest(prose=prose):
                path.write_text(prose, encoding="utf-8")
                report = self.assert_failure("ERR-SEED-OWNER-001")
                self.assertTrue(any(finding["file"] == "docs/seed-planted.md"
                                    and finding["code"] == "ERR-SEED-OWNER-001"
                                    for finding in report["findings"]))

    def test_missing_or_invalid_registry_fails_closed(self):
        path = self.root / checker.REGISTRY
        path.unlink()
        self.assert_failure("ERR-SEED-INPUT-001")
        path.write_text("{invalid JSON", encoding="utf-8")
        self.assert_failure("ERR-SEED-INPUT-001")

    def test_reports_and_proof_logs_never_disclose_title_or_prose(self):
        path = self.root / "docs/seed-planted.md"
        path.write_text(f"### `FSS-001` — {SECRET}\nUnowned FSS-999: {SECRET}\n", encoding="utf-8")
        report = self.assert_failure("ERR-SEED-OWNER-001")
        self.assertNotIn(SECRET, json.dumps(report))
        self.document["requirements"][0]["title"] = SECRET
        (self.root / checker.REGISTRY).write_text(json.dumps(self.document), encoding="utf-8")
        report = self.assert_failure("ERR-SEED-MIGRATION-001")
        self.assertNotIn(SECRET, json.dumps(report))
        out = self.root.parent / "private-proof"
        summary = checker.publish_proof(self.root, out)
        self.assertEqual(summary["status"], "failed")
        self.assertFalse(checker.verify_proof(out))
        for artifact in out.rglob("*"):
            if artifact.is_file():
                self.assertNotIn(SECRET.encode(), artifact.read_bytes(), str(artifact.relative_to(out)))

    def test_proof_nominal_negative_and_recovery_scenarios_are_verifiable(self):
        out = self.root.parent / "proof"
        summary = checker.publish_proof(self.root, out)
        self.assertEqual(summary["status"], "passed")
        self.assertTrue(checker.verify_proof(out))
        records = [json.loads(line) for line in (out / "transcript.jsonl").read_text(encoding="utf-8").splitlines()]
        scenarios = {record["scenario"]: record for record in records}
        expected = {"corpus": "passed", "recovery": "passed", "before": "failed",
                    "missing-first": "failed", "missing-last": "failed", "internal-gap": "failed",
                    "duplicate": "failed", "reorder": "failed", "version": "failed",
                    "count-240": "failed", "count-249": "failed", "count-251": "failed",
                    "corpus-count-240": "failed", "corpus-count-249": "failed",
                    "corpus-count-251": "failed"}
        for name, status in expected.items():
            with self.subTest(scenario=name):
                record = scenarios[name]
                self.assertTrue(record["matched"])
                payload = json.loads((out / "artifacts" / (record["artifact"][7:] + ".json")).read_text(encoding="utf-8"))
                self.assertEqual(payload["result" if name == "before" else "status"], status)

    def test_proof_rejects_tamper_and_missing_root_then_recovers(self):
        out = self.root.parent / "proof"
        checker.publish_proof(self.root, out)
        self.assertTrue(checker.verify_proof(out))
        files = [out / "summary.json", out / "transcript.jsonl", out / "proof.root"]
        files.extend(sorted((out / "artifacts").glob("*.json")))
        for path in files:
            with self.subTest(artifact=str(path.relative_to(out))):
                original = path.read_bytes()
                try:
                    path.write_bytes(original + b"tamper")
                    self.assertFalse(checker.verify_proof(out))
                    path.unlink()
                    self.assertFalse(checker.verify_proof(out))
                finally:
                    path.write_bytes(original)
                self.assertTrue(checker.verify_proof(out))

    def test_architecture_checker_preserves_seed_failure_identity(self):
        document = copy.deepcopy(self.document)
        document["requirements"].pop()
        (self.root / checker.REGISTRY).write_text(json.dumps(document), encoding="utf-8")
        valid, findings, _ = architecture_checker.validate_consistency(self.root)
        self.assertFalse(valid)
        self.assertIn("ERR-SEED-COUNT-001", {finding.code for finding in findings})


if __name__ == "__main__":
    unittest.main()
