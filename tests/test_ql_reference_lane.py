#!/usr/bin/env python3
"""Contract & fault tests for reusable lane QL-REFERENCE-001 (scripts/lanes/reference.sh, fss-x4a.29.17)."""

import hashlib
import json
import subprocess
import tempfile
import unittest
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
SCRIPT = REPO / "scripts" / "lanes" / "reference.sh"


class TestQlReferenceLane(unittest.TestCase):
    def test_list_covers_all_five_reference_pillars(self) -> None:
        out = subprocess.check_output(["bash", str(SCRIPT), "--list"], text=True)
        lines = [line.split("\t") for line in out.strip().splitlines() if line.strip()]
        self.assertEqual(len(lines), 9)
        pillars = {parts[1] for parts in lines}
        self.assertEqual(
            pillars,
            {
                "schema_and_golden_registry",
                "ledger_oracle",
                "object_oracle",
                "graph_oracle",
                "event_and_model_oracle",
            },
        )
        for parts in lines:
            self.assertEqual(parts[0], "QL-REFERENCE-001")

    def test_missing_prerequisite_fails_closed_non_pass(self) -> None:
        proc = subprocess.run(
            ["bash", str(SCRIPT), "--dry-run-missing-prereq"],
            capture_output=True,
            text=True,
        )
        self.assertEqual(proc.returncode, 5)
        self.assertIn("unavailable_prerequisite", proc.stderr)

    def test_static_lane_run_and_standalone_verifier_and_tamper_refusals(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            run_dir = Path(td) / "ref-run"
            proc = subprocess.run(
                ["bash", str(SCRIPT), "--only-static", "--receipt-dir", str(run_dir)],
                capture_output=True,
                text=True,
                cwd=str(REPO),
            )
            self.assertEqual(proc.returncode, 0, f"stderr={proc.stderr}")
            receipt_path = run_dir / "reference-receipt.json"
            self.assertTrue(receipt_path.is_file())
            receipt = json.loads(receipt_path.read_text(encoding="utf-8"))
            self.assertEqual(receipt["laneId"], "QL-REFERENCE-001")
            self.assertEqual(receipt["status"], "passed")
            self.assertEqual(len(receipt["commands"]), 3)

            # Full verifier MUST refuse static-only receipt (cannot fake full oracle pass).
            refuse_partial = subprocess.run(
                ["bash", str(SCRIPT), "--verify-receipt", str(receipt_path)],
                capture_output=True,
                text=True,
                cwd=str(REPO),
            )
            self.assertNotEqual(refuse_partial.returncode, 0)
            self.assertIn("incomplete QL-REFERENCE-001 receipt", refuse_partial.stderr)

            # Static-only verifier passes on clean bundle.
            ver = subprocess.run(
                ["bash", str(SCRIPT), "--verify-receipt", str(receipt_path), "--allow-static-only"],
                capture_output=True,
                text=True,
                cwd=str(REPO),
            )
            self.assertEqual(ver.returncode, 0, f"stderr={ver.stderr}")
            self.assertIn("[PASS] QL-REFERENCE-001 standalone verifier", ver.stdout)

            # Fault 1: Tampering a step log invalidates digest.
            log_file = run_dir / "ref-01-schema-constitution.log"
            orig_bytes = log_file.read_bytes()
            log_file.write_bytes(orig_bytes + b"\ntampered")
            bad_digest = subprocess.run(
                ["bash", str(SCRIPT), "--verify-receipt", str(receipt_path), "--allow-static-only"],
                capture_output=True,
                text=True,
            )
            self.assertNotEqual(bad_digest.returncode, 0)
            log_file.write_bytes(orig_bytes)

            # Fault 2: Secret canary leak in a log (even with matching digest) MUST exit 3.
            steps_path = run_dir / "reference-steps.jsonl"
            orig_steps = steps_path.read_text(encoding="utf-8")
            leaked_bytes = orig_bytes + b"\nAuthorization: Bearer supersecret\n"
            log_file.write_bytes(leaked_bytes)
            leaked_digest = "sha256:" + hashlib.sha256(leaked_bytes).hexdigest()
            rows = [json.loads(line) for line in orig_steps.splitlines() if line.strip()]
            rows[0]["outputDigest"] = leaked_digest
            steps_path.write_text("\n".join(json.dumps(r) for r in rows) + "\n", encoding="utf-8")
            orig_receipt_text = receipt_path.read_text(encoding="utf-8")
            rec_copy = json.loads(orig_receipt_text)
            rec_copy["commands"][0]["outputDigest"] = leaked_digest
            receipt_path.write_text(json.dumps(rec_copy), encoding="utf-8")
            secret_fail = subprocess.run(
                ["bash", str(SCRIPT), "--verify-receipt", str(receipt_path), "--allow-static-only"],
                capture_output=True,
                text=True,
            )
            self.assertEqual(secret_fail.returncode, 3)

            # Fault 3: Skipped status in receipt MUST fail closed.
            log_file.write_bytes(orig_bytes)
            steps_path.write_text(orig_steps, encoding="utf-8")
            rec_skip = json.loads(orig_receipt_text)
            rec_skip["commands"][0]["status"] = "skipped"
            receipt_path.write_text(json.dumps(rec_skip), encoding="utf-8")
            skip_fail = subprocess.run(
                ["bash", str(SCRIPT), "--verify-receipt", str(receipt_path), "--allow-static-only"],
                capture_output=True,
                text=True,
            )
            self.assertNotEqual(skip_fail.returncode, 0)

            # Fault 4: Path-traversal logFile (even with matching digest!) MUST fail closed.
            outside_file = Path(td) / "outside.log"
            outside_file.write_bytes(b"outside-data\n")
            outside_digest = "sha256:" + hashlib.sha256(b"outside-data\n").hexdigest()
            trav_rows = [json.loads(line) for line in orig_steps.splitlines() if line.strip()]
            trav_rows[0]["logFile"] = "../outside.log"
            trav_rows[0]["outputDigest"] = outside_digest
            steps_path.write_text("\n".join(json.dumps(r) for r in trav_rows) + "\n", encoding="utf-8")
            rec_trav = json.loads(orig_receipt_text)
            rec_trav["commands"][0]["outputDigest"] = outside_digest
            receipt_path.write_text(json.dumps(rec_trav), encoding="utf-8")
            trav_fail = subprocess.run(
                ["bash", str(SCRIPT), "--verify-receipt", str(receipt_path), "--allow-static-only"],
                capture_output=True,
                text=True,
            )
            self.assertEqual(trav_fail.returncode, 2)
            self.assertIn("unsafe step log filename", trav_fail.stderr)

            # Fault 5: Symlink logFile inside run_dir escaping outside MUST fail closed.
            sym_log = run_dir / "escape.log"
            sym_log.symlink_to(outside_file)
            sym_rows = [json.loads(line) for line in orig_steps.splitlines() if line.strip()]
            sym_rows[0]["logFile"] = "escape.log"
            sym_rows[0]["outputDigest"] = outside_digest
            steps_path.write_text("\n".join(json.dumps(r) for r in sym_rows) + "\n", encoding="utf-8")
            sym_fail = subprocess.run(
                ["bash", str(SCRIPT), "--verify-receipt", str(receipt_path), "--allow-static-only"],
                capture_output=True,
                text=True,
            )
            self.assertEqual(sym_fail.returncode, 2)
            self.assertIn("missing or escaped step log artifact", sym_fail.stderr)


if __name__ == "__main__":
    unittest.main()
