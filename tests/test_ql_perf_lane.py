#!/usr/bin/env python3
"""Contract & fault tests for reusable lane QL-PERF-001 (scripts/lanes/perf.sh, fss-x4a.29.19)."""

import hashlib
import json
import subprocess
import tempfile
import unittest
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
SCRIPT = REPO / "scripts" / "lanes" / "perf.sh"


class TestQlPerfLane(unittest.TestCase):
    def test_list_covers_all_five_perf_pillars(self) -> None:
        out = subprocess.check_output(["bash", str(SCRIPT), "--list"], text=True)
        lines = [line.split("\t") for line in out.strip().splitlines() if line.strip()]
        self.assertEqual(len(lines), 8)
        pillars = {parts[1] for parts in lines}
        self.assertEqual(
            pillars,
            {
                "workload_manifest_and_thresholds",
                "same_binary_aa_ab",
                "semantic_digest_parity",
                "percentile_distributions",
                "thermal_energy_counters",
            },
        )
        for parts in lines:
            self.assertEqual(parts[0], "QL-PERF-001")

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
            run_dir = Path(td) / "perf-run"
            proc = subprocess.run(
                ["bash", str(SCRIPT), "--only-static", "--receipt-dir", str(run_dir)],
                capture_output=True,
                text=True,
                cwd=str(REPO),
            )
            self.assertEqual(proc.returncode, 0, f"stderr={proc.stderr}")
            receipt_path = run_dir / "perf-receipt.json"
            metrics_path = run_dir / "perf-metrics.json"
            self.assertTrue(receipt_path.is_file())
            self.assertTrue(metrics_path.is_file())
            receipt = json.loads(receipt_path.read_text(encoding="utf-8"))
            self.assertEqual(receipt["laneId"], "QL-PERF-001")
            self.assertEqual(receipt["status"], "passed")
            self.assertEqual(len(receipt["commands"]), 2)
            metrics = json.loads(metrics_path.read_text(encoding="utf-8"))
            self.assertEqual(metrics["schema"], "fss.perf_lane_metrics.v1")
            self.assertEqual(metrics["stepCount"], 2)

            # Full verifier MUST refuse static-only receipt (cannot fake 5-pillar pass).
            refuse_partial = subprocess.run(
                ["bash", str(SCRIPT), "--verify-receipt", str(receipt_path)],
                capture_output=True,
                text=True,
                cwd=str(REPO),
            )
            self.assertNotEqual(refuse_partial.returncode, 0)
            self.assertIn("incomplete QL-PERF-001 receipt", refuse_partial.stderr)

            # Static-only verifier passes cleanly on unmodified bundle.
            ver = subprocess.run(
                ["bash", str(SCRIPT), "--verify-receipt", str(receipt_path), "--allow-static-only"],
                capture_output=True,
                text=True,
                cwd=str(REPO),
            )
            self.assertEqual(ver.returncode, 0, f"stderr={ver.stderr}")
            self.assertIn("[PASS] QL-PERF-001 standalone verifier", ver.stdout)

            # Fault 1: Tampered log invalidates digest.
            log_file = run_dir / "perf-01-workload-manifest-slo.log"
            orig_bytes = log_file.read_bytes()
            log_file.write_bytes(orig_bytes + b"\ntampered")
            bad_digest = subprocess.run(
                ["bash", str(SCRIPT), "--verify-receipt", str(receipt_path), "--allow-static-only"],
                capture_output=True,
                text=True,
            )
            self.assertNotEqual(bad_digest.returncode, 0)
            log_file.write_bytes(orig_bytes)

            # Fault 2: Secret canary leak in log (even with matching digest) exits 3.
            steps_path = run_dir / "perf-steps.jsonl"
            orig_steps = steps_path.read_text(encoding="utf-8")
            leaked_bytes = orig_bytes + b"\nAKIASECRETKEYEXAMPLE\n"
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

            # Fault 3: Skipped status in receipt fails closed.
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

            # Fault 4: Path-traversal logFile (even with matching digest) fails closed.
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

            # Fault 5: Symlink escape inside run_dir fails closed.
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

            # Fault 6: Forged stepDurationPercentilesMs in perf-metrics.json MUST fail closed.
            steps_path.write_text(orig_steps, encoding="utf-8")
            receipt_path.write_text(orig_receipt_text, encoding="utf-8")
            orig_metrics_text = metrics_path.read_text(encoding="utf-8")
            forged_metrics = json.loads(orig_metrics_text)
            forged_metrics["stepDurationPercentilesMs"]["p50"] = 999999
            metrics_path.write_text(json.dumps(forged_metrics), encoding="utf-8")
            forged_fail = subprocess.run(
                ["bash", str(SCRIPT), "--verify-receipt", str(receipt_path), "--allow-static-only"],
                capture_output=True,
                text=True,
            )
            self.assertEqual(forged_fail.returncode, 2)
            self.assertIn("stepDurationPercentilesMs mismatch", forged_fail.stderr)
            metrics_path.write_text(orig_metrics_text, encoding="utf-8")


if __name__ == "__main__":
    unittest.main()
