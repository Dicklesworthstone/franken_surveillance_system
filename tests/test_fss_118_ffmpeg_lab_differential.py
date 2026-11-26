#!/usr/bin/env python3
"""Unit, negative-control, and live sealed-oracle tests for FSS-118 (`fss-x4a.12.17`)."""

from __future__ import annotations

import json
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
RUNNER = REPO / "scripts" / "lab" / "ffmpeg_media_differential.py"

sys.path.insert(0, str(REPO / "scripts" / "lab"))
import ffmpeg_media_differential as diff_runner  # noqa: E402


class TestFss118FfmpegLabDifferential(unittest.TestCase):
    def test_simulated_missing_tool_fails_closed_exit_5(self) -> None:
        with tempfile.TemporaryDirectory(prefix="fss118-missing-") as tmp:
            proc = subprocess.run(
                [sys.executable, str(RUNNER), "--output-dir", tmp, "--simulate-missing-tool"],
                capture_output=True,
                text=True,
                check=False,
            )
            self.assertEqual(proc.returncode, diff_runner.EXIT_UNAVAILABLE)
            self.assertIn("unavailable_lab_oracle", proc.stderr)
            self.assertFalse((Path(tmp) / "ffmpeg-differential-receipt.json").exists())

    def test_verify_receipt_rejects_tampering_symlink_and_production_authority(self) -> None:
        with tempfile.TemporaryDirectory(prefix="fss118-verify-") as tmp:
            tmp_dir = Path(tmp)
            valid_receipt = {
                "schema": diff_runner.SCHEMA,
                "requirement_id": "FSS-118",
                "bead_id": "fss-x4a.12.17",
                "oracle_role": diff_runner.ORACLE_ROLE,
                "production_authority": False,
                "excluded_dimensions": ["production_runtime", "source_custody_authority"],
                "cases_total": 1,
                "cases_passed": 1,
                "verdict": "pass",
                "cases": [{"case_id": "synthetic", "status": "pass", "divergences": []}],
            }
            valid_receipt["receipt_digest"] = diff_runner.compute_receipt_digest(valid_receipt)
            p_valid = tmp_dir / "valid.json"
            p_valid.write_text(json.dumps(valid_receipt), encoding="utf-8")

            ok, _ = diff_runner.verify_receipt(p_valid)
            self.assertTrue(ok)

            # 1. Symlink refusal
            link = tmp_dir / "link.json"
            link.symlink_to(p_valid)
            ok_link, msg_link = diff_runner.verify_receipt(link)
            self.assertFalse(ok_link)
            self.assertIn("symlink", msg_link)

            # 2. Tampered digest refusal
            tampered = dict(valid_receipt)
            tampered["verdict"] = "fail"
            p_tampered = tmp_dir / "tampered.json"
            p_tampered.write_text(json.dumps(tampered), encoding="utf-8")
            ok_tamp, _ = diff_runner.verify_receipt(p_tampered)
            self.assertFalse(ok_tamp)

            # 3. Forged production_authority=True even with recomputed digest refused!
            forged_auth = dict(valid_receipt)
            forged_auth["production_authority"] = True
            forged_auth["receipt_digest"] = diff_runner.compute_receipt_digest(forged_auth)
            p_auth = tmp_dir / "forged_auth.json"
            p_auth.write_text(json.dumps(forged_auth), encoding="utf-8")
            ok_auth, msg_auth = diff_runner.verify_receipt(p_auth)
            self.assertFalse(ok_auth)
            self.assertIn("production_authority", msg_auth)

            # 4. Non-passing case even with recomputed digest refused!
            forged_case = dict(valid_receipt)
            forged_case["cases"] = [
                {"case_id": "bad", "status": "fail", "divergences": ["codec mismatch"]}
            ]
            forged_case["receipt_digest"] = diff_runner.compute_receipt_digest(forged_case)
            p_case = tmp_dir / "forged_case.json"
            p_case.write_text(json.dumps(forged_case), encoding="utf-8")
            ok_case, _ = diff_runner.verify_receipt(p_case)
            self.assertFalse(ok_case)

    def test_live_ffmpeg_differential_against_shipped_fss_probe(self) -> None:
        ffmpeg = diff_runner.find_tool(None, "ffmpeg")
        ffprobe = diff_runner.find_tool(None, "ffprobe")
        fss_probe = diff_runner.find_fss_probe(None)
        if not (ffmpeg and ffprobe and fss_probe):
            self.skipTest(
                f"live lab oracle tools unavailable on host (ffmpeg={ffmpeg}, ffprobe={ffprobe}, fss-probe={fss_probe})"
            )

        with tempfile.TemporaryDirectory(prefix="fss118-live-") as tmp:
            out_dir = Path(tmp)
            env = dict(os.environ)
            env["FSS_CANARY_SECRET"] = "top-secret-never-log-me-9911"
            proc = subprocess.run(
                [
                    sys.executable,
                    str(RUNNER),
                    "--output-dir",
                    str(out_dir),
                    "--fss-probe",
                    fss_probe,
                    "--ffmpeg",
                    ffmpeg,
                    "--ffprobe",
                    ffprobe,
                ],
                capture_output=True,
                text=True,
                env=env,
                check=False,
            )
            self.assertEqual(proc.returncode, 0, msg=f"stdout={proc.stdout}\nstderr={proc.stderr}")
            self.assertIn("CAPLOG fss_118_lab_differential verdict=pass cases_ok=12/12", proc.stdout)

            receipt_path = out_dir / "ffmpeg-differential-receipt.json"
            jsonl_path = out_dir / "differential.jsonl"
            self.assertTrue(receipt_path.is_file())
            self.assertTrue(jsonl_path.is_file())

            # Zero secret leakage into logs or receipt
            receipt_text = receipt_path.read_text(encoding="utf-8")
            jsonl_text = jsonl_path.read_text(encoding="utf-8")
            self.assertNotIn("top-secret-never-log-me-9911", receipt_text)
            self.assertNotIn("top-secret-never-log-me-9911", jsonl_text)

            # Standalone CLI receipt verifier passes
            vproc = subprocess.run(
                [sys.executable, str(RUNNER), "--verify-receipt", str(receipt_path)],
                capture_output=True,
                text=True,
                check=False,
            )
            self.assertEqual(vproc.returncode, 0, msg=vproc.stdout + vproc.stderr)
            self.assertIn("RECEIPT_VERIFY status=pass", vproc.stdout)

            # Tampering with sibling differential.jsonl MUST cause --verify-receipt to fail!
            jsonl_path.write_text(jsonl_text + '{"tampered":true}\n', encoding="utf-8")
            ok_tampered_jsonl, msg_tampered_jsonl = diff_runner.verify_receipt(receipt_path)
            self.assertFalse(ok_tampered_jsonl)
            self.assertIn("differential.jsonl", msg_tampered_jsonl)
            jsonl_path.write_text(jsonl_text, encoding="utf-8")

            doc = json.loads(receipt_text)
            self.assertEqual(doc["cases_total"], 12)
            self.assertEqual(doc["cases_passed"], 12)
            self.assertFalse(doc["production_authority"])
            self.assertEqual(doc["oracle_role"], "sealed_laboratory_oracle_only")
            jpeg_case = next(c for c in doc["cases"] if c["case_id"] == "jpeg_gray_pixel_parity")
            self.assertEqual(jpeg_case["pixel_count"], 221)
            self.assertLessEqual(jpeg_case["max_abs_delta"], diff_runner.JPEG_IDCT_MAX_ABS_DELTA)


if __name__ == "__main__":
    unittest.main()
