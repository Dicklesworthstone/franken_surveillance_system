#!/usr/bin/env python3
"""Planted-negative and positive test suite for NEG-002 standards-first camera access checker (fss-x4a.1.32.2).

Enforces the non-negotiable negative-evidence constraint NEG-002 from AGENTS.md and DEVICE_ADAPTER_MATRIX.md:
1. An adapter/capability registry entry cannot claim ONVIF/RTSP/local-stream capability
   without a qualifying evidence reference (marketing/app presence is rejected).
2. Proprietary/vendor/app-automation paths cannot be registered as stable native integrations
   (must remain Tier T3 authorized lab or T4 import).
3. Vendor tokens are scoped to their exact adapter capability (CAP-ADAPTER-AUTH-001 with device/account scope).
4. Stable ID NEG-002 and its normative decision must be preserved without weakening or renaming.
"""

from __future__ import annotations

import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))

try:
    from standards_first_adapter_checker import (
        ERR_PROPRIETARY_NATIVE_PROMOTION,
        ERR_STABLE_ID_MISSING,
        ERR_UNSCOPED_VENDOR_TOKEN,
        ERR_UNVERIFIED_STANDARDS_CLAIM,
        audit_standards_first_adapters,
    )
except ImportError:
    # Fallback to canonical error identities so tests fail closed
    ERR_UNVERIFIED_STANDARDS_CLAIM = "ERR-NEG002-UNVERIFIED-STANDARDS-CLAIM-001"
    ERR_PROPRIETARY_NATIVE_PROMOTION = "ERR-NEG002-PROPRIETARY-NATIVE-PROMOTION-001"
    ERR_UNSCOPED_VENDOR_TOKEN = "ERR-NEG002-UNSCOPED-VENDOR-TOKEN-001"
    ERR_STABLE_ID_MISSING = "ERR-NEG002-STABLE-ID-MISSING-001"
    audit_standards_first_adapters = None


def create_minimal_valid_env(tmp_dir: Path) -> tuple[Path, Path, Path, Path]:
    """Creates a minimal valid set of registry and doc files in a temp directory."""
    docs_dir = tmp_dir / "docs"
    docs_dir.mkdir(parents=True, exist_ok=True)
    neg_file = docs_dir / "NEGATIVE_EVIDENCE.md"
    neg_file.write_text(
        """# Negative evidence registry

### NEG-002 — Do not treat proprietary app access as a stable camera standard

- **Hypothesis:** a consumer camera advertised with Wi-Fi/cloud viewing has a stable local stream.
- **Finding:** public owner-facing documentation for target proprietary products does not establish
  a durable ONVIF/RTSP contract.
- **Decision:** standards-first adapters; vendor paths remain exact-tuple interoperability-lab work.
- **Revival:** official local API/profile support or a qualified owner-authorized adapter matrix.
""",
        encoding="utf-8",
    )

    reg_dir = tmp_dir / "registries"
    reg_dir.mkdir(parents=True, exist_ok=True)
    adapters_file = reg_dir / "DEVICE_ADAPTERS.md"
    adapters_file.write_text(
        """# Device adapter registry

| ID | Surface | Tier | Current state | Promotion gate |
|---|---|---:|---|---|
| `ADP-REPLAY-001` | deterministic replay | T0 | specified | `GATE-010` |
| `ADP-FILE-001` | bounded media import | T0/T4 | specified | `GATE-010` |
| `ADP-UVC-001` | UVC/UAC | T1 | specified | `GATE-020` |
| `ADP-INSTA-LINK-001` | Insta360 Link via UVC/UAC | T1 | researched, unimplemented | `GATE-020` |
| `ADP-RTSP-001` | RTSP/RTP | T1 | specified | `GATE-030` |
| `ADP-ONVIF-T-001` | ONVIF Profile T | T1 | specified | `GATE-030` |
| `ADP-ONVIF-M-001` | ONVIF Profile M metadata | T1 | specified | `GATE-030` |
| `ADP-WYZE-V4-LAB-001` | Wyze Cam v4 owner-auth lab | T3 | research target | `GATE-090` |
| `ADP-AOSU-P1MAX-LAB-001` | AOSU P1 Max owner-auth lab | T3 | research target | `GATE-090` |
| `ADP-DJI-FLIP-LAB-001` | DJI Flip manual capture/import lab | T3/T4 | research target | `GATE-100` |
| `ADP-S3-IMPORT-001` | S3-compatible import | T4 | specified | `GATE-040` |
""",
        encoding="utf-8",
    )

    caps_file = reg_dir / "CAPABILITIES.md"
    caps_file.write_text(
        """# Capability registry

| ID | Capability | Scope | Plane | Default |
|---|---|---|---|---|
| `CAP-ADAPTER-AUTH-001` | resolve one adapter secret handle | device/account | boundary | adapter host only |
| `CAP-ADAPTER-NET-001` | contact registered device/vendor endpoints | destination allowlist | boundary | adapter host only |
""",
        encoding="utf-8",
    )

    matrix_file = tmp_dir / "DEVICE_ADAPTER_MATRIX.md"
    matrix_file.write_text(
        """# Device adapter matrix

## 1. Adapter tiers

| Tier | Meaning | Release treatment |
|---|---|---|
| `T0 replay` | deterministic fixtures and prerecorded inputs | mandatory oracle; default-safe |
| `T1 open local` | standards with local owner-controlled transport | preferred production path |
| `T2 documented vendor` | documented protocol/API for exact product, implemented in first-party Rust | exact tuple; version-pinned; vendor SDK remains a lab oracle |
| `T3 authorized lab` | interoperability research against owner devices/accounts | non-default; exact firmware/app tuple; no auth bypass |
| `T4 import` | exported files or SD media | valid historical evidence, not live coverage |

## 2. Initial matrix

| Adapter ID | Product/surface | Known public interface | Initial tier | Planned capability | Current FSS state |
|---|---|---|---|---|---|
| `ADP-REPLAY-001` | FSS replay fixture | repository schema | T0 | packets, frames, metadata, faults, expected events | specified |
| `ADP-FILE-001` | MP4/MKV/JPEG/audio import | standard files | T0/T4 | bounded import with source hash and capture uncertainty | specified |
| `ADP-UVC-001` | generic UVC/UAC camera | USB UVC/UAC | T1 | modes, frames, audio, controls, reconnect | specified |
| `ADP-INSTA-LINK-001` | Insta360 Link | USB-C; UVC 1.1/UAC 1.0; H.264/MJPEG | T1 | reference UVC video/audio and bounded controls | research complete; unimplemented |
| `ADP-RTSP-001` | generic RTSP camera/NVR | RTSP/RTP | T1 | DESCRIBE/SETUP/PLAY, auth, RTP continuity, reconnect | specified |
| `ADP-ONVIF-T-001` | ONVIF Profile T client | H.264/H.265, imaging, events, metadata, PTZ/audio where supported | T1 | discovery, profiles, stream URI, events, settings, PTZ | specified |
| `ADP-ONVIF-M-001` | ONVIF Profile M metadata | analytics metadata/events | T1 | ingest metadata as derived vendor evidence | specified |
| `ADP-WYZE-V4-LAB-001` | Wyze Cam v4 | vendor app/cloud/local microSD; no public RTSP/ONVIF contract found | T3 | owner-authenticated live/import path if reproducible | research target only |
| `ADP-AOSU-P1MAX-LAB-001` | AOSU 4K P1 Max Solar | vendor app/base/local microSD/optional cloud; no public RTSP/ONVIF contract found | T3 | owner-authenticated event/live/import path if reproducible | research target only |
| `ADP-DJI-FLIP-LAB-001` | DJI Flip | DJI Fly live view and QuickTransfer; not listed in current Mobile SDK products | T3/T4 | manual calibration capture bridge or bounded import | research target only |
| `ADP-S3-IMPORT-001` | owner bucket/NVR export | S3-compatible objects | T4 | immutable import and manifest reconciliation | specified |
""",
        encoding="utf-8",
    )

    return neg_file, adapters_file, caps_file, matrix_file


class TestStandardsFirstPlantedNegatives(unittest.TestCase):
    """Planted-negative test cases verifying that unverified claims, proprietary promotion, and token escapes fail closed."""

    def test_marketing_or_app_presence_onvif_claim_rejected(self) -> None:
        """An adapter claiming ONVIF/RTSP capability based on marketing or app presence fails closed."""
        self.assertIsNotNone(audit_standards_first_adapters, "standards_first_adapter_checker module must be importable")
        with tempfile.TemporaryDirectory() as td:
            tmp_root = Path(td)
            create_minimal_valid_env(tmp_root)
            # Corrupt DEVICE_ADAPTER_MATRIX.md to claim ONVIF/RTSP based on marketing material
            bad_matrix = (
                tmp_root / "DEVICE_ADAPTER_MATRIX.md"
            ).read_text(encoding="utf-8").replace(
                "| `ADP-WYZE-V4-LAB-001` | Wyze Cam v4 | vendor app/cloud/local microSD; no public RTSP/ONVIF contract found | T3 | owner-authenticated live/import path if reproducible | research target only |",
                "| `ADP-WYZE-V4-LAB-001` | Wyze Cam v4 | marketing claim: advertised 2.5K Wi-Fi streaming; inferred ONVIF support | T1 | live RTSP stream | specified |",
            )
            (tmp_root / "DEVICE_ADAPTER_MATRIX.md").write_text(bad_matrix, encoding="utf-8")

            is_valid, findings, summary = audit_standards_first_adapters(tmp_root)
            self.assertFalse(is_valid, "Marketing-inferred ONVIF/RTSP claim must fail closed!")
            codes = [f.code for f in findings]
            self.assertIn(
                ERR_UNVERIFIED_STANDARDS_CLAIM,
                codes,
                f"Expected {ERR_UNVERIFIED_STANDARDS_CLAIM}, got {codes}",
            )

    def test_missing_qualifying_evidence_for_standards_claim_rejected(self) -> None:
        """Claiming open local standard T1 without authentic protocol interface fails closed."""
        self.assertIsNotNone(audit_standards_first_adapters, "standards_first_adapter_checker module must be importable")
        with tempfile.TemporaryDirectory() as td:
            tmp_root = Path(td)
            create_minimal_valid_env(tmp_root)
            # Add an unverified adapter claiming T1 with unverified interface
            matrix = tmp_root / "DEVICE_ADAPTER_MATRIX.md"
            content = matrix.read_text(encoding="utf-8")
            content = content.replace(
                "| `ADP-S3-IMPORT-001`",
                "| `ADP-UNKNOWN-CAM-001` | Unknown Smart Cam | consumer box Wi-Fi | T1 | continuous RTSP stream | specified |\n| `ADP-S3-IMPORT-001`",
            )
            matrix.write_text(content, encoding="utf-8")

            is_valid, findings, _ = audit_standards_first_adapters(tmp_root)
            self.assertFalse(is_valid, "Unverified standard claim without qualifying evidence must fail closed!")
            codes = [f.code for f in findings]
            self.assertIn(ERR_UNVERIFIED_STANDARDS_CLAIM, codes)

    def test_proprietary_adapter_promoted_to_t1_rejected(self) -> None:
        """A proprietary camera registered in Tier T1 (open local) fails closed."""
        self.assertIsNotNone(audit_standards_first_adapters, "standards_first_adapter_checker module must be importable")
        with tempfile.TemporaryDirectory() as td:
            tmp_root = Path(td)
            create_minimal_valid_env(tmp_root)
            # Corrupt DEVICE_ADAPTERS.md so proprietary Wyze Cam is registered as T1
            adapters_file = tmp_root / "registries" / "DEVICE_ADAPTERS.md"
            content = adapters_file.read_text(encoding="utf-8").replace(
                "| `ADP-WYZE-V4-LAB-001` | Wyze Cam v4 owner-auth lab | T3 | research target | `GATE-090` |",
                "| `ADP-WYZE-V4-LAB-001` | Wyze Cam v4 owner-auth lab | T1 | specified | `GATE-020` |",
            )
            adapters_file.write_text(content, encoding="utf-8")

            is_valid, findings, _ = audit_standards_first_adapters(tmp_root)
            self.assertFalse(is_valid, "Proprietary adapter promoted to T1 must fail closed!")
            codes = [f.code for f in findings]
            self.assertIn(ERR_PROPRIETARY_NATIVE_PROMOTION, codes)

    def test_proprietary_adapter_promoted_to_stable_native_rejected(self) -> None:
        """A proprietary camera registered with current state 'stable' or 'production' fails closed."""
        self.assertIsNotNone(audit_standards_first_adapters, "standards_first_adapter_checker module must be importable")
        with tempfile.TemporaryDirectory() as td:
            tmp_root = Path(td)
            create_minimal_valid_env(tmp_root)
            adapters_file = tmp_root / "registries" / "DEVICE_ADAPTERS.md"
            content = adapters_file.read_text(encoding="utf-8").replace(
                "| `ADP-AOSU-P1MAX-LAB-001` | AOSU P1 Max owner-auth lab | T3 | research target | `GATE-090` |",
                "| `ADP-AOSU-P1MAX-LAB-001` | AOSU P1 Max owner-auth lab | T3 | stable production native | `GATE-090` |",
            )
            adapters_file.write_text(content, encoding="utf-8")

            is_valid, findings, _ = audit_standards_first_adapters(tmp_root)
            self.assertFalse(is_valid, "Proprietary adapter promoted to stable production native must fail closed!")
            codes = [f.code for f in findings]
            self.assertIn(ERR_PROPRIETARY_NATIVE_PROMOTION, codes)

    def test_app_automation_or_screen_capture_as_native_integration_rejected(self) -> None:
        """Mobile screen capture or UI automation registered as a native integration fails closed."""
        self.assertIsNotNone(audit_standards_first_adapters, "standards_first_adapter_checker module must be importable")
        with tempfile.TemporaryDirectory() as td:
            tmp_root = Path(td)
            create_minimal_valid_env(tmp_root)
            adapters_file = tmp_root / "registries" / "DEVICE_ADAPTERS.md"
            content = adapters_file.read_text(encoding="utf-8")
            content = content.replace(
                "| `ADP-S3-IMPORT-001`",
                "| `ADP-AUTOSCREEN-001` | mobile screen capture native bridge | T1 | specified | `GATE-020` |\n| `ADP-S3-IMPORT-001`",
            )
            adapters_file.write_text(content, encoding="utf-8")

            is_valid, findings, _ = audit_standards_first_adapters(tmp_root)
            self.assertFalse(is_valid, "Mobile screen capture as native integration must fail closed!")
            codes = [f.code for f in findings]
            self.assertIn(ERR_PROPRIETARY_NATIVE_PROMOTION, codes)

    def test_unscoped_vendor_auth_token_rejected(self) -> None:
        """CAP-ADAPTER-AUTH-001 with broad/ambient/global scope fails closed."""
        self.assertIsNotNone(audit_standards_first_adapters, "standards_first_adapter_checker module must be importable")
        with tempfile.TemporaryDirectory() as td:
            tmp_root = Path(td)
            create_minimal_valid_env(tmp_root)
            caps_file = tmp_root / "registries" / "CAPABILITIES.md"
            content = caps_file.read_text(encoding="utf-8").replace(
                "| `CAP-ADAPTER-AUTH-001` | resolve one adapter secret handle | device/account | boundary | adapter host only |",
                "| `CAP-ADAPTER-AUTH-001` | resolve one adapter secret handle | * (global ambient token) | boundary | adapter host only |",
            )
            caps_file.write_text(content, encoding="utf-8")

            is_valid, findings, _ = audit_standards_first_adapters(tmp_root)
            self.assertFalse(is_valid, "Unscoped vendor auth token must fail closed!")
            codes = [f.code for f in findings]
            self.assertIn(ERR_UNSCOPED_VENDOR_TOKEN, codes)

    def test_unscoped_vendor_network_token_rejected(self) -> None:
        """CAP-ADAPTER-NET-001 with broad/unrestricted network scope fails closed."""
        self.assertIsNotNone(audit_standards_first_adapters, "standards_first_adapter_checker module must be importable")
        with tempfile.TemporaryDirectory() as td:
            tmp_root = Path(td)
            create_minimal_valid_env(tmp_root)
            caps_file = tmp_root / "registries" / "CAPABILITIES.md"
            content = caps_file.read_text(encoding="utf-8").replace(
                "| `CAP-ADAPTER-NET-001` | contact registered device/vendor endpoints | destination allowlist | boundary | adapter host only |",
                "| `CAP-ADAPTER-NET-001` | contact registered device/vendor endpoints | unrestricted-internet | boundary | adapter host only |",
            )
            caps_file.write_text(content, encoding="utf-8")

            is_valid, findings, _ = audit_standards_first_adapters(tmp_root)
            self.assertFalse(is_valid, "Unscoped vendor network token must fail closed!")
            codes = [f.code for f in findings]
            self.assertIn(ERR_UNSCOPED_VENDOR_TOKEN, codes)

    def test_missing_neg002_identity_fails_closed(self) -> None:
        """Missing or weakened NEG-002 section in docs/NEGATIVE_EVIDENCE.md fails closed."""
        self.assertIsNotNone(audit_standards_first_adapters, "standards_first_adapter_checker module must be importable")
        with tempfile.TemporaryDirectory() as td:
            tmp_root = Path(td)
            create_minimal_valid_env(tmp_root)
            # Remove NEG-002 from NEGATIVE_EVIDENCE.md
            neg_file = tmp_root / "docs" / "NEGATIVE_EVIDENCE.md"
            neg_file.write_text("# Negative evidence registry\n\nNo constraints recorded.\n", encoding="utf-8")

            is_valid, findings, _ = audit_standards_first_adapters(tmp_root)
            self.assertFalse(is_valid, "Missing NEG-002 section must fail closed!")
            codes = [f.code for f in findings]
            self.assertIn(ERR_STABLE_ID_MISSING, codes)


class TestStandardsFirstPositiveControls(unittest.TestCase):
    """Positive controls verifying that the real repository passes."""

    def test_real_repository_passes(self) -> None:
        """Real repository device adapters and capability registry pass with 0 errors."""
        self.assertIsNotNone(audit_standards_first_adapters, "standards_first_adapter_checker module must be importable")
        is_valid, findings, summary = audit_standards_first_adapters(ROOT)
        errors = [f for f in findings if f.severity == "error"]
        self.assertTrue(
            is_valid,
            f"Real repository audit failed with {len(errors)} error(s): {[f.message for f in errors]}",
        )
        self.assertEqual(len(errors), 0)
        self.assertEqual(summary["status"], "pass")
        self.assertGreaterEqual(summary["adapters_evaluated"], 11)

    def test_cli_json_mode(self) -> None:
        """CLI with --json outputs valid JSON payload with summary and findings."""
        checker_path = ROOT / "scripts" / "standards_first_adapter_checker.py"
        res = subprocess.run(
            [sys.executable, str(checker_path), "--json"],
            capture_output=True,
            text=True,
            check=False,
        )
        self.assertEqual(res.returncode, 0, f"CLI --json failed: {res.stderr}")
        data = json.loads(res.stdout)
        self.assertIn("summary", data)
        self.assertIn("findings", data)
        self.assertEqual(data["summary"]["status"], "pass")

    def test_cli_jsonl_mode(self) -> None:
        """CLI with --jsonl outputs valid JSONL audit records binding NEG-002."""
        checker_path = ROOT / "scripts" / "standards_first_adapter_checker.py"
        res = subprocess.run(
            [sys.executable, str(checker_path), "--jsonl"],
            capture_output=True,
            text=True,
            check=False,
        )
        self.assertEqual(res.returncode, 0, f"CLI --jsonl failed: {res.stderr}")
        lines = [line.strip() for line in res.stdout.strip().splitlines() if line.strip()]
        self.assertGreaterEqual(len(lines), 1)
        record = json.loads(lines[0])
        self.assertEqual(record["neg_id"], "NEG-002")
        self.assertEqual(record["status"], "passed")
        self.assertEqual(record["schema_version"], "fss.standards_first_adapter_audit.v1")


if __name__ == "__main__":
    unittest.main()
