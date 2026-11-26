#!/usr/bin/env python3
"""tests/test_release_publication.py — Contract, fault, cancel, crash-replay,
authority, and root-last publication test suite for FSS-192 (fss-x4a.26.12).
"""

from __future__ import annotations

import hashlib
import json
import os
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
SCRIPTS_DIR = REPO / "scripts"
if str(SCRIPTS_DIR) not in sys.path:
    sys.path.insert(0, str(SCRIPTS_DIR))

import release_publication as rp  # noqa: E402

BASIS_DIGEST = "sha256:" + hashlib.sha256(b"contract_basis:fss.release.v1").hexdigest()
MINISIGN = shutil.which("minisign") is not None


def _seed_artifacts(artifacts_dir: Path) -> list[str]:
    artifacts_dir.mkdir(parents=True, exist_ok=True)
    files = {
        "fss-x86_64-unknown-linux-gnu.tar.xz": b"deterministic-linux-archive-payload-v1",
        "fss-x86_64-unknown-linux-gnu.tar.xz.sha256": b"checksum-row-v1\n",
        "SHA256SUMS.txt": b"manifest-sums-v1\n",
    }
    for name, body in files.items():
        (artifacts_dir / name).write_bytes(body)
    return sorted(files.keys())


def _seed_sbom_leg(td: Path, version: str = "0.1.0", target: str = "x86_64-unknown-linux-gnu") -> dict[str, Path]:
    lock_path = td / "Cargo.lock"
    lock_text = 'version = 4\n\n[[package]]\nname = "fss-core"\nversion = "0.1.0"\n'
    lock_path.write_text(lock_text, encoding="utf-8")

    metadata = {"packages": [{"name": "fss-core", "version": "0.1.0"}]}
    meta_path = td / "metadata.json"
    meta_path.write_text(json.dumps(metadata, sort_keys=True), encoding="utf-8")
    md_digest = hashlib.sha256(json.dumps(metadata, sort_keys=True, separators=(",", ":")).encode()).hexdigest()
    ns_tail = hashlib.sha256(f"{version}:{target}:{md_digest}".encode()).hexdigest()

    sbom_path = td / "sbom.spdx.json"
    sbom_path.write_text(
        json.dumps(
            {
                "spdxVersion": "SPDX-2.3",
                "documentNamespace": f"https://fss.invalid/spdx/{ns_tail}",
                "packages": [{"name": "fss-core", "versionInfo": "0.1.0"}],
            },
            sort_keys=True,
        ),
        encoding="utf-8",
    )
    inv_path = td / "licenses.json"
    inv_path.write_text(
        json.dumps(
            {
                "schema": "fss.license_inventory.v1",
                "version": version,
                "target": target,
                "packages": [{"name": "fss-core", "version": "0.1.0", "license": "MIT"}],
            },
            sort_keys=True,
        ),
        encoding="utf-8",
    )
    rcpt_path = td / "qual_receipt.json"
    rcpt_path.write_text(
        json.dumps(
            {
                "status": "passed",
                "cargoLockDigest": "sha256:" + hashlib.sha256(lock_text.encode()).hexdigest(),
            },
            sort_keys=True,
        ),
        encoding="utf-8",
    )
    return {
        "sbom": sbom_path,
        "inventory": inv_path,
        "lock": lock_path,
        "metadata": meta_path,
        "receipt": rcpt_path,
    }


def _base_cfg(td: Path, expected_assets: list[str] | None = None, **overrides) -> rp.PublishConfig:
    kwargs = dict(
        release_id="rel:2026-11-21:v0.1.0",
        version="0.1.0",
        artifacts_dir=td / "artifacts",
        remote_store_dir=td / "remote",
        state_dir=td / "state",
        principal="operator:release-captain",
        capability="release:publish",
        lease_fence=1,
        builder_identity="builder:dsr-native-x86_64",
        signer_identity="signer:offline-release-hsm",
        contract_basis_digest=BASIS_DIGEST,
        toolchain_id="nightly-2026-08-31-x86_64-unknown-linux-gnu",
        expected_assets=expected_assets,
    )
    kwargs.update(overrides)
    return rp.PublishConfig(**kwargs)


class TestReleasePublication(unittest.TestCase):
    def test_root_last_upload_download_verify_and_idempotent_replay(self) -> None:
        with tempfile.TemporaryDirectory() as t:
            td = Path(t)
            expected = _seed_artifacts(td / "artifacts")
            sbom_leg = _seed_sbom_leg(td)
            cfg = _base_cfg(
                td,
                expected_assets=expected,
                sbom_path=sbom_leg["sbom"],
                license_inventory_path=sbom_leg["inventory"],
                cargo_lock_path=sbom_leg["lock"],
                metadata_path=sbom_leg["metadata"],
                qualification_receipt_path=sbom_leg["receipt"],
            )
            res = rp.publish_release(cfg)
            self.assertEqual(res["state"], "published", res)
            self.assertFalse(res["idempotentReplay"])
            self.assertEqual(
                res["transitions"],
                ["staged", "prepared", "uploaded_unverified", "download_verified", "published"],
            )
            self.assertGreater(res["costs"]["uploadBytes"], 0)
            self.assertGreater(res["costs"]["downloadBytes"], 0)

            # Independent read-only download verification passes.
            ver = rp.verify_published_release(td / "remote")
            self.assertEqual(ver["state"], "verified", ver)
            self.assertEqual(ver["rootDigest"], res["rootDigest"])
            self.assertEqual(ver["assetCount"], len(expected))

            # Exact idempotent replay succeeds without re-uploading.
            replay = rp.publish_release(cfg)
            self.assertEqual(replay["state"], "published")
            self.assertTrue(replay["idempotentReplay"])
            self.assertEqual(replay["planDigest"], res["planDigest"])

            # Mutating an artifact under the same release_id causes idempotency_conflict.
            (td / "artifacts" / "SHA256SUMS.txt").write_bytes(b"forged-sums-v2\n")
            conflict = rp.publish_release(cfg)
            self.assertEqual(conflict["state"], "failed")
            self.assertEqual(conflict["errorCode"], "idempotency_conflict")

    def test_download_corruption_and_extra_remote_asset_block_root_publication(self) -> None:
        with tempfile.TemporaryDirectory() as t:
            td = Path(t)
            expected = _seed_artifacts(td / "artifacts")

            # 1. Corrupt byte during download-verify -> root manifest MUST NOT be published!
            cfg_corrupt = _base_cfg(
                td,
                expected_assets=expected,
                remote_store_dir=td / "remote_corrupt",
                state_dir=td / "state_corrupt",
                faults=rp.FaultSchedule(corrupt_download_asset="SHA256SUMS.txt"),
            )
            res = rp.publish_release(cfg_corrupt)
            self.assertEqual(res["state"], "failed")
            self.assertEqual(res["errorCode"], "download_digest_mismatch")
            self.assertFalse(res.get("rootPublished", True))
            self.assertFalse((td / "remote_corrupt" / "root" / rp.ROOT_MANIFEST_NAME).exists())

            # 2. Extra unexpected remote file -> root manifest MUST NOT be published!
            cfg_extra = _base_cfg(
                td,
                expected_assets=expected,
                remote_store_dir=td / "remote_extra",
                state_dir=td / "state_extra",
                faults=rp.FaultSchedule(inject_extra_remote_asset="stray-unlisted.bin"),
            )
            res2 = rp.publish_release(cfg_extra)
            self.assertEqual(res2["state"], "failed")
            self.assertEqual(res2["errorCode"], "remote_asset_set_mismatch")
            self.assertFalse((td / "remote_extra" / "root" / rp.ROOT_MANIFEST_NAME).exists())

            # 3. Partial I/O during upload -> root manifest MUST NOT be published!
            cfg_partial = _base_cfg(
                td,
                expected_assets=expected,
                remote_store_dir=td / "remote_partial",
                state_dir=td / "state_partial",
                faults=rp.FaultSchedule(partial_write_asset="fss-x86_64-unknown-linux-gnu.tar.xz"),
            )
            res3 = rp.publish_release(cfg_partial)
            self.assertEqual(res3["state"], "failed")
            self.assertEqual(res3["errorCode"], "partial_io")
            self.assertFalse((td / "remote_partial" / "root" / rp.ROOT_MANIFEST_NAME).exists())

    def test_lost_ack_indeterminate_blocks_new_publishes_until_reconciled(self) -> None:
        with tempfile.TemporaryDirectory() as t:
            td = Path(t)
            expected = _seed_artifacts(td / "artifacts")
            cfg = _base_cfg(
                td,
                expected_assets=expected,
                faults=rp.FaultSchedule(lost_ack_on_root_publish=True),
            )
            res = rp.publish_release(cfg)
            self.assertEqual(res["state"], "indeterminate", res)
            self.assertEqual(res["errorCode"], "lost_ack_root_publish")

            # New unrelated release MUST be blocked while indeterminate release exists.
            cfg_other = _base_cfg(
                td,
                release_id="rel:2026-11-21:v0.1.1",
                version="0.1.1",
                expected_assets=expected,
                lease_fence=2,
            )
            blocked = rp.publish_release(cfg_other)
            self.assertEqual(blocked["state"], "failed")
            self.assertEqual(blocked["errorCode"], "indeterminate_pending")

            # Reconcile inspects remote store, downloads & verifies all assets, settles to published!
            rec = rp.reconcile_indeterminate(cfg.release_id, td / "remote", td / "state")
            self.assertEqual(rec["state"], "published", rec)
            self.assertEqual(rec["reconciled"], "confirmed_published")

            # Also verify confirmed_not_published branch when remote root is absent.
            cfg2 = _base_cfg(
                td,
                release_id="rel:2026-11-21:v0.2.0",
                version="0.2.0",
                remote_store_dir=td / "remote2",
                state_dir=td / "state2",
                expected_assets=expected,
                faults=rp.FaultSchedule(lost_ack_on_root_publish=True),
            )
            res2 = rp.publish_release(cfg2)
            self.assertEqual(res2["state"], "indeterminate")
            (td / "remote2" / "root" / rp.ROOT_MANIFEST_NAME).unlink()
            rec_not = rp.reconcile_indeterminate(cfg2.release_id, td / "remote2", td / "state2")
            self.assertEqual(rec_not["state"], "failed")
            self.assertEqual(rec_not["reconciled"], "confirmed_not_published")

    def test_cancellation_at_every_boundary_leaves_root_unpublished(self) -> None:
        with tempfile.TemporaryDirectory() as t:
            td = Path(t)
            expected = _seed_artifacts(td / "artifacts")
            for stage in ("prepare", "upload_asset", "download_verify", "publish_root"):
                remote = td / f"remote_{stage}"
                state = td / f"state_{stage}"
                cfg = _base_cfg(
                    td,
                    expected_assets=expected,
                    remote_store_dir=remote,
                    state_dir=state,
                    faults=rp.FaultSchedule(cancel_at=stage),
                )
                res = rp.publish_release(cfg)
                self.assertEqual(res["state"], "cancelled", f"stage={stage}: {res}")
                self.assertFalse((remote / "root" / rp.ROOT_MANIFEST_NAME).exists())

    def test_authority_latest_pressure_budget_secret_temp_sbom_and_journal_tamper_refusals(self) -> None:
        with tempfile.TemporaryDirectory() as t:
            td = Path(t)
            expected = _seed_artifacts(td / "artifacts")

            # Floating "latest" version refused.
            r_latest = rp.publish_release(_base_cfg(td, version="v1.0.0-latest", expected_assets=expected))
            self.assertEqual(r_latest["errorCode"], "forbidden_latest_alias")

            # Builder == signer refused (FSS-191).
            r_same = rp.publish_release(
                _base_cfg(td, builder_identity="same:id", signer_identity="same:id", expected_assets=expected)
            )
            self.assertEqual(r_same["errorCode"], "same_authority_refused")

            # Wrong capability refused.
            r_cap = rp.publish_release(_base_cfg(td, capability="release:read", expected_assets=expected))
            self.assertEqual(r_cap["errorCode"], "authority_refused")

            # Critical pressure refused.
            r_press = rp.publish_release(_base_cfg(td, pressure="critical", expected_assets=expected))
            self.assertEqual(r_press["errorCode"], "pressure_refused")

            # Tight byte budget refused before upload.
            r_budget = rp.publish_release(_base_cfg(td, max_total_bytes=8, expected_assets=expected))
            self.assertEqual(r_budget["errorCode"], "budget_exceeded")

            # Secret filename refused.
            sec_dir = td / "artifacts_secret"
            _seed_artifacts(sec_dir)
            (sec_dir / "signing.key").write_bytes(b"not-a-real-key")
            r_sec = rp.publish_release(_base_cfg(td, artifacts_dir=sec_dir))
            self.assertEqual(r_sec["errorCode"], "forbidden_secret_asset")

            # Leftover atomic temp file refused (FSS-189 / fss-0uofb).
            tmp_dir = td / "artifacts_temp"
            _seed_artifacts(tmp_dir)
            (tmp_dir / ".SHA256SUMS.txt.tmp.12345.0").write_bytes(b"partial")
            r_tmp = rp.publish_release(_base_cfg(td, artifacts_dir=tmp_dir))
            self.assertEqual(r_tmp["errorCode"], "leftover_atomic_temp")

            # SBOM cross-check mismatch refused before upload (FSS-190).
            sbom_leg = _seed_sbom_leg(td)
            sbom_leg["receipt"].write_text(json.dumps({"status": "failed", "cargoLockDigest": "sha256:00"}), encoding="utf-8")
            r_sbom = rp.publish_release(
                _base_cfg(
                    td,
                    expected_assets=expected,
                    sbom_path=sbom_leg["sbom"],
                    license_inventory_path=sbom_leg["inventory"],
                    cargo_lock_path=sbom_leg["lock"],
                    metadata_path=sbom_leg["metadata"],
                    qualification_receipt_path=sbom_leg["receipt"],
                )
            )
            self.assertEqual(r_sbom["errorCode"], "sbom_crosscheck_failed")

            # Stale lease fence & tampered journal refused.
            ok_pub = rp.publish_release(_base_cfg(td, expected_assets=expected, lease_fence=5))
            self.assertEqual(ok_pub["state"], "published")
            r_fence = rp.publish_release(
                _base_cfg(td, release_id="rel:fence-stale", version="0.1.1", expected_assets=expected, lease_fence=4)
            )
            self.assertEqual(r_fence["errorCode"], "stale_lease_fence")

            jpath = td / "state" / rp.JOURNAL_FILENAME
            jpath.write_text(jpath.read_text(encoding="utf-8").replace("0.1.0", "9.9.9", 1), encoding="utf-8")
            r_tamper = rp.publish_release(
                _base_cfg(td, release_id="rel:after-tamper", version="0.1.2", expected_assets=expected, lease_fence=6)
            )
            self.assertEqual(r_tamper["errorCode"], "journal_corrupt")

    def test_cli_publish_and_verify_subprocess_roundtrip(self) -> None:
        with tempfile.TemporaryDirectory() as t:
            td = Path(t)
            _seed_artifacts(td / "artifacts")
            cmd = [
                sys.executable,
                str(SCRIPTS_DIR / "release_publication.py"),
                "publish",
                "--release-id",
                "rel:cli:v0.1.0",
                "--version",
                "0.1.0",
                "--artifacts-dir",
                str(td / "artifacts"),
                "--remote-store-dir",
                str(td / "remote"),
                "--state-dir",
                str(td / "state"),
                "--principal",
                "operator:cli",
                "--builder",
                "builder:dsr-1",
                "--signer",
                "signer:hsm-1",
                "--contract-basis-digest",
                BASIS_DIGEST,
            ]
            proc = subprocess.run(cmd, capture_output=True, text=True, timeout=30)
            self.assertEqual(proc.returncode, 0, proc.stdout + proc.stderr)
            out = json.loads(proc.stdout)
            self.assertEqual(out["state"], "published")

            vproc = subprocess.run(
                [sys.executable, str(SCRIPTS_DIR / "release_publication.py"), "verify", "--remote-store-dir", str(td / "remote")],
                capture_output=True,
                text=True,
                timeout=30,
            )
            self.assertEqual(vproc.returncode, 0, vproc.stdout + vproc.stderr)
            vout = json.loads(vproc.stdout)
            self.assertEqual(vout["state"], "verified")
            self.assertEqual(vout["rootDigest"], out["rootDigest"])

    def test_post_publish_root_readback_failure_enters_indeterminate_and_reconciles(self) -> None:
        with tempfile.TemporaryDirectory() as t:
            td = Path(t)
            expected = _seed_artifacts(td / "artifacts")
            cfg = _base_cfg(
                td,
                release_id="rel:readback-fail",
                version="0.1.0",
                expected_assets=expected,
                faults=rp.FaultSchedule(fail_post_publish_root_check=True),
            )
            res = rp.publish_release(cfg)
            self.assertEqual(res["state"], "indeterminate")
            self.assertEqual(res["errorCode"], "post_publish_readback_failed")

            # Subsequent publish MUST be blocked until indeterminate is reconciled!
            blocked = rp.publish_release(
                _base_cfg(td, release_id="rel:blocked-after-readback", version="0.1.1", expected_assets=expected, lease_fence=2)
            )
            self.assertEqual(blocked["errorCode"], "indeterminate_pending")

            # Reconcile confirms the root landed intact and transitions cleanly to published!
            rec = rp.reconcile_indeterminate("rel:readback-fail", td / "remote", td / "state")
            self.assertEqual(rec["state"], "published")
            self.assertEqual(rec["reconciled"], "confirmed_published")

    def test_release_qualify_wrapper_publishes_and_verifies_remote(self) -> None:
        with tempfile.TemporaryDirectory() as t:
            td = Path(t)
            _seed_artifacts(td / "artifacts")
            pub = subprocess.run(
                [
                    "bash",
                    str(SCRIPTS_DIR / "release_qualify.sh"),
                    "publish",
                    "--release-id",
                    "rel:rq:v0.2.0",
                    "--version",
                    "0.2.0",
                    "--artifacts-dir",
                    str(td / "artifacts"),
                    "--remote-store-dir",
                    str(td / "remote"),
                    "--state-dir",
                    str(td / "state"),
                    "--principal",
                    "operator:rq",
                    "--builder",
                    "builder:dsr-1",
                    "--signer",
                    "signer:hsm-1",
                    "--contract-basis-digest",
                    BASIS_DIGEST,
                ],
                capture_output=True,
                text=True,
                timeout=30,
            )
            self.assertEqual(pub.returncode, 0, pub.stdout + pub.stderr)
            pub_out = json.loads(pub.stdout)
            self.assertEqual(pub_out["state"], "published")

            ver = subprocess.run(
                [
                    "bash",
                    str(SCRIPTS_DIR / "release_qualify.sh"),
                    "verify-remote",
                    "--remote-store-dir",
                    str(td / "remote"),
                ],
                capture_output=True,
                text=True,
                timeout=30,
            )
            self.assertEqual(ver.returncode, 0, ver.stdout + ver.stderr)
            ver_out = json.loads(ver.stdout)
            self.assertEqual(ver_out["state"], "verified")
            self.assertEqual(ver_out["rootDigest"], pub_out["rootDigest"])


if __name__ == "__main__":
    unittest.main()
