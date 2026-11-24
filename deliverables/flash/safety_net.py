#!/usr/bin/env python3
"""Flash safety-net CLI: manifest, verify, restore-capsule builder, and QEMU MTD drill.

Implements the pre-flash safety contract (bead fss-flash-safety-net-8th46):
  1. Per-family MTD layout registry (verified chip layouts only; unknown layouts marked honestly).
  2. SHA-256 + byte-size manifest generation & strict verification (catches truncation & bit-flips).
  3. Stock restore-capsule assembly with dm-verity coherence enforcement (refuses incoherent
     partial `system` or `boot` restores on dm-verity devices like Wyze HL_CAM4).
  4. Real `qemu-mipsel` emulated MTD drill:
       stock MTDs -> real wyze-capsule-4.52.17.106.tar flash (streams backups to wyze_backup_recv,
       writes Thingino) -> verify backup -> corrupt copy fails verify -> dm-verity refusal check ->
       build stock restore capsule -> run restore capsule under qemu-mipsel -> assert ALL 6 MTDs
       match original stock byte-for-byte + negative refusal controls (bad map, bad SHA-256).
"""
from __future__ import annotations

import argparse
import dataclasses
import datetime
import functools
import hashlib
import http.server
import json
import os
import re
import shutil
import socketserver
import subprocess
import sys
import tarfile
import tempfile
import threading
import time
from typing import Any

HERE = os.path.dirname(os.path.abspath(__file__))
REPO_ROOT = os.path.normpath(os.path.join(HERE, "..", ".."))
SCRIPTS_DIR = os.path.join(REPO_ROOT, "deliverables", "scripts")
FIRMWARE_DIR = os.path.join(REPO_ROOT, "deliverables", "firmware")

if SCRIPTS_DIR not in sys.path:
    sys.path.insert(0, SCRIPTS_DIR)

import build_ota_tar  # noqa: E402
import wyze_backup_recv  # noqa: E402

MANIFEST_SCHEMA = "fss.flash_backup_manifest.v1"


@dataclasses.dataclass(frozen=True)
class PartitionSpec:
    slot: int
    name: str
    size_bytes: int
    offset_bytes: int
    erase_bytes: int = 0x10000
    dm_verity: bool = False
    crc_gate: bool = False
    chip: str = "nor0"
    notes: str = ""


@dataclasses.dataclass(frozen=True)
class FamilySpec:
    family: str
    soc: str
    arch: str
    total_bytes: int
    live_mtd_layout_verified: bool
    dm_verity_coupled_partitions: tuple[str, ...]
    partitions: tuple[PartitionSpec, ...]
    brick_recovery_doc: str
    notes: str


# Grounded strictly in verified repo docs:
#   - wyze-hl_cam4: docs/exploit/flash-plan.md, deliverables/scripts/upgraderun.sh, ota_sim.sh
#   - tapo-c460:    docs/exploit/c460-flash-layout.md (nor0 + nor1)
#   - tapo-c660:    docs/exploit/c660-flash-plan.md (32 MiB SPI NOR, verify CRC gate at mtd4)
#   - yi/aosu/owlet: live /proc/mtd has NOT been dumped on our units; never fabricate sizes.
FAMILIES: dict[str, FamilySpec] = {
    "wyze-hl_cam4": FamilySpec(
        family="wyze-hl_cam4",
        soc="Ingenic T41NQ",
        arch="mipsel",
        total_bytes=16_777_216,
        live_mtd_layout_verified=True,
        dm_verity_coupled_partitions=("boot", "system"),
        partitions=(
            PartitionSpec(0, "uboot", 0x80000, 0x000000, notes="SPL + U-Boot + env (write LAST)"),
            PartitionSpec(1, "boot", 0x280000, 0x080000, notes="Kernel FIT + initramfs + dm-verity root hash"),
            PartitionSpec(2, "system", 0x5C0000, 0x300000, dm_verity=True, notes="SquashFS rootfs with dm-verity"),
            PartitionSpec(3, "back", 0x5C0000, 0x8C0000, notes="Backup bank"),
            PartitionSpec(4, "cfg", 0x100000, 0xE80000, notes="JFFS2 persistent config"),
            PartitionSpec(5, "provisioning", 0x80000, 0xF80000, notes="Device identity/MAC/RF calibration"),
        ),
        brick_recovery_doc="deliverables/flash/wyze-hl_cam4/BRICK-RECOVERY.md",
        notes="16 MiB SPI NOR; mtd2(system) is dm-verity coupled to mtd1(boot).",
    ),
    "tapo-c460": FamilySpec(
        family="tapo-c460",
        soc="SigmaStar SSC30KQ (SSC30X)",
        arch="arm",
        total_bytes=33_554_432,
        live_mtd_layout_verified=True,
        dm_verity_coupled_partitions=(),
        partitions=(
            PartitionSpec(0, "BOOT", 0x05F000, 0x000000, chip="nor0", notes="U-Boot 2021.10"),
            PartitionSpec(1, "ENV", 0x001000, 0x05F000, chip="nor0", notes="U-Boot env"),
            PartitionSpec(2, "VERIFY", 0x010000, 0x060000, chip="nor0", crc_gate=True, notes="Updater verify partition"),
            PartitionSpec(3, "factoryinfo", 0x010000, 0x070000, chip="nor0", notes="MAC/calibration — never overwrite"),
            PartitionSpec(4, "KERNEL", 0x2A0000, 0x080000, chip="nor0", notes="Linux kernel"),
            PartitionSpec(5, "MISC", 0x200000, 0x320000, chip="nor0"),
            PartitionSpec(6, "RTOS", 0x300000, 0x520000, chip="nor0"),
            PartitionSpec(7, "RAMDISK", 0x500000, 0x820000, chip="nor0", notes="Initramfs root"),
            PartitionSpec(8, "config", 0x010000, 0xD20000, chip="nor0"),
            PartitionSpec(9, "usrrecord", 0x2D0000, 0xD30000, chip="nor0"),
            PartitionSpec(10, "IPLXXX", 0x010000, 0x000000, chip="nor1"),
            PartitionSpec(11, "rootfs", 0x7F0000, 0x010000, chip="nor1"),
            PartitionSpec(12, "objdmodel", 0x800000, 0x800000, chip="nor1"),
        ),
        brick_recovery_doc="deliverables/flash/tapo-c460/BRICK-RECOVERY.md",
        notes="Dual 16 MiB SPI NOR (nor0 + nor1 = 32 MiB) from c460-flash-layout.md; confirm live /proc/mtd before writing.",
    ),
    "tapo-c660": FamilySpec(
        family="tapo-c660",
        soc="Novatek NS02301 (nvt98567, Cortex-A7)",
        arch="arm",
        total_bytes=33_554_432,
        live_mtd_layout_verified=True,
        dm_verity_coupled_partitions=("verify", "kernel", "rootfs"),
        partitions=(
            PartitionSpec(0, "loader", 0x010000, 0x000000),
            PartitionSpec(1, "fdt", 0x080000, 0x010000),
            PartitionSpec(2, "fdt.fast", 0x040000, 0x090000),
            PartitionSpec(3, "uboot", 0x080000, 0x0D0000),
            PartitionSpec(4, "verify", 0x010000, 0x150000, crc_gate=True, notes="U-Boot CRC bookkeeping gate"),
            PartitionSpec(5, "factoryinfo", 0x010000, 0x160000, notes="MAC/calibration — never overwrite"),
            PartitionSpec(6, "config", 0x020000, 0x170000),
            PartitionSpec(7, "rtos", 0x370000, 0x190000),
            PartitionSpec(8, "kernel", 0x4A0000, 0x500000),
            PartitionSpec(9, "rootfs", 0x560000, 0x9A0000),
            PartitionSpec(10, "source_fast", 0x100000, 0xF00000),
            PartitionSpec(11, "userrecord", 0x400000, 0x1000000),
            PartitionSpec(12, "service", 0x600000, 0x1400000),
            PartitionSpec(13, "objdmodel", 0x600000, 0x1A00000),
        ),
        brick_recovery_doc="deliverables/flash/tapo-c660/BRICK-RECOVERY.md",
        notes="32 MiB SPI NOR from c660-flash-plan.md; mtd4(verify) enforces partition CRC.",
    ),
    "yi": FamilySpec(
        family="yi",
        soc="Unknown (ARMv7 armeabi-v7a, Zowee OUI B0:D5:9D)",
        arch="arm",
        total_bytes=0,
        live_mtd_layout_verified=False,
        dm_verity_coupled_partitions=(),
        partitions=(),
        brick_recovery_doc="deliverables/flash/yi/BRICK-RECOVERY.md",
        notes="Live /proc/mtd unread; camera offline/asleep. Never assume sizes before live dump.",
    ),
    "aosu": FamilySpec(
        family="aosu",
        soc="Unknown (HomeBase H2E fw 2.10.5 + 4x SolarCam C8S2EA11)",
        arch="arm",
        total_bytes=0,
        live_mtd_layout_verified=False,
        dm_verity_coupled_partitions=(),
        partitions=(),
        brick_recovery_doc="deliverables/flash/aosu/BRICK-RECOVERY.md",
        notes="A/B bank semantics via TuyaOS TUYA_OTA_FULL; live /proc/mtd unread until local_key + shell.",
    ),
    "owlet": FamilySpec(
        family="owlet",
        soc="Unknown (Shenzhen Bilian Wi-Fi module, TUTK/Kalay SDK)",
        arch="unknown",
        total_bytes=0,
        live_mtd_layout_verified=False,
        dm_verity_coupled_partitions=(),
        partitions=(),
        brick_recovery_doc="deliverables/flash/owlet/BRICK-RECOVERY.md",
        notes="Cloud-gated TUTK credentials; live /proc/mtd unread.",
    ),
}


def utc_now() -> str:
    return datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def sha256_file(path: str) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as fh:
        while True:
            chunk = fh.read(1 << 20)
            if not chunk:
                break
            h.update(chunk)
    return h.hexdigest()


def md5_file(path: str) -> str:
    h = hashlib.md5()
    with open(path, "rb") as fh:
        while True:
            chunk = fh.read(1 << 20)
            if not chunk:
                break
            h.update(chunk)
    return h.hexdigest()


def get_family(name: str) -> FamilySpec:
    if name not in FAMILIES:
        raise ValueError(f"unknown family {name!r}; expected one of {sorted(FAMILIES)}")
    return FAMILIES[name]


def build_manifest(family_name: str, backup_dir: str, out_path: str | None = None) -> dict[str, Any]:
    fam = get_family(family_name)
    if not fam.live_mtd_layout_verified or not fam.partitions:
        raise ValueError(
            f"family {family_name!r} has no verified MTD partition table yet; dump /proc/mtd first"
        )
    backup_dir = os.path.abspath(backup_dir)
    partitions_doc: dict[str, dict[str, Any]] = {}
    total_bytes = 0
    errors: list[dict[str, Any]] = []

    for spec in fam.partitions:
        key = f"mtd{spec.slot}"
        filename = f"{key}.bin"
        fpath = os.path.join(backup_dir, filename)
        if not os.path.isfile(fpath):
            errors.append({"partition": key, "name": spec.name, "code": "MISSING_PARTITION", "path": fpath})
            continue
        actual_size = os.path.getsize(fpath)
        if actual_size == 0:
            errors.append({"partition": key, "name": spec.name, "code": "ZERO_BYTES", "expected_size": spec.size_bytes})
            continue
        if actual_size != spec.size_bytes:
            errors.append(
                {
                    "partition": key,
                    "name": spec.name,
                    "code": "SIZE_MISMATCH",
                    "expected_size": spec.size_bytes,
                    "actual_size": actual_size,
                }
            )
            continue
        digest = sha256_file(fpath)
        total_bytes += actual_size
        partitions_doc[key] = {
            "slot": spec.slot,
            "name": spec.name,
            "filename": filename,
            "offset_bytes": spec.offset_bytes,
            "size_bytes": actual_size,
            "sha256": digest,
            "dm_verity": spec.dm_verity,
            "crc_gate": spec.crc_gate,
            "chip": spec.chip,
        }

    if not errors and total_bytes != fam.total_bytes:
        errors.append(
            {
                "partition": "*",
                "code": "TOTAL_SIZE_MISMATCH",
                "expected_total": fam.total_bytes,
                "actual_total": total_bytes,
            }
        )

    if errors:
        raise RuntimeError(json.dumps({"ok": False, "family": family_name, "errors": errors}, indent=2))

    doc = {
        "schema_version": MANIFEST_SCHEMA,
        "family": fam.family,
        "soc": fam.soc,
        "arch": fam.arch,
        "dir": backup_dir,
        "generated_at_utc": utc_now(),
        "total_bytes": total_bytes,
        "complete_slots": [spec.slot for spec in fam.partitions],
        "partitions": partitions_doc,
    }
    target = out_path or os.path.join(backup_dir, "manifest.json")
    tmp = f"{target}.tmp.{os.getpid()}.{threading.get_ident()}"
    try:
        with open(tmp, "w", encoding="utf-8") as fh:
            json.dump(doc, fh, indent=2)
            fh.write("\n")
            fh.flush()
            os.fsync(fh.fileno())
        os.replace(tmp, target)
    except BaseException:
        if os.path.exists(tmp):
            try:
                os.unlink(tmp)
            except OSError:
                pass
        raise
    return doc


def verify_backup(
    family_name: str,
    backup_dir: str,
    manifest_path: str | None = None,
) -> dict[str, Any]:
    fam = get_family(family_name)
    if not fam.live_mtd_layout_verified or not fam.partitions:
        return {
            "ok": False,
            "family": family_name,
            "errors": [{"partition": "*", "code": "LAYOUT_UNVERIFIED", "detail": fam.notes}],
        }

    backup_dir = os.path.abspath(backup_dir)
    mpath = manifest_path or os.path.join(backup_dir, "manifest.json")
    errors: list[dict[str, Any]] = []
    verified: list[dict[str, Any]] = []

    if not os.path.isfile(mpath):
        return {
            "ok": False,
            "family": family_name,
            "manifest": mpath,
            "errors": [{"partition": "*", "code": "MISSING_MANIFEST", "path": mpath}],
        }

    try:
        with open(mpath, "r", encoding="utf-8") as fh:
            manifest = json.load(fh)
    except (OSError, json.JSONDecodeError) as exc:
        return {
            "ok": False,
            "family": family_name,
            "manifest": mpath,
            "errors": [{"partition": "*", "code": "INVALID_MANIFEST", "detail": str(exc)}],
        }

    if not isinstance(manifest, dict):
        return {
            "ok": False,
            "family": family_name,
            "manifest": mpath,
            "errors": [{"partition": "*", "code": "INVALID_MANIFEST", "detail": "manifest root must be JSON object"}],
        }

    mparts = manifest.get("partitions")
    if not isinstance(mparts, dict):
        return {
            "ok": False,
            "family": family_name,
            "manifest": mpath,
            "errors": [{"partition": "*", "code": "INVALID_MANIFEST", "detail": "missing partitions dict"}],
        }

    total_bytes = 0
    for spec in fam.partitions:
        key = f"mtd{spec.slot}"
        entry = mparts.get(key)
        if not isinstance(entry, dict):
            errors.append({"partition": key, "name": spec.name, "code": "MISSING_MANIFEST_ENTRY"})
            continue
        filename = entry.get("filename") or f"{key}.bin"
        if (
            not isinstance(filename, str)
            or os.path.basename(filename) != filename
            or filename in (".", "..")
            or "/" in filename
            or "\\" in filename
        ):
            errors.append({"partition": key, "name": spec.name, "code": "INVALID_FILENAME", "filename": filename})
            continue
        fpath = os.path.join(backup_dir, filename)
        if not os.path.isfile(fpath):
            errors.append({"partition": key, "name": spec.name, "code": "MISSING_PARTITION", "path": fpath})
            continue
        actual_size = os.path.getsize(fpath)
        if actual_size == 0:
            errors.append(
                {
                    "partition": key,
                    "name": spec.name,
                    "code": "ZERO_BYTES",
                    "expected_size": spec.size_bytes,
                    "actual_size": 0,
                }
            )
            continue
        if actual_size != spec.size_bytes:
            errors.append(
                {
                    "partition": key,
                    "name": spec.name,
                    "code": "SIZE_MISMATCH",
                    "expected_size": spec.size_bytes,
                    "actual_size": actual_size,
                }
            )
            continue
        manifest_size = entry.get("size_bytes")
        if manifest_size is not None:
            try:
                if isinstance(manifest_size, bool):
                    raise TypeError("bool is not a valid byte size")
                msz_int = int(manifest_size)
            except (ValueError, TypeError):
                errors.append(
                    {
                        "partition": key,
                        "name": spec.name,
                        "code": "MANIFEST_SIZE_MISMATCH",
                        "expected_size": spec.size_bytes,
                        "manifest_size": manifest_size,
                    }
                )
                continue
            if msz_int != spec.size_bytes:
                errors.append(
                    {
                        "partition": key,
                        "name": spec.name,
                        "code": "MANIFEST_SIZE_MISMATCH",
                        "expected_size": spec.size_bytes,
                        "manifest_size": manifest_size,
                    }
                )
                continue
        expected_sha = entry.get("sha256", "")
        if not isinstance(expected_sha, str) or len(expected_sha) != 64 or not re.fullmatch(r"[0-9a-fA-F]{64}", expected_sha):
            errors.append({"partition": key, "name": spec.name, "code": "MISSING_MANIFEST_SHA256"})
            continue
        actual_sha = sha256_file(fpath)
        if actual_sha != expected_sha.lower():
            errors.append(
                {
                    "partition": key,
                    "name": spec.name,
                    "code": "SHA256_MISMATCH",
                    "expected_sha256": expected_sha,
                    "actual_sha256": actual_sha,
                    "path": fpath,
                }
            )
            continue
        total_bytes += actual_size
        verified.append(
            {
                "partition": key,
                "name": spec.name,
                "size_bytes": actual_size,
                "sha256": actual_sha,
            }
        )

    if not errors and total_bytes != fam.total_bytes:
        errors.append(
            {
                "partition": "*",
                "code": "TOTAL_SIZE_MISMATCH",
                "expected_total": fam.total_bytes,
                "actual_total": total_bytes,
            }
        )

    return {
        "ok": len(errors) == 0,
        "family": fam.family,
        "dir": backup_dir,
        "manifest": mpath,
        "total_bytes": total_bytes,
        "verified_partitions": verified,
        "errors": errors,
    }


def check_verity_coherence(fam: FamilySpec, selected_names: set[str]) -> tuple[bool, str]:
    """Ensure coupled dm-verity or CRC-gated partitions are never restored incoherently."""
    coupled = set(fam.dm_verity_coupled_partitions)
    if not coupled:
        return True, "no coupled verity/CRC partitions declared"
    present = selected_names & coupled
    if present and present != coupled:
        missing = sorted(coupled - present)
        chosen = sorted(present)
        return (
            False,
            f"DM_VERITY_INCOHERENT: restoring {chosen} without coupled partition(s) {missing} "
            f"breaks boot/verity verification on {fam.family}",
        )
    return True, "coherent"


def build_restore_capsule(
    family_name: str,
    backup_dir: str,
    out_dir: str,
    host: str = "192.168.4.160",
    img_port: int = 8080,
    beacon_host: str | None = None,
    beacon_port: int = 8080,
    image_name: str = "stock-restore.bin",
    busybox_path: str | None = None,
    partitions_arg: str = "all",
    manifest_path: str | None = None,
) -> dict[str, Any]:
    fam = get_family(family_name)
    if fam.family != "wyze-hl_cam4":
        raise ValueError(f"OTA restore capsule builder currently supports wyze-hl_cam4 (got {family_name!r})")

    eff_beacon_host = beacon_host or host
    for label, val in (("host", host), ("beacon_host", eff_beacon_host)):
        if not isinstance(val, str) or not re.fullmatch(r"[A-Za-z0-9._:\-]+", val):
            raise ValueError(f"invalid {label} for shell template substitution: {val!r}")
    if not isinstance(image_name, str) or not re.fullmatch(r"[A-Za-z0-9._\-]+", image_name) or image_name in (".", ".."):
        raise ValueError(f"invalid image_name for shell template substitution: {image_name!r}")
    for label, port in (("img_port", img_port), ("beacon_port", beacon_port)):
        if not isinstance(port, int) or isinstance(port, bool) or not (1 <= port <= 65535):
            raise ValueError(f"invalid {label}: {port!r}")

    all_names = {p.name for p in fam.partitions}
    if partitions_arg.strip().lower() == "all":
        selected = set(all_names)
    else:
        selected = {p.strip() for p in partitions_arg.split(",") if p.strip()}
        unknown = selected - all_names
        if unknown:
            raise ValueError(f"unknown partition name(s): {sorted(unknown)}")

    coherent, reason = check_verity_coherence(fam, selected)
    if not coherent:
        raise PermissionError(reason)
    if selected != all_names:
        raise ValueError(
            "full 6-partition stock restore image is required for Wyze HL_CAM4 rollback "
            f"(requested subset {sorted(selected)}; pass --partitions all)"
        )

    ver = verify_backup(family_name, backup_dir, manifest_path=manifest_path)
    if not ver["ok"]:
        raise RuntimeError("backup verification failed before restore-capsule build:\n" + json.dumps(ver, indent=2))

    bb_path = busybox_path or os.path.join(FIRMWARE_DIR, "busybox-mipsel-static")
    if not os.path.isfile(bb_path):
        raise FileNotFoundError(f"static busybox not found at {bb_path}")

    os.makedirs(out_dir, exist_ok=True)
    stock_img_path = os.path.join(out_dir, image_name)
    stock_img_tmp = f"{stock_img_path}.tmp.{os.getpid()}.{threading.get_ident()}"
    per_part_sha: dict[str, str] = {}
    full_hasher = hashlib.sha256()
    written = 0
    try:
        with open(stock_img_tmp, "wb") as out_fh:
            for spec in fam.partitions:
                part_file = os.path.join(backup_dir, f"mtd{spec.slot}.bin")
                with open(part_file, "rb") as in_fh:
                    blob = in_fh.read()
                if len(blob) != spec.size_bytes:
                    raise RuntimeError(f"mtd{spec.slot} size mismatch during assembly")
                out_fh.write(blob)
                full_hasher.update(blob)
                per_part_sha[f"mtd{spec.slot}"] = hashlib.sha256(blob).hexdigest()
                written += len(blob)
            out_fh.flush()
            os.fsync(out_fh.fileno())
        if written != fam.total_bytes:
            raise RuntimeError(f"assembled stock image is {written} bytes, expected {fam.total_bytes}")
        os.replace(stock_img_tmp, stock_img_path)
    except BaseException:
        if os.path.exists(stock_img_tmp):
            try:
                os.unlink(stock_img_tmp)
            except OSError:
                pass
        raise
    stock_sha = full_hasher.hexdigest()

    template_path = os.path.join(HERE, "restore_stock.sh")
    with open(template_path, "r", encoding="utf-8") as fh:
        script = fh.read()

    subs = {
        "HOST": host,
        "IMG_PORT": str(img_port),
        "IMAGE": image_name,
        "SHA256": stock_sha,
        "BEACON_HOST": beacon_host or host,
        "BEACON_PORT": str(beacon_port),
        "MTD0_SHA": per_part_sha["mtd0"],
        "MTD1_SHA": per_part_sha["mtd1"],
        "MTD2_SHA": per_part_sha["mtd2"],
        "MTD3_SHA": per_part_sha["mtd3"],
        "MTD4_SHA": per_part_sha["mtd4"],
        "MTD5_SHA": per_part_sha["mtd5"],
    }
    for k, v in subs.items():
        script = script.replace(f"@{k}@", v)

    with open(bb_path, "rb") as fh:
        bb_bytes = fh.read()

    tar_bytes = build_ota_tar.build_tar(script, [("busybox", bb_bytes)])
    capsule_path = os.path.join(out_dir, "Upgrade.tar")
    capsule_tmp = f"{capsule_path}.tmp.{os.getpid()}.{threading.get_ident()}"
    try:
        with open(capsule_tmp, "wb") as fh:
            fh.write(tar_bytes)
            fh.flush()
            os.fsync(fh.fileno())
        os.replace(capsule_tmp, capsule_path)
    except BaseException:
        if os.path.exists(capsule_tmp):
            try:
                os.unlink(capsule_tmp)
            except OSError:
                pass
        raise

    receipt = {
        "ok": True,
        "family": fam.family,
        "dm_verity_coherent": True,
        "capsule_path": os.path.abspath(capsule_path),
        "capsule_size_bytes": len(tar_bytes),
        "capsule_md5": hashlib.md5(tar_bytes).hexdigest(),
        "capsule_sha256": hashlib.sha256(tar_bytes).hexdigest(),
        "stock_image_path": os.path.abspath(stock_img_path),
        "stock_image_size_bytes": written,
        "stock_image_sha256": stock_sha,
        "per_partition_sha256": per_part_sha,
        "rendered_at_utc": utc_now(),
    }
    receipt_path = os.path.join(out_dir, "restore_receipt.json")
    receipt_tmp = f"{receipt_path}.tmp.{os.getpid()}.{threading.get_ident()}"
    try:
        with open(receipt_tmp, "w", encoding="utf-8") as fh:
            json.dump(receipt, fh, indent=2)
            fh.write("\n")
            fh.flush()
            os.fsync(fh.fileno())
        os.replace(receipt_tmp, receipt_path)
    except BaseException:
        if os.path.exists(receipt_tmp):
            try:
                os.unlink(receipt_tmp)
            except OSError:
                pass
        raise
    return receipt


class _QuietHTTPHandler(http.server.SimpleHTTPRequestHandler):
    beacons: list[str] = []

    def do_GET(self):
        if self.path.startswith("/fss-ran"):
            self.beacons.append(self.path)
            self.send_response(200)
            self.send_header("Content-Length", "2")
            self.end_headers()
            self.wfile.write(b"ok")
            return
        return super().do_GET()

    def log_message(self, fmt, *args):
        pass


class _LocalHTTPServer:
    def __init__(self, directory: str):
        self.directory = directory
        self.beacons: list[str] = []
        handler_cls = type(
            "_DrillHandler",
            (_QuietHTTPHandler,),
            {"beacons": self.beacons},
        )
        bound = functools.partial(handler_cls, directory=directory)
        self._srv = socketserver.ThreadingTCPServer(("127.0.0.1", 0), bound)
        self._srv.daemon_threads = True
        self.port = self._srv.server_address[1]
        self._thread = threading.Thread(target=self._srv.serve_forever, daemon=True)

    def start(self) -> None:
        self._thread.start()

    def stop(self) -> None:
        self._srv.shutdown()
        self._srv.server_close()
        self._thread.join(timeout=2.0)


def _deterministic_partition_bytes(slot: int, name: str, size: int) -> bytes:
    """Create deterministic, distinct, non-trivial synthetic stock partition contents."""
    # Repeat a partition-unique 4096-byte page seeded by SHA-256 with page-index tags
    # so every 4 KiB block across all 6 partitions is distinct and verifiable.
    out = bytearray(size)
    seed_prefix = f"FSS-STOCK-SYNTHETIC:{slot}:{name}:".encode()
    header = hashlib.sha256(seed_prefix).digest()
    block_count = size // 4096
    # Build a 4096-byte deterministic base pattern, then stamp unique block index per 4 KiB page.
    base_page = bytearray(header * 128)  # 32 * 128 = 4096
    for idx in range(block_count):
        off = idx * 4096
        out[off : off + 4096] = base_page
        tag = f"P{slot}:{idx:05d}".encode()
        out[off : off + len(tag)] = tag
    return bytes(out)


def _write_proc_mtd(path: str, specs: list[tuple[int, str, int]]) -> None:
    lines = ["dev:    size   erasesize  name"]
    for slot, name, size in specs:
        lines.append(f'mtd{slot}: {size:08x} 00010000 "{name}"')
    with open(path, "w", encoding="utf-8") as fh:
        fh.write("\n".join(lines) + "\n")


def _make_qemu_bb_wrapper(wrapper_path: str, qemu_bin: str, busybox_bin: str) -> None:
    # Busybox selects applet by argv[0]; wrapper must NOT be named `busybox`.
    # Intercept `reboot` cleanly so emulated drills don't invoke reboot(2).
    script = (
        "#!/bin/sh\n"
        'if [ "${1:-}" = "reboot" ]; then\n'
        '  echo "[sim] reboot intercepted"\n'
        "  exit 0\n"
        "fi\n"
        f'exec "{qemu_bin}" "{busybox_bin}" "$@"\n'
    )
    with open(wrapper_path, "w", encoding="utf-8") as fh:
        fh.write(script)
    os.chmod(wrapper_path, 0o755)


def _safe_extractall(tf: tarfile.TarFile, dest: str) -> None:
    if hasattr(tarfile, "data_filter"):
        tf.extractall(dest, filter="data")
    else:
        tf.extractall(dest)


def run_wyze_drill(
    work_dir: str | None = None,
    qemu_bin: str = "qemu-mipsel",
    capsule_tar: str | None = None,
    thingino_img: str | None = None,
    busybox_bin: str | None = None,
) -> dict[str, Any]:
    """Execute the full emulated MTD safety-net drill for wyze-hl_cam4."""
    fam = get_family("wyze-hl_cam4")
    qemu_path = shutil.which(qemu_bin)
    if not qemu_path:
        raise FileNotFoundError(f"{qemu_bin} not found in PATH; install qemu-user to run emulated MTD drill")

    cap_path = capsule_tar or os.path.join(FIRMWARE_DIR, "wyze-capsule-4.52.17.106.tar")
    img_path = thingino_img or os.path.join(
        FIRMWARE_DIR, "thingino-wyze_cam4_t41nq_os04d10_atbm6062s-tailnet.bin"
    )
    bb_src = busybox_bin or os.path.join(FIRMWARE_DIR, "busybox-mipsel-static")
    for p in (cap_path, img_path, bb_src):
        if not os.path.isfile(p):
            raise FileNotFoundError(f"required drill input missing: {p}")

    cleanup_work = False
    if work_dir is None:
        work_dir = tempfile.mkdtemp(prefix="fss-flash-drill-")
        cleanup_work = True
    else:
        os.makedirs(work_dir, exist_ok=True)

    http_srv = None
    backup_srv = None
    try:
        dev_dir = os.path.join(work_dir, "dev")
        http_dir = os.path.join(work_dir, "http")
        backup_dir = os.path.join(work_dir, "backups")
        corrupt_dir = os.path.join(work_dir, "corrupt_copy")
        restore_out = os.path.join(work_dir, "restore_capsule")
        cap_extract = os.path.join(work_dir, "cap_flash")
        restore_extract = os.path.join(work_dir, "cap_restore")
        for d in (dev_dir, http_dir, backup_dir, restore_out, cap_extract, restore_extract):
            os.makedirs(d, exist_ok=True)

        # ---- Phase 1: Seed synthetic stock MTDs + /proc/mtd ----------------
        stock_hashes: dict[str, str] = {}
        mtd_specs = [(p.slot, p.name, p.size_bytes) for p in fam.partitions]
        for spec in fam.partitions:
            blob = _deterministic_partition_bytes(spec.slot, spec.name, spec.size_bytes)
            with open(os.path.join(dev_dir, f"mtdblock{spec.slot}"), "wb") as fh:
                fh.write(blob)
            stock_hashes[f"mtd{spec.slot}"] = hashlib.sha256(blob).hexdigest()
        proc_mtd = os.path.join(work_dir, "proc_mtd")
        _write_proc_mtd(proc_mtd, mtd_specs)

        # Copy real Thingino image into HTTP serve dir
        shutil.copy2(img_path, os.path.join(http_dir, "img.bin"))
        with open(img_path, "rb") as fh:
            thingino_bytes = fh.read()
        thingino_sha = hashlib.sha256(thingino_bytes).hexdigest()

        # Start local HTTP server (image + beacons) and contiguous-port BackupServer
        http_srv = _LocalHTTPServer(http_dir)
        http_srv.start()

        # Find a free contiguous 6-port range for base_port+1..base_port+6
        base_port = None
        for cand in range(28440, 29400, 10):
            try:
                srv = wyze_backup_recv.BackupServer(
                    backup_dir=backup_dir,
                    base_port=cand,
                    slots=6,
                    family="wyze-hl_cam4",
                    bind_host="127.0.0.1",
                )
                srv.start()
                backup_srv = srv
                base_port = cand
                break
            except OSError:
                continue
        if backup_srv is None or base_port is None:
            raise RuntimeError("could not allocate 6 contiguous loopback ports for BackupServer")

        # ---- Phase 2: Execute REAL wyze-capsule-4.52.17.106.tar under qemu-mipsel ----
        with tarfile.open(cap_path, "r") as tf:
            _safe_extractall(tf, cap_extract)
        flash_bb = os.path.join(cap_extract, "Upgrade", "busybox")
        os.chmod(flash_bb, 0o755)
        flash_bb_wrap = os.path.join(cap_extract, "bb_wrap.sh")
        _make_qemu_bb_wrapper(flash_bb_wrap, qemu_path, flash_bb)

        flash_script = os.path.join(cap_extract, "Upgrade", "upgraderun.sh")
        with open(flash_script, "r", encoding="utf-8") as fh:
            s = fh.read()
        tmp_thingino = os.path.join(work_dir, "dl_thingino.bin")
        s = s.replace("/proc/mtd", proc_mtd)
        s = s.replace("/dev/mtdblock", os.path.join(dev_dir, "mtdblock"))
        s = s.replace("BB=/tmp/Upgrade/busybox", f"BB={flash_bb_wrap}")
        s = s.replace("HOST=192.168.4.160", "HOST=127.0.0.1")
        s = s.replace("PORT=443", f"PORT={base_port}")
        s = s.replace("IMG_PORT=8080", f"IMG_PORT={http_srv.port}")
        s = s.replace("BEACON_HOST=192.168.4.160", "BEACON_HOST=127.0.0.1")
        s = s.replace(":8080/fss-ran", f":{http_srv.port}/fss-ran")
        s = s.replace("/tmp/thingino.bin", tmp_thingino)
        s = s.replace("sleep 5", "sleep 0")
        with open(flash_script, "w", encoding="utf-8") as fh:
            fh.write(s)

        r_flash = subprocess.run(["sh", flash_script], capture_output=True, text=True, timeout=180)
        if r_flash.returncode != 0:
            raise RuntimeError(f"Phase 2 flash failed rc={r_flash.returncode}:\n{r_flash.stdout}\n{r_flash.stderr}")

        # Verify all 6 MTDs now match Thingino byte-exact
        off = 0
        for spec in fam.partitions:
            with open(os.path.join(dev_dir, f"mtdblock{spec.slot}"), "rb") as fh:
                actual = fh.read()
            expected = thingino_bytes[off : off + spec.size_bytes]
            if actual != expected:
                raise AssertionError(f"Phase 2: mtdblock{spec.slot} does not match Thingino slice")
            off += spec.size_bytes

        # Wait briefly for BackupServer manifest flush on final partition
        ver_clean = verify_backup("wyze-hl_cam4", backup_dir)
        deadline = time.time() + 5.0
        while not ver_clean["ok"] and time.time() < deadline:
            time.sleep(0.1)
            ver_clean = verify_backup("wyze-hl_cam4", backup_dir)
        if not ver_clean["ok"]:
            raise AssertionError(f"Phase 2: captured backup failed verify: {ver_clean}")

        # Verify captured backup hashes equal original synthetic stock hashes
        for entry in ver_clean["verified_partitions"]:
            part = entry["partition"]
            if entry["sha256"] != stock_hashes[part]:
                raise AssertionError(f"Phase 2: captured {part} hash != original stock hash")

        # ---- Phase 3: Corruption & truncation negative controls ------------
        shutil.copytree(backup_dir, corrupt_dir)
        mtd2_corrupt = os.path.join(corrupt_dir, "mtd2.bin")
        with open(mtd2_corrupt, "r+b") as fh:
            b0 = fh.read(1)
            fh.seek(0)
            fh.write(bytes([b0[0] ^ 0xFF]))
        ver_corrupt = verify_backup("wyze-hl_cam4", corrupt_dir)
        if ver_corrupt["ok"]:
            raise AssertionError("Phase 3: verify unexpectedly passed on bit-flipped mtd2.bin")
        corrupt_codes = [(e["partition"], e["code"]) for e in ver_corrupt["errors"]]
        if ("mtd2", "SHA256_MISMATCH") not in corrupt_codes:
            raise AssertionError(f"Phase 3: expected ('mtd2', 'SHA256_MISMATCH'), got {corrupt_codes}")

        # Truncation negative control
        mtd4_trunc = os.path.join(corrupt_dir, "mtd4.bin")
        with open(mtd4_trunc, "r+b") as fh:
            fh.truncate(4096)
        ver_trunc = verify_backup("wyze-hl_cam4", corrupt_dir)
        trunc_codes = [(e["partition"], e["code"]) for e in ver_trunc["errors"]]
        if ("mtd4", "SIZE_MISMATCH") not in trunc_codes:
            raise AssertionError(f"Phase 3: expected ('mtd4', 'SIZE_MISMATCH'), got {trunc_codes}")

        # ---- Phase 4: dm-verity coherence negative control -----------------
        verity_refused = False
        try:
            build_restore_capsule(
                family_name="wyze-hl_cam4",
                backup_dir=backup_dir,
                out_dir=os.path.join(work_dir, "bad_verity"),
                partitions_arg="system",
                busybox_path=bb_src,
            )
        except PermissionError as exc:
            if "DM_VERITY_INCOHERENT" in str(exc):
                verity_refused = True
        if not verity_refused:
            raise AssertionError("Phase 4: incoherent system-only restore was NOT refused")

        # ---- Phase 5: Build full stock restore capsule + run under qemu-mipsel ----
        restore_receipt = build_restore_capsule(
            family_name="wyze-hl_cam4",
            backup_dir=backup_dir,
            out_dir=restore_out,
            host="127.0.0.1",
            img_port=http_srv.port,
            beacon_host="127.0.0.1",
            beacon_port=http_srv.port,
            image_name="stock-restore.bin",
            busybox_path=bb_src,
        )
        # Assert OTA_MD5 matches built capsule file
        if md5_file(restore_receipt["capsule_path"]) != restore_receipt["capsule_md5"]:
            raise AssertionError("Phase 5: restore capsule MD5 mismatch")

        shutil.copy2(restore_receipt["stock_image_path"], os.path.join(http_dir, "stock-restore.bin"))

        with tarfile.open(restore_receipt["capsule_path"], "r") as tf:
            _safe_extractall(tf, restore_extract)
        rest_bb = os.path.join(restore_extract, "Upgrade", "busybox")
        os.chmod(rest_bb, 0o755)
        rest_bb_wrap = os.path.join(restore_extract, "bb_wrap.sh")
        _make_qemu_bb_wrapper(rest_bb_wrap, qemu_path, rest_bb)

        rest_script = os.path.join(restore_extract, "Upgrade", "upgraderun.sh")
        with open(rest_script, "r", encoding="utf-8") as fh:
            rs = fh.read()
        tmp_restore_img = os.path.join(work_dir, "dl_stock_restore.bin")
        rs_patched = (
            rs.replace("BB=/tmp/Upgrade/busybox", f"BB={rest_bb_wrap}")
            .replace("MTD_PROC=/proc/mtd", f"MTD_PROC={proc_mtd}")
            .replace("MTDBLK_PREFIX=/dev/mtdblock", f"MTDBLK_PREFIX={os.path.join(dev_dir, 'mtdblock')}")
            .replace("TMP_IMG=/tmp/stock-restore.bin", f"TMP_IMG={tmp_restore_img}")
        )
        with open(rest_script, "w", encoding="utf-8") as fh:
            fh.write(rs_patched)

        # ---- Phase 5a: Refusal control — wrong MTD layout writes 0 bytes ----
        bad_mtd = os.path.join(work_dir, "bad_proc_mtd")
        _write_proc_mtd(bad_mtd, [(0, "uboot", 0x40000), (1, "wrong", 0xFC0000)])
        bad_map_script = os.path.join(restore_extract, "bad_map_restore.sh")
        with open(bad_map_script, "w", encoding="utf-8") as fh:
            fh.write(rs_patched.replace(f"MTD_PROC={proc_mtd}", f"MTD_PROC={bad_mtd}"))
        r_bad_map = subprocess.run(["sh", bad_map_script], capture_output=True, text=True, timeout=60)
        if r_bad_map.returncode == 0 or "unexpected-mtd-map" not in (r_bad_map.stdout + r_bad_map.stderr):
            raise AssertionError(f"Phase 5a: wrong MTD map was not refused: rc={r_bad_map.returncode}")
        # Confirm MTDs are still untouched Thingino bytes
        if sha256_file(os.path.join(dev_dir, "mtdblock0")) != hashlib.sha256(thingino_bytes[:0x80000]).hexdigest():
            raise AssertionError("Phase 5a: bad MTD map modified mtdblock0!")

        # ---- Phase 5b: Refusal control — wrong HTTP image SHA-256 writes 0 bytes ----
        shutil.copy2(img_path, os.path.join(http_dir, "bad-stock.bin"))
        bad_sha_script = os.path.join(restore_extract, "bad_sha_restore.sh")
        with open(bad_sha_script, "w", encoding="utf-8") as fh:
            fh.write(rs_patched.replace("stock-restore.bin", "bad-stock.bin"))
        r_bad_sha = subprocess.run(["sh", bad_sha_script], capture_output=True, text=True, timeout=60)
        if r_bad_sha.returncode == 0 or "image-sha256-mismatch" not in (r_bad_sha.stdout + r_bad_sha.stderr):
            raise AssertionError(f"Phase 5b: wrong SHA-256 image was not refused: rc={r_bad_sha.returncode}")
        if sha256_file(os.path.join(dev_dir, "mtdblock0")) != hashlib.sha256(thingino_bytes[:0x80000]).hexdigest():
            raise AssertionError("Phase 5b: bad SHA-256 modified mtdblock0!")

        # ---- Phase 5c: Execute valid stock restore under qemu-mipsel -------
        r_restore = subprocess.run(["sh", rest_script], capture_output=True, text=True, timeout=180)
        if r_restore.returncode != 0:
            raise RuntimeError(
                f"Phase 5c stock restore failed rc={r_restore.returncode}:\n{r_restore.stdout}\n{r_restore.stderr}"
            )

        # Assert ALL 6 MTDs now match ORIGINAL stock hashes byte-for-byte!
        restored_hashes: dict[str, str] = {}
        for spec in fam.partitions:
            key = f"mtd{spec.slot}"
            actual_sha = sha256_file(os.path.join(dev_dir, f"mtdblock{spec.slot}"))
            restored_hashes[key] = actual_sha
            if actual_sha != stock_hashes[key]:
                raise AssertionError(
                    f"Phase 5c: restored {key} sha256 {actual_sha} != original stock {stock_hashes[key]}"
                )

        # ---- Phase 5d: Also prove restore works from Thingino's 6-part /proc/mtd map! ----
        # Flash Thingino back into synthetic Thingino-map MTD files, then restore stock over it.
        th_dev_dir = os.path.join(work_dir, "dev_thingino")
        os.makedirs(th_dev_dir, exist_ok=True)
        thingino_specs = [
            (0, "boot", 320 * 1024),
            (1, "env", 64 * 1024),
            (2, "backup", 64 * 1024),
            (3, "kernel", 1600 * 1024),
            (4, "rootfs", 13312 * 1024),
            (5, "data", 1024 * 1024),
        ]
        off = 0
        for slot, _name, sz in thingino_specs:
            with open(os.path.join(th_dev_dir, f"mtdblock{slot}"), "wb") as fh:
                fh.write(thingino_bytes[off : off + sz])
            off += sz
        th_proc_mtd = os.path.join(work_dir, "proc_mtd_thingino")
        _write_proc_mtd(th_proc_mtd, thingino_specs)
        th_restore_script = os.path.join(restore_extract, "thingino_map_restore.sh")
        with open(th_restore_script, "w", encoding="utf-8") as fh:
            fh.write(
                rs.replace("BB=/tmp/Upgrade/busybox", f"BB={rest_bb_wrap}")
                .replace("MTD_PROC=/proc/mtd", f"MTD_PROC={th_proc_mtd}")
                .replace("MTDBLK_PREFIX=/dev/mtdblock", f"MTDBLK_PREFIX={os.path.join(th_dev_dir, 'mtdblock')}")
                .replace("TMP_IMG=/tmp/stock-restore.bin", f"TMP_IMG={tmp_restore_img}")
            )
        r_th_restore = subprocess.run(["sh", th_restore_script], capture_output=True, text=True, timeout=180)
        if r_th_restore.returncode != 0:
            raise RuntimeError(
                f"Phase 5d Thingino-map restore failed rc={r_th_restore.returncode}:\n"
                f"{r_th_restore.stdout}\n{r_th_restore.stderr}"
            )
        # Re-assemble full chip from Thingino-map MTDs and verify SHA-256 == stock image!
        reassembled = hashlib.sha256()
        for slot, _name, _sz in thingino_specs:
            with open(os.path.join(th_dev_dir, f"mtdblock{slot}"), "rb") as fh:
                reassembled.update(fh.read())
        if reassembled.hexdigest() != restore_receipt["stock_image_sha256"]:
            raise AssertionError("Phase 5d: Thingino-map restored chip SHA-256 != original stock SHA-256")

        return {
            "ok": True,
            "family": "wyze-hl_cam4",
            "mode": "emulated-qemu-mipsel",
            "hardware_touched": False,
            "timestamp_utc": utc_now(),
            "capsule_tested": os.path.abspath(cap_path),
            "thingino_image_sha256": thingino_sha,
            "stock_image_sha256": restore_receipt["stock_image_sha256"],
            "restore_capsule_md5": restore_receipt["capsule_md5"],
            "phases": {
                "flash_and_backup_capture": "PASS",
                "backup_verify_clean": "PASS",
                "corrupt_mtd2_rejected": "PASS",
                "truncated_mtd4_rejected": "PASS",
                "incoherent_dm_verity_refused": "PASS",
                "wrong_mtd_map_refused_zero_writes": "PASS",
                "wrong_sha256_refused_zero_writes": "PASS",
                "restore_over_stock_map_byte_exact": "PASS",
                "restore_over_thingino_map_byte_exact": "PASS",
            },
            "beacons_recorded": len(http_srv.beacons),
            "stock_partition_sha256": restored_hashes,
        }
    finally:
        if backup_srv is not None:
            backup_srv.stop()
        if http_srv is not None:
            http_srv.stop()
        if cleanup_work and os.path.isdir(work_dir):
            shutil.rmtree(work_dir, ignore_errors=True)


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description="FSS camera flash safety-net CLI")
    sub = ap.add_subparsers(dest="cmd", required=True)

    sub.add_parser("families", help="List supported camera families and MTD layout metadata")

    p_man = sub.add_parser("manifest", help="Generate atomic SHA-256 manifest for a captured backup dir")
    p_man.add_argument("--family", required=True)
    p_man.add_argument("--dir", required=True)
    p_man.add_argument("--out", default=None)

    p_ver = sub.add_parser("verify", help="Verify backup partition files against layout and manifest SHA-256s")
    p_ver.add_argument("--family", required=True)
    p_ver.add_argument("--dir", required=True)
    p_ver.add_argument("--manifest", default=None)

    p_rest = sub.add_parser("build-restore-capsule", help="Build verified stock restore OTA capsule")
    p_rest.add_argument("--family", required=True)
    p_rest.add_argument("--backup-dir", required=True)
    p_rest.add_argument("--out-dir", required=True)
    p_rest.add_argument("--host", default="192.168.4.160")
    p_rest.add_argument("--img-port", type=int, default=8080)
    p_rest.add_argument("--beacon-host", default=None)
    p_rest.add_argument("--beacon-port", type=int, default=8080)
    p_rest.add_argument("--image-name", default="stock-restore.bin")
    p_rest.add_argument("--busybox", default=None)
    p_rest.add_argument("--partitions", default="all")
    p_rest.add_argument("--manifest", default=None)

    p_drill = sub.add_parser("drill", help="Run real qemu-mipsel emulated MTD flash/corrupt/restore drill")
    p_drill.add_argument("--family", default="wyze-hl_cam4")
    p_drill.add_argument("--work-dir", default=None)
    p_drill.add_argument("--qemu", default="qemu-mipsel")
    p_drill.add_argument("--capsule", default=None)
    p_drill.add_argument("--image", default=None)
    p_drill.add_argument("--busybox", default=None)
    p_drill.add_argument("--out", default=None, help="Optional path to write JSON drill receipt")

    args = ap.parse_args(argv)

    if args.cmd == "families":
        out = {
            k: {
                "soc": v.soc,
                "arch": v.arch,
                "total_bytes": v.total_bytes,
                "live_mtd_layout_verified": v.live_mtd_layout_verified,
                "dm_verity_coupled_partitions": list(v.dm_verity_coupled_partitions),
                "partition_count": len(v.partitions),
                "brick_recovery_doc": v.brick_recovery_doc,
                "notes": v.notes,
            }
            for k, v in FAMILIES.items()
        }
        print(json.dumps(out, indent=2))
        return 0

    if args.cmd == "manifest":
        try:
            doc = build_manifest(args.family, args.dir, args.out)
            print(json.dumps(doc, indent=2))
            return 0
        except Exception as exc:
            print(str(exc), file=sys.stderr)
            return 1

    if args.cmd == "verify":
        res = verify_backup(args.family, args.dir, args.manifest)
        print(json.dumps(res, indent=2))
        return 0 if res["ok"] else 1

    if args.cmd == "build-restore-capsule":
        try:
            receipt = build_restore_capsule(
                family_name=args.family,
                backup_dir=args.backup_dir,
                out_dir=args.out_dir,
                host=args.host,
                img_port=args.img_port,
                beacon_host=args.beacon_host,
                beacon_port=args.beacon_port,
                image_name=args.image_name,
                busybox_path=args.busybox,
                partitions_arg=args.partitions,
                manifest_path=args.manifest,
            )
            print(json.dumps(receipt, indent=2))
            return 0
        except PermissionError as exc:
            print(json.dumps({"ok": False, "code": "DM_VERITY_INCOHERENT", "error": str(exc)}, indent=2), file=sys.stderr)
            return 2
        except Exception as exc:
            print(json.dumps({"ok": False, "error": str(exc)}, indent=2), file=sys.stderr)
            return 1

    if args.cmd == "drill":
        try:
            fam = get_family(args.family)
        except ValueError as exc:
            print(json.dumps({"ok": False, "family": args.family, "error": str(exc)}, indent=2), file=sys.stderr)
            return 2
        if fam.family != "wyze-hl_cam4":
            print(
                json.dumps(
                    {
                        "ok": False,
                        "family": fam.family,
                        "status": "blocked",
                        "reason": f"emulated drill only implemented for wyze-hl_cam4; see {fam.brick_recovery_doc}",
                    },
                    indent=2,
                ),
                file=sys.stderr,
            )
            return 2
        res = run_wyze_drill(
            work_dir=args.work_dir,
            qemu_bin=args.qemu,
            capsule_tar=args.capsule,
            thingino_img=args.image,
            busybox_bin=args.busybox,
        )
        if args.out:
            os.makedirs(os.path.dirname(os.path.abspath(args.out)), exist_ok=True)
            out_tmp = f"{args.out}.tmp.{os.getpid()}.{threading.get_ident()}"
            try:
                with open(out_tmp, "w", encoding="utf-8") as fh:
                    json.dump(res, fh, indent=2)
                    fh.write("\n")
                    fh.flush()
                    os.fsync(fh.fileno())
                os.replace(out_tmp, args.out)
            except BaseException:
                if os.path.exists(out_tmp):
                    try:
                        os.unlink(out_tmp)
                    except OSError:
                        pass
                raise
        print(json.dumps(res, indent=2))
        return 0

    return 2


if __name__ == "__main__":
    sys.exit(main())
