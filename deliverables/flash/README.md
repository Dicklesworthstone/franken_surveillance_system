# Camera Flash Safety Net (`deliverables/flash/`)

Pre-flash backup capture, verification, stock rollback capsule assembly, QEMU MTD drill, and
per-family brick-recovery guides (`fss-flash-safety-net-8th46`).

## Core Invariants

1. **No `/tmp` backup storage:** `com.jeffreyemanuel.fss-backup-recv` writes directly to
   `flash-images/wyze-hl_cam4/live-capture/` with atomic tmp+fsync+rename, history archival of
   distinct prior captures, and an atomic `manifest.json` carrying per-partition SHA-256 digests.
2. **Verify before write, re-read after write:** `safety_net.py verify` rejects missing files,
   zero-byte captures, truncated streams (`SIZE_MISMATCH`), and bit-flips (`SHA256_MISMATCH`).
   `restore_stock.sh` refuses any unknown `/proc/mtd` layout, verifies full-image SHA-256 on the
   camera before modifying flash, writes high-to-low with bootloader (`mtd0`) last, and re-hashes
   every written partition from `/dev/mtdblockN` before reboot.
3. **dm-verity / CRC coherence:** `build-restore-capsule` fails closed (`DM_VERITY_INCOHERENT`,
   exit code `2`) if asked to restore `system` (`mtd2`) without coupled `boot` (`mtd1`) on
   `wyze-hl_cam4`.
4. **Honest hardware vs. emulation boundary:** The `drill` subcommand proves the real
   `wyze-capsule-4.52.17.106.tar` + `wyze_backup_recv.py` + `restore_stock.sh` contract under
   `qemu-mipsel` against synthetic 16 MiB MTD files. It does **not** claim physical camera bytes
   were captured until real non-zero partitions land in `flash-images/<family>/`.

## Commands

```bash
python3 deliverables/flash/safety_net.py families
python3 deliverables/flash/safety_net.py manifest --family wyze-hl_cam4 --dir flash-images/wyze-hl_cam4/live-capture
python3 deliverables/flash/safety_net.py verify --family wyze-hl_cam4 --dir flash-images/wyze-hl_cam4/live-capture
python3 deliverables/flash/safety_net.py build-restore-capsule \
  --family wyze-hl_cam4 --backup-dir flash-images/wyze-hl_cam4/live-capture --out-dir /tmp/wyze-restore
python3 deliverables/flash/safety_net.py drill --family wyze-hl_cam4
```

## Per-Family Recovery Guides

- [wyze-hl_cam4/BRICK-RECOVERY.md](wyze-hl_cam4/BRICK-RECOVERY.md)
- [tapo-c460/BRICK-RECOVERY.md](tapo-c460/BRICK-RECOVERY.md)
- [tapo-c660/BRICK-RECOVERY.md](tapo-c660/BRICK-RECOVERY.md)
- [yi/BRICK-RECOVERY.md](yi/BRICK-RECOVERY.md)
- [aosu/BRICK-RECOVERY.md](aosu/BRICK-RECOVERY.md)
- [owlet/BRICK-RECOVERY.md](owlet/BRICK-RECOVERY.md)
