# Wyze HL_CAM4 backup rescue — 2026-11-06 12:48

## Ground truth at rescue time

/tmp/fwbackup contained **six 0-byte mtd*.bin files** (created 11:49 by the
persistent fss-backup-recv daemon touching targets) — NO real partition data
has ever been captured from .39/.51. The receivers (444-449) have been
listening since 2026-11-05 with `no connection` on every port (see
/tmp/ota/backup.log). The camera has never reached the installer's
backup-streaming step (step 2 of upgraderun.sh) because the chain has not
completed past assis download.

## What must exist BEFORE the first flash

1. A full 6-partition backup streamed by the capsule installer (the real
   bytes), captured by receivers 444-449 into this directory.
2. sha256 + size manifest per partition (fill in below when real data lands).
3. Restore path verified (loop-device emulated mtd layout, see
   fss-flash-safety-net-8th46).

## Partition layout (from EV-H-002-VERITY bead, initramfs S18_mountall)

| mtd | name         | notes                          |
|-----|--------------|--------------------------------|
| 0   | uboot        | bootloader                     |
| 1   | boot         | kernel                         |
| 2   | system       | squashfs, dm-verity'ed         |
| 3   | back         | backup bank (A/B)              |
| 4   | cfg          | jffs2, rw                      |
| 5   | provisioning | provisioning data              |

## Manifest (fill on capture)

| partition | file | bytes | sha256 |
|-----------|------|-------|--------|
| mtd0 | mtd0.bin | — | — |
| mtd1 | mtd1.bin | — | — |
| mtd2 | mtd2.bin | — | — |
| mtd3 | mtd3.bin | — | — |
| mtd4 | mtd4.bin | — | — |
| mtd5 | mtd5.bin | — | — |
