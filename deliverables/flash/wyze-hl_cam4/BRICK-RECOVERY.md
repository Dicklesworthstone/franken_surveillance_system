# Brick Recovery — Wyze Cam v4 (`wyze-hl_cam4`, Ingenic T41NQ)

Grounded in `docs/exploit/flash-plan.md`, `deliverables/scripts/upgraderun.sh`, and
`deliverables/flash/restore_stock.sh`.

## Hardware & Flash Map (Verified)

- **SoC:** Ingenic T41NQ (`mipsel`), 16 MiB (`16,777,216` B) SPI NOR.
- **Stock MTD Layout (`cat /proc/mtd`):**

| Slot | Name | Offset | Size | Notes |
|---|---|---|---|---|
| `mtd0` | `uboot` | `0x000000` | `0x080000` (512 KiB) | SPL + U-Boot + env — **write LAST** |
| `mtd1` | `boot` | `0x080000` | `0x280000` (2560 KiB) | Kernel FIT + initramfs + dm-verity root hash |
| `mtd2` | `system` | `0x300000` | `0x5C0000` (5888 KiB) | SquashFS rootfs — **dm-verity coupled to `mtd1`** |
| `mtd3` | `back` | `0x8C0000` | `0x5C0000` (5888 KiB) | Backup bank |
| `mtd4` | `cfg` | `0xE80000` | `0x100000` (1024 KiB) | JFFS2 rw config |
| `mtd5` | `provisioning` | `0xF80000` | `0x080000` (512 KiB) | Wi-Fi MAC / RF calibration / unit identity |

- **Thingino Post-Flash Map:** `320k(boot), 64k(env), 64k(backup), 1600k(kernel), 13312k(rootfs), 1024k(data)` (tailnet build; exact sum `16,777,216` B).
- **dm-verity Constraint:** Never restore `mtd2` (`system`) independently of `mtd1` (`boot`) on a stock kernel. `safety_net.py build-restore-capsule` enforces full 6-partition coherent rollback.

## Recovery Tier 1 — Live Shell / OTA Rollback (No Disassembly)

If either the stock OTA channel (`assis`) or Thingino SSH (`dropbear`) is reachable:

```bash
python3 deliverables/flash/safety_net.py verify \
  --family wyze-hl_cam4 --dir flash-images/wyze-hl_cam4/live-capture
python3 deliverables/flash/safety_net.py build-restore-capsule \
  --family wyze-hl_cam4 \
  --backup-dir flash-images/wyze-hl_cam4/live-capture \
  --out-dir /tmp/wyze-stock-restore \
  --host 192.168.4.160 --img-port 8080
```

Serve `/tmp/wyze-stock-restore/stock-restore.bin` on `192.168.4.160:8080`, then either deliver
`/tmp/wyze-stock-restore/Upgrade.tar` through the OTA broker or extract and run `Upgrade/upgraderun.sh`
as root under Thingino. `restore_stock.sh` accepts both stock and Thingino `/proc/mtd` maps,
verifies SHA-256 before writing, writes high-to-low (`mtd0` last), and re-hashes flash before reboot.

## Recovery Tier 2 — Thingino U-Boot / TFTP / microSD Recovery

If `mtd0` (Thingino U-Boot `2026.10-rc4 for isvp-t41`) is intact, interrupt U-Boot on serial UART
(`115200 8N1`, TX/RX/GND pads on main PCB — **exact board pad silkscreen has NOT been physically
measured on `.39`/`.51` in this repo; verify pad voltage 3.3V and ground continuity with a
multimeter before attaching an adapter**):

```text
setenv ipaddr 192.168.4.39
setenv serverip 192.168.4.160
sf probe 0
tftpboot 0x80600000 stock-restore.bin
sf erase 0x0 0x1000000
sf write 0x80600000 0x0 0x1000000
reset
```

## Recovery Tier 3 — Hard Brick (`mtd0` Corrupted / Power Loss Mid-Write)

If power failed while writing `mtd0`:
1. **Ingenic USB Cloner (`cloner` / T41 bootrom):** Pull the T41 boot-select / USB-boot pad (verify
   against physical PCB before bridging; unmeasured on our units) and re-flash the 16 MiB
   `stock-restore.bin` or `thingino-wyze_cam4_t41nq_os04d10_atbm6062s-tailnet.bin` over USB.
2. **External SPI NOR Clip (SOIC-8 / WSON-8):** Desolder or clip directly onto the 16 MiB SPI NOR
   flash at 3.3V with a programmer (`flashrom -p <programmer> -w stock-restore.bin -v`).

## Emulated Drill Status

- **Emulated `qemu-mipsel` drill:** Implemented and verified by `safety_net.py drill --family wyze-hl_cam4`.
- **Real physical `.39`/`.51` partition backup status:** Pending first live capsule execution (backups now directed to persistent `flash-images/wyze-hl_cam4/live-capture/`).
