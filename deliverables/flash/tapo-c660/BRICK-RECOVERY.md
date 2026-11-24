# Brick Recovery — Tapo C660 (`tapo-c660`, Novatek NS02301 / `nvt98567`)

Grounded in `docs/exploit/c660-flash-plan.md` and `docs/exploit/tapo-recovery.md`.

## Hardware & Flash Map (From Stock Image)

- **SoC:** Novatek NS02301 (`nvt98567`, Cortex-A7, Linux 5.10.168), 32 MiB (`33,554,432` B) SPI NOR.
- **Bootloader:** Tapo-patched U-Boot 2021.10 (`SIGNATUREMETHOD_NONE`, `ENCRYPT_UBOOT_OFF`, no RSA/FIT signing).
- **CRC Bookkeeping Gate (`mtd4` `verify`):** U-Boot checks partition CRCs against `verify` (`tapo_check_Is_verify_crc` / `validateFirmwareWithRecover`). Writing `kernel` (`mtd8`) or `rootfs` (`mtd9`) without updating or handling `verify` causes recovery fallback or boot halt.
- **Partitions (`c660-flash-plan.md` §2):**
  `mtd0 loader (64K)`, `mtd1 fdt (512K)`, `mtd2 fdt.fast (256K)`, `mtd3 uboot (512K)`,
  `mtd4 verify (64K)`, `mtd5 factoryinfo (64K — never overwrite)`, `mtd6 config (128K)`,
  `mtd7 rtos (3520K)`, `mtd8 kernel (4736K)`, `mtd9 rootfs (5504K)`, `mtd10 source_fast (1024K)`,
  `mtd11 userrecord (4096K)`, `mtd12 service (6144K)`, `mtd13 objdmodel (6144K)`.
- **Mandatory Pre-Flash Rule:** Read live `cat /proc/mtd` (initramfs carries `mtd14..17` nodes too) and capture/hash all partitions off `/tmp` into `flash-images/tapo-c660/` before any write.

## Recovery Tier 1 — Soft Wedge / Deep Sleep

- Battery camera enters deep sleep after probe timeouts (ARP/TCP silent — not a brick).
- Wake via Tapo app live view or physical power button; reboot via Tapo app (`Settings -> Device info -> Reboot`) or ~10 s button hold if wedged.
- Verify liveness via DS login POST (`device_confirm`), respecting >= 3 s inter-request pacing.

## Recovery Tier 2 — U-Boot Serial Console & TFTP Recovery

- **UART:** `console=ttyS0,115200` (from DTB `/chosen/bootargs`, 3.3V TTL). **Exact PCB pad
  locations on the C660 have NOT been physically probed in this repo; verify pinout with a
  multimeter before connecting.**
- Interrupt U-Boot at boot, confirm RAM load address via `printenv`, then restore `verify`,
  `kernel`, and `rootfs` together from verified stock backups via TFTP (`tftp_serve.py`):

```text
setenv ipaddr 192.168.5.76
setenv serverip 192.168.4.160
sf probe 0
tftpboot ${loadaddr} mtd4.bin
sf erase 0x150000 0x10000
sf write ${loadaddr} 0x150000 0x10000
tftpboot ${loadaddr} mtd8.bin
sf erase 0x500000 0x4A0000
sf write ${loadaddr} 0x500000 0x4A0000
tftpboot ${loadaddr} mtd9.bin
sf erase 0x9A0000 0x560000
sf write ${loadaddr} 0x9A0000 0x560000
reset
```

## Recovery Tier 3 — Hard Brick (`loader` / `uboot` Corrupted)

External 32 MiB SPI NOR programmer (`flashrom`) writing the verified full-chip backup, or Novatek
SD-card / USB loader recovery (`FW98567A.bin` — unverified on this board until UART/PCB inspection).

## Drill Status

- **Blocked on camera wake + live root shell + MTD dump** on `.5.76` (zero bytes written to unit).
