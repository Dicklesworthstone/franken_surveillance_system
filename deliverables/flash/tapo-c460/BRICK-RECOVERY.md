# Brick Recovery — Tapo C460 (`tapo-c460`, SigmaStar SSC30KQ)

Grounded in `docs/exploit/tapo-recovery.md`, `docs/exploit/c460-flash-layout.md`, and
`docs/exploit/c460-openipc-flash.md`.

## Hardware & Flash Map (From Stock Image)

- **SoC:** SigmaStar SSC30KQ (`arm`), dual 16 MiB SPI NOR (`nor0` + `nor1` = 32 MiB).
- **Bootloader:** U-Boot 2021.10 (`loados nor by_header RAMDISK by_header; loados nor by_header KERNEL by_header; dcache off; bootm ${loados_addr}`).
- **Partitions (`c460-flash-layout.md`):**
  - `nor0`: `BOOT` (0x05F000), `ENV` (0x001000), `VERIFY` (0x010000), `factoryinfo` (0x010000 — **never overwrite**), `KERNEL` (0x2A0000), `MISC` (0x200000), `RTOS` (0x300000), `RAMDISK` (0x500000), `config` (0x010000), `usrrecord` (0x2D0000).
  - `nor1`: `IPLXXX` (0x010000), `rootfs` (0x7F0000), `objdmodel` (0x800000).
- **Mandatory Pre-Flash Rule:** Confirm live `cat /proc/mtd` and dump ALL 13 partitions off `/tmp` into `flash-images/tapo-c460/` with `safety_net.py manifest` before writing a single byte.

## Recovery Tier 1 — Soft Wedge (Userspace Deadlock, No Flash Touched)

A failed RAM-only probe leaves TCP 443/8800 accepting SYN-ACK with zero TLS bytes (`tapo-recovery.md`):
1. Reboot via Tapo app (`Settings -> Device info -> Reboot`), OR hold the physical power button
   ~10 s (a 10 s battery pull is insufficient; pull battery for >= 60 s if using battery removal).
2. Wait 20–40 s for Wi-Fi rejoin.
3. Verify liveness with a real DS login POST (`device_confirm` JSON), never `ping` or `nc -z`.

## Recovery Tier 2 — U-Boot Serial Console & TFTP Recovery

- **UART:** SigmaStar `ttyS0` at `115200 8N1` (3.3V TTL). **Exact PCB pad locations on the C460
  have NOT been physically probed in this repo; verify 3.3V VCC/GND/TX/RX on the opened PCB before
  connecting.**
- Interrupt U-Boot at power-on (`Enter` / `Ctrl-C`), confirm `sf probe 0 0:0` (`nor0`) and
  `sf probe 0 0:1` (`nor1`), then restore captured stock partitions over TFTP:

```text
setenv ipaddr 192.168.4.243
setenv serverip 192.168.4.160
sf probe 0 0:0
tftpboot 0x21000000 mtd4.bin
sf erase 0x80000 0x2A0000
sf write 0x21000000 0x80000 0x2A0000
tftpboot 0x21000000 mtd7.bin
sf erase 0x820000 0x500000
sf write 0x21000000 0x820000 0x500000
reset
```

*(Verify `0x21000000` load address against live `printenv` before writing; never touch `factoryinfo`.)*

## Recovery Tier 3 — Hard Brick (`BOOT` / `IPLXXX` Corrupted)

External SPI NOR programmer (`flashrom`) on `nor0` and/or `nor1` using the verified full-chip dump,
or SigmaStar ISP tool over I2C/UART recovery pads.

## Drill Status

- **Blocked on live root shell + physical MTD dump** on `.243` (pre-flash safety images `uImage.ssc30kq` and `rootfs.squashfs.ssc30kq` are committed; zero bytes written to `.243`).
