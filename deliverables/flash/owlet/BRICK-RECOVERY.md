# Brick Recovery — Owlet Cam (`owlet`, TUTK / Kalay)

Grounded in `docs/exploit/owlet-apk.md` and `docs/exploit/owlet-h1-frida-runbook.md`.

## Hardware & Flash Map Status (Honest State)

- **Known facts:** `192.168.4.163`, MAC `38:01:46:ab:83:8a` (Shenzhen Bilian Wi-Fi module OUI),
  ThroughTek/Kalay (`libIOTCAPIs.so` / `libAVAPIs.so`) protocol gated behind Firebase Auth +
  `camera-kms.owletdata.com` (`tutkid`, `password`, `authKey`).
- **SoC & MTD layout:** **UNREAD.** No root shell or firmware dump has been obtained yet;
  `safety_net.py` marks `owlet` as `live_mtd_layout_verified: false`.

## Recovery Tier 1 — Standard Hardware Reset

- Power-cycle or hold the physical reset button per Owlet pairing procedure to restore Wi-Fi/cloud
  pairing without touching firmware partitions.

## Recovery Tier 2 — UART / External Flash Programmer

- **UART pinout, bootloader, and TFTP commands:** **UNMEASURED** (enclosure unopened, no stock
  firmware image dumped yet). Before any future flash write, open/probe UART (3.3V TTL), confirm
  bootloader prompt and `/proc/mtd`, and capture a full verified partition backup into
  `flash-images/owlet/<mac>-<date>/`.

## Drill Status

- **Blocked on Owlet account credentials / KMS token** (`owlet-apk.md`). Zero bytes written.
