# Brick Recovery — Yi Camera (`yi`, ARMv7 `armeabi-v7a`, Zowee OUI `B0:D5:9D`)

Grounded in `docs/exploit/yi-runbook.md` and `docs/exploit/yi-u1.md`.

## Hardware & Flash Map Status (Honest State)

- **Known facts:** Unit MAC `b0:d5:9d:9a:8e:c4` (last seen `192.168.4.20` / `192.168.6.156`), 32-bit
  ARM (`armeabi-v7a`). Exact model variant (Home Camera 2 vs 3 vs other), SoC, firmware string, and
  live `/proc/mtd` layout are **UNREAD** because the camera is offline/asleep.
- **No fabricated layout:** `safety_net.py` explicitly marks `yi` as `live_mtd_layout_verified: false`
  and refuses to build a restore capsule until a real `/proc/mtd` dump + full partition backup is
  captured into `flash-images/yi/<mac>-<date>/`.

## Recovery Tier 1 — Soft / Config Recovery (No Flash Write)

- Standard Yi reset button (paperclip hold ~5–10 s until voice prompt) returns the camera to
  pairing/re-provisioning mode without touching bootloader/kernel flash.

## Recovery Tier 2 — microSD Recovery Firmware (Standard Yi Bootloader Path)

Most Yi ARMv7 units check the root of a FAT32 microSD card at boot for vendor recovery images
(`home_*` / `rootfs_*` depending on exact board prefix, e.g. `yi-hack` / stock recovery pairs).
**Exact filenames depend on the unread model/board ID** — determine the exact board prefix from the
unit label or first live readout (`yi-runbook.md` STEP 0–2) before staging any microSD recovery file.

## Recovery Tier 3 — UART / External Flash Recovery

- **UART pinout & bootloader prompt:** **UNMEASURED** on this physical unit until PCB inspection
  (typically 3.3V `115200 8N1` U-Boot console; verify voltage and ground before attaching).
- **External flash programmer:** Full SPI NOR dump via `flashrom` before any custom firmware write.

## Drill Status

- **Blocked on camera online / operator re-provision** (`yi-runbook.md`). Zero bytes written.
