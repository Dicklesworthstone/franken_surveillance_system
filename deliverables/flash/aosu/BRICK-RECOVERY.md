# Brick Recovery — AOSU HomeBase H2E & SolarCams (`aosu`, TuyaOS)

Grounded in `docs/exploit/aosu-flash-preplan.md`, `docs/exploit/aosu-localkey.md`, and
`docs/exploit/tuya-fresh-registration-runbook.md`.

## Hardware & Flash Map Status (Honest State)

- **Fleet:** HomeBase `H2E2DA110000807` (fw `2.10.5`, MAC `60:d5:61:21:4d:36`, `192.168.4.126`) +
  4x battery SolarCam `C8S2EA11` (fw `2.6.22`).
- **Flash layout:** **UNREAD.** Live `/proc/mtd` has never been read because TCP 6668 Tuya 3.5 LAN
  access is gated on `local_key` (requires fresh Tuya IoT registration per
  `tuya-fresh-registration-runbook.md`).
- **A/B Bank Semantics (`aosu-flash-preplan.md` §4):** TuyaOS `TUYA_OTA_FULL = 1` documents A/B
  area switching, and wrong-shape/wrong-digest `0x1A` probes reject without writing flash. However,
  whether the H2E bootloader validates before switching banks is **unproven** — never send a
  real-image `[WRITE][RISK]` frame before capturing a backup or testing base-first with recovery
  plan ready.

## Recovery Tier 1 — Backlog Wedge / App Recovery

- Rapid TCP 6668 connect/close cycles (~20) wedge the accept backlog for ~30 s; it self-heals on
  backoff. Never flood 6668; negotiate single-shot (`CLIENT_LMT 3`, `ALLOW_NO_KEY_NUM 3`).
- Standard hardware reset button + AOSU app re-pairing recovers config-only faults.

## Recovery Tier 2 — UART / Bootloader / External Flash

- **UART pinout, bootloader version, and TFTP commands:** **UNMEASURED** on `H2E2DA110000807`
  (chassis unopened). Verify 3.3V TTL TX/RX/GND on PCB and capture full flash dump via serial/SPI
  programmer (`flashrom`) before attempting any non-A/B direct flash write.
- **Sequencing Rule:** Always prove recovery on HomeBase H2E first; never flash battery SolarCams
  (`C8S2EA11`) first or while asleep.

## Drill Status

- **Blocked on `local_key` acquisition** (operator Tuya IoT account / Android capture). Zero bytes written.
