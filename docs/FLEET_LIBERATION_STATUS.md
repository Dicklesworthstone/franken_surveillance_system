# Fleet liberation status — Aardvark, 2026-10-22

Goal: root on the owner's cameras over the LAN only, then replace vendor firmware with open
standards (RTSP/ONVIF) plus native tailnet membership. No SD card, no UART, no disassembly, no
vendor developer program.

This file is the honest scoreboard. Everything is owner-device research; nothing is flashed.

## Where each family actually stands

| Family | Unit(s) | Root mechanism | State | Blocking fact |
|---|---|---|---|---|
| Wyze Cam v4 (HL_CAM4 4.52.17.26) | `.4.23`, `.4.24`, `.5.242`, `.6.25`, `.5.181` | `assis` OTA: cloud descriptor → our HTTPS → tar → `sh upgraderun.sh` as root | **delivery plane complete, dispatch not firing** | the device consumes shadow deltas and accepts `run_action` (`code 1`, `result 3`) but issues no GET |
| AOSU HomeBase H2E | `.4.37` | Tuya 3.5 LAN OTA `0x1A/0x1B/0x1C` inside the authenticated session | unstarted; unauthenticated 51028 proxy confirmed earlier | `local_key` not recovered, so no session; digest-vs-hmac question unresolved |
| TP-Link Tapo C460 v1.0 | `.6.70` / `.6.71` | CVE-2026-105810 `connectAp` stack overflow (auth) | payload built, never sent | needs an admin session; the offline `device_confirm` verifier did not crack the password (1.65 M candidates) |
| Yi IPC | `.6.156` | CVE-2018-3910 SSID command injection into `popen` | mechanism only, never fired | needs one app re-provision onto an attacker SSID (physical-ish, allowed) |
| Canary | `.6.85` | unknown; outbound-only | located, zero open TCP ports, UDP quiet | no inbound surface at all |
| Owlet | not located | unknown | not on the LAN by OUI or by TUTK `0x0601` sweep | device identity unknown |

## What is now proven, per layer

1. **Delivery** (Wyze): owner token → device IoT certificate issuance (`200 SUCCESS`) → mutual-TLS
   MQTT to the AWS IoT broker with the device `thing_name` → shadow delta accepted and echoed into
   `reported`. A Let's Encrypt endpoint the device's own CA bundle validates
   (`ssl_verify_result 0`) is live. The missing link is the device-side dispatch, not the plumbing.
2. **Replacement firmware**: a 16 MiB Thingino image with `tailscaled` 1.104.2, `serve` rules for
   TCP 554/80, dropbear, ONVIF and prudynt RTSP is built and deterministic (`docs/exploit/firmware-build.md`).
   Boot region is byte-identical to the pinned upstream installer image; only rootfs/env differ.
3. **Install script**: `deliverables/scripts/upgraderun.sh` reads `/proc/mtd`, refuses an unexpected
   map, streams every partition out first, verifies a pinned image digest, writes high-offset first
   and the bootloader last.
4. **Exploit dogfood**: CVE-2026-38698 on this build is a remote DoS, not a root primitive
   (`docs/exploit/av-overread.md`). It is still useful as a forced-iCamera-restart trigger.

## The one thing to do next

Power-cycle `.4.23` with the current `desired` shadow state (URL + real MD5 already published). The
cloud reports `conn_state 1` and every `run_action` is accepted, so a boot-time resync is the
cheapest way to distinguish "dispatch never fires" from "dispatch fires only at boot". If the server
log shows a GET, the rest of the chain is already built and the negative capsule / no-write capsule
/ flash sequence can run in order.

## Safety invariants

- One camera per agent; TUTK refuses concurrent sessions.
- Nothing writes flash until the negative 20-byte capsule has produced a GET and the MD5 gate has
  been observed.
- The full-image write includes the bootloader; the only recovery from a bad boot write is TFTP/USB
  plus UART, which is outside the current constraint.
