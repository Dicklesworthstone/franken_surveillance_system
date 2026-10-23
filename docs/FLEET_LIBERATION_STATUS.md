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

## Retest log, 2026-10-23 02:0x (MagentaOwl)

| Unit | Reachability | Consequence |
|---|---|---|
| `.4.37` AOSU | ping + 443/6668/51028 open | unchanged; the 51028 proxy is still alive |
| `.4.24` Wyze | ping + 53 open, sessions work | unchanged |
| `.6.70` / `.6.71` Tapo | ping + ARP, **all TCP filtered** (80/443/554/2020/6668/8800) | cannot re-verify the model over the wire right now |
| `.6.156` Yi | ping + ARP, TCP 80 closed as always, **WS-Discovery now silent** | injection remains the only path; nothing to hit first |
| `.6.85` Canary | **does not answer ping** | was up earlier today, now unplugged or asleep |

The Tapo pair answering ICMP while dropping every SYN is consistent with a source-address ban after
the earlier 1.2 × 10^9-candidate `device_confirm` run; it is not consistent with the units being off
(ARP resolves and ICMP is answered). Recorded so the next reader does not read it as a model change:
the C460 v1.0 / C660 v1.6 identification came from UDP 20002 TDP and still stands, and **every
published 2026 Tapo CVE is model-locked away from both units**.

### AOSU — why it cannot move without one secret

`0x1A/0x1B/0x1C` live inside the authenticated Tuya 3.5 GCM session, so the LAN OTA question cannot
even be asked without the 16-byte `local_key`. Nothing on the wire yields it and the account API has
no `localKey` field; the only source is the Tuya OEM channel, which needs the app's signing material
(extracted, still `ILLEGAL_CLIENT_ID`). Every downstream step is scripted and waiting:
`deliverables/scripts/ev-pack-h-003-send-ota-start.py` sends the wrong-shape `0x1A` first, then a
wrong-digest body — the ordering matters because a parse failure returns the same `retcode 1` as a
digest rejection.

### Yi — what is staged, and what still needs a human

`deliverables/scripts/yi_u1.py` now carries both payloads with their length check
(`x$(nc 192.168.4.160 4444|sh)`, 28 octets, fits in the 32-octet SSID budget; the quoted
`telnetd` fallback at 22) and a listener that gives an interactive root shell. Remaining human step:
broadcast that SSID and re-provision the camera in the Yi app. Pass condition is a shell from
`192.168.6.156`; the persistence pass is the same shell after `reboot` with the SSID unchanged.

### Dispatch experiments that all failed (do not repeat)

1. Delta with the stale `desired` still set → no GET.
2. Fresh delta, `.tar` URL, both the zero MD5 and the *true* MD5 (i.e. one matching and one
   not-matching the file) → no GET.
3. Third delta with a deliberately different MD5 (`1111…`, neither the file's nor `reported`'s) so
   the device could not dedupe on digest → no GET.
4. Vendor-shaped path `/wuv2/upgrade/HL_CAM4/firmware/<ver>.tar` instead of a bare name → no GET.
5. `run_action` after the params were understood (`app_ver` required, else `1001`) → `code 1`,
   `result 3`, `session_id`, still no GET, no reboot after 25 s or 150 s.

So the device consumes shadow state (`reported` tracks every key we set) but does not act on it
without a resync. **The single remaining test is a power cycle**, or tapping the device's own MQTT
session to see whether any `cmd` frame is delivered at all.

### Why an iCamera crash is not enough to resync the shadow

Crashing `iCamera` only restarts that one process; `iotclient` — the process that owns the MQTT
session and the shadow subscription — keeps running, so the delta is never re-delivered. Verified:
a triple crash run on `.4.24` killed the stream at 10.6 s, the box answered ping 5 s later, and the
`desired` URL was still un-fetched. For the same reason the cloud `restart`/`reboot` actions
(`result 3`) do not help. `docs/exploit/ota-path.md` §9.7 lists the five dispatch variants that
also failed. The box needs a real power cycle.
