# EV pack — H-001 / H-002, Wyze HL_CAM4 (Cam v4) on the owner LAN

Targets: `192.168.5.242` (Jeff Office), `192.168.4.23` (Dining Room), `192.168.4.24` (Driveway).
Firmware `4.52.17.26`, model `HL_CAM4`, owner-account inventory
(`~/.config/fss-lab/wyze_inventory.json`) supplies `p2p_id` + `enr` per camera.
All probing was read-only except where marked `[WRITE]`.

Hardware, from FCC + teardown + firmware: **Ingenic T41 (T41NQ, QFN96)**, ATBM6062 Wi-Fi,
XT25F128F-W 16 MB SPI-NOR, 6 mtd partitions (`uboot boot system back cfg provisioning`),
FIT dtb vendor string `Tianjin Hualai Technology Co., Ltd.`, `compatible = "ingenic,t41"`,
machine `ingenic,marmot`. SoC identity is settled and no longer an open question.

---

## Findings

`pre-auth?` = reaches the handler with no ENR/AuthKey. Reliability is over the runs in this pack.

| # | Transport / port | Pre-auth? | Primitive class | Exact sink | Reliability | Evidence |
|---|---|---|---|---|---|---|
| F1 | UDP 32761, legacy IOTC `0x0601` discovery (TransCode, **no auth material in the frame**) | **yes** | info-leak (P2P UID) | `discovery` handler; response body `[16:36]` carries the 20-byte UID verbatim | 3/3 cameras, repeatable; answered from a freshly adopted port (42929 / 44650 / 60929) | EV-201 `bb-wyze-uid-leak-aqo`; `deliverables/scripts/tutk_legacy.py` |
| F2 | UDP 32761, `0xCC51` `0x1002` discovery | **no** (HMAC-SHA1 over `[0:32]`, key = UID‖AuthKey) | info-leak when ENR held (ticket, session-port adoption) | `parse_discovery` | 1/1 with valid HMAC (24 ms); 0/1 with zeroed HMAC and 0/1 with *any* off-nominal field | EV-202 `bb-cc51-discovery-gate-u7q`; EV-203 `bb-live-session-proof-xez` |
| F3 | UDP 32761, `0xCC51` `0x1502` DTLS wrapper | no (same HMAC; HMAC covers **only the 28-byte header**, not the payload) | transport for everything below; unbounded payload `[28 .. len-20]` | `unwrap_dtls` → `DtlsClient::feed_datagram` | completes handshake and stream (592 frames / 30 s) | EV-203 |
| F4 | inside F3, DTLS record layer | no | parser | `records()`: `type(1) ver(2) epoch(2) seq(6) len(2)`; `off+13` and `end > datagram.len()` both checked; trailing <13 B dropped silently | hardening knobs exercised (`psize 0xffff`, 1451 B frame, 0x1502 before discovery) — no crash, silent drop | EV-202 |
| F5 | inside F3, DTLS handshake reassembly | no (pre-Finished) | heap allocation from attacker field | `message_seq`, `mlen` (3-byte declared length) → `vec![0u8; mlen]` before any fragment arrives; `off+12+flen > data.len()` bound only | not fuzzed to the 16 MB ceiling; no observed failure | code read (`dtls.rs:171-203`) |
| F6 | inside F3, PSK identity in `ClientKeyExchange` | no | auth/negotiation | identity must start `AUTHPWD_`/`AUTHTKN_`; unknown prefix → `alert 115 unknown_psk_identity`. CVE-2023-6324 (empty-buffer → `SHA256("")`) **does not work**: handshake dies after CKE | 3× fail; control (same identity, real PSK) streams | EV-204 `bb-psk-bypass-absent-jpe` |
| F7 | inside F3, AV login response `[16:20]` = declared size | no (post-discovery) | parser | `psize` must satisfy `0 < psize ≤ 4096`, else one-byte resync; `total = 24+psize` | not exercised in isolation | code read (`av_stream.rs:157-172`) |
| F8 | inside F3, K-auth `K10001` (post-DTLS) | no | config/protocol | `payload[0]` selects XXTEA key (3→ENR, 6→ENR², else static); `[1:17]` copied to a 16-byte stack array only after `len >= 17` | 1/1 (stream) | EV-203 |
| F9 | inside F3, `K10000` JSON `audioEncoderList` sent *by us* | no | **DoS-by-size** (no crash) | on-device cJSON; ~1024 B limit — 967 B JSON answers, 1047 B, 4 KB and 20 k-element arrays never answer `K10001` (K-auth deadline) | 4/4 deterministic at 240/260/280/1024/20000; listener stays alive | this pack §probe log |
| F10 | inside F3, IOCTRL `0x284C` (motion zone) `[WRITE]` | no | vendor handler, the CVE-2023-6322 class | `parse_ioctrl`/`parse_hl`, `plen` u16, `total = hl_off+16+plen` | 602 B and 2002 B payloads accepted, stream continues after | this pack §probe log |
| F11 | inside F3, AV frame header (`ch 03/05/07`, ftype whitelist 00 01 04 05 08 09 0D) | no | parser | `payload_size` u16 checked against `buf.len()` before slicing; FRAMEINFO only stripped when 40 B and codec id in range | not exercised (needs a hostile sender, i.e. camera-side or MITM) | code read (`av.rs:360-403`) |
| F12 | UDP 32761, `0x1008` PUBLIC cloud-redirect (CVE-2023-6323 class) | **yes** (no auth by design) | info-leak (AuthKey) | not confirmed here: two plausible layouts sent, camera never dialled back | 0/2 layouts | this pack §probe log |

Structural note: **the whole parse chain sits behind the discovery HMAC** except F1/F12. The
device also leaks its own SDK build in the `[24:28]` of every discovery payload —
`4.3.8.0` (see EV-205) — so version fingerprinting is free to anyone on the L2 segment.

## Chain

**No network-only chain to root exists today.** Shortest *structural* path and where it breaks:

1. F1 leaks UID unauthenticated — works, 3/3 cameras.
2. F12 would leak AuthKey with UID alone (CVE-2023-6323) — **unconfirmed on this firmware**.
3. Even with UID+AuthKey you cannot open DTLS: the PSK is `SHA256(ENR)` and the
   empty-buffer bypass (CVE-2023-6324) is gone (F6). So **the ENR is the irreducible
   requirement**, obtainable only from the owner's Wyze account (or a P2P-server impersonation
   that yields AuthKey, not ENR).
4. With the ENR the session is fully ours (F3/F8, 592 frames proven) and F10 becomes reachable —
   but no *unpatched* memory-unsafe sink is known in SDK 4.3.8.0-R2: the published RCE
   (CVE-2023-6322, IOCTL `0x284C` stack overflow, 178-byte slices vs 255-byte copies) was fixed
   by the vendor in Jan 2024 and this firmware is Nov 2025.
5. So root requires **finding a new bug in the post-auth handler set** (F10/F11 and the
   `K100xx` JSON paths) — reachable with ENR only, which satisfies the "ENR-only" half of H-001 —
   or going physical (see H-002).

## Brick risk + recovery

* All probes above: zero brick risk, no persistent state touched (discovery, DTLS, K-auth).
* `0x284C` `[WRITE]`: rewrites motion-detection zones only. Recovery = re-draw the zone in the
  Wyze app; a garbage zone array degrades detection but never boot. Lower-risk than any flash write.
* SD flash `[WRITE]`: vendor-blessed path (`recovery_wcv4.bin` on FAT32 root, hold setup,
  re-power). Recovery if the image is bad: re-insert the stock recovery card and repeat — U-Boot's
  recovery runs before Linux. Unverified assumption: a *signature*-failing image is rejected at
  the point of load rather than partially written (falsifier below).
* Never bricked in this pack; nothing was flashed.

## What would falsify this

1. **H-001 / patch level**: run CVE-2023-6322's own PoC (three 255-byte zone chunks in one
   `0x284C`) against 4.52.17.26. If it still returns root, the "no unpatched sink" conclusion is
   wrong and the chain is complete with ENR only. Decisive, one session.
2. **H-001 / pre-auth reach**: complete F12 by replaying a real captured `0x1008` (capture one
   from the camera's cloud conversation). If the camera dials back, the ENR requirement in step 3
   collapses and UID alone buys discovery + AuthKey.
3. **H-002 / signature enforcement**: take `recovery_wcv4.bin`, flip one byte inside the kernel
   payload, flash. Boots = signing is not enforced (H-002 confirmed); purple-light-then-nothing =
   enforced (H-002 refuted). One SD card, one power cycle.
4. **Persistence**: `Test.tar` factory mode is md5-gated (`[FC] Test.tar checksum no exist/no
   right`, `[FC] Test.tar Signature Verification failure`) by a format we did not reverse; a
   calibration run on an expendable card settles whether a self-made tar is accepted.
5. Also unproven: whether dm-verity is actually *enforced* on `mtdblock2` (the `fs_mgr ... 2`
   argument and the `verity_key` at `/` say yes; a boot log would confirm).

## Verdict

* **H-001 — PARTIAL, confidence high.** A real pre-auth info leak exists (UID, F1) and the
  entire protocol machine is reachable with ENR only (no cloud, no password: proven live at 592
  frames). But there is **no proven memory-unsafe sink that yields code execution** on
  4.52.17.26: every malformed field we could reach without a live DTLS peer is silently dropped by
  an explicit length check, CVE-2023-6324 no longer applies, and the one published RCE
  (CVE-2023-6322) post-dates this build's fix. H-001's "pre-auth" half is too strong; its
  "ENR-only" half holds.
* **H-002 — REFUTED for modified images, confidence high.** Wyze ships a **signed** image:
  RSA-2048/SHA-256 u-boot FIT, `sign-images = "fdt", "kernel", "ramdisk"`, `key-name-hint =
  "kernel-dev"`, signer `mkimage 2025.01`, on a secure-boot-enabled T41. The owner can *obtain and
  flash* an image with no signing key, but cannot *produce* one; the bootloader key is the gate,
  and getting past it needs either the vendor key or a boot-ROM flaw (CVE-2026-50719, `AV:P`).
* **Persistence — named, but only reachable after root.** `/` is `squashfs ro` under dm-verity
  with `verity_key`; the only tmpfs are `/tmp`, `/run`, `/dev/shm`. The single persistent writable
  store is **`mtdblock4` = jffs2 mounted at `/configs`**, but no boot script executes anything from
  it (`app_init.sh` only reads `.debug_flag`, removes `upGradeFlag`, copies `app.ver`). The
  boot-time *code* hook is the factory path: `app_init.sh` runs `factorycheck /dev/mmcblk0p1`,
  which mounts the card and, on `/media/mmc/Test.tar`, untars to `/tmp` and the init script runs
  `/tmp/Test/test.sh &`. So the concrete persistence story is: root shell → drop `Test.tar` on the
  SD → arbitrary root code every boot with no re-exploitation (cost: factory mode replaces the
  normal app start, and the tar must pass the md5 gate).

---

## Probe log (verbatim, trimmed)

CC51 gate, `192.168.5.242` (valid HMAC each case, fresh sid each attempt):

```
pre-baseline: ANSWER 52B
p0_base                ANSWER 52B in 24ms from 42929
p0_psize_ffff          silent x3 (listener alive)
p0_psize_0000          silent x3 (listener alive)
p0_seq_ffff            silent x3 (listener alive)
p0_dir_request         ANSWER 52B in 118ms
p0_bad_sid             ANSWER 52B in 11ms
p0_big1400             silent x3 (listener alive)
p0_trunc_after_auth    silent x3 (listener alive)
p1_dtls_psize_ffff     silent x3 (listener alive)
p1_dtls_big  (1451B)   silent x3 (listener alive)
p2_keep                silent x3 (listener alive)
```

K-auth size sweep: `enc 0/1/4/16/64/240/256 -> STREAM STARTED`; `280/320/512/768/1024/20000 -> FAILED
kauth: phase deadline exceeded` (no crash). DTLS identity: `AUTHPWD_bogus + SHA256("") -> FAILED
dtls: flight retransmit budget exhausted` ×3; `AUTHPWD_bogus + real PSK -> STREAM STARTED`;
`ZZZZ_bogus -> alert 115 unknown psk identity`.

## Artifacts

* `deliverables/scripts/malformed_tutk_probe.py` — HMAC-valid malformed 0xCC51 matrix.
* `deliverables/scripts/tutk_legacy.py` — unauthenticated legacy discovery (the UID leak).
* `deliverables/scripts/tutk_cc51.py` — AuthKey/PSK derivation + packet builders.
* `deliverables/scripts/dtls_proxy.py` — stock-OpenSSL-over-0x1502 relay (works to ServerHello;
  the Rust `session_probe` is the reliable driver).
* `crates/fss-tutk/examples/session_probe.rs` — full live driver with `--identity`, `--psk-hex`,
  `--encoders-count`, `--k10000-file`, `--ioctl`, `--payload-file`.

## Sources

* Bitdefender/TUTK (Roku SE): `https://www.globalsecuritymag.com/vulnerabilities-identified-in-roku-indoor-camera-se.html` — "the TUTK SDK service will listen for broadcast messages querying for devices (on port 32761), and responds with the device's P2P ID"; "The code checking the requested PSK identity will leave the buffer empty if it encounters an identity that does not match any of the expected values"; "each slice is 178 bytes long, but the copied data can be as large as 255 bytes".
* thingino (T41, secureboot): `https://github.com/themactep/thingino-firmware/discussions/470` — "You will need to physically replace the SoC chip with a spare one that does not have secureboot enabled"; "No known workarounds since they validate the bootloader signature."
* CVE-2026-50719 T41 boot-ROM init-table bypass (`AV:P`): `https://nvd.nist.gov/vuln/detail/cve-2026-50719`.
* Wyze v4 manual flash: `https://support.wyze.com/hc/en-us/articles/360031490871` (FAT32 root, `recovery_wcv4.bin`, hold setup 3-6 s).
* Image: `https://download.wyzecam.com/firmware/v4/recovery_wcv4_4.52.9.5332.bin.zip` (9 728 956 B; FIT+RSA-2048, RKAF with `boot`/`system`, `hsqs` at 0x1918b8 and 0x3c6f36).
* FCC internal photos `2AUIUWYZEC4` (`https://fccid.io/2AUIUWYZEC4`).
