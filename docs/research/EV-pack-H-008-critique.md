# EV pack — H-008 critique (both sides attacked)

**Session:** RS-20261022-camera-root · **Date:** 2026-10-22 · **Author:** DevilsAdvocate
**Target:** H-008 = *"no network-only root exists on current firmware for any family; the only honest path to
replacement firmware is per-family owner rituals or a class-A (OpenIPC) purchase; treat the fleet as
data-lanes-only."*

**Method:** primary sources only (vendor advisories, CVE/NVD, upstream project repos, published console logs),
plus bounded read-only live probes on `en1`. Read-only throughout — nothing was written, rebooted or flashed.
Beads: `bb-*-ajt`, `bb-*-z6q`, `bb-*-d7i`, `bb-*-miq`, `bb-*-tgd`, `bb-*-s7s`, `bb-*-p9h`, `bb-*-wiu`,
`bb-*-ia5`, `bb-*-9hu`, `bb-*-xxu`, `bb-*-cp2`.

---

## 0. Two scope corrections that change the attack surface

| # | Census said | Actually is | Evidence |
|---|---|---|---|
| 1 | `192.168.4.20` = "Shenzhen Youhua (candidate Owlet/base)" | **Google (OUI MA-L `44:07:0B` = Google, Inc.)**, a Cast device. `:8443` serves a Google Cast leaf cert `O=Google Inc, OU=Cast, CN=L17AL3 FA8FCA7C39CC`, issuer `CN=Chromecast ICA 7 (Audio Assist 2)`; TCP 8009 (Cast) open; `GET /setup/eureka_info?params=version,build_version,name` → `{"name":"Gracie Studio speaker","version":13}`. Named "Gracie". | EV-109, live 2026-10-22 |
| 2 | `192.168.4.70` = "TP-Link Systems (Tapo)" | Tapo **confirmed**, model **not** confirmed. `:443` cert is `CN=TAPO-DEVICE, O=TP` — Tapo's cert never encodes model or hardware version, so the wire cannot tell C100 from C200 v5. Live pre-auth `getConnectStatus` returns `-40401` + `encrypt_type:["3"]` + RSA key + nonce. `:554` **refused** (3 retries), `:80`/`:2020` closed, `:443` open. | live 2026-10-22 |

Owlet is therefore still unlocated; H-007's "other hosts" reduces to one Cast endpoint plus four
zero-TCP Intellirocks/Govee rows.

### 0b. CVE-2026-102369, nailed down (Main's five questions)

| Question | Answer |
|---|---|
| CVSS | CNA (TP-Link) **CVSS 4.0 = 8.7 High**, `AV:A/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N`. Tenable's v3.1 mirror records **8.8 High**. NVD status **Deferred** — no NVD-assigned score. |
| Affected range | **Exact, and narrow**: Tapo **C200 hardware v5 only**, versions `< V5_1.4.6 Build 260709 Rel.27675n`; Tapo **C120 hardware v1 only**, versions `< 1.9.4 Build 260813`. Named products only — C100/C110/C210/C310 are **not** covered, even though C100 v5 shares the sibling auth bug (CVE-2025-14300). |
| Pre-auth? | **Yes.** `PR:N`, `UI:N`, and the advisory text says "unauthenticated attacker on the same local network". The 2026-08-18 record title was literally *"Unauthenticated Administrative Authentication Bypass via device_confirm Replay"*. |
| Fixed in the fleet's build? | **Unknowable on the wire.** `.70`'s cert is `CN=TAPO-DEVICE, O=TP` — Tapo's self-signed cert carries no model or hardware version, for any model. `554` refused and `80`/`2020` closed fit both a C100 and a C200-with-RTSP-off. Only the chassis label or an authenticated `getDeviceInfo` settles it. |
| Publication-day 0-day? | **No — coordinated, fix first.** CVE reserved 2026-09-28, published 2026-10-01; the fixed build was already posted to the US download page on **2026-08-17**, ~6 weeks earlier. But: **no public exploit code** (EPSS 0.003, CISA KEV = No, SSVC `Exploitation: None`, `Automatable: No`), and a unit that has not been updated since July is still vulnerable *today*. So the risk is "undocumented, not unpatchable", and the practical question is one label read. |


---

## 1. What actually enforces the lockdown, per family

The load-bearing question for H-008 is *not* "is there an exploit" but "if you win exec, can you make it
survive a reboot, and if not, is the only persistence a signed image". That reduces to the SoC, its boot
verification, and the fs layout.

**Say it loudly: every family on this LAN except the Google endpoint has a SoC with either no boot-time
verification at all or a broken one, so "it's signed, therefore H-008" is not an argument here.**

| Family / host | SoC (source) | Boot verification actually present | Rootfs / persistence substrate | Verdict on "signing refutes H-008" |
|---|---|---|---|---|
| Wyze `.23/.24/.5.242` | **Ingenic T31X/T31ZX** (v3, board `WYZEV3_T31GC2053`, FCC 2AUIUWYZEC3) — EV-104; **Ingenic T41** (v4, FCC 2AUIUWYZEC4) — EV-103 | **None on v2/v3/v4.** "Beginning with the Wyze Cam Pan 3, Wyze has implemented secure boot on their SoC chips." (EV-104). And even where T31 secure boot *is* burned, the mask ROM compares **one 32-bit word** of the RSA output against the digest — 128 bits → 32 bits, forgery in ~3–4 min on a commodity CPU, unpatchable (CVE-2026-50720, EV-102). T41 falls in the sibling class CVE-2026-50719 (init-table executed *before* verification). | 16 MB SPI NOR, squashfs + `jffs2`; **stock U-Boot boots a kernel from an SD card with no verification** — that is exactly the mechanism `wz_flash-helper`/Thingino use ("Your camera does not have verified boot on hardware level. Your camera U-boot supports booting a kernel file from SD card") EV-110 | **Cannot refute on signing grounds.** The gate is *delivery* (SD slot), not crypto. |
| AOSU HomeBase `.37` | Tuya-class; SoC **unconfirmed** (`[INFERENCE]` Anyka AK3918 — `6668` is the Tuya local port, and every Anyka firmware family found carries `anyka_service.sh` with the same SD hook) | No secure boot in the Anyka family; root-exec hook with no signature gate at boot: `/usr/sbin/anyka_service.sh` copies `/mnt/update.nor.sh` from SD to `/tmp/net.sh` **and runs it as root** (CVE-2025-63296, EV-111) | squashfs root, writable `/tmp` + config partition; on-device `updater local A=…sqsh4` flashes a local image with **no key** (EV-108) | **Cannot refute on signing grounds.** Delivery is SD again, but the `updater` binary means *any* exec is one step from persistent. |
| Tapo `.70` | **Realtek RTS3903** + `rx5281` radio — read off the stock U-Boot banner: `Board: IPCAM RTS3903 CPU: 500M :rx5281 prid=0xdc02` (EV-106) | **Yes, real.** U-Boot prints `Firmware check failed!` on a rejected image (EV-106). OTA container is **encrypted and signed**: own download of `…_up_boot-signed_….bin` = 8 128 512 bytes, header `00 00 02 00 55 aa` then ciphertext, no `hsqs`/`sqsh`/`UBI` magic anywhere, 7.95–7.96 bits/byte in all 12 sampled blocks, binwalk 0 hits (EV-105) | Encrypted squashfs; `factory_up_boot.bin` on SD is the only field-load path; `check_upgrade` requires `/dev/mmcblk0p1` (a real partition table), so camera-formatted cards silently skip it (EV-107) | **Refutes it.** No key ⇒ no custom image. Runtime exec is the only network route. |
| Yi `.6.156` | Hi3518E (yi-hack-v3/v4) or Anyka AK3918 on the newer "Yi IoT" build | None | SD-only updater; user-owned `equip_test.sh` variants are SN-prefix-keyed | Cannot refute on signing; delivery is SD. |
| Intellirocks `.35/.36/.40/.6.70` | unknown; **no TCP answers at all** in the census | unknown | unknown | Nothing to refute with. |
| Google/Cast `.20` | Google silicon, Fuchsia/Cast (`[INFERENCE]` from the Fuchsia-era Cast cert chain) | Full signed chain; no ADB | Cast `eureka_info` + CastV2 `:8009`; no shell | **Refutes it**, hard. |
| Canary | not on LAN | — | — | — |

**Consequence:** H-008's *replacement-firmware* half is right — Tapo and the Google endpoint genuinely cannot
take an attacker image without a ritual (Tapo: SD `factory_up_boot.bin`; Wyze: SD no-tool installer; Yi:
SD). Its *root* half is a different question, and it is wrong for Tapo (below).

---

## 2. Findings

Primitive inventory. `pre-auth?` = reachable with no owner credential. Reliability is my estimate for
*vendor-firmware-you-actually-have*, not for the CVE in the abstract.

| # | Family | Transport / port | Pre-auth? | Class | Exact sink | Reliability | Evidence |
|---|---|---|---|---|---|---|---|
| F-1 | Tapo C120 v1 / C200 **v5** | HTTPS `:443` | **Yes** (`PR:N`) | **RCE (auth-bypass → cmd injection) + config-write (service enablement)** | `device_confirm` challenge replay → admin session; then "MacTool handler" input concatenated into a shell, executing "within the device management process" — uhttpd, `[INFERENCE]` root, per CVE-2021-4045's "uhttpd binary running by default as root" on this same product line | **High if model+fw match**; zero public exploit code (EPSS 0.003, SSVC Exploitation `None`) | EV-101, EV-112 |
| F-2 | Tapo (same models) | HTTPS `:443` | **Yes** | auth-bypass → admin token | same `device_confirm` replay, CVE-2026-15315 (the auth half, CVSS 8.8 AV:A) | High | EV-101 chain |
| F-3 | Tapo | HTTPS `:443` | Yes | auth-bypass + info-leak (first-setup state) | `connectAP` unauthenticated, CVE-2025-14300; `scan` leaks SSID/BSSID/crypto, CVE-2026-78577 | High | vendor FAQ 5321 |
| F-4 | Tapo | HTTPS `:443` | Yes | DoS (memory-safety adjacent) | RTSP `Authorization` header length overflow, CVE-2026-1871 (CWE-121); NULL deref in connect parser, CVE-2026-9032 | High | EV-101, NVD |
| F-5 | Tapo | HTTPS `:443` | Yes | stepping stone to persistence | SD `factory_up_boot.bin` accepts **any older** version — no monotonic check; "I can downgrade from 1.3.11 to any fw version" | High (needs card+ritual) | EV-107 |
| F-6 | Wyze v3/v4 | UDP `32761` (TUTK/IOTC NEW, `0xCC51`) | No — discovery is HMAC-gated on the camera's own uid/enr/mac | transport/auth | owner creds live in `~/.config/fss-lab/`; unauth 52-byte `0x1002` gets silence, correct HMAC gets seq=1 + ticket (Main, in-session) | n/a | Main context |
| F-7 | Wyze v4 | UDP `32761`, `0x1502` DTLS wrapper | **Yes, reached** | parser (memory-safety **open**) | structurally valid ClientHello → **fatal alert 2 / `0x32` decode_error**; garbage → silence ⇒ wrapper accepted, DTLS server parser is the live surface | unknown — unproven sink | Main context |
| F-8 | Wyze v3/v4 | SD slot → stock U-Boot | physical | **persistent root, no crypto gate** | U-Boot boots an SD kernel unverified; Thingino/`wz_flash-helper` write partitions, then SSH `root:root` | **Very high** (community-default method) | EV-110 |
| F-9 | Wyze (bonus) | — | — | signing bypass | T31 ROM 32-bit-word compare lets a forged SPL pass secure boot on a unit that *has* it burned | High, but physical (SPI write) | EV-102 |
| F-10 | AOSU/Tuya | TCP `6668` (Tuya local, 3.1–3.5) | Handshake is acceptance-checked but payload is key-encrypted | info/state + `[INFERENCE]` exec | my 3.1 probes were accepted and closed with empty reply (read-only, no corrupt result). Key is obtainable **without the dev program** via QR-code account login (`tuya-local-key`). Protocol documented (`PROTOCOL.md`, Tuya 3.4) | Unknown | EV-108, op. cit. |
| F-11 | AOSU/Tuya | TCP `443`, `8888`, `51028` | unknown | `51028` open, no banner; `8888`/`443` flapped on 3 retries (sleeping) | — | low confidence | live 2026-10-22 |
| F-12 | Anyka class (AOSU/Yi-IoT `[INFERENCE]`) | SD → `anyka_service.sh` | physical | **root exec at boot** | `/mnt/update.nor.sh` → `/tmp/net.sh` → root (CVE-2025-63296). Also `_ak39_factory.ini` enables factory mode with `telnetd:23` | High | EV-111, EV-108 |
| F-13 | Yi | UDP `3702` WS-Discovery only | yes | info-leak | replies `dn:NetworkVideoTransmitter` but the advertised `http://…/onvif/device_service` listener never opens (NEG-006) | — | project NEG-006 |
| F-14 | Cast `.20` | HTTPS `:8443`, TCP `:8009` | **Yes** | info/config | `eureka_info` → name/version; CastV2 control (volume/reboot). No ADB, no shell | very high, low value | EV-109 |
| F-15 | Intellirocks `.35/.36/.40/.6.70` | none | — | — | zero open TCP in census | — | census |

### Inert / refuted surfaces (recorded so nobody re-walks them)

- Tier-1 dead ends for H-008's defenders: none of the seven rows has an *open authenticated debug console*
  (no telnetd, no sshd, no ADB) on stock firmware — every one is either crypto-locked (Tapo, Google) or
  silent (Wyze, Yi, Govee).
- Tapo is **not** "signed therefore safe": the C200 v5 line ships uhttpd as root and the Oct-2026 bug is
  pre-auth.

---

## 3. Chain

### 3a. Tapo `.70` — the one real network-only chain

```
unauth replay of device_confirm challenge  ->  admin session
   ->  enable the privileged service (available only after a reboot)
   ->  [WRITE] reboot
   ->  injected input in the MacTool handler  ->  arbitrary commands as root in uhttpd
   ->  persistence: the service enablement is config state and survives reboot;
      re-inject to regain the shell after each boot, or (unverified) drop a hook on the
      writable partition if one exists
```

Steps 1 and 2 are one POST each; the only physical action is a **power-cycle, which cannot brick**.
Falsifier that would kill it, in order of likelihood:

1. `.70` is not a C200 v5 or C120 v1 → different uhttpd, chain does not apply (C100 v5 shares the auth
   bug via CVE-2025-14300 but has no CVE of its own).
2. `.70` already runs `≥ V5_1.4.6 Build 260709` / `≥ 1.9.4 Build 260813` (fixed builds went up on the US
   download page 2026-08-17, i.e. **six weeks before** the 2026-10-01 publication, so this is plausible).
3. "Privileged service" turns out to be a one-shot busybox `telnetd` with no way to re-arm, making it
   *one* reboot-surviving session rather than persistent root.
4. `/` is a read-only squashfs with no writable overlay, so nothing can be planted — you would be
   re-exploiting by design (still "survives reboot without re-exploitation" only if the service persists).

Residual unknown: the chain is documented by the CNA but there is **no public PoC**, so step-level
sequencing (exact `device_confirm` bytes, the service name, the MacTool parameter) has to be recovered
by hand.

### 3b. Wyze — chain exists, but not network-only

`[WRITE, physical]` FAT32 + MBR card → `wz_flash-helper` profile for the exact SoC (`t31x` and `t31a` are
not interchangeable) → Thingino; SSH `root:root` (EV-110). Persistent, reboot-surviving, ~3 min, and the
only real brick risk is a wrong-SoC image. **No network-only variant is demonstrated by anyone**: the
TUTK DTLS parser (F-7) is reached pre-auth and *is* memory-unsafe in principle, but no corruptible sink is
published.

### 3c. AOSU — no chain (reasons)

Transport is Tuya-local, whose payloads are AES-encrypted under a per-device `local_key`. Getting the key
without a developer program is solved (QR account login). What is **not** shown anywhere is a Tuya DP or
command that writes a file or execs. So: one credential hop to a state channel, then a wall. Falsifier:
a documented `upgrade`/`mcu_ota`/`cmd` command or a DP that reaches `anyka_service.sh`.

### 3d. Yi — no chain

Stock daemon updates only from SD (`equip_test.sh` via the card); ONVIF is advertised but gated
pre-provisioning (NEG-006); no other TCP listener. Falsifier: a firmware build that opens the SOAP
listener before provisioning, or a pre-auth parser bug in the WSD responder.

### 3e. Google `.20`, Intellirocks — no chain

Cast/Fuchsia: `eureka_info` + CastV2 only; no shell. Govee rows answer nothing on TCP.

---

## 4. Fleet rank

Ordered by `(pre-auth? × reliability) ÷ (brick risk × physical prerequisite)`. "Pre" = needs no owner
credential, "Phy" = needs something physical, "Elbow" = effort/unknowns.

| Rank | Row | Pre | Rel | Brick | Phy | Elbow | Why here |
|---|---|---|---|---|---|---|---|
| **1** | **Tapo `.70`** | **1.0** | 0.7 (no PoC; model unconfirmed) | **0.3** — worst case is a power-cycle, and U-Boot has an HTTP recovery | 0 (power-cycle only) | 0.8 — must hand-build the replay | Only true pre-auth→root shape on the LAN. Its brick risk is real *only* if you also flash an image, which the chain does not require. |
| 2 | Wyze v3/v4 (`.23/.24/.5.242`) | 0.3 (auth-gated discovery) | 0.95 | 0.35 — wrong SoC build is fatal; no Ethernet, no TFTP fallback | 0.8 (card + slot access) | 0.25 — recipes exist | Highest certainty per unit of cleverness, lowest creativity. Wins on *reliability*, loses to Tapo purely on the physical prerequisite. |
| 3 | AOSU `.37` | 0.5 | 0.35 | 0.4 | 0.7 (if Anyka) | 0.9 (key + find an exec DP) | Cheapest to *reach*, most unknown to *finish*. |
| 4 | Yi `.6.156` | 0.2 | 0.9 (yi-hack, if variant matches) | 0.45 (SN-prefix variant mismatch = hang) | 0.9 | 0.4 | Needs SN prefix + exact variant before you touch it. |
| 5 | Google `.20` | 0.9 | 0.9 | **0.05** | 0 | 0.7 | Practically unbrickable, and practically unexploitable. Pure data lane. |
| 6 | Intellirocks ×4 | 0 | 0 | 0.1 | 0 | 1.0 | Nothing answers; unknown SoC. |
| 7 | Canary | — | — | — | — | — | Not on the LAN; out of reach until located. |

The ranking's practical message: **the only row worth a network-only attempt is the one row with the
highest theoretical brick risk, and its chain happens not to touch flash.** That inversion is the single
thing the optimists have right and the pessimists have not noticed.

---

## 5. Brick risk + recovery (the five the optimists skip)

1. **Bootloader env corruption — Wyze.** The Thingino switch writes `u-boot` env for SSID/password
   (`setup_thingino_env.sh`). Wyze has **no Ethernet**. A half-written env = no radio = no network, and the
   only rescue is another SD boot if U-Boot itself is still sane. Documented failure mode: "your camera
   would not be able to connect to Wi-Fi. In order to fix, you have to run the program again with it
   enabled" (EV-110) — which needs the same SD path to still work.
2. **No TFTP / no wired fallback.** Tapo's recovery is a U-Boot `httpd` bound to `192.168.0.10` — and "the
   web tflash recovery will need a cable for cable network, **wifi does not work**" (EV-106). On a wifi-only
   C200 the recovery path presupposes a link the device does not have. Wyze has no U-Boot httpd at all.
3. **Missing factory partition / partial write.** `switch_firmware_with_all_partitions=no` is the
   recommended setting and it deliberately leaves `aback`, `kback`, `backupa`, `backupd` untouched
   (EV-110) — those are the stock update's staging partitions. Blank them and the next stock OTA has
   nowhere to stage, which is a *delayed* brick that shows up weeks later.
4. **Unrecoverable OTP/eFuse.** Any T31/T41 unit with secure boot burned is one-way: "the OTP key cannot be
   modified or reset … the only way to fix the device is to replace the SoC chip" (Thingino). This is why
   the 32-bit ROM flaw (EV-102) matters more than it looks — without it, a wrong image on a Pan 3+ is dead
   silicon.
5. **No U-Boot console on the affected Tapo hardware.** The C200 has console pads but no header; there is a
   standing issue titled *"No serial on C200 (EU) / 3.20"*. And where a user did reach U-Boot after a bad
   OTA, the stock `bootm` said `Firmware check failed!` and the SD method did not work **because "the
   recovery sd flash are part of the firmware"** — i.e. the recovery script is inside the thing that
   broke. Real 2023-12 brick wave in that thread, three separate units, one RMA.

**Recovery, ranked, per family:** power-cycle (Tapo chain, always) → SD re-flash of the *stock* image with
`factory_up_boot.bin` (works only if the fs still boots) → U-Boot httpd over a wired link (Tapo only) →
desolder SPI + CH341a from a dump taken *before* the first write (Wyze/Ingenic; `wz_flash-helper` Backup
exists precisely for this).

---

## 6. What would falsify this (the decisive missing tests)

| For | Decisive test | Cost |
|---|---|---|
| Killing H-008 on Tapo | Read the chassis label (or one authenticated `getDeviceInfo`) to fix model + hardware version, then send the two-step replay from §3a and run `id`. **One POST pair decides the whole session.** | ~30 min, no write except the chain's own reboot |
| Killing H-001 | Complete an IOTC `0x1502` handshake with owner creds, then fuzz the post-handshake DTLS record and AVAPI parsers with boundary-length fields | 2 h, read-only |
| Killing H-003 | QR account login → `local_key`; then Tuya 3.4 `dp_query` + dump the DP catalogue looking for `upgrade`/`cmd`/`reboot` | 2 h, read-only |
| Killing H-004 | Same key, then push a Tuya `mcu_ota` with a modified `.sqsh4` and observe whether CRC/signature rejects | needs a write |
| Keeping H-008 on Wyze | Take one Wyze offline, get the raw `demo.bin`/`factory_up_boot` slot on port 32761 to accept an image *without* an SD card — nobody has published this | days |
| Confirming the Tapo fix level | `.70` on `≥V5_1.4.6` ⇒ H-008 resurrects for Tapo and rank 1 collapses to rank 2 | one label read |

---

## 7. Kill list

| Hypothesis | Call | Reason |
|---|---|---|
| **H-002** (Wyze accepts owner-producible unsigned image) | **Half-dead by scope, not by fact** — the *claim is true* (stock U-Boot boots an unverified SD kernel, EV-110) but it is an **SD** path, so on its own it does not refute H-008. Kill it as an H-008 refuter. | EV-110, EV-103, EV-104 |
| **H-004** (Tuya/Glazero OTA takes attacker image) | **Dead as an H-008 refuter.** Tuya OTA arrives via the cloud, not the LAN; no LAN-triggerable OTA is documented. Nothing on `.37` speaks OTA (only `6668`, `51028`, `8888`, `443`). | live probes; F-11 |
| **H-006** (Yi has an SD-less network root) | **Dead.** The WSD responder never opens its own advertised SOAP port (NEG-006); the update path is the SD `equip_test.sh`; no other listener. | NEG-006 |
| **H-007** (debug surface on "other" hosts) | **Dead.** `.20` is a Cast endpoint: `eureka_info` + 8009 only, no ADB. Govee rows answer zero TCP. | EV-109, census |
| **H-005** | **Not dead — promoted.** See §8. | EV-101, EV-112 |
| **H-008 itself** | **Dead for Tapo, standing for the other five.** See §9. | §3 |

## 8. Survives

| Hypothesis | Why it survives | Single cheapest decisive test |
|---|---|---|
| **H-005** (Tapo pre-auth exec) | Only row with `PR:N` on every step, vendor-published, fixed build only since July/Aug 2026, and the owner's `.70` answers the exact pre-auth handshake (`getConnectStatus` → `-40401`, `encrypt_type:["3"]`, RSA key, nonce). | Label read to fix the model; then the two-step replay and `id`. |
| **H-001** (TUTK DTLS/AVAPI sink) | Pre-auth reachability is *proven* (fatal `decode_error` on a valid ClientHello ⇒ the wrapper parses and hands to the DTLS server). Only the sink is unproven. | Malformed DTLS record post-handshake, boundary lengths, with owner creds. |
| **H-003** (Tuya key + exec DP) | Key acquisition without the dev program is solved; 3.1 handshake is accepted. The unproven part is the DP surface, not access. | `dp_query` catalogue dump with the recovered key. |

---

## 9. Verdict

**H-008: PARTIAL — refuted for exactly one family, standing for the other five.** Confidence **0.75** that
the Tapo refutation holds *if* `.70` is a C200 v5 or C120 v1 below the fixed build; **0.9** that no
network-only root exists for Wyze, AOSU, Yi, the Cast endpoint and the Govee rows on current firmware.

Both extremes fail:

- **Optimists fail** because there is no network-only root on Wyze despite a fully broken boot chain
  (no secure boot on v3/v4, and even the ROM verification is worth 32 bits) — the gate is *delivery*, not
  crypto. Same for AOSU: an unsigned root-exec SD hook exists and still needs a card.
- **H-008 as written fails** because it says *"no network-only root … for any family"* and Tapo C200 v5 /
  C120 v1 have a vendor-documented, unauthenticated, no-credential, reboot-surviving path to root, with
  zero flash write and a worst-case recoverable by power-cycling.

**Replacement firmware is still ritual-only** (SD card for Tapo/Wyze/Yi, `updater`-from-shell for Anyka),
so the "data-lanes-only" fleet posture is right as a *default* and wrong as a *rule*: Tapo is the one lane
that can be promoted to a root-managed node without touching hardware, and everything else stays
data-lanes.

**Ranked next actions:** (1) read the `.70` label; (2) if C200 v5/C120 v1 < fix, run §3a; (3) if patched,
pull one Wyze and run the Thingino SD install — it is the highest-certainty result in this fleet and it
cannot be made worse by waiting.
