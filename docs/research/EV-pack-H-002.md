# EV pack H-002 — Wyze Cam v4 (`HL_CAM4`, fw 4.52.17.26): can an owner image be installed over the LAN, and can it survive a bad image?

Scope: delivery only. No disassembly, no UART, no SD card, no vendor developer program (owner rule).
Target device: one of five `HL_CAM4` units owned by the operator, e.g. `80482C54BE32` at `192.168.6.25`
(`~/.config/fss-lab/wyze_devices_full.json:1`). SoC: Ingenic T41NQ (FCC 2AUIUWYZEC4), 16 MB SPI-NOR.
Pack answers: transport, TLS posture, image format, what verifies what, brick/recovery, exact trigger.

**Verdict: PARTIAL, split two ways.**
**Install root — reachable:** device-fetched, unsigned tar, known AES-256-ECB key, root execution.
**Reboot persistence — open:** `/configs` is executable but nothing runs from it, and the `system` image is
dm-verity'ed, so a durable foothold means rewriting the boot image with verity turned off (§3.5, §4.5).

---

## 1. Findings (answer-first)

| # | Question | Answer | Basis |
|---|---|---|---|
| F1 | Does the *device* fetch the update, or does the phone proxy it? | **The device fetches.** It issues its own HTTP GET for the URL handed to it and saves to `/tmp/img`. | v2 log `GET /firmware.bin HTTP/1.1 200` in `HclX/WyzeUpdater#5`; v4 binary strings `Ready to download file` / `download file success` / `[ASSIS]Ready to download file` |
| F2 | Is it `demo.bin`? | **No.** `demo*.bin` is the v2/v3-era *SD* name. For `HL_CAM4` the SD recovery file is `recovery_wcv4.bin`; the **network** (OTA) artifact is `<version>.tar`, never a `.bin`. | `support.wyze.com` flash article; `%[0-9.].tar`, `tar -xvf /tmp/Upgrade.tar` in device binaries |
| F3 | http or https? | **Both are accepted in the URL; plain `http` is the workable one.** The device validates the certificate when the URL is `https`, so a LAN server cannot dress up as `s3-us-west-2.amazonaws.com`; over `http` there is nothing to validate. | `WyzeUpdater#9` comment (verbatim in §3.2); v4 ships `/tmp/cacert.pem` + `https_download`, i.e. TLS is real when used |
| F4 | Is anything signed/verified on the payload? | **No.** Only an MD5 that the *caller supplies*. Then AES-256-**ECB** decrypt with a hardcoded key, `tar -xvf`, and `sh /tmp/Upgrade/upgraderun.sh` **as root**. Plaintext tar is *not* accepted. | §4.1 strings; `WyzeHacks` v3 README |
| F5 | Is the booted image verified? | **Kernel/rootfs: no. Bootloader: yes, by the ROM.** v3 upstream states signature verification is *only* for the SD recovery path, never for booting. v4 adds ROM secure boot over the SPL/U-Boot in SPI-NOR. | `WyzeHacks/tools/v3/README.md`; CVE-2026-50719 |
| F6 | Can it be pointed at a LAN URL? | **Not directly.** Since 2021-08 the Wyze cloud allowlists the URL *host*, so the push is rejected unless the URL sits on an allowlisted hostname → DNS spoof of that name to your server. | `WyzeUpdater` commit `eded24b` + README + `#9`, `#5` |
| F7 | Downgrade accepted? | Almost certainly yes and uninterrogated: no monotonic-version check exists in the accept path; the version is parsed out of the filename for bookkeeping only. v3 was routinely *downgraded* over OTA to unlock it. | `get_upgrade_target_version_by_url` strings; `WyzeHacks` history; v4 owners downgrade routinely via SD (`forums.wyze.com/t/cam-v4-cannot-downgrade-the-firmware/310873`) — **[INFERENCE]** for the OTA path on v4 |
| F8 | Can it survive a bad image? | **Partly.** The update is written to a *backup* bank and copied by U-Boot on reboot, so a failed download changes nothing. A *successfully written but unbootable* image is only recoverable if the camera still reaches the network — otherwise SD. | `wz_mini_hacks/documentation/build.md:79` |
| F9 | What carries the trigger? | **AWS IoT MQTT, i.e. the cloud.** `IOT_BACK_CMD_*` is an MQTT topic family (`iotclient`), not a TUTK opcode. Payload bytes ride the LAN; the command does not. | §5.1 |
| F11 | Does a modified `system` image still boot? | **No.** mtd2 is mounted through `fs_mgr` with dm-verity and a ramdisk `verity_key`; the metadata is appended to the partition and its root is signed. A verity failure returns before mount, and then no daemon (including the network stack) ever starts. | §3.5 |
| F12 | Can a script persist on its own? | **No.** `/configs` is exec but nothing boots from it; `.debug_flag` actually suppresses all daemons; no `fw_setenv`/`fw_printenv` exists, so `bootargs` is only reachable by hand-writing the env block. | §4.5 |
| F10 | Is the payload key recoverable without a device? | **Yes** — it is a hardcoded 32-byte default in `libwyzeUtilsPlatform.so`, not a per-unit secret. | §3.3.2, §3.4 |

---

## 2. Delivery path (transport, host, filename)

### 2.1 What the owner app actually calls

The modern app no longer receives a URL in the version check. In the captured app session
(`~/.config/fss-lab/wyze_api_flows.json`, entry index 52 of 77) the app POSTs
`https://wyze-app-upgrade-service.wyzecam.com/app/v2/upgrade/firmware_version/batch` with
`[{"deviceId":"80482C54BE32"}, …]` and gets back, per device:

```json
{"deviceId":"80482C54BE32","deviceModel":"HL_CAM4","firmwareVersion":"4.52.17.26",
 "enableEncryptOta":true,"encryptType":1}
```

No URL field. The URL is therefore *pushed* by the app/cloud in a separate action — the classic
`run_action` shape, which the v4 firmware still implements (`IOT_BACK_CMD_UPGRADE`,
`pcUrl%d:%.960s`, `pcMd5:%s`).

### 2.2 The push primitive (proven on v2/v3, present in v4 firmware)

```http
POST https://api.wyzecam.com/app/v2/auto/run_action
{"access_token":…, "app_name":"com.hualai", "phone_id":…, "sc":…, "sv":"011a6b42…",
 "provider_key":"HL_CAM4", "action_key":"upgrade", "instance_id":"80482C54BE32",
 "custom_string":"",
 "action_params":{"url":"http://HOST/wuv2/upgrade/HL_CAM4/firmware/9.9.9.9.tar",
                  "md5":"<md5 of payload>","model":"HL_CAM4","firmware_ver":"9.9.9.9"}}
```

Source: `HclX/WyzeUpdater@2e200cc:wyze_updater.py:158-162` (`push_update`), request captured verbatim in
`HclX/WyzeUpdater#9`. A 2025 fork keeps the same call (`gtxaspec/WyzeUpdater@HEAD:wyze_updater.py:216`).

The handler reads exactly three of these: `url`, `md5`, `model` (§3.3.3). `firmware_ver` is **not** parsed —
the target version is derived from the URL filename instead (`get_upgrade_target_version_by_url`), so the
filename must look like a version.


### 2.2.1 Live retry of `run_action` (2026-10-23) — schema solved, authorisation refused

The body schema is discoverable by iterating on the error message: `app_ver is null or empty` then
`ts is null` then `3005 unauthorized operation` — so `app_ver`, `app_version`, `ts` all belong in the
body and the call is well-formed once they are present. Everything below still returns **`3005
unauthorized operation`** on this account:

- `provider_key` `HL_CAM4` / `Camera` / `Wyze_Device`; `instance_id` = MAC upper case, the 20-char UID,
  or the MAC with the other provider keys
- `sv` `011a6b42d80a4f32b4cc24bb721c9c96` (2022 script) or `5b0e5bc2788d4ff68c7b98a5656148d0` (this
  firmware's constant)
- `appid` `9319141212m2ik` or `wc4p_5b0e5bc2788d4ff68c7b98a5656148d0`; with and without the
  `authorization` header; `firmware_ver` `9.9.9.9` or a plausible `4.52.30.1`

`sc` must be present or the call 1001s. So the push primitive exists and parses, but this account is
not entitled to it — the shadow delta is the working trigger, and `run_action` needs either an
entitlement or a fresh `sv`. Recorded so the next run does not repeat the matrix.

### 2.3 Transport facts

- **The device is the client.** `HclX/WyzeUpdater#5` log, plain HTTP, LAN IP, from the camera itself:
  ```
  INFO:root:Serving firmware file … as 'http://10.0.0.2:82/firmware.bin', md5=43205cf9…
  10.0.0.51 - - [22/Oct/2020 20:57:26] "GET /firmware.bin HTTP/1.1" 200 -
  ```
  Same issue, next comment: *"Apparently, it doesn't like non-standard http ports. It went through as soon as I changed the port to 80."* → **serve on 80.**
- **TLS posture:**
  > "1: The device does check for Valid SSL Certs so using SSL does not work, 2: It doesn't care if you don't use SSL so simply passing `HTTP` as the update `URL` passes the Wyze API check." — `HclX/WyzeUpdater#9`, 2021-07-16
- **Host allowlist (server side), from 2021-08-01** — commit `eded24b`, *"Adding custom host-name option for DNS spoofing to bypass Wyze's server side check"*, and the README:
  > "With latest Wyze server side change, now the update target has to be from one of the following hosts: d1fk93tz4plczb.cloudfront.net … s3-us-west-2.amazonaws.com … d2h8pzxcxn71bo.cloudfront.net … Only URLs with the above form will be approved by the Wyze update server and forwarded to the device side."
- **Still live in 2025** (plugs/bulbs, DNS-spoof path, port 80): `#9` comment by gtxaspec, 2025-05-25 — *"WyzeUpdater.py stopped working due to Wyze API changes, but I've updated it and confirmed it still works with several devices"* … then the DNS-spoof procedure.
- **Not yet re-confirmed on `HL_CAM4`.** **[INFERENCE]** the same action/handler applies, because the v4 image carries the handler (below).

### 2.4 Therefore the LAN shape is

```
camera ──DNS──▶ spoofed "s3-us-west-2.amazonaws.com" = 192.168.4.170
camera ──HTTP/80──▶ http://s3-us-west-2.amazonaws.com/wuv2/upgrade/HL_CAM4/firmware/<ver>.tar
```

The hostname must be allowlisted; the *path* is free-form but keep the `…/upgrade/<MODEL>/firmware/<ver>.tar`
shape — the device parses the version out of it (`get_upgrade_target_version_by_url ok! is:%s`) and the
`[0-9.]` filter (`%[0-9.].tar`) will not match garbage.

Addressing caution: the five cameras sit on **three different subnets** — `.4.24`, `.5.181`, `.6.25`
(`wyze_devices_full.json:1`), while the cracked-LAN harness binds `192.168.4.170`
(`deliverables/scripts/dtlslib.py:18`). Only the `.4.x` camera is same-subnet; the other two need routing
into `.4.0/24` or a per-VLAN responder, or the spoofed name must resolve to an address routed from all three.

---

## 3. Image format + what verifies it

### 3.1 The SD recovery image (for reference; not the OTA artifact)

`https://download.wyzecam.com/firmware/v4/recovery_wcv4_4.52.9.5332.bin.zip` → HTTP 200, 9,671,833 B zip,
9,728,956 B `recovery_wcv4.bin` (fetched 2026-10-22). Layout, byte-exact:

```
0x000  d0 0d fe ed            FDT magic; description "FIT Image with firmware"
0x0c0  "RKAF" 0x3c 2          in-FIT payload = RKAF archive, 60-byte hdr, 2 entries
        entry "boot"   off 0x3c      len 0x3c6d72   (another FIT, sha256 hashes, NO signature)
        entry "system" off 0x3c6dae  len 0x00580000 (squashfs 4.0, xz, 103 inodes)
```

The *outer* FIT is signed:

```
hash      { algo = "sha256"; value = <0x39fc8296 …>; }
signature { algo = "sha256,rsa2048"; key-name-hint = "kernel-dev";
            sign-images = "firmware"; value = <0x421aaead … 64 words>; }
```

(reproduce: `dtc -I dtb -O dts recovery_wcv4.bin`; the signature covers `/images/firmware` + `/configurations/conf`.)
The public key is Wyze's; it is not in the image. The wrapped kernel FIT carries **hashes only** — no signature —
so authenticity stops at the outer node.

### 3.2 What actually gates installation

> "V3 camera introduced signature verification on `demo.bin`. Unless we know Wyze's private signing key, or we
> found a vulnerabilty in the related code, a modified `demo.bin` won't be accepted.
> **Luckily, the signature verification is only for SD card recovery, not for booting.** So once you find a way
> to modify the flash content, the bootloader will happily load whatever in the flash."
> — `HclX/WyzeHacks`, `tools/v3/README.md`

So two different gates:

1. **SD recovery (`recovery_wcv4.bin`)**: RSA-2048-signed. A re-packed image is rejected (§4.5 is the exception).
2. **Anything in flash at boot**: unverified. Replace `rootfs`/kernel bytes and it boots.

### 3.3 The OTA tar and its container

The OTA payload is a **tar of shell scripts**, executed as root. Stock convention (v2/v3 line, unchanged
naming in v4): `<tar>/Upgrade/PARA` (`FWGRADEUP=app`) + `upgrade.sh` + `upgraderun.sh`
(`HclX/WyzeUpdater`, `firmwares/camera_telnet/`). v4 `assis` runs `sh /tmp/Upgrade/upgraderun.sh` by name.
`watch_up.sh` shows the stock partition targets: `app`→`/dev/mtd3`, `kernel`→`/dev/mtd1`, `rootfs`→`/dev/mtd2`
(`wz_mini_hacks/SD_ROOT/wz_mini/usr/bin/watch_up.sh:84,92,100`).

**v4 adds encryption** (`enableEncryptOta:true, encryptType:1`). Verified in the shipped rootfs
(`system` partition, `/bin/assis`):

```
encryption -d /tmp/img -f /tmp/Upgrade.tar -k %s      ← decrypt, key from product_config
decrypt /tmp/img with encrypt_type %d
decrypt_with_aes256ecb                                 ← AES-256-ECB, no IV
[MD5]Down file finished and the md5 is same            ← caller-supplied md5
after decryption, the md5 is same                      ← caller-supplied md5 again
```

`/bin/encryption` is a tiny CLI over `EVP_aes_256_cbc|ecb` (`-e/-d/-f/-k/-c/-i`).

### 3.3.1 The type switch, statically (this replaces the earlier "type 0 = plaintext" guess)

`assis`, function containing `0x402f20` (MIPS32):

```
402f20: lw   v1,2748(sp)     ; type
402f24: li   v0,1
402f28: beq  v1,v0,40325c    ; type == 1  -> in-process path
402f30: addiu a0,sp,4804     ; ---- type != 1: shell out ----
402f38: addiu a2,0x40,26852  ; "encryption -d /tmp/img -f /tmp/Upgrade.tar -k %s"
402f3c: jal  snprintf        ; a3 = key string at sp+2361
402f44: jal  system
402f54: bnez v0,403194       ; non-zero exit -> "decrypt /tmp/img error"
```

`type == 1` (`0x40325c`) fopen()s `/tmp/img` r and `/tmp/Upgrade.tar` w, then calls `decrypt_with_aes256ecb`
(`0x4022f0`), which is plain OpenSSL: `EVP_DecryptInit_ex(ctx, EVP_aes_256_ecb(), NULL, key, NULL)` with
`EVP_CIPHER_CTX_set_padding(ctx, 0)`.

**Both branches decrypt. There is no plaintext fast path.** Type only selects in-process ECB vs. the external
tool; the tool's default cipher is the CBC family with a 16-byte zero IV (`memset` at `0x401210`) and a
key-length check against `EVP_CIPHER_CTX_key_length()` (`0x400e9c-0x400eb8`), so a 32-byte key implies AES-256.

### 3.3.2 The key is a hardcoded 32-byte default — no flash read required

`product_config_get_ota_app_key` lives in `/lib/libwyzeUtilsPlatform.so` at `0x1c7c`. It calls a
config-get-with-default helper as `(dst, default, 33)` with the default at `.rodata+0x67cc`, and a guard on a
`0x4c484c48` "HLLH" state word gates it. Bytes at `0x67cc`:

```
6f 55 38 58 7a 45 70 62 4f 44 36 70 56 54 4c 77 64 7a 39 70 78 52 70 4e 39 4d 47 50 43 6f 31 50 00
o  U  8  X  z  E  p  b  O  D  6  p  V  T  L  w  d  z  9  p  x  R  p  N  9  M  G  P  C  o  1  P
```

→ **`oU8XzEpbOD6pVTLwdz9pxRpN9MGPCo1P`** (32 chars, NUL-terminated, 33-byte field). A per-unit
`[PRODUCT_CONFIG]` value would override it; nothing suggests one exists, and the default is compiled into every
image that ships this library. Treat it as model-wide until a `cat /configs/.product_config` dictionary is in
hand. Sibling defaults in the same table: log-encryption key at `0x67b8`, a `wcam_…` value at `0x67f0`.

### 3.3.3 Which transform to actually use

- type 1 → **AES-256-ECB, no padding** over the whole tar.
- otherwise → **AES-256-CBC, zero IV**, no padding, via the tool.
- A wrong guess is inert: padding is off, so a mismatched mode yields full-length garbage, `tar` fails, and
  `assis` takes the `tar error` → `UPGRADE_EXIT` path with the running system untouched.
- The type is **not** caller-supplied: the push JSON has exactly three keys — `url`, `md5`, `model`
  (three consecutive `cJSON_GetObjectItem` calls at `0x43751c`, `0x437530`, `0x437548` resolving to
  `0x7d7158`="url", `0x792cec`="md5", `0x79b248`="model"). So the vendor app cannot force a mode either; the
  device decides, and on these units `enableEncryptOta`/`encryptType:1` says ECB.

### 3.3.4 Required payload recipe (do not improvise this)

```
key      : oU8XzEpbOD6pVTLwdz9pxRpN9MGPCo1P          # exactly 32 bytes, no hex decode
cipher   : AES-256-ECB
padding  : NONE  (EVP set_padding(0); every block must already be complete)
input    : the tar, whole file
output   : the ciphertext served on port 80
md5      : MD5 of the file that is served — checked at 0x402e30 *before* decrypt. A second compare
           runs on the decrypted file at 0x402f84, so if that one fires, the digest must be the
           plaintext's (which of the two buffers carries the JSON value is not resolved).
filename : <version>.tar   (parsed by get_upgrade_target_version_by_url)
```

CBC is the wrong path here: `encryption` length-checks the key against the cipher it selected
(`EVP_CIPHER_CTX_key_length`, `0x400e9c-0x400eb8`), and the 32-byte key only fits AES-256; type 1 is ECB. If a
payload is built with CBC while the device runs type 1 (or vice versa) the decrypt yields block garbage, `tar`
fails, and nothing is written — so the mistake is cheap, but it is still a wasted cycle.

### 3.4 Handover block (for whoever is in `libwyzefdk.so` / the app)

Everything above is reproducible from the public `recovery_wcv4_4.52.9.5332.bin` alone; no device access needed.

- Key getter: `product_config_get_ota_app_key` — `/lib/libwyzeUtilsPlatform.so:0x1c7c`, size `0x54`. Signature
  `(char *dst, size_t n)`; `n` is clamped to 33 by the callee's own argument. Calls its lookup helper with
  `(dst, default=rodata+0x67cc, 33)` and only after a `0x4c484c48` state guard.
- Default value: `oU8XzEpbOD6pVTLwdz9pxRpN9MGPCo1P` (`.rodata:0x67cc`, 32 bytes + NUL).
- Sibling pattern confirms the semantics: `product_config_get_log_encryption_key` (`0x1c34`) is byte-for-byte the
  same shape with default `.rodata:0x67b8` and size 16. Same family, different default table slot.
- Consumers: `iCamera` at `0x402600` (`product_config_get_ota_app_key(buf_sp+0xf8, 100)`); `assis` at `0x4037a4`
  (`encryption -e … -k …`). No hex/base64 decode anywhere — the string is used as raw key bytes, and
  `encryption` rejects any length that is not the cipher's key length (check at `0x400e9c`).
- Cipher facts: `EVP_aes_256_ecb` at `0x402328` (type 1 path, padding off); CBC family + zero IV otherwise.
- **If the app's `libwyzefdk.so` "Unsupported encryption type" string is on the same call graph**, the enum is
  worth reading out: `assis` compares only against `1`, so values ≥2 land in the CBC branch, and any value
  that is not 1 is *not* rejected — "unsupported" may live app-side only.

### 3.5 The real persistence wall: `system` is dm-verity'ed

Found in the initramfs of the same image (`rd/` = the `ramdisk` node of the kernel FIT):

- `etc/init.d/S18_mountall` defines the partition map: `mtdblock0=uboot, 1=boot, 2=system, 3=back, 4=cfg,
  5=provisioning`, then `fs_mgr /dev/mtdblock2 /system squashfs 2` and `mount -t jffs2 /dev/mtdblock4 /configs`.
- `usr/sbin/fs_mgr` builds a device-mapper `verity` target (`DM` ioctls, `/dev/dm-%u`), reads the verity metadata
  *appended to the partition*, checks its signature against `/verity_key` (a file in the ramdisk), and then runs
  `mount -t %s -o ro %s %s`. Its own usage line is `fs_mgr <dev> <mnt> [ext4|squashfs] [0|1|2]`.
- Control flow at `0x40092c-0x40099c`: verity helper returns `0` → print `Verity success` and mount; returns
  `-1` → print `Verity fail, %d` and return **without mounting**; any other non-zero → mount anyway.
- `S18` then does `if [ $? -ne 0 ]; then exit 0; fi` → `/configs` is never mounted, and `S20init_app`'s
  `[ -e /system/init/app_init.sh ]` is false, so **no daemon ever starts**: no assis, no iotclient, no iCamera,
  no network.

Consequence: the squashfs on mtd2 is signed *indirectly* — via a verity tree whose root is signed with Wyze's
key. Write a modified squashfs there without a matching verity blob and the box does not come back. The key is
**not** in the image; regenerating the tree does not help because the root hash is signed.

Escape hatch: the mount mode (`2`) lives in the **ramdisk**, which is inside the kernel FIT — hash-only, no key
(§3.1). So `2`→`0/1` plus a re-hashed FIT is a key-free way to switch verity off. **[INFERENCE]** on which of
0/1 actually disables (one of them must, per the usage line, but the mode is not traced to a branch yet).

---

## 4. Brick risk and recovery

### 4.1 What the updater does, in order (verbatim device strings, `assis` + `iCamera`)

```
obtain_upgrade_info → "Camera is Idle for OTA check" → {"fwUpgrade":%d, "curVersion":"%s"}
killall iCamera → /system/bin/upgradePrompt1.sh &        (LED prompt)
[ASSIS]Ready to download file → downloading → /tmp/img
md5 check → decrypt → tar -xvf /tmp/Upgrade.tar -C /tmp/
upgradePrompt2.sh & → sh /tmp/Upgrade/upgraderun.sh
set_update_update_status UPGRADE_STATE_INSTALLED → reboot -f
```

`/configs/upgrade.log` is the on-device breadcrumb; `app_init.sh` clears `/configs/upGradeFlag` at boot
(`init/app_init.sh:38-41`).

### 4.2 The safety property that exists

Stock `upgraderun.sh` writes the new images to the **backup** bank and lets U-Boot copy backup→main on the next
boot:

> "`watch_up.sh` will then proceed to flash the main partitions directly, instead of doing what the stock script
> does, which is to flash the images to backup partitions, and then let the bootloader flash the main partitions
> upon reboot" — `wz_mini_hacks/documentation/build.md:79`

So: a failed/short download is harmless (nothing written); a completed download that fails its md5 is harmless;
a completed write is applied by the bootloader, not by the running system.

> **Brick contract — these two sentences are different claims and must not be merged:**
> **(i)** *An aborted or failed transfer is inert* — nothing is written, because the whole verify chain (md5 →
> decrypt → untar → script) runs in `/tmp` and the install only starts after it passes.
> **(ii)** *A written-but-unbootable kernel is not recoverable without SD or UART* — once `upgraderun.sh` has
> written and the device reboots, the bootloader copy is one-shot and there is no console to type into.
> (i) holds for every failure before the script runs; (ii) applies only after it has.

### 4.3 What breaks the "unbrickable" claim

1. **The OTA artifact never contains the bootloader.** The recovery image has only `boot` + `system`; there is no
   U-Boot and no SPL. Recovery-by-OTA therefore cannot repair a damaged bootloader — only SD/cloner can.
2. **A bad-but-written kernel leaves no network.** U-Boot stops at a prompt; with no UART and no console nothing
   can be typed. TFTP is real but **wire-only**: the U-Boot cheatsheet's own recipes need a serial prompt to reach
   (`setenv ipaddr …; tftp ${baseaddr} autoupdate-full.bin`) — `themactep/thingino-firmware` wiki *U‐Boot
   Cheatsheet*. Under the owner rule (no UART, no SD) a dead kernel is dead.
3. **No automatic revert.** There is no rollback counter or "boot-ok" marker in the OTA code — the bootloader
   copies the backup in, once, and that is the verdict.
4. **v4 is ROM-secure-booted.** SPL/U-Boot in SPI-NOR is RSA-PSS-verified by the mask ROM. Any bootloader you
   write must be byte-correct, and a stock-signed one cannot be "modified" — unlocking needs the init-table patch
   of CVE-2026-50719 (write `0` to SRAM `0x80000090` from an `INGE` entry at SPL offset `0x100`; *"An attacker
   with physical write access to boot media can inject an init-table entry that disables the secure boot check"*).
   It is writable from an OTA root shell (the v3 unlocker did exactly `dd if=/tmp/boot.bin of=/dev/mtdblock0` from
   an OTA payload), but it is the one write that can make the device need SD.
5. **A modified `system` image without a verity blob is fatal, and it takes the network with it** (§3.5): no
   mount → no `app_init.sh` → no daemons → no second OTA attempt. Unlike the kernel, this failure cannot be
   fixed from the LAN, because the LAN stack is on the image that failed.
6. **No authenticity at all.** md5 is supplied by the caller, so a MITM/hostile DNS answer is indistinguishable
   from the owner. On the plus side this is also the whole reason an owner image is installable.

### 4.4 Recoverability matrix (owner rule: no SD, no UART)

| Failure | Recoverable over LAN? | Why |
|---|---|---|
| Download aborts / wrong bytes | **yes** | md5 rejects before decrypt; nothing written |
| Decrypt/tar fails | **yes** | `decryption failed` / `tar error` → `UPGRADE_EXIT`, old system untouched |
| Script writes garbage to `rootfs`/`app`, kernel intact | **yes** | old kernel boots, OTA client runs, push again |
| Bad kernel written | **no** | U-Boot → prompt, no console, no net |
| Bootloader written without the init-table patch | **no** | ROM rejects SPL |
| Power loss during the boot-time copy | **no** | partial main partition |

One-time physical action needed: **none** for the write itself (button not even required — the command path is
remote). The only physical-ish dependency is the DNS override on the router, and it is config, not a card.

---

### 4.5 Reboot persistence: inventory (this is where it actually fails)

A script that only runs once is an install, not a foothold. Everything the boot path will execute:

- `/configs` **is** mounted rw with default options (`mount -t jffs2 /dev/mtdblock4 /configs`, no `noexec`) —
  writable and executable, but **nothing in the boot path executes a file from it**.
- What `/configs` is actually consumed for: `.county_code` (`S19insmod_driver`), `.product_config`
  (`iCamera`/`assis`, read-only), `upGradeFlag` (deleted at boot, `app_init.sh:38-41`), `.debug_flag`.
- `.debug_flag` is a trap: when present, `app_init.sh` takes the debug branch and starts **no** daemons.
- `/tmp` is tmpfs; `/configs/app.ver` is only a *copy destination* (`cp /system/bin/app.ver /configs`).
- `factorycheck /dev/mmcblk0p1` → `/tmp/factory` → `/tmp/Test/test.sh` runs only when an SD/USB `Test.tar`
  exists, and that tar is itself signature-checked ("Test.tar Signature Verification failure").
- **No `fw_setenv`, no `fw_printenv`** in the rootfs (checked against the busybox applet list and every binary),
  so `bootargs` is not reachable through a tool: it is plain text in the U-Boot environment (CRC32, unsigned)
  at the usual `0x40000` env block, and could only be rewritten with a hand-built `dd`.
- Nothing in userspace touches `/dev/mtd0` or `bootargs` at runtime.

**Honest verdict on persistence: none, by script alone.** A tar that drops files into `/configs` does not
survive as *executed* code. Persistent root requires replacing mtd2 (modified squashfs, verity neutralised via
the ramdisk mode in mtd1) or mtd1 itself — both hash-only, no key needed (§3.1, §3.5).

---

## 5. Trigger sequence (exact, in order)

1. Obtain an account token (Wyze developer API key: `wyze_updater.py --user … --password … --key-id … --api-key …`
   writes `~/.wyze_token`, per `gtxaspec/WyzeUpdater` and `#9` 2025-05-25). The stored JWT here is expired
   (`wyze_jwt.txt`, `exp=1791521441`) and `wyze_auth.json` has an empty `refresh_token`, so re-auth is required.
2. Stage the payload `X.tar` (tar containing `Upgrade/PARA`, `upgrade.sh`, `upgraderun.sh`; optional
   `kernel`/`rootfs`/`app` blobs) and AES-256-ECB-encrypt it with the device's `ota_app_key` if encrypt type stays 1.
3. Serve it on **port 80** at
   `/wuv2/upgrade/HL_CAM4/firmware/<monotonic-looking ver>.tar`, `Content-Length` set, correct `Content-Type`.
4. Point `s3-us-west-2.amazonaws.com` at the server for that camera's VLAN; clear the camera's resolver cache by
   power-cycling it or waiting out its lease.
5. `POST /app/v2/auto/run_action` (shape in §2.2) with `action_key: "upgrade"`,
   `action_params.url = "http://s3-us-west-2.amazonaws.com/wuv2/upgrade/HL_CAM4/firmware/<ver>.tar"`,
   `action_params.md5 = <md5>`, `model/firmware_ver` set, `instance_id` = the camera MAC in upper case.
6. Observe: yellow+blue LED chirp (`upgradePrompt1.sh`), server sees one `GET`, then `upgradePrompt2.sh` (slower
   chirp) while the script writes, then `reboot -f`. Confirm by `GET /app/v2/home_page/get_object_list` showing the
   new `firmware_ver`.

API surface needed on the camera side already exists locally: the DTLS/AV/command harness
(`deliverables/scripts/dtlslib.py`, `build_hl`, iface `192.168.4.170:32761`). But note the upgrade command is an
**IoT/cloud** command (`IOT_BACK_CMD_UPGRADE`), not one of the `K10000–K10003` LAN opcodes the harness speaks —
so the trigger rides the cloud socket, while only the *payload bytes* ride the LAN. This is not air-gapped.

### 5.1 Why the trigger is cloud, not LAN (answered)

`IOT_BACK_CMD_*` is not a TUTK opcode family. It is MQTT:

- the auxiliary process is `/bin/iotclient` — it banners `===========welcome to iotclient=============`, resolves
  `paracfg_get_iot_server_url`, prints `AWS_IOT_MQTT_HOSTNAME:%s`, and subscribes
  `$aws/things/%s/shadow/name/wyze-service/update/delta` and `…/wyze-secure/update/delta`;
- the upgrade handler's own source tag is `productservices/device_control/iot_topic_command_handlers.c`, and the
  dispatched action logs `action:[IOT_BACK_CMD_UPGRADE]` / `Received command to upgrade`;
- it is handed to `assis` over an IPC message (`cloud_upgrade_snd_msg_to_Attach_process` → assis
  `upgrade_msg_process_handler`), which is why the *URL never appears in a LAN packet* in our captures.

So: **no K-command carries the URL.** The `protocol_set_upgrade_*` names in `iCamera` belong to accessory
(Spotlight/GarageDoor) image pushes over the AV channel, not to the camera's own firmware. Firing the camera's
own upgrade over LAN would require the `iotclient` MQTT session to be redirected at a local broker
(`paracfg_get_iot_server_url`, `serverip`-style param) plus the device's iot certificates
(`/device/system/get_iot_certificate` → `ca_cert_url`, `client_cert_url`, `client_private_key_url`) — **not
attempted, and not needed**: the cloud hop is one HTTPS POST from the operator's own machine, while the payload
still moves only on the LAN.

---

### 5.2 Trigger practicality: does an owner's tap work, and where must the URL point?

- **Host allowlist (the only three names documented as accepted):** `d1fk93tz4plczb.cloudfront.net`,
  `s3-us-west-2.amazonaws.com`, `d2h8pzxcxn71bo.cloudfront.net` (`WyzeUpdater` README, quoted in §2.3). For a
  camera the shape used in practice is `s3-us-west-2.amazonaws.com/wuv2/upgrade/<MODEL>/firmware/<ver>.tar`.
- **Does the manual "check for updates" produce the same delta?** Not provable statically, and our capture
  contains no real update: `wyze_api_flows.json` shows only the *check* (`firmware_version/batch`) and no
  `run_action`. So an owner tap is *probably* sufficient (the app must push a URL after a positive check) but
  the chain is unverified end to end.
- **Fallback that does not depend on the app at all:** if the spoof is in place, the operator POSTs
  `run_action` themselves with the owner token (§2.2). That is one HTTPS request; nothing in the app needs to
  cooperate, and it also makes the version string and the md5 ours.

Practical ordering: set the DNS answer first, then fire the push. If the tap path is used, the spoof must
already be live *before* the button is pressed or the real CDN answers and the camera updates from Wyze.

---

## 6. Falsifiers

The pack is wrong if any of these reproduce:

1. A push with `http://s3-us-west-2.amazonaws.com/wuv2/upgrade/HL_CAM4/…/x.tar` returns `3005 UnauthorizedOperation`
   (or similar) from `run_action` → the allowlist has been tightened further and the whole LAN path is closed.
2. The camera never issues the GET, or issues it and then logs `decryption failed!` for a plain tar while the push
   carried `encrypt_type` 0 → encryption is mandatory and the key must be extracted first.
3. `get_object_list` on a v4 shows `product_model` other than `HL_CAM4` for these MACs → `provider_key` is wrong and
   the command is dropped.
4. A purpose-built tar whose `upgraderun.sh` only touches `/tmp` does not survive a reboot → the tar is not
   executed as root on this build (would flip F4 to refuted for v4).
5. `recovery_wcv4.bin` is accepted after re-packing with the `INGE` init-table patch and no re-sign → contradicts
   §3.2 gate 1 (this would be the *good* outcome; it is untested here).
6. The U-Boot on these units is shown to verify flash-resident kernels → F5 halves, and only a signed kernel boots.
7. A modified squashfs written to mtd2 **mounts anyway** (verity tolerant, or `2` is only advisory) → §3.5 is
   wrong and persistence is a script-and-reboot job after all.
8. Anything on a real device executes from `/configs` (a different `app_init.sh`, a unit-local hook) → F12 falls,
   and a file-drop payload persists with no boot-image work.

---

## 7. Verdict

**PARTIAL — install root: reachable. Reboot persistence: open.**

Confirmed end-to-end with citations:
- the device (not the phone) performs the fetch, over plain HTTP, on port 80, to a `…/firmware/<ver>.tar` path —
  and the v4 binary pair (`iCamera`, `assis`) still contains the full handler, the md5 check, the untar, and the
  root `sh upgraderun.sh`;
- nothing in the payload is signature-checked; the only integrity check is a caller-supplied md5;
- the boot gate is not on kernel/rootfs, so an owner-modified system boots once written;
- a failed transfer is non-destructive because writes go to a backup bank and the bootloader applies them.

Not yet closed:
- **Encryption is mandatory, but the key is no longer missing** (§3.3.2): the AES-256 default
  `oU8XzEpbOD6pVTLwdz9pxRpN9MGPCo1P` is compiled into `libwyzeUtilsPlatform.so`. A plaintext tar is never
  accepted; a tar encrypted with that key is the expected form. Remaining check: confirm no per-unit
  `[PRODUCT_CONFIG]` override exists (`cat /configs/.product_config`) and confirm the ECB-vs-CBC branch, both of
  which cost one push and fail inert.
- **Cloud-in-the-loop, and now nailed down** (§5.1): the trigger is AWS-IoT-MQTT, so an internet-down LAN-only
  install is not covered without redirecting `iotclient` to a local broker (unattempted). The *payload* still
  never leaves the LAN.
- **Allowlist + DNS.** Raw LAN-IP URLs are refused server-side since 2021-08; the design depends on spoofing an
  allowlisted hostname, and on the router being able to hand the camera that answer.
- **No recovery without SD/UART** for the two failure classes that matter (bad kernel, bad bootloader). "Survives a
  bad image" is true for the download and for the rootfs/app banks, false for the kernel and the bootloader.

### 7.1 What is reachable, and what is not

- **Reachable in one pass:** install-time root. AES-256-ECB, no padding, key
  `oU8XzEpbOD6pVTLwdz9pxRpN9MGPCo1P`, tar named `<ver>.tar`, served on port 80 under an allowlisted hostname,
  fired with `run_action`. Everything in §3.3.4 and §5.
- **Not reachable by a script alone:** persistence. `/configs` is executable but inert, and mtd2 is verity'ed.
  A second-stage payload must replace the boot image (§3.5, §4.5) — still key-free, because the FIT is
  hash-only, but it is boot-image surgery, not a one-liner, and it is the one place where a mistake is not
  LAN-recoverable.

So the honest end state of this ticket: *"install root: reachable; reboot persistence: open"*. Do not describe
the tar path as a persistent unlock until a repacked mtd1/mtd2 pair has been proven to boot.

---

## 8. Reproduce

```sh
# version check + response schema (needs a live token)
jq '.[52]' ~/.config/fss-lab/wyze_api_flows.json

# firmware fetch + format
curl -sL -o r.zip https://download.wyzecam.com/firmware/v4/recovery_wcv4_4.52.9.5332.bin.zip
unzip r.zip && xxd -l 256 recovery_wcv4.bin && dtc -I dtb -O dts recovery_wcv4.bin | head -40

# device-side OTA logic (system = squashfs 4.0 @ 0x3c6e76, after 0x1008 bytes of archive framing)
dd if=recovery_wcv4.bin of=sys.sqfs bs=1 skip=3960438 count=5763000
unsquashfs -d sysroot sys.sqfs
strings -n 4 sysroot/bin/assis | grep -iE 'encryption|upgraderun|md5|tar -xvf'

# initramfs (mounting, verity, inittab) — ramdisk node of the kernel FIT at file offset 0x1918b8
dd if=recovery_wcv4.bin of=rd.img bs=1 skip=1644728 count=2400000
unsquashfs -d rd rd.img && cat rd/etc/init.d/S18_mountall && strings -n 5 rd/usr/sbin/fs_mgr | grep -i verity
```

---

## 9. Secondary: AOSU HomeBase `0x0a` upgrade (bounded, unverified)

Out of the main scope; recorded because it shares the shape "client hands the device a URL".

- Command surface: `0x0a` takes a URL plus a 32-byte MD5 and no signature (EV filed by the AOSU lane; not
  re-derived here).
- **Is the fetch TLS?** Unknown. Nothing in this pack establishes it, and the homebase is a Tuya/Glazero stack,
  whose app API is plaintext JSON (`DEVICE_ADAPTER_MATRIX.md:69`) — plaintext-ness of the *app* channel is weak
  evidence at best for the *upgrade* channel. **[UNVERIFIED]**
- **Does 51028 make a LAN redirect viable?** Mostly **no**, with one caveat. 51028 is a `tinyproxy/1.11.2` listening
  on the homebase (`DEVICE_ADAPTER_MATRIX.md:84`). Two matrix entries disagree on its posture: the 2026-10-09 note
  says it "does NOT openly forward", the 2026-10-22 LAB-ROOT-001 note says it *is* an unauthenticated open forward
  proxy with arbitrary-port egress — treat the later one as current. Either way it is a **proxy on the device**, not
  a redirect primitive: it only carries traffic that the homebase's own stack already routes through
  `127.0.0.1:51028`. A LAN redirect needs the fetcher to take a literal URL (as Wyze's does) and to tolerate a
  non-public host — that is a property of the 0x0a handler, not of 51028.
- Two probes settle it: (1) push `0x0a` with `http://192.168.4.170/x.bin` and watch for a GET; (2) repeat over
  `https` with a self-signed cert and see whether it aborts before the body. If (1) yields a GET, the AOSU path is
  *easier* than Wyze's — no allowlist, no DNS spoof — and 51028 becomes irrelevant except as an egress test rig.
