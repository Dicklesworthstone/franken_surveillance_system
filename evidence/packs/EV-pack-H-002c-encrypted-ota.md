# EV-pack-H-002c — Wyze HL_CAM4 `enableEncryptOta` / `encryptType:1`

Pack: H-002c · Target: Wyze HL_CAM4 (Cam v4, Ingenic T41) · Built 2026-10-22
Firmware analysed: **4.52.17.26** (exact fleet version)

**Verdict on "an owner can produce a network-installable image": `PARTIAL`.**
Split the two halves, because they have different answers:

| half | answer | why |
|---|---|---|
| **install root** | **yes, achievable** | payload is an unsigned TAR whose `upgraderun.sh` executes **as root, at install time**; AES-256-ECB under a public default key, or CBC under any other type. |
| **reboot persistence** | **blocked** | U-Boot does **required-key** FIT verification with `kernel-dev` on every boot (`sha256,rsa2048:kernel-dev+ … OK`), and `/system` is dm-verity-gated by `/verity_key` inside the signed ramdisk. |

Boot **does** verify — this is not the older "verify if a signature is present"
branch. An unsigned FIT is loaded and then rejected. The only persistence routes are
(a) a Wyze-signed image, (b) rewriting the boot loader env so a *signed* boot FIT runs
*our* `init=` (plain CRC-only env, unproven on this build — §5), or (c) hardware
(CVE-2026-50719 / SoC swap — §4).

`upgraderun.sh` running as root at install time is by itself a working primitive the
moment DNS + plain-HTTP redirection is in place, independent of the boot gate: it can
read MTD0, pad the jffs2 `/configs`, `fw_setenv`-style write the env sector, or exfil
`/configs/.product_config`.

---

## 1. Findings — `encryptType: 1` is AES-256-ECB with a device-provisioned key

`enableEncryptOta:true, encryptType:1` was returned for **all five** owned units by
`POST https://wyze-app-upgrade-service.wyzecam.com/app/v2/upgrade/firmware_version/batch`
(captured flow `~/.config/fss-lab/wyze_api_flows.json` idx 52; response shows the two
fields verbatim for every `deviceId`). The OTA object URL is *not* in that response.

The executor is `bin/assis` (path string embedded in the binary:
`app/assistantprocess/platform/ingenict41/upgrade/platform_upgrade.c` — T41-specific).
The install sequence, in binary order (strings at file offsets, `bin/assis` from
`system.sqfs` of `recovery_wcv4_4.52.17.26.bin.zip`):

| # | evidence | meaning |
|---|----------|---------|
| 1 | `[ASSIS]url:%s, MD5:%s` | caller-supplied URL + encrypted-blob MD5 |
| 2 | `[ASSIS]md5 error exit actual_file_md5:%s, param_md5:%s` | MD5 of the **encrypted** download, checked before decrypt |
| 3 | `decrypt /tmp/img with encrypt_type %d` | branch on encrypt type |
| 4 | `encryption -d /tmp/img -f /tmp/Upgrade.tar -k %s` | non-type-1 path: external tool |
| 5 | `[ASSIS]after decryption, the md5 check failed` | second MD5, over the **plaintext** |
| 6 | `[ASSIS] mv /tmp/img /tmp/Upgrade.tar` → `tar -xvf /tmp/Upgrade.tar -C /tmp/` → `sh /tmp/Upgrade/upgraderun.sh` | payload is a TAR with a root shell script |

Disassembly of the dispatch (`bin/assis`, vaddr, `llvm-objdump -d` output kept at
`/tmp/assis.s`):

```
406c2c: lw   $3, 0xabc($sp)          ; encrypt_type
406c30: addiu $2, $zero, 1
406c34: beq  $3, $2, 0x406f68        ; type == 1  -> in-process decryptor
406c3c: addiu $4, $sp, 0x12c4        ; else: snprintf(cmd,0x200,
406c44: addiu $6, $6, -0x5114        ;   "encryption -d /tmp/img -f /tmp/Upgrade.tar -k %s")
406c50: jal  0x40c8a0                ; system(cmd)
```

Type 1 lands on `0x406f68`, which streams 1 KiB chunks through `0x405fd0` =
`decrypt_with_aes256ecb` (log tag of the same name at `.rodata` 0x40b1xx). That
function is:

```
405ff8: jal  0x40cca0        ; EVP_CIPHER_CTX_new
406020: jal  0x40cb40        ; EVP_aes_256_ecb()
406024: jal  0x40c990        ; EVP_DecryptInit_ex(ctx, EVP_aes_256_ecb(), NULL, key, NULL)
40603c: jal  0x40ce60        ; EVP_CIPHER_CTX_set_padding(ctx, 0)   <- $5 = $zero
406054: jal  0x40cf50        ; EVP_DecryptUpdate(ctx, in, len, out, &outlen)
406070: jal  0x40cbe0        ; EVP_DecryptFinal_ex
```

So: **AES-256-ECB, padding disabled, no IV/nonce, key = the raw 32-byte key buffer.**

`libwyzefdk.so` carries the same scheme in its cloud callback `WYZE_OTA_CallBack`
(0xdafc): it parses `firmwareUrl`, `firmwareMd5`, `firmwareVer`, `deviceModel`,
`firmwareEncryptMd5`, `firmwareEncryptKey`, `firmwareEncryptType` as cJSON members
(.rodata 0x1f038/0x1f044/0x1f05c/0x1f050/0x1f068/0x1f07c/0x1f090), base64-decodes the
key (`wyze_base64_decode`), **requires decoded length == 0x20**, and does the same
`EVP_DecryptInit_ex` + `set_padding(ctx,0)` + Update/Final sequence (0xe174–0xe254).
Note the library imports only `EVP_aes_128_ecb` while demanding a 32-byte buffer —
the 16-byte read of OpenSSL's fixed-size cipher takes the first half. `assis` is the
authoritative installer on this model and is unambiguous (256-bit, full buffer).

Both MD5s are enforced (`firmwareEncryptMd5` pre-decrypt, `firmwareMd5` post-decrypt),
so an owner-built payload must supply matching digests — trivial, since the owner
computes them.

## 2. Scheme

```
cloud (MQTT shadow, $aws/things/<did>/shadow/update; method APPPushOTA)
        │  {url, md5_plain, ver, model, md5_enc, key, encryptType}
        ▼
camera: GET <url> over HTTP -> /tmp/img        (plain HTTP port 80 to an allowlisted host)
        MD5(/tmp/img) == firmwareEncryptMd5 ?
        encryptType == 1 ? aes_256_ecb(key, no padding) -> /tmp/Upgrade.tar
                         : /system/bin/encryption -d /tmp/img -f /tmp/Upgrade.tar -k <key>
        MD5(/tmp/Upgrade.tar) == firmwareMd5 ?
        tar -xvf /tmp/Upgrade.tar -C /tmp/ ; sh /tmp/Upgrade/upgraderun.sh
```

The OTA object is therefore **not** the file published on the SD page: the SD artifact
(`recovery_wcv4.bin`, name enforced by Wyze's own flash article) is a plaintext
`d00dfeed` FIT v17 → `RKAF` container (`boot` FIT + xz squashfs `system`, both signed).
The OTA object is an encrypted TAR that writes whatever `upgraderun.sh` says.

## 3. Key source — model-wide default constant

`product_config_get_ota_app_key` is implemented in `lib/libwyzeUtilsPlatform.so`
(0x1c58, 84 bytes):

```
1c64: lw  $2, -0x7fe8($gp)      ; product_config struct
1c6c: lui $3, 0x4c48
1c70: lw  $5, -0x5a68($2)       ; provisioned field
1c74: addiu $3, $3, 0x4c48      ; 0x4c484c48 == "HLHL" sentinel
1c80: bne $5, $3, 0x1ca0        ; provisioned -> return 1
1c8c: lw  $25, -0x7ed8($gp)     ; strncpy
1c90: addiu $6, $zero, 0x21     ; 33 bytes
1c98: addiu $5, $5, 0x6224      ; .rodata 0x6224
```

`.rodata` 0x6224 = **`oU8XzEpbOD6pVTLwdz9pxRpN9MGPCo1P`** (32 ASCII chars + NUL).
**This is a public compile-time constant, not a credential** — it ships in every unit's
`libwyzeUtilsPlatform.so` and is readable from any firmware dump; an OTA key is not
secret in the owner sense. Siblings in the same constant block:
`34t4fsdgdtt54dg2` (0x6210, userdata-encryption default) and
`wcam_fcdeff5fc99b9b7b` (0x6248, `ota_app_id` default).

Both digests are enforced, in this order: `firmwareEncryptMd5` over the **ciphertext**
before decrypt, `firmwareMd5` over the **plaintext** after. The owner computes both.

Population: the lib reads `/dev/mtdblock5` (the 64 KiB `provisioning` MTD, per
`u-boot` cmdline `mtdparts=…,64K(provisioning)`), magic-checks it, and fills
`mac_addr / product_model / product_type / hardware_version / auth_key`
(log formats `[PRODUCT] [auth_key] [%.100s]`, `[PRODUCT_CONFIG]`). `iCamera` also
carries the path `/configs/.product_config` as the writable overlay. Factory-time
values land in provisioning; on a unit where the field is the `"HLHL"` sentinel the
compiled default is used.

**The empty-key path is real in code but not the stock case.** `product_config_get_ota_app_key`
always fills the 33-byte buffer — `"HLHL"` → `strncpy(default)`, return 0; anything else →
return 1 with the provisioned value in place. `key[0]` is therefore zero **only if the
provisioned `auth_key` is an empty string**, which a stock camera does not have. So on a
stock HL_CAM4 the decrypt always runs and `encrypt_type` only picks the algorithm; pushing
type 0 does *not* by itself skip decryption, it just routes to AES-128-CBC in the external
tool. The practical bypass is to encrypt with the public default key, or to blank the key
first (we own the root shell, so provisioned-blank is reachable, not free).

The skip branch itself is unambiguous: `lbu 0x938($sp)` (key[0]) → `bnez 0x406d54`, which
is `[ASSIS] mv /tmp/img /tmp/Upgrade.tar` + `system("mv …")`, i.e. a plaintext TAR is
accepted verbatim.

`encrypt_type` values other than 1 are not rejected — they fall through to the external
`encryption` tool, whose default cipher is AES-128-CBC (`bin/encryption` usage text:
`aes-128-cbc is the default`; `EVP_aes_128_cbc`/`EVP_aes_256_cbc` imported, `-c` selects).

## 4. Can the owner produce an image?

**Install side — yes.** Payload = any TAR containing `upgraderun.sh`; encrypt it
AES-256-ECB under the public default key, publish both MD5s. The camera fetches it over
plain HTTP, decrypts, and runs the script **as root, before any verification of what the
script then writes** — the installer itself has no signing check.

**Boot side — no, not yet.** Proven on wire from a real HL_CAM4 boot log
(gtxaspec/wz_mini_hacks issue #760):

```
## Loading kernel from FIT Image at 80600000 ...
   Verifying Hash Integrity ... sha256,rsa2048:kernel-dev+ sha256,rsa2048:kernel-dev+ OK
```

Required-key FIT verification with `kernel-dev` on every boot from the `boot` MTD
(`mtdparts=…,4544K(boot)…`, offset 0x30000). The recovery FIT carries exactly
`algo = "sha256,rsa2048"`, `key-name-hint = "kernel-dev"`, 256-byte `value`, at
`/configurations/conf/signature` (timestamp 0x6aace998). The private half is Wyze's;
it is not in the image, and the `kernel-dev` public key is inside the U-Boot partition
(192 KiB at MTD 0), which the update package does not ship. Additionally the ramdisk
holds `/verity_key` and boots `fs_mgr /dev/mtdblock2 /system squashfs 2`, so a modified
squashfs must also re-sign its verity root hash.

Escapes, in order of cost. The cheapest is *not* hardware: rewrite `bootargs` in the
U-Boot env so the signed kernel runs our `init=` (§5) — unproven but key-free. Hardware:
(a) replace the SoC with a non-secure-boot T41 —
secure boot *is* enabled on this model ("secure-boot enabled, verified", #760;
thingino: "physically replace the SoC", "no known workarounds since they validate the
bootloader signature"); (b) CVE-2026-50719 — T41 boot ROM executes an attacker init
table from the SPL header before checking the secure-boot state, hardware-validated on
a secureboot-enabled T41, needs physical write to boot media (SPI).

`wz_flash-helper` does **not** help here: `build.sh` accepts only `t20|t31`, and its
`v2_install/fw_tool.sh` "pack" is `cat` + `mkimage -A MIPS -O linux -T firmware -n jz_fw`
— a legacy uImage with CRCs and no RSA at all. It works on v2/v3 only because those
U-Boots do not verify; the v4 bootloader does.

## 5. Bootargs / U-Boot env — cheapest persistence candidate

If the env can be written from root, `init=` can point at a script on `/configs` and the
signed kernel + signed ramdisk still boot, so verification never has to be beaten. What
is actually established:

- **Bootargs are plain text and not signed.** They come from U-Boot's default env; the
  live log prints `Using default environment` and the resulting cmdline is the compiled
  `CONFIG_BOOTARGS` form (`console=ttyS1,… init=/linuxrc root=/dev/ram0 rootfstype=squashfs
  … mtdparts=sfc0_nor:192K(uboot),4544K(boot),5632K(system),5632K(back),320K(cfg),64K(provisioning)`).
  There is no FIT/signature over `bootargs`; the FIT signature covers kernel/ramdisk/fdt only.
- **The vendor tree has no env-managed boot.** `include/configs/isvp_t31.h` (GPL
  `t31x_uboot.tar.gz`, the closest published T41 ancestor) only defines env geometry under
  `CONFIG_ENV_IS_IN_MMC` / `CONFIG_ENV_IS_IN_SPI_FLASH`; the SPI build's
  `CONFIG_ENV_OFFSET` = `CONFIG_SYS_MONITOR_LEN + CONFIG_UBOOT_OFFSET`, i.e. inside the
  `uboot` MTD, the last 4 KiB sect of a 4 KiB-granule env, single copy (no `_REDUND`).
- **But nothing in the shipped rootfs writes it**: no `fw_setenv`, no `fw_printenv`, no
  `fw_env.config` anywhere in `system.sqfs` or the recovery ramdisk, and no userland
  string mentions `bootargs`/`setenv`. `mtdparts` also lists no env partition.
- **A bad env does not brick**: the failure mode is exactly what the log shows —
  U-Boot falls back to the compiled defaults. With no `_REDUND` copy, a torn write
  degrades to the same fallback.
- **Reachability of our script at `init=` time is the hard part.** `/configs` is jffs2 on
  `/dev/mtdblock4`, mounted only later by the signed ramdisk's `etc/init.d/S18_mountall`
  (`mount -t jffs2 /dev/mtdblock4 /configs`), *after* `fs_mgr /dev/mtdblock2 /system`.
  At `init=` the only mounted fs is `root=/dev/ram0` (squashfs), which already contains an
  empty `/configs` mountpoint — so our script must mount mtdblock4 itself before exec'ing
  anything. jffs2 mounts without `noexec`, so binaries on `/configs` are executable and
  `sh` from the ramdisk always is.

**Status: plausible, unproven.** The env is unverified but this build may be
`CONFIG_ENV_IS_NOWHERE` (which would make `fw_setenv` a no-op). Deciding it needs MTD0:
look for `fw_env`/`saveenv` and `CONFIG_ENV_IS_IN_SPI_FLASH` strings, then write one env
sect from the root shell and re-read it after reboot.

## 6. Blocker

Persistence, not installation. Two concrete unknowns: (1) is the v4 U-Boot built with a
writable env driver (`CONFIG_ENV_IS_IN_SPI_FLASH`) or `CONFIG_ENV_IS_NOWHERE`; (2) what
is the `kernel-dev` public key / does the SD path enforce it. Both fall out of one dump:
`dd if=/dev/mtdblock0` from a unit we already have root on at install time — strings for
`fw_env`/`saveenv`/`CONFIG_ENV…`, and the embedded public key. Then, if the env driver
exists, the write test: `fw_setenv bootargs … init=/configs/x`, reboot, observe.
Confirming boot-gate behaviour independently is the one-byte flip in `recovery_wcv4.bin`
(expect a rejected SD flash).

Everything else — algorithm, key, key provenance, default constant, digest order and
direction, script boundary, root-at-install — is established above.

## Citations

- Flow: `~/.config/fss-lab/wyze_api_flows.json` idx 52 (`enableEncryptOta`, `encryptType:1`, 5 devices, no URL).
- Image: `https://download.wyzecam.com/firmware/v4/recovery_wcv4_4.52.17.26.bin.zip` (9,742,765 B, `last-modified: Mon, 05 Oct 2026`, sha256 `1f76e5ca6bd3691b06049ce44bf619aff706b3d4fac62897cc10d8c352a505ee`) → `recovery_wcv4.bin` 9,798,588 B, `d00dfeed` v17, desc `FIT Image with firmware`, image `recovery` desc `recover image`, payload `RKAF` @0xc8 (hlen 0x3c, `boot` 0x3c/0x45ed72, `system` 0x45edae/0x4f9000).
- Flash filename: Wyze article 360031490871 — "Ensure the unzipped file is named “recovery_wcv4.bin”".
- Boot verify: https://github.com/gtxaspec/wz_mini_hacks/issues/760 (log quote; "secure-boot enabled, verified").
- Secure boot: https://github.com/themactep/thingino-firmware/discussions/470 ("physically replace the SoC"; "no known workarounds since they validate the bootloader signature").
- CVE: https://app.opencve.io/cve/CVE-2026-50719 (init table executed before the secure-boot decision).
- Helper scope: `/tmp/wzfh/build.sh` (`t20|t31`), `/tmp/wzmh/v2_install/fw_tool.sh` (`mkimage … -n jz_fw`).
- Env geometry: `t31x_uboot/include/configs/isvp_t31.h:560-577` (`CONFIG_ENV_IS_IN_SPI_FLASH` branch, `CONFIG_ENV_OFFSET` inside `uboot` MTD, no `_REDUND`); GPL tarball `https://s3-us-west-2.amazonaws.com/download.wyzecam.com/firmware/gpl/t31x_uboot.tar.gz`.
- `/configs` mount: recovery ramdisk `etc/init.d/S18_mountall:18` (`mount -t jffs2 /dev/mtdblock4 /configs`), after `fs_mgr /dev/mtdblock2 /system squashfs 2`.
- No `fw_setenv`/`fw_printenv`/`fw_env.config` in `system.sqfs` or the ramdisk (verified by name search).
