# EV pack — H-002b: what actually goes *in* a T41 image, and does T41 support exist

Target: Wyze Cam v4, `HL_CAM4`, fw **4.52.17.26**, SoC **Ingenic T41 (T41NQ, QFN96)**.
Question narrowed to image content, not the delivery transport (that is pack H-002).
Frame: if an owner-supplied image must be produced at all, what is in it, does the FLOSS firmware exist for
this SoC, and how much RAM/flash is there to put it in.

Local primary artifacts used (all read-only):

| Path | What it is |
|---|---|
| `~/fw-lab/wyze/recovery_wcv4_4.52.17.26.bin.zip` | the official OTA/recovery download for **4.52.17.26** (owner's own download, unzipped locally) |
| `~/fw-lab/wyze/recovery_wcv4.bin` | unzipped image, 9,798,588 B — a **FIT** (`0xd00dfeed`) |
| `~/fw-lab/wyze/part_boot.bin` | carved partition 0 of the above, 4,582,770 B — FIT: dtb + kernel + initramfs |
| `~/fw-lab/wyze/part_system.bin` | carved partition 1, 5,214,208 B — squashfs app partition + dm-verity tail |
| `~/fw-lab/wyze/rootfs/` | `part_system.bin` unpacked (the app/`system` rootfs) |
| `/tmp/rd/root/` | initramfs (the FIT's mislabelled `ramdisk` slot) unpacked |

---

## Bottom line

1. **The image is not "firmware" in any useful sense.** It is a signed FIT wrapping a 2-entry partition map
   (`boot`, `system`) that the stock updater writes blind. There is no kernel for a foreign rootfs to be
   dropped into; `boot` **is** the kernel, the DTB and the initramfs, all in one signed blob.
2. **T41 support exists in exactly one project: thingino.** It is 16 days old, `cameras-exp` only, ships in no
   release, covers 2 of the 3 sensor variants, and has no `wz_flash-helper` profile. **OpenIPC has zero T41
   support** (0 hits vs 110 for `t31` in `OpenIPC/firmware@master`).
3. **The image is 9,796,978 B into a 16 MB flash** — 58 % of the chip before any of your own bytes. A custom
   image that keeps the vendor U-Boot has ~6.4 MB of headroom total for *both* a rootfs and the app.
4. **RAM is 128 MB and thingino already spends 64 MB of it on the VPU** before Linux starts
   (`wyze_cam4_t41nq*_defconfig:BR2_THINGINO_RMEM_MB=64`). No zram driver is enabled. Tailscale is possible
   only in `--tun=userspace-networking` mode, is the first consumer of a ~64 MB budget, and its ~30 MB Go
   binary probably does not fit the 16 MB flash next to the camera stack at all.
5. **`wz_flash-helper` does not do T41.** It has overlays for `t20` and `t31` only; its own supported-camera
   table lists T20/T31 and nothing newer. The T41 install path is a different one, and it needs the
   `secureboop` SPL patch because the v4's SoC **is** eFuse-locked.
6. The stock U-Boot's layout is `uboot/boot/system/back/cfg/provisioning`. Thingino's layout is
   `uboot/env/kernel/rootfs/data`. **You cannot keep the vendor layout and use a thingino image**, and you
   cannot keep the stock U-Boot and use a self-built image without its RSA key.

---

## 1. Support matrix, per project, with evidence

| Project | T41 build target | Sensor coverage | Installable on v4 | Citation |
|---|---|---|---|---|
| **thingino** | yes, `configs/cameras-exp/wyze_cam4_t41nq_{gc4653,os04d10}_atbm6062s` | 2 of 3 (GC4653, OS04D10); **no `sc401ai` variant** although the vendor image ships `sensor_sc401ai_t41.ko` | only by self-build; not in the `firmware-2026-10-04` release | tree listing of `themactep/thingino-firmware@master`; `fleet-index.json` of that release contains 0 occurrences of `cam4` or `t41` |
| **OpenIPC** | **none** | — | no | `OpenIPC/firmware@master` recursive tree: 4,729 paths, `grep -ci t41` = **0**; `br-ext-chip-ingenic/board/` contains only `t20 t21 t23 t31 t40` (`ls` of that dir → `['board','configs']`; board children enumerated) |
| **wz_flash-helper** | **none** | — | no | `gtxaspec/wz_flash-helper@main`: `wz_flash-helper_overlay/` = `t20/`, `t31/` only; `docs/README.md` supported-cameras table ends at Ingenic T31 with "ATOM Cam 2 / Untested" |
| **wz_mini_hacks** | **none** | — | no | `README.md:5` "**Ingenic based T20/T31 based devices only!**" |

thingino's own position, verbatim, in order:

> **gtxaspec, 2025-01-29** (discussion #470): "In regards to the Wyze V4, it will be supported eventually, but
> with some caveats. You will need to physically replace the SoC chip with a spare one that does not have
> secureboot enabled. The Soc has a QFN96 footprint." … "The sensors can vary, the V4 has a lottery of 3
> different sensors I believe: os04d10 gc4653 sc401ai"

> **gtxaspec, 2025-07-03** (discussion #685): "initial T41 support is already in the repo. Wyze V4 can be
> supported, with a CPU swap. The CPU has secureboot enabled, so you'll need a hot air rework station to swap
> the chip with one that is not locked."

> **gtxaspec, 2026-10-06** (discussion #470): "V4 is already supported in the master branch."

> **issue #554** (closed 2025-03-13, virmaior): "supported as in easily done- no. supported as in replace the
> chip - yes"

So: the *chip-swap* claim is the 2025 position and it is now superseded — `BR2_PACKAGE_THINGINO_SECUREBOOP=y`
is in both cam4 defconfigs, and `package/thingino-secureboop/Config.in` states the mechanism:

> "T23/T32/T40/T41/A1: init-table write into the SPL header. T31: signature collision on the partial RSA check."

That is CVE-2026-50719 applied to the SPL, so **no rework station is required** for the bootloader stage.
`[INFERENCE]` — nobody has published a v4 boot log with a secureboopped U-Boot; the config being present is
not a run.

History of the cam4 profiles (all of it, it is that new): `2026-10-06` add; `2026-10-06` "30 MB rmem, default
nmem"; `2026-10-13` "hold mmc_power 61+59 low for SD in U-Boot"; `2026-10-16` "adjust rmem" (30 → 64);
`2026-10-17` "fix clocks, fix nmem"; `2026-10-18` "add gpio.ircut". Six commits in twelve days = still
converging.

---

## 2. What is physically in the stock image

`recovery_wcv4.bin` decoded (`dtc -I dtb -O dts`):

```
/ { description = "FIT Image with firmware";
    images/firmware { description = "recover image"; data = [52 4b 41 46 …];  # "RKAF"
                      hash { algo = "sha256"; value = <…>; } };
    configurations/conf { firmware = "firmware";
        signature { algo = "sha256,rsa2048"; key-name-hint = "kernel-dev";
                    signer-name = "mkimage"; sign-images = "firmware"; … } }; }
```

The FIT's single payload is a `RKAF` container, not a filesystem:

```
offset  bytes            meaning
0x00    52 4b 41 46      "RKAF"
0x04    3c 00 00 00      header length = 0x3c
0x08    02 00 00 00      nparts = 2
0x0c    "boot"+pad16     name
0x1c    3c 00 00 00      data offset  = 0x3c
0x20    72 ed 45 00      data size    = 4,582,770   (= part_boot.bin, exact)
0x24    "system"+pad16   name
0x34    ae ed 45 00      data offset  = 0x45edae     (= 0x3c + 0x45ed72)
0x38    00 90 4f 00      data size    = 5,214,208   (= part_system.bin, exact)
```

**There is no `uboot` entry and no `cfg` entry.** The update replaces the kernel and the app; it never touches
the bootloader. 9,796,978 B of a 16 MB XT25F128F (`discussion #470`: "16MB XT25F128F-W storage").

### `boot` (4,582,770 B) — a second FIT, also rsa2048

`dtc` on `part_boot.bin`:

| node | type | load | entry | compression | size |
|---|---|---|---|---|---|
| `fdt` | `flat_dt`, arch mips | `0x83000000` | – | none | 16,617 B |
| `kernel` | `kernel`, os linux | `0x80f00000` | `0x80f00000` | **none** (raw MIPS) | 1,627,152 B |
| `ramdisk` | `ramdisk` | `0x0` | – | none | **2,936,832 B — actually squashfs** |

`signature { algo="sha256,rsa2048"; key-name-hint="kernel-dev"; sign-images="fdt","kernel","ramdisk" }`

The "ramdisk" slot is `hsqs` squashfs 4.0 / xz / 501 inodes: it is the **initramfs root**, mounted by the
kernel, and it is where the partition map and the verity key live. Not a ramdisk in the initrd sense.

### `system` (5,214,208 B) — squashfs app partition, dm-verity

- `hsqs`, xz, **84 inodes**, 5,130,254 B of filesystem, then **83,954 B of verity metadata + signature**.
- Mounted read-only through `fs_mgr` with verity enabled — `etc/init.d/S18_mountall:14`:
  `fs_mgr /dev/mtdblock2 /system squashfs 2` (third arg `2` = verity; `fs_mgr` usage string is
  `./fs_mgr /dev/mtdblockN /mount_path [ext4 or squashfs] [0 or 1 or 2]`).
- Trust anchor is `/verity_key` (**524 B**, RSA) inside the *boot* partition's initramfs. Swapping the trust
  anchor therefore means rewriting `boot`, which means re-signing `boot`.
- `fs_mgr` failure is non-fatal at the init level: `S18_mountall:15-17` does `if [ $? -ne 0 ]; then exit 0; fi`,
  so a bad `system` = no app, box still on the network. `[INFERENCE]` on whether the stock U-Boot then
  falls back to the `back` slot.

Full partition map, from the initramfs itself (`/tmp/rd/root/etc/init.d/S18_mountall:6-11`):

```
mtdblock0 uboot      mtdblock1 boot       mtdblock2 system
mtdblock3 back       mtdblock4 cfg(jffs2)  mtdblock5 provisioning
```

`back` is a full second copy of the bootable set; `cfg` is jffs2 and holds `/configs/upGradeFlag`, which
`app_init.sh:39-41` deletes at app start — i.e. a flag that survives only if the app *fails* to start.
That is a rollback counter for something. `[INFERENCE]`: that something is U-Boot; confirming it needs
`fw_printenv` output, which needs root or UART.

### Userspace content (the parts that matter for a rewrite)

`/bin`: `iCamera` (5,446,632 B — **705 `IMP_*` symbols statically linked**, so no `libimp.so` exists to copy),
`assis` (the OTA agent), `iotclient`, `sinker`, `dmon`, `logcat`, `impdbg`.
`/lib`: `libwyzefdk.so`, `libwyzeUtils*.so`, `liblocalsdk_hwcrypto.so` (→ `/dev/aes`), `libcurl`, `libmbedcrypto`,
OpenSSL 1.1, `libfdk-aac`.
`/local/cacert.pem` = stock Mozilla bundle, dated 2020 — TLS validation is real, from a stale root set.

Kernel modules are **not** in `system`; they are in the initramfs `/lib/modules` (13 `.ko`), because `system`
is verity-sealed and the driver set is boot-critical. Note `avpu.ko` is loaded with `avpu_clk=552000000`
(`S19insmod_driver:16`) while thingino runs the same IP at 600 MHz — that is one of the things the
`2026-10-17` commit changed.

---

## 3. The minimum viable self-built image

Two designs. Both are 16 MB full-flash images written from 0x0, nothing partial.

### Design A — keep the stock U-Boot (target: `boot` + `system` only)

| Partition | Content | Rule |
|---|---|---|
| `boot` | FIT: your dtb (`load 0x83000000`) + raw MIPS kernel (`entry 0x80f00000`) + squashfs initramfs | **must carry a valid `sha256,rsa2048` signature from a key the stock U-Boot trusts**, and the `conf` node must list `fdt`/`kernel`/`ramdisk` |
| `system` | your rootfs squashfs **+ verity metadata + signature** | must verify against the `/verity_key` you put in the initramfs, or `fs_mgr` refuses and you get an app-less camera |
| `uboot`, `back`, `cfg`, `provisioning` | untouched | — |

Consequences:
- You need `mkimage -F -k <keydir>` and a verity signer (`veritysetup` from cryptsetup, or AOSP `verity_signer`).
- You need Wyze's public key **out of** the U-Boot control DTB to know whether your key can be added — or you
  must sign with a key U-Boot already has, which means Wyze's private key, which we do not have.
  **Blocker unless U-Boot verification is off.**
- You inherit the 4.4.94 vendor kernel if you want the vendor IMP ABI, or you bring your own kernel and lose
  `iCamera` (and with it the Wyze cloud path).
- `[INFERENCE]`, and it is the single cheapest thing to test: flip one byte in the kernel payload of
  `recovery_wcv4.bin`, re-name it `recovery_wcv4.bin`, hold setup 3–6 s at power-on. Flash = no verification.
  Purple→solid blue = it wrote a corrupt kernel and you have your answer the hard way (recovery still works,
  so no brick). `[INFERENCE]` that the flash path also checks; the outer FIT hash is `sha256` and only
  meaningful if something validates it.

### Design B — replace U-Boot (target: thingino's own layout)

Thingino's layout (`docs/firmware/firmware-image-structure.md`), written from offset 0:

| Partition | Size | Content |
|---|---|---|
| `uboot` | 320 KB fixed (the same doc's subheading says 256 KB; `CONFIG_ENV_OFFSET=0x50000` settles it at 320) | SPL + U-Boot, LZMA payload |
| `env` | 64 KB fixed (`CONFIG_ENV_OFFSET=0x50000`, `configs/uboot/layout/sfcnor.config`) | env blob from `uenv.txt`, and **your Wi-Fi SSID/PSK**, because the box has no Ethernet |
| `kernel` | dynamic, 64 KB-aligned | uImage |
| `rootfs` | dynamic | squashfs |
| `data` | **all remaining flash** | jffs2, overlay upperdir at `root/` |

This is the design that actually works, and it is also why the vendor layout is irrelevant after the first
write: the partition table is *U-Boot's* `mtdparts`, and it is rewritten with the flash
(`package/thingino-sysupgrade/files/flash-ota`, `set_mtdparts` → `fw_setenv mtdparts`).

`BR2_PACKAGE_THINGINO_SECUREBOOP=y` is what lets that 320 KB bootloader start on a locked SoC.

Supply chain for Design B, resolved: `soc/ingenic/t41.mk` names `isvp_t41nq_sfcnor`, and that target is real —
`gtxaspec/u-boot`, branch **`ingenic-t-series`**, ships `configs/isvp_t41nq_sfcnor_defconfig`,
`board/ingenic/isvp-t41/`, and `arch/mips/dts/t41nq-isvp*.dts*`. It is **not** in the
`gtxaspec/u-boot-ingenic` releases the thingino wiki points at (those are tagged `uboot-xb1-*` and carry no
`isvp_t4*` asset at all) and not in upstream u-boot. The defconfig fixes the region layout unambiguously:
`CONFIG_SPL_MAX_SIZE=0x13000`, `CONFIG_SYS_SPI_U_BOOT_OFFS=0x14000`, `CONFIG_ENV_OFFSET=0x50000`,
`CONFIG_ENV_SIZE=0x10000` — i.e. 0x00000-0x50000 is bootloader, env is 0x50000-0x60000, and kernel follows.
It also carries `CONFIG_BUTTON_CMD=y`/`CONFIG_BUTTON_GPIO=y` (the setup-button command hook),
`CONFIG_XBURST_MAC_FROM_EFUSE=y`, `CONFIG_ETH_DESIGNWARE_INGENIC=y` with `CONFIG_PHY_MOTORCOMM`,
`CONFIG_CMD_DHCP`, `CONFIG_CMD_NFS`, `CONFIG_USB_HOST_ETHER` + `CONFIG_USB_ETHER_ASIX[88179]` — so the
bootloader has a net stack and a USB-Ethernet path even though the box has no RJ45. `CONFIG_CMD_TFTP*` is not
written out (it defaults on with `NET`); confirm by `strings` on a built `u-boot-lzma.img` before relying on
it. Nothing in the defconfig sets `CONFIG_FIT_SIGNATURE`, so a self-built kernel must be a **uImage**, not a
signed FIT.

---

## 4. Budget

| Resource | Value | Source |
|---|---|---|
| Flash | 16 MB (XT25F128F) | `discussion #470`; thingino `FLASH_SIZE_MB=16` |
| Stock image | 9,796,978 B = 58 % | RKAF sizes above |
| Stock model blobs | none (IMP is linked into `iCamera`) | 705 `IMP_*` symbols |
| RAM | **128 MB** (`t41nq` → `SOC_RAM_MB := 128`, `soc/ingenic/t41.mk`) | thingino |
| Reserved for VPU | **64 MB** (`BR2_THINGINO_RMEM_MB=64`) | cam4 defconfig |
| For Linux | ~64 MB `[INFERENCE]` (arithmetic; nmem=0 makes nothing else reserved) | — |
| zram | **driver off** — `CONFIG_ZRAM` absent from `t41.generic.config` while `CONFIG_ZSMALLOC=y` is present | `board/ingenic/xburst2/kernel/4.4.94/t41.generic.config` |
| Kernel | 4.4.94 — the only T41 kernel thingino carries | `board/ingenic/xburst2/kernel/4.4.94/` |

Nothing else fits in `data` after rootfs: at 16 MB with a ~2 MB kernel and a ~10 MB rootfs, `data` is low
single-digit MB. That is the `/overlay` and the config store and the swap candidate all at once.

### Sensor lottery

Vendor ships **three** modules (`sensor_gc4653_t41.ko`, `sensor_os04d10_t41.ko`, `sensor_sc401ai_t41.ko`,
17–18 KB each) and **two** IQ blobs (`/etc/sensor/gc4653-t41.bin`, `os04d10-t41.bin`, 254,032 B each).
`iCamera` carries all three names as strings and picks one at runtime.
Thingino has configs for two. A third-variant unit (`sc401ai`) has **no ready image**.

IQ blobs do not need to come out of stock flash: `thingino/ingenic-sdk` carries
`sensor-iq/t41/{gc4653,os04d10,sc401ai}.bin` and `4.4.94/sensor-src/t41/{gc4653,os04d10,sc401ai}.c`,
consumed via `BR2_PACKAGE_THINGINO_ISP_PROPRIETARY` → `BR2_PACKAGE_INGENIC_SDK`. The complete vendor-blob
list a T41 image needs is exactly:

- `tx-isp-t41.ko` (the ISP; 729,116 B in the vendor build) — from the Ingenic SDK, or the vendor one
- `sensor_<model>_t41.ko` for **your** sensor — SDK
- `sensor-iq/t41/<model>.bin` — SDK
- `atbm606x_wifi6_sdio.ko` (1,481,432 B) — ATBM6062S is SDIO, no mainline driver; thingino has its own
  `BR2_PACKAGE_WIFI_ATBM6062S`
- `avpu.ko` (VPU encoder), `audio.ko`, `soc-nna.ko` if you use them

---

## 5. Tailscale

**Mode: `tailscaled --tun=userspace-networking` — the only mode that cannot fail.**

`t41.generic.config:948` is `# CONFIG_TUN is not set`. Caveat that matters: buildroot's `tailscale` package
forces `CONFIG_TUN` back on through `TAILSCALE_LINUX_CONFIG_FIXUPS` (`package/tailscale/tailscale.mk`, a
`KCONFIG_ENABLE_OPT,CONFIG_TUN` line), and `package/thingino-tailscale/Config.in` merely `select`s
`BR2_PACKAGE_TAILSCALE`. So a *tailscale build* gets a tun-capable kernel and `--tun=tailscale0` becomes
available; the *base* v4 config does not have it. Until one build proves otherwise, assume userspace mode.

Userspace mode means: no route for the kernel, `tailscaled` terminates TCP/UDP in-process and forwards into
localhost. That is fine for reaching the camera's own RTSP/web UI. **It is not fine for routing anything
else through the camera** — no `--advertise-routes`, no subnet router.

RAM: `tailscaled` is a Go binary (`GOARCH=mipsle CGO_ENABLED=0`,
`package/thingino-tailscale/thingino-tailscale.mk`); expect ~30–45 MB RSS `[INFERENCE]`, i.e. **half to
two-thirds of the ~64 MB Linux has**. It also pulls `BR2_PACKAGE_TAILSCALE` with `ts_omit_iptables`, so no
netfilter work.

Swap: **SD is out by policy, so zram or a swapfile on `data`.**
- zram: `CONFIG_ZSMALLOC=y` is already there; `CONFIG_ZRAM` is not — one line (`CONFIG_ZRAM=m`) plus a
  rebuild. Costs CPU on a 2-core xburst2 and buys maybe 2:1 on compressible pages. Does not add capacity.
- swapfile on the jffs2 `data` partition: simplest, no rebuild, but jffs2 write amplification on a NOR chip
  with a 100k-cycle budget and a live overlay on the same region.
- Order of preference for a first attempt: zram 32 MB, then `tailscaled` with `--tun=userspace-networking`,
  then measure. If RSS is over ~40 MB the image needs `--no-logs-no-support` and a 24 MB rmem retune, or
  Tailscale is simply too big for this box alongside prudynt.

**Flash, not just RAM, is the binding constraint.** `tailscaled` is a Go binary of roughly the same order as
the whole stock app partition: a static mipsle `tailscaled` + `tailscale` CLI is ~30 MB stripped `[INFERENCE]`,
which xz's to maybe 6–8 MB in squashfs. The image has ~14.4 MB after U-Boot/env and a ~2 MB kernel, and the
camera rootfs is already ~7–10 MB. **A naive `BR2_PACKAGE_THINGINO_TAILSCALE=y` most likely does not fit.**
`package/thingino-tailscale/Config.in` only gates on `FLASH_SIZE_MB > 8`, which is a permissiveness check, not
a fit check. Mitigations, in order: extra `TAILSCALE_TAGS` omits (`ts_omit_iptables` is already set; the
`ts_omit_*` family strips aws/bird/tap/kube etc.), `-s -w` ldflags, drop the web UI packages, and only then
consider whether 16 MB NOR is the right medium at all.

---

## 6. One-time physical action accounting

| Step | Physical? |
|---|---|
| identify the sensor (must: 3-way lottery) | **open the case and read the die** `[INFERENCE]` that there is no software tell of a *3rd* variant before first boot |
| write the thingino image | **no** — SD card is a *medium*, not a device action; the v4 boots `recovery_wcv4.bin` from FAT32 with setup held 3–6 s (Wyze KB 360031490871: "press and hold the setup button … keep holding … 3-6 seconds") |
| get back if it fails | **`recovery_wcv4.bin` on the same SD restores stock — while the stock U-Boot is still there**, because the stock update never writes the `uboot` partition. Once thingino's U-Boot is on the chip, the recovery filename becomes thingino's `autoupdate-full.bin` and reverting to stock needs the stock U-Boot written back first |
| chip swap | **not needed** post-CVE-2026-50719 `[INFERENCE]` |

So the flash path is SD-shaped on both ends. The LAN question in pack H-002 has to solve *getting the 16 MB
in without the card*; H-002b only says what the 16 MB should contain.

---

## 7. Blockers, ranked

1. **stock U-Boot signature trust** — cannot sign a `boot` FIT with Wyze's key. Decides whether Design A is
   possible at all. Test: one flipped byte (§3A).
2. **nothing published** — no v4 boot log, no release asset, six-commit-old config, 2-of-3 sensors.
3. **`wz_flash-helper` has no T41 overlay** — partition names differ (`boot/system/back/cfg/provisioning` vs
   `boot/kernel/rootfs/data`), so stock backup/restore profiles cannot be reused verbatim; the switch-firmware flow
   needs a `t41` overlay written from the map in §2 plus the SD power sequencing from the 2026-10-13 commit.
4. **the T41 U-Boot is on an undocumented branch** (`gtxaspec/u-boot@ingenic-t-series`, not in the wiki's
   `u-boot-ingenic` releases, not upstream) — buildable, but not discoverable from the instructions.
5. **64 MB rmem of 128 MB** — anything added (Tailscale, an RTSP re-streamer, a second app) is eating a
   quarter-megabyte-of-RAM-per-kilobyte-of-feature budget.
6. **`system` is verity-sealed and its key lives in `boot`** — a partial image that updates one and not the
   other bricks the app while the box happily stays on Wi-Fi and looks fine.
7. **ATBM6062S** — SDIO, no mainline driver, vendor blob only. No alternative firmware can replace it.

## 8. What would falsify this

- A `thingino-wyze_cam4_*.bin` asset appearing in a `firmware-*` release, or a `t41` overlay in
  `wz_flash-helper` → the "nothing published" blocker is gone.
- A v4 boot log showing secureboop working → the chip-swap folklore is fully dead (it already should be).
- A byte-flipped `recovery_wcv4.bin` being *rejected* by the bootloader → Design A needs a key we do not have,
  and every custom image must carry a replacement U-Boot.
- `CONFIG_TUN=y` appearing in `wyze_cam4`'s defconfig → the Tailscale mode question changes, not its cost.

---

## Citations

Repo (fetched via GitHub raw/API, `themactep/thingino-firmware@master` unless stated):

- `soc/ingenic/t41.mk` — `t41nq` → `SOC_RAM_MB := 128`, `SOC_UBOOT := isvp_t41nq_sfcnor`
- `configs/cameras-exp/wyze_cam4_t41nq_gc4653_atbm6062s/…_defconfig` — `BR2_INGENIC_SOC_MODEL="t41nq"`,
  `BR2_THINGINO_RMEM_MB=64`, `BR2_PACKAGE_THINGINO_SECUREBOOP=y`, `BR2_PACKAGE_WIFI_ATBM6062S=y`,
  `FLASH_SIZE_MB=16`, `BR2_THINGINO_SDCARD=y`
- `configs/cameras-exp/wyze_cam4_t41nq_os04d10_atbm6062s/…_defconfig` — same, `os04d10`
- `configs/uboot/layout/sfcnor.config` — `CONFIG_ENV_OFFSET=0x50000`, `CONFIG_ENV_SIZE=0x10000`
- `docs/firmware/firmware-image-structure.md` — partition table, sizes, `data` = jffs2 overlay
- `board/ingenic/xburst2/kernel/4.4.94/t41.generic.config:948` — `# CONFIG_TUN is not set`; `CONFIG_ZSMALLOC=y`
- `package/thingino-isp/Config.in` — `BR2_PACKAGE_THINGINO_ISP_PROPRIETARY` → `INGENIC_SDK`, `INGENIC_LIB_LIBIMP`
- `package/ingenic-sdk/ingenic-sdk.mk` — `INGENIC_SDK_SITE = https://github.com/thingino/ingenic-sdk`,
  IQ from `sensor-iq/<soc>/<version>/`
- `package/thingino-secureboop/Config.in` — "T23/T32/T40/T41/A1: init-table write into the SPL header"
- `package/thingino-tailscale/{Config.in,thingino-tailscale.mk}` — `GOARCH=mipsle CGO_ENABLED=0`,
  `depends on FLASH_SIZE_MB > 8`
- `package/thingino-sysupgrade/files/flash-ota` — `set_mtdparts` → `fw_setenv mtdparts`
- `gtxaspec/u-boot@ingenic-t-series`: `configs/isvp_t41nq_sfcnor_defconfig`, `board/ingenic/isvp-t41/Kconfig`,
  `arch/mips/dts/t41nq-isvp*.dts*`, `include/configs/isvp-t41.h`
- `gtxaspec/wz_flash-helper@main`: `docs/README.md` (T20/T31 only), `docs/Limitation.md`,
  `wz_flash-helper_overlay/{t20,t31}`
- `gtxaspec/wz_mini_hacks@master/README.md:5` — "T20/T31 based devices only"
- `OpenIPC/firmware@master` — 0 `t41` paths of 4,729; `br-ext-chip-ingenic/board/` = t20/t21/t23/t31/t40

External:

- <https://github.com/themactep/thingino-firmware/discussions/470> — 16 MB XT25F128F, sensor lottery, QFN96,
  "V4 is already supported in the master branch"
- <https://github.com/themactep/thingino-firmware/discussions/685> — "initial T41 support", chip-swap position
- <https://github.com/themactep/thingino-firmware/issues/554> — "supported as in easily done- no"
- <https://support.wyze.com/hc/en-us/articles/360031490871> — v4 flash: file must be named
  `recovery_wcv4.bin`, hold setup 3–6 s, solid purple, "If the card remains inserted, the camera will attempt
  to firmware flash every time it reboots"
- <https://github.com/buildroot/buildroot/blob/master/package/tailscale/tailscale.mk> —
  `KCONFIG_ENABLE_OPT,CONFIG_TUN` in `TAILSCALE_LINUX_CONFIG_FIXUPS`

Local (file:line):

- `/tmp/rd/root/etc/init.d/S18_mountall:6-11` — partition symlinks; `:14` — `fs_mgr … squashfs 2`;
  `:15-17` — verity failure `exit 0`; `:18` — jffs2 `cfg`
- `/tmp/rd/root/etc/init.d/S19insmod_driver:16` — `avpu_clk=552000000`; `:17` — `tx-isp-t41.ko`;
  `:56` — `atbm606x_wifi6_sdio.ko`
- `~/fw-lab/wyze/rootfs/init/app_init.sh:39-41` — `upGradeFlag` deleted at app start
- `~/fw-lab/wyze/rootfs/etc/{cloud_profile.ini,sensor/}` — domains; `gc4653-t41.bin`, `os04d10-t41.bin`
- `~/fw-lab/wyze/recovery_wcv4.bin` @0xc8 `RKAF`, `part_boot.bin` FIT props, `part_system.bin` verity tail
