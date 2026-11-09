# nt98567 (Novatek NS02301) — OpenIPC board config

The Tapo C660 is a Novatek **NS02301**, and OpenIPC has the `nt9856x` family but no `nt98567`
board. These two files are that board config: `nt98566_lite_defconfig` with the model switched
and the **32 MiB** NOR size (the C660's, per `docs/exploit/c660-flash-plan.md`), plus the kernel
config. Nothing is built yet.

Drop both into a shallow clone and build:

```sh
git clone --depth 1 https://github.com/OpenIPC/firmware /tmp/oi
cp nt98567_lite_defconfig /tmp/oi/br-ext-chip-novatek/configs/
cp nt98567.generic.config  /tmp/oi/br-ext-chip-novatek/board/nt9856x/
cd /tmp/oi && git submodule update --init --depth 1
make BOARD=nt98567_lite
```

Expected gaps, in the order they will bite:

1. **Kernel config** — `nt98566.generic.config` targets nt98566. The C660's own defconfig exists
   in the vendor tree (`Novatek-OSS/kernel@oss/linux-5.10.168`,
   `arch/arm/configs/ns02301_ipc_a32_evb_defconfig_nor_release`); diff against it before trusting
   the copy.
2. **DTS** — `sc835hai_cfg_567.dtsi` (sensor + Wi-Fi `18211_nvtfmac`) lives in the GPL drop at
   `~/fss-exploit/CameraKIT.tar.bz2`; it has to be wired into the board dir.
3. **Sensor** — the C660 uses `sen_sc835hai`; the kernel config must carry that driver, not
   nt98566's.
4. **Flash map** — 32 MiB NOR with the C660's own partition split; the stock `bootargs`/
   `mtdparts` are in `c660_fw.bin.dec`.

This is a from-source build, so it does not run on the same turn as the exploit; the carrier
(ROP → telnetd) is armed and independent of it.
