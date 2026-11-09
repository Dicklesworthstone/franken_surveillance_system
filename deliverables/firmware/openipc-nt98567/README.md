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

## Build friction seen on this host (2026-11-09)

- `sources.buildroot.net` (BR2_BACKUP_SITE) **404s** `libevent-openipc-<sha>-br1.tar.gz` and
  buildroot treats that as fatal instead of falling through. Set `BR2_BACKUP_SITE=""` in
  `general/openipc.fragment` for the build.
- buildroot's git downloader calls GNU `date -d @epoch`; BSD `date` has no `-d` and the download
  bails with "corrupted git cache" / `popd: directory stack empty`. A `date` shim ahead in PATH
  is enough:

  ```sh
  mkdir -p /tmp/gbin && printf '#!/bin/bash\ncase "$1" in -d) shift; s=$1; shift; \
    case "$s" in @*) exec /bin/date -r "${s#@}" "$@";; *) exec /bin/date "$@";; esac;; esac; \
    exec /bin/date "$@"\n' > /tmp/gbin/date && chmod +x /tmp/gbin/date
  PATH=/tmp/gbin:$PATH make BOARD=nt98567_lite
  ```
- `/Volumes/USB_NVME` was not mounted, so `TARGET` stayed at the default `<tree>/output`
  (`/tmp/oi/output`, ~2.5 GB and growing). Mount the NVMe or set `TARGET` deliberately.

### The path that works here: build in a Linux container

macOS host-tool portability is a long fight (`host-makedevs` needs `fgetgrent`, which macOS
libc lacks). Build in a container instead; the tree and output are bind-mounted:

```sh
open -a Docker   # the daemon was not running
docker run --rm -v /tmp/oi:/work -w /work debian:12 bash -lc \
  'apt-get update -qq && apt-get install -y -qq build-essential git wget curl cpio unzip \
   rsync bc libncurses-dev python3 file bzip2 xz-utils zstd perl && \
   make BOARD=nt98567_lite TARGET=/work/out-linux'
```

Two downloads need pre-seeding because their upstreams are broken from here:

- `libevent-openipc` — `sources.buildroot.net` 404s it (see above);
- `uboot-tools-2021.07` — `ftp.denx.de` accepts the connection and then stalls. Fetched from
  GitHub's tag archive instead (`u-boot/u-boot@v2021.07`) and the local `uboot-tools.hash`
  updated to those bytes; GNU tar detects the gzip regardless of the `.tar.bz2` name.

### Two more host facts, both fatal until handled

- **The prebuilt toolchain is x86_64**, so the container must be `--platform linux/amd64` (on
  Apple Silicon that is emulation). An arm64 container builds host tools fine and then dies on
  `Cannot execute cross-compiler … Trace/breakpoint trap`.
- **The make jobserver does not survive that emulation**: recursive kernel make aborts with
  `write jobserver: Bad file descriptor`. Building with `BR2_JLEVEL=1` (no jobserver) is the
  only way through it; it is slow, which is the real cost of building this port on this host.
- Bind mounts into Docker Desktop also break `chmod` from inside the container (`Permission
  denied` on extracted files) — build into a **named volume**, not a host directory, and copy
  sources in once.
