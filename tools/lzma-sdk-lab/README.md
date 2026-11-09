# Vendor LZMA SDK lab harness

`LzmaDec.c` in the C460 GPL drop is **LZMA SDK 9.18 beta** (see its `history.txt`), a different
generation from liblzma/xz. The C460 ramdisk blocks fail in liblzma after four bytes, so this
harness decodes them with the vendor's own decoder instead of guessing about xz compatibility.

```sh
# unzip + tar -xJf the GPL drop, then:
printf '#define CONFIG_LZMA 1\n' > config.h
printf 'void *memcpy(void*,const void*,unsigned long);\nvoid *memset(void*,int,unsigned long);\n' > common.h
mkdir -p linux && printf '#include <string.h>\n' > linux/string.h
printf '#define WATCHDOG_RESET() do{}while(0)\n' > watchdog.h
cc -O2 -I. -o lzd lzd.c <drop>/sdk/soc/ssc30x/boot/u-boot/lib/lzma/LzmaDec.c
./lzd <image> <stream-offset> <dict> <lc> <lp> <pb>
```

Result so far (2026-11-09): every framing tried — stream at `0x420284+0/1/5/6`, dict from the
block's own bytes (LE and BE) and 1 MiB…1.1 GB, props `(3,0,2)`, `(0,2,2)`, `(2,0,0)` — returns
`SZ_ERROR_DATA` with zero output. liblzma decodes the *same* offsets for four bytes and then
reports corrupt, and those four bytes are `27 05 xx`, so magic and framing are right and the
divergence is inside the coder. Both decoders agreeing rules out "liblzma is just stricter".
