# sensor_sc5336p_mipi — SigmaStar infinity6e (SSC30KQ) driver for the SmartSens SC5336P

The C460's sensor is not supported by OpenIPC: upstream has no sc5336 driver, the vendor module
is built for 5.10.117 while the image kernel is 4.9.84, and the vendor GPL drop ships only
`sdk/soc/ssc30x/boot`. This directory holds a driver written for the image kernel so the camera
is not blind after a flash.

## Provenance

- Skeleton: `sigmastar/infinity6e/sensor_gc4653_mipi.c` from https://github.com/OpenIPC/sensors
  (MIT) — renamed, `SENSOR_I2C_ADDR` 0x60 (0x30 << 1), mode moved to 2880x1620, gain model
  reduced to a direct AGAIN pair.
- Register tables, mode, exposure/gain/VTS/mirror semantics: `t41/sc5336p.c` from
  thingino/ingenic-sdk (same sensor, Ingenic host), translated to the SigmaStar API; register
  addresses and values are copied, not invented. The init table is complete (192 entries,
  including the software reset and the 20 ms settle).

## Registers used

    exposure  0x3e00[3:0] << 12 | 0x3e01 << 4 | 0x3e02[7:4]
    again     0x3e07 (low), 0x3e09 (high)     VTS 0x320e/0x320f
    mirror    0x3221                          ID  0x3107 = 0xce, 0x3108 = 0x50

## Build

    make -C <this dir> SENSOR_VERSION=infinity6e OPENIPC_SNS_MODEL=sc5336p KSRC=<kernel 4.9.84 src>

Requires the include/ set from `OpenIPC/sensors` (sigmastar/infinity6e/include). The module must
show `vermagic` containing `4.9.84`.

## Build evidence (2026-11-11)

Built against the image's own kernel config (`br-ext-chip-sigmastar/board/infinity6e/
infinity6e-ssc012b.config`, `make modules_prepare`) on 212.90.121.76:

    make KSRC=<linux-custom> SENSOR_VERSION=infinity6e OPENIPC_SNS_MODEL=sc5336p \
         ARCH=arm CROSS_COMPILE=arm-linux-gnueabihf- KCFLAGS="-march=armv7-a -mthumb" modules

- compile: 0 errors, `MODPOST 2 modules`, `LD [M] sensor_sc5336p_mipi.ko`
- `modinfo` → `vermagic: 4.9.84 SMP preempt mod_unload ARMv7 thumb2 p2v8` — byte-identical to the
  vendor module's vermagic apart from the version it was compiled for
- 18 undefined symbols, all framework API (`CamOs*`, `Drv*Sensor*`) plus core `printk`/`msleep`
  — the same set a sibling sensor module carries
- md5 `ff36b365e26afce674f6726e7fe940ba`, 73,688 B

`KCFLAGS="-march=armv7-a -mthumb"` is required: host gcc 15 against 4.9.84 otherwise emits
Thumb-1 that the old kernel's inline asm rejects.

Not yet verified: loading on a real camera (needs the sensor present and the DS alive).
