# EV pack — H-013: Wyze Cam v4 `iCamera` K-command handler audit (why the v3 `audioEncoderList` bug is dead)

Target: Wyze Cam v4 `HL_CAM4`, firmware **4.52.17.26**, Ingenic T41. Image
`recovery_wcv4_4.52.17.26.bin.zip` sha256 `21b05cbd…f5f0a21`; `/system/bin/iCamera` (MIPS32r2, uClibc,
stripped, **no canary, no NX, no PIE**).

Method: full `llvm-objdump` disassembly, independent re-derivation by two agents, and execution of the
real handler in a qemu-user/gdb harness under a mocked session context. Live camera tests on
`192.168.4.23/.24/.5.242` all pre-auth over TUTK NEW (`0xCC51`).

---

## Bottom line

1. **The v3 `audioEncoderList` stack overflow does not exist in 4.52.17.26.** The loop is capped at
   `min(array_size, 10)` by a branch-delay-slot constant; only `dest[0..9]` are written, and the saved
   `ra` at `dest[31]` is never reachable through the list.
2. Every handler in the K10000–K10003 cluster was measured/derived; there is **no attacker-controlled
   overwrite**. The tightest margin is 2 bytes (510 into 512) and it is unreachable by count.
3. The dispatcher, receive buffer and framing were mapped as a by-product; this is the harness other
   lanes should use for any K-command claim.

## 1. Dispatch (corrected addresses)

The handler table is 8-byte records `{u16 cmdA,u16 cmdB,u32 handler}` at **vaddr `0x8d5ca0`**
(file `0x4c5ca0`, mapping `vaddr-0x410000`). `0x8d5ca0 = 0x27112710` → `0x467f00`; neighbours
`0x8d5c98` (0200/0300 → `0x46750c`) and `0x8d5ca8` (2713/2712 → `0x45e988`). `0x284C/0x284D` is entry 80
at `0x8d5f18` → `0x464258`.

Invocation: `0x467930 lw $25,4($2); 0x467934 jalr.hb $25` with `a0 = ctx`, after `bsearch` over the
table keyed on `ctx+0xa0`. `ctx` is one of five 0x8fc-byte session slots at `0x95739c+n*0x8fc`.
Callback registered at `0x95a098`, invoked from the channel reader at `0x46d64c`.

## 2. Receive buffer

`0x46d320 addiu $21,$16,0x9c`; `0x46d358 addiu $7,$zero,0x400`; read via `0x6738e4`. Frame: 16-byte
header at `ctx+0x9c` (`HL`, cmd u16 @+0xa0, declared len u16 @+0xa2, payload @+0xac). A declared
length may exceed the bytes actually received (832 stale bytes were parsed by cJSON in the harness);
the transport caps at 0x400 and the handler gates on `(len-1) <u 0x384`.

## 3. Per-site audit

| Site | Claim | Measurement | Verdict |
|---|---|---|---|
| `0x467f00` K10000/10001 | `cameraInfo.audioEncoderList` → 10-int stack array at `sp+0x430`, bounded by `cJSON_GetArraySize` | `bnez` at `0x467e48` has delay slot `addiu $2,$zero,0xa` at `0x467e4c`; `beq $18,$2` at `0x467e84` exits at index 10. Live: 40/76-element lists write `dest[0..9]` only; `ra` at `dest[31]` untouched | **safe** (cap, not size) |
| same | `memcpy(sp+0x30, ctx+0xac, len)` at `0x468254` | gate 1..900 before the copy; 900 bytes ends `sp+0x3b4`, 0x4c short of the 0x400 buffer | safe, 124 B margin |
| `0x46750c` K2712/2713 | two byte writes per element into `sp+0x18`, u8 count `ctx+0xac` | 255 × 2 = 510 into 0x200 bytes; `ra` at `sp+0x224` | safe, 2 B short |
| same output loop | three bytes per element into `ctx+0x4ad` | 255 × 3 = 765; 0x44f to slot end | safe |
| `0x464258` K284C/284D | 32-byte fixed copy per entry, count `ctx+0xad`, entries of 0xb2 into `sp+0x230` | `sltiu $19,4` + `bnez` returns early at count ≥ 4; max i=2 ends `sp+0x424`, saved `s0` at 0x44c | safe |

The 2000-element live timeout is the >900 gate skipping the parse, not corruption.

## 4. ROP material kept for the next bug

`ra` is at `dest[31]`, epilogue `0x468158 lw $ra,0x4ac($sp) … jr.hb $ra` with delay
`addiu sp,sp,0x4b0` (so at hijack `sp = &dest[32]`). Known-good gadgets: `0x433290`
(`addiu a0,sp,0x18; lw ra,0x64(sp); jr ra; addiu sp,sp,0x68`), `0x815cc4`
(`lw t9,0x24(sp); jalr.hb t9`): `system` PLT `0x8befa0` (slot `0x8d4d40`), `__assert` `0x8bef80`.
`system` is called from four in-tree sites, so the slot is resolved.

## 5. Harness

`~/fss-exploit/lab` — `fss-mips` image (qemu-mipsel 7.2, gdb-multiarch, gcc-mipsel), rootfs, and
`EMULATOR-NOTES.md` with `t8.gdb` (parser) and `t15.gdb` (full handler). The full `iCamera` still
cannot reach `init_net` under qemu-user because guest `execve()` of MIPS binaries returns ENOEXEC;
the handler can still be driven directly, which is enough for parser work.

## 6. Live responses (for repeat work)

The lab client is `~/projects/fss-interop-lab/wyze_newproto` with added cfg keys `psk_identity`,
`psk_override_hex`, `k10000_json`. AUTHTKN_* identities still exist in the binary
(`memcmp` at `0x67a58c` vs `0x88e878`) but every `AUTHTKN_` identity returns DTLS
`unknown_psk_identity` on 4.52.17.26; `AUTHPWD_admin` + `PSK=SHA256(ENR)` works.
