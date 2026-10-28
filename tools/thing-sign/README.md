# Tuya/Thing request signer — offline harness

Goal: compute `Gz-Sign` for `a1-us.iotbing.com/api.json` without a phone.

The sign is `ThingApiSignManager.generateSignatureSdk` → `SecureNativeApi.doCommandNative(ctx, 1, bytes)`,
a native command in `libthing_security.so` (Android arm64). It cannot be reimplemented from the
Java side alone, so this harness runs the real library under a stub Android environment and calls the
registered JNI method by name.

## What works

- The library loads on Alpine/musl + Temurin arm64: musl tolerates the bionic `LIBC` symbol versions,
  and `stub.c` supplies the bionic-only surface (`__sF`, `__*_chk`, `__system_property_get`,
  `__errno`, `AAsset*`).
- Stub `android.content.Context` / `PackageManager` / `PackageInfo` / `Signature` satisfy the
  context walk; `Signature` returns a real DER certificate from `/data/cert.der`.
- Assets are served from `/w/assets` (extracted from the APK).
- `computeDigest("abc","key")` returns `aee1dd678aea01125dfc861f41d4072d` — the crypto core runs.
- `doCommandNative(ctx, 1, canonical_string)` reaches the signer and reads `assets/t_s.bmp`
  (a 100x75 24-bit BMP whose payload is the stego key).

- The real Glazero signing certificate is recovered from the APK's **v2 signing block** (there are no
  v1 `META-INF/*.RSA` files), so `Signature.toByteArray()` returns the genuine DER.

## What is still missing

1. `assets/tecrkcehc_ext` — a literal asset name the signer opens; absent from the APK, so it is
   fetched or produced at runtime. The miss is logged by the stub.
2. `checkStatus` returns **-1** (anti-tamper failure) even with the real certificate and package
   name, so the signer refuses. Whatever else it compares — likely the cert digest against a baked
   value, or fields of `tecrkcehc_ext` (currently a copy of `t_s.bmp`, a guess).
3. `t_s_daily.bmp` — also absent, same family as `tecrkcehc_ext`; both are runtime-supplied rather
   than bundled. Placeholder formats (BMP copy, random, hex digest, JSON digest) all keep the status
   at `-1` or bail earlier.
4. The **appSecret** passed to `doCommandNative(ctx, 0, secret, appId, false)` at SDK init
   (`ThingNetworkSecurity` line ~95). We only know the appId (`clientId`). With the clientId as a
   stand-in, `cmd 1` returns null.

## Run

```sh
mkdir -p libs assets && cp <split>/lib/arm64-v8a/lib{c++_shared,thing_security,thing_security_algorithm}.so libs/
unzip -o <base.apk> 'assets/*' -d .
docker build --platform linux/arm64 -f Dockerfile.jvm -t fss-jvm .
docker run --rm --platform linux/arm64 fss-jvm            # sign `in.txt`
docker run --rm --platform linux/arm64 fss-jvm java -cp /w/out Run digest
```

`in.txt` is the canonical string for the captured request (sorted `k=v`, `||`-joined, `postData`
replaced by swapped MD5-base64). Expected sign: `2d2b754c…88e0`.

`Dockerfile.musl` + `harness.c` are the JVM-free variant (fake `JNIEnv` table, slot names in
`slotnames.txt`); it reaches the same place with less fidelity.

## 2026-10-28 (PearlGull, fss-fkkpw): base-APK re-mined — `t_cdc.tcfg` found, `cers` found

Re-extraction of the **base** APK (`com.glazero.android.apk` from
`~/Downloads/Aosu_5.10.12_APKPure.xapk`) found two assets the earlier asset census missed:

- `assets/t_cdc.tcfg` — 4926 bytes, binary, MD5 `e981b2ca2a73ef3e3e8951f7c28bf065`.
  Opened at `0x13210` (`AAssetManager_open` with `t_cdc.tcfg` at `.rodata 0x7f58`), read fully,
  and parsed by the function at `0x13500` (varargs `stp q0,q1`-style call site). Copied into
  `assets/`; harness runs unchanged with it present (`RESULT` identical, so it is not on the
  `cmd 1` path, but `checkStatus`/init may read it — not yet distinguished).
- `assets/cers` — 4555 bytes, base64 lines (60 lines, line 0 decodes to 57 ASCII hex chars).
  **No dex string references it and `libthing_security.so` does not name it** — likely read by
  another library or via resources. Not on the harness path either.

`libthing_security.so` (arm64, MD5 `465e5af0…`, same as `libs/`) disassembly landmarks
(`llvm-objdump`, all `JNI_OnLoad`-span):

| address | fact |
|---|---|
| `0x1362c–0x13648` | `AAssetManager_open` with **`t_s.bmp` XOR `t_s_daily.bmp` chosen by `csel` on w20 bit0** — the daily variant is a runtime flag, not a separate asset hunt |
| `0x19214–0x19220` | opens **`tecrkcehc_ext`** (0x8782), full read into `malloc` buffer, len stored at `x19+0x80`, ptr at `x19+0x78` |
| `0x1950c` | **16-char decimal literal `7178265647164836`** (`.rodata 0x81e0`) SSO-constructed and passed to the parse helper at `0x18dbc` — candidate built-in default seed/key |
| `0x1a230` | the `0x9040` base64 blob is the **mbedtls base64 self-test vector** — not signer data (dead end) |
| `0x13210` | opens `t_cdc.tcfg` then calls the parser `0x13500` |

Baseline still: `checkStatus -1`, `INIT=null`, `RESULT=abe3a823…` (unchanged by both new assets
on the `cmd 1` path — the acceptance gate is the *content* of `tecrkcehc_ext`, which is what the
parser-acceptance sweep targets next).

### Mirror hunt (2026-10-28, PearlGull) — no new APK source reachable without Cloudflare/auth

| source | result |
|---|---|
| apkmirror `wp-json/v2/search` | 403 (5660 B wall) |
| apkpure `/search` + `d.apkpure.com/b/XAPK/...` | 403 both |
| apkcombo | connection failure |
| apk4fun, apkmonk | 403 / unreachable |
| evozi apk-downloader | reachable but fully client-side (Next.js, no server API found in HTML) |
| android-apk.org | JS redirect loop, no APK |
| **play.google.com listing** | **200** — Play is readable without auth; live version **5.10.22** ("What's new"), `[[["5.10.22"]]]` in page data. Delivery of the APK itself requires the Google account delivery protocol (token + device registration) — out of lane scope; a Play-installed copy or its `/data/data/com.glazero.android/` dir remains the surest blob source. |

Play listing also confirms the fleet's 5.10.12 is one minor behind current.

### Parser-acceptance harness (`ext_acceptance.py`, 2026-10-28) — results

`ext_acceptance.py` mirrors the blob parser/consumer evaluation order exactly (addresses from
the arm64 `libthing_security.so`, MD5 `465e5af0…`):

| step | site | semantics |
|---|---|---|
| newline scan | `0x192e8` | first `\n` scanning from **index 1**; none → `-1` |
| decimal field | `0x1930c–0x19368` | backward digit accumulate with `pow(10,k)` (non-digits skipped), stored `ctx+0x14` |
| payload split | `0x193d8` | base64 payload = `[newline+1, len)`; remainder-length guard `cmn #0x10` at `0x19388` |
| decode | `0x18c68→0x18ce0` | strict `mbedtls_base64_decode` (rejects embedded newlines/whitespace) |
| decrypt | `0x18dbc→0x10fb0→0x11098` | **AES-128-ECB** (FIPS-197 tables in-binary: SBOX `0x756f`, Rcon `0x7470`, InvSBOX `0x766f`, InvShiftRows idx `0x7410`; 9 main rounds), key from init state |
| normalize | `0x18e9c–0x18ee0` | plaintext → string with **every NUL byte replaced by `'0'`** (`movz w24,#0x3002`) |

AES-128 core validated against FIPS-197 Appendix C.1 (key `000102…`, ct `69c4e0d8…` → pt
`00112233…` PASS) and round-key schedule matches C.1 (`w4=d6aa74fd…`, `w40=13111d7f…`).

**Live-gate matrix** (each candidate swapped into `assets/tecrkcehc_ext`, real JVM harness):

| candidate | class | dec len | live result |
|---|---|---|---|
| current placeholder (t_s.bmp copy) | cipher | 128 | `checkStatus -1`, RESULT `abe3a823…` (baseline) |
| AES-enc json-keys (16B-padded) | cipher | 32 | unchanged baseline |
| AES-enc csv-keys | cipher | 16 | unchanged baseline |
| AES-enc fips197 vector | cipher | 16 | unchanged baseline |
| raw 32-byte | cipher | 32 | unchanged baseline |
| raw 27-byte JSON (not block-multiple) | b64 | 27 | **SIGSEGV in musl** (`ld-musl+0x2a0e4`) |
| raw 11-byte CSV | b64 | 11 | **SIGSEGV** (same) |
| trailing-newline base64 (`-padnl`) | shape | — | strict decode rejects → parse class only |

Conclusions, all measured:

1. **Block alignment is a hard requirement** — non-multiple-of-16 decoded content crashes the
   signer path (the decrypt runs unguarded). Any synthesized blob must decode to a multiple
   of 16.
2. **The embedded `\n` of multi-line base64 (`cers` shape) is rejected** by the strict decoder —
   `cers` is *not* in `tecrkcehc_ext` format; its 60-line base64 would fail at `0x18ce0`.
3. `checkStatus -1` and `cmd 1` result are **insensitive** to placeholder *content* in the
   16/32-byte cipher class — the acceptance gate needs the genuine plaintext (or the crash
   class difference indicates the decimal field at `ctx+0x14` gates a length-sensitive copy
   that our placeholders satisfy trivially). Next discriminating run: vary the decimal field
   against a fixed payload and watch for a length check mismatch path.
4. Sweep driver: `python3 ext_acceptance.py sweep --out DIR` regenerates all candidates;
   `decrypt` mode + `--keyhex` full-pipeline-decrypts a candidate offline.
