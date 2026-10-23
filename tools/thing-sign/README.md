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
3. The **appSecret** passed to `doCommandNative(ctx, 0, secret, appId, false)` at SDK init
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
