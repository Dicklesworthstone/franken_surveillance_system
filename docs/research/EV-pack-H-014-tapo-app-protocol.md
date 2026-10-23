# EV-pack-H-014 — Tapo Android app (3.22.105): local protocol, third account, ONVIF

Status: evidence from the official app; confirms and extends `EV-pack-H-012` without a device
round-trip. Owner-supplied APK: `~/Downloads/TP-Link+Tapo_3.22.105_APKPure.xapk`
(`com.tplink.iot.apk`, base `classes*.dex`). Decompiled with the lab jadx.

## 1. Login handshake (client side)

`com.tplink.libtapocameranetwork.util.SecureUtils__SecureUtilsKt`:

- `m(password, session)` → `appConfirm = SHA256_HEX(password) + cnonce + nonce` (concatenated, **not**
  re-hashed) and stores it in the session.
- cell `s(...)`/`t(...)` → `isDeviceUseTPPassword` compares the camera's `device_confirm` against
  `SHA256_HEX(cnonce + SHA256_HEX(password) + nonce)`, i.e. exactly the order used by our
  empty-`cnonce` bypass in `EV-pack-H-012`.
- `o(...)` → `lsk = SHA256("lsk" + cnonce + nonce + p2)[:16]`,
  `ivb = SHA256("ivb" + cnonce + nonce + p2)[:16]`, `p2 = SHA256_HEX(cnonce + SHA256_HEX(pw) + nonce)`.
  Our client's `p2 = device_confirm` so the derivation is identical.
- `r(...)`/`s(...)` (tag) = `SHA256_HEX(SHA256_HEX(pw) + cnonce + requestsJson + seq)`, `\/` escaped.
- `loginWithNoPwdSync` still requires a password unless the device is in TP-cloud-password mode
  (`isDeviceUseTPPassword == true`); it only skips the write-back of a new password.

Consequence: the bypass is not an accident of a single field — with `cnonce = ""` the two SHA-256
orderings in the spec collapse, so `device_confirm` is replayable as `digest_passwd`.

## 2. Third account (`changeThirdAccount`)

`model/AccountInfo.java` secondary constructor:

```java
new AccountInfo("third_account", username, md5hex(password), "", rsaPkcs1(password), ...)
```

i.e. JSON `{"secname":"third_account","username":u,"passwd":MD5_HEX,"ciphertext":BASE64_RSA}`.
Two RSA-1024 public keys are compiled in (`libtapocameranetwork.util.k`, `d` and `e`); `e` is selected
when the trailing `unique_key` integer is present. Key `d` (first PEM) is the default.

The default camera-account username is `TPL075526460603` when the device reports a "no-hub battery
cam" component, otherwise `admin` (`k.g(boolean)`). `setAccountEnabled`/`changeThirdAccount` are the
only writes; `getThirdAccount` returns `{username, enabled, public_key}` and caches it in
`CameraSettingRepository`.

## 3. ONVIF / RTSP surface

- ONVIF listens on **TCP 2020**, path `/onvif/service`; RTSP on 554 (`/stream1`, `/stream2`), events
  on 1024/1025, media on 8800. The third account is exactly the credential an NVR uses
  (`rtsp://user:pass@host/stream1`).
- `OnvifSecurityConfig` (`tls_enable`, `tls_version`, `auth_type`, `auth_algo`) plus
  `setOnvifSecurityConfig` allow tightening digest auth/TLS. `isSupportCameraAccount[V2]` gates the
  feature per device.
- Some ONVIF calls (`GetCapabilities`, `GetServices`, `GetSystemDateAndTime`) answer without auth.

## 4. Local transport constants (unchanged)

`POST /stok=<token>/ds`, body `{"method":"multipleRequest","params":{"requests":[...]}}`, `seq` header,
AES-128-CBC responses. `connectAp` is the overflow sink (`H-012`, `H-002b`). Firmware upgrade is
cloud-driven (`checkFirmwareVersionByCloud` → `startFirmwareUpgrade` with section
`firmware_download`); the request carries no URL, so a local update server is not a shortcut.

## 5. Static file behaviour on 443 (observed, not from the app)

`GET /` → bare 404. Guessed file paths (`/bin/main`, `/etc/passwd`) return
`401 {"data":{"code":-40407},"error_code":-40401}` with **no `WWW-Authenticate` header**, so they are
not digest-protected file reads; `/bin/main` later hung the dispatcher. Root path mapping is still
unknown; treat 443 as API-only until proven otherwise.

## Reproduce

```bash
unzip -p <xapk> com.tplink.iot.apk > /tmp/tapo.apk
unzip -o -q /tmp/tapo.apk 'classes*.dex' -d /tmp/tapo-dex
jadx --no-res --no-imports -d /tmp/tapo-src /tmp/tapo-dex/classes5.dex   # util/k, AccountInfo, SecureUtils
```

## 6. Prior art that changes the C460/C660 plan (deadc0de.sh, C500, 2026)

<https://deadc0de.sh/posts/tapo-c500-two-cves/> (CVE-2026-104944/104945) and
<https://deadc0de.sh/posts/tapo-c500-root/>:

- **A monitor respawns `/bin/main`** after a crash; UART shows `signal SIGILL caught` and the service
  returns in ~13 s. A connectAp crash is therefore a ~15 s outage, not a reboot. Recoveries seen on
  `.4.70` (24 s) match this.
- **TDP** is an unauthenticated UDP protocol on 20002/20010 with a TLV dispatcher that indexes a
  6-slot table up to type 0x18; type 6+ calls a name string as a pointer (SIGILL). Packet builder and
  checksum are public (`anaskalt/CVE-2026-104944`). It is a device-independent DoS and a second
  unauth parser surface; handler bodies were not fuzzed in that work.
- **ONVIF** lives on TCP 2020 at `/onvif/service`, not 443; `RemovePreset` writes parsed ints past a
  32-entry stack array and the loop is bounded by request offset, not the array. That handler is
  authenticated but reachable with the third account. Media is RTSP 554 `/stream1|/stream2`, events
  1024/1025, media 8800.
- The app rootfs is **AES-128-CFB1 with the first 512 bytes encrypted at rest**; the key is compiled
  into the kernel (`CONFIG_ENCRYPT_ROOTFS_KEY` in the matching GPL drop) with a fixed IV. The app
  partition is therefore only readable from a flash dump, but a dump is offline-decryptable once the
  GPL key for the exact model is read.
- **Battery models sleep their Wi-Fi**; LAN probes do not wake them, the cloud path does. Every
  interactive test needs an app-side wake, and a held TCP session does not prevent sleep.

## 7. C460 observations (2026-10-23)

- Port 2020 is **closed** even with the third account provisioned and `stok` root; ONVIF is either
  disabled per model or needs `setOnvifSecurityConfig`/a later service start. 554/8800 behave the same.
- `/bin/main` answers `401 {"data":{"code":-40407}}` with **no `WWW-Authenticate`**, and repeats the
  same body for `/etc/passwd`; a `stok`-less cookie replay does not change it, so the path mapping is
  unresolved rather than digest-protected.
- Login is rate-limited while the app boots: during the wake window the second step can return a fresh
  challenge (`code -40401`, `time`/`max_time` 9/10). Sleep ≥5 s after the first step before sending
  `digest_passwd`.
