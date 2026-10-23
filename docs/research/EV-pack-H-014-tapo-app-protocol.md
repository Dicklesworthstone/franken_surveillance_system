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
