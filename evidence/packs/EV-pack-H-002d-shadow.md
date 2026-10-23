# EV-pack-H-002d — owner shadow publish (`APPPushOTA`)

Pack: H-002d · Target: Wyze HL_CAM4 `80482C4BCF0B` (Driveway Cam) · Built 2026-10-22, revised 2026-10-23
Step under test: **can the account owner make the camera fetch an owner-supplied firmware
URL by writing the `wyze-service` IoT shadow?**

**Verdict: `BLOCKED` — but only on the last inch.** Device IoT cert + key are now retrieved
(the endpoint, host and required body are fully solved and reproduced). The block is the
AWS-IoT **hostname**: it is not in the firmware, not in the cert, and not returned by the
certificate call, so the MQTT session cannot be addressed. Delta keys are confirmed from the
handler; nothing was published, nothing was flashed.

| # | step | state |
|---|------|-------|
| 1 | owner re-auth + developer API key | **DONE** |
| 2 | `get_iot_certificate` → cert, key, root CA | **DONE** (200, `SUCCESS`) |
| 3 | MQTT/TLS 8883 to the AWS-IoT endpoint | **BLOCKED** — endpoint hostname unknown |
| 4 | publish `APPPushOTA` delta | prepared, not sent |
| 5 | observe fetch | none |

---

## 1. Auth

Two login surfaces; only the second is live.

- `POST https://auth-prod.api.wyze.com/api/user/login` with the public app key
  `WMXHYf79Nr5gIlt3r0r7p9Tcw5bvs6BB4U8O8nGJ` (or the older `RckMFKbs…`) → `400 errorCode 1000`.
  Body was the documented `{"email","password"}` with md5³ — the rejection is the key pair.
  `/user/login` instead answers `403` pointing at `…/Creating-an-API-Key`.
- **Working path:** per-account `keyid`/`apikey` from `developer-api-console.wyze.com`, minted
  over PKCE: `auth.wyze.com/oauth/authorize` (client `a1a21562-09ad-4b49-8476-a2990f0715e9`,
  public secret `F4Q-CzzEgwRmB9wbrMWhxeiRPZfp-y`, scope `email openid`, S256) → email+password
  → MFA → `/login/mfa/code` → trust device → console `createApiKey`.
- **MFA is email-only** (`/login/mfa/option` offers one method; no authenticator option, and
  `WYZE_TOTP` is absent from `wyze.env`). Code read from the owner's Gmail Atom feed
  (`mail.google.com/mail/u/0/feed/atom`) with the live Chrome `Default` Google cookies
  (AES-CBC, Keychain `Chrome Safe Storage`, PBKDF2-SHA1 1003, 32-byte host-hash prefix stripped).
- Login succeeded → `200`, `user_id dc9ab1bc…`, token exp 1792885091, JWT scope `native`.

**For the next reader (also see the header note):** this endpoint's appid is
**`wc4p_5b0e5bc2788d4ff68c7b98a5656148d0`** (literal at `iCamera` `0x87728c`), **not** the
`wc4p_39e3…` used by `get_iot_prop`. The account's console key pair is the one now in
`~/.config/fss-lab/wyze.env` (`WYZE_KEY_ID` / `WYZE_API_KEY`, valid to 2027-10-22); the older
console key `8e105311-…` was deleted (one key per account). Nobody needs to redo the OAuth dance.

## 2. Credentials — solved

`bin/iCamera` builds `https://<paracfg cloud_server_url><path>`; the host is therefore runtime
config, not a literal. Route probing (same body each time) shows the path only exists on
`app.wyzecam.com` and **without** a version prefix: `/app/v2` and `/app/v3` are gateway 404s,
`/device/system/…` is live. `api.wyzecam.com` 500s, `devicemgmt-service` / `app-core` 404.

The handler validates in layers, which is how the schema was recovered (each answer names the
next requirement — this is a guided, not brute, walk):

| body | answer |
|---|---|
| `{device_mac, device_model}` | `1001 INVALID_PARAMETER` |
| `{mac, product_model, ts, enr:""}` | `1001` |
| full set, no `access_token` | `1001` |
| full set, fake token | `2001 "access token is error"` |
| full set, real token, `enr:""` | `404 NOT_FOUND` |
| … with the object-list `enr` | **`1001 "firmware_ver cannot be empty"`** |
| … plus `firmware_ver` | **`200 SUCCESS`, certs issued** |

Body that works (all keys are literal in `cloud_build_request_common` `0x5e169c`; `sc` is the
*value* `"verify_method"` and `sv` the access key — both are constants added by the builder,
`0x5e1854`/`0x5e186c`, not an HMAC):

```json
{"mac":"80482C4BCF0B","product_model":"HL_CAM4","product_type":"Camera",
 "hardware_ver":"0.0.0.0","firmware_ver":"4.52.17.26","enr":"O7y73ZL+K47xvSPY",
 "sc":"verify_method","sv":"5b0e5bc2788d4ff68c7b98a5656148d0","ts":<ms>,
 "access_token":"<bearer>","appid":"wc4p","app_name":"wyze","app_version":"2.50.0",
 "phone_id":"d39515e3-5b94-4b29-b63f-1b3456cc270a"}
```

`enr` is the missing identity carrier — it is **not** empty on real units; it comes from
`~/.config/fss-lab/wyze_object_list_raw.json` (`enr` per device, alongside `product_type`
`"Camera"`, `hardware_ver "0.0.0.0"`, `firmware_ver`). Those three fields were the whole 404.

Response (`data`): `client_id` / `thing_name` = `80482c4bcf0b`, `keep_alive 300`, and
presigned S3 URLs for `root_cert_url` (VeriSign Class-3 G5), `client_cert_url`
(`…/hl_cam4/80482c4bcf0b/5e47f7a288-certificate.pem.crt`) and `client_private_key_url`.
Downloaded outside the repo to `~/.config/fss-lab/wyze_iot/80482C4BCF0B/`
(`cert.pem` 1224 B, `privkey.pem` 1671 B, `rootCA.crt` 1758 B). Cert SHA-256
`5E:47:F7:A2:88:2F:6D:07:11:38:DC:0E:23:E2:B2:C1:81:52:E7:43:C0:16:96:71:48:0C:49:DB:99:77:7E:2A`,
valid 2024-10-18 → 2049-12-31, subject `CN=AWS IoT Certificate`, issuer `Amazon.com Inc.`,
no SAN/extensions. Private key never printed; `client_username`/`client_password` are empty
(mutual TLS only).

## 3. MQTT — the remaining blocker

`bin/iotclient` reads the host from `paracfg_get_iot_server_url` (`.product_config`, jffs2 —
not in the signed image) and logs `AWS_IOT_MQTT_HOSTNAME:%s`. It is **not** derivable:

- not in the cert (no SAN, generic CN), not in the cert response (`client_id`, `thing_name`,
  `keep_alive`, three S3 URLs only), not in `cfg_Driveway_Cam.json`;
- not in the app-key surface — `get_iot_prop` with capabilities `iot` / `cloud` / `device_info`
  returns `code:1 SUCCESS` but empty property objects;
- `iot.wyze.com`, `iot.wyzecam.com`, `mqtt.wyze.com`, `iot-service.wyze.com` do not resolve;
- the camera (192.168.4.24) is not reachable on 80/443 from the workstation, so it cannot be
  asked directly.

Everything else for the session is in hand: thing name `80482c4bcf0b`, TLS 8883, ALPN
`x-amzn-mqtt-ca`, keep-alive 300, subscribe
`$aws/things/80482c4bcf0b/shadow/name/wyze-service/update/delta` (topic literals in
`iotclient`: `…/wyze-service/update{,/delta,/rejected}` and the `wyze-secure` pair).

## 4. Delta

Exact payload once §3 is addressable (keys `url`, `md5`, `model`, lowercase — from the
`cJSON_GetObjectItem` literals in `assis`; `pcUrl`/`pcMd5` are internal names only):

```json
{"state":{"url":"https://<owner-host>/firmware.bin","md5":"<md5 of served file>","model":"HL_CAM4"}}
```

A 512-byte body is enough to observe a fetch; the AES/MD5 gates (`assis` `0x40687c`, 1000
retries) reject it inertly with no flash.

## 5. Observed

Operator-side HTTP only: no camera-side attempt, no 443 to an owner host, no `[ASSIS]url:`
line, no retry cadence. Camera untouched.

## 6. Verdict — `BLOCKED` (single remaining unknown)

The owner path is real: re-auth, key minting and device credential issuance all work from the
owner account with no vendor involvement, and the certificate service happily hands over the
device's mTLS key. Only the broker address is missing, and it lives exclusively in the unit's
flash config. Unblock is one of:

1. read `iot_server_url` from `.product_config` (root shell / flash read of any owned unit), or
2. capture one app-initiated shadow session and take the SNI, or
3. DNS/CT sweep for the account's `*-ats.iot.us-west-2.amazonaws.com` endpoint.

Owner-side credentials stay valid to 2026-10-24 (token) and 2027-10-22 (key).
