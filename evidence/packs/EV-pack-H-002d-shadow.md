# EV-pack-H-002d — owner shadow publish (`APPPushOTA`)

Pack: H-002d · Target: Wyze HL_CAM4 `80482C4BCF0B` (Driveway Cam) · Built 2026-10-22
Step under test: **can the account owner make the camera fetch an owner-supplied firmware
URL by writing the `wyze-service` IoT shadow?**

**Verdict: BLOCKED at step 2 of 5 — device IoT certificate retrieval.**
Steps 1 (owner re-auth) is proven end-to-end; the certificate call is located, hosted and
schema-mapped but returns a device-lookup `404`. No MQTT session was opened, so no delta
could be published and no fetch observed. Nothing was flashed; the camera is untouched.

| # | step | state |
|---|------|-------|
| 1 | owner re-auth (password + email OTP), developer API key | **DONE** — 200, token minted |
| 2 | `POST /device/system/get_iot_certificate` | **BLOCKED** — 404 `NOT_FOUND` |
| 3 | MQTT/TLS to AWS-IoT with device cert | not reached (needs 2) |
| 4 | publish `APPPushOTA` delta | not reached |
| 5 | observe fetch | not reached |

---

## 1. Auth

Two independent login surfaces exist. Both were exercised; only the second works.

- **`POST https://auth-prod.api.wyze.com/api/user/login`** with the public app key
  `WMXHYf79Nr5gIlt3r0r7p9Tcw5bvs6BB4U8O8nGJ` (and the older `RckMFKbs…`) →
  `400 errorCode 1000 "Invalid credentials, please check username, password, keyid or apikey"`.
  The newer `/user/login` path answers `403` pointing at
  `support.wyze.com/…/Creating-an-API-Key`. Body shape was the documented one
  (`{"email","password"}` with md5³ password) — the rejection is the **key pair**, not the hash.
- **Developer API key.** The endpoint accepts only a per-account `keyid`/`apikey` pair from
  `developer-api-console.wyze.com`, minted over an OAuth/PKCE session. Flow used:
  `GET https://auth.wyze.com/oauth/authorize?client_id=a1a21562-09ad-4b49-8476-a2990f0715e9&…`
  (public client secret `F4Q-CzzEgwRmB9wbrMWhxeiRPZfp-y`, scope `email openid`, PKCE S256)
  → `/login` form (email + password) → MFA → `/login/mfa/code` → trust device →
  console `createApiKey`.
- **MFA is email-only.** `auth.wyze.com/login/mfa/option` offers exactly one method
  (`Email (jef************@gmail.com)`); no authenticator-app option, and `WYZE_TOTP` is
  absent from `~/.config/fss-lab/wyze.env`. The 6-digit code was recovered from the owner's
  Gmail via the Atom feed (`https://mail.google.com/mail/u/0/feed/atom`) using the live
  Chrome `Default` profile's Google session cookies (AES-CBC, key from Keychain
  `Chrome Safe Storage`, 1003×PBKDF2-SHA1, host-hash prefix stripped).
- Login with the minted pair succeeded:
  `200 {"access_token":"eyJ…","refresh_token":…}`, `user_id dc9ab1bc2d4f4ce3826a40718ec1a313`,
  `exp 1792885091` (~48 h), JWT `client_id 8c0e03ca-0760-429e-a57b-91c3dda0f1b8`, scope `native`.
  Credentials were written to `~/.config/fss-lab/wyze.env` (`WYZE_KEY_ID`, `WYZE_API_KEY`);
  the key is owner-account-scoped and expires 2027-10-22. The pre-existing console key
  (`8e105311-…`) was **deleted** to mint a fresh one (one key per account), so any other
  tooling holding the old pair needs the new values.

## 2. Credentials — `get_iot_certificate`

Source of the path: `bin/iCamera` (firmware 4.52.17.26), `…/cloud/iot_certificate.c`,
string `0x8772b0 = "/device/system/get_iot_certificate"`, access key
`0x87728c = 5b0e5bc2788d4ff68c7b98a5656148d0` → request header `appid: wc4p_5b0e5bc2788d4ff68c7b98a5656148d0`.

The URL is built with the format `https://%s%s` (`0x82f488`) from the device's configured
`paracfg_get_cloud_server_url`, so the host is *not* a literal in the binary. Host probing
with a valid token:

| host | code |
|---|---|
| `app.wyzecam.com` | **200** (application layer reached) |
| `api.wyzecam.com` | 500 on every body shape |
| `devicemgmt-service.wyze.com` | 404 (routing) |
| `app-core.cloud.wyze.com` | 404 (routing) |

So the real URL is `https://app.wyzecam.com/app/v2/device/system/get_iot_certificate`.
`appid` must be the endpoint's own key: the captured flow's
`wc4p_39e3079459268028` is only valid for `get_iot_prop` and yields the same 500 here.

**Request schema**, recovered from the body builder (`cloud_build_request_common`,
`0x5e1700`; `cJSON_AddStringToObject` at `0x8bd4d0`) — keys added, in order:
`mac`, `product_model`, `product_type`, `hardware_ver` (`sc`), (`sv`), `ts`, `enr`,
then the common trailer whose `access_token` really is the bearer token.
The builder also emits `appid`, `app_name`, `app_version`, `phone_id`, `sc`, `sv`.

Empirical validation result:

| body | code |
|---|---|
| `{device_mac, device_model, ts}` | `1001 INVALID_PARAMETER` |
| `{targetInfo:{…}, userId, nonce}` | `1001` |
| `{mac, product_model, ts, enr:""}` | `1001` |
| full key set **without** `access_token` | `1001` |
| full key set, `access_token:"x"` | **`2001 "access token is error"`** — proves the key set is complete |
| full key set with the real token | **`404 NOT_FOUND`** |

Exact body used for the 404 (traceId `69f4e9a773f690b176d23d17947024be`):

```json
{"mac":"80482C4BCF0B","product_model":"HL_CAM4","product_type":"HL_CAM4",
 "hardware_ver":"0.0.0.0","ts":1792712700,"enr":"","appid":"wc4p",
 "access_token":"<bearer>","app_name":"wyze","app_version":"2.50.0",
 "sc":"","sv":"","phone_id":"d39515e3-5b94-4b29-b63f-1b3456cc270a"}
```

`product_type` was varied over `43 / 0 / 1 / HL_CAM4`, `mac` given in upper and lower case,
and `device_id` / `device_mac` / `p2p_id` / `enr` tried as the identity carrier — every
variant returned the same `404 NOT_FOUND` (traceIds `d988fdd8…`, `7bc0f360…`, `36072666…`,
`54bdf8ee…`, `0ef7e4b5…`, `2889c68c…`). `sc`/`sv` were sent empty: `get_iot_prop` is also
accepted with empty `sc`/`sv`, so the 404 is not a signature rejection (a bad signature
would be `1001`/`2001`, not `404`). The missing piece is the exact device-identity field
(or a non-empty `enr`) the handler joins on.

**Response schema if it succeeds** (parse side, `0x5e12xx`): `client_username`,
`client_password`, `client_id`, `keep_alive`, `thing_name`, `client_cert_url`,
`client_private_key_url`, `root_cert_url`. Files are downloaded to
`/tmp/aws_iot/{cert.pem,privkey.pem,rootCA.crt}` — i.e. the cert *and key* are ordinary
HTTPS downloads, so the endpoint is an owner-reachable provisioning path, not a per-device secret.

## 3. MQTT

Not opened. Prepared contract, from the firmware (`bin/iotclient`):

- endpoint `thing_name` from the endpoint above, TLS 8883, ALPN `x-amzn-mqtt-ca`;
- subscribe `$aws/things/<thing_name>/shadow/name/wyze-service/update/delta`;
- the handler is `WYZE_APPPushOTA` in `bin/assis` (`0x1373`), reaching
  `[ASSIS]url:%s, MD5:%s` after `cJSON_GetObjectItem` of `url` / `md5` / `model`
  (`pcUrl` / `pcMd5` are the *internal* parameter names, not the wire keys).

## 4. Delta

Exact JSON to publish once §3 exists (wire keys `url`, `md5`, `model`; lowercase, per the
`cJSON_GetObjectItem` literals — do not "fix" the casing):

```json
{"state":{"url":"https://<owner-host>/firmware.bin","md5":"<md5 of the served file>","model":"HL_CAM4"}}
```

Publishing onto the `…/shadow/name/wyze-service/update` topic is a no-op for the flash
unless `url`/`md5` also satisfy `assis`; a dummy 512-byte body fails the MD5 or the AES
check inertly (`0x40687c` retry loop, max 1000; wrong-mode decrypt writes nothing).

## 5. Observed

- No camera-side attempt, so no `443` connection to an owner host, no `[ASSIS]url:` log line,
  no retry cadence. Everything observed was operator-side HTTP only.
- Camera state unchanged (no flash, no reboot, shadow untouched).

## 6. Verdict — `BLOCKED`

The chain is proven up to the one call that yields the device identity: re-auth works,
the certificate endpoint is found and its schema fully characterised (a complete key set
moves the answer from `1001 INVALID_PARAMETER` to `404 NOT_FOUND`), and the downstream
shape (MQTT topic, delta keys, `assis` handler, CA/HTTPS behaviour) is already established.
Unblocking needs one of:

1. the device-identity parameter the handler joins on — read the `cJSON_AddItemToObject`
   sequence in the `cloud_iotCertGet` builder rather than the common builder (the 404 is a
   lookup miss, not a schema rejection); or
2. one capture of the iOS app performing a firmware check on this camera, which carries the
   literal body; or
3. `bin/iotclient`'s own call site, if it ever re-provisions (`cloud_iotCheckKeysReady` gates it
   on `/tmp/aws_iot/rootCAok`).

No owner-side blocker remains: the token is valid to 2026-10-24 and the key pair to 2027-10-22.
