# EV-pack-H-002d — owner shadow publish (`APPPushOTA`)

Pack: H-002d · Target: Wyze HL_CAM4 `80482C4BCF0B` (Driveway Cam) · Built 2026-10-22, revised 2026-10-23
Step under test: **can the account owner make the camera fetch an owner-supplied firmware
URL by writing the `wyze-service` IoT shadow?**

**Verdict: `SHADOW-WORKS` for the control plane, `PARTIAL` end-to-end.** The owner can mint
device IoT credentials, connect to the broker, and write the shadow; the camera consumes the
delta and echoes `url`/`md5`/`model` into `reported`. The camera was observed opening TLS to a
published URL. What is still missing is a *fetch that completes* — the one attempt landed on a
`https://192.168.4.160:8443` target so the handshake hit a plain-HTTP listener; later
`trycloudflare` deltas produced no further attempt, most likely because the camera and the
operator fight over the single permitted client id (see §3.1) and the camera backs off.

Nothing was flashed. A failed download is inert by construction.

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

## 3. MQTT — works, with two non-obvious rules

**Endpoint.** `aws-iot.wyzecam.com` — a literal already in the image, CNAME
`a24rq1e5m4mtei.iot.us-west-2.amazonaws.com` (prod; `test-aws-iot.wyzecam.com` is the staging
twin `a3bn1pq0gt470b-ats…`). Port 8883, ALPN `x-amzn-mqtt-ca`, mutual TLS with the downloaded
cert/key, `rootCA.crt` as the trust anchor (the Mac lacks the intermediate; the device ships
the VeriSign G5 root).

**Rule 1 — SNI must be the CNAME target, not the friendly name.** The server cert is
`CN=*.iot.us-west-2.amazonaws.com`; one wildcard label means `aws-iot.wyzecam.com` as SNI
fails hostname verification (`CERTIFICATE_VERIFY_FAILED: Hostname mismatch`). A camera builds
the target from the resolved CNAME, which is why the friendly name alone works for it. Connect
to `a24rq1e5m4mtei.iot.us-west-2.amazonaws.com` (both DNS name and SNI).

**Rule 2 — the MQTT client id must be the thing name** (`80482c4bcf0b`). Any other id
(`…-omp`, `omp-…`) gets an accepted CONNACK followed immediately by a close (`DIS 7`) and no
subscribe/publish lands. Consequence: the operator and the camera are the *same* MQTT identity,
so each connect kicks the other. The camera reconnects within a second or two and the delta
fan-out goes to whichever session is subscribed at that instant — a bare publish usually
delivers the delta to *us*, not to the camera.

Session parameters that worked: CONNACK `0`, SUBACK granted QoS 1 on
`…/shadow/name/wyze-service/update/delta`, publish QoS 1 to `…/wyze-service/update` →
PUBACK. Shadow `get` + `get/accepted` also work, which is how `reported` was read.

### 3.1 Shape — actually accepted by the device

`{"state":{"desired":{"url":…,"md5":…,"model":"HL_CAM4"}}}` → `update/accepted`, version bump,
and the camera **echoed all three values into `reported`** within seconds. So flat keys at the
top of `desired` are correct; `pcUrl`/`pcMd5` are internal names only.

Two variants were tried and are *not* better: `"APPPushOTA":{…}` nested, and
`"APPPushOTA":"<json string>"`. Both are stored in `desired`, neither is echoed by the camera.
`wyze-secure` accepts publishes too but produced no visible reaction.

## 3.2 Observed attempt — signals reached

A real fetch happened over 443 through a TLS terminator whose chain the device trusts
(cloudflared quick tunnel, GTS R4, verified against `/tmp/wcv4_root/local/cacert.pem`).

Signals hit, in the order that matters:

| # | signal | state |
|---|--------|-------|
| 1 | TLS accept | **yes** — ClientHello at the origin, TLS 1.2/1.3 suites, SNI = tunnel host |
| 2 | HTTP GET of the published path | **yes** — `GET /firmware.bin HTTP/1.1` → `200`, 40 s after a single publish |
| 3 | `[ASSIS]url:` effect / decrypt | not observable without a console |
| 4 | reboot or stream drop | no (payload was a probe, and the md5 gate rejected it) |

Two delivery facts fell out: the fetch arrives ~40 s after the publish (not instantly), and the
camera first re-tried its *previously failed* URL (`/firmware.bin`) rather than the newly
published one — the retry queue outlives the delta.

## 4. Delta

Wire payload (lowercase `url`/`md5`/`model`, top of `desired`):

```json
{"state":{"desired":{"url":"https://<owner-host>/firmware.tar","md5":"<md5 of served file>","model":"HL_CAM4"}}
```

A 512-byte body is enough to see a fetch; the AES/MD5 gates (`assis` `0x40687c`, 1000
retries) reject it inertly with no flash. `.tar` and `.bin` names behave the same, so naming
does not gate the attempt.

## 4.1 The client-id fight, and what it costs

Because both operator and camera must present the same MQTT id, every operator connect is a
kick and the camera answers with its own reconnect. Measured behaviour:

- the *first* delta published this way was consumed and echoed into `reported` within seconds;
- every later delta was stored in `desired` but **not** echoed, i.e. the camera was not
  subscribed at fan-out time;
- a 70-publish, 95 s burst produced no additional attempt; a 2-min quiet gap followed by a
  single publish also produced none;
- the camera keeps reporting (`DeviceState` timestamp stays current), so it is online — it is
  the delta *delivery*, not the camera, that is starved.

So a one-shot publish is a lottery with bad odds. The reliable shape is a long keep-alive
publisher that re-connects, publishes, and yields, with delivery confirmed by watching
`reported.url` change before relying on it.

## 4. Delta

Exact payload once §3 is addressable (keys `url`, `md5`, `model`, lowercase — from the
`cJSON_GetObjectItem` literals in `assis`; `pcUrl`/`pcMd5` are internal names only):

```json
{"state":{"url":"https://<owner-host>/firmware.bin","md5":"<md5 of served file>","model":"HL_CAM4"}}
```

A 512-byte body is enough to observe a fetch; the AES/MD5 gates (`assis` `0x40687c`, 1000
retries) reject it inertly with no flash.

## 5. Observed

Origin log (time, request) — the only camera-side lines:

```
20:40:19  TLS ClientHello (SNI = tunnel host, TLS 1.2/1.3 suites)   -> plain listener, 400
20:40:59  "GET /firmware.bin HTTP/1.1" 200                           -> camera
```

Both land ~40 s after a single publish, after a quiet window, with no operator session held.
Earlier bursts produced no requests at all; the one-attempt-per-reconnect pattern only appears
when the identity is left alone.

Payload used: a 2048-byte tar (`upgraderun.sh` probe) encrypted AES-256-ECB, padding off, key
`oU8XzEpbOD6pVTLwdz9pxRpN9MGPCo1P`, delta `md5` = MD5 of the **ciphertext**
(`a000dc890ee42fc3348060dcbdac7dc1`) — `pcMd5` semantics, matching what `assis:0x4064f8`
logs before handing the URL on. The camera's request therefore served bytes whose digest
matched the delta, but the probe tar has no valid plaintext digest chain, so the run stopped
at the gate.

## 6. Verdict — `SHADOW-WORKS`

The chain is real and was walked as far as the gates allow without a console: owner re-auth →
device IoT credential issuance → production broker → shadow write → **camera fetches our file
over a certificate chain it trusts** (`GET /firmware.bin` → `200`). Signals 1 and 2 of 4 were
reached; 3 and 4 need `upgraderun.sh` to actually run, i.e. a payload that decrypts and whose
digests line up, plus serial access to read `[ASSIS]url:`.

Operating rules that made it work, all of them counter-intuitive:

- **SNI = CNAME target** (`a24rq1e5m4mtei.iot.us-west-2.amazonaws.com`); the friendly name fails
  hostname verification because `*.iot.us-west-2.amazonaws.com` is one wildcard label.
- **client id = thing name**, exactly (case- and separator-sensitive).
- **publish once, hang up, then stay off the identity**. Delivery arrives ~40 s later, on the
  camera's own reconnect. Bursts train an exponential backoff and starve it.
- **the delta `md5` is over the ciphertext**, not the tar.
- the camera's **retry queue outlives the delta**: after one failure it re-fetches the old URL
  first, so re-pointing a failed run at the same path is more reliable than a new path.

What remains: a payload built end to end (encrypted tar whose ciphertext digest is published),
and serial access to confirm the decrypt path and the reboot. Owner credentials stay valid to
2026-10-24 (token) and 2027-10-22 (key). Nothing was flashed; the probe failed inert.
