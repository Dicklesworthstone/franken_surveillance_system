# EV pack H-003 — owner-account `local_key` retrieval + `0x1A` shape/digest discrimination

Scope: `local_key` for the owner HomeBase `H2E2DA110000807` (192.168.4.37) from the owner's own
AOSU/Glazero cloud account; if obtained, drive `0x1A` on TCP 6668 under a Tuya 3.5 session to
discriminate body shape (A/B) and record the wrong-`md5` status. No flash.

**Verdict: KEY-ABSENT (AOSU app API) — SHAPE UNTESTED.**
The AOSU cloud API returns no `localKey`, `devKey`, `seckey`, `uuid`, `gwId`, `devId` or
`productKey` on any reachable endpoint. Device identity in this API is `sn` + `snCoop` only.
Keys live on the Tuya OEM channel (`a1-us.iotbing.com`), which is app-signed; the session could
not be opened under the AOSU app identity (§4). No authenticated 6668 session therefore exists to
drive `0x1A`, so neither shape is confirmed. The previously observed blind behaviour (silent 0-byte
hold for every command, incl. `0x1A`) is unchanged.

---

## 1. What was done

Owner credentials from `~/.config/fss-lab/aosu.env` (values never printed). Authentication ran over
the live AOSU app API; all calls are owner-authorized and read-only.

### 1.1 Host and login recovered from the capture
- Host: `https://api-us.aosulife.com` (`~/.config/fss-lab/flows/cam-20261007T124425.flows`, flow
  index with `request.path=/v1/user/login`).
- Login: `POST /v1/user/login?uuid=<UUID>&t=<ms>`,
  body `countryAbbr=US&countryCode=1&email=…&password=<AES b64>&pwType=2&region=us&type=1`.
- The captured login ciphertext is deterministic: replaying it returns `errno 0` and the same
  `sid` (`a8097b8d…`, prefix only) — the session token is stable per account, so no password
  re-encryption was needed.

### 1.2 A new finding: `gz-sign` is not enforced
Replaying the captured `getList` with `gz-sign` omitted entirely returns `errno 0`. An expired
session instead returns **`errno 202 "sid过期"`**, so the only gate is the `gz-sid` value. Every
endpoint below could therefore be probed without deriving the sign algorithm
(`md5`-over-path variants were tried offline against two known pairs and do not match).

---

## 2. Endpoints tried (homebase `H2E2DA110000807`, plus one camera `C8S2EA110002358`)

Live `getList` first — full inventory, 5 devices, no keys:

| endpoint | body | errno | key material? |
|---|---|---|---|
| `POST /v1/dev/getList` | — | 0 | no (`devAttr`, `support`, `extend` only) |
| `POST /v1/dev/getInfoBySn` | `sn=<hb>` | 0 | no — returns the 4 child cams, no keys |
| `POST /v1/dev/getInfoBySn` | `sn=<cam>` | 0 | no |
| `POST /v1/dev/getInfoByCode` | `code=<sn>` | 0 | no |
| `POST /v1/dev/getInfoBySSID` | `ssid=HomeBase` | 0 | no |
| `POST /v1/dev/getModelInfoBySn` | `sn=<hb>` | 0 | no (bind email masked, model, devType) |
| `POST /v1/dev/getSnType` | `sn=<hb>` | 0 | no |
| `POST /v1/dev/getListByCoopUUIDList` | `coopUUID[]=<sn>` | 0 | no |
| `POST /v1/dev/capability` | sn/devSn/JSON | 410002 | params unknown, no keys |
| `POST /v1/appSetting/getBySn` | `devType=3&model=H2E&sn=<hb>` | 0 | settings tree only |
| `POST /v1/app/getConfig` | — | 0 | no (client config only) |
| `POST /v1/sts/getPlayInfo` | `type=tuya\|p2p&rtmId&rtcId&sn[]&refresh` | 0 | `tokenRtm` empty, no key |
| `POST /v1/sts/getMultiMqttInfo` | `type=…&sn[]` | 0 | `mqttInfoList` empty |

404 (route does not exist on this host), 14 paths × 4 bodies, all `404 page not found`:
`/v1/dev/{getDetail,getInfo,get,getBySn,getKey,getLocalKey,getDevInfo,detail,getAttr,query,getSecret,getToken,getConnectInfo,getStatus}`;
plus `/v1/{user,tuya,account,dev}/{getTuyaInfo,getTuyaToken,getTuya,getTuyaSid,getTuyaUser,tuyaLogin,getThirdToken,getToken,getEc,getEncryptCode,getSid,refreshSid,getTuyaAccount,getAccount}`.

Route list cross-checked against the shipped app (`classes11/15/16.dex`): the only `dev/*` verbs
the app itself calls are the ones above — there is no device-detail route carrying secrets.

---

## 3. Where the key actually lives

`DEVICE_ADAPTER_MATRIX.md` already records it: device keys ride the encrypted Tuya OEM channel
(`a1-us.iotbing.com/api.json`), keyed at app login. Confirmed again: all 36 `api.json` calls in the
capture are `postData`-encrypted; the plaintext route (`a=…`) is rejected
(`ILLEGAL_CLIENT_ID` / `API_OR_API_VERSION_WRONG`), so `tuya.m.device.get` cannot be read off the
capture without the app's signing material.

---

## 4. Tuya-side attempt (why it did not close)

Signing material was extracted from the current public Android build (`com.glazero.android`,
`classes`+`arm64` splits):
`THING_SMART_APPKEY=7hvgpakg784c3pj5qe3e` (prefix), `THING_SMART_SECRET` (32 chars, from
`AndroidManifest.xml`), signer certificate SHA-256 from the APK Signing Block
(`2de8fc7e…`), plus `assets/fixed_key.bmp`.

Results against `https://a1-us.iotbing.com/api.json`:

- AOSU identity (manifest appKey + app secret + app cert): **`ILLEGAL_CLIENT_ID "Invalid client;No access"`**
  for every action shape tried (`m.life.home.space.list`, `thing.m.user.third.login`), with and
  without `clientId`, `bundleId`, `bizDM`, `et=3`/`et=0.0.2`, and with a deliberately broken
  signature (broken signature produces the same error ⇒ the host resolves the client *by signature*,
  so appKey is not the client identity by itself).
- Known-good control: SmartLife profile (`ekmnwp9f…`) against the same host with the captured Tuya
  `sid` **passes the signature check** and returns `{"t":…,"sign":…,"result":…}` for
  `m.life.home.space.list`. The result does not decrypt under the derived key (session-bound
  `ecode` was minted for the AOSU client) and `et=0.0.2` answers `not ok`. So the AOSU account's
  Tuya session is reachable but unreadable.
- `thing.m.user.third.login` with the AOSU `sid` as access token: `THIRD_API_INVOKE_EXCEPTION`
  (jwt) / `UNKNOWN_THIRD_PLATFORM` (other types) — no fresh `sid`+`ecode` minted.
- Email/password login at Tuya with the owner's AOSU password: `USER_PASSWD_WRONG` (the Tuya
  account password is set independently at AOSU registration).

Open sub-item, carried forward: the 32-char `app_key` token is steganographed in
`assets/fixed_key.bmp`. The current SDK reads it with a bit-plane decoder
(`read_keys_from_content` in `libthing_security_algorithm.so`, `0x4abc`/`0x4c70`/`0x52 6c`: header
byte 0/1/2, then bit-decoded length-prefixed coefficient blocks, `idx=(hash(key)%len)/2`). A
Python re-implementation of that layout parses the 2019-vintage `test.bmp` fixture but no offset in
the shipped `fixed_key.bmp` yields a plausible header (0 of 22 500 positions), so the shipped file
uses a further transform that was not cracked in this pass.

---

## 5. `0x1A` test status

No key ⇒ no session key ⇒ every `0x1A` frame is a pre-session frame against `ALLOW_NO_KEY_NUM 3`.
That measurement already exists (`EV-pack-H-003` §"Consequence for the blind drive"): `0x1A` with a
24-byte body holds the socket, 0 bytes returned — indistinguishable from a bogus command, because
dispatch happens after GCM verification. Nothing new was flashed or reset in this run.

Body shapes queued for the first keyed attempt (unchanged, for the next run):
- **A** — JSON descriptor `{"type":..,"size":..,"httpsUrl":..,"hmac":..,"md5":..}` (512 B is ample).
- **B** — 24-byte `len:u32be|crc32:u32be|md5[16]`.

Expected signature of a *shape* decision: retcode **1** + ASCII reason = wrong shape; silence then a
late OTA status = shape parsed; digest rejection surfaces as **45** (download) or **49** (upgrade).
Budget: at most 3 pre-session frames; negotiate first, then stay under the session key.

---

## 6. Reproduce

```
# host is public, sign is optional, sid is stable
curl -s https://api-us.aosulife.com/v1/user/login?uuid=<UUID>&t=<ms> \
  -H 'gz-appid: com.glazero.ios' -H 'gz-pid: glazero' \
  --data 'countryAbbr=US&countryCode=1&email=<e>&password=<captured b64>&pwType=2&region=us&type=1'
curl -s 'https://api-us.aosulife.com/v1/dev/getList?uuid=<UUID>&t=<ms>' -H 'gz-sid: <sid>'
curl -s 'https://api-us.aosulife.com/v1/dev/getInfoBySn?uuid=<UUID>&t=<ms>' -H 'gz-sid: <sid>' --data 'sn=H2E2DA110000807'
```

Secrets used but not printed: `aosu.env`, captured `gz-sid`, Tuya app key/secret.
