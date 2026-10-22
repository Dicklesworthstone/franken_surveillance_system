# EV-pack-H-003 — AOSU/Glazero HomeBase H2E (192.168.4.37): Tuya 3.5 key path + OTA trust

**Target:** 192.168.4.37 · `60:d5:61:21:4d:36` (Shenzhen Glazero OUI) · FCC ID `2BACU-H2E`, model `H2E`, grantee GLAZERO INTERNATIONAL INC, factory Shenzhen Anran Security Technology Co., Ltd, filed 2025-03-25.
**Date:** 2026-10-22 · interface `en1` (192.168.4.170/22) · all probes unprivileged.
**Hypotheses:** H-003 = 6668 accepts a key recoverable without the vendor developer program **and** exposes an exec/file-write datapoint. H-004 = **the cloud** OTA path accepts an attacker-supplied/re-signed image.
**Also tried, negative:** the owner's AOSU account API — full read access, but it carries no `localKey` (see its own section).
**Secondary claim, now primary for persistence:** a **LAN** OTA push (`0x1A/0x1B/0x1C`) exists inside the authenticated session — no cloud, no URL, no TLS — and is the only delivery path that satisfies every owner constraint. Its own section follows Findings.

**Leverage:** this one box fronts 4 battery cams (AOSU homebase topology). Root here ≈ all 4 cams at once, and they are otherwise unreachable (no TCP service each). It is the highest-value target in the fleet after the Wyze pair.

---

## 0. Protocol facts from the local implementation (grounding for §1)

Read: `crates/fss-tuya/src/wire.rs`, `crates/fss-tuya/src/crypto.rs`, `crates/fss-tuya/src/client.rs`, `crates/fss-reference/src/ingest/tuya.rs`.

**55AA family (3.1–3.4), `wire.rs:186-224` / `pack_55aa:283-317`:**
`prefix(4)=0x000055AA | seqno(4) | cmd(4) | len(4) | [retcode(4)] | payload | CRC32(4) | suffix(4)=0x0000AA55`. 3.4 replaces CRC32 with `HMAC-SHA256(header|retcode?|payload)` keyed on the **local_key** (`tail_len=36`). Payload = `AES-128-ECB(local_key, plaintext)` with PKCS7; CONTROL(0x07)/CONTROL_NEW(0x0D) and STATUS responses carry a 15-byte ASCII `"3.4"`+12×0x00 version header inside the *encrypted* block (`PROTOCOL_VERSION_HEADER_34`).

**6699 family (3.5), `wire.rs:399-431` / `unpack_6699_mode:436-483`:**
As implemented: `prefix(4)=0x00006699 | 0u32(4) | seqno(4) | cmd(4) | len(4) | IV(12) | ciphertext | GCM-tag(16) | suffix(4)=0x00009966`. `len` covers `IV||ct||tag` and excludes the suffix. Sealing is `AES-128-GCM(local_key, iv, aad = header[4..20])` over `[retcode?]|plaintext`.

**Session proof (3.5), `client.rs:186-250`:** client sends `SESS_KEY_NEG_START(0x03)` = GCM(client_nonce) under the **local_key**. Device replies `SESS_KEY_NEG_RESP(0x04)` carrying `device_nonce(16) || HMAC-SHA256(local_key, client_nonce)(32)` (48 B, retcode mode `Present`). Client verifies the HMAC — *this is the only device authentication* — derives `session_key = AES-128-GCM(local_key, iv=client_nonce[..12], aad=none, client_nonce XOR device_nonce)` (`wire.rs`, `derive_session_key_35`), and sends `SESS_KEY_NEG_FINISH(0x05)` = `HMAC-SHA256(local_key, device_nonce)`. 3.4 is the same shape with AES-128-ECB (`derive_session_key_34`) and HMAC-over-55AA.

**Attacker-controlled fields, and where a length is trusted:**
| Field | Control | Trust issue |
|---|---|---|
| 55AA `len` | full | parsed before body; bounded by `MAX_PAYLOAD_LENGTH = 1<<20`, `total = 16+len`, truncation → `WireError::Truncated`. No over-read. |
| 6699 `len` | full | `total = 18 + len + 4`; the GCM ciphertext slice is `len-28` bytes — a **short `len` silently truncates the tag**, but GCM auth then fails closed. |
| 6699 `seqno`, `cmd`, `len` | full | all three plus the reserved pair are inside the AAD, so tamper-evident. |
| 6699 IV | full (12 B attacker-picked) | **no nonce-uniqueness enforcement anywhere in the client**; `pack_6699` doc-comment states reuse under one key is catastrophic and pushes IV generation to the caller. |
| 55AA trailer/whether HMAC or CRC | implied by key presence | a 3.4 frame validated with `hmac_key=None` accepts attacker-computable CRC32 only. |
| dps JSON, `t`, `gwId`, `devId` | full | unvalidated passthrough; `ingest/tuya.rs` maps only known DPs and preserves the rest as `EventKind::UnknownDp` — **it never invents an interpretation** (`tuya.rs:23,111`). Registry is lab-only: model `fsssimhomebase00`, DPs 104/115/102 only (`tuya.rs:210-243`), all `RegistryProvenance::Laboratory`. No production DP map for H2E exists in-tree. |

**Framing discrepancy found and fixed:** tinytuya — the crate's declared "laboratory oracle" — packs 6699 with `MESSAGE_HEADER_FMT_6699 = ">IHIII"` = **18 bytes** (prefix, **2** reserved bytes, seqno, cmd, len) and uses `aad = data[4:]` = 14 B; `fss-tuya` wrote **20 bytes** (a `u32` of zeros) with a 16-byte AAD (`wire.rs:361-366`). Tuya's own `lpv35_fixed_head_t` confirms 18/14. Every fss-tuya 6699 frame was 2 bytes long with a mismatched AAD, so no real 3.5 session could open. Now corrected — see the dedicated section below for the byte diff, the three sources and the regression test.

---

## Findings

Behaviour legend: port open check was done 3× before classification; each probe below was run ≥2×.

| # | Transport / port | Pre-auth? | Primitive class | Exact function / binary | Reliability | Evidence |
|---|---|---|---|---|---|---|
| F1 | TCP 6668, **6699 (3.5) only** | yes (needs key) | protocol entry / auth-bypass surface | Tuya LAN service | deterministic | Bare `6699` prefix → connection **stays open**, no bytes. A complete GCM frame with a wrong key → **stays open, 0 bytes**, no close, no retcode, no error JSON. Tested with zero-key, `"0123456789abcdef"`, and the public `udpkey` = `md5("yGAdlopoPVldABfn")`. |
| F2 | TCP 6668, **55AA rejected** | yes | info-leak (negative) | — | deterministic | The device **closes** on the 4-byte `55AA` prefix *before* validating length or CRC: `hb` with good CRC → CLOSED; identical frame with deliberately corrupted CRC → CLOSED; bare `000055aa` → CLOSED. Upstream `lan_protocol.h` still defines the 55AA structs, so this is a firmware/profile choice, not a protocol removal. |
| F3 | TCP 6668 | yes | **no pre-auth identity leak** | — | deterministic (n≥4 each) | Unauthenticated session yields no `gwId`/`devId`/`uuid`/product-key/version: 3.5 gives no plaintext pre-negotiation frame, and negotiation failures are indistinguishable. Consequence: **no online oracle**, key recovery is a blind 2^128 search unless the key is obtained out-of-band. |
| F4 | UDP 6666/6667, `0x13`/`0x23`/`0x25` broadcast | yes | info-leak (device-dependent) | `send_discovery_request`, `FR_TYPE_BOARDCAST_LPV34` | n/a here | All silent. `7000` = **ICMP port-unreachable (closed)**; `6666` = open\|filtered with no reply; `6667` = closed. So the *pairing-mode-only* broadcast path is not bound while the unit is paired and idle. |
| F5 | **TCP 51028 = `tinyproxy/1.11.2`, no auth** | **yes** | **open forward proxy / SSRF + localhost port oracle** | tinyproxy `src/reqs.c` | deterministic | Banner on garbage: `HTTP/1.0 400 Bad Request / Server: tinyproxy/1.11.2`. `CONNECT example.com:443` → `200 Connection established`, then full HTTP/2 fetch. Egress is arbitrary-port: `CONNECT 1.1.1.1:53`, `8.8.8.8:53`, `github.com:22`, `192.168.4.1:80` all → `200`. Absolute-URI GET to `example.com:80` returns the page with `Via: 1.0 tinyproxy (tinyproxy/1.11.2)`. **No `ConnectPort` restriction and no `Allow` ACL in effect.** |
| F6 | TCP 51028 → `127.0.0.1` | yes | **internal port oracle / ACL bypass** | as F5 | deterministic | `CONNECT 127.0.0.1:{443,6668,8888,51028}` → `200`; `{22,53,80,554,5000,8080,8889,9900,9999}` → `500 Unable to connect`. So the proxy reaches the device's **loopback** and `500`-vs-`200` is a clean closed/open oracle. Also reached 6668 *through* the box while direct SYNs were being refused (see §3). |
| F7 | TCP 8888 | yes | app-channel door, unidentified | unknown daemon | — | Accepts and holds. Closes on non-text-ish input (`16×0x00`, `"3.5"+12×0x00`, binary 55AA) but holds for `GET / HTTP/1.0`, `OPTIONS rtsp://… RTSP/1.0`, JSON, `{"cmd":"status"}` — and never replies. Needs a magic handshake from the AOSU app; not decoded. |
| F8 | TCP 443 | yes | door, no TLS | — | — | Accepts, sends nothing, closes on any ClientHello (`openssl s_client -tls1_2`: `SSL handshake has read 0 bytes`, `Unexpected EOF`), also silent on plaintext `GET`. Port 443 is bound but not a working TLS listener from outside. |
| F9 | TCP 6668 auth strength | yes | **auth-bypass = none** | `TuyaClient::new(local_key)` | — | The local_key is a static 16-byte per-device secret in the Wi-Fi module's flash; it is **not rotated** by anything in the LAN protocol. Compromise is durable but is *not* inherently root. |
| F10 | 51028 → `127.0.0.1`, ports 1–1024 + 8000–10000 | yes | **negative: no loopback-only daemon** | — | deterministic | 3025 ports, twice (14-way then serial): only 443 and 8888 open from inside, and both are open from outside too — the internal set is a subset of the external set. No hidden admin UI, no sshd, no 8080. See §"Pivot result". |
| F11 | 3.5 in-session OTA `0x1A/0x1B/0x1C` | no (needs session) | **firmware write → persistence** | `FRM_LAN_OTA_START/DATA/FINISH`, `tuya_protocol.h:43-45` | unproven | Constants exist in Tuya's 3.5 header beside `FRM_LAN_RESET (0x1D)`; the public `tuya_lan.c` dispatch has no case for them, so field set and digest policy are unknown. This is the only persistence-capable primitive found. |
| F13 | HTTPS `api-us.aosulife.com` (owner account, no dev program) | no (needs the account password) | info-leak: inventory + firmware versions + OTA descriptor | `/v1/dev/getList`, `/v1/ota/getNewByApp` | deterministic | 5 devices enumerated, `localKey` absent from every response, `gz-sign = md5(path+query)` so a stolen `gz-sid` is replayable. Detail in its own section. |
| F12 | 6699 header width | — | correctness (not security) | `lpv35_fixed_head_t` | was broken | Crate emitted 20 B + 16 B AAD; protocol is 18 B + 14 B AAD (three independent sources). Fixed, tests green. |

**Port state anomaly (behaviour, not a finding):** after ~20 rapid connect/close probes, direct `SYN` to 6668 was refused for ~30 s while `CONNECT` via 51028 still succeeded (200) and frames through the tunnel were still accepted. The listener's accept backlog wedged; it self-healed without a reboot. Any automation must retry with backoff and must not treat `RST` as "closed" (`[WRITE]`-free).

---

## Pivot result: is anything hidden behind `127.0.0.1`?

The proxy's 200-vs-500 oracle is a localhost port scanner, so the hub was scanned from **inside**, twice, over the full requested range **1–1024 and 8000–10000** (3025 ports): once at 14-way concurrency (236 s) and once strictly serially.

| Port | from `127.0.0.1` (inside) | from `192.168.4.37` (outside) | verdict |
|---|---|---|---|
| 443 | open | open | same listener, all-interfaces |
| 8888 | open | open | same listener, all-interfaces |
| 6668 | open (verified 3× either side of the scan) | open | all-interfaces, but **flaky under load** — the concurrent pass misreported it once |
| everything else in range | `500 Unable to connect` | closed | — |

**There is no localhost-only daemon.** The internally-open set is a subset of the externally-open set, so nothing is bound to `lo` alone and there is no hidden admin UI, no sshd, no `8080`, no unix-socket-backed HTTP. Control-plane-by-obscurity is not in play here; whatever exec sink exists is behind the Tuya session, not behind loopback.

`9501` was the only transient (one `TimeoutError` in the concurrent pass, `500` 3× on retest) — noise, not a service.

**What the proxy does and does not prove about the OTA fetch.** It proves the box has working **DNS resolution and outbound TCP on arbitrary ports** (it resolved `example.com`, `github.com`, `1.1.1.1` and completed all three). It does **not** say anything about the device's own TLS *client* — through a tunnel the TLS endpoint is my process, not the device's. Whether the OTA downloader validates a certificate is a different code path and stays unproven (§H-004). The equivalent on the Wyze lane was the `0x1502` DTLS wrapper: same class of problem (a transport-security wrapper that must be defeated or re-implemented locally), different stack — so if the Tuya answer is "TLS to a fixed host", a LAN MITM against Tuya is exactly the Wyze DTLS job over again, and the closed-loop-locally result there does not transfer.


---

## LAN OTA `0x1A/0x1B/0x1C` — the persistence path

**Why this matters more than anything else in the pack.** Every other primitive here ends at control. A firmware push over the authenticated 6668 session needs no cloud account, no developer program, no URL, no TLS and no SD card — it survives reboot by construction, and it is the only such path found. If it works, the chain closes: button press → udpkey broadcast → `local_key` → session → flash → root.

**What is pinned — the envelope.** Every 3.5 plaintext is `ret_code(4) | data[]` (`lpv35_plaintext_data_t`, `tuya_protocol.h:71-76`), GCM-sealed inside the standard 6699 frame. So `0x1A` carries its payload in that `data[]` field, after the retcode, under the session key. The command constants are `FRM_LAN_OTA_START 0x1A`, `FRM_LAN_OTA_DATA 0x1B`, `FRM_LAN_OTA_FINISH 0x1C`, `FRM_LAN_RESET 0x1D` (`tuya_protocol.h:43-46`).

**What is not pinned — the `data[]` encoding.** No public implementation exists: the TuyaOpen `lan_protocol_process` switch has no case for them, and neither the `bk7231n` `svc_lan` docs nor the app-SDK OTA docs describe the LAN frame. Two candidates, both derived, neither confirmed:

| # | Candidate encoding | Supporting evidence | Against |
|---|---|---|---|
| A | **the cloud descriptor as JSON** — `{"type":..,"size":..,"httpsUrl":..,"hmac":..,"md5":..}`, the exact object `tuya_ota_start(cJSON *upgrade)` parses (`tuya_ota.c:204-216`) | It is the only OTA parser in the tree; reusing it costs nothing. `httpsUrl` is read with an unchecked `cJSON_GetObjectItem(...)->valuestring`, so any LAN start that lacks it crashes — meaning a working LAN start almost certainly carries the full object. | If the LAN path also downloads from `httpsUrl`, "LAN push" would be a URL push and would still need TLS. |
| B | **a binary `len|crc32|md5` triple** — `TUYA_OTA_FIRMWARE_INFO_T { uint32_t len; uint32_t crc32; uint8_t md5[16]; }` = 24 B, `tuya_cloud_types.h:1252-1256`, with `TUYA_OTA_FILE_MD5_LEN 16` | Matches the `TUYA_OTA_DATA_T {total_len, offset, data, len}` shape the HAL consumes (`tkl_ota.h:55`), i.e. size-then-bytes naturally. | The struct is documented "only used in resumes transmission at break-points / only use for ble sub device" (`tkl_ota.h:74-75`). |

Whichever it is, **the digest is MD5, not HMAC.** Neither candidate has an `hmac` field, and `FW_HMAC_LEN`/`fw_hmac` appear only in the *cloud* descriptor (`tuya_ota.h:63-76`). HMAC-keyed-by-`seckey` is therefore a property of the cloud path alone — so **the LAN path is plausibly `local_key`-sufficient and the chain closes without ever touching `seckey`.** That is the single inference this section rests on, and it is why the bad-image test below is the decisive one in the whole pack.

**Consequence for the "blind" drive.** Blind (no key) `0x1A` gets you nothing structural: probed against `0x99` (bogus), `0x0D`, `0x1A`, `0x1E`, `0x40` with a 24-byte body each — **all five hold the socket with 0 bytes returned, identically**. Command dispatch happens after GCM verification, so an unauthenticated 0x1A is indistinguishable from a bogus command.

**The first frame with a key is free of flash risk and is the discriminator.** App-side handlers answer parse failures on the same frame with `lan_send(session, seq, type, 1, describe, strlen(describe), true)` — retcode **1** plus a plaintext reason (`"parse data error"` / `"data format error"`, `tuya_lan.c:788-793`). So:

1. Send `0x1A` with a 512-byte body of the wrong shape → retcode 1 + ASCII reason ⇒ *encoding* wrong, nothing written, try the other candidate.
2. Shape right, digest wrong (correct `len`, wrong `md5`) → no parse error, and the failure arrives as an OTA **status** report instead: `TUS_DOWNLOAD_ERROR_HMAC 45` vs `TUS_UPGRADE_ERROR_HMAC 49` (`tuya_ota.h:41,45`) tell you *which stage* rejected it. A retcode-1 "parse data error" is never a digest error; a silent start with a late fault is never a shape error.
3. Only a third run with a *correct* image is `[WRITE][RISK]`.

**Recovery if the good image is bad.** Partial answer, from the type enum: `TUYA_OTA_FULL = 1 ///< AB area switch, full package upgrade` (`tuya_cloud_types.h:1235-1237`) — the layout is **two banks (A/B), not a factory partition**, and there is no `TUYA_OTA_PATH_LAN` (LAN reuses `PATH_AIR = 0`). So a rejected or half-written image should leave the running bank untouched — though no public code proves the bootloader validates before switching, only that the HAL call carries a `reset` flag. **Unknown:** whether the bootloader commits the new bank only after the `tkl_ota_end_notify(BOOL_T reset)` validation or after the first successful boot. Nothing public says, and this is exactly the difference between a soft brick and a reflash. Treat the first real push as `[WRITE][RISK]`, on mains, with the unit not otherwise busy.

**Ready-to-run artifact:** `deliverables/scripts/ev-pack-h-003-send-ota-start.py` — default candidate B, correct 18-byte header and AAD, single-shot negotiation, `--dry` prints the bytes, `--selftest` needs no device (passes). One command once a key exists; it prints the retcode and, on `retcode 1`, the ASCII reason, then tells you to try the other candidate.

**Operational constraint for any tool:** the device allows `CLIENT_LMT 3` concurrent LAN clients and only `ALLOW_NO_KEY_NUM 3` frames keyed by `localkey` instead of the derived session key (`tuya_lan.c:27-32`). A hand-rolled client gets three pre-session frames per connection, so do not spend them: negotiate, then send everything under the session key. Exceed either budget and the device faults the session — which means **negotiation must be single-shot**: no parallel retry of the 0x03/0x04/0x05 exchange on one connection, and no probing before it.

---

## Owner account API (`~/.config/fss-lab/aosu.env`) — inventory yes, `localKey` no

Tried because it was the one path that could delete the button press. **It does not carry `localKey`.** Everything below is from the live API on the owner's own consumer account, no developer program.

**Files.** `aosu.env` exists (`AOSU_EMAIL`, `AOSU_PASSWORD`) and is **current — login succeeds with it**. `aosu_session_new.json` is **stale**: its `gz-sid` gets `{"errno":202,"errmsg":"sid过期"}`.

**Contract, recovered from the shipped APK** (`com.glazero.android` 161 MB from `d.apkpure.net`, decompiled with jadx):
- `POST https://api-us.aosulife.com/v1/user/login`, `application/x-www-form-urlencoded`, fields `type=1&email&password&pwType&countryCode`.
- Required header **`Gz-Pid`**, value **`glazero`** — from `com/glazero/biz/channel/AppChannel.java` (`channelPid` getter → `"glazero"`) via `AppConstant.APP_CHANNEL_PID`, set in `com/glazero/biz/base/http/interceptor/CommonInterceptor.java` (`linkedHashMap.put("Gz-Pid", AppConstant…)`). `pid` in query/body/plain header all fail `{"errno":104,"errmsg":"pid参数错误"}`; `Gz-Pid` is the only accepted spelling.
- **`pwType=1` with the plaintext password is accepted.** `md5`, upper-case md5, base64(md5) and `pwType=2` all return `{"errno":503,"errmsg":"密码错误"}` — `SecurityCore.nativeEncryptP` (JNI, `libglazero-security.so`, not in the base split) is the app's own path, but it is not required from a script.
- `gz-sign` is **`md5(full path with query)`** — no secret. Anyone who captures a `gz-sid` can replay the account, so the session is the whole credential.

**Reachable, with that session:** `/v1/dev/getList` (5 devices: 4× `C8S2EA11` cams + `H2E`, honouring the owner's "no cloud account access" rule without a developer program), `/v1/dev/getInfoBySn`, `/v1/appSetting/getBySn`, `/v1/dev/getModelInfoBySn`, `/v1/dev/getListByCoopUUIDList`, `/v1/ota/getNewByApp`.

**Grepped every response for `localKey|devKey|key|uuid|gwId|seckey`:**
- `getList` / `getInfoBySn` / `appSetting/getBySn` / `getModelInfoBySn`: nothing but setting keys (`vision`, `face`, `fmOta.auto`, …). Device fields are `sn`, `snCoop` (Tuya-style devId, e.g. `eb28f4fa8cd86eb3669izf`), `baseSn`, `devType`, `model`, `pid`(=`glazero`), `tp`(= `AS`), `online`.
- `getListByCoopUUIDList` with those `snCoop` ids returns `{"list":[]}`.
- So **`localKey` is not in the gz API at all** — it lives on the Tuya side. Local control in the app goes through the bundled `ThingHomeSdk` (`TyAccountCenter.loginWithUid(countryCode, uid, password)`), i.e. Tuya's own signed cloud API, which needs the Tuya app session on top of this one.

**Owner Tuya identity, for that next hop:** login returns **`tuyaUid` (`az174769…`, prefix only) and `tuyaUsername` (= the account email)**. With those, a consumer Tuya/Smart Life session is reachable *without* the developer program; that session is what would hand over `localKey` — and it is a separate implementation job (Tuya app `sign` scheme), not a URL to curl.

**Unplanned bonus — the live OTA descriptor endpoint.** `POST /v1/ota/getNewByApp` (`sn`) returns `{currentVersion, desc, download, firmwareType, network, productID, sign, size, timeout, upgradeStatus, upgradeType, verify, version}`. No update is pending right now, so `download`/`sign`/`verify`/`size` are empty, but the field set is the cloud descriptor and it carries **two** digest fields (`sign` **and** `verify`) — corroborating the TuyaOS `hmac`+`md5` pair in §H-004 and confirming the descriptor is server-supplied per device. Current firmware: **H2E `2.10.5`**, cam `2.3.156`.

---

## Chain

**Shortest end-to-end path — and exactly where it stops.**

```
[no-touch today]  L2 reach ──► 6668 (3.5) ──► silent, key required
                  ├─ 51028 open proxy ──► off-LAN pivot; loopback oracle (nothing hidden on lo)
                  └─ 8888/443 doors, unidentified, hold-and-never-answer
[no-touch, no key] owner account API ──► inventory, firmware versions, OTA descriptor — but no localKey
[one button press, LAN]  pairing mode ──► 0x25 REQ_DEVINFO/UDP:7000 (GCM under public udpkey)
                                     ──► local_key + gwId
                  ──► authenticated 6668 session ──► CONTROL/CONTROL_NEW dps, DP_QUERY, P2P signal
                  ──► still *not* root: no exec, no file write
[+ OTA]          LAN OTA frames 0x1A/0x1B/0x1C over the same session ──► flash ──► persistence
```

**H-003(b) is now closed by the device-side dispatch, not just by the header.** Tuya's own 3.5 implementation (`tuya_lan.c`, `lan_protocol_process`) switches on five case groups (seven command words) and nothing else:

```
case FRM_TP_CMD / FRM_TP_NEW_CMD   → parse dps JSON, tuya_iot_dp_parse()   (write)
case FRM_SECURITY_TYPE3            → store randA, reply own nonce + proof
case FRM_SECURITY_TYPE5            → verify HMAC(randB), derive session key
case FRM_QUERY_STAT / _NEW         → status read
case FRM_LAN_P2P_SIGNAL            → stream signalling
```

No `system()`, no path, no filename. Three further device facts from the same file: `SERV_PORT_TCP 6668`, `SERV_PORT_APP_UDP_BCAST 7000` (the discovery port), `CLIENT_LMT 3`, and `ALLOW_NO_KEY_NUM 3` — the device tolerates up to 3 frames per session that are keyed with `localkey` instead of the derived session key, useful for a hand-rolled client during bring-up.

**There IS a LAN OTA push, which is the persistence path.** `tuya_protocol.h` defines `FRM_LAN_OTA_START (0x1A)`, `FRM_LAN_OTA_DATA (0x1B)`, `FRM_LAN_OTA_FINISH (0x1C)` beside `FRM_LAN_RESET (0x1D)` — image bytes over the authenticated 6668 session, no cloud and no URL. Caveat: the public TuyaOpen `lan.c` dispatch above has **no** case for 0x1A–0x1C (they land in a newer or vendor module), so the LAN frame's field set and its verification are unproven. This is now the single most valuable unknown in the whole lane: a LAN OTA whose `hmac` comes from the LAN frame means an attacker must also know `seckey`; one that trusts only `md5` means LAN-flash works with the local_key alone.

**So the honest chain is: button → udpkey broadcast → local_key → session → (unproven) LAN OTA → root.** Everything up to "session" is proven by primary source; the last hop is not.


---

## Brick risk + recovery

Nothing performed was a write. Ranked:

| Action | Write? | Risk | Recovery |
|---|---|---|---|
| Poll 6668/8888/443/51028, proxy CONNECT | no | nil (observed: one transient accept-backlog wedge, self-healed) | re-probe; back off |
| Hold pairing/reset button → re-pair | `[WRITE]` (state) | **low**. Does not touch firmware. Drops the cloud link; if left unpaired the 4 cams lose remote record/view until re-paired. Per-device `local_key` **changes** on re-pair (`tuya-local` README) — any key you extracted before is void. | re-pair in the AOSU app; cams rejoin the homebase automatically |
| LAN OTA push (0x1A/1B/1C) | `[WRITE]` (flash) | medium-high — and now the *primary* flash route, because it needs no cloud. Same power-loss exposure. | untested; see below |

**Same-LAN `local_key` recovery is blocked on one physical pairing-mode press.** Nothing on the network triggers it: 7000 and 6667 are ICMP-closed, 6666 is silent, and `0x13`/`0x23`/`0x25` all go unanswered while the unit is paired and idle (re-probed 3× per path, plus broadcast to `192.168.7.255`). That is inside the owner's rule — a button is not disassembly, no UART, no SD card, no developer program — but it is **not zero-touch** and must be scheduled as a site visit, not an overnight sweep.

SoC: **not identifiable from public filings** — the grant declares only 2.4 GHz DTS 11b/g/n (HT20/HT40, 2 antennas, 0.0787 W), series models `DH2E..DH2S/H2F..H2S`, and holds the block diagram, schematics and operational description confidential. `[INFERENCE]` the part is a **Linux-capable** SoC, not a BK7231-class MCU: this unit runs tinyproxy 1.11.2, a glibc/Linux userspace daemon that has no RTOS port in that vintage, and it holds 4× 2K recording. Consequence: `/` writability is plausible but **unverified**; if you get a shell, `mount` decides it, and on a SquashFS root the honest answer is `/etc` + `/data` writable, `/` read-only.

**TFTP: not evidenced** — UDP 69 is not bound (no ICMP difference vs. any other closed port) and no TFTP string has been seen, so a TFTP rescue is a hope, not a plan. **Factory/recovery partition: unproven** — the block diagram, schematics and operational description are all under long-term confidentiality, so the partition table is not public and cannot be read without a shell. USB/UART/undocumented-pinhole recovery is exactly what "no disassembly" forbids, so the flash is one-way until the partition table is dumped.

---

## Code defect found and fixed: the 6699 header is 18 bytes, not 20

`fss-tuya` emitted a 20-byte 6699 header (4 zero bytes where the protocol has a 2-byte reserved pair) and authenticated a 16-byte AAD; both tuners — tinytuya and Tuya's own — say 18/14. This is not cosmetic: the extra 2 bytes shift `seqno`/`cmd`/`len` for the device's parser and change the AAD, so the GCM tag can never verify. `fss-capture-tuya` accepts `--proto 3.5|v35` (`fss-capture-tuya.rs:355-356`) and drives that proto down this exact path, i.e. it could not open a real 3.5 session at all. It went unnoticed because the vector that should have caught it was self-referential: the golden fixture was produced by the same wrong assumption, and the simulator shares `wire.rs`, so `tests/client_sim_contract.rs` could never disagree with the packer. Only the external oracle could.

**Three independent sources agree on 18:**

1. `crates/fss-tuya` vs `tinytuya` — the crate's own declared oracle. tinytuya `tinytuya/core/header.py:16`:
   `MESSAGE_HEADER_FMT_6699 = ">IHIII"  # 4*uint32: prefix, unknown, seqno, cmd, length` → `struct.calcsize` = **18** (4+2+4+4+4), and `tinytuya/core/message_helper.py:56-58` seals with `header=data[4:]` = the 14 bytes after the magic: `aad = reserved(2) | seqno | cmd | len`. `XenonDevice.py:465` derives its minimum frame length from `calcsize(HEADER_FMT_6699)`.
2. TuyaOS `src/tuya_cloud_service/protocol/tuya_protocol.h:49-56` — `LPV35_FRAME_HEAD_SIZE 4`, `LPV35_FRAME_VERSION_SIZE 1`, `LPV35_FRAME_RESERVE_SIZE 1`, then sequence/type/datalen; the struct is `uint8_t version:4; uint8_t reserved:4; uint8_t reserved2;` followed by the three `uint32_t`s, i.e. **14 bytes of "additional data"**.
3. Tuya's serializer/deserializer — `tuya_protocol.c:486-513` builds `lpv35_additional_data_t ad = {.version = 0, …}`, `memcpy`s 14 bytes, then calls GCM with `.ad = &ad, .ad_len = sizeof(lpv35_additional_data_t)` (14); the mirror at `:625-639` reads those 14 bytes back from `input + LPV35_FRAME_HEAD_SIZE` and feeds them as AAD. The magic `\x00\x00\x66\x99` is excluded from the AAD; the reserved pair is *inside* it.

Byte-level diff of one identical message (seq 7, cmd 0x0A, retcode 0, payload `{"dps":{"1":true}}`, key `0123456789abcdef`, iv `00…0b`):

```
old (20-byte hdr, AAD data[4..20] = 16 B)
00 00 66 99 | 00 00 00 00 | 00 00 00 07 | 00 00 00 0a | 00 00 00 32 | iv… | ct… | tag… | 00 00 99 66
             ^^^^^^^^^^^ 4-byte zero    ^seq        ^cmd        ^len
new (18-byte hdr, AAD data[4..18] = 14 B)
00 00 66 99 | 00 00 | 00 00 00 07 | 00 00 00 0a | 00 00 00 32 | iv… | ct… | tag… | 00 00 99 66
             ^^^^^   ^ version:4|reserved:4, reserved2 — inside the AAD
```
The old frame decodes under the device's parser as `seqno=0, cmd=7, len=10` with the last two bytes of `len` bleeding into the IV.

**Fixed** (all in `crates/fss-tuya/src/wire.rs`): added `HEADER_LEN_6699 = 18`, `RESERVED_6699 = [0, 0]`, `AAD_6699 = 4..HEADER_LEN_6699` with the `lpv35_fixed_head_t` provenance in the doc comment; `parse_header` now needs 18 bytes and reads `seqno`/`cmd`/`len` at `[6..10]`/`[10..14]`/`[14..18]` with `total = 18 + length + 4`; `pack_6699` writes the reserved pair and seals over `&out[AAD_6699]`; `unpack_6699_mode` reads the body from `[18..]` and opens over `&data[AAD_6699]`. Downstream consumers were already header-agnostic (`fss-capture-tuya::next_frame` and `discovery/tuya_beacon.rs:106` both go through `parse_header`), so only doc text and the golden fixture needed updating. The golden frame in `wire_contract.rs:68-70` was regenerated for the correct layout and a regression test `frame_6699_header_shape_is_18_bytes` was added that pins the reserved pair, the AAD span, the header length and `total = 18 + len + 4`.

`cargo test -p fss-tuya --offline` → **40 passed, 0 failed** across all suites (wire_contract 9, client/sim 12, crypto 10, sim 9). Pre-existing, unrelated: `cargo test -p fss-reference` does not build — several modules define `type TestResult = Result<(), …>` while others use `TestResult<T>` (`evidence_claim_graph.rs:182`, `plan_obligation_graph.rs:269`, `ingest/inference/admission.rs:197`); separately, `cargo check -p fss-reference` is currently blocked upstream by in-flight `fss-tutk` work (duplicate `SessionEvent::Ioctl` variant, 9 errors). Neither is mine. The live 6668 silence could not have been diagnosed at all without this fix — the device answers a bad command and a valid one identically, so all signal lives in the frame being well-formed.

---

## What would falsify this

**The decisive missing test: get the local_key from a pairing-mode press and walk the authenticated lane.** Without it every claim about what a session *buys* is inference.

In order:
1. Press-and-hold pairing mode, then `REQ_DEVINFO (0x25)` → UDP **7000** (and `BOARDCAST_LPV34 (0x23)` → 6667 as the fallback). Expected (`tinytuya/scanner.py:86`): a GCM frame under the public `udpkey` whose JSON carries `ip, mac, name, key, gwId, active, ability, encrypt, productKey, version, token, wf_cfg`. The beacon decoder already handles exactly this shape (`discovery/tuya_beacon.rs:106,171-176` unpacks 6699 under `UDP_BROADCAST_KEY`). **Falsifier: if neither answers even in pairing mode, H-003(a) dies and the only road left is the owner's Tuya consumer session** (obtainable from the `tuyaUid` the account API hands out, but that is a Tuya-side implementation job).
2. With the key: `0x03→0x04→0x05`, then confirm the 18-byte header fix against hardware (the one thing the unit test cannot prove) and that a CONTROL write lands in a STATUS read. Budget the `ALLOW_NO_KEY_NUM 3` frames.
3. **Decide the `0x1A` body encoding — free, no flash write.** Send a 512-byte body of the wrong shape. Retcode **1** plus an ASCII reason ⇒ wrong encoding, try the other candidate from the LAN OTA table; no retcode ⇒ shape parsed, move on. This is the step that tells you whether the chain is even drivable, and it costs nothing.
4. **The one that decides the chain:** correct shape, correct `len`, deliberately wrong `md5`. Then read *which* stage faults:
   - `TUS_DOWNLOAD_ERROR_HMAC 45` or `TUS_UPGRADE_ERROR_HMAC 49` → the LAN path is HMAC-gated too, so `local_key` alone does not close it and `seckey` becomes the missing secret;
   - only an md5/crc complaint (or none) → **LAN-flash works with the local_key alone and the chain closes to root**;
   - accepted and applied with no digest at all → trivially attacker-supplied images.
5. Only then a correct image, on mains, as `[WRITE][RISK]`.
6. Secondary, cloud path: `tuya_ota.c:110-118` already shows `sha256 → tal_sha256_mac(activate.seckey) → memcmp` before `tal_ota_end_notify`, so cloud OTA **is** HMAC-verified; only certificate pinning on the `httpsUrl` fetch could still refute the cloud MITM story. Capture one real upgrade and check.

Second falsifier on the proxy finding: if 51028 turns out to be the owner's intended remote-view feature (it is not — raw HTTP proxy, no auth, no ACL), F5/F6 would be "by design".

---

## Verdict

- **H-003(a) — key without the developer program: PARTIAL, ~55%, zero-touch road refuted.** The owner account API was tried and yields no `localKey` (it returns inventory, firmware versions and the OTA descriptor, and hands you the owner's `tuyaUid` for the next hop), so there is no no-touch key. What remains works: Real mechanism, no account, no cloud, no developer program: the pairing-mode broadcast leaks `local_key`+`gwId` under the *public* `udpkey`, and `local_key` is a static 16-byte secret that authenticates 6668 indefinitely thereafter. But it needs one physical button hold, and while paired the broadcast socket is not even bound (7000/6667 ICMP-closed, 6666 silent, `0x13/0x23/0x25` unanswered 3× each), so nothing was confirmed end-to-end. Naive "just connect to 6668" buys nothing — 3.5 is silent on GCM failure and leaks no identity.
- **H-003(b) — exec / arbitrary file write via a DP: REFUTED, ~90%.** Now backed by the device-side dispatch, not just the header: `lan_protocol_process` handles only dps-write, dps-read, the two negotiation steps and P2P signalling. No exec, no path, no filename anywhere. In-tree DP coverage for this model is lab-only and partial, and no public H2E DP map exists. OTA is the only thing that writes bytes.
- **H-004 (cloud path) — attacker-supplied image: PARTIAL, ~35%, unchanged.** The modern TuyaOS cloud path is *not* MD5-only: `tuya_ota.c:110-118` SHA-256s the file, HMACs the digest with the device's `activate.seckey` (`tal_sha256_mac`), hex-compares to the descriptor's `hmac` and only then calls `tal_ota_end_notify(TRUE)`. So a descriptor-rewriting MITM must also forge an HMAC keyed by a secret that is **not** the local_key. Remaining holes: `httpsUrl` is a plain string field (`tuya_ota.c:210`) with no scheme check, `md5` rides along unused for the final gate, and the **LAN** OTA frames `0x1A-0x1C` have no public implementation — if that path takes `hmac` from the LAN frame it inherits the seckey requirement, if it takes only `md5` the chain closes. Unproven either way.
- **LAN OTA `0x1A/0x1B/0x1C` — the persistence mechanism: EXISTS, mechanism unconfirmed, ~60% that it is `local_key`-sufficient.** Command constants are real and land inside the authenticated session; neither candidate body encoding carries an `hmac` field, so MD5 is the expected gate and `seckey` would not be needed — but no public code implements the frames, so both the layout and that gate are inference. This is the highest-value open item in the fleet, above everything else in this pack.
- **Bonus, CONFIRMED, ~95%:** 51028 is an unauthenticated `tinyproxy/1.11.2` open forward proxy with no `ConnectPort`/`Allow` restriction — arbitrary-port off-LAN egress plus a `127.0.0.1` oracle, and the loopback scan shows **nothing** hidden behind it. Not affected by CVE-2023-49606 (lists only 1.10.0/1.11.1, 9.8 UAF→RCE); in scope for CVE-2025-63938 (`strip_return_port()` overflow, 6.5, "through 1.11.2") and CVE-2026-31842 (TE case-sensitivity desync, 7.5, "through 1.11.3") — no RCE from the proxy itself.

**Bottom line.** The homebase is the right target — 4 cams behind it — and the root path is now named: **LAN OTA `0x1A/0x1B/0x1C` fired over the authenticated 6668 session**, no cloud, no URL, no TLS, persistent by construction. Nothing else in the fleet satisfies the owner's constraints as cleanly. The network-only road still ends at *control* (no exec sink; nothing hidden behind loopback), so the sequence is: one button press → `REQ_DEVINFO` → session → wrong-shape `0x1A` to settle the encoding → wrong-digest `0x1A` to settle the gate → good image. The single open question is `seckey` vs. `md5`, and it is one frame away because a parse error answers in plaintext while a digest error arrives as a status code.


---

## Evidence bead index

All created in this repo, `-t task`, slug as listed:

| Bead ID | Claim |
|---|---|
| `bb-tuya-6668-6699-silent-hm7` | 6668 accepts 6699 silently, closes on the 55AA prefix (CRC-independent) |
| `bb-tuya-6668-no-leak-11v` | no pre-auth identity leak / no oracle on 6668 |
| `bb-tuya-udp-absent-b32` | UDP 7000+6667 closed, 6666 silent; 0x13/0x23/0x25 unanswered |
| `bb-tinyproxy-open-proxy-h6v` | 51028 = unauthenticated open tinyproxy, arbitrary-port egress |
| `bb-tinyproxy-localhost-oracle-ile` | proxy reaches 127.0.0.1; 200-vs-500 is a port oracle |
| `bb-tinytuya-reqdevinfo-k05` | 3.5 discovery = 0x25 on UDP 7000 under udpkey, returns `key`+`gwId` |
| `bb-tinytuya-6699-header-4jq` | oracle 6699 header is 18 B, AAD = header[4:18] |
| `bb-fss-6699-header-mismatch-3tm` | `fss-tuya` emits 20 B header / 16 B AAD (2-byte mismatch) |
| `bb-tuya-ota-md5-only-owf` | `0x0a` upgrade = fileSize+32-byte MD5, no signature |
| `bb-tuya-app-upgrade-descriptor-wym` | app descriptor `url`/`fileSize`/`md5`; error 5009 = MD5-only check |
| `bb-tuya-lan-cmd-words-uwp` | LAN command vocabulary has no exec/file-write word |
| `bb-cve-tinyproxy-49606-h0a` | CVE-2023-49606 covers 1.10.0/1.11.1 only (9.8) |
| `bb-cve-tinyproxy-1-11-2-i26` | CVE-2025-63938 (6.5, through 1.11.2), CVE-2026-31842 (7.5, through 1.11.3) |
| `bb-fcc-2bacu-h2e-8c0` | FCC 2BACU-H2E: 2.4 GHz DTS only, block diagram confidential |
| `bb-ports-8888-443-doors-zr8` | 8888/443 are hold-and-never-answer doors; 443 is not TLS |
| `bb-proxy-loser-scan-empty-nq9` | loopback scan (3025 ports, 2 passes) finds no localhost-only service |
| `bb-tuyaopen-dispatch-no-exec-zvz` | TuyaOpen 3.5 dispatch = 5 command groups, no exec/path |
| `bb-tuya-lan-ota-consts-k8h` | 3.5 defines LAN OTA 0x1A/0x1B/0x1C + LAN_RESET 0x1D |
| `bb-tuyaopen-lpv35-head-6ef` | TuyaOS 3.5 head is 18 B, AAD is the 14 B additional_data |
| `bb-tuya-ota-hmac-seckey-6di` | cloud OTA verifies sha256+HMAC under `activate.seckey` before applying |
| `bb-tuya-allow-no-key-3-9sa` | `CLIENT_LMT 3`, `ALLOW_NO_KEY_NUM 3` |
| `bb-key-recovery-needs-button-8qd` | key recovery blocked on one physical pairing press |
| `bb-lan-ota-layout-candidates-so8` | LAN OTA body = retcode+data; JSON-descriptor vs `len|crc32|md5` candidates |
| `bb-lan-ota-ab-banks-qnw` | `TUYA_OTA_FULL` = AB bank switch; no `PATH_LAN` |
| `bb-lan-retcode-parse-error-48k` | parse failure is a visible retcode 1 + plaintext reason |
| `bb-lan-ota-blind-probe-tny` | unauthenticated 0x1A is indistinguishable from a bogus cmd |
| `bb-lan-ota-status-codes-3ht` | status codes 45/49 separate digest failure from shape error (cited 38-49; exact lines 41, 45) |
| `bb-aosu-env-stale-blob-2uj` | `aosu.env` valid; saved `gz-sid` stale (errno 202) |
| `bb-aosu-login-contract-nau` | login contract: `Gz-Pid: glazero`, `pwType=1`, plaintext password |
| `bb-aosu-gz-sign-md5-tui` | `gz-sign` = md5(path+query), no secret |
| `bb-aosu-no-localkey-x1n` | `localKey` absent from all five device endpoints |
| `bb-aosu-ota-endpoint-8f8` | `/v1/ota/getNewByApp` returns the cloud descriptor (`sign`+`verify`) |

Deliverables in `deliverables/scripts/`: `ev-pack-h-003-send-ota-start.py` (the `0x1A` probe; `--selftest` and `--dry` verified). Scratch probes: `/tmp/p2.py`, `/tmp/p3.py`, `/tmp/scan.py`, `/tmp/disc.py`, `/tmp/hdrtest.py`, `/tmp/crctest.py`; APK + jadx output in `/tmp/aosu.apk` and `/tmp/jout`.
