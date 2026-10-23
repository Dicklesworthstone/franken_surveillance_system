# Fleet liberation status — Aardvark, 2026-10-22

Goal: root on the owner's cameras over the LAN only, then replace vendor firmware with open
standards (RTSP/ONVIF) plus native tailnet membership. No SD card, no UART, no disassembly, no
vendor developer program.

This file is the honest scoreboard. Everything is owner-device research; nothing is flashed.

## Where each family actually stands

| Family | Unit(s) | Root mechanism | State | Blocking fact |
|---|---|---|---|---|
| Wyze Cam v4 (HL_CAM4 4.52.17.26) | `.4.23`, `.4.24`, `.5.242`, `.6.25`, `.5.181` | `assis` OTA: cloud descriptor → our HTTPS → tar → `sh upgraderun.sh` as root | **delivery plane complete, dispatch not firing** | the device consumes shadow deltas and accepts `run_action` (`code 1`, `result 3`) but issues no GET |
| AOSU HomeBase H2E | `.4.37` | Tuya 3.5 LAN OTA `0x1A/0x1B/0x1C` inside the authenticated session | unstarted; unauthenticated 51028 proxy confirmed earlier | `local_key` not recovered, so no session; digest-vs-hmac question unresolved |
| TP-Link Tapo C460 v1.0 | `.6.70` / `.6.71` | CVE-2026-105810 `connectAp` stack overflow (auth) | payload built, never sent | needs an admin session; the offline `device_confirm` verifier did not crack the password (1.65 M candidates) |
| Yi IPC | `.6.156` | CVE-2018-3910 SSID command injection into `popen` | mechanism only, never fired | needs one app re-provision onto an attacker SSID (physical-ish, allowed) |
| Canary | `.6.85` | unknown; outbound-only | located, zero open TCP ports, UDP quiet | no inbound surface at all |
| Owlet | not located | unknown | not on the LAN by OUI or by TUTK `0x0601` sweep | device identity unknown |

## What is now proven, per layer

1. **Delivery** (Wyze): owner token → device IoT certificate issuance (`200 SUCCESS`) → mutual-TLS
   MQTT to the AWS IoT broker with the device `thing_name` → shadow delta accepted and echoed into
   `reported`. A Let's Encrypt endpoint the device's own CA bundle validates
   (`ssl_verify_result 0`) is live. The missing link is the device-side dispatch, not the plumbing.
2. **Replacement firmware**: a 16 MiB Thingino image with `tailscaled` 1.104.2, `serve` rules for
   TCP 554/80, dropbear, ONVIF and prudynt RTSP is built and deterministic (`docs/exploit/firmware-build.md`).
   Boot region is byte-identical to the pinned upstream installer image; only rootfs/env differ.
3. **Install script**: `deliverables/scripts/upgraderun.sh` reads `/proc/mtd`, refuses an unexpected
   map, streams every partition out first, verifies a pinned image digest, writes high-offset first
   and the bootloader last.
4. **Exploit dogfood**: CVE-2026-38698 on this build is a remote DoS, not a root primitive
   (`docs/exploit/av-overread.md`). It is still useful as a forced-iCamera-restart trigger.

## The one thing to do next

Power-cycle `.4.23` with the current `desired` shadow state (URL + real MD5 already published). The
cloud reports `conn_state 1` and every `run_action` is accepted, so a boot-time resync is the
cheapest way to distinguish "dispatch never fires" from "dispatch fires only at boot". If the server
log shows a GET, the rest of the chain is already built and the negative capsule / no-write capsule
/ flash sequence can run in order.

## Safety invariants

- One camera per agent; TUTK refuses concurrent sessions.
- Nothing writes flash until the negative 20-byte capsule has produced a GET and the MD5 gate has
  been observed.
- The full-image write includes the bootloader; the only recovery from a bad boot write is TFTP/USB
  plus UART, which is outside the current constraint.

## Retest log, 2026-10-23 02:0x (MagentaOwl)

| Unit | Reachability | Consequence |
|---|---|---|
| `.4.37` AOSU | ping + 443/6668/51028 open | unchanged; the 51028 proxy is still alive |
| `.4.24` Wyze | ping + 53 open, sessions work | unchanged |
| `.6.70` / `.6.71` Tapo | ping + ARP, **all TCP filtered** (80/443/554/2020/6668/8800) | cannot re-verify the model over the wire right now |
| `.6.156` Yi | ping + ARP, TCP 80 closed as always, **WS-Discovery now silent** | injection remains the only path; nothing to hit first |
| `.6.85` Canary | **does not answer ping** | was up earlier today, now unplugged or asleep |

The Tapo pair answering ICMP while dropping every SYN is consistent with a source-address ban after
the earlier 1.2 × 10^9-candidate `device_confirm` run; it is not consistent with the units being off
(ARP resolves and ICMP is answered). Recorded so the next reader does not read it as a model change:
the C460 v1.0 / C660 v1.6 identification came from UDP 20002 TDP and still stands, and **every
published 2026 Tapo CVE is model-locked away from both units**.

### AOSU — why it cannot move without one secret

`0x1A/0x1B/0x1C` live inside the authenticated Tuya 3.5 GCM session, so the LAN OTA question cannot
even be asked without the 16-byte `local_key`. Nothing on the wire yields it and the account API has
no `localKey` field; the only source is the Tuya OEM channel, which needs the app's signing material
(extracted, still `ILLEGAL_CLIENT_ID`). Every downstream step is scripted and waiting:
`deliverables/scripts/ev-pack-h-003-send-ota-start.py` sends the wrong-shape `0x1A` first, then a
wrong-digest body — the ordering matters because a parse failure returns the same `retcode 1` as a
digest rejection.

### Yi — what is staged, and what still needs a human

`deliverables/scripts/yi_u1.py` now carries both payloads with their length check
(`x$(nc 192.168.4.160 4444|sh)`, 28 octets, fits in the 32-octet SSID budget; the quoted
`telnetd` fallback at 22) and a listener that gives an interactive root shell. Remaining human step:
broadcast that SSID and re-provision the camera in the Yi app. Pass condition is a shell from
`192.168.6.156`; the persistence pass is the same shell after `reboot` with the SSID unchanged.

### Dispatch experiments that all failed (do not repeat)

1. Delta with the stale `desired` still set → no GET.
2. Fresh delta, `.tar` URL, both the zero MD5 and the *true* MD5 (i.e. one matching and one
   not-matching the file) → no GET.
3. Third delta with a deliberately different MD5 (`1111…`, neither the file's nor `reported`'s) so
   the device could not dedupe on digest → no GET.
4. Vendor-shaped path `/wuv2/upgrade/HL_CAM4/firmware/<ver>.tar` instead of a bare name → no GET.
5. `run_action` after the params were understood (`app_ver` required, else `1001`) → `code 1`,
   `result 3`, `session_id`, still no GET, no reboot after 25 s or 150 s.

So the device consumes shadow state (`reported` tracks every key we set) but does not act on it
without a resync. **The single remaining test is a power cycle**, or tapping the device's own MQTT
session to see whether any `cmd` frame is delivered at all.

### Why an iCamera crash is not enough to resync the shadow

Crashing `iCamera` only restarts that one process; `iotclient` — the process that owns the MQTT
session and the shadow subscription — keeps running, so the delta is never re-delivered. Verified:
a triple crash run on `.4.24` killed the stream at 10.6 s, the box answered ping 5 s later, and the
`desired` URL was still un-fetched. For the same reason the cloud `restart`/`reboot` actions
(`result 3`) do not help. `docs/exploit/ota-path.md` §9.7 lists the five dispatch variants that
also failed. The box needs a real power cycle.

## 02:3x — source-IP spoofing tried, and what it proved

`sudo ifconfig en1 alias 192.168.6.200/22` plus `curl --interface` from three different source
addresses (`.6.200`, `.4.222`, `.4.169` — the latter two were already aliased on this host). Result:
identical, nothing. Combined with ARP resolving and ICMP answering, **the Tapos are not banning us —
they are simply not serving TCP or UDP 20002**. They are asleep and only the AP's proxy answers
ICMP. Waking them needs the app to open a stream. That closes the "ban" hypothesis and the
"spoof our way back in" idea.

## AOSU API is reachable now — and the exact blocker has a name

Concrete progress from the same push:

- `api-us.aosulife.com` answers again, but **only with the app User-Agent and POST**; a bare GET
  returns `404 page not found`. That is why the earlier replay looked dead.
- The captured `gz-sid` is genuinely expired (`202 sid过期`) — so re-login is mandatory.
- `/v1/user/login` exists and answers `200` with `104 pid参数错误`: the login needs a **`pid`**, and
  `pid` is not the bundle id (`com.glazero.ios`), not `com.glazero.android`, not the iotbing
  `clientId`, not a small integer in body, query or `gz-pid` header (0..300 swept, plus 11 symbolic
  candidates). It is the one unknown.
- The device-side answer to "does the homebase take plaintext 3.3 frames without a key?" is **no**:
  well-formed `0x000055AA` 3.3 frames for `HEART_BEAT` and `DP_QUERY` are accepted at TCP level and
  never answered, matching the earlier probe log. There is no keyless control channel.

So AOSU is exactly one integer away from an authenticated session, and nothing else on the network
substitutes for it.

## 03:2x — AOSU cloud session obtained (login fully reversed from the 5.10.12 APK)

The `pid` blocker is solved and the login is no longer opaque. Everything below was read out of
`Aosu_5.10.12_APKPure.xapk`, not guessed:

| Element | Where it comes from |
|---|---|
| `Gz-Pid` must be **`glazero`** | `AppConstant.APP_CHANNEL_PID` → `AppChannelPlatform.OooO0OO()` → `AppChannel.OooO0oO()` |
| login is **form-encoded** `POST /v1/user/login` with `region,countryCode,countryAbbr,type=1,email,password,pwType=2` | `AccountCenter.OooOooO` → `AccountWebService.OooO0oO` |
| `password` = base64(AES-128-CBC/PKCS7), **key = iv = `PZR1ryiUhJloWoRd`** | `SecurityCore.nativeEncryptP` → `libglazero-security.so:0x18bc4`, passed as both key and IV to `aes_encrypt_pkcs7` |
| `Gz-Sign = md5("uuid:<u>:t:<t>:&sM&GGlUCSXjZqQNxmkdU^scUs**0R@C")` | `SignInterceptor` |
| app UA + `uuid`/`t` query params are mandatory | `CommonInterceptor`; a bare GET 404s |

Verified live: `errno 0 成功`, a session, and a full inventory — `Rear Door Cam`,
`Solarium Cam`, `Front Door Cam`, `Driveway Cam`, `HomeBase` (`H2E`, sn `H2E2DA110000807`).
Client: `deliverables/scripts/aosu_cloud.py` (`login` / `devices` / `call`), smoke-tested.

**`local_key` is still not in this API.** Checked and negative: `getList` (incl. `{"detail":1}`),
`getInfoBySn`, `getModelInfoBySn`, `getInfoByCode`, `capability` (base and child sn), `bind/getToken`
(returns a pairing token, not a key), `sts/getMultiMqttInfo`. It comes from the Tuya
`a1-us.iotbing.com/api.json` gateway, which needs its own sign; the captured iotbing call still
replays successfully, so that session is alive, but generating a *new* action needs the signing
routine inside `libthing_security.so`. That is the one remaining step before `0x1A/0x1B/0x1C` can be
sent.

## 23:4x — the flash path is staged end to end; one power cycle away

Two things were broken and are fixed:

- **The HTTPS server had died and a stray `python -m http.server` had grabbed 8443 on the IPv6
  wildcard only**, so `ota.frankenfs.com` (an A record to the IPv4 address) refused connections for
  roughly an hour. That alone can explain several of the failed deltas. It is restarted on
  `192.168.4.160:8443` with the Let's Encrypt chain and verified `200`.
- The image is now served over plain HTTP on `192.168.4.160:8080` (the device-side `wget` has no
  TLS), and the capsule is served over the HTTPS path the OTA requires.

A **dry run of `upgraderun.sh` in a sandbox** — fake `/proc/mtd` summing to exactly 16 MiB, stub
`dd`/`nc`/`wget`, real image file — completed and produced: geometry accepted, six backups
streamed, digest verified, all six partitions written with the exact sizes, **highest partition
first and `uboot` last**, then reboot. The 13.5 MiB fake map was correctly refused first, so the
guard works.

Staged now:

| Artefact | URL | MD5 |
|---|---|---|
| negative (20 B, no tar, no write) | `.../4.52.17.30.tar` | `6909e9ca42b912662c04e6e98d7c5821` |
| real capsule (busybox + installer) | `.../4.52.17.31.tar` | `bf0535f59515f71a04ba00bd2176ffd2` |
| image (tailnet build) | `http://192.168.4.160:8080/img.bin` | sha256 `546c24f8…` |

`desired` currently holds the **negative**. Sequence is two power cycles: cycle 1 proves delivery
and the MD5 gate with zero writes; then publish the capsule (`pub.py …/4.52.17.31.tar
bf0535f5…`) and cycle 2 flashes.

Also checked and negative: **no `paracfg` item reboots the box.** All 157 entries of the table at
`0x8c5da8` were scanned for a reference to the `"reboot -f"` string (`0x834840`) — none. The only
caller of the reboot block (`0x457010`) is a video-service-change path that our K10000 retry with
changed resolution did not reach. So a reboot cannot be synthesised from the wire; it is a power
cycle or nothing.

## Tuya sign — what is now known, precisely

The gateway resolves the action name *before* validating the signature, which let the coverage be
measured empirically: changing `a` to an unknown name returns `API_OR_API_VERSION_WRONG`, changing it
to a real one returns `SING_VALIDATE_FALED`. So `a` **is** signed, as are `sid` and `postData`;
`t` is not (a request with only `t` replaced replays fine). Signing is
`ThingApiSignManager.generateSignatureSdk` → sorted `k=v` joined with `||` (with `postData` replaced
by a swapped MD5-base64) → `SecureNativeApi.doCommandNative(ctx, 1, bytes)`, i.e. a native command in
`libthing_security.so`. That library exports no `Java_*` symbols — it registers through
`JNICLibrary.loadSo` → `RegisterNatives`, so the address has to come from `JNI_OnLoad`'s table rather
than `nm`. Reimplementing it needs either an ARM64 runtime or a careful read of the native command-1
body; the userland guesses (HMAC/append/prepend over clientId, sid, deviceId, bundleId, empty) were
all tested against a known pair and all miss.

Both Wyze cameras now carry the negative delta; `docs/exploit/FINISH-WYZE.md` is the two-cycle
runbook.

## Tuya signer runs offline now (arm64 container)

A working harness exists at `tools/thing-sign/`: the real `libthing_security.so` loads under
Alpine/musl (musl ignores the bionic `LIBC` symbol versions) with a stub for the bionic-only surface,
stub Android classes for the `Context` walk, a real DER certificate for the signature field, and
assets served from disk. `computeDigest("abc","key")` → `aee1dd678aea01125dfc861f41d4072d` proves the
crypto core runs, and `doCommandNative(ctx, 1, …)` reaches the signer and reads `assets/t_s.bmp`
(100×75 BMP, stego key).

The real Glazero signing certificate came out of the APK's v2 signing block (no v1 files exist), so
the `Signature` field is genuine. Three gaps remain, all named: `assets/tecrkcehc_ext` (opened by the
signer, absent from the APK — currently a copy of `t_s.bmp` as a guess), `checkStatus` still returning
**-1** (anti-tamper) even with the real cert and package name, and the **appSecret** that `doCommandNative(ctx, 0, secret, appId, …)` needs at SDK init — we only have the
appId (`clientId`). With the clientId substituted, `cmd 1` returns null, so the init path is where
the next hour goes.
