# EV pack H-900 — archaeology of `franken_surveillance_system`

**Scope.** Read-only extraction of every already-established protocol fact from
`/Users/jemanuel/projects/franken_surveillance_system` (HEAD `51f45e20`) so no investigator
re-derives it, plus the firmware-replacement claims. Repo is untouched; no probe was run.

**Framing that dominates every finding below.** This repository is an *interoperability
ingest* project, not an exploit project. Three separate statements of charter exist:

| statement | cite |
|---|---|
| "FSS is not a covert-access toolkit, an exploit framework" | `COMPREHENSIVE_PLAN_FOR_FRANKEN_SURVEILLANCE_SYSTEM.md:225` |
| "`NONGOAL-002`: publishing credential bypasses, universal tokens, or vendor exploits" | `COMPREHENSIVE_PLAN_FOR_FRANKEN_SURVEILLANCE_SYSTEM.md:543` |
| "no exploit development anywhere (owner charter)" | `DEVICE_ADAPTER_MATRIX.md:145` |

Consequence for H-900: everything the repo "proves" is *authenticated reachability*
(ENR/local_key/a token in hand). It proves **no** memory-corruption RCE, no auth bypass, no
persistence — because it never looked for them. Absence below is therefore *charter absence*,
not *negative evidence*; only NEG-004/005/006 were actually run as falsification tests.

---

## Findings

Legend: **PA** = pre-auth (no owner secret). Primitive classes: RCE / LPE / INFO (info-leak) /
CFG (config-write) / AUTH (auth-bypass) / STREAM (media).

### F-1 — TUTK/IOTC NEW (`0xCC51`) wire protocol — Wyze Cam v4 / HL_CAM4 / 4.52.17.26

| field | value |
|---|---|
| transport | UDP 32761 (discovery), then camera-chosen source port |
| PA? | **No** — discovery HMAC is keyed by the camera's own UID+ENR+MAC (see F-2) |
| class | STREAM + INFO (camera self-report) + AUTH (challenge/response) |
| code | `crates/fss-tutk/src/wire.rs`, `src/session.rs`, `src/av.rs`, `src/xxtea.rs`, `src/dtls.rs` |
| reliability | high for the exact tuple; live-proven 2026-10-07/08 (beads `fss-x4a.21.2.2`, `.6`) |
| evidence | EV-901, EV-902, EV-904, EV-910, EV-911 |

Exact recovered facts (each one cost a lab run; do not re-derive):

- **Discovery is 52 bytes, `0x1002`, trailer HMAC-SHA1.** Header 32 B; `[6:8]=0x0028` payload
  size; `[8:10]=0x0000` request / `0xFFFF` response; `[12:14]` seq; `[14:16]` ticket; `[16:24]`
  session id; `[24:32]` fixed capabilities `00 08 03 04 1D 00 00 00`; `[32:52]`
  `HMAC-SHA1(UID‖AuthKey, hdr[0..32])` (`wire.rs:60-64,209-231`).
- **HMAC key = `UID(20 ASCII) ‖ AuthKey(8)`, 28 bytes**; `NewProto::new` returns `None` unless
  UID is *exactly* 20 bytes (`wire.rs:177-189`).
- **`AuthKey = Base64(SHA256(ENR ‖ MAC.to_uppercase())[0..6])` with `+`→`Z`, `/`→`9`, `=`→`A`**
  (`wire.rs:81-101`).
- **PSK = `SHA256(ENR)` with every byte after the first NUL zeroed** — "TUTK SDK treats the
  binary PSK as a NUL-terminated C string" (`wire.rs:112-121`). This is the so-called NUL quirk;
  the truncating variant `derive_psk_truncated` exists only for Python-oracle parity
  (`wire.rs:123-133`), and `SessionConfig.psk_truncated` (`session.rs:55-57`) selects it.
- **DTLS 1.2, `TLS_ECDHE_PSK_WITH_CHACHA20_POLY1305_SHA256` = `0xCCAC`, PSK identity
  `AUTHPWD_admin`**, premaster `u16|Z ‖ u16|PSK` (RFC 5489 §2) (`dtls.rs:1-2,36-40,543-547`).
  All crypto is first-party: SHA-1/SHA-256/HMAC (`digest.rs:1-5`), X25519 TweetNaCl port
  (`x25519.rs:1-5`), ChaCha20-Poly1305 (`chacha.rs:1-6`).
- **`0x1502` DTLS wrapper**: 28-byte header, channel in the **high** byte of `[12:14]`
  (`0x0010 | channel<<8`), `[24:28]` constant `01 00 00 00`, HMAC **over the 28-byte header
  only** (`wire.rs:288-311`, crate doc `lib.rs:11-18`). `unwrap_dtls` validates the declared
  size against `len()-12` and re-HMACs the header (`wire.rs:314-336`).
- **`0x0009` message-ACK is mandatory** (24-byte layout) and a 100 ms ACK ticker runs while
  streaming (`lib.rs:22,30`; `av.rs:158-166`; `session.rs:27-28`).
- **Post-discovery the session must adopt the camera's response source port** —
  `session.rs:6-7`; harness `fss-capture-tutk.rs:205-212`.
- **AV login** 1 then 2 ten ms later; **K10000 → K10001 challenge → K10002 → K10003 →
  K10010 → K10011** (`session.rs:2-10,655-760`; `av.rs:230-247`).
- **K-auth response is XXTEA** over the 16-byte challenge, keyed by camera-chosen mode:
  status 1 = `16×0xFF`, status 3 = `ENR[0:16]`, status 6 = double decrypt
  `ENR[0:16]` then `ENR[16:32]` (`xxtea.rs:112-124`, `av.rs:264-279`). **So possession of ENR
  is the whole auth oracle — no per-session secret.**
- **Success test is the verbatim string** `"connectionRes":"1"`; there is no JSON parser
  (`session.rs:902-905`).
- **`0x1202` keepalive** (48 B) is *not in the public reference doc*; discovered by capture
  (`wire.rs:16-18,339-361`).
- **Unknown `(model, firmware)` fails closed before K10010** (`session.rs:697-717`) — relevant
  to an exploit: a PoC driver reusing `TutkSession` must pass `known_tuples` or nothing streams
  (`fss-capture-tutk.rs:190,199` hard-codes `("HL_CAM4","4.52.17.26")`).

**Length taken from the packet (asked explicitly):**
`av::parse_hl` takes `plen` from `data[6..8]` and computes `total = 16 + plen`, only checking
`data.len() >= total` (`av.rs:186-192`); `parse_ioctrl` documents that it "Trusts the HL
header's own payload length over the wrapper's size field (the doc's 'HL + 4' ambiguity)"
(`av.rs:215-216`). `av_stream::find_hl` scans for `"HL"` then cuts at `i + 16 + plen`
(`av_stream.rs:253-262`) with **no upper cap on `plen`** beyond u16. The only capped packet
length is the AV-login response: `psize` rejected if `0` or `> 4096`
(`av_stream.rs:160-166`). So a malicious/hostile peer controls frame-extent from inside the
frame. For a PoC driving a *camera* this is not exploitable, but it is the place to look if the
PoC ever accepts camera-authored bytes into a fixed buffer.

### F-2 — Credential-less Wyze discovery: proven impossible for this tuple

| field | value |
|---|---|
| transport | UDP 32761 `0x1002` |
| PA? | **No** |
| class | (falsified primitive) |
| evidence | **EV-902**, NEG-004, NEG-005 |

- OLD-protocol `0x0601` LAN-search (empty-UID broadcast, 2,700-case cipher differential vs the
  CuboAI oracle, 0 failures) got **0 answers in every round** while a target was concurrently
  answering NEW discovery — NEW firmware absorbs OLD probes (`docs/NEGATIVE_EVIDENCE.md`
  NEG-004).
- Owner-identity `0x1002` probe → response every time; **foreign-identity probe → zero
  responses**. The camera silently eats HMACs not keyed by its own uid/enr/mac (NEG-005,
  copied at `crates/fss-reference/src/discovery/dispatch.rs:116-124`).
- Repo therefore keeps bare-Wyze-OUI at `Possible`/`ImportOnly` and names the ingredient
  (`dispatch.rs:116-124`).

### F-3 — Tuya 3.4/3.5 LAN (AOSU HomeBase H2E / C8S2EA11)

| field | value |
|---|---|
| transport | TCP 6668 (6699/GCM 3.5), UDP 6667 beacons (cmd 0x23 / 0x13) |
| PA? | **partially** — beacons are; the session is not |
| class | STREAM/DP + CFG (write dps) + INFO |
| code | `crates/fss-tuya/src/{wire,crypto,client,sim}.rs`; `fss-reference/src/ingest/tuya.rs` |
| reliability | oracle-exact vs tinytuya, never run against the real homebase (local_key missing) |
| evidence | EV-905, EV-906 |

- Framing: `55AA` (`prefix|seq|cmd|len`, CRC32 or HMAC-SHA256 trailer) and `6699`
  (`prefix|0|seq|cmd|len`, AES-128-GCM, AAD = hdr `[4..20]`) (`wire.rs:1-25`).
- Negotiation: cmd 3 client nonce → cmd 4 device nonce + `HMAC(local_key, client_nonce)` →
  cmd 5 `HMAC(local_key, device_nonce)`; session key = AES-128(local_key) over
  `local_nonce ^ remote_nonce` (`client.rs:1-12,162-215`).
- **Beacons are credential-less**: cmd 0x13 under public `udpkey = md5("yGAdlopoPVldABfn")`
  (a precomputed constant, `wire.rs:20-24`), cmd 0x23 under the device local_key
  (`wire.rs:1-25`). Beacons therefore corroborate brand+presence with no owner secret.
- `8668`-family surface as characterized: 443 accepts but **completes no TLS without a client
  cert** (mutual-TLS device-cloud); 6668 **silently drops a wrong-key cmd 3**; 8888
  active-closes on unframed input (app channel, handshake unmapped); 51028 is
  `tinyproxy/1.11.2` and does **not** openly forward; 554/8554 closed (`DEVICE_ADAPTER_MATRIX.md:80-85`, EV-906).
- Media continuity is **explicitly not established**: Tuya video rides the encrypted iotbing
  OEM stream and every report says `media_continuity:"unverified"`
  (`fss-capture-tuya.rs:16-18,435`; `DEVICE_ADAPTER_MATRIX.md:93-94`).

### F-4 — Yi IPC: WS-Discovery answers, everything else shut

| field | value |
|---|---|
| transport | UDP 3702 WS-Discovery only |
| PA? | yes (announcement) but useless alone |
| class | INFO |
| evidence | **EV-909**, NEG-006 |

WSD responder is reliable *when* the full WS-Addressing header (MessageID/Action) is present;
header-less probes are ignored. `XAddrs http://192.168.6.156/onvif/device_service` plus
Profile/Streaming/ptz/video_analytics scopes are advertised, but **zero TCP ports open across
the full 1-65535 range in every state**, and SOAP-over-UDP to :3702 is silent
(`docs/NEGATIVE_EVIDENCE.md` NEG-006, `DEVICE_ADAPTER_MATRIX.md:29`). SOAP is gated behind
first-time vendor-app provisioning.

### F-5 — `fss-tuya`/`fss-tutk` are `#![forbid(unsafe_code)]`, sans-IO, and therefore drop-in PoC harnesses

`crates/fss-tutk/src/lib.rs:1`, `crates/fss-tuya/src/lib.rs:1`, `crates/fss-provision/src/lib.rs`
(`#![forbid(unsafe_code)]`), and both protocol crates state "performs no I/O, opens no socket"
(`fss-tutk/src/lib.rs:4-5`, `fss-tuya/src/lib.rs:6-9`). `TutkSession` is a pump:
`feed_datagram(bytes, now_ns)` / `poll_send()` / `poll_event()` / `advance(now_ns)`
(`session.rs:447-449`, `:349-356`); `TuyaClient` is `start_session` / `negotiate_finish` /
`handle` (`client.rs:162-262`). No threads, clocks or sockets in either.

### F-6 — Families with **no** repository coverage at all

| family | repo coverage |
|---|---|
| TP-Link Tapo (192.168.4.70, 443 open) | **none**. `"tapo"` exists only as a vocabulary token in `crates/fss-core/src/identity.rs:1156`. No adapter row, crate, recipe, or port map (EV-907). |
| Reolink / EZVIZ / IMOU | same: vocabulary only (`identity.rs:1154-1157`). |
| Canary | device not on LAN; `fss-tp7iu` blocked on presence (`DEVICE_ADAPTER_MATRIX.md:153`). |
| Owlet | **not mentioned anywhere** (no hits). |

---

## Family → proven / plan-only / missing

| family | repo *proves* (live) | *only* plan or claim | missing |
|---|---|---|---|
| Wyze v4 (`.23/.24/.242`) | full NEW-protocol byte layout; discovery→DTLS→login→K-auth→H.264 stream, 379 frames/20 s 0 gaps on 2026-10-08; OLD probe dead; credential-less discovery dead (EV-901/902/904/910/911; beads `fss-x4a.21.2.2`, `.6`) | "no public custom firmware exists"; "no legitimate on-device path"; goal "met without firmware work" (`DEVICE_ADAPTER_MATRIX.md:150`, `recipe.rs:558-566`, EV-903) | any code-exec primitive; whether anything but 32761 listens; bootloader; whether flash is even writable from LAN |
| AOSU H2E homebase | Tuya 3.5 stack byte-exact vs oracle; beacons live-validated 2026-10-07; 6668/8888/51028/443 characterized (EV-905/906) | "None (locked …)"; data path pending local_key (`DEVICE_ADAPTER_MATRIX.md:151`, `recipe.rs:567-576`) | the local_key itself; 8888 handshake; whether iotbing video can be reached LAN-only; any CFG write over 6668 |
| Yi IPC | WSD announcement + full-range TCP closure (EV-909, NEG-006) | "one QR pairing opens ONVIF permanently" (`DEVICE_ADAPTER_MATRIX.md:124,149`); yi-hack SD class | post-provisioning ONVIF behaviour (untested); yi-hack SN-prefix mapping; **no network-only path at all** |
| Tapo | nothing (EV-907) | nothing | brand row, ports, protocol, credentials |
| Canary | nothing | T4 research target (`fss-tp7iu`) | device presence |
| OpenIPC class A | recipe + `Transformer::NetworkUpdate` ordering, `sd-image` layout (`sdimage.rs`, `bundle.rs`) | Coupler image quality — "Coupler is WIP" (`DEVICE_ADAPTER_MATRIX.md:121`) | any owned class-A device on this LAN |
| Generic standards | RTSP/ONVIF conformance suite (`crates/fss-reference/tests/rtsp_contract.rs`) | — | a device that actually speaks it |

---

## Chain

Shortest **network-only** path the repo supports, per family. Note up front: **none of these is a
root chain.** The repo's own model (`family.rs:18-20`, `recipe.rs:26-37`) splits *software*
(firmware replacement, `Transport`) from *data* (ingest, `DataLane`) and gives Wyze/AOSU
`FLocked` + `Transport::None`. So the honest answer is:

**Wyze v4 — no chain to root; longest reachable rung is authenticated stream + camera JSON.**
`ENR` (+UID/MAC) → `0x1002` → DTLS-PSK → AV login → XXTEA K-auth → `K10003` camera JSON.
Every step exists in-tree and was live-run. Root would require an RCE the repo has never looked
for. EV-903 records the repo's verdict.

**AOSU — no chain; gated on one secret.** Corrected ordering for a chain attempt:
`local_key` → cmd 3/4/5 on 6668 → `dp_query`/`control` → `ioctl`-equivalent dps writes
(`client.rs:246-260`). No shell, no file write, no update command exists in `fss-tuya`.

**Yi — no chain.** Nothing answers TCP until someone opens the app once (NEG-006).

### Falsifier that killed each candidate (explicit)

| candidate | killed by |
|---|---|
| Wyze: discover cameras with no credentials | NEG-005 (EV-902) |
| Wyze: OLD-protocol sweep to reach older firmware | NEG-004 (0 answers) |
| Wyze: browse/update over HTTP | no port 80/443/554 answers at all (census: filtered-timeout) |
| AOSU: 443 device-cloud as an entry | needs a *client cert* (mTLS) — no client key on the LAN |
| AOSU: 51028 as a proxy pivot | tinyproxy "does NOT openly forward" (EV-906) |
| Yi: ONVIF SOAP straight off | full-range TCP closed in every state (EV-909) |

---

## Brick risk + recovery

Because none of the above *writes*, the baseline risk is compile-and-run only. Per-write story:

| write | risk | recovery |
|---|---|---|
| Wyze stream start (`K10010`) | none — video enable only | power-cycle clears it |
| Wyze audio enable (`K10010 media=2`) | none; privacy switch only | power-cycle / next session with `audio:false` |
| Wyze `K10010` with a *bogus* media type | low: `StreamStart` phase deadline (10 s) then `Terminal` (`session.rs:29`, `:731-750`) | drop session, reconnect; camera unaffected |
| Wyze anything that changes the tuple | session **quarantines** and refuses to stream (`session.rs:697-717`) — no camera-side change, but a PoC driver with a hard-coded tuple silently stops working after a firmware bump | pass the real `(model, firmware)` |
| AOSU control/dps write (cmd 0x07/0x0D) | low; Tuya dps writes are ordinary state | device re-announces state on next `dp_query`; worst case power-cycle the homebase |
| AOSU session-key churn from rapid reconnects | unmeasured (`fss-x4a.21.3.2` asks for a 10-min soak) | wait for cmd 4 timeout, reconnect |
| **Any real firmware flash** (only for class-A/Yi) | high | repo's own line: `Some("TFTP+UART recovery per yi-hack; vendor-app factory reset restores stock")` (both `recipe.rs:547`) and `Some("TFTP+UART recovery; the stock web-UI can re-flash the stock image")` (`recipe.rs:583`). Both need UART — so a network-only flash of a bricked unit is *not* recoverable network-only. That is the one place the "no UART" rule bites. |

`fss-provision` models the "can we proceed at all" gate as typed refusals —
`ProvisionError::AlreadyFlashed` (`planner.rs:313`), `MissingPrerequisite(Prerequisite)`
(`planner.rs:317`), rendered as a valid exit-0 answer, never a guess (`fss-provision.rs:44-49`).

---

## What would falsify this

The decisive missing test, per family, in one sentence each:

1. **Wyze** — run `fss-capture-tutk` with the real cfg and confirm a `K10003` JSON comes back
   with the expected `model`/`firmware`; if discovery answers, F-1 holds and the remaining work
   is purely "where is the memory bug". If it does not, the repo's whole Wyze corpus is stale.
2. **Wyze firmware-replacement claim** — the repo's "no public custom firmware exists"
   (`DEVICE_ADAPTER_MATRIX.md:150`) is the single most falsifiable sentence in it, last
   reviewed 2026-10-16, and was never checked against third-party firmware (EV-908: zero
   `wyze-bridge`/`thingino` mentions). One upstream project shipping a v4 image falsifies it.
3. **AOSU** — a `local_key` (official Tuya IoT API, `fss-cgnug`) and one `dp_query` on 6668;
   a successful session plus a decode of the dps map falsifies the "locked" claim at the data
   layer.
4. **Yi** — the untested 5 minutes after an owner app pairing: if 80 still RSTs, `fss-u3e43`'s
   "pairing opens ONVIF permanently" is wrong.
5. **Tapo** — anything at all; one `nmap -p-` and one TLS grab either creates or refutes a row.

---

## Verdict

**PARTIAL** against H-900 (network-only root with reboot persistence): the repo delivers a
*complete, live-proven, credential-gated authenticated path* to Wyze video/JSON and an
*oracle-exact but never-live* Tuya path to AOSU, and it delivers **neither root nor any
persistence mechanism**. Confidence that the protocol facts are correct: **high** (live-run,
byte-differential-verified, with the subtleties that usually break reimplementations — NUL PSK,
high-byte channel, header-only HMAC, port adoption, mandatory ACK — all recorded). Confidence
that "no chain exists": **low-to-moderate**, because it is largely *unsearched*:

- The repo never ran an unauthenticated fuzzer, never checked a single firmware version for a
  CVE, and has no bootloader/flash-layout note for any family.
- Two concrete untested hypotheses survive the archaeology: `parse_hl`'s unvalidated
  packet-supplied length (F-1) and the 443 mutual-TLS client-cert requirement (EV-906) — the
  latter is a *server* needing a client cert, which is the usual shape of a device-cloud
  identity leak.
- Family misassignment in the live census (`192.168.4.70` Tapo, `192.168.4.20` Shenzhen Youhua
  on 8443/9000) is the cheapest unexploited surface, and the repo contributes **nothing** to it.

So: credible ingest archaeology, and a documented gap where an exploit chain would have to be
built by hand.

---

## Answers to the four specific questions

**(a) Does any doc say Wyze/AOSU firmware replacement is impossible, and on what evidence?**
Yes — flatly, and it is a *claim without primary evidence*.

- `DEVICE_ADAPTER_MATRIX.md:150` — "Wyze Cam v4 | **No public custom firmware exists** | No
  legitimate on-device path"; `:151` — "AOSU | **None** (locked Glazero/Tuya homebase + deeply
  embedded battery cams)".
- `DEVICE_ADAPTER_MATRIX.md:138` — "Wyze/AOSU are `f_locked` / `Transport::None` (no
  legitimate firmware-replacement path)".
- `recipe.rs:558-566` — "No legitimate custom-firmware path (**would need exploit development,
  out of charter**)" and "no on-device path" (EV-903).

Evidence offered for any of it: **none**. No CVE lookup, no vendor advisory, no upstream
project, no firmware-download URL. The basis is `INTEROPERABILITY_LAB.md` §4 (stop when the
path "would require bypassing authentication") plus §6 red lines — i.e. a scope decision
presented as a capability finding. `fss-provision` then hard-codes the decision as data
(`CameraFamily::WyzeV4 → FrictionClass::FLocked, Transport::None`, `recipe.rs:553-566`;
`FrictionClass::FLocked = 6`, `family.rs:129`), so the claim is now load-bearing for the
machine-readable matrix. **This is the most important correction this pack carries: "out of
charter" ≠ "impossible", and the two are stored identically.**

**(b) Exact owner-auth ingredient per family (from the typed enum, not prose).**
`AuthIngredient` in `crates/fss-reference/src/discovery/dispatch.rs:45-54`:

| family | ingredient | cite |
|---|---|---|
| Wyze / TUTK | `WyzeUidEnr` — UID + ENR from the account inventory | `dispatch.rs:46`, `:76-80`, `:116-124` |
| AOSU / Tuya | `AosuLocalKey` — the 16-byte device `local_key` | `dispatch.rs:48`, `:82-86` |
| Resideo | `ResideoWebCredentials` (embedded Digest auth) | `dispatch.rs:51-52`, `:88-93` |
| standards / Yi-after-pairing | `StandardsEndpointCredentials` | `dispatch.rs:53`, `:94-100` |
| Tapo, Canary, Owlet | **unmodelled** | EV-907 |

Note `dispatch.rs:48` says the local_key comes "via fresh app login capture or IPA
toolchain", while `fss-cgnug` pursues the easier official Tuya IoT developer API; also
`DEVICE_ADAPTER_MATRIX.md:85` cites "NEG-003" for the local_key gate, but `NEG-003` in
`docs/NEGATIVE_EVIDENCE.md` is about VLMs — a dangling cite worth fixing.

**(c) Sans-IO crates reusable as a PoC harness.**
All three of `fss-tutk`, `fss-tuya`, `fss-provision` are `#![forbid(unsafe_code)]` and purely
byte-in/byte-out (F-5). A PoC would own only the socket, the clock and the nonce source — which
is exactly what `fss-capture-tutk.rs:169-217` (`UdpSocket` + 20 ms read timeout + port
adoption) and `fss-capture-tuya.rs:245-260` (`TcpStream` + reassembly) already demonstrate.
The one thing they do *not* give a PoC is a raw escape hatch into `TutkSession`'s internals:
the API is the pumped state machine, and `known_tuples` must be satisfied or the session
quarantines before `K10010`.

---

## Existing bead state (`.beads`, prefix `bb-`)

| bead | status | conclusion carried |
|---|---|---|
| `fss-x4a.21.2` | open | feature umbrella; "Blocking: owner UID+ENR per cam" |
| `fss-x4a.21.2.1` | **closed** | UID/ENR/MAC extracted from MITM flows — the credential blocker is *retired* |
| `fss-x4a.21.2.2` | **closed** | live python proof, discovery→DTLS→login→K-auth→first frames |
| `fss-x4a.21.2.3`–`.6` | **closed** | tuple binding, simulator, Rust port, custody ingest |
| `fss-x4a.21.2.7` | open | GATE-090 qualification — "Only after this passes does the adapter leave non-default lab status" |
| `fss-x4a.21.3` | open | AOSU umbrella; "Blocking: device local_key + stream path" |
| `fss-x4a.21.3.1`, `.3` | **blocked** | MITM extraction; video path |
| `fss-x4a.21.3.2` | open | live Tuya session — "With the real local_key" |
| `fss-x4a.21.3.4`–`.6` | **closed** | sim, client, ingest semantics |
| `fss-x4a.21.3.7` | in_progress | qualification profile, unqualified |
| `fss-cgnug` | open | LAB-AOSU-8, the MITM-free local_key route (`fss-x4a.21.3.1` used `fss-cgnug` only as the text; they are not linked) |
| `fss-u3e43` | open | Yi ONVIF-after-pairing; unstarted |
| `fss-tp7iu` | open | Canary, needs device presence |
| `fss-yodhk.3`/`.4` | **closed** | OLD-probe cipher and Tuya beacon decoder as oracles |
| `fss-nltq0` | **closed** | the original passive recon campaign |

No bead in the store records a "root" or "RCE" conclusion for any camera. The nearest is
`fss-x4a.21.2.7`/`fss-x4a.21.3.7`, both about *qualification of ingest*.

## `fss-cli` binaries usable against these devices today

Run from a build of `fss-cli`; every live command requires `--owner-authorized`.

1. **`fss-discover`** — read-only census/fingerprint:
   `fss-discover --subnet 192.168.4.0/22 --iface 192.168.4.170 --owner-authorized --json`
   (documented form `docs/discovery_liveness_protocols.md:20-21`; `-h` text at
   `fss-discover.rs:23-40`). Emits the typed missing ingredient per candidate.
2. **`fss-capture-tutk`** — live Wyze stream into custody:
   `fss-capture-tutk --root <ABS> --cfg <cfg.json> [--secs N] --owner-authorized`
   (`fss-capture-tutk.rs:27-33`). cfg JSON (mode 600):
   `{"uid":"<20 chars>","enr":"<enr>","mac":"<AA:BB:..>","camera_ip":"192.168.4.23","camera_port":32761[,"bind_ip":"192.168.4.170"]}`.
   Exit artefacts: `fss.tutk_capture_cli.v1`.
3. **`fss-capture-tuya`** — live Tuya session into custody:
   `fss-capture-tuya --root <ABS> --cfg <cfg.json> [--secs N] --owner-authorized`
   (`fss-capture-tuya.rs:36-42`). cfg JSON:
   `{"ip":"192.168.4.37","port":6668,"local_key":"<32 hex>","proto":"3.5"[,"homebase":"…","model":"…"]}`.
   Exit artefact: `fss.tuya_capture_cli.v2`, always `media_continuity:"unverified"`.
4. **`fss-provision`** — offline, no device touched:
   `fss-provision families --json`; `fss-provision plan --family wyze_v4 --fw 4.52.17.26 --json`;
   `fss-provision sd-image --family yi --release <r> --json` (`fss-provision.rs:29-50`).
   Returns `missing_prerequisite` / `already_flashed` typed, exit 0.
5. **`fss-onvif`** / **`fss-capture-onvif`** — for the Yi device *after* pairing only.

Confirm with `cargo run --bin <name> -- --help`. `fss-capture-tutk`/`fss-capture-tuya` are the
two worth wrapping: both already own the socket, the clock and the cfg-file secret loading, and
both import the sans-IO cores directly, so a PoC can call the crate APIs beside them instead of
re-implementing framing.
