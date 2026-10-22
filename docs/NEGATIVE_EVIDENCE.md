# Negative evidence ledger

This ledger records hypotheses that failed, did not improve the system, or produced a narrower
result than expected. A failed experiment is not deleted when a new candidate appears.

## Required fields

| Field | Meaning |
|---|---|
| ID | Stable `NEG-###` identifier |
| Date / commit | Exact experiment context |
| Hypothesis | What was expected and why |
| Setup | Corpus, device/model/firmware/platform, policy, command, and artifact digests |
| Result | Measurements, failures, divergences, and confidence |
| Decision | Reject, retain as oracle, narrow scope, or revisit |
| Revival condition | New evidence that would justify repeating the work |

## Entries

No implementation experiments have been run. The architecture research already records these
negative constraints:

### NEG-001 — Do not make DJI Flip SDK support an architectural dependency

- **Hypothesis:** the drone can be treated as a normal officially supported DJI Mobile SDK source.
- **Finding:** current public supported-product documentation does not establish DJI Flip support.
- **Decision:** recorded-file import and authorized capture-bridge experiments only; manual flight;
  an unsupported result is acceptable.
- **Revival:** an official compatible SDK/product listing or a repeatable, owner-authorized,
  supportable capture surface.

### NEG-002 — Do not treat proprietary app access as a stable camera standard

- **Hypothesis:** a consumer camera advertised with Wi-Fi/cloud viewing has a stable local stream.
- **Finding:** public owner-facing documentation for target proprietary products does not establish
  a durable ONVIF/RTSP contract.
- **Decision:** standards-first adapters; vendor paths remain exact-tuple interoperability-lab work.
- **Revival:** official local API/profile support or a qualified owner-authorized adapter matrix.

### NEG-003 — Do not select one frontier VLM as the complete security stack

- **Hypothesis:** the newest large multimodal model can replace detection, tracking, geometry, and
  calibrated event policy.
- **Finding:** latency, licensing, temporal grounding, reproducibility, and failure isolation differ
  by task; no single current candidate establishes the complete contract.
- **Decision:** progressive model cascade with immutable generations and held-out event gauntlets.
- **Revival:** a candidate passes every task, license, cost, privacy, and deterministic boundary
  against the decomposed incumbent under the same workload.

### NEG-004 — TUTK OLD-protocol LAN search does not discover Wyze NEW-protocol firmware

- **Hypothesis:** the credential-less TUTK/IOTC OLD-protocol `0x0601` LAN-search probe
  (TransCodePartial cipher, byte-exact vs the CuboAI-verified oracle) discovers the owner's Wyze
  cameras on the authorized LAN, giving a pre-credential discovery path.
- **Date / commit:** 2026-10-07 first negative (python oracle); 2026-10-08 Rust re-run at
  `0dfff448` (`fss-tutk::oldproto` + `examples/oldproto_probe.rs`).
- **Setup:** owner LAN 192.168.4.0/22; 88-byte `0x0601` probe, empty UID (all devices), 3 rounds;
  targets: 255.255.255.255:32761, 192.168.7.255:32761 (directed broadcast), and unicast to all
  three known Wyze addresses (192.168.4.23/.24, 192.168.5.242). Cipher differential vs oracle:
  2,700 cases, 0 failures.
- **Result:** 0 answers in every round — Wyze NEW-protocol (0xCC51) firmware absorbs OLD-protocol
  probes without responding (does not answer empty-UID search). One camera (192.168.4.23) was
  verifiably awake and answering NEW-protocol discovery on port 32761 during the same window, so
  the absence is protocol behavior, not an offline camera.
- **Decision:** narrow scope — the probe is retained for older-firmware Wyze tuples and other TUTK
  brands (CuboAI, Shenzhen IPCs); it is NOT a discovery path for the qualified
  HL_CAM4/4.52.17.26 tuple. NEW-protocol `0x1002` discovery is the only supported path there.
- **Revival:** a Wyze firmware generation that answers `0x0601`, or an owner-added device of
  another TUTK brand on the LAN.

### NEG-005 — TUTK-NEW discovery corroboration is not credential-less

- **Hypothesis:** a credential-less 0x1002 NEW-protocol discovery probe can corroborate
  a Wyze-OUI host as a live TUTK camera during LAN discovery (any response proves a
  0xCC51 listener, regardless of auth outcome).
- **Date / commit:** 2026-10-09; probe at `fss-reference/src/discovery/service.rs`
  (removed; the note remains).
- **Setup:** identical probe bytes and socket shape, two identities: the owner's real
  camera identity (uid/enr/mac from the lab cfg) vs a foreign test identity, both to
  the same awake camera (192.168.4.23:32761, verified answering minutes earlier).
- **Result:** owner-identity probe → response from :44650 every time; foreign-identity
  probe (either source bind) → zero responses across repeated attempts. The camera
  silently absorbs probes whose 0x1002 HMAC is not keyed by ITS OWN uid/enr/mac.
- **Decision:** discovery cannot corroborate Wyze hosts without owner credentials.
  Fingerprint keeps bare Wyze-OUI at Possible (Wyze also makes non-camera devices);
  the dispatch path names UID+ENR as the ingredient that both corroborates and
  onboardss. Tuya beacons remain credential-less corroboration (unauthenticated
  broadcasts).
- **Revival:** a firmware generation that answers discovery with a well-known or
  identity-less key, or an owner-provisioned credential store wired into discovery.

### NEG-006 — Yi IPC (Zowee ODM) advertises ONVIF but gates the SOAP service pre-provisioning

- **Hypothesis:** a Yi camera (b0:d5:9d Zowee ODM MAC, generic "IPC" ONVIF stack,
  192.168.6.156) that answers ONVIF WS-Discovery with `dn:NetworkVideoTransmitter` and
  Profile/Streaming scopes exposes its ONVIF SOAP service for standards-first access
  (RTSP/ONVIF without the vendor app).
- **Date / commit:** 2026-10-09; passive LAN observation, owner device.
- **Setup:** WSD multicast Probe (full WS-Addressing header incl. MessageID) → ProbeMatch
  with XAddrs `http://192.168.6.156/onvif/device_service`, Scopes
  `Profile/Streaming hardware/IPC type/video_encoder type/audio_encoder type/ptz
  type/video_analytics`. Then TCP connects to the advertised port 80 (+554/8554/8899),
  full 1-65535 scan, source-bound connects from both host interfaces, SOAP-over-UDP to
  :3702, unicast WSD, and an 8s rapid-retry window immediately after each ProbeMatch.
- **Result:** the WSD responder is active and reliable (answers within seconds whenever a
  properly-headered Probe arrives; silently ignores header-less probes — MessageID/Action
  are mandatory). The TCP listener NEVER opens: port 80 RSTs when idle, times out right
  after WSD exchanges, zero open ports across the entire range in every state. The SOAP
  service is gated behind first-time vendor-app provisioning (classic generic-IPC
  firmware behavior); UDP surface is silent everywhere else.
- **Decision:** standards-first onboarding of this device requires completing vendor-app
  provisioning once (owner decision), after which the advertised ONVIF service is the
  intended path — no exploit sought. The advertisement itself is retained as camera
  evidence: `WsdMatch::is_onvif_camera()` classifies from ProbeMatch types/scopes even
  while the SOAP listener is gated. AOSU-style vendor workarounds stay out of scope.
- **Revival:** provisioning the device through the vendor app (which the owner controls),
  or a firmware generation that ships with the SOAP listener open.

## NEG-006 — Wyze Cam v4 4.52.17.26 (2026-10-22, GrayBadger)

**Hypothesis.** The published v3 TUTK chain still works on the v4, giving root over the LAN.

| Attempt | Result | Decision |
|---|---|---|
| CVE-2023-6324 empty-PSK identity (`AUTHTKN_`, and `AUTHTKN_deadbeef`) | DTLS fatal alert 115 `unknown_psk_identity`; `AUTHPWD_admin` + owner ENR succeeds to streaming | refuted, owner ENR is mandatory on this build |
| CVE-2023-6322 `audioEncoderList` overflow with 11/29/38/300 entries | K-auth fine up to the 900-byte payload guard; loop is hard-capped at 10 ints into a 10-int array | refuted, the v3 ROP chain cannot be reused |
| 0x284C with 257/258/261/765 junk bytes | acked `0x284D=02`, no reboot | retained as "reachable but format unknown" (`bb-h001`) |
| `AUTHTKN_` over the legacy 0x0402 path (stock PoC semantics) | discovery 0x0402/0x0001 answers and leaks the UID; `0x1b02` session request never answered | PoC stalls before `SSL_connect`; use the CC51 session instead |
| Enabling telnet via `paracfg` item 11 over K10000 `cameraInfo` (`settingParm.telnet` string and number, `settingParm.telntSwitch`, top-level `telntSwitch`) | K-auth and stream unaffected, TCP/23 stays closed | `fss-wyze-telnet-item-11-g7xy3` |
| Enabling telnet via ioctl 0x1f40 (JSON body, then raw LE pair `80 27 01 00`) | ack `0x0001` echoes the cmd, port 23 closed | same bead |

**Revival:** a captured app→camera zone/settings save (the app can emit one), a firmware build
below 4.52.17.26, or a decoded paracfg blob layout.

## NEG-007 — CC51 frame disembodiment (same session)

**Hypothesis.** The Pan-v3 PoC frame can be replayed byte-for-byte on the v4.

| Framing tried | Result |
|---|---|
| PoC bytes verbatim (0x540 B) as raw DTLS appdata | accepted, no reaction |
| `0c000000` + session id + PoC bytes | accepted, no reaction |
| `0c000b00` + PoC bytes (v3 prefix duplicated) | accepted, no reaction |
| `07 01` + PoC bytes minus 4 (channel/frame-type rewrite) | treated as AV data: stream slowed to ~1.4 fps |
| same, declared size forced to `0x800` / `0xFFFF` at `[16..18]` | **crash + reboot in ~8 s** |

**Decision.** The header is channel/type at `[0..2]` and declared size at `[16..18]`; a frame of
1264 real bytes declaring `0xFFFF` is the crash primitive. Retained as the base for a heap spray.
**Revival:** a v4 heap object with a controllable function pointer, or an info leak.

## NEG-008 — paracfg telnet item 11 is reachable, but there is no telnetd (2026-10-22, FuchsiaCat)

**Hypothesis.** The only shell-executing config path (`telnetd &`) can be triggered over the wire
without cloud, giving a root shell.

| Attempt | Result |
|---|---|
| Table audit | entry **is** present: `0x8d5da8 {0x2780,0x2781} -> 0x462878` (earlier "not in table" note was wrong) |
| `0x2780` payload `01`, `02`, then `01` on .4.23 | each acked `0x2781=[01]`; handler calls `paracfg_set(0x0b,v)` + `exec_shell_async("telnetd &")` for v=1, `killall -9 telnetd` for v=2 |
| TCP/23 after both transitions | refused every time |
| Rootfs audit | **no `telnetd` anywhere**: not in busybox applets (`/bin`, `/sbin`), no dropbear; `exec_shell_async` fails silently |

**Decision.** Item 11 is dead on 4.52.17.26 unless a `telnetd` binary is added. The command/response
pair is retained for any build whose rootfs ships one. (`fss-wyze-telnet-item-11-g7xy3`)

**Revival:** firmware with busybox `telnetd`; or a writable PATH entry plus a delivered binary.

## NEG-009 — 0x284C (CVE-2023-6322 handler) is length-capped on the v4 (2026-10-22, FuchsiaCat)

**Hypothesis.** The v3 motion-zone stack overflow survives on the v4 handler.

| Check | Result |
|---|---|
| Handler 0x464258 | zone count must be `< 4`; each zone is a 32-byte rect + length byte |
| Copy bound | data copied into 178-byte strides only when `1 <= len <= 144` (total 534 into 540, then 535) |
| Wire test | count 1 and count 4 sends do not crash; high counts ack `02` (rejected), junk lengths are skipped |

**Decision.** The 144-byte cap is the guard the v3 code lacked. Not re-exploitable via the same
shape; a bug would need a different field of the handler.
