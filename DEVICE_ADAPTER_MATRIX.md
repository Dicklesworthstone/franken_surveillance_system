# Device adapter matrix

**Evidence snapshot:** 2026-10-07 (interoperability-lab update: Wyze TUTK-NEW protocol proven live on owner LAN; AOSU Tuya stack identified)
**Meaning of this file:** research and admission plan, not a list of working integrations

## 1. Adapter tiers

| Tier | Meaning | Release treatment |
|---|---|---|
| `T0 replay` | deterministic fixtures and prerecorded inputs | mandatory oracle; default-safe |
| `T1 open local` | standards with local owner-controlled transport | preferred production path |
| `T2 documented vendor` | documented protocol/API for exact product, implemented in first-party Rust | exact tuple; version-pinned; vendor SDK remains a lab oracle |
| `T3 authorized lab` | interoperability research against owner devices/accounts | non-default; exact firmware/app tuple; no auth bypass |
| `T4 import` | exported files or SD media | valid historical evidence, not live coverage |

## 2. Initial matrix

| Adapter ID | Product/surface | Known public interface | Initial tier | Planned capability | Current FSS state |
|---|---|---|---|---|---|
| `ADP-REPLAY-001` | FSS replay fixture | repository schema | T0 | packets, frames, metadata, faults, expected events | specified |
| `ADP-FILE-001` | MP4/MKV/JPEG/audio import | standard files | T0/T4 | bounded import with source hash and capture uncertainty | specified |
| `ADP-UVC-001` | generic UVC/UAC camera | USB UVC/UAC | T1 | modes, frames, audio, controls, reconnect | specified |
| `ADP-INSTA-LINK-001` | Insta360 Link | USB-C; UVC 1.1/UAC 1.0; H.264/MJPEG | T1 | reference UVC video/audio and bounded controls | research complete; unimplemented |
| `ADP-RTSP-001` | generic RTSP camera/NVR | RTSP/RTP | T1 | DESCRIBE/SETUP/PLAY, auth, RTP continuity, reconnect | specified |
| `ADP-ONVIF-T-001` | ONVIF Profile T client | H.264/H.265, imaging, events, metadata, PTZ/audio where supported | T1 | discovery, profiles, stream URI, events, settings, PTZ | specified |
| `ADP-ONVIF-M-001` | ONVIF Profile M metadata | analytics metadata/events | T1 | ingest metadata as derived vendor evidence | specified |
| `ADP-WYZE-V4-LAB-001` | Wyze Cam v4 | **Lab-proven 2026-10-07:** TUTK/IOTC NEW (0xCC51) — 0x1002 discovery, DTLS 1.2 ECDHE_PSK_CHACHA20_POLY1305 (PSK=SHA256(ENR)), AV login, K-auth, H.264 stream; owner-auth via account API inventory (UID+ENR); LAN-only after inventory | T3 | owner-authenticated live stream; **pure-Rust delivered:** fss-tutk sans-IO core (wire/digest/XXTEA/X25519/ChaCha20-Poly1305/DTLS/AV) + fss-reference `ingest::tutk` acquisition→capsule→ledger wiring | **Rust e2e vs simulator 4/4 lanes (fss-x4a.21.2.6): 30/30 frames byte-identical passthrough, ContinuityVerified, refusal/timeout lanes honest; live-camera revalidation + compatibility tuple pending (.7)** |
| `ADP-AOSU-P1MAX-LAB-001` | AOSU 4K P1 Max Solar | **Stack identified 2026-10-07:** Glazero/Tuya — UDP 6667 0x55aa cmd-0x23 beacons; 6699/GCM-dialect surface on TCP 6668 (differential probe); app API plaintext JSON (gz-* auth); device keys/stream setup ride the encrypted iotbing OEM channel (login-keyed) | T3 | owner-authenticated event/live/import path if reproducible | stack mapped; Tuya 3.5 client built (32/32 vectors); local_key extraction pending fresh-login capture |
| `ADP-DJI-FLIP-LAB-001` | DJI Flip | DJI Fly live view and QuickTransfer; not listed in current Mobile SDK products | T3/T4 | manual calibration capture bridge or bounded import | research target only |
| `ADP-S3-IMPORT-001` | owner bucket/NVR export | S3-compatible objects | T4 | immutable import and manifest reconciliation | specified |

## 3. Important corrections

### Insta360 Link

The Link is not a Wi-Fi security camera. It is a USB webcam that publicly specifies UVC 1.1/UAC
1.0 and H.264/MJPEG output. That makes it valuable as a high-quality, standards-based acquisition
fixture, but it does not validate Wi-Fi discovery, battery behavior, cloud auth, or outdoor camera
reconnect.

### Wyze Cam v4

Public product documentation describes 2.5K video, Wi-Fi, local microSD, app/cloud behavior, and
H.264, but does not publish an ONVIF or RTSP contract. Community reports are useful discovery
signals, not authoritative capability. The lab must independently establish the exact transport
and authorization path for devices/accounts owned by the operator.

**Lab resolution (2026-10-07, LAB-2026-10-07-002/003/007):** the transport is TUTK/IOTC over UDP
32761, NEW variant (magic 0xCC51) on firmware ≥ 4.52.9.5332 (operator fleet: 4.52.17.26,
model HL_CAM4). Authorization is owner-account inventory (official API yields per-cam
`p2p_id` + `enr`); afterwards the session is **LAN-only**: 0x1002 discovery (HMAC-SHA1,
session-port adoption), DTLS 1.2 `ECDHE_PSK_WITH_CHACHA20_POLY1305` with
PSK = SHA256(ENR) (NUL-truncated per TUTK SDK quirk), AV login, XXTEA K-auth, H.264/H.265
AV frames. Live python proof streams all 3 owner cams (fss-x4a.21.2.2). No RTSP/ONVIF
surface exists; credential bypass was not used and is out of scope.

### AOSU P1 Max

Public pages describe 4K, Wi-Fi, local microSD, app/base and optional cloud behavior, but no stable
open-stream contract was found. Battery/solar cameras may also be event-driven rather than
continuous. FSS must never represent an import or wake-on-event feed as continuous perimeter
coverage.

**Lab resolution (2026-10-07, LAB-2026-10-07-001/004/005/006):** the operator fleet is a
HomeBase H2E + four C8S2EA11 battery cams (only two online at capture). The homebase runs a
Glazero/Tuya stack: 0x55aa cmd-0x23 discovery beacons on UDP 6667 every 5 s, a Tuya 3.5
(6699/GCM) listener on TCP 6668, and silent TCP 443/8888/51028. The owner app API is
plaintext JSON with `gz-uid/gz-sid/gz-sign` session auth and yields full inventory plus the
account's Tuya identity (`tuyaUid`); device keys and stream setup ride the encrypted Tuya
OEM (iotbing) channel keyed at app login. Battery cams remain event-driven: an import or
wake-on-event feed is never represented as continuous perimeter coverage.

### DJI Flip

DJI documents live feed in DJI Fly and file transfer. The current Mobile SDK supported-product list
includes products such as Mini 3/Mini 3 Pro and enterprise aircraft, but not Flip. Therefore:

- no native SDK support claim;
- no autonomous mission claim;
- no unsupported control reverse engineering in the production path;
- initial value comes from manual flight, app-authorized capture, recorded file import, or a
  narrowly qualified owner-side display/capture bridge.

## 4. Readiness dimensions per adapter

Every adapter row expands into this matrix:

| Dimension | Required evidence |
|---|---|
| identity | exact manufacturer/model/hardware/firmware/app/API and sanitized fixture digest |
| discovery | bounded enumeration; no broad network scanning; deterministic identity |
| authorization | owner-provided credentials or local physical trust; no bypass; revocation test |
| secret custody | OS secret provider, scoped token, zero logging/prompt/evidence leakage |
| stream start | request/accepted/first-frame/continuity states with receipts |
| media | exact codec/container/modes, parameter changes, corrupt input behavior |
| timestamps | clock basis, jitter, buffering, reconnect, sequence discontinuity |
| events | semantics, duplication, ordering, backfill, vendor false positives |
| controls | supported PTZ/settings; prepare/commit/idempotency/observation |
| reconnect | network loss, power cycle, token expiry, app/cloud outage, IP change |
| cancellation | adapter-region quiescence, obligation closure, and descriptor/credential release |
| firmware drift | unknown generation behavior and safe downgrade/disable |
| privacy | masks, audio defaults, log redaction, vendor cloud disclosure |
| performance | source bitrate, CPU/RAM, reconnect latency, packet loss, energy |
| soak | long-run continuity and leak evidence |
| negative evidence | unsupported features, failed methods, known ambiguity |

No aggregate “supported” field replaces the dimensions.

## 5. Adapter capability protocol

A production proprietary adapter is first-party safe Rust. It may run in-process under a narrowed
`Cx` or in a separately supervised **FSS Rust** executable when fault/resource isolation is worth
the protocol cost. It receives only:

- a one-device/account capability and exact compatibility tuple;
- an opaque secret handle rather than plaintext in config or command arguments;
- network destinations narrowed to registered device/vendor endpoints;
- explicit CPU, memory, bandwidth, retry, deadline, and output budgets;
- a typed acquisition/control request and anchor;
- bounded reserve/commit output subjects.

It emits:

- immutable device/firmware/app/protocol identity;
- acquisition and control receipts;
- packet capsules or imported-file object roots;
- health, coverage, clock, continuity, and degradation evidence;
- sanitized diagnostics and a terminal drain certificate.

It cannot open the canonical ledger directly, enumerate unrelated secrets/devices, access the
archive keyring, mutate model/calibration/policy state, or recover effect authority from ambient
configuration. Vendor SDKs, app automation, browser capture, and foreign helper binaries remain
fixture-only laboratory tools and cannot become a supported production adapter path.

## 6. Authorized interoperability workflow

1. Isolate the owned test device/account on a lab network.
2. Record exact hardware, firmware, app, region, account settings, and consent.
3. Use normal vendor authentication and operation first.
4. Capture the smallest traffic/behavior sample necessary to describe the owner-side interface.
5. Sanitize credentials, identifiers, audio/video, and third-party data immediately.
6. Produce a protocol hypothesis and deterministic simulator fixture.
7. Implement against the simulator before live hardware.
8. Differentially compare simulator and device under bounded operations.
9. Test token expiry, password change, device removal, rate limits, cloud outage, and firmware drift.
10. Publish only interface descriptions needed for interoperability; never publish live secrets,
    universal tokens, bypasses, persistence, or third-party access techniques.
11. Keep the adapter non-default until security/privacy/compatibility gates pass.

## 7. Standards preference

FSS prefers ONVIF Profile T over legacy Profile S for new IP integrations. Profile T’s published
scope includes H.264/H.265, imaging, motion/tamper events, metadata, HTTPS streaming, PTZ, and
bidirectional audio where the device supports them. Profile M is treated as optional analytics
metadata and never as ground truth: vendor object labels remain derived evidence with exact device
identity.

The ONVIF conformant-products database—not a marketplace listing or logo—is the authority for a
product conformance claim.

## 8. Qualification fixtures

Initial device fixture families:

- stable 30/60-minute stream;
- packet loss, reorder, duplicate, late packets, burst jitter;
- power cycle and Wi-Fi roam;
- credentials revoked/rotated;
- app/cloud service unavailable;
- firmware known/unknown;
- day, low light, IR, glare, rain, snow, insects, foliage;
- privacy-mask and audio-disabled operation;
- control timeout before/after physical movement;
- cancellation during authentication, first-frame wait, decode, and reconnect;
- local spool full and archive backlog.
