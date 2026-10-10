# Qualification profile — ADP-AOSU-P1MAX-LAB-001 (GATE-090)

Bead: fss-x4a.21.3.7. Registry row: `ADP-AOSU-P1MAX-LAB-001` (realized in
`crates/fss-reference/src/adapter_aosu.rs`, bead fss-x4a.30.89.9).
Status convention: **MEASURED** = retained proof exists in-repo (cited);
**PARTIAL** = some proof retained, remainder named; **BLOCKED** = no proof yet;
every BLOCKED names its exact unblock condition. Nothing here upgrades a claim
beyond the proof actually retained (AGENTS.md §12).

## Compatibility tuple binds

| Coordinate | Value | State |
|---|---|---|
| Camera model | C8S2EA11 (4x: Rear Door, Solarium, Front Door, Driveway) | MEASURED (owner MITM inventory, 2026-10-07) |
| Homebase | H2E (Glazero/Tuya stack) | MEASURED (beacon + surface evidence) |
| App | aosu 5.5.11 (build 21713) | MEASURED (owner MITM, 2026-10-07) |
| Region | US | MEASURED |
| Adapter revision | `gen:fss1:adapters-v1` (runtime id `adapter:adp-aosu-p1max-lab-001`) | MEASURED (typed registry row) |
| Protocol | Tuya LAN 3.5 (6699/GCM), 3.4 understood | MEASURED (oracle byte-exact vectors) |

## 1. Auth / revocation

- Session negotiation (3.4 + 3.5) implemented first-party in `fss-tuya`
  (`TuyaClient`, `HomebaseSim`): success, wrong-key silent rejection,
  proof-mismatch rejection, message-budget expiry — **MEASURED** against the
  deterministic simulator and tinytuya-oracle vectors (32/32 + 7/7 + 8/8 green).
- Live-device auth and revocation behavior — **BLOCKED** on the owner
  `local_key` (NEG-003, LAB-AOSU-1). Unblock: owner MITM fresh-login capture.

## 2. Lockout bounds

- Probing policy: all lab probing is owner-scoped, single-device, rate-limited,
  and stops at the first auth boundary (INTEROPERABILITY_LAB §4 stop rule).
- Actual device lockout/throttle behavior — **BLOCKED** (same unblock).
  Until measured, no automated auth-attempt loop may run against the homebase.

## 3. Soak / reconnect

- Simulator lanes: offline-for-N-frames, reboot recovery, session expiry,
  post-expiry renegotiation — **MEASURED** (client↔sim differential tests).
- Live soak/reconnect — **BLOCKED** (same unblock).

## 4. Firmware-drift quarantine

- Beacon announcements carry the firmware/protocol version field; the tuple
  is bound in the registry row and the compatibility table above — design
  **MEASURED** (beacon decode evidence: `"version":"3.4"` class markers).
- Automatic fail-closed quarantine on an unknown tuple (the TUTK lane's
  `known_tuples` pattern) — **PARTIAL**: mechanism exists in the Wyze lane;
  the AOSU live session (LAB-AOSU-2) must adopt it at session setup. Not yet
  wired — named, not silent.

## 5. Zero-secrets audit

- **MEASURED — PASS** as of 2026-10-09: every key in `fss-tuya` and the
  ingest mapper is a documented synthetic fixture (`fss_sim_test_key`,
  zero/vector keys); the well-known udpkey is a public protocol constant,
  not an owner secret; no real device key, token, Wi-Fi name, address, or
  capture payload exists anywhere in the repository. The real `local_key`
  has never entered the repo (it does not exist in our possession yet).

## 6. Simulator-vs-live differential

- Simulator: fully deterministic (counter-derived nonces/IVs; no clock/RNG)
  with oracle byte-exact wire vectors — **MEASURED**.
- Live differential: client against the owned H2E homebase — **BLOCKED**
  (same unblock). The only live-protocol evidence so far: the homebase drops
  a wrong-key cmd-3 silently on TCP 6668, matching simulator wrong-key
  behavior (2026-10-09 probe) — **PARTIAL**, recorded as a surface fact, not
  a session differential.

## 7. Cost rows

- Simulator message budgets are deterministic and asserted in tests
  (negotiation = 3 frames; heartbeat/dp_query/control = 1 round-trip each) —
  **MEASURED** (protocol-shape costs).
- Wall-clock/CPU/battery-cost rows — **BLOCKED** (same unblock; battery-cam
  wake economics are only measurable live).

## 8. Negative evidence (unsupported/unknown features named)

| Finding | State | Reference |
|---|---|---|
| Owner `local_key` not extractable without fresh-login MITM | MEASURED | NEG-003 |
| No local RTSP on homebase (554/8554 closed) | MEASURED (2026-10-09 probe) | DEVICE_ADAPTER_MATRIX §3 |
| TCP 443 = mutual-TLS device-cloud; no handshake without client cert | MEASURED | same |
| TCP 51028 = tinyproxy/1.11.2, does not openly forward | MEASURED | same |
| TCP 8888 app local channel: active-close on unframed input; handshake unmapped | MEASURED (behavior) / BLOCKED (semantics, LAB-AOSU-1) | same |
| dps schema semantics (dp→meaning map) | BLOCKED (LAB-AOSU-1; mapper preserves raw) | `ingest/tuya.rs` DpsRegistry |
| Battery-cam wake latency / event economics | BLOCKED (live) | — |
| Video stream path (local channel vs relay) | BLOCKED (LAB-AOSU-3) | — |

## Promotion posture

GATE-090 promotion is **not claimed**. Every BLOCKED row above collapses to a
single owner action: the LAB-AOSU-1 fresh-login MITM capture that yields the
`local_key`. The entire downstream stack (client, mapper, simulator
differential harness, registry identity) is built and oracle-verified; the
live evidence slots into prepared rows.
