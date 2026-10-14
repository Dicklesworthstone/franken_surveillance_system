# Bounded native HEVC recording supervision

`rtsp::live_avc::automatic::reconnect::hevc::SupervisedHevcRecording` composes the
existing automatic native HEVC recorder with the shared reconnect schedule and
whole-run resource reservations. It does not replace `fss-capture-rtsp reconnect`,
introduce a runtime, implement a daemon, or qualify a physical camera.

## Admission and ownership

Construct with an exact `TcpBinding`, `ReconnectPolicy`, owner monotonic time,
and optionally an independent `ReconnectBudget` using `new_with_budget`.
Construction performs no I/O. `connect` takes a complete `LiveHevcConfig` and
`LiveHevcRecordingConfig`; the first admitted profile pins the protocol scope,
realm and authentication policy, all HEVC receive limits, exact VPS/SPS/PPS byte
identities (including uninterpreted suffixes), sensor and stream, payload type,
media timescale and collection limits. Later attempts may explicitly shrink TCP
or native step ceilings but cannot change that profile. Each attempt supplies its
new stream generation and explicit source anchor/receive-clock provenance.

Each admitted attempt reserves its complete native receive/send/call/step ceiling
before opening a socket. Reservations never refund. Resource, scope or backoff
refusal opens no socket, consumes no attempt ordinal and does not install a first
profile. Scheduler calls still consume their separate work allowance and check
live authority and time. The original recorder validates native configuration.

`poll` returns the existing native recording output tagged with its generation.
Every wire chunk, consumed authentication challenge, original receiver event,
source-only picture-boundary witness, prepared window and retirement remains
caller-owned. `supply_timing` and `seal` require the exact active generation. A
stale timing response cannot alter a replacement recorder, and neither RTP time
nor arrival time is silently used as decode time.

## Reconnect is not source continuity

Eligible transient connect/read/write failures transfer their original retirement
and enter `Retired`. Physical TCP EOF must additionally pass through the original
receiver and complete capture drain. A closed socket, prepared window or local
`Ended` value alone cannot authorize a retry. Handle all terminal ownership, then
call `acknowledge_retirement` with a fresh owner-clock observation to start capped
backoff. The next `expected_binding()` has a fresh generation and needs independent
live authority. Every attempt starts fresh DESCRIBE/authentication/SETUP/PLAY.

HEVC EOB is an observed bitstream end, not a camera outage. Its final picture can
still need explicit timing and publication; after native draining it stops with
`ReconnectStop::SourceEnded` rather than reconnecting. This additive stop variant
must be handled by callers exhaustively matching `ReconnectStop`. Existing AVC
classification, budgets and constructor signatures are unchanged. No canonical
recording, journal or durable schema bytes change.

RTP markers and TCP EOF cannot complete an HEVC picture. Unverified tails remain
in their original events; they do not become selected samples or false continuity.
Packet gaps, codec faults, authentication/authority refusals and exhausted native
work stop the supervisor. Cancellation preserves original ownership and an already
established terminal reason. It sends no TEARDOWN and grants no publication effect.

## Validation and remaining boundary

This increment supplies native loopback and pure classification tests. Run the
following on the repository-pinned compiler; do not treat the presence of tests
as evidence they passed:

```sh
cargo +nightly-2026-08-31 test --locked --offline \
  -p fss-reference --lib rtsp::live_avc::automatic
cargo +nightly-2026-08-31 test --locked --offline \
  -p fss-reference --test supervised_hevc_recording_contract \
  --test live_hevc_recording_contract
```

The supplied tests cover plain/Digest short I/O, actual picture/EOF draining,
fresh generation/authentication, source EOB with final timing, unverified tails,
pre-connect resource/scope refusal, immutable profiles, stale timing, revocation,
packet gaps, prepared-window cancellation and root-last publication/cold reopen
of source windows after reconnect capacity runs out.

Compilation, formatting and Rust test execution have not been verified for this
patch. It is not a DSR, platform, camera, field-continuity or release qualification.
Cold supervisor resume, production asynchronous orchestration, fleet scheduling,
TLS, independent whole-run storage budgets and measured resource refunds are not
implemented by this API. Source custody and publication still have their own
separate grants, budgets and retention obligations. No bead is closed by this work.
