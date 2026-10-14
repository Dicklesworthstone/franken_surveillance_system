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
caller-owned. `seal` requires the exact active generation. `supply_timing_for` requires
an exact picture ticket, not just a generation. Neither RTP time nor arrival time
is silently used as decode time.

## Match the selected description before SETUP

The original `AutomaticLiveHevcRecording` now checks the recorder's expected
payload against the actual selected HEVC description before capture can schedule
SETUP. A matching offer in another media section cannot repair a mismatch. A
refusal uses the existing `Capture(Collection(StreamMismatch))` category and
transfers the exact original SDP/control event in `unoffered_event`, alongside
native/capture retirement and any already-read TCP suffix. It sends no SETUP,
creates no false media samples and is not eligible for automatic reconnect.
Plain and Digest negotiation use the same gate; informational responses do not
trigger it. Independently supplied VPS/SPS/PPS and source bytes retain their
existing validation owners and are not replaced by signaling.

## Picture-specific timing replies

After `poll` returns the native `TimingRequired` event, obtain its
`HevcTimingTicket` from `timing_ticket()`. The ticket contains the original bounded
picture metadata and a supervisor-local ordinal. A private in-memory owner
identity distinguishes supervisors even when source keys, timestamps and ordinals
are identical. Copies refer to the same request, not additional admissions.

```rust
// `supervisor` already owns the authorized native recording and has returned
// TimingRequired. `timing` comes from the independent owner-approved clock basis.
let ticket = supervisor.timing_ticket().ok_or("no held picture")?;
let request = ticket.request();
// An asynchronous timing worker may hold a ticket clone with this exact request.
let timed = supervisor.supply_timing_for(&ticket, timing, now, authority)?;
```

A successful timing admission consumes the ticket. Repeated polls and safe
invalid-value refusals preserve it and the original residence deadline. A stale
same-generation reply, a ticket from another supervisor, or an old-generation
reply returns `Timing(StaleTicket)` without timing a picture or performing native
I/O. Live authority, cancellation, absolute lifetime and scheduler work are still
checked first: a stale ticket cannot hide revocation. Native fatal refusal and
all terminal/cancel paths invalidate pending tickets while returning original
work. Ordinals never reset across reconnects; exhaustion fails closed instead of
wrapping.

Tickets are process-local correlation objects, not durable source identities,
trusted timestamps or capabilities. They cannot be serialized and restored as
permission to time a picture. The new `supply_timing_for` method is additive. The original
`supply_timing(key, ...)` remains available for synchronous current-picture callers;
it still fences only generation and cannot detect same-generation delayed replies.
Both paths consume the pending ticket on successful native timing admission. Use
only the ticketed method for asynchronous/retryable timing. Existing HEVC, native
and AVC timing method signatures are unchanged.

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

The capture-selection and picture-ticket increments were executed locally with
nightly-2026-08-31 (rustc 1.100.0-nightly, 908501772). The complete source snapshot
070282d7e71a0b22513f53d901809cd98ee4505d and installed compiler came from the
checksum-verified native-supervision reproduction artifact. Both increments were
applied to that source without changing dependencies or compiler inputs. Run:

```sh
cargo +nightly-2026-08-31 test --locked --offline \
  -p fss-reference --lib rtsp::live_avc::automatic
cargo +nightly-2026-08-31 test --locked --offline \
  -p fss-reference --test supervised_hevc_recording_contract \
  --test live_hevc_recording_contract --test hevc_recording_selection_contract \
  --test hevc_capture_contract --test hevc_recording_publication_contract
```

The supplied tests cover plain/Digest short I/O, actual picture/EOF draining,
fresh generation/authentication, source EOB with final timing, unverified tails,
pre-connect resource/scope refusal, immutable profiles, stale timing, revocation,
packet gaps, prepared-window cancellation and root-last publication/cold reopen
of source windows after reconnect capacity runs out. Additional contracts cover
selected-description refusal before SETUP, exact metadata plus read-ahead
retirement, selected-track isolation, interim responses and revocation precedence.
Timing contracts cover stable repeated polls, single-use replies, identical
metadata across owners, safe value correction, counter exhaustion and old-ticket
refusal across picture/generation transitions. All 101 tests in the above
selection passed: 44 automatic/supervision unit tests and 57 HEVC integration
tests, including all seventeen newly added tests. The first selection-only
increment separately passed all 30 selected integration tests. Changed Rust
files pass the pinned formatter. These results describe the exact source
snapshot plus these increments, not unrelated concurrent changes subsequently
combined on main. A broader `--lib rtsp::` run also passed all 190 unit tests
(including the 44 above), for 247 distinct passed tests including integration.
Clippy was executed and failed on six denied `expect()` calls in untouched
`ingest/tutk.rs`, `discovery/tuya_beacon.rs` and `discovery/census.rs`; existing
size/style warnings remain in the capture types. This is not a clean Clippy,
native-platform, DSR, release or field-continuity qualification.
Cold supervisor resume, production asynchronous orchestration, fleet scheduling,
TLS, independent whole-run storage budgets and measured resource refunds are not
implemented by this API. Source custody and publication still have their own
separate grants, budgets and retention obligations. No bead is closed by this work.
