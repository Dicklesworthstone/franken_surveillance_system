# UniFi Direct: experimental packet reference

This is an in-progress owner-authorized interoperability lane. Native discovery
has contacted one owner-controlled G4, and native ingress has processed a
passive capture through loopback. It does **not** yet implement a networked
controller, authenticate a peer, directly acquire a camera stream, write a
recording, or claim general device or firmware support.
Existing UniFi Protect export handling is separate and remains unchanged.

## Working reference and proposed route

The laboratory setup used xuio/scrypted-unifi-direct commit
`2920ce8896aadd603e2847d17554905592d155e8` and an owner-authorized G4 Instant.
The device reported firmware `UVC.v4.70.37.67.M_9b6a37f.240320.0635` on
2026-11-04. The Rust discovery probe and passive-media replay observations below
apply to that owned laboratory device and do not establish full compatibility.
The camera's management connection used a TLS WebSocket, and the controller
commanded a TCP push using `extendedFlv`. This wire description is based on the
reference implementation and must be checked against sanitized fixtures and
exact device/firmware tuples. The emulator's peer address and claimed identity
are not cryptographic camera authentication.

An eight-second, in-memory, passive observation of this G4's 720p push on
2026-11-04 yielded 1,100,611 contiguous captured TCP payload bytes. A structural
scanner found 208 video, 109 audio, and 2 metadata candidate tags; all 318
measured gaps between adjacent candidates were 16 bytes. Only aggregate counts
and sizes were retained from that observation. The observation started
midstream and did not validate sender identity, decode, continuity, every frame,
other camera models or longer runs; it does not justify assuming all UniFi
trailers are 16 bytes. No source media or credentials were added to the repository.
A second in-memory 720p observation found 208 structurally framed AVC sample
candidates. All 208 matched a four-byte NAL-length walk and reported a zero
composition offset; two claimed FLV keyframe type and 206 inter-frame type.
Those are observations of tag framing, not proof of the configuration record,
valid H.264 syntax, successful decoding, or future camera behavior.

On 2026-11-05, a native Asupersync UDP discovery test on `trj` sent one
owner-scoped local broadcast and received one UVC candidate: the G4 Instant,
whose response advertised the same address as its sender. This is an
unauthenticated discovery claim, not proof of ownership, adoption state, or
access authority. The test made no camera configuration changes. The exact
executed stripped test binary's SHA-256 was
`5f33b5be478defe9c7186c076ac5bba6a395325c476f6d78d442f65e65dd41af`.

Also on 2026-11-05, an eight-second passive capture of the running camera's
existing push was reassembled in memory. Because capture began midstream, the
laboratory harness prepended a synthetic FLV header and replayed the resulting
96,697-byte input through `TcpIngress` and `DirectIngress` over native
Asupersync loopback on `trj`. The Rust code returned 209 AVC sample-tag
candidates and preserved the complete received source in emitted records and
the remaining 16-byte tail. Eleven choices skipped an earlier incomplete
candidate; 315 records were therefore marked provisional. This is actual G4
traffic processed by the Rust path, not a direct camera TCP connection, a
verified boundary/decoder result, source custody, or a continuous recording.
No captured media or credentials were written into the repository.

The intended native path is an authority-scoped and cancellation-owned
controller, a bounded TCP ingress, source-preserving extended-FLV parsing, and
source-linked compressed pictures handed to the existing native media and
archive owners. Audio, detections, control effects, and outward interoperability
remain separately qualified capabilities. TLS dependency admission remains
open under `DEP-TLS-001` and must not be bypassed by an unqualified dependency
or a hidden foreign process.

The currently pinned `asupersync = 0.5.0` exposes a `tls` feature that enables
`rustls/ring`. That is not the pure-Rust provider direction specified in the
open TLS record. A newer local Asupersync checkout has a provider-independent
`tls-core` feature, but it is not the version pinned by this project and its
presence does not establish FSS admission or qualification. The implementation
must qualify a compatible provider and exact feature/dependency closure, either
through a justified Asupersync upgrade or the separately scoped TLS boundary
described by the existing ADR; enabling `tls` on 0.5.0 is not a resolution.
The intended `rustls-rustcrypto` provider's upstream README at revision
[`70f76c039e587192688af18a80d5d6435dedaf22`](https://github.com/RustCrypto/rustls-rustcrypto/blob/70f76c039e587192688af18a80d5d6435dedaf22/README.md)
advises against production use and identifies incomplete TLS support. The
exact release and provider choice therefore need review as part of the open
admission; this observation does not authorize switching to a native provider
or silently relaxing the project's policy.
At that development revision, its provider hook, key-exchange code and
randomized signer also obtain system entropy directly. The project requires
an explicitly scoped entropy authority, so swapping only one randomness hook
would not establish compliance; the exact candidate's full entropy path needs
qualification.
The existing dependency record principally describes outbound client TLS;
this use is an inbound TLS server. Its server certificate and key custody,
camera-side certificate validation behavior, server entropy, and peer identity
policy require explicit treatment in the applicable admission record and tests.
Possession of a server certificate alone does not authenticate the camera.
The locally installed Asupersync 0.5.0 source does expose a generic
`WebSocketAcceptor` over `AsyncRead + AsyncWrite`, bounded frame/message limits,
and read-ahead handling. It is a candidate for a request-owned WebSocket layer
once the TLS transport is resolved; its availability alone does not prove the
G4 handshake, cancellation, authentication, or compatibility with the final
TLS owner. The reference sends JSON in binary WebSocket messages, so a future
driver must preserve that framing and the `secure_transfer` subprotocol.
The owner must retain bytes read past the HTTP upgrade header, account for an
interrupted or partially written upgrade response, and keep the WebSocket
receive/close machinery serviced while waiting for the agreement delay. It
must not interpret a local successful write or a claimed MAC address as a
confirmed peer identity or completed camera effect.
The reference stream-start command is a remote settings change, not a passive
subscription: it can also redirect other tracks to a null destination. A
native stream owner must authorize and account for each changed track, avoid
disturbing another active consumer, and preserve uncertain outcomes. Merely
opening a listener does not start a camera push.
The pinned Asupersync TLS source explicitly says an interrupted handshake is
not cancel-safe: the owner must drop that connection, not reuse it. Listener,
handshake, idle, and receive budgets need bounded watchdogs and native-runtime
tests; deterministic in-memory socket tests alone cannot qualify kernel I/O.

## Current code boundary

`fss_packet::extended_flv` provides pure, allocation-free borrowed views of an
FLV header and a structurally valid tag, plus a bounded search for a successor
tag after a vendor trailer. The caller retains the original bytes, sees the
unmodified header and trailer, and must separately bind source offsets, clock,
identity, authority, and continuity. A matching back-reference is a heuristic
candidate: adversarial trailer bytes can contain a fake tag. The conservative
search defers later matches when an earlier candidate is incomplete, so the
result cannot change merely because reads were split differently. An explicit
provisional search can return a later candidate sooner and flags the unresolved
earlier candidate; it may change with more input and must not become a durable
source-boundary claim. The ingress owner must cap buffered bytes, processing
work and time: a malicious peer can otherwise deliberately delay completion.

`fss_packet::extended_flv::avc` adds bounded AVC video header, configuration
and length-prefixed NAL views. SPS, PPS, and sample NALs expose their exact
ranges in the original tag; signed composition offsets are preserved. A sample
is admitted only after its complete NAL-length walk passes. Frame-type flags
and observed IDR NAL type do not prove a complete or decodable picture. The
caller still owns cross-tag camera, stream-generation and configuration-epoch
binding; the structural parser does not validate full H.264 syntax.
`fss_packet::extended_flv::stream` incrementally frames caller-provided
contiguous bytes and returns exact original segments and offsets. Its optional
low-latency mode propagates a provisional marker after any skipped incomplete
candidate; its conservative mode can wait indefinitely on a plausible long
candidate, as observed on the real G4. Neither mode proves a genuine boundary.

The next media owner should bind each tag's range to a retained immutable source
object or an explicit non-retention record before composing tag-relative NAL
ranges with object offsets. It must keep source receive-clock observations
separate from the wrapping FLV timestamp and signed composition offset. A
configuration change or reconnect must fence the old stream/configuration
generation; passing a configuration from an unrelated camera or old epoch to
the pure parser is possible and must be prevented at that owner boundary.
Neither a provisional boundary nor a structurally matched IDR header becomes
a decoded-picture, coverage, authenticated-camera, or source-durability claim.
The recorded-RTP reference offers a useful design precedent: it validates
mapped NAL bytes against the borrowed original, and its import owner separately
stages original source chunks and records publication outcomes. An FLV owner
needs its own stream-offset and retained-object mapping, including the case
where a tag crosses object chunks; RTP sequence numbers and markers do not
exist on that path. Capture intervals must come from the receiving owner, not
from FLV media timestamps.

`fss_reference::unifi_direct` models the hello, time-sync, correlated
parameter-agreement messages, and preparation of a one-track stream-start
settings request without I/O. The caller supplies a stable
controller identity, exact wall-clock values, the monotonic interval after the
hello write, and local transport outcomes. Agreement preparation requires at
least a half second of owner-reported elapsed time; a future runtime must own
the clock and timer rather than inventing this observation.
Only a proven unwritten message may be retried; an indeterminate write retires
the session from automatic progress. Explicit close returns a payload-free
retirement record naming any unresolved prepared message, agreement request,
or time-sync reply; the I/O owner must retain or reconcile those facts. An
agreement reply is an observation, not authentication or adoption proof. The
stream-start reference prepares a literal IPv4 destination, an owner-supplied
stream name and typed channel/codecs; it deliberately omits other tracks. The
caller must authorize the destination and settings, ensure the listener exists,
account for other users and shared camera audio state, and retain the exact
request for reconciliation. A correlated settings response and any status
fields are untrusted observations, not proof of a successful setting or a
live stream. The reference has no WebSocket framing, peer identity, I/O owner,
event handling, or Asupersync-owned network service.
The future I/O owner must resolve the agreement write before feeding a reply
to this state machine, or retain and replay an early reply after resolving the
local write. The reference currently rejects a reply observed before the write
receipt; it does not buffer or silently discard that reply for the owner.

The packet and controller references have no native live controller, incremental
storage owner, media assembly, session-to-sensor custody, or persistence
format. Synthetic tests are not live-camera or security qualification. Do not
replace the running recorder or claim source continuity on this basis.

`fss_runtime::tcp_ingress` is an experimental bounded original-byte reader
for an already accepted Asupersync TCP stream. The explicit registered task
must hold resource-scoped media and network grants, and each read reserves
bounded byte and network budget before touching the socket. A dropped pending
read keeps its reservation with the same unforgeable task binding; a completed
read remains in the owner until the caller moves it or explicitly retires the
owner. The resulting source chunk is not a durable-custody receipt. Listener
authorization, peer authentication, idle supervision, canonical clock
observations, source publication, and binding to a camera/session remain the
caller's responsibilities. `fss_reference::unifi_direct::ingress` composes
that reader with the incremental FLV framer, preserving any incomplete source
at retirement. It is not connected to the controller or a durable recorder.

`fss_reference::unifi_direct::discovery` sends one explicitly scoped v1 UDP
query over Asupersync and returns bounded, unauthenticated UVC candidates. It is
not yet integrated with the general discovery command or an automatic enrollment
and setup owner. Wi-Fi onboarding for unprovisioned devices, credential custody,
current controller ownership and safe adoption remain independent requirements.
The experimental `fss-unifi-discover` command exposes this primitive as one
three-second broadcast on an explicitly specified IPv4 interface and prefix.
It requires `--owner-authorized`, an operator principal and an existing
authorization digest; the digest identifies the operator-supplied authorization,
but the command does not independently verify its provenance. Output labels
each candidate as unverified and setup as unavailable. It never enrolls the
device or proves that absent candidates do not exist. It is a standalone lab
projection, not the general discovery command or an automatic setup service.

## Scoped verification and handoff

At base `ec4b6a4c7073321cbd30162783adbbd101c0c0f6`, the three packet source
and test files were tested as a clean overlay on the remote Linux worker
`vmi1156319`: `cargo test -j 1 --locked --offline -p fss-packet --test
extended_flv_contract` passed all six synthetic tests. The clean-overlay
fingerprint was `5e63bbcc1426a47f99a7375ce64fd63ae4c2e530a2202ce0a471dc44ca4e838c`.
A subsequent clean-overlay run on the same worker passed
`cargo test -j 1 --locked --offline -p fss-packet --tests`, including the
extended-FLV and AVC synthetic contract suites and the existing packet tests.
Its source overlay fingerprint was
`a27c18c4eb967dda7814808ea6782fca21fc733a26160cf82aeb311b3eebe01e`.
After that run, the AVC suite gained a test wrapping the repository's generated
H.264 laboratory fixture in FLV tags. It passed all eight targeted tests on the
same worker at overlay fingerprint
`62db80e33c83f2b37ec5a7e5a26d97637d89fd38580660bb4cc24ab16ed26512`.
The test passes original SPS/PPS and one IDR NAL from FLV spans to the existing
bounded H.264 syntax parser; it does not decode the picture or establish
retained evidence.
The direct-controller reference and its seven synthetic contract tests passed
`cargo test -j 1 --locked --offline -p fss-reference --test
unifi_direct_controller_contract` on the same worker using clean overlay
`e31e756f825eb3c5ac4a25a2c9e2f4d742cd2afc6fc878480602154f1340adad`.
That test covers pure negotiation state and local write outcomes, not WebSocket
transport, TLS, camera interoperability, or remote effects.
After the one-track stream-start reference was added, the same command passed
all 11 synthetic controller tests on the same worker using clean overlay
`906b297aca8b8943ebb3efbb8db44455d37e1d5636659fe98bbf27755c423927`.
The extra tests cover serialized fields, selected-track scope, reply correlation,
input refusal, and written/unwritten/uncertain retirement. They do not send a
camera command or establish camera codec or settings compatibility.
At base `c09e0261f435b1bdcddbe5ce1f4c102a43c77098`, the bounded TCP reader and
async task boundary passed five native Linux contract tests plus all 17 existing
synchronous owned-execution tests on `vmi1156319` with clean overlay
`b6bcc47c497b9810b98a5f01cabe8b51a03a763838d5e3b2994d6df4b5170d5d`.
The TCP tests used real loopback sockets and covered a parked read being dropped
and retried, task-binding refusal, missing media authority, source retirement,
and exact byte transfer. They do not establish camera interoperability, live
recording, native async cancellation wakeup, or durable source custody.
The incremental framer passed four stream contracts plus six existing FLV and
eight AVC contracts at base `d229d849a7cfffa422f374d29c10b2423aa57440` and
overlay `854b05cf67a235cecf5d978c4e0f3ff47a91f096edbbba9709cbf8583be3ec29`.
The integrated TCP-to-FLV tests passed two synthetic cases at base
`07e56dd391c33dbb9b9f6b38d4fcb5c1aaa24187` and overlay
`eb2cdd3060d2ec3790992d4dddea18e3e2de25e1abe541a1e83f7702fd1b91ae`; their
separately invoked owner-camera replay test passed on `trj` as described above.
The native discovery target passed two synthetic tests at base
`e569638aa3f490d87b95c06d7cfbf7534442b848` and overlay
`425726a1619d754fe99d85ddbddce13fa74c11386e4373e54cdb28c5043031c2`, followed
by the separately invoked one-test real-device run on `trj` described above.
The discovery CLI's two argument and JSON-escaping unit tests passed on
`vmi1156319` using base `51bf09a2844a8ad82f03feac6fdb10eb35e1bc96` and
overlay `11684f16769ba8cbd79bb191db76138adc6766cfdbc31a2385400b20e707e551`.
This is not a full workspace, release, live-camera, media-decode, or
retention qualification. A separate test attempt on `ts1` timed out before
execution. The semantic-plane checker with doctests skipped reports 690 errors
both on the clean base and on this checkout, with identical findings; the new
module is registered as support and added no finding to that comparison.
Unmodified `fss-packet/src/onvif_metadata/receiver.rs` also has six
`clippy::result_large_err` failures under the requested `-D warnings` run;
the strict Clippy invocation did not pass and this lane makes no wider lint
claim. A second targeted Clippy run passed on `vmi1156319` with
`-D warnings -A clippy::result_large_err`; this exception is scoped to the
diagnostic run and is not a change to the release gate.
After adding the AVC reference, the same scoped Clippy command passed for both
extended-FLV test targets with overlay fingerprint
`637b015a5b31120ba24347ff3358afe994f12054e120b7741c425ef8590887da`;
the later multi-parameter-set test is covered by the full packet test run above.
The latest AVC test target, including the encoded-fixture handoff, also passed
the same scoped Clippy command at overlay fingerprint
`62db80e33c83f2b37ec5a7e5a26d97637d89fd38580660bb4cc24ab16ed26512`.

Current continuation: obtain real sanitized protocol fixtures without
disrupting the recorder; connect the bounded FLV AVC payload/configuration
reference and its typed source spans to a transport-neutral media ownership contract.
The active camera, the current transitional recorder, source capture authority,
TLS admission, controller cutover, and eventual deletion/retention proof are
independent open boundaries. The operating recorder must not be stopped merely
to test this parser.

## Next work and qualification

1. Exercise the reference against synthetic and sanitized owned-device traces;
   retain ambiguity and divergence instead of silently choosing convenient
   boundaries. Test maximum tag/trailer bounds and allocation/work budgets.
2. Implement region-owned, explicitly scoped TLS/WebSocket controller and
   camera push ingress after qualifying the exact TLS provider closure. Treat
   management commands as effects and preserve uncertain outcomes.
3. Bind immutable original byte spans and receive-time intervals to parsed
   configuration and compressed access units; build an FLV-source-specific
   recording path. The existing `AvcMuxer` takes `AvcPictureGroup` and emits
   `NalSourceSpan` mappings defined for RTP, so the current public API cannot
   honestly accept FLV source spans unchanged. Extract a transport-neutral
   picture/mux input and mapping contract or add an independently qualified
   FLV-specific owner; preserve the existing RTP contract and durable formats.
   RTP packet custody cannot be asserted for FLV bytes.
4. Qualify the single-camera vertical slice against the real device with a
   reversible one-controller-at-a-time cutover, then cover gaps, reconnect,
   disk pressure, audio policy, retention, and soak before migration.
