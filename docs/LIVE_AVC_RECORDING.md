# Native live H.264 capture and recording

`rtsp::live_avc::LiveAvcConnection` composes the native TCP link with the existing
Digest/RTSP client and loss-aware RTP/AVC receiver. Its
`recording::LiveAvcRecording` owner additionally connects ordered receiver events
to `RecordingCapture` and the source-linked recording muxer. These are executable
Rust APIs, not a CLI daemon, hardware qualification, or a new asynchronous runtime.

## Establish explicit authority and scope

The runtime supplies one `TcpBinding`: an exact approved socket address, RTSP
host/port authority, stream generation/SSRC, and explicit plaintext approval. The
presentation and control URI authorities must match that binding before a socket
can open. No DNS, redirect, peer selection, alternate codec, or reconnect occurs.
`TcpAuthority` checks the live lease/revocation/cancellation/budget at I/O boundaries.
Production adapters still need the accepted Asupersync-owned topology and their
own secure credential, timing, custody, readiness and shutdown owners.

For recording, additionally supply `LiveRecordingConfig` with canonical sensor,
stream, generation, authority/receive-clock provenance, expected RTP payload type,
media tick rate and `CollectorLimits`. Invalid recording configuration is rejected
before connecting. Neither a URI, a checksum, nor a caller-provided timestamp grants
permission to contact a camera, retain evidence, or disclose footage.

Create a connection using `connect(config, now, authority)`, or the combined owner
using `LiveAvcRecording::connect(config, recording, now, authority)`. All `now`
values are from the same runtime-owned monotonic clock; agents must not choose them.
The absolute connection lease is never renewed by challenges, short reads, or EOF.
Both the connection and combined recorder have a finite driver-call budget in
addition to socket-call, byte, source/picture and metadata ceilings.

## Drive negotiation and I/O

Explicitly call `request` for DESCRIBE, SETUP and PLAY. The first request is unsigned;
the accepted server challenge can be answered through `respond` using borrowed
`DigestCredentials` and fresh owner-generated cnonce entropy. Later requests use
the existing bounded Digest lifecycle. No password, cnonce generator or credential
lookup is installed in the connection. A queued command is not a send receipt;
`TcpWriteStep::Sent` is not a matching server acknowledgement. Playing means that
PLAY was acknowledged, not that frames or continuous coverage exist.

Drive `poll(SocketReadiness, now, authority)` from the owning readiness/timer loop.
Each call performs bounded local progress and at most one native socket operation.
The caller must also arrange the `next_wake_ns` timer when the socket is silent.
Writable readiness advances the exact unsent suffix, never replays a prefix. A
held authentication challenge stops socket read-ahead. KeepAliveDue is surfaced
for an explicit owner command, not an automatically authorized effect.

`LiveAvcStep::Wire` transfers exact original TCP bytes before any parsed results
from them. Those bytes can contain private control information or challenges;
never print them. The caller must retain them or account for an explicit omission
before polling again. This transfer is not a durable custody claim. The structured
outer Debug implementations do not dump URI, credential, challenge, or media bytes.

## Collect recording windows without inventing time

The combined owner drains capture before reading more network input. Ordered RTP
sources reach the existing collector before their completed pictures. On
`CapturePoll::TimingRequired`, call `supply_timing` with an explicit `RecordingTiming`
containing decode time, positive duration and composition offset in the configured
media ticks. RTP timestamps and arrival timestamps are not substituted for DTS,
duration or physical capture time. Invalid timing preserves the held picture for
correction; waiting does not extend its original bounded lifetime.

Process `TimedCapture` too: non-IDR startup pictures and unselected originals remain
explicit owned results, not silently recorded or dropped data. Under collection
pressure, `seal` can prepare a completed prefix; poll to take that exact window,
then publish or otherwise assume custody before driving more input. Collection
limits and input lifetimes remain enforced, and no second unbounded queue is added.
The lease/authority checks also run while capture is waiting for timing or space.

`CapturePoll::Window` is the existing `PreparedRecording`. Its four child objects
are original RTP source, MP4 initialization, MP4 media, and the canonical index.
Pass it unchanged to `recording::local::RecordingPublication`, using a separately
owned `LocalRootPublisher`, slot, budget, deadline and cancellation policy. Child
staging is source-first; root publication happens last. Retain the plan until the
exact root is durably published or reconciled. A prepared window, queued request
or parsed picture alone is never reported as published evidence.

## Faults and terminal ownership

A recording discontinuity, receiver restart, fatal protocol event, or expired
collection lifetime stops the live socket as well as the collector. Cancellation
never automatically sends TEARDOWN or claims remote completion. A partial request,
unqueued prepared request, unread TCP chunk, held challenge, receiver retirement,
untimed picture, completed unpublished group and trailing source remain explicit
terminal ownership. Already transferred prepared windows are not retracted.

Actual TCP EOF first drains accepted protocol/media input. Only an actual receiver
EOF is offered to recording completion; an error is not substituted for EOF.
Incomplete fragments and unverified terminal picture boundaries cannot become
completed samples. Source and retirement events remain distinguishable from a
successful window or physical absence. After terminal ownership transfers, repeated
polls return `Ended` without emitting another receipt or replaying source.

Raw-ingress retention, encryption, physical capture-clock calibration, a persistent
recording/archive scheduler, camera discovery, TLS, reconnect/backoff and actual
camera qualification are not supplied by this composition. The recorded media is
source-linked compressed H.264, not a certificate of decoded picture completeness.

## Authored regression tests

The connection module has nine native-loopback tests for scoped negotiation,
Digest, short writes, readiness, held challenges, queue refusal, revocation,
deadlines, EOF and finite work. The recording module has ten tests covering actual
synthetic AVC bytes sent through a real loopback socket, explicit timing, timing
expiry/refusal, source preservation, pressure/sealing, revocation, wrong-stream
failure and truncated-fragment EOF. Its publication test stages source first,
checks absence of a visible root before publication, reopens local custody with
identical source/media/index identities, and compares roots across TCP chunk sizes
1, 7 and 4096. All endpoints are local fixtures, not third-party cameras.

```sh
cargo test -p fss-reference --lib rtsp::live_avc
```

These tests were authored but **not executed** in this editing environment:
`cargo` and `rustc` are unavailable. API review, lexical checks and exact blob and
manifest hash verification do not establish compilation, passing Rust tests,
hardware interoperability, production safety, or release qualification.
