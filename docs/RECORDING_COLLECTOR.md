# Bounded continuous AVC recording collection

`fss_reference::rtsp::recording_collector::RecordingCollector` connects ordered
original-packet events and completed AVC picture groups to the existing
`prepare_recording` / root-last publication path. This advances the GOP-aware
chunking portion of WP-060 and FSS-115. It does not close their qualification,
live acquisition, encrypted storage, or complete-picture gates.

## Ownership and driver

Construct the collector with a canonical `RecordingScope`, the exact receiver
`StreamKey`, negotiated payload type, explicit media tick rate and
`CollectorLimits`. Feed every ordered source event before the corresponding
picture. `push_ordered` takes a borrowed `OrderedRtpPacket`: a bounded copy is
retained while the original receiver event stays with the caller. The lower
`push_source` API accepts `RecordingPacket` with the same binding checks.

Supply completed groups through `push_picture(CollectedPicture, now_ns)` with
explicit DTS, duration and signed PTS-minus-DTS offset. The collector never
infers DTS from RTP timestamps, network order, VUI or receive time. Receive
times are preserved, including reversal after transport reordering. Collection
time is monotonic and controls only collection lifetime.

A next IDR seals the previous IDR-led window only when their original packet
sets are disjoint. Sources already delivered for the next picture are kept as
lookahead. An IDR sharing a STAP packet with the prior group stays in the active
window; a later safe IDR can cut it. An explicit `seal` with an unconsumed packet
suffix fails exact source verification instead of trimming that original packet.

There is one immutable ready window. `take_ready` transfers it once to the
publication owner. While it is retained, new sources and pictures are refused
with `Backpressure`, not evicted. All failed picture admissions return the
owned picture intact; source admissions borrow input and consume nothing on
failure. A failed seal preserves all active originals and pictures for retry,
inspection or explicit abandonment. `RecordingPublication` consumes the exact
prepared bytes, not a second remux of the stream.

## Joining, stopping and faults

Before an IDR start, complete non-IDR groups are returned as `AwaitingIdr` along
with older unselected originals. The last original packet remains retained in
case another group shares it. An IDR in that same packet cannot be used as an
independent start; waiting continues until a packet-disjoint IDR. Admission of
the selected IDR returns any preceding unselected original prefix explicitly.
Neither skipped groups nor unselected packets are described as recorded.

Call `interrupt` for receiver delivery gaps, codec failures, reconstruction or
assembly retirement, and other source discontinuities before admitting later
pictures. It returns all unsealed originals and completed groups, not just
counts. It does not retract a ready window. Replay, configuration and timeline
high-water marks survive the interruption; the next selected range starts at
an IDR, without upgrading its original discontinuity/boundary classification.

The oldest retained original's collection admission sets a fixed deadline.
Rollover retains the lookahead packet's original admission time instead of
resetting it at picture completion. `poll` at the deadline transfers all pending
inputs in `UnsealedRecording`; it never invents a complete tail or an archive.
Late source/picture admission cannot clear an expired deadline. `finish` seals
only already completed groups and returns trailing originals. `cancel` returns
ready and unsealed ownership separately. No `Drop` path publishes or deletes.

## Bounds and qualification

Independent limits cover original datagrams/bytes, completed samples/NAL bytes,
NAL/span metadata and 1 ns..60 s pending lifetime. Defaults retain up to 4,096
packets, 8 MiB source bytes, 256 samples, 8 MiB NAL bytes and 16,384 NALs/spans.
A ready plan has the existing separate 32 MiB recording bound. Preparation has
additional bounded temporary copies and metadata; these byte counts are not
claims of exact allocator/RSS usage. Collection alone is not durable source
custody. The ingress owner must retain source that is malformed, never reaches
ordered delivery, or is refused under pressure, with an explicit omission when
retention is not authorized/possible. This module adds no retention policy or
permission to read/disclose private media.

```sh
cargo test --locked -p fss-reference --test recording_collector_contract
bash scripts/qualify.sh --lane rust
```

The collector contracts use the actual H.264/AVC receiver over the retained
synthetic Baseline fixture, including FU-A and shared-packet STAP cases. They
cover exact window readback, lookahead, transactional retries, startup omission
ownership, expiry, timing, replay, cancellation and EOF. These are authored
Rust tests, not retained passing Rust receipts: the authoring environment has
no Rust compiler. No live-camera, decoding, complete-picture, privacy-transform,
production-storage or whole-repository qualification claim is made.
