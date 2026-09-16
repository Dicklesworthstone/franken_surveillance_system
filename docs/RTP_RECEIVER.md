# Bounded RTP ordered delivery

`fss-packet::RtpReorderBuffer` fills the ordered-input gap between the packet
sequence tracker and H.264 depacketization. It advances FSS-048/FSS-112 under
WP-050; it does not close the full RTP, RTSP, or H.264 work packages.

## Driving the receiver

Construct it with the owner's nonzero ingress binding, nonzero stream generation,
negotiated SSRC and payload type, and explicit `ReorderLimits`. Supply complete
original datagrams to `ingest` with monotonically nondecreasing receiver time.
The first packet remains on sequence probation; only the second consecutive
packet establishes the delivery baseline, as in the existing sequence tracker.

Call `poll` until it returns `Pending`, and arrange a wake at its `wake_at_ns`
even if no further network traffic arrives. A poll releases at most one owned
original datagram or one compact missing-position range. Ready packets are
released immediately; a hole waits until the oldest queued witness reaches its
configured delay. Duplicates and later arrivals cannot postpone that deadline.

A full packet or byte budget refuses the new input without consuming its
sequence or changing the receiver clock. Drain ready/expired work, then retry
using current monotonic time; the refused packet is not spuriously a duplicate.
Retain source custody independently of this derivative queue, including input
that was refused, still on probation, or too late for ordered delivery.

## Boundaries and lifecycle

The queue has independent bounds of 1..128 datagrams, 12 bytes..16 MiB of queued
wire data, and 1 ns..60 s of hole wait. Wire parsing has its own `PacketLimits`.
Metadata reservation is fallible and bounded; no packet copy occurs before
budget checks. Delivered bytes include original headers, extensions, and padding,
and preserve the supplied admission time. That time is not camera capture time.

Sequence wrap is handled in extended space. Late recovery after an emitted gap
may improve transport statistics but never retracts that delivery-gap receipt
or resurrects already retired reconstruction. Conflicting duplicate bytes are
refused while the original is still queued; this is not sender authentication.

`finish` stops admission and drains queued data with explicit intervening gaps;
it never invents a missing tail. `cancel` immediately retires the queue with a
payload-free receipt. A confirmed restart also retires the queue and closes
admission: reopening requires the same ingress and a strictly newer generation.
The owner must drain or cancel the old generation and retain its receipts.

This API opens no socket, reads no ambient clock, spawns no worker, and grants
no sensor authority. It does not certify access-unit completeness, decodability,
physical absence, capture continuity, or durable publication.

## Regression coverage and qualification

`tests/reorder_contract.rs` covers all 720 permutations of six packets, each
single-hole position, wrap, deadline-only progress, duplicate storms, late input,
transactional byte/packet refusal, source-byte ownership, clock reversal, wrong
bindings, restart, EOF, cancellation, arithmetic exhaustion, and debug redaction.

Targeted command: `cargo test -p fss-packet --test reorder_contract`.
Repository authority remains `bash scripts/qualify.sh --lane rust` and the
policy lane. The authoring environment has no Rust toolchain; these Rust tests
are supplied but not represented as executed or qualified here.
