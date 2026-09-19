# Continuous HEVC recording collection

`rtsp::hevc_recording_collector::HevcRecordingCollector` selects bounded,
IDR-led windows from ordered original RTP and the existing HEVC picture groups.
It connects the live picture path to `prepare_hevc_recording` and its existing
source-first/root-last publication plan. No socket, worker, decoder, storage
implementation, authority grant or durable byte format is introduced.

## Owner-driven collection

Pin `RecordingScope`, the exact receiver `StreamKey` and payload mapping,
`HevcConfiguration`, a positive media timescale and `CollectorLimits` at
construction. Call `push_ordered` for source events before admitting their
completed pictures. `push_picture` borrows the picture and requires explicit
`HevcRecordingTiming`; every success/refusal leaves that picture caller-owned.
Process each picture before polling further upstream source output. Receive
and collection clocks remain separate; no assumed frame rate supplies timing.

A packet-aligned IDR begins selection. Earlier predicted pictures are reported
as `AwaitingIdr`, with originals released from active collection returned to the
owner. A later IDR seals the preceding completed window when its media can be
separated at packet boundaries. The sealed source includes the actual packet
that proved the prior final picture's boundary. That same complete packet (or
FU chain) can also begin the next source object. The media samples do not overlap.
A packet whose contents close both sides of the proposed cut defers rotation;
it is never split, trimmed, or partly represented as complete source evidence.

The collector retains original packets and small process-local picture
commitments, not duplicate decoded surfaces or a second copy of picture NALs.
Before publishing a prepared result, native packet/assembly/remux replay must
reproduce each observed picture's timestamp, boundary, IDR classification and
commitment to every NAL byte and exact RTP/FU source mapping. Its commitment
encoding is private scratch state, not a new durable schema. The existing HEVC
recording representation and verifier remain unchanged.

## Pressure, time and source ownership

There is one active source window and at most one ready prepared root. Ready
output backpressures further source/picture admissions until `take_ready`.
Independent source bytes/packets and picture bytes/samples/NALs/spans have hard
ceilings. Capacity and timing failures preserve the existing semantic state and
borrowed input. A too-long GOP produces pressure, not an invented IDR or eviction.
Explicit `seal` can finish an already observed prefix; a shared-packet prefix
that does not pass native replay remains unsealed and retryable.

The oldest retained original's collection time fixes the deadline. Rotation
and consumer retries cannot refresh shared lookahead age. Drive `expire` at
`next_wake_ns` even without network input. Expiry, `invalidate` and `cancel`
transfer all retained originals, unsealed picture commitments/timings, and any
already prepared root. A prepared root is never retroactively cancelled. The
caller must propagate transport/codec invalidation before sealing later work.

`finish` seals only already boundary-closed groups; it does not flush a missing
EOF boundary or synthesize EOS. After taking ready output, `cancel` transfers
trailing originals. Returned/released source bytes may already occur in a
prepared source object: release from this collector is never permission to
delete independent source custody or assert durable retention. All output still
requires the existing explicit publisher, privacy policy and recovery owner.

## Ordered RTSP event capture

`rtsp::hevc_recording_capture::HevcRecordingCapture` privately owns a configured
collector and consumes the existing `RtspHevcPictureClient` events in order.
Offer one event, then poll the capture to a waiting state before polling more
upstream input. Its extra state is one held event/picture with a fixed five-second
residence deadline. It does not create a second receiver, parser or authentication
implementation and exposes no mutable collector escape hatch.

Source events are copied transactionally into collection and returned intact.
Completed picture events produce `TimingRequired`; `supply_timing` returns BOTH
the selection result and the complete original picture event, including EOB or
remote-session receipts. Incorrect timing/capacity retains that same event and
its original deadline. Ready `Window` output must be taken before more input.
Capacity pressure advertises the fixed wake rather than busy-polling.

Transport gaps, source restarts, codec/assembly refusals, fragment/picture/queue
expiry and incomplete-FU EOF automatically fence collection. A held invalidation
cannot be bypassed with `seal`. Prepared earlier windows survive in retirement
receipts; unsealed originals and the invalidating event are transferred intact.
RTCP validation failure, ordinary control responses and Digest credential waits
are not video loss. The caller still owns and must drive upstream authentication,
I/O cancellation and timers; it must deliver their failures before attempting a
seal. This bridge does not infer unobserved upstream success or authority.

Clean EOF returns its original event/tail without selecting an unverified tail,
then emits `Sealed`, any ready `Window`, and a final `Ended` transfer. An observed
EOB picture follows the same drain only after explicit timing admission; its
original terminal receipts remain in `TimedHevcCapture`. Repeated terminal polls
never repeat owned source or publication output. Publish returned windows through
the unchanged `RecordingPublication`; retrieve them with `load_hevc_recording`.

## Validation boundary

```sh
cargo test -p fss-reference --test hevc_collection_contract --test hevc_capture_contract
```

Contracts use the retained synthetic HEVC source fixture through the real RTP,
picture and recording owners. They cover two-window collection, whole AP/FU
boundary reuse, unsafe-cut deferral, independent receive clocks, corrected
retries, immutable ready-output backpressure, original-age expiry, startup IDR
selection, source mismatch, fixed ceilings and unclosed EOF tails. Rust execution
was unavailable in this editing environment; no passing build/test/qualification
receipt is claimed. The event-capture contracts additionally exercise plain and
SHA-256 Digest RTSP negotiation, real supplied TCP frames, required timing and
retry/expiry, gap-before-seal fencing, incomplete-FU EOF, RTCP isolation, source
pressure, EOB receipts, chunk partition invariance, and two collected windows
published/reopened by the existing local storage owner. These are authored tests,
not executed qualification evidence. The normative qualification entrypoint is unchanged.
