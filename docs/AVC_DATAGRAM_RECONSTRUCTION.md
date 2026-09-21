# Cold AVC reconstruction from retained original datagrams

`rtsp::datagram_reconstruction::DatagramAvcReplay` connects `DatagramArchive`
to the existing pure-Rust `AvcReceiver`. It reads and re-verifies original RTP/RTCP
observations from the caller's current `LocalRootPublisher`, not a second source
cache, camera connection or foreign decoder. The same publisher remains available
between steps for publication of downstream derived recordings.

Supply an independently accepted recovered archive, exact SPS/PPS bytes (without
Annex-B start codes), payload number, packetization mode, RTCP mode, every receiver
limit and configuration evidence. Missing configuration is not reconstructed from
defaults or an unrelated latest SDP. A digest binds the complete source prefix,
parameter bytes, configuration evidence, limits and scheduler policy. It is an
interpretation identity, not authentication, original-live-schedule equivalence,
camera timing calibration or permission to disclose source.

## Three clocks remain different

The replayer uses recorded parser-completion receive times as a virtual scheduling
clock. It drains immediately available native receiver output between observations.
A receiver wake strictly before the next recorded arrival advances virtual time
without reading that arrival. A future tie chooses arrival admission; the native
receiver's own deadline rules still apply inside that admission. Current storage
admission time and its absolute lease are independent. Neither becomes picture
DTS, duration, composition time or physical camera capture time.

This deliberately defines a reproducible new interpretation; it does not claim to
reconstruct the original live CPU/poll schedule. Source identity and interpretation
identity remain distinct. Every original observation is returned, including RTP
probation, duplicate sequence numbers, identical retransmissions and invalid RTCP.
Malformed RTP returns `InputRefused` with the exact source and receiver retirement.
Confirmed stream restart closes the old-epoch attempt instead of changing epochs.

## A durable prefix is not EOF

At the last retained arrival the receiver's immediately available output drains,
then the result is `PrefixExhausted`. The driver never calls `finish()` and never
advances a timer beyond that last arrival merely to empty a queue. Remaining packet,
fragment and picture accounting is returned explicitly. A prefix ending halfway
through FU-A therefore cannot become an invented complete picture or recording.
Native receiver termination is `CodecEnded`, with unconsumed source count and the
original terminal event. It can follow in-band termination or a previously surfaced
configuration refusal; it is not a clean-end or TCP EOF claim.

Each step performs at most one original read/admission or one receiver poll result
or timer advance. The source store's own read may perform multiple bounded storage
calls. Runtime ceilings cover complete source bytes, total calls, current deadline,
source-read work and a conservative worst-case receiver traversal/copy reservation.
Those units are admission bounds, not calibrated CPU/performance measurements.
No automatic retry or silent truncation occurs when a bound is exhausted.

Pass the live storage-authority/cancellation probe and cooperative work budget at
every step. Source corruption, deletion, uncertain custody or cancellation fences
the attempt. A post-computation refusal returns the withheld original/media result
along with receiver retirement. Clock regression is a safe unchanged-state refusal.
No cleanup path deletes retained evidence, contacts a camera or flushes codec EOF.
The source store still requires protected ownership and independently trusted pins
when whole-store rollback is in the threat model.

## Reconstruct publishable recording windows

`datagram_reconstruction::recording::DatagramRecordingReplay` owns the source
replayer and the existing `RecordingCapture`/`RecordingCollector`. Supply a
`RecordingReplaySpec` with the exact recording scope, media tick rate, collection
bounds and independently accepted timing evidence. Generation and receive-clock
identity must agree with source custody. A second interpretation digest binds
these choices to the complete receiver interpretation. It does not claim that
user-supplied timing is measured camera time.

Call `step` with the current storage clock, authority/cancellation probe and work
budget. `Source` returns original RTP/RTCP outcomes; `MediaQueued` transfers one
ordered native receiver event into capture. `Capture` retains the existing typed
vocabulary, including `TimingRequired`, `Receiver`, `Backpressure` and `Window`.
Capture drains before another source observation is read. Repeated timing waits
therefore cannot read ahead, replace the held picture or renew residence limits.

Respond to `TimingRequired` with `supply_timing(RecordingTiming { decode_time,
duration, composition_offset }, ...)`. Invalid or overflowing timing is refused
without losing the picture. The current storage clock governs collection residence;
original packet receive times remain historical. Explicit `seal` can release a
completed prefix under collection pressure; existing packet-disjointness and
source replay validation still apply.

Source exhaustion returns `PrefixReady`, not an automatic EOF or seal. The owner
explicitly calls `finish_prefix`, which seals only already completed, timed groups.
Further `step` calls return any ordinary `PreparedRecording`, then `FinishedPrefix`
with all incomplete receiver, packet and picture accounting. No receiver finish
method is called. An unmarked final picture and a truncated FU-A remain unrecorded
source, not a completed final frame. Earlier invalidation stops collection instead
of silently sealing a successful terminal window.

A `Window` is the existing immutable recording type. It can immediately pass to
`RecordingPublication` using the same publisher between replay steps, or to the
existing checkpointed/journaled archive writer. The reconstruction owner neither
publishes automatically nor invents another output format. Preserve its source
pin and interpretation digest alongside the returned recording root in the
runtime's evidence graph; this API alone does not publish a canonical lineage
entry. The recording root separately commits the actual media timing and packet
selection; explicit seal choices are not inferred from the configuration digest.

Errors preserve ownership across every composition boundary. Failed source reads
stop both owners. Failed media admission returns the unoffered event. Cancellation
after extracting a prepared window or admitting a timing result returns that exact
withheld result with the remaining collection, rather than losing it through an
error return. Prefix finalization, cancellation and faults transfer terminal work
once; none reconnects a camera, deletes evidence or acknowledges an archive write.

## Validation and limits

Thirteen authored integration tests use real encoded AVC, the existing Digest/RTSP
parser to obtain opaque source observations, and the actual filesystem publisher.
They cover cold native-receiver comparison, independent clocks and configuration,
truncated fragments, duplicates, invalid RTCP, malformed RTP, timer scheduling,
post-read cancellation, corruption, budgets, deadlines and empty prefixes.
Thirteen additional recording integration tests cover byte-identical canonical
media, same-owner publication and cold reopen, timing pressure/correction, unmarked
and fragmented tails, gaps, collection limits, post-window/post-timing cancellation,
clock isolation, scope identity and explicit prefix finalization. These 26 authored
tests are not 26 executed passes.

```sh
cargo test -p fss-reference --test datagram_avc_reconstruction
cargo test -p fss-reference --test datagram_recording_reconstruction
```

Rust compilation, tests, rustfmt and Clippy were not run in this editing environment
because cargo/rustc are unavailable. Static checks are not compiled-Rust evidence.
This is not full raw-TCP preservation, a hardware decoder, a restored live session,
a production throughput claim, or a qualification/gate closure.
