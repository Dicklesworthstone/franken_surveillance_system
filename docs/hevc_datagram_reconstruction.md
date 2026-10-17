# Cold HEVC datagram reconstruction

Source-first RTSP capture retains RTP/RTCP before a picture or recording exists.
`DatagramHevcReplay` and `DatagramHevcRecordingReplay` now consume that separately
recovered, explicitly pinned source inventory. They do not contact a camera,
follow a mutable latest pointer, infer missing SDP, or make source bytes durable.

## Two distinct interpretation layers

`fss_reference::rtsp::datagram_reconstruction::hevc::DatagramHevcReplay` replays
original observations through `H265Receiver`. Its explicit `HevcReplaySpec` binds
the negotiated payload, no-DON setting, every native packet/reordering/fragment
limit, RTCP policy and configuration-evidence identity. Nonzero DON is refused
rather than downgraded. Original probation, duplicate and malformed datagrams
remain observable even when they cannot become media. RTCP validation is separate
from video reconstruction and does not calibrate a camera clock.

The nested `recording::DatagramHevcRecordingReplay` adds the native `HevcAssembler`
and `HevcRecordingCapture`, not an alternate codec or remuxer. Supply an exact
validated `HevcConfiguration`, original `RecordingScope`, explicit time scale,
assembly/collector ceilings and independent timing-evidence identity in
`HevcRecordingReplaySpec`. The scope's generation and receive clock must match the
source archive. Parameter bytes, grouping policy, collector limits and timing
basis bind the recording interpretation. Every actual supplied timing and seal
choice is additionally bound by the returned recording root.

## Driving the recording owner

First reopen the source `LocalRootPublisher` and recover `DatagramArchive` using
the original `DatagramScope`, finite limits and the previously saved `DatagramPin`.
The source scope/retention evidence must come from the original approved capture;
a digest does not authenticate a grant. Supply current read authorization through
`PublishCancellation`, and one finite `WorkBudget` shared by the whole replay.
A new reconstruction needs its own current absolute deadline and step allowance.

Construct `DatagramHevcRecordingReplay::new(&archive, transport_spec,
recording_spec, bounds, now_ns)`, then call `step(&publisher, now_ns, cancel,
&mut budget)`. Retain every transferred output before advancing:

- `Source` preserves the original datagram/admission/RTCP result or deterministic
  receive-clock progress. `MediaQueued` only means one native event entered capture.
- `Capture(HevcCapturePoll::TimingRequired(request))` requires explicit media ticks
  through `supply_timing`. RTP timestamps and receive time never become DTS.
  Missing or invalid timing keeps the same picture held and blocks later reads.
  Preserve the returned `TimedHevcCapture`, including released original packets.
- `Capture(HevcCapturePoll::Window(window))` is an ordinary `PreparedHevcRecording`.
  It can be published through `RecordingPublication::new(window.publication_plan(),
  ...)` or the existing independently journaled HEVC archive writer. Preparation
  and `Window` are not publication receipts. Source replay never publishes itself.
- `PrefixReady` requires an explicit `finish_prefix` or `cancel` decision.
  `finish_prefix` returns the existing `HevcCollectionSeal`, including released
  originals. Continue stepping to transfer the prepared window and `FinishedPrefix`.
  Preserve its retirement: it includes incomplete grouping, fragment state, queued
  NALs, original source boundary and any remaining collection work.

A capacity refusal can be resolved with an explicit `seal` of a verified completed
prefix where the native collector permits it. It never authorizes splitting an
original datagram or discarding a required HEVC boundary witness. A safe refusal
has no terminal retirement and is still charged against finite work/step bounds.
A fatal refusal transfers remaining ownership exactly once; callers must not
replace it with a successful result or automatically restart acquisition.

## Prefix exhaustion is not EOF

Historical receive time drives reorder, fragment and grouping behavior. The
current storage clock governs authorization, reconstruction deadlines and capture
residence, but is never media time. The transport replayer drains receiver output
between recorded arrivals; equal-time arrivals precede future transport wakes.
Grouping expires against the next historical event before any corresponding new
NAL enters assembly. This is a frozen deterministic interpretation, not a claim
that the original live poll schedule has been recovered.

Reaching the last retained observation does **not** call receiver or assembler
`finish()`, invent a future timeout, or manufacture a complete final picture.
`RetainedPrefix` means exactly that bounded inventory was exhausted. An observed
in-band EOB is separately reported as `EndOfBitstream`: later selected observations
are not read, `observations_read` can be less than the selected pin's count, and
post-EOB NALs from the same aggregate packet remain in retirement. Neither boundary
asserts TCP EOF, scene continuity, a healthy camera, or complete capture.

Source corruption, missing custody, restarts, packet loss and invalidating codec
results stop recording interpretation. Invalid RTCP remains an independent result.
Current revocation after producing an output returns that exact output in the
failure retirement. Post-timing and post-seal refusals likewise retain accepted
timing outcomes, released originals and any prepared recording.

## Validation and boundaries

`datagram_hevc_reconstruction` checks cold original-source/native-receiver equality,
fragmented inputs, duplicates, malformed RTP/RTCP, exact limit identities, timer
bounds, corruption, current clock reversal, cancellation and withheld originals.
`datagram_hevc_recording_reconstruction` checks canonical native-recording equality,
whole boundary-witness preservation, explicit timing/backpressure, genuine EOB,
post-EOB queued NALs, historical expiry, loss, empty/incomplete prefixes and current
operation bounds. A cold publication test takes the original datagram store offline
before reopening and decoding the reconstructed recording with the native decoder.

These are bounded library APIs. There is no new CLI reconstruction command, saved
HEVC timing recipe, implicit configuration recovery, encryption, continuous-NVR
throughput qualification or physical-camera certification. Incomplete source stays
incomplete. Existing recording formats, archive barriers and AVC behavior are unchanged.
