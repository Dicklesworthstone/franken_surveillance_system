# Portable recording reconstruction recipes

`rtsp::recording_recipe::RecordingRecipe` retains the inputs previously required
from outside the cold reconstruction path: original SPS/PPS, payload and packetization
selection, RTCP policy, every receiver/collector limit, recording scope, clock-evidence
identities and every ordered picture-timing decision. The version-one hand-written
canonical encoding binds an exact `DatagramPin`, the existing native interpretation
and the complete timing list. It contains no camera credentials or source media.

## Prepare and execute

Construct a recipe from an independently accepted `DatagramArchive`, `AvcReplaySpec`,
`RecordingReplaySpec` and `Vec<RecordingTimingDecision>`. Each decision records the
exact `PictureTimingRequest`, the observation count at which it appeared, and explicit
`RecordingTiming`. The ordinary `DatagramRecordingReplay` can supply those requests
while the timing owner records its decisions. Do not infer them from RTP timestamps.

`RecordingRecipe::from_canonical_bytes` reconstructs owned parameter bytes and
instructions against a separately selected source prefix. `RecordingRecipeLimits`
provides independent whole-byte, timing-count and componentwise receiver/collector
ceilings. Stored bounds never widen current authority, and a tighter ceiling refuses
rather than changing the interpretation. Operational step, source-byte and deadline
budgets are supplied separately when constructing `PlannedRecordingReplay`.

Drive `PlannedRecordingReplay::step` with the existing publisher, current storage
time, live cancellation/authority probe and cooperative work budget. It delegates
all source verification, packet processing and recording generation to the existing
native reconstruction path. An observed timing request must match the next retained
request and observation count exactly. The next step applies that decision and
returns the ordinary `TimedCapture`, including any unselected originals. There is
no manual timing override, mutable inner replay, default duration or silent skip.

The fixed version-one cut policy uses the collector's packet-disjoint IDR cuts and
explicitly seals completed groups after `PrefixReady`. It does not encode arbitrary
manual mid-prefix seals. Capacity pressure requiring such a seal refuses the recipe
and returns remaining work; it does not silently choose another window layout.
`PrefixFinalizing` is not a publication or source-completeness receipt. Windows are
ordinary `PreparedRecording` values for existing publication/archive APIs.

Missing, mismatched and unused decisions are distinct failures. A mismatch returns
the original held picture, source/receiver state and withheld output. Native errors
and cancellation stop the attempt; only a current-clock regression is safely
retryable in place. Successful earlier windows remain separate outputs even if a
later mismatch stops the recipe. Consumers must not label the whole interpretation
successful before its actual terminal `FinishedPrefix` result.

## Evidence and durability boundaries

A valid encoding certifies only well-formed instructions bound to a selected source.
It is not proof that the decisions match native reconstruction, that source is still
available, or that any recording has been published. Only execution checks picture
matches. The underlying source owner rehashes originals during actual reads.

Historical receive timestamps, current storage deadlines and explicit media ticks
remain separate. Resource deadlines can stop a slow replay; they are not serialized
as a reusable lease. The policy defines a reproducible interpretation under admitted
budgets, not a claim that the original live CPU schedule was recovered. Source
prefix exhaustion never calls codec finish or synthesizes an unmarked final frame.
Configuration evidence and timing evidence are provenance identities, not grants.

The first implementation provides portable memory encoding and execution. Persistent
source-closed publication is a separate layer, not implied by `canonical_bytes()`.
The source owner and independently accepted scope still have to be recovered. This
is not a restored live camera, decoder qualification, capture-clock calibration,
raw-TCP recovery, automatic policy activation or a replacement canonical ledger.

## Validation

Twelve authored Rust integration tests exercise original encoded AVC, actual datagram
custody and native replay. They cover byte-identical recording/source/index output,
signed composition offsets, independent storage clocks, every truncated encoding,
trailing/unknown bytes, source/configuration mismatch, external ceilings, invalid
and overflowing timing, exact request mismatch, missing/unused decisions, no read
ahead, retryable clock regression, incomplete FU-A, collection pressure and cancellation.
The shared reconstruction fixture also now uses the actual `DatagramArchiveLimits`
type and the actual recovery argument order instead of the nonexistent `DatagramLimits`.

```sh
cargo test -p fss-reference --test recording_recipe
cargo test -p fss-reference --test datagram_avc_reconstruction
cargo test -p fss-reference --test datagram_recording_reconstruction
```

Rust compilation, tests, rustfmt and Clippy have not run in this authoring environment:
no Rust toolchain is installed. Static source/hash checks do not establish passing
Rust tests or promote a qualification gate.
