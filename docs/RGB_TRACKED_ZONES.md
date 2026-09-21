# RGB neural detections to anonymous trajectories and image-zone observations

`fss_reference::ingest::rgb_tracking` connects actual `RgbInference` and
`RgbDetectionReport` values to the existing `fss-twin` `ImageTracker` and
`ImageZoneMonitor`. It implements no second assignment, motion, or zone algorithm.
The reference crate now depends on the already-present first-party `fss-geometry`
and `fss-twin` crates. There is no new external package, async runtime, or I/O.

## Select a class and keep the original grid

Construct `RgbTrackingContract::new(&head_contract, class_index,
selection_evidence)` and pass it to `RgbZoneTracker::new` with an explicit episode,
tracking policy, image-zone basis, polygon set and temporal policy. The selected
class is an entry in the exact model vocabulary, not a verified person identity.
Use a separately scoped owner for another class. Multi-label alternatives from a
single row must not become multiple objects in the same anonymous tracker.

`prepare_rgb_tracking` consumes a matching actual inference/report pair. Every
post-NMS survivor receives a `RgbTrackingDecision`: a selected-class proposal or
an explicit other-class outcome. Original subpixel bounds, rows, class scores and
clipping flags remain visible. The original detection report retains all head
rows, privacy exclusions and suppression links. Keep both objects to hydrate
these details; digests are not evidence custody.

All selected-class proposals must fit the existing tracker (hard ceiling 64,
possibly narrowed by its policy). Overflow refuses the complete input. There is
no score-ranked truncation and no automatic eviction to accommodate a busy scene.

Boxes are outwardly expanded from 1/256 source pixels to integer pixel-edge
rectangles for the existing tracker. Each edge grows by less than one pixel.
The exact subpixel box is retained alongside that projection. This expansion can
turn a definite zone relation into Boundary, not manufacture a definite side.
Tracking gating slack must accommodate this quantization and the detector's own
measurement uncertainty; no physical accuracy is inferred. Clipped or image-edge
boxes are partial, so they cannot justify definite inside/outside relations.

`ImageZoneBasis` and polygons use the **original coded RGB image grid**. Inference
has already undone its resize/letterbox. Do not supply rectified or world-space
polygons under the original image-domain identity. This bridge applies no lens
correction, ground-contact assumption, camera motion compensation or calibration.

## Availability is a separate input

Every observation requires `RgbFrameAdmission::new(source, availability,
evidence)`. It binds the exact encoded frame, exposure, camera, capture interval,
clock, image mode, calibration and permission mask. A stale or mismatched decision
is refused before temporal state changes. A nonzero evidence digest only links a
caller declaration: it is not authentication or an independently computed health
finding. The upstream owner must establish that declaration through its authorized
screening path; successful inference and high scores are not health evidence.

Available empty output does not certify absence. Unobservable and Disturbed
frames retain proposals without assimilating measurements, and interrupt zone
observations rather than inventing exits. Privacy remains the detector's complete
source-footprint check; the bridge never widens that permission mask.

## Atomic tracking and resumable zones

`RgbZoneTracker::observe(&inference, &detections, admission, &mut budget)` prepares
the source-bound conversion, validates the zone basis, and invokes the existing
transactional tracker. An outer error leaves both temporal states unchanged.
`RgbZoneProgress::Pending` means tracking **already consumed** this exposure but
its zone stage could not complete. The owner retains the complete preparation and
accepted tracking receipt, refuses new observations, and exposes no stale zone
report. Call `resume` with a new authorized work allowance; it does not ingest
another exposure or age tracks twice. A completed resume is idempotent.

Inspect `prepared()`, `tracking_report()`, `tracker()` and `zone_report()` before
advancing. The tracker returns every candidate edge, unresolved association,
coasting hypothesis and retirement. The zone monitor supplies observed-inside,
entry/exit-between-observations, sampled dwell, interruption and expiry with
original source endpoints. These remain derived observations, not continuous
presence proofs, corroboration, canonical event publication or effect authority.

## Complete JPEG processor and owned delivery

`rgb_tracking::pipeline::RgbJpegZonePipeline::new(&model, &head, &mut temporal)`
borrows the exact frozen model/head and exclusive `RgbZoneTracker`. It reuses the
existing `RgbDetector` and temporal bridge; it introduces no new neural,
association, or zone engine. An owner with pending zone work cannot be attached
until that obligation is resolved. Another task cannot advance the borrowed
tracker while the pipeline exists.

Call `run_jpeg` with `RgbDetectionInput`, a matching `RgbFrameAdmission`, existing
RGB inference limits, a native decoder budget, a head-projection budget, a
geometry/work budget, and `ScalarExecCx`. Use the same owner cancellation request
for the decoder, scalar context and cancellable geometry budget. No implicit
thread or cancellation bridge is installed. The scalar context is checked again
before the final ownership transfer.

The public phases make partial completion inspectable:

| Phase | Work already accepted | Next operation |
|---|---|---|
| Ready | No held input or output | Submit one JPEG and source-specific admission |
| Projection | Complete neural tensors and owned permission mask | Resume only head decoding |
| Tracking | Complete inference and detection report | Retry temporal preparation/assimilation |
| Zones | Exact tracking receipt and preparation | Resume only zone derivation |
| Snapshot | Complete tracking and zone results | Retry only the bounded owned-output copy |
| Complete | Whole source-linked output held | Take the result before submitting another JPEG |

`resume` accepts no JPEG, source, model, mask, or replacement admission. Completed
stages therefore cannot be rerun or reinterpreted through that method. A failure
keeps its input available. An outer cancellation error can occur after inference
or temporal acceptance; inspect `phase()` and the retained records rather than
assuming that an error means the exposure was not consumed. Old tracking/zone
reports are hidden while an earlier stage of the current frame is pending.

A completed `RgbZoneCompletion` owns the original neural/detection result, source
permission mask and availability declaration, plus all selected/other-class
outcomes, active tracks, candidate edges, detection decisions, retirements, zone
cells and events. Prior/current tracking and zone digests, configuration and
source endpoints are copied unchanged. `take_complete()` moves the entire result
to the caller. It remains readable after later inputs advance the tracker or the
processor is dropped. Untaken output blocks new JPEGs, so accepted transitions
cannot be silently overwritten.

Snapshot allocation is a separate explicit boundary after temporal commit. Its
logical vector/record bytes are checked against a 4 MiB ceiling and reserved from
the supplied work budget before fallible copies. Snapshot failure preserves the
already committed zone results and never repeats zone/event generation. Byte
accounting reflects Rust record layout on the host; it does not participate in
result identities or claim whole-process peak memory. No allocation is required
after the final cancellation check to hand off a successful result.

`retire()` consumes the processor and transfers its phase, admission, unfinished
neural or detector input, or untaken complete result. The separate temporal owner
is released and retains any accepted tracking state and pending zone obligation.
Retirement does not reset that history, accept another exposure, or certify the
failed stage as complete. Pending source work must be diagnosed, resumed or ended
explicitly by its owner.

These owned records are in-memory evidence handles, not durable source custody.
The original JPEG bytes, model package and head contract must remain retained by
their existing owners. There is no automatic health classifier, pretrained neural
model, camera acquisition, persistence, canonical event publication or alert
transport in this processor.

## Validation status

Nine bridge contracts and ten complete-processor contracts were authored. The
bridge contracts cover actual JPEG/convolution-derived movement through
entry/dwell/exit, multi-label selection, outward subpixel bounds, unavailable
frames, wrong sources/bases, replay, complete-input overflow, cancellation and
every work-unit cutoff around the temporal commit boundary. Processor contracts
cover JPEG-derived entry/dwell/exit, owned output across advancement, retained
masks, every public pending stage, output-copy pressure, untaken-result
backpressure, explicit retirement, cancellation and source/contract refusal.
Numeric coefficients
are test fixtures, not pretrained people-detection weights or quality evidence.
Rust compilation, test execution, rustfmt, Clippy and controlled device
qualification have not run in this authoring environment (no Rust toolchain).
Independent Python/Pillow/PyTorch checks verify the generated fixture geometry;
those checks do not execute the Rust bridge.
