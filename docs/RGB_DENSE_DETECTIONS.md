# Source-space detections from native RGB neural outputs

`fss_reference::ingest::rgb_detections` interprets actual opaque `RgbInference`
outputs. It closes the tensor-to-proposal gap without a mock model, a second
runtime, caller-invented boxes or an implicit model-family convention.

## Frozen head contract

Create `RgbDetectionContract::new(RgbDetectionSpec { ... })` with the exact RGB
model digest, output port, ordered unique class labels and all numerical settings.
The selected F32 tensor must be exactly one of these declared layouts:

- `HeadLayout::Rows`: `[1, N, 4+C]`, or `[1, N, 5+C]` with objectness.
- `HeadLayout::Channels`: `[1, 4+C, N]`, or `[1, 5+C, N]` with objectness.

Each record begins with four already-decoded corner or center/size coordinates.
`HeadBoxes` explicitly selects pixel or normalized model-input coordinates.
Normalized coordinates refer to the full target grid, including letterbox padding.
There is no automatic sigmoid, anchor decode, stride/grid inference, distribution
focal loss decode, end-to-end six-column interpretation, rotation or mask parsing.
An exporter must produce this exact declared contract; a model name is insufficient.

Class and optional objectness values independently use `HeadScore::Probability`
or `HeadScore::Logit`. The latter uses the existing deterministic sigmoid.
Combined confidence is one F32 objectness-times-class multiplication, or class
score alone. `HeadClasses::Best` selects one class (lowest index on exact ties);
`MultiLabel` emits every class reaching the inclusive ppm threshold. These scores
are uncalibrated model outputs, not probabilities of identity or danger.

Every row is validated, including below-threshold rows and losing classes.
Nonfinite values, invalid probabilities, reversed corners and nonpositive sizes
refuse the entire projection. Valid boxes may extend outside the model image:
clipping or a padding-only outcome is explicit rather than a fabricated source box.

## Projection and privacy

Call `project_rgb_detections(&inference, &contract, allowed, &mut budget, &cx)`.
The supplied source-grid 0/1 mask must match the exact mask digest and dimensions
retained by inference. Its summed-area table tests the *entire touched pixel
footprint*, not just the proposal center. Any denied pixel excludes that proposal
with `PrivateFootprint`. Input masking alone does not authorize a model prediction
over a denied area. This deliberately conservative rule can exclude objects close
to privacy boundaries; the code does not silently weaken it.

The actual `ResizeGeometry` reverses stretching or integer letterboxing into the
original coded source grid. Coordinates are outward-rounded to 1/256 source
pixels, consistent with the existing detector precision. They are not rectified
world coordinates, a visible ground contact or a calibrated physical error bound.
Clipped proposals retain a `clipped` flag; padding-only proposals never enter NMS.

## Complete decisions and deterministic suppression

NMS is class-aware on the quantized source boxes. Descending combined score,
then ascending original row, then ascending class establishes a total order.
Suppression uses exact integer cross-multiplication and **strictly greater-than**
IoU comparison against the configured ppm threshold. Every pre-NMS candidate
survives in `candidates()`, with a stable index of its retained suppressor.
`detections()` contains all survivors; `rows()` contains every selected head row,
including score, padding and privacy exclusions. Keep the original inference and
contract to hydrate all raw tensors and class vocabulary.

The hard ceilings are 32,768 rows, 4,096 admitted pre-NMS candidates and 256
survivors. Owner ceilings can narrow these. Overflow always refuses the complete
projection; it never implements an undisclosed pre- or post-NMS top-k. An 8,400-row
head is therefore supported when its full accepted candidate set fits the declared
bounds. `RgbDetectionBudget` accounts deterministic mask/score/geometry/sort/NMS
and receipt work, with a separate per-call logical scratch-vector ceiling. This
is not elapsed time, energy or total process memory. Failed work is not refunded.

No inference/tracker/ledger mutation occurs. All refusals leave the opaque input
available for a bounded retry; final cancellation is checked before output. Report
identities bind the exact source inference, full tensor digest, contract, actual
geometry, row decisions and candidate suppression. A local digest is not durable
source custody, canonical event publication, coverage or alert authority.

## One-frame resumable JPEG processor

`rgb_detections::pipeline::RgbDetector::new(&model, &contract)` borrows a frozen
model and matching head contract, including its implementation source fingerprint.
Use `run_jpeg` with `RgbDetectionInput`, the existing `RgbRunLimits`, separate
native decoder and detection work budgets, and the caller's `ScalarExecCx`.
It performs actual color decoding, masking, resizing, graph execution and the
projection described above. Original source bytes remain the caller's custody.

The processor retains a bounded copy of the exact mask before inference. That
copy's bytes/work are reserved from the preprocessing allowance in addition to
the existing inference costs. A completed run exposes `mask_copy_work()` separately
from `inference().preprocess_work()`. The mask copy prevents later mutations of
the caller's input buffer from reinterpreting a pending result.

`RgbDetectionStep::Complete` transfers the full inference, owned mask and complete
detection report. `Pending(error)` means neural execution succeeded but head
projection failed. Inspect `pending()` for the actual accepted tensors. New JPEGs
are refused while pending; `resume` repeats **only** postprocessing on those same
tensors and permissions, with no additional decode or graph execution. Resumption
failure retains the pending state. Completion takes it only after the projection's
final cancellation check and requires no post-commit allocation.

Permanent shape/contract refusals and cancelled owners can be ended explicitly
with `retire()`, which transfers unfinished inference and mask ownership. The
caller can diagnose or reprocess under an explicitly revised contract; nothing
automatically changes thresholds, drops a frame or silently swaps models. The
processor is in-memory, not a durable restart checkpoint, capture-exposure dedup
service, tracking owner or coverage witness. Retain the outputs before dropping
this owner, and use the existing custody/publication plane for persistence.

Ten integration tests exercise actual JPEG -> Conv2d -> Reshape -> dense-head
execution, source-dependent classes and corners, denied-pixel noninterference,
full-footprint refusal, mixed entry-point receipt equality, retained masks,
pending backpressure, cancellation, explicit retirement, and every public
postprocessing work cutoff. Their numeric graph weights are fixtures, not a
trained detector or accuracy claim. A separate Pillow/PyTorch oracle checked
512 generated JPEG/head cases and five targeted fixtures; this is still not
execution of the Rust processor.

## Scope and validation

This is detector-head postprocessing, not a pretrained model distribution, generic
ONNX converter, model quality qualification, tracker, world-event inference or
camera/alert service. Existing luma detection and RGB model formats are unchanged.
The RGB inference implementation is not edited by this feature, avoiding incidental
changes to its source-pinned model identity.

Fifteen Rust core tests and ten integration tests were authored for tensor layouts, objectness/logits,
letterbox reversal, subpixels, privacy, class/NMS ties, all core work cutoffs,
8,400-row admission and refusal semantics. They are **not compiled or executed**
in the authoring sandbox: no Rust toolchain is installed. Independent Python
checks cover 10,000 NMS cases, 20,000 mask-footprint cases, 20,000 geometry cases and
2,000 layout/objectness cases. These are formula/oracle checks, not Rust integration
or real-camera validation. Controlled native qualification remains required.

Format convention reference (no external runtime/code dependency):
https://docs.ultralytics.com/reference/utils/nms/
