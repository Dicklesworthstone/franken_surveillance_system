# Bounded recording-to-analysis execution

`ingest::recording_pipeline::run_recording` connects an exact retained JPEG/MJPEG
import to canonical decoding, frozen-model inference and the existing complete
`AnalysisReport`. Operators no longer need to execute one frame at a time and
manually copy run identities into an analysis plan. This is sequential local
reference execution, not a live-camera daemon, model activation or event policy.

## Request and result

`RecordingRequest` selects a contiguous positive range of at most 256 source
segments, an explicit grayscale/YCbCr interpretation, exact detector model/output
contract, local tracker policy, source/decode/report ceilings and a per-invocation
tensor-accounting ceiling. `run_recording` also takes the exact `RecordedModel`,
shared work budgets and explicit deployment/execution contexts. The range must
exist in the completed original import before any derived publication begins.
Model digest, output shape/port, row limits and tracker policy are preflighted.

Each selected segment is decoded and its exact model invocation completed through
the existing owners. Only one decoded frame/model result is held by the runner at
a time. The ordered run IDs then feed `AnalysisPlan` and `AnalysisReport::read`.
The resulting report uses the existing FSSARPT1 bytes and is directly consumable
by the recorded-event workflow. There is no parallel report encoding or shadow
ledger. Postprocessing is reconstructed after the numeric prefix completes;
an invalid numeric box can therefore refuse the final report after model runs
have already been retained.

A complete report means the requested analysis was performed, not that every
real object was detected. Source gaps and capture uncertainty remain in capsules;
the tracker still reports resets, missed observations, retirements and ambiguous
association. Empty detections are not certified absence. Nothing publishes event
revisions, sends notifications or authenticates a physical identity.

## Shared budgets and bounded failure

`RecordingBudget` has independent cumulative JPEG, model, detector and association
work buckets. A frame never receives a freshly reset whole-job model budget.
Verified cached decodes/inferences consume zero new numeric work. They still
require source, tensor and receipt verification; final postprocessing is charged
again on retry. The model tensor ceiling is checked for cached results too.

The scalar executor does not return partial work accounting on failure. A new
model attempt therefore reserves its remaining allowance before execution.
Success settles to its exact receipt work; failure retains the reservation. The
reported charge is a conservative reservation in that case, not measured executed
MACs. A caller must explicitly supply a fresh allowance for another failed-attempt
retry. Existing successful receipt accounting is historical and is never billed
again as fresh execution. These buckets do not measure source I/O, serialization,
clones, whole-process peak memory, latency or energy. Existing storage/read bounds
and contexts remain responsible for their own boundaries.

Every loop and major boundary checks the parent and executor contexts. The codec
can additionally receive its existing owner cancellation flag through
`DecodeBudget::cancellable`. Cancellation within a model is governed by the
provided ScalarExecCx; parent cancellation is checked between composition steps.
No detached worker or independent cancellation tree is created.

## Restart and integrity

An exact retry starts from the original first segment, revalidates retained
frames/runs, then rebuilds the same full association history. It needs no original
recording path. A caller may recover the exact retained model object by its digest
once it has been staged by an inference invocation; loading that object is not a
model-registry admission decision. Different ranges or model/output policies are
new analysis requests, not implicit resumes of the old history.

`RecordingFailure` reports its stage, pending segment, complete ordered inference
prefix, new/reused counts and current deployment anchor. It contains no partial
AnalysisReport. During an analysis-stage failure all selected model runs may
already be complete. On decode/inference failure, the pending segment may also
have staged objects or a completed prerequisite decode. Those are not erased or
called job success. Retrying after a root-to-receipt cut delegates recovery to the
owning publication implementation.

Completed decoded custody is now fail-closed: a missing or damaged pixel object,
receipt or root never triggers silent codec re-execution or replacement. Only
absence of the exact final decode batch permits normal execution/resume. A
separate authorized repair workflow remains necessary for corrupt completed data.
No decoder format, decoder identity, scalar code or model-run profile is changed
by this composition and custody correction.

## Validation

`cargo test -p fss-reference --test recording_pipeline_contract` exercises full
recording execution and restart, zero-numeric-work reuse, cumulative budgets,
failed reservations, malformed requests, analysis-stage failure, cancellation,
root/receipt interruption, missing/corrupt completed pixels, cached limits and
empty detection results. Tests are added, not executed in the editing environment:
Rust/Cargo are unavailable. Local pinned-toolchain qualification remains required.
