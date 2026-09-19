# Retained recording analysis

`fss_reference::ingest::analysis` composes the existing retained inference, detector-output
projection and single-camera association kernels into a complete recording-level report.
It addresses the CAP-INFER / detector / within-camera tracking integration slice of plan
sections 15-16. It does not close production model admission, live operation, or quality gates.

## Contract

Create an `AnalysisPlan` with one exact import identity, explicit JPEG interpretation,
`DetectionSpec`, `TrackingConfig`, and an increasing list of `(segment_index, run_identity)`
selections. The model, labels, box coordinates, score/NMS thresholds, tracker policy and
selection are immutable. A selection may contain gaps; the existing tracker retires old
associations with explicit reset reasons rather than fabricating continuity.

`AnalysisReport::read` reopens each exact retained model run and decoded frame, validates
custody, applies the detector contract, and rebuilds the track history. It performs no model
execution or authority append. Each report includes the complete original detector projection,
source capsule and uncertain clock/capture interval, active and stale hypotheses, retirements,
ambiguity and all reset reasons. No top-k truncation is used. A failure returns no partial report.

`AnalysisReport::verify` loads the embedded plan and recomputes every projection from retained
custody, comparing the entire report byte for byte. Saved track bytes are not trusted as a
checkpoint. This supports restart verification without the original source or model-file path,
provided the retained source, model, decoded frame and run graphs remain available. Missing or
changed custody fails closed. Unrelated later authority commits do not re-anchor earlier runs.

Verification proves detector/association reconstruction, not independent numerical model
execution. Use `RecordedInference::verify_by_replay` for the latter. Hash agreement alone is
not provenance authentication; the verifier must be given an authorized deployment.

## Limits and cost

One report admits at most 256 explicitly selected frames, a 128 KiB recipe and 16 MiB encoded
output. Caller ceilings may be lower, never higher. Existing retained-read and decoded-image
limits apply to each source. `AnalysisBudget` contains independent cumulative detector-row/NMS
and association-solver allowances. Failed work remains charged; a new report must not be used
to reset an existing caller budget. Report size failure is explicit, never silent truncation.

Worst-case work is bounded by the existing per-frame 4096-row detector and 128-track / 256-
detection association ceilings, multiplied by the selected frame count and clamped by the two
work allowances. These units are not latency, CPU, energy, or total process-memory measurements.
The report and verified per-frame objects occupy additional bounded memory.

## Internal formats and compatibility

`FSSAPLN1` / `fss.recorded_analysis_plan.v1` binds the original detector contract bytes, tracker
configuration, source interpretation and ordered run selections. `FSSARPT1` /
`fss.recorded_analysis_report.v1` embeds that plan and complete existing detector/track encodings.
All fields use `fss-core` canonical encoding. Counts are bounded before allocation, trailing data
is rejected and plans must round-trip exactly. Unsupported versions are refused, not guessed.
These are internal reference export/replay formats, not a new public agent operation vocabulary.
No existing model, inference, detector or tracking encoding or executor fingerprint is changed.

An empty detection set is not observed absence. A confirmed track remains a local association
hypothesis, not a person identity, corroborated event, threat probability or effect authorization.
Reports over selected frames do not prove coverage of the rest of the recording.

## Focused validation

```sh
cargo test -p fss-reference ingest::analysis::tests
cargo test -p fss-reference --test recorded_analysis_contract
```

The authored arithmetic fixture checks actual retained JPEG/MJPEG ingestion and inference,
source-bound detections, multi-frame association, gap resets, restart, budget refusals,
forged/rehashed report refusal and cancellation. Rust tests were added but were not executable
in the editing environment, which lacked the pinned toolchain. No release qualification is claimed.
