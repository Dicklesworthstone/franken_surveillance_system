# Source-linked image motion pipeline

`fss_twin::image_motion::pipeline` composes the existing native JPEG decoder,
rectifier, frozen-background detector and anonymous image tracker. It does not
accept caller-invented detection boxes. The separate `image_motion` module derives
conditional velocity/covariance from the tracker's last two actual observations.

## Entry points

`analyze_jpeg_motion` takes a `JpegMotionInput` containing one complete JPEG,
its original `JpegFrameBinding`, the exact coded-grid permission mask, and its
owner-supplied `FrameCapture`. Supply the admitted `RectificationPlan`, a frozen
`JpegBackground`, explicit foreground and motion policies, native decoder limits,
and caller-owned decode/geometry budgets. The plan's source domain must already
include `mjpeg::decoded_image_domain`; the existing decoder validates every source
hash, mask, interpretation, dimension and calibration binding.

`analyze_luma_motion` takes an already validated `RawGrayFrame`, an admitted
rectification plan and frozen `RectifiedBackground`. It executes the same
foreground/trajectory/motion stages without pretending to decode the input.

`track_foreground_motion` consumes a borrowed opaque `ForegroundReport` produced
by the real foreground detector. It calls the existing
`ImageTracker::update_foreground` bridge, so direct and composite ingestion share
exactly the same detector and component identities. It is also the integration point for the
existing framed/multipart/HTTP MJPEG paths: retain their original source-range
receipts and pass their contained foreground report. No network ownership,
source framing, clock interpretation or decoding is replaced here.

Create an `ImageTracker` with an explicit episode and `ImageTrackingPolicy`.
Choose numerical assumptions with `ImageMotionPolicy`; there are no inferred or
silently calibrated noise values. All work stays synchronous under the caller's
runtime/region ownership. No new async runtime or background worker is introduced.

## Read the stage result before retrying

The JPEG/luma entry points return an outer error only when source processing or
foreground extraction failed **before tracking**. An outer success retains the
actual image, permissions, source receipts and foreground report even if a later
stage was refused. Inspect `result.analysis().outcome()`:

```rust,ignore
match result.analysis().outcome() {
    MotionPipelineOutcome::TrackingFailed(error) => {
        // Tracker unchanged. Retain the actual image/report and handle the cause.
        // A capacity/generation refusal is not permission to truncate or reset.
    }
    MotionPipelineOutcome::Tracked { tracking, motion } => {
        // This exposure was accepted. Retain tracking even when motion is Err.
        // Never ingest this exposure again to retry optional motion.
        // Retry estimate_image_motion(&tracker, tracking, policy, &mut budget)
        // before advancing the tracker; an old receipt becomes explicitly stale.
    }
}
```

A work limit spent in a failed stage is not refunded. A failed optional motion
stage does not revoke a successfully accepted tracking receipt. This split is
intentional: hiding the accepted receipt behind a single error could cause a
caller to replay an already-consumed source.

## Evidence and uncertainty

The automatic detector generation binds the frozen background digest and every
foreground-policy field. Camera, clock, capture interval, calibration, image
domain and permission-mask identities are preserved. Every component retains its
exact half-open bounds and a distinct hash bound to the complete foreground
report and component record. Count overflow refuses the complete input; it does
not choose a top-k subset. Edge/unknown silhouettes remain partial. Broad changes
are disturbed and no-comparable-pixel frames are unobservable, not safe/empty.

Motion estimation is a **two-observation conditional Gaussian model**, not a
full-history smoother or a Kalman replacement for the tracker's association
logic. It uses Joseph-form updates and explicit acceleration/measurement/velocity
priors. It rejects uncertain capture timestamps instead of inventing midpoints.
Partial silhouettes, missing pairs and exceeded fitting/prediction horizons
produce explicit unknowns. Coasting predictions retain the exact original source
pair and are labelled as predictions. Covariance is not a certified geometry
bound, calibrated identity confidence, ground contact, physical speed, or absence.

No person/vehicle classifier, biometric identification, camera acquisition,
alert delivery, persistence, canonical publication or live-device qualification
is supplied by this module. The owner must retain source bytes/receipts through
existing custody and publication interfaces. These local computations confer no
authorization to inspect pixels, identify people, or emit effects.

## Validation status

Eight numerical/trajectory unit tests and eleven pipeline integration tests were
added. The pipeline tests include actual luma extraction and the repository's
native JPEG fixtures, plus all deterministic budget cuts around the tracking
commit boundary. They have **not been compiled or executed in the authoring
sandbox**, which has no Rust toolchain. Independent Python matrix checks exercised
2,000 covariance cases and 10,000 irregular filter steps; these validate the
transcribed formulas, not the compiled Rust integration or real-camera behavior.
