# Reference Kalman tracking

`fss_reference::ingest::tracker::MultiObjectTracker` maintains anonymous image
tracks used by the reference event/cross-camera APIs. It is not the distinct
`LocalBoxTracker` used by recorded-analysis plans or the twin image tracker.

The filter uses `[cx, cy, vx, vy]`, one frame per step, independent per-axis
position/velocity process noise, and independent position measurement noise.
Prediction transports the full covariance through the constant-velocity model;
measurement correction uses the Joseph covariance update. Matching and coasting
output use the current prediction, not the previous observation. A Lost track
remains a prediction: `misses` is nonzero, so the event generator must not treat it
as a current detection. `min_hits = 1` confirms on the first observed frame.

This repairs the reference motion implementation described by comprehensive-plan
section 16. It does not grant identity, source custody, calibrated uncertainty,
coverage, negative evidence, or effect authority. Old runs are not rewritten or
claimed numerically equivalent; replay qualification must pin the source revision.

Regression source: `ingest/tracker/motion_contract.rs`. Run with the pinned Rust
workspace toolchain:

```sh
cargo test -p fss-reference ingest::tracker
cargo fmt --all -- --check
cargo clippy -p fss-reference --all-targets -- -D warnings
```

Session validation limitation: no Rust compiler, Cargo, rustfmt, or Clippy was
available. Authored Rust tests are not claimed executed. Independent numerical
checks and source/diff/hash checks are supplementary, not release qualification.

## Global matching and bounded admission

Both `step` and `try_step` use global bipartite assignment, maximizing the number
of supported matches before total IoU rounded to millionths. The overlap gate is
applied before quantization. Even a zero threshold does not make disjoint boxes
support an association. Ties use stable track-ID and detection-geometry traversal;
identical duplicate boxes have no distinguishable physical identity. Unmatched
birth IDs are assigned in geometry order rather than input order.

The rectangular Hungarian implementation computes costs on demand, with linear
auxiliary storage and O(T^2 * (T+D)) assignment work. `TRACKER_ALGORITHM` names the
numerical policy. Matching is an image-trajectory hypothesis, not an identity or
corroboration certificate. Ambiguous physical crossings still require evidence.

`try_step(detections, TrackerLimits::default())` is the bounded entry point. It
admits at most 128 active tracks, 128 detections per frame, and 4,194,304 Hungarian
column relaxations; owners can narrow every ceiling. An empty frame needs no
assignment work. Input is never truncated and active tracks are never silently
evicted to satisfy capacity. Same-step retirement can free room for new tracks.

Invalid input, work/capacity refusal, counter exhaustion or nonfinite Kalman
arithmetic returns a typed `TrackerStepError` without changing the previous
filter state, frame count or next identity. Candidate state is temporary and
bounded by the admitted tracks plus detections. `step` retains its existing
infallible signature for trusted compatibility callers; those callers still own
input/resource/counter validity and should migrate to `try_step` at trust boundaries.

`assignment_contract.rs` adds twelve tests, including a 4096-matrix exhaustive
oracle, the greedy trap, identity continuity through crossings, input permutations,
zero-overlap refusal, retry equivalence and atomic failure boundaries. Session
checks additionally compared 1000 assignment matrices with an independent SciPy
solver and exercised crossing/occlusion trajectories using a separate matrix
Kalman implementation. These checks are not executions of the Rust tests.
