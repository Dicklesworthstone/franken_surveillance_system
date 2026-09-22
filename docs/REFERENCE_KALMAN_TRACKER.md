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
