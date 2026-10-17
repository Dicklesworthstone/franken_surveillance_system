# Temporal multi-camera reconstruction — native reference

`fss_geometry::temporal_triangulation::triangulate_motion` reconstructs a
constant-velocity feature from staggered multi-camera observations. It advances
the reference geometry/time gate in FSS-099 (`fss-x4a.19.1`, WP-130), not the full
association or retained watch/corroborate workflow. It is not a deployment-qualified
feature or a release receipt.

## Contract

The existing simultaneous `triangulation::triangulate` API is unchanged. The new
API fits a constant-velocity trajectory to four through 128 already-associated
undistorted image observations from at least two logical cameras. Every
observation supplies its own calibrated world-to-camera pose and nominal capture
time. The caller must have qualified a common world frame and clock; no receive
timestamp, unresolved capture interval, camera name or model score establishes
that qualification.

The motion model is

```text
X(t) = position_at_reference + velocity_per_second * (t - reference_time)
```

The reference time is the integer midpoint of the earliest/latest capture times.
Only checked, bounded differences of i128 nanosecond timestamps are converted to
floating point. Position coordinates are centered on a canonical camera center;
time is normalized by the observed span. The maximum span is sixty seconds, which
is a resource bound, not a claim that constant velocity holds for that duration.

A weighted bearing-line least-squares solve initializes six parameters. Analytic
pixel-reprojection Gauss-Newton refinement with a finite backtracking line search
then fits the original image observations. Both stages use a six-by-six
Cholesky inverse with positive-pivot and condition-number refusal. They do not
add regularization that would manufacture missing position/velocity information.

```rust,ignore
use fss_geometry::temporal_triangulation::{
    TemporalTriangulationOptions, triangulate_motion,
};
use fss_geometry::WorkBudget;

// observations: Vec<TimedCalibratedView>, already associated and clock/frame-qualified.
let mut budget = WorkBudget::new(2_000_000);
let fitted = triangulate_motion(
    &observations,
    TemporalTriangulationOptions::default(),
    &mut budget,
)?;
```

The complete camera/time membership and every Euclidean residual are returned.
Every observation must pass the final pixel gate. No observation is silently
discarded, no identity is selected, and no independent failure-domain count is
inferred from the number of observations. Multiple times from the same camera
are allowed; duplicate camera/time pairs are refused.

## Limits and refusal

The caller controls maximum reprojection error, camera distance, speed, condition
number and iteration count. Distance and speed use the supplied world's units,
not implicitly metres. The hard ceilings are 128 observations, 32 iterations and
eight line-search trials per iteration. Work is O(N (1 + I B)) and scratch O(N),
with fixed-size six-dimensional solves. Sorting, validation, allocation and
numeric work are charged to `WorkBudget`; cancellation and budget exhaustion
return no partial trajectory.

Simultaneous inputs, a missing baseline, rank deficiency or an ill-conditioned
normal system cannot establish velocity. Such inputs are refused, not silently
interpreted as stationary. The original simultaneous-point API remains available
for its separate contract.

## Uncertainty and downstream obligations

The six-by-six covariance contains position/velocity cross-covariances. It is
converted from normalized time to seconds and inflated by excess weighted
residual variance. It is conditional on exact camera poses and nominal times,
correct associations, constant velocity and independent isotropic pixel noise.
It excludes camera calibration error, clock error, rolling shutter, exposure
intervals, acceleration, association error and shared failure modes.

Do not use this covariance as total uncertainty, a coverage witness, an identity
certificate or effect authority. Do not silently replace an uncertain timestamp
with its midpoint. A downstream owner still needs source/calibration/clock and
privacy-generation bindings, applicability checks, complete custody, visibility,
shared-cause accounting and a registered receipt before retaining or acting on a
result. None of that deployment integration is implemented by this geometry kernel.

## Native validation

```sh
cargo test --locked --offline -p fss-geometry --test temporal_triangulation_contract
cargo test --locked --offline -p fss-geometry
cargo clippy --locked --offline --no-deps -p fss-geometry --all-targets -- -D warnings
```

On 2026-10-17 the pinned `nightly-2026-08-31` compiler executed all 16 temporal
contracts and the full 126-test geometry suite with locked offline dependencies
and debug assertions. Strict all-target geometry Clippy and the pinned formatter
also passed. Tests cover staggered reconstruction, noisy data and covariance,
stationary targets, exact input permutation, large absolute timestamps,
rank-deficient geometry, timing/observation limits, no silent outlier removal,
speed/distance gates, cancellation and exhausted work.

These are native synthetic geometry checks, not camera/field or whole-workspace
qualification. Full native qualification remains the repository-owned
`scripts/qualify.sh` workflow. A numerical oracle is not a substitute for Rust
execution, source custody, calibration currency or field validation.
