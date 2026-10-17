# Capture-interval validation of temporal reconstruction

`fss_geometry::temporal_validation::triangulate_motion_validated` composes the
[nominal time-aware fit](temporal_triangulation_reference.md) with genuinely
held-out observation membership. Validation images never influence the fitted
position, velocity or pixel-noise covariance. This extends the reference FSS-099
geometry/time gate without granting association, calibration or effect authority.

## Complete intervals, not convenient timestamps

An `IntervalCalibratedView` carries the calibrated image measurement and an
inclusive `[earliest, latest]` capture interval on the fit's common signed i128
clock. The camera pose and pinhole image mode must be fixed throughout that
interval. The function never substitutes the midpoint, optimizes the timestamp,
or clips the interval to make a measurement agree.

For a constant-velocity world trajectory in front of a fixed pinhole camera,
projection traces a straight image segment. The largest Euclidean residual is at
an endpoint; the smallest is the distance to the closest point on that segment.
The implementation evaluates those extrema analytically, not by sparse time
sampling. A scale-aware floating-point margin widens the residual range near a
gate boundary; it is numerical caution, not verified interval arithmetic.

Every holdout receives one explicit result:

- `ConsistentForAllTimes`: its entire modeled interval satisfies the pixel gate.
- `TimingAmbiguous`: only some times may satisfy the gate, or rounding straddles it.
- `Inconsistent`: no modeled time satisfies the gate.
- `NotObservable`: the complete interval fails near-plane, distance or image-domain
  admission. It is not silently clipped or reported as evidence of physical absence.

`MotionValidation::consistent_for_all_capture_times()` is true only for a
nonempty complete inventory whose rows are all consistent. Widening a holdout's
time uncertainty cannot turn a failed all-times gate into support: it keeps the
fit fixed and adds possible times rather than selecting a favorable one. Some
inconsistent results can become timing-ambiguous as their intervals widen. That
is weaker information, not stronger corroboration.

## Usage

```rust,ignore
use fss_geometry::temporal_triangulation::TemporalTriangulationOptions;
use fss_geometry::temporal_validation::triangulate_motion_validated;
use fss_geometry::WorkBudget;

// training: &[TimedCalibratedView], qualified nominal times for the fit.
// holdouts: &[IntervalCalibratedView], separate measurements with full time ranges.
let report = triangulate_motion_validated(
    training,
    holdouts,
    TemporalTriangulationOptions::default(),
    &mut WorkBudget::new(4_000_000),
)?;
// Inspect every report.checks row; report.fit is still only a conditional fit.
```

The same reprojection and camera-distance limits apply to fit and validation.
Both phases consume one caller-owned budget and cancellation flag. Training and
holdout sets are independently limited to 128 observations. Beyond the fit,
admission is O(H log H + H N), projection is O(H), and scratch is O(H).
An exhausted budget returns no partial fit or validation inventory.

Intervals must be valid and remain within the fitting time window: this API does
not certify extrapolation. Empty validation, overlapping same-camera holdouts,
and any holdout interval containing a training time from the same camera are
refused. Canonical camera/interval ordering makes the result and work independent
of input ordering. Camera/time non-overlap establishes only distinct membership;
it does not prove separate original media or statistical independence.

## What remains conditional

This validates a fixed constant-velocity candidate over the holdout time ranges;
it does not propagate uncertain training timestamps into a family of fits.
Input poses, intrinsics, feature association and common clock must already be
qualified. Calibration uncertainty, pixel-noise uncertainty in the fitted state,
acceleration, rolling shutter, source custody, privacy generations and shared
failure domains remain separate obligations. A successful check is neither a
physical-truth certificate nor authorization to publish an event or dispatch an
alert. Deployment watch/corroborate integration remains outside these kernels.

## Executed checks

On 2026-10-17 pinned `nightly-2026-08-31` executed all 14 interval-validation
contracts and the full 140-test geometry suite, with locked offline dependencies
and debug assertions. Strict all-target geometry Clippy and source formatting
also passed. The contracts include midpoint-only false agreement, uncertainty
widening, complete residual ranges checked against dense projections, visibility
refusal, fitting-evidence reuse, duplicate/overlapping holdouts, extrapolation,
large epochs, permutation invariance and cancellation/late work exhaustion.

```sh
cargo test --locked --offline -p fss-geometry --test temporal_validation_contract
cargo test --locked --offline -p fss-geometry
cargo clippy --locked --offline --no-deps -p fss-geometry --all-targets -- -D warnings
```

The repository-wide qualifier was attempted but did not complete its policy scan
before the execution timeout. No full-workspace, DSR or field qualification is
claimed from these synthetic geometry checks.
