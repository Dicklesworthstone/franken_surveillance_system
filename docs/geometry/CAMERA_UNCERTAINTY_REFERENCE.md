# Conditional camera uncertainty reference

## Implemented surface and limits

`fss-geometry` can propagate the full within-camera bundle covariance to a
held-exact world point using `AdjustedCamera::project_uncertainty`. It preserves
pose/intrinsics/radial cross terms, the aspect-held focal coupling, and the
bundle solver's left-rotation/additive-translation tangent convention. It also
propagates optical-axis depth uncertainty. No dependency or I/O is added.

For joint bundle results, prefer `BundleAdjustment::project_camera_uncertainty`.
It checks the current geometry basis and **every** camera dependency, not just the
camera being projected. The result retains basis, gauge, dependency generations,
observation-noise provenance, and fixed-parameter declarations. Inputs called
`current` must be resolved from authority; copying the old estimate's generations
is not a freshness check. A changed survey/control set must mint a new twin basis.

The optional `linearized_frustum` operation encloses a caller-chosen sigma-scaled
local contour without clipping at image edges. It returns `Inside`, `Outside`,
`Boundary`, or `CrossesCameraPlane`. The last outcome takes precedence even if the
pixel covariance is zero: perspective can be undefined along uncertain depth.
The image domain is half-open: left/top are included; right/bottom are excluded.

These are reference mathematical results, **not** coverage witnesses, calibrated
probabilities, or authority to infer absence. Existing coverage-witness paths are
unchanged. No bead, production gate, release claim, or detection-quality claim is
closed by this addition. In particular:

- The world point is held exact. A jointly fitted landmark requires its covariance
  **and** camera/landmark cross covariance; adding marginal variances as if they
  were independent would invent an assumption the API does not justify.
- A held gauge or fixed lens parameter does not have zero physical uncertainty.
  In the aspect-held model, the fixed `Fy` slot denotes a fixed aspect, not a
  physically fixed `fy`; its derivative follows the free focal parameter.
- Output pixels use the declared bundle radial model's raw image domain. They
  cannot be mixed with an undistorted/dewarped image without an explicit transform.
- Perspective/distortion are linearized locally. A sigma multiplier is not a
  confidence probability, and an enclosed linearized contour is not a globally
  certified nonlinear bound. Occlusion, privacy, timing, point uncertainty,
  outliers, lens-model error and detector quality still require separate evidence.

## Numerical contract and refusal behavior

The free and fixed parameters must form one complete disjoint 12-slot camera
block. Axis indexes, focal-model compatibility, matrix shape and finite values are
checked before use. Full positive-semidefiniteness is checked, not just positive
diagonals or pairwise correlations. Covariance is normalized to correlation units
before factorization to avoid an absolute threshold shared by radians, world units
and pixels. Symmetry discrepancies no larger than 64 machine epsilons at normalized
scale are averaged; larger discrepancies refuse. Negative pivots are never clipped,
regularized or repaired. Exact zero and factorizable semidefinite matrices are
supported; numerically unresolved near-singular matrices may conservatively refuse.

Propagation computes `A = J L`, then `A A^T`, retaining correlations without
catastrophic subtraction of output variances. Every nonfinite result refuses.
Malformed input, stale/missing/duplicate generations, a changed basis, budget
exhaustion and cooperative cancellation return typed errors, not a zero-variance
or low-confidence substitute. A failed computation never returns a partial result.

## Explicit work accounting

| Operation | Bound | Fixed reference charge |
| --- | --- | ---: |
| Camera covariance projection | At most 12 parameters; bounded cubic factorization | 12,000 units |
| Joint dependency validation | At most 32 entries; bounded quadratic comparison | 4,096 units |
| Linearized contour assessment | Constant work | 64 units |

These are deterministic reference work units, not measured instruction counts or
latency claims. All work is synchronous, with cancellation checked before charging
and before returning. A refused charge does not partially consume that charge;
a later failure can retain earlier successful charges. No partial output escapes.

## Usage

```rust
use fss_geometry::{
    BUNDLE_UNCERTAINTY_VALIDATION_WORK_UNITS, BundleAdjustment,
    BundleProjectionUncertainty, CAMERA_UNCERTAINTY_WORK_UNITS, CameraGeneration,
    FRUSTUM_UNCERTAINTY_WORK_UNITS, GeometryBasis, LinearizedFrustumAssessment,
    ProjectionUncertaintyError, WorkBudget,
};

fn assess(
    bundle: &BundleAdjustment,
    current_basis: GeometryBasis,
    current_dependencies: &[CameraGeneration],
    camera: u64,
    held_exact_world_point: [f64; 3],
) -> Result<(BundleProjectionUncertainty, LinearizedFrustumAssessment), ProjectionUncertaintyError> {
    let mut budget = WorkBudget::new(
        BUNDLE_UNCERTAINTY_VALIDATION_WORK_UNITS
            + CAMERA_UNCERTAINTY_WORK_UNITS
            + FRUSTUM_UNCERTAINTY_WORK_UNITS,
    );
    let estimate = bundle.project_camera_uncertainty(
        camera, current_basis, current_dependencies, held_exact_world_point, &mut budget,
    )?;
    let boundary = estimate.projection().linearized_frustum(3.0, &mut budget)?;
    Ok((estimate, boundary))
}
```

## Tests and qualification boundary

The new `uncertainty` tests cover correlation signs, aspect-held focal length,
finite-difference derivatives, nonzero camera translation, parameter permutations,
malformed/indefinite/asymmetric matrices, scale disparity, exact singular covariance,
nonfinite geometry, budgets, cancellation, half-open edges, camera-plane crossing,
and freshness of **other** cameras in a joint solve. A synthetic integration test
runs the existing control-point bundle solver, then projection and contour assessment.

Run on the repository's pinned toolchain:

```sh
cargo fmt --all -- --check
cargo test -p fss-geometry uncertainty
cargo test -p fss-geometry
cargo clippy -p fss-geometry --all-targets -- -D warnings
```

Then run the applicable repository qualification lanes. The authoring environment
for this patch had no Rust toolchain and could not execute these commands. The
Python numerical audit distributed with the patches is an independent mathematical
cross-check, not execution of the Rust implementation or a retained release proof.
