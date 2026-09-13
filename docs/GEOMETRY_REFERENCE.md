# Property geometry reference kernel

`fss-geometry` begins the executable BTI-01/BTI-03/BTI-05 spatial path. It is a
synchronous safe-Rust library with no production dependencies or ambient I/O.
It does not parse `.blend`/GLB, run a detector, or certify a property.

The typed mesh importer validates already evaluated property-world vertex and
triangle tables, nonzero owner-resolved feature handles, finite bounds, topology,
nondegenerate triangles, and allocation/work limits before publishing an immutable
mesh. Source hashes, transforms, scale uncertainty, current/historical selection,
and feature-handle resolution belong to the importing owner. GeometryBasis is a
process-local resolved property/revision key, not a new durable identity system.

The camera kernel defines undistorted zero-skew pinhole observations on pixel-edge
coordinates (pixel centers are i+0.5,j+0.5), proper world-to-camera transforms,
optical centers, positive-depth projection, and world rays. Distorted/fisheye/raw
sensor images must not be passed as pinhole pixels. Identity is a valid transform;
uncalibrated is an evidence state, not a forbidden matrix.

The scalar triangle path preserves support-layer alternatives and exact feature /
triangle / barycentric lineage. It does not substitute object bounds for surfaces.
Opaque segment intersection excludes an explicit endpoint margin, keeping optical
occlusion separate from support. A negative mesh intersection is not evidence that
an unknown or dynamic real-world occluder is absent. Coincident hits preserve
separate triangle lineage and must not be counted as independent observations.

All loops have count ceilings, work accounting, and owner cancellation checks.
Failures return no successful partial support set; exhausted output capacity does
not discard a deeper stair/deck/ground hypothesis silently. Debug summaries omit
pose, ray, and hit coordinates. Float computation has numerical tolerances, not a
claim of cross-platform bit identity or physical accuracy.

Validation commands on the accepted repository toolchain:

```sh
cargo test --locked -p fss-geometry
cargo clippy --locked -p fss-geometry --all-targets -- -D warnings
cargo fmt --all -- --check
```

The authoring environment has no Rust compiler. Contract tests are checked in,
but compilation, Rust test execution, formatting, and repository qualification
remain outstanding. BTI-01/03/05 and their parent FSS beads remain open until the
complete import, calibration, evidence, and retained qualification contracts pass.

## Supplied-correspondence camera registration

`estimate_camera_pose` now solves the missing **2D-to-3D** problem, not the existing
3D-to-3D Horn alignment. It fixes the supplied map and known pinhole intrinsics,
normalizes the 3D controls, solves small symmetric systems with bounded Jacobi
iterations, recovers a proper rotation, and refines on SE(3) using analytic image
Jacobians and damped robust least squares. Translation steps are normalized to
local support extent rather than an assumed metric unit. Six-point deterministic
RANSAC rejects incorrect matches; both inlier count/fraction and image/3D support
floors apply. Hypotheses failing cheirality or numerical conditioning are refused.

The admitted initial family is nonplanar, known-intrinsics, undistorted pinhole.
Planar/collinear or weakly conditioned controls fail explicitly; no claim of
P3P, planar homography pose, fisheye fitting, unknown focal-length solving, or
automatic feature matching is made. The methods follow the problem distinction
in https://docs.opencv.org/4.x/d5/d1f/calib3d_solvePnP.html; OpenCV is not a dependency.

Search preserves up to eight distinct passing modes. Close modes use documented
numerical clustering thresholds, not purported physical confidence intervals.
The sampling schedule is bounded and cannot prove that all alternatives were
exhausted. Candidate fields distinguish fit-only residuals from excluded checks.
`validate_candidate` never refits: it refuses held landmarks overlapping ANY fit
input, including rejected outliers, by supplied identity, physical group, exact
world coordinate, or pixel. A failed holdout retains every residual; behind-camera
points never count as zero error. These guards do not prove physical independence,
correct reconstruction scale, or the absence of correlated map error.

Executable example and independent end-to-end check:

```sh
cargo run --locked --offline -p fss-geometry --example register_camera
python3 scripts/test_geometry_replay.py
```

The example registers a synthetic camera whose center is independently fixed at
[4,-8,5], scores twelve excluded controls, and intersects an independently computed
observation ray with the support mesh at [4,2,0]. It emits one bounded JSON record,
not an FSS authority receipt. No real property imagery or private skill code ships.

Authoring numerical checks (not Rust execution): an independent Python calculation
of normalized DLT/Jacobi/SE(3) refinement matched OpenCV 4.13.0 on 80 seeded noisy
synthetic problems (maximum optical-center difference about 3.1e-9 world units),
and 24 independent Jacobi systems passed eigenvector/orthogonality checks. Separate
calculations rejected 10/40 incorrect matches and retained both 20-point modes of
an ambiguous 40-point set. These sanity checks concern the mathematics; they do
not substitute for compiling or executing the checked-in Rust. The real Rust
example, its Python consumer, contract tests, and qualification still need a Rust
compiler. No physical accuracy, calibration covariance, or production claim follows.
