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
