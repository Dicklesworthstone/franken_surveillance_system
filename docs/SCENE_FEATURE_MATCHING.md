# Native JPEG feature matching and scene reconstruction

`fss-scene-fuse match` takes two JPEG views, an imported property twin and a
declared camera rig through native feature extraction, automatic correspondence
selection and 3D point reconstruction. The caller supplies the source, camera
and timing declarations; individual pixel correspondences are discovered from
the images.

```sh
cargo run -p fss-cli --bin fss-scene-fuse -- match \
  --twin property.fsstwin --rig cameras.json --query pair.json \
  --left left.jpg --right right.jpg \
  --report-out reconstructed.json
```

The result is a set of conditional **stationary feature-point hypotheses** in
the twin's coordinate frame. It includes the complete candidate table, source
hashes, rejected or ambiguous features, successful points and geometric
refusals. It does not identify people, merge persistent tracks, certify camera
calibration, activate a world model or publish an event.

This implements an image-based portion of `fss-x4a.19.1` / FSS-099. That broader
cross-camera association bead remains open: this command does not qualify
moving-object identity, measured field accuracy or the aggregate association
release gate.

## Inputs and declarations

The rig uses the existing `fss.scene_camera_rig.v1` contract and pins the exact
twin package and source scene. Camera poses use world-to-camera rotation and
translation in the twin's unchanged source units. This command accepts the
existing authored nominal, undistorted pinhole rig profile. Unknown calibration
error remains unknown.

The query format is `fss.scene_feature_match_query.v1`. The example below uses
digest placeholders; replace them with the exact SHA-256 values. Unknown fields,
duplicate keys, missing assumptions and noncanonical integer timestamps refuse.

```json
{
  "schema": "fss.scene_feature_match_query.v1",
  "camera_rig_digest": "sha256:<exact cameras.json bytes>",
  "privacy_domain": 9,
  "clock": 11,
  "clock_evidence": "sha256:<common capture-clock evidence or explicit assumption>",
  "association_basis": "sha256:<stationary common-feature evidence or assumption>",
  "reference_time_ns": "1050",
  "max_capture_span_ns": 100,
  "motion": "static_during_capture_hull",
  "left": {
    "camera": 1,
    "source_digest": "sha256:<complete original left.jpg bytes>",
    "image_domain_digest": "sha256:<qualified left image-domain declaration>",
    "mapping_basis": "sha256:<left source-to-camera mapping declaration>",
    "capture_ns": ["1000", "1100"],
    "sigma_pixels": 0.5,
    "component_interpretation": "grayscale",
    "mask": {"kind": "all_allowed"}
  },
  "right": {
    "camera": 2,
    "source_digest": "sha256:<complete original right.jpg bytes>",
    "image_domain_digest": "sha256:<qualified right image-domain declaration>",
    "mapping_basis": "sha256:<right source-to-camera mapping declaration>",
    "capture_ns": ["1000", "1100"],
    "sigma_pixels": 0.5,
    "component_interpretation": "grayscale",
    "mask": {"kind": "all_allowed"}
  },
  "extraction": {"threshold": 20, "maximum_features": 128, "separation": 6},
  "matching": {
    "maximum_hamming_distance": 64,
    "ratio_percent": 80,
    "maximum_epipolar_distance_pixels": 1.0
  },
  "triangulation": {
    "min_views": 2,
    "max_outliers": 0,
    "max_reprojection_pixels": 2.0
  }
}
```

Digest strings are `sha256:` followed by exactly 64 lower-case hex digits, and
all required pins must be nonzero. Hashes bind declarations; hashing an assumption
does not make it measured evidence. Both cameras must use the requested clock
and privacy namespace. The reference time must lie within the full capture hull,
including timestamp uncertainty, and both intervals must fit camera validity.
The complete hull must fit the explicit allowance, at most one second. A moving
feature cannot be admitted by substituting frame-arrival times or interval
midpoints for this static-scene declaration.

Each source must have a distinct camera and original JPEG byte identity. The
native decoder admits its existing baseline and progressive Huffman profiles.
Declare `grayscale` for a one-component image or `ycbcr` for a supported
three-component image. The command uses full-range luma. It does not apply Exif
orientation, ICC conversion, crop, distortion correction or an inferred camera
mapping. Decoded dimensions must equal the rig's undistorted image grid; supply
properly qualified input pixels and the matching rig.

### Allowed-pixel masks

Every view explicitly chooses a mask policy. `{"kind":"all_allowed"}` admits
the complete decoded grid and forbids an additional mask argument. For an
exclusion mask, use `{"kind":"file","digest":"sha256:<exact mask bytes>"}`
and pass the corresponding `--left-mask` or `--right-mask` path.

A mask is a tightly packed row-major byte array with one byte per decoded pixel:
`1` allows the pixel, `0` excludes it. Other values, wrong lengths, wrong hashes,
missing mask files or undeclared extra mask files refuse. A feature is extracted
only when its **entire 33×33 descriptor footprint** is allowed. A fully excluded
view produces an explicit no-support report, not a fabricated point. The input
mask is an operator policy; it is not a permission grant or retained privacy
certificate.

## Matching and geometric meaning

The native FAST-9/oriented BRIEF-256 extractor preserves its descriptor algorithm
identity, exact pixels and mask digest, extraction settings and omission counts.
At most 128 features per view enter association. Tile quotas, spacing and the
selection limit may omit local maxima; those omissions remain counted.

All selected descriptors participate in matching. A pair must pass the absolute
Hamming threshold, be mutual nearest neighbors, and pass the strict best-to-next
ratio in **both** directions. Equal best distances and a missing runner-up are
ambiguous. The algorithm evaluates these rules before epipolar screening, so
geometry cannot hide an appearance competitor to manufacture uniqueness.

Each Cartesian pair also receives both directed nominal point-to-epipolar-line
distances. Coincident camera centers and degenerate epipolar lines remain
unobservable. Only a descriptor candidate passing both epipolar distances is
offered to the existing native `fuse_scene_point` owner. Both views are required;
outlier omission is disabled. Weak, behind-camera or contradictory geometry
retains a refusal beside any successful companion hypotheses.

Each successful point retains source observation evidence, complete capture
intervals, reprojection residuals, ray angle, condition number, conditional pixel
noise covariance and nominal visibility against the exact imported static mesh.
An occlusion contradiction is retained. Covariance does not cover camera pose,
intrinsics, clock error, correspondence error, motion, rolling shutter, shared
failure modes or map error. Relative-scale twins stay in relative source units.

The new kernel uses separate versioned association, pair and observation evidence
domains. It does not change the older private calibration matcher's behavior or
historical calibration record bytes.

## Reports, limits and cancellation

The outer format is `fss.scene_feature_match.v1`. `report_digest` hashes the exact
UTF-8 `report` member. Its `fss.scene_feature_match_report.v1` body contains the
original query declarations, exact source/rig/twin identities, decode receipts,
camera snapshots, feature inventory, full Cartesian pair table, per-feature
outcomes and every attempted point hypothesis. Camera and feature order are
canonical. Image-local feature IDs are not physical identities.

| Exit | Meaning |
|---|---|
| `0` | At least one reconstructed point and no selected geometric refusals |
| `3` | No reconstruction, or some selected hypotheses refused |
| `2` | Input, source pin, I/O, authority, work, cancellation or complete-output failure |

An unmatched or ambiguous feature remains in the report but does not by itself
invalidate successful independent matches. Inspect all dispositions and
assumptions before using a point.

Inputs must be bounded regular files: twin 64 MiB, rig and query 1 MiB each,
JPEGs 16 MiB each, masks 4 MiB each. Paths come only from command-line arguments.
The complete report is at most 8 MiB, including its newline; `--max-report-bytes`
may lower that limit to at least 1,024 bytes. Overflow refuses the complete
request without trimming the candidate inventory.

`--work-units` defaults to 2,000,000,000 and is capped at 5,000,000,000.
This command has a separate image-processing allowance: two fully allowed
1080p grids need more than 1.27 billion units for feature detection alone. Twin import,
native decoding, masked extraction, association, geometry and complete report
serialization share the allowance. A decoder cannot consume more than the
remaining allowance. Full-inventory serialization work is reserved even when a
smaller output byte limit will refuse the result.

`--timeout-ms` defaults to 30,000 and is capped at 3,600,000. A borrowed owner
cancellation/deadline probe reaches decoder and geometry work charges, including
feature extraction. No detached timer task is created. Cancellation returns no
partial reconstruction or successful cost receipt. The local context follows
request/drain/finalize ownership.

`--report-out` exclusively creates a new private file after the complete result
is computed. Existing outputs are refused, not overwritten. The file and stdout
receive identical JSON bytes and a final newline. A write failure is explicit;
an incomplete newly created file may remain for inspection.

## Validation scope

The native association suite passes 17 actual Cargo tests, including independent
rectified and oblique camera geometry, extracted shifted texture, repeated
appearance, off-epipolar candidates, weak/behind-camera geometry, occlusion
contradictions, complete timing uncertainty, permutation and cancellation.
Strict scoped Clippy passes for that kernel and test target.

The exact production parser/pipeline/report modules pass 16 additional tests.
Two original independently encoded grayscale JPEG fixtures pass through the
native decoder and feature extractor and reconstruct the analytically known
depth of 10 without caller-provided correspondences. Tests cover complete
deterministic report hashes, masks and no support, source/grid/clock/privacy
failures, cumulative work, staged deadlines and output refusal. The decoder's
three new probe contracts pass against the exact native source. The fixture
construction and hashes are in `crates/fss-cli/tests/fixtures/scene_match.md`.

These synthetic tests qualify the bounded implementation and arithmetic; they
do not measure field correspondence accuracy or validate authored camera poses.
See `IMPLEMENTATION_STATUS.md` for the real CLI owner test/build status.
