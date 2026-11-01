# Retained scene matching with native lens correction

Both `fss-scene-fuse retained-match` and `retained-multimatch` accept version 2
queries with an explicit image interpretation for each retained camera view.
Raw Brown–Conrady and central fisheye images can now enter the existing native
matching and 3D reconstruction path without external image preprocessing.
Explicit pinhole crop/resize is supported through the same native transformation.

```sh
fss-scene-fuse retained-multimatch \
  --root deployment --site site:example \
  --twin property.fsstwin --rig cameras.json --query retained-cameras-v2.json \
  --work-units 16000000000 --timeout-ms 300000 \
  --report-out corrected-scene.json
```

The two-camera command supports the same view declarations; its maximum geometry
allowance is `--work-units 5000000000`. Choose work and timeout bounds for the
actual source/target grids. These are cumulative allowances, not throughput claims.

## Version 2 queries

The schemas are:

- `fss.scene_feature_match_retained_query.v2` for two cameras, using `left`/`right`.
- `fss.scene_feature_multimatch_retained_query.v2` for 3–8 cameras, using `views`.

Source selection, capture/clock alignment, rig pins, matching/extraction options,
and stationary-feature assumptions retain their existing meanings. See
[retained matching](RETAINED_SCENE_MATCHING.md) and
[multi-camera matching](RETAINED_MULTICAMERA_MATCHING.md) for those fields.

In each version 2 view, replace `image_domain_digest` with a required `image`
object. An already-undistorted native source uses:

```json
{
  "kind": "pinhole",
  "image_domain_digest": "sha256:NATIVE_PINHOLE_DOMAIN_HEX"
}
```

A distorted source uses an explicit correction declaration:

```json
{
  "kind": "rectified",
  "source_domain_digest": "sha256:RAW_SOURCE_MODE_HEX",
  "lens_basis": "sha256:DECLARED_LENS_EVIDENCE_HEX",
  "source_intrinsics": {
    "width": 1920,
    "height": 1080,
    "fx": 1100.0,
    "fy": 1100.0,
    "cx": 960.0,
    "cy": 540.0
  },
  "distortion": {
    "kind": "brown_conrady",
    "radial": [-0.08, 0.01, 0.0],
    "tangential": [0.0005, -0.0003]
  },
  "maximum_radius": 1.1,
  "luma_range": "full"
}
```

The values above demonstrate the shape, not a calibration for a particular
camera. Replace digest placeholders with complete nonzero SHA-256 identities
and supply the measured or explicitly assumed model for the selected source.
`lens_basis` binds that declaration's evidence; a hash does not validate it.

Mixed pinhole and corrected views are supported. Version 1 keeps its original
native-pinhole semantics and successful report format. A v1 query rejects the
new `image` field, and v2 rejects the old per-view `image_domain_digest` field.
Unknown, duplicate, contradictory or incomplete model fields refuse.

## Source grid and target camera

`source_intrinsics` describes the original native decoded grid. The decoded
source dimensions must match exactly. Source capture, capsule, exposure, pixels,
native decoder receipt and current privacy cannot be substituted by the query.

**Target intrinsics come exclusively from the selected camera in `cameras.json`.**
There is no query-side target override. The rig remains an undistorted pinhole
rig with the same authored camera pose; a different target grid can express a
crop or resize through its dimensions, focal lengths and principal point.
Update the exact `camera_rig_digest` whenever the rig bytes change.

All coordinates use the existing pixel-edge convention, with raster centers at
half-integer coordinates. Source and target share optical axes and center.
Correction does not silently rotate the optical camera, apply Exif orientation,
estimate stabilization, change a mount pose, or reinterpret a stitched panorama.

The native plan computes its actual sampling-map digest and output image-domain
digest from the declared source model and exact rig target. The query does not
guess a corrected output hash. The source-to-camera `mapping_basis` remains a
separate explicit declaration.

## Supported lens and sample models

| `distortion.kind` | Parameters and meaning |
|---|---|
| `pinhole` | No coefficients. With differing source/target intrinsics, applies an explicit crop/resize. |
| `brown_conrady` | `radial: [k1,k2,k3]` for normalized-radius powers 2, 4 and 6; `tangential: [p1,p2]`. |
| `fisheye` | `coefficients: [k1,k2,k3,k4]` in the angular polynomial `theta_d = theta * (1 + k1*theta² + k2*theta⁴ + k3*theta⁶ + k4*theta⁸)`. Central rays in the front optical hemisphere only. |

The native rectifier uses sufficient whole-domain non-folding checks. Folded,
nonfinite, unsupported or numerically inconclusive models refuse. All selected
plans are compiled and admitted before the first native source decode can
publish a JPEG derivative. This includes later views in a multi-camera query.

`maximum_radius` is the largest admitted undistorted normalized radius, from
`0.000001` through `64`. Source and target are each bounded to 4,096 pixels per
axis and 4,194,304 pixels total. Coefficient magnitudes are at most 100; the
whole-domain checks can reject models within those numeric bounds.

`luma_range` explicitly describes the decoded samples supplied to correction:

- `full` uses the native 0–255 samples directly.
- `video` clamps samples to 16–235 and expands to 0–255 before interpolation.

This declaration does not discover the camera's range. Corrected output is
full-range grayscale. The native rectifier uses a bounded Q16 backward map and
Q32 bilinear interpolation with half-up rounding. Unmapped samples remain
unavailable; there is no border replication to manufacture observations.

## Privacy follows original sample support

The current retained policy supplies the original-image allowed mask. If any
positive-weight interpolation tap is private, the output sample is unavailable
before contributing source values are read. Out-of-source and out-of-lens
samples are also unavailable. The native extractor then checks the complete
33×33 descriptor footprint on this corrected mask.

A source mask therefore affects its full resampled support; it is not merely
copied at the same pixel coordinates onto a different grid. Fully masked or
unmapped views produce empty diagnostics while still undergoing all source,
camera, clock and privacy checks. No caller mask override is introduced.

## Complete versioned output

A v2 query produces the corresponding `fss.scene_feature_match_retained.v2`
or `fss.scene_feature_multimatch_retained.v2` envelope. Original geometry,
component, source-revalidation and exit-status semantics remain unchanged.
Each source view additionally contains `image_processing`:

| Field | Meaning |
|---|---|
| `kind` | `native_pinhole` or `native_rectified`. |
| `output` | Actual feature exposure, pixel digest, image domain and dimensions. |
| `allowed_mask_digest` | Actual allowed mask on the feature grid. |
| `model` for corrected views | Complete source/target intrinsics, lens family and coefficients, source/lens pins, radius and luma transfer. |
| `source` for corrected views | Original exposure, native storage digest, raw allowed-mask digest, source domain/lens basis, native dimensions, packed stride and range. |
| `map_digest` | Actual compiled native sampling table. |
| `coverage` | Complete mapped/outside-lens/outside-source/allowed/privacy-rejected sample accounting. This is geometric image support, not live sensor coverage. |

The enclosing view's original `source.pixel_digest`, dimensions, capsule and
native decoder receipt keep their original meaning. They are not overwritten
with the corrected image. Original exposure remains unchanged, so rectifying
one frame multiple ways does not create independent observations.

`sigma_pixels` belongs to the **actual feature output grid**. Resizing does not
automatically rescale a source-noise assumption. Native point covariance remains
conditional on declared independent output-pixel noise and fixed camera geometry;
interpolation correlations, lens-parameter error, camera/map/clock/motion and
correspondence errors are explicitly outside that covariance.

After constructing the complete source-dependent analysis, sealed owners
revalidate original retained ranges and current privacy. Final source-read
accounting includes those checks. No partial successful report is emitted for
source loss, changed privacy, cancellation or insufficient work/output allowance.
The existing private, exclusive report-file behavior remains in force.

## Work and calibration boundaries

Plan compilation, resampling, mask propagation, extraction, matching and report
serialization share the command's cumulative geometry allowance. Original source
reads, JPEG work and video byte/luma admission retain their separate existing
ceilings. Each sampling map uses eight bytes per target pixel; at eight maximum
target grids the admitted maps can occupy 256 MiB. Maps are released after
feature extraction, before scene geometry/report construction. Native source
frames are decoded sequentially.

This closes the raw-image-to-scene path for supported declared models. Lens
estimation, adopted-calibration authority, rolling shutter, moving-feature
correspondence and field accuracy remain separate work. The reusable sealed Rust
API is documented in [Retained feature extraction](RETAINED_FEATURE_EXTRACTION.md).
