# Multi-camera scene reconstruction

`fss-scene-fuse` reconstructs selected common features from several cameras in the coordinate
frame of an imported property. It can also estimate a feature's position and velocity jointly
from camera exposures taken at different times. Every solved feature is reported at the same
requested scene time, so a consumer can display the results together without treating packet
arrival times or different camera frames as simultaneous.

This is an offline, native Rust analysis path over owner-selected files. It connects the
existing point triangulator and the temporal triangulator to the imported scene mesh and a
strict camera rig. It produces derived geometric hypotheses; it does not activate calibration,
publish world/event revisions, establish person identity, fetch source media, or control cameras.
The algorithms consume selected corresponding image features, so a detector or operator still
has to propose which observations refer to the same physical feature. A generic detector box
bottom is not automatically a common visible feature.

## Run the command

```sh
cargo run -p fss-cli --bin fss-scene-fuse -- \
  --twin property.fsstwin \
  --rig property.cameras.json \
  --observations observations.json \
  --report-out scene-report.json
```

The report is also written to stdout. `--report-out` creates a new file with private permissions
on Unix and refuses an existing destination. All inputs are regular files; JSON inputs are at
most 1 MiB each, and the twin package is at most 64 MiB. Input documents cannot introduce extra
paths or URLs for the command to read. The default shared import/geometry allowance is
100,000,000 work units; `--work-units N` accepts 1 through 1,000,000,000.

The camera rig pins the exact SHA-256 of both the `FSSTWIN1` package and its source scene.
The observation query pins the exact SHA-256 of the camera rig file. Whitespace changes in
that file require updating the query's pin. The report additionally retains a canonical semantic
rig digest, the exact observation file digest, the source scene digest, and the property revision.
Changing an imported mesh, camera mode, scene revision or rig cannot silently reuse an old query.

The expected inputs are:

| Input | Purpose |
|---|---|
| `property.fsstwin` | Evaluated source geometry, semantic surface bindings, scale declaration and source-scene identity. |
| `property.cameras.json` | Camera positions/orientations and undistorted pinhole image modes, explicitly bound to the same twin. |
| `observations.json` | Source-bearing feature correspondences, full capture intervals and one shared reference time. |

Blender can author the property and camera placements; the implemented export path is
documented in [TWIN_IMPORT_REFERENCE.md](TWIN_IMPORT_REFERENCE.md). Existing glTF/GLB scenes
can use the bounded importer documented in [GLTF_SCENE_IMPORT.md](GLTF_SCENE_IMPORT.md). Both
paths produce the same native twin and camera-rig inputs. The broader evaluated interchange
boundary is described in [BLENDER_TWIN_INTEGRATION_PLAN.md](../BLENDER_TWIN_INTEGRATION_PLAN.md).
Imported rig camera placements remain `authored_nominal` with unknown calibration error.
A successful fit does not change that status.

## Camera rig

The `fss.scene_camera_rig.v1` document has these fields:

```json
{
  "schema": "fss.scene_camera_rig.v1",
  "source_scene_digest": "sha256:SOURCE_SCENE_HASH",
  "twin_digest": "sha256:TWIN_PACKAGE_HASH",
  "geometry_basis": {"property": 1, "revision": 1},
  "coordinate_frame": "RH_Z_UP",
  "evaluation_scope": "the exact evaluation scope declared by the twin",
  "cameras": [
    {
      "camera": 1,
      "calibration": 1,
      "image_domain": 1,
      "clock": 1,
      "privacy_domain": 1,
      "validity_ns": [0, 18446744073709551615],
      "source_object_id": "CameraFront",
      "image_model": "undistorted_pinhole",
      "world_to_camera": {
        "rotation": [[1, 0, 0], [0, 1, 0], [0, 0, 1]],
        "translation": [2, 0, 0]
      },
      "intrinsics": {"width": 640, "height": 480, "fx": 400, "fy": 400, "cx": 320, "cy": 240},
      "error": null,
      "status": "authored_nominal"
    }
  ]
}
```

Digest placeholders above stand for complete 64-digit hashes. The matrix convention is
`camera_point = rotation * world_point + translation`: translation is **not** the camera
center. The center is `-transpose(rotation) * translation`. The optical camera looks along
positive camera Z, image X points right, and image Y points down. A Blender export must convert
its camera axes to this convention and evaluate the object's complete world transform. The
example camera looks along world positive Z purely to illustrate the matrix convention.

All coordinates remain in the twin's source units. Scale is retained as relative, estimated,
or measured-anchor evidence. Focal lengths and principal points are in image pixels. Pixel
coordinates follow the geometry kernel's pixel-edge convention, with pixel centers at
`(column + 0.5, row + 0.5)`. Distorted/fisheye/raw image points require a separate qualified
rectification and a matching image-domain generation.

The shared rig reader rejects improper rotations, duplicate camera or authored-object IDs,
unknown fields, unsupported image modes, invalid generations, reversed validity intervals,
and mismatched source, scope, twin or property basis. At most 64 cameras are accepted. Only
cameras actually referenced by the query are included in the report's camera inventory. Rig
identities and validity times are exact JSON integers; preserve their integer representation
when editing the authoring tools' output.

## Observation query

The query contains one common clock and reference time for all hypotheses. Nanosecond fields
and integer identities accept exact JSON integers or canonical decimal strings; outputs use
decimal strings where large integers could lose precision in a JavaScript consumer.

```json
{
  "schema": "fss.scene_fusion_query.v1",
  "camera_rig_digest": "sha256:EXACT_CAMERA_RIG_FILE_HASH",
  "privacy_domain": 1,
  "clock": 1,
  "clock_evidence": "sha256:CAPTURE_CLOCK_MAPPING_RECORD_HASH",
  "reference_time_ns": "1500000000",
  "hypotheses": [
    {
      "id": "feature:gate-post",
      "association_evidence": "sha256:COMMON_FEATURE_HYPOTHESIS_RECORD_HASH",
      "max_capture_span_ns": "100000000",
      "motion": {"kind": "static"},
      "observations": [
        {
          "source_digest": "sha256:FIRST_SOURCE_OBJECT_HASH",
          "evidence_digest": "sha256:FIRST_OBSERVATION_RECORD_HASH",
          "camera": 1,
          "track": 42,
          "exposure": 1,
          "image_domain": 1,
          "capture_ns": ["1500000000", "1500000000"],
          "pixel_min": [453.3333333333333, 240],
          "pixel_max": [453.3333333333333, 240],
          "visible_contact": true,
          "sigma_pixels": 0.5
        },
        {
          "source_digest": "sha256:SECOND_SOURCE_OBJECT_HASH",
          "evidence_digest": "sha256:SECOND_OBSERVATION_RECORD_HASH",
          "camera": 2,
          "track": 17,
          "exposure": 1,
          "image_domain": 1,
          "capture_ns": ["1500000000", "1500000000"],
          "pixel_min": [186.6666666666667, 240],
          "pixel_max": [186.6666666666667, 240],
          "visible_contact": true,
          "sigma_pixels": 0.5
        }
      ]
    }
  ]
}
```

This two-camera example assumes the rig additionally contains camera 2 with the same
intrinsics/rotation and translation `[-2, 0, 0]`; the nominal reconstructed point is `[0, 0, 6]`.
Source, observation, association and clock handles must be nonzero SHA-256 identities. This
command retains them for provenance and subsequent hydration; it does not verify that those
source records exist or that the assertions they contain are physically correct.

`pixel_min` and `pixel_max` describe a selected visible feature rectangle, not the entire object
bounding box. The nominal solve uses its center. The rectangle remains in the report and is
not converted into a Gaussian noise estimate. `sigma_pixels` separately declares the isotropic
pixel-noise assumption. The upstream `track` identifier is anonymous and may differ between
cameras; the explicit association hypothesis links the selected physical features.

### Motion modes

| `motion.kind` | Inputs and behavior |
|---|---|
| `static` | Explicitly assumes the selected feature is stationary. Uses two to 32 distinct cameras and a capture hull of at most one second. |
| `linear` | Requires `velocity_per_second: [vx, vy, vz]` and a nonzero `evidence` digest. Moves each viewing ray into the requested reference-time frame before fitting; shares the point solver's bounds. |
| `infer_linear` | Requires `max_capture_uncertainty_ns`, the maximum full interval width. Fits position and velocity jointly from at least four observations across at least two distinct cameras, with repeated exposures allowed and a capture hull of at most sixty seconds. |

For inferred velocity, use:

```json
{
  "kind": "infer_linear",
  "max_capture_uncertainty_ns": "1000000"
}
```

Zero admits exact capture times only. The full capture hull, including timestamp uncertainty,
must fit `max_capture_span_ns`. Interval midpoints are used only by the explicitly nominal
motion fit; capture uncertainty remains separate. The requested reference time must fall
within the nominal observation range, and extrapolation is refused. A clock step, ambiguous
time mapping, unknown contact or incompatible camera generation requires new or improved input
evidence. Arrival time is never substituted for capture time.

An optional `triangulation` object on each hypothesis changes explicit solver limits. The
complete effective policy is retained in the report, including defaulted fields:

| Field | Point modes default | Inferred motion default |
|---|---:|---:|
| `max_reprojection_pixels` | 3 | 3 |
| `max_distance` | 1000 source units | 1000 source units |
| `max_condition_number` | 1e10 | 1e10, in normalized-time coordinates |
| `max_iterations` | 16 | 16 |
| `min_views` | 2 | Not an option; at least two cameras and four observations required |
| `max_outliers` | 0 | Not an option; every observation must fit |
| `min_ray_angle_radians` | 0.001 | Not an option; full motion conditioning is checked |
| `max_speed` | Not an option | 20 source units per second |

Point fusion retains every rejected camera's residual and visibility diagnosis when an
explicit outlier allowance is supplied. Competing equally supported geometric consensuses
are refused. Inferred motion requires every observation to satisfy the reprojection gate;
it does not discard a disagreeing exposure to make a trajectory appear coherent.

## Report and failure semantics

The outer object contains `report_digest` and `report`. The digest is SHA-256 over the exact
UTF-8 JSON representation of the `report` member produced by the command, without the outer
wrapper or terminal newline. This is a deterministic report identity, not a root-last
publication or an `EvidenceDeltaBatch` record.

Hypotheses are ordered by ID. Their observations are ordered by camera, capture interval,
exposure and evidence identity. Per-view native diagnostics follow the solver's canonical
camera/time ordering. Reordering the query changes its exact file digest while preserving the
same native solutions, source inventory and hypothesis result order.

Each hypothesis retains the exact source handles, image domains, calibration generations,
capture intervals, selected pixels, motion assumptions and effective solver policy. Solved
results contain position, optional inferred velocity, conditional covariance, conditioning and
reprojection diagnostics, capture hull, and a visibility diagnosis for every camera exposure.
A nominal point behind an imported opaque surface stays visible as a `conflicted` result;
geometric fit does not erase source/map disagreement. Clear nominal mesh visibility does not
certify physical visibility or absence of an object.

Hypothesis `knowledge` uses the canonical values `estimated` for a clean geometric result,
`conflicted` for nominal mesh disagreement, and `unknown` when the estimate is refused.

Covariance covers only the declared independent isotropic pixel-noise model with nominal
poses and times. It excludes calibration, clock, pixel-rectangle, association, motion-model,
rolling-shutter, shared-mode and map uncertainty. Inferred-motion covariance is a full 6×6
matrix ordered `[x, y, z, vx, vy, vz]`, including cross-covariances and rebasing to the shared
reference time. This does not quantify total physical uncertainty or justify extrapolation.

One failed hypothesis does not silently disappear or erase a successful companion. Refused
results retain all observations and a typed unavailable estimate. Malformed documents or
incompatible rig/privacy/clock/image-domain bindings reject the complete query before a report
file is created. Duplicate source evidence or camera exposures, weak geometry, excessive timing
uncertainty, nonconvergence and work exhaustion remain explicit refusals.

| Exit code | Meaning |
|---|---|
| `0` | Every hypothesis produced a geometric result; inspect `knowledge` and uncertainty before using it. |
| `3` | The complete report contains one or more refused hypotheses. |
| `2` | Input, I/O, authority or complete-report failure; a typed JSON error is written to stderr. |

At most 64 hypotheses, 128 observations per inferred-motion hypothesis and 2,048 observations
in the complete query are admitted. Point hypotheses are limited to 32 observations. Bounds
cause explicit failure rather than a truncated inventory. A failed report write names its
incomplete-output state; inspect the newly created destination before retrying.

## Reproduce the native checks

```sh
cargo test -p fss-cli --bin fss-scene-fuse
cargo test -p fss-cli --test scene_fusion_cli
cargo test -p fss-twin multiview
```

These tests include a known three-camera trajectory with staggered exposures, static and
externally supplied velocity modes, exact replay, input-order invariance, preservation of
failed hypotheses, timing uncertainty, duplicate source evidence, camera domain mismatch,
mesh conflicts, cancellation, exclusive report creation, retained budget refusals, and exact
timestamp/identity round-trips near `u64::MAX`. They establish the implemented
reference contract on synthetic geometry; they do not establish field detection, physical
camera calibration, automatic cross-camera identity assignment or live streaming quality.
