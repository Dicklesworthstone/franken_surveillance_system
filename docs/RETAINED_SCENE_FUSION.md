# 3D scene reconstruction from retained detector tracks

`fss-scene-fuse retained-fuse` connects verified retained detector results and native tracking
to the existing multi-camera point and motion solvers. It reconstructs selected common features
in the imported property's coordinate frame at one shared reference time. This closes the gap
between the retained-track path and the original `fss-scene-fuse` command, which accepts loose
caller-declared observation handles.

The command gets source identities, actual assigned detector rows, image dimensions and capture
intervals from retained custody. Camera placements, source-to-camera mappings, undistorted image
applicability, clock alignment and feature correspondences remain explicit operator assumptions.
A geometric fit does not certify those assumptions, establish a person's identity or activate a
calibration/event/effect.

## Run it

First retain package detections with `fss-infer package-detect --retain yes`. Use
`fss-event report` to obtain exact native track identities and their tracker recipes, as described
in [RETAINED_HANDOFFS.md](RETAINED_HANDOFFS.md). Obtain the corresponding source generation,
capsule, segment and assigned detection-row identities from the retained owner projection.
The `bindings` in a `retained-handoffs` report already expose these fields, including all actual
observations. Handoff transitions can be empty when obtaining only this source inventory.

Import an evaluated Blender or glTF/GLB scene and camera rig using the existing
[twin import](TWIN_IMPORT_REFERENCE.md) or [glTF import](GLTF_SCENE_IMPORT.md) path. Then run:

```sh
fss-scene-fuse retained-fuse \
  --root /path/to/existing/deployment --site site:example \
  --twin property.fsstwin --rig property.cameras.json \
  --selection retained-scene-selection.json \
  --report-out retained-scene-report.json
```

`--expected-input sha256:HEX` optionally pins the exact selection file bytes.
`--expected-anchor sha256:HEX` optionally pins SHA-256 of the full canonical deployment anchor.
The selection always pins the exact rig file, and that rig pins the native twin and source scene.
Changing whitespace in the rig changes its file digest and requires a new selection pin.

The deployment must already exist. Its standard startup recovery may reconcile unfinished
publication or effect journal state; this command does not dispatch effects or publish new events.
The command reads retained original bytes without reacquiring loose images or loading a model.

## Selection document

The input schema is `fss.scene_fusion_retained_query.v1`. The following template illustrates one
feature seen by two cameras. Every uppercase digest placeholder must be replaced by an actual
nonzero SHA-256 value. The example pixel coordinates must also be replaced by selected features
inside the actual retained detector rectangles.

```json
{
  "schema": "fss.scene_fusion_retained_query.v1",
  "session": "session:scene-review",
  "generation": "sha256:ANALYSIS_GENERATION",
  "clock_evidence": "sha256:DECLARED_COMMON_CLOCK",
  "camera_rig_digest": "sha256:EXACT_RIG_FILE_HASH",
  "privacy_domain": 1,
  "clock": 1,
  "reference_time_ns": "1500000000",
  "selections": [
    {
      "id": "front",
      "report_digest": "sha256:RETAINED_REPORT_A",
      "label": "person",
      "tracking": {
        "confirmation_hits": 2,
        "maximum_missed_frames": 1,
        "minimum_iou_ppm": 100000
      },
      "track": "sha256:NATIVE_TRACK_A",
      "calibration": "sha256:DECLARED_CALIBRATION_A",
      "alignment": {
        "import_identity": "sha256:ACTUAL_IMPORT_A",
        "stream_id": "stream:front-generation",
        "clock_basis": "estimated",
        "offset_ns": [-1000000, 1000000],
        "basis": "sha256:DECLARED_ALIGNMENT_A"
      }
    },
    {
      "id": "yard",
      "report_digest": "sha256:RETAINED_REPORT_B",
      "label": "person",
      "tracking": {
        "confirmation_hits": 2,
        "maximum_missed_frames": 1,
        "minimum_iou_ppm": 100000
      },
      "track": "sha256:NATIVE_TRACK_B",
      "calibration": "sha256:DECLARED_CALIBRATION_B",
      "alignment": {
        "import_identity": "sha256:ACTUAL_IMPORT_B",
        "stream_id": "stream:yard-generation",
        "clock_basis": "estimated",
        "offset_ns": [-2000000, 2000000],
        "basis": "sha256:DECLARED_ALIGNMENT_B"
      }
    }
  ],
  "camera_bindings": [
    {
      "selection": "front",
      "camera": 1,
      "camera_generation": "sha256:ACTUAL_SOURCE_CAMERA_GENERATION_A",
      "calibration": "sha256:DECLARED_CALIBRATION_A",
      "image_domain": 1,
      "mapping_basis": "sha256:DECLARED_FRONT_TO_RIG_CAMERA_MAPPING",
      "image_domain_basis": "sha256:DECLARED_FRONT_UNDISTORTED_IMAGE_APPLICABILITY"
    },
    {
      "selection": "yard",
      "camera": 2,
      "camera_generation": "sha256:ACTUAL_SOURCE_CAMERA_GENERATION_B",
      "calibration": "sha256:DECLARED_CALIBRATION_B",
      "image_domain": 1,
      "mapping_basis": "sha256:DECLARED_YARD_TO_RIG_CAMERA_MAPPING",
      "image_domain_basis": "sha256:DECLARED_YARD_UNDISTORTED_IMAGE_APPLICABILITY"
    }
  ],
  "hypotheses": [
    {
      "id": "feature:selected-common-point",
      "association_evidence": "sha256:DECLARED_COMMON_FEATURE_HYPOTHESIS",
      "max_capture_span_ns": "100000000",
      "motion": {"kind": "static"},
      "observations": [
        {
          "selection": "front",
          "segment": 15,
          "detection_row": 0,
          "capsule_digest": "sha256:ACTUAL_CAPSULE_A",
          "pixel_min": [453.0, 239.5],
          "pixel_max": [453.5, 240.5],
          "visible_contact": true,
          "sigma_pixels": 0.5,
          "contact_basis": "sha256:DECLARED_FRONT_FEATURE_SELECTION"
        },
        {
          "selection": "yard",
          "segment": 14,
          "detection_row": 2,
          "capsule_digest": "sha256:ACTUAL_CAPSULE_B",
          "pixel_min": [186.5, 239.5],
          "pixel_max": [187.0, 240.5],
          "visible_contact": true,
          "sigma_pixels": 0.5,
          "contact_basis": "sha256:DECLARED_YARD_FEATURE_SELECTION"
        }
      ]
    }
  ]
}
```

### Source selection and camera binding

Each selection is the same strict source-selection shape used by `retained-handoffs`. It names
an existing report, exact label, bounded tracking recipe and actual native track. The source
owner rebuilds that analysis, verifies its root, source import, capsules, original encoded bytes
and current privacy binding, and retains every assigned observation in native display order.
Unmatched frames also pass through the owner because they affect tracking and confirmation.

Each selected track must map to exactly one rig camera and contribute to a hypothesis. The
camera generation must match the owner's actual sensor/stream/dimensions digest, and source
dimensions must equal the rig's image dimensions exactly. One actual sensor cannot count as
several cameras. Several tracks can share one rig camera only within the same exact source
import, sensor, stream, generation and declared calibration. A source mode change therefore
cannot silently reuse another track's image domain or segment-derived exposure aliases.

`calibration` is an explicit assumption handle tied to the selected rig camera; it must match
the corresponding selection. It is not a physical calibration certificate. `mapping_basis`
records why that retained source is assigned to the authored camera. `image_domain_basis`
records the assumption that source pixels already belong to the rig's undistorted pinhole
domain. This command performs no lens rectification. A raw distorted source needs an appropriate
upstream transform and matching domain; equal dimensions alone do not establish this.

### Common-feature selection

A feature selects an exact `(selection, segment, detection_row, capsule_digest)` from the native
tracker's actual assignments. It cannot inject a replacement source digest, sensor, capture
interval, detector score, model or detection rectangle. Its selected pixel rectangle must lie
inside the real clipped detector rectangle, represented by the source owner in 1/256 pixels.

The selected rectangle is an operator-declared common physical feature. The command does not
automatically triangulate a whole object box or call two box bottoms the same contact point.
`contact_basis` and `association_evidence` preserve those assumptions. The nominal solver uses
the selected rectangle's center; `sigma_pixels` separately declares independent isotropic pixel
noise. The rectangle itself is not converted into a Gaussian error estimate.

Query-local track aliases use sorted selection IDs and consecutive integers. Exposure aliases
are checked `segment + 1` values within one exact imported stream. The outer report retains the
alias recipe and every original track, source, capsule and invocation identity. No digest is
truncated into a durable integer ID.

### Time and motion

Original capture intervals remain signed 128-bit nanoseconds in source bindings, with their
original clock basis and capture-time label. Mapping uses checked interval addition:
`[capture_low + offset_low, capture_high + offset_high]`. It cannot narrow uncertainty or turn an
estimated clock into a disciplined clock. The geometry profile requires a representable
nonnegative aligned interval; negative or overflowing results refuse explicitly. Receive time
never substitutes for capture time.

The existing [scene-fusion motion modes and solver policies](SCENE_FUSION.md#motion-modes) apply:
`static`, explicitly supplied constant velocity through `linear`, and jointly fitted position
and velocity through `infer_linear`. All hypotheses share the requested reference time.
Inferred motion requires at least four exposures across at least two cameras and refuses
extrapolation. The full timestamp uncertainty remains available alongside the nominal fit.

## Output, bounds and failure behavior

The outer `schema` is `fss.scene_fusion_retained.v1`. Its `report_digest` hashes the exact UTF-8
JSON `report` member, excluding the wrapper and
terminal newline. The report contains the complete source projection, full authority anchor,
every source binding and observation, complete declaration document, local alias mapping, and
the unchanged native geometric result structure under `geometry`. The inner report has its own
digest and identifies its retained-source provenance. These report identities are not authority
ledger publications or a promise of permanent retrievability.

The owner reopens and revalidates the full projection after geometry and report construction.
Missing/deleted/corrupt source, privacy withdrawal, anchor drift or cancellation prevents output.
Geometric failures remain complete per-hypothesis results beside solved companions. Unsupported
geometry, unknown feature visibility, weak triangulation, conflicting correspondences and work
exhaustion do not produce fabricated positions.

| Boundary | Maximum |
| --- | --- |
| Twin file | 64 MiB |
| Rig / selection file | 1 MiB each |
| Native selected tracks | 32 |
| Report/label/tracker recipes | 4, with at most 64 frames each |
| Hypotheses / total selected features | 64 / 2,048 |
| Original source reads | One cumulative 4 GiB allowance, including revalidation |
| Geometry work | Default 100,000,000; configurable through 1,000,000,000 units |
| Elapsed deadline | Default 30 seconds; configurable through one hour |
| Complete report | 8 MiB including newline; can be lowered |

`--work-units`, `--timeout-ms` and `--max-report-bytes` set these caller ceilings. The same owner
cancellation/deadline probe is checked at every native geometry work charge and around bounded
source reads. Blocking filesystem calls retain their underlying owner boundaries; this is not
a hard real-time syscall-preemption guarantee. Exhaustion never truncates a source inventory.

`--report-out` exclusively creates a new private file with exactly the stdout bytes, including
newline. Existing files refuse before expensive analysis. A failed write may leave an explicit
incomplete new file; the error requires inspecting it before retrying. Exit `0` means all
hypotheses solved, `3` means a complete report includes geometric refusals, and `2` means the
complete request or output failed.

## Validation boundary

Fourteen exact-source native tests passed: eleven parser/adapter/geometry contracts and three
geometry cancellation contracts. These reconstruct a known point from three cameras, recover
position and velocity from six staggered observations, and check exact pins, detector bounds,
full clock uncertainty, source-to-camera consistency, visibility refusals and evidence identity.
The current-source Cargo geometry/fusion suites also passed all 201 tests, including the three
new cancellation contracts. Running the complete parser/rig/adapter harness passed all 23
tests, including its twelve existing JSON and camera-rig regressions.

Seven additional command tests use real JPEG ingest, first-party detector package execution and
retained tracking before removing loose source files and reopening custody. Fault cases cover
source damage, privacy withdrawal, mismatched source/image generations, exact observation pins,
cancellation, deadlines and complete-output limits. These command tests have not yet typechecked
or executed: two full build attempts were killed while compiling genuine pinned Asupersync, and
a serialized retry remains delayed by shared host memory pressure. The passing pure tests do not
execute deployment recovery, sealed source-owner
revalidation or command output. No runtime dependency or qualification gate was replaced.

```sh
cargo test --locked --offline -p fss-cli --bin fss-scene-fuse
cargo test --locked --offline -p fss-geometry --test work_budget_probe_contract
```

The passing pure fixtures establish source-to-geometry transformation and solver behavior. They do not
establish trained-detector accuracy, automatic feature matching, physical camera calibration,
live multi-camera synchronization or production qualification. Covariance remains conditional
on declared independent pixel noise and excludes pose, clock, feature-rectangle, correspondence,
motion-model, rolling-shutter, shared-mode and map errors.
