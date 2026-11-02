# Reconstruct retained scenes with adopted camera geometry

`fss-scene-fuse retained-calibrated-match` connects the existing site-calibration
and adoption workflow to automatic native scene reconstruction. It consumes
the exact currently adopted intrinsics and poses for stereo points, joint
multi-camera points, or moving-feature trajectories. Original camera sources,
current privacy and calibration adoption remain separately authenticated.

For static pair or multi-camera results, the companion
[`retained-calibrated-atlas`](ADOPTED_RECONSTRUCTION_ATLAS.md) command exports
selected points and their actual reference descriptors as a portable atlas for
the existing `fss-file localize` camera-registration workflow.

## Run an analysis

Start with the canonical calibration produced by `fss-event calibrate` and
the selected cameras' retained `fss-event calibration adopt` receipts. Keep
each original observation text or frame metadata file. The
[recorded event workflow](RECORDED_EVENT_WORKFLOW.md) describes calibration
production, adoption, inspection and invalidation.

```sh
fss-scene-fuse retained-calibrated-match \
  --root deployment --site site:example \
  --twin property.fsstwin --rig adopted-cameras.json \
  --query retained-query.json --report-out calibrated-scene.json \
  --work-units 16000000000 --timeout-ms 300000
```

The command reuses these exact query contracts:

| Query schema | Reconstruction | Selected sources |
|---|---|---|
| `fss.scene_feature_match_retained_query.v1` or `.v2` | Static stereo points | Two cameras, one exposure each |
| `fss.scene_feature_multimatch_retained_query.v1` or `.v2` | Joint static points | Three through eight cameras, one exposure each |
| `fss.scene_feature_motion_match_retained_query.v1` | Common-time position and constant velocity | Four through sixteen exposures from two through eight fixed cameras |

See [retained stereo matching](RETAINED_SCENE_MATCHING.md),
[multi-camera matching](RETAINED_MULTICAMERA_MATCHING.md) and
[moving-feature matching](RETAINED_TEMPORAL_MATCHING.md) for complete source,
clock, privacy, correspondence and numerical-policy fields. Set the query's
`camera_rig_digest` to SHA-256 of the exact adopted rig JSON bytes. Every camera
listed in that rig must participate in the query.

Optional `--expected-input` pins the query bytes; `--expected-anchor` pins the
entry deployment authority. `--principal` selects the replay principal. A
report goes to stdout and, if requested, an identical private create-only file.

## Declare the adopted rig

The strict input schema is `fss.scene_camera_rig_adopted.v1`. This structural
example has two cameras; replace every uppercase digest placeholder with the
exact nonzero 64-digit lowercase SHA-256 value from your artifacts or receipts.

```json
{
  "schema": "fss.scene_camera_rig_adopted.v1",
  "source_scene_digest": "sha256:SOURCE_SCENE_HEX",
  "twin_digest": "sha256:TWIN_PACKAGE_HEX",
  "geometry_basis": {"property": "1", "revision": "1"},
  "coordinate_frame": "RH_Z_UP",
  "evaluation_scope": "YOUR_EXACT_IMPORTED_TWIN_SCOPE",
  "calibration": {
    "path": "site.calibration",
    "digest": "sha256:FSSCAL_SEMANTIC_IDENTITY_HEX",
    "file_digest": "sha256:COMPLETE_CALIBRATION_FILE_HEX"
  },
  "cameras": [
    {
      "camera": "1",
      "sensor_id": "sensor:left",
      "adoption_digest": "sha256:LEFT_ADOPTION_RECEIPT_HEX",
      "original_input": {
        "path": "left.observations",
        "digest": "sha256:LEFT_ORIGINAL_INPUT_FILE_HEX"
      },
      "source_object_id": "left-camera",
      "image_domain": "1",
      "clock": "1",
      "privacy_domain": "1",
      "validity_ns": ["0", "18446744073709551615"]
    },
    {
      "camera": "2",
      "sensor_id": "sensor:right",
      "adoption_digest": "sha256:RIGHT_ADOPTION_RECEIPT_HEX",
      "original_input": {
        "path": "right.observations",
        "digest": "sha256:RIGHT_ORIGINAL_INPUT_FILE_HEX"
      },
      "source_object_id": "right-camera",
      "image_domain": "1",
      "clock": "1",
      "privacy_domain": "1",
      "validity_ns": ["0", "18446744073709551615"]
    }
  ]
}
```

The calibration's `digest` is its domain-separated FSSCAL identity, also used
by adoption. It is **different from** `file_digest`, the SHA-256 of the complete
file. Original inputs have their own whole-file SHA-256 pins. Relative paths
resolve against the rig document's directory; absolute paths are accepted.
Every file must satisfy the command's bounded regular-file checks.

Camera handles, sensor IDs and source-object labels must be unique. Numeric
handles are nonzero; time bounds are ordered and inclusive. The parser accepts
canonical unsigned integer tokens or decimal strings and rejects unknown or
duplicate fields. The complete calibration and original inputs use the native
SHA-256 provenance profile.

There are no pose, intrinsics, generation, status or error overrides in the
rig. Those values come from the verified calibration and retained adoption.
The source-object mapping, local image/clock/privacy handles and requested use
interval remain explicit owner declarations. An adoption does not measure clock
alignment, establish an expiry or prove that the physical camera has not moved.

## Image compatibility and current authority

This first profile requires images already in the **exact original calibrated
pinhole domain**. FSSCAL01 correspondence inputs and FSSCAL02 frame inputs are
supported. The command verifies original input bytes, image-domain identity,
actual decoded dimensions and, where recorded, JPEG component interpretation.
Nonzero radial distortion and v2 rectification declarations refuse explicitly.
Matching dimensions alone do not establish compatible crop or lens geometry.

Each selected retained source must name the physical sensor bound by the
current adoption. The receipt must agree on calibration identity, camera
handle/name, twin package and both intrinsics and extrinsics generations.
Missing, superseded, withdrawn or corrupt adoption custody refuses the analysis.
Another camera handle cannot alias the same adopted physical sensor.

The command first checks source capsule pins, then resolves calibration and
image declarations before decoding. All source-dependent association and
report analysis is serialized before final original-source/current-privacy and
calibration-adoption/withdrawal revalidation. The deployment's exclusive owner
guard remains held through file and stdout publication. The report preserves
both entry and final anchors; ordinary retained JPEG derivative publication can
advance the latter. A later withdrawal requires a new analysis.

## Interpret the report

The outer schema is `fss.scene_feature_match_adopted.v1`. `report_digest` hashes
the exact compact UTF-8 `report` object bytes. Parsing and reserializing may
change those bytes. `report.analysis` includes:

- The exact query, rig, semantic rig, imported twin and source-scene identities,
  property basis, scale, requested scene time, capture hull and authority anchors.
- The original query and adopted-rig declarations, complete source views and
  native decode/feature/privacy provenance. Repeated camera observations map to
  their exact original exposure.
- The complete calibration provenance: FSSCAL identities, atlas/control/tie
  policy, original image bases, every joint camera generation, selected current
  adoption receipts, refined geometry, solve diagnostics and local covariance.
- The complete native correspondence diagnostics, all alternatives and refusals,
  fitted points or trajectories, per-observation residuals and nominal visibility.

`analysis.geometry` wraps the established native diagnostics with one consistent
`kind`, `outcome`, scene time, capture hull and count policy. Its
`native_diagnostics` retains the native pair, multi-camera or temporal format.
The outer counts and outcome determine the new command's exit status.

`solved` counts numerical fits even when visibility conflicts remain.
`unresolved` counts nontrivial unresolved/refused components **including** fitted
components with nominal occlusion conflicts; `nominal_occlusion_conflicts` is
that latter subset. Isolated unmatched features remain visible diagnostics.
No alternatives are discarded to improve the outcome or shrink the report.

Camera status is `adopted_current`, which states retained owner authority.
Absolute camera error stays `unknown`. Calibration covariance remains a
conditional camera marginal in its original parameter order, without
cross-camera blocks. Reconstruction covariance remains conditional on pixel
noise and the supplied model; calibration covariance is not silently folded
into it or promoted into a conservative projection bound. Camera movement,
map/clock error, correspondence error and physical accuracy still require their
own evidence. Results remain derived cognition and establish no physical identity.

## Bounds, costs and failures

| Resource | Ceiling |
|---|---:|
| Rig cameras / selected query cameras | 16 / 8 |
| Original selected exposures | 16 |
| Features per exposure / total actual selected features | 128 / 256 |
| Calibration / each original input / complete inputs | 4 MiB / 1 MiB / 20 MiB |
| Authority batches / deltas traversed | 65,536 each |
| Cumulative authority-read reservations, including revalidation | 64 MiB |
| Cumulative original source reads, including revalidation | 4 GiB |
| Geometry, extraction and report work | 8 billion default; 16 billion maximum |
| JPEG decoder work | 2 billion |
| Video encoded bytes / coded-luma admission units | 512 MiB / 2,147,483,648 |
| Complete report, including newline | 32 MiB |
| Timeout | 30,000 ms default; 3,600,000 ms maximum |

The query keeps its narrower mode-specific limits. The cost object separately
reports geometry work, original reads, calibration input bytes, reserved and
verified authority bytes, JPEG work and video admission. Final revalidation is
included. CPU time, energy and peak memory are explicitly unmeasured.

Exit **0** means at least one fit and no nontrivial unresolved, refused or
nominally occluded component. Exit **3** preserves a complete analysis with no
fit or remaining unresolved components. Exit **2** covers input, custody,
privacy, calibration currency, cancellation, resource and publication failures.

No analysis failure creates a successful report. Native JPEG decode may retain
its ordinary derivative receipt before a later refusal. Output files are
private on Unix (`0600`), create-only and synchronized before stdout. Publication
failure may leave a newly created partial or complete file for inspection;
existing outputs are never overwritten. This command publishes no calibration,
world revision, persistent track, event or external effect.

For the native sealed-owner interface, see
[retained calibration API](RETAINED_SCENE_CALIBRATION_API.md).
