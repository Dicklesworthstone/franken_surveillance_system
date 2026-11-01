# Reconstruct moving features from retained camera exposures

`fss-scene-fuse retained-motion-match` automatically associates native image
features across repeated retained exposures and estimates 3D position and
constant velocity in the exact imported property twin. It supports JPEG, AVC
and HEVC source owners and the existing native pinhole, Brown-Conrady and fisheye
image paths.

This command fills the gap between static `retained-match`/`retained-multimatch`
and `retained-fuse` with manually supplied moving-feature correspondences.
It is a bounded derived scene analysis. It does not activate a calibration,
merge persistent tracks, identify a person or create localization landmarks.

## Run the command

```sh
fss-scene-fuse retained-motion-match \
  --root deployment --site site:example \
  --twin property.fsstwin --rig cameras.json \
  --query moving-features.json \
  --report-out moving-scene.json \
  --work-units 16000000000 --timeout-ms 300000
```

The root, twin and rig inputs use the existing
[retained scene matching](RETAINED_SCENE_MATCHING.md) contracts. Optional
`--expected-input` and `--expected-anchor` pins constrain the exact query bytes
and entry deployment anchor. `--principal` declares the current replay principal.
The report is written to stdout and, when requested, to a private create-only
file. Existing files and symlinks refuse before source decoding.

## Select repeated exposures

The exact query schema is `fss.scene_feature_motion_match_retained_query.v1`.
It has these top-level fields:

| Field | Meaning |
|---|---|
| `camera_rig_digest` | SHA-256 of the exact rig document bytes. |
| `privacy_domain`, `clock`, `clock_evidence` | Shared owner-resolved privacy and capture-clock declarations. |
| `association_basis` | Nonzero digest of evidence or an explicit assumption supporting the conditional common-feature/motion analysis. |
| `reference_time_ns` | One global scene time at which every successful trajectory reports position. |
| `max_capture_span_ns` | Maximum **full** earliest/latest capture hull, from 1 through 60,000,000,000 ns. |
| `max_capture_uncertainty_ns` | Maximum width of any capture interval, no larger than the hull allowance; zero admits exact timestamps only. |
| `motion` | Exactly `constant_velocity_during_capture_hull`. |
| `views` | Four through sixteen exact retained exposure selections from two through eight logical cameras. |
| `extraction` | Existing native FAST/BRIEF threshold, maximum feature count and separation. |
| `matching` | Absolute Hamming distance and strict mutual best/runner-up ratio. |
| `triangulation` | Optional native motion-fit limits. |

The query accepts canonical unsigned integer tokens or decimal strings for its
integer fields. It rejects duplicate/unknown fields, nonfinite numbers, missing
pins and unsupported options. Solver numerical limits are checked before native
source decoding.

Each `views` item uses the **existing v2 image declaration** documented in
[retained lens matching](RETAINED_LENS_MATCHING.md), even though this new query
schema is version 1. A direct image declaration is:

```json
{
  "kind": "pinhole",
  "image_domain_digest": "sha256:EXACT_DECLARED_PINHOLE_DOMAIN_HEX"
}
```

Replace the digest placeholder with the full nonzero SHA-256 value. A rectified
image declaration retains its source intrinsics, lens family/coefficients,
radius, luma range, source-domain and lens-basis pins. Target intrinsics come
from the exact rig. All image plans are admitted before decoding any source.

The rest of a view retains the existing `camera`, `mapping_basis`, `sigma_pixels`,
`source` and `alignment` fields. The source pins the import, segment, original
capsule, encoded bytes and sensor. AVC/HEVC selections also pin the complete
bounded decode range. The owner supplies capture intervals, dimensions, pixels,
features and current privacy masks; those facts cannot be inserted into the query.

Repeated views of a camera must keep its sensor, stream, source-clock basis,
additive clock-alignment interval/basis, image model and mapping declaration.
Different retained imports of that stream may participate. A physical sensor
cannot be relabeled as two logical cameras. Duplicate capsule, import/segment
or actual original-exposure identities refuse. Per-exposure pixel-noise
estimates may differ; repeated cameras still share their calibration uncertainty.

For example, two cameras with observations at two or three different capture
times can supply enough constraints. Capture times need not coincide across
cameras. All sources must share the declared common-clock mapping, and the
whole selected inventory must fit the timing and feature allowances.

### Matching and solver policy

```json
{
  "matching": {
    "maximum_hamming_distance": 32,
    "ratio_percent": 80
  },
  "triangulation": {
    "max_reprojection_pixels": 3.0,
    "max_distance": 1000.0,
    "max_speed": 20.0,
    "max_condition_number": 10000000000.0,
    "max_iterations": 16
  }
}
```

This is a policy fragment, not a complete query. Distance and speed use the
twin's source units and source units per second. They are not automatically
metres. The optional solver fields default to the values shown.

All descriptors in the opposing exposure compete before a match is selected.
The ratio must pass strictly in both directions, with a distinct runner-up;
ties and missing runner-up support remain ambiguous. The command does not apply
a stationary epipolar gate to observations of a moving point at different times.

Each candidate component needs one feature per exposure, complete direct pair
support, at least four observations and at least two cameras. The native solver
fits position and velocity together using every observation's own nominal time.
An observation is not discarded to make a trajectory pass. A component that
cannot bracket `reference_time_ns` refuses; the command does not clamp its time
or extrapolate it into a common display timestamp.

## Read the complete moving scene

The outer report schema is `fss.scene_feature_motion_match_retained.v1`.
`report.analysis` contains entry/final anchors, query declarations, exact twin
and rig identities, scale/map-error declarations, complete source views and
the native geometry graph. `report.cost` contains final geometry work, shared
source reads including revalidation, and the separate JPEG/video decoder axes.

Source rows under `report.analysis.views` contain:

- `index`: the zero-based canonical view index, ordered by camera, capture interval
  and original exposure digest;
- `exposure`: the query-local solver handle `index + 1`;
- `view`: the complete source/decoder/feature/clock/image-processing record.

Repeated cameras are matched back to their **exact original exposure**, not to
the first record with the same camera ID. Original raw image and corrected
feature-image identities remain separate. Original exposure identity survives
rectification.

`report.analysis.geometry` contains every exposure pair's Cartesian descriptor
table and per-feature nearest alternatives, every selected-link component,
original full capture hull and the unchanged requested scene time. Component
outcomes explicitly distinguish unmatched features, conflicting exposure cycles,
incomplete pair support, insufficient observations/cameras, fitted trajectories
and native refusals. See the [native API contract](TEMPORAL_FEATURE_ASSOCIATION.md).

A fitted trajectory reports position, velocity, all 36 entries of its conditional
6x6 pixel-noise covariance, residuals for every original observation and nominal
mesh visibility at each exposure's time. A visibility conflict remains in the
report and prevents an unqualified success exit. The covariance does not include
camera, map, clock, correspondence, lens, interpolation, rolling-shutter or
acceleration errors. Source declarations do not establish calibrated field accuracy.

The outer `report_digest` hashes the exact compact UTF-8 report-body bytes.
Parsing and reserializing can change those bytes. Native scene, pair, component
and observation digests independently preserve their canonical input identities.
Permuting the same exposures leaves native geometry identities unchanged; the
original query-byte hash still records that the query document changed.

## Privacy, publication and limits

All source-dependent geometry and report analysis is serialized before every
sealed source owner revalidates its original retained range and current privacy
policy. A previously published decoded derivative does not substitute for lost
or corrupt original custody. Source or privacy failure produces no successful
report. Native JPEG processing may publish its ordinary retained derivative;
analysis is not a transaction that rolls back that existing owner behavior.

Output files are private on Unix (`0600`) and create-only. File synchronization
precedes stdout. Publication failure can leave a new partial or complete file;
inspect that path and use a fresh output name after resolving the failure.
Cancellation/deadline checks also run after report construction and after file
publication, before success output. No existing output is overwritten.

| Resource | Ceiling |
|---|---:|
| Original exposures / logical cameras | 16 / 8 |
| Selected features per exposure / total actual features | 128 / 256 |
| Complete descriptor rows / exposure pairs | 30,720 / 120 |
| Capture hull | 60 seconds |
| Video coding segments per selected range | 64 |
| Shared original source reads, including final revalidation | 4 GiB |
| Geometry/extraction/report work | 8 billion default; 16 billion maximum |
| JPEG decoder work | 2 billion |
| Video encoded bytes / coded-luma admission units | 512 MiB / 2,147,483,648 |
| Complete report, including newline | 32 MiB |
| Timeout | 30,000 ms default; 3,600,000 ms maximum |

These are admission ceilings, not throughput promises. In particular, sixteen
full-resolution exposures may exceed the geometry allowance. Lower
`--max-report-bytes` is allowed, but no feature, pair, source or alternative is
silently dropped to fit it.

Exit **0** means at least one motion reconstruction and no nontrivial unresolved,
refused or nominally occluded component. Exit **3** preserves the complete report
when there is no motion reconstruction or some components remain unresolved.
Isolated unmatched features remain diagnostics. Exit **2** covers invalid input,
authority, source/privacy, resource/cancellation and publication failure.
