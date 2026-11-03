# Joint scene reconstruction from retained camera views

`fss-scene-fuse retained-multimatch` automatically associates native image
features across **three through eight retained camera frames**, then fits joint
stationary points in the imported property twin. It consumes authenticated JPEG,
AVC/H.264 or HEVC/H.265 sources directly. No exported image, supplied feature
coordinates or detector model is required.

```sh
fss-scene-fuse retained-multimatch \
  --root deployment --site site:example \
  --twin property.fsstwin --rig cameras.json --query retained-cameras.json \
  --report-out reconstructed.json
```

The command preserves every camera-pair decision and every connected feature
component. A joint point uses all cameras participating in its component.
Inconsistent cycles, incomplete chains and failed geometry remain explicit;
the command does not prune conflicting evidence to make a point appear solved.
The report is derived cognition and does not activate calibration, physical
identity, world revisions, events or effects.

The original v1 query below selects native pinhole images. The same command also
accepts [v2 image declarations](RETAINED_LENS_MATCHING.md) for mixed direct and
corrected views, including native Brown–Conrady/fisheye correction and explicit
pinhole crop/resize. Original source and corrected feature grids remain distinct.

## Select the source frames

Use the source-selection procedure and `fss-file decode` output documented in
[retained two-camera matching](RETAINED_SCENE_MATCHING.md). Each view has the
same strict `camera`, `image_domain_digest`, `mapping_basis`, `sigma_pixels`,
`source` and `alignment` fields. Source import, coding segment, capsule, encoded
bytes, sensor, stream and original clock pins are checked before decoding any
selected frame. Native source owners authenticate the actual retained bytes.

The camera rig must already contain all selected camera entries and pin the
exact twin. Its common clock and privacy namespace must agree with the query.
Source pixels must belong to each declared undistorted pinhole camera mode.
Camera placement, source-to-rig mapping, image-domain applicability, additive
clock alignment and a stationary scene over the full capture hull remain
explicit operator declarations.

The new schema is
`schemas/scene_feature_multimatch_retained_query.v1.json`. It replaces the pair
query's `left` and `right` with a `views` array of 3–8 complete view objects.
All common policy fields retain their two-camera meanings. For example, after
adding the third camera to `cameras.json` and writing its exact view selection
to `third-view.json`, an existing pair query can be extended with:

```python
import hashlib
import json
from pathlib import Path

query = json.loads(Path("retained-pair.json").read_text())
query["schema"] = "fss.scene_feature_multimatch_retained_query.v1"
query["camera_rig_digest"] = "sha256:" + hashlib.sha256(
    Path("cameras.json").read_bytes()
).hexdigest()
query["views"] = [
    query.pop("left"),
    query.pop("right"),
    json.loads(Path("third-view.json").read_text()),
]
query["extraction"]["maximum_features"] = 64
Path("retained-cameras.json").write_text(json.dumps(query, indent=2) + "\n")
```

The requested reference time and capture-span policy must admit the complete
new source set. Recompute `--expected-input` if used. Every logical camera,
retained sensor ID, encoded-source digest and exposure must be distinct across
the entire selection, including nonadjacent views. Distinct retained labels
alone do not certify independently measured physical cameras.

The native owner supplies dimensions, pixels, original capture intervals,
exposure identity and current deployment privacy. The query cannot override
those facts. Every full 33×33 descriptor footprint must be allowed by the
current privacy mask. An empty or fully masked view still participates in all
source, camera, clock, validity and privacy checks.

AVC/HEVC selections consume a complete admitted IDR/IRAP-starting range of at
most 64 coding segments containing the selected segment. Later malformed input
or an unavailable selected picture refuses the request. The source codecs can
be mixed when their admitted image and descriptor domains agree.

## From pair evidence to joint points

All unordered camera pairs run the existing symmetric appearance and nominal
epipolar matcher. Three cameras produce three pair reports; eight produce 28.
Each report contains every Cartesian feature pair, nearest-descriptor ties,
appearance/epipolar dispositions, selected hypotheses and two-camera geometric
estimates or refusals. No descriptor pair disappears because a later point fits.

Selected appearance correspondences that pass the epipolar gate connect a
scene-wide feature graph. A pair's failed 3D solve does not erase an otherwise
supported edge: a third, well-separated view can resolve weak two-camera depth.
The original weak-pair refusal remains in its camera-pair report.

Every connected component has one explicit outcome:

| Outcome | Meaning |
|---|---|
| `unmatched` | One isolated feature has no selected link. All pair diagnostics remain available. |
| `camera_conflict` | A connected cycle includes multiple features from the same camera. All members and links are retained; no identity is chosen. |
| `incomplete_cycle_support` | Members have distinct cameras, but one or more direct pair links are not selected. Exact missing pair/decision references explain why transitive association is insufficient. |
| `estimated` | Every pair of members has direct support, and one native static point fits all participating cameras under the declared geometry policy. |
| `refused` | Complete correspondence support exists, but the joint native geometry solver refuses. The reason and original pair solutions remain visible. |

The optional `triangulation` policy retains `min_views: 2` and `max_outliers: 0`
for individual pair matching. Each joint solve internally requires **all** of
its component's cameras and still removes no outliers. A component may contain
only two cameras even when the full selection contains more; its exact members
and contributing point views are reported. Additional unrelated or unmatched
cameras do not become evidence for that point.

Point coordinates remain in the twin's source-world units with the original
scale declaration. Covariance is conditional on fixed cameras and independent
pixel noise. It excludes correspondence, camera, map, clock and motion error.
Residuals, conditioning, ray angles and nominal mesh occlusion contradictions
remain visible; nominal occlusion does not authorize silently dropping a view.

## Full intervals and explicit subset times

Each original source interval is aligned by the checked additive interval
declared for that source. The command preserves the full resulting intervals,
camera validity and the full scene hull. The scene hull must be no longer than
one second and contain `reference_time_ns`. No midpoint replaces uncertainty.

A subset can have a narrower hull that excludes the requested scene time.
Under the explicit assumption that the features are stationary over the
**entire** scene hull, each pair/component uses:

```text
solve_time = clamp(requested_scene_time, subset_earliest, subset_latest)
```

Both times and the full subset hull appear in the report and evidence identity.
For cameras captured over `[100,110]`, `[120,130]` and `[200,210]` with requested
time `205`, the first pair solves at `130`, while a three-view component solves
at `205`. The first pair is not presented as an observation at time `205`.
This policy estimates neither clock synchronization nor object velocity.

## Report, source revalidation and exit status

The envelope schema is `fss.scene_feature_multimatch_retained.v1`; its digest
covers the exact UTF-8 bytes of the `fss.scene_feature_multimatch_retained_report.v1`
body. `report.analysis.views` contains each complete source capsule, native
receipt, selected features and camera snapshot once. `analysis.geometry` carries
all camera pairs and components, with indices linking each selected or missing
component edge to its original pair decision. Input permutation does not change
the canonical native geometry inventory.

The analysis also retains the exact query, twin/rig identities, full assumptions
and entry/final authority anchors. Ordinary JPEG decode publication can advance
the anchor and may complete before a later refusal. Valid subsequent JPEG
publications do not invalidate earlier selected sources. `--expected-anchor`
checks the entry anchor; it does not pretend decoding leaves the ledger unchanged.

After complete source-dependent report construction, every sealed owner
revalidates its original source range and current privacy. JPEG also reopens
its exact retained pixels and receipt without repairing damaged custody.
Missing or changed source, deletion, changed privacy, authority mismatch,
cancellation or resource exhaustion prevents release of the entire report.
Final costs include these checks. Only wrapping immutable analysis with its
costs and digest follows revalidation.

`--report-out` exclusively creates a new private file with exactly the stdout
bytes. Existing files and symlinks refuse. A write failure may leave a partial
new output file; it does not authorize overwriting an existing file.

| Exit | Meaning |
|---|---|
| `0` | At least one estimated component and no camera-conflict, incomplete-cycle or refused components. |
| `3` | No estimated component, or at least one unresolved/refused component; the complete diagnostic report is still emitted. |
| `2` | Input, custody, privacy, authority, resource or I/O failure. No partial successful analysis is emitted. |

Unmatched singleton features remain diagnostics and do not alone force exit 3.
A pair refusal resolved by a successful joint estimate remains visible without
making that joint result fail. Counts distinguish pair estimates/refusals from
component estimates/refusals.

## Bounded work

| Resource | Bound |
|---|---|
| Selected cameras | 3–8 |
| Selected features | At most 128 per view and **256 actual features total** |
| Complete Cartesian pair rows | At most 28,672 across all camera pairs |
| Pair-specific feature outcomes | At most 1,792, including all nearest ties |
| Pair hypotheses / selected links | At most 896 |
| Geometry, masks, extraction and complete report work | Default 8 billion units; configurable up to 16 billion |
| Original source reads, including provenance and final checks | Shared 4 GiB |
| JPEG decoder work | Shared 2 billion units |
| Video encoded-byte admission | Shared 512 MiB |
| Video coded-luma capacity admission | Shared 2,147,483,648 units |
| Decoded image | At most 4,096 per axis and 4,194,304 pixels |
| Complete report, including newline | At most 32 MiB |

`maximum_features` is a per-view extraction cap. With eight cameras, requesting
32 per view guarantees the aggregate selected inventory cannot exceed 256.
A larger per-view request is valid if actual selected counts fit; exceeding the
aggregate refuses before pair expansion, without trimming already selected
features. The 8-billion geometry allowance admits full native FAST extraction
grids over eight 1080p images in its work model; decoder bounds and timeout still
apply independently. This is an allowance statement, not a throughput claim.

Each cumulative allowance covers the whole command and never resets per source.
Video luma capacity is an admission bound that includes buffered, skipped and
failed work, not measured decoded output or CPU time. Source images are decoded
sequentially; only immutable selected features and owner bindings persist
between views. Report work charges all repeated pair outcomes and all joint
diagnostics before serialization. Output is complete or refused at its byte cap.

Default timeout is 30 seconds, configurable up to one hour. Source reads, native
decode and geometry preserve their existing cancellation/checkpoint boundaries.
CPU time, energy and peak memory remain explicitly unmeasured. Field matching
quality, automatic camera calibration, moving-object identity and production
qualification are separate remaining work.
