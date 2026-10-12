# Whole-recording two-camera corroboration

`fss-event corroborate --stream-corroborate` runs foreground detection and tracking over both
complete retained recordings, then associates their ground-zone entries. Each camera keeps its
own foreground model and tracker throughout its scan, so entries after the ordinary mode's
128-frame limit remain observable.

The native MJPEG, H.264 and H.265 paths process frames in display order. The two recordings can
have different lengths. Each complete recording must contain at most 65,536 retained segments;
an oversized input is refused. This operation starts from each recording's beginning and does
not restore an arbitrary codec or tracker snapshot.

## Analyze a pair of recordings

Both imports need explicit operator capture-time hints and distinct sensor identities. The
original input files are unnecessary once each import's retained custody is complete.

```sh
fss-event corroborate \
  --root /path/to/deployment --site site:home \
  --camera "east:${EAST_IMPORT:?supply the east import identity}" \
  --camera "west:${WEST_IMPORT:?supply the west import identity}" \
  --ground east:1,0,0,0,1,0,0,0,1 \
  --ground west:-1,0,96,0,1,0,0,0,1 \
  --zone door:56,0,40,48 \
  --interpretation gray \
  --time-gate-ns 10000000 --distance-gate 16 \
  --stream-corroborate \
  --report-out /path/to/review/door-corroboration.json
```

The example homographies describe a synthetic 96-pixel-wide mirrored camera pair. Supply the
actual owner-declared image-to-ground transforms, zone coordinates and association gates for
the selected recordings. A homography is an explicit geometric assumption, not a verified
camera calibration. For native H.264/H.265 and YCbCr JPEG inputs, use `--interpretation ycbcr`.

The mode supports the existing foreground thresholds, tracker settings, decoder limits,
`--tolerate-decode-refusals`, `--sensor-health conservative-v1`, failure-domain declarations,
digest-pinned trained detector packages, report export and exact event approvals. Optional
poses, exact site calibration, scene meshes and visibility settings add the conservative
geometry screen described below. `--retain-coverage` remains refused before deployment I/O:
this mode owns positive ground observations and their association, and produces no coverage
or absence witness.

## What supports an entry and an association

Each confirmed **actual matched** track sample supplies the bottom-centre foot point of its
filtered image box. The declared homography projects that point to ground coordinates. The
first eligible sample inside a ground zone becomes an entry for that tracker epoch, track and
zone. Tracking outside a ground zone continues, so a later ground-zone entry can be found.
Predicted positions during missed detections do not establish entries.

Source gaps and tolerated decode refusals reset the tracker epoch. Inter-coded decoding resumes
only at a supported random-access boundary. The report preserves exclusions and restarts;
tracks cannot bridge them. Index-derived times that become unreliable after a source gap do
not support association. Unknown capture time is refused, and capture hints remain labelled
operator assumptions.

Association applies the existing ground-distance gate and worst-case separation of the two
capture intervals before global assignment. A midpoint that looks close cannot admit a pair
whose uncertainty exceeds the time gate. A candidate remains an unclassified event with its
source and uncertainty attached; the first observation inside a zone does not establish the
exact physical crossing time.

Owner-declared common causes use the ordinary syntax:

```sh
--failure-domain network:home-lan=east,west
--failure-domain power:shared-ups=east,west
```

Connected cameras count as one effective supporting domain. Both positive observations are
retained, but their policy result remains witnessed activity with `Hold`. Disjoint declared
domains are not a measurement of physical independence, and undeclared dependencies remain
unknown.

## Check geometric support over the complete recordings

The owner-supplied `--ground` homographies remain required and still project the actual
observed foot points. Optional geometry checks support for every selected ground zone. It can
exclude a zone from association when the supplied camera/scene geometry cannot support it.
It never manufactures an observation or establishes physical camera position or currency.

To use an exact site calibration, add:

```sh
--calibration /path/to/site.fsscal \
--calibration-digest "${CALIBRATION_DIGEST:?supply the exact calibration digest}" \
--camera-generation east:1:1 \
--camera-generation west:1:1 \
--visibility-grid 8 \
--visibility-threshold-ppm 900000
```

Generation arguments are `CAMERA:INTRINSICS:EXTRINSICS`; substitute the exact generations.
The calibration must contain the selected named cameras, complete covariance partitions and
supported native pinhole models. Decoded image dimensions, exact camera parameter bits and
declared homographies must agree. Retained adoption records apply with exact camera-to-sensor
binding. Where no adoption exists, owner assertions remain labelled as such. A changed or newly
introduced adoption invalidates the previous analysis basis and requires fresh analysis/approval.

Alternatively, the ordinary `--pose` syntax supplies explicit per-camera poses labelled as
owner arguments, without a site-calibration covariance claim. Visibility options alone screen
the supplied homographies. With no geometry options, historical homography-only recipes,
reports and event identities retain their existing behavior.

An optional neutral scene package supplies occlusion geometry:

```sh
--scene-mesh /path/to/site.fsstwin \
--scene-mesh-digest "${SCENE_PACKAGE_DIGEST:?supply the exact scene package digest}" \
--scene-source-digest "${SOURCE_SCENE_DIGEST:?supply its source-scene digest}"
```

Both scene identities are checked. A supplied calibration must name the same scene coordinate
provenance. A mesh cannot establish visibility from an unknown camera origin; supply the
corresponding pose or calibration. Native screening checks frustum support, current privacy
masks and available mesh visibility. Calibrated cameras also run pose covariance perturbations
and the full camera covariance guard. Boundary ambiguity or excessive uncertainty withdraws
support instead of relying on the nominal pose alone.

Each camera reports `geometry_support`: exact geometry recipe and receipt digests,
pose/generation/adoption provenance, scene identities, per-zone support decisions, work and
full-camera guard counts. Actual entries remain in the observation inventory. Excluded entries
have disposition `geometry_support_unavailable` and cannot enter cross-camera association;
already unreliable capture-time dispositions remain explicit. Zero supported pairs does not
establish that the zone was empty.

A shared calibration or scene mesh automatically contributes a common cause to the existing
dependency model. An admitted pair using shared geometric authority follows the existing
witnessed-activity/`Hold` policy for shared domains. Geometry composes with trained class
evidence and conservative sensor-health screening without adding independent votes or
converting class scores into calibrated event probabilities.

The exact calibration archive is limited to 4 MiB and scene archive to 64 MiB. Visibility uses
2–32 samples per grid side and a threshold of 1–1,000,000 ppm. One 200-million-unit nominal/pose
work allowance covers all zones of each camera; a separate full-camera guard has a
64-million-unit allowance across all zones. Fixed native ceilings are bound into the immutable
recipe. Exhaustion refuses analysis instead of replenishing the budget for each zone.

Publication retains both exact archives beneath each camera root with the canonical geometry
configuration and computed receipts. Current adoption is checked before analysis, publication
and event commitment. Completed retries require the original retained archives and cannot
repair missing custody from loose files. Cold `read` restores retained geometry and recomputes
receipts under current privacy/adoption authority; explicit `verify` also reruns both original
media scans. Loose geometry files are unnecessary for retained-event operations. Large archives
may require larger explicit [cold metadata-read limits](long_event_replay.md).

## Add native trained class evidence

Add the ordinary detector options to the two-camera command:

```sh
--detector-package /path/to/verified-detector.fssmodel \
--detector-digest "${PACKAGE_DIGEST:?supply the exact package digest}" \
--detector-max-inferences 8 \
--detector-frames-per-track 2
```

The exact archive and detection-head contract are verified before either recording is opened.
The complete foreground/tracker scan finds the first actual confirmed match inside each ground
zone. A second native color pass selects that entry and bounded following actual matches from
the same camera, tracker epoch and local track. It uses the current privacy mask and supports
MJPEG, AVC and HEVC, including entries beyond frame 128. The placeholder image rectangle used
to configure the foreground walker has no role in selecting ground entries or model frames.

**One inference allowance and one detection-head work budget cover both recordings.** Admission
proceeds in camera order, then entry order and selected display position; repeated use of the
same camera/coding segment does not spend another inference slot. A selected frame consumes
its slot even if decoding, preprocessing, execution or the detection head refuses it. A first
camera that consumes the allowance leaves explicit `budget_exhausted` records for the second.
Inference executes in each native decoder's traversal order so inter-picture dependencies remain
valid; detection-head work follows that execution order. Neither allowance replenishes on entry,
frame, camera, gap or codec recovery.

The report includes whole-analysis and per-camera admission counters, native pipeline attempts,
completed model-plus-head results, consumed detection-head work and additional source/JPEG/pixel
work. An attempted pipeline is not a claim that model arithmetic completed. Source bytes, JPEG
work and pixel ceilings each span both passes of their camera; tracker assignment and the
foreground trace retain their first-pass bounds.

Each class annotation records the exact camera/import, epoch/local track, ground zone, entry
display position, selected display position, coding segment and source capsule. Both complete
camera closures retain all selected annotations, including entries that have no counterpart.
The selected pair's exact class-record lists are bound into its association identity and retained
provenance. They do not add policy evidence votes, calibrated probabilities, physical identities
or additional independent domains. Ground observations and declared common causes still decide
`Corroborated` versus `Witnessed`/`Hold`; the same model used twice is not a second independent
verifier. Scores remain uncalibrated, event kind remains unclassified and probability remains
`[0,1]`.

## Privacy, health and whole-scan budgets

Current per-sensor privacy masks apply before perception. Masked ground zones cannot support
entries. Each camera's exact privacy generation is included in the analysis identity and
rechecked before publication, together with its retained sources and analyzed capsules.

Optional conservative sensor-health screening evaluates both complete camera scans. A suspect
or incomplete screen blocks publication while keeping the diagnostic result available. A clear
screen does not establish camera health or detection quality.

The four aggregate limits apply **separately to each camera's entire scan**:

| Option | Default per camera | Scope |
|---|---:|---|
| `--stream-read-bytes` | 536,870,912 | Decoder source reads, including configuration and recovery probes |
| `--stream-pixel-budget` | 1,073,741,824 | Foreground luma and, when selected, native RGB-pass pixel work |
| `--stream-assignment-work` | 1,073,741,824 | In-camera tracker assignment work |
| `--stream-trace-bytes` | 8,388,608 | Complete bounded scan identity and geometry trace |

Reservations do not refill at frame, chunk or recovery boundaries. The total two-camera
reservation is twice the chosen per-camera ceiling; cross-camera association has its own bounded
work allowance. Metadata, source revalidation and publication retain their separate owner
bounds. This is not an accounting claim for all operating-system I/O or memory.

Exhaustion refuses the analysis before event publication. All aggregate limits participate in
the new mode's identity, even when changing a limit does not change the observed entries.

## Review, publish and restart

Without `--approve`, the complete `fss.long_corroboration_report.v1` projection is read-only.
Review each candidate's proposal and rerun its exact `publish_command`. A comma-separated
`--approve sha256:PROPOSAL[,sha256:PROPOSAL...]` publishes only the matching candidates.

The complete report is bounded before publication. A new analysis or privacy binding requires
a new approval; ordinary short-recording corroboration approvals cannot authorize this mode.
Publication revalidates both cameras, retains the provenance graph root-last, and uses the
existing guarded event publisher. Exact completed retries do not append another event. Cold
retry recomputes from retained source, and damaged or deleted custody is refused.

Each published camera analysis also retains the complete owner recipe under the reported
`plan_digest`: both imports and homographies, ground zones, perception thresholds, all codec
and scan limits, recovery mode, common-cause declarations, decoder identities and health
policy. The recipe is bounded to 128 KiB and belongs to the event's source closure. The typed
`LongCorroborationRecipe::from_retained_bytes` API verifies an independently pinned digest and
recovers those exact inputs; `analyze` reruns them against current retained source and privacy
authority. Unknown semantics, changed bytes or trailing data are refused. A remembered command
is therefore unnecessary to recover the published computation's owner settings. Replaying a
recipe does not authorize event publication, and an exact publication retry refuses damaged
recipe custody even when an earlier event already exists.

Detector-enabled recipes add an explicit ground-selection/global-budget policy and the complete
model execution component. Publication retains the exact package archive, component recipe,
both bounded outcomes and all class records beneath the camera roots. The camera analyses bind
cumulative admission/head-work counters before and after each camera. Missing or damaged model
custody refuses even an otherwise completed publication retry. Model-free recipes and their
publication identities retain their original bytes.

The policy can report an alert-preparation affordance for an admitted corroborated event.
Preparing or dispatching an alert remains its own separately approved operation. An empty
result has no absence-certification meaning, and this mode publishes no coverage witness.

Focused native regression targets:

```sh
cargo test -p fss-cli --test corroborate_stream_cli
cargo test -p fss-cli --test corroborate_stream_geometry_cli
cargo test -p fss-cli --test corroborate_stream_detector_cli
cargo test -p fss-reference --test long_corroboration_contract
```

Synthetic fixtures exercise the pipeline and evidence contracts. They do not qualify live
camera throughput, deployment detection accuracy, a continuous service, or a release.

## Read and verify a published event

Use `fss-event read --root DIR --site SITE --event-id ID` to inspect an original published
whole-recording candidate after restart. The response explicitly distinguishes inspection from
native replay and supplies exact revision/provenance pins and a verification command.
`fss-event verify` reruns the retained computation and compares the complete analysis and event.
See [cold event recovery](long_event_replay.md) for recipe scope, bounds and validation status.
