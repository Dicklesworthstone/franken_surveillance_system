# Recorded analysis to durable unresolved event candidates

`fss-event` connects retained inference and local association to the existing event owner.
It builds complete replayable analysis reports, prepares an exact candidate, publishes only
that approved candidate, and reopens the event and its provenance after a process restart.
The only trained model is the verified YOLOX-Nano package (`models/yolox-nano`), reachable
through the watch/corroborate detection cascade and through retained package reports (the last
two sections); its scores are uncalibrated. No calibrated detection quality, physical identity,
threat classification, notification transport, or effect authority is introduced. Coverage
witnesses exist only for `watch` and `corroborate`, and only when retained with their exact
approval (see the coverage section).

## Build the complete report

First import the recording and run an explicitly supplied model with the existing `fss-file`
and `fss-infer` workflows. Create a UTF-8 run list with one `SEGMENT SHA256_RUN_ID` pair per
line in strictly increasing segment order. Blank rows, extra fields, duplicate/reversed
segments, non-SHA256 identities, more than 64 rows, and files over 64 KiB are refused.
A skipped segment remains an explicit association reset; it does not establish continuity.

```sh
cargo run -p fss-cli --bin fss-event -- report \
  --root ./camera-evidence --site site:home \
  --import-id sha256:IMPORT_DIGEST --runs ./runs.txt --interpretation ycbcr \
  --model-digest sha256:MODEL_DIGEST --output-port detections \
  --labels vehicle,animal --box-format xyxy --coordinates normalized \
  --report-out ./analysis.bin
```

Replace digest placeholders with the exact recorded identities. Labels and coordinate
conventions must match the model's explicit output contract, not a guess based on tensor
positions. `gray` selects grayscale JPEG and `ycbcr` JPEG YCbCr. This command revalidates
retained runs, performs detector postprocessing and association, and writes the existing
canonical `AnalysisReport` format. It does not execute graph operators or append event authority.
It prints the report digest and observed local track IDs that can be selected for investigation.

Detector defaults are minimum score 500000 ppm, NMS IoU 500000 ppm, 4096 rows and 128 survivors.
Tracker defaults are minimum IoU 100000 ppm, confirmation after 2 consecutive hits, maximum 1
missed processed frame, and 128 tracks. Override the corresponding `--minimum-score-ppm`,
`--nms-iou-ppm`, `--minimum-iou-ppm`, `--confirmation-hits`, `--maximum-missed-frames` and
`--maximum-tracks` options explicitly. These are uncalibrated proposal settings, not deployment
alert policy. The exact chosen settings are frozen into the report's reconstruction plan.

## Prepare, review, and publish the exact candidate

```sh
cargo run -p fss-cli --bin fss-event -- prepare \
  --root ./camera-evidence --site site:home \
  --report ./analysis.bin --report-digest sha256:REPORT_DIGEST \
  --track sha256:TRACK_DIGEST --event-out ./proposed-event.json

cargo run -p fss-cli --bin fss-event -- publish \
  --root ./camera-evidence --site site:home \
  --report ./analysis.bin --report-digest sha256:REPORT_DIGEST \
  --track sha256:TRACK_DIGEST --proposal-digest sha256:REVIEWED_PROPOSAL_DIGEST
```

`prepare` recomputes the entire report from retained evidence and returns `proposal_digest`.
It writes no event or provenance authority. The optional JSON export uses the existing
canonical `EventHypothesis` schema. `publish` recomputes the report and current event
preconditions again, checks the exact approval digest, retains the provenance graph root-last,
and delegates the final event revision to `ReferenceDeployment::publish_event`. It does not
append the reserved event family through the generic ledger API.

Every candidate is `unclassified` and `indeterminate`, with an uncalibrated probability
interval [0,1] and an explicit policy abstention. Track confirmation does not upgrade this
state. All event evidence edges are derived-from edges, not corroborating physical-presence
witnesses. Model receipts are the actual retained invocation receipt objects, not detector
reports disguised as model receipts. Original capsule capture uncertainty, ambiguous
associations, missed observations, resets and retirements remain in the retained report.
The candidate's time interval is an evidence window, not arrival, departure, velocity, or dwell.

The event identity is stable for the exact local track history. Publishing the same proposal
again keeps the original revision and completion anchor. A longer report may supersede the
candidate only when it contains the exact previous ordered frame plan and byte-identical
previous detector/association projections as a full prefix. New evidence cannot drop or
reinterpret old evidence. Reordered or shortened history, a different tracking history, or
an independently changed event is refused rather than silently replacing the earlier decision.
A separate operator policy that adjudicates the event is never overwritten by this bridge.

## Recover after restart

```sh
cargo run -p fss-cli --bin fss-event -- read \
  --root ./camera-evidence --site site:home --event-id event:recorded:TRACK_HEX \
  --event-out ./recovered-event.json --report-out ./recovered-analysis.bin
```

Use the exact `event_id` returned by preparation/publication. The original recording, model
file and exported analysis file are no longer required; their retained custody is required.
Recovery follows the current authoritative event object, verifies its entire event-revision
chain, verifies the provenance root and bytes, and reproduces the detector/association report.
This is postprocessing replay, not independent numerical model replay. The latter remains
`RecordedInference::verify_by_replay` / `fss-infer replay`.

A cancellation after provenance publication but before event publication leaves only an
explicit prerequisite graph. `read` still refuses an absent event. An exact retry can complete
publication. A committed event is not rolled back by a subsequent export/stdout failure.

## Bounds and format ownership

The bridge admits at most 64 report frames to preserve the event schema's 64-model-receipt
bound without truncation. The report ceiling is 16 MiB; `--max-report-bytes` can narrow it.
`--detection-work-units` and `--association-work-units` are separate cumulative allowances,
each defaulting to 100000000 units. Revalidation of an earlier event's report and final
publication checks consume the same allowances. Refused work is not refunded. These limits
are not total process memory, elapsed time, energy or throughput measurements. Serialized
reports, reconstructed observations and staged-byte copies are additional bounded allocations.

`ingest::recorded_event` owns the new internal provenance metadata: length-delimited magic
`FSSREVT1`, u32 version 1, domain `fss.recorded_event_provenance.v1`, and SHA256 identities for
policy, local track, and the existing canonical report. The object manifest roots the report,
all detector/association projections, source capsules and sensor labels, real model receipts,
model-run roots and decoded-frame roots. Its root is the event decision-path fingerprint.
Unknown versions, noncanonical suffixes, changed source graphs, unavailable publication roots,
and inconsistent event bytes fail closed. Event bytes and authority still use the existing
`EventHypothesis`, event lineage, sensor-tamper guard, and ordered `EvidenceDeltaBatch` formats.

The local authorized operator process and filesystem permissions are the trust boundary.
`--principal` is an audit label, not remote authentication. No network, device-control or
notification grants are introduced. Exports must be new files outside the deployment;
existing files/symlinks are not overwritten. Unix exports are owner-only and file-fsynced,
not an atomic export-root transaction. I/O errors can leave partial exports; nonzero exits
must not be ignored. Opening this workflow never performs explicit repair or retention changes.

## Validation

```sh
cargo test -p fss-reference ingest::recorded_event::tests
cargo test -p fss-cli --bin fss-event
cargo test -p fss-cli --test recorded_event_cli_contract
```

Tests cover no-write preparation, exact approval, real model receipt linkage, conservative
candidate semantics, full-prefix revisions, independent-owner conflicts, cancellation before
staging, interruption after provenance publication, exact retry, restart without original
files, report/approval tampering, budget refusals, CLI report reconstruction and export safety.
They were added but not executed in this editing environment because no Rust toolchain was
available. This is an unqualified implementation, not a release or model-quality claim.

## Model-free candidates: `fss-event watch`

For a recording with no trained model, `fss-event watch` (library:
`fss_reference::ingest::recorded_watch`) runs retained decode (JPEG/MJPEG through the canonical
JPEG codec, or an IDR-led H.264 range through `fss-codec-h264`), the running-variance
foreground model (`ingest::foreground`), the constant-velocity Kalman tracker with global IoU
association (`ingest::tracker`), and the zone gate (`ingest::eventgen`). A confirmed track whose
filtered centre enters an operator-drawn zone yields one candidate per (zone, track) per run.

```sh
fss-event watch --root DIR --site SITE --import-id sha256:HEX --interpretation gray \
  --zone door:64,0,32,32 [--zone ...] [--first-segment N --segment-count M]
```

The analysis is read-only and deterministic (equal retained source and plan give byte-identical
JSON). It prints a bounded `fss.recorded_watch_report.v1` JSON report: plan, analysis and policy
digests, decoded frame count and size, zones, foreground box and confirmed-track counts, and per
candidate the zone, tracker-local track id, entry segment, frame range, per-frame evidence
(segment, retained capsule digest, luma digest, observation-record digest, filtered box), event
id, proposal digest, provenance root, status (`prepared`, `published`, `already_published`) and,
for prepared candidates, the exact rerun command with `--approve`.

Publication keeps this document's authority model: nothing is written without the exact
proposal digest. `--approve sha256:P[,sha256:Q]` checks every digest against the fresh analysis
before any write (`ERR-WATCH-APPROVAL-STALE-001` otherwise), retains the provenance graph
(analysis record, policy, observation records, retained capsules, import root) root-last, then
calls the deployment's guarded event publisher with a `Hold` decision. The event is
`Unclassified`, `Indeterminate`, abstains, has probability [0, 1], and carries non-supporting
derived evidence from one sensor failure domain: it is never corroborated and authorizes no
alert or other effect. A rerun finds the exact revision and reports `already_published` without
writing; a different event under the same candidate identity is `ERR-IDEMPOTENCY-CONFLICT-001`.
`fss-event read` does not reopen watch events (their policy differs from model-backed reports).

Thresholds, zones and Kalman noise are uncalibrated operator/policy choices. The committed tests
use synthetic MJPEG scenes and an FFmpeg `testsrc2` H.264 fixture: they prove the wiring and the
authority path, not detection quality, and a run with no candidate never certifies absence by
itself (only a retained coverage witness does, over its exact domain).

## Two-sensor corroboration: `fss-event corroborate`

`fss-event corroborate` (library: `fss_reference::ingest::recorded_corroboration`) is the first
path that can produce a `Corroborated` event from real retained bytes. It takes two completed
imports from two different sensors that cover the same period:

```sh
fss-file import ... --sensor sensor:east --receive-time-ns N \
  --capture-start-ns S --capture-uncertainty-ns U --assumed-fps F   # and likewise for west
fss-event corroborate --root DIR --site SITE \
  --camera east:sha256:IMPORT_A --camera west:sha256:IMPORT_B \
  --ground east:1,0,0,0,1,0,0,0,1 --ground west:-1,0,96,0,1,0,0,0,1 \
  --zone door:56,0,40,48 --interpretation gray --time-gate-ns 250000000 --distance-gate 16 \
  [watch thresholds and budgets] [--approve sha256:P[,sha256:Q]] [--report-out FILE]
```

Each recording (1..128 frames) runs the watch pipeline over the whole decoded frame. The foot
point (bottom centre of each confirmed track's filtered box) is projected through the camera's
`--ground` homography (row-major `h11..h33`, image pixels to owner ground units). The homography
is an owner assertion like a zone and **not** a calibration certificate: non-finite or singular
matrices, and foot points that map to or beyond the horizon, are refused
(`ERR-CORROBORATE-HOMOGRAPHY-INVALID-001`), but nothing about lens, pose or residuals is
verified. The first confirmed observation whose ground point lies in a ground zone is that
track's entry. Entries of the two sensors into the same zone are associated by the existing
global assignment (`ingest::cross_camera::associate_detailed`, zero ambiguity margin, minimum
score 0) with the time gate applied to interval midpoints and the distance gate to ground points.

Corroboration rule:

- Failure domains: one recording sensor is one failure domain (`recorded-sensor:<sha256 of the
  sensor id>`). The two sensor ids must differ (`ERR-CORROBORATE-SAME-SENSOR-001`; the same
  import twice is refused the same way). The zone-entry policy
  (`evaluate_zone_entry_corroboration`) marks an event `Corroborated` only when its supporting
  edges come from two distinct sensors, two distinct capture roots and two distinct failure
  domains; `fss_core` independently refuses a corroborated revision without two domains.
- Time: both imports must carry operator capture hints (`capture_time_label ==
  operator_assumption`), else `ERR-CORROBORATE-TIME-UNKNOWN-001`; their conservative capture
  spans must overlap, else `ERR-CORROBORATE-TIME-UNALIGNED-001`. Nothing aligns clocks by
  assumption, and the hints remain operator claims (no synchronisation certificate). A stably
  matched pair is corroborated only when the **worst case** separation over both entry frames'
  capture intervals is within `--time-gate-ns`; otherwise both entries are reported
  `time_gate_uncertain`.
- Geometry: the ground distance between the two entry points must be within `--distance-gate`.

The analysis is read-only and deterministic and prints `fss.recorded_corroboration_report.v1`:
per camera (import, root, sensor id, failure domain, frames, confirmed tracks, capture span,
watch plan/analysis digests, homography digest), every ground entry with its disposition
(`corroborated`, `no_counterpart_entry`, `no_admissible_counterpart`, `ambiguous`,
`time_gate_uncertain`), and per corroborated candidate the worst-case separation, ground
distance, event id, state, revision digest, `policy_action`, proposal digest, provenance root,
status and exact publish command. `--approve` checks every digest against the fresh analysis
before any write (`ERR-CORROBORATE-APPROVAL-STALE-001`), retains the provenance graph (policy,
association record, both entry records, both sensor labels, both import roots and entry
capsules) root-last and publishes the policy decision through the deployment's guarded event
publisher. The event is `Corroborated` and `Unclassified` with probability [0, 1]: independently
observed, not classified, identified or calibrated. The policy reports `prepare_alert` as an
affordance; **nothing is prepared or sent** by this command (`alert_prepared: false`).

## One alert per corroborated event: `fss-event alert`

```sh
fss-event alert --root DIR --site SITE --event-id ID --relay 127.0.0.1:8080 --path /hook \
  --plaintext-approval sha256:HEX --deadline-ms 5000                      # 1. proposes
  ... --approve sha256:PLAN                                               # 2. prepares
  ... --approve sha256:PLAN --dispatch sha256:DISPATCH                    # 3. commits + sends
```

1. Without `--approve`, the plan is computed against current authority in a scratch journal with
   the existing `prepare_reference_alert` gates (corroborated state, committed `PrepareAlert`
   decision path, current receipt, no open sensor tamper in the lineage); nothing durable is
   written. The report carries the plan digest (intent, obligation, channel, event root and
   revision, route digest, principal) and the exact next command.
2. `--approve PLAN` durably prepares the intent through `DurableEffectJournal::prepare_alert`:
   operation, idempotency key and terminal-proof obligation are journaled. The operation,
   idempotency and obligation identities are derived from the event revision and the route, so
   the same request cannot be prepared twice. The report carries the dispatch digest (plan
   digest, the durable prepared record, the deadline and the principal).
3. `--approve PLAN --dispatch DISPATCH` rehydrates the prepared plan from the journal and ledger
   (`rehydrate_reference_alert_plan`, which trusts nothing supplied), then `WebhookAttempt::begin`
   revalidates all event authority and commits durably before any network I/O. One plaintext
   HTTP/1.1 POST goes to the exact relay (no DNS, redirects, credentials or retries) and the
   observation is recorded. The CLI-owned `WebhookAuthority` admits only the approved route,
   journal file, intent and recorded effect authority; commit only while the operation is still
   prepared; network boundaries only while it is committed and before the deadline measured on a
   monotonic clock from `--deadline-ms`; and recording only for that committed operation; the
   owning Cx cancellation denies. The command only receives `CAP-ALERT-COMMIT-001` when
   `--dispatch` is given.

A complete 2xx head is recorded as `adapter_accepted` with `delivery_claim:
relay_acceptance_only`: it proves relay acceptance, never human delivery, and the obligation stays
pending. A lost acknowledgement, timeout, refusal, malformed or non-2xx response is recorded as
`indeterminate` and exits 1 with `ERR-EFFECT-INDETERMINATE-001`. Any rerun after commit reports
the journaled state (`already_dispatched`) and never resends. Wrong or stale approvals, a
changed route, principal or deadline are `ERR-ALERT-APPROVAL-STALE-001`; an event that is not
corroborated or holds an open tamper is `ERR-ALERT-NOT-ELIGIBLE-001`; unreadable or tampered
authority fails before any commit or send. Journal times come from the host clock at the CLI
boundary; the deadline is measured independently.

The committed tests (`crates/fss-cli/tests/corroborate_cli_contract.rs`) run the real binaries
on generated MJPEG scenes (two mirrored views of one moving square) and a loopback relay owned
by the test. They prove the wiring, the gates and the effect authority path, not detection
quality or real-camera geometry; no corroborated event never certifies absence.

## Coverage witnesses: `--retain-coverage`

A missing candidate is not absence. What `watch` and `corroborate` can certify is narrower:
over which interval each zone was actually observable by this exact pipeline. Every report
carries a `coverage` member (`fss.recorded_watch_coverage.v1`; library
`fss_reference::ingest::recorded_coverage`) proposing one record per analysed recording:

- one fss-core `CoverageWitness` (rendered as `fss.coverage_witness.v1`) per (sensor, zone,
  maximal contiguous interval) in which frames decoded continuously (no source gap, missing or
  skipped RASL segment; by default a decode refusal refuses the whole run and retains nothing,
  see `--tolerate-decode-refusals` below), the zone lies inside the decoded frame (an image zone)
  or is geometrically visible (a ground zone, see below), the background model is past its warm-up
  (`BACKGROUND_WARMUP_FRAMES` = 4: the first frame initializes the mean, the next three the
  variance), the tracker could still confirm a track before the run ends (the last
  `confirmation_hits - 1` frames are confirmation latency), no zone entry was emitted, capture
  time is an operator hint (`operator_assumption`), and no source gap precedes the frame in the
  import (after a gap the frame index no longer predicts capture time). Unknown capture time
  means no witness, never an assumed clock.
- the witness's certain bounds run from the latest possible capture of its first frame to the
  earliest possible capture of its last frame; a run whose bounds invert is `interval_too_short`.
- the witness binds the basis authority anchor the analysis read, its domain
  (`<source>:<sensor digest>:<scope>:<start>..<end>`), and a predicate naming the sensor, zone and
  pipeline generation (`fss.recorded_watch_pipeline_generation.v1`: policy, decoder label,
  detector and tracker parameters, owner homography for ground zones, warm-up, zone geometry).
- every other frame is an explicit uncovered interval with its reason: `background_warmup`,
  `confirmation_latency`, `zone_entry` (naming the candidate and the event it publishes),
  `segment_not_decoded`, `capture_time_unknown`, `capture_time_unreliable_after_gap`,
  `zone_outside_frame`, `interval_too_short`, and (below) `occluded`, `outside_frustum` and
  `decode_refused`.

### Geometric ground-zone visibility (fss-2h5zq.53)

Being inside the image is a 2D statement; a ground zone behind a wall, or beyond the camera's
view of the ground, is not observable however it maps into the frame. `corroborate` therefore
computes each ground zone's coverage geometrically
(`fss_reference::ingest::ground_visibility`):

- **Sampling.** The zone polygon is sampled on the ground plane (`z = 0` of the frame shared by
  the homographies, poses and mesh) at the centres of a `grid x grid` lattice over its bounding
  box (even-odd inside test). `--visibility-grid N` (2..32, default 8: 64 samples).
- **Projection.** Each sample is projected into the camera: through the inverse of the owner
  homography (the image point must map back, in front of the camera, onto the same ground
  point), or through an owner calibrated pinhole pose
  (`--pose NAME:W,H,fx,fy,cx,cy,r11..r33,tx,ty,tz`, world-to-camera). A sample behind the camera
  or outside the half-open decoded image is `outside_frustum`. A pose whose intrinsics describe
  another image size, or that disagrees with the camera's homography over a zone, is refused
  (`ERR-CORROBORATE-POSE-INVALID-001`).
- **Occlusion.** With an owner scene mesh (`--scene-mesh FILE --scene-mesh-digest sha256:PACKAGE
  --scene-source-digest sha256:SCENE`, an fss-twin `FSSTWIN1` package verified against both
  digests before any source is read; `ERR-CORROBORATE-VISIBILITY-001` otherwise) and a pose, the
  segment from the optical centre to each visible sample is tested against every opaque mesh
  triangle; a hit is `occluded`. Without a mesh (`no_scene_mesh`) or without a pose for that
  camera (`no_camera_pose`) occlusion is `occlusion_unknown`: it is never assumed clear, and the
  claim is labelled **frustum-only**.
- **Threshold.** `--visibility-threshold-ppm N` (default 1000000: every sample visible). A zone
  below it, or with no visible sample, is not observable for coverage: every frame is uncovered
  as `occluded` (most hidden samples occluded) or `outside_frustum`, and it carries no witness.

Each zone of such a record carries a `visibility` object (`camera_model`, `sampling`, `samples`,
`visible`, `outside_frustum`, `occluded`, `visible_fraction_ppm`, `threshold_ppm`, `state`,
`cause`, `occlusion`, `occlusion_unknown_reason`, `scene_mesh_digest`, `claim`:
`frustum_only` or `frustum_and_mesh_occlusion`); every witness predicate appends the visible
fraction, the sampling policy and the occlusion model ("occlusion_unknown ...: the claim is
frustum-only" without a mesh). The grid, threshold, pose and mesh digest are bound into the
pipeline generation and the camera's analysis identity. Such a record is version 2 of
`fss.recorded_watch_coverage.v1`; a record without geometry keeps its exact version-1 bytes
(pinned by `crates/fss-reference/tests/watch_coverage_golden.rs`). Orient marks a covered
frustum-only zone in its declared domain (`(frustum-only: occlusion_unknown)`), its cell
statement and its named gaps; an occluded or out-of-frustum zone is `not_observable` with that
reason and its sample counts. `watch` has only image zones (no homography or pose), so its
coverage is unchanged. Candidates and events never depend on the visibility inputs.

### Decode refusals as coverage gaps: `--tolerate-decode-refusals` (fss-fnrgr)

By default a typed decode refusal anywhere in the range refuses the whole `watch` run, exactly
as before. With the bare flag `--tolerate-decode-refusals` (echoed in every rerun and retain
command), a refusal in the middle of a recording becomes a gap instead
(`fss_reference::ingest::tolerant_decode`):

- JPEG/MJPEG: the refused frame (malformed, truncated or unsupported coding) is one
  `decode_refused` segment; the next frame decodes normally.
- H.264/H.265: nothing is concealed; decoding restarts at the next segment that opens as an IDR
  (H.264) or IRAP (H.265) range, and every segment from the refused access unit to that restart
  that returned no picture is `decode_refused`. The codecs report a truncated access unit as
  their bound (`ERR-DECODE-BOUNDS-001`), so that id is recorded.
- A retained source gap inside the range is handled the same way (MJPEG resumes at the next
  frame; H.264/H.265 at the next IDR/IRAP, `ERR-DECODE-H264-RANGE-GAP-001` or `-H265-`).
- Tracking restarts after every gap with fresh track identities: no track is ever bridged across
  it. The last `confirmation_hits - 1` frames before each restart are `confirmation_latency`, so
  no witness spans a gap or claims a frame whose entry could not have been confirmed.
- The report adds `decode_refusals` (first/last segment and error id per run) and each
  `decode_refused` interval names its `error_id`; the refused runs and restarts are part of the
  analysis identity. Custody failures, resource bounds of the composition, budget exhaustion
  and cancellation still refuse the run; a range in which nothing decodes returns its first
  refusal; the detector cascade is refused over a gapped range. A tolerant run that meets no
  refusal is byte-identical to the default run.

Orient then sees two witness windows around the gap: the zone is `not_observable between` them,
and follow certifies no silence over it.

### Pose provenance and owner-asserted camera generations (fss-x8j0v follow-up)

When a corroborate camera's ground visibility uses a pinhole pose, its coverage record binds
where that pose came from (version 4 of `fss.recorded_watch_coverage.v1`): `owner_pose_argument`
for a `--pose`, or `site_calibration` with the pinned calibration digest, the camera handle and
its intrinsics and extrinsics generations. The provenance digest
(`fss.coverage_pose_provenance.v1`) is bound into the camera's analysis identity. The coverage
report, orient's zone cells and a cold reopen all show it; a posed version-2/3 record written
before this binding is shown as `unrecorded`. Records of cameras without a pose keep their bytes.

Sensor capsules do not carry a camera's generation. `--camera-generation
NAME:INTRINSICS:EXTRINSICS` (requires `--calibration`) is the owner's assertion that a calibrated
camera still has exactly those generations: a mismatch is
`ERR-SITE-CALIBRATION-GENERATION-STALE-001` before any source is read and nothing is appended; a
match is recorded `owner_asserted_not_observed`, and a calibrated camera without an assertion
`unasserted_unknown`.

### Retained calibration adoption (fss-x8j0v follow-up)

`fss-event calibration adopt --root DIR --site SITE --calibration FILE --calibration-digest
sha256:HEX --bind NAME:SENSOR [--bind ...] [--approve sha256:APPROVAL]` makes a calibration the
deployment's current one for the bound cameras. The file is verified against its pin first.
Without `--approve` it prints each proposed receipt and the exact approval digest
(`fss.calibration_adoption_approval.v1`, over the calibration, the bindings and each camera's
current adoption) and writes nothing. With the approval it retains one `FSSTLR01` receipt
(`fss.twin_localization_receipt.v1`) per camera in the `twin_localization_receipt` family, on
`object:twin-localization:camera-<handle>`, all in one authority batch. A receipt carries the
adoption generation, camera handle and name, the bound sensor, the calibration digest and twin,
the intrinsics and extrinsics generations, and a link to the receipt it supersedes.

- **Sensor binding.** The owner names the sensor; adoption requires a readable retained capsule of
  it. A camera's sensor is fixed after its first adoption, and a sensor belongs to one camera
  handle (`ERR-CALIBRATION-ADOPTION-SENSOR-CONFLICT-001`). Binding the sensor rather than one
  import keeps the adoption valid for every later recording.
- **Monotone.** A later adoption may raise a generation or replace the calibration at the same
  generation; it may not lower a generation or re-adopt a calibration the camera superseded
  (`ERR-CALIBRATION-ADOPTION-REGRESSION-001`). Every receipt stays in the ledger.
- **Approval.** A stale or tampered approval is `ERR-CALIBRATION-ADOPTION-APPROVAL-STALE-001`
  before any write; an exact rerun writes nothing. `calibration show` lists every adopted camera's
  current receipt and history.

`corroborate --calibration` consults the retained receipts before any frame is decoded. A camera
whose current receipt names exactly this calibration and generation, over a recording of the
adopted sensor, is recorded `adopted_current`, followed by the receipt digest in the provenance
(the two earlier currencies keep their bytes). A camera with adoptions and another calibration is
refused: `ERR-CALIBRATION-ADOPTION-STALE-001` when the calibration or a generation not above the
adopted one was superseded, `ERR-CALIBRATION-ADOPTION-UNADOPTED-001` otherwise, and
`ERR-CALIBRATION-ADOPTION-SENSOR-MISMATCH-001` for a recording of another sensor; nothing is
appended. An `--camera-generation` assertion does not override an adoption. A camera without
adoptions keeps the owner-asserted or unasserted currency.

Non-claim: `adopted_current` means the deployment retains the owner's approval-gated adoption of
that calibration. It is owner authority, not a physical measurement: nothing observes that the
camera has not moved, zoomed or been relensed since.

### Privacy masks with geometry and tolerant decode (fss-bgqkd)

A sensor's retained privacy mask (`fss-event privacy-mask declare`, see `PRIVACY.md`) composes
with both extensions above:

- **Ground zones.** A corroborate ground zone is masked when either rule holds (the stricter
  wins): the conservative image-preimage rule (the bounding box of the zone's corner preimages
  contains a masked pixel) or the geometric rule (an in-view visibility sample projects onto a
  masked pixel). Each sample is counted once: outside the frustum, else `privacy_masked` (the
  mesh is not consulted for it), else occluded, else visible. The visibility object then names
  `privacy_masked` (its count) and the cause `privacy_masked`; such a record is version 3 of
  `fss.recorded_watch_coverage.v1` (every visibility block carries the count). A record without
  a masked sample keeps its version-1 or version-2 bytes. The pipeline generation binds the
  geometry parameters and the mask binding.
- **Tolerant decode.** Frames that do decode are masked exactly as in a default run (MJPEG in
  the tolerant source, H.264/H.265 in their ranges); refused segments stay `decode_refused`.
- **Reason precedence.** Per zone and segment exactly one reason is recorded: `decode_refused`
  (or `segment_not_decoded`) first, since no pixels exist; then a `zone_entry` the builder
  named; then `privacy_masked`; then the pre-mask order (`capture_time_unknown`, `occluded` /
  `outside_frustum`, `zone_outside_frame`, `capture_time_unreliable_after_gap`,
  `background_warmup`, `confirmation_latency`, `interval_too_short`).

```sh
fss-event watch ... --zone door:64,0,32,32                                   # proposes
fss-event watch ... --zone door:64,0,32,32 --retain-coverage sha256:APPROVAL # retains
```

Retained coverage is authority-plane evidence and follows the candidates' approval discipline:
the analysis writes nothing; `--retain-coverage` must equal the report's `approval_digest`
(which binds the record digests and so the basis anchor), checked before any write
(`ERR-COVERAGE-APPROVAL-STALE-001` otherwise), and commits the record in one
`coverage_witness` ledger batch. `--approve` alone never retains coverage; a run that publishes
candidates re-proposes coverage against the new anchor. A rerun of a retained analysis reports
`already_retained` and writes nothing. `corroborate` proposes one record per camera over its
ground zones and retains both under one approval.

`fss session orient` (alias `fss orient`) then assesses every objective zone (every zone of a retained record and every zone
a published event names): `stale` when the sensor has newer retained evidence than any analysis
of the zone's current pipeline generation (older generations are never reused), `not_observable`
when the freshest analysis has no witness or the current witnesses leave a hole that is not
exactly a published event's entry frame, `covered` otherwise, with its declared window and the
named gaps outside it. The capsule is `complete` only when every objective zone is covered; then
`fss session follow` (alias `fss follow`) since the anchor of such an orientation returns the
engine's silence certificate, whose authorized domain names the witnesses
(`fss://coverage/<witness digest>`). That holds across a harmless ledger advance too (for example
an `fss-file decode` receipt): the engine compares decision semantics under the registered
`meaningfulDeltaComparison` rules (`architecture/agent_contracts.json`), so the ledger-head
restatement and re-priced affordance costs are not changes, and orient cites the last batch that
changed each fact's inputs rather than the head. Newer unanalysed evidence still ends the silence
as protected coverage loss. The committed tests
(`crates/fss-cli/tests/coverage_cli_contract.rs`) cover the quiet scene, unknown capture time,
a source gap, staleness after new evidence, a motion scene with its event, corroboration,
approval gating, and silence across a harmless successor commit on synthetic MJPEG scenes;
`crates/fss-cli/tests/coverage_geometry_gap_cli_contract.rs`,
`crates/fss-reference/tests/ground_visibility_coverage_contract.rs` and
`crates/fss-reference/tests/decode_gap_coverage_contract.rs` cover geometric visibility (in view,
behind a mesh wall, outside the frustum, frustum-only without a mesh, pose and mesh refusals) and
decode gaps (a corrupt MJPEG frame with and without the flag, no track bridging, an H.264
corrupted P slice resuming at the next IDR, no silence over a gap, determinism). They prove the
contract, not detection quality.

## Detection cascade: `--detector-package` on `watch` and `corroborate`

Detection is a cascade, not a monolith (README): the model-free watch stage decodes every frame,
finds foreground, tracks it and gates zone entries; a trained detector then runs only where the
cheap stage says it matters (library `fss_reference::ingest::detector_cascade`).

```sh
fss-event watch ... --zone door:200,0,160,640 \
  --detector-package models/yolox-nano/yolox_nano.fmpk \
  --detector-digest sha256:5b6568750faa375de3742e5eb310fbd4e22ff26e1ba727f193b79ab984a68c74 \
  --detector-max-inferences 4 [--detector-frames-per-track 2] [--detector-min-iou-ppm 300000] \
  [--detector-minimum-score-ppm N]
```

- Loading: the package is read (bounded regular file) and verified by `RgbDetectorPackage::load`
  before any source is read: a whole-archive digest other than `--detector-digest` is
  `ERR-MODEL-PACKAGE-DIGEST-001` before parsing. `--detector-max-inferences` (1..64) is mandatory;
  cascade bounds are `ERR-DETECTOR-CASCADE-PLAN-001`. Without any `--detector-*` option the watch
  and corroborate outputs are byte-for-byte unchanged (pinned by
  `crates/fss-reference/tests/watch_report_golden.rs` against the pre-cascade tree).
- Frame selection: for each candidate (a confirmed track entering a zone) the zone-entry frame,
  then the track's first confirmed frame, then its following matched frames, up to
  `--detector-frames-per-track` K (1..8, default 1). Unique frames are admitted in candidate
  order against the budget; the rest are `budget_exhausted` (`ERR-DETECTOR-CASCADE-BUDGET-001`)
  per frame, never dropped. A per-frame detector refusal is `detector_refused`
  (`ERR-PACKAGE-DETECT-001`). `corroborate` uses one budget for both recordings.
- Inference: the full decoded frame, letterboxed exactly as the package spec declares (the same
  path as `fss-infer package-detect`). JPEG frames use the native colour decode; H.264/H.265
  frames use their decoded luma and chroma through the declared BT.601 limited-range transform
  (`ycbcr420_bt601_limited_rgb`, `recorded_decode::video_rgb`).
- Association: each surviving detection against the track's filtered box at that frame by
  integer IoU on the 1/256-pixel grid; the best IoU (then score, then row) at or above
  `--detector-min-iou-ppm` is associated, otherwise `no_association`.
- Evidence: one canonical `fss.detector_class_evidence.v1` record per selected frame (label,
  uncalibrated score bits, bounds, IoU, package digest and generation, import, segment, frame
  RGB, inference, output and head-report digests). In `watch` each record is an event evidence
  edge in the sensor's own failure domain: `supports` for an associated detection, derived-from
  otherwise. The event stays `Unclassified`, `Indeterminate` and abstaining; one sensor can
  never corroborate (fss-core refuses a corroborated revision with one failure domain). In
  `corroborate` the records are retained in the candidate's provenance and bound into its
  association identity and proposal digest, but they are **not** edges of the zone-entry policy
  event, so the `Corroborated` state and the `prepare_alert` affordance rest only on the two
  sensors' own witnesses. No reviewed policy path for class-conditioned event kinds exists, so
  no kind is ever derived from a detector score.
- Identity and coverage: the cascade identity (`fss.detector_cascade.v1`: policy, package
  archive/manifest/model/graph/contract digests, model id, generation, K, budget, IoU, colour
  transforms) is bound into the candidate identity, the analysis record and every coverage
  pipeline generation, so a cascade analysis never reuses model-free witnesses or events.
- Report: a `detector_cascade` member lists the policy and package identities, the selected,
  inferred, budget-skipped, refused and cascade-skipped frames, `inference_count`, per inferred
  frame its digests and detections, and `scores: uncalibrated`; each candidate (or ground entry)
  carries `class_evidence`.

Release scalar inference costs about 3 s per 416x416 frame; debug builds about a minute. The
committed tests (`crates/fss-reference/tests/detector_cascade_contract.rs`,
`crates/fss-cli/tests/detector_cascade_cli_contract.rs`) use a synthetic person-shaped
silhouette (the YOLOX conformance generator) walking into a zone and run exactly one inference
each; they prove selection, budget, association and evidence wiring, not detection quality.

## Trained-detector reports: `package-detect --retain` -> `report` -> `prepare` -> `publish`

`fss-event report` consumes a `fss.package_detection_report.v1` through retained custody
(library `fss_reference::ingest::package_event`), so the report/prepare/publish flow works with
the trained detector:

```sh
fss-infer package-detect --root DIR --site SITE --import-id sha256:IMPORT --first-segment 0 \
  --frames 8 --interpretation ycbcr --package models/yolox-nano/yolox_nano.fmpk \
  --package-digest sha256:5b65...8c74 --retain yes > report.json   # receipt on stderr
fss-event report --root DIR --site SITE --package-report sha256:$(sha256sum < report.json) \
  --label person [--confirmation-hits N --maximum-missed-frames N --minimum-iou-ppm N] \
  --report-out ./package-analysis.bin
fss-event prepare --root DIR --site SITE --report ./package-analysis.bin \
  --report-digest sha256:ANALYSIS --track sha256:TRACK
fss-event publish ... --proposal-digest sha256:PROPOSAL
```

1. `--retain yes` retains the exact report JSON and a canonical `FSSPDET1` record
   (`fss.package_detection_record.v1`) root-last with one cognition-plane
   `package_detection_record` delta. Only the deployment's own computation is retained, never an
   operator-supplied file; an exact rerun is `already_retained`. stdout stays the exact report.
2. `report --package-report DIGEST --label NAME` reopens the retained record from custody (no
   model execution), tracks the label's detections with the watch pipeline's Kalman tracker (fixed
   noise; tracking policy explicit) and exports a canonical `FSSPANR1`
   `fss.package_analysis_report.v1`. An unretained digest is
   `ERR-PACKAGE-EVENT-UNAVAILABLE-001`; an unknown label is `ERR-PACKAGE-EVENT-REQUEST-001`.
3. `prepare`/`publish` recognise the package report by its magic and rebuild it from custody on
   every call. The event (`event:package:<track>`) is `Unclassified`, `Indeterminate`,
   abstaining, probability [0, 1]; each matched frame is an observation record, a supporting
   derived edge when a label detection overlaps the track, all in one sensor failure domain.
   Publication needs the exact proposal digest (`ERR-PACKAGE-EVENT-APPROVAL-STALE-001`), retains
   provenance root-last and uses the guarded event publisher with `Hold`; an exact rerun reports
   `already_published` without writing. `fss-event read` does not reopen package events (their
   policy differs), and a package event is never extended by a longer report.
