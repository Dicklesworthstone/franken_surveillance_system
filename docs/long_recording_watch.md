# Whole-recording zone-entry analysis

`fss-event watch --stream-watch` scans a retained recording for confirmed foreground-track
entries across the complete selected range. The foreground model and tracker remain alive
between frames, including across the ordinary watch mode's 128-frame boundary. A candidate
that first appears late in the recording can therefore be found without dividing the file into
independent analysis windows.

This reference workflow can run alone or attach a digest-pinned trained detector to selected
confirmed entry frames. A candidate describes an actual matched foreground track inside an
owner-declared image zone. It remains **unclassified, indeterminate,
single-sensor, probability [0,1], Hold**. This command neither prepares nor dispatches an alert.
Synthetic fixtures establish workflow behavior and evidence linkage; they do not establish
recognition accuracy on real camera footage.

## Analyze a retained recording

```sh
fss-event watch \
  --root /path/to/deployment --site site:home \
  --import-id "${IMPORT_ID:?supply the retained import identity}" \
  --interpretation gray \
  --zone porch:100,80,400,300 \
  --stream-watch \
  --report-out /path/to/review/porch-entries.json
```

The source must already be retained by `fss-file import`, `fss-import-http`, or `fss-import-rtsp` and have explicit
operator capture-time hints. Those hints remain assumptions; this command does not calibrate camera clocks or infer
UTC. The original import path is unnecessary once custody is complete.

MJPEG/JPEG uses the native JPEG decoder. Set `--interpretation ycbcr` for YCbCr images and
inter-coded H.264/H.265 recordings. Supported container imports use their existing native range
decoders, including indexed or fragmented MP4, QuickTime and Matroska. An inter-coded range
must begin at an H.264 IDR or H.265 IRAP picture. The scan processes pictures in display order,
and each candidate retains both its absolute display-order `entry_position` and source coding
`entry_segment`, with the exact `entry_capsule_digest`.

`--first-segment` and `--segment-count` select a bounded range. Without a count, the complete
remaining recording is selected if it contains 1 through 65,536 segments. An oversized range
is refused; there is no silent truncation. Each invocation starts a fresh analysis and does not
resume an in-memory tracker from another process.

Foreground thresholds, tracker configuration, decoder dimensions/pixel limits,
`--tolerate-decode-refusals`, `--approve`, and `--report-out` remain available. The new mode is
explicitly separate from `--stream-dwell` and its duration/gap rules. `--retain-coverage` is
refused before deployment I/O because this entry workflow owns no absence certificate.

## Add trained class evidence across the complete recording

The existing detector options also apply to `--stream-watch`:

```sh
fss-event watch \
  --root /path/to/deployment --site site:home \
  --import-id "${IMPORT_ID:?supply the retained import identity}" \
  --interpretation ycbcr --zone porch:100,80,400,300 \
  --stream-watch \
  --detector-package /path/to/model.fmpk \
  --detector-digest "${MODEL_DIGEST:?supply the verified package SHA-256}" \
  --detector-max-inferences 8 \
  --detector-frames-per-track 2
```

The complete bounded package archive is checked against the requested digest and admitted by
the native package owner before source analysis. No model is loaded implicitly. A quiet scan
can load the requested package but performs no inference when there is no confirmed entry.

The first pass scans the complete range in native display order with one foreground model and
tracker. A second pass materializes masked native RGB only for selected entry frames and later
actual matches of the same track and epoch. Predicted positions, gap bridges and an unrelated
track cannot supply class evidence. MJPEG reads selected frames; AVC and HEVC replay their native
prediction dependencies while only selected pictures materialize RGB. An entry after frame 128
can receive detector evidence without restarting the tracker or increasing the short-cascade
frame limit.

`--detector-max-inferences` must be 1 through 64 and applies to the entire recording.
`--detector-frames-per-track` must be 1 through 8; for this workflow it limits selected actual
matches per entry. Selection follows entry order and then matching display positions. Reused
coding segments share one inference. `--detector-min-iou-ppm` controls the existing box
association gate, and `--detector-minimum-score-ppm` optionally pins an explicit detection-head
threshold. A changed package, threshold, selection or bound changes the analysis and approval.

The report adds `detector_cascade` and per-candidate `class_evidence`, including selected,
inferred, budget-skipped and refused segments, exact capsule identities and class associations.
`inference_pipeline_attempts` counts entries into the native inference pipeline;
`inferences_completed` counts completed model-plus-head results. `model_invoked` means that
the pipeline was attempted: preprocessing can refuse before model arithmetic, and the head can
refuse after model execution. The report does not turn either case into a completed inference
or negative observation. A budget-skipped or refused frame supplies no absence evidence.

Class evidence retains the original sensor and common-cause identity. Its scores remain
uncalibrated; even a class association leaves the event's kind, state, probability and action
unchanged. No unretained model receipt or independent corroboration claim is created.

## Entry, gaps, health and privacy

One candidate is produced for the first confirmed **actual match** whose rounded filtered
track center is strictly inside a zone, for each tracker epoch, track and zone. A predicted
location during a missed detection does not qualify. Later observations of the same track in
that zone do not produce repeated entries.
The first observed sample inside a zone does not by itself prove that a physical boundary
crossing occurred between two observed frames.

An explicit source or tolerated decode gap resets foreground and tracker state and advances the
tracker epoch. Tracks cannot bridge the gap. Inter-coded decode resumes at the next admitted
IDR/IRAP picture. The report lists decode refusals and tracking restarts. Source omissions or
gaps can invalidate index-derived capture hints; unreliable time is counted and cannot support
a candidate. Regressing admitted capture bounds refuse the complete scan.

The sensor's current privacy mask is applied before perception. A zone containing masked pixels
cannot support a candidate. A new privacy generation invalidates an unpublished approval.

The optional screen uses the same masked decoded pixels:

```sh
fss-event watch \
  --root /path/to/deployment --site site:home \
  --import-id "${IMPORT_ID:?supply the retained import identity}" \
  --interpretation gray --zone porch:100,80,400,300 \
  --stream-watch --sensor-health conservative-v1
```

The screen reports sustained clipping, exact repeated frames and contrast collapse as suspected
degradation. A finding or incomplete screen blocks publication for the complete scan; diagnostic
candidates remain visible, their `publish_command` is null, and even an exact candidate approval
is refused. A clear screen does not certify physical health, tamper absence or detection quality.

An empty result never proves that a person, intrusion or other event was absent. This mode
publishes no coverage witness or certified silence result.

## Aggregate limits

Every aggregate budget applies to the whole scan. Counters are not replenished per frame,
chunk, track or candidate.

| Option | Default | Accounted work |
|---|---:|---|
| `--stream-read-bytes` | 536,870,912 | Source bytes admitted by the decoder cursor, configuration and recovery probes |
| `--stream-pixel-budget` | 1,073,741,824 | Foreground luma samples plus selected MJPEG RGB pixels or second-pass AVC/HEVC luma samples |
| `--stream-assignment-work` | 1,073,741,824 | Checked tracker assignment work admitted |
| `--stream-trace-bytes` | 8,388,608 | Complete bounded identity and geometry trace |
| `--work-units` | Existing decoder default | Native JPEG decoding work across the selected range |

All four `--stream-*` ceilings must be positive. Maximum source read is 512 MiB, pixel and
assignment ceilings are at most 68,719,476,736 each, and the trace ceiling is 8 MiB. Existing
per-frame codec and object bounds still apply. The optional health screen maintains its own
cumulative sample count under the pixel ceiling. Aggregate options without `--stream-watch`
are rejected; the existing `--dwell-*` budget names remain specific to `--stream-dwell`.

Exhaustion refuses the complete analysis before event publication or report export. The four
aggregate ceilings and JPEG work allowance are bound into this mode's analysis identity;
changing them requires reviewing a fresh approval even when the detected entries are unchanged.
With a trained detector, source bytes, JPEG work and pixel accounting span both passes without
replenishment. The canonical detector recipe additionally retains all native codec/read fields,
the model import reservation, inference/preprocessing/output limits and detection-head bounds.
The library's `LongWatchLimits.decode` owns source and RGB decoding; package inference and head
limits own the corresponding native model stages. Other original package decode settings are
retained for exact recipe identity, without granting a second decoding allowance.
Metadata, journal and publication operations retain their separate owner bounds;
these counters do not claim total-system I/O, memory, latency or energy accounting.

## Review, publication and recovery

The complete `fss.long_watch_report.v1` report carries source and analysis identities, authority
basis, privacy binding, decode and timing exclusions, aggregate costs and each candidate's exact
approval. JSON is bounded as a complete object before any approved event is committed.

Without `--approve`, analysis appends no event authority. Review a candidate's `publish_command`
and rerun with its exact `--approve sha256:PROPOSAL`, or a comma-separated set of reviewed
proposal digests. Every supplied approval must match the fresh analysis. Changing the source,
range, zone, perception configuration, aggregate limits, screening or privacy binding changes
the approved proposal. Ordinary short-watch and dwell approvals cannot authorize whole-recording
entries.

Publication revalidates retained source and privacy, retains a shared analysis graph and
candidate provenance root-last, then publishes the event through the existing guarded
publisher. A cold retry recomputes from retained custody and returns `already_published` for
exact completed candidates without another event or effect append. Source deletion or privacy
drift can instead make retry invalid. A report-file or stdout failure after commitment does not
undo the committed event; rerun the exact request to recover its status.

The command exposes only identity and scalar evidence metadata in JSON. It does not copy raw
pixel arrays into the report or turn an uncalibrated foreground score into a model confidence.
Detector-backed publication retains the exact package archive, canonical execution recipe,
bounded outcome and every referenced class record in the shared analysis closure. Preview
alone does not retain these new objects. Missing or changed source/privacy custody still
refuses publication, including when an old approval is supplied.

## Validation scope

The focused regression families are:

```sh
cargo test -p fss-cli --test watch_stream_entry_cli
cargo test -p fss-reference --test long_watch_contract
cargo test -p fss-cli --test watch_stream_detector_cli --test detector_cascade_cli_contract
```

On 2026-10-10, the pinned native toolchain passed all 58 selected tests: 16 whole-recording
reference contracts, 31 focused CLI tests and 11 cold replay library cases. The CLI tests
include six new detector cases, eight existing
stream-watch cases, three short detector cases, six legacy cold replay cases and eight replay
parser/output cases. Together, these tests execute the retained YOLOX package, including an entry after frame
150, shared budget refusal, independent executor cancellation, explicit head refusal, stale
approvals, native AVC picture reordering and HEVC color conversion. Publication and cold replay
pass after removing the loose source/model files; removing the retained model archive makes
both inspection and verification refuse with unchanged authority. Canonical recipe tests
cover every numeric reservation and reject narrowed read authority and changed generations.
The cold replay library tests also reject substituting a different valid same-camera capsule
for an entry's exact coding segment, while preserving legacy one- and two-camera recovery.

Native builds kept the pinned compiler and dependencies, disabled test debug information and
incremental compilation, and serialized the reference compiler frontend/backend to fit shared
build memory. Debug assertions remained enabled. These are functional fixture tests, without
a full-workspace, live-device, detection-quality or release-qualification claim.

It exercises a late entry in a 300-frame native MJPEG recording, a 300-frame H.264 MP4 with
B-pictures, exact publication and cold retry after the original source file is removed, cross-mode
approval rejection, aggregate budget failures, unknown capture time, health-screen publication
blocking and the empty-result boundary. Existing short-watch, streaming dwell and health CLI
families remain separate regression gates. This reference feature does not establish a release,
live-device throughput, detection-quality or complete qualification claim.

## Read and verify a published event

Use `fss-event read --root DIR --site SITE --event-id ID` to inspect an original published
whole-recording candidate after restart. The response explicitly distinguishes inspection from
native replay and supplies exact revision/provenance pins and a verification command.
`fss-event verify` reruns the retained computation and compares the complete analysis and event.
For a detector-backed publication, inspection also reports the retained model/recipe identities
and native kernel generation. Verification reloads the archived package from deployment custody
and reruns the exact trained computation; the original model path is unnecessary. Stored recipe
reservations must fit the current replay ceilings, and every analysis, class association and
event must reproduce exactly. Inspection alone does not run or certify the model.
See [cold event recovery](long_event_replay.md) for recipe scope, bounds and validation status.
