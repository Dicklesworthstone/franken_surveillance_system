# Recorded analysis to durable unresolved event candidates

`fss-event` connects retained inference and local association to the existing event owner.
It builds complete replayable analysis reports, prepares an exact candidate, publishes only
that approved candidate, and reopens the event and its provenance after a process restart.
No pretrained model, calibrated detection quality, physical identity, threat classification,
coverage certificate, notification transport, or effect authority is introduced.

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
authority path, not detection quality, and a run with no candidate never certifies absence.

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
