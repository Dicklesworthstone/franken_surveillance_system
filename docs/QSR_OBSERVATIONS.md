# QSR observations from retained detector tracks

`fss-event qsr` turns an existing, retained, historically screened package-zone
report into sampled zone counts and presence, sampled dwell, and ordered lane-stage
endpoint observations. It reopens the native source evidence before answering.
It does not run a second detector or tracker, acquire a camera stream, publish a
security event, retain a new QSR object, or grant an effect capability.

This is an unqualified reference implementation for VIT-012. Its output counts
confirmed model-track observations. It does not measure detector quality, count
unique physical people, certify an empty scene, infer customer service, or provide
the future `fss/1` QSR view. Queue wait, door-open state, POS joins and cross-camera
lane journeys still require their own evidence and qualified interpretations.

## Read an existing report

The command uses the deployment's normal exclusive startup and recovery. That
startup may clean recovery metadata and mark interrupted committed effects
`Indeterminate`. The QSR projection itself creates no reports or events and
dispatches no effects; the command does not promise an unchanged filesystem.

The input must be a retained `fss.package_zone_report.v2` created through the
existing `fss-event package-zones analyze --require-health-screening yes` workflow.
That workflow first reopens retained package detections, computes exact assigned
track boxes, and proposes a report. Retain that report with its exact
`--retain sha256:APPROVAL` before using it here. QSR refuses a v1 unscreened report.

For a selected package label such as `person`, annotate a queue and a register:

```sh
fss-event qsr \
  --root /absolute/path/to/existing/deployment \
  --site site:restaurant \
  --report-digest sha256:RETAINED_SCREENED_ZONE_REPORT \
  --zone-role counter_queue:queue \
  --zone-role register_2:register
```

Every role names an existing zone in the source report. Unannotated zones remain
`area`. Roles change the interpretation label, not geometry, detector class,
tracking policy, privacy policy or evidence. The source report has one exact
package vocabulary label. The command does not reinterpret an arbitrary label as
`person`, combine different vehicle classes, or identify an employee.

For a vehicle-class report whose existing zones mark successive lane positions:

```sh
fss-event qsr \
  --root /absolute/path/to/existing/deployment \
  --site site:restaurant \
  --report-digest sha256:RETAINED_SCREENED_VEHICLE_ZONE_REPORT \
  --lane-stage order_point \
  --lane-stage pay_window \
  --lane-stage present_window
```

The argument order is the lane order. At least two distinct stages are required.
A lane stage cannot also carry a different zone role. Unknown, duplicate,
conflicting and oversized annotations refuse before any result is delivered.

## What the observations mean

| Output | Interpretation |
| --- | --- |
| `confirmed_track_count` | Number of actual, confirmed, complete assigned boxes strictly inside this zone on this source frame. Predicted/coasting positions never contribute. |
| `presence: observed` | At least one such observation exists. Class scores remain uncalibrated model outputs. |
| `presence: not_observed` | No such observation exists on this admitted sample. The result does not establish physical absence or detector recall. |
| `presence: unknown`, count `null` | The zone is masked, or the exact source frame lacks matching complete historical screening without findings. This is not a count of zero. |
| `tentative_tracks`, `boundary_tracks`, `partial_tracks`, `unobserved_tracks` | Exclusions remain visible. Tentative tracks are not retroactively confirmed, clipped silhouettes have no definite full-box relation, and missing assignments are not departures. |
| `maximum_observed_count` | Maximum count among supported samples. It is `null` when no sample supports a count. |
| `observed_tracks` | Distinct anonymous IDs within this exact source analysis. Fragmented tracks may belong to the same physical object; this is not a unique-person count. |
| `sampled_zone_dwell` | The original zone owner's exact maximal qualifying run, endpoint bounds and sample count. It remains sampled presence rather than continuous occupancy or queue wait. |
| `observed_lane_stage_transition` | One track was actually observed inside two adjacent declared stages, with supported observations between them. The interval bounds separation of first inside sightings, rather than entry, departure, service or handoff time. |

For example, if the first inside sample at the order point has capture bounds
`[100, 102]` and the first inside sample at the pay window has bounds `[130, 132]`,
the endpoint-separation interval is `[28, 32]`. An intermediate complete confirmed
observation outside both stages can preserve the observed trajectory. A missing
assignment, tentative or clipped sample, source discontinuity, unreliable capture
time, excessive sample gap, excluded historical screen, or masked lane stage
breaks it.

When a box is inside overlapping stages, the result records `ambiguous_stage`
instead of choosing an order. A jump from order to present records
`skipped_stage`, and a move backward records `reversed_stage`. Later observations
may start another partial sequence. No record fills in a missed stage or asserts a
completed customer journey.

## Source, policy and coverage bindings

The only public constructor is `QsrObservationReport::open`. It selects an exact
retained report through `PackageZoneReport::open`, which rechecks source custody,
the source model/detection record, native tracking reconstruction, current privacy,
historical diagnostic custody and deletion state. A changed privacy interpretation,
withdrawn source, corrupt diagnostic or stale screened report refuses rather than
returning an empty observation set or repairing the source.

The JSON reports the original package/model generation, class, package and analysis
digests, source import/root, source and retention anchors, privacy binding and each
source frame's capsule and historical diagnostic handles. Capture-time labels and
clock bases are preserved. An `operator_assumption` remains an assumption; this
projection does not create a UTC or clock-discipline witness.

Coverage is `finite_sampled_source_frames`. Every source frame appears, including
unknown and excluded frames. Historical screening describes only the retained
finite scan, not current camera health. `continuous_coverage_certified` and
`absence_certified` are always false. The report is useful evidence for a downstream
review, and it does not independently authorize a customer media use.

The canonical read-result digest binds `FSSQSR01`, version 1,
`fss.qsr_observation_report.v1`, the versioned observation policy, exact source
report and provenance root, normalized role configuration, explicit lane order and
all derived rows. `fss.qsr_observation_config.v1` identifies the annotation
configuration. This is a reproducible read identity, not a retained publication or
an approval. Existing package-zone v1/v2 encodings remain unchanged.

## Bounds and verification

The source owner bounds the input to 16 zones, 64 frames and 8,192 complete
track × zone × frame cells. QSR preserves these bounds, emits every selected sample
and interruption, and refuses complete JSON output above 8 MiB. It never ranks away
unknown samples or truncates the observations to make a result fit.

The complete canonical result and JSON are constructed before a final native revalidation
of source custody, current privacy/deletion, the principal, durable ledger head and retained
report proof. This second reconstruction spends the original source-health allowance's
remaining work; it does not refill a new allowance. Cancellation or a failed check at this
boundary returns no successful report. `to_json()` returns the already admitted immutable
snapshot of the completed read, without performing another read or implying later freshness.

Tests include actual retained JPEG and numeric FMPK model execution through the
existing detection, tracking, screening and custody owners, followed by QSR cold
reconstruction. Separate reducer cases cover missing/tentative/clipped samples,
masking with zero tracks, unknown health, ambiguous and out-of-order stages,
capture-time regression, uncertainty widening, integer extremes, malformed cell
matrices, cancellation and bounds. The numeric fixture is test data, not evidence
of detection accuracy on real restaurant footage.

Final-delivery regressions cancel both after rendering and during the second actual source
reconstruction. They also check cumulative historical-screening work, unchanged source
canonical bytes and no new authority commits. These complement the existing native tests
for diagnostic corruption, current privacy and original-source deletion.

```sh
cargo test -p fss-reference --lib ingest::qsr_observations
cargo test -p fss-reference --test package_zones_contract health::qsr
cargo test -p fss-cli --bin fss-event qsr::tests
```

The machine projection is defined in
[`qsr_observation_report.v1.json`](../schemas/qsr_observation_report.v1.json).
The observation definitions and limits are registered in
[`QSR_OBSERVATIONS.md`](../registries/QSR_OBSERVATIONS.md).
