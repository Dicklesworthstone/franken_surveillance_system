# QSR observations from retained detector tracks

`fss query --target qsr` and `fss-event qsr` turn an existing, retained, historically screened package-zone
report into sampled zone counts and presence, sampled dwell, and ordered lane-stage
endpoint observations. It reopens the native source evidence before answering.
It does not run a second detector or tracker, acquire a camera stream, publish a
security event, retain a new QSR object, or grant an effect capability.

This is an unqualified reference implementation for VIT-012. Its output counts
confirmed model-track observations. It does not measure detector quality, count
unique physical people, certify an empty scene or infer customer service.
The canonical query uses the existing `fss/1` AOP-005 response contract. Queue wait, door-open state, POS joins and cross-camera
lane journeys still require their own evidence and qualified interpretations.

## Canonical CLI and MCP query

Use the canonical query when a read must coexist with an active deployment writer
and leave every deployment file unchanged. It reads the current authority and effect
journals without recovery, verifies the exact retained source through one immutable
owner, and returns the complete sampled observations with the deployment's protected
knowledge, contradictions and unresolved obligations. It performs no model inference.

The selected digest is a retained, historically screened
`fss.package_zone_report.v2`, created and retained through the workflow below.
Source verification reads original encoded evidence internally, so the local operator
must explicitly enable it. It grants no media disclosure or effect capability.

```sh
fss query --target qsr --json \
  --root /absolute/path/to/existing/deployment \
  --principal principal:restaurant-operator \
  --report-digest sha256:RETAINED_SCREENED_ZONE_REPORT \
  --verify-qsr-source=yes \
  --zone-roles '[{"zone":"counter_queue","role":"queue"},{"zone":"register_2","role":"register"}]'
```

For an ordered lane, use `--lane-stages '["order_point","pay_window","present_window"]'`.
Lane roles are inferred from this ordered list; do not also assign those zones an
area, queue or register role. All annotations must name existing source zones.
An optional `--anchor` pins the current authority/effect-history token returned by
an earlier query. A changed head refuses that request.

For MCP, the launcher binds the deployment and principal and grants QSR verification
separately from recorder replay verification:

```sh
fss-mcp --root /absolute/path/to/existing/deployment \
  --principal principal:restaurant-operator \
  --allow-qsr-source-verification
```

After the standard MCP initialization handshake, call the existing `query` tool:

```json
{
  "target": "qsr",
  "report_digest": "sha256:RETAINED_SCREENED_ZONE_REPORT",
  "zone_roles": [{"zone": "counter_queue", "role": "queue"}]
}
```

Clients cannot change the bound root/principal, enable source verification, request
media hydration, select a loose file, or use historical/continuation selectors.
The native result is preserved as complete named JSON values in the existing
`AgentCognitiveEnvelope.v1` propositions, inside `AgentResponseEnvelope.v1`.
Each `claim:qsr:<section>:<ordinal>` preserves one exact native array row; non-array
sections and empty arrays use `claim:qsr:<section>`. The native QSR digest and
source/provenance handles remain explicit. Unknown samples are never converted to
zero, and all selected rows must fit the 256 KiB complete response or it refuses.

The default cumulative allowance is 1 GiB of payload reads and 1,000,000 read
attempts, including final source and authority revalidation. CLI options
`--max-query-read-bytes` and `--max-query-read-objects` can select smaller bounds
or increase them to at most 4 GiB and 4,000,000 attempts. MCP uses the corresponding
`max_query_read_bytes` and `max_query_read_objects` keys with canonical decimal
strings. These measure payload reads, not filesystem syscall counts. The
60-second deadline is cooperative; CPU time and full output tokens are unmetered.

## Native fss-event read

The command opens an established deployment without running effect reconciliation.
Prepared, committed and indeterminate effects keep their exact journal state;
reading a QSR report cannot stand in for recovery of an interrupted dispatch.
Missing deployments, missing journals and foreign site identities are refused.
The existing exclusive deployment lock and local publisher recovery still apply,
so recovery metadata may change. This is not an immutable `fss/1` query surface or
a promise of an unchanged filesystem.

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

The native `fss-event qsr` command uses `QsrObservationReport::open_existing`, which keeps its deployment
handle inside the reference owner. API callers with nonstandard deployment capacities
use `open_existing_with_limits` and supply the exact original limits; layout v1 retains
only their digest, so the values cannot be inferred. The CLI uses standard capacities
and refuses a different persisted digest.

Callers that already own a deployment may continue to use `QsrObservationReport::open`.
The canonical bridge instead uses `QsrObservationReport::open_retained` with an
`ImmutableRetainedSource` and finishes that same owner's final revalidation before
returning. All constructors select an exact retained report through `PackageZoneReport::open`,
which rechecks source custody,
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

Existing-store regressions seed prepared, committed and indeterminate operations with
pending obligations, then compare both journal files exactly across successful, refused
and cancelled reads. Actual `fss-event` process cases check the same boundary and exact
native JSON output. The API cases also cover custom capacity identities, foreign contexts,
missing journals and continued local publisher recovery. These added cases are authored
and source-reviewed; native execution is pending at this implementation checkpoint.

```sh
cargo test -p fss-reference --test qsr_observations_existing_contract
cargo test -p fss-cli --test qsr_cli_contract
cargo test -p fss-reference --lib ingest::qsr_observations
cargo test -p fss-reference --test package_zones_contract health::qsr
cargo test -p fss-cli --bin fss-event qsr::tests
cargo test --locked --offline -p fss-reference --test qsr_observations_immutable_contract --test agent_qsr_contract
cargo test --locked --offline -p fss-cli --test qsr_query_cli_contract
cargo test --locked --offline -p fss-cli --bin fss-mcp qsr
```

The machine projection is defined in
[`qsr_observation_report.v1.json`](../schemas/qsr_observation_report.v1.json).
The observation definitions and limits are registered in
[`QSR_OBSERVATIONS.md`](../registries/QSR_OBSERVATIONS.md).
