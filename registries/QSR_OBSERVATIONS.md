# QSR observation vocabulary

These are derived read views over one exact retained
`fss.package_zone_report.v2`, exposed by `fss-event qsr`. They are separate from
security `EventKind` hypotheses. Reading them creates no event, retained object,
rights lease, notification, device action or assertion about a physical person.

The source owner must cold-reopen the retained report and verify its original
model/tracker evidence, complete historical screening assessment, source custody,
current privacy policy and deletion state. A missing or refused source produces
a typed refusal. It never becomes a successful zero count.

## Registered observations

| ID | Observation | Supporting evidence and exact meaning | Limit |
|---|---|---|---|
| `QSR-OBS-COUNT-001` | Observed track count in a zone | For one source frame, count actual confirmed assignments of the source report's selected model class whose complete unclipped boxes lie strictly inside the existing zone. Report supporting analysis-local track digests and excluded tentative, boundary, partial and unobserved rows. | A queue role annotates the region; the count is not a calibrated physical queue length, detector recall claim or unique-customer count. |
| `QSR-OBS-PRESENCE-001` | Sampled presence in an area, queue or register zone | `observed` means at least one supporting confirmed track. `not_observed` means none was observed in that admitted sample. Masked or historically unsupported samples are `unknown` with a null count. | `not_observed` never certifies absence, an empty scene, an unused register, a transaction or lack of service. |
| `QSR-OBS-DWELL-001` | Source-sampled zone dwell | Project an existing source-owner `sampled_dwell` event with its exact supporting track, source frames, capture bounds and minimum/maximum duration. Recheck that every supporting sample remains confirmed, inside, unclipped, time-reliable and historically supported. | The source maximum-sample-gap policy remains in force. This is sampled track dwell, not continuous occupancy, waiting time, door state or door-open duration. |
| `QSR-OBS-LANE-STAGE-001` | Adjacent ordered lane-stage observations | For one analysis-local track, follow explicitly ordered existing stage zones. Two unambiguous adjacent stage observations support conservative lower/upper bounds on their observed endpoint separation. Each transition retains its source-frame endpoints. | No inferred crossing time, queue wait, order/payment/presentation action, service duration, physical identity or complete vehicle trip is certified. |

## Roles and source scope

`area`, `queue`, `register` and `lane_stage` are operator annotations on existing
source-zone IDs. They do not modify polygons, detector classes or tracking
policy. Unannotated source zones default to `area`. Role declarations are unique
and normalized to source-zone order. A lane has either no stages or two through
sixteen distinct existing stages in the explicitly requested order; conflicting
roles and unknown zones refuse.

Reports cover the source report's finite sample only: at most sixteen zones and
sixty-four source frames. Observed counts concern the selected model class, which
is exposed with its label, class index, package digest, model ID/generation and
detector/tracker policy roots. Track identities are scoped to that analysis and
must not be treated as stable identities of people or vehicles across reports.

## Uncertainty and continuity

A complete report includes one row for every source-zone/frame pair, including
unknown and zero-observation rows. Zone summaries preserve supported and unknown
sample counts separately. A maximum observed count is null when no sample was
admitted. Neither a summary nor an empty track inventory supplies an absence
certificate or continuous-coverage witness.

An in-progress lane sequence is interrupted by a source boundary, a source gap
beyond the existing maximum, unavailable or unreliable time, historical health
exclusions, a masked stage, missing/tentative/clipped observations, overlapping
stage membership, or reversed/skipped stages. Interruptions retain a typed reason
and supporting frame coordinates. Later observed stages can begin a new bounded
sequence; they do not repair the interrupted one.

The observation schema carries exact source report/provenance digests, current
privacy binding, retained authority/health references, complete frame/capture
coordinates and explicit false absence, continuous-coverage, current-camera-
health and detection-quality claims. The existing source health screen is a
finite historical observation, not evidence of current camera availability.

## Identity and compatibility

`fss.qsr_observation_report.v1` is a bounded read-result encoding. Its canonical
identity binds the exact retained source report/provenance root, reducer policy,
normalized configuration and every complete output row. Configuration has the
separate `fss.qsr_observation_config.v1` domain. The immutable
`QSR_OBSERVATION_POLICY` string describes reducer semantics and has its own
reported digest; it grants no model or authority generation.

Changed source evidence, roles, lane order or reducer policy requires a different
identity. Complete bounded JSON is returned or the read refuses; no truncated
success, predicted missing observation, synthetic detector output or fallback
source is admitted. Read-only result bytes do not constitute a durable retention
promise or an authenticated receipt from a physical camera.

See [the operator workflow](../docs/QSR_OBSERVATIONS.md) and
[the report schema](../schemas/qsr_observation_report.v1.json).
