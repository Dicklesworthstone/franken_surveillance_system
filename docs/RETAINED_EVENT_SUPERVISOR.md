# Supervise retained native detector evidence

`fss-event supervise --retained-plan` evaluates a bounded sequence of cumulative evidence windows
over current, published package events. It reopens the exact native detections assigned to those
events' local tracks, verifies retained source custody and current privacy/deletion restrictions,
and produces a complete read-only class-advice report. Original media, model files and exported
analysis files are not needed for this read.

The command accepts selectors and exact source pins. It does not accept detector scores from
the plan. An event's probability interval cannot substitute for an original detector score.
The native model was executed when `fss-infer package-detect --retain yes` produced the retained
detection. Supervision rebuilds the recorded tracker analysis and checks source provenance;
it does not execute the model again or independently qualify detector accuracy.

## Prepare the sources

Use the existing native package-event workflow:

1. Import authorized source media with `fss-file import`.
2. Run `fss-infer package-detect --retain yes` with the exact package archive pin. Its report
   contains package/model/head-contract digests, vocabulary, source capsules, conservative
   capture intervals and surviving detection rows.
3. Run `fss-event report --package-report DIGEST --label LABEL --report-out FILE` to construct
   the exact tracked analysis. Prepare and publish the chosen track through `fss-event prepare`
   and `fss-event publish` using their exact report and proposal pins.
4. Read each published event to obtain the exact native inputs available to the supervisor:

```sh
fss-event read \
  --root /absolute/deployment \
  --site site:home \
  --event-id event:EXACT_PUBLISHED_EVENT
```

Package-event reads include a `retained_supervisor_sources=` line whose value is a complete JSON
object. It lists the observed current authority state root, current event revision root, source
report/track identities, label, package/model/head-contract/class pins, and the native sensor,
capture interval and original score bits of each actually assigned detection. Each observation
contains a `selector` object that can be copied directly into a retained plan. This projection
uses the already verified native analysis and introduces no additional source reads. The complete
inventory is bounded by the existing `--max-report-bytes` allowance and is never truncated.

| Retained plan field | Value from the verified inventory |
| --- | --- |
| `site_lineage`, `expected_authority_root`, `label` | Same-named top-level inventory values |
| Camera `package_digest`, `model_digest`, `contract_digest`, `class_index` | Same-named top-level inventory values |
| Camera `sensor_id` | The selected observation's native `sensor_id` |
| Event `event_id`, `expected_event_root` | Same-named top-level inventory values |
| Window `observations[]` | Exact `observations[].selector` object |

Choose a camera alias and use it consistently in the camera and event rows. Failure domains,
calibration applicability, prior, severity, windows and limits remain explicit owner choices.
The inventory does not activate any of them. Its `expected_authority_root` is the observed
deployment head; the older `authority_sequence=` line remains the event's original publication
anchor. A later durable head change makes the copied plan stale and requires a fresh inventory.

Native API users can obtain the same bindings through `PackageEvent::open`, `root`, `report`,
`track`, `PackageAnalysisReport::retained`, and the selected `PackageTrack::observations`.

A capsule/row from another track, another sensor or another model cannot be borrowed. The
supervisor checks the complete assignment again, even when the detector report contains the row.
Current operator revisions outside the package-event policy are refused; the command cannot
silently substitute the event's earlier unresolved state.

## Run an explicit retained plan

```sh
sha256sum retained-supervisor.json

fss-event supervise \
  --root /absolute/deployment \
  --site site:home \
  --retained-plan retained-supervisor.json \
  --retained-digest sha256:EXACT_FILE_SHA256 \
  --report-out /absolute/exports/retained-supervisor-report.json
```

The digest covers the complete input bytes, including whitespace and any final newline. It is
checked before JSON parsing. The plan must be a regular file of at most 256 KiB. The deployment
must already exist, and its current authority state root must equal the requested root. The
optional report destination must be new and outside the deployment. The complete same JSON is
printed to stdout.

The following is a structural template. Replace every placeholder with the actual retained
identity and use explicit policy choices appropriate to the intended class question. Class
indices come from each pinned package's vocabulary.

```json
{
  "schema": "fss.retained_supervisor_plan.v1",
  "site_lineage": "site:home",
  "hypothesis_id": "hyp:class:person",
  "expected_authority_root": "sha256:CURRENT_AUTHORITY_STATE_ROOT",
  "label": "person",
  "start_ns": "1000000000",
  "cameras": [
    {
      "camera_id": "east",
      "sensor_id": "sensor:east",
      "package_digest": "sha256:EXACT_PACKAGE_ARCHIVE",
      "model_digest": "sha256:EXACT_NATIVE_MODEL",
      "contract_digest": "sha256:EXACT_DETECTION_HEAD_CONTRACT",
      "class_index": 0,
      "failure_domains": ["power:east-supply"],
      "calibration": null
    }
  ],
  "events": [
    {
      "camera_id": "east",
      "event_id": "event:EXACT_PUBLISHED_EVENT",
      "expected_event_root": "sha256:EXACT_CURRENT_EVENT_REVISION"
    }
  ],
  "windows": [
    {
      "window_index": 0,
      "end_ns": "2000000000",
      "observations": [
        {
          "event_id": "event:EXACT_PUBLISHED_EVENT",
          "capsule_digest": "sha256:EXACT_SOURCE_CAPSULE",
          "segment": 0,
          "detection_row": 7
        }
      ]
    },
    {
      "window_index": 1,
      "end_ns": "3000000000",
      "observations": []
    }
  ],
  "prior": [0, 0],
  "policy": {
    "generation": "policy:class-review:v1",
    "alert_threshold": 1800,
    "retain_threshold": 0,
    "reject_threshold": -1000,
    "min_independent_support": 2,
    "urgent_single_domain_threshold": null,
    "max_wait_ns": 0,
    "look_penalty_per_doubling": 0,
    "operator_confirmation_available": false
  },
  "severity": {
    "expected_harm": 10000,
    "false_alert_cost": 500,
    "delay_cost_per_second": 100,
    "reversible": false
  },
  "limits": {
    "max_read_bytes": 134217728,
    "max_read_attempts": 8192,
    "max_journal_bytes": 16777216,
    "max_report_bytes": 2097152
  }
}
```

Every field in the template is required. `calibration` is explicitly either `null` or the existing
`fss.score_calibration.v1` count-calibration object. Unknown fields, duplicate keys, duplicate
camera aliases/sensors, unused event pins and duplicate selections within one window are refused.
Exact integer values may be JSON integers or canonical decimal strings; fractional/exponential
values cannot stand in for integer identities, times or limits.

One camera is admitted for honest single-sensor advice. The policy must still require at least
two independent supporting domains. Selecting two cameras running the same native model does
not manufacture independence.

## Time, repetition and missing observations

`start_ns` and each `end_ns` are evidence-clock coordinates, not elapsed execution time or wall
clock arrival times. Window indices are consecutive from zero and end times strictly increase.
The complete conservative capture interval of every selected source must fit inside
`[start_ns, end_ns]` when it is first selected.

The supervisor reopens each selected original capsule and binds its actual clock basis. It
admits UTC or estimated bases only, with a common original basis across selected observations.
Unmapped device or host-monotonic clocks and mixed bases are refused. Each native observation
retains its `clock_basis` and original import `capture_time_label`; the report explicitly says
`clock_synchronization: "not_established"`. A broad unknown estimated interval such as
`[0, receive_time]` is never upgraded into synchronized UTC or precise capture time.

Each window evaluates the union of unique native detections selected so far. A later window can
add selections, repeat earlier selections, or contain an empty array. Repeating a source row
does not add another likelihood increment; omitting it later does not remove it. This is a finite
cumulative analysis, not a sliding expiry policy or a persistent live monitoring service.

Each window retains the exact selection-to-observation links, the number of new and unique
observations, and cameras without new selections. Missing evidence remains explicitly not
observable or uncalibrated. The query has a coverage gap: selected class detections cannot
establish detector-class absence, a healthy camera interval or uninterrupted acquisition.

## Calibration, common causes and effects

With `calibration: null`, the command reports exact native scores while preserving their lack
of numeric calibration authority. To request calibrated advice, supply the existing count table
for each sensor. The parser independently reconstructs the table's digest and all supplied
derived values. Applicability is an owner assertion for this exact retained plan, not deployment
calibration activation or a statistical qualification certificate.

The shared fusion implementation converts each original `f32` score into outward ppm bounds.
When those bounds cross a calibration-bin edge, both bins contribute to the likelihood-interval
hull. The prior and consequence assumptions remain separate explicit inputs.

Intrinsic native source, model and calibration dependencies are preserved. Additional declared
failure domains can reduce independence; aliases, new event IDs, repeated windows or renamed
generations cannot increase it. Every window includes the existing complete fusion query and
outcome, with shared-cause clusters, exclusions and counterfactuals.

The report always includes `effects_authorized: false`, `supports_absence_claim: false`, and
`anytime_bound_verified: false`. Its class advice does not change event taxonomy or state,
establish a physical actor's identity, associate tracks across cameras, prove zone entry, or
authorize an alert. Prepared event/effect operations remain separate owners. There is no
sequential likelihood accumulator or claimed Ville guarantee in retained mode.

## Read accounting and current authority

The read allowance is shared across all selected events and all nested object reads after
existing deployment owners have opened. It does not refill for a new event or window. The byte
counter reserves stored object envelopes, including their headers and a bounded EOF probe;
it is conservative read accounting, not a measurement of total physical storage traffic.
Failed reads spend attempts and reservations too. Metadata, privacy, deletion and original-source
objects read through the same spool remain under the allowance.

Opening/recovery, filesystem metadata operations and journal observations are separate from
that object allowance. `max_journal_bytes` bounds each journal in each of the two fresh authority
observations. The report records the exact observed authority sequence/state, ledger root and
effect root. A durable head change during analysis refuses the complete result. An unchanged
head observation is not a lock against a future change after the response.

Hard collection ceilings are 8 cameras, 32 events, 32 windows, 128 unique detections and 512
total selectors, including repeats. Complete output is capped at 2 MiB and at the requested
smaller report bound. Capacity, source, privacy, cancellation and authority refusals produce no
partial successful advice. Clean read/retry runs append no events, source publications or
effects; opening existing owners retains their established recovery behavior.

If a later privacy revision makes the retained computation inapplicable, the source reader
refuses it. A committed deletion denies access even before every underlying byte has been
unlinked. Missing or corrupt evidence is never repaired from loose files by this command.

## Legacy simulation and verification scope

`fss-event supervise --plan FILE` keeps the existing `fss.supervisor_plan.v1` simulation. Its
scores, evidence identifiers, health and coverage are caller supplied. The report preserves
its existing schema and numeric fields while adding `observation_basis: "caller_supplied_simulation"`,
`source_custody_verified: false`, `effects_authorized: false`, `anytime_bound_verified: false`
and the explicit statistical assumption. Numeric Ville formula values do not establish a
valid anytime false-alarm bound for arbitrary scores or floor-clamped repeated observations.

Focused contracts are in `supervisor_retained_contract`, the retained input unit tests, the
shared spool read-budget tests, and the existing package-event reader contracts. The fresh
process cases exercise real native package retention/publication, CLI inventory-to-plan binding,
exact original score bits and clock labels, cold deterministic retries, shared causes, repeated
evidence, missing camera coverage, source/time/package substitution, resource refusals, corrupt
custody, current masks and actual import deletion. These fixtures make no detector-quality or
complete NS-1 qualification claim.
