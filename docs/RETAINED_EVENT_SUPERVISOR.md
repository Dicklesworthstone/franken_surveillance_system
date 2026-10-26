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

## Discover and supervise published events automatically

Use `--discover-plan` when the deployment already contains published package events and you want
the system to find their exact native rows. Configure the cameras, source generations, class,
capture windows, calibration, policy and limits once. Discovery reads the bounded current event
catalog, verifies relevant package events, builds the exact selection plan and immediately runs
the same retained supervisor.

The request is a strict wrapper around the existing plan schema:

```json
{
  "schema": "fss.retained_supervisor_discovery.v1",
  "maximum_catalog_events": 256,
  "plan": {
    "schema": "fss.retained_supervisor_plan.v1",
    "site_lineage": "site:home",
    "hypothesis_id": "hyp:class:person",
    "expected_authority_root": "sha256:CURRENT_AUTHORITY_STATE_ROOT",
    "label": "person",
    "start_ns": "0",
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
    "events": [],
    "windows": [
      {"window_index": 0, "end_ns": "2000000000", "observations": []},
      {"window_index": 1, "end_ns": "3000000000", "observations": []}
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
}
```

Replace the identity placeholders using the pinned package and current deployment inventory, as
for an explicit retained plan. The request contains no event IDs, capsule IDs, detection rows or
supplied scores: `plan.events` and every window's `observations` must be empty. All ordinary plan
fields remain required and use the same parser and validation. The complete wrapper, including
whitespace, is capped at 256 KiB and pinned before parsing.

```sh
sha256sum discover-supervisor.json

fss-event supervise \
  --root /absolute/deployment \
  --site site:home \
  --discover-plan discover-supervisor.json \
  --discover-digest sha256:EXACT_FILE_SHA256 \
  --report-out /absolute/exports/discovered-supervisor-report.json
```

Discovery and explicit selection are mutually exclusive modes. The command requires an existing
deployment and the exact requested authority head. It neither imports media, runs the detector,
publishes new events nor activates an alert.

Discovery assigns each verified detection to the first window containing its complete conservative
capture interval. Later windows retain cumulative evidence without selecting the same row again.
A configured camera with no selected detection remains explicitly unobservable. An empty selection
does not establish class absence, healthy acquisition or complete coverage.

The `fss.retained_supervisor_discovery_report.v1` output contains:

- `selected_plan`: a complete executable `fss.retained_supervisor_plan.v1`, including verified
  event roots and exact source-row selectors;
- `supervision`: the ordinary retained supervisor report with original scores, clocks, full
  fusion queries/outcomes and shared-cause accounting;
- `discovery`: bounded catalog, metadata, source-opening and selection counts, plus explicit
  exclusions carrying the affected event/root and source-verification status;
- `read_usage`: discovery and supervision costs under the same nonrefillable object allowance;
- a receipt binding the complete result, including exclusions and selected plan.

For a configured sensor in the requested interval, source custody and current privacy/deletion
restrictions are checked before package, model, head-contract, class or label mismatch exclusions.
A mismatched generation remains explicitly excluded; it cannot hide a private, deleted or corrupt
targeted source. Metadata-only exclusions outside the requested sensor/time scope are labeled
`source_verified: false`.

`maximum_catalog_events` admits 1 through 4096 current events. A separate 65536-object hard ceiling
bounds catalog enumeration. Exceeding a catalog, source-read, selection, exclusion or complete-output
bound refuses the whole operation; discovery never silently truncates the event set. Its output
ceiling applies to the entire wrapper, including the executable selected plan. Opening/recovery and
filesystem metadata retain their existing separate accounting; the report names the three fresh
journal observations used by discovery and supervision together. Metadata authority-history scans
also have a separate conservative work ceiling exposed in the discovery accounting.

An exported `selected_plan` can be pinned and run through `--retained-plan` while its authority
head remains current. It reproduces the native evidence and window answers. Its read-accounting
receipt differs because an explicit run does not repeat catalog discovery. A cold retry of the
same discovery request at the same unchanged deployment produces the same complete result.
This is bounded discovery over already published evidence, not a persistent live subscription.

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

## Revalidating a historical discovery result

The library exposes the complete sorted source inventory of a discovery report through
`RetainedDiscoveryReport::source_inventory()`. It includes every metadata-read package event:
selected events, generation-excluded native sources, and sensor/time exclusions that were checked
only as metadata. Each entry retains its exact event revision and original verification class.

`revalidate_retained_discovery_sources` checks that inventory against an explicitly selected
current authority root. Metadata-only entries must still have their original verified revision.
Every originally native-verified entry goes through the native package reader again, including
sources excluded because their package/model/head did not match the requested generation. Current
privacy, deletion, missing custody and corruption therefore still apply to historical disclosure.

The validation brackets these reads with fresh bounded ledger/effect history, uses one shared
nonrefillable stored-object allowance, and returns a receipt with its consumed read costs. Its
output explicitly says `complete_current_catalog: false`: newly arrived events require a fresh
discovery. Revalidating old evidence does not add another likelihood increment or turn an old
report into a new current-state conclusion. The caller must retain the original report-to-inventory
binding; a supplied subset is not proof of a complete original inventory.

`RetainedDiscoveryRequest::for_authority(root)` changes only the explicitly supplied expected
authority root. It preserves the finite windows, cameras, model pins, calibration, policy and
limits, and grants no session or source access by itself.

## Durable polling with an existing session

Session supervision adds restart-safe delivery to discovery. Open a session through the existing
agent interface, then select a stable session-local subscription label:

```sh
fss session open --json \
  --root /absolute/deployment \
  --principal principal:local-operator \
  --mission "Review retained native detector evidence" \
  --objective "Preserve source verification and exact delivery progress" \
  --view brief --budget-tokens 100000

fss-event supervise \
  --root /absolute/deployment --site site:home \
  --discover-plan discover-supervisor.json \
  --discover-digest sha256:EXACT_FILE_SHA256 \
  --session session:ID_FROM_SESSION_OPEN \
  --subscription retained-person-review \
  --authority-root sha256:CURRENT_AUTHORITY_STATE_ROOT \
  --max-poll-attempts 16
```

Keep the exact original discovery file and its digest for every command on that subscription.
The registration freezes its bytes, camera/model/calibration/policy choices, finite capture
windows, source-read caps, report bound and lifetime attempt ceiling. The separate
`--authority-root` explicitly selects the current deployment head for each invocation; it
does not edit the registered template. A changed interpretation generation requires an explicit
fresh session. Changing a subscription's configuration or increasing its allowance is refused.

A first poll performs complete current discovery and native supervision. It stores the complete
report, original authority, exact metadata/native source inventory and delivery receipt in the
existing session journal before releasing output. The `fss.retained_supervisor_session_report.v1`
envelope includes the embedded `report`, its exact `payload_digest`, and a `delivery_receipt`.

While a delivery remains pending, another poll revalidates every original source under the
explicit current authority, then returns the original report bytes and delivery receipt.
The envelope keeps `report_authority_root` separate from `current_authority_root` and
`source_validation`. New events are not spliced into that historical report. Metadata-only
exclusions retain their original verification class; sources previously opened natively,
including generation exclusions, must pass native privacy, deletion and custody checks again.

Acknowledge the exact receipt in a separate invocation using the same registration arguments:

```sh
fss-event supervise \
  --root /absolute/deployment --site site:home \
  --discover-plan discover-supervisor.json \
  --discover-digest sha256:EXACT_FILE_SHA256 \
  --session session:ID_FROM_SESSION_OPEN \
  --subscription retained-person-review \
  --authority-root sha256:CURRENT_AUTHORITY_STATE_ROOT \
  --max-poll-attempts 16 \
  --acknowledge sha256:EXACT_DELIVERY_RECEIPT
```

To recover a lost response, repeat the same registration arguments with `--inspect yes`.
Inspection requires an already registered subscription and the same live session, immutable
configuration and explicit current authority. Its `state: "inspected"` response exposes
`pending_receipt`, `last_acknowledged`, `last_discarded`, historical report digests and cumulative
budget counters, with `report: null` and no current source-validation assertion. It performs no
native source-object reads and consumes no new attempt, so it works after source deletion or
attempt exhaustion. An unknown subscription is refused without registration. Existing bounded
journal recovery and live session-clock admission still apply; inspection is not a way to
retrieve old payloads or bypass current source checks.

A new ACK first revalidates the pending report's sources, then consumes only that exact delivery.
Repeating the most recent committed ACK is idempotent and does not consume a newer pending
report. ACK returns no report and performs no successor evaluation. A subsequent poll recomputes
the entire active scope from unique source observations; previous scores are never added again.
Without explicit scheduling, the active scope remains all configured windows.

Use `--discard sha256:EXACT_DELIVERY_RECEIPT` instead of `--acknowledge` to abandon an
unavailable or unwanted pending report explicitly. Discard requires the live owning session and
current authority but no native source reads. It records `discarded`, never `acknowledged`,
and releases no old report bytes. An exact last-discard retry also preserves any successor.

### Discover work after losing the conversation or recipe

An existing live session can discover all its subscriptions without knowing a label or retaining
the discovery file:

```bash
fss-event supervise --root /path/to/deployment --site site:example \
  --principal principal:local-operator --session session:EXISTING \
  --authority-root sha256:CURRENT_DEPLOYMENT_ROOT --list yes
```

The complete `fss.retained_supervisor_inventory.v1` response lists subscriptions in label order.
It includes pending delivery and report receipts, original report anchors, unfinished charged
reservations, schedule progress and terminal receipts, immutable limits, and every lifetime
charge. `attempts_remaining` is the original ceiling minus reserved attempts; failed or interrupted
work is never refunded. The report can be exported with `--report-out FILE`. Other plan, subscription
and action flags cannot be mixed with `--list`.

Listing verifies the current deployment root, the live session owner and the existing supervision
capability/privacy gates, then replays the complete pinned session journal. It reserves no native
attempt and exposes no configuration bytes, report bytes, source identities or source inventory.
It remains useful when native sources have disappeared or the lifetime attempt budget is exhausted.
Historical authority and generation mismatches are explicit metadata, not permission to reuse the
old report. Session clock/expiry observations and root-pin recovery retain their existing durable
semantics. Use a returned label with `--resume yes` for a separately admitted operation.

Session open retries, handoff and resume also discover this work. Their situations retain protected
summaries of pending receipts, schedule position, unfinished reservations and spent budgets; a view
that cannot hold protected context refuses rather than silently dropping it. Handoff task identities
name the subscriptions, and their recovery affordance expands the complete current metadata. The
sealed situation fingerprint binds the exact retained state without copying private report bytes.
Current supervision state changes the situation fingerprint even when the evidence anchor has not
moved. Resume publishes one workspace advance when that fingerprint changes; an identical retry
reuses it. A changed sealed handoff is explicitly distinguished from the evidence-only delta, so it
cannot produce a false unchanged/silence claim. Listing or handing off work does not acknowledge it,
advance its schedule, validate its sources or authorize an effect.

### Resume without the original plan file

An existing subscription retains the exact discovery configuration bytes and their SHA-256,
source/report ceilings and lifetime attempt allowance in its session journal. Use those stored
values when the external plan file is unavailable:

```sh
fss-event supervise \
  --root /absolute/deployment --site site:home \
  --principal principal:local-operator \
  --session session:ID_FROM_SESSION_OPEN \
  --subscription retained-person-review \
  --authority-root sha256:CURRENT_AUTHORITY_STATE_ROOT \
  --resume yes
```

Without an action flag, this polls the existing subscription. Add `--inspect yes` to recover its
pending receipt and counters without releasing report bytes or spending another native attempt.
The same mode accepts an exact `--acknowledge` or `--discard`, or a scheduled
`--advance-window INDEX --after-receipt RECEIPT` operation.

Do not supply `--discover-plan`, `--discover-digest`, retained/legacy plan flags,
`--max-poll-attempts` or `--schedule` with `--resume`. These combinations are refused. Recovery
uses the original bytes and allowance; it does not rewrite the configuration, recreate a missing
subscription, activate a schedule, refresh a lease or reset consumed work. The session, subscription
and explicit current authority root remain required.

Configuration recovery goes through the live admitted session owner, its exclusive journal and
root pin, and current history checks. The actual action opens the owner again and requires that
the exact registration still exists. Recovery itself performs no native source-object reads and
does not expose the stored pending payload. A resumed pending poll or new ACK still revalidates
the original source inventory under current privacy, deletion and custody restrictions. Inspection
and explicit discard remain available after native attempt exhaustion, subject to the same live
session authority.

### Advance through an immutable cumulative schedule

Before its first source attempt, opt a new subscription into its exact predeclared schedule:

```sh
fss-event supervise \
  --root /absolute/deployment --site site:home \
  --discover-plan discover-supervisor.json \
  --discover-digest sha256:EXACT_FILE_SHA256 \
  --session session:ID_FROM_SESSION_OPEN \
  --subscription retained-person-schedule \
  --authority-root sha256:CURRENT_AUTHORITY_STATE_ROOT \
  --max-poll-attempts 16 \
  --schedule yes
```

The original file declares 1 through 32 cumulative windows. Registration and schedule admission
commit atomically, with only window index `0` active (`active_window_count: 1`). Configuration
returns status only; run a separate ordinary poll with the same arguments and no action flag.
An existing exact registration can opt in only before its first attempt. Repeating an already
configured schedule preserves its current prefix, pending report and lifetime charges.

After that prefix's report is acknowledged or explicitly discarded, activate the next window:

```sh
fss-event supervise \
  --root /absolute/deployment --site site:home \
  --discover-plan discover-supervisor.json \
  --discover-digest sha256:EXACT_FILE_SHA256 \
  --session session:ID_FROM_SESSION_OPEN \
  --subscription retained-person-schedule \
  --authority-root sha256:CURRENT_AUTHORITY_STATE_ROOT \
  --max-poll-attempts 16 \
  --advance-window 1 \
  --after-receipt sha256:EXACT_ACKNOWLEDGED_OR_DISCARDED_DELIVERY_RECEIPT
```

`--advance-window` uses the next **zero-based** index. It requires the exact terminal delivery
receipt for the current prefix. Pending reports block advancement; skipping, rewinding and
changing the original endpoints or policy are refused. A new publication clears the previous
terminal permission until that new delivery is ACKed or discarded. Retrying the latest exact
advance preserves any successor pending report; an older advance cannot rewind later progress.
Advancement returns status only, and the next ordinary poll is separate.

Each poll reconstructs all windows in the active prefix from original native observations,
preserving the starting time, window indices, prior, calibration and unique-source accounting.
Historical pending reports retain their original prefix and bytes during current source
revalidation. The session envelope and `--inspect yes` expose `active_window_index`,
`active_window_count`, `total_windows`, `active_end_ns`, `report_window_count`, the current
terminal receipt and the latest advance receipt. `all_windows_active` identifies schedule
progress only; it establishes no acquisition completion or coverage.

Schedule changes never reset attempts or read charges. If a failed repeat after a terminal
delivery leaves a reserved attempt, an explicit valid advance may abandon that attempt without
refund. Discard remains an explicit invalidation, never an ACK. No clock chooses a new endpoint,
and advancing a requested capture bound creates no absence, synchronized-time or effect claim.

### Persistent work accounting and recovery

`--max-poll-attempts` is a finite lifetime ceiling from 1 through 64. Before a fresh native
evaluation, pending redelivery validation or new ACK validation, the owner durably reserves one
attempt and the **full** registered `max_read_bytes` and `max_read_attempts` caps. It pins
that journal change before source work begins. Failed work, cancellation and process crashes do
not refund the reservation. The envelope exposes cumulative `attempts_reserved`,
`reserved_bytes` and `reserved_read_attempts`; separate source validation records measured
read consumption. These counters do not include opening/recovery or filesystem metadata.

Inspection, schedule configuration/advancement, an exact already-committed ACK retry and an
explicit discard need no new source attempt. Choose a ceiling that leaves room to validate and
acknowledge delivered reports: with a ceiling of one,
the initial evaluation can succeed but a new source-validating ACK cannot. Discard remains
available after that allowance is exhausted, and it does not reset the allowance.

The existing exclusive session writer, crash-classifying journal, root pin and evidence clock
own this state under `agent/sessions`. No loose cursor file, source publication or effect record
is created. Register, configure schedule, advance, reserve, publish, release, ACK and discard are
canonical bounded commands re-executed during recovery. Torn/uncertain appends retain the existing reconciliation behavior;
a failed response may follow committed progress and must not be interpreted as rollback.
Older readers refuse the new journal record kind instead of silently dropping delivery progress.
Schedule commands add distinct tags within that record kind; older readers also refuse unknown
tags. Existing unscheduled command bytes, state digests and delivery receipts remain unchanged.

Pending payloads are private historical cognition. Inspection exposes descriptors and counters,
not a raw-payload accessor; the journal and its backups require the existing protected agent
storage. Every historical release uses current native source checks, so committed source
deletion or privacy changes can block it even while its pending descriptor remains durable.
The complete output stays within the registered report bound and 2 MiB hard ceiling, with
16 KiB reserved for its session envelope. The same strict output parser admits a fresh report
before publication and on redelivery; ordinary operator-input parser limits remain unchanged.

Each invocation performs one finite inspection, schedule configuration, advance, poll, ACK or
discard. This interface has no background timer or automatic window advancement. It does not
establish persistent statistical exposure accounting, qualified
calibration, class absence, cross-camera physical identity or effect authorization.

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
custody, current masks and actual import deletion. Discovery contracts additionally verify automatic
catalog-to-plan selection, executable explicit replay, first-enclosing capture windows, missing
cameras, explicit generation exclusions, shared discovery/supervision budgets and exact cold retries.
Durable-session contracts additionally exercise cold redelivery and exact ACK/discard, unrelated
authority advancement, current deletion of an originally native-verified generation exclusion,
nonrefillable lifetime attempts, receipt recovery without source reads after exhaustion/deletion,
and unchanged canonical source/effect inventories. Journal unit
contracts inject all four real append crash phases for reservation, publication, release and ACK,
then reopen and recover exact pending state. Schedule contracts exercise atomic configuration
and advancement at all four crash phases, exact terminal-receipt retries, preserved successor
reports, cumulative native prefixes and exhausted lifetime allowances after cold recovery.
Recovery contracts delete the external configuration file, recover the original pending report
and schedule in fresh processes, preserve exhausted allowances, refuse foreign or replacement
scope, and recheck actual source deletion before resumed delivery or ACK. Frozen legacy command
and state vectors check unscheduled compatibility. These fixtures make
no detector-quality or complete NS-1 qualification claim.
