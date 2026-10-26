# Supervise native detector records before a tracked event exists

`fss-event supervise --detection-plan` reads retained native detector computations directly.
An actual detector row can contribute class advice even when it comes from one stationary
frame or a short sentinel burst that has no confirmed track and no published event.

Ordinary retained package detection, long-recording sentinel analysis and RTSP campaign
sentinel analysis already publish the same `package_detection_record` children. This command
opens those children through their existing custody owner. The original loose media, model
archive and exported JSON files are unnecessary once that custody is retained.

## Prepare a finite request

Use the camera, class, calibration, prior, policy, time-window and read-limit template described
in [retained event supervision](RETAINED_EVENT_SUPERVISOR.md). The nested plan retains schema
`fss.retained_supervisor_plan.v1`, an empty `events` array and empty `observations` arrays in
every window. The direct detector wrapper has exactly three fields:

| Field | Value |
| --- | --- |
| `schema` | `fss.retained_detection_discovery.v1` |
| `maximum_catalog_reports` | An explicit integer from 1 through 4096. |
| `plan` | The complete validated empty-selection native supervisor plan. |

The wrapper differs from event discovery. Its exact bytes need their own SHA-256 pin:

```sh
fss-event supervise \
  --root /owner/deployment --site site:home \
  --detection-plan /owner/detection-plan.json \
  --detection-digest sha256:EXACT_FILE_DIGEST
```

Supply the current deployment authority root inside the nested plan. The owner must explicitly
choose each sensor, native package/model/head contract, class, any calibration applicability,
prior and policy. No detector score, physical identity, coverage assertion or camera-health
override is accepted from the request. One camera is permitted; class advice still requires the
configured minimum of at least two independent supporting domains for corroboration.

This finite invocation has no background timer or automatic event publication. It returns a
complete report or a refusal. `--report-out FILE` uses the ordinary guarded report export.

## Native discovery and cumulative evidence

Discovery inventories current canonical detector records and their exact root-last
publications under bounded catalog and history work. Sensor/time exclusions preserve their
metadata verification class. Every report relevant to the requested sensor and time scope is
opened through `RetainedPackageDetection` before package, model, head or class filtering.
A generation mismatch cannot hide corrupt source custody or bypass current privacy or deletion.

Each actual matching row enters the first cumulative window containing its complete original
capture interval. The report preserves source clock basis and the original capture-time label;
an estimated interval never becomes synchronized UTC. Overlapping detector reports retain all
selection provenance while the same native source row contributes evidence only once.

The report schema is `fss.retained_detection_discovery_report.v1`. It includes exact report,
record and detection-root identities, native score bits and outward-rounded score intervals,
inference/output/head references, complete cumulative fusion queries, outcomes, dependency
clusters and counterfactuals. Shared model, package, head and calibration causes remain shared
even when camera aliases or report boundaries differ.

An empty class result is an observed computation with no selected class row. It does not prove
absence, complete sampling, a quiet scene or a healthy camera. Unsampled sentinel time and
unrelated frames do not acquire negative evidential weight. The command establishes no track,
cross-camera actor association, zone entry, alert authority or anytime false-alarm guarantee.

## Withhold support from diagnosed sources

Before fusion, the supervisor reads one bounded current historical-health catalog. Each selected
row is assessed against exact import identity/root, sensor, source segment and current verified
privacy interpretation. The output distinguishes unknown diagnostic coverage, a finite screen
without findings, incomplete screening and retained findings.

A matching finding or incomplete screen changes that row's fusion observability to
`not_observable`. The original score, pixels' source identity, selected calibration and diagnostic
provenance remain in the report. Withholding removes both positive and negative likelihood
contributions; a compromised observation cannot turn into evidence against the class.

Diagnostic thresholds can trigger after the first affected frame. The conservative withholding
scope is therefore the diagnostic's finite requested scan, with the actual threshold interval
reported separately. A clear later screen cannot erase an earlier matching adverse finding.
Unrelated imports, sensors, source ranges or privacy generations do not borrow those findings.

The screen is a retained heuristic assessment, not proof of present camera health, physical
failure, tampering or recovery. Metadata and provenance are verified; the supervisor does not
rerun the health trace or the neural model. Complete current source custody remains the native
detector owner's responsibility and is rechecked for every relevant source.

## Bounds and historical source validation

The existing shared object-read byte/attempt allowance covers detector and diagnostic reads.
Separate finite catalog, history, diagnostic-comparison and finding limits bound CPU and
metadata work. A run admits at most 128 unique native observations, 512 selected rows, 32 source
imports and 32 cumulative windows. Reports are bounded to 2 MiB and are never truncated.
Opening/recovering the deployment retains its existing independent admission limits.

`RetainedDetectionReport::source_inventory` retains the complete original inventory, including
native-verified generation exclusions. `revalidate_detection_sources` binds that inventory to
an explicitly supplied current authority root and rechecks its original verification classes.
It neither inserts new reports into the historical result nor repeats a likelihood update.

Selected reports also pin their exact source-health interpretation. New relevant diagnostics,
withdrawn diagnostic custody or a changed interpretation refuse historical reuse. Unrelated
later authority does not alter these source-specific health digests. A validation receipt is
current source checking, not a new class result or effect grant.

## Durable polling and recovery

The same detector request can be owned by an existing live session. Register its exact bytes,
subscription label and finite lifetime attempt allowance; optionally activate the predeclared
cumulative windows as an explicit schedule:

```sh
fss-event supervise \
  --root /owner/deployment --site site:home \
  --detection-plan /owner/detection-plan.json \
  --detection-digest sha256:EXACT_FILE_DIGEST \
  --session session:EXISTING --subscription detector-watch \
  --authority-root sha256:CURRENT_AUTHORITY_ROOT \
  --max-poll-attempts 16 --schedule yes
```

The existing session must authorize this subscription and remain live. The registered plan,
schedule and lifetime ceiling are immutable. Each call performs one finite operation; no hidden
timer runs after the process exits. Later calls can recover without the original plan file:

```sh
fss-event supervise \
  --root /owner/deployment --site site:home \
  --session session:EXISTING --subscription detector-watch \
  --authority-root sha256:CURRENT_AUTHORITY_ROOT --resume yes
```

The recovered configuration's exact digest and schema select the detector owner. Pending
delivery repeats the exact stored report bytes after current source and health revalidation.
New detector reports do not enter that historical delivery. Revalidation uses the original
active window prefix, even if later reports now fit a later window.

The ordinary `--inspect yes`, `--acknowledge sha256:DELIVERY_RECEIPT`,
`--discard sha256:DELIVERY_RECEIPT` and paired `--advance-window NEXT_ZERO_BASED_INDEX
--after-receipt sha256:DELIVERY_RECEIPT` actions also work with `--resume yes`. A pending
report must be acknowledged or discarded before advancing the finite schedule. The full
[session lifecycle](RETAINED_EVENT_SUPERVISOR.md) retains the same authority and recovery rules.

Native source pins retain report, record and detection-root identities, verification class and
the optional exact health-context digest. They are distinct from event source pins: no synthetic
event identifier is created. A nonempty native inventory uses additive journal publication tag 8
and its own delivery-receipt domain; existing event-only publications keep their original bytes.
An older reader refuses the new command rather than dropping its source inventory.

A new relevant frozen-frame diagnostic, withdrawn privacy permission, deleted evidence or corrupt
native custody refuses replay and first acknowledgement. The pending receipt and original bytes
remain retained for inspection or explicit discard. Evaluation and source revalidation reserve a
full durable attempt before work, including failed attempts; restart, ACK, discard, source repair
and window advancement cannot replenish the lifetime allowance.

## Focused verification

```sh
cargo test --locked --offline -p fss-cli --test supervisor_retained_contract detection::
cargo test --locked --offline -p fss-reference --lib ingest::historical_health::exposure::
cargo test --locked --offline -p fss-reference --lib agent_session::checkpoint::journal::supervision::
```

The native contracts use real JPEG decoding and the committed YOLOX package. They cover reports
without any event revision, overlapping-source deduplication, complete capture containment,
empty native output, generation exclusions, read/output bounds, current privacy and deletion,
source corruption and fresh-authority historical validation. Durable native scenarios exercise
file-free scheduled recovery, exact replay after new source publication, health changes, corrupt
generation exclusions, ACK/discard and lifetime quota exhaustion. Journal regressions cover every
publication crash boundary, additive-codec corruption and read-only inventory recovery.

Synthetic fixture images validate this wiring and failure behavior; they do not qualify
real-world detector accuracy or NS-1. Authored regressions require execution under the pinned
toolchain; source review and formatting alone do not establish a passing test result.
