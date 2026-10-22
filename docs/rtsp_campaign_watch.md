# Watch independently retained RTSP campaign attempts

`fss-watch-rtsp-campaign` turns an exact, independently saved campaign-history
prefix into native motion, region and track reports for every available retained
recording in that prefix. It uses the same native AVC/HEVC import, decode and watch
owners as `fss-import-rtsp` and `fss-event watch`. Each attempt keeps its own archive,
generation, clocks, failure history and analysis state.

This command closes the gap between [durable campaign history](rtsp_campaign_history.md)
and downstream watch. An operator can analyze several successful or partially
recorded attempts together, preserve empty and unknown attempts in the report,
and rerun the resulting native watch after the original camera archives go
offline. It neither starts capture nor publishes an event or alert.

## Select one independently saved history prefix

Save the complete `pin` from a `history_durable` capture receipt independently of
the history store. All four coordinates are required:

```json
{
  "approval": "sha256:...",
  "plan": "sha256:...",
  "root": "sha256:...",
  "records": 7
}
```

Use the exact history directory and original principal label. If needed, inspect
that prefix first with `fss-capture-rtsp campaign-inspect`, as described in the
history guide. Inspection does not open the original recording archives.

The selected pin is an immutable prefix, not a request for the latest history.
Selecting an earlier start-only pin keeps that attempt's finish unknown even if a
later successful finish exists in the same directory. Planned successors absent
from the prefix are not silently included. A verified prefix does not establish
that no later history, footage or attempt exists.

## Supply one explicit row for every selected start

`--requests` is a bounded JSON array in exact, consecutive attempt order. It must
contain one row for **every started attempt in the selected prefix**. Do not omit
an empty or failed attempt, and do not add a planned successor whose start is not
selected. The maximum is 16 rows.

Each row contains exactly `ordinal` and `request`. A non-null request is an array
of ordinary `fss-import-rtsp` option/value strings. A null request preserves an
attempt for which the selected history contains no catalog:

```json
[
  {"ordinal": 1, "request": ["--archive", "/owner/capture/porch.attempt-0001", "..."]},
  {"ordinal": 2, "request": null}
]
```

The abbreviated array above illustrates the shape, not executable arguments.
Every non-null array must include:

| Required binding | Native options |
| --- | --- |
| Exact retained attempt archive | `--archive` |
| Common destination and current operator | `--root`, `--site`, and `--principal` when overriding its default |
| Entire saved catalog selection | `--catalog-slot` with `--catalog-root`, or ordered `--catalog-pages SLOT@ROOT,...` |
| Original codec and namespace | `--codec avc\|hevc`, `--sensor-id`, `--stream-id`, `--generation`, `--anchor` |
| Original attempt clocks | `--receive-clock`, `--decode-clock`, `--time-scale`, `--receive-time-ns` |
| Explicit capture-time assumptions | `--capture-start-ns`, `--capture-uncertainty-ns` |
| Native capacity limits | `--max-frames`, `--max-windows`, `--max-pages`, `--max-original-bytes`, `--max-media-bytes` as needed |
| Current original-evidence consent | `--owner-authorized yes`, `--read-originals yes`, `--retain-originals yes` |

Use the actual native catalog coordinates from the selected history and capture
receipts. Multiple catalogs must appear in their complete saved order. A single
catalog is valid only when it is the entire saved selection. Window-only import,
a subset, a reordered list and a guessed catalog all refuse. The native page
reader remains bounded to its supported page count; larger selections refuse
rather than truncating the recording.

The supplied namespace must match the original archive namespace committed by
the frozen capture plan. In particular, `--anchor` is the original capture
anchor, not the child capture approval. Each successor uses its derived receive
and decode clocks and its own generation. The capture preview and native
receipts provide those identities. No clock, codec or missing namespace is
inferred from the contents of a directory.

Capture start and uncertainty remain explicit operator assumptions for each
attempt. Receive timestamps are not promoted to capture timestamps. Supplying
adjacent capture ranges does not establish continuity across attempts.

All children use the exact outer destination, site and principal. Child
`--approve`, `--max-work` and `--timeout-ms` are forbidden: the outer command owns
the current approval, shared history/import work and deadline. Child native plan
previews retain their standalone defaults for reference; those defaults do not
create fresh work accounts or deadlines during campaign execution.

## Preview, review and approve the complete operation

Once `REQUESTS` contains the complete JSON array, run:

```bash
fss-watch-rtsp-campaign \
  --history-root /owner/campaign-history/porch \
  --history-approval "$SAVED_APPROVAL" \
  --history-plan "$SAVED_PLAN" \
  --history-root-digest "$SAVED_ROOT" \
  --history-records "$SAVED_RECORDS" \
  --root /owner/analysis/porch --site site:porch \
  --principal principal:local-operator \
  --requests "$REQUESTS" \
  --interpretation ycbcr --zone entrance:0,0,640,480 \
  --owner-authorized yes --read-originals yes --retain-originals yes
```

The zone coordinates must fit the actual native image geometry. Review detector,
tracker, screening and decode settings for the intended analysis. `--help` lists
their defaults and the shared resource controls.

Without `--approve-import`, the command emits a pure plan. It does not read a
clock, inspect a directory, create a lock, open a recording or connect to a camera.
The preview includes the exact selected pin, all native request plans, shared
watch settings, aggregate reservations and resource ceilings. Repeat the same
command with `--approve-import` set to its `approval_digest`.

The approval binds every selected history coordinate, path, owner, native request,
watch setting and budget. A capture approval, standalone import approval or stale
campaign-watch approval cannot execute a different plan. Changing any of those
inputs requires reviewing the new preview.

## Validate the whole selection before importing

After exact approval, the command first reads the selected immutable history and
validates the complete attempt mapping. It rejects a missing selected archive,
wrong path, clock, namespace, catalog order or count before creating the analysis
deployment. It also checks canonical aliases and nesting between the destination,
history and **every frozen** archive, pin-journal and original-datagram store,
including planned attempts beyond the selected prefix. A destination cannot be
placed inside a future attempt's custody store.

Historical paths describe where evidence was recorded; the current operation
separately binds access to its principal, capabilities, selected roots, cancellation
state and deadline. The original camera, credentials, pin-journal owner and
original-datagram-store owner are not opened. Catalog imports verify the original
RTP closure retained by the recording archive itself.

Each selected archive is opened through its native publisher. This takes its
existing lock and can finish publication recovery; campaign analysis as a whole
is therefore not a read-only source operation. History inspection itself stays
read-only and does not rewrite or resynchronize the selected history.

Before the first destination import, the native pipeline verifies every selected
recording and its original closure. It then imports all recordings before running
any watch analysis, so every report uses the same final destination evidence
anchor. Source closure and the exact history are verified again before the
complete result is released. Current destination privacy masks apply before
perception. Background and tracking state restart for each attempt.

## Read partial and unknown states accurately

The completed report preserves every selected start, its retained native result
and the controller's original completion/continuation decision:

| `status` | Meaning |
| --- | --- |
| `analyzed` | The complete saved catalog selection was imported and passed through native watch; the original attempt may still have failed. |
| `recorded_no_durable_pictures` | The selected native observation explicitly recorded zero durable pictures and no catalog. |
| `recorded_pictures_without_catalog` | Durable pictures were recorded, but no catalog was saved in the selected history. No implicit archive scan turns them into a selection. |
| `started_without_retained_finish` | This prefix contains the start and no finish. Completion, picture count and custody remain unknown. |
| `native_observation_unavailable` | A finish was retained without a native observation. Counts and native outcome remain unavailable. |

The last four states require `request: null`. Their recording archives are not
opened and no watch result is fabricated. An all-null selected prefix can still
produce a useful explicit inventory without touching any media archive.

For catalogued attempts, the report separates `recorded_durable_pictures`,
`catalogued_pictures` and `decoded_pictures`. A failed capture may have sealed
pictures that never reached a catalog. Its saved catalogs remain analyzable while
`recorded_pictures_without_catalog` preserves that unindexed remainder and
`all_recorded_pictures_catalogued` is false. Native decode refusal, screening and
health details remain in the watch report; cataloguing a sample does not prove
that the sample was decoded or suitable for perception.

Native capture failure and campaign failure remain visible even when retained
footage produces candidates. A later success cannot erase an earlier failed
attempt. Quiet analysis, a null row, a missing source or a history prefix cannot
certify absence or complete scene coverage. No tracker is joined across attempts.

## Bound the complete native operation

The outer approval separates three kinds of capacity:

| Account | Scope |
| --- | --- |
| `--max-work` | One account shared by initial history admission, core history verification, source preparation, imports and final re-verification; it is never reset per attempt. |
| `--archive-read-bytes` | One enforced byte account for all selected native archive owners, including startup inventory/recovery and every later source read. Default 1 GiB; maximum 16 GiB. |
| Native watch limits | Per-recording read, pixel, screening, assignment, JPEG-work and trace ceilings, with the whole-campaign reservation shown before approval. |

Native archive-owner filesystem operations have a separate fixed aggregate ceiling of
1,000,000, also shown in the approval preview. It remains active throughout source
owner lifetimes. A source read reserves its bounded request before access and
refunds unused bytes only after success; a failed read retains its reservation.
A refused source action remains a failure even if native recovery classifies the
affected object and continues its scan. Releasing an already held source lock
remains possible after the access grant ends.

The result's `archive_io` reports startup bytes/operations separately from total
bytes/operations. Successful-run byte counts reflect bytes actually returned.
`history_and_import_work` reports the separate work account. These counters do
not describe native analysis pixel work as source-open IO.

`--timeout-ms` is one cooperative deadline checked at native IO and analysis
boundaries. One native analysis is work-bounded and `ReplayCx`-cancellable; the
timer does not preempt it mid-analysis. A blocking host filesystem call is not
forcibly interrupted. History
object, scan, storage, record and metadata limits apply on each exact inspection;
the preview reserves three inspections, and they share the same outer work
account. `--max-report-bytes` bounds the complete operator report, including native
reports and rerun commands. Output is complete or refused, never truncated into a
partial conclusion.

## Retry and rerun from retained destination custody

Imports are incremental. A later failure, exhausted ceiling or lost output can
leave earlier exact imports durable. Preserve all stores, repeat the same approved
plan and let native import reconciliation reuse existing identities. Retries do
not append duplicate ledger/effect records for the same import. They recompute
watch under the current destination evidence and privacy state, so a changed
deployment can legitimately produce a different analysis identity.

Each analyzed row has an entry in `native_watch_reruns` with an exact
`fss-event watch --stream-watch` command. It binds the retained import, complete
range, interpretation, zones, detector/tracker settings, screening, tolerance and
native decode/work limits. Null rows have no rerun command.

After import, those commands use destination-retained originals. The original
recording archives can be offline. With unchanged evidence and privacy state, the
native rerun preserves the analysis and candidate proposal identities. Rerun
hints do not grant event publication: review any candidate through the existing
separate event publication workflow. Neither importing nor rerunning opens a
camera, resumes a campaign or rewrites a recovery pin.

## Native regression checks

The new core contracts cover exact saved prefixes, independent archives, retained
failures and unindexed pictures, missing/corrupt closure, shared budget refusals,
current authority and retry reconciliation. The process cases in
`crates/fss-cli/tests/capture_rtsp_cli/campaign_watch.rs` use the real native
capture, campaign-watch and event binaries with owned loopback AVC fixtures:

```bash
cargo +nightly-2026-08-31 test --locked --offline \
  -p fss-reference --test rtsp_campaign_watch_contract
cargo +nightly-2026-08-31 test --locked --offline \
  -p fss-cli --bin fss-watch-rtsp-campaign
cargo +nightly-2026-08-31 test --locked --offline \
  -p fss-cli --test capture_rtsp_cli campaign::history::watch
```

These contracts exercise native custody, detection, tracking and cold process
wiring. They do not qualify real-camera interoperability, field detector quality,
continuous coverage or a release decision.

### Focused native execution, 2026-10-22

The pinned `nightly-2026-08-31` compiler successfully built the six production
entrypoints with locked, offline Cargo resolution: `fss-watch-rtsp-campaign`,
`fss-watch-rtsp-selected`, `fss-capture-rtsp`, `fss-import-rtsp`, `fss-file` and
`fss-event`. On the memory-constrained verification host, the unchanged repository
test sources were then compiled serially with that same compiler against the exact
production Cargo artifacts. This was a focused native harness run, not a complete
workspace test or release qualification.

| Executed target | Result |
| --- | --- |
| `rtsp_campaign_watch_contract` | 12 passed |
| `local_scoped_publication` | 4 passed |
| `fss-watch-rtsp-campaign` binary unit target | 10 passed: 4 pure-plan/approval and 6 archive-IO contracts |
| Existing `fss-watch-rtsp-selected` binary unit/native target | 7 passed |
| `capture_rtsp_cli`, filter `campaign::history::watch` | 4 passed; 73 unrelated tests filtered out |

The CLI execution commands for the compiled native test targets were:

```bash
/tmp/fss-campaign-watch-tests/fss-watch-rtsp-campaign --test-threads=1 --nocapture
/tmp/fss-campaign-watch-tests/fss-watch-rtsp-selected --test-threads=1 --nocapture
/tmp/fss-campaign-watch-tests/capture_rtsp_cli \
  campaign::history::watch --test-threads=1 --nocapture
```

The four process cases cover two independently retained successful AVC archives
plus an empty authentication-failed attempt; exact earlier start-only selection;
eleven history, namespace, page, path, principal and budget refusals before
destination creation; and retained EOF-shortfall footage without a successful
campaign claim. They also verify unchanged import/effect journals on exact retry
and native reruns after source archives go offline. Analysis and candidate
proposal digests match exactly at the non-multiple pixel ceiling `20481`, covering
the shared AVC macroblock-budget rounding through the actual event entrypoint.
