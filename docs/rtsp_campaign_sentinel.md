# Run the trained detector across an exact RTSP campaign

`fss-sentinel-rtsp-campaign` samples independently retained RTSP recordings with
the native trained RGB detector. Sampling depends on source coordinates and an
explicit campaign allowance. Stationary footage reaches the model even when the
foreground detector produces no candidate.

The command accepts the same exact saved campaign prefix and complete native
import requests as [campaign watch](rtsp_campaign_watch.md). It preserves failed,
empty, unavailable and start-only attempts in one report. Each recording keeps
its original generation, clocks, capture assumptions and custody. No camera is
opened and no event, alert or capture resume is authorized.

## Select the saved history and native recordings

Follow the [campaign-history guide](rtsp_campaign_history.md) to save all four
`CampaignPin` coordinates independently: `approval`, `plan`, `root` and `records`.
The selected prefix remains exact even if later history exists.

`--requests` contains one consecutive, one-based `ordinal` for every selected
started attempt. A non-null `request` contains the ordinary `fss-import-rtsp`
option/value array. It must name the exact recorded archive, its **complete saved
ordered catalog inventory**, codec, sensor, stream, generation, original capture
anchor, derived receive/decode clocks and explicit capture-time assumptions.
Every child uses the same outer destination, site and principal. Current owner,
original-read and original-retention acknowledgements are required both outside
and inside each native request.

Use `request: null` only when this prefix contains no catalog for that attempt.
Those rows do not open a source archive. A window selection, omitted catalog,
reordered page, guessed namespace, wrong archive or missing selected row refuses.
The complete request contract and examples are in the campaign-watch guide;
sentinel uses the same parser and current filesystem admission.

## Pin a local model and preview the complete operation

Choose an existing native RGB `.fmpk` package and independently verify its full
SHA-256 identity. This command does not download or activate models. Package
bytes are read only after exact approval and `--read-model yes`.

For example, after setting the saved pin variables, full `REQUESTS` JSON, package
path and expected digest:

```bash
fss-sentinel-rtsp-campaign \
  --history-root /owner/campaign-history/porch \
  --history-approval "$SAVED_APPROVAL" \
  --history-plan "$SAVED_PLAN" \
  --history-root-digest "$SAVED_ROOT" \
  --history-records "$SAVED_RECORDS" \
  --root /owner/analysis/porch --site site:porch \
  --principal principal:local-operator \
  --requests "$REQUESTS" --interpretation ycbcr \
  --package "$MODEL_PATH" --package-digest "$MODEL_DIGEST" \
  --read-model yes --retain-analysis yes \
  --sentinel-every-frames 16 --sentinel-burst-frames 3 \
  --sentinel-max-inferences 48 \
  --owner-authorized yes --read-originals yes --retain-originals yes
```

All three sampling options and the `yes|no` retention choice are explicit.
`--interpretation ycbcr` matches native AVC/HEVC. No zone or foreground setting is
needed. Numeric `--threads 1..64` defaults to one; automatic host discovery is not
part of a pure preview. The default kernel backend is `optimized-cpu`;
`--kernels scalar-reference` is an explicit alternative.

Without `--approve-import`, the command emits only a plan. It does not read a
clock, inspect a directory, lock an archive, open the model or contact a camera.
Review the saved prefix, full native requests, model identity, retention choice
and resource reservations. Repeat the identical command with `--approve-import`
set to the returned `approval_digest`. Changes to those inputs, paths, model,
backend, threads, score threshold or resource ceilings produce a different
approval. A capture, standalone import or campaign-watch approval cannot execute
this plan.

Approved execution first validates the exact history mapping and current path
authority. Canonical aliases and overlaps among the destination, history, model
and every frozen archive, pin and original-datagram path refuse, including planned
successors outside the selected prefix. It reads and verifies the bounded model
before opening recording owners or creating the destination. It then verifies
all selected native originals, imports every selected recording, and performs
model work at their common destination evidence basis. Optional retention has
its own later anchors. Original custody and the exact history are checked again
before a complete report is released.

## One inference allowance across all attempts

The period is `1..65536` frames. A burst is `1..8` contiguous frames, no longer
than the period. The whole campaign allowance is `1..1024` inferences and must
admit at least one complete burst. Each individual native recording remains
bounded to 64 inferences.

Allocation uses actual verified catalogued frame counts, before any import. It
grants one complete burst to each eligible attempt in ordinal order, then repeats
that round while allowance remains. It never gives the first recording all the
allowance merely because that recording is processed first. For example, with
two two-frame recordings, period one, burst one and campaign allowance two, each
recording receives one inference and retains one explicit unsampled frame.

Short tails, whole bursts denied by the allowance and unused partial allowance
remain visible. An attempt shorter than one burst does not run the detector.
Burst sampling does not join trackers between bursts or recordings.

For admitted native AVC/HEVC recordings, the decoder drains the complete strict
imported range, including frames not sent to RGB inference. A source gap, missing
selected image or decode refusal fails the computation. Current destination
privacy masks apply. Sampling fewer model frames therefore reduces model work
without pretending that unsampled inter-frame video can be skipped during decode.

## Read the attempt states and counts

| `status` | What it establishes |
| --- | --- |
| `analyzed` | At least one complete burst ran under the exact native model recipe. Original capture failure remains separately visible. |
| `budget_skipped` | The full saved catalog was imported, but no complete burst received an inference allowance. No detector result was produced. |
| `too_short_for_burst` | The verified catalog contains fewer frames than the requested burst. No detector result was produced. |
| `recorded_no_durable_pictures` | The selected native observation explicitly recorded zero durable pictures and no catalog. |
| `recorded_pictures_without_catalog` | Pictures were recorded, but this prefix contains no catalog selecting them. They are not scanned into an invented selection. |
| `started_without_retained_finish` | The selected prefix contains a start without a retained finish. Counts and outcome remain unknown. |
| `native_observation_unavailable` | A finish exists without a native observation. Native outcome and counts remain unavailable. |

The last four states use null requests. An all-null prefix still returns an exact
inventory and touches no recording archive; the explicitly approved package is
still read and verified. No row claims a quiet scene or absence.

The report separates `recorded_durable_pictures`, `catalogued_pictures`,
`decoded_pictures` and `model_sampled_pictures`. A failed capture may contain
sealed pictures that never reached a catalog; `recorded_pictures_without_catalog`
preserves that remainder. `allocation` separates eligible, admitted and
budget-skipped bursts. `unsampled_ranges` shows source coordinates, and
`strict_native_video_range_drained` is false when no native analysis ran.

Trained outputs remain uncalibrated. A successful invocation establishes what the
verified package computed from these retained images; it does not establish
recognition quality, continuous coverage, a physical-world fact or effect
authority. Neither quiet foreground nor absent/skipped inference certifies that
an object was absent.

## Shared resources and current authority

| Control | Scope |
| --- | --- |
| `--sentinel-max-inferences` | One campaign model-call allowance, allocated in complete bursts. |
| `--stream-read-bytes` | One native analysis source-chunk pool; default and hard maximum 512 MiB. |
| `--stream-pixel-budget` | One native analysis pixel/coded-capacity pool; default 1 GiB, maximum 64 GiB. |
| Native JPEG/head work | One campaign pool for each, using the existing defaults of 1 billion and 2 billion work units. |
| `--max-macs`, `--max-tensor-bytes`, `--max-output-bytes` | Per-inference native model ceilings; the preview also reserves their checked campaign totals. |
| `--max-frame-pixels` | Optional narrowing of per-frame native coded capacity. AVC uses whole macroblocks, rounded down. |
| `--max-work` | One account for all history inspections, source verification/import work and bounded model reads. |
| `--archive-read-bytes` | One enforced account across all source-owner recovery and later archive reads, default 1 GiB and maximum 16 GiB. |
| `--sentinel-report-bytes` | One pool for all native sentinel reports, up to 16 MiB. |
| `--max-report-bytes` | Complete outer operator report, including every native report and replay hint. |

Reserved output is at most 1 GiB in aggregate. The default 16 MiB per-inference
output ceiling therefore admits at most 64 reserved inferences; larger campaign
allowances require an explicit smaller `--max-output-bytes`. The preview shows
whole-campaign MAC/output sums and refuses arithmetic overflow before I/O.

Archive filesystem operations have a separate fixed aggregate ceiling of
1,000,000. Current capabilities, selected roots and cancellation/deadline checks
remain attached for the entire source-owner lifetime. A refused operation stays
a failure even if recovery catches an individual scan error. Native archive
opening takes its lock and may finish existing recovery, so the complete command
is not a read-only source operation. History inspection itself stays read-only.

The successful result separates startup and total `archive_io`, actual
`model_read_bytes`, `history_import_model_work`, campaign native `usage`, and the
approved reservations. Retention reserves conservative source and direct-report
read admission, including exact-retry verification. This is not a runtime meter
for all destination disk I/O: destination opening, import metadata and publication
continue to use their existing native limits.

`--timeout-ms` is cooperative at model/archive I/O and native operation
boundaries. It does not preempt a native decode, inference or retention operation,
nor interrupt a blocking host filesystem call. Native execution also retains its
own finite resource limits and cancellation checkpoints.

## Retain, retry and replay exact native computations

`--retain-analysis yes` retains each analyzed attempt's complete native sentinel
aggregate, exact package, execution recipe and ordinary child reports as
cognition. Its `retained.report_digest` is a cold replay handle. The outer
`native_sentinel_reruns` array contains an exact `fss-infer sentinel-replay`
command only for an actually retained aggregate.

Those commands load the saved per-attempt recipe, including its residual share
of the campaign resource pools. Their current admission ceilings permit that
recipe; they do not reconstruct or replace it. After successful retention, the
original capture archives and loose model file can be offline. Recomputed native
report bytes and their digest must match the retained aggregate exactly.

`--retain-analysis no` still imports originals and runs admitted model work, but
does not retain model/report cognition or claim a retained replay command. Short,
skipped and null rows have no replay handle under either choice.

Imports and retention are incremental. Later failure or output loss can leave
earlier native work durable. Preserve the stores and retry the exact approved
plan; native reconciliation reuses imports and identical retained results.
Changed current evidence or privacy can legitimately refuse the old computation.
Only a complete successful report confirms the whole selected campaign operation.
Retained child reports remain available to the existing separately authorized
event workflow; their existence does not itself publish an event or alert.

## Focused native regression commands

```bash
cargo test -p fss-reference --test rtsp_campaign_sentinel_plan_contract
cargo test -p fss-reference --test rtsp_campaign_sentinel_contract
cargo test -p fss-cli --bin fss-sentinel-rtsp-campaign
cargo test -p fss-cli --bin fss-watch-rtsp-campaign
cargo test -p fss-cli --bin fss-watch-rtsp-selected
cargo test -p fss-cli --test capture_rtsp_cli campaign::history::sentinel -- --test-threads=1
cargo test -p fss-cli --test capture_rtsp_cli campaign::history::watch -- --test-threads=1
```

Focused proof on 2026-10-22 used the pinned native compiler
`rustc 1.100.0-nightly (908501772 2026-08-30)`, the actual eight production
commands, and unchanged test target sources linked against the native dependency
graph. Production features and source gates stayed enabled. The three CLI unit
targets passed 13, 11 and 7 cases respectively; the new sentinel process scenarios
passed 3/3 and the existing campaign-watch scenarios passed 4/4. Those are 38
passing executions covering 32 distinct test bodies: six shared archive-I/O
cases execute in both campaign binaries. The watch preview golden bytes also
remained exact. These are the focused targets represented by the commands above.

The process fixture serves checked-in AVC through owned loopback RTSP, including
repeated identical IDR pictures. Native capture, import, foreground watch, trained
inference, retention and cold replay all run as real Rust executables. The tests
also cover failed/empty attempts, exact older start-only selection, short and
globally skipped bursts, shared pixel exhaustion, unchanged retry journals and
refusal before destination creation. These are wiring and custody proofs, not a
camera, detector-quality or release qualification.
