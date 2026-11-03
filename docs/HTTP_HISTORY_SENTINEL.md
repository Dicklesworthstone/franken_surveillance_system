# Trained detector sampling across a retained HTTP history

`fss-sentinel-http-history` sends scheduled original JPEGs from an exact ended HTTP
reconnect history through a pinned native RGB detector. Sampling does not require
foreground motion. Quiet footage, including a subject that was already stationary
when recording began, can therefore reach the trained detector even when the
motion-based history watcher has no entry candidate.

The command verifies every selected connection, imports all complete original JPEGs,
and allocates complete inference bursts across the imported recordings. It returns
source-linked native detector reports and can retain their exact model and recipes for
cold numerical replay. Detection scores remain uncalibrated; this workflow does not
claim field accuracy, person identity, physical arrival, continuous occupancy or
absence. It publishes no events and sends no alerts.

## Select the source and model

1. Capture explicitly reserved generations with
   `fss-capture-reconnect --durable-history yes`, using the
   [durable history workflow](HTTP_RECONNECT_HISTORY.md).
2. Save the acknowledged `(session, root, connections)` pin independently. Use the
   exact saved prefix, including its empty and failed connections. A reserved future
   generation and an unfinished current wire prefix are outside that ended history.
3. Supply one camera and capture-time binding for every selected connection. Supply a
   local native `.fmpk` detector package and its independently expected SHA-256 digest.
   The command does not download a model or change an active model.
4. Preview, review and approve the exact offline operation.

A saved `history_prepared` pin may be used when its acknowledgement was lost, but the
cold verifier must prove that exact root is durable. Directory contents never select
an implicit latest history. The original archive must already exist. The archive and
destination must be separate, non-nested stores, and the package must be outside both.
Archive opening takes the existing publisher's exclusive lock and performs its normal
recovery synchronization; concurrent capture into that archive is not supported by
this synchronous operation.

## Preview and approve

Each `--binding` has the following fields, in native connection order with strictly
increasing generations:

```text
GENERATION,SENSOR,STREAM,RECEIVE_NS,CAPTURE_START_NS,UNCERTAINTY_NS,FPS
```

For a saved two-connection history containing generations 40 and 41:

```sh
fss-sentinel-http-history \
  --archive /srv/fss/front-camera-originals \
  --root /srv/fss/retained-site --site site:home \
  --principal principal:local-operator \
  --history-session "$HISTORY_SESSION_SHA256" \
  --history-root "$HISTORY_ROOT_SHA256" --history-connections 2 \
  --binding 40,sensor:front,stream:front-40,1791504600000000000,1791504000000000000,1000000,10 \
  --binding 41,sensor:front,stream:front-41,1791505200000000000,1791504600000000000,1000000,10 \
  --interpretation gray \
  --package /srv/fss/models/yolox_nano.fmpk --package-digest "$MODEL_SHA256" \
  --sentinel-every-frames 16 --sentinel-burst-frames 3 --sentinel-max-inferences 48 \
  --retain-analysis yes \
  --owner-authorized yes --read-originals yes --retain-originals yes --read-model yes \
  --max-frames-per-generation 4096 --max-bytes-per-generation 67108864 \
  --max-history-reads 8192 --max-history-bytes 536870912 \
  --max-work 1000000000000 --max-framing-work 10000000000 \
  --timeout-ms 600000
```

Use `--interpretation ycbcr` for the explicitly declared JPEG Y/Cb/Cr source contract;
`gray` declares grayscale. The command does not guess an interpretation from pixels.
The example's generations and timestamps are owner declarations that must be replaced
with the values appropriate to the selected history.

Without `--approve-import`, validation and preview perform no filesystem, clock,
model or network I/O. The `fss.http_history_sentinel_operator.v1` preview includes
`approval_digest`, the exact history and bindings, model/backend identity, retention
choice and checked resource reservations. Repeat the same command with:

```text
--approve-import sha256:<the preview's exact 64-hex-digit approval>
```

The approval binds source, destination and model paths, site, principal, ordered
bindings, package digest, native backend generation, threshold, sampling, retention,
thread count and resource/deadline limits. The library plan uses
`fss.http_history_sentinel_plan.v1`; the CLI additionally binds its runtime and path
choices in `fss.http_history_sentinel_cli_plan.v1`. Neither is a capture or event
approval.

All capture timing remains an explicit operator assumption. Receive-clock timestamps
are never converted into capture timestamps. Preview validates the last possible frame
under the admitted per-generation frame ceiling, so the entire reserved capture
interval must fit the declared receive time. Sampling periods are source-frame counts,
not measured elapsed-time coverage. The destination sensor's current privacy mask is
applied before every model execution and checked again before the combined report is
released.

## One allocation and one resource pool

Each connection starts its own schedule at source frame zero. A burst contains
`--sentinel-burst-frames` consecutive frames; successive starts are separated by
`--sentinel-every-frames`. The processor grants one complete burst per eligible
connection per round, in original connection order, until the shared inference
allowance is spent or no eligible bursts remain. Allocation uses actual completed
import receipts, not receive-read counts or an assumed camera duration.

For two recordings with six and four frames, period two, one-frame bursts and an
allowance of three inferences, the selections are `[0, 2]` and `[0]`. The second
connection gets a turn before the first takes its second burst. With two-frame bursts
and an allowance of five, only two complete bursts are admitted; the remaining single
inference does not authorize a partial burst.

A complete history has at most 32 connections. The whole-history inference allowance
is at most 2048, and each native recording still admits at most 64 inferred frames.
A burst is at most eight frames and cannot exceed its period. These bounds are not
raised for long recordings. Unselected ranges, quota-skipped bursts and short tails
remain explicit. Separate bursts and reconnects never become one continuous track.

Source-read bytes, decoded pixels, JPEG work, detection-head work and native report
bytes share one nonrenewable pool across the complete invocation. A later generation
receives only the residual grant. Preprocessing and model-execution ceilings remain
per frame, with checked whole-invocation reservations. Combined admitted model tensor
outputs cannot exceed 1 GiB while all computations await optional retention.

HTTP MJPEG inference decodes only admitted independent JPEGs. Unsampled originals are
retained and their custody is verified, but their unexecuted model or decode work is
not reported as completed. Final verification covers every imported recording,
including all source capsules, unselected suffixes and entirely quota-skipped or
short recordings. It checks both reconstructed media and copied original HTTP bytes;
reconstructed JPEGs alone cannot replace missing original provenance.

| Option | Default and scope |
| --- | --- |
| `--sentinel-every-frames` | Required; 1..65536 source frames between burst starts. |
| `--sentinel-burst-frames` | Required; 1..8, no greater than the period. |
| `--sentinel-max-inferences` | Required; one whole-history ceiling, at least one full burst and at most 2048, also subject to output reservations. |
| `--max-frames-per-generation` | 128; can be explicitly raised through 4096. |
| `--max-bytes-per-generation` | 64 MiB; independent original-response and reconstructed-media import ceilings. |
| `--max-history-reads` / `--max-history-bytes` | 8192 reads / 512 MiB for complete exact history verification. |
| `--stream-read-bytes` | 512 MiB shared native inference source-read pool, including original provenance reads. |
| `--stream-pixel-budget` | 1 GiB of pixel samples shared across native computations. |
| `--sentinel-report-bytes` | 16 MiB shared complete native report allowance. |
| `--max-macs` / `--max-tensor-bytes` | 8 billion MACs / 256 MiB per native inference. |
| `--max-output-bytes` | 16 MiB per inference; count times this ceiling must fit the 1 GiB combined output bound. |
| `--max-frame-pixels` | Optional narrowing, 256..9437184; retains the corresponding exact native JPEG/AVC/HEVC ceilings, even though HTTP inference uses JPEG. |
| `--minimum-score-ppm` | Optional inclusive 0..1000000 threshold; otherwise uses the package contract. |
| `--kernels` / `--threads` | `optimized-cpu` / 1; `scalar-reference` is available, with 1..64 execution threads. |
| `--max-work` | 1 trillion units shared by history verification, model reading, import and final custody work. |
| `--max-framing-work` | 10 billion units shared by HTTP/MIME framing across all connections. |
| `--archive-read-bytes` | 1 GiB shared by archive opening/recovery and subsequent source reads. |
| `--timeout-ms` | 30000; explicit values through 600000. Cooperative at I/O/native-operation boundaries, without preempting an active native operation. |
| `--max-report-bytes` | 33619968 bytes for the complete CLI result, including every native report and replay command. |

Native custody and metadata owners retain their separate bounded checks; those checks
do not replenish inference resources. The preview reports the separate initial/final
history, import and final destination-verification reservations. Insufficient work,
missing custody, malformed input, source/decode gaps, model refusal or cancellation
reject the complete operation. They never become a successful skipped-frame analysis.

## Read the complete result

The completed CLI envelope contains `report`, a
`fss.http_history_sentinel_report.v1` projection. Its `generations` array contains every
selected connection in native order. Each row preserves the exact source scope and
wire prefix, explicit camera/capture assumptions, native completion/failure outcome,
import receipt, allocation, unsampled ranges and optional native report/retention.

| Status | Meaning |
| --- | --- |
| `analyzed` | All granted complete bursts were inferred; unsampled ranges remain explicit. |
| `budget_skipped` | Originals were imported, but no complete inference grant remained. |
| `too_short_for_burst` | Originals were imported, but the configured burst does not fit. |
| `empty_response` | The ended native connection retained no response bytes. |
| `no_complete_jpeg` | Replay reached a nonempty exact prefix without a complete original JPEG. |

The processing status is independent of the native outcome. A failed response can
contain complete, source-backed JPEGs that are analyzed; its original `source_failed`
outcome remains visible. Empty and failed connections are never dropped, and a valid
prefix never becomes proof of completed capture or scene absence.

All imports complete before model work, giving every native computation the common
`analysis_basis_sequence` and `analysis_basis_root`. All computations complete before
requested retention begins. `usage`
contains actual native accounting; `reservation` contains admitted ceilings. Each
row's `sentinel` is the unchanged complete native long-sentinel JSON, with separate
ordinary package-detection reports for its independent bursts. There is no foreground
gate and no cross-burst or cross-generation tracker state.

## Retain and replay after the source goes offline

`--retain-analysis yes` asks the existing native aggregate owner to retain complete
per-generation reports, exact recipes and the complete original model archive. Imported
source custody already contains the original HTTP response bytes, framing provenance,
JPEG media and source capsules. Native report handles can therefore be opened and
numerically replayed after both the original capture archive and the loose package file
are unavailable.

The completed CLI envelope includes `native_sentinel_reruns`. Its per-generation
`command` is a complete, quoted `fss-infer sentinel-replay` command with the report
identity, destination, principal and caller ceilings. Copy that emitted command. It
uses the stored recipe and backend, verifies current custody and privacy, and emits the
exact native sentinel JSON after numerical identity verification. It does not read a
loose model path or reconnect the camera.

For `--retain-analysis no`, the imported originals remain durable, but no native
aggregate/model retention is requested and replay commands are `null`. Generations
that received no inference grant also have no native aggregate or replay command,
even when analysis retention was requested.

A stopped invocation can leave an earlier import or retained aggregate durable. Retry
the same approved operation: the native owners verify and reuse completed imports and
matching aggregates, rather than adding a second progress journal or repairing missing
custody. Computation may run again; this command is not an inference checkpoint
continuation. Each invocation has its approved finite account, with no refill between
its generations. Current authority and privacy are checked again; a stale retained
mask cannot authorize replay under a different current policy.

## Validation scope

`crates/fss-reference/tests/http_history_sentinel_contract.rs` exercises real loopback
HTTP acquisition, native JPEG decoding and the repository's pinned YOLOX-nano package.
Its ten regressions cover quiet-frame inference and fair allocation, failed/empty/
short/quota-skipped outcomes, admission and later-source refusals, shared resource
conservation, interrupted import and retention reconciliation, cold numerical replay,
current privacy, final custody damage and exact plan/native burst bounds. The CLI tests
cover pure preview and approval binding plus actual capture, approval, retained replay
and refusal behavior. These are implementation contracts, not detector-quality or
real-camera deployment certification; execution results are recorded separately in
[implementation status](../IMPLEMENTATION_STATUS.md).

Related workflows: [motion-based HTTP history watch](HTTP_HISTORY_WATCH.md),
[whole-recording native sentinel](LONG_RECORDING_SENTINEL.md), and
[RTSP campaign sentinel](rtsp_campaign_sentinel.md).
