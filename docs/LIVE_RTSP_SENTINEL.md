# Capture a camera into retained native detector evidence

`fss-capture-rtsp sentinel` carries one approved native RTSP recording through
source import, trained detection and durable retention. It uses the existing camera,
catalog import, AVC/HEVC decoder, native model executor and publication owners.
There is no external video process or runtime model download.

The resulting ordinary detector child reports can be selected by the existing
retained supervisor. The retained aggregate records the complete sampling recipe,
source range, package identity and child reports for offline numerical replay.
This is a bounded acquisition operation; scheduling additional camera runs remains
an explicit operation.

## Review one complete plan

Start with the ordinary [native capture options](rtsp_capture_cli.md). Add the
deployment, explicit import time coordinates, digest-pinned local FMPK package,
sampling bounds and four analysis permissions. Capture and pin paths must be new;
their parents, the deployment parent and the model file's parent must already
exist. Archive, pins, deployment, model and optional credential paths must be
separate and nonnested, including through resolved parent aliases.

For example, this plans a 50-picture AVC recording at an asserted 25 pictures per
second, with two one-frame inference bursts:

```sh
fss-capture-rtsp sentinel \
  --root /owner/private/porch-archive \
  --pins /owner/recovery/porch-pins \
  --peer 192.168.1.40:554 --authority 192.168.1.40:554 \
  --presentation /stream/main --control-root /stream \
  --sensor-id sensor:porch --stream-id stream:porch \
  --generation 1 --ingress 1 --ssrc 7 \
  --anchor "$SOURCE_ANCHOR" --receive-clock "$RECEIVE_CLOCK" \
  --timing-evidence "$TIMING_EVIDENCE" --journal-id "$JOURNAL_ID" \
  --frame-duration-ticks 3600 --stop-after-pictures 50 \
  --owner-authorized yes --plaintext yes --retain-originals yes \
  --deployment-root /owner/deployments/home --site home \
  --receive-time-ns "$RECEIVE_TIME_NS" \
  --capture-start-ns "$CAPTURE_START_NS" \
  --capture-uncertainty-ns "$CAPTURE_UNCERTAINTY_NS" \
  --package /owner/models/yolox_nano.fmpk \
  --package-digest sha256:5b6568750faa375de3742e5eb310fbd4e22ff26e1ba727f193b79ab984a68c74 \
  --read-originals yes --read-model yes \
  --execute-perception yes --retain-analysis yes \
  --sentinel-every-frames 25 --sentinel-burst-frames 1 \
  --sentinel-max-inferences 2 --analysis-timeout-ms 600000
```

Use the actual camera scope and nonzero owner identities. The package digest above
names the repository's `models/yolox-nano/yolox_nano.fmpk`; a different package
requires its own verified digest. Receive time, capture start and uncertainty are
explicit inputs to the native importer. Capture intervals must be nonnegative
and fit within the supplied receive bound. The command labels capture time
`operator_assumption`; it establishes no clock calibration.

Without `--approve`, the command only parses and validates the plan: no filesystem,
clock, model or camera access occurs. Its JSON preview has schema
`fss.rtsp_capture_sentinel_cli.v1`, phase `planned`, and an outer `approval`.
Review that outer plan, then repeat the same command with
`--approve sha256:OUTER_APPROVAL`. The nested ordinary capture approval alone is
insufficient. Changing the destination, model, capture assumptions, sampling,
kernel backend or any effective bound changes the outer approval.

The ordinary native AVC/HEVC and optional scoped Digest-authentication options
remain available. Unsupported camera/codec profiles still refuse through their
existing owners. Successful transport capture alone does not prove that the
native pixel decoder admits the bitstream.

## What approved execution does

1. Verify explicit authority, distinct paths and the exact local package digest.
   Load the native package and validate any score override before camera contact.
2. Run one owned native capture. Both its returned outcome and typed observation
   must report settled success, the exact requested nonzero picture count,
   complete catalog pages, snapshot and independent journal pins.
3. Import those actual ordered page slots and roots into the selected deployment.
   Transcript text and guessed catalog names never select the source.
4. Decode the whole admitted range and execute the trained detector on the
   declared motion-independent bursts. Current destination privacy masks apply.
5. Retain the model/recipe/source closure, ordinary native detector children and
   aggregate. Emit their immutable identities and offline replay arguments.

Unselected time and frames without proposals do not certify absence. A single
camera's proposals do not establish corroboration. This operation grants no
event-publication or alert-dispatch authority.

## Output and recovery

Execution preserves the ordinary capture JSONL and adds complete bounded rows
under `fss.rtsp_capture_sentinel_cli.v1`. Treat `kind: "sentinel_retained"` as the
success report only when the process also exits successfully.

| Row kind | Durable progress and next action |
|---|---|
| `sentinel_model_ready` | The pinned package loaded before camera contact. |
| `sentinel_capture_ready` | Complete native catalog/snapshot/journal pins and exact approved `fss-import-rtsp` arguments are available. |
| `sentinel_imported` | The import identity, source proof and exact `fss-infer package-detect` continuation are available. |
| `sentinel_retained` | Aggregate and ordinary child report digests, usage and exact `fss-infer sentinel-replay` arguments are available. |
| `sentinel_capture_refused` | Capture failed or remained unsettled; available native recovery pins are reported and analysis has not started. |
| `sentinel_analysis_refused` | Earlier originals/imports may be durable. Exact available continuations and any unconfirmed computed report identity remain visible. Child retention may already exist. |

The `offline_*_program` field names the executable. The matching
`offline_*_args` array contains arguments only; preserve each array element
exactly, including spaces and apostrophes. These are argument vectors, not shell
commands to concatenate or evaluate.

After capture, repair or repeat analysis from the retained source. Repeating the
live command against existing capture or pin roots refuses before contacting the
camera. It never silently reacquires footage. If output fails after publication,
preserve all stores and inspect the last complete native progress rows; missing
terminal output is not evidence of rollback.

Successful `sentinel-replay` uses the deployment's retained model and source
custody. It does not need the camera, original external archive or loose package
file, and does not append evidence or effect journals.

## Bounds and deadline semantics

The outer approval includes the complete native capture plan and all effective
analysis limits. Useful analysis controls are:

| Option | Meaning |
|---|---|
| `--analysis-timeout-ms` | 1–600000 ms; starts before model preflight and includes capture elapsed time. |
| `--analysis-work` | Finite path/model/import work allowance. |
| `--archive-read-bytes` | Shared, nonrenewable source-archive byte allowance; archive operations also have a fixed ceiling. |
| `--import-max-original-bytes`, `--import-max-media-bytes` | Native import custody bounds. |
| `--stream-read-bytes`, `--stream-pixel-budget` | Whole-range source and decoded-pixel bounds. |
| `--max-macs`, `--max-tensor-bytes` | Independent limits for each admitted inference. |
| `--sentinel-report-bytes` | Complete aggregate report ceiling. |
| `--max-frame-pixels` | Optional narrowing of native codec capacity. |
| `--minimum-score-ppm` | Explicit detector threshold override, bound into approval and retained recipe. |
| `--kernels`, `--threads` | `optimized-cpu` or `scalar-reference`, and a numeric native execution thread count. |

The analysis deadline is cooperative at I/O and native phase boundaries. It does
not preempt an in-progress native decode, inference or retention operation.
The capture phase retains its existing runtime deadline and bounded drain owner.
Destination custody uses the existing native limits; this command does not claim
a whole-process destination-I/O meter or hard realtime completion.

## Verification scope

The real-process regression target uses bounded loopback RTP, the checked-in
pinned detector, actual import/retention and cold replay. It covers pure previews,
changed approvals, model refusal before contact, complete capture-to-replay
composition, no repeated camera acquisition, capture failure and analysis recovery.

```sh
cargo test --locked --offline -p fss-cli --test capture_rtsp_cli live_sentinel
```

This feature is implemented but not release-qualified. Source/API review and
formatting are distinct from successful compilation and test execution.
`scripts/qualify.sh` remains the release qualification entrypoint.
