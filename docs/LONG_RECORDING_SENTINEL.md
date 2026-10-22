# Motion-independent detection across long recordings

`fss-infer package-detect --stream-sentinel yes` sends explicit periodic bursts
to the verified native detector independently of foreground, tracks and events.
It accepts retained source ranges and periods up to 65,536 segments, so static or
slowly changing footage can reach the trained detector beyond the original
64-segment sentinel limit. This implements the retained long-recording slice of
FSS-078 / RISK-007 / OPEN-006.

## Run and retain

```sh
fss-infer package-detect \
  --root /path/to/deployment --site site:home \
  --import-id sha256:IMPORT_DIGEST \
  --first-segment 0 --frames 4096 --interpretation ycbcr \
  --package /path/to/yolox_nano.fmpk \
  --package-digest sha256:PACKAGE_DIGEST \
  --stream-sentinel yes \
  --sentinel-every-frames 1024 --sentinel-burst-frames 3 \
  --sentinel-max-inferences 12 \
  --max-frame-pixels 2097152 --stream-pixel-budget 8589934592 \
  --retain yes
```

Replace digest placeholders with exact retained-import and verified-package
identities. No model is downloaded and no camera connection is opened. The command
accepts retained MJPEG, H.264 and H.265 imports. The example's frame ceiling fits
padded 1920-by-1080 video; the actual source's coded dimensions must fit. Its whole
pixel allowance is 8,589,934,592 **luma samples**, not resident-memory bytes.

Existing package threshold, kernel backend, execution threads, per-frame limits
and export options remain available. `--report-out FILE` must be a new file
outside the deployment. Ordinary package detection and the original
[short sentinel](SENTINEL_DETECTION.md) keep their existing limits and report
bytes. Long sampling requires explicit opt-in and is not enabled by `watch`.

## Schedule and omissions

The period is measured in source segments relative to `--first-segment`, not wall
clock time. A burst is 1–8 contiguous segments, defaults to 3, and cannot exceed the
period or source range. Both `--sentinel-every-frames` and
`--sentinel-max-inferences` are required. The inference allowance is shared across
the entire operation, is at most 64 and must admit at least one complete burst.

Only whole bursts are admitted in source order. Later scheduled bursts that cannot
fit are explicitly `budget_exhausted`; a short tail is unsampled. The complete
complement is retained as compact source ranges. With 170 source segments, period
130, burst 3 and allowance 6:

| Segments | Result |
| --- | --- |
| 0–2 | First detector burst |
| 3–129 | Unsampled range of 127 segments |
| 130–132 | Second detector burst |
| 133–169 | Unsampled range of 37 segments |

Changing the range, period, burst or allowance changes the schedule identity even
when selected frames coincide. Separate bursts never become a continuous track.

## Whole-operation budgets and native execution

Source reads, JPEG reconstruction and detection-head work have shared allowances
that never restart per burst. Preprocessing, model MACs and tensor scratch retain
their per-inference limits. The checked aggregate reservation precedes source
reads and accounts for admitted inference, preprocessing, model and output work.

| Option | Default | Meaning and maximum |
| --- | ---: | --- |
| `--stream-read-bytes` | 536,870,912 | Whole-analysis source chunk bytes; maximum 536,870,912 |
| `--stream-pixel-budget` | 1,073,741,824 | Whole-analysis luma work allowance; maximum 68,719,476,736 |
| `--max-report-bytes` | 16,777,216 | Complete aggregate JSON bytes; maximum 16,777,216 |
| `--max-frame-pixels` | Native codec defaults | Optional narrowing ceiling, 256–9,437,184 pixels |
| `--max-macs` | 8,000,000,000 | Model execution ceiling per inference; aggregate arithmetic must also fit |
| `--max-tensor-bytes` | 268,435,456 | Tensor scratch per inference; maximum 268,435,456 |

MJPEG reads and decodes only admitted frames. Remaining whole-operation pixels
narrow the native JPEG frame gate before raster reconstruction.

AVC/HEVC decode the complete requested IDR/IRAP-led range once, including the suffix
after the last sample. Inter-picture references and native display order remain
intact; RGB conversion and inference run only on selected pictures. A late child
that begins on a non-keyframe is an analysis interval from that outer decoder,
not authorization to seek without its reference prefix.

Encoded video bytes and configured coded-luma capacity are admitted independently
before decode. Every access unit consumes its configured capacity, including
decoder read-ahead and skipped CRA leading pictures. The default capacity is
9,437,184 samples per access unit. A known smaller camera ceiling permits a longer
range within the same work allowance. `--max-frame-pixels` only narrows native
limits; AVC rounds down to whole 256-pixel macroblocks. Reports distinguish this
conservative admission charge from actual returned raster pixels.

Sparse inference saves model work without promising proportional video-decode
savings. Source/decode gaps, missing selected pictures, selected skipped CRA
pictures, inconsistent bursts, cancellation or exhausted resources refuse the
computation. No partial success report is printed. Current approved sensor masks
are applied before inference and remain bindings of retention and replay.

## Aggregate retention and retry

`fss.long_sentinel_detection_report.v1` binds the import and source range, complete
schedule and omissions, package/model identities, privacy projection, resource
reservations and usage, and each ordinary child package report. Child JSON bytes
and digests retain `fss.package_detection_report.v1`, including its final newline.

With `--retain yes`, the native owner validates the entire model archive, each
child's source/privacy bindings, every requested source capsule including
unsampled segments, and original source/acquisition custody before new writes.
Existing package retention publishes the children, then the aggregate root is
published last with its exact JSON, canonical recipe and complete model archive.

Retention completes before export or successful stdout output. Stderr gives
`long_sentinel_retained`, `status` (`retained` or `already_retained`), `root`,
`recipe`, `package`, `children` and `authority_sequence`. Computation JSON retains
`retention: not_asserted_by_computation`; publication is established by the separate
retention receipt.

Interrupted publication can leave completed children durable. Retry the exact
source, model, schedule and limits to reconcile them and finish the aggregate.
Existing child roots are not republished. Missing or changed custody, owner
replacement, conflicting authority or a new privacy generation refuses.

## Cold numerical replay

Use the aggregate report identity from `long_sentinel_retained`:

```sh
fss-infer sentinel-replay \
  --root /path/to/deployment --site site:home \
  --report-digest sha256:AGGREGATE_REPORT_DIGEST \
  --stream-pixel-budget 8589934592
```

Replay loads the retained model and canonical recipe, restores the exact backend,
threshold, original source range, schedule and limits, recomputes native inference,
and compares the complete report bytes/digest. It accepts no replacement model,
source, threshold or sampling schedule. Loose inputs may be removed after their
independent native retention has succeeded.

Independent current source, pixel, report, MAC, tensor and frame ceilings must
admit the saved recipe; they do not replace its settings. The larger pixel
allowance in the run example must therefore also be admitted on replay.
`--max-metadata-bytes` independently bounds retained metadata reads (default
67,108,864; maximum 134,217,728 bytes). Existing bounded child-custody reads and
analysis share an explicitly reserved owner; custody checks do not renew analysis
or inference budgets.

Cold open verifies retained history, root, manifest, recipe, archive, children,
full source custody and current privacy. Native video replay reconstructs the
original prefix. A narrowed current limit, damaged data, missing capsule, changed
privacy or failed exact comparison refuses. Success prints the reproduced JSON.
Native deployment opening can finish existing restart recovery; replay creates
no new detection or event publication.

## Investigate a child

Use a completed burst's **child report digest** with the existing event workflow:

```sh
fss-event report --root /path/to/deployment --site site:home \
  --package-report sha256:CHILD_REPORT_DIGEST --label person \
  --confirmation-hits 3 --report-out burst-analysis.bin
```

Each burst is tracked independently. Review candidates through the existing
prepare/exact-approval/publish path. Model labels remain uncalibrated supporting
evidence; sampling grants no publication or external-effect authority. It does not
certify continuous coverage, absence, identity, intent or recognition accuracy.

## Validation and remaining scope

Focused native targets are:

```sh
cargo test --locked -p fss-reference --test long_sentinel_contract
cargo test --locked -p fss-cli --bin fss-infer
cargo test --locked -p fss-cli --test long_sentinel_cli_contract
cargo test --locked -p fss-cli --test sentinel_detection_cli_contract
```

Core contracts exercise long scheduling/overflow, shared budgets, late AVC/HEVC
non-keyframe samples, strict suffix validation and decode-ahead, foreign authority,
cancellation, source/model/privacy custody, root-last retries and cold package-event
access. The process contract imports 170 static JPEG frames, verifies no foreground
candidate, samples beyond segment 64, compares an ordinary child, retains and
investigates independent bursts, removes loose inputs and replays in another
process. It also checks current ceilings and privacy changes.

The color-bar fixture's `tie` predictions test native wiring and exact reproduction,
not recognition accuracy. Always-on monitoring, wall-clock cadence, tolerant video
recovery, calibrated quality/recall measurements and continuous-coverage proofs
remain separate work. Focused tests do not replace full workspace/release or
physical-camera qualification.
