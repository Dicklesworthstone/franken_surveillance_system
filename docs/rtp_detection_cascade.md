# Explicit activity/sentinel detection over retained RTP

This reference slice connects FSS-078 / WP-090 sampling to the current-custody native
H.264 detector. It does not activate a deployment policy or change ordinary `detect`,
`track`, or `motion` behavior. It is not a live camera supervisor or a recall qualification.

## What is selected, and what is never omitted

`RtpDetectionCascade` owns the same native receipt decoder and verified neural executor
as `RtpPackageDetector`. It checks source custody and current privacy for every decoded
frame. The shared integer pixel-change kernel compares masked luma, and the existing
activity-policy scheduler chooses expensive RGB conversion, preprocessing, inference and
head projection. There is no second decode pass, caller-supplied frame/receipt pair, or
independent model-execution implementation.

Sentinels use zero-based native **display positions**, not coding-order groups, successful
inference counts, RTP timestamps, or seconds. Position zero and every multiple of the
explicit stride are selected. Motion and comparison resets select their configured
follow-up burst without shifting that sentinel phase. Owner-required positions also select
inference. Their digest-bearing reasons are inclusion constraints, not capabilities.

A missing predecessor, a source gap, an epoch change or a changed comparison interpretation
is unmeasured, not quiet. When the comparison-work or configured baseline-storage allowance
cannot admit a comparison, the frame is selected for inference. Actual allocation failures
remain terminal. This does not widen neural authority or resources: inability to admit the
required model invocation ends the scan unsuccessfully. Native, custody, receipt, comparison,
decision, color, preprocessing, neural, tensor and output allowances are separate.
Nothing is replenished by a recovery or baseline reset.

## Operator command

Use an existing completed retained RTP root and the exact SHA-256 of a verified local RGB
detector package. Thresholds below illustrate syntax; they are **not calibrated settings**:

```sh
fss-decode-rtp cascade \
  --root /owner/private/deployment --site site:home \
  --source-root "$RETAINED_RTP_ROOT" --custody current \
  --package /owner/models/detector.fmpk --package-sha256 "$PACKAGE_SHA256" \
  --pixel-delta 16 --minimum-changed-pixels 64 --minimum-changed-ppm 1000 \
  --sentinel-stride 10 --post-activity-frames 2 \
  --max-comparisons 64000000 --max-inference-frames 128 \
  --report-out /owner/private/review/cascade.jsonl
```

The source root, package, current-custody mode, new private report destination, pixel delta,
changed-pixel count and sentinel stride are required. The usual exact SPS/PPS selection,
source-read, native decode and recovery bounds remain available. Sampling accepts no pixel
export. The report must be outside the deployment and cannot overwrite an existing file.
An invalid package or failed admission creates no report.

Optional sampling bounds are `--max-baseline-bytes` (0..4194304),
`--max-sampling-bytes` (4096..67108864), `--max-comparisons` (including zero), and
`--max-inference-frames` (1..1024). Decision encoding reserves 4096 bytes before each
comparison, then refunds unused bytes on successful encoding. Consequently a remaining
encoding balance smaller than 4096 cannot admit another decision even when its eventual
encoding might be shorter.

To require particular source display positions, add a bounded map:

```sh
  --required-frames "3=$INCLUSION_BASIS,17=$INCLUSION_BASIS"
```

Each basis is an explicit `sha256:HEX` reason identity. Positions must be unique and below
4096. Map order is canonicalized. A required position that is never observed keeps the scan
incomplete; the implementation never fabricates its frame or treats the requirement as met.
This command-line map is bounded to a 4096-byte argument; the native API separately supports
up to 4096 entries. A changed inclusion map or sampling allowance changes the cascade recipe.

`--sentinel-stride 1` selects every frame. Under matching execution limits, the new cascade
retains each original detector result identity as well as adding its sampling-result chain.
Omitting the `cascade` command is the supported way to keep the existing exhaustive workflow.

## Reports and interpretation

The report format is `fss.retained_rtp_cascade_report.v1`. Each completed decoded position
has a `sampling` row with a native frame-receipt identity, canonical decision bytes/digest,
source group and decoder epoch, predecessor result, all inclusion reasons, measurement or
explicit reset/resource fallback, and the coupled result digest. Inferred frames additionally
use the existing `frame` and `proposal` rows. A skipped frame has `model_executed:false` and
`detection_sha256:null`; this means **not executed**, never an empty detector result.

The chain contains both included and skipped positions. Native progress, refusals and gaps
remain visible. Numerical output indices remain the true source display positions: sampling
positions 0 and 2 must not renumber them as frames 0 and 1. Native frame receipts can be
reproduced using the existing receipt workflow; the sampling report is not a signature,
a durable source publication or a promise of future custody.

`sampling_complete:true` requires complete native input, one result for every decoded frame,
successful inference for every selected frame, and no unresolved required positions.
`all_frames_inferred` is a separate statement and is false after any skip. Both are distinct
from physical absence, threat probability, camera health and measured detection recall.
A failure may leave a bounded partial report, but does not emit a successful final report
digest. Output failure stops the next native step; no further model work runs detached.

The current implementation deliberately does not feed sparsely selected results into the
ordinary tracker. Tracking across skipped intervals needs an explicit missing-observation
contract; a quiet sampling decision is not a negative object observation.

## Cost model and qualification boundary

For N decoded frames and K selected frames, expensive work is K color/preprocess/model/head
invocations rather than N. Native decode, current-custody readback and frame receipts still
cover all N frames. Additional cost is at most the admitted pixel comparisons, one bounded
previous-luma allocation, bounded required-position metadata, and decision/report encoding.
This describes work admission, not a wall-time speedup or a field-accuracy result.

Native regression cases compare exhaustive and stride-one numerical identities, preserve
true sparse display positions and cold replay, and exercise budget/memory inference floors,
required frames, bursts, source damage, privacy/custody changes and cancellation. CLI cases
exercise private deterministic reports, unchanged ordinary detection, inclusion constraints,
incomplete sources and refusal before output creation.

These new cases have been authored but were not run in the preparation environment, which
has no Rust compiler. Compilation, rustfmt, Clippy, native test execution, model/field recall,
platform performance and release qualification remain unverified. FSS-078 and WP-090 are not
closed by this slice. Use the accepted pinned compiler for validation:

```sh
cargo +nightly-2026-08-31 test --locked --offline -p fss-reference \
  --test rtpdump_detection_contract
cargo +nightly-2026-08-31 test --locked --offline -p fss-cli \
  --bin fss-decode-rtp --test rtp_detection_cli
```
